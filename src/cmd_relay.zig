//! `deed relay`: fetch relays' NIP-11 information documents.
//!
//! One JSON line per relay, in the order given. The document is passed through
//! as the relay wrote it (whitespace aside), so a field this build has never
//! heard of still reaches the reader.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const http = @import("http.zig");

const nip11 = nostr.nip11;

pub const summary = "fetch relays' NIP-11 information documents";

pub const ready = true;

pub const usage =
    \\deed relay: fetch relays' NIP-11 information documents
    \\
    \\Usage:
    \\  deed relay [options] <relay>...
    \\
    \\Asks each relay for its information document over HTTP and prints one
    \\JSON line per relay, in the order given. A relay is a wss:// or ws://
    \\URL, an https:// or http:// URL, or a bare host (read as wss://).
    \\
    \\Options:
    \\  --pretty           indent each document over several lines
    \\  --timeout <ms>     give up on a relay after this long (default 10000)
    \\  --allow-http       permit plain http to a host that is not local
    \\
    \\Exits: 1 if any relay failed, after saying why on stderr; the others are
    \\still printed.
    \\
;

/// Relays asked at once.
const batch = 16;

/// A document is a page of settings; this is generous.
const max_doc_bytes = 1024 * 1024;

const Settings = struct {
    pretty: bool = false,
    timeout_ms: u64 = 10_000,
    allow_http: bool = false,
};

const Outcome = struct {
    ok: bool,
    /// The line to print, or the reason it failed. Owned.
    text: []u8,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var settings: Settings = .{};
    var relays: std.ArrayList([]const u8) = .empty;
    defer relays.deinit(gpa);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        } else if (std.mem.eql(u8, a, "--pretty")) {
            settings.pretty = true;
        } else if (std.mem.eql(u8, a, "--allow-http")) {
            settings.allow_http = true;
        } else if (std.mem.eql(u8, a, "--timeout")) {
            i += 1;
            if (i >= args.len) {
                try err.writeAll("deed relay: --timeout needs a number of milliseconds\n");
                return cli.exit_usage;
            }
            const ms = std.fmt.parseInt(u32, args[i], 10) catch 0;
            if (ms == 0 or ms > 3_600_000) {
                try err.print("deed relay: '{s}' is not a number of milliseconds from 1 to 3600000\n", .{args[i]});
                return cli.exit_usage;
            }
            settings.timeout_ms = ms;
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed relay: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else {
            try relays.append(gpa, a);
        }
    }
    if (relays.items.len == 0) {
        try err.writeAll("deed relay: give at least one relay\n\n");
        try err.writeAll(usage);
        return cli.exit_usage;
    }

    var failures: usize = 0;
    var start: usize = 0;
    while (start < relays.items.len) {
        const group = relays.items[start..@min(start + batch, relays.items.len)];
        start += group.len;

        var outcomes: [batch]Outcome = undefined;
        askAll(gpa, io, group, settings, outcomes[0..group.len]);
        for (group, outcomes[0..group.len]) |relay, o| {
            defer gpa.free(o.text);
            if (o.ok) {
                try out.print("{s}\n", .{o.text});
            } else {
                failures += 1;
                try err.print("deed relay: {s}: {s}\n", .{ relay, o.text });
            }
        }
    }
    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

/// Asks every relay of `group` at once, and writes relay `i`'s outcome to `out[i]`.
fn askAll(gpa: std.mem.Allocator, io: std.Io, group: []const []const u8, s: Settings, out: []Outcome) void {
    var futures: [batch]?std.Io.Future(Outcome) = @splat(null);
    for (group, 0..) |relay, i| {
        futures[i] = io.concurrent(ask, .{ gpa, io, relay, s }) catch null;
    }
    for (group, 0..) |relay, i| {
        out[i] = if (futures[i]) |*f| f.await(io) else ask(gpa, io, relay, s);
    }
}

fn ask(gpa: std.mem.Allocator, io: std.Io, relay: []const u8, s: Settings) Outcome {
    if (document(gpa, io, relay, s)) |text| {
        return .{ .ok = true, .text = text };
    } else |e| {
        return .{ .ok = false, .text = reasonText(gpa, e) };
    }
}

const Failure = http.Error || error{ BadStatus, NotADocument, BadRelayUrl };

fn reasonText(gpa: std.mem.Allocator, e: Failure) []u8 {
    const sentence: []const u8 = switch (e) {
        error.BadStatus => "the relay answered with an HTTP error",
        error.NotADocument => "the reply is not a JSON object",
        error.BadRelayUrl => "not a relay URL",
        else => |h| http.describe(h),
    };
    return gpa.dupe(u8, sentence) catch @constCast("failed");
}

/// The document for `relay`, one line (or indented, if asked). Caller owns it.
fn document(gpa: std.mem.Allocator, io: std.Io, relay: []const u8, s: Settings) Failure![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const given = if (std.mem.indexOf(u8, relay, "://") == null)
        try std.fmt.allocPrint(arena, "wss://{s}", .{relay})
    else
        relay;
    const url = nip11.httpUrl(arena, given) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadRelayUrl,
    };

    var res = try http.fetch(gpa, io, url, .{
        .headers = &.{.{ .name = nip11.accept_header_name, .value = nip11.accept_header_value }},
        .timeout_ms = s.timeout_ms,
        .max_bytes = max_doc_bytes,
        .allow_http = s.allow_http,
    });
    defer res.deinit(gpa);
    if (!res.ok()) return error.BadStatus;
    return render(gpa, res.body, s.pretty);
}

/// `body` as one line, or indented. It must be a JSON object.
fn render(gpa: std.mem.Allocator, body: []const u8, pretty: bool) Failure![]u8 {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '{') return error.NotADocument;
    if (!(try std.json.validate(gpa, trimmed))) return error.NotADocument;

    var buf: std.Io.Writer.Allocating = .init(gpa);
    errdefer buf.deinit();
    if (pretty) {
        const parsed = std.json.parseFromSlice(std.json.Value, gpa, trimmed, .{}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.NotADocument,
        };
        defer parsed.deinit();
        std.json.Stringify.value(parsed.value, .{ .whitespace = .indent_2 }, &buf.writer) catch return error.OutOfMemory;
    } else {
        // The bytes as written, minus the whitespace between tokens.
        var in_string = false;
        var escaped = false;
        for (trimmed) |c| {
            if (in_string) {
                try appendByte(&buf, c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    in_string = false;
                }
                continue;
            }
            switch (c) {
                ' ', '\t', '\r', '\n' => {},
                '"' => {
                    in_string = true;
                    try appendByte(&buf, c);
                },
                else => try appendByte(&buf, c),
            }
        }
    }
    return buf.toOwnedSlice() catch error.OutOfMemory;
}

fn appendByte(buf: *std.Io.Writer.Allocating, c: u8) error{OutOfMemory}!void {
    buf.writer.writeByte(c) catch return error.OutOfMemory;
}

// ---- tests ---------------------------------------------------------------

const doc_text =
    \\{
    \\  "name": "Test Relay",
    \\  "description": "a \"quoted\"  description",
    \\  "supported_nips": [1, 11, 42],
    \\  "something_new": {"a": 1}
    \\}
;

fn runForTest(io: std.Io, args: []const []const u8, out: *std.Io.Writer.Allocating, err: *std.Io.Writer.Allocating) !u8 {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the relay verb leaked");
    return run(da.allocator(), io, args, &out.writer, &err.writer);
}

test "a relay's document prints as one line, unknown fields kept" {
    const io = std.testing.io;
    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/", .body = doc_text }}, 1);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const url = try srv.url(&ub, "/");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();

    const code = try runForTest(io, &.{url}, &out, &err);
    try std.testing.expectEqual(cli.exit_ok, code);
    try std.testing.expectEqualStrings("", err.written());
    try std.testing.expectEqualStrings(
        "{\"name\":\"Test Relay\",\"description\":\"a \\\"quoted\\\"  description\",\"supported_nips\":[1,11,42],\"something_new\":{\"a\":1}}\n",
        out.written(),
    );
}

test "--pretty indents, and a failed relay is reported while the rest print" {
    const io = std.testing.io;
    var srv: http.TestServer = undefined;
    try srv.start(io, &.{
        .{ .path = "/good", .body = doc_text },
        .{ .path = "/html", .body = "<html>nope</html>" },
    }, 3);
    defer srv.stop(io);

    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    var b3: [64]u8 = undefined;
    const good = try srv.url(&b1, "/good");
    const html = try srv.url(&b2, "/html");
    const gone = try srv.url(&b3, "/gone");

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();

    const code = try runForTest(io, &.{ "--pretty", html, good, gone }, &out, &err);
    try std.testing.expectEqual(cli.exit_fail, code);
    try std.testing.expect(std.mem.startsWith(u8, out.written(), "{\n  \"name\": \"Test Relay\""));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "not a JSON object") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "HTTP error") != null);
}

test "a relay that never answers fails at the deadline" {
    const io = std.testing.io;
    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/", .delay_ms = 20_000 }}, 1);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const url = try srv.url(&ub, "/");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();

    const code = try runForTest(io, &.{ "--timeout", "300", url }, &out, &err);
    try std.testing.expectEqual(cli.exit_fail, code);
    try std.testing.expectEqualStrings("", out.written());
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "timed out") != null);
}

test "usage mistakes exit 2" {
    const io = std.testing.io;
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_usage, try runForTest(io, &.{}, &out, &err));
    try std.testing.expectEqual(cli.exit_usage, try runForTest(io, &.{"--bogus"}, &out, &err));
    try std.testing.expectEqual(cli.exit_usage, try runForTest(io, &.{ "--timeout", "0", "x" }, &out, &err));
}

test "a wss URL becomes the https document URL" {
    const gpa = std.testing.allocator;
    const u = try nip11.httpUrl(gpa, "wss://relay.example/path");
    defer gpa.free(u);
    try std.testing.expectEqualStrings("https://relay.example/path", u);
}

test {
    _ = @import("http.zig");
}
