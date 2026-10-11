//! `deed admin`: manage a relay over NIP-86.
//!
//! One JSON-RPC style call per method, sent as an HTTPS POST with the
//! `application/nostr+json+rpc` content type and a NIP-98 `Authorization`
//! header that binds the body by its sha256. The relay's `result` is printed
//! as JSON on stdout; a relay that answers with an error, or does not answer
//! like a NIP-86 relay, is reported on stderr with exit status 1.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const http = @import("http.zig");
const keyinput = @import("keyinput.zig");
const curl = @import("cmd_curl.zig");
const signing = @import("signing.zig");

const keys = nostr.keys;
const nip86 = nostr.nip86;

pub const summary = "manage a relay with the NIP-86 management API";

pub const ready = true;

pub const usage =
    \\deed admin: manage a relay with the NIP-86 management API
    \\
    \\Usage:
    \\  deed admin [options] <relay-url> <method> [args...]
    \\
    \\Sends one NIP-86 call to the relay's HTTP endpoint, signed with your key,
    \\and prints the relay's result as JSON. A wss:// or ws:// relay URL is
    \\sent as https:// or http://, and a bare host is read as https://.
    \\
    \\Methods:
    \\  supportedmethods                       what the relay offers
    \\  banpubkey | unbanpubkey <pubkey> [reason]
    \\  allowpubkey | unallowpubkey <pubkey> [reason]
    \\  listbannedpubkeys | listallowedpubkeys
    \\  allowevent | banevent <id> [reason]
    \\  listbannedevents | listeventsneedingmoderation
    \\  blockip | unblockip <ip> [reason]
    \\  listblockedips
    \\  changerelayname | changerelaydescription | changerelayicon <text>
    \\  allowkind | disallowkind <kind>...     one call per kind
    \\  listallowedkinds
    \\
    \\A pubkey is npub1... or 64 hex characters; an id is 64 hex characters.
    \\
    \\Options:
    \\  --sec <key>      the secret key to sign with (nsec1..., hex or
    \\                   ncryptsec1...), or a remote signer as bunker://...
    \\                   Falls back to $NOSTR_SECRET_KEY.
    \\  --pretty         indent the JSON
    \\  --timeout <s>    give up after this many seconds (default 15)
    \\  --allow-http     permit plain http to a host that is not local
    \\
    \\Exits 1 if the relay refuses the call or cannot be reached.
    \\
    \\Examples:
    \\  deed admin wss://relay.example.com supportedmethods
    \\  deed admin relay.example.com banpubkey npub1... "spam"
    \\  deed admin relay.example.com allowkind 1 30023
    \\
;

const Settings = struct {
    sec: ?[]const u8 = null,
    pretty: bool = false,
    timeout_ms: u64 = 15_000,
    allow_http: bool = false,
};

/// The HTTP URL to POST to for a relay as a person writes it. Ends in a path,
/// because that is the URL the server sees and the one the event must name.
pub fn httpUrl(arena: std.mem.Allocator, relay: []const u8) std.mem.Allocator.Error![]u8 {
    var scheme: []const u8 = "https";
    var rest = relay;
    if (std.mem.indexOf(u8, relay, "://")) |at| {
        const given = relay[0..at];
        rest = relay[at + 3 ..];
        if (std.ascii.eqlIgnoreCase(given, "ws") or std.ascii.eqlIgnoreCase(given, "http")) {
            scheme = "http";
        } else if (std.ascii.eqlIgnoreCase(given, "wss") or std.ascii.eqlIgnoreCase(given, "https")) {
            scheme = "https";
        } else {
            // Left as it is, for the HTTP client to refuse by name.
            return arena.dupe(u8, relay);
        }
    }
    const cut = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    const slash: []const u8 = if (cut < rest.len and rest[cut] == '/') "" else "/";
    return std.fmt.allocPrint(arena, "{s}://{s}{s}{s}", .{ scheme, rest[0..cut], slash, rest[cut..] });
}

const Built = union(enum) {
    ok: []const nip86.Request,
    /// A sentence for the user; the call is not made.
    bad: []const u8,
};

fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

/// The calls for `method` with its arguments. Every string lives in `arena`.
fn build(arena: std.mem.Allocator, gpa: std.mem.Allocator, method: []const u8, rest: []const []const u8) !Built {
    const Tag = std.meta.Tag(nip86.Request);
    const tag = std.meta.stringToEnum(Tag, method) orelse
        return .{ .bad = try std.fmt.allocPrint(arena, "unknown method '{s}' (see 'deed admin help')", .{method}) };

    const calls = try arena.alloc(nip86.Request, 1);
    switch (tag) {
        .supportedmethods,
        .listbannedpubkeys,
        .listallowedpubkeys,
        .listeventsneedingmoderation,
        .listbannedevents,
        .listallowedkinds,
        .listblockedips,
        => {
            if (rest.len != 0) return .{ .bad = try std.fmt.allocPrint(arena, "{s} takes no arguments", .{method}) };
            calls[0] = switch (tag) {
                .supportedmethods => .supportedmethods,
                .listbannedpubkeys => .listbannedpubkeys,
                .listallowedpubkeys => .listallowedpubkeys,
                .listeventsneedingmoderation => .listeventsneedingmoderation,
                .listbannedevents => .listbannedevents,
                .listallowedkinds => .listallowedkinds,
                else => .listblockedips,
            };
        },
        .banpubkey, .unbanpubkey, .allowpubkey, .unallowpubkey, .allowevent, .banevent, .blockip, .unblockip => {
            if (rest.len < 1 or rest.len > 2)
                return .{ .bad = try std.fmt.allocPrint(arena, "{s} takes one argument and an optional reason", .{method}) };
            const reason: ?[]const u8 = if (rest.len == 2) rest[1] else null;
            var value: []const u8 = rest[0];
            switch (tag) {
                .banpubkey, .unbanpubkey, .allowpubkey, .unallowpubkey => {
                    const pk = keyinput.publicKey(gpa, value) catch
                        return .{ .bad = try std.fmt.allocPrint(arena, "'{s}' is not a public key (want npub1... or 64 hex characters)", .{value}) };
                    value = try nostr.hex.encode(arena, &pk);
                },
                .allowevent, .banevent => {
                    if (!isHex64(value))
                        return .{ .bad = try std.fmt.allocPrint(arena, "'{s}' is not an event id (want 64 hex characters)", .{value}) };
                    value = try std.ascii.allocLowerString(arena, value);
                },
                else => {
                    _ = std.Io.net.IpAddress.parse(value, 0) catch
                        return .{ .bad = try std.fmt.allocPrint(arena, "'{s}' is not an IP address", .{value}) };
                },
            }
            const t: nip86.Target = .{ .value = value, .reason = reason };
            calls[0] = switch (tag) {
                .banpubkey => .{ .banpubkey = t },
                .unbanpubkey => .{ .unbanpubkey = t },
                .allowpubkey => .{ .allowpubkey = t },
                .unallowpubkey => .{ .unallowpubkey = t },
                .allowevent => .{ .allowevent = t },
                .banevent => .{ .banevent = t },
                .blockip => .{ .blockip = t },
                else => .{ .unblockip = t },
            };
        },
        .changerelayname, .changerelaydescription, .changerelayicon => {
            if (rest.len != 1) return .{ .bad = try std.fmt.allocPrint(arena, "{s} takes one argument: the new text", .{method}) };
            calls[0] = switch (tag) {
                .changerelayname => .{ .changerelayname = rest[0] },
                .changerelaydescription => .{ .changerelaydescription = rest[0] },
                else => .{ .changerelayicon = rest[0] },
            };
        },
        .allowkind, .disallowkind => {
            if (rest.len == 0) return .{ .bad = try std.fmt.allocPrint(arena, "{s} needs a kind number", .{method}) };
            const many = try arena.alloc(nip86.Request, rest.len);
            for (rest, 0..) |k, i| {
                const n = std.fmt.parseInt(u16, k, 10) catch
                    return .{ .bad = try std.fmt.allocPrint(arena, "'{s}' is not a kind number", .{k}) };
                many[i] = if (tag == .allowkind) .{ .allowkind = n } else .{ .disallowkind = n };
            }
            return .{ .ok = many };
        },
    }
    return .{ .ok = calls };
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var settings: Settings = .{};
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(gpa);

    var only_positional = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (only_positional or a.len < 2 or a[0] != '-') {
            try positional.append(gpa, a);
        } else if (std.mem.eql(u8, a, "--")) {
            only_positional = true;
        } else if (cli.isOneOf(a, &.{ "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        } else if (std.mem.eql(u8, a, "--pretty")) {
            settings.pretty = true;
        } else if (std.mem.eql(u8, a, "--allow-http")) {
            settings.allow_http = true;
        } else if (std.mem.eql(u8, a, "--sec")) {
            i += 1;
            if (i >= args.len) {
                try err.writeAll("deed admin: --sec needs a key\n");
                return cli.exit_usage;
            }
            settings.sec = args[i];
        } else if (std.mem.eql(u8, a, "--timeout")) {
            i += 1;
            const secs = if (i < args.len) std.fmt.parseInt(u32, args[i], 10) catch null else null;
            if (secs == null) {
                try err.writeAll("deed admin: --timeout needs a number of seconds\n");
                return cli.exit_usage;
            }
            settings.timeout_ms = @as(u64, secs.?) * 1000;
        } else {
            try err.print("deed admin: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
    }

    if (positional.items.len == 1 and std.mem.eql(u8, positional.items[0], "help")) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    if (positional.items.len < 2) {
        try err.writeAll("deed admin: needs a relay URL and a method (see 'deed admin help')\n");
        return cli.exit_usage;
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const method = try std.ascii.allocLowerString(arena, positional.items[1]);
    const built = try build(arena, gpa, method, positional.items[2..]);
    const calls = switch (built) {
        .ok => |c| c,
        .bad => |msg| {
            try err.print("deed admin: {s}\n", .{msg});
            return cli.exit_usage;
        },
    };

    var signer = (signing.fromFlag(gpa, io, "admin", settings.sec, err) catch |e| switch (e) {
        error.BadKey => return cli.exit_fail,
        else => return e,
    }) orelse return cli.exit_usage;
    defer signer.deinit();

    const url = try httpUrl(arena, positional.items[0]);

    for (calls) |call| {
        const body = try nip86.encodeRequest(arena, call);
        const now = std.Io.Timestamp.now(io, .real).toSeconds();
        // NIP-86 signs the call as NIP-98 does a POST with this body.
        const auth = signer.httpAuthHeader(arena, now, url, "POST", body) catch |e| return signing.report("admin", e, err);
        const headers = [_]http.Header{.{ .name = "Authorization", .value = auth }};

        var response = http.fetch(gpa, io, url, .{
            .method = .POST,
            .headers = &headers,
            .body = .{ .bytes = body },
            .content_type = nip86.content_type,
            .timeout_ms = settings.timeout_ms,
            // A redirect would change the URL the event names.
            .max_redirects = 0,
            .allow_http = settings.allow_http,
        }) catch |e| {
            try err.print("deed admin: {s}: {s}\n", .{ url, http.describe(e) });
            return cli.exit_fail;
        };
        defer response.deinit(gpa);

        var parsed = nip86.parseResponse(gpa, response.body) catch |e| switch (e) {
            error.OutOfMemory => return e,
            error.InvalidResponse => {
                if (response.ok()) {
                    try err.print("deed admin: {s}: not a NIP-86 response\n", .{url});
                } else {
                    try err.print("deed admin: {s}: HTTP error {d}\n", .{ url, response.status });
                }
                return cli.exit_fail;
            },
        };
        defer parsed.deinit();

        if (parsed.err) |msg| {
            try err.print("deed admin: {s}: relay error: {s}\n", .{ call.method(), msg });
            return cli.exit_fail;
        }
        if (!response.ok()) {
            try err.print("deed admin: {s}: HTTP error {d}\n", .{ url, response.status });
            return cli.exit_fail;
        }
        const result = parsed.result orelse {
            try err.print("deed admin: {s}: not a NIP-86 response\n", .{url});
            return cli.exit_fail;
        };
        try std.json.Stringify.value(result, .{ .whitespace = if (settings.pretty) .indent_2 else .minified }, out);
        try out.writeByte('\n');
    }
    return cli.exit_ok;
}

// ---- tests ---------------------------------------------------------------

const testing = std.testing;
const Io = std.Io;

test "a relay URL becomes the HTTP URL the call is signed for" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("https://relay.example.com/", try httpUrl(a, "wss://relay.example.com"));
    try testing.expectEqualStrings("http://localhost:7777/", try httpUrl(a, "ws://localhost:7777/"));
    try testing.expectEqualStrings("https://relay.example.com/", try httpUrl(a, "relay.example.com"));
    try testing.expectEqualStrings("https://relay.example.com/admin", try httpUrl(a, "https://relay.example.com/admin"));
    try testing.expectEqualStrings("https://relay.example.com/?x=1", try httpUrl(a, "WSS://relay.example.com?x=1"));
    try testing.expectEqualStrings("ftp://relay.example.com", try httpUrl(a, "ftp://relay.example.com"));
}

fn runAdmin(io: Io, args: []const []const u8, out: *Io.Writer.Allocating, err: *Io.Writer.Allocating) !u8 {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the admin verb leaked");
    return run(da.allocator(), io, args, &out.writer, &err.writer);
}

test "supportedmethods round trip over ws:// with a verifying header" {
    const io = testing.io;
    var srv: curl.CaptureServer = undefined;
    try srv.start(io, .ok, "{\"result\":[\"banpubkey\",\"supportedmethods\"]}", 1);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const http_url = try srv.url(&ub, "/");
    var wb: [64]u8 = undefined;
    const relay = try std.fmt.bufPrint(&wb, "ws://{s}", .{http_url["http://".len .. http_url.len - 1]});

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    const code = try runAdmin(io, &.{ "--sec", curl.test_secret, relay, "supportedmethods" }, &out, &err);
    try testing.expectEqualStrings("", err.written());
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqualStrings("[\"banpubkey\",\"supportedmethods\"]\n", out.written());

    try testing.expectEqualStrings("POST", srv.sentMethod());
    try testing.expectEqualStrings(nip86.content_type, srv.sentContentType());
    try testing.expectEqualStrings("{\"method\":\"supportedmethods\",\"params\":[]}", srv.sentBody());
    try curl.expectSigned(io, srv.sentAuth(), http_url, "POST", srv.sentBody());
}

test "banpubkey maps an npub and a reason onto the call" {
    const io = testing.io;
    var srv: curl.CaptureServer = undefined;
    try srv.start(io, .ok, "{\"result\":true}", 3);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const http_url = try srv.url(&ub, "/");

    const raw = [_]u8{0x11} ** 32;
    const npub = try nostr.nip19.encodeNpub(testing.allocator, raw);
    defer testing.allocator.free(npub);

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    var code = try runAdmin(io, &.{ "--sec", curl.test_secret, http_url, "banpubkey", npub, "spam" }, &out, &err);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqualStrings("true\n", out.written());
    const want = "{\"method\":\"banpubkey\",\"params\":[\"" ++ "11" ** 32 ++ "\",\"spam\"]}";
    try testing.expectEqualStrings(want, srv.sentBody());
    try curl.expectSigned(io, srv.sentAuth(), http_url, "POST", want);

    // One call per kind.
    code = try runAdmin(io, &.{ "--sec", curl.test_secret, http_url, "allowkind", "1", "30023" }, &out, &err);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqualStrings("{\"method\":\"allowkind\",\"params\":[30023]}", srv.sentBody());
    try testing.expectEqualStrings("true\ntrue\ntrue\n", out.written());
}

test "a relay error goes to stderr with exit 1" {
    const io = testing.io;
    var srv: curl.CaptureServer = undefined;
    try srv.start(io, .unauthorized, "{\"error\":\"not the relay owner\"}", 1);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const http_url = try srv.url(&ub, "/");

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    const code = try runAdmin(io, &.{ "--sec", curl.test_secret, http_url, "listbannedpubkeys" }, &out, &err);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expectEqualStrings("", out.written());
    try testing.expect(std.mem.indexOf(u8, err.written(), "relay error: not the relay owner") != null);
}

test "an answer that is not NIP-86 is reported with its status" {
    const io = testing.io;
    var srv: curl.CaptureServer = undefined;
    try srv.start(io, .not_found, "<html>nope</html>", 1);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const http_url = try srv.url(&ub, "/");

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    const code = try runAdmin(io, &.{ "--sec", curl.test_secret, http_url, "supportedmethods" }, &out, &err);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expect(std.mem.indexOf(u8, err.written(), "HTTP error 404") != null);
}

test "bad arguments are refused before anything is sent" {
    const io = testing.io;
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    const cases = [_][]const []const u8{
        &.{"relay.example.com"},
        &.{ "relay.example.com", "frobnicate" },
        &.{ "relay.example.com", "banpubkey", "not-a-key" },
        &.{ "relay.example.com", "banevent", "abc" },
        &.{ "relay.example.com", "blockip", "999.1.1.1" },
        &.{ "relay.example.com", "allowkind", "many" },
        &.{ "relay.example.com", "changerelayname" },
        &.{ "relay.example.com", "listallowedkinds", "extra" },
    };
    for (cases) |c| {
        err.writer.end = 0;
        try testing.expectEqual(cli.exit_usage, try runAdmin(io, c, &out, &err));
        try testing.expect(err.written().len > 0);
    }
}

test "a call signed by a remote signer carries a header by the user that verifies" {
    const io = testing.io;
    const signertest = @import("signertest.zig");
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the admin verb leaked");
    const gpa = da.allocator();

    var rig: signertest.Rig = undefined;
    try rig.init(gpa, io, .serve);
    defer rig.deinit();

    var srv: curl.CaptureServer = undefined;
    try srv.start(io, .ok, "{\"result\":[\"supportedmethods\"]}", 1);
    defer srv.stop(io);
    var ub: [64]u8 = undefined;
    const http_url = try srv.url(&ub, "/");

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "--sec", rig.uri(), http_url, "supportedmethods" }, &out.writer, &err.writer);
    try testing.expectEqualStrings("", err.written());
    try testing.expectEqual(cli.exit_ok, code);

    var ctx = keys.Signer.init();
    defer ctx.deinit();
    const pk = try nostr.nip98.verifyHeader(testing.allocator, ctx, srv.sentAuth(), .{
        .url = http_url,
        .method = "POST",
        .body = srv.sentBody(),
        .now = Io.Timestamp.now(io, .real).toSeconds(),
    });
    try testing.expectEqualSlices(u8, &rig.user.public_key, &pk);
}
