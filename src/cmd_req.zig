//! `deed req`: build a subscription, and run it.
//!
//! With no relay arguments it prints the REQ envelope and stops, which makes
//! the filter itself inspectable before anybody dials anything. nak does the
//! same and it is the right default for a tool whose whole point is that you
//! can see what it is about to send.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const relayset = @import("relayset.zig");

const filter = nostr.filter;
const message = nostr.message;
const hex = nostr.hex;

pub const usage =
    \\deed req: build a subscription, and run it
    \\
    \\Usage:
    \\  deed req [options] [<relay-url>...]
    \\
    \\Options:
    \\  -k, --kind <n>       event kind, repeatable
    \\  -a, --author <key>   author, as npub1… or 64 hex characters, repeatable
    \\  -i, --id <id>        event id, as note1… or 64 hex characters, repeatable
    \\  -e <id>              an `e` tag value, repeatable
    \\  -p <key>             a `p` tag value, repeatable
    \\  -t <topic>           a `t` tag value, repeatable
    \\  -l, --limit <n>      how many events to ask each relay for
    \\  -s, --since <n>      unix seconds, events at or after
    \\  -u, --until <n>      unix seconds, events at or before
    \\      --bare           print the filter alone, without the REQ envelope
    \\      --store <path>   keep every event this receives in a local store
    \\      --local          answer from the store alone, dialling nothing
    \\      --stream         keep reading after the relays have sent what they hold
    \\      --timeout <ms>   give up on relays still answering (default 30000)
    \\
    \\A relay that has not accepted the connection within five seconds, or
    \\within --timeout if that is shorter, is named on stderr and left out.
    \\Looking up a relay's name is the one step that cannot be cut short.
    \\
    \\Given no relay, it prints what it would send and stops, so a filter can be
    \\read before it is asked of anybody:
    \\
    \\  deed req -k 1 -l 5
    \\  ["REQ","deed",{"kinds":[1],"limit":5}]
    \\
;

/// The filter a run is about, and the relays to ask.
pub const Request = struct {
    filter: filter.Filter,
    relays: []const []const u8,
    bare: bool,
    store_path: ?[]const u8 = null,
    stream: bool = false,
    local: bool = false,
    timeout_ms: i64 = default_timeout_ms,
};

/// How long a run waits on relays still answering, once they are reached.
/// Reaching them has its own, shorter bound (`dial.default_timeout_ms`).
///
/// Thirty seconds: long enough for a slow relay on a slow link, short enough
/// that a script does not hang on one gone quiet.
pub const default_timeout_ms: i64 = 30_000;

const max_values = 64;

/// What a repeated flag collects. Fixed, because a command line naming more
/// than this many authors is a file being piped in by the wrong route.
fn Collected(comptime T: type) type {
    return struct {
        items: [max_values]T = undefined,
        len: usize = 0,

        fn push(self: *@This(), v: T) bool {
            if (self.len >= self.items.len) return false;
            self.items[self.len] = v;
            self.len += 1;
            return true;
        }
        fn slice(self: *const @This()) ?[]const T {
            return if (self.len == 0) null else self.items[0..self.len];
        }
    };
}

/// A 32-byte key or id, as `npub1…`/`note1…`/`nsec1…` or 64 hex characters.
fn idOrKey(gpa: std.mem.Allocator, s: []const u8) ?[32]u8 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (t.len == 64) return hex.decodeFixed(32, t) catch null;
    if (std.mem.startsWith(u8, t, "npub1")) return nostr.nip19.decodeNpub(gpa, t) catch null;
    if (std.mem.startsWith(u8, t, "note1")) return nostr.nip19.decodeNote(gpa, t) catch null;
    return null;
}

pub const ParseError = error{ Usage, BadValue };

/// Reads the flags into a filter. The relays are whatever is left over.
pub fn parse(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    ids: *Collected([32]u8),
    authors: *Collected([32]u8),
    kinds: *Collected(u16),
    e_tags: *Collected([]const u8),
    p_tags: *Collected([]const u8),
    t_tags: *Collected([]const u8),
    tags: *[3]filter.TagFilter,
    relays: *Collected([]const u8),
    err: *std.Io.Writer,
) !?Request {
    var f = filter.Filter{};
    var bare = false;
    var stream = false;
    var local = false;
    var store_path: ?[]const u8 = null;
    var timeout_ms: i64 = default_timeout_ms;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) return null;
        if (std.mem.eql(u8, a, "--bare")) {
            bare = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--stream")) {
            stream = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--local")) {
            local = true;
            continue;
        }
        if (!std.mem.startsWith(u8, a, "-")) {
            if (!relays.push(a)) {
                try err.writeAll("deed req: too many relays\n");
                return ParseError.Usage;
            }
            continue;
        }

        const takes_value = cli.isOneOf(a, &.{
            "-k",      "--kind", "-a",      "--author", "-i",        "--id",
            "-e",      "-p",     "-t",      "-l",       "--limit",   "-s",
            "--since", "-u",     "--until", "--store",  "--timeout",
        });
        if (!takes_value) {
            try err.print("deed req: unknown option '{s}'\n", .{a});
            return ParseError.Usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed req: '{s}' needs a value\n", .{a});
            return ParseError.Usage;
        }
        const v = args[i];

        if (cli.isOneOf(a, &.{ "-k", "--kind" })) {
            const n = std.fmt.parseInt(u16, v, 10) catch {
                try err.print("deed req: '{s}' is not a kind number\n", .{v});
                return ParseError.BadValue;
            };
            _ = kinds.push(n);
        } else if (cli.isOneOf(a, &.{ "-a", "--author" })) {
            const k = idOrKey(gpa, v) orelse {
                try err.print("deed req: '{s}' is not a key\n", .{v});
                return ParseError.BadValue;
            };
            _ = authors.push(k);
        } else if (cli.isOneOf(a, &.{ "-i", "--id" })) {
            const k = idOrKey(gpa, v) orelse {
                try err.print("deed req: '{s}' is not an id\n", .{v});
                return ParseError.BadValue;
            };
            _ = ids.push(k);
        } else if (std.mem.eql(u8, a, "-e")) {
            _ = e_tags.push(v);
        } else if (std.mem.eql(u8, a, "-p")) {
            _ = p_tags.push(v);
        } else if (std.mem.eql(u8, a, "-t")) {
            _ = t_tags.push(v);
        } else if (cli.isOneOf(a, &.{ "-l", "--limit" })) {
            f.limit = std.fmt.parseInt(u32, v, 10) catch {
                try err.print("deed req: '{s}' is not a limit\n", .{v});
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-s", "--since" })) {
            f.since = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed req: '{s}' is not a unix timestamp\n", .{v});
                return ParseError.BadValue;
            };
        } else if (std.mem.eql(u8, a, "--store")) {
            store_path = v;
        } else if (std.mem.eql(u8, a, "--timeout")) {
            timeout_ms = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed req: '{s}' is not a number of milliseconds\n", .{v});
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-u", "--until" })) {
            f.until = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed req: '{s}' is not a unix timestamp\n", .{v});
                return ParseError.BadValue;
            };
        }
    }

    f.ids = ids.slice();
    f.authors = authors.slice();
    f.kinds = kinds.slice();

    // The tag filters live in the caller's array so they outlive this function.
    var tag_len: usize = 0;
    if (e_tags.slice()) |v| {
        tags[tag_len] = .{ .letter = 'e', .values = v };
        tag_len += 1;
    }
    if (p_tags.slice()) |v| {
        tags[tag_len] = .{ .letter = 'p', .values = v };
        tag_len += 1;
    }
    if (t_tags.slice()) |v| {
        tags[tag_len] = .{ .letter = 't', .values = v };
        tag_len += 1;
    }
    if (tag_len > 0) f.tags = tags[0..tag_len];

    return .{
        .filter = f,
        .relays = relays.slice() orelse &.{},
        .bare = bare,
        .store_path = store_path,
        .stream = stream,
        .local = local,
        .timeout_ms = timeout_ms,
    };
}

/// The subscription id every run uses.
///
/// Fixed rather than random: one subscription per process, closed when the
/// process ends, so a unique id would buy nothing and would make the envelope
/// this prints different every time it is run, which is worse for a tool whose
/// output people paste into issues.
pub const subscription_id = "deed";

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var ids: Collected([32]u8) = .{};
    var authors: Collected([32]u8) = .{};
    var kinds: Collected(u16) = .{};
    var e_tags: Collected([]const u8) = .{};
    var p_tags: Collected([]const u8) = .{};
    var t_tags: Collected([]const u8) = .{};
    var tags: [3]filter.TagFilter = undefined;
    var relays: Collected([]const u8) = .{};

    const req = parse(gpa, args, &ids, &authors, &kinds, &e_tags, &p_tags, &t_tags, &tags, &relays, err) catch |e| {
        return switch (e) {
            ParseError.Usage => cli.exit_usage,
            ParseError.BadValue => cli.exit_fail,
            else => return e,
        };
    } orelse {
        try out.writeAll(usage);
        return cli.exit_ok;
    };

    // Answered from what is already kept, without dialling. This is the half
    // that makes keeping worth doing: a store nothing reads back is a log.
    if (req.local) {
        const path = req.store_path orelse {
            try err.writeAll("deed req: --local needs --store to read from\n");
            return cli.exit_usage;
        };
        const z = try gpa.dupeZ(u8, path);
        defer gpa.free(z);
        var st = nostr.store.Store.open(z, .{}) catch |e| {
            try err.print("deed req: cannot open the store at {s}: {s}\n", .{ path, @errorName(e) });
            return cli.exit_fail;
        };
        defer st.deinit();

        var result = st.query(gpa, req.filter) catch |e| {
            try err.print("deed req: the store could not answer: {s}\n", .{@errorName(e)});
            return cli.exit_fail;
        };
        defer result.deinit();
        for (result.events) |ev| {
            const json = try nostr.event.toJson(gpa, ev);
            defer gpa.free(json);
            try out.print("{s}\n", .{json});
        }
        return cli.exit_ok;
    }

    // No relay named: say what would be sent, and stop. The filter is the thing
    // worth seeing before it is asked of anybody.
    if (req.relays.len == 0) {
        const text = if (req.bare) blk: {
            var list: std.ArrayList(u8) = .empty;
            errdefer list.deinit(gpa);
            try req.filter.appendJson(&list, gpa);
            break :blk try list.toOwnedSlice(gpa);
        } else try message.encodeReq(gpa, subscription_id, &.{req.filter});
        defer gpa.free(text);
        try out.print("{s}\n", .{text});
        return cli.exit_ok;
    }

    var store: ?nostr.store.Store = null;
    defer if (store) |*st| st.deinit();
    if (req.store_path) |path| {
        const z = gpa.dupeZ(u8, path) catch {
            try err.writeAll("deed req: out of memory opening the store\n");
            return cli.exit_fail;
        };
        defer gpa.free(z);
        store = nostr.store.Store.open(z, .{}) catch |e| {
            try err.print("deed req: cannot open the store at {s}: {s}\n", .{ path, @errorName(e) });
            return cli.exit_fail;
        };
    }

    const outcome = try relayset.query(gpa, io, req.relays, &.{req.filter}, out, err, .{
        .until_eose = !req.stream,
        .deadline_ms = req.timeout_ms,
        .poll_ms = 100,
        .store = if (store) |*st| st else null,
    });

    // Reaching no relay at all is a failed run. Reaching some is not: the
    // events that arrived are real, and every relay that did not answer was
    // named on stderr as it failed.
    if (outcome.dialled == 0) {
        try err.writeAll("deed req: no relay answered\n");
        return cli.exit_fail;
    }
    return cli.exit_ok;
}

const Run = struct { code: u8, out: []const u8, err: []const u8 };

fn runReq(args: []const []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    const code = try run(std.testing.allocator, std.testing.io, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

test "a filter with no relay is printed rather than sent" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "-l", "5" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("[\"REQ\",\"deed\",{\"kinds\":[1],\"limit\":5}]\n", r.out);
    try std.testing.expectEqualStrings("", r.err);
}

test "--bare drops the envelope and keeps the filter" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "--bare" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("{\"kinds\":[1]}\n", r.out);
}

test "a repeated flag collects rather than replaces" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "-k", "6", "-k", "16", "--bare" }, &ob, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[1,6,16]}\n", r.out);
}

test "an author is taken as an npub or as hex, and means the same thing" {
    const hex_key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const npub = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d";

    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const from_hex = try runReq(&.{ "-a", hex_key, "--bare" }, &ob, &eb);

    var ob2: [4096]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const from_npub = try runReq(&.{ "-a", npub, "--bare" }, &ob2, &eb2);

    try std.testing.expectEqualStrings(from_hex.out, from_npub.out);
    // And what goes on the wire is hex, which is what a relay reads.
    try std.testing.expect(std.mem.indexOf(u8, from_hex.out, hex_key) != null);
}

test "tag filters land under their own letter" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-t", "zig", "-t", "nostr", "--bare" }, &ob, &eb);
    try std.testing.expectEqualStrings("{\"#t\":[\"zig\",\"nostr\"]}\n", r.out);
}

test "an empty filter is a legal subscription, not an error" {
    // `{}` asks a relay for everything. It is a thing somebody may genuinely
    // want to see the envelope for, so printing it beats refusing it.
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{"--bare"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("{}\n", r.out);
}

test "the exit codes say which kind of wrong it was" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    // A value that will not parse: the command ran and the value was bad.
    const bad_value = try runReq(&.{ "-k", "notanumber" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, bad_value.code);
    try std.testing.expectEqualStrings("", bad_value.out);

    // A flag nobody knows: the command was not understood.
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const unknown = try runReq(&.{"--nope"}, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_usage, unknown.code);

    // A flag with nothing after it.
    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const dangling = try runReq(&.{"-k"}, &ob3, &eb3);
    try std.testing.expectEqual(cli.exit_usage, dangling.code);

    // A key that is neither hex nor bech32.
    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const bad_key = try runReq(&.{ "-a", "alice" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_fail, bad_key.code);
}

test "help is printed on stdout and succeeds" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{"--help"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "deed req") != null);
}
