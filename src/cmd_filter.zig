//! `deed filter`: keep the events that match a filter.
//!
//! The local half of `deed req`: the same flags, but the events come from
//! stdin instead of a relay. Events are not verified here, because that is
//! `deed verify`'s job and the two compose.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const filterflags = @import("filterflags.zig");
const cmd_req = @import("cmd_req.zig");

const filter = nostr.filter;
const event = nostr.event;

/// Shown beside the name in `deed help`.
pub const summary = "keep the events on stdin that match a filter";

pub const ready = true;

/// An event that will not fit here is one no relay would carry either.
const max_record_bytes = 1 << 20;

pub const usage =
    \\deed filter: keep the events on stdin that match a filter
    \\
    \\Usage:
    \\  deed filter [options] [<filter-json>...] < events.jsonl
    \\
    \\Options:
    \\  -k, --kind <n>       event kind, repeatable
    \\  -a, --author <key>   author, as npub1... or 64 hex characters, repeatable
    \\  -i, --id <id>        event id, as note1... or 64 hex characters, repeatable
    \\  -e <id>              an `e` tag value, repeatable
    \\  -p <key>             a `p` tag value, repeatable
    \\  -t <topic>           a `t` tag value, repeatable
    \\  -d <name>            a `d` tag value, repeatable
    \\  -h <name>            an `h` tag value, repeatable
    \\  -T, --tag <x=value>  a tag value under any one-letter name, repeatable
    \\      --search <text>  keep events whose content contains this, ignoring case
    \\  -l, --limit <n>      stop after this many matches
    \\  -s, --since <time>   events at or after: unix seconds, 2h, 3d, 2026-10-01
    \\  -u, --until <time>   events at or before: the same forms as --since
    \\      --check          exit 1 when nothing matched
    \\
    \\Reads events as newline-delimited JSON on stdin and prints, unchanged, the
    \\ones that match. A filter given as JSON (an argument that starts with {)
    \\is read as `deed req` reads it, and flags are laid over it. An event
    \\matches when it satisfies any one filter. Nothing is checked about the
    \\signature: pipe through `deed verify` for that.
    \\
    \\A line that is not an event is named on stderr and skipped.
    \\
    \\  deed req -k 1 -l 100 wss://relay.example | deed filter -t nostr --check
    \\
    \\Exits: 0 when it ran (and, with --check, something matched); 1 if a value
    \\or a filter is bad, a line was not an event, or, with --check, nothing
    \\matched; 2 if the command line was not understood.
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    // Streaming for the reason `main` gives for the writers: a positional
    // read re-reads records an earlier reader on the same descriptor consumed.
    const buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(buf);
    var reader = std.Io.File.stdin().readerStreaming(io, buf);
    return runWith(gpa, args, &reader.interface, out, err);
}

/// `run`, with the reader the events come from given.
pub fn runWith(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    stdin: *std.Io.Reader,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var flags: filterflags.Flags = .{};
    var jsons: filterflags.Collected([]const u8) = .{};
    var check = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "--help" }) or (std.mem.eql(u8, a, "-h") and i + 1 >= args.len)) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--check")) {
            check = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "{")) {
            if (!jsons.push(a)) {
                try err.writeAll("deed filter: too many filters\n");
                return cli.exit_usage;
            }
            continue;
        }
        if (!filterflags.isFilterFlag(a)) {
            if (std.mem.startsWith(u8, a, "-")) {
                try err.print("deed filter: unknown option '{s}'\n", .{a});
            } else {
                try err.print("deed filter: '{s}' is not an option or a JSON filter; events are read from stdin\n", .{a});
            }
            return cli.exit_usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed filter: '{s}' needs a value\n", .{a});
            return cli.exit_usage;
        }
        flags.accept(gpa, "filter", a, args[i], err) catch |e| switch (e) {
            filterflags.ParseError.BadValue => return cli.exit_fail,
            else => return e,
        };
    }

    var filters: std.ArrayList(filter.Filter) = .empty;
    for (jsons.items[0..jsons.len]) |text| {
        cmd_req.parseJsonFilters(arena, "filter", text, &filters, err) catch |e| switch (e) {
            filterflags.ParseError.BadValue => return cli.exit_fail,
            else => return e,
        };
    }
    const from_flags = flags.finish();
    if (filters.items.len == 0) {
        try filters.append(arena, from_flags);
    } else if (flags.any()) {
        for (filters.items) |*f| f.* = try filterflags.overlay(arena, f.*, from_flags);
    }

    // Stop after this many matches, when every filter says how many it wants.
    var cap: ?u64 = 0;
    for (filters.items) |f| {
        if (f.limit) |l| {
            cap = @max(cap.?, l);
        } else {
            cap = null;
            break;
        }
    }

    var input = cli.Input.init(&.{}, stdin);
    var matched: u64 = 0;
    var bad: usize = 0;
    while (try input.next()) |record| {
        if (cap) |c| if (matched >= c) break;
        const line = switch (record) {
            .line => |l| std.mem.trim(u8, l, " \t"),
            .too_long => {
                try err.print("deed filter: skipped an event longer than {d} bytes\n", .{max_record_bytes});
                bad += 1;
                continue;
            },
        };
        var parsed = event.fromJson(gpa, line) catch |e| {
            try err.print("deed filter: not an event: {s}\n", .{@errorName(e)});
            bad += 1;
            continue;
        };
        defer parsed.deinit();
        if (!matchesAny(filters.items, parsed.value)) continue;
        try out.print("{s}\n", .{line});
        matched += 1;
    }

    if (bad > 0) return cli.exit_fail;
    if (check and matched == 0) return cli.exit_fail;
    return cli.exit_ok;
}

fn matchesAny(filters: []const filter.Filter, ev: event.Event) bool {
    for (filters) |f| {
        if (!f.matches(ev)) continue;
        if (f.search) |q| {
            if (std.ascii.indexOfIgnoreCase(ev.content, q) == null) continue;
        }
        return true;
    }
    return false;
}

const Run = struct { code: u8, out: []const u8, err: []const u8 };

fn runFilter(args: []const []const u8, stdin: []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    var reader: std.Io.Reader = .fixed(stdin);
    const code = try runWith(std.testing.allocator, args, &reader, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

/// Three events, one JSON line each, built by hand so the tests need no key.
const lines =
    "{\"id\":\"" ++ "01" ** 32 ++ "\",\"pubkey\":\"" ++ "aa" ** 32 ++ "\",\"created_at\":100,\"kind\":1,\"tags\":[[\"t\",\"nostr\"],[\"x\",\"one\"]],\"content\":\"Hello Zig\",\"sig\":\"" ++ "00" ** 64 ++ "\"}\n" ++
    "{\"id\":\"" ++ "02" ** 32 ++ "\",\"pubkey\":\"" ++ "bb" ** 32 ++ "\",\"created_at\":200,\"kind\":7,\"tags\":[[\"d\",\"slug\"]],\"content\":\"+\",\"sig\":\"" ++ "00" ** 64 ++ "\"}\n" ++
    "{\"id\":\"" ++ "03" ** 32 ++ "\",\"pubkey\":\"" ++ "aa" ** 32 ++ "\",\"created_at\":300,\"kind\":1,\"tags\":[[\"h\",\"group\"]],\"content\":\"second\",\"sig\":\"" ++ "00" ** 64 ++ "\"}\n";

fn expectIds(out: []const u8, ids: []const u8) !void {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, out, '\n');
    while (it.next()) |l| {
        if (l.len == 0) continue;
        try std.testing.expect(n < ids.len);
        const needle = [_]u8{ '0', ids[n], '0', ids[n] };
        try std.testing.expect(std.mem.indexOf(u8, l, &needle) != null);
        n += 1;
    }
    try std.testing.expectEqual(ids.len, n);
}

test "filter keeps the events a kind flag matches, unchanged" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runFilter(&.{ "-k", "1" }, lines, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("", r.err);
    // ids 01 and 03: the first and third lines, byte for byte.
    var it = std.mem.splitScalar(u8, lines, '\n');
    const first = it.next().?;
    _ = it.next();
    const third = it.next().?;
    var want: [2048]u8 = undefined;
    const w = try std.fmt.bufPrint(&want, "{s}\n{s}\n", .{ first, third });
    try std.testing.expectEqualStrings(w, r.out);
}

test "filter matches on tags, authors, times and search" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const by_tag = try runFilter(&.{ "-t", "nostr" }, lines, &ob, &eb);
    try expectIds(by_tag.out, "1");

    var ob2: [4096]u8 = undefined;
    const generic = try runFilter(&.{ "-T", "x=one" }, lines, &ob2, &eb);
    try expectIds(generic.out, "1");

    var ob3: [4096]u8 = undefined;
    const d_tag = try runFilter(&.{ "-d", "slug" }, lines, &ob3, &eb);
    try expectIds(d_tag.out, "2");

    var ob4: [4096]u8 = undefined;
    const h_tag = try runFilter(&.{ "-h", "group" }, lines, &ob4, &eb);
    try expectIds(h_tag.out, "3");

    var ob5: [4096]u8 = undefined;
    const author = try runFilter(&.{ "-a", "bb" ** 32 }, lines, &ob5, &eb);
    try expectIds(author.out, "2");

    var ob6: [4096]u8 = undefined;
    const window = try runFilter(&.{ "-s", "150", "-u", "250" }, lines, &ob6, &eb);
    try expectIds(window.out, "2");

    var ob7: [4096]u8 = undefined;
    const search = try runFilter(&.{ "--search", "hello" }, lines, &ob7, &eb);
    try expectIds(search.out, "1");
}

test "filter takes JSON filters, lays flags over them, and ORs several" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const two = try runFilter(&.{ "{\"kinds\":[7]}", "{\"#h\":[\"group\"]}" }, lines, &ob, &eb);
    try expectIds(two.out, "23");

    var ob2: [4096]u8 = undefined;
    const over = try runFilter(&.{ "{\"kinds\":[7]}", "-k", "1" }, lines, &ob2, &eb);
    try expectIds(over.out, "13");
}

test "filter -l stops after that many matches" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runFilter(&.{ "-k", "1", "-l", "1" }, lines, &ob, &eb);
    try expectIds(r.out, "1");
}

test "filter exits 0 on no match unless --check asks otherwise" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const quiet = try runFilter(&.{ "-k", "9" }, lines, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, quiet.code);
    try std.testing.expectEqualStrings("", quiet.out);

    var ob2: [4096]u8 = undefined;
    const checked = try runFilter(&.{ "-k", "9", "--check" }, lines, &ob2, &eb);
    try std.testing.expectEqual(cli.exit_fail, checked.code);

    var ob3: [4096]u8 = undefined;
    const hit = try runFilter(&.{ "-k", "7", "--check" }, lines, &ob3, &eb);
    try std.testing.expectEqual(cli.exit_ok, hit.code);
}

test "filter names a line that is not an event, skips it, and exits 1" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const input = "not json\n" ++ lines;
    const r = try runFilter(&.{ "-k", "7" }, input, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "deed filter: not an event:") != null);
    try expectIds(r.out, "2");
}

test "filter: bad values and bad options earn the usual exit codes" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    try std.testing.expectEqual(cli.exit_fail, (try runFilter(&.{ "-k", "x" }, "", &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_fail, (try runFilter(&.{"{\"kinds\":\"1\"}"}, "", &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_usage, (try runFilter(&.{"--nope"}, "", &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_usage, (try runFilter(&.{"-k"}, "", &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_usage, (try runFilter(&.{"wss://relay"}, "", &ob, &eb)).code);
    const help = try runFilter(&.{"--help"}, "", &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, help.code);
    try std.testing.expect(std.mem.indexOf(u8, help.out, "deed filter") != null);
}
