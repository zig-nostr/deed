//! `deed count`: how many events match a filter (NIP-45).
//!
//! Every relay is asked at once. Each connected relay gets one reader task,
//! and a timer task runs beside them: whatever has not answered when it fires
//! is cancelled and reported as silent. No relay is polled in turn.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const filterflags = @import("filterflags.zig");
const jsonout = @import("jsonout.zig");
const cmd_req = @import("cmd_req.zig");
const storepath = @import("storepath.zig");

const Io = std.Io;
const filter = nostr.filter;
const message = nostr.message;
const relay = nostr.relay;

/// Shown beside the name in `deed help`.
pub const summary = "count the events that match a filter (NIP-45)";

pub const ready = true;

pub const usage =
    \\deed count: count the events that match a filter (NIP-45)
    \\
    \\Usage:
    \\  deed count [options] [<filter-json>...] [<relay-url>...]
    \\  deed count --local --store <path> [options]
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
    \\      --search <text>  a NIP-50 search, for relays that support it
    \\  -s, --since <time>   events at or after: unix seconds, 2h, 3d, 2026-10-01
    \\  -u, --until <time>   events at or before: the same forms as --since
    \\      --sum            print one number: the relays' counts added together
    \\      --json           print JSON instead of text
    \\      --store <path>   a local store to count from, with --local
    \\      --local          count from the store alone, dialling nothing
    \\      --timeout <ms>   give up on relays that have not answered (default 10000)
    \\
    \\Prints one line per relay that answered: its URL, a tab, and its count. A
    \\count a relay marks as approximate has "~" in front of the number. A
    \\filter can also be given as JSON, as an argument that starts with {; flags
    \\are laid over it.
    \\
    \\--sum adds the relays' counts. The same event is held by many relays and
    \\there is no way to tell, from a count, which ones overlap, so the sum is
    \\an upper bound on the number of distinct events, not that number.
    \\
    \\A relay that does not support COUNT (it answers CLOSED or NOTICE, or says
    \\nothing until --timeout) is named on stderr and left out. With --local the
    \\number comes from the store alone and there is no URL to print.
    \\
    \\Exits: 0 if at least one relay answered or --local succeeded; 1 if a value
    \\is bad, a store cannot be read, or no relay answered; 2 if the command
    \\line was not understood.
    \\
;

/// The subscription id every request uses.
const subscription_id = "deed";

pub const default_timeout_ms: i64 = 10_000;

const Request = struct {
    filter: filter.Filter,
    relays: []const []const u8,
    local: bool,
    store_path: ?[]const u8,
    sum: bool,
    json: bool,
    timeout_ms: i64,
};

const Collected = filterflags.Collected;
const ParseError = filterflags.ParseError;

fn parse(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    flags: *filterflags.Flags,
    relays: *Collected([]const u8),
    jsons: *Collected([]const u8),
    err: *Io.Writer,
) !?Request {
    var local_only = false;
    var sum = false;
    var json = false;
    var store_path: ?[]const u8 = null;
    var timeout_ms: i64 = default_timeout_ms;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "--help" })) return null;
        if (std.mem.eql(u8, a, "-h") and i + 1 >= args.len) return null;
        if (std.mem.eql(u8, a, "--local")) {
            local_only = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--sum")) {
            sum = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--json")) {
            json = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "{")) {
            if (!jsons.push(a)) {
                try err.writeAll("deed count: too many filters\n");
                return ParseError.Usage;
            }
            continue;
        }
        if (!std.mem.startsWith(u8, a, "-")) {
            if (!relays.push(a)) {
                try err.writeAll("deed count: too many relays\n");
                return ParseError.Usage;
            }
            continue;
        }

        const is_filter = filterflags.isFilterFlag(a) and !cli.isOneOf(a, &.{ "-l", "--limit" });
        if (!is_filter and !cli.isOneOf(a, &.{ "--store", "--timeout" })) {
            try err.print("deed count: unknown option '{s}'\n", .{a});
            return ParseError.Usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed count: '{s}' needs a value\n", .{a});
            return ParseError.Usage;
        }
        const v = args[i];
        if (is_filter) {
            try flags.accept(gpa, "count", a, v, err);
        } else if (std.mem.eql(u8, a, "--store")) {
            store_path = v;
        } else {
            timeout_ms = std.fmt.parseInt(i64, v, 10) catch -1;
            if (timeout_ms < 0) {
                try err.print("deed count: '{s}' is not a number of milliseconds\n", .{v});
                return ParseError.BadValue;
            }
        }
    }

    return .{
        .filter = flags.finish(),
        .relays = relays.slice() orelse &.{},
        .local = local_only,
        .store_path = store_path,
        .sum = sum,
        .json = json,
        .timeout_ms = timeout_ms,
    };
}

/// What one relay came to.
const Answer = struct {
    index: usize,
    kind: enum { counted, refused, failed } = .failed,
    count: u64 = 0,
    approximate: bool = false,
    /// Why a relay refused or failed, copied out of the message that said so.
    note: [160]u8 = undefined,
    note_len: usize = 0,

    fn setNote(self: *Answer, text: []const u8) void {
        const n = @min(text.len, self.note.len);
        for (text[0..n], self.note[0..n]) |c, *d| d.* = if (c < 0x20 or c == 0x7f) ' ' else c;
        self.note_len = n;
    }

    fn noteText(self: *const Answer) []const u8 {
        return self.note[0..self.note_len];
    }
};

const Arrival = union(enum) {
    answer: Answer,
    timer: Io.Cancelable!void,
};

/// Sends a text frame. The library sends REQ and EVENT through private
/// helpers and has no public COUNT, so the frame is built here and written
/// under the connection's own write lock.
fn sendText(gpa: std.mem.Allocator, io: Io, r: *relay.Relay, text: []const u8) !void {
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    var mask: [4]u8 = undefined;
    io.randomSecure(&mask) catch return error.RandomFailed;
    try nostr.websocket.appendClientFrame(&frame, gpa, .text, text, mask);
    r.conn.write_lock.lockUncancelable(io);
    defer r.conn.write_lock.unlock(io);
    try r.conn.stream.writeAll(frame.items);
}

/// The one reader for one relay: sends the COUNT, then reads until it is
/// answered, refused, or the connection ends.
fn countOne(gpa: std.mem.Allocator, io: Io, r: *relay.Relay, text: []const u8, index: usize) Answer {
    var ans: Answer = .{ .index = index };
    sendText(gpa, io, r, text) catch |e| {
        ans.setNote(@errorName(e));
        return ans;
    };
    while (true) {
        var msg = (r.receive() catch |e| {
            ans.setNote(@errorName(e));
            return ans;
        }) orelse {
            ans.kind = .refused;
            ans.setNote("the connection closed before it answered");
            return ans;
        };
        defer msg.deinit();
        switch (msg.value) {
            .count => |c| {
                if (!std.mem.eql(u8, c.subscription_id, subscription_id)) continue;
                ans.kind = .counted;
                ans.count = c.count;
                ans.approximate = c.approximate orelse false;
                return ans;
            },
            .closed => |c| {
                if (!std.mem.eql(u8, c.subscription_id, subscription_id)) continue;
                ans.kind = .refused;
                ans.setNote(c.message);
                return ans;
            },
            // A NOTICE is free text: a relay may greet, warn or complain about
            // something else before it answers. Only one that is about COUNT
            // is a refusal; the rest are waited past, up to the deadline.
            .notice => |n| {
                if (std.ascii.findIgnoreCase(n.message, "count") == null) continue;
                ans.kind = .refused;
                ans.setNote(n.message);
                return ans;
            },
            else => {},
        }
    }
}

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var flags: filterflags.Flags = .{};
    var relays: Collected([]const u8) = .{};
    var jsons: Collected([]const u8) = .{};

    const req = parse(gpa, args, &flags, &relays, &jsons, err) catch |e| {
        return switch (e) {
            ParseError.Usage => cli.exit_usage,
            ParseError.BadValue => cli.exit_fail,
            else => return e,
        };
    } orelse {
        try out.writeAll(usage);
        return cli.exit_ok;
    };

    var filters: std.ArrayList(filter.Filter) = .empty;
    for (jsons.items[0..jsons.len]) |text| {
        cmd_req.parseJsonFilters(arena, "count", text, &filters, err) catch |e| switch (e) {
            ParseError.BadValue => return cli.exit_fail,
            else => return e,
        };
    }
    if (filters.items.len == 0) {
        try filters.append(arena, req.filter);
    } else if (flags.any()) {
        for (filters.items) |*f| f.* = try filterflags.overlay(arena, f.*, req.filter);
    }

    if (req.local) return countLocal(gpa, io, req, filters.items, out, err);

    if (req.store_path != null) {
        try err.writeAll("deed count: --store is only for --local\n");
        return cli.exit_usage;
    }
    if (req.relays.len == 0) {
        try err.writeAll("deed count: name a relay to ask, or use --local with --store\n");
        return cli.exit_usage;
    }
    if (req.relays.len > dial.max_relays) {
        try err.print("deed count: at most {d} relays at once\n", .{dial.max_relays});
        return cli.exit_usage;
    }

    // A long list of ids or authors goes out as several filters, as in req.
    const pieces = filterflags.splitLarge(arena, filters.items) catch |e| switch (e) {
        error.TooManyFilters => {
            try err.print("deed count: too many ids and authors together: a filter naming more than {d} of both is not sent in more than {d} pieces\n", .{ filterflags.chunk_size, filterflags.max_pieces });
            return cli.exit_usage;
        },
        else => |other| return other,
    };
    const text = try message.encodeCount(gpa, subscription_id, pieces);
    defer gpa.free(text);

    const started = Io.Timestamp.now(io, .awake).toMilliseconds();
    const dial_ms = @min(dial.default_timeout_ms, req.timeout_ms);
    var outcomes: [dial.max_relays]dial.Outcome = undefined;
    dial.all(gpa, io, req.relays, dial_ms, outcomes[0..req.relays.len]);
    defer for (outcomes[0..req.relays.len]) |o| switch (o) {
        .connected => |r| r.deinit(),
        else => {},
    };

    var answers: [dial.max_relays]?Answer = @splat(null);

    var buf: [dial.max_relays + 1]Arrival = undefined;
    var sel = Io.Select(Arrival).init(io, &buf);
    var pending: usize = 0;
    for (outcomes[0..req.relays.len], 0..) |o, i| switch (o) {
        .connected => |r| {
            sel.concurrent(.answer, countOne, .{ gpa, io, r, text, i }) catch {
                var a: Answer = .{ .index = i };
                a.setNote("could not start a reader");
                answers[i] = a;
                continue;
            };
            pending += 1;
        },
        else => {},
    };

    if (pending > 0) {
        const elapsed = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
        const left = @max(req.timeout_ms - elapsed, 0);
        sel.concurrent(.timer, Io.sleep, .{ io, Io.Duration.fromMilliseconds(left), .awake }) catch |e| {
            // Without a timer the wait has no bound: stop the readers and say so.
            for (outcomes[0..req.relays.len], 0..) |o, i| switch (o) {
                .connected => |r| if (answers[i] == null) r.shutdown(io),
                else => {},
            };
            while (sel.cancel()) |_| {}
            return e;
        };
    }

    var timed_out = false;
    while (pending > 0) {
        const arrival = sel.await() catch break;
        switch (arrival) {
            .answer => |a| {
                answers[a.index] = a;
                pending -= 1;
            },
            .timer => {
                timed_out = true;
                break;
            },
        }
    }
    if (timed_out) {
        // A reader parked in receive cannot see the deadline, so the sockets
        // are shut first and the cancel after.
        for (outcomes[0..req.relays.len], 0..) |o, i| switch (o) {
            .connected => |r| if (answers[i] == null) r.shutdown(io),
            else => {},
        };
    }
    while (sel.cancel()) |late| switch (late) {
        // A reader cut off by the deadline ends in an error of our own
        // making, which is not worth reporting as the relay's failure.
        .answer => |a| if (answers[a.index] == null and !(timed_out and a.kind != .counted)) {
            answers[a.index] = a;
        },
        .timer => {},
    };

    // Reporting, in the order the relays were named.
    var answered: usize = 0;
    var total: u64 = 0;
    var any_approx = false;
    var lines: std.ArrayList(u8) = .empty;
    defer lines.deinit(gpa);
    for (req.relays, 0..) |url, i| {
        const ans = answers[i] orelse {
            switch (outcomes[i]) {
                .failed => |e| try err.print("deed count: {s}: could not connect: {s}\n", .{ url, dial.describe(e) }),
                else => try err.print("deed count: {s}: no answer within {d} ms\n", .{ url, req.timeout_ms }),
            }
            continue;
        };
        switch (ans.kind) {
            .counted => {
                answered += 1;
                total +|= ans.count;
                if (ans.approximate) any_approx = true;
                if (req.sum) continue;
                if (req.json) {
                    try lines.appendSlice(gpa, "{\"relay\":");
                    try jsonout.appendString(&lines, gpa, url);
                    try lines.print(gpa, ",\"count\":{d}", .{ans.count});
                    if (ans.approximate) try lines.appendSlice(gpa, ",\"approximate\":true");
                    try lines.appendSlice(gpa, "}\n");
                } else {
                    try lines.print(gpa, "{s}\t{s}{d}\n", .{ url, if (ans.approximate) "~" else "", ans.count });
                }
            },
            .refused => try err.print("deed count: {s}: does not support COUNT: {s}\n", .{ url, ans.noteText() }),
            .failed => try err.print("deed count: {s}: failed: {s}\n", .{ url, ans.noteText() }),
        }
    }

    if (answered == 0) {
        try err.writeAll("deed count: no relay answered\n");
        return cli.exit_fail;
    }
    if (req.sum) {
        try printTotal(out, total, req.json, any_approx);
    } else {
        try out.writeAll(lines.items);
    }
    return cli.exit_ok;
}

fn printTotal(out: *Io.Writer, total: u64, json: bool, approximate: bool) !void {
    if (json) {
        try out.print("{{\"count\":{d}{s}}}\n", .{ total, if (approximate) ",\"approximate\":true" else "" });
    } else {
        try out.print("{d}\n", .{total});
    }
}

/// Counts what the store holds. An event two filters both match is counted
/// once, and a `limit` is ignored: a count is of everything that matches.
fn countLocal(
    gpa: std.mem.Allocator,
    io: Io,
    req: Request,
    filters: []const filter.Filter,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    const path = req.store_path orelse {
        try err.writeAll("deed count: --local needs --store to read from\n");
        return cli.exit_usage;
    };
    var st = (try storepath.open(gpa, io, "count", path, .existing, err)) orelse return cli.exit_fail;
    defer st.deinit();

    var seen = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen.deinit();
    for (filters) |f| {
        var unlimited = f;
        unlimited.limit = null;
        var result = st.query(gpa, unlimited) catch |e| {
            try err.print("deed count: the store could not answer: {s}\n", .{@errorName(e)});
            return cli.exit_fail;
        };
        defer result.deinit();
        for (result.events) |ev| _ = try seen.fetchPut(ev.id, {});
    }
    try printTotal(out, seen.count(), req.json, false);
    return cli.exit_ok;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testrelay = @import("testrelay.zig");

const Ran = struct { code: u8, out: []const u8, err: []const u8 };

fn runCount(gpa: std.mem.Allocator, args: []const []const u8, out_buf: []u8, err_buf: []u8) !Ran {
    var out: Io.Writer = .fixed(out_buf);
    var err: Io.Writer = .fixed(err_buf);
    const code = try run(gpa, std.testing.io, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

/// A scripted relay that serves `n` connections, one after another.
fn startMany(rl: *testrelay.Relay, io: Io, handler: testrelay.CustomFn, n: usize) !void {
    try rl.startFor(io, .custom, n);
    rl.custom = handler;
    rl.custom_ctx = null;
}

const Script = struct {
    fn counts(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        _ = ctx;
        if (std.mem.indexOf(u8, frame, "\"COUNT\"") == null) return;
        const reply = try message.encodeCountReply(std.testing.allocator, "deed", 42, null);
        defer std.testing.allocator.free(reply);
        try testrelay.sendText(w, reply);
    }
    fn countsApprox(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        _ = ctx;
        if (std.mem.indexOf(u8, frame, "\"COUNT\"") == null) return;
        const reply = try message.encodeCountReply(std.testing.allocator, "deed", 8, true);
        defer std.testing.allocator.free(reply);
        try testrelay.sendText(w, reply);
    }
    fn closes(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        _ = ctx;
        if (std.mem.indexOf(u8, frame, "\"COUNT\"") == null) return;
        try testrelay.sendText(w, "[\"CLOSED\",\"deed\",\"unsupported: no COUNT here\"]");
    }
};

test "a relay that answers COUNT is printed as url, tab, number" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var rl: testrelay.Relay = undefined;
    try rl.startCustom(io, Script.counts, null);
    defer rl.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, rl.port());

    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    const r = try runCount(gpa, &.{ "-k", "1", url }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    var want: [64]u8 = undefined;
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{s}\t42\n", .{url}), r.out);
}

test "--sum adds, --json is JSON, and an approximate count is marked" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var a: testrelay.Relay = undefined;
    try startMany(&a, io, Script.counts, 3);
    defer a.stop(io);
    var b: testrelay.Relay = undefined;
    try startMany(&b, io, Script.countsApprox, 3);
    defer b.stop(io);
    var ua: [40]u8 = undefined;
    var ub: [40]u8 = undefined;
    const url_a = try testrelay.url(&ua, a.port());
    const url_b = try testrelay.url(&ub, b.port());

    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    var r = try runCount(gpa, &.{ "--sum", url_a, url_b }, &ob, &eb);
    try std.testing.expectEqualStrings("50\n", r.out);

    r = try runCount(gpa, &.{ url_a, url_b }, &ob, &eb);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\t~8\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\t42\n") != null);

    r = try runCount(gpa, &.{ "--json", url_b }, &ob, &eb);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\"count\":8,\"approximate\":true}") != null);
}

test "a relay that answers CLOSED is named on stderr and the others still count" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var good: testrelay.Relay = undefined;
    try startMany(&good, io, Script.counts, 2);
    defer good.stop(io);
    var bad: testrelay.Relay = undefined;
    try startMany(&bad, io, Script.closes, 2);
    defer bad.stop(io);
    var ug: [40]u8 = undefined;
    var ubad: [40]u8 = undefined;
    const url_good = try testrelay.url(&ug, good.port());
    const url_bad = try testrelay.url(&ubad, bad.port());

    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    var r = try runCount(gpa, &.{ url_good, url_bad }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "does not support COUNT: unsupported: no COUNT here") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\t42\n") != null);

    r = try runCount(gpa, &.{url_bad}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "no relay answered") != null);
}

const Greets = struct {
    fn noticeThenCounts(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        _ = ctx;
        if (std.mem.indexOf(u8, frame, "\"COUNT\"") == null) return;
        try testrelay.sendText(w, "[\"NOTICE\",\"welcome to the relay\"]");
        const reply = try message.encodeCountReply(std.testing.allocator, "deed", 42, null);
        defer std.testing.allocator.free(reply);
        try testrelay.sendText(w, reply);
    }
    fn noticeRefuses(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        _ = ctx;
        if (std.mem.indexOf(u8, frame, "\"COUNT\"") == null) return;
        try testrelay.sendText(w, "[\"NOTICE\",\"unknown command: COUNT\"]");
    }
    /// Answers with how many filters the COUNT carried.
    fn filterCount(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        _ = ctx;
        if (std.mem.indexOf(u8, frame, "\"COUNT\"") == null) return;
        const n = std.mem.count(u8, frame, "\"ids\":[");
        const reply = try message.encodeCountReply(std.testing.allocator, "deed", n, null);
        defer std.testing.allocator.free(reply);
        try testrelay.sendText(w, reply);
    }
};

test "a NOTICE that is not about COUNT does not make the relay unsupported" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var rl: testrelay.Relay = undefined;
    try rl.startCustom(io, Greets.noticeThenCounts, null);
    defer rl.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, rl.port());
    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    const r = try runCount(gpa, &.{ "-k", "1", url }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\t42\n") != null);
    try std.testing.expectEqualStrings("", r.err);
}

test "a NOTICE that refuses COUNT is still a refusal" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var rl: testrelay.Relay = undefined;
    try rl.startCustom(io, Greets.noticeRefuses, null);
    defer rl.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, rl.port());
    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    const r = try runCount(gpa, &.{ "-k", "1", url }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "does not support COUNT: unknown command") != null);
}

test "COUNT filters naming many ids go out split" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var rl: testrelay.Relay = undefined;
    try rl.startCustom(io, Greets.filterCount, null);
    defer rl.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, rl.port());

    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(gpa);
    try json.appendSlice(gpa, "{\"ids\":[");
    for (0..600) |i| {
        if (i > 0) try json.append(gpa, ',');
        try json.print(gpa, "\"{x:0>64}\"", .{i + 1});
    }
    try json.appendSlice(gpa, "]}");
    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    const r = try runCount(gpa, &.{ json.items, url }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\t2\n") != null);
}

test "a silent relay is bounded by the deadline" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var quiet: testrelay.Relay = undefined;
    try quiet.startFor(io, .silent, 2);
    defer quiet.stop(io);
    var good: testrelay.Relay = undefined;
    try startMany(&good, io, Script.counts, 2);
    defer good.stop(io);
    var uq: [40]u8 = undefined;
    var ug: [40]u8 = undefined;
    const url_quiet = try testrelay.url(&uq, quiet.port());
    const url_good = try testrelay.url(&ug, good.port());

    var ob: [512]u8 = undefined;
    var eb: [512]u8 = undefined;
    const started = Io.Timestamp.now(io, .awake).toMilliseconds();
    var r = try runCount(gpa, &.{ "--timeout", "400", url_quiet, url_good }, &ob, &eb);
    const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(took < 3_000);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "no answer within 400 ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "\t42\n") != null);

    r = try runCount(gpa, &.{ "--timeout", "300", url_quiet }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
}

test "--local counts a store, once per event, ignoring limit" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/store.mdb", .{root[0..root_len]});

    {
        var sink: [256]u8 = undefined;
        var sink_w: Io.Writer = .fixed(&sink);
        var st = (try storepath.open(gpa, io, "count", path, .create, &sink_w)) orelse return error.TestUnexpectedResult;
        defer st.deinit();
        var signer = try nostr.keys.Signer.initRandomized(io);
        defer signer.deinit();
        const kp = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        for (0..3) |n| {
            const ev = try nostr.event.create(arena, signer, kp, 1700000000 + @as(i64, @intCast(n)), 1, &.{}, "x", null);
            _ = try st.putEvent(gpa, ev);
        }
        const other = try nostr.event.create(arena, signer, kp, 1700000100, 7, &.{}, "+", null);
        _ = try st.putEvent(gpa, other);
    }

    var ob: [256]u8 = undefined;
    var eb: [256]u8 = undefined;
    var r = try runCount(gpa, &.{ "--local", "--store", path, "-k", "1" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("3\n", r.out);

    r = try runCount(gpa, &.{ "--local", "--store", path }, &ob, &eb);
    try std.testing.expectEqualStrings("4\n", r.out);

    r = try runCount(gpa, &.{ "--local", "--json", "--store", path, "{\"kinds\":[1],\"limit\":1}" }, &ob, &eb);
    try std.testing.expectEqualStrings("{\"count\":3}\n", r.out);

    r = try runCount(gpa, &.{ "--local", "--store", path, "-l", "1" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
}

test "usage errors and missing arguments" {
    const gpa = std.testing.allocator;
    var ob: [4096]u8 = undefined;
    var eb: [256]u8 = undefined;
    var r = try runCount(gpa, &.{"--local"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    r = try runCount(gpa, &.{"-k"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    r = try runCount(gpa, &.{ "-k", "1" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    r = try runCount(gpa, &.{"--help"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
}
