//! Asking a set of relays one question, and collecting what comes back.
//!
//! Shared by `req` and `fetch`, because they differ in how the question is
//! built and not at all in how it is asked.
//!
//! A command line is a SHORT-LIVED process, which changes the shape of this
//! from what a long-running client does. There is no reconnect, no backoff and
//! no liveness tracking: a relay that will not answer inside the deadline is a
//! relay this run does without, and the run says so on stderr rather than
//! waiting for it.

const std = @import("std");
const nostr = @import("nostr");
const dial = @import("dial.zig");

const filter = nostr.filter;
const message = nostr.message;
const relay = nostr.relay;

pub const Options = struct {
    /// Stop once every relay that answered has sent EOSE.
    ///
    /// A relay sends EOSE when it has finished replaying what it has stored,
    /// so this is the difference between "everything you have" and "everything
    /// you have, and then whatever arrives while I wait".
    until_eose: bool = true,
    /// The run gives up on relays still answering here, whatever they are
    /// doing. Reaching them has its own, shorter bound: see `dial`.
    ///
    /// A relay can stall at any point: while connecting, during TLS, at the
    /// websocket upgrade, or after accepting the subscription. Waiting on it
    /// is survivable at an interactive prompt and not in a script, which is
    /// where a command line spends most of its life.
    deadline_ms: i64,
    /// How long one read may block before the loop moves to the next relay.
    /// Short, because it is a round-robin across relays rather than a wait.
    poll_ms: i64,
    /// Every event that arrives is written here before it is printed.
    store: ?*nostr.store.Store = null,
};

pub const Outcome = struct {
    /// Relays that answered the dial.
    dialled: usize = 0,
    /// Relays that could not be reached at all.
    unreachable_count: usize = 0,
    /// Distinct events printed.
    events: usize = 0,
    /// Relays that reached EOSE before the deadline.
    complete: usize = 0,
};

const max_relays = dial.max_relays;

/// Events held for one store write. LMDB syncs to disk on every commit, so
/// writing each event as it arrives costs a sync apiece; a batch costs one.
const batch_max = 512;

/// Events that have passed every check and wait to be stored, then printed.
/// Each one's message is kept alive until then, because the event borrows it.
const Pending = struct {
    msgs: std.ArrayList(message.ParsedRelayMessage) = .empty,

    fn deinit(self: *Pending, gpa: std.mem.Allocator) void {
        for (self.msgs.items) |*m| m.deinit();
        self.msgs.deinit(gpa);
    }

    /// Stores what is held in one transaction, then prints it. Stored before
    /// printed, so a run interrupted partway through still kept what it had
    /// already shown.
    fn flush(self: *Pending, gpa: std.mem.Allocator, store: *nostr.store.Store, out: *std.Io.Writer, result: *Outcome) !void {
        if (self.msgs.items.len == 0) return;
        defer {
            for (self.msgs.items) |*m| m.deinit();
            self.msgs.clearRetainingCapacity();
        }
        var events: [batch_max]nostr.event.Event = undefined;
        var outcomes: [batch_max]nostr.store.IngestResult = undefined;
        for (self.msgs.items, 0..) |m, i| events[i] = m.value.event.event;
        const n = self.msgs.items.len;
        store.ingestBatch(gpa, events[0..n], .{}, outcomes[0..n]) catch {};
        for (events[0..n]) |ev| {
            const json = try nostr.event.toJson(gpa, ev);
            defer gpa.free(json);
            try out.print("{s}\n", .{json});
        }
        result.events += n;
    }
};

/// Whether an event answers any of the questions this run asked.
///
/// A relay is not obliged to be honest about what it sends, and a subscription
/// is not a promise. Without this a relay could answer `-k 1` with anything it
/// liked and the output would carry it.
fn matchesAny(filters: []const filter.Filter, ev: nostr.event.Event) bool {
    for (filters) |f| {
        if (f.matches(ev)) return true;
    }
    return false;
}

/// The subscription every run uses. One per process, closed by the process.
pub const subscription_id = "deed";

/// Dials `urls`, asks each the same question, and prints every distinct event
/// as one line of JSON.
///
/// Events are deduplicated across relays by id: the same note held by four
/// relays is one line, which is what makes piping this into `deed verify`
/// mean something.
pub fn query(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    filters: []const filter.Filter,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    opts: Options,
) !Outcome {
    var result = Outcome{};

    var relays: [max_relays]?*relay.Relay = @splat(null);
    var done: [max_relays]bool = @splat(false);
    const n = @min(urls.len, max_relays);
    if (urls.len > max_relays) {
        try err.print("deed: {d} relays were named, and only the first {d} are asked\n", .{ urls.len, max_relays });
    }

    defer for (relays[0..n]) |maybe| {
        if (maybe) |r| {
            r.shutdown(io);
            r.deinit();
        }
    };

    // All at once, so the slowest relay costs its own wait and not everybody
    // else's too, and never longer than the run itself may take.
    var dialled: [max_relays]dial.Outcome = undefined;
    const dial_ms = @min(dial.default_timeout_ms, opts.deadline_ms);
    dial.all(gpa, io, urls[0..n], dial_ms, &dialled);

    for (urls[0..n], 0..) |url, i| {
        // Named, not swallowed. A run that quietly asked three relays instead
        // of four looks like the fourth had nothing.
        const r = switch (dialled[i]) {
            .connected => |r| r,
            .failed => |e| {
                try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
                result.unreachable_count += 1;
                done[i] = true;
                continue;
            },
            .timed_out => {
                try err.print("deed: {s}: no answer within {d} ms\n", .{ url, dial_ms });
                result.unreachable_count += 1;
                done[i] = true;
                continue;
            },
        };
        r.subscribe(subscription_id, filters) catch |e| {
            try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
            r.shutdown(io);
            r.deinit();
            result.unreachable_count += 1;
            done[i] = true;
            continue;
        };
        relays[i] = r;
        result.dialled += 1;
    }
    if (result.dialled == 0) return result;

    var seen = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen.deinit();

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();

    var pending: Pending = .{};
    defer pending.deinit(gpa);

    // `.awake` is this standard library's monotonic clock: it cannot go
    // backwards when somebody adjusts the system time mid-run, which `.real`
    // can, and a deadline that can move backwards is not one.
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    while (true) {
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        if (started.durationTo(now).raw.toMilliseconds() >= opts.deadline_ms) {
            try err.writeAll("deed: gave up waiting for the relays still answering\n");
            break;
        }

        var any_live = false;
        // Set when a relay had nothing ready, so what is held gets written
        // and shown now rather than waiting for a batch that is not coming.
        var idle = false;
        for (relays[0..n], 0..) |maybe, i| {
            const r = maybe orelse continue;
            if (done[i]) continue;
            any_live = true;

            var msg = (r.receiveTimeout(std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(opts.poll_ms), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => {
                    idle = true;
                    continue;
                },
                else => {
                    // A relay that drops mid-answer is a relay this run does
                    // without. The events it already sent are still good.
                    try err.print("deed: a relay stopped answering: {s}\n", .{@errorName(e)});
                    done[i] = true;
                    continue;
                },
            }) orelse {
                done[i] = true;
                continue;
            };
            // Unless it is held for the store, in which case the batch owns it.
            var held = false;
            defer if (!held) msg.deinit();

            switch (msg.value) {
                .event => |e| {
                    if (seen.contains(e.event.id)) continue;
                    // Checked before it is trusted. A relay can send anything,
                    // including an event nobody signed or one that answers a
                    // question this run did not ask. nak verifies by default and
                    // drops both (go-nostr relay.go:399-410), and a tool whose
                    // output people pipe into other tools has to do the same:
                    // this is the last point where a forgery can be stopped.
                    if (!(nostr.event.verify(gpa, signer, e.event) catch false)) {
                        try err.print("deed: a relay sent an event that is not correctly signed\n", .{});
                        continue;
                    }
                    if (!matchesAny(filters, e.event)) {
                        try err.print("deed: a relay sent an event nobody asked for\n", .{});
                        continue;
                    }
                    try seen.put(e.event.id, {});
                    if (opts.store) |s| {
                        // Already checked above, so the store is not asked to
                        // check it again.
                        try pending.msgs.append(gpa, msg);
                        held = true;
                        if (pending.msgs.items.len == batch_max) try pending.flush(gpa, s, out, &result);
                    } else {
                        const json = try nostr.event.toJson(gpa, e.event);
                        defer gpa.free(json);
                        try out.print("{s}\n", .{json});
                        result.events += 1;
                    }
                },
                .eose => {
                    result.complete += 1;
                    if (opts.until_eose) done[i] = true;
                },
                .closed => |c| {
                    try err.print("deed: a relay closed the subscription: {s}\n", .{c.message});
                    done[i] = true;
                },
                .notice => |notice| try err.print("deed: notice: {s}\n", .{notice.message}),
                // A relay asking for NIP-42 is asking for a signature this verb
                // was not given a key for. Saying so beats looking like a relay
                // with nothing to say.
                .auth => try err.print("deed: a relay wants authentication, which this verb cannot give it\n", .{}),
                .ok => {},
            }
        }
        if (opts.store) |st| {
            if (idle) try pending.flush(gpa, st, out, &result);
        }
        if (!any_live) break;
    }

    if (opts.store) |st| try pending.flush(gpa, st, out, &result);
    return result;
}

test "a relay that never answers the dial costs the run its deadline, not forever" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();

    // Listed first, where a dial that waited on it one relay at a time would
    // never have reached the one behind it.
    var silent = try testrelay.listen(io);
    defer silent.deinit(io);
    var live: testrelay.Relay = undefined;
    try live.start(io, .accept);
    defer live.stop(io);

    var bufs: [2][40]u8 = undefined;
    const urls = [_][]const u8{
        try testrelay.url(&bufs[0], silent.socket.address.ip4.port),
        try testrelay.url(&bufs[1], live.port()),
    };
    const filters = [_]filter.Filter{.{ .kinds = &.{1}, .limit = 1 }};

    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);

    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try query(gpa, io, &urls, &filters, &out, &err, .{ .deadline_ms = 500, .poll_ms = 50 });
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 1), outcome.dialled);
    try std.testing.expectEqual(@as(usize, 1), outcome.unreachable_count);
    try std.testing.expectEqual(@as(usize, 1), outcome.complete);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "no answer within 500 ms") != null);
    try std.testing.expect(took < 3_000);
}

test "events kept in a store are written in batches, and every one is stored and printed" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Two full batches and part of a third.
    const n = batch_max * 2 + 176;
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    const serving = try arena.alloc([]const u8, n);
    for (serving, 0..) |*ev, i| {
        const e = try nostr.event.create(arena, signer, kp, 1_700_000_000 + @as(i64, @intCast(i)), 1, &.{}, try std.fmt.allocPrint(arena, "note {d}", .{i}), null);
        ev.* = try nostr.event.toJson(arena, e);
    }

    var relay_: testrelay.Relay = undefined;
    try relay_.start(io, .serve);
    relay_.serving = serving;
    defer relay_.stop(io);
    var buf: [40]u8 = undefined;
    const urls = [_][]const u8{try testrelay.url(&buf, relay_.port())};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/store.mdb", .{dir_buf[0..dir_len]});
    var st = try nostr.store.Store.open(path.ptr, .{});
    defer st.deinit();

    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    const outcome = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 10_000, .poll_ms = 50, .store = &st });

    try std.testing.expectEqual(@as(usize, n), outcome.events);
    try std.testing.expectEqual(@as(usize, n), std.mem.count(u8, out.written(), "\n"));
    try std.testing.expectEqual(@as(usize, n), try st.eventCount());
}

test "a relay that pings and never reads does not hold the run past its deadline" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();

    // Answering its pings fills a socket it never reads, so a pong written
    // without a bound would hold the read, and the run, forever.
    var pinger: testrelay.Relay = undefined;
    try pinger.start(io, .pings_deaf);
    defer pinger.stop(io);
    var live: testrelay.Relay = undefined;
    try live.start(io, .accept);
    defer live.stop(io);

    var bufs: [2][40]u8 = undefined;
    const urls = [_][]const u8{
        try testrelay.url(&bufs[0], pinger.port()),
        try testrelay.url(&bufs[1], live.port()),
    };
    const filters = [_]filter.Filter{.{ .kinds = &.{1}, .limit = 1 }};
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();

    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 1000, .poll_ms = 50, .until_eose = true });
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 1), outcome.complete);
    try std.testing.expect(took < 5_000);
}

test "relays past the most one run dials are named as left out, not dropped quietly" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();

    // Closed ports: each dial is refused at once.
    var closed = try testrelay.listen(io);
    const port = closed.socket.address.ip4.port;
    closed.deinit(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, port);
    var urls: [max_relays + 1][]const u8 = undefined;
    for (&urls) |*u| u.* = url;
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    _ = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 500, .poll_ms = 50 });
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "deed: 33 relays were named, and only the first 32 are asked\n") != null);
}

test {
    // Forces this file to be analysed. `_ = @import("relayset.zig")` alone
    // imports it without ever compiling a function body nobody references, so
    // the build would go green over code that does not compile.
    std.testing.refAllDecls(@This());
}
