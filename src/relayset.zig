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
//!
//! Each relay that answered the dial gets a reader task of its own. It sends
//! the subscription, answers pings and NIP-42 challenges, parses what arrives
//! and hands it to the calling thread through one queue. The calling thread
//! does the rest: it drops duplicates, checks signatures, stores and prints,
//! tracks EOSE, and stops at the deadline, which a timer task puts into the
//! same queue. So an event is seen the moment it arrives whichever relay sends
//! it, and a relay that says nothing costs nothing until the deadline.

const std = @import("std");
const nostr = @import("nostr");
const dial = @import("dial.zig");
const auth = @import("auth.zig");

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
    /// Every event that arrives is written here before it is printed.
    store: ?*nostr.store.Store = null,
    /// Answer NIP-42 challenges with this key. Null answers none.
    auth: ?auth.Options = null,
    /// How long `auth.force_pre_auth` waits for a challenge before asking
    /// without one. Never longer than the deadline.
    challenge_wait_ms: i64 = 3_000,
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
    /// The store could not take a batch. Nothing from that batch or after it
    /// was printed, because printing comes after storing; the run has failed.
    store_failed: bool = false,
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
        // Once the store has failed, nothing more is printed: an event shown
        // but not kept is what storing first is there to prevent.
        if (result.store_failed) return;
        store.ingestBatch(gpa, events[0..n], .{}, outcomes[0..n]) catch {
            result.store_failed = true;
            return;
        };
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

/// What a reader hands the calling thread.
const Heard = struct {
    index: usize = 0,
    what: union(enum) {
        /// An event, EOSE, CLOSED, a notice, or a challenge this run has no
        /// key to answer. The calling thread owns it.
        msg: message.ParsedRelayMessage,
        /// The relay asked for authentication, and the reader is giving it.
        authenticating,
        /// The relay refused the authentication, with its reason. Owned.
        auth_refused: []u8,
        /// No challenge came in time under `force_pre_auth`.
        no_challenge,
        subscribe_failed: anyerror,
        /// The connection went away: null when the relay closed it.
        lost: ?anyerror,
        /// The run's time is up.
        deadline,
    },

    fn deinit(self: *Heard, gpa: std.mem.Allocator) void {
        switch (self.what) {
            .msg => |*m| m.deinit(),
            .auth_refused => |t| gpa.free(t),
            else => {},
        }
    }
};

/// What every reader shares with the calling thread.
const Shared = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    filters: []const filter.Filter,
    auth: ?auth.Options,
    challenge_wait_ms: i64,
    relays: [max_relays]?*relay.Relay = @splat(null),
    readers: [max_relays]?std.Io.Future(void) = @splat(null),
    /// Set before a reader is cancelled, so it hands nothing over on its way
    /// out. A put after the cancel could otherwise wait on a full queue that
    /// nobody is reading while this thread waits for the reader.
    quiet: [max_relays]std.atomic.Value(bool) = @splat(.init(false)),
    heard: std.Io.Queue(Heard) = undefined,
    heard_buf: [512]Heard = undefined,

    fn tell(self: *Shared, i: usize, what: @FieldType(Heard, "what")) bool {
        if (self.quiet[i].load(.acquire)) return false;
        self.heard.putOne(self.io, .{ .index = i, .what = what }) catch return false;
        return true;
    }

    /// Stops relay `i`'s reader and waits for it.
    fn stopReader(self: *Shared, i: usize) void {
        if (self.readers[i]) |*f| {
            self.quiet[i].store(true, .release);
            f.cancel(self.io);
            self.readers[i] = null;
        }
    }

    /// Stops every reader, closes every connection, and frees whatever was
    /// left in the queue.
    fn deinit(self: *Shared) void {
        for (0..self.urls.len) |i| {
            self.stopReader(i);
            if (self.relays[i]) |r| {
                r.shutdown(self.io);
                r.deinit();
                self.relays[i] = null;
            }
        }
        var buf: [32]Heard = undefined;
        while (true) {
            const n = self.heard.get(self.io, &buf, 0) catch break;
            if (n == 0) break;
            for (buf[0..n]) |*h| h.deinit(self.gpa);
        }
    }
};

/// Reads relay `i` until its connection goes away or the run lets it go.
///
/// It also does every write the relay gets: the subscription, the pongs, and
/// any NIP-42 answer. A write to a relay that has stopped reading waits, and
/// one waiting here is cut short when the reader is cancelled; one made from
/// the calling thread would hold it instead.
///
/// `receive` rather than `receiveTimeout`: with no deadline the read goes
/// straight to the socket, where a cancel reaches it, including in the middle
/// of a TLS record. A cancel is never swallowed here. Every error from a
/// blocking call ends the task, so nothing blocks again after a cancel.
fn readLoop(sh: *Shared, i: usize) void {
    const r = sh.relays[i].?;
    const url = sh.urls[i];

    var challenge: ?[]u8 = null;
    defer if (challenge) |c| sh.gpa.free(c);
    // The answer the relay has not yet said OK to.
    var auth_id: ?[32]u8 = null;
    // A refusal asked for authentication before any challenge arrived.
    var want_auth = false;
    // One authentication per refusal, and one retry per run: a relay that
    // refuses again after it is not asked a third time.
    var retried = false;
    var subscribed = false;

    var wait_until: ?std.Io.Clock.Timestamp = null;
    if (sh.auth) |a| {
        if (a.force_pre_auth) wait_until = .fromNow(sh.io, .{ .raw = .fromMilliseconds(sh.challenge_wait_ms), .clock = .awake });
    }
    if (wait_until == null) {
        r.subscribe(subscription_id, sh.filters) catch |e| {
            _ = sh.tell(i, .{ .subscribe_failed = e });
            return;
        };
        subscribed = true;
    }

    while (true) {
        const got = if (wait_until) |d| r.receiveTimeout(.{ .deadline = d }) else r.receive();
        var msg = (got catch |e| switch (e) {
            error.Timeout => {
                // Asked without one, and the relay can still refuse.
                wait_until = null;
                if (!sh.tell(i, .no_challenge)) return;
                r.subscribe(subscription_id, sh.filters) catch |se| {
                    _ = sh.tell(i, .{ .subscribe_failed = se });
                    return;
                };
                subscribed = true;
                continue;
            },
            else => {
                _ = sh.tell(i, .{ .lost = e });
                return;
            },
        }) orelse {
            _ = sh.tell(i, .{ .lost = null });
            return;
        };

        switch (msg.value) {
            .auth => |c| {
                const a = sh.auth orelse {
                    if (!sh.tell(i, .{ .msg = msg })) {
                        msg.deinit();
                        return;
                    }
                    continue;
                };
                defer msg.deinit();
                const copy = sh.gpa.dupe(u8, c.challenge) catch |e| {
                    _ = sh.tell(i, .{ .lost = e });
                    return;
                };
                if (challenge) |old| sh.gpa.free(old);
                challenge = copy;
                if (wait_until != null or want_auth) {
                    wait_until = null;
                    want_auth = false;
                    auth_id = sendAuth(sh, r, a, url, copy) catch |e| {
                        _ = sh.tell(i, .{ .lost = e });
                        return;
                    };
                }
            },
            .ok => |o| {
                defer msg.deinit();
                const id = auth_id orelse continue;
                if (!std.mem.eql(u8, &o.event_id, &id)) continue;
                auth_id = null;
                if (!o.accepted) {
                    const text = sh.gpa.dupe(u8, o.message) catch |e| {
                        _ = sh.tell(i, .{ .lost = e });
                        return;
                    };
                    if (!sh.tell(i, .{ .auth_refused = text })) sh.gpa.free(text);
                    return;
                }
                // Asked once more, now that the relay knows who is asking.
                r.subscribe(subscription_id, sh.filters) catch |e| {
                    _ = sh.tell(i, .{ .subscribe_failed = e });
                    return;
                };
                subscribed = true;
            },
            .closed => |c| {
                const a = sh.auth orelse {
                    if (!sh.tell(i, .{ .msg = msg })) {
                        msg.deinit();
                        return;
                    }
                    continue;
                };
                if (retried or !subscribed or !std.mem.eql(u8, c.subscription_id, subscription_id) or !auth.isAuthRequired(c.message)) {
                    if (!sh.tell(i, .{ .msg = msg })) {
                        msg.deinit();
                        return;
                    }
                    continue;
                }
                msg.deinit();
                retried = true;
                subscribed = false;
                if (!sh.tell(i, .authenticating)) return;
                if (challenge) |ch| {
                    auth_id = sendAuth(sh, r, a, url, ch) catch |e| {
                        _ = sh.tell(i, .{ .lost = e });
                        return;
                    };
                } else {
                    // The challenge may follow the refusal. Until it does
                    // there is nothing to sign.
                    want_auth = true;
                }
            },
            .event, .eose, .notice => if (!sh.tell(i, .{ .msg = msg })) {
                msg.deinit();
                return;
            },
            // A query never sends COUNT or NEG-OPEN, so these are noise.
            .count, .neg_msg, .neg_err => msg.deinit(),
        }
    }
}

/// Signs and sends the answer to `challenge`. Returns its id.
fn sendAuth(sh: *Shared, r: *relay.Relay, a: auth.Options, url: []const u8, challenge: []const u8) ![32]u8 {
    var ans = try auth.answer(sh.gpa, sh.io, a, url, challenge);
    defer ans.deinit();
    try r.authenticate(ans.event);
    return ans.id;
}

fn deadlineAfter(q: *std.Io.Queue(Heard), io: std.Io, ms: i64) void {
    io.sleep(.fromMilliseconds(ms), .awake) catch return;
    q.putOne(io, .{ .what = .deadline }) catch return;
}

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

    const n = @min(urls.len, max_relays);
    if (urls.len > max_relays) {
        try err.print("deed: {d} relays were named, and only the first {d} are asked\n", .{ urls.len, max_relays });
    }

    var sh: Shared = .{
        .gpa = gpa,
        .io = io,
        .urls = urls[0..n],
        .filters = filters,
        .auth = opts.auth,
        .challenge_wait_ms = @min(opts.challenge_wait_ms, opts.deadline_ms),
    };
    sh.heard = .init(&sh.heard_buf);
    defer sh.deinit();

    // Whether relay `i` still counts: answered the dial, and has not finished,
    // closed, or gone away.
    var live: [max_relays]bool = @splat(false);
    var live_count: usize = 0;

    // All at once, so the slowest relay costs its own wait and not everybody
    // else's too, and never longer than the run itself may take.
    var dialled: [max_relays]dial.Outcome = undefined;
    const dial_ms = @min(dial.default_timeout_ms, opts.deadline_ms);
    dial.all(gpa, io, urls[0..n], dial_ms, &dialled);

    // Every connection is kept before anything is written, so a failed write
    // cannot strand one that `deinit` would never see.
    for (dialled[0..n], 0..) |d, i| switch (d) {
        .connected => |r| sh.relays[i] = r,
        else => {},
    };
    for (urls[0..n], 0..) |url, i| {
        // Named, not swallowed. A run that quietly asked three relays instead
        // of four looks like the fourth had nothing.
        switch (dialled[i]) {
            .connected => {},
            .failed => |e| {
                try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
                result.unreachable_count += 1;
                continue;
            },
            .timed_out => {
                try err.print("deed: {s}: no answer within {d} ms\n", .{ url, dial_ms });
                result.unreachable_count += 1;
                continue;
            },
        }
        // `concurrent`, never `async`: past its limit `async` runs the task
        // inline, and an inline reader would be this thread waiting on one
        // relay while the others go unread.
        sh.readers[i] = io.concurrent(readLoop, .{ &sh, i }) catch |e| {
            try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
            result.unreachable_count += 1;
            continue;
        };
        live[i] = true;
        live_count += 1;
        result.dialled += 1;
    }
    if (result.dialled == 0) return result;

    // The deadline counts from here, once the relays are reached. The timer
    // sleeps on `.awake`, this standard library's monotonic clock: it cannot
    // go backwards when somebody adjusts the system time mid-run, which
    // `.real` can, and a deadline that can move backwards is not one.
    var timer = try io.concurrent(deadlineAfter, .{ &sh.heard, io, opts.deadline_ms });
    defer timer.cancel(io);

    var seen = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen.deinit();

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();

    var pending: Pending = .{};
    defer pending.deinit(gpa);

    while (live_count > 0) {
        // What is ready is taken without waiting. When nothing is, what is
        // held gets written and shown now rather than waiting for a batch
        // that is not coming.
        var one: [1]Heard = undefined;
        const ready = sh.heard.get(io, &one, 0) catch break;
        if (ready == 0) {
            if (opts.store) |st| try pending.flush(gpa, st, out, &result);
            one[0] = sh.heard.getOne(io) catch break;
        }
        var h = one[0];
        // Unless it is held for the store, in which case the batch owns it.
        var held = false;
        defer if (!held) h.deinit(gpa);

        if (h.what == .deadline) {
            try err.writeAll("deed: gave up waiting for the relays still answering\n");
            break;
        }
        const i = h.index;
        if (!live[i]) continue;
        const url = urls[i];

        switch (h.what) {
            .msg => |m| switch (m.value) {
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
                        try pending.msgs.append(gpa, m);
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
                    if (opts.until_eose) finish(&sh, &live, &live_count, i);
                },
                .closed => |c| {
                    try err.print("deed: a relay closed the subscription: {s}\n", .{c.message});
                    finish(&sh, &live, &live_count, i);
                },
                .notice => |notice| try err.print("deed: notice: {s}\n", .{notice.message}),
                // A relay asking for NIP-42 when this run has no key to answer
                // with. Saying so beats looking like a relay with nothing to say.
                .auth => try err.print("deed: a relay wants authentication, which needs --auth\n", .{}),
                .ok => {},
                .count, .neg_msg, .neg_err => {},
            },
            .authenticating => try err.print("deed: {s}: authenticating\n", .{url}),
            .auth_refused => |t| {
                try err.print("deed: {s}: authentication refused: {s}\n", .{ url, t });
                finish(&sh, &live, &live_count, i);
            },
            .no_challenge => try err.print("deed: {s}: no authentication challenge within {d} ms, asking without one\n", .{ url, sh.challenge_wait_ms }),
            .subscribe_failed => |e| {
                try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
                result.dialled -= 1;
                result.unreachable_count += 1;
                finish(&sh, &live, &live_count, i);
            },
            .lost => |why| {
                // A relay that drops mid-answer is a relay this run does
                // without. The events it already sent are still good.
                if (why) |e| try err.print("deed: a relay stopped answering: {s}\n", .{@errorName(e)});
                finish(&sh, &live, &live_count, i);
            },
            .deadline => unreachable,
        }
    }

    if (opts.store) |st| try pending.flush(gpa, st, out, &result);
    if (result.store_failed) try err.writeAll("deed: the store could not be written, so events from that point were not printed\n");
    return result;
}

/// Relay `i` is done: its reader is stopped, and what it already handed over
/// is ignored.
fn finish(sh: *Shared, live: *[max_relays]bool, live_count: *usize, i: usize) void {
    if (!live[i]) return;
    live[i] = false;
    live_count.* -= 1;
    sh.stopReader(i);
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
    const outcome = try query(gpa, io, &urls, &filters, &out, &err, .{ .deadline_ms = 500 });
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
    const outcome = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 10_000, .store = &st });

    try std.testing.expectEqual(@as(usize, n), outcome.events);
    try std.testing.expectEqual(@as(usize, n), std.mem.count(u8, out.written(), "\n"));
    try std.testing.expectEqual(@as(usize, n), try st.eventCount());
}

test "a store that cannot take a batch prints nothing for it and says so" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    // Together far more than the map below can hold.
    const serving = try arena.alloc([]const u8, 60);
    for (serving, 0..) |*ev, i| {
        const body = try arena.alloc(u8, 8_000);
        @memset(body, 'x');
        _ = try std.fmt.bufPrint(body, "{d}", .{i});
        const e = try nostr.event.create(arena, signer, kp, 1_700_000_000 + @as(i64, @intCast(i)), 1, &.{}, body, null);
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
    var st = try nostr.store.Store.open(path.ptr, .{ .map_size = 1 << 17 });
    defer st.deinit();

    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    const outcome = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 5_000, .store = &st });
    try std.testing.expect(outcome.store_failed);
    try std.testing.expectEqual(@as(usize, 0), out.written().len);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "the store could not be written") != null);
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
    const outcome = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 1000, .until_eose = true });
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
    _ = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 500 });
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "deed: 33 relays were named, and only the first 32 are asked\n") != null);
}

/// A writer that notes when the first byte reached it, and keeps nothing.
const FirstWrite = struct {
    io: std.Io,
    at: ?i64 = null,
    w: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *FirstWrite = @alignCast(@fieldParentPtr("w", w));
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| n += d.len;
        n += data[data.len - 1].len * splat;
        if (n > 0 and self.at == null) self.at = std.Io.Timestamp.now(self.io, .awake).toMilliseconds();
        return n;
    }
};

/// One signed kind 1 event as JSON, from a fixed key.
pub fn testEvent(arena: std.mem.Allocator, io: std.Io, content: []const u8) ![]const u8 {
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    const ev = try nostr.event.create(arena, signer, kp, 1_700_000_000, 1, &.{}, content, null);
    return nostr.event.toJson(arena, ev);
}

test "an event from the last of five relays is printed at once, although four never answer" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Answer the upgrade and then nothing, ahead of the one that answers. Read
    // in turn, each would cost the run a wait before the next one was asked.
    var silent: [4]testrelay.Relay = undefined;
    for (&silent) |*r| try r.start(io, .silent);
    defer for (&silent) |*r| r.stop(io);
    var live: testrelay.Relay = undefined;
    try live.start(io, .serve);
    live.serving = &.{try testEvent(arena, io, "first")};
    defer live.stop(io);

    var bufs: [5][40]u8 = undefined;
    var urls: [5][]const u8 = undefined;
    for (&silent, 0..) |*r, i| urls[i] = try testrelay.url(&bufs[i], r.port());
    urls[4] = try testrelay.url(&bufs[4], live.port());
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};

    var out: FirstWrite = .{ .io = io };
    var err: std.Io.Writer.Allocating = .init(arena);
    const deadline_ms = 600;
    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try query(gpa, io, &urls, &filters, &out.w, &err.writer, .{ .deadline_ms = deadline_ms });
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 5), outcome.dialled);
    try std.testing.expectEqual(@as(usize, 1), outcome.events);
    try std.testing.expectEqual(@as(usize, 1), outcome.complete);
    try std.testing.expect(out.at.? - started < 20);
    // The silent ones hold the run to its deadline and not past it.
    try std.testing.expect(took >= deadline_ms);
    try std.testing.expect(took < deadline_ms + 1_000);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "gave up waiting") != null);
}

/// A relay that keeps its events behind NIP-42. It refuses a REQ with
/// `auth-required:` until it gets an AUTH whose `relay` tag is `want_url` and
/// whose challenge is its own, and serves `event` after that.
pub const AuthRelay = struct {
    want_url: []const u8,
    event: []const u8,
    /// Send the challenge after the refusal rather than before it.
    challenge_last: bool = false,
    authed: bool = false,
    reqs: usize = 0,
    auths: usize = 0,

    pub const challenge = "chal-7f3a";

    pub fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const testrelay = @import("testrelay.zig");
        const self: *AuthRelay = @ptrCast(@alignCast(ctx.?));
        const a = std.heap.page_allocator;
        var parsed = try std.json.parseFromSlice(std.json.Value, a, frame, .{});
        defer parsed.deinit();
        const items = parsed.value.array.items;
        const kind = items[0].string;
        if (std.mem.eql(u8, kind, "REQ")) {
            self.reqs += 1;
            const sub = items[1].string;
            if (!self.authed) {
                if (!self.challenge_last) try testrelay.sendText(w, "[\"AUTH\",\"" ++ challenge ++ "\"]");
                const closed = try std.fmt.allocPrint(a, "[\"CLOSED\",\"{s}\",\"auth-required: who are you\"]", .{sub});
                defer a.free(closed);
                try testrelay.sendText(w, closed);
                if (self.challenge_last) try testrelay.sendText(w, "[\"AUTH\",\"" ++ challenge ++ "\"]");
                return;
            }
            const ev = try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ sub, self.event });
            defer a.free(ev);
            try testrelay.sendText(w, ev);
            const eose = try std.fmt.allocPrint(a, "[\"EOSE\",\"{s}\"]", .{sub});
            defer a.free(eose);
            try testrelay.sendText(w, eose);
        } else if (std.mem.eql(u8, kind, "AUTH")) {
            self.auths += 1;
            const ev = items[1].object;
            const id = ev.get("id").?.string;
            const tags = ev.get("tags").?.array.items;
            var relay_ok = false;
            var challenge_ok = false;
            for (tags) |t| {
                const pair = t.array.items;
                if (std.mem.eql(u8, pair[0].string, "relay")) relay_ok = std.mem.eql(u8, pair[1].string, self.want_url);
                if (std.mem.eql(u8, pair[0].string, "challenge")) challenge_ok = std.mem.eql(u8, pair[1].string, challenge);
            }
            const good = relay_ok and challenge_ok and ev.get("kind").?.integer == 22242;
            if (good) self.authed = true;
            const ok = try std.fmt.allocPrint(a, "[\"OK\",\"{s}\",{s},\"{s}\"]", .{ id, if (good) "true" else "false", if (good) "" else "auth-required: wrong relay" });
            defer a.free(ok);
            try testrelay.sendText(w, ok);
        }
    }
};

pub fn authOptions() !auth.Options {
    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    return .{ .keypair = try signer.keyPairFromSecretKey([_]u8{0x44} ** 32) };
}

test "with --auth a relay that refuses until it is told who is asking is answered, and asked again" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for ([_]bool{ false, true }) |challenge_last| {
        var script: AuthRelay = .{ .want_url = undefined, .event = try testEvent(arena, io, "members only"), .challenge_last = challenge_last };
        var r: testrelay.Relay = undefined;
        try r.startCustom(io, AuthRelay.handle, &script);
        defer r.stop(io);
        var buf: [40]u8 = undefined;
        const url = try testrelay.url(&buf, r.port());
        script.want_url = url;

        const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
        var out: std.Io.Writer.Allocating = .init(arena);
        var err: std.Io.Writer.Allocating = .init(arena);
        const outcome = try query(gpa, io, &.{url}, &filters, &out.writer, &err.writer, .{ .deadline_ms = 3_000, .auth = try authOptions() });

        try std.testing.expectEqual(@as(usize, 1), outcome.events);
        try std.testing.expectEqual(@as(usize, 1), outcome.complete);
        try std.testing.expectEqual(@as(usize, 1), script.auths);
        try std.testing.expectEqual(@as(usize, 2), script.reqs);
        try std.testing.expect(std.mem.indexOf(u8, err.written(), try std.fmt.allocPrint(arena, "deed: {s}: authenticating\n", .{url})) != null);
        try std.testing.expect(std.mem.indexOf(u8, err.written(), "closed the subscription") == null);
    }
}

test "without --auth the refusal is reported, and nothing is signed" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var script: AuthRelay = .{ .want_url = undefined, .event = try testEvent(arena, io, "members only") };
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, AuthRelay.handle, &script);
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, r.port());
    script.want_url = url;

    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const outcome = try query(gpa, io, &.{url}, &filters, &out.writer, &err.writer, .{ .deadline_ms = 3_000 });

    try std.testing.expectEqual(@as(usize, 0), outcome.events);
    try std.testing.expectEqual(@as(usize, 0), script.auths);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "deed: a relay wants authentication, which needs --auth\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "deed: a relay closed the subscription: auth-required: who are you\n") != null);
}

test "an answer naming some other relay is refused, reported, and not tried again" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The relay knows itself by a name other than the one dialled, so the
    // answer's `relay` tag, which is the dialled URL, does not match it.
    var script: AuthRelay = .{ .want_url = "wss://relay.example", .event = try testEvent(arena, io, "members only") };
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, AuthRelay.handle, &script);
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, r.port());

    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try query(gpa, io, &.{url}, &filters, &out.writer, &err.writer, .{ .deadline_ms = 3_000, .auth = try authOptions() });
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 0), outcome.events);
    try std.testing.expectEqual(@as(usize, 1), script.auths);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), try std.fmt.allocPrint(arena, "deed: {s}: authentication refused: auth-required: wrong relay\n", .{url})) != null);
    // Ends on the refusal, not at the deadline.
    try std.testing.expect(took < 2_000);
}

test "--force-pre-auth against a relay that sends no challenge asks without one, in bounded time" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var r: testrelay.Relay = undefined;
    try r.start(io, .serve);
    r.serving = &.{try testEvent(arena, io, "open")};
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, r.port());

    var opts = try authOptions();
    opts.force_pre_auth = true;
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try query(gpa, io, &.{url}, &filters, &out.writer, &err.writer, .{ .deadline_ms = 3_000, .auth = opts, .challenge_wait_ms = 150 });
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 1), outcome.events);
    try std.testing.expectEqual(@as(usize, 1), outcome.complete);
    try std.testing.expect(took >= 150);
    try std.testing.expect(took < 2_000);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "no authentication challenge within 150 ms, asking without one\n") != null);
}

test "--force-pre-auth against a relay that sends its challenge first authenticates before asking" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var script: AuthRelay = .{ .want_url = undefined, .event = try testEvent(arena, io, "members only") };
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, AuthRelay.handle, &script);
    r.greeting = "[\"AUTH\",\"" ++ AuthRelay.challenge ++ "\"]";
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, r.port());
    script.want_url = url;

    var opts = try authOptions();
    opts.force_pre_auth = true;
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const outcome = try query(gpa, io, &.{url}, &filters, &out.writer, &err.writer, .{ .deadline_ms = 3_000, .auth = opts });

    try std.testing.expectEqual(@as(usize, 1), outcome.events);
    try std.testing.expectEqual(@as(usize, 1), script.auths);
    // Asked once, after the answer, not refused first and asked again.
    try std.testing.expectEqual(@as(usize, 1), script.reqs);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "no authentication challenge") == null);
}

test "a relay still answering at the deadline is let go, whatever its reader is doing" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the query leaked");
    const gpa = da.allocator();

    // One reader stuck writing a pong, one waiting on a read that never ends,
    // one reading notices as fast as they come, one cut short mid-subscription.
    var pinger: testrelay.Relay = undefined;
    try pinger.start(io, .pings_deaf);
    defer pinger.stop(io);
    var silent: testrelay.Relay = undefined;
    try silent.start(io, .silent);
    defer silent.stop(io);
    var chatty: testrelay.Relay = undefined;
    try chatty.start(io, .chatty);
    defer chatty.stop(io);
    var pongs: testrelay.Relay = undefined;
    try pongs.start(io, .pongs);
    defer pongs.stop(io);

    var bufs: [4][40]u8 = undefined;
    const urls = [_][]const u8{
        try testrelay.url(&bufs[0], pinger.port()),
        try testrelay.url(&bufs[1], silent.port()),
        try testrelay.url(&bufs[2], chatty.port()),
        try testrelay.url(&bufs[3], pongs.port()),
    };
    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();

    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try query(gpa, io, &urls, &filters, &out.writer, &err.writer, .{ .deadline_ms = 400, .auth = try authOptions() });
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;

    try std.testing.expectEqual(@as(usize, 4), outcome.dialled);
    try std.testing.expectEqual(@as(usize, 0), outcome.complete);
    try std.testing.expect(took < 3_000);
}

test {
    // Forces this file to be analysed. `_ = @import("relayset.zig")` alone
    // imports it without ever compiling a function body nobody references, so
    // the build would go green over code that does not compile.
    std.testing.refAllDecls(@This());
    _ = @import("auth.zig");
}
