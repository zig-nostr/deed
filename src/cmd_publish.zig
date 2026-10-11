//! `deed publish`: offer signed events to relays, and say which were published.
//!
//! Reads events the way every other verb reads its records, so the thing that
//! made them is somebody else's business: `deed event -c "hi" | deed publish
//! wss://...` is the ordinary path, and a file of events works the same way.
//!
//! What comes out on stdout is what was published: each event that at least one
//! relay accepted, once the relays have answered or its deadline has passed.
//! Every answer goes to stderr with the event's id on it, and a notice with the
//! relay's URL.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const auth = @import("auth.zig");
const signing = @import("signing.zig");
const relayset = @import("relayset.zig");

const hex = nostr.hex;
const relay = nostr.relay;

/// An event too big for this is one no relay would take either.
const max_record_bytes = 1 << 20;

/// How long the relays get to take one event and answer it, all of them
/// together.
///
/// An absolute deadline, not a wait that starts again with every message: a
/// relay that keeps sending notices and never answers would otherwise hold the
/// run for as long as it liked.
pub const default_timeout_ms: i64 = 10_000;

pub const usage =
    \\deed publish: offer signed events to relays
    \\
    \\Usage:
    \\  deed publish [--timeout <ms>] [--auth] <relay-url>... [<event-json>...]
    \\
    \\Relays are positional: name each as a ws:// or wss:// argument. Reads events
    \\as newline-delimited JSON on stdin when given no event arguments, checks
    \\each one, and offers it to every relay named.
    \\
    \\  deed event -c "hello" | deed publish wss://relay.example
    \\
    \\Prints each event that at least one relay accepted, once the relays have
    \\answered or the deadline has passed, so what comes out is what was
    \\published:
    \\
    \\  deed event - < drafts.jsonl | deed publish wss://a wss://b > sent.jsonl
    \\
    \\Every relay's answer is reported on stderr with the event's id. An event
    \\no relay accepted, or whose signature does not check out, is reported
    \\there and not printed.
    \\
    \\Options:
    \\      --timeout <ms>   how long the relays get to take each event and
    \\                       answer it (default 10000)
++ auth.usage_lines ++
    \\
    \\A relay that has not accepted the connection within five seconds, or
    \\within --timeout if that is shorter, is named on stderr and left out.
    \\Looking up a relay's name is the one step that cannot be cut short.
    \\
    \\Exits: 0 when every event was accepted by at least one relay, 1 when any
    \\was not or there was nothing to publish, and 2 when the command made no
    \\sense.
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);
    var timeout_ms: i64 = default_timeout_ms;
    var auth_flags: auth.Flags = .{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--timeout")) {
            i += 1;
            if (i == args.len) {
                try err.writeAll("deed publish: --timeout needs a number of milliseconds\n");
                return cli.exit_usage;
            }
            timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch {
                try err.print("deed publish: --timeout needs a number of milliseconds, not '{s}'\n", .{args[i]});
                return cli.exit_usage;
            };
            if (timeout_ms <= 0) {
                try err.writeAll("deed publish: --timeout must be more than zero\n");
                return cli.exit_usage;
            }
            continue;
        }
        switch (auth_flags.take(args, &i)) {
            .taken => continue,
            .missing_value => {
                try err.print("deed publish: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            },
            .not_mine => {},
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed publish: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        // A relay URL is a relay URL; anything else is an event.
        if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try urls.append(gpa, a);
        } else {
            try positionals.append(gpa, a);
        }
    }

    if (urls.items.len == 0) {
        try err.writeAll("deed publish: name at least one relay to publish to\n");
        return cli.exit_usage;
    }
    if (urls.items.len > dial.max_relays) {
        try err.print("deed publish: name at most {d} relays\n", .{dial.max_relays});
        return cli.exit_usage;
    }
    const auth_opts = auth.resolve(gpa, io, auth_flags, "publish", err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };
    defer if (auth_opts) |o| o.deinit(gpa);

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
    var input = cli.Input.initJson(positionals.items, &stdin_reader.interface);

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();

    // Dialled when the first event that checks out arrives, not before. Empty
    // or unreadable input has nothing to publish, and opens no connection.
    var set: Set = undefined;
    set.init(gpa, io, "publish", urls.items, auth_opts);
    defer set.deinit();

    // Every record is something the caller asked to have published, whether
    // or not it turned out to be an event.
    var records: usize = 0;
    var published: usize = 0;

    while (try input.next()) |record| {
        records += 1;
        const json = switch (record) {
            .line => |l| std.mem.trim(u8, l, " \t"),
            .too_long => {
                try err.print("deed publish: skipped an event longer than {d} bytes\n", .{max_record_bytes});
                try err.flush();
                continue;
            },
        };

        var parsed = nostr.event.fromJson(gpa, json) catch |e| {
            try err.print("deed publish: not an event: {s}\n", .{@errorName(e)});
            try err.flush();
            continue;
        };
        defer parsed.deinit();
        const ev = parsed.value;

        const id = try hex.encode(gpa, &ev.id);
        defer gpa.free(id);

        // Checked before anything is sent. A relay would refuse it, but the
        // refusal would read as the relay's problem rather than the event's.
        if (!(nostr.event.verify(gpa, signer, ev) catch false)) {
            try err.print("deed publish: {s}: not sent, bad signature\n", .{id});
            try err.flush();
            continue;
        }

        try set.refresh(err);
        try set.ready(@min(dial.default_timeout_ms, timeout_ms), err);
        try set.preAuth(@min(challenge_wait_ms, timeout_ms), err);
        if (set.live() == 0) {
            try err.print("deed publish: {s}: not published, no relay could be reached\n", .{id});
            try err.flush();
            continue;
        }

        if (try set.offer(ev, id, timeout_ms, err)) {
            const wire = try nostr.event.toJson(gpa, ev);
            defer gpa.free(wire);
            try out.print("{s}\n", .{wire});
            try out.flush();
            published += 1;
        } else {
            try err.print("deed publish: {s}: not published, no relay accepted it in time\n", .{id});
        }
        try err.flush();
    }

    try set.reportAll(err);

    if (records == 0) {
        try err.writeAll("deed publish: nothing to publish\n");
        return cli.exit_fail;
    }
    if (published < records) {
        try err.print("deed publish: {d} of {d} published\n", .{ published, records });
        return cli.exit_fail;
    }
    return cli.exit_ok;
}

/// Offers one signed event to `urls` and says whether any relay accepted it.
/// The shared publisher for the verbs that sign something themselves: one
/// reader per relay, the relays asked at once, every answer written to `err`
/// under `verb`. At most `dial.max_relays` relays are used.
pub fn publishOne(
    gpa: std.mem.Allocator,
    io: std.Io,
    verb: []const u8,
    urls: []const []const u8,
    ev: nostr.event.Event,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !bool {
    const id = try hex.encode(gpa, &ev.id);
    defer gpa.free(id);
    var set: Set = undefined;
    set.init(gpa, io, verb, urls[0..@min(urls.len, dial.max_relays)], null);
    defer set.deinit();
    try set.ready(@min(dial.default_timeout_ms, timeout_ms), err);
    if (set.live() == 0) {
        try err.print("deed {s}: {s}: not published, no relay could be reached\n", .{ verb, id });
        try err.flush();
        return false;
    }
    const accepted = try set.offer(ev, id, timeout_ms, err);
    try set.reportAll(err);
    try err.flush();
    return accepted;
}

/// The relays one run publishes to.
///
/// Each connected relay has its own reader for the whole run. It answers pings,
/// hands answers and notices to this thread through `heard`, and says the
/// moment its connection goes away. So an answer is seen as soon as it arrives
/// whichever relay sends it, a relay that closes while the run waits for input
/// is known about before the next event is sent to it, and a relay that stalls
/// in the middle of a read holds up only its own reader.
const Set = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// The verb the messages are written under: `publish`, `post`, `profile set`.
    verb: []const u8,
    urls: []const []const u8,
    conns: [dial.max_relays]?*relay.Relay,
    state: [dial.max_relays]State,
    readers: [dial.max_relays]?std.Io.Future(void),
    /// Set before a reader is cancelled, so it hands nothing over on its way
    /// out. A put after the cancel could otherwise wait on a full queue that
    /// nobody is reading while this thread waits for the reader.
    quiet: [dial.max_relays]std.atomic.Value(bool),
    /// Which connection a message came from. Bumped whenever a relay is let
    /// go, so what its old reader left in the queue is recognised and dropped.
    gen: [dial.max_relays]u32,
    /// Notices a relay has sent this run, across every connection to it.
    /// Counted by the readers, so a relay sending them as fast as it can does
    /// not fill the queue with lines nobody will see.
    notices: [dial.max_relays]std.atomic.Value(u32),
    heard: std.Io.Queue(Heard),
    heard_buf: [256]Heard,
    /// The key NIP-42 challenges are answered with, when `--auth` was given.
    auth: ?auth.Options,
    /// The latest challenge each connection sent. Owned, and let go with the
    /// connection, because a challenge is good for the connection it came on.
    challenge: [dial.max_relays]?[]u8,
    /// Whether this connection is past `--force-pre-auth`: answered, refused,
    /// or given up on waiting for a challenge.
    pre_authed: [dial.max_relays]bool,
    /// Which event a deadline marker in `heard` belongs to.
    seq: u64,

    const State = enum {
        /// Not dialled yet.
        idle,
        connected,
        /// Was connected and went away. Dialled again for the next event:
        /// a relay that drops an idle connection is still a relay.
        closed,
        /// Not tried again this run: it failed to dial, or it stopped
        /// reading what was sent to it.
        gone,
    };

    /// What a reader hands over. Text is copied out of the message, which the
    /// reader frees, and is freed here once it has been dealt with.
    const Heard = struct {
        index: usize = 0,
        gen: u32 = 0,
        what: union(enum) {
            ok: struct { id: [32]u8, accepted: bool, message: []u8 },
            notice: []u8,
            /// A NIP-42 challenge, handed over only when there is a key to
            /// answer it with.
            challenge: []u8,
            more_notices,
            /// The connection went away: null when the relay closed it.
            lost: ?anyerror,
            /// This event's time is up. Everything a reader handed over
            /// before it is ahead of it in the queue.
            deadline: u64,
        },
    };

    fn init(self: *Set, gpa: std.mem.Allocator, io: std.Io, verb: []const u8, urls: []const []const u8, auth_opts: ?auth.Options) void {
        self.* = .{
            .gpa = gpa,
            .io = io,
            .verb = verb,
            .urls = urls,
            .conns = @splat(null),
            .state = @splat(.idle),
            .readers = @splat(null),
            .quiet = @splat(.init(false)),
            .gen = @splat(0),
            .notices = @splat(.init(0)),
            .heard = undefined,
            .heard_buf = undefined,
            .seq = 0,
            .auth = auth_opts,
            .challenge = @splat(null),
            .pre_authed = @splat(false),
        };
        self.heard = .init(&self.heard_buf);
    }

    fn deinit(self: *Set) void {
        for (0..self.urls.len) |i| _ = self.release(i);
        // What the readers left behind, text included.
        var buf: [32]Heard = undefined;
        while (true) {
            const n = self.heard.get(self.io, &buf, 0) catch break;
            if (n == 0) break;
            for (buf[0..n]) |h| self.free(h);
        }
    }

    fn free(self: *Set, h: Heard) void {
        switch (h.what) {
            .ok => |o| self.gpa.free(o.message),
            .notice, .challenge => |t| self.gpa.free(t),
            .more_notices, .lost, .deadline => {},
        }
    }

    fn live(self: *const Set) usize {
        var n: usize = 0;
        for (self.conns[0..self.urls.len]) |c| {
            if (c != null) n += 1;
        }
        return n;
    }

    /// Stops relay `i`'s reader and waits for it.
    fn stopReader(self: *Set, i: usize) void {
        if (self.readers[i]) |*f| {
            self.quiet[i].store(true, .release);
            f.cancel(self.io);
            self.readers[i] = null;
        }
    }

    /// Stops relay `i`'s reader, waits for it, and closes the connection.
    /// Returns how many messages it could not read.
    fn release(self: *Set, i: usize) u64 {
        self.stopReader(i);
        if (self.challenge[i]) |c| self.gpa.free(c);
        self.challenge[i] = null;
        self.pre_authed[i] = false;
        const r = self.conns[i] orelse return 0;
        self.conns[i] = null;
        self.gen[i] +%= 1;
        const unreadable = r.unreadable();
        r.shutdown(self.io);
        r.deinit();
        return unreadable;
    }

    /// Lets go of relay `i`, saying first what it sent that could not be read.
    fn drop(self: *Set, i: usize, next: State, err: *std.Io.Writer) !void {
        const unreadable = self.release(i);
        self.state[i] = next;
        try reportUnreadable(err, self.verb, self.urls[i], unreadable);
    }

    fn startReader(self: *Set, i: usize) !void {
        self.quiet[i].store(false, .release);
        self.readers[i] = try self.io.concurrent(readLoop, .{ self, i, self.gen[i], self.conns[i].? });
    }

    /// Reads relay `i` until its connection goes away or this run lets it go.
    ///
    /// `receive` rather than `receiveTimeout`: with no deadline the read goes
    /// straight to the socket, where a cancel reaches it, including in the
    /// middle of a TLS record.
    fn readLoop(self: *Set, i: usize, gen: u32, r: *relay.Relay) void {
        while (true) {
            var msg = (r.receive() catch |e| {
                _ = self.tell(i, gen, .{ .lost = e });
                return;
            }) orelse {
                _ = self.tell(i, gen, .{ .lost = null });
                return;
            };
            defer msg.deinit();
            switch (msg.value) {
                .ok => |o| {
                    const text = self.gpa.dupe(u8, o.message) catch {
                        _ = self.tell(i, gen, .{ .lost = error.OutOfMemory });
                        return;
                    };
                    if (!self.tell(i, gen, .{ .ok = .{ .id = o.event_id, .accepted = o.accepted, .message = text } })) {
                        self.gpa.free(text);
                        return;
                    }
                },
                .notice => |n| {
                    const count = self.notices[i].fetchAdd(1, .monotonic) + 1;
                    if (count <= max_notices) {
                        const text = self.gpa.dupe(u8, n.message) catch {
                            _ = self.tell(i, gen, .{ .lost = error.OutOfMemory });
                            return;
                        };
                        if (!self.tell(i, gen, .{ .notice = text })) {
                            self.gpa.free(text);
                            return;
                        }
                    } else if (count == max_notices + 1) {
                        if (!self.tell(i, gen, .more_notices)) return;
                    }
                },
                // A challenge is not a refusal yet. If the relay needs it
                // answered, the OK that follows says so, and the challenge
                // is kept for then.
                .auth => |c| if (self.auth != null) {
                    const text = self.gpa.dupe(u8, c.challenge) catch {
                        _ = self.tell(i, gen, .{ .lost = error.OutOfMemory });
                        return;
                    };
                    if (!self.tell(i, gen, .{ .challenge = text })) {
                        self.gpa.free(text);
                        return;
                    }
                },
                .event, .eose, .closed, .count, .neg_msg, .neg_err => {},
            }
        }
    }

    fn tell(self: *Set, i: usize, gen: u32, what: @FieldType(Heard, "what")) bool {
        if (self.quiet[i].load(.acquire)) return false;
        self.heard.putOne(self.io, .{ .index = i, .gen = gen, .what = what }) catch return false;
        return true;
    }

    fn deadlineAfter(q: *std.Io.Queue(Heard), io: std.Io, ms: i64, seq: u64) void {
        io.sleep(.fromMilliseconds(ms), .awake) catch return;
        q.putOne(io, .{ .what = .{ .deadline = seq } }) catch return;
    }

    /// Deals with what the readers handed over while nothing was waiting for
    /// an answer: a relay that went away is let go, to be dialled again for
    /// the next event, and notices are reported.
    fn refresh(self: *Set, err: *std.Io.Writer) !void {
        var buf: [32]Heard = undefined;
        // At most a queue's worth. Relays still sending as this reads could
        // otherwise keep it going for as long as they liked.
        var taken: usize = 0;
        while (taken < self.heard_buf.len) {
            const n = self.heard.get(self.io, &buf, 0) catch return;
            if (n == 0) return;
            taken += n;
            for (buf[0..n], 0..) |h, k| {
                errdefer for (buf[k + 1 .. n]) |rest| self.free(rest);
                defer self.free(h);
                if (h.what == .deadline or h.gen != self.gen[h.index]) continue;
                switch (h.what) {
                    .lost => try self.drop(h.index, .closed, err),
                    .challenge => |t| try self.keepChallenge(h.index, t),
                    .notice => |t| try self.printNotice(err, h.index, t),
                    .more_notices => try err.print("deed {s}: {s}: more notices, not shown\n", .{ self.verb, self.urls[h.index] }),
                    .ok, .deadline => {},
                }
            }
        }
    }

    /// Dials every relay not dialled yet, and every relay that went away
    /// since the last event, all at once.
    fn ready(self: *Set, bound_ms: i64, err: *std.Io.Writer) !void {
        var which: [dial.max_relays]usize = undefined;
        var n: usize = 0;
        for (0..self.urls.len) |i| {
            if (self.state[i] != .idle and self.state[i] != .closed) continue;
            which[n] = i;
            n += 1;
        }
        try self.dialSome(which[0..n], bound_ms, .gone, err);
    }

    /// Dials the relays in `which` at once. A relay that cannot be reached is
    /// left in `failed`: `.gone` when it could never be reached, `.closed` when
    /// only this attempt, squeezed into what was left of a deadline, failed.
    fn dialSome(self: *Set, which: []const usize, bound_ms: i64, failed: State, err: *std.Io.Writer) !void {
        if (which.len == 0) return;
        var urls: [dial.max_relays][]const u8 = undefined;
        for (which, 0..) |i, k| urls[k] = self.urls[i];
        var outcomes: [dial.max_relays]dial.Outcome = undefined;
        dial.all(self.gpa, self.io, urls[0..which.len], bound_ms, &outcomes);
        // Every connection is stored before anything is written, so a failed
        // write cannot strand one that `deinit` would never see.
        for (outcomes[0..which.len], which) |o, i| switch (o) {
            .connected => |r| {
                self.conns[i] = r;
                self.state[i] = .connected;
            },
            .failed, .timed_out => self.state[i] = failed,
        };
        for (outcomes[0..which.len], which) |o, i| switch (o) {
            .connected => self.startReader(i) catch |e| {
                try err.print("deed {s}: {s}: {s}\n", .{ self.verb, self.urls[i], dial.describe(e) });
                try self.drop(i, .gone, err);
            },
            .failed => |e| try err.print("deed {s}: {s}: {s}\n", .{ self.verb, self.urls[i], dial.describe(e) }),
            .timed_out => try err.print("deed {s}: {s}: no answer within {d} ms\n", .{ self.verb, self.urls[i], bound_ms }),
        };
    }

    const Sent = struct {
        index: usize,
        result: anyerror!void,
    };

    const SendArrival = union(enum) {
        sent: Sent,
        timer: std.Io.Cancelable!void,
    };

    const SendKind = enum { event, auth };

    fn sendOne(r: *relay.Relay, ev: nostr.event.Event, kind: SendKind, index: usize) Sent {
        return .{ .index = index, .result = switch (kind) {
            .event => r.publish(ev),
            .auth => r.authenticate(ev),
        } };
    }

    /// Sends `ev` to the relays in `which` at once, and marks each one that
    /// took it as waiting. A send can block: a relay that has stopped reading
    /// fills the socket, and the write waits for room that never comes, so
    /// whatever is still sending at the deadline is cancelled and let go.
    ///
    /// Every send is finished or cancelled before this returns, whatever
    /// happens, because each one holds the event and its relay.
    fn sendSome(
        self: *Set,
        which: []const usize,
        ev: nostr.event.Event,
        kind: SendKind,
        id: []const u8,
        deadline: std.Io.Clock.Timestamp,
        timeout_ms: i64,
        stalled: State,
        waiting: *[dial.max_relays]bool,
        /// Where a send that failed outright is handed back instead of being
        /// reported, so the caller can try it once more. Null reports it.
        send_failed: ?*[dial.max_relays]?anyerror,
        err: *std.Io.Writer,
    ) !void {
        var results: [dial.max_relays]?Sent = @splat(null);
        var late: [dial.max_relays]bool = @splat(false);
        var started: [dial.max_relays]bool = @splat(false);
        {
            var buf: [dial.max_relays + 1]SendArrival = undefined;
            var sel = std.Io.Select(SendArrival).init(self.io, &buf);
            defer while (sel.cancel()) |a| switch (a) {
                .sent => |s| {
                    results[s.index] = s;
                    late[s.index] = true;
                },
                .timer => {},
            };
            var pending: usize = 0;
            for (which) |i| {
                const r = self.conns[i] orelse continue;
                sel.concurrent(.sent, sendOne, .{ r, ev, kind, i }) catch {
                    // No concurrency to spare. Sent here instead, which is only
                    // as bounded as the relay is willing to read.
                    results[i] = sendOne(r, ev, kind, i);
                    continue;
                };
                started[i] = true;
                pending += 1;
            }
            if (pending > 0) sel.concurrent(.timer, std.Io.sleep, .{ self.io, .fromMilliseconds(msLeft(self.io, deadline)), .awake }) catch {};
            while (pending > 0) {
                const a = sel.await() catch break;
                switch (a) {
                    .sent => |s| {
                        results[s.index] = s;
                        pending -= 1;
                    },
                    .timer => break,
                }
            }
            // A send still going at the deadline may be waiting for the
            // connection's write lock rather than for the socket, behind the
            // relay's own reader writing a pong to a relay that has stopped
            // reading. That wait cannot be cancelled, so the reader is stopped
            // first, which lets go of the lock, before the sends are joined.
            if (pending > 0) for (which) |i| {
                if (started[i] and results[i] == null) self.stopReader(i);
            };
        }
        // Every send has been joined by now, so what follows can write, and
        // fail to, without anything still using the event or a relay.
        for (which) |i| {
            const s = results[i] orelse continue;
            if (s.result) {
                waiting[i] = true;
            } else |e| {
                if (late[i]) {
                    // Still sending at the deadline. Whatever reached the
                    // socket is half a frame, so this connection is done.
                    try err.print("deed {s}: {s}: {s}: could not send within {d} ms\n", .{ self.verb, id, self.urls[i], timeout_ms });
                    try self.drop(i, stalled, err);
                } else if (send_failed) |f| {
                    f[i] = e;
                    try self.drop(i, .closed, err);
                } else {
                    try err.print("deed {s}: {s}: {s}: {s}\n", .{ self.verb, id, self.urls[i], dial.describe(e) });
                    try self.drop(i, .closed, err);
                }
            }
        }
    }

    /// Offers `ev` to every connected relay at once and collects their
    /// answers, all against one deadline. Returns whether any relay accepted.
    fn offer(
        self: *Set,
        ev: nostr.event.Event,
        id: []const u8,
        timeout_ms: i64,
        err: *std.Io.Writer,
    ) !bool {
        const io = self.io;
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake });
        var waiting: [dial.max_relays]bool = @splat(false);
        var resent: [dial.max_relays]bool = @splat(false);

        var which: [dial.max_relays]usize = undefined;
        var n: usize = 0;
        for (0..self.urls.len) |i| {
            if (self.conns[i] == null) continue;
            which[n] = i;
            n += 1;
        }
        var send_failed: [dial.max_relays]?anyerror = @splat(null);
        try self.sendSome(which[0..n], ev, .event, id, deadline, timeout_ms, .gone, &waiting, &send_failed, err);
        // A relay that dropped an idle connection can also be found out by the
        // send itself rather than by the read after it: Windows refuses the
        // write at once where POSIX takes it and reports the close next. Either
        // way it gets the one fresh connection and one more try that a close
        // while waiting gets below.
        for (0..self.urls.len) |i| {
            const e = send_failed[i] orelse continue;
            if (msLeft(io, deadline) >= min_resend_ms) {
                resent[i] = true;
                try self.dialSome(&.{i}, @min(dial.default_timeout_ms, msLeft(io, deadline)), .closed, err);
                if (self.conns[i] != null) {
                    // Reports its own failure this time.
                    try self.sendSome(&.{i}, ev, .event, id, deadline, timeout_ms, .closed, &waiting, null, err);
                    continue;
                }
            }
            try err.print("deed {s}: {s}: {s}: {s}\n", .{ self.verb, id, self.urls[i], dial.describe(e) });
        }

        self.seq += 1;
        var timer = try io.concurrent(deadlineAfter, .{ &self.heard, io, msLeft(io, deadline), self.seq });
        defer timer.cancel(io);

        // NIP-42, per relay: the answer awaiting its OK, whether this event
        // has already been through one authentication, and whether a refusal
        // asked for one before any challenge had arrived.
        var auth_id: [dial.max_relays]?[32]u8 = @splat(null);
        var auth_tried: [dial.max_relays]bool = @splat(false);
        var want_auth: [dial.max_relays]bool = @splat(false);

        var accepted = false;
        while (anyOf(&waiting)) {
            const h = self.heard.getOne(io) catch break;
            defer self.free(h);
            if (h.what == .deadline) {
                if (h.what.deadline != self.seq) continue;
                for (0..self.urls.len) |i| {
                    if (waiting[i]) try err.print("deed {s}: {s}: {s}: no answer within {d} ms\n", .{ self.verb, id, self.urls[i], timeout_ms });
                }
                break;
            }
            if (h.gen != self.gen[h.index]) continue;
            const i = h.index;
            const url = self.urls[i];
            switch (h.what) {
                .ok => |o| {
                    if (auth_id[i]) |aid| if (std.mem.eql(u8, &o.id, &aid)) {
                        auth_id[i] = null;
                        waiting[i] = false;
                        if (o.accepted) {
                            // Offered once more, now that the relay knows who
                            // is offering it.
                            try self.sendSome(&.{i}, ev, .event, id, deadline, timeout_ms, .closed, &waiting, null, err);
                        } else {
                            try err.print("deed {s}: {s}: {s}: authentication refused: ", .{ self.verb, id, url });
                            try writeEscaped(err, o.message);
                            try err.writeAll("\n");
                        }
                        continue;
                    };
                    // An answer about some other event, such as one an
                    // earlier wait gave up on, is not an answer to this.
                    if (!waiting[i] or !std.mem.eql(u8, &o.id, &ev.id)) continue;
                    if (!o.accepted and self.auth != null and !auth_tried[i] and auth.isAuthRequired(o.message)) {
                        auth_tried[i] = true;
                        try err.print("deed {s}: {s}: {s}: authenticating\n", .{ self.verb, id, url });
                        if (self.challenge[i] != null) {
                            auth_id[i] = try self.authenticate(i, id, deadline, timeout_ms, &waiting, err);
                        } else {
                            // The challenge may follow the refusal.
                            want_auth[i] = true;
                        }
                        continue;
                    }
                    waiting[i] = false;
                    if (o.accepted) accepted = true;
                    try err.print("deed {s}: {s}: {s}: {s}", .{ self.verb, id, url, if (o.accepted) "accepted" else "refused: " });
                    if (o.accepted and o.message.len > 0) {
                        try err.writeAll(" (");
                        try writeEscaped(err, o.message);
                        try err.writeAll(")");
                    } else if (!o.accepted) {
                        try writeEscaped(err, o.message);
                    }
                    try err.writeAll("\n");
                },
                .challenge => |t| {
                    try self.keepChallenge(i, t);
                    if (want_auth[i] and waiting[i]) {
                        want_auth[i] = false;
                        auth_id[i] = try self.authenticate(i, id, deadline, timeout_ms, &waiting, err);
                    }
                },
                .notice => |t| try self.printNotice(err, i, t),
                .more_notices => try err.print("deed {s}: {s}: more notices, not shown\n", .{ self.verb, url }),
                .lost => |why| {
                    const was_waiting = waiting[i];
                    waiting[i] = false;
                    try self.drop(i, .closed, err);
                    if (!was_waiting) continue;
                    // A relay that dropped an idle connection only finds out
                    // when something is sent down it. One fresh connection and
                    // one more try, inside the same deadline.
                    // Only with time left to do it in; a relay that cannot be
                    // reached in the last few milliseconds is still dialled
                    // again for the next event.
                    if (!resent[i] and msLeft(io, deadline) >= min_resend_ms) {
                        resent[i] = true;
                        try self.dialSome(&.{i}, @min(dial.default_timeout_ms, msLeft(io, deadline)), .closed, err);
                        if (self.conns[i] != null) {
                            try self.sendSome(&.{i}, ev, .event, id, deadline, timeout_ms, .closed, &waiting, null, err);
                            if (waiting[i]) continue;
                        }
                    }
                    if (why) |e| {
                        try err.print("deed {s}: {s}: {s}: {s}\n", .{ self.verb, id, url, dial.describe(e) });
                    } else {
                        try err.print("deed {s}: {s}: {s}: closed before answering\n", .{ self.verb, id, url });
                    }
                },
                .deadline => unreachable,
            }
        }
        return accepted;
    }

    /// Keeps the latest challenge relay `i` sent on this connection.
    fn keepChallenge(self: *Set, i: usize, text: []const u8) !void {
        const copy = try self.gpa.dupe(u8, text);
        if (self.challenge[i]) |old| self.gpa.free(old);
        self.challenge[i] = copy;
    }

    /// Answers relay `i`'s challenge. Returns the answer's id when it was
    /// sent, and leaves `waiting[i]` saying whether it was: a send that fails
    /// lets the relay go, as any other does.
    fn authenticate(
        self: *Set,
        i: usize,
        id: []const u8,
        deadline: std.Io.Clock.Timestamp,
        timeout_ms: i64,
        waiting: *[dial.max_relays]bool,
        err: *std.Io.Writer,
    ) !?[32]u8 {
        var ans = auth.answer(self.gpa, self.io, self.auth.?, self.urls[i], self.challenge[i].?) catch |e| {
            // A remote signer that refused or went quiet: this relay goes
            // without an answer, as one whose send failed does.
            const why = signing.describe(e) orelse return e;
            waiting[i] = false;
            try err.print("deed {s}: {s}: cannot authenticate: {s}\n", .{ self.verb, self.urls[i], why });
            return null;
        };
        defer ans.deinit();
        waiting[i] = false;
        try self.sendSome(&.{i}, ans.event, .auth, id, deadline, timeout_ms, .closed, waiting, null, err);
        return if (waiting[i]) ans.id else null;
    }

    /// With `--force-pre-auth`, waits for each new connection's challenge and
    /// answers it before anything is offered, all at once and within
    /// `bound_ms`. A relay with no challenge by then is offered events
    /// without one, and can still ask.
    fn preAuth(self: *Set, bound_ms: i64, err: *std.Io.Writer) !void {
        const a = self.auth orelse return;
        if (!a.force_pre_auth) return;
        var pending: [dial.max_relays]bool = @splat(false);
        for (0..self.urls.len) |i| pending[i] = self.conns[i] != null and !self.pre_authed[i];
        if (!anyOf(&pending)) return;

        const io = self.io;
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(bound_ms), .clock = .awake });
        var auth_id: [dial.max_relays]?[32]u8 = @splat(null);
        var sent: [dial.max_relays]bool = @splat(false);
        for (0..self.urls.len) |i| {
            if (!pending[i] or self.challenge[i] == null) continue;
            auth_id[i] = try self.authenticate(i, "AUTH", deadline, bound_ms, &sent, err);
            if (auth_id[i] == null) pending[i] = false;
        }

        self.seq += 1;
        var timer = try io.concurrent(deadlineAfter, .{ &self.heard, io, msLeft(io, deadline), self.seq });
        defer timer.cancel(io);

        while (anyOf(&pending)) {
            const h = self.heard.getOne(io) catch break;
            defer self.free(h);
            if (h.what == .deadline) {
                if (h.what.deadline != self.seq) continue;
                for (0..self.urls.len) |i| {
                    if (!pending[i]) continue;
                    self.pre_authed[i] = true;
                    if (auth_id[i] == null) {
                        try err.print("deed {s}: {s}: no authentication challenge within {d} ms, publishing without one\n", .{ self.verb, self.urls[i], bound_ms });
                    } else {
                        try err.print("deed {s}: {s}: no answer to authentication within {d} ms\n", .{ self.verb, self.urls[i], bound_ms });
                    }
                }
                break;
            }
            if (h.gen != self.gen[h.index]) continue;
            const i = h.index;
            switch (h.what) {
                .challenge => |t| {
                    try self.keepChallenge(i, t);
                    if (pending[i] and auth_id[i] == null) {
                        auth_id[i] = try self.authenticate(i, "AUTH", deadline, bound_ms, &sent, err);
                        if (auth_id[i] == null) pending[i] = false;
                    }
                },
                .ok => |o| {
                    const aid = auth_id[i] orelse continue;
                    if (!std.mem.eql(u8, &o.id, &aid)) continue;
                    pending[i] = false;
                    self.pre_authed[i] = true;
                    if (!o.accepted) {
                        try err.print("deed {s}: {s}: authentication refused: ", .{ self.verb, self.urls[i] });
                        try writeEscaped(err, o.message);
                        try err.writeAll("\n");
                    }
                },
                .notice => |t| try self.printNotice(err, i, t),
                .more_notices => try err.print("deed {s}: {s}: more notices, not shown\n", .{ self.verb, self.urls[i] }),
                .lost => {
                    pending[i] = false;
                    try self.drop(i, .closed, err);
                },
                .deadline => unreachable,
            }
        }
    }

    fn printNotice(self: *Set, err: *std.Io.Writer, i: usize, text: []const u8) !void {
        try err.print("deed {s}: {s}: notice: ", .{ self.verb, self.urls[i] });
        try writeEscaped(err, text);
        try err.writeAll("\n");
    }

    fn reportAll(self: *Set, err: *std.Io.Writer) !void {
        for (0..self.urls.len) |i| {
            if (self.conns[i] == null) continue;
            try reportUnreadable(err, self.verb, self.urls[i], self.release(i));
        }
    }
};

fn anyOf(flags: *const [dial.max_relays]bool) bool {
    for (flags) |f| {
        if (f) return true;
    }
    return false;
}

/// Notices shown per relay per run before the rest are counted and not shown.
const max_notices = 8;

/// How long `--force-pre-auth` waits for a new connection's challenge.
const challenge_wait_ms: i64 = 3_000;

/// The least time left in which a relay that closed before answering is dialled
/// and sent the event again.
const min_resend_ms = 250;

fn reportUnreadable(err: *std.Io.Writer, verb: []const u8, url: []const u8, n: u64) !void {
    if (n > 0) try err.print("deed {s}: {s}: skipped {d} unreadable {s}\n", .{ verb, url, n, if (n == 1) "message" else "messages" });
}

/// Milliseconds until `deadline`, never below zero.
fn msLeft(io: std.Io, deadline: std.Io.Clock.Timestamp) i64 {
    const left = deadline.raw.nanoseconds - std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    if (left <= 0) return 0;
    return @intCast(@min(@divFloor(left, std.time.ns_per_ms), std.math.maxInt(i64)));
}

const writeEscaped = relayset.writeEscaped;

// ---------------------------------------------------------------------------
// Tests: the real command, against real relays on loopback.
// ---------------------------------------------------------------------------

const testrelay = @import("testrelay.zig");

/// A signed kind 1 event as one line of JSON, from a fixed key.
fn signedEvent(arena: std.mem.Allocator, io: std.Io, content: []const u8) ![]const u8 {
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
    const ev = try nostr.event.create(arena, signer, kp, 1700000000, 1, &.{}, content, null);
    return nostr.event.toJson(arena, ev);
}

fn idOf(arena: std.mem.Allocator, json: []const u8) ![]const u8 {
    var parsed = try nostr.event.fromJson(arena, json);
    defer parsed.deinit();
    return hex.encode(arena, &parsed.value.id);
}

const Ran = struct {
    code: u8,
    out: []const u8,
    err: []const u8,
    ms: i64,
};

/// Runs `deed publish` with `args`, dialling through an allocator that
/// captures no stack traces (see `testrelay.DialAllocator`).
fn runPublish(arena: std.mem.Allocator, args: []const []const u8) !Ran {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("publish leaked");
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const code = try run(da.allocator(), io, args, &out.writer, &err.writer);
    return .{
        .code = code,
        .out = out.written(),
        .err = err.written(),
        .ms = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started,
    };
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "an accepted event is printed, and every relay's answer is on stderr with its id" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var yes: testrelay.Relay = undefined;
    try yes.start(io, .accept);
    defer yes.stop(io);
    var no: testrelay.Relay = undefined;
    try no.start(io, .refuse);
    defer no.stop(io);

    var bufs: [2][40]u8 = undefined;
    const yes_url = try testrelay.url(&bufs[0], yes.port());
    const no_url = try testrelay.url(&bufs[1], no.port());
    const ev = try signedEvent(arena, io, "hello");
    const id = try idOf(arena, ev);

    const r = try runPublish(arena, &.{ yes_url, no_url, ev });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), r.out);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "deed publish: {s}: {s}: accepted\n", .{ id, yes_url })));
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "deed publish: {s}: {s}: refused: invalid: test refusal\n", .{ id, no_url })));
}

test "an event no relay accepted is not printed, and the run fails" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var no: testrelay.Relay = undefined;
    try no.start(io, .refuse);
    defer no.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");
    const id = try idOf(arena, ev);

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, no.port()), ev });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "deed publish: {s}: not published, no relay accepted it in time\n", .{id})));
    try std.testing.expect(contains(r.err, "deed publish: 0 of 1 published\n"));
}

test "one event not published fails the run, and the others still go out" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var yes: testrelay.Relay = undefined;
    try yes.start(io, .accept);
    defer yes.stop(io);
    var buf: [40]u8 = undefined;
    const good = try signedEvent(arena, io, "hello");
    const later = try signedEvent(arena, io, "later");
    // Signed, then altered: its id no longer matches its content.
    const forged = try std.mem.replaceOwned(u8, arena, try signedEvent(arena, io, "original"), "original", "tampered");
    const forged_id = try idOf(arena, forged);

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, yes.port()), good, forged, "not json", later });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n{s}\n", .{ good, later }), r.out);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "deed publish: {s}: not sent, bad signature\n", .{forged_id})));
    try std.testing.expect(contains(r.err, "deed publish: not an event: "));
    try std.testing.expect(contains(r.err, "deed publish: 2 of 4 published\n"));
    // The forgery never reached the relay.
    try std.testing.expectEqual(@as(usize, 2), yes.events.load(.monotonic));
}

test "a relay that already had the event counts as accepting it, and says so" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var dup: testrelay.Relay = undefined;
    try dup.start(io, .duplicate);
    defer dup.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, dup.port()), ev });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), r.out);
    try std.testing.expect(contains(r.err, ": accepted (duplicate: already have it)\n"));
}

test "the answers have one deadline, however much a relay talks" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    // A notice every 100 ms and never an answer. A wait that started again
    // with every message would never end.
    var chatty: testrelay.Relay = undefined;
    try chatty.start(io, .chatty);
    defer chatty.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, chatty.port());
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ "--timeout", "400", url, ev });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "{s}: no answer within 400 ms\n", .{url})));
    try std.testing.expect(contains(r.err, ": notice: still here\n"));
    try std.testing.expect(r.ms < 3_000);
}

test "a relay that never answers the dial does not hold the others" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var silent = try testrelay.listen(io);
    defer silent.deinit(io);
    var yes: testrelay.Relay = undefined;
    try yes.start(io, .accept);
    defer yes.stop(io);
    var bufs: [2][40]u8 = undefined;
    const silent_url = try testrelay.url(&bufs[0], silent.socket.address.ip4.port);
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ "--timeout", "1000", silent_url, try testrelay.url(&bufs[1], yes.port()), ev });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), r.out);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "deed publish: {s}: no answer within 1000 ms\n", .{silent_url})));
    try std.testing.expect(r.ms < 3_000);
}

test "a message the relay sends that cannot be read does not cost the answer" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var odd: testrelay.Relay = undefined;
    try odd.start(io, .unreadable_first);
    defer odd.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, odd.port()), ev });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(contains(r.err, ": accepted\n"));
    try std.testing.expect(contains(r.err, ": skipped 1 unreadable message\n"));
}

test "text from a relay cannot forge a line or reach the terminal" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var bad: testrelay.Relay = undefined;
    try bad.start(io, .hostile);
    defer bad.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");
    const id = try idOf(arena, ev);

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, bad.port()), ev });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOfScalar(u8, r.err, 0x1b) == null);
    // The claim is there, but inside the refusal, on the refusal's own line.
    try std.testing.expect(!contains(r.err, try std.fmt.allocPrint(arena, "\ndeed publish: {s}: ws://x: accepted", .{id})));
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "refused: invalid: \\x1b[31mred\\x0adeed publish: {s}: ws://x: accepted\n", .{id})));
}

test "an event carrying a key NIP-01 does not name is published as the event that was signed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var yes: testrelay.Relay = undefined;
    try yes.start(io, .accept);
    defer yes.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");
    const extra = try std.mem.concat(arena, u8, &.{ "{\"seen_on\":[\"wss://a\"],", ev[1..] });

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, yes.port()), extra });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), r.out);
}

test "a command that makes no sense is refused before anything is dialled" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &.{"{}"})).code);
    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &.{ "--nope", "ws://127.0.0.1:1" })).code);
    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &.{ "--timeout", "soon", "ws://127.0.0.1:1" })).code);
    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &.{ "--timeout", "0", "ws://127.0.0.1:1" })).code);

    var many: [dial.max_relays + 1][]const u8 = undefined;
    for (&many) |*u| u.* = "ws://127.0.0.1:1";
    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &many)).code);
}

test "a relay that stops reading is dropped at the deadline, and the others still get every event" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var deaf: testrelay.Relay = undefined;
    try deaf.start(io, .deaf);
    defer deaf.stop(io);
    var yes: testrelay.Relay = undefined;
    try yes.start(io, .unreadable_first);
    defer yes.stop(io);
    var bufs: [2][40]u8 = undefined;
    const deaf_url = try testrelay.url(&bufs[0], deaf.port());

    // Big enough that a relay reading none of them fills the socket within a
    // few events, and the write to it waits for room that never comes.
    //
    // The other relay sends a message that cannot be read ahead of each
    // answer, and its answer to the event stuck behind the deaf relay arrives
    // while that write is still waiting. It is counted all the same.
    const big = try arena.alloc(u8, 900 * 1024);
    @memset(big, 'x');
    var args: [8][]const u8 = undefined;
    args[0] = "--timeout";
    args[1] = "500";
    args[2] = deaf_url;
    args[3] = try testrelay.url(&bufs[1], yes.port());
    for (args[4..], 0..) |*a, i| {
        big[0] = @intCast('a' + i);
        a.* = try signedEvent(arena, io, big);
    }

    const r = try runPublish(arena, &args);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqual(@as(usize, 4), std.mem.count(u8, r.out, "\n"));
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "{s}: could not send within 500 ms\n", .{deaf_url})));
    try std.testing.expectEqual(@as(usize, 4), yes.events.load(.monotonic));
    try std.testing.expect(r.ms < 10_000);
}

test "a relay that closed while the run waited for input is dialled again" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    // Closes after each answer, and takes a second connection.
    var once: testrelay.Relay = undefined;
    try once.startFor(io, .close_after_ok, 2);
    defer once.stop(io);
    var buf: [40]u8 = undefined;
    const first = try signedEvent(arena, io, "first");
    const second = try signedEvent(arena, io, "second");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, once.port()), first, second });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n{s}\n", .{ first, second }), r.out);
    try std.testing.expectEqual(@as(usize, 2), once.events.load(.monotonic));
}

test "an answer about some other event is not taken as this event's" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var stale: testrelay.Relay = undefined;
    try stale.start(io, .stale_ok);
    defer stale.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, stale.port()), ev });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(contains(r.err, ": refused: invalid: not this one\n"));
}

test "nothing is dialled for input that has nothing to publish" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    // A closed port: dialling it would be reported, and it is not.
    var closed = try testrelay.listen(io);
    const port = closed.socket.address.ip4.port;
    closed.deinit(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, port);

    const r = try runPublish(arena, &.{ url, "not json" });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(contains(r.err, "deed publish: not an event: "));
    try std.testing.expect(!contains(r.err, url));
}

test "pongs arriving back to back do not keep the wait going" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var pongs: testrelay.Relay = undefined;
    try pongs.start(io, .pongs);
    defer pongs.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, pongs.port());
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ "--timeout", "300", url, ev });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "{s}: no answer within 300 ms\n", .{url})));
    try std.testing.expect(r.ms < 3_000);
}

test "a relay's notices are shown up to a point" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var burst: testrelay.Relay = undefined;
    try burst.start(io, .notice_burst);
    defer burst.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ "--timeout", "200", try testrelay.url(&buf, burst.port()), ev });
    try std.testing.expectEqual(@as(usize, max_notices), std.mem.count(u8, r.err, ": notice: again\n"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, r.err, ": more notices, not shown\n"));
}

test "control characters in an acceptance or a notice are shown as escapes too" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var bad: testrelay.Relay = undefined;
    try bad.start(io, .hostile_accept);
    defer bad.stop(io);
    var buf: [40]u8 = undefined;
    const ev = try signedEvent(arena, io, "hello");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, bad.port()), ev });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOfScalar(u8, r.err, 0x1b) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, r.err, 0x7f) == null);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "\xc2\x9b") == null);
    try std.testing.expect(contains(r.err, ": notice: \\x1bbad\\x7f\\u009b31m\n"));
    try std.testing.expect(contains(r.err, ": accepted (note\\x1b[2J\\u009b2J\\x7f)\n"));
}

test "an answer behind a ping or a run of notices is counted, however many relays are silent" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var pinger: testrelay.Relay = undefined;
    try pinger.start(io, .ping_then_ok);
    defer pinger.stop(io);
    var talker: testrelay.Relay = undefined;
    try talker.start(io, .notices_then_ok);
    defer talker.stop(io);
    var silent: [20]testrelay.Relay = undefined;
    for (&silent) |*r| try r.start(io, .silent);
    defer for (&silent) |*r| r.stop(io);

    var bufs: [22][40]u8 = undefined;
    var args: [25][]const u8 = undefined;
    args[0] = "--timeout";
    args[1] = "1000";
    for (&silent, 0..) |*r, i| args[2 + i] = try testrelay.url(&bufs[i], r.port());
    const pinger_url = try testrelay.url(&bufs[20], pinger.port());
    const talker_url = try testrelay.url(&bufs[21], talker.port());
    args[22] = pinger_url;
    args[23] = talker_url;
    const ev = try signedEvent(arena, io, "hello");
    args[24] = ev;

    const r = try runPublish(arena, &args);
    // Accepted by two relays is published, whatever the silent ones do.
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), r.out);
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "{s}: accepted\n", .{pinger_url})));
    try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "{s}: accepted\n", .{talker_url})));
}

test "a relay that pings and then closes is dialled again for the next event" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var r1: testrelay.Relay = undefined;
    try r1.startFor(io, .ping_then_close, 2);
    defer r1.stop(io);
    var buf: [40]u8 = undefined;
    const first = try signedEvent(arena, io, "first");
    const second = try signedEvent(arena, io, "second");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, r1.port()), first, second });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n{s}\n", .{ first, second }), r.out);
}

test "an event sent down a connection that then closes is offered again on a fresh one" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    // The second event reaches the first connection, which closes without
    // answering. It is offered once more on a second connection.
    var flaky: testrelay.Relay = undefined;
    try flaky.startFor(io, .close_on_second_event, 2);
    defer flaky.stop(io);
    var buf: [40]u8 = undefined;
    const first = try signedEvent(arena, io, "first");
    const second = try signedEvent(arena, io, "second");

    const r = try runPublish(arena, &.{ try testrelay.url(&buf, flaky.port()), first, second });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n{s}\n", .{ first, second }), r.out);
    try std.testing.expectEqual(@as(usize, 3), flaky.events.load(.monotonic));
}

test "a relay that pings and never reads does not hold the run, although its reader is stuck writing a pong" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var pinger: testrelay.Relay = undefined;
    try pinger.start(io, .pings_deaf);
    defer pinger.stop(io);
    var yes: testrelay.Relay = undefined;
    try yes.start(io, .accept);
    defer yes.stop(io);
    var bufs: [2][40]u8 = undefined;
    const pinger_url = try testrelay.url(&bufs[0], pinger.port());
    const first = try signedEvent(arena, io, "first");
    const second = try signedEvent(arena, io, "second");

    // The second send to it waits behind the reader's pong for the write lock.
    const r = try runPublish(arena, &.{ "--timeout", "500", pinger_url, try testrelay.url(&bufs[1], yes.port()), first, second });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n{s}\n", .{ first, second }), r.out);
    try std.testing.expect(r.ms < 5_000);
}

test "notices are counted per relay across its connections" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var talker: testrelay.Relay = undefined;
    try talker.startFor(io, .notices_then_close, 3);
    defer talker.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, talker.port());
    var args: [4][]const u8 = undefined;
    args[0] = url;
    for (args[1..], 0..) |*a, i| a.* = try signedEvent(arena, io, try std.fmt.allocPrint(arena, "event {d}", .{i}));

    const r = try runPublish(arena, &args);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqual(@as(usize, max_notices), std.mem.count(u8, r.err, ": notice: again\n"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, r.err, ": more notices, not shown\n"));
}

/// A relay that takes events only from somebody who has authenticated. It
/// refuses each EVENT with `auth-required:` until it gets an AUTH whose `relay`
/// tag is `want_url` and whose challenge is its own.
const AuthRelay = struct {
    want_url: []const u8 = "",
    /// Send the challenge after the refusal rather than before it.
    challenge_last: bool = false,
    authed: bool = false,
    events: usize = 0,
    auths: usize = 0,

    const challenge = "chal-90d1";

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *AuthRelay = @ptrCast(@alignCast(ctx.?));
        const a = std.heap.page_allocator;
        var parsed = try std.json.parseFromSlice(std.json.Value, a, frame, .{});
        defer parsed.deinit();
        const items = parsed.value.array.items;
        const kind = items[0].string;
        const ev = items[1].object;
        const id = ev.get("id").?.string;
        var text: [256]u8 = undefined;
        if (std.mem.eql(u8, kind, "EVENT")) {
            self.events += 1;
            if (self.authed) return testrelay.sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
            if (!self.challenge_last) try testrelay.sendText(w, "[\"AUTH\",\"" ++ challenge ++ "\"]");
            try testrelay.sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",false,\"auth-required: members only\"]", .{id}));
            if (self.challenge_last) try testrelay.sendText(w, "[\"AUTH\",\"" ++ challenge ++ "\"]");
        } else if (std.mem.eql(u8, kind, "AUTH")) {
            self.auths += 1;
            var relay_ok = false;
            var challenge_ok = false;
            for (ev.get("tags").?.array.items) |t| {
                const pair = t.array.items;
                if (std.mem.eql(u8, pair[0].string, "relay")) relay_ok = std.mem.eql(u8, pair[1].string, self.want_url);
                if (std.mem.eql(u8, pair[0].string, "challenge")) challenge_ok = std.mem.eql(u8, pair[1].string, challenge);
            }
            const good = relay_ok and challenge_ok and ev.get("kind").?.integer == 22242;
            if (good) self.authed = true;
            try testrelay.sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",{s},\"{s}\"]", .{ id, if (good) "true" else "false", if (good) "" else "auth-required: wrong relay" }));
        }
    }
};

const test_sec = "44" ** 32;

test "with --auth an event a relay refused until it knew who was publishing is offered again, and published" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    for ([_]bool{ false, true }) |challenge_last| {
        var script: AuthRelay = .{ .challenge_last = challenge_last };
        var r: testrelay.Relay = undefined;
        try r.startCustom(io, AuthRelay.handle, &script);
        defer r.stop(io);
        var buf: [40]u8 = undefined;
        const url = try testrelay.url(&buf, r.port());
        script.want_url = url;
        const ev = try signedEvent(arena, io, "members only");
        const id = try idOf(arena, ev);

        const res = try runPublish(arena, &.{ "--auth", "--sec", test_sec, "--timeout", "3000", url, ev });
        try std.testing.expectEqual(cli.exit_ok, res.code);
        try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), res.out);
        try std.testing.expect(contains(res.err, try std.fmt.allocPrint(arena, "deed publish: {s}: {s}: authenticating\n", .{ id, url })));
        try std.testing.expect(contains(res.err, try std.fmt.allocPrint(arena, "deed publish: {s}: {s}: accepted\n", .{ id, url })));
        try std.testing.expectEqual(@as(usize, 1), script.auths);
        try std.testing.expectEqual(@as(usize, 2), script.events);
    }
}

test "an authentication naming some other relay is refused, and the event is not published" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var script: AuthRelay = .{ .want_url = "wss://relay.example" };
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, AuthRelay.handle, &script);
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, r.port());
    const ev = try signedEvent(arena, io, "members only");
    const id = try idOf(arena, ev);

    const res = try runPublish(arena, &.{ "--auth", "--sec", test_sec, "--timeout", "3000", url, ev });
    try std.testing.expectEqual(cli.exit_fail, res.code);
    try std.testing.expectEqualStrings("", res.out);
    try std.testing.expect(contains(res.err, try std.fmt.allocPrint(arena, "deed publish: {s}: {s}: authentication refused: auth-required: wrong relay\n", .{ id, url })));
    try std.testing.expectEqual(@as(usize, 1), script.events);
    try std.testing.expect(res.ms < 2_000);
}

test "without --auth a refusal asking for authentication stays a refusal" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var script: AuthRelay = .{};
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, AuthRelay.handle, &script);
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, r.port());
    script.want_url = url;
    const ev = try signedEvent(arena, io, "members only");

    const res = try runPublish(arena, &.{ url, ev });
    try std.testing.expectEqual(cli.exit_fail, res.code);
    try std.testing.expect(contains(res.err, ": refused: auth-required: members only\n"));
    try std.testing.expectEqual(@as(usize, 0), script.auths);
}

test "--force-pre-auth against a relay that sends no challenge still publishes, in bounded time" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;

    var yes: testrelay.Relay = undefined;
    try yes.start(io, .accept);
    defer yes.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, yes.port());
    const ev = try signedEvent(arena, io, "hello");

    const res = try runPublish(arena, &.{ "--force-pre-auth", "--sec", test_sec, "--timeout", "300", url, ev });
    try std.testing.expectEqual(cli.exit_ok, res.code);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{ev}), res.out);
    try std.testing.expect(contains(res.err, try std.fmt.allocPrint(arena, "deed publish: {s}: no authentication challenge within 300 ms, publishing without one\n", .{url})));
    try std.testing.expect(res.ms < 3_000);
}

test "the auth flags are checked before anything is dialled" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &.{ "--sec", test_sec, "ws://127.0.0.1:1", "{}" })).code);
    try std.testing.expectEqual(cli.exit_usage, (try runPublish(arena, &.{ "ws://127.0.0.1:1", "--sec" })).code);
    try std.testing.expectEqual(cli.exit_fail, (try runPublish(arena, &.{ "--auth", "--sec", "not-a-key", "ws://127.0.0.1:1", "{}" })).code);
}

test "an event is published through a CONNECT proxy and a SOCKS5 proxy" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    const proxy = @import("proxy.zig");

    for ([_]testrelay.Tunnel.Kind{ .connect, .socks5 }, [_][]const u8{ "http://", "socks5h://" }) |kind, scheme| {
        var yes: testrelay.Relay = undefined;
        try yes.start(io, .accept);
        defer yes.stop(io);
        var tun: testrelay.Tunnel = undefined;
        try tun.start(io, kind, 1);
        defer tun.stop(io);

        const saved = proxy.global;
        defer proxy.global = saved;
        var pb: [64]u8 = undefined;
        proxy.global = .{ .explicit = .{ .url = try tun.url(&pb, scheme), .name = "--proxy", .explicit = true } };

        const url = try std.fmt.allocPrint(arena, "ws://relay.example.test:{d}", .{yes.port()});
        const ev = try signedEvent(arena, io, "hello through a proxy");
        const id = try idOf(arena, ev);
        const r = try runPublish(arena, &.{ url, ev });
        try std.testing.expectEqual(cli.exit_ok, r.code);
        try std.testing.expect(contains(r.err, try std.fmt.allocPrint(arena, "deed publish: {s}: {s}: accepted\n", .{ id, url })));
        try std.testing.expectEqual(@as(usize, 1), yes.events.load(.monotonic));
        try std.testing.expectEqual(@as(usize, 1), tun.opened.load(.monotonic));
    }
}
