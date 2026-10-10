//! NIP-77 negentropy against one relay, and the plain reads around it.
//!
//! `reconcile` runs one negentropy session for a filter: this side holds a
//! set of (created_at, id) items, the relay holds its own, and at the end this
//! side knows which ids only it has (`have`) and which only the relay has
//! (`need`). No event body crosses the wire to learn that.
//!
//! A relay that does not speak NIP-77 says so in one of several ways: a
//! NOTICE about an unknown command, a CLOSED for the session, a message the
//! parser has no case for, or nothing at all. All of them come back as
//! `unsupported`, so the caller can fall back to a plain REQ. A relay that
//! does speak it and then refuses (NEG-ERR) or sends a reply that cannot be
//! read comes back as `failed`. Either way the caller still has a working
//! answer to give, which is the REQ it would have sent without NIP-77.
//!
//! Every wait is bounded by an absolute deadline the caller passes in, so a
//! run made of several steps shares one budget and no step waits past it.
//!
//! `fetchIds` and `collect` are the REQ side: events by id in batches, and
//! everything a filter matches. Both verify what arrives before handing it
//! over, because a relay can send anything.

const std = @import("std");
const nostr = @import("nostr");

const Io = std.Io;
const nip77 = nostr.nip77;
const message = nostr.message;
const relay = nostr.relay;
const ws = nostr.websocket;
const Filter = nostr.filter.Filter;
const Event = nostr.event.Event;

/// How long a relay gets to answer NEG-OPEN before it is taken not to
/// support NIP-77. A relay that does support it answers the first message
/// at once: it is one pass over its index.
pub const default_open_timeout_ms: i64 = 5_000;

/// The largest negentropy message this side produces. Work that does not fit
/// waits for a later round. Twice this in hex has to fit under the relay's
/// own message limit, and the library refuses anything over 1 MiB of hex, so
/// this stays well below both.
pub const default_frame_size_limit: u64 = 128 * 1024;

/// The negentropy session id. One session per connection at a time.
pub const neg_sub_id = "deed-neg";

/// The REQ subscription id `fetchIds` and `collect` use.
pub const req_sub_id = "deed-sync";

/// How many ids one REQ asks for. Relays cap the size of a filter, and a few
/// hundred ids is under every cap seen in practice.
pub const default_batch: usize = 250;

pub const Id = [32]u8;

/// An absolute instant `ms` milliseconds from now on the awake clock.
pub fn deadlineIn(io: Io, ms: i64) Io.Clock.Timestamp {
    return Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .raw = .fromMilliseconds(ms), .clock = .awake });
}

fn earlier(a: Io.Clock.Timestamp, b: Io.Clock.Timestamp) Io.Clock.Timestamp {
    return if (a.raw.nanoseconds <= b.raw.nanoseconds) a else b;
}

/// A short reason, held inline so an outcome owns nothing.
pub const Note = struct {
    buf: [240]u8 = undefined,
    len: usize = 0,
    /// The connection is gone, so a fallback has to dial again.
    lost: bool = false,

    fn of(lost: bool, comptime fmt: []const u8, args: anytype) Note {
        var n: Note = .{ .lost = lost };
        const s = std.fmt.bufPrint(&n.buf, fmt, args) catch blk: {
            const tail = "...";
            @memcpy(n.buf[n.buf.len - tail.len ..], tail);
            break :blk n.buf[0..];
        };
        n.len = s.len;
        sanitize(n.buf[0..n.len]);
        return n;
    }

    pub fn text(self: *const Note) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Replaces control characters, so text a relay wrote cannot drive the
/// terminal it is printed on.
pub fn sanitize(s: []u8) void {
    for (s) |*c| {
        if (c.* < 0x20 or c.* == 0x7f) c.* = '?';
    }
}

/// What one reconciliation found. Both lists are distinct ids. Owned.
pub const Diff = struct {
    /// Ids this side holds and the relay does not.
    have: []Id,
    /// Ids the relay holds and this side does not.
    need: []Id,
    /// Negentropy messages received.
    rounds: u32,

    pub fn deinit(self: *Diff, gpa: std.mem.Allocator) void {
        gpa.free(self.have);
        gpa.free(self.need);
        self.* = undefined;
    }
};

pub const Outcome = union(enum) {
    diff: Diff,
    /// The relay never engaged: no NEG-MSG came back for the session.
    unsupported: Note,
    /// The relay engaged and the session did not finish: NEG-ERR, a reply
    /// that could not be read, the deadline, or a lost connection.
    failed: Note,

    pub fn deinit(self: *Outcome, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .diff => |*d| d.deinit(gpa),
            else => {},
        }
    }
};

pub const Options = struct {
    /// Every wait in the session ends here.
    deadline: Io.Clock.Timestamp,
    /// How long to wait for the first reply before calling the relay
    /// unsupported. Capped by `deadline`.
    open_timeout_ms: i64 = default_open_timeout_ms,
    frame_size_limit: u64 = default_frame_size_limit,
    max_rounds: u32 = 10_000,
};

/// Sends one text frame on `r`. The library keeps its own sender private,
/// and has no NEG-* sender, so this builds the frame the way it does: masked,
/// under the connection's write lock, written whole.
pub fn sendText(gpa: std.mem.Allocator, r: *relay.Relay, text: []const u8) !void {
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    var mask: [4]u8 = undefined;
    r.io.randomSecure(&mask) catch return error.RandomFailed;
    try ws.appendClientFrame(&frame, gpa, .text, text, mask);
    r.conn.write_lock.lockUncancelable(r.io);
    defer r.conn.write_lock.unlock(r.io);
    try r.conn.stream.writeAll(frame.items);
}

fn sendNegClose(gpa: std.mem.Allocator, r: *relay.Relay) void {
    const text = message.encodeNegClose(gpa, neg_sub_id) catch return;
    defer gpa.free(text);
    sendText(gpa, r, text) catch {};
}

/// Whether a NOTICE reads as a relay turning down a command it does not know.
/// Relays word it in their own ways: strfry says "bad msg: unknown cmd",
/// others "unknown message type" or "unsupported". A notice that is about
/// something else (a welcome, a rate warning) is not taken as a refusal.
fn noticeRefuses(text: []const u8) bool {
    const words = [_][]const u8{ "unknown", "unsupported", "not supported", "neg-open", "negentropy", "bad msg", "invalid message", "unrecognized" };
    for (words) |w| {
        if (std.ascii.indexOfIgnoreCase(text, w) != null) return true;
    }
    return false;
}

const IdSet = std.AutoArrayHashMapUnmanaged(Id, void);

/// Runs one NIP-77 session against `r` for `filter`, from the items in
/// `storage`. The session is closed with NEG-CLOSE however it ends, except
/// after a NEG-ERR, which closes it on the relay's side.
///
/// Errors are the ones a caller cannot act on as an outcome, out of memory
/// above all. Everything the relay does comes back as the outcome.
pub fn reconcile(
    gpa: std.mem.Allocator,
    io: Io,
    r: *relay.Relay,
    filter: Filter,
    storage: *const nip77.Storage,
    opts: Options,
) !Outcome {
    var initiator = nip77.Initiator.init(storage, .{
        .frame_size_limit = opts.frame_size_limit,
        .max_rounds = opts.max_rounds,
    }) catch |e| return .{ .failed = .of(false, "negentropy could not start: {s}", .{@errorName(e)}) };

    {
        const first = initiator.initiate(gpa) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .failed = .of(false, "negentropy could not start: {s}", .{@errorName(e)}) },
        };
        defer gpa.free(first);
        const first_hex = try nip77.toHex(gpa, first);
        defer gpa.free(first_hex);
        const open = try message.encodeNegOpen(gpa, neg_sub_id, filter, first_hex);
        defer gpa.free(open);
        sendText(gpa, r, open) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .unsupported = .of(true, "the relay could not be written to: {s}", .{@errorName(e)}) },
        };
    }

    var have: IdSet = .empty;
    defer have.deinit(gpa);
    var need: IdSet = .empty;
    defer need.deinit(gpa);

    const open_deadline = earlier(opts.deadline, deadlineIn(io, opts.open_timeout_ms));
    var rounds: u32 = 0;
    var notice: Note = .{};

    while (true) {
        const engaged = rounds > 0;
        const wait_until = if (engaged) opts.deadline else open_deadline;
        var msg = (r.receiveTimeout(.{ .deadline = wait_until }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Timeout => {
                sendNegClose(gpa, r);
                if (engaged) return .{ .failed = .of(false, "the time ran out partway through", .{}) };
                if (notice.len > 0) return .{ .unsupported = .of(false, "no answer to NEG-OPEN; the relay said: {s}", .{notice.text()}) };
                return .{ .unsupported = .of(false, "no answer to NEG-OPEN", .{}) };
            },
            else => {
                const note: Note = .of(true, "the connection failed: {s}", .{@errorName(e)});
                return if (engaged) .{ .failed = note } else .{ .unsupported = note };
            },
        }) orelse {
            const note: Note = .of(true, "the relay closed the connection", .{});
            return if (engaged) .{ .failed = note } else .{ .unsupported = note };
        };
        defer msg.deinit();

        switch (msg.value) {
            .neg_msg => |m| {
                if (!std.mem.eql(u8, m.sub_id, neg_sub_id)) continue;
                rounds += 1;
                const bytes = nip77.fromHex(gpa, m.hex) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        sendNegClose(gpa, r);
                        return .{ .failed = .of(false, "the relay's reply is not hex", .{}) };
                    },
                };
                defer gpa.free(bytes);
                var step = initiator.reconcile(gpa, bytes) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        sendNegClose(gpa, r);
                        return .{ .failed = .of(false, "the relay's reply could not be read: {s}", .{@errorName(e)}) };
                    },
                };
                defer step.deinit(gpa);
                for (step.have) |id| try have.put(gpa, id, {});
                for (step.need) |id| try need.put(gpa, id, {});

                const next = step.message orelse {
                    sendNegClose(gpa, r);
                    const have_out = try gpa.dupe(Id, have.keys());
                    errdefer gpa.free(have_out);
                    const need_out = try gpa.dupe(Id, need.keys());
                    return .{ .diff = .{ .have = have_out, .need = need_out, .rounds = rounds } };
                };
                const next_hex = try nip77.toHex(gpa, next);
                defer gpa.free(next_hex);
                const text = try message.encodeNegMsg(gpa, neg_sub_id, next_hex);
                defer gpa.free(text);
                sendText(gpa, r, text) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return .{ .failed = .of(true, "the relay could not be written to: {s}", .{@errorName(e)}) },
                };
            },
            .neg_err => |e| {
                if (!std.mem.eql(u8, e.sub_id, neg_sub_id)) continue;
                const note: Note = .of(false, "NEG-ERR: {s}", .{e.reason});
                return if (engaged) .{ .failed = note } else .{ .unsupported = note };
            },
            .closed => |c| {
                if (!std.mem.eql(u8, c.subscription_id, neg_sub_id)) continue;
                const note: Note = .of(false, "CLOSED: {s}", .{c.message});
                return if (engaged) .{ .failed = note } else .{ .unsupported = note };
            },
            .notice => |n| {
                if (engaged) continue;
                if (noticeRefuses(n.message)) {
                    return .{ .unsupported = .of(false, "NOTICE: {s}", .{n.message}) };
                }
                notice = .of(false, "{s}", .{n.message});
            },
            else => {},
        }
    }
}

/// Builds a negentropy item set from events already in memory. Repeated ids
/// are kept once, and an event with a negative timestamp is left out, as the
/// store leaves it out.
pub fn storageFromEvents(gpa: std.mem.Allocator, events: []const Event) !nip77.Storage {
    var items: std.ArrayList(nip77.Item) = .empty;
    defer items.deinit(gpa);
    var seen: IdSet = .empty;
    defer seen.deinit(gpa);
    for (events) |ev| {
        if (ev.created_at < 0) continue;
        if ((try seen.fetchPut(gpa, ev.id, {})) != null) continue;
        try items.append(gpa, .{ .created_at = @intCast(ev.created_at), .id = ev.id });
    }
    return nip77.Storage.fromSlice(gpa, items.items);
}

/// Builds a negentropy item set from newline-delimited event JSON, as `req
/// --only-missing <file>` reads it. A line that is not an event is skipped
/// and counted in `skipped`.
pub fn storageFromJsonl(gpa: std.mem.Allocator, text: []const u8, skipped: *usize) !nip77.Storage {
    var items: std.ArrayList(nip77.Item) = .empty;
    defer items.deinit(gpa);
    var seen: IdSet = .empty;
    defer seen.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        var parsed = nostr.event.fromJson(gpa, line) catch {
            skipped.* += 1;
            continue;
        };
        defer parsed.deinit();
        const ev = parsed.value;
        if (ev.created_at < 0) continue;
        if ((try seen.fetchPut(gpa, ev.id, {})) != null) continue;
        try items.append(gpa, .{ .created_at = @intCast(ev.created_at), .id = ev.id });
    }
    return nip77.Storage.fromSlice(gpa, items.items);
}

/// What receives each event `fetchIds` or `collect` accepts. The event
/// borrows the message it came in, so it is valid only for the call.
pub const Sink = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, ev: Event) anyerror!void,

    fn put(self: Sink, ev: Event) !void {
        return self.func(self.ctx, ev);
    }
};

pub const ReadResult = struct {
    /// Events handed to the sink.
    delivered: usize = 0,
    /// Events dropped: not correctly signed, or not asked for.
    bad: usize = 0,
    /// The deadline passed before the relay finished.
    timed_out: bool = false,
    /// The connection went away.
    lost: bool = false,
    /// The relay closed the subscription; its reason, if so.
    closed: ?Note = null,
};

const Want = union(enum) {
    /// Only these ids, each once. The value is whether it has arrived.
    ids: *std.AutoHashMapUnmanaged(Id, bool),
    filter: Filter,
};

/// Reads one subscription to its EOSE.
fn drain(
    gpa: std.mem.Allocator,
    r: *relay.Relay,
    want: Want,
    verify: bool,
    signer: nostr.keys.Signer,
    sink: Sink,
    deadline: Io.Clock.Timestamp,
    result: *ReadResult,
) !void {
    while (true) {
        var msg = (r.receiveTimeout(.{ .deadline = deadline }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Timeout => {
                result.timed_out = true;
                return;
            },
            else => {
                result.lost = true;
                return;
            },
        }) orelse {
            result.lost = true;
            return;
        };
        defer msg.deinit();
        switch (msg.value) {
            .event => |e| {
                if (!std.mem.eql(u8, e.subscription_id, req_sub_id)) continue;
                const ev = e.event;
                switch (want) {
                    .ids => |m| {
                        const slot = m.getPtr(ev.id) orelse {
                            result.bad += 1;
                            continue;
                        };
                        if (slot.*) continue;
                        if (verify and !(try nostr.event.verify(gpa, signer, ev))) {
                            result.bad += 1;
                            continue;
                        }
                        slot.* = true;
                    },
                    .filter => |f| {
                        if (!f.matches(ev) or (verify and !(try nostr.event.verify(gpa, signer, ev)))) {
                            result.bad += 1;
                            continue;
                        }
                    },
                }
                try sink.put(ev);
                result.delivered += 1;
            },
            .eose => |e| if (std.mem.eql(u8, e.subscription_id, req_sub_id)) return,
            .closed => |c| if (std.mem.eql(u8, c.subscription_id, req_sub_id)) {
                result.closed = .of(false, "{s}", .{c.message});
                return;
            },
            else => {},
        }
    }
}

pub const ReadOptions = struct {
    deadline: Io.Clock.Timestamp,
    batch: usize = default_batch,
    /// Check each event's id and signature before handing it over. Off only
    /// where the events are counted rather than used.
    verify: bool = true,
};

/// Asks `r` for the events with `ids`, `batch` at a time, and hands each one
/// that arrives correctly signed to `sink`, once. An event a relay sends that
/// was not asked for is dropped. Stops early when the deadline passes or the
/// connection goes.
pub fn fetchIds(
    gpa: std.mem.Allocator,
    r: *relay.Relay,
    ids: []const Id,
    signer: nostr.keys.Signer,
    sink: Sink,
    opts: ReadOptions,
) !ReadResult {
    var result: ReadResult = .{};
    var wanted: std.AutoHashMapUnmanaged(Id, bool) = .empty;
    defer wanted.deinit(gpa);
    var start: usize = 0;
    while (start < ids.len) {
        const end = @min(ids.len, start + @max(opts.batch, 1));
        const batch = ids[start..end];
        start = end;
        wanted.clearRetainingCapacity();
        for (batch) |id| try wanted.put(gpa, id, false);
        const f: Filter = .{ .ids = batch, .limit = @intCast(batch.len) };
        r.subscribe(req_sub_id, &.{f}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                result.lost = true;
                return result;
            },
        };
        try drain(gpa, r, .{ .ids = &wanted }, opts.verify, signer, sink, opts.deadline, &result);
        if (result.lost or result.timed_out) return result;
        r.unsubscribe(req_sub_id) catch {};
    }
    return result;
}

/// Asks `r` for everything `filter` matches, to the relay's EOSE, and hands
/// each event that matches the filter (and, with `verify`, is correctly
/// signed) to `sink`. A relay can send an event twice; deduplicating is the
/// sink's business.
pub fn collect(
    gpa: std.mem.Allocator,
    r: *relay.Relay,
    filter: Filter,
    signer: nostr.keys.Signer,
    sink: Sink,
    opts: ReadOptions,
) !ReadResult {
    var result: ReadResult = .{};
    r.subscribe(req_sub_id, &.{filter}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            result.lost = true;
            return result;
        },
    };
    try drain(gpa, r, .{ .filter = filter }, opts.verify, signer, sink, opts.deadline, &result);
    if (!result.lost) r.unsubscribe(req_sub_id) catch {};
    return result;
}

// -- tests -------------------------------------------------------------------

const testrelay = @import("testrelay.zig");
const testing = std.testing;

/// A relay for tests that holds a set of signed events and answers REQ,
/// EVENT and, when `nip77` is set, the NEG-* messages with the library's
/// own responder over that set.
pub const SetRelay = struct {
    gpa: std.mem.Allocator = std.heap.page_allocator,
    /// Event JSON. EVENTs this relay accepts are appended.
    events: std.ArrayList([]const u8) = .empty,
    nip77: bool = true,
    /// What it does with NEG-OPEN when `nip77` is false.
    refusal: enum { notice, closed, silent } = .notice,
    /// Answer every NEG-OPEN with a negentropy message that cannot be read.
    malformed: bool = false,
    /// The responder's frame size limit. Small, so the test relay's frames
    /// stay under its 64 KiB writer and sessions take several rounds.
    frame_size_limit: u64 = 4096,
    neg_opens: usize = 0,
    reqs: usize = 0,
    storage: ?nip77.Storage = null,

    pub fn deinit(self: *SetRelay) void {
        for (self.events.items) |e| self.gpa.free(e);
        self.events.deinit(self.gpa);
        if (self.storage) |*s| s.deinit(self.gpa);
    }

    pub fn add(self: *SetRelay, json: []const u8) !void {
        try self.events.append(self.gpa, try self.gpa.dupe(u8, json));
    }

    /// The ids it holds.
    pub fn ids(self: *const SetRelay, gpa: std.mem.Allocator) !std.AutoHashMapUnmanaged(Id, void) {
        var out: std.AutoHashMapUnmanaged(Id, void) = .empty;
        errdefer out.deinit(gpa);
        for (self.events.items) |e| {
            var p = try nostr.event.fromJson(gpa, e);
            defer p.deinit();
            try out.put(gpa, p.value.id, {});
        }
        return out;
    }

    fn rebuild(self: *SetRelay, a: std.mem.Allocator, f: Filter) !void {
        if (self.storage) |*s| s.deinit(self.gpa);
        self.storage = null;
        var list: std.ArrayList(Event) = .empty;
        for (self.events.items) |e| {
            const p = try nostr.event.fromJson(a, e);
            if (f.matches(p.value)) try list.append(a, p.value);
        }
        self.storage = try storageFromEvents(self.gpa, list.items);
    }

    fn reply(self: *SetRelay, a: std.mem.Allocator, w: *Io.Writer, sub: []const u8, hex_in: []const u8) !void {
        if (self.malformed) {
            try testrelay.sendText(w, try message.encodeNegMsg(a, sub, "61ffff"));
            return;
        }
        const bytes = try nip77.fromHex(a, hex_in);
        var responder = try nip77.Responder.init(&self.storage.?, .{ .frame_size_limit = self.frame_size_limit });
        const out = try responder.reconcile(a, bytes);
        try testrelay.sendText(w, try message.encodeNegMsg(a, sub, try nip77.toHex(a, out)));
    }

    pub fn handle(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        const self: *SetRelay = @ptrCast(@alignCast(ctx.?));
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var parsed = try message.parseClientMessage(a, frame);
        defer parsed.deinit();
        switch (parsed.value) {
            .req => |q| {
                self.reqs += 1;
                for (self.events.items) |e| {
                    const p = try nostr.event.fromJson(a, e);
                    var hit = false;
                    for (q.filters) |f| hit = hit or f.matches(p.value);
                    if (!hit) continue;
                    try testrelay.sendText(w, try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ q.subscription_id, e }));
                }
                try testrelay.sendText(w, try message.encodeEose(a, q.subscription_id));
            },
            .event => |ev| {
                const json = try nostr.event.toJson(a, ev);
                try self.add(json);
                try testrelay.sendText(w, try message.encodeOk(a, ev.id, true, ""));
            },
            .neg_open => |o| {
                self.neg_opens += 1;
                if (!self.nip77) switch (self.refusal) {
                    .notice => return testrelay.sendText(w, "[\"NOTICE\",\"ERROR: bad msg: unknown cmd\"]"),
                    .closed => return testrelay.sendText(w, try message.encodeClosed(a, o.sub_id, "error: not supported")),
                    .silent => return,
                };
                try self.rebuild(a, o.filter);
                try self.reply(a, w, o.sub_id, o.initial_hex);
            },
            .neg_msg => |m| try self.reply(a, w, m.sub_id, m.hex),
            else => {},
        }
    }
};

/// `n` signed kind-1 events, as JSON, with timestamps that repeat so the
/// sets have ties to order by id.
pub fn signedEvents(a: std.mem.Allocator, n: usize, seed: u8) ![][]const u8 {
    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x21} ** 32);
    const out = try a.alloc([]const u8, n);
    for (out, 0..) |*o, i| {
        const t: i64 = 1_700_000_000 + @as(i64, @intCast(i / 3));
        const content = try std.fmt.allocPrint(a, "e{d}-{d}", .{ seed, i });
        const ev = try nostr.event.create(a, signer, kp, t, 1, &.{}, content, [_]u8{0} ** 32);
        o.* = try nostr.event.toJson(a, ev);
    }
    return out;
}

fn startSet(io: Io, rel: *testrelay.Relay, set: *SetRelay, url_buf: []u8) ![]const u8 {
    try rel.startCustom(io, SetRelay.handle, set);
    return testrelay.url(url_buf, rel.port());
}

fn eventsOf(a: std.mem.Allocator, jsons: []const []const u8) ![]Event {
    const out = try a.alloc(Event, jsons.len);
    for (jsons, out) |j, *e| e.* = (try nostr.event.fromJson(a, j)).value;
    return out;
}

test "random set differences come back as exactly what each side lacks" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for ([_]u64{ 1, 2, 3 }) |seed| {
        const all = try signedEvents(a, 300, @intCast(seed));
        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();

        var set: SetRelay = .{};
        defer set.deinit();
        var mine: std.ArrayList([]const u8) = .empty;
        var want_have: std.AutoHashMapUnmanaged(Id, void) = .empty;
        var want_need: std.AutoHashMapUnmanaged(Id, void) = .empty;
        for (all) |j| {
            const id = (try nostr.event.fromJson(a, j)).value.id;
            switch (rand.uintLessThan(u8, 4)) {
                0 => {
                    try mine.append(a, j);
                    try want_have.put(a, id, {});
                },
                1 => {
                    try set.add(j);
                    try want_need.put(a, id, {});
                },
                else => {
                    try mine.append(a, j);
                    try set.add(j);
                },
            }
        }

        var rel: testrelay.Relay = undefined;
        var url_buf: [40]u8 = undefined;
        const url = try startSet(io, &rel, &set, &url_buf);
        defer rel.stop(io);
        const r = try relay.dial(gpa, io, url);
        defer r.deinit();

        var storage = try storageFromEvents(gpa, try eventsOf(a, mine.items));
        defer storage.deinit(gpa);
        var outcome = try reconcile(gpa, io, r, .{ .kinds = &.{1} }, &storage, .{
            .deadline = deadlineIn(io, 10_000),
            .frame_size_limit = 4096,
        });
        defer outcome.deinit(gpa);
        const d = outcome.diff;
        try testing.expectEqual(want_have.count(), d.have.len);
        try testing.expectEqual(want_need.count(), d.need.len);
        for (d.have) |id| try testing.expect(want_have.contains(id));
        for (d.need) |id| try testing.expect(want_need.contains(id));
        try testing.expect(d.rounds > 1);
    }
}

test "an empty local set learns every id the relay holds" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var set: SetRelay = .{};
    defer set.deinit();
    for (try signedEvents(a, 200, 9)) |j| try set.add(j);
    var rel: testrelay.Relay = undefined;
    var url_buf: [40]u8 = undefined;
    const url = try startSet(io, &rel, &set, &url_buf);
    defer rel.stop(io);
    const r = try relay.dial(gpa, io, url);
    defer r.deinit();

    var storage = try nip77.Storage.fromSlice(gpa, &.{});
    defer storage.deinit(gpa);
    var outcome = try reconcile(gpa, io, r, .{}, &storage, .{ .deadline = deadlineIn(io, 10_000) });
    defer outcome.deinit(gpa);
    try testing.expectEqual(@as(usize, 200), outcome.diff.need.len);
    try testing.expectEqual(@as(usize, 0), outcome.diff.have.len);
}

test "a relay without NIP-77 is reported as unsupported, however it says so" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var storage = try nip77.Storage.fromSlice(gpa, &.{});
    defer storage.deinit(gpa);

    for ([_]@FieldType(SetRelay, "refusal"){ .notice, .closed, .silent }) |how| {
        var set: SetRelay = .{ .nip77 = false, .refusal = how };
        defer set.deinit();
        var rel: testrelay.Relay = undefined;
        var url_buf: [40]u8 = undefined;
        const url = try startSet(io, &rel, &set, &url_buf);
        defer rel.stop(io);
        const r = try relay.dial(gpa, io, url);
        defer r.deinit();

        const started = Io.Timestamp.now(io, .awake).toMilliseconds();
        var outcome = try reconcile(gpa, io, r, .{}, &storage, .{
            .deadline = deadlineIn(io, 10_000),
            .open_timeout_ms = 300,
        });
        defer outcome.deinit(gpa);
        const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
        try testing.expect(outcome == .unsupported);
        try testing.expect(!outcome.unsupported.lost);
        try testing.expect(took < 5_000);
        // A NOTICE or a CLOSED is an answer, and is acted on at once.
        if (how != .silent) try testing.expect(took < 250);
    }
}

test "a malformed NEG-MSG ends the session instead of hanging it" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var set: SetRelay = .{ .malformed = true };
    defer set.deinit();
    var rel: testrelay.Relay = undefined;
    var url_buf: [40]u8 = undefined;
    const url = try startSet(io, &rel, &set, &url_buf);
    defer rel.stop(io);
    const r = try relay.dial(gpa, io, url);
    defer r.deinit();

    var storage = try nip77.Storage.fromSlice(gpa, &.{});
    defer storage.deinit(gpa);
    var outcome = try reconcile(gpa, io, r, .{}, &storage, .{ .deadline = deadlineIn(io, 10_000) });
    defer outcome.deinit(gpa);
    try testing.expect(outcome == .failed);
    try testing.expect(std.mem.indexOf(u8, outcome.failed.text(), "Malformed") != null);
}

test "fetchIds hands over each asked-for event once, verified" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var set: SetRelay = .{};
    defer set.deinit();
    const all = try signedEvents(a, 30, 4);
    for (all) |j| try set.add(j);
    var rel: testrelay.Relay = undefined;
    var url_buf: [40]u8 = undefined;
    const url = try startSet(io, &rel, &set, &url_buf);
    defer rel.stop(io);
    const r = try relay.dial(gpa, io, url);
    defer r.deinit();

    var ids: [10]Id = undefined;
    for (&ids, 0..) |*id, i| id.* = (try nostr.event.fromJson(a, all[i * 3])).value.id;

    const Count = struct {
        n: usize = 0,
        fn put(ctx: *anyopaque, _: Event) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.n += 1;
        }
    };
    var count: Count = .{};
    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const res = try fetchIds(gpa, r, &ids, signer, .{ .ctx = &count, .func = Count.put }, .{
        .deadline = deadlineIn(io, 10_000),
        .batch = 4,
    });
    try testing.expectEqual(@as(usize, 10), res.delivered);
    try testing.expectEqual(@as(usize, 10), count.n);
    try testing.expectEqual(@as(usize, 3), set.reqs);
}

test "a notice that is not a refusal is not taken as one" {
    try testing.expect(noticeRefuses("ERROR: bad msg: unknown cmd"));
    try testing.expect(noticeRefuses("NEG-OPEN is not supported here"));
    try testing.expect(!noticeRefuses("welcome to the relay"));
}

test "a reason a relay wrote cannot carry terminal controls" {
    const n: Note = .of(false, "NOTICE: {s}", .{"a\x1b[2Jb\n"});
    try testing.expectEqualStrings("NOTICE: a?[2Jb?", n.text());
}
