//! `deed sync`: find what one side has and the other lacks with NIP-77
//! negentropy, then copy it across.
//!
//! Three shapes. Relay to relay: learn the ids each relay holds for the
//! filter, then fetch what the destination lacks from the source, by id, and
//! publish it to the destination. Relay and store: reconcile the store's items
//! against the relay, then pull what the store lacks, push what the relay
//! lacks, or both.
//!
//! Learning a relay's ids costs 32 bytes an event and no bodies: a negentropy
//! session started from an empty set is answered with the relay's whole id
//! list. Between a store and a relay it costs less again, because only the
//! ranges that differ are ever listed.
//!
//! A relay that does not speak NIP-77 is asked the same question with a plain
//! REQ instead, with a warning, so a sync still happens: it only costs more.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const filterflags = @import("filterflags.zig");
const storepath = @import("storepath.zig");
const negclient = @import("negclient.zig");

const Io = std.Io;
const relay = nostr.relay;
const nip77 = nostr.nip77;
const Filter = nostr.filter.Filter;
const Event = nostr.event.Event;
const Id = negclient.Id;

/// Shown beside the name in `deed help`.
pub const summary = "copy what is missing between relays or a store, with NIP-77";

pub const ready = true;

pub const usage =
    \\deed sync: copy what is missing between relays or a store, with NIP-77
    \\
    \\Usage:
    \\  deed sync [options] <from-relay> <to-relay>
    \\  deed sync [options] <relay> --store <path>     pull into the store
    \\  deed sync [options] --store <path> <relay>     push from the store
    \\
    \\Options:
    \\  -k, -a, -i, -e, -p, -t, -d, -h, -T, -s, -u, -l, --search
    \\                       the filter, as `deed req` takes them; a filter can
    \\                       also be given as one JSON object argument
    \\      --store <path>   a local store, as one side of the sync
    \\      --direction <d>  pull, push or both, with --store; overrides the
    \\                       order of the arguments
    \\  -q, --quiet          print one line of counts instead of the events
    \\      --timeout <ms>   give up on the whole sync after this (default 60000)
    \\
    \\Relay to relay, every event the first relay holds for the filter and the
    \\second lacks is fetched from the first, checked, and published to the
    \\second. With a store, the order says which way: the relay first pulls
    \\into the store, the store first pushes to the relay. --direction both
    \\does both from one reconciliation.
    \\
    \\Each event that lands is printed as one line of JSON: published events
    \\the relay accepted, and pulled events that were new to the store.
    \\
    \\A relay that does not support NIP-77 is named on stderr and asked with a
    \\plain REQ instead, which downloads what the filter matches rather than
    \\only the ids.
    \\
    \\Exits: 0 when everything missing was copied; 1 if a relay could not be
    \\reached, refused an event, or an event could not be fetched; 2 if the
    \\command line was not understood.
    \\
;

pub const default_timeout_ms: i64 = 60_000;

pub const Direction = enum { pull, push, both };

const Shape = union(enum) {
    relays: struct { from: []const u8, to: []const u8 },
    store: struct { url: []const u8, path: []const u8, direction: Direction },
};

const Request = struct {
    shape: Shape,
    filter: Filter,
    quiet: bool,
    timeout_ms: i64,
};

const ParseError = filterflags.ParseError;

fn parse(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    args: []const []const u8,
    flags: *filterflags.Flags,
    err: *std.Io.Writer,
) !?Request {
    var relays: [2][]const u8 = undefined;
    var n_relays: usize = 0;
    var store_path: ?[]const u8 = null;
    var store_first = false;
    var direction: ?Direction = null;
    var quiet = false;
    var timeout_ms: i64 = default_timeout_ms;
    var json: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "--help" })) return null;
        if (std.mem.eql(u8, a, "-h") and i + 1 >= args.len) return null;
        if (cli.isOneOf(a, &.{ "-q", "--quiet" })) {
            quiet = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "{")) {
            if (json != null) {
                try err.writeAll("deed sync: NIP-77 reconciles one filter, and two were given\n");
                return ParseError.Usage;
            }
            json = a;
            continue;
        }
        if (!std.mem.startsWith(u8, a, "-")) {
            if (n_relays == 2) {
                try err.writeAll("deed sync: too many relays; sync takes two, or one and --store\n");
                return ParseError.Usage;
            }
            relays[n_relays] = a;
            n_relays += 1;
            continue;
        }
        const takes_value = filterflags.isFilterFlag(a) or
            cli.isOneOf(a, &.{ "--store", "--timeout", "--direction" });
        if (!takes_value) {
            try err.print("deed sync: unknown option '{s}'\n", .{a});
            return ParseError.Usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed sync: '{s}' needs a value\n", .{a});
            return ParseError.Usage;
        }
        const v = args[i];
        if (filterflags.isFilterFlag(a)) {
            try flags.accept(gpa, "sync", a, v, err);
        } else if (std.mem.eql(u8, a, "--store")) {
            store_path = v;
            store_first = n_relays == 0;
        } else if (std.mem.eql(u8, a, "--timeout")) {
            timeout_ms = std.fmt.parseInt(i64, v, 10) catch -1;
            if (timeout_ms <= 0) {
                try err.print("deed sync: '{s}' is not a number of milliseconds\n", .{v});
                return ParseError.BadValue;
            }
        } else if (std.mem.eql(u8, a, "--direction")) {
            direction = std.meta.stringToEnum(Direction, v) orelse {
                try err.print("deed sync: '{s}' is not a direction; it is pull, push or both\n", .{v});
                return ParseError.Usage;
            };
        }
    }

    var f = flags.finish();
    if (json) |text| {
        const base = try filterflags.parseJson(arena, "sync", text, err);
        f = if (flags.any()) try filterflags.overlay(arena, base, f) else base;
    }

    const shape: Shape = if (store_path) |path| blk: {
        if (n_relays != 1) {
            try err.writeAll("deed sync: with --store, name exactly one relay\n");
            return ParseError.Usage;
        }
        break :blk .{ .store = .{
            .url = relays[0],
            .path = path,
            .direction = direction orelse if (store_first) .push else .pull,
        } };
    } else blk: {
        if (direction != null) {
            try err.writeAll("deed sync: --direction is for --store; between relays the order of the two says which way\n");
            return ParseError.Usage;
        }
        if (n_relays != 2) {
            try err.writeAll("deed sync: name a relay to copy from and a relay to copy to, or one relay and --store\n");
            return ParseError.Usage;
        }
        break :blk .{ .relays = .{ .from = relays[0], .to = relays[1] } };
    };
    return .{ .shape = shape, .filter = f, .quiet = quiet, .timeout_ms = timeout_ms };
}

/// What one run did, for the exit code and for --quiet.
const Stats = struct {
    /// Ids found on one side and not the other, in the direction being copied.
    missing: usize = 0,
    /// Events that landed: accepted by the relay, or new to the store.
    landed: usize = 0,
    /// Refused by the relay or the store, or not answered in time.
    refused: usize = 0,
    /// Missing, and the side that holds them did not send them.
    not_found: usize = 0,
    /// Sent though not asked for, or not correctly signed.
    bad: usize = 0,
    /// A relay could not be reached, or went away partway.
    unreachable_relay: bool = false,

    fn ok(self: Stats) bool {
        return self.refused == 0 and self.not_found == 0 and !self.unreachable_relay;
    }
};

const Ctx = struct {
    gpa: std.mem.Allocator,
    io: Io,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    filter: Filter,
    quiet: bool,
    deadline: Io.Clock.Timestamp,
    signer: nostr.keys.Signer,
    stats: Stats = .{},

    fn remainingMs(self: *const Ctx) i64 {
        const now = Io.Clock.Timestamp.now(self.io, .awake);
        const left = now.durationTo(self.deadline).raw.toMilliseconds();
        return @max(left, 1);
    }

    /// Dials `url` under the dial timeout and what is left of the run.
    fn connect(self: *Ctx, url: []const u8) !?*relay.Relay {
        var outcome: [1]dial.Outcome = undefined;
        dial.all(self.gpa, self.io, &.{url}, @min(dial.default_timeout_ms, self.remainingMs()), &outcome);
        switch (outcome[0]) {
            .connected => |r| return r,
            .failed => |e| try self.err.print("deed sync: {s}: could not connect: {s}\n", .{ url, @errorName(e) }),
            .timed_out => try self.err.print("deed sync: {s}: did not answer in time\n", .{url}),
        }
        self.stats.unreachable_relay = true;
        return null;
    }

    fn print(self: *Ctx, ev: Event) !void {
        self.stats.landed += 1;
        if (self.quiet) return;
        const json = try nostr.event.toJson(self.gpa, ev);
        defer self.gpa.free(json);
        try self.out.print("{s}\n", .{json});
    }

    fn readOptions(self: *const Ctx, verify: bool) negclient.ReadOptions {
        return .{ .deadline = self.deadline, .verify = verify };
    }

    fn noteRead(self: *Ctx, url: []const u8, res: negclient.ReadResult) !void {
        self.stats.bad += res.bad;
        if (res.bad > 0) try self.err.print("deed sync: {s}: dropped {d} events that were not asked for or not correctly signed\n", .{ url, res.bad });
        if (res.closed) |c| try self.err.print("deed sync: {s}: the relay closed the request: {s}\n", .{ url, c.text() });
        if (res.timed_out) try self.err.print("deed sync: {s}: the time ran out\n", .{url});
        if (res.lost) {
            try self.err.print("deed sync: {s}: the connection went away\n", .{url});
            self.stats.unreachable_relay = true;
        }
    }

    fn noFallbackNote(self: *Ctx, url: []const u8, note: *const negclient.Note) !void {
        try self.err.print("deed sync: {s}: no NIP-77 ({s}); asking with a plain REQ instead\n", .{ url, note.text() });
    }
};

/// Events held between fetching and using them. Each owns its memory: the
/// JSON it was parsed from as well, because a parsed event borrows its
/// strings from the text.
const Held = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayList(Entry) = .empty,
    seen: std.AutoHashMapUnmanaged(Id, void) = .empty,

    const Entry = struct { json: []u8, parsed: nostr.event.Parsed };

    fn deinit(self: *Held) void {
        for (self.list.items) |*e| {
            e.parsed.deinit();
            self.gpa.free(e.json);
        }
        self.list.deinit(self.gpa);
        self.seen.deinit(self.gpa);
    }

    fn put(ctx: *anyopaque, ev: Event) anyerror!void {
        const self: *Held = @ptrCast(@alignCast(ctx));
        if ((try self.seen.fetchPut(self.gpa, ev.id, {})) != null) return;
        const json = try nostr.event.toJson(self.gpa, ev);
        errdefer self.gpa.free(json);
        var p = try nostr.event.fromJson(self.gpa, json);
        errdefer p.deinit();
        try self.list.append(self.gpa, .{ .json = json, .parsed = p });
    }

    fn sink(self: *Held) negclient.Sink {
        return .{ .ctx = self, .func = put };
    }

    fn events(self: *const Held, buf: *std.ArrayList(Event)) !void {
        buf.clearRetainingCapacity();
        for (self.list.items) |e| try buf.append(self.gpa, e.parsed.value);
    }
};

/// Ids alone, for a side whose events are only counted.
const IdsOnly = struct {
    gpa: std.mem.Allocator,
    set: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,

    fn put(ctx: *anyopaque, ev: Event) anyerror!void {
        const self: *IdsOnly = @ptrCast(@alignCast(ctx));
        try self.set.put(self.gpa, ev.id, {});
    }

    fn sink(self: *IdsOnly) negclient.Sink {
        return .{ .ctx = self, .func = put };
    }
};

fn publishEach(r: *relay.Relay, events: []const Event, sent: *usize) anyerror!void {
    for (events) |ev| {
        try r.publish(ev);
        sent.* += 1;
    }
}

/// Offers `events` to `r` and waits for each one's OK, printing the accepted
/// ones. All are sent before any answer is read, so a batch costs one round
/// trip rather than one an event. The sending is bounded by the deadline as
/// the reading is: a relay that stops reading fills the socket, and a write
/// into a full socket would otherwise wait for room forever.
fn publish(ctx: *Ctx, r: *relay.Relay, url: []const u8, events: []const Event) !void {
    if (events.len == 0) return;
    const gpa = ctx.gpa;
    var sent: usize = 0;
    negclient.writeBy(ctx.io, ctx.deadline, publishEach, .{ r, events, &sent }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        error.Timeout => {
            try ctx.err.print("deed sync: {s}: the relay stopped reading; {d} of {d} events were sent before the time ran out\n", .{ url, sent, events.len });
            ctx.stats.unreachable_relay = true;
            ctx.stats.refused += events.len;
            return;
        },
        else => {
            try ctx.err.print("deed sync: {s}: the connection went away while publishing\n", .{url});
            ctx.stats.unreachable_relay = true;
            ctx.stats.refused += events.len;
            return;
        },
    };
    var pending: std.AutoHashMapUnmanaged(Id, usize) = .empty;
    defer pending.deinit(gpa);
    for (events, 0..) |ev, i| try pending.put(gpa, ev.id, i);
    while (pending.count() > 0) {
        var msg = (r.receiveTimeout(.{ .deadline = ctx.deadline }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Timeout => {
                try ctx.err.print("deed sync: {s}: {d} events were not answered in time\n", .{ url, pending.count() });
                ctx.stats.refused += pending.count();
                return;
            },
            else => null,
        }) orelse {
            try ctx.err.print("deed sync: {s}: the connection went away with {d} events unanswered\n", .{ url, pending.count() });
            ctx.stats.unreachable_relay = true;
            ctx.stats.refused += pending.count();
            return;
        };
        defer msg.deinit();
        switch (msg.value) {
            .ok => |o| {
                const kv = pending.fetchRemove(o.event_id) orelse continue;
                if (o.accepted) {
                    try ctx.print(events[kv.value]);
                } else {
                    ctx.stats.refused += 1;
                    const reason = try gpa.dupe(u8, o.message);
                    defer gpa.free(reason);
                    negclient.sanitize(reason);
                    const id_hex = std.fmt.bytesToHex(o.event_id, .lower);
                    try ctx.err.print("deed sync: {s}: refused {s}: {s}\n", .{ url, &id_hex, reason });
                }
            },
            else => {},
        }
    }
}

fn publishAll(ctx: *Ctx, r: *relay.Relay, url: []const u8, events: []const Event) !void {
    var start: usize = 0;
    while (start < events.len) : (start += negclient.default_batch) {
        try publish(ctx, r, url, events[start..@min(events.len, start + negclient.default_batch)]);
        if (ctx.stats.unreachable_relay) return;
    }
}

/// The ids `r` holds for the filter: from a negentropy session started from
/// an empty set, or from a REQ when the relay will not do that. With `keep`, a
/// REQ's events are kept there too, so they need not be fetched again.
fn relayIds(ctx: *Ctx, conn: **relay.Relay, url: []const u8, keep: *Held, keep_bodies: bool) !?[]Id {
    const gpa = ctx.gpa;
    var empty = try nip77.Storage.fromSlice(gpa, &.{});
    defer empty.deinit(gpa);
    const outcome = try negclient.reconcile(gpa, ctx.io, conn.*, ctx.filter, &empty, .{ .deadline = ctx.deadline });
    switch (outcome) {
        .diff => |d| {
            gpa.free(d.have);
            return d.need;
        },
        .unsupported, .failed => |note| {
            try ctx.noFallbackNote(url, &note);
            if (note.lost) {
                negclient.release(conn.*, ctx.deadline);
                conn.* = (try ctx.connect(url)) orelse return null;
            }
        },
    }
    var ids: IdsOnly = .{ .gpa = gpa };
    defer ids.set.deinit(gpa);
    const res = if (keep_bodies)
        try negclient.collect(gpa, conn.*, ctx.filter, ctx.signer, keep.sink(), ctx.readOptions(true))
    else
        try negclient.collect(gpa, conn.*, ctx.filter, ctx.signer, ids.sink(), ctx.readOptions(false));
    try ctx.noteRead(url, res);
    if (res.lost) return null;
    if (keep_bodies) {
        var it = keep.seen.keyIterator();
        while (it.next()) |id| try ids.set.put(gpa, id.*, {});
    }
    return try gpa.dupe(Id, ids.set.keys());
}

fn betweenRelays(ctx: *Ctx, from_url: []const u8, to_url: []const u8) !void {
    const gpa = ctx.gpa;
    var from = (try ctx.connect(from_url)) orelse return;
    defer negclient.release(from, ctx.deadline);
    var to = (try ctx.connect(to_url)) orelse return;
    defer negclient.release(to, ctx.deadline);

    var kept: Held = .{ .gpa = gpa };
    defer kept.deinit();
    const from_ids = (try relayIds(ctx, &from, from_url, &kept, true)) orelse return;
    defer gpa.free(from_ids);
    var unused: Held = .{ .gpa = gpa };
    defer unused.deinit();
    const to_ids = (try relayIds(ctx, &to, to_url, &unused, false)) orelse return;
    defer gpa.free(to_ids);

    var on_to: std.AutoHashMapUnmanaged(Id, void) = .empty;
    defer on_to.deinit(gpa);
    for (to_ids) |id| try on_to.put(gpa, id, {});
    var missing: std.ArrayList(Id) = .empty;
    defer missing.deinit(gpa);
    for (from_ids) |id| if (!on_to.contains(id)) try missing.append(gpa, id);
    ctx.stats.missing += missing.items.len;

    var evs: std.ArrayList(Event) = .empty;
    defer evs.deinit(gpa);

    // The source answered a plain REQ, so its events are already here.
    if (kept.list.items.len > 0) {
        for (kept.list.items) |e| if (!on_to.contains(e.parsed.value.id)) try evs.append(gpa, e.parsed.value);
        return publishAll(ctx, to, to_url, evs.items);
    }

    var start: usize = 0;
    while (start < missing.items.len) {
        const end = @min(missing.items.len, start + negclient.default_batch);
        const batch = missing.items[start..end];
        start = end;
        var got: Held = .{ .gpa = gpa };
        defer got.deinit();
        const res = try negclient.fetchIds(gpa, from, batch, ctx.signer, got.sink(), ctx.readOptions(true));
        try ctx.noteRead(from_url, res);
        ctx.stats.not_found += batch.len - got.list.items.len;
        try got.events(&evs);
        try publish(ctx, to, to_url, evs.items);
        if (res.lost or res.timed_out or ctx.stats.unreachable_relay) return;
    }
}

/// Stores what `held` has in one transaction and prints what was new.
fn ingest(ctx: *Ctx, store: *nostr.store.Store, held: *const Held) !void {
    const gpa = ctx.gpa;
    var evs: std.ArrayList(Event) = .empty;
    defer evs.deinit(gpa);
    try held.events(&evs);
    if (evs.items.len == 0) return;
    const results = try gpa.alloc(nostr.store.IngestResult, evs.items.len);
    defer gpa.free(results);
    // Every event here was verified as it arrived.
    store.ingestBatch(gpa, evs.items, .{}, results) catch |e| {
        try ctx.err.print("deed sync: the store could not take the events: {s}\n", .{@errorName(e)});
        ctx.stats.refused += evs.items.len;
        return;
    };
    for (evs.items, results) |ev, res| switch (res) {
        .added, .replaced => try ctx.print(ev),
        else => {},
    };
}

fn pullIds(ctx: *Ctx, r: *relay.Relay, url: []const u8, store: *nostr.store.Store, ids: []const Id) !void {
    var start: usize = 0;
    while (start < ids.len) {
        const end = @min(ids.len, start + negclient.default_batch);
        const batch = ids[start..end];
        start = end;
        var got: Held = .{ .gpa = ctx.gpa };
        defer got.deinit();
        const res = try negclient.fetchIds(ctx.gpa, r, batch, ctx.signer, got.sink(), ctx.readOptions(true));
        try ctx.noteRead(url, res);
        ctx.stats.not_found += batch.len - got.list.items.len;
        try ingest(ctx, store, &got);
        if (res.lost or res.timed_out) return;
    }
}

fn pushIds(ctx: *Ctx, r: *relay.Relay, url: []const u8, store: *nostr.store.Store, ids: []const Id) !void {
    var start: usize = 0;
    while (start < ids.len) {
        const end = @min(ids.len, start + negclient.default_batch);
        const batch = ids[start..end];
        start = end;
        var found = store.query(ctx.gpa, .{ .ids = batch }) catch |e| {
            try ctx.err.print("deed sync: the store could not be read: {s}\n", .{@errorName(e)});
            ctx.stats.not_found += batch.len;
            return;
        };
        defer found.deinit();
        ctx.stats.not_found += batch.len - found.events.len;
        try publish(ctx, r, url, found.events);
        if (ctx.stats.unreachable_relay) return;
    }
}

fn withStore(ctx: *Ctx, url: []const u8, path: []const u8, direction: Direction) !u8 {
    const gpa = ctx.gpa;
    var store = (try storepath.open(gpa, ctx.io, "sync", path, if (direction == .push) .existing else .create, ctx.err)) orelse return cli.exit_fail;
    defer store.deinit();

    var r = (try ctx.connect(url)) orelse return cli.exit_fail;
    defer negclient.release(r, ctx.deadline);

    var storage = nip77.Storage.fromStore(gpa, &store, ctx.filter) catch |e| {
        try ctx.err.print("deed sync: the store could not be read: {s}\n", .{@errorName(e)});
        return cli.exit_fail;
    };
    defer storage.deinit(gpa);

    var outcome = try negclient.reconcile(gpa, ctx.io, r, ctx.filter, &storage, .{ .deadline = ctx.deadline });
    defer outcome.deinit(gpa);
    switch (outcome) {
        .diff => |d| {
            if (direction != .push) {
                ctx.stats.missing += d.need.len;
                try pullIds(ctx, r, url, &store, d.need);
            }
            if (direction != .pull and !ctx.stats.unreachable_relay) {
                ctx.stats.missing += d.have.len;
                try pushIds(ctx, r, url, &store, d.have);
            }
            return cli.exit_ok;
        },
        .unsupported, .failed => |note| {
            try ctx.noFallbackNote(url, &note);
            if (note.lost) {
                negclient.release(r, ctx.deadline);
                r = (try ctx.connect(url)) orelse return cli.exit_fail;
            }
        },
    }

    // The relay's side of the filter, whole.
    var held: Held = .{ .gpa = gpa };
    defer held.deinit();
    const res = try negclient.collect(gpa, r, ctx.filter, ctx.signer, held.sink(), ctx.readOptions(true));
    try ctx.noteRead(url, res);
    if (res.lost) return cli.exit_fail;

    if (direction != .pull) {
        var mine = store.query(gpa, ctx.filter) catch |e| {
            try ctx.err.print("deed sync: the store could not be read: {s}\n", .{@errorName(e)});
            return cli.exit_fail;
        };
        defer mine.deinit();
        var lacking: std.ArrayList(Event) = .empty;
        defer lacking.deinit(gpa);
        for (mine.events) |ev| if (!held.seen.contains(ev.id)) try lacking.append(gpa, ev);
        ctx.stats.missing += lacking.items.len;
        try publishAll(ctx, r, url, lacking.items);
    }
    if (direction != .push) {
        for (held.list.items) |e| {
            if (!(store.hasEvent(e.parsed.value.id) catch false)) ctx.stats.missing += 1;
        }
        try ingest(ctx, &store, &held);
    }
    return cli.exit_ok;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var flags: filterflags.Flags = .{};
    const req = (parse(gpa, arena_state.allocator(), args, &flags, err) catch |e| return switch (e) {
        ParseError.Usage => cli.exit_usage,
        ParseError.BadValue => cli.exit_fail,
        else => e,
    }) orelse {
        try out.writeAll(usage);
        return cli.exit_ok;
    };

    var ctx: Ctx = .{
        .gpa = gpa,
        .io = io,
        .out = out,
        .err = err,
        .filter = req.filter,
        .quiet = req.quiet,
        .deadline = negclient.deadlineIn(io, req.timeout_ms),
        .signer = nostr.keys.Signer.init(),
    };
    defer ctx.signer.deinit();

    var code = switch (req.shape) {
        .relays => |p| blk: {
            try betweenRelays(&ctx, p.from, p.to);
            break :blk cli.exit_ok;
        },
        .store => |s| try withStore(&ctx, s.url, s.path, s.direction),
    };
    const st = ctx.stats;
    if (req.quiet) {
        try out.print("{d} missing, {d} copied, {d} refused, {d} not found\n", .{ st.missing, st.landed, st.refused, st.not_found });
    }
    if (code == cli.exit_ok and !st.ok()) code = cli.exit_fail;
    return code;
}

// -- tests -------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");
const SetRelay = negclient.SetRelay;

test {
    _ = negclient;
}

const Run = struct { code: u8, out: []const u8, err: []const u8 };

fn runSync(gpa: std.mem.Allocator, args: []const []const u8, ob: []u8, eb: []u8) !Run {
    var out: std.Io.Writer = .fixed(ob);
    var err: std.Io.Writer = .fixed(eb);
    const code = try run(gpa, testing.io, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

fn countLines(s: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, '\n');
    while (it.next()) |l| {
        if (l.len > 0) n += 1;
    }
    return n;
}

const Split = struct { x_only: usize, y_only: usize };

/// Splits `all` at random between two sets: some on both, some on one only.
fn split(all: []const []const u8, seed: u64, x: *SetRelay, y: *SetRelay) !Split {
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var s: Split = .{ .x_only = 0, .y_only = 0 };
    for (all) |j| switch (rand.uintLessThan(u8, 4)) {
        0 => {
            try x.add(j);
            s.x_only += 1;
        },
        1 => {
            try y.add(j);
            s.y_only += 1;
        },
        else => {
            try x.add(j);
            try y.add(j);
        },
    };
    return s;
}

/// Every id `want` holds is in `have`.
fn holdsAll(gpa: std.mem.Allocator, have: *const SetRelay, want: *const SetRelay) !bool {
    var h = try have.ids(gpa);
    defer h.deinit(gpa);
    var w = try want.ids(gpa);
    defer w.deinit(gpa);
    var it = w.keyIterator();
    while (it.next()) |id| if (!h.contains(id.*)) return false;
    return true;
}

fn syncRelays(src: *SetRelay, dst: *SetRelay, extra: []const []const u8, ob: []u8, eb: []u8) !Run {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the sync leaked");
    const gpa = da.allocator();

    var rs: testrelay.Relay = undefined;
    try rs.startCustom(io, SetRelay.handle, src);
    defer rs.stop(io);
    var rd: testrelay.Relay = undefined;
    try rd.startCustom(io, SetRelay.handle, dst);
    defer rd.stop(io);
    var b1: [40]u8 = undefined;
    var b2: [40]u8 = undefined;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, extra);
    try argv.append(gpa, try testrelay.url(&b1, rs.port()));
    try argv.append(gpa, try testrelay.url(&b2, rd.port()));
    return runSync(gpa, argv.items, ob, eb);
}

test "relay to relay: what the destination lacks is copied, and only that" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]u64{ 11, 12 }) |seed| {
        const all = try negclient.signedEvents(a, 120, @intCast(seed));
        var src: SetRelay = .{};
        defer src.deinit();
        var dst: SetRelay = .{};
        defer dst.deinit();
        const parts = try split(all, seed, &src, &dst);
        const src_before = src.events.items.len;

        const ob = try a.alloc(u8, 1 << 20);
        var eb: [4096]u8 = undefined;
        const r = try syncRelays(&src, &dst, &.{}, ob, &eb);
        try testing.expectEqualStrings("", r.err);
        try testing.expectEqual(cli.exit_ok, r.code);
        try testing.expectEqual(parts.x_only, countLines(r.out));
        try testing.expect(try holdsAll(testing.allocator, &dst, &src));
        // The copy goes one way: the source was not written to.
        try testing.expectEqual(src_before, src.events.items.len);
        // Both sides were asked with NIP-77, and the source only by id after.
        try testing.expectEqual(@as(usize, 1), src.neg_opens);
        try testing.expectEqual(@as(usize, 1), dst.neg_opens);
        try testing.expectEqual(@as(usize, 1), src.reqs);
    }
}

test "relay to relay: relays without NIP-77 fall back to REQ, with a warning" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const all = try negclient.signedEvents(a, 60, 21);
    var src: SetRelay = .{ .nip77 = false };
    defer src.deinit();
    var dst: SetRelay = .{ .nip77 = false };
    defer dst.deinit();
    const parts = try split(all, 21, &src, &dst);

    const ob = try a.alloc(u8, 1 << 20);
    var eb: [4096]u8 = undefined;
    const r = try syncRelays(&src, &dst, &.{ "-q", "-k", "1" }, ob, &eb);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "no NIP-77") != null);
    try testing.expect(std.mem.indexOf(u8, r.err, "plain REQ") != null);
    try testing.expect(try holdsAll(testing.allocator, &dst, &src));
    var want: [80]u8 = undefined;
    const line = try std.fmt.bufPrint(&want, "{d} missing, {d} copied, 0 refused, 0 not found\n", .{ parts.x_only, parts.x_only });
    try testing.expectEqualStrings(line, r.out);
}

test "relay to relay: a malformed NEG-MSG falls back instead of hanging" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const all = try negclient.signedEvents(a, 40, 31);
    var src: SetRelay = .{ .malformed = true };
    defer src.deinit();
    var dst: SetRelay = .{};
    defer dst.deinit();
    _ = try split(all, 31, &src, &dst);

    const ob = try a.alloc(u8, 1 << 20);
    var eb: [4096]u8 = undefined;
    const r = try syncRelays(&src, &dst, &.{}, ob, &eb);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "Malformed") != null);
    try testing.expect(try holdsAll(testing.allocator, &dst, &src));
}

fn tmpStorePath(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(testing.io, &root);
    return std.fmt.bufPrint(buf, "{s}/store.mdb", .{root[0..root_len]});
}

test "a store and a relay: pull fills the store, push fills the relay, both do both" {
    const io = testing.io;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for ([_]Direction{ .pull, .push, .both }, 0..) |dir, k| {
        for ([_]bool{ true, false }) |with_nip77| {
            var da: testrelay.DialAllocator = .init;
            defer if (da.deinit() == .leak) @panic("the sync leaked");
            const gpa = da.allocator();

            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var pb: [std.fs.max_path_bytes]u8 = undefined;
            const path = try tmpStorePath(&tmp, &pb);
            const path_z = try a.dupeZ(u8, path);

            const all = try negclient.signedEvents(a, 90, @intCast(40 + k));
            var local: SetRelay = .{};
            defer local.deinit();
            var remote: SetRelay = .{ .nip77 = with_nip77 };
            defer remote.deinit();
            const parts = try split(all, 40 + k, &local, &remote);

            {
                var store = try nostr.store.Store.open(path_z.ptr, .{});
                defer store.deinit();
                for (local.events.items) |j| {
                    var p = try nostr.event.fromJson(gpa, j);
                    defer p.deinit();
                    _ = try store.ingest(gpa, p.value, .{});
                }
            }

            var rel: testrelay.Relay = undefined;
            try rel.startCustom(io, SetRelay.handle, &remote);
            defer rel.stop(io);
            var ub: [40]u8 = undefined;
            const url = try testrelay.url(&ub, rel.port());

            const args: []const []const u8 = switch (dir) {
                .pull => &.{ url, "--store", path },
                .push => &.{ "--store", path, url },
                .both => &.{ "--store", path, url, "--direction", "both" },
            };
            const ob = try a.alloc(u8, 1 << 20);
            var eb: [4096]u8 = undefined;
            const r = try runSync(gpa, args, ob, &eb);
            try testing.expectEqual(cli.exit_ok, r.code);
            if (!with_nip77) try testing.expect(std.mem.indexOf(u8, r.err, "plain REQ") != null);

            const want: usize = switch (dir) {
                .pull => parts.y_only,
                .push => parts.x_only,
                .both => parts.x_only + parts.y_only,
            };
            try testing.expectEqual(want, countLines(r.out));
            if (dir != .pull) try testing.expect(try holdsAll(testing.allocator, &remote, &local));

            var store = try nostr.store.Store.open(path_z.ptr, .{});
            defer store.deinit();
            const expect_count: usize = if (dir == .push) local.events.items.len else all.len;
            try testing.expectEqual(expect_count, try store.eventCount());
        }
    }
}

test "the command line says which way, and refuses what it cannot do" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const gpa = testing.allocator;
    try testing.expectEqual(cli.exit_usage, (try runSync(gpa, &.{"ws://a"}, &ob, &eb)).code);
    try testing.expectEqual(cli.exit_usage, (try runSync(gpa, &.{ "ws://a", "ws://b", "ws://c" }, &ob, &eb)).code);
    try testing.expectEqual(cli.exit_usage, (try runSync(gpa, &.{ "ws://a", "ws://b", "--direction", "pull" }, &ob, &eb)).code);
    try testing.expectEqual(cli.exit_usage, (try runSync(gpa, &.{ "ws://a", "ws://b", "--store", "x" }, &ob, &eb)).code);
    try testing.expectEqual(cli.exit_usage, (try runSync(gpa, &.{ "--store", "x", "ws://a", "--direction", "sideways" }, &ob, &eb)).code);
    try testing.expectEqual(cli.exit_usage, (try runSync(gpa, &.{ "ws://a", "ws://b", "{}", "{}" }, &ob, &eb)).code);
    const help = try runSync(gpa, &.{"--help"}, &ob, &eb);
    try testing.expectEqual(cli.exit_ok, help.code);
    try testing.expect(std.mem.startsWith(u8, help.out, "deed sync:"));

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var w: std.Io.Writer = .fixed(&eb);
    var flags: filterflags.Flags = .{};
    const pull = (try parse(gpa, arena.allocator(), &.{ "ws://a", "--store", "s" }, &flags, &w)).?;
    try testing.expectEqual(Direction.pull, pull.shape.store.direction);
    flags = .{};
    const push = (try parse(gpa, arena.allocator(), &.{ "--store", "s", "ws://a", "-k", "7" }, &flags, &w)).?;
    try testing.expectEqual(Direction.push, push.shape.store.direction);
    try testing.expectEqual(@as(u16, 7), push.filter.kinds.?[0]);
    flags = .{};
    const forced = (try parse(gpa, arena.allocator(), &.{ "ws://a", "--store", "s", "--direction", "push" }, &flags, &w)).?;
    try testing.expectEqual(Direction.push, forced.shape.store.direction);
}

test "an unreachable relay fails the run" {
    const io = testing.io;
    var closed = try testrelay.listen(io);
    const port = closed.socket.address.ip4.port;
    closed.deinit(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, port);
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runSync(da.allocator(), &.{ url, url, "--timeout", "3000" }, &ob, &eb);
    try testing.expectEqual(cli.exit_fail, r.code);
}

const PublishDone = struct {
    done: std.atomic.Value(bool) = .init(false),

    fn run(ctx: *Ctx, r: *relay.Relay, url: []const u8, evs: []const Event, self: *PublishDone) void {
        publish(ctx, r, url, evs) catch {};
        self.done.store(true, .release);
    }
};

test "a relay that stops reading cannot hold a sync past its deadline" {
    const io = testing.io;
    const gpa = std.heap.page_allocator;
    var deaf: testrelay.Relay = undefined;
    try deaf.start(io, .deaf);
    defer deaf.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, deaf.port());

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x21} ** 32);
    // Far more than the socket buffers on both ends hold.
    const big = try a.alloc(u8, 16 * 1024);
    @memset(big, 'x');
    var evs: [250]Event = undefined;
    for (&evs, 0..) |*e, k| e.* = try nostr.event.create(a, signer, kp, 1_700_000_000 + @as(i64, @intCast(k)), 1, &.{}, big, null);

    var ob: [64]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&ob);
    var eb: [4096]u8 = undefined;
    var ew: std.Io.Writer = .fixed(&eb);
    var ctx: Ctx = .{
        .gpa = gpa,
        .io = io,
        .out = &ow,
        .err = &ew,
        .filter = .{},
        .quiet = true,
        .deadline = negclient.deadlineIn(io, 500),
        .signer = signer,
    };
    var outcome: [1]dial.Outcome = undefined;
    dial.all(gpa, io, &.{url}, 2000, &outcome);
    const r = outcome[0].connected;
    var flag: PublishDone = .{};
    var fut = try io.concurrent(PublishDone.run, .{ &ctx, r, url, &evs, &flag });
    var waited: usize = 0;
    while (!flag.done.load(.acquire) and waited < 3000) : (waited += 50) try io.sleep(.fromMilliseconds(50), .awake);
    const finished = flag.done.load(.acquire);
    // Unblocks the write when it did not give up by itself, so the test ends.
    r.shutdown(io);
    fut.await(io);
    r.deinit();
    try testing.expect(finished);
    try testing.expect(ctx.stats.refused == evs.len);
    try testing.expect(std.mem.indexOf(u8, ew.buffered(), "stopped reading") != null);
}
