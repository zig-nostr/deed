//! Where a person reads and writes: their NIP-65 relay list, found and checked.
//!
//! `deed relays` prints it, and the verbs that follow a person to their own
//! relays (the outbox model) ask for it here.
//!
//! The list comes from a NAMED set of relays and nowhere else. There is no
//! built-in default: deed contacts a relay only when the user named it, on the
//! command line or in `DEED_RELAYS`. A relay that holds many people's lists is
//! the right thing to name, and which one is the user's call.
//!
//! What counts as the list is the newest kind 10002 event whose signature
//! checks out. Only when a person has published none is their kind 3 follow
//! list read for the relay hints older clients put in its content.

const std = @import("std");
const nostr = @import("nostr");
const relayset = @import("relayset.zig");

const nip65 = nostr.nip65;
const filter = nostr.filter;

/// Where a person's relays came from.
pub const Source = enum {
    /// A signed kind 10002 relay list.
    relay_list,
    /// The relay hints in a kind 3 follow list, which older clients used
    /// before kind 10002 existed. Used only when there is no kind 10002.
    contacts,
    /// Nothing was found.
    none,

    pub fn label(self: Source) []const u8 {
        return switch (self) {
            .relay_list => "relay-list",
            .contacts => "contacts",
            .none => "none",
        };
    }
};

pub const Options = struct {
    /// The relays to ask. Never defaulted: see the module comment.
    bootstrap: []const []const u8,
    /// Read before the network and written by it, when given.
    store: ?*nostr.store.Store = null,
    /// Ask the relays even when the store already holds a list. The fetched
    /// list replaces the cached one.
    refresh: bool = false,
    timeout_ms: i64 = 10_000,
};

pub const Entry = struct {
    pubkey: [32]u8,
    source: Source,
    relays: []const nip65.RelayEntry,
    created_at: i64 = 0,
};

/// One answer per pubkey asked about, in the order asked.
pub const Lists = struct {
    arena: *std.heap.ArenaAllocator,
    entries: []Entry,

    pub fn deinit(self: *Lists) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }

    pub fn find(self: *const Lists, pubkey: [32]u8) ?*const Entry {
        for (self.entries) |*e| {
            if (std.mem.eql(u8, &e.pubkey, &pubkey)) return e;
        }
        return null;
    }
};

/// Relay URLs, owned.
pub const Urls = struct {
    arena: *std.heap.ArenaAllocator,
    urls: []const []const u8,

    pub fn deinit(self: *Urls) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// The relays `DEED_RELAYS` names, comma or space separated, appended to
/// `list`. The strings point into the environment and live as long as the
/// process. Nothing is added when it is unset.
pub fn appendEnvBootstrap(gpa: std.mem.Allocator, list: *std.ArrayList([]const u8)) !void {
    const value = std.c.getenv("DEED_RELAYS") orelse return;
    try appendSplit(gpa, list, std.mem.span(value));
}

fn appendSplit(gpa: std.mem.Allocator, list: *std.ArrayList([]const u8), text: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, text, ", \t\r\n");
    while (it.next()) |url| try list.append(gpa, url);
}

/// The relays this person lists as theirs to write to: the ones to read their
/// notes from.
pub fn writeRelays(gpa: std.mem.Allocator, io: std.Io, pubkey: [32]u8, opts: Options, err: *std.Io.Writer) !Urls {
    return pick(gpa, io, pubkey, opts, err, .write);
}

/// The relays a verb falls back to when none was named: where `pubkey` writes,
/// found through the relays in `extra` and `DEED_RELAYS`. Null after saying
/// why on `err` when there is nowhere to ask, or the person lists no relay.
pub fn followWriteRelays(
    gpa: std.mem.Allocator,
    io: std.Io,
    verb: []const u8,
    pubkey: [32]u8,
    extra: []const []const u8,
    store: ?*nostr.store.Store,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !?Urls {
    var bootstrap: std.ArrayList([]const u8) = .empty;
    defer bootstrap.deinit(gpa);
    try bootstrap.appendSlice(gpa, extra);
    try appendEnvBootstrap(gpa, &bootstrap);
    if (bootstrap.items.len == 0) {
        try err.print("deed {s}: name a relay, or name one to find the relays in use through (with --relay, or DEED_RELAYS)\n", .{verb});
        return null;
    }
    var found = try writeRelays(gpa, io, pubkey, .{ .bootstrap = bootstrap.items, .store = store, .timeout_ms = timeout_ms }, err);
    if (found.urls.len == 0) {
        found.deinit();
        try err.print("deed {s}: found no relay list to follow, so name a relay\n", .{verb});
        return null;
    }
    return found;
}

/// The relays this person lists as theirs to read from: the ones to send them
/// something at.
pub fn readRelays(gpa: std.mem.Allocator, io: std.Io, pubkey: [32]u8, opts: Options, err: *std.Io.Writer) !Urls {
    return pick(gpa, io, pubkey, opts, err, .read);
}

fn pick(gpa: std.mem.Allocator, io: std.Io, pubkey: [32]u8, opts: Options, err: *std.Io.Writer, which: enum { read, write }) !Urls {
    var lists = try lookupMany(gpa, io, &.{pubkey}, opts, err);
    defer lists.deinit();

    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    var urls: std.ArrayList([]const u8) = .empty;
    for (lists.entries[0].relays) |r| {
        if (if (which == .read) r.read else r.write) try urls.append(a, try a.dupe(u8, r.url));
    }
    return .{ .arena = arena, .urls = try urls.toOwnedSlice(a) };
}

/// One person's lists, both directions at once.
pub fn lookup(gpa: std.mem.Allocator, io: std.Io, pubkey: [32]u8, opts: Options, err: *std.Io.Writer) !Lists {
    return lookupMany(gpa, io, &.{pubkey}, opts, err);
}

/// Many people's lists. One REQ naming every author goes to each bootstrap
/// relay, and a second one, only for the people with no kind 10002, asks for
/// their kind 3.
pub fn lookupMany(gpa: std.mem.Allocator, io: std.Io, pubkeys: []const [32]u8, opts: Options, err: *std.Io.Writer) !Lists {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();

    var entries: std.ArrayList(Entry) = .empty;
    for (pubkeys) |pk| {
        var seen = false;
        for (entries.items) |e| {
            if (std.mem.eql(u8, &e.pubkey, &pk)) seen = true;
        }
        if (!seen) try entries.append(a, .{ .pubkey = pk, .source = .none, .relays = &.{} });
    }
    const all = entries.items;

    try fill(gpa, io, a, all, nip65.kind, .relay_list, opts, err);
    try fill(gpa, io, a, all, 3, .contacts, opts, err);
    return .{ .arena = arena, .entries = all };
}

/// Finds `kind` for every entry still without a list, in the store and then at
/// the bootstrap relays.
fn fill(
    gpa: std.mem.Allocator,
    io: std.Io,
    a: std.mem.Allocator,
    all: []Entry,
    kind: u16,
    source: Source,
    opts: Options,
    err: *std.Io.Writer,
) !void {
    var missing: std.ArrayList([32]u8) = .empty;
    defer missing.deinit(gpa);
    for (all) |e| {
        if (e.source == .none) try missing.append(gpa, e.pubkey);
    }
    // A kind 3 is only worth asking for when kind 10002 found no one, and then
    // only for those it missed. A person with a 10002 is never in `missing`.
    if (missing.items.len == 0) return;

    const kinds = [_]u16{kind};
    if (opts.store) |st| {
        if (!opts.refresh) {
            var q = try st.query(gpa, .{ .authors = missing.items, .kinds = &kinds });
            defer q.deinit();
            for (q.events) |ev| try apply(gpa, a, all, ev, kind, source);
        }
    }

    missing.clearRetainingCapacity();
    for (all) |e| {
        if (e.source == .none) try missing.append(gpa, e.pubkey);
    }
    if (missing.items.len == 0 or opts.bootstrap.len == 0) return;

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // relayset checks every signature and drops anything that does not answer
    // the question, and stores what is left. A forged list never gets here.
    _ = try relayset.query(gpa, io, opts.bootstrap, &.{.{ .authors = missing.items, .kinds = &kinds }}, &out.writer, err, .{
        .until_eose = true,
        .deadline_ms = opts.timeout_ms,
        .store = opts.store,
    });

    var lines = std.mem.splitScalar(u8, out.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = nostr.event.fromJson(gpa, line) catch continue;
        defer parsed.deinit();
        try apply(gpa, a, all, parsed.value, kind, source);
    }
}

/// Keeps `ev` as the person's list when it is newer than what is held.
fn apply(gpa: std.mem.Allocator, a: std.mem.Allocator, all: []Entry, ev: nostr.event.Event, kind: u16, source: Source) !void {
    if (ev.kind != kind) return;
    for (all) |*e| {
        if (!std.mem.eql(u8, &e.pubkey, &ev.pubkey)) continue;
        if (e.source != .none and ev.created_at <= e.created_at) return;
        const relays = if (kind == nip65.kind) try fromRelayList(gpa, a, ev) else try fromContacts(gpa, a, ev.content);
        e.* = .{ .pubkey = e.pubkey, .source = source, .relays = relays, .created_at = ev.created_at };
        return;
    }
}

/// Only these can be dialled, and a stranger's list is not trusted to hold
/// anything else.
fn isRelayUrl(url: []const u8) bool {
    return std.mem.startsWith(u8, url, "wss://") or std.mem.startsWith(u8, url, "ws://");
}

fn fromRelayList(gpa: std.mem.Allocator, a: std.mem.Allocator, ev: nostr.event.Event) ![]const nip65.RelayEntry {
    var parsed = try nip65.parseRelayList(gpa, ev);
    defer parsed.deinit();
    var out: std.ArrayList(nip65.RelayEntry) = .empty;
    for (parsed.list.entries) |r| {
        if (!isRelayUrl(r.url)) continue;
        try out.append(a, .{ .url = try a.dupe(u8, r.url), .read = r.read, .write = r.write });
    }
    return out.toOwnedSlice(a);
}

/// Kind 3 content from older clients: `{"wss://relay": {"read": true, "write": true}}`.
/// Anything that is not that is an empty list, not an error.
fn fromContacts(gpa: std.mem.Allocator, a: std.mem.Allocator, content: []const u8) ![]const nip65.RelayEntry {
    var out: std.ArrayList(nip65.RelayEntry) = .empty;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, content, .{}) catch return out.toOwnedSlice(a);
    defer parsed.deinit();
    if (parsed.value != .object) return out.toOwnedSlice(a);
    var it = parsed.value.object.iterator();
    while (it.next()) |kv| {
        if (!isRelayUrl(kv.key_ptr.*)) continue;
        var read = true;
        var write = true;
        if (kv.value_ptr.* == .object) {
            const o = kv.value_ptr.object;
            if (o.get("read")) |v| read = v == .bool and v.bool;
            if (o.get("write")) |v| write = v == .bool and v.bool;
        }
        try out.append(a, .{ .url = try a.dupe(u8, kv.key_ptr.*), .read = read, .write = write });
    }
    return out.toOwnedSlice(a);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

/// A relay that answers a REQ for kind 10002 or kind 3 with the event it was
/// given for that kind, and counts the REQs.
pub const Script = struct {
    list: ?[]const u8 = null,
    list2: ?[]const u8 = null,
    contacts: ?[]const u8 = null,
    reqs: std.atomic.Value(usize) = .init(0),

    pub fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Script = @ptrCast(@alignCast(ctx.?));
        if (std.mem.indexOf(u8, frame, "\"REQ\"") == null) return;
        _ = self.reqs.fetchAdd(1, .monotonic);
        var buf: [8192]u8 = undefined;
        const wants_list = std.mem.indexOf(u8, frame, "\"kinds\":[10002]") != null;
        const wants_contacts = std.mem.indexOf(u8, frame, "\"kinds\":[3]") != null;
        const served = [_]?[]const u8{
            if (wants_list) self.list else null,
            if (wants_list) self.list2 else null,
            if (wants_contacts) self.contacts else null,
        };
        for (served) |maybe| {
            const ev = maybe orelse continue;
            try testrelay.sendText(w, try std.fmt.bufPrint(&buf, "[\"EVENT\",\"deed\",{s}]", .{ev}));
        }
        try testrelay.sendText(w, "[\"EOSE\",\"deed\"]");
    }
};

/// Starts `relay` as a scripted relay that serves `connections` dials, one per
/// lookup phase that reaches the network.
pub fn startScript(relay: *testrelay.Relay, io: std.Io, script: *Script, connections: usize) !void {
    try relay.startFor(io, .custom, connections);
    relay.custom = Script.handle;
    relay.custom_ctx = script;
}

const Fixture = struct {
    signer: nostr.keys.Signer,
    arena: std.heap.ArenaAllocator,

    fn init(io: std.Io) !Fixture {
        return .{ .signer = try nostr.keys.Signer.initRandomized(io), .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(self: *Fixture) void {
        self.signer.deinit();
        self.arena.deinit();
    }
    fn keyPair(self: *Fixture, byte: u8) !nostr.keys.KeyPair {
        return self.signer.keyPairFromSecretKey([_]u8{byte} ** 32);
    }
    fn signed(self: *Fixture, kp: nostr.keys.KeyPair, at: i64, kind: u16, tags: []const nostr.event.Tag, content: []const u8) ![]const u8 {
        const a = self.arena.allocator();
        const ev = try nostr.event.create(a, self.signer, kp, at, kind, tags, content, null);
        return nostr.event.toJson(a, ev);
    }
};

const list_tags = [_]nostr.event.Tag{
    &.{ "r", "wss://in.example", "read" },
    &.{ "r", "wss://out.example", "write" },
    &.{ "r", "wss://both.example" },
    &.{ "r", "https://not-a-relay.example" },
};

fn expectUrls(want: []const []const u8, got: Urls) !void {
    try testing.expectEqual(want.len, got.urls.len);
    for (want, got.urls) |w, g| try testing.expectEqualStrings(w, g);
}

test "a signed relay list gives the read and write relays" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("outbox leaked");
    const gpa = da.allocator();
    var fx = try Fixture.init(io);
    defer fx.deinit();
    const kp = try fx.keyPair(0x31);

    var script: Script = .{ .list = try fx.signed(kp, 1_700_000_000, 10002, &list_tags, "") };
    var relay: testrelay.Relay = undefined;
    try startScript(&relay, io, &script, 2);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const bootstrap = [_][]const u8{try testrelay.url(&buf, relay.port())};
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    var w = try writeRelays(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap }, &err.writer);
    defer w.deinit();
    try expectUrls(&.{ "wss://out.example", "wss://both.example" }, w);
    var r = try readRelays(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap }, &err.writer);
    defer r.deinit();
    try expectUrls(&.{ "wss://in.example", "wss://both.example" }, r);
}

test "the newest of two relay lists wins" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("outbox leaked");
    const gpa = da.allocator();
    var fx = try Fixture.init(io);
    defer fx.deinit();
    const kp = try fx.keyPair(0x32);

    const old = [_]nostr.event.Tag{&.{ "r", "wss://old.example" }};
    const new = [_]nostr.event.Tag{&.{ "r", "wss://new.example" }};
    var script: Script = .{
        .list = try fx.signed(kp, 1_700_000_000, 10002, &old, ""),
        .list2 = try fx.signed(kp, 1_700_000_100, 10002, &new, ""),
    };
    var relay: testrelay.Relay = undefined;
    try startScript(&relay, io, &script, 1);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const bootstrap = [_][]const u8{try testrelay.url(&buf, relay.port())};
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    var w = try writeRelays(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap }, &err.writer);
    defer w.deinit();
    try expectUrls(&.{"wss://new.example"}, w);
}

test "a kind 3 is read only when there is no relay list" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("outbox leaked");
    const gpa = da.allocator();
    var fx = try Fixture.init(io);
    defer fx.deinit();
    const kp = try fx.keyPair(0x33);

    const legacy = "{\"wss://legacy-in.example\":{\"read\":true,\"write\":false},\"wss://legacy-out.example\":{\"read\":false,\"write\":true},\"http://skipped.example\":{}}";
    var script: Script = .{ .contacts = try fx.signed(kp, 1_700_000_000, 3, &.{}, legacy) };
    var relay: testrelay.Relay = undefined;
    try startScript(&relay, io, &script, 3);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const bootstrap = [_][]const u8{try testrelay.url(&buf, relay.port())};
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    var lists = try lookup(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap }, &err.writer);
    defer lists.deinit();
    try testing.expectEqual(Source.contacts, lists.entries[0].source);
    try testing.expectEqual(@as(usize, 2), lists.entries[0].relays.len);

    // With a relay list as well, the kind 3 is not used.
    script.list = try fx.signed(kp, 1_600_000_000, 10002, &.{&.{ "r", "wss://real.example" }}, "");
    var again = try lookup(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap }, &err.writer);
    defer again.deinit();
    try testing.expectEqual(Source.relay_list, again.entries[0].source);
    try testing.expectEqualStrings("wss://real.example", again.entries[0].relays[0].url);
}

test "a forged relay list is ignored" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("outbox leaked");
    const gpa = da.allocator();
    var fx = try Fixture.init(io);
    defer fx.deinit();
    const kp = try fx.keyPair(0x34);

    const real = try fx.signed(kp, 1_700_000_000, 10002, &.{&.{ "r", "wss://honest.example" }}, "");
    // Same event, one relay swapped after signing.
    const forged = try std.mem.replaceOwned(u8, fx.arena.allocator(), real, "honest.example", "evil.example!");
    var script: Script = .{ .list = forged };
    var relay: testrelay.Relay = undefined;
    try startScript(&relay, io, &script, 2);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const bootstrap = [_][]const u8{try testrelay.url(&buf, relay.port())};
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    var lists = try lookup(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap }, &err.writer);
    defer lists.deinit();
    try testing.expectEqual(Source.none, lists.entries[0].source);
    try testing.expect(std.mem.indexOf(u8, err.written(), "not correctly signed") != null);
}

test "a list that was stored is used without asking a relay" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("outbox leaked");
    const gpa = da.allocator();
    var fx = try Fixture.init(io);
    defer fx.deinit();
    const kp = try fx.keyPair(0x35);

    var script: Script = .{ .list = try fx.signed(kp, 1_700_000_000, 10002, &list_tags, "") };
    var relay: testrelay.Relay = undefined;
    try startScript(&relay, io, &script, 2);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const bootstrap = [_][]const u8{try testrelay.url(&buf, relay.port())};
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/store.mdb", .{dir_buf[0..dir_len]});
    var st = try nostr.store.Store.open(path.ptr, .{});
    defer st.deinit();

    var first = try writeRelays(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap, .store = &st }, &err.writer);
    defer first.deinit();
    try expectUrls(&.{ "wss://out.example", "wss://both.example" }, first);
    try testing.expectEqual(@as(usize, 1), script.reqs.load(.monotonic));

    // No relay named at all, and the answer is the same.
    var second = try writeRelays(gpa, io, kp.public_key, .{ .bootstrap = &.{}, .store = &st }, &err.writer);
    defer second.deinit();
    try expectUrls(&.{ "wss://out.example", "wss://both.example" }, second);

    // Named, but the store answers first: still one request in total.
    var third = try readRelays(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap, .store = &st }, &err.writer);
    defer third.deinit();
    try testing.expectEqual(@as(usize, 1), script.reqs.load(.monotonic));

    // --refresh goes back to the relay.
    var fourth = try readRelays(gpa, io, kp.public_key, .{ .bootstrap = &bootstrap, .store = &st, .refresh = true }, &err.writer);
    defer fourth.deinit();
    try testing.expectEqual(@as(usize, 2), script.reqs.load(.monotonic));
}

test "many people are asked about in one request" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("outbox leaked");
    const gpa = da.allocator();
    var fx = try Fixture.init(io);
    defer fx.deinit();
    const a = try fx.keyPair(0x36);
    const b = try fx.keyPair(0x37);

    var script: Script = .{
        .list = try fx.signed(a, 1_700_000_000, 10002, &.{&.{ "r", "wss://a.example" }}, ""),
        .list2 = try fx.signed(b, 1_700_000_000, 10002, &.{&.{ "r", "wss://b.example" }}, ""),
    };
    var relay: testrelay.Relay = undefined;
    try startScript(&relay, io, &script, 1);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const bootstrap = [_][]const u8{try testrelay.url(&buf, relay.port())};
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    var lists = try lookupMany(gpa, io, &.{ a.public_key, b.public_key, a.public_key }, .{ .bootstrap = &bootstrap }, &err.writer);
    defer lists.deinit();
    try testing.expectEqual(@as(usize, 2), lists.entries.len);
    try testing.expectEqualStrings("wss://a.example", lists.find(a.public_key).?.relays[0].url);
    try testing.expectEqualStrings("wss://b.example", lists.find(b.public_key).?.relays[0].url);
    try testing.expectEqual(@as(usize, 1), script.reqs.load(.monotonic));
}

test "DEED_RELAYS style text splits on commas and spaces" {
    var list: std.ArrayList([]const u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendSplit(testing.allocator, &list, "wss://a.example, wss://b.example  ws://c.example");
    try testing.expectEqual(@as(usize, 3), list.items.len);
    try testing.expectEqualStrings("ws://c.example", list.items[2]);
}
