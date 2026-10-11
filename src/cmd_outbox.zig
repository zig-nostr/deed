//! `deed outbox`: look after the relay lists a store has kept.
//!
//! Every verb that follows a person to their own relays reads their NIP-65
//! list (kind 10002) through `outbox.zig`, and keeps what it fetched in the
//! store named with `--store`. This verb is for that cache: what it holds,
//! fetching fresh lists over it, and emptying it.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const jsonout = @import("jsonout.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const storepath = @import("storepath.zig");

const hex = nostr.hex;
const nip65 = nostr.nip65;

/// Shown beside the name in `deed help`.
pub const summary = "list, refresh and clear the cached relay lists in a store";

pub const ready = true;

pub const usage =
    \\deed outbox: list, refresh and clear the cached relay lists in a store
    \\
    \\Usage:
    \\  deed outbox list    --store <path> [<pubkey>...] [--json]
    \\  deed outbox refresh <pubkey>... --store <path> [<relay-url>...]
    \\  deed outbox clear   --store <path> (<pubkey>... | --all)
    \\
    \\The relay lists are the kind 10002 events (NIP-65) that deed keeps in the
    \\store whenever it follows a person to their relays. A pubkey is an npub or
    \\64 hex characters.
    \\
    \\list     One line per relay: the pubkey, the relay URL, and read, write
    \\         or read,write, separated by tabs. With pubkeys, only theirs.
    \\         --json prints one object per person instead.
    \\refresh  Asks the relays named for each person's current list and keeps
    \\         the newest one it gets, replacing the cached copy. A person the
    \\         relays have no list for keeps the cached copy. Prints the
    \\         pubkey, where the list came from and how many relays it names.
    \\clear    Removes the cached lists of the pubkeys named, or all of them
    \\         with --all, and prints how many it removed. Other events in the
    \\         store are left alone.
    \\
    \\Options:
    \\      --store <path>   the store (required)
    \\  -r, --relay <url>    a relay to ask (refresh; repeatable; a bare ws:// or
    \\                       wss:// argument works too)
    \\      --json           list: one JSON object per person
    \\      --all            clear: every cached list
    \\      --timeout <ms>   refresh: give up on relays still answering
    \\                       (default 10000)
    \\
    \\refresh asks only the relays you name, with --relay or in DEED_RELAYS
    \\(comma or space separated). deed has no built-in list.
    \\
    \\Exits: 0 when everything asked for was done; 1 when something failed (a
    \\refresh that found no list, for example); 2 if the command line was not
    \\understood.
    \\
;

const Command = enum { list, refresh, clear };

/// Most lists one `list` or `clear` looks at.
const max_lists: u32 = 1_000_000;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed outbox: say what to do: list, refresh or clear (see 'deed help outbox')\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    const cmd = std.meta.stringToEnum(Command, args[0]) orelse {
        try err.print("deed outbox: unknown command '{s}' (want list, refresh or clear)\n", .{args[0]});
        return cli.exit_usage;
    };

    var store_path: ?[]const u8 = null;
    var relays: std.ArrayList([]const u8) = .empty;
    defer relays.deinit(gpa);
    var people: std.ArrayList([32]u8) = .empty;
    defer people.deinit(gpa);
    var as_json = false;
    var all = false;
    var timeout_ms: i64 = 10_000;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--json")) {
            as_json = true;
        } else if (std.mem.eql(u8, a, "--all")) {
            all = true;
        } else if (cli.isOneOf(a, &.{ "--store", "-r", "--relay", "--timeout" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed outbox: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (std.mem.eql(u8, a, "--store")) {
                store_path = args[i];
            } else if (std.mem.eql(u8, a, "--timeout")) {
                timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch 0;
                if (timeout_ms <= 0) {
                    try err.print("deed outbox: '{s}' is not a number of milliseconds above 0\n", .{args[i]});
                    return cli.exit_usage;
                }
            } else {
                try relays.append(gpa, args[i]);
            }
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed outbox: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (isRelayUrl(a)) {
            try relays.append(gpa, a);
        } else {
            const pk = keyinput.publicKey(gpa, keyinput.stripUri(a)) catch {
                try err.print("deed outbox: {s}: not an npub or 64 hex characters\n", .{a});
                return cli.exit_usage;
            };
            try people.append(gpa, pk);
        }
    }

    const path = store_path orelse {
        try err.print("deed outbox {s}: needs a store: pass --store <path>\n", .{@tagName(cmd)});
        return cli.exit_usage;
    };
    switch (cmd) {
        .refresh => if (people.items.len == 0) {
            try err.writeAll("deed outbox refresh: name at least one pubkey\n");
            return cli.exit_usage;
        },
        .clear => {
            if (people.items.len == 0 and !all) {
                try err.writeAll("deed outbox clear: name the pubkeys to clear, or pass --all\n");
                return cli.exit_usage;
            }
            if (people.items.len != 0 and all) {
                try err.writeAll("deed outbox clear: --all and pubkeys together make no sense\n");
                return cli.exit_usage;
            }
        },
        .list => {},
    }
    if (cmd == .refresh) {
        try outbox.appendEnvBootstrap(gpa, &relays);
        if (relays.items.len == 0) {
            try err.writeAll("deed outbox refresh: name a relay to ask, with --relay or DEED_RELAYS\n");
            return cli.exit_usage;
        }
    }

    const mode: storepath.Mode = if (cmd == .refresh) .create else .existing;
    var store = (try storepath.open(gpa, io, "outbox", path, mode, err)) orelse return cli.exit_fail;
    defer store.deinit();

    return switch (cmd) {
        .list => cmdList(gpa, &store, people.items, as_json, out, err),
        .refresh => cmdRefresh(gpa, io, &store, people.items, relays.items, timeout_ms, out, err),
        .clear => cmdClear(gpa, &store, people.items, out, err),
    };
}

fn isRelayUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "wss://") or std.mem.startsWith(u8, s, "ws://");
}

/// A relay URL out of a stored list is a stranger's text: only a plain one is
/// printed, so a list cannot write escape sequences or extra lines.
fn plain(url: []const u8) bool {
    if (!isRelayUrl(url)) return false;
    for (url) |c| if (c <= ' ' or c == 0x7f) return false;
    return true;
}

fn marker(read: bool, write: bool) []const u8 {
    if (read and write) return "read,write";
    return if (read) "read" else "write";
}

fn byPubkey(_: void, a: nostr.event.Event, b: nostr.event.Event) bool {
    return std.mem.order(u8, &a.pubkey, &b.pubkey) == .lt;
}

fn cmdList(
    gpa: std.mem.Allocator,
    store: *nostr.store.Store,
    people: []const [32]u8,
    as_json: bool,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    const kinds = [_]u16{nip65.kind};
    var found = store.query(gpa, .{
        .kinds = &kinds,
        .authors = if (people.len == 0) null else people,
        .limit = max_lists,
    }) catch {
        try err.writeAll("deed outbox list: could not read the store\n");
        return cli.exit_fail;
    };
    defer found.deinit();

    const events = try gpa.dupe(nostr.event.Event, found.events);
    defer gpa.free(events);
    std.mem.sort(nostr.event.Event, events, {}, byPubkey);

    for (events) |ev| {
        var parsed = nip65.parseRelayList(gpa, ev) catch continue;
        defer parsed.deinit();
        const pk = try hex.encode(gpa, &ev.pubkey);
        defer gpa.free(pk);
        var line: std.ArrayList(u8) = .empty;
        defer line.deinit(gpa);
        if (as_json) {
            try line.print(gpa, "{{\"pubkey\":\"{s}\",\"created_at\":{d},\"relays\":[", .{ pk, ev.created_at });
            var first = true;
            for (parsed.list.entries) |r| {
                if (!plain(r.url)) continue;
                if (!first) try line.append(gpa, ',');
                first = false;
                try line.appendSlice(gpa, "{\"url\":");
                try jsonout.appendString(&line, gpa, r.url);
                try line.print(gpa, ",\"read\":{s},\"write\":{s}}}", .{ if (r.read) "true" else "false", if (r.write) "true" else "false" });
            }
            try line.appendSlice(gpa, "]}\n");
        } else {
            for (parsed.list.entries) |r| {
                if (!plain(r.url)) continue;
                try line.print(gpa, "{s}\t{s}\t{s}\n", .{ pk, r.url, marker(r.read, r.write) });
            }
        }
        try out.writeAll(line.items);
    }
    return cli.exit_ok;
}

fn cmdRefresh(
    gpa: std.mem.Allocator,
    io: std.Io,
    store: *nostr.store.Store,
    people: []const [32]u8,
    relays: []const []const u8,
    timeout_ms: i64,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var lists = try outbox.lookupMany(gpa, io, people, .{
        .bootstrap = relays,
        .store = store,
        .refresh = true,
        .timeout_ms = timeout_ms,
    }, err);
    defer lists.deinit();

    var code: u8 = cli.exit_ok;
    for (lists.entries) |e| {
        const pk = try hex.encode(gpa, &e.pubkey);
        defer gpa.free(pk);
        if (e.source == .none) {
            try err.print("deed outbox: {s}: no relay list found\n", .{pk});
            code = cli.exit_fail;
            continue;
        }
        var n: usize = 0;
        for (e.relays) |r| {
            if (plain(r.url)) n += 1;
        }
        try out.print("{s}\t{s}\t{d}\n", .{ pk, e.source.label(), n });
    }
    return code;
}

fn cmdClear(
    gpa: std.mem.Allocator,
    store: *nostr.store.Store,
    people: []const [32]u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    const kinds = [_]u16{nip65.kind};
    const removed = store.removeMatching(gpa, .{
        .kinds = &kinds,
        .authors = if (people.len == 0) null else people,
        .limit = max_lists,
    }) catch {
        try err.writeAll("deed outbox clear: could not change the store\n");
        return cli.exit_fail;
    };
    try out.print("{d}\n", .{removed});
    return cli.exit_ok;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

const Rig = struct {
    signer: nostr.keys.Signer,
    arena: std.heap.ArenaAllocator,
    script: outbox.Script,
    relay: testrelay.Relay,
    npub: []const u8,
    pubkey_hex: []const u8,
    tmp: testing.TmpDir,
    store_path: []const u8,

    fn setUp(self: *Rig, io: std.Io, connections: usize, at: i64) !void {
        self.signer = try nostr.keys.Signer.initRandomized(io);
        self.arena = std.heap.ArenaAllocator.init(testing.allocator);
        const a = self.arena.allocator();
        const kp = try self.signer.keyPairFromSecretKey([_]u8{0x51} ** 32);
        const tags = [_]nostr.event.Tag{
            &.{ "r", "wss://in.example", "read" },
            &.{ "r", "wss://out.example", "write" },
            &.{ "r", "wss://both.example" },
        };
        const ev = try nostr.event.create(a, self.signer, kp, at, 10002, &tags, "", null);
        self.script = .{ .list = try nostr.event.toJson(a, ev) };
        self.npub = try nostr.nip19.encodeNpub(a, kp.public_key);
        self.pubkey_hex = try hex.encode(a, &kp.public_key);
        try outbox.startScript(&self.relay, io, &self.script, connections);
        self.tmp = testing.tmpDir(.{});
        var root: [std.fs.max_path_bytes]u8 = undefined;
        const n = try self.tmp.dir.realPath(io, &root);
        self.store_path = try std.fmt.allocPrint(a, "{s}/outbox-store", .{root[0..n]});
    }

    fn tearDown(self: *Rig, io: std.Io) void {
        self.relay.stop(io);
        self.tmp.cleanup();
        self.arena.deinit();
        self.signer.deinit();
    }
};

const Ran = struct {
    code: u8,
    out: std.Io.Writer.Allocating,
    err: std.Io.Writer.Allocating,

    fn deinit(self: *Ran) void {
        self.out.deinit();
        self.err.deinit();
    }
};

fn runArgs(io: std.Io, args: []const []const u8) !Ran {
    var r: Ran = .{
        .code = 0,
        .out = .init(testing.allocator),
        .err = .init(testing.allocator),
    };
    errdefer r.deinit();
    r.code = try run(testing.allocator, io, args, &r.out.writer, &r.err.writer);
    return r;
}

test "refresh fetches a list into the store, list shows it, clear removes it" {
    const io = testing.io;
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var rig: Rig = undefined;
    try rig.setUp(io, 1, 1_700_000_000);
    defer rig.tearDown(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, rig.relay.port());

    var fetched = try runArgs(io, &.{ "refresh", rig.npub, "--store", rig.store_path, "--relay", url });
    defer fetched.deinit();
    try testing.expectEqual(cli.exit_ok, fetched.code);
    const want_refresh = try std.fmt.allocPrint(testing.allocator, "{s}\trelay-list\t3\n", .{rig.pubkey_hex});
    defer testing.allocator.free(want_refresh);
    try testing.expectEqualStrings(want_refresh, fetched.out.written());

    var listed = try runArgs(io, &.{ "list", "--store", rig.store_path });
    defer listed.deinit();
    try testing.expectEqual(cli.exit_ok, listed.code);
    const want_list = try std.fmt.allocPrint(
        testing.allocator,
        "{0s}\twss://in.example\tread\n{0s}\twss://out.example\twrite\n{0s}\twss://both.example\tread,write\n",
        .{rig.pubkey_hex},
    );
    defer testing.allocator.free(want_list);
    try testing.expectEqualStrings(want_list, listed.out.written());

    var json = try runArgs(io, &.{ "list", rig.npub, "--store", rig.store_path, "--json" });
    defer json.deinit();
    try testing.expect(std.mem.indexOf(u8, json.out.written(), "{\"url\":\"wss://out.example\",\"read\":false,\"write\":true}") != null);
    try testing.expect(std.mem.indexOf(u8, json.out.written(), "\"created_at\":1700000000") != null);

    var cleared = try runArgs(io, &.{ "clear", "--all", "--store", rig.store_path });
    defer cleared.deinit();
    try testing.expectEqualStrings("1\n", cleared.out.written());

    var after = try runArgs(io, &.{ "list", "--store", rig.store_path });
    defer after.deinit();
    try testing.expectEqualStrings("", after.out.written());
}

test "a refresh that finds nothing keeps the cached list" {
    const io = testing.io;
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var rig: Rig = undefined;
    try rig.setUp(io, 1, 1_700_000_000);
    defer rig.tearDown(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, rig.relay.port());
    var first = try runArgs(io, &.{ "refresh", rig.npub, "--store", rig.store_path, "-r", url });
    first.deinit();

    // A relay that knows nothing is asked for 10002 and then for kind 3.
    var none: outbox.Script = .{};
    var relay2: testrelay.Relay = undefined;
    try outbox.startScript(&relay2, io, &none, 2);
    defer relay2.stop(io);
    var buf2: [40]u8 = undefined;
    const url2 = try testrelay.url(&buf2, relay2.port());

    var miss = try runArgs(io, &.{ "refresh", rig.npub, "--store", rig.store_path, url2 });
    defer miss.deinit();
    try testing.expectEqual(cli.exit_fail, miss.code);
    try testing.expectEqualStrings("", miss.out.written());
    try testing.expect(std.mem.indexOf(u8, miss.err.written(), "no relay list found") != null);

    var listed = try runArgs(io, &.{ "list", "--store", rig.store_path });
    defer listed.deinit();
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, listed.out.written(), "\n"));
}

test "clear with pubkeys leaves other people's lists alone" {
    const io = testing.io;
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var rig: Rig = undefined;
    try rig.setUp(io, 1, 1_700_000_000);
    defer rig.tearDown(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, rig.relay.port());
    var first = try runArgs(io, &.{ "refresh", rig.npub, "--store", rig.store_path, "-r", url });
    first.deinit();

    const other = try nostr.nip19.encodeNpub(rig.arena.allocator(), [_]u8{0x77} ** 32);
    var miss = try runArgs(io, &.{ "clear", other, "--store", rig.store_path });
    defer miss.deinit();
    try testing.expectEqualStrings("0\n", miss.out.written());
    var still = try runArgs(io, &.{ "list", "--store", rig.store_path });
    defer still.deinit();
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, still.out.written(), "\n"));

    var hit = try runArgs(io, &.{ "clear", rig.pubkey_hex, "--store", rig.store_path });
    defer hit.deinit();
    try testing.expectEqualStrings("1\n", hit.out.written());
}

test "the command line is checked before the store is touched" {
    const io = testing.io;
    var a = try runArgs(io, &.{});
    defer a.deinit();
    try testing.expectEqual(cli.exit_usage, a.code);
    var b = try runArgs(io, &.{"levitate"});
    defer b.deinit();
    try testing.expectEqual(cli.exit_usage, b.code);
    var c = try runArgs(io, &.{ "list", "--bogus" });
    defer c.deinit();
    try testing.expectEqual(cli.exit_usage, c.code);
    var d = try runArgs(io, &.{"list"});
    defer d.deinit();
    try testing.expect(std.mem.indexOf(u8, d.err.written(), "--store") != null);
    var e = try runArgs(io, &.{ "clear", "--store", "/nonexistent/x" });
    defer e.deinit();
    try testing.expectEqual(cli.exit_usage, e.code);
    var f = try runArgs(io, &.{ "refresh", "--store", "/nonexistent/x" });
    defer f.deinit();
    try testing.expectEqual(cli.exit_usage, f.code);
    var g = try runArgs(io, &.{ "list", "--store", "/nonexistent/dir/x" });
    defer g.deinit();
    try testing.expectEqual(cli.exit_fail, g.code);
}
