//! `deed relays`: where a person reads and writes.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const jsonout = @import("jsonout.zig");
const outbox = @import("outbox.zig");
const storepath = @import("storepath.zig");

const nip19 = nostr.nip19;
const hex = nostr.hex;

/// Shown beside the name in `deed help`.
pub const summary = "show the relays a person reads from and writes to";

/// False keeps the verb out of `deed help`.
pub const ready = true;

pub const usage =
    \\deed relays: show the relays a person reads from and writes to
    \\
    \\Usage:
    \\  deed relays [options] <npub|nprofile|hex> [<relay-url>...]
    \\
    \\Looks up the person's relay list (NIP-65, kind 10002) at the relays you
    \\name, checks its signature, and prints one relay URL per line. Their
    \\inbox relays are the ones they read from, where you send them something.
    \\Their outbox relays are the ones they write to, where you read their notes.
    \\If they have no relay list, the relay hints in their kind 3 follow list are
    \\used instead.
    \\
    \\Options:
    \\  -r, --relay <url>    a relay to ask (repeatable; a bare ws:// or wss://
    \\                       argument works too)
    \\      --inbox          only the relays they read from, as bare URLs
    \\      --outbox         only the relays they write to, as bare URLs
    \\      --json           one JSON object instead of lines
    \\      --store <path>   read a cached list from a local store first, and
    \\                       keep what is fetched
    \\      --refresh        ask the relays even if the store has a list
    \\      --timeout <ms>   give up on relays still answering (default 10000)
    \\
    \\With neither --inbox nor --outbox (or with both), each line is the URL, a
    \\tab, and read, write or read,write.
    \\
    \\deed never contacts a relay you did not name, and has no built-in list. The
    \\environment variable DEED_RELAYS (comma or space separated) names relays
    \\for every run; --relay adds to it. A relay that indexes many people's
    \\relay lists answers best: the larger public relays of this kind, such as
    \\wss://purplepag.es or wss://relay.damus.io, are the usual choices.
    \\An nprofile's own relay hints are asked as well.
    \\
    \\Exits: 0 if a relay list was found; 1 if none was or no relay answered; 2 if
    \\the command line was not understood.
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var code: ?[]const u8 = null;
    var bootstrap: std.ArrayList([]const u8) = .empty;
    defer bootstrap.deinit(gpa);
    var store_path: ?[]const u8 = null;
    var timeout_ms: i64 = 10_000;
    var want_in = false;
    var want_out = false;
    var as_json = false;
    var refresh = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--inbox")) {
            want_in = true;
        } else if (std.mem.eql(u8, a, "--outbox")) {
            want_out = true;
        } else if (std.mem.eql(u8, a, "--json")) {
            as_json = true;
        } else if (std.mem.eql(u8, a, "--refresh")) {
            refresh = true;
        } else if (cli.isOneOf(a, &.{ "-r", "--relay", "--store", "--timeout" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed relays: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try bootstrap.append(gpa, args[i]);
            } else if (std.mem.eql(u8, a, "--store")) {
                store_path = args[i];
            } else {
                timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch {
                    try err.print("deed relays: '{s}' is not a number of milliseconds\n", .{args[i]});
                    return cli.exit_fail;
                };
            }
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed relays: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try bootstrap.append(gpa, a);
        } else if (code == null) {
            code = a;
        } else {
            try err.writeAll("deed relays: takes one person\n");
            return cli.exit_usage;
        }
    }

    const raw = code orelse {
        try err.writeAll("deed relays: needs an npub, nprofile or hex public key\n");
        return cli.exit_usage;
    };

    var hints: ?[][]u8 = null;
    defer if (hints) |list| {
        for (list) |h| gpa.free(h);
        gpa.free(list);
    };
    const pubkey = blk: {
        const s = keyinput.stripUri(raw);
        if (keyinput.hasPrefix(s, "nprofile1")) {
            const p = nip19.decodeNprofile(gpa, s) catch {
                try err.print("deed relays: {s}: not a code deed can read\n", .{raw});
                return cli.exit_fail;
            };
            hints = p.relays;
            break :blk p.pubkey;
        }
        break :blk keyinput.publicKey(gpa, s) catch {
            try err.print("deed relays: {s}: not an npub, nprofile or hex public key\n", .{raw});
            return cli.exit_fail;
        };
    };
    if (hints) |list| for (list) |h| try bootstrap.append(gpa, h);
    try outbox.appendEnvBootstrap(gpa, &bootstrap);

    var store: ?nostr.store.Store = null;
    defer if (store) |*st| st.deinit();
    if (store_path) |path| {
        store = (try storepath.open(gpa, io, "relays", path, .create, err)) orelse return cli.exit_fail;
    }

    if (bootstrap.items.len == 0 and store == null) {
        try err.writeAll("deed relays: name a relay to ask, with --relay or DEED_RELAYS\n");
        return cli.exit_usage;
    }

    var lists = try outbox.lookup(gpa, io, pubkey, .{
        .bootstrap = bootstrap.items,
        .store = if (store) |*st| st else null,
        .refresh = refresh,
        .timeout_ms = timeout_ms,
    }, err);
    defer lists.deinit();
    const entry = lists.entries[0];

    if (as_json) {
        try writeJson(gpa, out, entry);
    } else {
        const marked = want_in == want_out;
        for (entry.relays) |r| {
            if (!marked and want_in and !r.read) continue;
            if (!marked and want_out and !r.write) continue;
            if (marked) {
                try out.print("{s}\t{s}\n", .{ r.url, marker(r.read, r.write) });
            } else {
                try out.print("{s}\n", .{r.url});
            }
        }
    }

    if (entry.source == .none) {
        try err.writeAll("deed relays: no relay list found for that person\n");
        return cli.exit_fail;
    }
    return cli.exit_ok;
}

fn marker(read: bool, write: bool) []const u8 {
    if (read and write) return "read,write";
    return if (read) "read" else "write";
}

fn writeJson(gpa: std.mem.Allocator, out: *std.Io.Writer, entry: outbox.Entry) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const pk = try hex.encode(gpa, &entry.pubkey);
    defer gpa.free(pk);
    try buf.print(gpa, "{{\"pubkey\":\"{s}\",\"source\":\"{s}\",\"relays\":[", .{ pk, entry.source.label() });
    for (entry.relays, 0..) |r, n| {
        if (n > 0) try buf.append(gpa, ',');
        try buf.appendSlice(gpa, "{\"url\":");
        try jsonout.appendString(&buf, gpa, r.url);
        try buf.print(gpa, ",\"read\":{s},\"write\":{s}}}", .{ if (r.read) "true" else "false", if (r.write) "true" else "false" });
    }
    try buf.appendSlice(gpa, "]}\n");
    try out.writeAll(buf.items);
}

const testing = std.testing;
const testrelay = @import("testrelay.zig");

const Rig = struct {
    fx_signer: nostr.keys.Signer,
    arena: std.heap.ArenaAllocator,
    script: outbox.Script,
    relay: testrelay.Relay,
    npub: []const u8,
};

fn runRelays(rig: *Rig, io: std.Io, extra: []const []const u8, out: *std.Io.Writer.Allocating, err: *std.Io.Writer.Allocating) !u8 {
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, rig.relay.port());
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(testing.allocator);
    try args.append(testing.allocator, rig.npub);
    try args.append(testing.allocator, "--relay");
    try args.append(testing.allocator, url);
    try args.appendSlice(testing.allocator, extra);
    return run(testing.allocator, io, args.items, &out.writer, &err.writer);
}

fn setUp(rig: *Rig, io: std.Io, connections: usize) !void {
    rig.fx_signer = try nostr.keys.Signer.initRandomized(io);
    rig.arena = std.heap.ArenaAllocator.init(testing.allocator);
    const a = rig.arena.allocator();
    const kp = try rig.fx_signer.keyPairFromSecretKey([_]u8{0x41} ** 32);
    const tags = [_]nostr.event.Tag{
        &.{ "r", "wss://in.example", "read" },
        &.{ "r", "wss://out.example", "write" },
        &.{ "r", "wss://both.example" },
    };
    const ev = try nostr.event.create(a, rig.fx_signer, kp, 1_700_000_000, 10002, &tags, "", null);
    rig.script = .{ .list = try nostr.event.toJson(a, ev) };
    rig.npub = try nip19.encodeNpub(a, kp.public_key);
    try outbox.startScript(&rig.relay, io, &rig.script, connections);
}

fn tearDown(rig: *Rig, io: std.Io) void {
    rig.relay.stop(io);
    rig.arena.deinit();
    rig.fx_signer.deinit();
}

test "relays prints every relay with its marker, or only one direction bare" {
    const io = testing.io;
    var rig: Rig = undefined;
    try setUp(&rig, io, 3);
    defer tearDown(&rig, io);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    try testing.expectEqual(cli.exit_ok, try runRelays(&rig, io, &.{}, &out, &err));
    try testing.expectEqualStrings("wss://in.example\tread\nwss://out.example\twrite\nwss://both.example\tread,write\n", out.written());

    out.clearRetainingCapacity();
    try testing.expectEqual(cli.exit_ok, try runRelays(&rig, io, &.{"--inbox"}, &out, &err));
    try testing.expectEqualStrings("wss://in.example\nwss://both.example\n", out.written());

    out.clearRetainingCapacity();
    try testing.expectEqual(cli.exit_ok, try runRelays(&rig, io, &.{"--outbox"}, &out, &err));
    try testing.expectEqualStrings("wss://out.example\nwss://both.example\n", out.written());
}

test "relays --json is one object" {
    const io = testing.io;
    var rig: Rig = undefined;
    try setUp(&rig, io, 1);
    defer tearDown(&rig, io);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(cli.exit_ok, try runRelays(&rig, io, &.{"--json"}, &out, &err));
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"source\":\"relay-list\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "{\"url\":\"wss://out.example\",\"read\":false,\"write\":true}") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out.written(), "\n"));
}

test "relays with no relay named does not guess one" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const npub = try nip19.encodeNpub(testing.allocator, [_]u8{0x42} ** 32);
    defer testing.allocator.free(npub);
    // Skipped when the environment names relays, which would make this a
    // network test.
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{npub}, &out.writer, &err.writer));
    try testing.expect(std.mem.indexOf(u8, err.written(), "name a relay") != null);
}
