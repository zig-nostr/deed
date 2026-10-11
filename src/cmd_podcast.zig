//! `deed podcast`: list the episodes of a podcast published on Nostr.
//!
//! Read only. A podcast is a pubkey that publishes a kind 10154 metadata event
//! and kind 54 episodes, each carrying a `title` and an `audio` tag. A person
//! can also point at podcasts they make with a kind 10064 or 10164 list of `p`
//! tags; a listed podcast counts only when its own metadata names that person
//! back, so nobody can claim a podcast they do not make.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const relayset = @import("relayset.zig");
const cmd_decode = @import("cmd_decode.zig");

const nip19 = nostr.nip19;
const hex = nostr.hex;
const filter = nostr.filter;
const Event = nostr.event.Event;

pub const summary = "list the episodes of a podcast published on Nostr";

pub const ready = true;

pub const usage =
    \\deed podcast: list the episodes of a podcast published on Nostr
    \\
    \\Usage:
    \\  deed podcast [list] <npub|nprofile|hex|name@domain> [options]
    \\
    \\Prints one line per episode, newest first: the first eight characters of
    \\the event id, the date, the title, and the media URL, separated by tabs.
    \\An episode with no title shows <untitled>, and one with no audio tag shows
    \\a dash where the URL goes.
    \\
    \\The person may be the podcast itself (it has published kind 10154
    \\metadata) or someone who lists podcasts they make (kind 10064 or 10164,
    \\accepted when the podcast's metadata names them back). With several
    \\podcasts found, each is listed under a header line.
    \\
    \\This only reads. It does not play audio, download it, or open a player:
    \\There is no play or info subcommand: pass the URL to whatever plays media
    \\on your machine.
    \\
    \\Options:
    \\  -r, --relay <url>    where to look (repeatable; a bare ws:// or wss://
    \\                       argument works too). An nprofile's hints and a
    \\                       NIP-05 name's relays are used as well
    \\  -l, --limit <n>      most episodes per podcast (default 50)
    \\      --timeout <ms>   give up on relays still answering (default 30000)
    \\      --allow-local    let a NIP-05 name resolve to an address on this
    \\                       machine or network (refused by default)
    \\
    \\With no relay named, the person's own write relays are looked up through
    \\the relays in DEED_RELAYS. deed has no built-in relay list.
    \\
    \\Exits: 0 on success; 1 if no podcast was found or no relay answered; 2 if
    \\the command line was not understood.
    \\
;

/// Events held in memory, parsed from the lines a query printed.
const Events = struct {
    parsed: std.ArrayList(nostr.event.Parsed) = .empty,

    fn deinit(self: *Events, gpa: std.mem.Allocator) void {
        for (self.parsed.items) |*p| p.deinit();
        self.parsed.deinit(gpa);
    }
};

/// Asks `urls` one question and keeps the events that come back. Every one was
/// checked by `relayset.query` before it was printed.
fn collect(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    f: filter.Filter,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !Events {
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    _ = try relayset.query(gpa, io, urls, &.{f}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
    });
    var events: Events = .{};
    errdefer events.deinit(gpa);
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var p = nostr.event.fromJson(gpa, line) catch continue;
        events.parsed.append(gpa, p) catch |e| {
            p.deinit();
            return e;
        };
    }
    return events;
}

fn tagValue(ev: Event, name: []const u8) ?[]const u8 {
    for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], name)) return t[1];
    }
    return null;
}

/// The newest of `kind` by `author`, if any.
fn newest(events: Events, kind: u16, author: ?[32]u8) ?Event {
    var best: ?Event = null;
    for (events.parsed.items) |p| {
        const ev = p.value;
        if (ev.kind != kind) continue;
        if (author) |a| if (!std.mem.eql(u8, &a, &ev.pubkey)) continue;
        if (best == null or ev.created_at > best.?.created_at) best = ev;
    }
    return best;
}

fn namesBack(meta: Event, who: [32]u8) bool {
    for (meta.tags) |t| {
        if (t.len < 2 or !std.mem.eql(u8, t[0], "p")) continue;
        const pk = hex.decodeFixed(32, t[1]) catch continue;
        if (std.mem.eql(u8, &pk, &who)) return true;
    }
    return false;
}

/// Writes `text` on one line, with every control character shown as a space.
/// Titles and URLs are chosen by whoever published the event.
fn writeClean(w: *std.Io.Writer, text: []const u8) !void {
    for (text) |c| try w.writeByte(if (c < 0x20 or c == 0x7f) ' ' else c);
}

fn writeDate(w: *std.Io.Writer, created_at: i64) !void {
    const secs: u64 = if (created_at < 0) 0 else @intCast(created_at);
    const day = (std.time.epoch.EpochSeconds{ .secs = secs }).getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    try w.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1 });
}

fn newestFirst(_: void, a: nostr.event.Parsed, b: nostr.event.Parsed) bool {
    if (a.value.created_at != b.value.created_at) return a.value.created_at > b.value.created_at;
    return std.mem.order(u8, &a.value.id, &b.value.id) == .lt;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var target: ?[]const u8 = null;
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);
    var limit: u32 = 50;
    var allow_local = false;
    var timeout_ms: i64 = 30_000;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (i == 0 and std.mem.eql(u8, a, "list")) continue;
        if (std.mem.eql(u8, a, "--allow-local")) {
            allow_local = true;
            continue;
        }
        if (cli.isOneOf(a, &.{ "play", "info" }) and i == 0) {
            try err.print("deed podcast: '{s}' is not supported: this only lists episodes\n", .{a});
            return cli.exit_usage;
        }
        if (cli.isOneOf(a, &.{ "-r", "--relay", "-l", "--limit", "--timeout" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed podcast: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try urls.append(gpa, args[i]);
            } else if (cli.isOneOf(a, &.{ "-l", "--limit" })) {
                limit = std.fmt.parseInt(u32, args[i], 10) catch {
                    try err.print("deed podcast: '{s}' is not a number of episodes\n", .{args[i]});
                    return cli.exit_fail;
                };
            } else {
                timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch {
                    try err.print("deed podcast: '{s}' is not a number of milliseconds\n", .{args[i]});
                    return cli.exit_fail;
                };
            }
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed podcast: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try urls.append(gpa, a);
        } else if (target == null) {
            target = a;
        } else {
            try err.writeAll("deed podcast: takes one person or podcast\n");
            return cli.exit_usage;
        }
    }
    const raw = target orelse {
        try err.writeAll("deed podcast: needs an npub, nprofile, hex public key or name@domain\n");
        return cli.exit_usage;
    };

    // Who, and the relays the code or the name already carries.
    var hint_list: ?[][]u8 = null;
    defer if (hint_list) |list| {
        for (list) |h| gpa.free(h);
        gpa.free(list);
    };
    var resolved: ?nostr.nip05.Resolved = null;
    defer if (resolved) |*r| r.deinit();
    const who: [32]u8 = blk: {
        const s = keyinput.stripUri(raw);
        if (keyinput.hasPrefix(s, "nprofile1")) {
            const p = nip19.decodeNprofile(gpa, s) catch {
                try err.print("deed podcast: {s}: not a code deed can read\n", .{raw});
                return cli.exit_fail;
            };
            hint_list = p.relays;
            for (p.relays) |h| try urls.append(gpa, h);
            break :blk p.pubkey;
        }
        if (cmd_decode.isNip05(s) and !keyinput.hasPrefix(s, "npub1")) {
            resolved = cmd_decode.resolveNip05Opts(gpa, io, s, !allow_local) catch |e| {
                try err.print("deed podcast: {s}: {s}\n", .{ raw, cmd_decode.reason(e) });
                return cli.exit_fail;
            };
            for (resolved.?.relays) |h| try urls.append(gpa, h);
            break :blk resolved.?.pubkey;
        }
        break :blk keyinput.publicKey(gpa, s) catch {
            try err.print("deed podcast: {s}: not an npub, nprofile, hex public key or name@domain\n", .{raw});
            return cli.exit_fail;
        };
    };

    var followed: ?outbox.Urls = null;
    defer if (followed) |*f| f.deinit();
    if (urls.items.len == 0) {
        followed = try outbox.followWriteRelays(gpa, io, "podcast", who, &.{}, null, timeout_ms, err) orelse return cli.exit_usage;
        for (followed.?.urls) |u| try urls.append(gpa, u);
    }

    // The person's own podcast metadata, and the lists that point at others.
    var first = try collect(gpa, io, urls.items, .{
        .authors = &.{who},
        .kinds = &.{ 10154, 10064, 10164 },
    }, timeout_ms, err);
    defer first.deinit(gpa);

    var podcasts: std.ArrayList(Podcast) = .empty;
    defer podcasts.deinit(gpa);
    if (newest(first, 10154, who)) |meta| try podcasts.append(gpa, .{ .pubkey = who, .meta = meta });

    var listed: std.ArrayList([32]u8) = .empty;
    defer listed.deinit(gpa);
    for ([_]u16{ 10064, 10164 }) |kind| {
        const list = newest(first, kind, who) orelse continue;
        for (list.tags) |t| {
            if (t.len < 2 or !std.mem.eql(u8, t[0], "p")) continue;
            const pk = hex.decodeFixed(32, t[1]) catch continue;
            if (std.mem.eql(u8, &pk, &who)) continue;
            var dup = false;
            for (listed.items) |l| dup = dup or std.mem.eql(u8, &l, &pk);
            if (!dup) try listed.append(gpa, pk);
        }
    }

    var second: Events = .{};
    defer second.deinit(gpa);
    if (listed.items.len > 0) {
        second = try collect(gpa, io, urls.items, .{ .authors = listed.items, .kinds = &.{10154} }, timeout_ms, err);
        for (listed.items) |pk| {
            const meta = newest(second, 10154, pk) orelse continue;
            if (namesBack(meta, who)) try podcasts.append(gpa, .{ .pubkey = pk, .meta = meta });
        }
    }

    if (podcasts.items.len == 0) {
        const npub = try nip19.encodeNpub(gpa, who);
        defer gpa.free(npub);
        try err.print("deed podcast: no podcasts found for {s}\n", .{npub});
        return cli.exit_fail;
    }

    for (podcasts.items) |pod| {
        var eps = try collect(gpa, io, urls.items, .{
            .authors = &.{pod.pubkey},
            .kinds = &.{54},
            .limit = limit,
        }, timeout_ms, err);
        defer eps.deinit(gpa);
        std.mem.sort(nostr.event.Parsed, eps.parsed.items, {}, newestFirst);

        if (podcasts.items.len > 1) {
            const npub = try nip19.encodeNpub(gpa, pod.pubkey);
            defer gpa.free(npub);
            try out.writeAll("# ");
            try writeClean(out, tagValue(pod.meta, "title") orelse "<untitled>");
            try out.print(" ({s})\n", .{npub});
        }
        const shown = @min(eps.parsed.items.len, limit);
        for (eps.parsed.items[0..shown]) |p| {
            const ev = p.value;
            const id = try hex.encode(gpa, &ev.id);
            defer gpa.free(id);
            try out.print("{s}\t", .{id[0..8]});
            try writeDate(out, ev.created_at);
            try out.writeByte('\t');
            try writeClean(out, tagValue(ev, "title") orelse "<untitled>");
            try out.writeByte('\t');
            try writeClean(out, tagValue(ev, "audio") orelse "-");
            try out.writeByte('\n');
        }
        if (shown == 0) {
            try err.writeAll("deed podcast: no episodes found for that podcast\n");
        }
    }
    return cli.exit_ok;
}

const Podcast = struct {
    pubkey: [32]u8,
    meta: Event,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

/// A relay that answers each REQ with the fixtures whose kind the REQ names.
const Script = struct {
    served: []const Served,

    const Served = struct { kind: u16, json: []const u8 };

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Script = @ptrCast(@alignCast(ctx.?));
        if (std.mem.indexOf(u8, frame, "\"REQ\"") == null) return;
        const at = std.mem.indexOf(u8, frame, "\"kinds\":[") orelse return;
        const rest = frame[at + "\"kinds\":[".len ..];
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return;
        var wanted = std.mem.tokenizeScalar(u8, rest[0..close], ',');
        var buf: [8192]u8 = undefined;
        while (wanted.next()) |k| {
            const kind = std.fmt.parseInt(u16, k, 10) catch continue;
            for (self.served) |s| {
                if (s.kind != kind) continue;
                try testrelay.sendText(w, try std.fmt.bufPrint(&buf, "[\"EVENT\",\"deed\",{s}]", .{s.json}));
            }
        }
        try testrelay.sendText(w, "[\"EOSE\",\"deed\"]");
    }
};

fn sign(arena: std.mem.Allocator, signer: nostr.keys.Signer, kp: nostr.keys.KeyPair, at: i64, kind: u16, tags: []const nostr.event.Tag, content: []const u8) ![]const u8 {
    const ev = try nostr.event.create(arena, signer, kp, at, kind, tags, content, null);
    return nostr.event.toJson(arena, ev);
}

test "episodes come back newest first with title, date and media URL" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x61} ** 32);

    const meta_tags = [_]nostr.event.Tag{&.{ "title", "The Show" }};
    const old_tags = [_]nostr.event.Tag{ &.{ "title", "First" }, &.{ "audio", "https://cdn.example/1.mp3" } };
    const new_tags = [_]nostr.event.Tag{ &.{ "title", "Second\x1b[31m" }, &.{ "audio", "https://cdn.example/2.mp3" } };
    const bare_tags = [_]nostr.event.Tag{};
    // 2023-11-14 and 2024-01-01.
    const served = [_]Script.Served{
        .{ .kind = 10154, .json = try sign(arena, signer, kp, 1_700_000_000, 10154, &meta_tags, "") },
        .{ .kind = 54, .json = try sign(arena, signer, kp, 1_700_000_000, 54, &old_tags, "one") },
        .{ .kind = 54, .json = try sign(arena, signer, kp, 1_704_067_200, 54, &new_tags, "two") },
        .{ .kind = 54, .json = try sign(arena, signer, kp, 1_690_000_000, 54, &bare_tags, "three") },
    };
    var script: Script = .{ .served = &served };
    var relay: testrelay.Relay = undefined;
    try relay.startFor(io, .custom, 3);
    relay.custom = Script.handle;
    relay.custom_ctx = &script;
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    const npub = try nip19.encodeNpub(arena, kp.public_key);
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try run(gpa, io, &.{ "list", npub, "--relay", url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);

    var lines = std.mem.splitScalar(u8, out.written(), '\n');
    const l1 = lines.next().?;
    const l2 = lines.next().?;
    const l3 = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, l1, "\t2024-01-01\tSecond [31m\thttps://cdn.example/2.mp3") != null);
    try testing.expect(std.mem.indexOf(u8, l2, "\t2023-11-14\tFirst\thttps://cdn.example/1.mp3") != null);
    try testing.expect(std.mem.indexOf(u8, l3, "\t2023-07-22\t<untitled>\t-") != null);
    try testing.expect(std.mem.indexOfScalar(u8, out.written(), 0x1b) == null);
}

test "a listed podcast counts only when its metadata names the lister back" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const host = try signer.keyPairFromSecretKey([_]u8{0x62} ** 32);
    const real = try signer.keyPairFromSecretKey([_]u8{0x63} ** 32);

    const host_hex = try hex.encode(arena, &host.public_key);
    const real_hex = try hex.encode(arena, &real.public_key);
    const list_tags = [_]nostr.event.Tag{&.{ "p", real_hex }};
    const meta_tags = [_]nostr.event.Tag{ &.{ "title", "Listed Show" }, &.{ "p", host_hex } };
    const ep_tags = [_]nostr.event.Tag{ &.{ "title", "Pilot" }, &.{ "audio", "https://cdn.example/p.mp3" } };
    const served = [_]Script.Served{
        .{ .kind = 10064, .json = try sign(arena, signer, host, 1_700_000_000, 10064, &list_tags, "") },
        .{ .kind = 10154, .json = try sign(arena, signer, real, 1_700_000_000, 10154, &meta_tags, "") },
        .{ .kind = 54, .json = try sign(arena, signer, real, 1_700_000_100, 54, &ep_tags, "") },
    };
    var script: Script = .{ .served = &served };
    var relay: testrelay.Relay = undefined;
    try relay.startFor(io, .custom, 3);
    relay.custom = Script.handle;
    relay.custom_ctx = &script;
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    const npub = try nip19.encodeNpub(arena, host.public_key);
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try run(gpa, io, &.{ npub, url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\tPilot\thttps://cdn.example/p.mp3") != null);

    // Without the name back, the list alone gives nothing.
    const unclaimed = [_]nostr.event.Tag{&.{ "title", "Listed Show" }};
    const served2 = [_]Script.Served{
        .{ .kind = 10064, .json = served[0].json },
        .{ .kind = 10154, .json = try sign(arena, signer, real, 1_700_000_000, 10154, &unclaimed, "") },
        .{ .kind = 54, .json = served[2].json },
    };
    script.served = &served2;
    var relay2: testrelay.Relay = undefined;
    try relay2.startFor(io, .custom, 3);
    relay2.custom = Script.handle;
    relay2.custom_ctx = &script;
    defer relay2.stop(io);
    var url_buf2: [40]u8 = undefined;
    const url2 = try testrelay.url(&url_buf2, relay2.port());
    var out2: std.Io.Writer.Allocating = .init(arena);
    var err2: std.Io.Writer.Allocating = .init(arena);
    const none = try run(gpa, io, &.{ npub, url2 }, &out2.writer, &err2.writer);
    try testing.expectEqual(cli.exit_fail, none);
    try testing.expectEqual(@as(usize, 0), out2.written().len);
    try testing.expect(std.mem.indexOf(u8, err2.written(), "no podcasts found") != null);
}

test "play and info are refused, and a missing person is a usage error" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{ "play", "x" }, &out.writer, &err.writer));
    try testing.expect(std.mem.indexOf(u8, err.written(), "only lists") != null);
    err.clearRetainingCapacity();
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{}, &out.writer, &err.writer));
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{ "a", "b" }, &out.writer, &err.writer));
}
