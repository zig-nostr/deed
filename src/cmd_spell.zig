//! `deed spell`: fetch a spell (kind 777) and run the REQ its tags describe.
//!
//! A spell keeps a subscription in an event: `k`, `authors`, `ids`, `tag`,
//! `limit`, `since`, `until` and `search` tags are the filter, `relays` says
//! where to ask (`$outbox` meaning each author's own write relays), and
//! `$me` and `$contacts` stand for the reader and the people they follow.
//! The format follows the spells in use on relays today, since no merged NIP
//! defines it yet. The spell is checked like any event before it is used.

const std = @import("std");
const nostr = @import("nostr");
const auth = @import("auth.zig");
const cli = @import("cli.zig");
const cmd_req = @import("cmd_req.zig");
const filterflags = @import("filterflags.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const relayset = @import("relayset.zig");

const nip19 = nostr.nip19;
const filter = nostr.filter;

/// Shown beside the name in `deed help`.
pub const summary = "fetch a spell and run the subscription it holds";

pub const ready = true;

pub const spell_kind: u16 = 777;

pub const usage =
    \\deed spell: fetch a spell and run the subscription it holds
    \\
    \\Usage:
    \\  deed spell [options] <nevent|naddr|note|id> [<relay-url>...]
    \\
    \\A spell is a kind 777 event whose tags describe a REQ. It is looked for at
    \\the relays in the code, the ones named here, and those given with --relay or
    \\in DEED_RELAYS, and its signature is checked before it is used. Then the
    \\subscription runs as `deed req` would run it, against the relays the spell
    \\lists plus any named here; a spell that lists none, or lists $outbox, asks
    \\each author's own write relays (as `deed req --outbox`).
    \\
    \\$me and $contacts in `authors` and `tag` stand for the reader and the people
    \\they follow. Say who the reader is with --pub, or with --sec.
    \\
    \\Options:
    \\      --pub <key>      who $me is, as npub1... or 64 hex characters
    \\      --sec <key>      who $me is, from a secret key; with --auth it also
    \\                       answers NIP-42 challenges
    \\  -n, --outbox-relays-per-pubkey <n>
    \\                       how many of an author's write relays to ask (default 3)
    \\  -r, --relay <url>    where to look for the spell and for relay lists,
    \\                       repeatable (and DEED_RELAYS)
    \\      --stream         keep reading after the relays have sent what they hold
    \\                       (it cannot be combined with $outbox)
    \\      --timeout <ms>   give up on relays still answering (default 30000)
    \\      --auth, --force-pre-auth
    \\                       answer NIP-42 challenges (needs --sec)
    \\
    \\A spell without a `close-on-eose` tag still ends once the relays have sent
    \\what they hold, unless --stream is given.
    \\
    \\Exits: 0 on success; 1 if the spell cannot be found or read, or no relay
    \\answered; 2 if the command line was not understood.
    \\
;

const max_relays_listed = 64;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var code: ?[]const u8 = null;
    var relays: std.ArrayList([]const u8) = .empty;
    var bootstrap: std.ArrayList([]const u8) = .empty;
    var pub_arg: ?[]const u8 = null;
    var sec_arg: ?[]const u8 = null;
    var per_pubkey: []const u8 = "3";
    var timeout_arg: []const u8 = "30000";
    var timeout_ms: i64 = cmd_req.default_timeout_ms;
    var stream = false;
    var auth_flags: auth.Flags = .{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (cli.isOneOf(arg, &.{ "help", "--help", "-h" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        switch (auth_flags.take(args, &i)) {
            .taken => continue,
            .missing_value => {
                try err.print("deed spell: '{s}' needs a value\n", .{arg});
                return cli.exit_usage;
            },
            .not_mine => {},
        }
        if (std.mem.eql(u8, arg, "--stream")) {
            stream = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            if (!cli.isOneOf(arg, &.{ "--pub", "-n", "--outbox-relays-per-pubkey", "-r", "--relay", "--timeout" })) {
                try err.print("deed spell: unknown option '{s}'\n", .{arg});
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed spell: '{s}' needs a value\n", .{arg});
                return cli.exit_usage;
            }
            const v = args[i];
            if (std.mem.eql(u8, arg, "--pub")) {
                pub_arg = v;
            } else if (cli.isOneOf(arg, &.{ "-n", "--outbox-relays-per-pubkey" })) {
                per_pubkey = v;
            } else if (cli.isOneOf(arg, &.{ "-r", "--relay" })) {
                try bootstrap.append(a, v);
            } else {
                timeout_arg = v;
                timeout_ms = std.fmt.parseInt(i64, v, 10) catch {
                    try err.print("deed spell: '{s}' is not a number of milliseconds\n", .{v});
                    return cli.exit_fail;
                };
            }
            continue;
        }
        if (std.mem.startsWith(u8, arg, "wss://") or std.mem.startsWith(u8, arg, "ws://")) {
            try relays.append(a, arg);
        } else if (code == null) {
            code = arg;
        } else {
            try err.writeAll("deed spell: takes one code\n");
            return cli.exit_usage;
        }
    }
    sec_arg = auth_flags.sec;
    const raw = code orelse {
        try err.writeAll("deed spell: needs the code of a spell\n");
        return cli.exit_usage;
    };

    // What the code names.
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = .{spell_kind};
    var d_values: [1][]const u8 = undefined;
    var tag_filters: [1]filter.TagFilter = undefined;
    var fetch_filter: filter.Filter = .{};
    var fetch_relays: std.ArrayList([]const u8) = .empty;
    try fetch_relays.appendSlice(a, relays.items);
    try fetch_relays.appendSlice(a, bootstrap.items);
    try outbox.appendEnvBootstrap(a, &fetch_relays);

    const s = keyinput.stripUri(raw);
    if (keyinput.hasPrefix(s, "nevent1")) {
        const p = nip19.decodeNevent(a, s) catch return badCode(err, raw);
        ids[0] = p.id;
        fetch_filter = .{ .ids = ids[0..1] };
        for (p.relays) |r| try fetch_relays.append(a, r);
    } else if (keyinput.hasPrefix(s, "note1")) {
        ids[0] = nip19.decodeNote(a, s) catch return badCode(err, raw);
        fetch_filter = .{ .ids = ids[0..1] };
    } else if (keyinput.hasPrefix(s, "naddr1")) {
        const p = nip19.decodeNaddr(a, s) catch return badCode(err, raw);
        if (p.kind != spell_kind) {
            try err.print("deed spell: {s} names kind {d}, and a spell is kind {d}\n", .{ raw, p.kind, spell_kind });
            return cli.exit_fail;
        }
        authors[0] = p.pubkey;
        d_values[0] = p.identifier;
        tag_filters[0] = .{ .letter = 'd', .values = d_values[0..1] };
        fetch_filter = .{ .authors = authors[0..1], .kinds = kinds[0..1], .tags = tag_filters[0..1] };
        for (p.relays) |r| try fetch_relays.append(a, r);
    } else if (s.len == 64) {
        ids[0] = (nostr.hex.decodeFixed(32, s)) catch return badCode(err, raw);
        fetch_filter = .{ .ids = ids[0..1] };
    } else return badCode(err, raw);

    if (fetch_relays.items.len == 0) {
        try err.writeAll("deed spell: name a relay to look for the spell at (as an argument, with --relay, or in DEED_RELAYS)\n");
        return cli.exit_usage;
    }

    const auth_opts = auth.resolve(a, auth_flags, "spell", err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };

    // The spell, checked by the same code every run uses.
    var spell_ev = (try fetchOne(a, gpa, io, fetch_relays.items, fetch_filter, timeout_ms, auth_opts, err)) orelse {
        try err.print("deed spell: {s}: no spell found at those relays\n", .{raw});
        return cli.exit_fail;
    };
    defer spell_ev.deinit();
    const spell = spell_ev.value;
    if (spell.kind != spell_kind) {
        try err.print("deed spell: that event is kind {d}, and a spell is kind {d}\n", .{ spell.kind, spell_kind });
        return cli.exit_fail;
    }

    // Who $me is, only if the spell asks.
    var me: ?[32]u8 = null;
    if (pub_arg) |p| {
        me = keyinput.publicKey(a, p) catch {
            try err.print("deed spell: '{s}' is not a public key (want npub1... or 64 hex characters)\n", .{p});
            return cli.exit_fail;
        };
    } else if (sec_arg) |sk_raw| {
        const sk = keyinput.secretKeyForVerb(a, "spell", sk_raw, err) catch return cli.exit_fail;
        var signer = nostr.keys.Signer.init();
        defer signer.deinit();
        const kp = signer.keyPairFromSecretKey(sk) catch {
            try err.writeAll("deed spell: not a secret key (want nsec1... or 64 hex characters)\n");
            return cli.exit_fail;
        };
        me = kp.public_key;
    }

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    var ctx: Ctx = .{ .a = a, .gpa = gpa, .io = io, .me = me, .relays = fetch_relays.items, .timeout_ms = timeout_ms, .auth = auth_opts, .err = err };
    const json = (try buildFilter(&ctx, spell.tags, now)) orelse return cli.exit_fail;

    // Where to ask.
    var uses_outbox = true;
    var explicit: std.ArrayList([]const u8) = .empty;
    try explicit.appendSlice(a, relays.items);
    for (spell.tags) |t| {
        if (t.len == 0 or !std.mem.eql(u8, t[0], "relays")) continue;
        uses_outbox = false;
        for (t[1..]) |v| {
            if (std.mem.eql(u8, v, "$outbox")) {
                uses_outbox = true;
            } else if (std.mem.startsWith(u8, v, "wss://") or std.mem.startsWith(u8, v, "ws://")) {
                try explicit.append(a, v);
            }
        }
    }
    if (explicit.items.len > max_relays_listed) explicit.items.len = max_relays_listed;

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(a, json);
    try argv.appendSlice(a, &.{ "--timeout", timeout_arg });
    if (stream) try argv.append(a, "--stream");
    if (uses_outbox) try argv.appendSlice(a, &.{ "--outbox", "-n", per_pubkey });
    for (bootstrap.items) |r| try argv.appendSlice(a, &.{ "--relay", r });
    if (auth_flags.auth) try argv.append(a, "--auth");
    if (auth_flags.force_pre_auth) try argv.append(a, "--force-pre-auth");
    if (auth_opts != null) if (auth_flags.sec) |sk| try argv.appendSlice(a, &.{ "--sec", sk });
    try argv.appendSlice(a, explicit.items);

    if (!uses_outbox and explicit.items.len == 0) {
        try err.writeAll("deed spell: the spell lists no relay: name one\n");
        return cli.exit_usage;
    }
    return cmd_req.runWith(gpa, io, argv.items, null, out, err);
}

fn badCode(err: *std.Io.Writer, raw: []const u8) !u8 {
    try err.print("deed spell: {s}: not a code naming a spell (want nevent, naddr, note or 64 hex characters)\n", .{raw});
    return cli.exit_fail;
}

/// The first verified event the relays send for `f`.
fn fetchOne(
    a: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    f: filter.Filter,
    timeout_ms: i64,
    auth_opts: ?auth.Options,
    err: *std.Io.Writer,
) !?nostr.event.Parsed {
    _ = a;
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    const outcome = try relayset.query(gpa, io, urls, &.{f}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
        .auth = auth_opts,
    });
    _ = outcome;
    // The newest, for a replaceable spell asked for by address.
    var best: ?nostr.event.Parsed = null;
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var p = nostr.event.fromJson(gpa, line) catch continue;
        if (best) |*b| {
            if (p.value.created_at > b.value.created_at) {
                b.deinit();
                best = p;
            } else p.deinit();
        } else best = p;
    }
    return best;
}

const Ctx = struct {
    a: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    me: ?[32]u8,
    relays: []const []const u8,
    timeout_ms: i64,
    auth: ?auth.Options,
    err: *std.Io.Writer,
    contacts: ?[]const []const u8 = null,

    fn meHex(self: *Ctx) !?[]const u8 {
        const pk = self.me orelse {
            try self.err.writeAll("deed spell: this spell uses $me or $contacts: say who you are with --pub or --sec\n");
            return null;
        };
        return try nostr.hex.encode(self.a, &pk);
    }

    /// The pubkeys of the reader's newest follow list.
    fn followed(self: *Ctx) !?[]const []const u8 {
        if (self.contacts) |c| return c;
        const me = self.me orelse {
            try self.err.writeAll("deed spell: this spell uses $me or $contacts: say who you are with --pub or --sec\n");
            return null;
        };
        const k = [_]u16{3};
        const au = [_][32]u8{me};
        var ev = (try fetchOne(self.a, self.gpa, self.io, self.relays, .{ .authors = &au, .kinds = &k, .limit = 1 }, self.timeout_ms, self.auth, self.err)) orelse {
            try self.err.writeAll("deed spell: found no follow list for $contacts\n");
            return null;
        };
        defer ev.deinit();
        var list: std.ArrayList([]const u8) = .empty;
        for (ev.value.tags) |t| {
            if (t.len >= 2 and std.mem.eql(u8, t[0], "p") and t[1].len == 64) try list.append(self.a, try self.a.dupe(u8, t[1]));
        }
        self.contacts = list.items;
        return list.items;
    }

    /// One value of a tag, with $me and $contacts replaced. Null after saying
    /// why when it cannot be.
    fn expand(self: *Ctx, v: []const u8, into: *std.ArrayList([]const u8)) !bool {
        if (std.mem.eql(u8, v, "$me")) {
            const h = (try self.meHex()) orelse return false;
            try into.append(self.a, h);
        } else if (std.mem.eql(u8, v, "$contacts")) {
            const list = (try self.followed()) orelse return false;
            try into.appendSlice(self.a, list);
        } else try into.append(self.a, v);
        return true;
    }
};

const TagValues = struct { name: []const u8, values: std.ArrayList([]const u8) = .empty };

/// The JSON filter a spell's tags describe. Null after saying why on stderr
/// when a tag cannot be read.
fn buildFilter(ctx: *Ctx, tags: []const nostr.event.Tag, now: i64) !?[]const u8 {
    const a = ctx.a;
    const err = ctx.err;
    var ids: std.ArrayList([]const u8) = .empty;
    var authors: std.ArrayList([]const u8) = .empty;
    var kinds: std.ArrayList(u16) = .empty;
    var tagged: std.ArrayList(TagValues) = .empty;
    var limit: ?u32 = null;
    var since: ?i64 = null;
    var until: ?i64 = null;
    var search: ?[]const u8 = null;

    for (tags) |t| {
        if (t.len == 0) continue;
        const name = t[0];
        if (std.mem.eql(u8, name, "cmd")) {
            if (t.len < 2 or !std.mem.eql(u8, t[1], "REQ")) {
                try err.writeAll("deed spell: only REQ spells can be run\n");
                return null;
            }
        } else if (std.mem.eql(u8, name, "k")) {
            for (t[1..]) |v| {
                if (std.fmt.parseInt(u16, v, 10)) |n| try kinds.append(a, n) else |_| {}
            }
        } else if (std.mem.eql(u8, name, "authors") or std.mem.eql(u8, name, "ids")) {
            const is_authors = name[0] == 'a';
            var vals: std.ArrayList([]const u8) = .empty;
            for (t[1..]) |v| if (!try ctx.expand(v, &vals)) return null;
            for (vals.items) |v| {
                const key = filterflags.idOrKey(a, v) orelse {
                    try err.print("deed spell: '{s}' in '{s}' is not a 64 character hex value\n", .{ v, name });
                    return null;
                };
                const h = try nostr.hex.encode(a, &key);
                try (if (is_authors) authors else ids).append(a, h);
            }
        } else if (std.mem.eql(u8, name, "tag")) {
            if (t.len < 3) continue;
            if (t[1].len != 1) {
                try err.print("deed spell: '{s}' is not a one-letter tag name\n", .{t[1]});
                return null;
            }
            var tv: TagValues = .{ .name = t[1] };
            for (t[2..]) |v| if (!try ctx.expand(v, &tv.values)) return null;
            try tagged.append(a, tv);
        } else if (std.mem.eql(u8, name, "limit")) {
            if (t.len >= 2) limit = std.fmt.parseInt(u32, t[1], 10) catch null;
        } else if (std.mem.eql(u8, name, "since") or std.mem.eql(u8, name, "until")) {
            if (t.len < 2) continue;
            const when = filterflags.parseTime(t[1], now) orelse {
                try err.print("deed spell: '{s}' is not a time in '{s}'\n", .{ t[1], name });
                return null;
            };
            if (name[0] == 's') since = when else until = when;
        } else if (std.mem.eql(u8, name, "search")) {
            if (t.len >= 2) search = t[1];
        }
    }

    var buf: std.Io.Writer.Allocating = .init(a);
    const w = &buf.writer;
    try w.writeByte('{');
    var first = true;
    if (ids.items.len > 0) first = try writeStrings(w, first, "ids", ids.items);
    if (authors.items.len > 0) first = try writeStrings(w, first, "authors", authors.items);
    if (kinds.items.len > 0) {
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("\"kinds\":[");
        for (kinds.items, 0..) |k, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("{d}", .{k});
        }
        try w.writeByte(']');
    }
    for (tagged.items) |tv| {
        if (tv.values.items.len == 0) continue;
        var key: [2]u8 = .{ '#', tv.name[0] };
        first = try writeStrings(w, first, &key, tv.values.items);
    }
    if (since) |v| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("\"since\":{d}", .{v});
    }
    if (until) |v| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("\"until\":{d}", .{v});
    }
    if (limit) |v| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("\"limit\":{d}", .{v});
    }
    if (search) |v| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("\"search\":");
        try std.json.Stringify.encodeJsonString(v, .{}, w);
    }
    try w.writeByte('}');
    return buf.written();
}

fn writeStrings(w: *std.Io.Writer, first: bool, key: []const u8, values: []const []const u8) !bool {
    if (!first) try w.writeByte(',');
    try w.print("\"{s}\":[", .{key});
    for (values, 0..) |v, i| {
        if (i > 0) try w.writeByte(',');
        try std.json.Stringify.encodeJsonString(v, .{}, w);
    }
    try w.writeByte(']');
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

test "a spell's tags become a filter, with $me replaced" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var err: std.Io.Writer.Allocating = .init(a);
    const me = [_]u8{0xab} ** 32;
    var ctx: Ctx = .{ .a = a, .gpa = testing.allocator, .io = testing.io, .me = me, .relays = &.{}, .timeout_ms = 1000, .auth = null, .err = &err.writer };
    const tags = [_]nostr.event.Tag{
        &.{ "cmd", "REQ" },
        &.{ "k", "1", "6" },
        &.{ "authors", "$me" },
        &.{ "tag", "t", "zig", "nostr" },
        &.{ "since", "2h" },
        &.{ "limit", "20" },
        &.{ "search", "a \"b\"" },
        &.{ "relays", "$outbox" },
    };
    const json = (try buildFilter(&ctx, &tags, 10_000)).?;
    try testing.expectEqualStrings(
        "{\"authors\":[\"" ++ "ab" ** 32 ++ "\"],\"kinds\":[1,6],\"#t\":[\"zig\",\"nostr\"],\"since\":2800,\"limit\":20,\"search\":\"a \\\"b\\\"\"}",
        json,
    );

    // Without a reader, $me is refused and says what to pass.
    ctx.me = null;
    try testing.expect((try buildFilter(&ctx, &tags, 10_000)) == null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "--pub") != null);

    // Only REQ spells run.
    const count_tags = [_]nostr.event.Tag{&.{ "cmd", "COUNT" }};
    try testing.expect((try buildFilter(&ctx, &count_tags, 0)) == null);
}

test "a spell is fetched, checked and run against the relays it lists" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const reader = try signer.keyPairFromSecretKey([_]u8{0x71} ** 32);
    const other = try signer.keyPairFromSecretKey([_]u8{0x72} ** 32);

    const mine = try nostr.event.create(arena, signer, reader, 1_700_000_100, 1, &.{}, "my note", null);
    const theirs = try nostr.event.create(arena, signer, other, 1_700_000_200, 1, &.{}, "their note", null);

    var home: testrelay.Relay = undefined;
    try home.startFor(io, .serve, 2);
    defer home.stop(io);
    var hb: [40]u8 = undefined;
    const home_url = try testrelay.url(&hb, home.port());

    const spell_tags = [_]nostr.event.Tag{
        &.{ "cmd", "REQ" },
        &.{ "k", "1" },
        &.{ "authors", "$me" },
        &.{ "relays", home_url },
        &.{"close-on-eose"},
    };
    const spell = try nostr.event.create(arena, signer, other, 1_700_000_300, spell_tags_kind, &spell_tags, "my notes", null);
    home.serving = &.{
        try nostr.event.toJson(arena, spell),
        try nostr.event.toJson(arena, mine),
        try nostr.event.toJson(arena, theirs),
    };

    const id_hex = try nostr.hex.encode(arena, &spell.id);
    const me_hex = try nostr.hex.encode(arena, &reader.public_key);
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try run(gpa, io, &.{ id_hex, "--pub", me_hex, "--timeout", "5000", home_url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expect(std.mem.indexOf(u8, out.written(), "my note") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "their note") == null);

    // No reader named, and the spell needs one.
    var out2: std.Io.Writer.Allocating = .init(arena);
    var err2: std.Io.Writer.Allocating = .init(arena);
    var home2: testrelay.Relay = undefined;
    try home2.start(io, .serve);
    home2.serving = home.serving;
    defer home2.stop(io);
    var hb2: [40]u8 = undefined;
    const home2_url = try testrelay.url(&hb2, home2.port());
    const code2 = try run(gpa, io, &.{ id_hex, "--timeout", "5000", home2_url }, &out2.writer, &err2.writer);
    try testing.expectEqual(cli.exit_fail, code2);
    try testing.expect(std.mem.indexOf(u8, err2.written(), "--pub") != null);
}

const spell_tags_kind: u16 = spell_kind;
