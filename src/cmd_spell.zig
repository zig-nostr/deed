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
const signing = @import("signing.zig");
const cli = @import("cli.zig");
const cmd_req = @import("cmd_req.zig");
const filterflags = @import("filterflags.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const relayset = @import("relayset.zig");

const nip19 = nostr.nip19;
const http = @import("http.zig");
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
    \\The relays a spell lists are the spell author's choice, so they are printed
    \\to stderr before anything is asked of them. A listed relay at a loopback
    \\or private network address (localhost, 127.x, 10.x, 192.168.x, a name with
    \\no dot, and the like) is refused unless --allow-local is given, or the
    \\address was also named on this command line. NIP-42 challenges are
    \\answered only at relays named on this command line, never at relays that
    \\came from the spell or from $outbox.
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
    \\      --allow-local    accept listed relays at loopback or private addresses
    \\      --auth, --force-pre-auth
    \\                       answer NIP-42 challenges (needs --sec), at the relays
    \\                       named on this command line
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
    var allow_local = false;
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
        if (std.mem.eql(u8, arg, "--allow-local")) {
            allow_local = true;
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
                timeout_ms = std.fmt.parseInt(i64, v, 10) catch 0;
                if (timeout_ms <= 0) {
                    try err.print("deed spell: --timeout needs a number of milliseconds above zero, not '{s}'\n", .{v});
                    return cli.exit_usage;
                }
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

    // The allocator, not the arena: a remote signer's readers allocate from
    // their own threads.
    // An ncryptsec is opened here, once, and every reader after this (the
    // challenge answers, $me, the nested req runs) is handed the plain key.
    var plain_key: ?keyinput.PlainKey = null;
    defer if (plain_key) |*k| k.deinit();
    if (auth_flags.auth or auth_flags.force_pre_auth) {
        if (auth_flags.sec orelse envSecret()) |raw_key| {
            var session = keyinput.terminalSession();
            defer session.deinit();
            plain_key = keyinput.decryptOnce(gpa, "spell", raw_key, &session, err) catch |e| switch (e) {
                error.BadKey => return cli.exit_fail,
                else => return e,
            };
            if (plain_key) |*k| auth_flags.sec = k.slice();
        }
    }
    sec_arg = auth_flags.sec;
    const auth_opts = auth.resolve(gpa, io, auth_flags, "spell", err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };
    defer if (auth_opts) |o| o.deinit(gpa);

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
    } else if (auth_opts) |o| {
        // The key or remote signer already open for NIP-42 says who the user
        // is: opening it again would read the key a second time.
        if (o.remote) |r| {
            me = r.publicKey();
        } else if (o.keypair) |kp| {
            me = kp.public_key;
        }
    } else if (sec_arg) |sk_raw| {
        var signer = (try signing.open(gpa, io, "spell", sk_raw, err)) orelse return cli.exit_fail;
        defer signer.deinit();
        me = signer.publicKey();
    }

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    var ctx: Ctx = .{ .a = a, .gpa = gpa, .io = io, .me = me, .relays = fetch_relays.items, .timeout_ms = timeout_ms, .auth = auth_opts, .err = err };
    const json = (try buildFilter(&ctx, spell.tags, now)) orelse return cli.exit_fail;

    // Where to ask.
    var uses_outbox = true;
    var from_spell: std.ArrayList([]const u8) = .empty;
    for (spell.tags) |t| {
        if (t.len == 0 or !std.mem.eql(u8, t[0], "relays")) continue;
        uses_outbox = false;
        for (t[1..]) |v| {
            if (std.mem.eql(u8, v, "$outbox")) {
                uses_outbox = true;
            } else if (std.mem.startsWith(u8, v, "wss://") or std.mem.startsWith(u8, v, "ws://")) {
                try from_spell.append(a, v);
            }
        }
    }
    if (from_spell.items.len > max_relays_listed) {
        try err.print("deed spell: the spell lists {d} relays; only the first {d} are used\n", .{ from_spell.items.len, max_relays_listed });
        from_spell.items.len = max_relays_listed;
    }

    // The ones the spell adds to what was named here.
    var added: std.ArrayList([]const u8) = .empty;
    for (from_spell.items) |u| {
        if (containsUrl(relays.items, u) or containsUrl(bootstrap.items, u) or containsUrl(added.items, u)) continue;
        try added.append(a, u);
    }
    if (from_spell.items.len > 0 or uses_outbox) {
        try err.writeAll("deed spell: the spell asks ");
        if (from_spell.items.len == 0) {
            try err.writeAll("each author's own write relays");
        } else {
            for (from_spell.items, 0..) |u, k| {
                try err.writeAll(if (k == 0) "" else ", ");
                try relayset.writeEscaped(err, u);
            }
            if (uses_outbox) try err.writeAll(", and each author's own write relays");
        }
        try err.writeByte('\n');
    }
    if (!allow_local) {
        for (added.items) |u| if (isLocalRelay(u)) {
            try err.writeAll("deed spell: the spell lists a relay at a loopback or private address, which is not asked: ");
            try relayset.writeEscaped(err, u);
            try err.writeAll("\nName it on the command line, or pass --allow-local, to ask it.\n");
            return cli.exit_fail;
        };
    }

    if (relays.items.len == 0 and from_spell.items.len == 0 and !uses_outbox) {
        try err.writeAll("deed spell: the spell lists no relay: name one\n");
        return cli.exit_usage;
    }

    // NIP-42 is answered only where the reader named the relay. What the spell
    // added, and the outbox relays, are asked without it.
    var trusted: std.ArrayList([]const u8) = .empty;
    try trusted.appendSlice(a, relays.items);
    for (from_spell.items) |u| if (containsUrl(relays.items, u) or containsUrl(bootstrap.items, u)) {
        if (!containsUrl(trusted.items, u)) try trusted.append(a, u);
    };
    const authing = auth_opts != null;
    if (authing and (added.items.len > 0 or uses_outbox)) {
        try err.writeAll("deed spell: NIP-42 challenges are answered only at relays named on the command line, not at relays from the spell\n");
    }

    const base = [_][]const u8{ json, "--timeout", timeout_arg };
    if (!authing or (added.items.len == 0 and !uses_outbox)) {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(a, &base);
        if (stream) try argv.append(a, "--stream");
        if (uses_outbox) try argv.appendSlice(a, &.{ "--outbox", "-n", per_pubkey });
        for (bootstrap.items) |r| try argv.appendSlice(a, &.{ "--relay", r });
        if (authing) try appendAuth(a, &argv, auth_flags);
        try argv.appendSlice(a, trusted.items);
        try argv.appendSlice(a, added.items);
        return cmd_req.runWith(gpa, io, argv.items, null, out, err);
    }

    // Two passes, so the relays that may be answered and the ones that may not
    // never share a connection setting.
    var code1: u8 = cli.exit_fail;
    if (trusted.items.len > 0) {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(a, &base);
        if (stream) try argv.append(a, "--stream");
        try appendAuth(a, &argv, auth_flags);
        try argv.appendSlice(a, trusted.items);
        code1 = try cmd_req.runWith(gpa, io, argv.items, null, out, err);
    }
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &base);
    if (stream) try argv.append(a, "--stream");
    if (uses_outbox) try argv.appendSlice(a, &.{ "--outbox", "-n", per_pubkey });
    for (bootstrap.items) |r| try argv.appendSlice(a, &.{ "--relay", r });
    try argv.appendSlice(a, added.items);
    const code2 = try cmd_req.runWith(gpa, io, argv.items, null, out, err);
    return if (code1 == cli.exit_ok or code2 == cli.exit_ok) cli.exit_ok else code2;
}

fn envSecret() ?[]const u8 {
    const value = std.c.getenv("NOSTR_SECRET_KEY") orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

fn appendAuth(a: std.mem.Allocator, argv: *std.ArrayList([]const u8), flags: auth.Flags) !void {
    if (flags.auth) try argv.append(a, "--auth");
    if (flags.force_pre_auth) try argv.append(a, "--force-pre-auth");
    if (flags.sec) |sk| try argv.appendSlice(a, &.{ "--sec", sk });
}

fn containsUrl(list: []const []const u8, url: []const u8) bool {
    for (list) |u| if (std.mem.eql(u8, u, url)) return true;
    return false;
}

/// The host of a ws:// or wss:// URL, without brackets, userinfo or port.
fn relayHost(url: []const u8) []const u8 {
    const sep = std.mem.indexOf(u8, url, "://") orelse return "";
    var rest = url[sep + 3 ..];
    if (std.mem.indexOfAny(u8, rest, "/?#")) |e| rest = rest[0..e];
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| rest = rest[at + 1 ..];
    if (rest.len > 0 and rest[0] == '[') {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return rest;
        return rest[1..close];
    }
    if (std.mem.indexOfScalar(u8, rest, ':')) |c| rest = rest[0..c];
    return rest;
}

/// True for a relay at this machine or on a private network: loopback,
/// RFC 1918, link-local, carrier-grade NAT, unique-local IPv6, and the names
/// that only mean something inside a network (no dot, .local, .internal, ...).
/// A name that resolves to such an address is not seen here.
fn isLocalRelay(url: []const u8) bool {
    var host = relayHost(url);
    while (host.len > 0 and host[host.len - 1] == '.') host = host[0 .. host.len - 1];
    if (host.len == 0) return true;
    if (http.isLoopbackHost(host)) return true;
    if (std.Io.net.IpAddress.parse(host, 0)) |addr| {
        return switch (addr) {
            .ip4 => |v4| isPrivateV4(v4.bytes),
            .ip6 => |v6| isPrivateV6(v6.bytes),
        };
    } else |_| {}
    // 2130706433, 0x7f.1 and the like are addresses spelled oddly.
    var digits_only = true;
    for (host) |c| if (!std.ascii.isDigit(c) and c != '.') {
        digits_only = false;
    };
    if (digits_only or std.ascii.startsWithIgnoreCase(host, "0x")) return true;
    if (std.mem.indexOfScalar(u8, host, '.') == null) return true;
    const suffixes = [_][]const u8{ ".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet", ".private" };
    for (suffixes) |suf| if (std.ascii.endsWithIgnoreCase(host, suf)) return true;
    return false;
}

fn isPrivateV4(b: [4]u8) bool {
    if (b[0] == 0 or b[0] == 10 or b[0] == 127) return true;
    if (b[0] == 169 and b[1] == 254) return true;
    if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return true;
    if (b[0] == 192 and b[1] == 168) return true;
    if (b[0] == 100 and b[1] >= 64 and b[1] <= 127) return true;
    return false;
}

fn isPrivateV6(b: [16]u8) bool {
    if (std.mem.eql(u8, b[0..15], &[_]u8{0} ** 15) and (b[15] == 0 or b[15] == 1)) return true;
    if ((b[0] & 0xfe) == 0xfc) return true;
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true;
    if (std.mem.eql(u8, b[0..10], &[_]u8{0} ** 10) and b[10] == 0xff and b[11] == 0xff) return isPrivateV4(b[12..16].*);
    return false;
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
            if (t[1].len != 1 or !std.ascii.isAlphabetic(t[1][0])) {
                try err.writeAll("deed spell: the tag name '");
                try relayset.writeEscaped(err, t[1]);
                try err.writeAll("' is not a single letter\n");
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
        const key: [2]u8 = .{ '#', tv.name[0] };
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
    try std.json.Stringify.encodeJsonString(key, .{}, w);
    try w.writeAll(":[");
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

test "loopback, private and bare-name relays are told apart from public ones" {
    const local = [_][]const u8{
        "ws://localhost:7777",
        "ws://127.0.0.1",
        "ws://127.5.5.5:1",
        "wss://10.1.2.3",
        "wss://172.16.0.1/x",
        "wss://172.31.255.255",
        "ws://192.168.1.10:80",
        "ws://169.254.169.254",
        "ws://100.64.0.1",
        "ws://0.0.0.0",
        "ws://[::1]:9",
        "ws://[fd00::1]",
        "ws://[fe80::1]",
        "ws://[::ffff:10.0.0.1]",
        "ws://nas",
        "ws://printer.local",
        "ws://x.internal",
        "ws://2130706433",
        "ws://0x7f.1",
        "ws://user@localhost",
        "ws://localhost.",
    };
    for (local) |u| testing.expect(isLocalRelay(u)) catch |e| {
        std.debug.print("expected local: {s}\n", .{u});
        return e;
    };
    const public = [_][]const u8{
        "wss://relay.damus.io",
        "wss://nos.lol/",
        "wss://8.8.8.8",
        "wss://172.32.0.1",
        "wss://100.128.0.1",
        "wss://[2606:4700::1111]",
    };
    for (public) |u| testing.expect(!isLocalRelay(u)) catch |e| {
        std.debug.print("expected public: {s}\n", .{u});
        return e;
    };
}

test "a tag name that is not a letter is refused, and the key is written as JSON" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var err: std.Io.Writer.Allocating = .init(a);
    var ctx: Ctx = .{ .a = a, .gpa = testing.allocator, .io = testing.io, .me = null, .relays = &.{}, .timeout_ms = 1000, .auth = null, .err = &err.writer };
    const quote = [_]nostr.event.Tag{&.{ "tag", "\"", "x" }};
    try testing.expect((try buildFilter(&ctx, &quote, 0)) == null);
    const digit = [_]nostr.event.Tag{&.{ "tag", "1", "x" }};
    try testing.expect((try buildFilter(&ctx, &digit, 0)) == null);
    const ok = [_]nostr.event.Tag{&.{ "tag", "p", "x" }};
    try testing.expectEqualStrings("{\"#p\":[\"x\"]}", (try buildFilter(&ctx, &ok, 0)).?);
}

test "a --timeout that is not a number exits 2" {
    const gpa = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try testing.expectEqual(cli.exit_usage, try run(gpa, testing.io, &.{ "--timeout", "soon", "ab" ** 32 }, &out.writer, &err.writer));
    try testing.expectEqual(cli.exit_usage, try run(gpa, testing.io, &.{ "--timeout", "0", "ab" ** 32 }, &out.writer, &err.writer));
}

/// A relay that answers every REQ with `serving` and counts the AUTH frames
/// it is sent, after greeting each connection with a challenge.
const Counting = struct {
    serving: []const []const u8 = &.{},
    auths: usize = 0,

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Counting = @ptrCast(@alignCast(ctx.?));
        const a = std.heap.page_allocator;
        var parsed = try std.json.parseFromSlice(std.json.Value, a, frame, .{});
        defer parsed.deinit();
        const items = parsed.value.array.items;
        const verb = items[0].string;
        if (std.mem.eql(u8, verb, "AUTH")) {
            self.auths += 1;
            const id = items[1].object.get("id").?.string;
            const ok = try std.fmt.allocPrint(a, "[\"OK\",\"{s}\",true,\"\"]", .{id});
            defer a.free(ok);
            try testrelay.sendText(w, ok);
        } else if (std.mem.eql(u8, verb, "REQ")) {
            for (self.serving) |ev| {
                const m = try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ items[1].string, ev });
                defer a.free(m);
                try testrelay.sendText(w, m);
            }
            const eose = try std.fmt.allocPrint(a, "[\"EOSE\",\"{s}\"]", .{items[1].string});
            defer a.free(eose);
            try testrelay.sendText(w, eose);
        }
    }
};

const Fixture = struct {
    da: testrelay.DialAllocator = .init,
    arena_state: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(std.heap.page_allocator),
    home: testrelay.Relay = undefined,
    far: testrelay.Relay = undefined,
    home_state: Counting = .{},
    far_state: Counting = .{},
    home_buf: [40]u8 = undefined,
    far_buf: [40]u8 = undefined,
    home_url: []const u8 = "",
    far_url: []const u8 = "",
    spell_id: []const u8 = "",

    /// `home` holds the spell, which lists `far` and nothing else.
    fn start(self: *Fixture, io: std.Io, home_conns: usize, far_conns: usize) !void {
        const arena = self.arena_state.allocator();
        try self.home.startFor(io, .custom, home_conns);
        try self.far.startFor(io, .custom, far_conns);
        self.home.custom = Counting.handle;
        self.home.custom_ctx = &self.home_state;
        self.far.custom = Counting.handle;
        self.far.custom_ctx = &self.far_state;
        self.home.greeting = "[\"AUTH\",\"chal-home\"]";
        self.far.greeting = "[\"AUTH\",\"chal-far\"]";
        self.home_url = try testrelay.url(&self.home_buf, self.home.port());
        self.far_url = try testrelay.url(&self.far_buf, self.far.port());

        var signer = try nostr.keys.Signer.initRandomized(io);
        defer signer.deinit();
        const author = try signer.keyPairFromSecretKey([_]u8{0x72} ** 32);
        const tags = [_]nostr.event.Tag{
            &.{ "cmd", "REQ" },
            &.{ "k", "1" },
            &.{ "relays", self.far_url },
            &.{"close-on-eose"},
        };
        const spell = try nostr.event.create(arena, signer, author, 1_700_000_300, spell_kind, &tags, "", null);
        const note = try nostr.event.create(arena, signer, author, 1_700_000_400, 1, &.{}, "from far", null);
        self.home_state.serving = try arena.dupe([]const u8, &.{try nostr.event.toJson(arena, spell)});
        self.far_state.serving = try arena.dupe([]const u8, &.{try nostr.event.toJson(arena, note)});
        self.spell_id = try nostr.hex.encode(arena, &spell.id);
    }

    fn finish(self: *Fixture, io: std.Io) void {
        self.far.stop(io);
        self.home.stop(io);
        self.arena_state.deinit();
        if (self.da.deinit() == .leak) @panic("the spell verb leaked");
    }
};

test "a relay the spell lists at a local address is not asked without --allow-local" {
    const io = testing.io;
    var f: Fixture = .{};
    try f.start(io, 1, 0);
    defer f.finish(io);
    const gpa = f.da.allocator();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ f.spell_id, "--timeout", "3000", f.home_url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expectEqualStrings("", out.written());
    // The spell's relays were shown, and the refusal says how to go on.
    try testing.expect(std.mem.indexOf(u8, err.written(), f.far_url) != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "--allow-local") != null);
}

test "with --allow-local the listed relay is asked, and NIP-42 is answered only where I named the relay" {
    const io = testing.io;
    var f: Fixture = .{};
    try f.start(io, 2, 1);
    defer f.finish(io);
    const gpa = f.da.allocator();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{
        f.spell_id, "--allow-local",                                                    "--auth",    "--force-pre-auth",
        "--sec",    "3131313131313131313131313131313131313131313131313131313131313131", "--timeout", "3000",
        f.home_url,
    }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expect(std.mem.indexOf(u8, out.written(), "from far") != null);
    try testing.expect(f.home_state.auths > 0);
    try testing.expectEqual(@as(usize, 0), f.far_state.auths);
}
