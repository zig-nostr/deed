//! `deed git`: NIP-34, code collaboration over nostr.
//!
//! The read side asks relays for a repository announcement (kind 30617), its
//! state (30618), and the patches (1617), issues (1621) and pull requests
//! (1618) that name it. Every event is verified by the query before it is
//! looked at, and everything a relay wrote is printed with its control
//! characters escaped.
//!
//! The write side signs. `announce` reads the repository's name, remotes and
//! root commit by running `git` (an argument vector, never a shell string) and
//! publishes a 30617. That kind is replaceable, so it reads the current one
//! first and refuses to write over one it found, or over a relay that did not
//! finish answering. `send-patch` runs `git format-patch --stdout` and
//! publishes one 1617 per commit, threaded as NIP-34 asks.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const publish = @import("cmd_publish.zig");
const relayset = @import("relayset.zig");

const event = nostr.event;
const filter = nostr.filter;
const nip19 = nostr.nip19;

/// Shown beside the name in `deed help`.
pub const summary = "NIP-34 repositories, patches and issues: read them, announce, send patches";

pub const ready = true;

pub const usage =
    \\deed git: NIP-34 repositories, patches and issues: read them, announce, send patches
    \\
    \\Usage:
    \\  deed git repo <repo> [options] [<relay-url>...]
    \\  deed git state <repo> [options] [<relay-url>...]
    \\  deed git patches <repo> [options] [<relay-url>...]
    \\  deed git issues <repo> [options] [<relay-url>...]
    \\  deed git pulls <repo> [options] [<relay-url>...]
    \\  deed git announce [options] [<relay-url>...]
    \\  deed git send-patch --repo <repo> [options] <commit-range> [<relay-url>...]
    \\
    \\A <repo> is an naddr1 code, or <npub>/<identifier> (also nostr://npub/id and
    \\nostr://npub/<relay>/id). The relays asked are the ones named, the ones the
    \\naddr carries and, for everything after the announcement, the ones the
    \\announcement lists. With none named, the relays the owner writes to are
    \\found through --relay or DEED_RELAYS.
    \\
    \\Read:
    \\  repo       the announcement: name, description, web, clone URLs, relays,
    \\             maintainers
    \\  state      the newest kind 30618: HEAD and the refs with their commits
    \\  patches    kind 1617, newest first: id, date, author, role, subject
    \\  issues     kind 1621: id, date, author, subject
    \\  pulls      kind 1618: id, date, author, subject
    \\
    \\Options for the read verbs:
    \\      --json             print the verified events as JSON lines
    \\      --limit <n>        ask each relay for at most n events (default 500)
    \\      --apply-ready <id> patches only: print that patch (an id or a prefix of at
    \\                         least 8 hex characters) as a git-am mbox on stdout. A
    \\                         root patch brings the rest of its series, in order, as
    \\                         long as the same author sent them
    \\  -r, --relay <url>      where to look up the owner's relay list, repeatable
    \\      --timeout <ms>     how long the relays get (default 10000)
    \\
    \\Announce publishes a kind 30617 for the git repository in the current
    \\directory (or -C). It reads the repository name, the network URLs of its
    \\remotes and its root commit with git. The relays named are published to and
    \\listed in the announcement. It prints the event only if a relay accepted it.
    \\An announcement that already exists is never written over unless --replace
    \\is given, and --replace replaces the whole of it.
    \\
    \\Options for announce:
    \\      --sec <key>         secret key, as nsec1..., ncryptsec1... or 64 hex
    \\                          characters. Falls back to $NOSTR_SECRET_KEY.
    \\  -C <dir>                the repository (default: here)
    \\      --id <identifier>   the d tag (default: the directory name, kebab-case)
    \\      --name <text>       the project name (default: the directory name)
    \\      --description <t>   a one line description
    \\      --web <url>         a page for browsing, repeatable
    \\      --clone <url>       a clone URL, repeatable; replaces the remotes found
    \\      --maintainer <key>  another maintainer, npub or hex, repeatable
    \\      --replace           write over an announcement that exists
    \\      --dry-run           print the signed event, publish and read nothing
    \\  -r, --relay <url>       where to find your relay list, repeatable
    \\      --timeout <ms>      how long the relays get (default 10000)
    \\
    \\Send-patch runs git format-patch on the commit range, in -C, and publishes
    \\one kind 1617 per commit to the relays the announcement lists. The first
    \\carries a root tag, each later one replies to the one before it. Patches of
    \\60 kB or more are refused, because NIP-34 asks for a pull request then.
    \\
    \\Options for send-patch:
    \\      --repo <repo>       the repository to send to
    \\      --sec <key>         as for announce
    \\  -C <dir>                the local repository (default: here)
    \\      --to <key>          also tag this person, repeatable
    \\      --revision-of <id>  this series replaces the root patch with that id
    \\      --dry-run           print the signed events and publish nothing
    \\  -r, --relay <url>       as above
    \\      --timeout <ms>      how long the relays get (default 10000)
    \\
    \\  deed git repo npub1.../deed wss://relay.example
    \\  deed git patches naddr1... --apply-ready 1a2b3c4d | git am
    \\  deed git send-patch --repo naddr1... --sec nsec1... HEAD~2..HEAD
    \\
    \\Exits 0 on success, 1 when nothing was found or nothing was accepted, and 2
    \\when the command made no sense.
    \\
;

const kind_announcement: u16 = 30617;
const kind_state: u16 = 30618;
const kind_patch: u16 = 1617;
const kind_pull: u16 = 1618;
const kind_issue: u16 = 1621;

/// NIP-34: patches are for events under 60 kB.
const max_patch_bytes = 60_000;

const Sub = enum { repo, state, patches, issues, pulls, announce, send_patch };

fn parseSub(name: []const u8) ?Sub {
    if (std.mem.eql(u8, name, "repo")) return .repo;
    if (std.mem.eql(u8, name, "state")) return .state;
    if (std.mem.eql(u8, name, "patches")) return .patches;
    if (std.mem.eql(u8, name, "issues")) return .issues;
    if (std.mem.eql(u8, name, "pulls")) return .pulls;
    if (std.mem.eql(u8, name, "announce")) return .announce;
    if (std.mem.eql(u8, name, "send-patch")) return .send_patch;
    return null;
}

fn verbName(sub: Sub) []const u8 {
    return switch (sub) {
        .repo => "git repo",
        .state => "git state",
        .patches => "git patches",
        .issues => "git issues",
        .pulls => "git pulls",
        .announce => "git announce",
        .send_patch => "git send-patch",
    };
}

const read_flags = [_][]const u8{ "--json", "--limit", "--timeout", "-r", "--relay" };
const patches_flags = read_flags ++ [_][]const u8{"--apply-ready"};
const announce_flags = [_][]const u8{ "--sec", "-C", "--id", "--name", "--description", "--web", "--clone", "--maintainer", "--replace", "--dry-run", "--timeout", "-r", "--relay" };
const send_flags = [_][]const u8{ "--sec", "-C", "--repo", "--to", "--revision-of", "--dry-run", "--timeout", "-r", "--relay" };

fn allowedFlags(sub: Sub) []const []const u8 {
    return switch (sub) {
        .repo, .state, .issues, .pulls => &read_flags,
        .patches => &patches_flags,
        .announce => &announce_flags,
        .send_patch => &send_flags,
    };
}

const Opts = struct {
    json: bool = false,
    dry_run: bool = false,
    replace: bool = false,
    timeout_ms: i64 = publish.default_timeout_ms,
    limit: u32 = 500,
    sec: ?[]const u8 = null,
    apply_ready: ?[]const u8 = null,
    dir: ?[]const u8 = null,
    id: ?[]const u8 = null,
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    repo: ?[]const u8 = null,
    revision_of: ?[]const u8 = null,
    positional: std.ArrayList([]const u8) = .empty,
    urls: std.ArrayList([]const u8) = .empty,
    bootstrap: std.ArrayList([]const u8) = .empty,
    web: std.ArrayList([]const u8) = .empty,
    clone: std.ArrayList([]const u8) = .empty,
    maintainers: std.ArrayList([]const u8) = .empty,
    to: std.ArrayList([]const u8) = .empty,
};

const Run = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Lives as long as the run. Everything but the parsed events is in it.
    arena: std.mem.Allocator,
    verb: []const u8,
    o: *Opts,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed git: needs a subcommand: repo, state, patches, issues, pulls, announce or send-patch\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    const sub = parseSub(args[0]) orelse {
        try err.print("deed git: '{s}' is not a subcommand\n", .{args[0]});
        return cli.exit_usage;
    };

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var o: Opts = .{};
    const verb = verbName(sub);
    switch (try parseOpts(arena, sub, verb, args[1..], &o, out, err)) {
        .ok => {},
        .help => return cli.exit_ok,
        .bad => return cli.exit_usage,
    }
    var rc: Run = .{ .gpa = gpa, .io = io, .arena = arena, .verb = verb, .o = &o, .out = out, .err = err };
    return switch (sub) {
        .repo, .state, .patches, .issues, .pulls => runRead(&rc, sub),
        .announce => runAnnounce(&rc),
        .send_patch => runSendPatch(&rc),
    };
}

const Parsed = enum { ok, help, bad };

/// `.bad` after saying what is wrong, `.help` after printing help.
fn parseOpts(
    a: std.mem.Allocator,
    sub: Sub,
    verb: []const u8,
    args: []const []const u8,
    o: *Opts,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !Parsed {
    const allowed = allowedFlags(sub);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (cli.isOneOf(arg, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return .help;
        }
        if (arg.len > 1 and arg[0] == '-') {
            var ok = false;
            for (allowed) |f| {
                if (std.mem.eql(u8, f, arg)) ok = true;
            }
            if (!ok) {
                try err.print("deed {s}: unknown option '{s}'\n", .{ verb, arg });
                return .bad;
            }
            if (std.mem.eql(u8, arg, "--json")) {
                o.json = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--dry-run")) {
                o.dry_run = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--replace")) {
                o.replace = true;
                continue;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed {s}: '{s}' needs a value\n", .{ verb, arg });
                return .bad;
            }
            const v = args[i];
            if (std.mem.eql(u8, arg, "--timeout")) {
                o.timeout_ms = std.fmt.parseInt(i64, v, 10) catch 0;
                if (o.timeout_ms <= 0) {
                    try err.print("deed {s}: --timeout needs a number of milliseconds, not '{s}'\n", .{ verb, v });
                    return .bad;
                }
            } else if (std.mem.eql(u8, arg, "--limit")) {
                o.limit = std.fmt.parseInt(u32, v, 10) catch 0;
                if (o.limit == 0) {
                    try err.print("deed {s}: --limit needs a positive number, not '{s}'\n", .{ verb, v });
                    return .bad;
                }
            } else if (cli.isOneOf(arg, &.{ "-r", "--relay" })) {
                try o.bootstrap.append(a, v);
            } else if (std.mem.eql(u8, arg, "--sec")) {
                o.sec = v;
            } else if (std.mem.eql(u8, arg, "--apply-ready")) {
                o.apply_ready = v;
            } else if (std.mem.eql(u8, arg, "-C")) {
                o.dir = v;
            } else if (std.mem.eql(u8, arg, "--id")) {
                o.id = v;
            } else if (std.mem.eql(u8, arg, "--name")) {
                o.name = v;
            } else if (std.mem.eql(u8, arg, "--description")) {
                o.description = v;
            } else if (std.mem.eql(u8, arg, "--repo")) {
                o.repo = v;
            } else if (std.mem.eql(u8, arg, "--revision-of")) {
                o.revision_of = v;
            } else if (std.mem.eql(u8, arg, "--web")) {
                try o.web.append(a, v);
            } else if (std.mem.eql(u8, arg, "--clone")) {
                try o.clone.append(a, v);
            } else if (std.mem.eql(u8, arg, "--maintainer")) {
                try o.maintainers.append(a, v);
            } else if (std.mem.eql(u8, arg, "--to")) {
                try o.to.append(a, v);
            }
        } else if (isRelayUrl(arg)) {
            try o.urls.append(a, arg);
        } else {
            try o.positional.append(a, arg);
        }
    }
    return .ok;
}

fn isRelayUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "wss://") or std.mem.startsWith(u8, s, "ws://");
}

/// A relay URL worth dialling, from something a stranger wrote.
fn validRelay(s: []const u8) bool {
    if (!isRelayUrl(s) or s.len > 512) return false;
    for (s) |c| {
        if (c <= 0x20 or c == 0x7f) return false;
    }
    return true;
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

// ---------------------------------------------------------------------------
// Tags and text
// ---------------------------------------------------------------------------

fn firstTag(ev: event.Event, name: []const u8) ?event.Tag {
    for (ev.tags) |t| {
        if (t.len >= 1 and std.mem.eql(u8, t[0], name)) return t;
    }
    return null;
}

fn tagValue(ev: event.Event, name: []const u8) ?[]const u8 {
    const t = firstTag(ev, name) orelse return null;
    return if (t.len >= 2) t[1] else null;
}

fn hasTagValue(ev: event.Event, name: []const u8, value: []const u8) bool {
    for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], name) and std.mem.eql(u8, t[1], value)) return true;
    }
    return false;
}

fn tag(a: std.mem.Allocator, parts: []const []const u8) !event.Tag {
    return a.dupe([]const u8, parts);
}

/// `a` after `b`: newer, and on a tie the lower id, as relays keep it.
fn newerThan(a: event.Event, b: event.Event) bool {
    if (a.created_at != b.created_at) return a.created_at > b.created_at;
    return std.mem.order(u8, &a.id, &b.id) == .lt;
}

fn parsedNewer(_: void, a: event.Parsed, b: event.Parsed) bool {
    return newerThan(a.value, b.value);
}

fn parsedOlder(_: void, a: event.Parsed, b: event.Parsed) bool {
    return newerThan(b.value, a.value);
}

fn safe(w: *std.Io.Writer, text: []const u8) !void {
    try relayset.writeEscaped(w, text);
}

fn field(w: *std.Io.Writer, key: []const u8, text: []const u8) !void {
    try w.print("{s}: ", .{key});
    try safe(w, text);
    try w.writeByte('\n');
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn isCommitId(s: []const u8) bool {
    return (s.len == 40 or s.len == 64) and isHex(s);
}

/// The first line of `text`, cut to `max` bytes on a character boundary.
fn firstLine(text: []const u8, max: usize) []const u8 {
    const end = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    var line = std.mem.trimEnd(u8, text[0..end], "\r");
    if (line.len > max) {
        var cut = max;
        while (cut > 0 and (line[cut] & 0xc0) == 0x80) cut -= 1;
        line = line[0..cut];
    }
    return line;
}

/// The subject of a git-format-patch mbox, without its `[PATCH n/m]` prefix.
fn patchSubject(content: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        const l = std.mem.trimEnd(u8, line, "\r");
        if (l.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(l, "subject:")) {
            var s = std.mem.trim(u8, l["subject:".len..], " \t");
            if (s.len > 0 and s[0] == '[') {
                if (std.mem.indexOfScalar(u8, s, ']')) |close| s = std.mem.trimStart(u8, s[close + 1 ..], " \t");
            }
            return firstLine(s, 100);
        }
    }
    return "(no subject)";
}

fn dateOf(buf: *[10]u8, secs: i64) []const u8 {
    const days = @divFloor(secs, 86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe: i64 = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const y = yoe + era * 400 + @as(i64, if (m <= 2) 1 else 0);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ @as(u64, @intCast(@max(y, 0))), @as(u64, @intCast(m)), @as(u64, @intCast(d)) }) catch buf[0..0];
}

fn kebab(a: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            try out.append(a, std.ascii.toLower(c));
        } else if (out.items.len > 0 and out.items[out.items.len - 1] != '-') {
            try out.append(a, '-');
        }
    }
    while (out.items.len > 0 and out.items[out.items.len - 1] == '-') _ = out.pop();
    return out.items;
}

// ---------------------------------------------------------------------------
// Repository references
// ---------------------------------------------------------------------------

const Ref = struct {
    owner: [32]u8,
    id: []const u8,
    hints: []const []const u8,
};

fn pctDecode(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                try out.append(a, b);
                i += 2;
                continue;
            } else |_| {}
        }
        try out.append(a, s[i]);
    }
    return out.items;
}

/// An naddr1 code, `npub/identifier`, or the same as a `nostr://` URL, which
/// may carry a relay hint between the two.
fn parseRef(a: std.mem.Allocator, raw: []const u8) ?Ref {
    var s = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.startsWith(u8, s, "nostr://")) {
        s = s["nostr://".len..];
    } else if (std.mem.startsWith(u8, s, "nostr:")) {
        s = s["nostr:".len..];
    }
    if (std.mem.startsWith(u8, s, "naddr1")) {
        const p = nip19.decodeNaddr(a, s) catch return null;
        if (p.kind != kind_announcement or p.identifier.len == 0) return null;
        var hints: std.ArrayList([]const u8) = .empty;
        for (p.relays) |r| {
            if (validRelay(r)) hints.append(a, r) catch return null;
        }
        return .{ .owner = p.pubkey, .id = p.identifier, .hints = hints.items };
    }
    var parts: [3][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, '/');
    while (it.next()) |part| {
        if (n == 3) return null;
        parts[n] = part;
        n += 1;
    }
    if (n < 2) return null;
    const owner = keyinput.publicKey(a, parts[0]) catch return null;
    const id = pctDecode(a, parts[n - 1]) catch return null;
    if (id.len == 0) return null;
    var hints: std.ArrayList([]const u8) = .empty;
    if (n == 3) {
        const h = pctDecode(a, parts[1]) catch return null;
        const url = if (isRelayUrl(h)) h else std.fmt.allocPrint(a, "wss://{s}", .{h}) catch return null;
        if (!validRelay(url)) return null;
        hints.append(a, url) catch return null;
    }
    return .{ .owner = owner, .id = id, .hints = hints.items };
}

// ---------------------------------------------------------------------------
// Asking relays
// ---------------------------------------------------------------------------

const Fetched = struct {
    events: []event.Parsed,
    dialled: usize,
    complete: usize,
    /// An event handed to the caller, which owns it from then on.
    taken: ?usize = null,

    fn deinit(self: *Fetched, gpa: std.mem.Allocator) void {
        for (self.events, 0..) |*p, i| {
            if (self.taken == null or self.taken.? != i) p.deinit();
        }
        gpa.free(self.events);
    }
};

/// One question to `urls`. The query has already verified every event and
/// checked it against `f`.
fn fetch(rc: *Run, urls: []const []const u8, f: filter.Filter) !Fetched {
    const take = urls[0..@min(urls.len, dial.max_relays)];
    var buf: std.Io.Writer.Allocating = .init(rc.gpa);
    defer buf.deinit();
    const o = try relayset.query(rc.gpa, rc.io, take, &.{f}, &buf.writer, rc.err, .{
        .until_eose = true,
        .deadline_ms = rc.o.timeout_ms,
    });
    var list: std.ArrayList(event.Parsed) = .empty;
    errdefer {
        for (list.items) |*p| p.deinit();
        list.deinit(rc.gpa);
    }
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var p = event.fromJson(rc.gpa, line) catch continue;
        list.append(rc.gpa, p) catch |e| {
            p.deinit();
            return e;
        };
    }
    return .{ .events = try list.toOwnedSlice(rc.gpa), .dialled = o.dialled, .complete = o.complete };
}

fn addUnique(a: std.mem.Allocator, list: *std.ArrayList([]const u8), url: []const u8) !void {
    for (list.items) |u| {
        if (std.mem.eql(u8, u, url)) return;
    }
    if (list.items.len >= dial.max_relays) return;
    try list.append(a, url);
}

/// Asks `urls` for the owner's announcement with identifier `id`.
fn fetchAnnouncement(rc: *Run, urls: []const []const u8, owner: [32]u8, id: []const u8) !struct { newest: ?event.Parsed, fetched: Fetched } {
    const authors = [1][32]u8{owner};
    const kinds = [1]u16{kind_announcement};
    const dv = [1][]const u8{id};
    const tf = [1]filter.TagFilter{.{ .letter = 'd', .values = &dv }};
    var fetched = try fetch(rc, urls, .{ .authors = &authors, .kinds = &kinds, .tags = &tf });
    var best: ?usize = null;
    for (fetched.events, 0..) |p, i| {
        const d = tagValue(p.value, "d") orelse "";
        if (!std.mem.eql(u8, d, id)) continue;
        if (best == null or newerThan(p.value, fetched.events[best.?].value)) best = i;
    }
    // Hand the winner out and let `fetched` drop the rest.
    var newest: ?event.Parsed = null;
    if (best) |b| {
        newest = fetched.events[b];
        fetched.taken = b;
    }
    return .{ .newest = newest, .fetched = fetched };
}

const Resolved = struct {
    owner: [32]u8,
    id: []const u8,
    ann: event.Parsed,
    /// The announcement's relays, then the ones that were named.
    relays: []const []const u8,
    address: []const u8,
};

fn resolve(rc: *Run, raw: []const u8) !?Resolved {
    const a = rc.arena;
    const ref = parseRef(a, raw) orelse {
        try rc.err.print("deed {s}: '{s}' is not a repository: want an naddr1 code or npub/identifier\n", .{ rc.verb, raw });
        return null;
    };
    var seeds: std.ArrayList([]const u8) = .empty;
    for (rc.o.urls.items) |u| try addUnique(a, &seeds, u);
    for (ref.hints) |u| try addUnique(a, &seeds, u);
    if (seeds.items.len == 0) {
        var followed = (try outbox.followWriteRelays(rc.gpa, rc.io, rc.verb, ref.owner, rc.o.bootstrap.items, null, rc.o.timeout_ms, rc.err)) orelse return null;
        defer followed.deinit();
        for (followed.urls) |u| try addUnique(a, &seeds, try a.dupe(u8, u));
    }

    var found = try fetchAnnouncement(rc, seeds.items, ref.owner, ref.id);
    defer found.fetched.deinit(rc.gpa);
    if (found.fetched.dialled == 0) {
        try rc.err.print("deed {s}: no relay answered\n", .{rc.verb});
        if (found.newest) |*p| p.deinit();
        return null;
    }
    const ann = found.newest orelse {
        try rc.err.print("deed {s}: no announcement for that repository was found\n", .{rc.verb});
        return null;
    };

    var relays: std.ArrayList([]const u8) = .empty;
    if (firstTag(ann.value, "relays")) |t| {
        for (t[1..]) |u| {
            if (validRelay(u)) try addUnique(a, &relays, try a.dupe(u8, u));
        }
    }
    for (seeds.items) |u| try addUnique(a, &relays, u);

    const owner_hex = try nostr.hex.encode(a, &ref.owner);
    return .{
        .owner = ref.owner,
        .id = ref.id,
        .ann = ann,
        .relays = relays.items,
        .address = try std.fmt.allocPrint(a, "{d}:{s}:{s}", .{ kind_announcement, owner_hex, ref.id }),
    };
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

fn runRead(rc: *Run, sub: Sub) !u8 {
    if (rc.o.positional.items.len != 1) {
        try rc.err.print("deed {s}: takes one repository: an naddr1 code or npub/identifier\n", .{rc.verb});
        return cli.exit_usage;
    }
    var res = (try resolve(rc, rc.o.positional.items[0])) orelse return cli.exit_fail;
    defer res.ann.deinit();

    switch (sub) {
        .repo => return showRepo(rc, res),
        .state => return showState(rc, res),
        .patches => return listPatches(rc, res),
        .issues => return listPlain(rc, res, kind_issue),
        .pulls => return listPlain(rc, res, kind_pull),
        else => unreachable,
    }
}

fn printJson(rc: *Run, ev: event.Event) !void {
    const json = try event.toJson(rc.gpa, ev);
    defer rc.gpa.free(json);
    try rc.out.print("{s}\n", .{json});
}

fn tagLines(rc: *Run, ev: event.Event, tag_name: []const u8, label: []const u8) !void {
    for (ev.tags) |t| {
        if (t.len < 2 or !std.mem.eql(u8, t[0], tag_name)) continue;
        for (t[1..]) |v| try field(rc.out, label, v);
    }
}

fn showRepo(rc: *Run, res: Resolved) !u8 {
    const ev = res.ann.value;
    if (rc.o.json) {
        try printJson(rc, ev);
        return cli.exit_ok;
    }
    const a = rc.arena;
    try field(rc.out, "name", tagValue(ev, "name") orelse res.id);
    try field(rc.out, "id", res.id);
    try field(rc.out, "owner", try nip19.encodeNpub(a, res.owner));
    if (tagValue(ev, "description")) |d| try field(rc.out, "description", d);
    try tagLines(rc, ev, "web", "web");
    try tagLines(rc, ev, "clone", "clone");
    try tagLines(rc, ev, "relays", "relays");
    if (firstTag(ev, "maintainers")) |t| {
        for (t[1..]) |m| {
            if (m.len == 64 and isHex(m)) {
                const pk = nostr.hex.decodeFixed(32, m) catch continue;
                try field(rc.out, "maintainer", try nip19.encodeNpub(a, pk));
            }
        }
    }
    for (ev.tags) |t| {
        if (t.len >= 3 and std.mem.eql(u8, t[0], "r") and std.mem.eql(u8, t[2], "euc")) try field(rc.out, "euc", t[1]);
    }
    try tagLines(rc, ev, "t", "tag");
    const naddr = try nip19.encodeNaddr(a, res.id, res.owner, kind_announcement, res.relays);
    try field(rc.out, "naddr", naddr);
    return cli.exit_ok;
}

fn showState(rc: *Run, res: Resolved) !u8 {
    const authors = [1][32]u8{res.owner};
    const kinds = [1]u16{kind_state};
    const dv = [1][]const u8{res.id};
    const tf = [1]filter.TagFilter{.{ .letter = 'd', .values = &dv }};
    var fetched = try fetch(rc, res.relays, .{ .authors = &authors, .kinds = &kinds, .tags = &tf });
    defer fetched.deinit(rc.gpa);
    var best: ?event.Event = null;
    for (fetched.events) |p| {
        const d = tagValue(p.value, "d") orelse "";
        if (!std.mem.eql(u8, d, res.id)) continue;
        if (best == null or newerThan(p.value, best.?)) best = p.value;
    }
    const ev = best orelse {
        try rc.err.print("deed {s}: no state was announced for that repository\n", .{rc.verb});
        return cli.exit_fail;
    };
    if (rc.o.json) {
        try printJson(rc, ev);
        return cli.exit_ok;
    }
    if (tagValue(ev, "HEAD")) |h| try field(rc.out, "HEAD", h);
    for (ev.tags) |t| {
        if (t.len < 2 or !std.mem.startsWith(u8, t[0], "refs/")) continue;
        if (!isCommitId(t[1])) continue;
        try safe(rc.out, t[0]);
        try rc.out.print("\t{s}\n", .{t[1]});
    }
    return cli.exit_ok;
}

fn fetchByKind(rc: *Run, res: Resolved, kind: u16) !Fetched {
    const kinds = [1]u16{kind};
    const av = [1][]const u8{res.address};
    const tf = [1]filter.TagFilter{.{ .letter = 'a', .values = &av }};
    return fetch(rc, res.relays, .{ .kinds = &kinds, .tags = &tf, .limit = rc.o.limit });
}

fn author(rc: *Run, pk: [32]u8) ![]const u8 {
    return nip19.encodeNpub(rc.arena, pk);
}

fn listPlain(rc: *Run, res: Resolved, kind: u16) !u8 {
    var fetched = try fetchByKind(rc, res, kind);
    defer fetched.deinit(rc.gpa);
    std.mem.sort(event.Parsed, fetched.events, {}, parsedNewer);
    for (fetched.events) |p| {
        const ev = p.value;
        if (rc.o.json) {
            try printJson(rc, ev);
            continue;
        }
        const subject = tagValue(ev, "subject") orelse firstLine(ev.content, 100);
        try printRow(rc, ev, null, subject);
    }
    return cli.exit_ok;
}

fn printRow(rc: *Run, ev: event.Event, role: ?[]const u8, subject: []const u8) !void {
    var db: [10]u8 = undefined;
    const id = try nostr.hex.encode(rc.arena, &ev.id);
    try rc.out.print("{s}\t{s}\t{s}", .{ id, dateOf(&db, ev.created_at), try author(rc, ev.pubkey) });
    if (role) |r| try rc.out.print("\t{s}", .{r});
    try rc.out.writeByte('\t');
    try safe(rc.out, subject);
    try rc.out.writeByte('\n');
}

fn patchRole(ev: event.Event) []const u8 {
    if (hasTagValue(ev, "t", "root-revision")) return "root-revision";
    if (hasTagValue(ev, "t", "root")) return "root";
    return "patch";
}

fn listPatches(rc: *Run, res: Resolved) !u8 {
    var fetched = try fetchByKind(rc, res, kind_patch);
    defer fetched.deinit(rc.gpa);
    if (rc.o.apply_ready) |want| return applyReady(rc, fetched.events, want);
    std.mem.sort(event.Parsed, fetched.events, {}, parsedNewer);
    for (fetched.events) |p| {
        if (rc.o.json) {
            try printJson(rc, p.value);
            continue;
        }
        try printRow(rc, p.value, patchRole(p.value), patchSubject(p.value.content));
    }
    return cli.exit_ok;
}

/// The id of the patch `ev` replies to, when it says so with an `e` tag.
fn replyTarget(ev: event.Event) ?[]const u8 {
    for (ev.tags) |t| {
        if (t.len >= 4 and std.mem.eql(u8, t[0], "e") and std.mem.eql(u8, t[3], "reply")) return t[1];
    }
    return null;
}

fn applyReady(rc: *Run, patches: []event.Parsed, want_raw: []const u8) !u8 {
    const a = rc.arena;
    const want = try std.ascii.allocLowerString(a, want_raw);
    if (want.len < 8 or want.len > 64 or !isHex(want)) {
        try rc.err.print("deed {s}: --apply-ready wants an event id, or a prefix of at least 8 hex characters\n", .{rc.verb});
        return cli.exit_usage;
    }
    var start: ?event.Event = null;
    for (patches) |p| {
        const id = try nostr.hex.encode(a, &p.value.id);
        if (!std.mem.startsWith(u8, id, want)) continue;
        if (start != null) {
            try rc.err.print("deed {s}: '{s}' names more than one patch\n", .{ rc.verb, want });
            return cli.exit_fail;
        }
        start = p.value;
    }
    const first = start orelse {
        try rc.err.print("deed {s}: no patch starts with '{s}'\n", .{ rc.verb, want });
        return cli.exit_fail;
    };

    var chain: std.ArrayList(event.Event) = .empty;
    try chain.append(a, first);
    if (hasTagValue(first, "t", "root") or hasTagValue(first, "t", "root-revision")) {
        // Only the root's own author extends its series, so a stranger cannot
        // slip a commit into it by replying.
        var last = first;
        while (chain.items.len <= patches.len) {
            const last_id = try nostr.hex.encode(a, &last.id);
            var next: ?event.Event = null;
            for (patches) |p| {
                if (!std.mem.eql(u8, &p.value.pubkey, &first.pubkey)) continue;
                const target = replyTarget(p.value) orelse continue;
                if (!std.mem.eql(u8, target, last_id)) continue;
                if (next == null or newerThan(next.?, p.value)) next = p.value;
            }
            const n = next orelse break;
            try chain.append(a, n);
            last = n;
        }
    }

    for (chain.items) |ev| {
        if (!std.mem.startsWith(u8, ev.content, "From ")) {
            const id = try nostr.hex.encode(a, &ev.id);
            try rc.err.print("deed {s}: {s}: the content is not a git-format-patch mbox, so git am could not read it\n", .{ rc.verb, id });
            return cli.exit_fail;
        }
    }
    for (chain.items) |ev| {
        try rc.out.writeAll(ev.content);
        if (!std.mem.endsWith(u8, ev.content, "\n")) try rc.out.writeByte('\n');
    }
    return cli.exit_ok;
}

// ---------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------

/// The standard output of `git <args>` run in `dir`, or null when git is not
/// there, or it failed. An argument vector, so nothing is read by a shell.
fn git(gpa: std.mem.Allocator, io: std.Io, dir: ?[]const u8, args: []const []const u8) ?[]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    argv.append(gpa, "git") catch return null;
    argv.appendSlice(gpa, args) catch return null;
    const cwd: std.process.Child.Cwd = if (dir) |d| .{ .path = d } else .inherit;
    const res = std.process.run(gpa, io, .{ .argv = argv.items, .cwd = cwd }) catch return null;
    defer gpa.free(res.stderr);
    const ok = switch (res.term) {
        .exited => |c| c == 0,
        else => false,
    };
    if (!ok) {
        gpa.free(res.stdout);
        return null;
    }
    return res.stdout;
}

/// `git`, trimmed, copied into `a`.
fn gitText(rc: *Run, args: []const []const u8) ?[]const u8 {
    const out = git(rc.gpa, rc.io, rc.o.dir, args) orelse return null;
    defer rc.gpa.free(out);
    const t = std.mem.trim(u8, out, " \t\r\n");
    return rc.arena.dupe(u8, t) catch null;
}

fn isNetworkUrl(u: []const u8) bool {
    if (u.len == 0) return false;
    for ([_][]const u8{ "https://", "http://", "git://", "ssh://" }) |p| {
        if (std.mem.startsWith(u8, u, p)) return true;
    }
    // scp-like: user@host:path
    return std.mem.indexOf(u8, u, "://") == null and u[0] != '/' and u[0] != '.' and
        std.mem.indexOfScalar(u8, u, '@') != null and std.mem.indexOfScalar(u8, u, ':') != null;
}

fn secretOrSay(rc: *Run) !?nostr.keys.SecretKey {
    const raw = rc.o.sec orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try rc.err.print("deed {s}: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n", .{rc.verb});
        return null;
    };
    return keyinput.secretKeyForVerb(rc.gpa, rc.verb, raw, rc.err) catch |e| switch (e) {
        error.BadKey => return null,
        else => return e,
    };
}

// ---------------------------------------------------------------------------
// Announce
// ---------------------------------------------------------------------------

fn runAnnounce(rc: *Run) !u8 {
    const a = rc.arena;
    if (rc.o.positional.items.len != 0) {
        try rc.err.print("deed {s}: takes no positional argument besides relay URLs, '{s}'\n", .{ rc.verb, rc.o.positional.items[0] });
        return cli.exit_usage;
    }
    const sk = (try secretOrSay(rc)) orelse return cli.exit_usage;

    const top = gitText(rc, &.{ "rev-parse", "--show-toplevel" }) orelse {
        try rc.err.writeAll("deed git announce: this is not a git repository, or git is not installed\n");
        return cli.exit_fail;
    };
    const base = blk: {
        const cut = std.mem.lastIndexOfAny(u8, top, "/\\");
        break :blk if (cut) |c| top[c + 1 ..] else top;
    };
    const name = rc.o.name orelse base;
    const id = rc.o.id orelse try kebab(a, base);
    if (id.len == 0) {
        try rc.err.writeAll("deed git announce: could not make an identifier from the directory name: pass --id\n");
        return cli.exit_usage;
    }

    var clones: std.ArrayList([]const u8) = .empty;
    if (rc.o.clone.items.len > 0) {
        for (rc.o.clone.items) |c| try clones.append(a, c);
    } else if (gitText(rc, &.{"remote"})) |remotes| {
        var it = std.mem.tokenizeScalar(u8, remotes, '\n');
        while (it.next()) |r| {
            const url = gitText(rc, &.{ "remote", "get-url", r }) orelse continue;
            if (!isNetworkUrl(url)) continue;
            var seen = false;
            for (clones.items) |c| {
                if (std.mem.eql(u8, c, url)) seen = true;
            }
            if (!seen) try clones.append(a, url);
        }
    }

    // The earliest commit identifies the repository among its forks. A
    // repository with several roots has the oldest listed last.
    var euc: ?[]const u8 = null;
    if (gitText(rc, &.{ "rev-list", "--max-parents=0", "HEAD" })) |roots| {
        if (std.mem.lastIndexOfScalar(u8, roots, '\n')) |nl| {
            euc = std.mem.trim(u8, roots[nl + 1 ..], " \r");
        } else euc = roots;
        if (euc) |e| {
            if (!isCommitId(e)) euc = null;
        }
    }

    var signer = try nostr.keys.Signer.initRandomized(rc.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(sk);

    // Where it is published, and what it lists as its relays.
    var urls: std.ArrayList([]const u8) = .empty;
    for (rc.o.urls.items) |u| try addUnique(a, &urls, u);
    if (urls.items.len == 0 and !rc.o.dry_run) {
        var followed = (try outbox.followWriteRelays(rc.gpa, rc.io, rc.verb, kp.public_key, rc.o.bootstrap.items, null, rc.o.timeout_ms, rc.err)) orelse return cli.exit_usage;
        defer followed.deinit();
        for (followed.urls) |u| {
            if (validRelay(u)) try addUnique(a, &urls, try a.dupe(u8, u));
        }
    }

    var tags: std.ArrayList(event.Tag) = .empty;
    try tags.append(a, try tag(a, &.{ "d", id }));
    try tags.append(a, try tag(a, &.{ "name", name }));
    if (rc.o.description) |d| try tags.append(a, try tag(a, &.{ "description", d }));
    if (rc.o.web.items.len > 0) try tags.append(a, try tagWith(a, "web", rc.o.web.items));
    if (clones.items.len > 0) try tags.append(a, try tagWith(a, "clone", clones.items));
    if (urls.items.len > 0) try tags.append(a, try tagWith(a, "relays", urls.items));
    if (euc) |e| try tags.append(a, try tag(a, &.{ "r", e, "euc" }));
    if (rc.o.maintainers.items.len > 0) {
        var ms: std.ArrayList([]const u8) = .empty;
        for (rc.o.maintainers.items) |m| {
            const pk = keyinput.publicKey(rc.gpa, m) catch {
                try rc.err.print("deed git announce: '{s}' is not an npub or a hex public key\n", .{m});
                return cli.exit_usage;
            };
            try ms.append(a, try nostr.hex.encode(a, &pk));
        }
        try tags.append(a, try tagWith(a, "maintainers", ms.items));
    }

    var created_at = std.Io.Timestamp.now(rc.io, .real).toSeconds();

    // The announcement is replaceable. Read the current one first, and write
    // nothing over a relay that has not finished saying what it holds.
    if (!rc.o.dry_run) {
        var found = try fetchAnnouncement(rc, urls.items, kp.public_key, id);
        defer found.fetched.deinit(rc.gpa);
        defer if (found.newest) |*p| p.deinit();
        if (found.fetched.dialled == 0) {
            try rc.err.writeAll("deed git announce: no relay answered, so any existing announcement could not be read. Nothing was written\n");
            return cli.exit_fail;
        }
        if (found.fetched.complete < urls.items.len) {
            try rc.err.print("deed git announce: only {d} of {d} relays finished sending what they hold, so an existing announcement may not have been seen. Nothing was written\n", .{ found.fetched.complete, urls.items.len });
            return cli.exit_fail;
        }
        if (found.newest) |cur| {
            if (!rc.o.replace) {
                try rc.err.print("deed git announce: '{s}' is already announced. Nothing was written. --replace writes over it with only what this run lists\n", .{id});
                return cli.exit_fail;
            }
            created_at = @max(created_at, cur.value.created_at + 1);
        }
    }

    const ev = try event.create(a, signer, kp, created_at, kind_announcement, tags.items, "", null);
    const wire = try event.toJson(a, ev);
    if (rc.o.dry_run) {
        try rc.out.print("{s}\n", .{wire});
        return cli.exit_ok;
    }
    if (!try publish.publishOne(rc.gpa, rc.io, "git announce", urls.items, ev, rc.o.timeout_ms, rc.err)) return cli.exit_fail;
    try rc.out.print("{s}\n", .{wire});
    return cli.exit_ok;
}

fn tagWith(a: std.mem.Allocator, name: []const u8, values: []const []const u8) !event.Tag {
    const t = try a.alloc([]const u8, values.len + 1);
    t[0] = name;
    @memcpy(t[1..], values);
    return t;
}

// ---------------------------------------------------------------------------
// Send-patch
// ---------------------------------------------------------------------------

const Patch = struct {
    sha: []const u8,
    text: []const u8,
};

const mbox_stamp = " Mon Sep 17 00:00:00 2001";

/// The commit id on a `From <sha> Mon Sep 17 ...` line, which is how
/// format-patch starts each message.
fn fromLineSha(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, "From ")) return null;
    const rest = line[5..];
    for ([_]usize{ 40, 64 }) |n| {
        if (rest.len == n + mbox_stamp.len and isHex(rest[0..n]) and std.mem.eql(u8, rest[n..], mbox_stamp)) return rest[0..n];
    }
    return null;
}

fn splitMbox(a: std.mem.Allocator, mbox: []const u8) ![]Patch {
    var out: std.ArrayList(Patch) = .empty;
    var starts: std.ArrayList(usize) = .empty;
    var shas: std.ArrayList([]const u8) = .empty;
    var pos: usize = 0;
    while (pos < mbox.len) {
        const end = std.mem.indexOfScalarPos(u8, mbox, pos, '\n') orelse mbox.len;
        const line = std.mem.trimEnd(u8, mbox[pos..end], "\r");
        if (fromLineSha(line)) |sha| {
            try starts.append(a, pos);
            try shas.append(a, sha);
        }
        pos = end + 1;
    }
    for (starts.items, 0..) |s, i| {
        const e = if (i + 1 < starts.items.len) starts.items[i + 1] else mbox.len;
        try out.append(a, .{ .sha = shas.items[i], .text = mbox[s..e] });
    }
    return out.items;
}

fn runSendPatch(rc: *Run) !u8 {
    const a = rc.arena;
    if (rc.o.positional.items.len != 1) {
        try rc.err.writeAll("deed git send-patch: takes one commit range, such as HEAD~2..HEAD\n");
        return cli.exit_usage;
    }
    const range = rc.o.positional.items[0];
    if (range.len == 0 or range[0] == '-') {
        try rc.err.print("deed git send-patch: '{s}' is not a commit range\n", .{range});
        return cli.exit_usage;
    }
    const repo_raw = rc.o.repo orelse {
        try rc.err.writeAll("deed git send-patch: needs --repo, the repository to send to\n");
        return cli.exit_usage;
    };
    const sk = (try secretOrSay(rc)) orelse return cli.exit_usage;

    var revision_of: ?[]const u8 = null;
    if (rc.o.revision_of) |r| {
        const low = try std.ascii.allocLowerString(a, r);
        if (low.len != 64 or !isHex(low)) {
            try rc.err.writeAll("deed git send-patch: --revision-of wants a 64 character event id\n");
            return cli.exit_usage;
        }
        revision_of = low;
    }
    var tos: std.ArrayList([]const u8) = .empty;
    for (rc.o.to.items) |t| {
        const pk = keyinput.publicKey(rc.gpa, t) catch {
            try rc.err.print("deed git send-patch: '{s}' is not an npub or a hex public key\n", .{t});
            return cli.exit_usage;
        };
        try tos.append(a, try nostr.hex.encode(a, &pk));
    }

    // The patches come first: nothing is asked of the network for a range
    // that has none.
    const mbox = git(rc.gpa, rc.io, rc.o.dir, &.{ "format-patch", "--stdout", range, "--" }) orelse {
        try rc.err.print("deed git send-patch: git could not make patches from '{s}'. Is this a git repository, and is that a range of its commits?\n", .{range});
        return cli.exit_fail;
    };
    defer rc.gpa.free(mbox);
    const patches = try splitMbox(a, mbox);
    if (patches.len == 0) {
        try rc.err.print("deed git send-patch: '{s}' holds no commits\n", .{range});
        return cli.exit_fail;
    }
    for (patches, 0..) |p, i| {
        if (p.text.len >= max_patch_bytes) {
            try rc.err.print("deed git send-patch: patch {d} of {d} ({s}) is {d} bytes. NIP-34 asks for a pull request at 60 kB, and nothing was sent\n", .{ i + 1, patches.len, p.sha[0..@min(12, p.sha.len)], p.text.len });
            return cli.exit_fail;
        }
    }

    var res = (try resolve(rc, repo_raw)) orelse return cli.exit_fail;
    defer res.ann.deinit();
    if (res.relays.len == 0) {
        try rc.err.writeAll("deed git send-patch: the announcement lists no relay, so name one\n");
        return cli.exit_fail;
    }

    var euc: ?[]const u8 = null;
    for (res.ann.value.tags) |t| {
        if (t.len >= 3 and std.mem.eql(u8, t[0], "r") and std.mem.eql(u8, t[2], "euc") and isCommitId(t[1])) euc = t[1];
    }
    const owner_hex = try nostr.hex.encode(a, &res.owner);

    var signer = try nostr.keys.Signer.initRandomized(rc.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(sk);
    const created_at = std.Io.Timestamp.now(rc.io, .real).toSeconds();

    var events: std.ArrayList(event.Event) = .empty;
    var prev_id: ?[]const u8 = null;
    for (patches, 0..) |p, i| {
        var tags: std.ArrayList(event.Tag) = .empty;
        try tags.append(a, try tag(a, &.{ "a", res.address }));
        if (euc) |e| try tags.append(a, try tag(a, &.{ "r", e }));
        try tags.append(a, try tag(a, &.{ "p", owner_hex }));
        for (tos.items) |t| {
            if (!std.mem.eql(u8, t, owner_hex)) try tags.append(a, try tag(a, &.{ "p", t }));
        }
        if (i == 0) {
            if (revision_of) |orig| {
                try tags.append(a, try tag(a, &.{ "t", "root-revision" }));
                try tags.append(a, try tag(a, &.{ "e", orig, "", "reply" }));
            } else {
                try tags.append(a, try tag(a, &.{ "t", "root" }));
            }
        } else {
            try tags.append(a, try tag(a, &.{ "e", prev_id.?, "", "reply" }));
        }
        try tags.append(a, try tag(a, &.{ "commit", p.sha }));
        try tags.append(a, try tag(a, &.{ "r", p.sha }));
        // parent, committer name, email, time, zone: one git call for all.
        if (git(rc.gpa, rc.io, rc.o.dir, &.{ "show", "-s", "--format=%P%n%cn%n%ce%n%ct%n%ci", p.sha })) |meta_raw| {
            defer rc.gpa.free(meta_raw);
            var lines = std.mem.splitScalar(u8, meta_raw, '\n');
            const parents = std.mem.trim(u8, lines.next() orelse "", " \r");
            const cname = std.mem.trimEnd(u8, lines.next() orelse "", "\r");
            const cmail = std.mem.trimEnd(u8, lines.next() orelse "", "\r");
            const ctime = std.mem.trim(u8, lines.next() orelse "", " \r");
            const cdate = std.mem.trim(u8, lines.next() orelse "", " \r");
            if (parents.len > 0) {
                const first_parent = parents[0 .. std.mem.indexOfScalar(u8, parents, ' ') orelse parents.len];
                if (isCommitId(first_parent)) try tags.append(a, try tag(a, &.{ "parent-commit", try a.dupe(u8, first_parent) }));
            }
            const zone = try zoneMinutes(a, cdate);
            try tags.append(a, try tag(a, &.{ "committer", try a.dupe(u8, cname), try a.dupe(u8, cmail), try a.dupe(u8, ctime), zone }));
        }
        const ev = try event.create(a, signer, kp, created_at, kind_patch, tags.items, p.text, null);
        try events.append(a, ev);
        prev_id = try nostr.hex.encode(a, &ev.id);
    }

    for (events.items, 0..) |ev, i| {
        const wire = try event.toJson(a, ev);
        if (rc.o.dry_run) {
            try rc.out.print("{s}\n", .{wire});
            continue;
        }
        if (!try publish.publishOne(rc.gpa, rc.io, "git send-patch", res.relays, ev, rc.o.timeout_ms, rc.err)) {
            try rc.err.print("deed git send-patch: patch {d} of {d} was not accepted, and the ones after it were not sent\n", .{ i + 1, events.items.len });
            return cli.exit_fail;
        }
        try rc.out.print("{s}\n", .{wire});
    }
    return cli.exit_ok;
}

/// The zone offset of a `git --format=%ci` date (`2026-10-11 09:30:00 +0230`),
/// in minutes, as text.
fn zoneMinutes(a: std.mem.Allocator, date: []const u8) ![]const u8 {
    const sp = std.mem.lastIndexOfScalar(u8, date, ' ') orelse return "0";
    const z = date[sp + 1 ..];
    if (z.len != 5 or (z[0] != '+' and z[0] != '-')) return "0";
    const hh = std.fmt.parseInt(i32, z[1..3], 10) catch return "0";
    const mm = std.fmt.parseInt(i32, z[3..5], 10) catch return "0";
    const total = hh * 60 + mm;
    return std.fmt.allocPrint(a, "{d}", .{if (z[0] == '-') -total else total});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

const test_secret = "22" ** 32;

const Kit = struct {
    signer: nostr.keys.Signer,
    kp: nostr.keys.KeyPair,
    arena: std.mem.Allocator,
    io: std.Io,

    fn init(arena: std.mem.Allocator, io: std.Io) !Kit {
        var signer = try nostr.keys.Signer.initRandomized(io);
        const kp = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
        return .{ .signer = signer, .kp = kp, .arena = arena, .io = io };
    }

    fn deinit(self: *Kit) void {
        self.signer.deinit();
    }

    fn make(self: *Kit, at: i64, kind: u16, tags: []const event.Tag, content: []const u8) ![]const u8 {
        const ev = try event.create(self.arena, self.signer, self.kp, at, kind, tags, content, null);
        return event.toJson(self.arena, ev);
    }

    fn idOf(self: *Kit, json: []const u8) ![]const u8 {
        var p = try event.fromJson(testing.allocator, json);
        defer p.deinit();
        return nostr.hex.encode(self.arena, &p.value.id);
    }
};

fn runCapture(arena: std.mem.Allocator, gpa: std.mem.Allocator, args: []const []const u8) !struct { code: u8, out: []const u8, err: []const u8 } {
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try run(gpa, testing.io, args, &out.writer, &err.writer);
    return .{ .code = code, .out = out.written(), .err = err.written() };
}

test "a repository reference is an naddr, npub/id, or a nostr URL with a relay hint" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const pk = [_]u8{0x33} ** 32;
    const npub = try nip19.encodeNpub(a, pk);
    const naddr = try nip19.encodeNaddr(a, "my-repo", pk, kind_announcement, &.{"wss://r.example"});

    const r1 = parseRef(a, naddr).?;
    try testing.expectEqualStrings("my-repo", r1.id);
    try testing.expectEqualSlices(u8, &pk, &r1.owner);
    try testing.expectEqualStrings("wss://r.example", r1.hints[0]);

    const r2 = parseRef(a, try std.fmt.allocPrint(a, "{s}/my%20repo", .{npub})).?;
    try testing.expectEqualStrings("my repo", r2.id);
    try testing.expectEqual(@as(usize, 0), r2.hints.len);

    const r3 = parseRef(a, try std.fmt.allocPrint(a, "nostr://{s}/relay.example/deed", .{npub})).?;
    try testing.expectEqualStrings("deed", r3.id);
    try testing.expectEqualStrings("wss://relay.example", r3.hints[0]);

    // The wrong kind of naddr, and things that are not references at all.
    const other = try nip19.encodeNaddr(a, "x", pk, 30023, &.{});
    try testing.expect(parseRef(a, other) == null);
    try testing.expect(parseRef(a, "just-a-word") == null);
    try testing.expect(parseRef(a, "npub1nope/x") == null);
}

test "a subject loses its patch prefix, and dates and identifiers are plain" {
    const mbox = "From 0123456789012345678901234567890123456789 Mon Sep 17 00:00:00 2001\nFrom: A <a@b.c>\nSubject: [PATCH 2/3] fix the thing\n\nbody\n";
    try testing.expectEqualStrings("fix the thing", patchSubject(mbox));
    try testing.expectEqualStrings("(no subject)", patchSubject("hello"));
    var b: [10]u8 = undefined;
    try testing.expectEqualStrings("2023-11-14", dateOf(&b, 1_700_000_000));
    try testing.expectEqualStrings("1970-01-01", dateOf(&b, 0));
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("my-cool-repo", try kebab(arena_state.allocator(), "My Cool_Repo!"));
    try testing.expectEqualStrings("120", try zoneMinutes(arena_state.allocator(), "2026-10-11 09:30:00 +0200"));
    try testing.expectEqualStrings("-330", try zoneMinutes(arena_state.allocator(), "2026-10-11 09:30:00 -0530"));
    try testing.expect(isNetworkUrl("git@host.example:me/repo.git"));
    try testing.expect(isNetworkUrl("https://host.example/me/repo"));
    try testing.expect(!isNetworkUrl("/home/me/repo"));
    try testing.expect(!isNetworkUrl("../repo"));
}

const Scene = struct {
    announcement: []const u8,
    state: []const u8,
    patch1: []const u8,
    patch2: []const u8,
    patch1_id: []const u8,
    issue: []const u8,
    pull: []const u8,
    forged: []const u8,
    stranger_reply: []const u8,
    naddr: []const u8,
};

/// Builds events for a repository "deed" owned by the test key, served by `r`.
fn buildScene(arena: std.mem.Allocator, kit: *Kit, url: []const u8) !Scene {
    const owner = try nostr.hex.encode(arena, &kit.kp.public_key);
    const addr = try std.fmt.allocPrint(arena, "30617:{s}:deed", .{owner});
    const commit_a = "a" ** 40;
    const announcement = try kit.make(1_700_000_000, kind_announcement, &.{
        try tag(arena, &.{ "d", "deed" }),
        try tag(arena, &.{ "name", "Deed" }),
        try tag(arena, &.{ "description", "a command line" }),
        try tag(arena, &.{ "web", "https://example.org/deed" }),
        try tag(arena, &.{ "clone", "https://example.org/deed.git", "git@example.org:deed.git" }),
        try tag(arena, &.{ "relays", url }),
        try tag(arena, &.{ "r", commit_a, "euc" }),
        try tag(arena, &.{ "maintainers", owner }),
    }, "");
    const state = try kit.make(1_700_000_100, kind_state, &.{
        try tag(arena, &.{ "d", "deed" }),
        try tag(arena, &.{ "refs/heads/main", "b" ** 40 }),
        try tag(arena, &.{ "HEAD", "ref: refs/heads/main" }),
    }, "");
    const mbox1 = "From " ++ ("c" ** 40) ++ mbox_stamp ++ "\nFrom: A <a@b.c>\nSubject: [PATCH 1/2] first\n\n---\n a | 1 +\n";
    const mbox2 = "From " ++ ("d" ** 40) ++ mbox_stamp ++ "\nFrom: A <a@b.c>\nSubject: [PATCH 2/2] second\n\n---\n a | 2 +\n";
    const patch1 = try kit.make(1_700_000_200, kind_patch, &.{
        try tag(arena, &.{ "a", addr }),
        try tag(arena, &.{ "t", "root" }),
    }, mbox1);
    const patch1_id = try kit.idOf(patch1);
    const patch2 = try kit.make(1_700_000_201, kind_patch, &.{
        try tag(arena, &.{ "a", addr }),
        try tag(arena, &.{ "e", patch1_id, "", "reply" }),
    }, mbox2);
    const issue = try kit.make(1_700_000_300, kind_issue, &.{
        try tag(arena, &.{ "a", addr }),
        try tag(arena, &.{ "subject", "it crashes" }),
    }, "steps to reproduce");
    const pull = try kit.make(1_700_000_400, kind_pull, &.{
        try tag(arena, &.{ "a", addr }),
        try tag(arena, &.{ "subject", "add a flag" }),
    }, "please pull");

    // A patch whose content was changed after signing: the id no longer fits.
    var forged_json = try kit.make(1_700_000_500, kind_patch, &.{try tag(arena, &.{ "a", addr })}, "From " ++ ("e" ** 40) ++ mbox_stamp ++ "\nSubject: real\n");
    const at = std.mem.indexOf(u8, forged_json, "Subject: real").?;
    const copy = try arena.dupe(u8, forged_json);
    @memcpy(copy[at .. at + 13], "Subject: evil");
    forged_json = copy;

    // A reply to the root from somebody else, which must not join the series.
    var stranger_signer = try nostr.keys.Signer.initRandomized(kit.io);
    defer stranger_signer.deinit();
    const skp = try stranger_signer.keyPairFromSecretKey([_]u8{0x55} ** 32);
    const sev = try event.create(arena, stranger_signer, skp, 1_700_000_202, kind_patch, &.{
        try tag(arena, &.{ "a", addr }),
        try tag(arena, &.{ "e", patch1_id, "", "reply" }),
    }, "From " ++ ("f" ** 40) ++ mbox_stamp ++ "\nSubject: [PATCH] sneaky\n", null);
    const stranger = try event.toJson(arena, sev);

    return .{
        .announcement = announcement,
        .state = state,
        .patch1 = patch1,
        .patch2 = patch2,
        .patch1_id = patch1_id,
        .issue = issue,
        .pull = pull,
        .forged = forged_json,
        .stranger_reply = stranger,
        .naddr = try nip19.encodeNaddr(arena, "deed", kit.kp.public_key, kind_announcement, &.{}),
    };
}

fn startServe(r: *testrelay.Relay, io: std.Io, arena: std.mem.Allocator, kit: *Kit, buf: []u8) !struct { url: []const u8, scene: Scene } {
    try r.startFor(io, .serve, 40);
    const url = try testrelay.url(buf, r.port());
    const scene = try buildScene(arena, kit, url);
    r.serving = try arena.dupe([]const u8, &.{ scene.announcement, scene.state, scene.patch1, scene.patch2, scene.issue, scene.pull, scene.forged, scene.stranger_reply });
    return .{ .url = url, .scene = scene };
}

test "repo, state, patches, issues and pulls read what the relay serves, and drop a forged patch" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("git leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var kit = try Kit.init(arena, testing.io);
    defer kit.deinit();

    var r: testrelay.Relay = undefined;
    var ubuf: [40]u8 = undefined;
    const s = try startServe(&r, testing.io, arena, &kit, &ubuf);
    defer r.stop(testing.io);

    const owner = try nip19.encodeNpub(arena, kit.kp.public_key);
    const ref = try std.fmt.allocPrint(arena, "{s}/deed", .{owner});

    const repo = try runCapture(arena, gpa, &.{ "repo", ref, s.url });
    try testing.expectEqual(cli.exit_ok, repo.code);
    try testing.expect(std.mem.indexOf(u8, repo.out, "name: Deed\n") != null);
    try testing.expect(std.mem.indexOf(u8, repo.out, "description: a command line\n") != null);
    try testing.expect(std.mem.indexOf(u8, repo.out, "clone: https://example.org/deed.git\n") != null);
    try testing.expect(std.mem.indexOf(u8, repo.out, "clone: git@example.org:deed.git\n") != null);
    try testing.expect(std.mem.indexOf(u8, repo.out, try std.fmt.allocPrint(arena, "relays: {s}\n", .{s.url})) != null);
    try testing.expect(std.mem.indexOf(u8, repo.out, "euc: " ++ ("a" ** 40) ++ "\n") != null);
    try testing.expect(std.mem.indexOf(u8, repo.out, try std.fmt.allocPrint(arena, "maintainer: {s}\n", .{owner})) != null);

    const st = try runCapture(arena, gpa, &.{ "state", ref, s.url });
    try testing.expectEqual(cli.exit_ok, st.code);
    try testing.expect(std.mem.indexOf(u8, st.out, "HEAD: ref: refs/heads/main\n") != null);
    try testing.expect(std.mem.indexOf(u8, st.out, "refs/heads/main\t" ++ ("b" ** 40) ++ "\n") != null);

    // The relay list comes from the announcement here: no relay is named.
    const naddr = try nip19.encodeNaddr(arena, "deed", kit.kp.public_key, kind_announcement, &.{s.url});
    const patches = try runCapture(arena, gpa, &.{ "patches", naddr });
    try testing.expectEqual(cli.exit_ok, patches.code);
    try testing.expect(std.mem.indexOf(u8, patches.out, "\troot\tfirst\n") != null);
    try testing.expect(std.mem.indexOf(u8, patches.out, "\tpatch\tsecond\n") != null);
    try testing.expect(std.mem.indexOf(u8, patches.out, "2023-11-14") != null);
    try testing.expect(std.mem.indexOf(u8, patches.out, "evil") == null);
    try testing.expect(std.mem.indexOf(u8, patches.out, "real") == null);

    const issues = try runCapture(arena, gpa, &.{ "issues", ref, s.url });
    try testing.expectEqual(cli.exit_ok, issues.code);
    try testing.expect(std.mem.indexOf(u8, issues.out, "\tit crashes\n") != null);
    try testing.expect(std.mem.indexOf(u8, issues.out, "first") == null);

    const pulls = try runCapture(arena, gpa, &.{ "pulls", ref, s.url, "--json" });
    try testing.expectEqual(cli.exit_ok, pulls.code);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}\n", .{s.scene.pull}), pulls.out);
}

test "apply-ready prints a series as an mbox, and a stranger's reply does not join it" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("git leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var kit = try Kit.init(arena, testing.io);
    defer kit.deinit();

    var r: testrelay.Relay = undefined;
    var ubuf: [40]u8 = undefined;
    const s = try startServe(&r, testing.io, arena, &kit, &ubuf);
    defer r.stop(testing.io);
    const ref = try std.fmt.allocPrint(arena, "{s}/deed", .{try nip19.encodeNpub(arena, kit.kp.public_key)});

    const series = try runCapture(arena, gpa, &.{ "patches", ref, s.url, "--apply-ready", s.scene.patch1_id[0..12] });
    try testing.expectEqual(cli.exit_ok, series.code);
    const want = "From " ++ ("c" ** 40) ++ mbox_stamp ++ "\nFrom: A <a@b.c>\nSubject: [PATCH 1/2] first\n\n---\n a | 1 +\n" ++
        "From " ++ ("d" ** 40) ++ mbox_stamp ++ "\nFrom: A <a@b.c>\nSubject: [PATCH 2/2] second\n\n---\n a | 2 +\n";
    try testing.expectEqualStrings(want, series.out);

    const none = try runCapture(arena, gpa, &.{ "patches", ref, s.url, "--apply-ready", "00000000" });
    try testing.expectEqual(cli.exit_fail, none.code);
    try testing.expectEqualStrings("", none.out);
    const short = try runCapture(arena, gpa, &.{ "patches", ref, s.url, "--apply-ready", "abc" });
    try testing.expectEqual(cli.exit_usage, short.code);
}

test "an unknown repository, and a missing relay, are reported and exit 1" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("git leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var kit = try Kit.init(arena, testing.io);
    defer kit.deinit();

    var r: testrelay.Relay = undefined;
    var ubuf: [40]u8 = undefined;
    const s = try startServe(&r, testing.io, arena, &kit, &ubuf);
    defer r.stop(testing.io);
    const owner = try nip19.encodeNpub(arena, kit.kp.public_key);

    const missing = try runCapture(arena, gpa, &.{ "repo", try std.fmt.allocPrint(arena, "{s}/nope", .{owner}), s.url });
    try testing.expectEqual(cli.exit_fail, missing.code);
    try testing.expect(std.mem.indexOf(u8, missing.err, "no announcement") != null);

    const bad = try runCapture(arena, gpa, &.{ "repo", "garbage", s.url });
    try testing.expectEqual(cli.exit_fail, bad.code);
    const flag = try runCapture(arena, gpa, &.{ "repo", "x", "--sec", "y" });
    try testing.expectEqual(cli.exit_usage, flag.code);
    const none = try runCapture(arena, gpa, &.{});
    try testing.expectEqual(cli.exit_usage, none.code);
}

/// A relay that serves one stored announcement, if it has one, and accepts
/// every event, keeping what it was sent.
const Sink = struct {
    stored: ?[]const u8 = null,
    count: usize = 0,
    frames: [8][]u8 = undefined,

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Sink = @ptrCast(@alignCast(ctx.?));
        const a = std.heap.page_allocator;
        var parsed = try std.json.parseFromSlice(std.json.Value, a, frame, .{});
        defer parsed.deinit();
        const items = parsed.value.array.items;
        const kind = items[0].string;
        if (std.mem.eql(u8, kind, "REQ")) {
            if (self.stored) |s| {
                const m = try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ items[1].string, s });
                defer a.free(m);
                try testrelay.sendText(w, m);
            }
            const m = try std.fmt.allocPrint(a, "[\"EOSE\",\"{s}\"]", .{items[1].string});
            defer a.free(m);
            try testrelay.sendText(w, m);
        } else if (std.mem.eql(u8, kind, "EVENT")) {
            if (self.count < self.frames.len) {
                self.frames[self.count] = try a.dupe(u8, frame);
                self.count += 1;
            }
            const m = try std.fmt.allocPrint(a, "[\"OK\",\"{s}\",true,\"\"]", .{items[1].object.get("id").?.string});
            defer a.free(m);
            try testrelay.sendText(w, m);
        }
    }
};

/// Like `startCustom`, for a run that opens several connections one after another.
fn startSink(r: *testrelay.Relay, sink: *Sink) !void {
    try r.startFor(testing.io, .custom, 16);
    r.custom = Sink.handle;
    r.custom_ctx = sink;
}

fn gitAvailable(gpa: std.mem.Allocator) bool {
    const v = git(gpa, testing.io, null, &.{"--version"}) orelse return false;
    gpa.free(v);
    return true;
}

const Repo = struct {
    tmp: testing.TmpDir,
    path: []const u8,

    fn init(arena: std.mem.Allocator, gpa: std.mem.Allocator, dir_name: []const u8) !Repo {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try tmp.dir.realPath(testing.io, &buf);
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ buf[0..n], dir_name });
        try tmp.dir.createDir(testing.io, dir_name, .default_dir);
        const self: Repo = .{ .tmp = tmp, .path = path };
        _ = self.g(gpa, &.{ "init", "-q" }) orelse return error.GitFailed;
        return self;
    }

    fn g(self: Repo, gpa: std.mem.Allocator, args: []const []const u8) ?[]u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        argv.appendSlice(gpa, &.{ "-c", "user.name=Tess", "-c", "user.email=tess@example.org", "-c", "commit.gpgsign=false" }) catch return null;
        argv.appendSlice(gpa, args) catch return null;
        return git(gpa, testing.io, self.path, argv.items);
    }

    fn commit(self: Repo, gpa: std.mem.Allocator, file: []const u8, text: []const u8, msg: []const u8) !void {
        var dir = try self.tmp.dir.openDir(testing.io, std.fs.path.basename(self.path), .{});
        defer dir.close(testing.io);
        try dir.writeFile(testing.io, .{ .sub_path = file, .data = text });
        gpa.free(self.g(gpa, &.{ "add", file }) orelse return error.GitFailed);
        gpa.free(self.g(gpa, &.{ "commit", "-q", "-m", msg }) orelse return error.GitFailed);
    }
};

test "announce reads the name, remotes and root commit from git, and never writes over one" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("git leaked");
    const gpa = da.allocator();
    if (!gitAvailable(gpa)) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var repo = try Repo.init(arena, gpa, "My Project");
    defer repo.tmp.cleanup();
    try repo.commit(gpa, "a.txt", "one\n", "first");
    gpa.free(repo.g(gpa, &.{ "remote", "add", "origin", "https://example.org/me/my-project.git" }) orelse return error.GitFailed);
    gpa.free(repo.g(gpa, &.{ "remote", "add", "local", "/srv/elsewhere" }) orelse return error.GitFailed);
    const head = repo.g(gpa, &.{ "rev-parse", "HEAD" }) orelse return error.GitFailed;
    defer gpa.free(head);
    const root = std.mem.trim(u8, head, " \n");

    var sink: Sink = .{};
    var r: testrelay.Relay = undefined;
    try startSink(&r, &sink);
    defer r.stop(testing.io);
    var ubuf: [40]u8 = undefined;
    const url = try testrelay.url(&ubuf, r.port());

    // Dry run: signed, printed, and nothing asked of any relay.
    const dry = try runCapture(arena, gpa, &.{ "announce", "-C", repo.path, "--sec", test_secret, "--dry-run", "--description", "mine", url });
    try testing.expectEqual(cli.exit_ok, dry.code);
    var p = try event.fromJson(gpa, std.mem.trim(u8, dry.out, "\n"));
    defer p.deinit();
    try testing.expect(try event.verify(gpa, nostr.keys.Signer.init(), p.value));
    try testing.expectEqual(kind_announcement, p.value.kind);
    try testing.expectEqualStrings("my-project", tagValue(p.value, "d").?);
    try testing.expectEqualStrings("My Project", tagValue(p.value, "name").?);
    try testing.expectEqualStrings("mine", tagValue(p.value, "description").?);
    const clone = firstTag(p.value, "clone").?;
    try testing.expectEqual(@as(usize, 2), clone.len);
    try testing.expectEqualStrings("https://example.org/me/my-project.git", clone[1]);
    try testing.expectEqualStrings(url, firstTag(p.value, "relays").?[1]);
    var euc_ok = false;
    for (p.value.tags) |t| {
        if (t.len == 3 and std.mem.eql(u8, t[0], "r") and std.mem.eql(u8, t[2], "euc") and std.mem.eql(u8, t[1], root)) euc_ok = true;
    }
    try testing.expect(euc_ok);
    try testing.expectEqual(@as(usize, 0), sink.count);

    // Live: nothing is stored, so it publishes and prints the event.
    const live = try runCapture(arena, gpa, &.{ "announce", "-C", repo.path, "--sec", test_secret, url });
    if (live.code != cli.exit_ok) std.debug.print("{s}\n", .{live.err});
    try testing.expectEqual(cli.exit_ok, live.code);
    try testing.expectEqual(@as(usize, 1), sink.count);
    try testing.expect(std.mem.indexOf(u8, live.out, "\"kind\":30617") != null);

    // Now one is stored: refused, and nothing more is sent.
    sink.stored = std.mem.trim(u8, live.out, "\n");
    const again = try runCapture(arena, gpa, &.{ "announce", "-C", repo.path, "--sec", test_secret, url });
    try testing.expectEqual(cli.exit_fail, again.code);
    try testing.expect(std.mem.indexOf(u8, again.err, "already announced") != null);
    try testing.expectEqualStrings("", again.out);
    try testing.expectEqual(@as(usize, 1), sink.count);

    const replaced = try runCapture(arena, gpa, &.{ "announce", "-C", repo.path, "--sec", test_secret, "--replace", url });
    try testing.expectEqual(cli.exit_ok, replaced.code);
    try testing.expectEqual(@as(usize, 2), sink.count);
    var np = try event.fromJson(gpa, std.mem.trim(u8, replaced.out, "\n"));
    defer np.deinit();
    var old = try event.fromJson(gpa, sink.stored.?);
    defer old.deinit();
    try testing.expect(np.value.created_at > old.value.created_at);
}

test "send-patch makes one threaded patch event per commit, with the tags NIP-34 names" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("git leaked");
    const gpa = da.allocator();
    if (!gitAvailable(gpa)) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var kit = try Kit.init(arena, testing.io);
    defer kit.deinit();

    var repo = try Repo.init(arena, gpa, "work");
    defer repo.tmp.cleanup();
    try repo.commit(gpa, "a.txt", "one\n", "first");
    try repo.commit(gpa, "a.txt", "one\ntwo\n", "second");
    try repo.commit(gpa, "b.txt", "other\n", "third");

    var sink: Sink = .{};
    var r: testrelay.Relay = undefined;
    try startSink(&r, &sink);
    defer r.stop(testing.io);
    var ubuf: [40]u8 = undefined;
    const url = try testrelay.url(&ubuf, r.port());
    const scene = try buildScene(arena, &kit, url);
    sink.stored = scene.announcement;

    const owner_hex = try nostr.hex.encode(arena, &kit.kp.public_key);
    const ref = try std.fmt.allocPrint(arena, "{s}/deed", .{try nip19.encodeNpub(arena, kit.kp.public_key)});
    var other_signer = try nostr.keys.Signer.initRandomized(testing.io);
    defer other_signer.deinit();
    const other = try other_signer.keyPairFromSecretKey([_]u8{0x66} ** 32);
    const other_hex = try nostr.hex.encode(arena, &other.public_key);

    const res = try runCapture(arena, gpa, &.{ "send-patch", "--repo", ref, "-C", repo.path, "--sec", test_secret, "--to", other_hex, "HEAD~2..HEAD", url });
    if (res.code != cli.exit_ok) std.debug.print("{s}\n", .{res.err});
    try testing.expectEqual(cli.exit_ok, res.code);
    try testing.expectEqual(@as(usize, 2), sink.count);

    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, res.out, "\n"), '\n');
    var ids: [2][]const u8 = undefined;
    var n: usize = 0;
    while (lines.next()) |line| : (n += 1) {
        var p = try event.fromJson(gpa, line);
        defer p.deinit();
        try testing.expect(try event.verify(gpa, nostr.keys.Signer.init(), p.value));
        try testing.expectEqual(kind_patch, p.value.kind);
        try testing.expect(std.mem.startsWith(u8, p.value.content, "From "));
        try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "30617:{s}:deed", .{owner_hex}), tagValue(p.value, "a").?);
        try testing.expect(hasTagValue(p.value, "p", owner_hex));
        try testing.expect(hasTagValue(p.value, "p", other_hex));
        try testing.expect(hasTagValue(p.value, "r", "a" ** 40));
        const commit = tagValue(p.value, "commit").?;
        try testing.expect(isCommitId(commit));
        try testing.expect(hasTagValue(p.value, "r", commit));
        try testing.expect(std.mem.startsWith(u8, p.value.content, try std.fmt.allocPrint(arena, "From {s} ", .{commit})));
        try testing.expect(isCommitId(tagValue(p.value, "parent-commit").?));
        const committer = firstTag(p.value, "committer").?;
        try testing.expectEqual(@as(usize, 5), committer.len);
        try testing.expectEqualStrings("Tess", committer[1]);
        try testing.expectEqualStrings("tess@example.org", committer[2]);
        if (n == 0) {
            try testing.expect(hasTagValue(p.value, "t", "root"));
            try testing.expect(firstTag(p.value, "e") == null);
            try testing.expect(std.mem.indexOf(u8, p.value.content, "second") != null);
        } else {
            try testing.expect(!hasTagValue(p.value, "t", "root"));
            const e = firstTag(p.value, "e").?;
            try testing.expectEqual(@as(usize, 4), e.len);
            try testing.expectEqualStrings(ids[0], e[1]);
            try testing.expectEqualStrings("reply", e[3]);
            try testing.expect(std.mem.indexOf(u8, p.value.content, "third") != null);
        }
        ids[n] = try nostr.hex.encode(arena, &p.value.id);
    }
    try testing.expectEqual(@as(usize, 2), n);

    // A revision points back at the root it replaces.
    const rev = try runCapture(arena, gpa, &.{ "send-patch", "--repo", ref, "-C", repo.path, "--sec", test_secret, "--dry-run", "--revision-of", scene.patch1_id, "HEAD~1", url });
    try testing.expectEqual(cli.exit_ok, rev.code);
    var rp = try event.fromJson(gpa, std.mem.trim(u8, rev.out, "\n"));
    defer rp.deinit();
    try testing.expect(hasTagValue(rp.value, "t", "root-revision"));
    try testing.expect(!hasTagValue(rp.value, "t", "root"));
    try testing.expectEqualStrings(scene.patch1_id, firstTag(rp.value, "e").?[1]);
    try testing.expectEqual(@as(usize, 2), sink.count);

    // Things that are not a range are turned away before any relay is asked.
    const flaglike = try runCapture(arena, gpa, &.{ "send-patch", "--repo", ref, "-C", repo.path, "--sec", test_secret, "--output=/tmp/x", url });
    try testing.expectEqual(cli.exit_usage, flaglike.code);
    const nothing = try runCapture(arena, gpa, &.{ "send-patch", "--repo", ref, "-C", repo.path, "--sec", test_secret, "HEAD..HEAD", url });
    try testing.expectEqual(cli.exit_fail, nothing.code);
    try testing.expectEqual(@as(usize, 2), sink.count);
}
