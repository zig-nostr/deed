//! `deed post`: write a note, a reply or a comment, and say which relays took it.
//!
//! The one verb a person types by hand, so it does the whole job: take the text
//! from an argument or from stdin, sign it, offer it to the relays named, and
//! print the event only if a relay accepted it. That last part is the same
//! contract `deed publish` keeps, so the output can be piped on as published.
//!
//! The pieces other verbs need are public here: reading the key, fetching the
//! newest matching event, offering one event to a set of relays, and asking a
//! person to confirm. `deed profile` uses all of them.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const signing = @import("signing.zig");
const publish = @import("cmd_publish.zig");
const relayset = @import("relayset.zig");

const event = nostr.event;
const filter = nostr.filter;
const hex = nostr.hex;
const nip19 = nostr.nip19;

/// Shown beside the name in `deed help`.
pub const summary = "publish a note, a reply or a comment";

pub const ready = true;

pub const default_timeout_ms: i64 = 10_000;

/// A note bigger than this is not one anybody typed.
const max_content_bytes = 1 << 20;

pub const usage =
    \\deed post: publish a note, a reply or a comment
    \\
    \\Usage:
    \\  deed post [options] [<text>] [<relay-url>...]
    \\
    \\Signs a kind 1 note with --sec and offers it to every relay named. The text
    \\is the one argument that is not a relay URL; with none, it is read from
    \\stdin. With no relay named it goes to the relays you write to, read from
    \\your relay list on the relays in DEED_RELAYS or given with --relay. Prints
    \\the signed event if at least one relay accepted it, and each relay's answer
    \\on stderr.
    \\
    \\  deed post "hello" --sec nsec1... wss://relay.example
    \\  echo "hello" | deed post --sec nsec1... wss://relay.example
    \\
    \\Options:
    \\      --sec <key>         secret key: nsec1..., ncryptsec1..., bunker://... or
    \\                          64 hex characters; $NOSTR_SECRET_KEY is read when
    \\                          --sec is absent
    \\      --reply <code>      reply to an event (nevent, note or 64 hex
    \\                          characters). The parent is fetched from the relays
    \\                          named, and the note gets NIP-10 root and reply
    \\                          tags and a p tag for everyone in the thread.
    \\      --comment <code>    comment on an event or an address (nevent or
    \\                          naddr) as a NIP-22 kind 1111 event, with the root
    \\                          scope in the uppercase tags and the parent in the
    \\                          lowercase ones.
    \\      --confirm           show the note and ask on the terminal before
    \\                          publishing. Refused when there is no terminal.
    \\      --dry-run           print the signed event and publish nothing. A
    \\                          reply or comment still fetches its parent.
    \\  -r, --relay <url>       where to look up your relay list when no relay is
    \\                          named, repeatable (and DEED_RELAYS)
    \\      --timeout <ms>      how long the relays get to answer (default 10000)
    \\
    \\A code carrying relay hints is looked up at those relays as well as the ones
    \\named. A code with an author but no hints is also looked up at the relays that
    \\author writes to. The note itself goes only to the ones named, or to yours.
    \\
    \\Exits: 0 when a relay accepted the note, 1 when none did, and 2 when the
    \\command made no sense.
    \\
;

const Options = struct {
    sec: ?[]const u8 = null,
    reply: ?[]const u8 = null,
    comment: ?[]const u8 = null,
    confirm: bool = false,
    dry_run: bool = false,
    timeout_ms: i64 = default_timeout_ms,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var opts = Options{};
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);
    var bootstrap: std.ArrayList([]const u8) = .empty;
    defer bootstrap.deinit(gpa);
    var text: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--confirm")) {
            opts.confirm = true;
        } else if (std.mem.eql(u8, a, "--dry-run")) {
            opts.dry_run = true;
        } else if (cli.isOneOf(a, &.{ "--sec", "--reply", "--comment", "--timeout", "-r", "--relay" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed post: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            const v = args[i];
            if (std.mem.eql(u8, a, "--sec")) {
                opts.sec = v;
            } else if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try bootstrap.append(gpa, v);
            } else if (std.mem.eql(u8, a, "--reply")) {
                opts.reply = v;
            } else if (std.mem.eql(u8, a, "--comment")) {
                opts.comment = v;
            } else {
                opts.timeout_ms = std.fmt.parseInt(i64, v, 10) catch 0;
                if (opts.timeout_ms <= 0) {
                    try err.print("deed post: --timeout needs a number of milliseconds, not '{s}'\n", .{v});
                    return cli.exit_usage;
                }
            }
        } else if (isRelayUrl(a)) {
            try urls.append(gpa, a);
        } else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
            try err.print("deed post: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (text == null) {
            text = a;
        } else {
            try err.writeAll("deed post: takes one note: quote the text so it is a single argument\n");
            return cli.exit_usage;
        }
    }

    if (opts.reply != null and opts.comment != null) {
        try err.writeAll("deed post: --reply and --comment cannot be used together\n");
        return cli.exit_usage;
    }
    if (urls.items.len > dial.max_relays) {
        try err.print("deed post: name at most {d} relays\n", .{dial.max_relays});
        return cli.exit_usage;
    }

    var signer = (signing.fromFlag(gpa, io, "post", opts.sec, err) catch |e| switch (e) {
        error.BadKey => return cli.exit_fail,
        else => return e,
    }) orelse return cli.exit_usage;
    defer signer.deinit();

    var content_owned: ?[]u8 = null;
    defer if (content_owned) |c| gpa.free(c);
    const content: []const u8 = text orelse blk: {
        const buf = try gpa.alloc(u8, 4096);
        defer gpa.free(buf);
        var stdin_reader = std.Io.File.stdin().readerStreaming(io, buf);
        const all = stdin_reader.interface.allocRemaining(gpa, .limited(max_content_bytes)) catch |e| {
            try err.print("deed post: could not read the note from stdin: {s}\n", .{@errorName(e)});
            return cli.exit_fail;
        };
        content_owned = all;
        break :blk std.mem.trimEnd(u8, all, "\r\n");
    };
    if (std.mem.trim(u8, content, " \t\r\n").len == 0) {
        try err.writeAll("deed post: nothing to post: give the text as an argument or on stdin\n");
        return cli.exit_usage;
    }

    var tty: ?Tty = null;
    defer if (tty) |*t| t.close();
    if (opts.confirm and !opts.dry_run) {
        tty = Tty.open(io) orelse {
            try err.writeAll("deed post: --confirm needs a terminal to ask on, and there is none\n");
            return cli.exit_fail;
        };
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No relay named: the relays the author writes to. A dry run that fetches
    // nothing needs no relay at all.
    var followed: ?outbox.Urls = null;
    defer if (followed) |*f| f.deinit();
    if (urls.items.len == 0 and (!opts.dry_run or opts.reply != null or opts.comment != null)) {
        followed = (try outbox.followWriteRelays(gpa, io, "post", signer.publicKey(), bootstrap.items, null, opts.timeout_ms, err)) orelse return cli.exit_usage;
        const take = @min(followed.?.urls.len, dial.max_relays);
        try urls.appendSlice(gpa, followed.?.urls[0..take]);
    }

    var kind: u16 = 1;
    var tags: []const event.Tag = &.{};
    if (opts.reply) |code| {
        tags = (try replyTagsFor(gpa, io, arena, code, urls.items, bootstrap.items, opts.timeout_ms, err)) orelse return cli.exit_fail;
    } else if (opts.comment) |code| {
        kind = 1111;
        tags = (try commentTagsFor(gpa, io, arena, code, urls.items, bootstrap.items, opts.timeout_ms, err)) orelse return cli.exit_fail;
    }

    // Confirmed before it is signed, so a remote signer is not asked to sign
    // a note that is then thrown away.
    if (tty) |*t| {
        if (!try t.confirm(content, urls.items.len)) {
            try err.writeAll("deed post: not published, not confirmed\n");
            return cli.exit_fail;
        }
    }

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const ev = signer.sign(arena, now, kind, tags, content) catch |e| return signing.report("post", e, err);
    const wire = try event.toJson(arena, ev);

    if (opts.dry_run) {
        try out.print("{s}\n", .{wire});
        return cli.exit_ok;
    }

    const accepted = try publishEvent(gpa, io, urls.items, ev, opts.timeout_ms, "post", err);
    if (accepted == 0) {
        try err.writeAll("deed post: not published, no relay accepted it\n");
        return cli.exit_fail;
    }
    try out.print("{s}\n", .{wire});
    return cli.exit_ok;
}

pub fn isRelayUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "wss://") or std.mem.startsWith(u8, s, "ws://");
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

pub const Found = struct {
    /// Relays that were reached.
    dialled: usize,
    /// Relays that said they had sent everything they had.
    complete: usize,
    /// The newest matching event, verified by the query.
    parsed: ?event.Parsed,
};

pub fn newerThan(a: event.Event, b: event.Event) bool {
    if (a.created_at != b.created_at) return a.created_at > b.created_at;
    // NIP-01: the lowest id wins a tie.
    return std.mem.order(u8, &a.id, &b.id) == .lt;
}

/// Asks `urls` the one question `f` and keeps the newest event any of them
/// answered with. Every event was verified and matched against `f` on the way.
pub fn fetchNewest(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    f: filter.Filter,
    timeout_ms: i64,
    store: ?*nostr.store.Store,
    err: *std.Io.Writer,
) !Found {
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    const o = try relayset.query(gpa, io, urls, &.{f}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
        .store = store,
    });
    var best: ?event.Parsed = null;
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var p = event.fromJson(gpa, line) catch continue;
        if (best) |*b| {
            if (newerThan(p.value, b.value)) {
                b.deinit();
                best = p;
            } else p.deinit();
        } else best = p;
    }
    return .{ .dialled = o.dialled, .complete = o.complete, .parsed = best };
}

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

/// Offers `ev` to every relay in `urls` and returns how many relays accepted
/// it: one if any did, since the shared publisher stops counting there. Each
/// relay's answer goes to `err`, with the event's id on it.
pub fn publishEvent(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    ev: event.Event,
    timeout_ms: i64,
    verb: []const u8,
    err: *std.Io.Writer,
) !usize {
    return if (try publish.publishOne(gpa, io, verb, urls, ev, timeout_ms, err)) 1 else 0;
}

// ---------------------------------------------------------------------------
// Asking a person
// ---------------------------------------------------------------------------

/// The controlling terminal, opened by name so a piped stdin and stdout do not
/// get in the way of asking. Where there is no such file (a service, Windows)
/// there is nobody to ask.
pub const Tty = struct {
    io: std.Io,
    file: std.Io.File,

    pub fn open(io: std.Io) ?Tty {
        const file = std.Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write }) catch return null;
        return .{ .io = io, .file = file };
    }

    pub fn close(self: *Tty) void {
        self.file.close(self.io);
    }

    /// Shows `what` and waits for a line. Only "y" or "yes" is a yes.
    pub fn confirm(self: *Tty, what: []const u8, relays: usize) !bool {
        var wbuf: [512]u8 = undefined;
        var w = self.file.writerStreaming(self.io, &wbuf);
        const shown = what[0..@min(what.len, 2000)];
        try w.interface.print("\n{s}{s}\n\nPublish to {d} relay(s)? [y/N] ", .{
            shown,
            if (what.len > shown.len) "..." else "",
            relays,
        });
        try w.interface.flush();
        var rbuf: [64]u8 = undefined;
        var r = self.file.readerStreaming(self.io, &rbuf);
        const line = (r.interface.takeDelimiter('\n') catch return false) orelse return false;
        const answer = std.mem.trim(u8, line, " \t\r");
        return std.ascii.eqlIgnoreCase(answer, "y") or std.ascii.eqlIgnoreCase(answer, "yes");
    }
};

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

fn mkTag(a: std.mem.Allocator, parts: []const []const u8) !event.Tag {
    return a.dupe([]const u8, parts);
}

fn hasPubkeyShape(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn appendPTag(a: std.mem.Allocator, list: *std.ArrayList(event.Tag), seen: *std.StringHashMapUnmanaged(void), pk_hex: []const u8) !void {
    if (seen.contains(pk_hex)) return;
    try seen.put(a, pk_hex, {});
    try list.append(a, try mkTag(a, &.{ "p", pk_hex }));
}

/// The NIP-10 tags for a reply to `parent`: marked `e` tags for the thread's
/// root and the direct parent, and a `p` tag for the parent's author followed by
/// everyone the parent already mentioned.
///
/// A parent that names a root (an `e` tag marked "root", or, in the older
/// positional form, the first `e` tag) makes that event the root and the parent
/// the "reply". A parent with neither is itself the root, so it is tagged once.
pub fn replyTags(a: std.mem.Allocator, parent: event.Event, hint: []const u8) ![]const event.Tag {
    const parent_id = try hex.encode(a, &parent.id);
    const parent_pk = try hex.encode(a, &parent.pubkey);

    var marked_root: ?event.Tag = null;
    var first_e: ?event.Tag = null;
    for (parent.tags) |t| {
        if (t.len < 2 or !std.mem.eql(u8, t[0], "e")) continue;
        if (first_e == null) first_e = t;
        if (t.len >= 4 and std.mem.eql(u8, t[3], "root")) {
            marked_root = t;
            break;
        }
    }
    // The positional form has no markers at all; trust its first `e` only then.
    const root_tag: ?event.Tag = marked_root orelse blk: {
        const f = first_e orelse break :blk null;
        break :blk if (f.len >= 4 and f[3].len > 0) null else f;
    };

    var list: std.ArrayList(event.Tag) = .empty;
    if (root_tag) |rt| {
        if (hasPubkeyShape(rt[1]) and !std.ascii.eqlIgnoreCase(rt[1], parent_id)) {
            const root_relay = if (rt.len >= 3) rt[2] else "";
            if (rt.len >= 5 and hasPubkeyShape(rt[4])) {
                try list.append(a, try mkTag(a, &.{ "e", rt[1], root_relay, "root", rt[4] }));
            } else {
                try list.append(a, try mkTag(a, &.{ "e", rt[1], root_relay, "root" }));
            }
            try list.append(a, try mkTag(a, &.{ "e", parent_id, hint, "reply", parent_pk }));
        } else {
            try list.append(a, try mkTag(a, &.{ "e", parent_id, hint, "root", parent_pk }));
        }
    } else {
        try list.append(a, try mkTag(a, &.{ "e", parent_id, hint, "root", parent_pk }));
    }

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    try appendPTag(a, &list, &seen, parent_pk);
    for (parent.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], "p") and hasPubkeyShape(t[1])) {
            try appendPTag(a, &list, &seen, t[1]);
        }
    }
    return list.toOwnedSlice(a);
}

/// What a NIP-22 comment is on.
pub const CommentTarget = struct {
    kind: u32,
    pubkey: [32]u8,
    /// Set for an event.
    id: ?[32]u8 = null,
    /// Set for an address: `kind:pubkey:identifier`.
    coordinate: ?[]const u8 = null,
    relay: []const u8 = "",
    /// The target's own tags. Only read when the target is itself a comment,
    /// whose root scope the new comment shares.
    tags: []const event.Tag = &.{},
};

/// The NIP-22 tags for a comment on `t`: the root scope in `E`/`A`, `K` and `P`,
/// the direct parent in `e`/`a`, `k` and `p`.
///
/// On anything but a comment the two are the same event. On a comment, the root
/// scope is copied from the comment's own uppercase tags, so a whole thread
/// keeps pointing at what it is about.
pub fn commentTags(a: std.mem.Allocator, t: CommentTarget) ![]const event.Tag {
    var list: std.ArrayList(event.Tag) = .empty;
    const kind_str = try std.fmt.allocPrint(a, "{d}", .{t.kind});
    const pk_hex = try hex.encode(a, &t.pubkey);

    var inherited = false;
    if (t.kind == 1111) {
        for (t.tags) |tag| {
            if (tag.len >= 2 and tag[0].len == 1 and std.mem.indexOfScalar(u8, "EAIKP", tag[0][0]) != null) {
                try list.append(a, tag);
                inherited = true;
            }
        }
    }

    if (t.id) |id| {
        const id_hex = try hex.encode(a, &id);
        if (!inherited) {
            try list.append(a, try mkTag(a, &.{ "E", id_hex, t.relay, pk_hex }));
            try list.append(a, try mkTag(a, &.{ "K", kind_str }));
            try list.append(a, try mkTag(a, &.{ "P", pk_hex }));
        }
        try list.append(a, try mkTag(a, &.{ "e", id_hex, t.relay, pk_hex }));
    } else {
        const coord = t.coordinate orelse return error.NoTarget;
        if (!inherited) {
            try list.append(a, try mkTag(a, &.{ "A", coord, t.relay }));
            try list.append(a, try mkTag(a, &.{ "K", kind_str }));
            try list.append(a, try mkTag(a, &.{ "P", pk_hex }));
        }
        try list.append(a, try mkTag(a, &.{ "a", coord, t.relay }));
    }
    try list.append(a, try mkTag(a, &.{ "k", kind_str }));
    try list.append(a, try mkTag(a, &.{ "p", pk_hex }));
    return list.toOwnedSlice(a);
}

// ---------------------------------------------------------------------------
// Resolving what a reply or comment is about
// ---------------------------------------------------------------------------

const Ref = struct {
    id: ?[32]u8 = null,
    author: ?[32]u8 = null,
    kind: ?u32 = null,
    identifier: ?[]u8 = null,
    hints: [][]u8 = &.{},

    fn deinit(self: *Ref, gpa: std.mem.Allocator) void {
        for (self.hints) |h| gpa.free(h);
        gpa.free(self.hints);
        if (self.identifier) |d| gpa.free(d);
    }
};

fn parseRef(gpa: std.mem.Allocator, raw: []const u8) !Ref {
    const s = keyinput.stripUri(std.mem.trim(u8, raw, " \t\r\n"));
    if (keyinput.hasPrefix(s, "nevent1")) {
        const p = try nip19.decodeNevent(gpa, s);
        return .{ .id = p.id, .author = p.author, .kind = p.kind, .hints = p.relays };
    }
    if (keyinput.hasPrefix(s, "naddr1")) {
        const p = try nip19.decodeNaddr(gpa, s);
        return .{ .author = p.pubkey, .kind = p.kind, .identifier = p.identifier, .hints = p.relays };
    }
    if (keyinput.hasPrefix(s, "note1")) return .{ .id = try nip19.decodeNote(gpa, s) };
    if (s.len == 64) return .{ .id = try hex.decodeFixed(32, s) };
    return error.InvalidPrefix;
}

/// The relays to look in: the ones named, then the code's own hints.
fn lookupUrls(gpa: std.mem.Allocator, named: []const []const u8, ref: Ref) !std.ArrayList([]const u8) {
    var urls: std.ArrayList([]const u8) = .empty;
    errdefer urls.deinit(gpa);
    for (named) |u| try urls.append(gpa, u);
    for (ref.hints) |h| {
        var seen = false;
        for (urls.items) |u| {
            if (std.mem.eql(u8, u, h)) seen = true;
        }
        if (!seen) try urls.append(gpa, h);
    }
    return urls;
}

fn fetchById(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    id: [32]u8,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !?event.Parsed {
    var ids = [1][32]u8{id};
    const found = try fetchNewest(gpa, io, urls, .{ .ids = &ids, .limit = 1 }, timeout_ms, null, err);
    return found.parsed;
}

/// The event `id`, asked of the relays in `urls` first. When they do not have
/// it, or there are none, and the code names its author but carries no relay
/// hints, it is asked of the relays that author writes to. `bootstrap` is where
/// that author's relay list is looked for, with `DEED_RELAYS`.
fn fetchParent(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    ref: Ref,
    id: [32]u8,
    bootstrap: []const []const u8,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !?event.Parsed {
    if (urls.len > 0) {
        if (try fetchById(gpa, io, urls, id, timeout_ms, err)) |p| return p;
    }
    const author = ref.author orelse return null;
    if (ref.hints.len > 0) return null;
    // With relays already tried and nothing to look the author up through,
    // there is nothing more to say than that the event was not found.
    if (urls.len > 0 and bootstrap.len == 0 and getEnv("DEED_RELAYS") == null) return null;
    var theirs = (try outbox.followWriteRelays(gpa, io, "post", author, bootstrap, null, timeout_ms, err)) orelse return null;
    defer theirs.deinit();
    return fetchById(gpa, io, theirs.urls, id, timeout_ms, err);
}

fn replyTagsFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    code: []const u8,
    named: []const []const u8,
    bootstrap: []const []const u8,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !?[]const event.Tag {
    var ref = parseRef(gpa, code) catch {
        try err.print("deed post: {s}: not an event a reply can go to (want nevent, note or 64 hex characters)\n", .{code});
        return null;
    };
    defer ref.deinit(gpa);
    const id = ref.id orelse {
        try err.writeAll("deed post: --reply needs an event, and an address names no single one: use --comment\n");
        return null;
    };
    var urls = try lookupUrls(gpa, named, ref);
    defer urls.deinit(gpa);
    if (urls.items.len == 0 and ref.author == null) {
        try err.writeAll("deed post: the parent has to be fetched to build the thread: name a relay\n");
        return null;
    }
    var parent = (try fetchParent(gpa, io, urls.items, ref, id, bootstrap, timeout_ms, err)) orelse {
        // A reply tagged without reading its parent would start a new thread
        // under a wrong root, so it is not built.
        try err.writeAll("deed post: could not fetch the parent from those relays, so the reply is not built\n");
        return null;
    };
    defer parent.deinit();
    if (parent.value.kind != 1) {
        try err.print("deed post: note: the parent is kind {d}; NIP-22 --comment is the reply for anything but a text note\n", .{parent.value.kind});
    }
    const hint: []const u8 = if (ref.hints.len > 0) try arena.dupe(u8, ref.hints[0]) else "";
    // Built into the arena, which outlives the parent freed above.
    return try replyTags(arena, parent.value, hint);
}

fn commentTagsFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    code: []const u8,
    named: []const []const u8,
    bootstrap: []const []const u8,
    timeout_ms: i64,
    err: *std.Io.Writer,
) !?[]const event.Tag {
    var ref = parseRef(gpa, code) catch {
        try err.print("deed post: {s}: not something a comment can go on (want nevent or naddr)\n", .{code});
        return null;
    };
    defer ref.deinit(gpa);
    const hint: []const u8 = if (ref.hints.len > 0) try arena.dupe(u8, ref.hints[0]) else "";

    if (ref.identifier) |d| {
        const coord = try std.fmt.allocPrint(arena, "{d}:{s}:{s}", .{
            ref.kind.?,
            try hex.encode(arena, &ref.author.?),
            d,
        });
        return try commentTags(arena, .{ .kind = ref.kind.?, .pubkey = ref.author.?, .coordinate = coord, .relay = hint });
    }

    const id = ref.id.?;
    // What a comment needs of its target is its author and kind, and for a
    // comment on a comment, its root. The code often carries the first two.
    if (ref.author != null and ref.kind != null and ref.kind.? != 1111) {
        return try commentTags(arena, .{ .kind = ref.kind.?, .pubkey = ref.author.?, .id = id, .relay = hint });
    }
    var urls = try lookupUrls(gpa, named, ref);
    defer urls.deinit(gpa);
    if (urls.items.len == 0 and ref.author == null) {
        try err.writeAll("deed post: the target has to be fetched to learn its author and kind: name a relay\n");
        return null;
    }
    var target = (try fetchParent(gpa, io, urls.items, ref, id, bootstrap, timeout_ms, err)) orelse {
        try err.writeAll("deed post: could not fetch the target from those relays, so the comment is not built\n");
        return null;
    };
    defer target.deinit();
    return try commentTags(arena, .{
        .kind = target.value.kind,
        .pubkey = target.value.pubkey,
        .id = id,
        .relay = hint,
        .tags = try copyTags(arena, target.value.tags),
    });
}

fn copyTags(a: std.mem.Allocator, tags: []const event.Tag) ![]const event.Tag {
    const dst = try a.alloc(event.Tag, tags.len);
    for (tags, dst) |t, *d| {
        const parts = try a.alloc([]const u8, t.len);
        for (t, parts) |p, *dp| dp.* = try a.dupe(u8, p);
        d.* = parts;
    }
    return dst;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testEvent(id_byte: u8, pk_byte: u8, kind: u16, tags: []const event.Tag) event.Event {
    return .{
        .id = [_]u8{id_byte} ** 32,
        .pubkey = [_]u8{pk_byte} ** 32,
        .created_at = 1_700_000_000,
        .kind = kind,
        .tags = tags,
        .content = "",
        .sig = [_]u8{0} ** 64,
    };
}

fn expectTag(tag: event.Tag, want: []const []const u8) !void {
    try testing.expectEqual(want.len, tag.len);
    for (want, tag) |w, g| try testing.expectEqualStrings(w, g);
}

test "a reply to a top-level note carries one root e tag and the author's p tag" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const parent = testEvent(0xaa, 0xbb, 1, &.{});
    const tags = try replyTags(a, parent, "wss://hint.example");
    try testing.expectEqual(@as(usize, 2), tags.len);
    try expectTag(tags[0], &.{ "e", "aa" ** 32, "wss://hint.example", "root", "bb" ** 32 });
    try expectTag(tags[1], &.{ "p", "bb" ** 32 });
}

test "a reply inside a thread marks the root and the parent, and keeps the thread's people" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const root = "11" ** 32;
    const other = "cc" ** 32;
    const parent_tags = [_]event.Tag{
        &.{ "e", root, "wss://root.example", "root" },
        &.{ "p", other },
        &.{ "p", "bb" ** 32 },
    };
    const parent = testEvent(0xaa, 0xbb, 1, &parent_tags);
    const tags = try replyTags(a, parent, "");
    try testing.expectEqual(@as(usize, 4), tags.len);
    try expectTag(tags[0], &.{ "e", root, "wss://root.example", "root" });
    try expectTag(tags[1], &.{ "e", "aa" ** 32, "", "reply", "bb" ** 32 });
    // The parent's author first, then the rest, each once.
    try expectTag(tags[2], &.{ "p", "bb" ** 32 });
    try expectTag(tags[3], &.{ "p", other });
}

test "an older positional thread names its first e tag as the root" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const root = "22" ** 32;
    const parent_tags = [_]event.Tag{ &.{ "e", root }, &.{ "e", "33" ** 32 } };
    const parent = testEvent(0xaa, 0xbb, 1, &parent_tags);
    const tags = try replyTags(a, parent, "");
    try expectTag(tags[0], &.{ "e", root, "", "root" });
    try expectTag(tags[1], &.{ "e", "aa" ** 32, "", "reply", "bb" ** 32 });
}

test "a comment on an event puts the same scope in upper and lower case" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const tags = try commentTags(a, .{ .kind = 30023, .pubkey = [_]u8{0xbb} ** 32, .id = [_]u8{0xaa} ** 32, .relay = "wss://r.example" });
    try testing.expectEqual(@as(usize, 6), tags.len);
    try expectTag(tags[0], &.{ "E", "aa" ** 32, "wss://r.example", "bb" ** 32 });
    try expectTag(tags[1], &.{ "K", "30023" });
    try expectTag(tags[2], &.{ "P", "bb" ** 32 });
    try expectTag(tags[3], &.{ "e", "aa" ** 32, "wss://r.example", "bb" ** 32 });
    try expectTag(tags[4], &.{ "k", "30023" });
    try expectTag(tags[5], &.{ "p", "bb" ** 32 });
}

test "a comment on an address uses A and a" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const tags = try commentTags(a, .{ .kind = 30023, .pubkey = [_]u8{0xbb} ** 32, .coordinate = "30023:pk:slug" });
    try expectTag(tags[0], &.{ "A", "30023:pk:slug", "" });
    try expectTag(tags[3], &.{ "a", "30023:pk:slug", "" });
}

test "a comment on a comment keeps the root scope and points the lowercase tags at the parent" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const parent_tags = [_]event.Tag{
        &.{ "E", "11" ** 32, "", "22" ** 32 },
        &.{ "K", "1" },
        &.{ "P", "22" ** 32 },
        &.{ "e", "11" ** 32, "", "22" ** 32 },
        &.{ "k", "1" },
        &.{ "p", "22" ** 32 },
    };
    const tags = try commentTags(a, .{ .kind = 1111, .pubkey = [_]u8{0xbb} ** 32, .id = [_]u8{0xaa} ** 32, .tags = &parent_tags });
    try testing.expectEqual(@as(usize, 6), tags.len);
    try expectTag(tags[0], &.{ "E", "11" ** 32, "", "22" ** 32 });
    try expectTag(tags[1], &.{ "K", "1" });
    try expectTag(tags[2], &.{ "P", "22" ** 32 });
    try expectTag(tags[3], &.{ "e", "aa" ** 32, "", "bb" ** 32 });
    try expectTag(tags[4], &.{ "k", "1111" });
    try expectTag(tags[5], &.{ "p", "bb" ** 32 });
}

test "a note needs a relay unless it is a dry run" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const sk = "11" ** 32;

    const code = try run(testing.allocator, testing.io, &.{ "hello", "--sec", sk }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_usage, code);

    err.clearRetainingCapacity();
    const dry = try run(testing.allocator, testing.io, &.{ "hello", "--sec", sk, "--dry-run" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, dry);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"kind\":1,") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"content\":\"hello\"") != null);
}

/// A relay that serves one event to any REQ and answers every EVENT.
pub const Script = struct {
    /// Served in answer to any REQ. Empty serves nothing.
    serve: []const u8 = "",
    /// The last EVENT frame the relay was offered.
    got: [8192]u8 = undefined,
    got_len: usize = 0,
    events: usize = 0,
    /// Answer an EVENT with a refusal.
    refuse: bool = false,

    pub fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Script = @ptrCast(@alignCast(ctx.?));
        const testrelay = @import("testrelay.zig");
        if (std.mem.startsWith(u8, frame, "[\"REQ\"")) {
            var line: [8192]u8 = undefined;
            if (self.serve.len > 0) {
                try testrelay.sendText(w, try std.fmt.bufPrint(&line, "[\"EVENT\",\"deed\",{s}]", .{self.serve}));
            }
            try testrelay.sendText(w, "[\"EOSE\",\"deed\"]");
        } else if (std.mem.startsWith(u8, frame, "[\"EVENT\"")) {
            self.events += 1;
            const n = @min(frame.len, self.got.len);
            @memcpy(self.got[0..n], frame[0..n]);
            self.got_len = n;
            const at = std.mem.indexOf(u8, frame, "\"id\":\"") orelse return error.BadFrame;
            const id = frame[at + 6 ..][0..64];
            var line: [256]u8 = undefined;
            try testrelay.sendText(w, try std.fmt.bufPrint(&line, "[\"OK\",\"{s}\",{s},\"{s}\"]", .{
                id,
                if (self.refuse) "false" else "true",
                if (self.refuse) "blocked: no" else "",
            }));
        }
    }
};

pub fn signedJson(a: std.mem.Allocator, io: std.Io, sk: [32]u8, kind: u16, tags: []const event.Tag, content: []const u8, at: i64) ![]const u8 {
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(sk);
    const ev = try event.create(a, signer, kp, at, kind, tags, content, null);
    return event.toJson(a, ev);
}

test "a scripted relay: a reply fetches its parent, publishes, and prints what was accepted" {
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the post leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const parent_json = try signedJson(a, io, [_]u8{0x21} ** 32, 1, &.{}, "the parent", 1_700_000_000);
    var parsed = try event.fromJson(a, parent_json);
    defer parsed.deinit();
    const parent_id = try hex.encode(a, &parsed.value.id);
    const parent_pk = try hex.encode(a, &parsed.value.pubkey);

    var script = Script{ .serve = parent_json };
    var relay: testrelay.Relay = undefined;
    // One connection to fetch the parent, one to publish.
    try relay.startFor(io, .custom, 2);
    relay.custom = Script.handle;
    relay.custom_ctx = &script;
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    const code = try run(gpa, io, &.{ "my reply", "--sec", "33" ** 32, "--reply", parent_id, url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqual(@as(usize, 1), script.events);
    const sent = script.got[0..script.got_len];
    try testing.expect(std.mem.indexOf(u8, sent, "\"root\"") != null);
    try testing.expect(std.mem.indexOf(u8, sent, parent_pk) != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"content\":\"my reply\"") != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "accepted") != null);
}

test "a refused note is not printed and the exit says so" {
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the post leaked");
    const gpa = da.allocator();

    var script = Script{ .refuse = true };
    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, Script.handle, &script);
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    const code = try run(gpa, io, &.{ "nope", "--sec", "33" ** 32, url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expect(std.mem.indexOf(u8, err.written(), "refused: blocked: no") != null);
}

test "with no relay named a note goes to the relays its author writes to" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the post leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var home_script = Script{};
    var home: testrelay.Relay = undefined;
    try home.startCustom(io, Script.handle, &home_script);
    defer home.stop(io);
    var home_buf: [40]u8 = undefined;
    const home_url = try testrelay.url(&home_buf, home.port());

    const sk = [_]u8{0x33} ** 32;
    const list_tags = [_]event.Tag{&.{ "r", home_url, "write" }};
    const list_json = try signedJson(a, io, sk, 10002, &list_tags, "", 1_700_000_000);
    var dir_script: outbox.Script = .{ .list = list_json };
    var directory: testrelay.Relay = undefined;
    try outbox.startScript(&directory, io, &dir_script, 1);
    defer directory.stop(io);
    var dir_buf: [40]u8 = undefined;
    const dir_url = try testrelay.url(&dir_buf, directory.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "hello", "--sec", "33" ** 32, "--relay", dir_url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqual(@as(usize, 1), home_script.events);
    try testing.expect(std.mem.indexOf(u8, out.written(), "\"content\":\"hello\"") != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "accepted") != null);
}

test "a reply to an event with an author and no hints reads the parent from the author's relays" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the post leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const parent_sk = [_]u8{0x21} ** 32;
    const parent_json = try signedJson(a, io, parent_sk, 1, &.{}, "the parent", 1_700_000_000);
    var parsed = try event.fromJson(a, parent_json);
    defer parsed.deinit();
    const code_text = try nip19.encodeNevent(a, parsed.value.id, &.{}, parsed.value.pubkey, null);

    // The parent lives on its author's relay, which nobody told the reply about.
    var parent_script = Script{ .serve = parent_json };
    var parent_relay: testrelay.Relay = undefined;
    try parent_relay.startCustom(io, Script.handle, &parent_script);
    defer parent_relay.stop(io);
    var parent_buf: [40]u8 = undefined;
    const parent_url = try testrelay.url(&parent_buf, parent_relay.port());

    const list_tags = [_]event.Tag{&.{ "r", parent_url, "write" }};
    var dir_script: outbox.Script = .{ .list = try signedJson(a, io, parent_sk, 10002, &list_tags, "", 1_700_000_000) };
    var directory: testrelay.Relay = undefined;
    try outbox.startScript(&directory, io, &dir_script, 1);
    defer directory.stop(io);
    var dir_buf: [40]u8 = undefined;
    const dir_url = try testrelay.url(&dir_buf, directory.port());

    // Where the reply goes is named, and is another relay.
    var mine_script = Script{};
    var mine: testrelay.Relay = undefined;
    // Asked for the parent first, then offered the reply.
    try mine.startFor(io, .custom, 2);
    mine.custom = Script.handle;
    mine.custom_ctx = &mine_script;
    defer mine.stop(io);
    var mine_buf: [40]u8 = undefined;
    const mine_url = try testrelay.url(&mine_buf, mine.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "answer", "--sec", "33" ** 32, "--reply", code_text, mine_url, "--relay", dir_url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqual(@as(usize, 1), mine_script.events);
    try testing.expect(std.mem.indexOf(u8, mine_script.got[0..mine_script.got_len], "\"root\"") != null);
}

test "a key that cannot be read exits 1 with one line, and a missing key is a usage error" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const code = try run(testing.allocator, testing.io, &.{ "hi", "--sec", "nope", "--dry-run" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, err.written(), "\n"));
    try testing.expect(std.mem.indexOf(u8, err.written(), "not a secret key") != null);
}

const Dribble = struct {
    io: std.Io,
    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Dribble = @ptrCast(@alignCast(ctx.?));
        if (!std.mem.startsWith(u8, frame, "[\"EVENT\"")) return;
        // A text frame declaring 1000 bytes, then one byte every 100 ms.
        try w.writeAll(&.{ 0x81, 126, 0x03, 0xE8 });
        try w.flush();
        var k: usize = 0;
        while (k < 40) : (k += 1) {
            try self.io.sleep(.fromMilliseconds(100), .awake);
            try w.writeAll(" ");
            try w.flush();
        }
    }
};

test "publishEvent is bounded by its timeout against a dribbling relay" {
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    const gpa = std.heap.page_allocator;
    var d = Dribble{ .io = io };
    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, Dribble.handle, &d);
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const j = try signedJson(arena_state.allocator(), io, [_]u8{0x21} ** 32, 1, &.{}, "x", 1_700_000_000);
    var p = try event.fromJson(arena_state.allocator(), j);
    defer p.deinit();
    var eb: [4096]u8 = undefined;
    var ew: std.Io.Writer = .fixed(&eb);
    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    _ = try publishEvent(gpa, io, &.{url}, p.value, 500, "post", &ew);
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;
    try testing.expect(took < 2000);
}
