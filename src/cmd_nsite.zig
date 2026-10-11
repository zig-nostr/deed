//! `deed nsite`: static websites on nostr and Blossom (NIP-5A).
//!
//! A site is one event, a manifest, that maps absolute paths to the sha256 of
//! the file served there (`["path", "/index.html", "<sha256>"]`), and the files
//! themselves live on Blossom servers under that hash. A root site is a kind
//! 15128 event, a named site a kind 35128 event with a `d` tag.
//!
//! deploy hashes every file, uploads the ones the published manifest does not
//! already name, and publishes a new manifest. download is the other way, and
//! writes a file only once the bytes that arrived hash to the name the manifest
//! gave. Both are bounded: a manifest may name only so many files, a file may
//! be only so large, and a whole site only so large.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const blossom = @import("cmd_blossom.zig");
const http = @import("http.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const publish = @import("cmd_publish.zig");
const relayset = @import("relayset.zig");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const event = nostr.event;
const hex = nostr.hex;

/// Shown beside the name in `deed help`.
pub const summary = "deploy, download and list static sites (NIP-5A)";

pub const ready = true;

pub const usage =
    \\deed nsite: deploy, download and list static sites (NIP-5A)
    \\
    \\Usage:
    \\  deed nsite deploy <dir> --server <blossom>... [--sec <key>] [<relay-url>...]
    \\  deed nsite download <npub> <dir> [<relay-url>...]
    \\  deed nsite list <npub> [<relay-url>...]
    \\
    \\A site is a manifest event that maps paths to the sha256 of the file served
    \\there, plus the files, which live on Blossom servers under that hash. By
    \\default the site is the person's root site (kind 15128); --name picks one
    \\of their named sites (kind 35128).
    \\
    \\deploy   Hashes every regular file under <dir>, uploads the ones the
    \\         published manifest does not already name to each --server, and
    \\         publishes the new manifest. A file the published manifest already
    \\         names is not uploaded again, but each --server is asked (HEAD) whether
    \\         it holds the file, and gets it if not. When the files, the servers
    \\         and the title, description and source are all the same as the
    \\         published manifest, nothing is published. The manifest names only
    \\         the servers that hold every file; if a file reached no server, or
    \\         no server holds every file, nothing is published. If the published
    \\         manifest cannot be read, or no relay finished answering, deploy
    \\         stops, because it could not tell what it would replace; --force goes
    \\         on. Prints the manifest event if at least one relay accepted it.
    \\         Symbolic links are skipped, and so are dot-files and
    \\         dot-directories (.git, .env, .DS_Store): a published file cannot be
    \\         taken back. --include-hidden publishes them.
    \\download Fetches the manifest and downloads each file from the servers the
    \\         manifest names (and any given with --server), in order, into
    \\         <dir>, which must not exist or be empty. A file is written only
    \\         when its bytes hash to the name in the manifest. Prints each path
    \\         as it is written.
    \\list     Prints the files of the manifest, one per line: the path, a tab
    \\         and the sha256. --sites prints the person's sites instead:
    \\         root or named, the name, the manifest's created_at and the
    \\         number of files.
    \\
    \\Options:
    \\  -s, --server <url>    a Blossom server (domain or URL); repeat it. deploy
    \\                        needs at least one and uploads to all of them, and
    \\                        names those that took every file;
    \\                        download adds them after the manifest's own
    \\      --sec <key>       deploy: the key that signs, as nsec1..., ncryptsec1...
    \\                        or 64 hex characters. Falls back to $NOSTR_SECRET_KEY
    \\      --name <d>        a named site, 1 to 13 characters of a-z, 0-9 and -,
    \\                        not ending in -
    \\      --title <text>    deploy: a title for the site
    \\      --description <text>
    \\                        deploy: a description for the site
    \\      --source <url>    deploy: where the source lives
    \\      --force           deploy: upload every file and publish even if the
    \\                        published manifest is the same, or cannot be read, or
    \\                        no relay finished answering
    \\      --include-hidden  deploy: publish dot-files and dot-directories too
    \\      --allow-local     download, deploy: let the servers asked for blobs resolve
    \\                        to loopback, private or link-local addresses (refused
    \\                        by default, so a manifest cannot aim deed at your
    \\                        own network)
    \\      --sites           list: the person's sites rather than one site's files
    \\  -r, --relay <url>     a relay (repeatable; a bare ws:// or wss:// argument
    \\                        works too)
    \\      --timeout <ms>    how long the relays get to answer (default 10000)
    \\
    \\With no relay named, deed finds the relays the person writes to through the
    \\relays in DEED_RELAYS (comma or space separated). deed has no built-in list.
    \\
    \\Limits: a manifest may name 10000 files, a file may be 100 MiB, and a site
    \\1 GiB. A manifest with a path that is not a plain absolute path (a ..
    \\segment, a backslash, a control character) is refused, and so is a
    \\download of paths that differ only in case (or, on Windows, that Windows
    \\cannot create).
    \\
    \\Exits: 0 when everything asked for was done; 1 when something failed;
    \\2 when the command line was not understood.
    \\
;

const Command = enum { deploy, download, list };

pub const kind_root: u16 = 15128;
pub const kind_named: u16 = 35128;

const max_files = 10_000;
const max_file_bytes: u64 = 100 * 1024 * 1024;
const max_site_bytes: u64 = 1024 * 1024 * 1024;
const max_path_bytes = 1024;
const blob_timeout_ms: u64 = 60_000;

// ---------------------------------------------------------------------------
// Manifests
// ---------------------------------------------------------------------------

const PathHash = struct {
    path: []const u8,
    sha: [32]u8,
};

const Manifest = struct {
    /// Sorted by path.
    paths: []const PathHash,
    servers: []const []const u8,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    source: ?[]const u8 = null,
    created_at: i64,
};

const ManifestError = error{ UnsafePath, TooManyFiles, OutOfMemory };

/// Whether `p` is a path a manifest may name and a download may write: an
/// absolute path of plain segments, ending in a file name.
fn safePath(p: []const u8) bool {
    if (p.len < 2 or p.len > max_path_bytes) return false;
    if (p[0] != '/' or p[p.len - 1] == '/') return false;
    if (!std.unicode.utf8ValidateSlice(p)) return false;
    for (p) |c| {
        if (c < 0x20 or c == 0x7f or c == '\\' or c == ':') return false;
    }
    var it = std.mem.splitScalar(u8, p[1..], '/');
    while (it.next()) |seg| {
        if (seg.len == 0) return false;
        if (std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

fn lessPath(_: void, a: PathHash, b: PathHash) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

/// Reads the `path` and `server` tags of a manifest. A path tag that is
/// malformed (no hash, a hash that is not 64 lowercase hex characters) is left
/// out; one whose path is unsafe fails the whole manifest, because writing the
/// rest of the site as if it were not there would hide that it is hostile.
fn parseManifest(a: std.mem.Allocator, ev: event.Event, bad_path: *[]const u8) ManifestError!Manifest {
    var paths: std.ArrayList(PathHash) = .empty;
    var servers: std.ArrayList([]const u8) = .empty;
    var meta: Manifest = .{ .paths = &.{}, .servers = &.{}, .created_at = ev.created_at };
    for (ev.tags) |tag| {
        if (tag.len >= 3 and std.mem.eql(u8, tag[0], "path")) {
            const sha = hex.decodeFixed(32, tag[2]) catch continue;
            if (tag[2].len != 64 or !isLowerHex(tag[2])) continue;
            if (!safePath(tag[1])) {
                bad_path.* = tag[1];
                return error.UnsafePath;
            }
            var dup = false;
            for (paths.items) |p| {
                if (std.mem.eql(u8, p.path, tag[1])) dup = true;
            }
            if (dup) continue;
            if (paths.items.len >= max_files) return error.TooManyFiles;
            try paths.append(a, .{ .path = try a.dupe(u8, tag[1]), .sha = sha });
        } else if (tag.len >= 2 and std.mem.eql(u8, tag[0], "server")) {
            try servers.append(a, try a.dupe(u8, tag[1]));
        } else if (tag.len >= 2 and std.mem.eql(u8, tag[0], "title") and meta.title == null) {
            meta.title = try a.dupe(u8, tag[1]);
        } else if (tag.len >= 2 and std.mem.eql(u8, tag[0], "description") and meta.description == null) {
            meta.description = try a.dupe(u8, tag[1]);
        } else if (tag.len >= 2 and std.mem.eql(u8, tag[0], "source") and meta.source == null) {
            meta.source = try a.dupe(u8, tag[1]);
        }
    }
    std.mem.sort(PathHash, paths.items, {}, lessPath);
    meta.paths = paths.items;
    meta.servers = servers.items;
    return meta;
}

fn isLowerHex(s: []const u8) bool {
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

/// The aggregate hash of NIP-5A: the sha256 of the sorted lines
/// `<sha256> <path>\n`.
fn aggregate(a: std.mem.Allocator, paths: []const PathHash) ![64]u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    for (paths) |p| {
        const h = std.fmt.bytesToHex(p.sha, .lower);
        try lines.append(a, try std.fmt.allocPrint(a, "{s} {s}\n", .{ &h, p.path }));
    }
    std.mem.sort([]const u8, lines.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    var h = Sha256.init(.{});
    for (lines.items) |l| h.update(l);
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// `^[a-z0-9-]{1,13}$`, not ending in `-`.
fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 13 or name[name.len - 1] == '-') return false;
    for (name) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-')) return false;
    }
    return true;
}

/// A server as the user or a manifest wrote it, as a URL without a trailing
/// slash. Null when it is not something to connect to.
fn normalizeServer(a: std.mem.Allocator, raw: []const u8) !?[]const u8 {
    const t = std.mem.trim(u8, raw, " \t\r\n");
    if (t.len == 0 or t.len > 512) return null;
    for (t) |c| if (c <= ' ' or c == 0x7f) return null;
    var s = t;
    while (s.len > 0 and s[s.len - 1] == '/') s = s[0 .. s.len - 1];
    if (std.mem.indexOf(u8, s, "://")) |_| {
        if (!std.ascii.startsWithIgnoreCase(s, "https://") and !std.ascii.startsWithIgnoreCase(s, "http://")) return null;
        return try a.dupe(u8, s);
    }
    if (s.len == 0) return null;
    return try std.fmt.allocPrint(a, "https://{s}", .{s});
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const Opts = struct {
    positionals: std.ArrayList([]const u8) = .empty,
    servers: std.ArrayList([]const u8) = .empty,
    relays: std.ArrayList([]const u8) = .empty,
    sec: ?[]const u8 = null,
    name: ?[]const u8 = null,
    title: ?[]const u8 = null,
    description: ?[]const u8 = null,
    source: ?[]const u8 = null,
    force: bool = false,
    include_hidden: bool = false,
    allow_local: bool = false,
    sites: bool = false,
    timeout_ms: i64 = 10_000,

    fn deinit(self: *Opts, gpa: std.mem.Allocator) void {
        self.positionals.deinit(gpa);
        self.servers.deinit(gpa);
        self.relays.deinit(gpa);
    }
};

fn isRelayUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "wss://") or std.mem.startsWith(u8, s, "ws://");
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed nsite: say what to do: deploy, download or list (see 'deed help nsite')\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    const cmd = std.meta.stringToEnum(Command, args[0]) orelse {
        try err.print("deed nsite: unknown command '{s}' (want deploy, download or list)\n", .{args[0]});
        return cli.exit_usage;
    };

    var opts: Opts = .{};
    defer opts.deinit(gpa);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, a, "--include-hidden")) {
            opts.include_hidden = true;
        } else if (std.mem.eql(u8, a, "--allow-local")) {
            opts.allow_local = true;
        } else if (std.mem.eql(u8, a, "--sites")) {
            opts.sites = true;
        } else if (cli.isOneOf(a, &.{ "-s", "--server", "-r", "--relay", "--sec", "--name", "--title", "--description", "--source", "--timeout" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed nsite: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            const v = args[i];
            if (cli.isOneOf(a, &.{ "-s", "--server" })) {
                try opts.servers.append(gpa, v);
            } else if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try opts.relays.append(gpa, v);
            } else if (std.mem.eql(u8, a, "--sec")) {
                opts.sec = v;
            } else if (std.mem.eql(u8, a, "--name")) {
                opts.name = v;
            } else if (std.mem.eql(u8, a, "--title")) {
                opts.title = v;
            } else if (std.mem.eql(u8, a, "--description")) {
                opts.description = v;
            } else if (std.mem.eql(u8, a, "--source")) {
                opts.source = v;
            } else {
                opts.timeout_ms = std.fmt.parseInt(i64, v, 10) catch 0;
                if (opts.timeout_ms <= 0) {
                    try err.print("deed nsite: '{s}' is not a number of milliseconds above 0\n", .{v});
                    return cli.exit_usage;
                }
            }
        } else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
            try err.print("deed nsite: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (isRelayUrl(a)) {
            try opts.relays.append(gpa, a);
        } else {
            try opts.positionals.append(gpa, a);
        }
    }

    if (opts.name) |n| {
        if (!validName(n)) {
            try err.writeAll("deed nsite: --name must be 1 to 13 characters of a-z, 0-9 and -, and not end in -\n");
            return cli.exit_usage;
        }
    }
    const want: usize = switch (cmd) {
        .deploy, .list => 1,
        .download => 2,
    };
    if (opts.positionals.items.len != want) {
        try err.print("deed nsite {s}: takes {s}\n", .{ @tagName(cmd), switch (cmd) {
            .deploy => "exactly one directory",
            .download => "an npub and a directory",
            .list => "exactly one npub",
        } });
        return cli.exit_usage;
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var servers: std.ArrayList([]const u8) = .empty;
    for (opts.servers.items) |raw| {
        const s = (try normalizeServer(arena, raw)) orelse {
            try err.print("deed nsite: '{s}' is not a server (want a domain or an http(s) URL)\n", .{raw});
            return cli.exit_usage;
        };
        try servers.append(arena, s);
    }

    return switch (cmd) {
        .deploy => deploy(gpa, io, arena, opts, servers.items, out, err),
        .download => download(gpa, io, arena, opts, servers.items, out, err),
        .list => list(gpa, io, arena, opts, out, err),
    };
}

// ---------------------------------------------------------------------------
// Relays
// ---------------------------------------------------------------------------

const Relays = struct {
    urls: []const []const u8,
    found: ?outbox.Urls,

    fn deinit(self: *Relays) void {
        if (self.found) |*f| f.deinit();
    }
};

/// The relays named, or else the ones the person writes to. Null after saying
/// why when there are none.
fn resolveRelays(gpa: std.mem.Allocator, io: Io, opts: Opts, pk: [32]u8, err: *Io.Writer) !?Relays {
    if (opts.relays.items.len > 0) return .{ .urls = opts.relays.items, .found = null };
    const found = (try outbox.followWriteRelays(gpa, io, "nsite", pk, &.{}, null, opts.timeout_ms, err)) orelse return null;
    return .{ .urls = found.urls, .found = found };
}

fn newerThan(a: event.Event, b: event.Event) bool {
    if (a.created_at != b.created_at) return a.created_at > b.created_at;
    return std.mem.order(u8, &a.id, &b.id) == .lt;
}

/// What a fetch found, and how many relays finished answering: none that did
/// means "no site" cannot be told from "nobody said".
const Fetched = struct {
    parsed: ?event.Parsed,
    /// Relays that sent everything they had before the deadline.
    complete: usize,
};

/// The newest event any relay returns for `f`. Every event was verified and
/// matched against the filter on the way.
fn fetchNewest(gpa: std.mem.Allocator, io: Io, urls: []const []const u8, f: nostr.filter.Filter, timeout_ms: i64, err: *Io.Writer) !Fetched {
    var buf: Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    const outcome = try relayset.query(gpa, io, urls, &.{f}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
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
    return .{ .parsed = best, .complete = outcome.complete };
}

fn fetchSite(gpa: std.mem.Allocator, io: Io, urls: []const []const u8, pk: [32]u8, name: ?[]const u8, timeout_ms: i64, err: *Io.Writer) !Fetched {
    const kinds = [1]u16{if (name == null) kind_root else kind_named};
    const authors = [1][32]u8{pk};
    var values: [1][]const u8 = undefined;
    var tf: [1]nostr.filter.TagFilter = undefined;
    var f: nostr.filter.Filter = .{ .kinds = &kinds, .authors = &authors, .limit = 1 };
    if (name) |n| {
        values[0] = n;
        tf[0] = .{ .letter = 'd', .values = &values };
        f.tags = &tf;
    }
    return fetchNewest(gpa, io, urls, f, timeout_ms, err);
}

fn publicKey(gpa: std.mem.Allocator, raw: []const u8, verb: []const u8, err: *Io.Writer) !?[32]u8 {
    return keyinput.publicKey(gpa, keyinput.stripUri(raw)) catch {
        try err.print("deed nsite {s}: {s}: not an npub or 64 hex characters\n", .{ verb, raw });
        return null;
    };
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn list(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, opts: Opts, out: *Io.Writer, err: *Io.Writer) !u8 {
    const pk = (try publicKey(gpa, opts.positionals.items[0], "list", err)) orelse return cli.exit_usage;
    var relays = (try resolveRelays(gpa, io, opts, pk, err)) orelse return cli.exit_fail;
    defer relays.deinit();

    if (opts.sites) return listSites(gpa, io, relays.urls, pk, opts.timeout_ms, out, err);

    var found = (try fetchSite(gpa, io, relays.urls, pk, opts.name, opts.timeout_ms, err)).parsed orelse {
        try err.writeAll("deed nsite list: no site found\n");
        return cli.exit_fail;
    };
    defer found.deinit();
    var bad: []const u8 = "";
    const m = parseManifest(arena, found.value, &bad) catch |e| {
        try reportManifest(err, "list", e, bad);
        return cli.exit_fail;
    };
    for (m.paths) |p| {
        const h = std.fmt.bytesToHex(p.sha, .lower);
        try out.print("{s}\t{s}\n", .{ p.path, &h });
    }
    return cli.exit_ok;
}

fn reportManifest(err: *Io.Writer, verb: []const u8, e: ManifestError, bad: []const u8) !void {
    switch (e) {
        error.UnsafePath => {
            try err.print("deed nsite {s}: the manifest names a path that is not a plain absolute path: ", .{verb});
            for (bad[0..@min(bad.len, 80)]) |c| {
                try err.writeByte(if (c < 0x20 or c == 0x7f) '?' else c);
            }
            try err.writeByte('\n');
        },
        error.TooManyFiles => try err.print("deed nsite {s}: the manifest names more than {d} files\n", .{ verb, max_files }),
        error.OutOfMemory => try err.print("deed nsite {s}: out of memory\n", .{verb}),
    }
}

fn listSites(gpa: std.mem.Allocator, io: Io, urls: []const []const u8, pk: [32]u8, timeout_ms: i64, out: *Io.Writer, err: *Io.Writer) !u8 {
    const kinds = [2]u16{ kind_root, kind_named };
    const authors = [1][32]u8{pk};
    var buf: Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    _ = try relayset.query(gpa, io, urls, &.{.{ .kinds = &kinds, .authors = &authors }}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
    });

    const Site = struct { parsed: event.Parsed, name: []const u8 };
    var sites: std.ArrayList(Site) = .empty;
    defer {
        for (sites.items) |*s| s.parsed.deinit();
        sites.deinit(gpa);
    }
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var p = event.fromJson(gpa, line) catch continue;
        var name: []const u8 = "";
        if (p.value.kind == kind_named) {
            for (p.value.tags) |t| {
                if (t.len >= 2 and std.mem.eql(u8, t[0], "d")) {
                    name = t[1];
                    break;
                }
            }
            if (!validName(name)) {
                p.deinit();
                continue;
            }
        }
        var replaced = false;
        for (sites.items) |*s| {
            if (s.parsed.value.kind != p.value.kind or !std.mem.eql(u8, s.name, name)) continue;
            replaced = true;
            if (newerThan(p.value, s.parsed.value)) {
                s.parsed.deinit();
                s.* = .{ .parsed = p, .name = name };
            } else p.deinit();
            break;
        }
        if (!replaced) try sites.append(gpa, .{ .parsed = p, .name = name });
    }

    std.mem.sort(Site, sites.items, {}, struct {
        fn lt(_: void, x: Site, y: Site) bool {
            if (x.parsed.value.kind != y.parsed.value.kind) return x.parsed.value.kind < y.parsed.value.kind;
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    for (sites.items) |s| {
        var files: usize = 0;
        for (s.parsed.value.tags) |t| {
            if (t.len >= 3 and std.mem.eql(u8, t[0], "path")) files += 1;
        }
        const is_root = s.parsed.value.kind == kind_root;
        try out.print("{s}\t{s}\t{d}\t{d}\n", .{
            if (is_root) "root" else "named",
            if (is_root) "-" else s.name,
            s.parsed.value.created_at,
            files,
        });
    }
    return cli.exit_ok;
}

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

const LocalFile = struct {
    /// The site path, `/css/site.css`.
    path: []const u8,
    /// Where it is on disk.
    disk: []const u8,
    sha: [32]u8,
    size: u64,
};

fn lessLocal(_: void, a: LocalFile, b: LocalFile) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

fn hashFile(io: Io, path: []const u8) !struct { sha: [32]u8, size: u64 } {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var rbuf: [64 * 1024]u8 = undefined;
    var fr = file.reader(io, &rbuf);
    var h = Sha256.init(.{});
    var size: u64 = 0;
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try fr.interface.readSliceShort(&chunk);
        if (n == 0) break;
        h.update(chunk[0..n]);
        size += n;
        if (size > max_file_bytes) return error.FileTooLarge;
    }
    return .{ .sha = h.finalResult(), .size = size };
}

/// Every regular file under `dir`, hashed. Null after saying why on `err` when
/// the directory cannot be read or holds something a site cannot carry.
fn scan(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, dir: []const u8, include_hidden: bool, err: *Io.Writer) !?[]LocalFile {
    var root = Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |e| {
        try err.print("deed nsite deploy: cannot read {s}: {s}\n", .{ dir, @errorName(e) });
        return null;
    };
    defer root.close(io);
    var walker = try root.walk(gpa);
    defer walker.deinit();

    var files: std.ArrayList(LocalFile) = .empty;
    var total: u64 = 0;
    while (walker.next(io) catch |e| {
        try err.print("deed nsite deploy: cannot read {s}: {s}\n", .{ dir, @errorName(e) });
        return null;
    }) |entry| {
        if (!include_hidden) {
            if (hiddenAt(entry.path)) |top| {
                // Said once, for the dot-file or dot-directory itself, and not
                // again for everything inside it.
                if (top) try err.print("deed nsite deploy: skipping the hidden {s} {s} (--include-hidden publishes it)\n", .{ if (entry.kind == .directory) "directory" else "file", entry.path });
                continue;
            }
        }
        switch (entry.kind) {
            .directory => continue,
            .sym_link => {
                try err.print("deed nsite deploy: skipping the symbolic link {s}\n", .{entry.path});
                continue;
            },
            .file => {},
            else => {
                try err.print("deed nsite deploy: skipping {s}: not a regular file\n", .{entry.path});
                continue;
            },
        }
        if (files.items.len >= max_files) {
            try err.print("deed nsite deploy: more than {d} files; a site may hold no more\n", .{max_files});
            return null;
        }
        var site_path: std.ArrayList(u8) = .empty;
        try site_path.append(arena, '/');
        for (entry.path) |c| try site_path.append(arena, if (c == std.fs.path.sep) '/' else c);
        if (!safePath(site_path.items)) {
            try err.print("deed nsite deploy: {s}: a site path cannot hold that name\n", .{entry.path});
            return null;
        }
        const disk = try std.fmt.allocPrint(arena, "{s}{c}{s}", .{ std.mem.trimEnd(u8, dir, "/\\"), std.fs.path.sep, entry.path });
        const h = hashFile(io, disk) catch |e| {
            if (e == error.FileTooLarge) {
                try err.print("deed nsite deploy: {s}: larger than {d} MiB\n", .{ entry.path, max_file_bytes / (1024 * 1024) });
            } else {
                try err.print("deed nsite deploy: cannot read {s}: {s}\n", .{ disk, @errorName(e) });
            }
            return null;
        };
        total += h.size;
        if (total > max_site_bytes) {
            try err.print("deed nsite deploy: the files add up to more than {d} MiB\n", .{max_site_bytes / (1024 * 1024)});
            return null;
        }
        try files.append(arena, .{ .path = site_path.items, .disk = disk, .sha = h.sha, .size = h.size });
    }
    std.mem.sort(LocalFile, files.items, {}, lessLocal);
    return files.items;
}

/// Null when no segment of `rel` starts with a dot; otherwise whether the last
/// segment is the one that does.
fn hiddenAt(rel: []const u8) ?bool {
    var it = std.mem.splitAny(u8, rel, "/\\");
    while (it.next()) |seg| {
        if (seg.len > 0 and seg[0] == '.') return it.peek() == null;
    }
    return null;
}

fn secretKey(gpa: std.mem.Allocator, flag: ?[]const u8, err: *Io.Writer) !?nostr.keys.SecretKey {
    const raw = flag orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.writeAll("deed nsite deploy: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n");
        return null;
    };
    return keyinput.secretKeyForVerb(gpa, "nsite deploy", raw, err) catch |e| switch (e) {
        error.BadKey => return null,
        else => return e,
    };
}

fn deploy(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, opts: Opts, servers: []const []const u8, out: *Io.Writer, err: *Io.Writer) !u8 {
    if (servers.len == 0) {
        try err.writeAll("deed nsite deploy: name a Blossom server with --server\n");
        return cli.exit_usage;
    }
    var sk = (try secretKey(gpa, opts.sec, err)) orelse return cli.exit_usage;
    defer std.crypto.secureZero(u8, &sk);

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(sk) catch {
        try err.writeAll("deed nsite deploy: not a usable secret key\n");
        return cli.exit_usage;
    };

    const files = (try scan(gpa, io, arena, opts.positionals.items[0], opts.include_hidden, err)) orelse return cli.exit_fail;
    if (files.len == 0) {
        try err.writeAll("deed nsite deploy: the directory holds no files\n");
        return cli.exit_fail;
    }

    var relays = (try resolveRelays(gpa, io, opts, kp.public_key, err)) orelse return cli.exit_fail;
    defer relays.deinit();

    // What is published now, so what has not changed is not sent again.
    // It is read even with --force, for the time it was made: a replaceable
    // event only replaces an older one.
    var fetched = try fetchSite(gpa, io, relays.urls, kp.public_key, opts.name, opts.timeout_ms, err);
    defer if (fetched.parsed) |*p| p.deinit();
    if (fetched.complete == 0) {
        if (!opts.force) {
            try err.writeAll("deed nsite deploy: no relay finished answering, so whether a site is already published is not known; try again, or pass --force to publish anyway\n");
            return cli.exit_fail;
        }
        try err.writeAll("deed nsite deploy: no relay finished answering; publishing anyway because of --force\n");
    }
    var existing: ?Manifest = null;
    var floor: ?i64 = null;
    if (fetched.parsed) |p| {
        floor = p.value.created_at;
        var bad: []const u8 = "";
        if (parseManifest(arena, p.value, &bad)) |m| {
            if (!opts.force) existing = m;
        } else |e| {
            try reportManifest(err, "deploy", e, bad);
            if (!opts.force) {
                try err.writeAll("deed nsite deploy: the published manifest cannot be read, so it is not replaced; pass --force to replace it\n");
                return cli.exit_fail;
            }
        }
    }

    // The key is handed to the uploader as hex: an ncryptsec has been opened
    // once, and is not asked about again for every file.
    const sec_hex = std.fmt.bytesToHex(sk, .lower);

    // A file is sent to every server named. One the published manifest already
    // names is only sent where a server does not hold it, which is asked with a
    // HEAD, because a server added since, or one that lost the blob, would
    // otherwise be listed in the manifest without having it.
    const held = try arena.alloc(bool, files.len * servers.len);
    @memset(held, false);
    var changed_files: usize = 0;
    var uploaded: usize = 0;
    for (files, 0..) |f, i| {
        var same = false;
        if (existing) |m| {
            for (m.paths) |p| {
                if (std.mem.eql(u8, p.path, f.path)) same = std.mem.eql(u8, &p.sha, &f.sha);
            }
        }
        if (!same) changed_files += 1;
        var sent = false;
        for (servers, 0..) |srv, j| {
            if (same and try blobPresent(gpa, io, srv, f.sha, !opts.allow_local)) {
                held[i * servers.len + j] = true;
                continue;
            }
            if (try uploadBlob(gpa, io, srv, f, &sec_hex, err)) {
                held[i * servers.len + j] = true;
                sent = true;
            }
        }
        if (sent) uploaded += 1;
        var anywhere = false;
        for (held[i * servers.len ..][0..servers.len]) |h| anywhere = anywhere or h;
        if (!anywhere) {
            try err.print("deed nsite deploy: {s} reached no server\n", .{f.path});
            try err.writeAll("deed nsite deploy: not every file could be uploaded, so no manifest was published\n");
            return cli.exit_fail;
        }
    }

    // Only a server that holds every file is listed: a manifest that names a
    // server without a file sends visitors to a 404.
    var listed: std.ArrayList([]const u8) = .empty;
    for (servers, 0..) |srv, j| {
        var all = true;
        for (0..files.len) |i| all = all and held[i * servers.len + j];
        if (all) {
            try listed.append(arena, srv);
        } else {
            try err.print("deed nsite deploy: {s} does not hold every file, so the manifest does not name it\n", .{srv});
        }
    }
    if (listed.items.len == 0) {
        try err.writeAll("deed nsite deploy: no server holds every file, so no manifest was published\n");
        return cli.exit_fail;
    }

    if (existing) |m| {
        if (changed_files == 0 and m.paths.len == files.len and
            sameText(m.title, opts.title) and sameText(m.description, opts.description) and
            sameText(m.source, opts.source) and try sameServers(arena, m.servers, listed.items))
        {
            try err.print("deed nsite deploy: nothing changed, so nothing was published ({d} files)\n", .{files.len});
            return cli.exit_ok;
        }
    }

    var pairs: std.ArrayList(PathHash) = .empty;
    for (files) |f| try pairs.append(arena, .{ .path = f.path, .sha = f.sha });
    const agg = try aggregate(arena, pairs.items);

    var tags: std.ArrayList(event.Tag) = .empty;
    if (opts.name) |n| try tags.append(arena, try tag2(arena, "d", n));
    for (files) |f| {
        const h = std.fmt.bytesToHex(f.sha, .lower);
        try tags.append(arena, try arena.dupe([]const u8, &.{ "path", f.path, try arena.dupe(u8, &h) }));
    }
    try tags.append(arena, try arena.dupe([]const u8, &.{ "x", try arena.dupe(u8, &agg), "aggregate" }));
    for (listed.items) |s| try tags.append(arena, try tag2(arena, "server", s));
    if (opts.title) |t| try tags.append(arena, try tag2(arena, "title", t));
    if (opts.description) |t| try tags.append(arena, try tag2(arena, "description", t));
    if (opts.source) |t| try tags.append(arena, try tag2(arena, "source", t));

    var now = Io.Timestamp.now(io, .real).toSeconds();
    if (floor) |t| {
        if (now <= t) now = t + 1;
    }
    const ev = try event.create(arena, signer, kp, now, if (opts.name == null) kind_root else kind_named, tags.items, "", null);

    const accepted = try publish.publishOne(gpa, io, "nsite", relays.urls, ev, opts.timeout_ms, err);
    if (!accepted) return cli.exit_fail;
    const json = try event.toJson(gpa, ev);
    defer gpa.free(json);
    try out.print("{s}\n", .{json});
    try err.print("deed nsite deploy: published {d} files ({d} uploaded, {d} unchanged)\n", .{ files.len, uploaded, files.len - uploaded });
    return cli.exit_ok;
}

fn sameText(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

/// Whether `published` (as a manifest wrote them) and `now` name the same
/// servers, in any order.
fn sameServers(arena: std.mem.Allocator, published: []const []const u8, now: []const []const u8) !bool {
    var theirs: std.ArrayList([]const u8) = .empty;
    for (published) |raw| {
        const n = (try normalizeServer(arena, raw)) orelse continue;
        var dup = false;
        for (theirs.items) |t| dup = dup or std.ascii.eqlIgnoreCase(t, n);
        if (!dup) try theirs.append(arena, n);
    }
    if (theirs.items.len != now.len) return false;
    for (now) |n| {
        var found = false;
        for (theirs.items) |t| found = found or std.ascii.eqlIgnoreCase(t, n);
        if (!found) return false;
    }
    return true;
}

/// Whether `srv` holds the blob: a HEAD for it (BUD-06 names the route). Any
/// other answer, or none, counts as not holding it.
fn blobPresent(gpa: std.mem.Allocator, io: Io, srv: []const u8, sha: [32]u8, deny_private: bool) !bool {
    const sha_hex = std.fmt.bytesToHex(sha, .lower);
    const url = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ srv, &sha_hex });
    defer gpa.free(url);
    var r = http.fetch(gpa, io, url, .{
        .method = .HEAD,
        .deny_private = deny_private,
        .timeout_ms = blob_timeout_ms,
        .max_bytes = std.math.maxInt(usize),
    }) catch return false;
    defer r.deinit(gpa);
    return r.ok();
}

/// Sends one file to one server, true once the server has confirmed the blob
/// under its hash.
fn uploadBlob(gpa: std.mem.Allocator, io: Io, srv: []const u8, f: LocalFile, sec_hex: []const u8, err: *Io.Writer) !bool {
    const sha_hex = std.fmt.bytesToHex(f.sha, .lower);
    const argv = [_][]const u8{ "upload", f.disk, "-s", srv, "--sec", sec_hex };
    var sink: Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    _ = try blossom.run(gpa, io, &argv, &sink.writer, err);
    return std.mem.indexOf(u8, sink.written(), &sha_hex) != null;
}

fn tag2(a: std.mem.Allocator, name: []const u8, value: []const u8) !event.Tag {
    return a.dupe([]const u8, &.{ name, value });
}

// ---------------------------------------------------------------------------
// download
// ---------------------------------------------------------------------------

/// True when `dir` is missing or an empty directory.
fn destinationFree(io: Io, dir: []const u8) !bool {
    var d = Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return true,
        else => return false,
    };
    defer d.close(io);
    var it = d.iterate();
    return (try it.next(io)) == null;
}

fn download(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, opts: Opts, extra: []const []const u8, out: *Io.Writer, err: *Io.Writer) !u8 {
    const pk = (try publicKey(gpa, opts.positionals.items[0], "download", err)) orelse return cli.exit_usage;
    const dir = std.mem.trimEnd(u8, opts.positionals.items[1], "/\\");
    if (dir.len == 0) {
        try err.writeAll("deed nsite download: the directory is empty\n");
        return cli.exit_usage;
    }
    if (!try destinationFree(io, dir)) {
        try err.print("deed nsite download: {s} exists and is not an empty directory\n", .{dir});
        return cli.exit_fail;
    }

    var relays = (try resolveRelays(gpa, io, opts, pk, err)) orelse return cli.exit_fail;
    defer relays.deinit();
    var found = (try fetchSite(gpa, io, relays.urls, pk, opts.name, opts.timeout_ms, err)).parsed orelse {
        try err.writeAll("deed nsite download: no site found\n");
        return cli.exit_fail;
    };
    defer found.deinit();
    var bad: []const u8 = "";
    const m = parseManifest(arena, found.value, &bad) catch |e| {
        try reportManifest(err, "download", e, bad);
        return cli.exit_fail;
    };
    if (m.paths.len == 0) {
        try err.writeAll("deed nsite download: the manifest names no files\n");
        return cli.exit_fail;
    }
    if (try diskConflict(arena, m.paths, builtin.os.tag == .windows)) |why| {
        try err.print("deed nsite download: {s}; nothing was written\n", .{why});
        return cli.exit_fail;
    }

    var servers: std.ArrayList([]const u8) = .empty;
    for (m.servers) |raw| {
        if (try normalizeServer(arena, raw)) |s| try servers.append(arena, s);
    }
    for (extra) |s| try servers.append(arena, s);
    if (servers.items.len == 0) {
        try err.writeAll("deed nsite download: the manifest names no server: add one with --server\n");
        return cli.exit_fail;
    }

    var code: u8 = cli.exit_ok;
    var total: u64 = 0;
    for (m.paths) |p| {
        const rel = p.path[1..];
        const dest = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, rel });
        const got = fetchBlob(gpa, io, arena, servers.items, p.sha, dest, max_site_bytes - total, !opts.allow_local, err) catch |e| {
            try err.print("deed nsite download: {s}: {s}\n", .{ p.path, @errorName(e) });
            code = cli.exit_fail;
            continue;
        };
        if (got) |size| {
            total += size;
            try out.print("{s}\n", .{p.path});
        } else {
            try err.print("deed nsite download: {s}: no server had it\n", .{p.path});
            code = cli.exit_fail;
        }
    }
    return code;
}

/// Device names Windows reserves, with or without an extension.
fn windowsReserved(seg: []const u8) bool {
    const stem = seg[0 .. std.mem.indexOfScalar(u8, seg, '.') orelse seg.len];
    const names = [_][]const u8{ "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" };
    for (names) |n| if (std.ascii.eqlIgnoreCase(stem, n)) return true;
    if (stem.len == 4 and stem[3] >= '1' and stem[3] <= '9') {
        if (std.ascii.eqlIgnoreCase(stem[0..3], "COM") or std.ascii.eqlIgnoreCase(stem[0..3], "LPT")) return true;
    }
    return false;
}

/// Why `paths` cannot be written to a disk as they are named, or null. Two
/// paths that differ only in case would overwrite each other on a disk that
/// folds case, and a file that is also a directory cannot be both. With
/// `windows`, a segment Windows cannot create is a reason too.
fn diskConflict(a: std.mem.Allocator, paths: []const PathHash, windows: bool) !?[]const u8 {
    var seen: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer seen.deinit(a);
    var dirs: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer dirs.deinit(a);
    for (paths) |p| {
        if (windows) {
            var it = std.mem.splitScalar(u8, p.path[1..], '/');
            while (it.next()) |seg| {
                const last = seg[seg.len - 1];
                if (last == '.' or last == ' ') return try std.fmt.allocPrint(a, "{s} has a name ending in a dot or a space, which Windows cannot create", .{p.path});
                if (windowsReserved(seg)) return try std.fmt.allocPrint(a, "{s} is named like a Windows device, which Windows cannot create", .{p.path});
            }
        }
        const folded = try std.ascii.allocLowerString(a, p.path);
        const gop = try seen.getOrPut(a, folded);
        if (gop.found_existing) {
            return try std.fmt.allocPrint(a, "{s} and {s} differ only in case and would overwrite each other on a disk that ignores case", .{ gop.value_ptr.*, p.path });
        }
        gop.value_ptr.* = p.path;
        var i: usize = 1;
        while (std.mem.indexOfScalarPos(u8, folded, i, '/')) |at| : (i = at + 1) {
            const d = try dirs.getOrPut(a, folded[0..at]);
            if (!d.found_existing) d.value_ptr.* = p.path;
        }
    }
    for (paths) |p| {
        const folded = try std.ascii.allocLowerString(a, p.path);
        if (dirs.get(folded)) |inside| {
            return try std.fmt.allocPrint(a, "{s} is both a file and a directory ({s} is inside it)", .{ p.path, inside });
        }
    }
    return null;
}

/// Gets the blob named `sha` from the first server that has it, and writes it
/// to `dest` only once what arrived hashes to `sha`. Returns its size, or null
/// when no server had it.
fn fetchBlob(
    gpa: std.mem.Allocator,
    io: Io,
    arena: std.mem.Allocator,
    servers: []const []const u8,
    sha: [32]u8,
    dest: []const u8,
    room: u64,
    deny_private: bool,
    err: *Io.Writer,
) !?u64 {
    const sha_hex = std.fmt.bytesToHex(sha, .lower);
    const cwd = Io.Dir.cwd();
    if (std.fs.path.dirname(dest)) |parent| try cwd.createDirPath(io, parent);
    const tmp = try std.fmt.allocPrint(arena, "{s}.{s}.part", .{ dest, sha_hex[0..8] });

    for (servers) |srv| {
        const url = try std.fmt.allocPrint(arena, "{s}/{s}", .{ srv, &sha_hex });
        const file = try cwd.createFile(io, tmp, .{});
        var closed = false;
        var finished = false;
        defer {
            if (!closed) file.close(io);
            if (!finished) cwd.deleteFile(io, tmp) catch {};
        }

        var wbuf: [64 * 1024]u8 = undefined;
        var fw = file.writer(io, &wbuf);
        var hbuf: [16 * 1024]u8 = undefined;
        var hashed = Io.Writer.Hashed(Sha256).initHasher(&fw.interface, Sha256.init(.{}), &hbuf);

        const cap: usize = @intCast(@min(max_file_bytes, room));
        const status = http.fetchTo(gpa, io, url, .{
            .deny_private = deny_private,
            .timeout_ms = blob_timeout_ms,
            .max_bytes = cap,
        }, &hashed.writer) catch |e| {
            if (e == error.PrivateAddress) {
                try err.print("deed nsite download: {s}: resolves to a private address (use --allow-local)\n", .{url});
            } else {
                try err.print("deed nsite download: {s}: {s}\n", .{ srv, http.describe(e) });
            }
            continue;
        };
        if (status < 200 or status >= 300) {
            try err.print("deed nsite download: {s}: {s}: HTTP {d}\n", .{ srv, sha_hex[0..12], status });
            continue;
        }
        hashed.writer.flush() catch continue;
        fw.interface.flush() catch continue;
        const size = fw.logicalPos();
        file.close(io);
        closed = true;

        const got = hashed.hasher.finalResult();
        if (!std.mem.eql(u8, &got, &sha)) {
            const theirs = std.fmt.bytesToHex(got, .lower);
            try err.print("deed nsite download: {s}: what arrived hashes to {s}, not {s}; nothing was kept\n", .{ srv, theirs[0..12], sha_hex[0..12] });
            continue;
        }
        try cwd.rename(tmp, cwd, dest, io);
        finished = true;
        return size;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

test "paths: plain absolute paths only" {
    try testing.expect(safePath("/index.html"));
    try testing.expect(safePath("/a/b/c.css"));
    try testing.expect(!safePath("index.html"));
    try testing.expect(!safePath("/"));
    try testing.expect(!safePath("/a/"));
    try testing.expect(!safePath("/../etc/passwd"));
    try testing.expect(!safePath("/a/./b"));
    try testing.expect(!safePath("/a//b"));
    try testing.expect(!safePath("/a\\b"));
    try testing.expect(!safePath("/C:/x"));
    try testing.expect(!safePath("/a\x00b"));
    try testing.expect(!safePath("/a\x1b[2Jb"));
}

test "site names follow the spec" {
    try testing.expect(validName("blog"));
    try testing.expect(validName("a-b-1"));
    try testing.expect(!validName(""));
    try testing.expect(!validName("Blog"));
    try testing.expect(!validName("trailing-"));
    try testing.expect(!validName("fourteen-chars"));
}

test "the aggregate hash is the one the spec gives" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const paths = [_]PathHash{
        .{ .path = "/index.html", .sha = try hex.decodeFixed(32, "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99") },
        .{ .path = "/favicon.ico", .sha = try hex.decodeFixed(32, "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321") },
    };
    const got = try aggregate(a, &paths);
    var h = Sha256.init(.{});
    h.update("186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99 /index.html\n");
    h.update("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 /favicon.ico\n");
    // Sorted ascending: the line starting "186e" comes before "fedc".
    const want = std.fmt.bytesToHex(h.finalResult(), .lower);
    try testing.expectEqualStrings(&want, &got);
}

/// A Blossom server on loopback that keeps what it is sent.
const BlobServer = struct {
    server: Io.net.Server,
    task: Io.Future(void),
    connections: usize,
    blobs: std.StringHashMapUnmanaged([]u8) = .empty,
    heads: usize = 0,
    /// HEADs for a blob by its hash.
    blob_heads: usize = 0,
    puts: usize = 0,
    gets: usize = 0,
    auth_seen: usize = 0,
    /// A GET serves the blob with its first byte changed.
    corrupt: bool = false,

    fn start(self: *BlobServer, io: Io, connections: usize) !void {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        self.* = .{
            .server = try address.listen(io, .{ .reuse_address = true }),
            .task = undefined,
            .connections = connections,
        };
        errdefer self.server.deinit(io);
        self.task = try io.concurrent(serve, .{ self, io });
    }

    fn stop(self: *BlobServer, io: Io) void {
        self.task.cancel(io);
        self.server.deinit(io);
        var it = self.blobs.iterator();
        while (it.next()) |kv| {
            std.heap.page_allocator.free(kv.key_ptr.*);
            std.heap.page_allocator.free(kv.value_ptr.*);
        }
        self.blobs.deinit(std.heap.page_allocator);
    }

    fn base(self: *const BlobServer, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}", .{self.server.socket.address.ip4.port}) catch unreachable;
    }

    fn serve(self: *BlobServer, io: Io) void {
        for (0..self.connections) |_| {
            const conn = self.server.accept(io) catch return;
            defer conn.close(io);
            self.handle(io, conn) catch {};
        }
    }

    fn handle(self: *BlobServer, io: Io, conn: Io.net.Stream) !void {
        const pa = std.heap.page_allocator;
        var rbuf: [8192]u8 = undefined;
        var wbuf: [8192]u8 = undefined;
        var r = conn.reader(io, &rbuf);
        var w = conn.writer(io, &wbuf);
        var s = std.http.Server.init(&r.interface, &w.interface);
        var req = try s.receiveHead();

        const method = req.head.method;
        var target_buf: [600]u8 = undefined;
        const target = req.head.target[0..@min(req.head.target.len, target_buf.len)];
        @memcpy(target_buf[0..target.len], target);
        const path = target_buf[0..target.len];
        var xsha_buf: [64]u8 = undefined;
        var have_xsha = false;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "authorization")) self.auth_seen += 1;
            if (std.ascii.eqlIgnoreCase(h.name, "x-sha-256") and h.value.len == 64) {
                @memcpy(&xsha_buf, h.value);
                have_xsha = true;
            }
        }

        if (std.mem.eql(u8, path, "/upload")) {
            if (method == .HEAD) {
                self.heads += 1;
                return req.respond("", .{ .keep_alive = false });
            }
            if (method == .PUT and have_xsha) {
                self.puts += 1;
                var body_bytes: std.ArrayList(u8) = .empty;
                defer body_bytes.deinit(pa);
                var chunk: [8192]u8 = undefined;
                const body = req.readerExpectNone(&chunk);
                var tmp: [8192]u8 = undefined;
                while (true) {
                    const n = body.readSliceShort(&tmp) catch break;
                    if (n == 0) break;
                    try body_bytes.appendSlice(pa, tmp[0..n]);
                }
                var digest: [32]u8 = undefined;
                Sha256.hash(body_bytes.items, &digest, .{});
                const got = std.fmt.bytesToHex(digest, .lower);
                if (!std.mem.eql(u8, &got, &xsha_buf)) return req.respond("", .{ .status = .bad_request, .keep_alive = false });
                const key = try pa.dupe(u8, &got);
                const value = try body_bytes.toOwnedSlice(pa);
                try self.blobs.put(pa, key, value);
                var reply: [512]u8 = undefined;
                const text = try std.fmt.bufPrint(&reply, "{{\"url\":\"http://127.0.0.1:{d}/{s}\",\"sha256\":\"{s}\",\"size\":{d},\"type\":\"application/octet-stream\",\"uploaded\":1}}", .{ self.server.socket.address.ip4.port, got, got, value.len });
                return req.respond(text, .{ .keep_alive = false });
            }
        }
        if (path.len == 65 and path[0] == '/' and method == .HEAD) {
            self.blob_heads += 1;
            const status: std.http.Status = if (self.blobs.contains(path[1..])) .ok else .not_found;
            return req.respond("", .{ .status = status, .keep_alive = false });
        }
        if (path.len == 65 and path[0] == '/' and method == .GET) {
            self.gets += 1;
            if (self.blobs.get(path[1..])) |bytes| {
                if (self.corrupt) {
                    const copy = try pa.dupe(u8, bytes);
                    defer pa.free(copy);
                    copy[0] ^= 0xff;
                    return req.respond(copy, .{ .keep_alive = false });
                }
                return req.respond(bytes, .{ .keep_alive = false });
            }
        }
        return req.respond("not found", .{ .status = .not_found, .keep_alive = false });
    }
};

/// A relay that keeps the last event it is offered and serves it to every REQ.
const SiteRelay = struct {
    stored: [32 * 1024]u8 = undefined,
    stored_len: usize = 0,
    events: std.atomic.Value(usize) = .init(0),
    /// Reads a REQ and never answers it.
    mute: bool = false,
    reqs: std.atomic.Value(usize) = .init(0),
    relay: testrelay.Relay = undefined,

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        const self: *SiteRelay = @ptrCast(@alignCast(ctx.?));
        if (std.mem.startsWith(u8, frame, "[\"REQ\"")) {
            _ = self.reqs.fetchAdd(1, .monotonic);
            if (self.mute) return;
            if (self.stored_len > 0) {
                const line = try std.fmt.allocPrint(std.heap.page_allocator, "[\"EVENT\",\"deed\",{s}]", .{self.stored[0..self.stored_len]});
                defer std.heap.page_allocator.free(line);
                try testrelay.sendText(w, line);
            }
            try testrelay.sendText(w, "[\"EOSE\",\"deed\"]");
        } else if (std.mem.startsWith(u8, frame, "[\"EVENT\"")) {
            const prefix = "[\"EVENT\",".len;
            const body = frame[prefix .. frame.len - 1];
            if (body.len > self.stored.len) return;
            @memcpy(self.stored[0..body.len], body);
            self.stored_len = body.len;
            _ = self.events.fetchAdd(1, .monotonic);
            const at = std.mem.indexOf(u8, frame, "\"id\":\"") orelse return error.BadFrame;
            var line: [160]u8 = undefined;
            try testrelay.sendText(w, try std.fmt.bufPrint(&line, "[\"OK\",\"{s}\",true,\"\"]", .{frame[at + 6 ..][0..64]}));
        }
    }

    fn start(self: *SiteRelay, io: Io, connections: usize) !void {
        self.stored_len = 0;
        try self.relay.startFor(io, .custom, connections);
        self.relay.custom = handle;
        self.relay.custom_ctx = self;
    }

    fn stop(self: *SiteRelay, io: Io) void {
        self.relay.stop(io);
    }

    fn url(self: *const SiteRelay, buf: []u8) ![]const u8 {
        return testrelay.url(buf, self.relay.port());
    }
};

const test_sec = "33" ** 32;

const Ran = struct {
    code: u8,
    out: Io.Writer.Allocating,
    err: Io.Writer.Allocating,

    fn deinit(self: *Ran) void {
        self.out.deinit();
        self.err.deinit();
    }
};

fn runStrict(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !Ran {
    var r: Ran = .{ .code = 0, .out = .init(testing.allocator), .err = .init(testing.allocator) };
    errdefer r.deinit();
    r.code = try run(gpa, io, args, &r.out.writer, &r.err.writer);
    return r;
}

/// As `runArgs`, with `--allow-local` added: the test servers are on loopback.
fn runArgs(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !Ran {
    if (args.len == 0) return runStrict(gpa, io, args);
    var buf: [32][]const u8 = undefined;
    @memcpy(buf[0..args.len], args);
    buf[args.len] = "--allow-local";
    return runStrict(gpa, io, buf[0 .. args.len + 1]);
}

const Tmp = struct {
    tmp: testing.TmpDir,
    root: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn init(self: *Tmp, io: Io) !void {
        self.* = .{ .tmp = testing.tmpDir(.{}) };
        self.len = try self.tmp.dir.realPath(io, &self.root);
    }

    fn deinit(self: *Tmp) void {
        self.tmp.cleanup();
    }

    fn path(self: *const Tmp, a: std.mem.Allocator, name: []const u8) ![]const u8 {
        return std.fmt.allocPrint(a, "{s}/{s}", .{ self.root[0..self.len], name });
    }
};

fn expectFile(io: Io, dir: Io.Dir, name: []const u8, want: []const u8) !void {
    const bytes = try dir.readFileAlloc(io, name, testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(want, bytes);
}

fn ownNpub(a: std.mem.Allocator, io: Io) ![]const u8 {
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    return nostr.nip19.encodeNpub(a, kp.public_key);
}

test "a site deployed and then downloaded comes back byte for byte" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site/css");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello</h1>" });
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/css/site.css", .data = "body{margin:0}" });
    const src = try tmp.path(a, "site");

    // fetch + publish for each of three deploys, and one fetch for the download.
    var relay: SiteRelay = .{};
    try relay.start(io, 6);
    defer relay.stop(io);
    // Uploads: HEAD and PUT per file, for two files and then for one, and then
    // one GET per file for the download.
    var blobs: BlobServer = undefined;
    try blobs.start(io, 14);
    defer blobs.stop(io);
    var rbuf: [64]u8 = undefined;
    var bbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const server_url = blobs.base(&bbuf);

    var first = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--title", "demo", relay_url });
    defer first.deinit();
    try testing.expectEqual(cli.exit_ok, first.code);
    try testing.expectEqual(@as(usize, 2), blobs.puts);
    try testing.expectEqual(@as(usize, 1), relay.events.load(.monotonic));
    // The printed event is the published manifest.
    var parsed = try event.fromJson(testing.allocator, std.mem.trim(u8, first.out.written(), "\n"));
    defer parsed.deinit();
    try testing.expectEqual(kind_root, parsed.value.kind);
    var paths: usize = 0;
    var has_x = false;
    var has_server = false;
    for (parsed.value.tags) |t| {
        if (std.mem.eql(u8, t[0], "path")) paths += 1;
        if (std.mem.eql(u8, t[0], "x") and std.mem.eql(u8, t[2], "aggregate")) has_x = true;
        if (std.mem.eql(u8, t[0], "server") and std.mem.eql(u8, t[1], server_url)) has_server = true;
    }
    try testing.expectEqual(@as(usize, 2), paths);
    try testing.expect(has_x and has_server);

    // The same site again: nothing is uploaded and nothing is published.
    var again = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--title", "demo", relay_url });
    defer again.deinit();
    try testing.expectEqual(cli.exit_ok, again.code);
    try testing.expectEqualStrings("", again.out.written());
    try testing.expect(std.mem.indexOf(u8, again.err.written(), "nothing changed") != null);
    try testing.expectEqual(@as(usize, 2), blobs.puts);
    try testing.expectEqual(@as(usize, 1), relay.events.load(.monotonic));

    // One file edited: only that one is uploaded, and a new manifest goes out.
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello again</h1>" });
    var third = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--title", "demo", relay_url });
    defer third.deinit();
    try testing.expectEqual(cli.exit_ok, third.code);
    try testing.expectEqual(@as(usize, 3), blobs.puts);
    try testing.expectEqual(@as(usize, 2), relay.events.load(.monotonic));

    const npub = try ownNpub(a, io);
    const dest = try tmp.path(a, "got");
    var got = try runArgs(gpa, io, &.{ "download", npub, dest, relay_url });
    defer got.deinit();
    try testing.expectEqual(cli.exit_ok, got.code);
    try testing.expectEqualStrings("/css/site.css\n/index.html\n", got.out.written());
    try expectFile(io, tmp.tmp.dir, "got/index.html", "<h1>hello again</h1>");
    try expectFile(io, tmp.tmp.dir, "got/css/site.css", "body{margin:0}");
}

test "download refuses bytes that do not hash to the name, and writes nothing" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello</h1>" });
    const src = try tmp.path(a, "site");

    var relay: SiteRelay = .{};
    try relay.start(io, 3);
    defer relay.stop(io);
    var blobs: BlobServer = undefined;
    try blobs.start(io, 3);
    defer blobs.stop(io);
    var rbuf: [64]u8 = undefined;
    var bbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const server_url = blobs.base(&bbuf);

    var up = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--name", "demo", relay_url });
    defer up.deinit();
    try testing.expectEqual(cli.exit_ok, up.code);

    blobs.corrupt = true;
    const npub = try ownNpub(a, io);
    const dest = try tmp.path(a, "got");
    var bad = try runArgs(gpa, io, &.{ "download", npub, dest, "--name", "demo", relay_url });
    defer bad.deinit();
    try testing.expectEqual(cli.exit_fail, bad.code);
    try testing.expectEqualStrings("", bad.out.written());
    try testing.expect(std.mem.indexOf(u8, bad.err.written(), "nothing was kept") != null);
    // Neither the file nor a temporary one is left behind.
    var d = try tmp.tmp.dir.openDir(io, "got", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    try testing.expect((try it.next(io)) == null);
}

test "a failed upload publishes nothing" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "x" });
    const src = try tmp.path(a, "site");

    var relay: SiteRelay = .{};
    try relay.start(io, 1);
    defer relay.stop(io);
    var rbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);

    // Nothing listens on port 1.
    var r = try runArgs(gpa, io, &.{ "deploy", src, "-s", "http://127.0.0.1:1", "--sec", test_sec, relay_url });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqualStrings("", r.out.written());
    try testing.expectEqual(@as(usize, 0), relay.events.load(.monotonic));
}

test "list shows a site's files and the person's sites" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    const sha = "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99";
    const tags = [_]event.Tag{
        &.{ "path", "/b.html", sha },
        &.{ "path", "/a.html", sha },
        &.{ "path", "/short", "zz" },
    };
    const ev = try event.create(a, signer, kp, 1_700_000_000, kind_root, &tags, "", null);

    var relay: SiteRelay = .{};
    try relay.start(io, 2);
    defer relay.stop(io);
    const json = try event.toJson(a, ev);
    @memcpy(relay.stored[0..json.len], json);
    relay.stored_len = json.len;
    var rbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const npub = try nostr.nip19.encodeNpub(a, kp.public_key);

    var files = try runArgs(gpa, io, &.{ "list", npub, relay_url });
    defer files.deinit();
    try testing.expectEqual(cli.exit_ok, files.code);
    try testing.expectEqualStrings("/a.html\t" ++ sha ++ "\n/b.html\t" ++ sha ++ "\n", files.out.written());

    var sites = try runArgs(gpa, io, &.{ "list", npub, "--sites", relay_url });
    defer sites.deinit();
    try testing.expectEqualStrings("root\t-\t1700000000\t3\n", sites.out.written());
}

test "a manifest that names a path outside the directory is refused" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    const sha = "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99";
    const tags = [_]event.Tag{
        &.{ "path", "/index.html", sha },
        &.{ "path", "/../escape.txt", sha },
        &.{ "server", "http://127.0.0.1:1" },
    };
    const ev = try event.create(a, signer, kp, 1_700_000_000, kind_root, &tags, "", null);
    var relay: SiteRelay = .{};
    try relay.start(io, 1);
    defer relay.stop(io);
    const json = try event.toJson(a, ev);
    @memcpy(relay.stored[0..json.len], json);
    relay.stored_len = json.len;
    var rbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const npub = try nostr.nip19.encodeNpub(a, kp.public_key);

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    const dest = try tmp.path(a, "got");
    var r = try runArgs(gpa, io, &.{ "download", npub, dest, relay_url });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqualStrings("", r.out.written());
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "not a plain absolute path") != null);
    try testing.expectError(error.FileNotFound, tmp.tmp.dir.access(io, "got", .{}));
}

test "the command line is checked before anything is sent" {
    const io = testing.io;
    const gpa = testing.allocator;
    var a = try runArgs(gpa, io, &.{});
    defer a.deinit();
    try testing.expectEqual(cli.exit_usage, a.code);
    var b = try runArgs(gpa, io, &.{"levitate"});
    defer b.deinit();
    try testing.expectEqual(cli.exit_usage, b.code);
    var c = try runArgs(gpa, io, &.{ "deploy", "somewhere", "--sec", test_sec });
    defer c.deinit();
    try testing.expectEqual(cli.exit_usage, c.code);
    try testing.expect(std.mem.indexOf(u8, c.err.written(), "--server") != null);
    var d = try runArgs(gpa, io, &.{ "deploy", "somewhere", "--name", "Bad Name" });
    defer d.deinit();
    try testing.expectEqual(cli.exit_usage, d.code);
    var e = try runArgs(gpa, io, &.{ "download", "npub1x" });
    defer e.deinit();
    try testing.expectEqual(cli.exit_usage, e.code);
    var f = try runArgs(gpa, io, &.{ "list", "not-a-key" });
    defer f.deinit();
    try testing.expectEqual(cli.exit_usage, f.code);
}

test "deploy leaves dot-files and dot-directories out unless asked" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site/.git");
    try tmp.tmp.dir.createDirPath(io, "site/css");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello</h1>" });
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/.env", .data = "SECRET=1" });
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/.DS_Store", .data = "junk" });
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/.git/config", .data = "[core]" });
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/css/.hidden.css", .data = "x" });
    const src = try tmp.path(a, "site");

    var relay: SiteRelay = .{};
    try relay.start(io, 4);
    defer relay.stop(io);
    var blobs: BlobServer = undefined;
    try blobs.start(io, 16);
    defer blobs.stop(io);
    var rbuf: [64]u8 = undefined;
    var bbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const server_url = blobs.base(&bbuf);

    var plain = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, relay_url });
    defer plain.deinit();
    try testing.expectEqual(cli.exit_ok, plain.code);
    try testing.expectEqual(@as(usize, 1), blobs.puts);
    try testing.expect(std.mem.indexOf(u8, plain.err.written(), "skipping the hidden directory .git") != null);
    try testing.expect(std.mem.indexOf(u8, plain.err.written(), "skipping the hidden file .env") != null);
    try testing.expect(std.mem.indexOf(u8, plain.err.written(), "css/.hidden.css") != null);
    try testing.expect(std.mem.indexOf(u8, plain.out.written(), ".env") == null);

    var all = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--include-hidden", relay_url });
    defer all.deinit();
    try testing.expectEqual(cli.exit_ok, all.code);
    try testing.expectEqual(@as(usize, 5), blobs.puts);
    try testing.expect(std.mem.indexOf(u8, all.out.written(), "/.git/config") != null);
}

test "deploy will not replace a manifest it cannot read, or publish blind" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello</h1>" });
    const src = try tmp.path(a, "site");

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    const sha = "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99";
    const tags = [_]event.Tag{
        &.{ "path", "/index.html", sha },
        &.{ "path", "/../escape.txt", sha },
    };
    const old = try event.create(a, signer, kp, 1_700_000_000, kind_root, &tags, "", null);

    var relay: SiteRelay = .{};
    try relay.start(io, 3);
    defer relay.stop(io);
    const json = try event.toJson(a, old);
    @memcpy(relay.stored[0..json.len], json);
    relay.stored_len = json.len;
    var blobs: BlobServer = undefined;
    try blobs.start(io, 4);
    defer blobs.stop(io);
    var rbuf: [64]u8 = undefined;
    var bbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const server_url = blobs.base(&bbuf);

    var refused = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, relay_url });
    defer refused.deinit();
    try testing.expectEqual(cli.exit_fail, refused.code);
    try testing.expect(std.mem.indexOf(u8, refused.err.written(), "cannot be read") != null);
    try testing.expectEqual(@as(usize, 0), relay.events.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), blobs.puts);

    var forced = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--force", relay_url });
    defer forced.deinit();
    try testing.expectEqual(cli.exit_ok, forced.code);
    try testing.expectEqual(@as(usize, 1), relay.events.load(.monotonic));

    // A relay that never finishes answering: whether a site exists is not known.
    var mute: SiteRelay = .{ .mute = true };
    try mute.start(io, 2);
    defer mute.stop(io);
    var mbuf: [64]u8 = undefined;
    const mute_url = try mute.url(&mbuf);
    var blind = try runArgs(gpa, io, &.{ "deploy", src, "-s", server_url, "--sec", test_sec, "--timeout", "400", mute_url });
    defer blind.deinit();
    try testing.expectEqual(cli.exit_fail, blind.code);
    try testing.expect(std.mem.indexOf(u8, blind.err.written(), "finished answering") != null);
    try testing.expectEqual(@as(usize, 0), mute.events.load(.monotonic));
}

test "paths that cannot all be written to a disk are caught up front" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const z = [_]u8{0} ** 32;
    const fine = [_]PathHash{ .{ .path = "/a/b.css", .sha = z }, .{ .path = "/a.html", .sha = z } };
    try testing.expect((try diskConflict(a, &fine, true)) == null);
    const cased = [_]PathHash{ .{ .path = "/Index.html", .sha = z }, .{ .path = "/index.html", .sha = z } };
    try testing.expect((try diskConflict(a, &cased, false)) != null);
    const both = [_]PathHash{ .{ .path = "/a", .sha = z }, .{ .path = "/a/b", .sha = z } };
    try testing.expect((try diskConflict(a, &both, false)) != null);
    const dot = [_]PathHash{.{ .path = "/news./x.html", .sha = z }};
    try testing.expect((try diskConflict(a, &dot, false)) == null);
    try testing.expect((try diskConflict(a, &dot, true)) != null);
    const space = [_]PathHash{.{ .path = "/x.html ", .sha = z }};
    try testing.expect((try diskConflict(a, &space, true)) != null);
    for ([_][]const u8{ "/con", "/NUL.txt", "/a/com1.js", "/Lpt9", "/aux.tar.gz" }) |name| {
        const one = [_]PathHash{.{ .path = name, .sha = z }};
        try testing.expect((try diskConflict(a, &one, true)) != null);
        try testing.expect((try diskConflict(a, &one, false)) == null);
    }
    const ok = [_]PathHash{ .{ .path = "/console.js", .sha = z }, .{ .path = "/com10", .sha = z } };
    try testing.expect((try diskConflict(a, &ok, true)) == null);
}

test "download refuses a manifest whose paths collide, and writes nothing" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    const sha = "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99";
    const other = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    const tags = [_]event.Tag{
        &.{ "path", "/Index.html", sha },
        &.{ "path", "/index.html", other },
        &.{ "server", "http://127.0.0.1:1" },
    };
    const ev = try event.create(a, signer, kp, 1_700_000_000, kind_root, &tags, "", null);
    var relay: SiteRelay = .{};
    try relay.start(io, 1);
    defer relay.stop(io);
    const json = try event.toJson(a, ev);
    @memcpy(relay.stored[0..json.len], json);
    relay.stored_len = json.len;
    var rbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const npub = try nostr.nip19.encodeNpub(a, kp.public_key);

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    const dest = try tmp.path(a, "got");
    var r = try runArgs(gpa, io, &.{ "download", npub, dest, relay_url });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "differ only in case") != null);
    try testing.expectError(error.FileNotFound, tmp.tmp.dir.access(io, "got", .{}));
}

test "download refuses a server on a private address unless --allow-local" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    const sha = "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99";
    const tags = [_]event.Tag{
        &.{ "path", "/index.html", sha },
        &.{ "server", "http://127.0.0.1:1" },
    };
    const ev = try event.create(a, signer, kp, 1_700_000_000, kind_root, &tags, "", null);
    var relay: SiteRelay = .{};
    try relay.start(io, 1);
    defer relay.stop(io);
    const json = try event.toJson(a, ev);
    @memcpy(relay.stored[0..json.len], json);
    relay.stored_len = json.len;
    var rbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const npub = try nostr.nip19.encodeNpub(a, kp.public_key);

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    const dest = try tmp.path(a, "got");
    var r = try runStrict(gpa, io, &.{ "download", npub, dest, relay_url });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "resolves to a private address (use --allow-local)") != null);
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "http://127.0.0.1:1/") != null);
}

/// The sha256 of `text`, in hex.
fn shaHex(text: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(text, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

fn manifestServers(a: std.mem.Allocator, json: []const u8) !std.ArrayList([]const u8) {
    var names: std.ArrayList([]const u8) = .empty;
    var parsed = try event.fromJson(testing.allocator, std.mem.trim(u8, json, "\n"));
    defer parsed.deinit();
    for (parsed.value.tags) |t| {
        if (std.mem.eql(u8, t[0], "server")) try names.append(a, try a.dupe(u8, t[1]));
    }
    return names;
}

test "a redeploy notices a changed title, a new server, and a blob a server lost" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello</h1>" });
    const src = try tmp.path(a, "site");

    var relay: SiteRelay = .{};
    try relay.start(io, 10);
    defer relay.stop(io);
    var one: BlobServer = undefined;
    try one.start(io, 20);
    defer one.stop(io);
    var two: BlobServer = undefined;
    try two.start(io, 10);
    defer two.stop(io);
    var rbuf: [64]u8 = undefined;
    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const url_one = one.base(&b1);
    const url_two = two.base(&b2);

    var first = try runArgs(gpa, io, &.{ "deploy", src, "-s", url_one, "--sec", test_sec, relay_url });
    defer first.deinit();
    try testing.expectEqual(cli.exit_ok, first.code);
    try testing.expectEqual(@as(usize, 1), relay.events.load(.monotonic));

    // Only the title changed: the manifest still has to go out.
    var titled = try runArgs(gpa, io, &.{ "deploy", src, "-s", url_one, "--sec", test_sec, "--title", "hello", relay_url });
    defer titled.deinit();
    try testing.expectEqual(cli.exit_ok, titled.code);
    try testing.expectEqual(@as(usize, 2), relay.events.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), one.puts);

    // Only a server was added: it gets the unchanged file, and is named.
    var added = try runArgs(gpa, io, &.{ "deploy", src, "-s", url_one, "-s", url_two, "--sec", test_sec, "--title", "hello", relay_url });
    defer added.deinit();
    try testing.expectEqual(cli.exit_ok, added.code);
    try testing.expectEqual(@as(usize, 3), relay.events.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), two.puts);
    try testing.expectEqual(@as(usize, 1), one.puts);
    const listed = try manifestServers(a, added.out.written());
    try testing.expectEqual(@as(usize, 2), listed.items.len);

    // Nothing changed and both servers hold the file: nothing goes out.
    var same = try runArgs(gpa, io, &.{ "deploy", src, "-s", url_one, "-s", url_two, "--sec", test_sec, "--title", "hello", relay_url });
    defer same.deinit();
    try testing.expect(std.mem.indexOf(u8, same.err.written(), "nothing changed") != null);
    try testing.expectEqual(@as(usize, 3), relay.events.load(.monotonic));

    // A server lost the blob: it is sent again.
    const sha = shaHex("<h1>hello</h1>");
    const lost = two.blobs.fetchRemove(&sha).?;
    std.heap.page_allocator.free(lost.key);
    std.heap.page_allocator.free(lost.value);
    var healed = try runArgs(gpa, io, &.{ "deploy", src, "-s", url_one, "-s", url_two, "--sec", test_sec, "--title", "hello", relay_url });
    defer healed.deinit();
    try testing.expectEqual(cli.exit_ok, healed.code);
    try testing.expectEqual(@as(usize, 2), two.puts);
}

test "the manifest names only the servers that took every file" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("nsite leaked");
    const gpa = da.allocator();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var tmp: Tmp = undefined;
    try tmp.init(io);
    defer tmp.deinit();
    try tmp.tmp.dir.createDirPath(io, "site");
    try tmp.tmp.dir.writeFile(io, .{ .sub_path = "site/index.html", .data = "<h1>hello</h1>" });
    const src = try tmp.path(a, "site");

    var relay: SiteRelay = .{};
    try relay.start(io, 2);
    defer relay.stop(io);
    var blobs: BlobServer = undefined;
    try blobs.start(io, 2);
    defer blobs.stop(io);
    var rbuf: [64]u8 = undefined;
    var bbuf: [64]u8 = undefined;
    const relay_url = try relay.url(&rbuf);
    const good = blobs.base(&bbuf);

    // Nothing listens on port 1: one server took the file, the other did not.
    var r = try runArgs(gpa, io, &.{ "deploy", src, "-s", good, "-s", "http://127.0.0.1:1", "--sec", test_sec, relay_url });
    defer r.deinit();
    try testing.expectEqual(cli.exit_ok, r.code);
    const listed = try manifestServers(a, r.out.written());
    try testing.expectEqual(@as(usize, 1), listed.items.len);
    try testing.expectEqualStrings(good, listed.items[0]);
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "does not hold every file") != null);
}
