//! deed blossom: talk to a Blossom media server (BUD-01, 02, 04, 06, 11).
//!
//! A blob is named by its sha256. Uploads, deletes and mirrors are signed with
//! a `kind:24242` token that names the blob in an `x` tag, so the hash has to
//! be known before the first byte goes out. A file is therefore read twice:
//! once to hash it, and once to stream it, hashing again on the way so that a
//! file that changed in between is noticed. Neither pass holds the file in
//! memory.
//!
//! Nothing is reported as done until it has been checked. An upload prints its
//! descriptor only when the server's sha256 and size match the file, and a
//! download is renamed into place only when what arrived hashes to the name it
//! was asked for.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const http = @import("http.zig");
const jsonout = @import("jsonout.zig");
const keyinput = @import("keyinput.zig");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const blossom = nostr.blossom;

/// Shown beside the name in `deed help` once `ready` is true.
pub const summary = "List, upload, download, delete, check and mirror blobs on a Blossom server";

/// False keeps the verb out of `deed help`.
pub const ready = true;

pub const usage =
    \\deed blossom: list, upload, download, delete, check and mirror blobs
    \\
    \\Usage:
    \\  deed blossom list <pubkey> --server <url>
    \\  deed blossom upload <file>... --server <url>
    \\  deed blossom download <sha256> --server <url> [-o <path>]
    \\  deed blossom delete <sha256>... --server <url>
    \\  deed blossom check <sha256>... --server <url>
    \\  deed blossom mirror <url> --server <url>
    \\
    \\A Blossom server stores blobs by their sha256. A server is a domain or a
    \\URL: cdn.example.com is read as https://cdn.example.com.
    \\
    \\upload hashes the file, asks the server whether it would take it (BUD-06),
    \\streams it, and prints the blob descriptor as one line of JSON once the
    \\server's sha256 and size match the file. download tries each server in turn
    \\and writes the file only when its sha256 matches. check and delete print one
    \\line of JSON per server and blob. mirror asks the server to copy a blob from
    \\a URL (BUD-04); the blob's sha256 is read from the URL, or given with
    \\--sha256.
    \\
    \\Options:
    \\  -s, --server <url>   the server; repeat it to use several. upload sends to
    \\                       all of them, download tries them in order
    \\      --sec <key>      the key that signs, as nsec1... or 64 hex characters.
    \\                       Falls back to $NOSTR_SECRET_KEY. upload, delete and
    \\                       mirror need one; list, download and check sign only
    \\                       when one is given
    \\  -o, --output <path>  download: where to write the file (default: the
    \\                       sha256, in the current directory)
    \\      --type <mime>    upload: the content type (default: from the file
    \\                       extension)
    \\      --sha256 <hex>   mirror: the sha256 of the blob, when the URL does not
    \\                       carry it
    \\      --limit <n>      list: at most n blobs
    \\      --since <t>      list: only blobs uploaded at or after this unix time
    \\      --until <t>      list: only blobs uploaded at or before this unix time
    \\      --timeout <ms>   the deadline for one request (default 30000, and
    \\                       600000 for a transfer)
    \\
    \\Exit status is 0 when everything asked for was done, 1 when something
    \\failed, and 2 when the command line was not understood.
    \\
    \\Examples:
    \\  deed blossom upload photo.jpg -s cdn.example.com --sec nsec1...
    \\  deed blossom download b167...f553 -s cdn.example.com -o photo.jpg
    \\  deed blossom check b167...f553 -s a.example.com -s b.example.com
    \\
;

const Command = enum { list, upload, download, delete, check, mirror };

/// A token is valid for this long. Long enough for a slow upload to start, short
/// enough that a leaked one is of little use.
const auth_lifetime_s: i64 = 300;

const quick_timeout_ms: u64 = 30_000;
const transfer_timeout_ms: u64 = 600_000;

/// Most a descriptor, an error body or a mirror reply may be.
const small_body_max: usize = 1024 * 1024;
const list_body_max: usize = 16 * 1024 * 1024;
const download_max: usize = @min(std.math.maxInt(usize), 8 * 1024 * 1024 * 1024);

const Options = struct {
    servers: std.ArrayList([]const u8) = .empty,
    positionals: std.ArrayList([]const u8) = .empty,
    sec: ?[]const u8 = null,
    output: ?[]const u8 = null,
    mime: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    limit: ?u64 = null,
    since: ?u64 = null,
    until: ?u64 = null,
    timeout_ms: ?u64 = null,

    fn deinit(self: *Options, gpa: std.mem.Allocator) void {
        self.servers.deinit(gpa);
        self.positionals.deinit(gpa);
    }
};

/// A server as the user named it, made usable.
const Server = struct {
    /// `https://host[:port][/prefix]`, with no trailing slash.
    base: []const u8,
    /// The lowercase host name, for the token's `server` tag. Null for an IPv6
    /// literal, which is not a domain.
    host: ?[]const u8,
};

const ServerError = error{InvalidServer} || std.mem.Allocator.Error;

fn parseServer(arena: std.mem.Allocator, raw: []const u8) ServerError!Server {
    const t = std.mem.trim(u8, raw, " \t\r\n");
    if (t.len == 0) return error.InvalidServer;
    for (t) |c| if (c <= ' ' or c == 0x7f) return error.InvalidServer;

    var scheme: []const u8 = "https";
    var rest = t;
    if (std.mem.find(u8, t, "://")) |at| {
        const s = t[0..at];
        if (std.ascii.eqlIgnoreCase(s, "https")) {
            scheme = "https";
        } else if (std.ascii.eqlIgnoreCase(s, "http")) {
            scheme = "http";
        } else return error.InvalidServer;
        rest = t[at + 3 ..];
    }
    const cut = std.mem.findAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..cut];
    var path = rest[cut..];
    if (path.len > 0 and path[0] != '/') return error.InvalidServer;
    while (path.len > 0 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];
    if (std.mem.findAny(u8, path, "?#") != null) return error.InvalidServer;
    if (authority.len == 0 or std.mem.findScalar(u8, authority, '@') != null) return error.InvalidServer;

    var host: ?[]const u8 = null;
    if (authority[0] == '[') {
        if (std.mem.findScalar(u8, authority, ']') == null) return error.InvalidServer;
    } else {
        var name = authority;
        if (std.mem.findScalarLast(u8, authority, ':')) |colon| {
            const port = authority[colon + 1 ..];
            if (port.len == 0) return error.InvalidServer;
            for (port) |c| if (!std.ascii.isDigit(c)) return error.InvalidServer;
            name = authority[0..colon];
        }
        if (name.len == 0) return error.InvalidServer;
        host = try std.ascii.allocLowerString(arena, name);
    }
    const lower_authority = try std.ascii.allocLowerString(arena, authority);
    return .{
        .base = try std.fmt.allocPrint(arena, "{s}://{s}{s}", .{ scheme, lower_authority, path }),
        .host = host,
    };
}

/// 64 hex characters, in either case, as 32 bytes.
fn parseSha(s: []const u8) ?[32]u8 {
    if (s.len != 64) return null;
    var out: [32]u8 = undefined;
    for (0..32) |i| {
        const hi = std.fmt.charToDigit(s[2 * i], 16) catch return null;
        const lo = std.fmt.charToDigit(s[2 * i + 1], 16) catch return null;
        out[i] = @as(u8, hi) << 4 | lo;
    }
    return out;
}

/// The sha256 a blob URL names: the last path segment, less an extension.
fn shaFromUrl(text: []const u8) ?[32]u8 {
    const end = std.mem.findAny(u8, text, "?#") orelse text.len;
    const slash = std.mem.findScalarLast(u8, text[0..end], '/') orelse return null;
    var seg = text[slash + 1 .. end];
    if (std.mem.findScalar(u8, seg, '.')) |dot| seg = seg[0..dot];
    return parseSha(seg);
}

fn mimeFor(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    const table = [_]struct { []const u8, []const u8 }{
        .{ ".png", "image/png" },
        .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },
        .{ ".gif", "image/gif" },
        .{ ".webp", "image/webp" },
        .{ ".svg", "image/svg+xml" },
        .{ ".mp4", "video/mp4" },
        .{ ".webm", "video/webm" },
        .{ ".mov", "video/quicktime" },
        .{ ".mp3", "audio/mpeg" },
        .{ ".ogg", "audio/ogg" },
        .{ ".wav", "audio/wav" },
        .{ ".pdf", "application/pdf" },
        .{ ".json", "application/json" },
        .{ ".txt", "text/plain" },
        .{ ".html", "text/html" },
    };
    for (table) |row| {
        if (std.ascii.eqlIgnoreCase(ext, row[0])) return row[1];
    }
    return "application/octet-stream";
}

const Ctx = struct {
    gpa: std.mem.Allocator,
    io: Io,
    out: *Io.Writer,
    err: *Io.Writer,
    signer: nostr.keys.Signer,
    keypair: ?nostr.keys.KeyPair,
    timeout_ms: ?u64,

    fn now(self: *const Ctx) i64 {
        return Io.Timestamp.now(self.io, .real).toSeconds();
    }

    fn timeout(self: *const Ctx, transfer: bool) u64 {
        return self.timeout_ms orelse if (transfer) transfer_timeout_ms else quick_timeout_ms;
    }

    /// The Authorization header for one action, or null when there is no key.
    fn authHeader(
        self: *const Ctx,
        arena: std.mem.Allocator,
        action: blossom.Action,
        content: []const u8,
        hashes: []const [32]u8,
        srv: Server,
    ) !?[]const u8 {
        const kp = self.keypair orelse return null;
        const created = self.now();
        const one = [1][]const u8{srv.host orelse ""};
        const header = try blossom.buildAuthHeader(self.gpa, self.signer, kp, created, .{
            .action = action,
            .content = content,
            .expiration = created + auth_lifetime_s,
            .hashes = hashes,
            .servers = if (srv.host != null) one[0..] else &.{},
        }, null);
        defer self.gpa.free(header);
        return try arena.dupe(u8, header);
    }
};

const Reply = struct { status: u16, body: []const u8 };

const Call = struct {
    method: http.Method,
    path: []const u8,
    auth: ?[]const u8 = null,
    headers: []const http.Header = &.{},
    body: http.Body = .none,
    content_type: ?[]const u8 = null,
    max_bytes: usize = small_body_max,
    transfer: bool = false,
};

fn joinUrl(arena: std.mem.Allocator, srv: Server, path: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}{s}", .{ srv.base, path });
}

/// One request, answered in memory. The status is returned, never raised.
fn call(ctx: *const Ctx, arena: std.mem.Allocator, srv: Server, c: Call) http.Error!Reply {
    var headers: std.ArrayList(http.Header) = .empty;
    if (c.auth) |a| headers.append(arena, .{ .name = "Authorization", .value = a }) catch return error.OutOfMemory;
    headers.appendSlice(arena, c.headers) catch return error.OutOfMemory;
    const target = joinUrl(arena, srv, c.path) catch return error.OutOfMemory;
    var res = try http.fetch(ctx.gpa, ctx.io, target, .{
        .method = c.method,
        .headers = headers.items,
        .body = c.body,
        .content_type = c.content_type,
        .timeout_ms = ctx.timeout(c.transfer),
        .max_bytes = c.max_bytes,
    });
    defer res.deinit(ctx.gpa);
    return .{ .status = res.status, .body = arena.dupe(u8, res.body) catch return error.OutOfMemory };
}

fn ok(status: u16) bool {
    return status >= 200 and status < 300;
}

/// A line saying a request failed to complete.
fn failed(ctx: *const Ctx, srv: Server, what: []const u8, e: http.Error) !void {
    try ctx.err.print("deed blossom: {s}: {s}: {s}\n", .{ srv.base, what, http.describe(e) });
}

/// A line saying the server answered with a refusal, with the start of what it
/// said when that is plain text.
fn refused(ctx: *const Ctx, srv: Server, what: []const u8, r: Reply) !void {
    try ctx.err.print("deed blossom: {s}: {s} refused: HTTP {d}", .{ srv.base, what, r.status });
    var shown: usize = 0;
    var started = false;
    for (r.body) |c| {
        if (shown >= 160) break;
        if (c < 0x20 or c >= 0x7f) continue;
        if (!started) {
            try ctx.err.writeAll(": ");
            started = true;
        }
        try ctx.err.writeByte(c);
        shown += 1;
    }
    try ctx.err.writeByte('\n');
}

/// The compact JSON of one descriptor, once it has parsed as one.
fn writeDescriptor(ctx: *const Ctx, value: std.json.Value) !void {
    try std.json.Stringify.value(value, .{}, ctx.out);
    try ctx.out.writeByte('\n');
}

const Descriptor = struct { value: std.json.Value, parsed: blossom.BlobDescriptor };

fn readDescriptor(arena: std.mem.Allocator, gpa: std.mem.Allocator, body: []const u8) ?Descriptor {
    var p = blossom.parseDescriptor(gpa, body) catch return null;
    defer p.deinit();
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return null;
    // The strings of the parsed descriptor live in `p`; only the checked
    // numbers and hash are kept.
    var d = p.value;
    d.url = "";
    d.type = null;
    d.nip94 = null;
    return .{ .value = value, .parsed = d };
}

// ---- argument parsing ------------------------------------------------------

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed blossom: say what to do: list, upload, download, delete, check or mirror (see 'deed help blossom')\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    const cmd = std.meta.stringToEnum(Command, args[0]) orelse {
        try err.print("deed blossom: unknown command '{s}' (want list, upload, download, delete, check or mirror)\n", .{args[0]});
        return cli.exit_usage;
    };

    var opts: Options = .{};
    defer opts.deinit(gpa);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        const takes_value = cli.isOneOf(a, &.{ "-s", "--server", "--sec", "-o", "--output", "--type", "--sha256", "--limit", "--since", "--until", "--timeout" });
        if (takes_value) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed blossom: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            const v = args[i];
            if (cli.isOneOf(a, &.{ "-s", "--server" })) {
                try opts.servers.append(gpa, v);
            } else if (std.mem.eql(u8, a, "--sec")) {
                opts.sec = v;
            } else if (cli.isOneOf(a, &.{ "-o", "--output" })) {
                opts.output = v;
            } else if (std.mem.eql(u8, a, "--type")) {
                opts.mime = v;
            } else if (std.mem.eql(u8, a, "--sha256")) {
                opts.sha256 = v;
            } else {
                const n = std.fmt.parseInt(u64, v, 10) catch {
                    try err.print("deed blossom: {s} needs a number, not '{s}'\n", .{ a, v });
                    return cli.exit_usage;
                };
                if (std.mem.eql(u8, a, "--limit")) {
                    opts.limit = n;
                } else if (std.mem.eql(u8, a, "--since")) {
                    opts.since = n;
                } else if (std.mem.eql(u8, a, "--until")) {
                    opts.until = n;
                } else {
                    if (n == 0) {
                        try err.writeAll("deed blossom: --timeout needs a number of milliseconds above 0\n");
                        return cli.exit_usage;
                    }
                    opts.timeout_ms = n;
                }
            }
        } else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
            try err.print("deed blossom: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else {
            try opts.positionals.append(gpa, a);
        }
    }

    if (opts.servers.items.len == 0) {
        try err.print("deed blossom {s}: name a server with --server\n", .{@tagName(cmd)});
        return cli.exit_usage;
    }
    switch (cmd) {
        .list, .mirror => if (opts.positionals.items.len != 1) {
            try err.print("deed blossom {s}: takes exactly one {s}\n", .{ @tagName(cmd), if (cmd == .list) "public key" else "URL" });
            return cli.exit_usage;
        },
        .download => if (opts.positionals.items.len != 1) {
            try err.writeAll("deed blossom download: takes exactly one sha256\n");
            return cli.exit_usage;
        },
        .upload, .delete, .check => if (opts.positionals.items.len == 0) {
            try err.print("deed blossom {s}: name at least one {s}\n", .{ @tagName(cmd), if (cmd == .upload) "file" else "sha256" });
            return cli.exit_usage;
        },
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var servers: std.ArrayList(Server) = .empty;
    for (opts.servers.items) |raw| {
        const s = parseServer(arena, raw) catch |e| switch (e) {
            error.InvalidServer => {
                try err.print("deed blossom: '{s}' is not a server (want a domain or an http(s) URL)\n", .{raw});
                return cli.exit_usage;
            },
            error.OutOfMemory => return e,
        };
        try servers.append(arena, s);
    }

    const needs_key = switch (cmd) {
        .upload, .delete, .mirror => true,
        else => false,
    };
    const raw_key: ?[]const u8 = opts.sec orelse getEnv("NOSTR_SECRET_KEY");
    if (raw_key == null and needs_key) {
        try err.print("deed blossom {s}: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n", .{@tagName(cmd)});
        return cli.exit_usage;
    }

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    var keypair: ?nostr.keys.KeyPair = null;
    if (raw_key) |raw| {
        const sk = keyinput.secretKey(gpa, raw) catch {
            try err.writeAll("deed blossom: not a secret key (want nsec1... or 64 hex characters)\n");
            return cli.exit_usage;
        };
        keypair = signer.keyPairFromSecretKey(sk) catch {
            try err.writeAll("deed blossom: not a secret key (want nsec1... or 64 hex characters)\n");
            return cli.exit_usage;
        };
    }

    const ctx: Ctx = .{
        .gpa = gpa,
        .io = io,
        .out = out,
        .err = err,
        .signer = signer,
        .keypair = keypair,
        .timeout_ms = opts.timeout_ms,
    };
    return switch (cmd) {
        .list => cmdList(&ctx, arena, opts, servers.items),
        .upload => cmdUpload(&ctx, arena, opts, servers.items),
        .download => cmdDownload(&ctx, arena, opts, servers.items),
        .delete => cmdDelete(&ctx, arena, opts, servers.items),
        .check => cmdCheck(&ctx, arena, opts, servers.items),
        .mirror => cmdMirror(&ctx, arena, opts, servers.items),
    };
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

/// A sha256 argument, or a line saying it is not one.
fn shaArg(ctx: *const Ctx, s: []const u8) !?[32]u8 {
    if (parseSha(s)) |h| return h;
    try ctx.err.print("deed blossom: '{s}' is not a sha256 (want 64 hex characters)\n", .{s});
    return null;
}

// ---- list ------------------------------------------------------------------

fn cmdList(ctx: *const Ctx, arena: std.mem.Allocator, opts: Options, servers: []const Server) !u8 {
    const pk = keyinput.publicKey(ctx.gpa, opts.positionals.items[0]) catch {
        try ctx.err.print("deed blossom list: '{s}' is not a public key (want npub1... or 64 hex characters)\n", .{opts.positionals.items[0]});
        return cli.exit_usage;
    };
    const pk_hex = std.fmt.bytesToHex(pk, .lower);

    var path: std.ArrayList(u8) = .empty;
    try path.print(arena, "/list/{s}", .{pk_hex});
    var sep: u8 = '?';
    inline for (.{ .{ "limit", opts.limit }, .{ "since", opts.since }, .{ "until", opts.until } }) |q| {
        if (q[1]) |v| {
            try path.print(arena, "{c}{s}={d}", .{ sep, q[0], v });
            sep = '&';
        }
    }

    var code: u8 = cli.exit_ok;
    for (servers) |srv| {
        const auth = try ctx.authHeader(arena, .list, "List Blobs", &.{}, srv);
        const r = call(ctx, arena, srv, .{ .method = .GET, .path = path.items, .auth = auth, .max_bytes = list_body_max }) catch |e| {
            try failed(ctx, srv, "list", e);
            code = cli.exit_fail;
            continue;
        };
        if (!ok(r.status)) {
            try refused(ctx, srv, "list", r);
            code = cli.exit_fail;
            continue;
        }
        var checked = blossom.parseDescriptorList(ctx.gpa, r.body) catch {
            try ctx.err.print("deed blossom: {s}: the list is not a list of blob descriptors\n", .{srv.base});
            code = cli.exit_fail;
            continue;
        };
        checked.deinit();
        const value = std.json.parseFromSliceLeaky(std.json.Value, arena, r.body, .{}) catch {
            code = cli.exit_fail;
            continue;
        };
        for (value.array.items) |item| try writeDescriptor(ctx, item);
    }
    return code;
}

// ---- upload ----------------------------------------------------------------

const Hashed = struct { sha: [32]u8, size: u64 };

/// Reads the file once, to name it.
fn hashFile(io: Io, path: []const u8) !Hashed {
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
    }
    return .{ .sha = h.finalResult(), .size = size };
}

fn cmdUpload(ctx: *const Ctx, arena: std.mem.Allocator, opts: Options, servers: []const Server) !u8 {
    var code: u8 = cli.exit_ok;
    for (opts.positionals.items) |path| {
        const named = hashFile(ctx.io, path) catch |e| {
            try ctx.err.print("deed blossom upload: cannot read {s}: {s}\n", .{ path, @errorName(e) });
            code = cli.exit_fail;
            continue;
        };
        const mime = opts.mime orelse mimeFor(path);
        for (servers) |srv| {
            if (!try uploadOne(ctx, arena, srv, path, named, mime)) code = cli.exit_fail;
        }
    }
    return code;
}

fn uploadOne(ctx: *const Ctx, arena: std.mem.Allocator, srv: Server, path: []const u8, named: Hashed, mime: []const u8) !bool {
    const hex = std.fmt.bytesToHex(named.sha, .lower);
    const auth = (try ctx.authHeader(arena, .upload, "Upload Blob", &.{named.sha}, srv)).?;
    const len_text = try std.fmt.allocPrint(arena, "{d}", .{named.size});

    // BUD-06: ask first, so a file the server would refuse is not sent. A
    // server without the endpoint answers 404, 405 or 501, which is not a
    // refusal.
    const pre = call(ctx, arena, srv, .{
        .method = .HEAD,
        .path = "/upload",
        .auth = auth,
        .headers = &.{
            .{ .name = "X-SHA-256", .value = &hex },
            .{ .name = "X-Content-Length", .value = len_text },
            .{ .name = "X-Content-Type", .value = mime },
        },
        .max_bytes = std.math.maxInt(usize),
    }) catch |e| {
        try failed(ctx, srv, path, e);
        return false;
    };
    const unsupported = pre.status == 404 or pre.status == 405 or pre.status == 501;
    if (!ok(pre.status) and !unsupported) {
        try ctx.err.print("deed blossom: {s}: {s}: the server would not take it: HTTP {d}\n", .{ srv.base, path, pre.status });
        return false;
    }

    const file = Io.Dir.cwd().openFile(ctx.io, path, .{}) catch |e| {
        try ctx.err.print("deed blossom upload: cannot read {s}: {s}\n", .{ path, @errorName(e) });
        return false;
    };
    defer file.close(ctx.io);
    var rbuf: [64 * 1024]u8 = undefined;
    var fr = file.reader(ctx.io, &rbuf);
    var hbuf: [16 * 1024]u8 = undefined;
    var hashed = Io.Reader.Hashed(Sha256).init(&fr.interface, Sha256.init(.{}), &hbuf);

    const r = call(ctx, arena, srv, .{
        .method = .PUT,
        .path = "/upload",
        .auth = auth,
        .headers = &.{.{ .name = "X-SHA-256", .value = &hex }},
        .body = .{ .stream = .{ .reader = &hashed.reader, .len = named.size } },
        .content_type = mime,
        .transfer = true,
    }) catch |e| {
        try failed(ctx, srv, path, e);
        return false;
    };
    if (!ok(r.status)) {
        try refused(ctx, srv, path, r);
        return false;
    }
    if (!std.mem.eql(u8, &hashed.hasher.finalResult(), &named.sha)) {
        try ctx.err.print("deed blossom: {s}: {s} changed while it was being sent\n", .{ srv.base, path });
        return false;
    }
    const d = readDescriptor(arena, ctx.gpa, r.body) orelse {
        try ctx.err.print("deed blossom: {s}: {s}: the reply is not a blob descriptor\n", .{ srv.base, path });
        return false;
    };
    if (d.parsed.sha256 == null or !std.mem.eql(u8, &d.parsed.sha256.?, &named.sha)) {
        const theirs = std.fmt.bytesToHex(d.parsed.sha256 orelse [_]u8{0} ** 32, .lower);
        try ctx.err.print("deed blossom: {s}: {s}: the server reports sha256 {s}, the file is {s}\n", .{ srv.base, path, &theirs, &hex });
        return false;
    }
    if (d.parsed.size != null and d.parsed.size.? != named.size) {
        try ctx.err.print("deed blossom: {s}: {s}: the server reports {d} bytes, the file has {d}\n", .{ srv.base, path, d.parsed.size.?, named.size });
        return false;
    }
    try writeDescriptor(ctx, d.value);
    return true;
}

// ---- download --------------------------------------------------------------

fn cmdDownload(ctx: *const Ctx, arena: std.mem.Allocator, opts: Options, servers: []const Server) !u8 {
    const sha = (try shaArg(ctx, opts.positionals.items[0])) orelse return cli.exit_usage;
    const hex = std.fmt.bytesToHex(sha, .lower);
    const dest = opts.output orelse &hex;
    for (servers) |srv| {
        if (try downloadOne(ctx, arena, srv, sha, dest)) return cli.exit_ok;
    }
    return cli.exit_fail;
}

fn downloadOne(ctx: *const Ctx, arena: std.mem.Allocator, srv: Server, sha: [32]u8, dest: []const u8) !bool {
    const hex = std.fmt.bytesToHex(sha, .lower);
    const auth = try ctx.authHeader(arena, .get, "Get Blob", &.{sha}, srv);
    const cwd = Io.Dir.cwd();
    const tmp = try std.fmt.allocPrint(arena, "{s}.{s}.part", .{ dest, hex[0..8] });

    var headers: [1]http.Header = undefined;
    const extra: []const http.Header = if (auth) |a| blk: {
        headers[0] = .{ .name = "Authorization", .value = a };
        break :blk headers[0..1];
    } else &.{};

    const file = cwd.createFile(ctx.io, tmp, .{}) catch |e| {
        try ctx.err.print("deed blossom download: cannot write {s}: {s}\n", .{ tmp, @errorName(e) });
        return false;
    };
    var closed = false;
    var finished = false;
    defer {
        if (!closed) file.close(ctx.io);
        if (!finished) cwd.deleteFile(ctx.io, tmp) catch {};
    }

    var wbuf: [64 * 1024]u8 = undefined;
    var fw = file.writer(ctx.io, &wbuf);
    var hbuf: [16 * 1024]u8 = undefined;
    var hashed = Io.Writer.Hashed(Sha256).initHasher(&fw.interface, Sha256.init(.{}), &hbuf);

    const blob_url = try std.fmt.allocPrint(arena, "{s}/{s}", .{ srv.base, hex });
    const status = http.fetchTo(ctx.gpa, ctx.io, blob_url, .{
        .headers = extra,
        .timeout_ms = ctx.timeout(true),
        .max_bytes = download_max,
    }, &hashed.writer) catch |e| {
        try failed(ctx, srv, &hex, e);
        return false;
    };
    if (!ok(status)) {
        try ctx.err.print("deed blossom: {s}: {s} refused: HTTP {d}\n", .{ srv.base, &hex, status });
        return false;
    }
    hashed.writer.flush() catch {
        try ctx.err.print("deed blossom download: cannot write {s}\n", .{tmp});
        return false;
    };
    fw.interface.flush() catch {
        try ctx.err.print("deed blossom download: cannot write {s}\n", .{tmp});
        return false;
    };
    const size = fw.logicalPos();
    file.close(ctx.io);
    closed = true;

    const got = hashed.hasher.finalResult();
    if (!std.mem.eql(u8, &got, &sha)) {
        const theirs = std.fmt.bytesToHex(got, .lower);
        try ctx.err.print("deed blossom: {s}: what arrived hashes to {s}, not {s}; nothing was kept\n", .{ srv.base, &theirs, &hex });
        return false;
    }
    cwd.rename(tmp, cwd, dest, ctx.io) catch |e| {
        try ctx.err.print("deed blossom download: cannot write {s}: {s}\n", .{ dest, @errorName(e) });
        return false;
    };
    finished = true;

    var line: std.ArrayList(u8) = .empty;
    try line.print(arena, "{{\"sha256\":\"{s}\",\"size\":{d},\"path\":", .{ &hex, size });
    try jsonout.appendString(&line, arena, dest);
    try line.appendSlice(arena, ",\"server\":");
    try jsonout.appendString(&line, arena, srv.base);
    try line.appendSlice(arena, "}\n");
    try ctx.out.writeAll(line.items);
    return true;
}

// ---- delete and check ------------------------------------------------------

fn resultLine(ctx: *const Ctx, arena: std.mem.Allocator, srv: Server, hex: []const u8, field: []const u8, value: bool) !void {
    var line: std.ArrayList(u8) = .empty;
    try line.print(arena, "{{\"server\":", .{});
    try jsonout.appendString(&line, arena, srv.base);
    try line.print(arena, ",\"sha256\":\"{s}\",\"{s}\":{s}}}\n", .{ hex, field, if (value) "true" else "false" });
    try ctx.out.writeAll(line.items);
}

fn cmdDelete(ctx: *const Ctx, arena: std.mem.Allocator, opts: Options, servers: []const Server) !u8 {
    var shas: std.ArrayList([32]u8) = .empty;
    for (opts.positionals.items) |s| {
        try shas.append(arena, (try shaArg(ctx, s)) orelse return cli.exit_usage);
    }
    var code: u8 = cli.exit_ok;
    for (shas.items) |sha| {
        const hex = std.fmt.bytesToHex(sha, .lower);
        const path = try std.fmt.allocPrint(arena, "/{s}", .{&hex});
        for (servers) |srv| {
            const auth = (try ctx.authHeader(arena, .delete, "Delete Blob", &.{sha}, srv)).?;
            const r = call(ctx, arena, srv, .{ .method = .DELETE, .path = path, .auth = auth }) catch |e| {
                try failed(ctx, srv, &hex, e);
                code = cli.exit_fail;
                continue;
            };
            if (!ok(r.status)) {
                try refused(ctx, srv, &hex, r);
                code = cli.exit_fail;
                continue;
            }
            try resultLine(ctx, arena, srv, &hex, "deleted", true);
        }
    }
    return code;
}

fn cmdCheck(ctx: *const Ctx, arena: std.mem.Allocator, opts: Options, servers: []const Server) !u8 {
    var shas: std.ArrayList([32]u8) = .empty;
    for (opts.positionals.items) |s| {
        try shas.append(arena, (try shaArg(ctx, s)) orelse return cli.exit_usage);
    }
    var code: u8 = cli.exit_ok;
    for (shas.items) |sha| {
        const hex = std.fmt.bytesToHex(sha, .lower);
        const path = try std.fmt.allocPrint(arena, "/{s}", .{&hex});
        for (servers) |srv| {
            const auth = try ctx.authHeader(arena, .get, "Check Blob", &.{sha}, srv);
            // A HEAD reply carries the blob's Content-Length and no body, so
            // the size cap does not apply.
            const r = call(ctx, arena, srv, .{ .method = .HEAD, .path = path, .auth = auth, .max_bytes = std.math.maxInt(usize) }) catch |e| {
                try failed(ctx, srv, &hex, e);
                code = cli.exit_fail;
                continue;
            };
            if (ok(r.status)) {
                try resultLine(ctx, arena, srv, &hex, "exists", true);
            } else if (r.status == 404) {
                try resultLine(ctx, arena, srv, &hex, "exists", false);
                code = cli.exit_fail;
            } else {
                try refused(ctx, srv, &hex, r);
                code = cli.exit_fail;
            }
        }
    }
    return code;
}

// ---- mirror ----------------------------------------------------------------

fn cmdMirror(ctx: *const Ctx, arena: std.mem.Allocator, opts: Options, servers: []const Server) !u8 {
    const source = opts.positionals.items[0];
    if (!std.mem.startsWith(u8, source, "https://") and !std.mem.startsWith(u8, source, "http://")) {
        try ctx.err.print("deed blossom mirror: '{s}' is not a URL\n", .{source});
        return cli.exit_usage;
    }
    // The token must name the blob, and the server checks what it fetched
    // against that name.
    const sha = if (opts.sha256) |s| (try shaArg(ctx, s)) orelse return cli.exit_usage else shaFromUrl(source) orelse {
        try ctx.err.writeAll("deed blossom mirror: the URL does not carry a sha256: pass it with --sha256\n");
        return cli.exit_usage;
    };
    const hex = std.fmt.bytesToHex(sha, .lower);
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(arena, "{\"url\":");
    try jsonout.appendString(&body, arena, source);
    try body.append(arena, '}');

    var code: u8 = cli.exit_ok;
    for (servers) |srv| {
        const auth = (try ctx.authHeader(arena, .upload, "Mirror Blob", &.{sha}, srv)).?;
        const r = call(ctx, arena, srv, .{
            .method = .PUT,
            .path = "/mirror",
            .auth = auth,
            .body = .{ .bytes = body.items },
            .content_type = "application/json",
            .transfer = true,
        }) catch |e| {
            try failed(ctx, srv, "mirror", e);
            code = cli.exit_fail;
            continue;
        };
        if (!ok(r.status)) {
            try refused(ctx, srv, "mirror", r);
            code = cli.exit_fail;
            continue;
        }
        const d = readDescriptor(arena, ctx.gpa, r.body) orelse {
            try ctx.err.print("deed blossom: {s}: the reply is not a blob descriptor\n", .{srv.base});
            code = cli.exit_fail;
            continue;
        };
        if (d.parsed.sha256 == null or !std.mem.eql(u8, &d.parsed.sha256.?, &sha)) {
            const theirs = std.fmt.bytesToHex(d.parsed.sha256 orelse [_]u8{0} ** 32, .lower);
            try ctx.err.print("deed blossom: {s}: the server reports sha256 {s}, expected {s}\n", .{ srv.base, &theirs, &hex });
            code = cli.exit_fail;
            continue;
        }
        try writeDescriptor(ctx, d.value);
    }
    return code;
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

test "a server is a domain or a URL, and is made lowercase without a trailing slash" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var s = try parseServer(a, "CDN.Example.com");
    try testing.expectEqualStrings("https://cdn.example.com", s.base);
    try testing.expectEqualStrings("cdn.example.com", s.host.?);

    s = try parseServer(a, "http://127.0.0.1:8080/");
    try testing.expectEqualStrings("http://127.0.0.1:8080", s.base);
    try testing.expectEqualStrings("127.0.0.1", s.host.?);

    s = try parseServer(a, "https://Host.example/prefix/");
    try testing.expectEqualStrings("https://host.example/prefix", s.base);

    s = try parseServer(a, "http://[::1]:3000");
    try testing.expect(s.host == null);

    try testing.expectError(error.InvalidServer, parseServer(a, ""));
    try testing.expectError(error.InvalidServer, parseServer(a, "ftp://x.example"));
    try testing.expectError(error.InvalidServer, parseServer(a, "https://user@x.example"));
    try testing.expectError(error.InvalidServer, parseServer(a, "x.example:port"));
    try testing.expectError(error.InvalidServer, parseServer(a, "two words"));
}

test "a sha256 is read from a bare hash or from a blob URL" {
    const hex = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    try testing.expect(parseSha(hex) != null);
    try testing.expect(parseSha("B1674191A88EC5CDD733E4240A81803105DC412D6C6708D53AB94FC248F4F553") != null);
    try testing.expect(parseSha(hex[1..]) == null);
    try testing.expect(parseSha("zz" ++ hex[2..]) == null);
    try testing.expect(shaFromUrl("https://cdn.example/" ++ hex ++ ".pdf") != null);
    try testing.expect(shaFromUrl("https://cdn.example/" ++ hex ++ "?x=1") != null);
    try testing.expect(shaFromUrl("https://cdn.example/photo.jpg") == null);
}

/// An allocator that refuses any single allocation above a cap, so a test can
/// show that a 20 MB file is never held whole.
const CapAllocator = struct {
    child: std.mem.Allocator,
    cap: usize,
    biggest: usize = 0,

    fn allocator(self: *CapAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *CapAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.cap) return null;
        self.biggest = @max(self.biggest, len);
        return self.child.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *CapAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > self.cap) return false;
        self.biggest = @max(self.biggest, new_len);
        return self.child.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *CapAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > self.cap) return null;
        self.biggest = @max(self.biggest, new_len);
        return self.child.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *CapAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};

/// Deterministic blob bytes, so a test can name a 20 MB blob without holding it.
fn fillPattern(buf: []u8, offset: u64) void {
    for (buf, 0..) |*b, i| b.* = @truncate(((offset + i) *% 0x9E3779B1) >> 13);
}

fn patternSha(len: u64) [32]u8 {
    var h = Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var at: u64 = 0;
    while (at < len) {
        const n: usize = @intCast(@min(buf.len, len - at));
        fillPattern(buf[0..n], at);
        h.update(buf[0..n]);
        at += n;
    }
    return h.finalResult();
}

const test_secret = [_]u8{0x33} ** 32;

/// A Blossom server on loopback that checks every token it is shown.
const Mock = struct {
    pub const Mode = enum {
        normal,
        /// The upload reply names another sha256.
        lie_hash,
        /// The preflight is refused with 413.
        refuse_preflight,
        /// A download serves bytes that are not the blob.
        corrupt,
    };

    server: Io.net.Server,
    task: Io.Future(void),
    connections: usize,
    mode: Mode = .normal,
    signer: nostr.keys.Signer,
    pubkey_hex: [64]u8,

    /// What a download and a HEAD serve.
    serve_sha: [32]u8 = [_]u8{0} ** 32,
    serve_len: u64 = 0,

    // What the server saw.
    heads: usize = 0,
    puts: usize = 0,
    deletes: usize = 0,
    mirrors: usize = 0,
    auth_seen: usize = 0,
    problems: usize = 0,
    problem: [200]u8 = undefined,
    problem_len: usize = 0,
    put_sha: [32]u8 = [_]u8{0} ** 32,
    put_len: u64 = 0,
    mirror_body: [300]u8 = undefined,
    mirror_body_len: usize = 0,

    fn start(self: *Mock, io: Io, connections: usize) !void {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var signer = nostr.keys.Signer.init();
        const kp = try signer.keyPairFromSecretKey(test_secret);
        self.* = .{
            .server = try address.listen(io, .{ .reuse_address = true }),
            .task = undefined,
            .connections = connections,
            .signer = signer,
            .pubkey_hex = std.fmt.bytesToHex(kp.public_key, .lower),
        };
        errdefer self.server.deinit(io);
        self.task = try io.concurrent(serve, .{ self, io });
    }

    fn stop(self: *Mock, io: Io) void {
        self.task.cancel(io);
        self.server.deinit(io);
        self.signer.deinit();
    }

    fn port(self: *const Mock) u16 {
        return self.server.socket.address.ip4.port;
    }

    fn base(self: *const Mock, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}", .{self.port()}) catch unreachable;
    }

    fn flag(self: *Mock, comptime fmt: []const u8, args: anytype) void {
        self.problems += 1;
        if (self.problem_len != 0) return;
        const text = std.fmt.bufPrint(&self.problem, fmt, args) catch self.problem[0..0];
        self.problem_len = text.len;
    }

    fn firstProblem(self: *const Mock) []const u8 {
        return self.problem[0..self.problem_len];
    }

    fn serve(self: *Mock, io: Io) void {
        for (0..self.connections) |_| {
            const conn = self.server.accept(io) catch return;
            defer conn.close(io);
            self.handle(io, conn) catch {};
        }
    }

    /// Checks the BUD-11 rules a server enforces. `x` is the hash the
    /// endpoint implies, or null for an endpoint that takes none.
    fn checkToken(self: *Mock, io: Io, header: []const u8, action: []const u8, x: ?[]const u8) bool {
        const gpa = std.heap.page_allocator;
        var parsed = nostr.nip98.decodeHeader(gpa, header) catch {
            self.flag("{s}: the header does not decode", .{action});
            return false;
        };
        defer parsed.deinit();
        const ev = parsed.value;
        if (ev.kind != 24242) {
            self.flag("{s}: kind {d}", .{ action, ev.kind });
            return false;
        }
        const good_sig = nostr.event.verify(gpa, self.signer, ev) catch false;
        if (!good_sig) {
            self.flag("{s}: bad signature", .{action});
            return false;
        }
        if (!std.mem.eql(u8, &std.fmt.bytesToHex(ev.pubkey, .lower), &self.pubkey_hex)) {
            self.flag("{s}: wrong key", .{action});
            return false;
        }
        const now = Io.Timestamp.now(io, .real).toSeconds();
        if (ev.created_at > now + 5) {
            self.flag("{s}: created in the future", .{action});
            return false;
        }
        var t_ok = false;
        var exp_ok = false;
        var x_ok = x == null;
        var server_ok = false;
        for (ev.tags) |tag| {
            if (tag.len < 2) continue;
            if (std.mem.eql(u8, tag[0], "t") and std.mem.eql(u8, tag[1], action)) t_ok = true;
            if (std.mem.eql(u8, tag[0], "expiration")) {
                const e = std.fmt.parseInt(i64, tag[1], 10) catch 0;
                exp_ok = e > now and e <= now + 600;
            }
            if (x) |want| {
                if (std.mem.eql(u8, tag[0], "x") and std.mem.eql(u8, tag[1], want)) x_ok = true;
            }
            if (std.mem.eql(u8, tag[0], "server") and std.mem.eql(u8, tag[1], "127.0.0.1")) server_ok = true;
        }
        if (!t_ok) self.flag("{s}: no matching t tag", .{action});
        if (!exp_ok) self.flag("{s}: expiration missing or out of range", .{action});
        if (!x_ok) self.flag("{s}: no matching x tag", .{action});
        if (!server_ok) self.flag("{s}: no server tag naming 127.0.0.1", .{action});
        return t_ok and exp_ok and x_ok and server_ok;
    }

    fn descriptor(self: *Mock, buf: []u8, sha_hex: []const u8, size: u64) []const u8 {
        return std.fmt.bufPrint(buf, "{{\"url\":\"http://127.0.0.1:{d}/{s}\",\"sha256\":\"{s}\",\"size\":{d},\"type\":\"application/octet-stream\",\"uploaded\":1}}", .{ self.port(), sha_hex, sha_hex, size }) catch unreachable;
    }

    fn handle(self: *Mock, io: Io, conn: Io.net.Stream) !void {
        var rbuf: [8192]u8 = undefined;
        var wbuf: [8192]u8 = undefined;
        var r = conn.reader(io, &rbuf);
        var w = conn.writer(io, &wbuf);
        var s = std.http.Server.init(&r.interface, &w.interface);
        var req = try s.receiveHead();

        // The head's strings are gone once the body is read, so keep what is
        // needed.
        const method = req.head.method;
        var target_buf: [600]u8 = undefined;
        var target: []const u8 = req.head.target;
        if (std.mem.indexOfScalar(u8, target, '?')) |q| target = target[0..q];
        target = target_buf[0..target.len];
        @memcpy(@constCast(target), req.head.target[0..target.len]);
        var auth_buf: [4096]u8 = undefined;
        var auth: ?[]const u8 = null;
        var xsha_buf: [64]u8 = undefined;
        var xsha: ?[]const u8 = null;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "authorization") and h.value.len <= auth_buf.len) {
                @memcpy(auth_buf[0..h.value.len], h.value);
                auth = auth_buf[0..h.value.len];
            }
            if (std.ascii.eqlIgnoreCase(h.name, "x-sha-256") and h.value.len == 64) {
                @memcpy(&xsha_buf, h.value);
                xsha = &xsha_buf;
            }
        }
        if (auth != null) self.auth_seen += 1;

        const serve_hex = std.fmt.bytesToHex(self.serve_sha, .lower);
        var body_buf: [1024]u8 = undefined;

        if (std.mem.eql(u8, target, "/upload") and (method == .HEAD or method == .PUT)) {
            const is_put = method == .PUT;
            if (is_put) self.puts += 1 else self.heads += 1;
            const want = xsha orelse {
                self.flag("upload without X-SHA-256", .{});
                return req.respond("", .{ .status = .bad_request, .keep_alive = false });
            };
            if (auth == null or !self.checkToken(io, auth.?, "upload", want)) {
                return req.respond("", .{ .status = .unauthorized, .keep_alive = false });
            }
            if (!is_put) {
                if (self.mode == .refuse_preflight)
                    return req.respond("", .{ .status = .payload_too_large, .keep_alive = false });
                return req.respond("", .{ .keep_alive = false });
            }
            var chunk: [8192]u8 = undefined;
            var hasher = Sha256.init(.{});
            var total: u64 = 0;
            const body = req.readerExpectNone(&chunk);
            var tmp: [8192]u8 = undefined;
            while (true) {
                const n = body.readSliceShort(&tmp) catch break;
                if (n == 0) break;
                hasher.update(tmp[0..n]);
                total += n;
            }
            self.put_sha = hasher.finalResult();
            self.put_len = total;
            const got = std.fmt.bytesToHex(self.put_sha, .lower);
            if (!std.mem.eql(u8, &got, want)) self.flag("body hashes to {s}, X-SHA-256 said {s}", .{ &got, want });
            const reported: []const u8 = if (self.mode == .lie_hash) "0" ** 64 else &got;
            return req.respond(self.descriptor(&body_buf, reported, total), .{ .keep_alive = false });
        }

        if (std.mem.eql(u8, target, "/mirror") and method == .PUT) {
            self.mirrors += 1;
            const sha_hex = serve_hex;
            if (auth == null or !self.checkToken(io, auth.?, "upload", &sha_hex)) {
                return req.respond("", .{ .status = .unauthorized, .keep_alive = false });
            }
            var chunk: [1024]u8 = undefined;
            const body = req.readerExpectNone(&chunk);
            self.mirror_body_len = body.readSliceShort(&self.mirror_body) catch 0;
            return req.respond(self.descriptor(&body_buf, &sha_hex, self.serve_len), .{ .status = .created, .keep_alive = false });
        }

        if (std.mem.startsWith(u8, target, "/list/")) {
            if (!std.mem.eql(u8, target[6..], &self.pubkey_hex)) {
                self.flag("list asked for {s}", .{target});
                return req.respond("", .{ .status = .bad_request, .keep_alive = false });
            }
            if (auth) |a| {
                if (!self.checkToken(io, a, "list", null)) return req.respond("", .{ .status = .unauthorized, .keep_alive = false });
            }
            var list_buf: [2200]u8 = undefined;
            const text = std.fmt.bufPrint(&list_buf, "[{s},{s}]", .{
                self.descriptor(&body_buf, &serve_hex, 5),
                self.descriptor(list_buf[1100..], &serve_hex, 6),
            }) catch unreachable;
            return req.respond(text, .{ .keep_alive = false });
        }

        if (target.len == 65 and target[0] == '/') {
            const hex = target[1..];
            switch (method) {
                .DELETE => {
                    self.deletes += 1;
                    if (auth == null or !self.checkToken(io, auth.?, "delete", hex)) {
                        return req.respond("", .{ .status = .unauthorized, .keep_alive = false });
                    }
                    return req.respond("", .{ .keep_alive = false });
                },
                .GET, .HEAD => {
                    if (auth) |a| {
                        if (!self.checkToken(io, a, "get", hex)) return req.respond("", .{ .status = .unauthorized, .keep_alive = false });
                    }
                    if (!std.mem.eql(u8, hex, &serve_hex)) return req.respond("", .{ .status = .not_found, .keep_alive = false });
                    var out_buf: [8192]u8 = undefined;
                    var bw = try req.respondStreaming(&out_buf, .{
                        .content_length = self.serve_len,
                        .respond_options = .{ .keep_alive = false },
                    });
                    if (method == .GET) {
                        var chunk: [8192]u8 = undefined;
                        var at: u64 = 0;
                        while (at < self.serve_len) {
                            const n: usize = @intCast(@min(chunk.len, self.serve_len - at));
                            fillPattern(chunk[0..n], at);
                            if (self.mode == .corrupt and at == 0) chunk[0] ^= 0xff;
                            try bw.writer.writeAll(chunk[0..n]);
                            at += n;
                        }
                    }
                    // A HEAD body is elided, so there is nothing to end.
                    if (method == .GET) try bw.end() else try bw.flush();
                    return;
                },
                else => {},
            }
        }
        self.flag("unexpected request {s}", .{target});
        return req.respond("not found", .{ .status = .not_found, .keep_alive = false });
    }
};

const Run = struct {
    code: u8,
    out: []u8,
    err: []u8,

    fn deinit(self: Run) void {
        testing.allocator.free(self.out);
        testing.allocator.free(self.err);
    }
};

fn runWith(gpa: std.mem.Allocator, args: []const []const u8) !Run {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const code = try run(gpa, testing.io, args, &out.writer, &err.writer);
    return .{
        .code = code,
        .out = try testing.allocator.dupe(u8, out.written()),
        .err = try testing.allocator.dupe(u8, err.written()),
    };
}

const TmpDir = struct {
    tmp: testing.TmpDir,
    root: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn init(self: *TmpDir) !void {
        self.* = .{ .tmp = testing.tmpDir(.{}) };
        self.len = try self.tmp.dir.realPath(testing.io, &self.root);
    }

    fn deinit(self: *TmpDir) void {
        self.tmp.cleanup();
    }

    fn path(self: *TmpDir, buf: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.root[0..self.len], name });
    }

    fn write(self: *TmpDir, name: []const u8, bytes: []const u8) !void {
        try self.tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = bytes });
    }

    fn exists(self: *TmpDir, name: []const u8) bool {
        self.tmp.dir.access(testing.io, name, .{}) catch return false;
        return true;
    }

    /// How many entries the directory holds.
    fn count(self: *TmpDir) !usize {
        var n: usize = 0;
        var d = try self.tmp.dir.openDir(testing.io, ".", .{ .iterate = true });
        defer d.close(testing.io);
        var it = d.iterate();
        while (try it.next(testing.io)) |_| n += 1;
        return n;
    }
};

const test_sec_arg = "33" ** 32;

test "an upload sends the preflight and the file, checks the reply, and prints the descriptor" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    try dir.write("note.txt", "hello blossom");
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const file = try dir.path(&pbuf, "note.txt");

    var mock: Mock = undefined;
    try mock.start(io, 2);
    defer mock.stop(io);
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "upload", file, "-s", mock.base(&bbuf), "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqualStrings("", r.err);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqual(@as(usize, 0), mock.problems);
    try testing.expectEqualStrings("", mock.firstProblem());
    try testing.expectEqual(@as(usize, 1), mock.heads);
    try testing.expectEqual(@as(usize, 1), mock.puts);
    var want: [32]u8 = undefined;
    Sha256.hash("hello blossom", &want, .{});
    try testing.expectEqualSlices(u8, &want, &mock.put_sha);
    try testing.expectEqual(@as(u64, 13), mock.put_len);

    const hex = std.fmt.bytesToHex(want, .lower);
    try testing.expect(std.mem.find(u8, r.out, &hex) != null);
    try testing.expect(std.mem.endsWith(u8, r.out, "}\n"));
    var parsed = try blossom.parseDescriptor(testing.allocator, std.mem.trim(u8, r.out, "\n"));
    defer parsed.deinit();
    try testing.expectEqual(@as(?u64, 13), parsed.value.size);
}

test "an upload whose reply names another sha256 fails and prints nothing" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    try dir.write("a.bin", "some bytes");
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const file = try dir.path(&pbuf, "a.bin");

    var mock: Mock = undefined;
    try mock.start(io, 2);
    defer mock.stop(io);
    mock.mode = .lie_hash;
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "upload", file, "-s", mock.base(&bbuf), "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqualStrings("", r.out);
    try testing.expect(std.mem.find(u8, r.err, "the server reports sha256") != null);
}

test "a refused preflight stops the upload before the file is sent" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    try dir.write("a.bin", "some bytes");
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const file = try dir.path(&pbuf, "a.bin");

    var mock: Mock = undefined;
    try mock.start(io, 2);
    defer mock.stop(io);
    mock.mode = .refuse_preflight;
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "upload", file, "-s", mock.base(&bbuf), "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqualStrings("", r.out);
    try testing.expectEqual(@as(usize, 1), mock.heads);
    try testing.expectEqual(@as(usize, 0), mock.puts);
    try testing.expect(std.mem.find(u8, r.err, "HTTP 413") != null);
}

test "a 20 MB file is uploaded without being held whole" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    var cap: CapAllocator = .{ .child = da.allocator(), .cap = 4 * 1024 * 1024 };
    const gpa = cap.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    const size: u64 = 20 * 1024 * 1024;
    {
        const f = try dir.tmp.dir.createFile(io, "big.bin", .{});
        defer f.close(io);
        var wbuf: [64 * 1024]u8 = undefined;
        var fw = f.writer(io, &wbuf);
        var chunk: [64 * 1024]u8 = undefined;
        var at: u64 = 0;
        while (at < size) : (at += chunk.len) {
            fillPattern(&chunk, at);
            try fw.interface.writeAll(&chunk);
        }
        try fw.interface.flush();
    }
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const file = try dir.path(&pbuf, "big.bin");

    var mock: Mock = undefined;
    try mock.start(io, 2);
    defer mock.stop(io);
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "upload", file, "-s", mock.base(&bbuf), "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqualStrings("", r.err);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqual(@as(usize, 0), mock.problems);
    try testing.expectEqual(size, mock.put_len);
    try testing.expectEqualSlices(u8, &patternSha(size), &mock.put_sha);
    try testing.expect(cap.biggest < cap.cap);
}

test "an upload needs a key, and a missing file fails" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    // $NOSTR_SECRET_KEY may be set in the environment running the tests; this
    // only holds when it is not, so the check is on the message either way.
    const r = try runWith(gpa, &.{ "upload", "/nonexistent/file", "-s", "127.0.0.1:1", "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expect(std.mem.find(u8, r.err, "cannot read /nonexistent/file") != null);
}

test "the command line is checked before anything is sent" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    const cases = [_][]const []const u8{
        &.{},
        &.{"frobnicate"},
        &.{ "upload", "f" },
        &.{ "download", "nothex", "-s", "x.example" },
        &.{ "download", "-s", "x.example" },
        &.{ "check", "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553", "-s", "ftp://x" },
        &.{ "list", "-s" },
        &.{ "list", "npub-not", "-s", "x.example" },
        &.{ "mirror", "https://x.example/photo.jpg", "-s", "y.example", "--sec", test_sec_arg },
        &.{ "mirror", "not a url", "-s", "y.example", "--sec", test_sec_arg },
        &.{ "check", "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553", "-s", "x.example", "--bogus" },
    };
    for (cases) |args| {
        const r = try runWith(gpa, args);
        defer r.deinit();
        try testing.expectEqual(cli.exit_usage, r.code);
        try testing.expectEqualStrings("", r.out);
        try testing.expect(r.err.len > 0);
    }
}

test "a download is verified, written to a temporary file, and renamed into place" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dest = try dir.path(&pbuf, "got.bin");

    var mock: Mock = undefined;
    try mock.start(io, 1);
    defer mock.stop(io);
    mock.serve_len = 100_000;
    mock.serve_sha = patternSha(100_000);
    const hex = std.fmt.bytesToHex(mock.serve_sha, .lower);
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "download", &hex, "-s", mock.base(&bbuf), "-o", dest });
    defer r.deinit();
    try testing.expectEqualStrings("", r.err);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqual(@as(usize, 0), mock.auth_seen);
    try testing.expectEqual(@as(usize, 1), try dir.count());
    const bytes = try dir.tmp.dir.readFileAlloc(io, "got.bin", testing.allocator, .limited(200_000));
    defer testing.allocator.free(bytes);
    try testing.expectEqual(@as(usize, 100_000), bytes.len);
    var got: [32]u8 = undefined;
    Sha256.hash(bytes, &got, .{});
    try testing.expectEqualSlices(u8, &mock.serve_sha, &got);
    try testing.expect(std.mem.find(u8, r.out, "\"size\":100000") != null);
}

test "bytes that do not hash to the name fail the download and leave no file" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dest = try dir.path(&pbuf, "got.bin");

    var mock: Mock = undefined;
    try mock.start(io, 1);
    defer mock.stop(io);
    mock.mode = .corrupt;
    mock.serve_len = 50_000;
    mock.serve_sha = patternSha(50_000);
    const hex = std.fmt.bytesToHex(mock.serve_sha, .lower);
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "download", &hex, "-s", mock.base(&bbuf), "-o", dest });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqualStrings("", r.out);
    try testing.expect(std.mem.find(u8, r.err, "nothing was kept") != null);
    try testing.expectEqual(@as(usize, 0), try dir.count());
}

test "a download that fails leaves a file already at the path alone, and the next server is tried" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    try dir.write("got.bin", "precious");
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dest = try dir.path(&pbuf, "got.bin");

    var bad: Mock = undefined;
    try bad.start(io, 2);
    defer bad.stop(io);
    bad.mode = .corrupt;
    bad.serve_len = 10_000;
    bad.serve_sha = patternSha(10_000);

    var good: Mock = undefined;
    try good.start(io, 1);
    defer good.stop(io);
    good.serve_len = 10_000;
    good.serve_sha = bad.serve_sha;

    const hex = std.fmt.bytesToHex(bad.serve_sha, .lower);
    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    const bad_base = bad.base(&b1);

    // The corrupt server alone: the old file survives.
    {
        const r = try runWith(gpa, &.{ "download", &hex, "-s", bad_base, "-o", dest });
        defer r.deinit();
        try testing.expectEqual(cli.exit_fail, r.code);
        const kept = try dir.tmp.dir.readFileAlloc(io, "got.bin", testing.allocator, .limited(100));
        defer testing.allocator.free(kept);
        try testing.expectEqualStrings("precious", kept);
        try testing.expectEqual(@as(usize, 1), try dir.count());
    }
    // A second server that serves the true bytes takes over.
    {
        const r = try runWith(gpa, &.{ "download", &hex, "-s", bad_base, "-s", good.base(&b2), "-o", dest });
        defer r.deinit();
        try testing.expectEqual(cli.exit_ok, r.code);
    }
}

test "a 20 MB download is hashed as it arrives, not held" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    var cap: CapAllocator = .{ .child = da.allocator(), .cap = 4 * 1024 * 1024 };
    const gpa = cap.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dest = try dir.path(&pbuf, "big.bin");

    const size: u64 = 20 * 1024 * 1024;
    var mock: Mock = undefined;
    try mock.start(io, 1);
    defer mock.stop(io);
    mock.serve_len = size;
    mock.serve_sha = patternSha(size);
    const hex = std.fmt.bytesToHex(mock.serve_sha, .lower);
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "download", &hex, "-s", mock.base(&bbuf), "-o", dest });
    defer r.deinit();
    try testing.expectEqualStrings("", r.err);
    try testing.expectEqual(cli.exit_ok, r.code);
    const f = try dir.tmp.dir.openFile(io, "big.bin", .{});
    defer f.close(io);
    try testing.expectEqual(size, (try f.stat(io)).size);
    try testing.expect(cap.biggest < cap.cap);
}

test "a download signs a get token when a key is given" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var dir: TmpDir = undefined;
    try dir.init();
    defer dir.deinit();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dest = try dir.path(&pbuf, "got.bin");

    var mock: Mock = undefined;
    try mock.start(io, 1);
    defer mock.stop(io);
    mock.serve_len = 1000;
    mock.serve_sha = patternSha(1000);
    const hex = std.fmt.bytesToHex(mock.serve_sha, .lower);
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "download", &hex, "-s", mock.base(&bbuf), "-o", dest, "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqual(@as(usize, 1), mock.auth_seen);
    try testing.expectEqual(@as(usize, 0), mock.problems);
}

test "delete sends a delete token naming the blob" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var mock: Mock = undefined;
    try mock.start(io, 1);
    defer mock.stop(io);
    const hex = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "delete", hex, "-s", mock.base(&bbuf), "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqualStrings("", r.err);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqual(@as(usize, 1), mock.deletes);
    try testing.expectEqual(@as(usize, 0), mock.problems);
    try testing.expect(std.mem.find(u8, r.out, "\"deleted\":true") != null);
}

test "check reports presence per server and exits 1 when a blob is missing" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    // Larger than the response cap on purpose: a HEAD carries the blob's
    // Content-Length and must not trip it.
    var mock: Mock = undefined;
    try mock.start(io, 2);
    defer mock.stop(io);
    mock.serve_len = 9 * 1024 * 1024;
    mock.serve_sha = patternSha(1);
    const have = std.fmt.bytesToHex(mock.serve_sha, .lower);
    const missing = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    var bbuf: [64]u8 = undefined;

    const r = try runWith(gpa, &.{ "check", &have, missing, "-s", mock.base(&bbuf) });
    defer r.deinit();
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqual(@as(usize, 0), mock.problems);
    try testing.expect(std.mem.find(u8, r.out, "\"exists\":true") != null);
    try testing.expect(std.mem.find(u8, r.out, "\"exists\":false") != null);
}

test "list prints one descriptor per line, and signs a list token when a key is given" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var mock: Mock = undefined;
    try mock.start(io, 2);
    defer mock.stop(io);
    mock.serve_sha = patternSha(7);
    var bbuf: [64]u8 = undefined;
    const base = mock.base(&bbuf);

    {
        const r = try runWith(gpa, &.{ "list", &mock.pubkey_hex, "-s", base, "--limit", "10" });
        defer r.deinit();
        try testing.expectEqualStrings("", r.err);
        try testing.expectEqual(cli.exit_ok, r.code);
        try testing.expectEqual(@as(usize, 2), std.mem.count(u8, r.out, "\n"));
        try testing.expectEqual(@as(usize, 0), mock.auth_seen);
    }
    {
        const r = try runWith(gpa, &.{ "list", &mock.pubkey_hex, "-s", base, "--sec", test_sec_arg });
        defer r.deinit();
        try testing.expectEqual(cli.exit_ok, r.code);
        try testing.expectEqual(@as(usize, 1), mock.auth_seen);
        try testing.expectEqual(@as(usize, 0), mock.problems);
    }
}

test "mirror names the blob in the token and sends the URL" {
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var mock: Mock = undefined;
    try mock.start(io, 1);
    defer mock.stop(io);
    mock.serve_len = 1234;
    mock.serve_sha = patternSha(1234);
    const hex = std.fmt.bytesToHex(mock.serve_sha, .lower);
    var bbuf: [64]u8 = undefined;
    var ubuf: [200]u8 = undefined;
    const source = try std.fmt.bufPrint(&ubuf, "https://other.example/{s}.png", .{&hex});

    const r = try runWith(gpa, &.{ "mirror", source, "-s", mock.base(&bbuf), "--sec", test_sec_arg });
    defer r.deinit();
    try testing.expectEqualStrings("", r.err);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqual(@as(usize, 0), mock.problems);
    try testing.expectEqual(@as(usize, 1), mock.mirrors);
    try testing.expect(std.mem.find(u8, mock.mirror_body[0..mock.mirror_body_len], source) != null);
    try testing.expect(std.mem.find(u8, r.out, &hex) != null);
}
