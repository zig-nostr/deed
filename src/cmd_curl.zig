//! `deed curl`: the system `curl`, with a NIP-98 `Authorization` header added.
//!
//! deed does not reimplement curl. It reads just enough of curl's command line
//! to know the method, the URL and (when the body is written inline) the
//! body, signs a `kind:27235` event for that request, and runs the real curl
//! with `-H "Authorization: Nostr ..."` in front of everything else, which is
//! passed through untouched. curl's exit status is deed's.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");

const keys = nostr.keys;
const nip98 = nostr.nip98;

pub const summary = "run curl with a NIP-98 signed Authorization header";

pub const ready = true;

pub const usage =
    \\deed curl: run curl with a NIP-98 signed Authorization header
    \\
    \\Usage:
    \\  deed curl [--sec <key>] [curl arguments...]
    \\  deed curl help
    \\
    \\Signs a kind 27235 event for the request curl is about to make and adds
    \\it as an "Authorization: Nostr <base64>" header. Everything else is
    \\handed to the system curl as written, and curl's exit status is the exit
    \\status here. deed reads three things from the arguments:
    \\
    \\  method   -X or --request; otherwise POST when -d, --data*, --json or
    \\           -F is present, PUT for -T, HEAD for -I, and GET for the rest
    \\  URL      --url, or the first argument that is not an option; it must
    \\           be a full http:// or https:// URL
    \\  body     what -d, --data, --data-raw, --data-ascii, --data-binary and
    \\           --json carry inline; its sha256 goes in the event's payload
    \\           tag. A body read from a file (@name), encoded by
    \\           --data-urlencode or sent with -F or -T is not known to deed,
    \\           so no payload tag is added for it
    \\
    \\Options:
    \\  --sec <key>   the secret key to sign with (nsec1..., hex or ncryptsec1...).
    \\                Falls back to $NOSTR_SECRET_KEY. Not passed on to curl.
    \\
    \\The header carries the time it was signed, and servers accept it for a
    \\minute or so. It is visible to other users of the machine in the process
    \\list while curl runs.
    \\
    \\Examples:
    \\  deed curl https://example.com/api/me
    \\  deed curl -X PUT -d '{"a":1}' https://example.com/api/thing
    \\
;

/// What deed needs to know about a curl command line.
pub const Parsed = struct {
    /// The method curl will use, a slice of the arguments or a literal.
    method: []const u8,
    /// The URL, a slice of the arguments.
    url: []const u8,
    /// The inline body, owned, or null when there is none or deed cannot see
    /// all of it.
    body: ?[]u8,
    /// The value of `--sec`, if given.
    sec: ?[]const u8,
    /// The arguments to hand to curl: everything but deed's own `--sec`.
    forward: []const []const u8,

    pub fn deinit(self: *Parsed, gpa: std.mem.Allocator) void {
        if (self.body) |b| gpa.free(b);
        gpa.free(self.forward);
        self.* = undefined;
    }
};

pub const ParseError = error{
    /// `--sec` was the last argument.
    SecNeedsValue,
    /// There is no URL among the arguments.
    NoUrl,
    /// The URL has no http:// or https:// scheme.
    NotAbsoluteUrl,
} || std.mem.Allocator.Error;

/// Short options of curl that take a value.
const short_with_value = "AbcCdDeEFHKmoOPQrtTuUwxXyYz";

/// Long options of curl that take a value. One that is missing here is read
/// as a switch, which only matters if its value comes before the URL.
const long_with_value = [_][]const u8{
    "--request",      "--header",          "--data",           "--data-raw",
    "--data-ascii",   "--data-binary",     "--data-urlencode", "--json",
    "--user",         "--output",          "--user-agent",     "--referer",
    "--cookie",       "--cookie-jar",      "--form",           "--form-string",
    "--max-time",     "--connect-timeout", "--proxy",          "--cacert",
    "--cert",         "--key",             "--write-out",      "--upload-file",
    "--retry",        "--retry-delay",     "--retry-max-time", "--range",
    "--config",       "--dump-header",     "--resolve",        "--max-redirs",
    "--limit-rate",   "--interface",       "--proxy-user",     "--capath",
    "--connect-to",   "--http-version",    "--oauth2-bearer",  "--aws-sigv4",
    "--output-dir",   "--time-cond",       "--continue-at",    "--expect100-timeout",
    "--trace",        "--trace-ascii",     "--stderr",         "--unix-socket",
    "--proxy-header", "--cert-type",       "--key-type",       "--pass",
    "--ciphers",      "--tls-max",         "--tls13-ciphers",  "--noproxy",
    "--max-filesize", "--speed-limit",     "--speed-time",     "--url-query",
    "--variable",     "--rate",            "--parallel-max",   "--local-port",
    "--url",
};

fn longTakesValue(name: []const u8) bool {
    for (long_with_value) |l| {
        if (std.mem.eql(u8, name, l)) return true;
    }
    return false;
}

const Kind = enum { none, request, data, data_raw, data_binary, data_urlencode, json, form, upload, url };

fn longKind(name: []const u8) Kind {
    const table = [_]struct { []const u8, Kind }{
        .{ "--request", .request },
        .{ "--data", .data },
        .{ "--data-ascii", .data },
        .{ "--data-raw", .data_raw },
        .{ "--data-binary", .data_binary },
        .{ "--data-urlencode", .data_urlencode },
        .{ "--json", .json },
        .{ "--form", .form },
        .{ "--form-string", .form },
        .{ "--upload-file", .upload },
        .{ "--url", .url },
    };
    for (table) |e| {
        if (std.mem.eql(u8, name, e[0])) return e[1];
    }
    return .none;
}

fn shortKind(c: u8) Kind {
    return switch (c) {
        'X' => .request,
        'd' => .data,
        'F' => .form,
        'T' => .upload,
        else => .none,
    };
}

const Seen = struct {
    explicit: ?[]const u8 = null,
    url: ?[]const u8 = null,
    unknown_body: bool = false,
    data: bool = false,
    json: bool = false,
    form: bool = false,
    upload: bool = false,
    head: bool = false,
    get: bool = false,
};

/// Reads the method, URL and inline body out of curl's arguments. The result
/// borrows `args`.
pub fn parseArgs(gpa: std.mem.Allocator, args: []const []const u8) ParseError!Parsed {
    var forward: std.ArrayList([]const u8) = .empty;
    errdefer forward.deinit(gpa);
    var pieces: std.ArrayList([]const u8) = .empty;
    defer pieces.deinit(gpa);

    var seen: Seen = .{};
    var sec: ?[]const u8 = null;
    var only_args = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (only_args or a.len < 2 or a[0] != '-') {
            // A lone "-" is a value (stdin). curl takes the first plain
            // argument as the URL.
            if (seen.url == null and !(a.len == 1 and a[0] == '-')) seen.url = a;
            try forward.append(gpa, a);
            continue;
        }
        if (std.mem.eql(u8, a, "--")) {
            only_args = true;
            try forward.append(gpa, a);
            continue;
        }

        if (a[1] == '-') {
            if (std.mem.eql(u8, a, "--sec")) {
                // deed's own; curl never sees it.
                if (i + 1 >= args.len) return error.SecNeedsValue;
                i += 1;
                sec = args[i];
                continue;
            }
            if (std.mem.eql(u8, a, "--head")) seen.head = true;
            if (std.mem.eql(u8, a, "--get")) seen.get = true;
            try forward.append(gpa, a);
            if (!longTakesValue(a) or i + 1 >= args.len) continue;
            i += 1;
            try forward.append(gpa, args[i]);
            try take(gpa, longKind(a), args[i], &seen, &pieces);
            continue;
        }

        // A cluster of short options: -sSL, -XPOST, -d'a=b'.
        try forward.append(gpa, a);
        var j: usize = 1;
        while (j < a.len) : (j += 1) {
            const c = a[j];
            if (c == 'I') seen.head = true;
            if (c == 'G') seen.get = true;
            if (std.mem.indexOfScalar(u8, short_with_value, c) == null) continue;
            var value: []const u8 = undefined;
            if (j + 1 < a.len) {
                value = a[j + 1 ..];
            } else if (i + 1 < args.len) {
                i += 1;
                value = args[i];
                try forward.append(gpa, value);
            } else break;
            try take(gpa, shortKind(c), value, &seen, &pieces);
            break;
        }
    }

    const target = seen.url orelse return error.NoUrl;
    if (!std.ascii.startsWithIgnoreCase(target, "http://") and !std.ascii.startsWithIgnoreCase(target, "https://"))
        return error.NotAbsoluteUrl;

    const method: []const u8 = seen.explicit orelse
        if (seen.head) "HEAD" else if (seen.get) "GET" else if (seen.data or seen.json or seen.form) "POST" else if (seen.upload) "PUT" else "GET";

    // Only a body deed can read in full has a hash worth signing.
    var body: ?[]u8 = null;
    if ((seen.data or seen.json) and !seen.get and !seen.unknown_body and pieces.items.len > 0) {
        body = try std.mem.join(gpa, if (seen.json) "" else "&", pieces.items);
    }
    errdefer if (body) |b| gpa.free(b);

    return .{
        .method = method,
        .url = target,
        .body = body,
        .sec = sec,
        .forward = try forward.toOwnedSlice(gpa),
    };
}

fn take(
    gpa: std.mem.Allocator,
    kind: Kind,
    value: []const u8,
    seen: *Seen,
    pieces: *std.ArrayList([]const u8),
) std.mem.Allocator.Error!void {
    switch (kind) {
        .request => seen.explicit = value,
        .url => {
            if (seen.url == null) seen.url = value;
        },
        .data, .data_binary, .json => {
            if (kind == .json) seen.json = true else seen.data = true;
            // "@name" reads a file and "@-" stdin: deed cannot see the bytes.
            if (value.len > 0 and value[0] == '@') {
                seen.unknown_body = true;
            } else {
                try pieces.append(gpa, value);
            }
        },
        .data_raw => {
            seen.data = true;
            try pieces.append(gpa, value);
        },
        .data_urlencode => {
            seen.data = true;
            seen.unknown_body = true;
        },
        .form => {
            seen.form = true;
            seen.unknown_body = true;
        },
        .upload => {
            seen.upload = true;
            seen.unknown_body = true;
        },
        .none => {},
    }
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

/// The secret key from the flag or `$NOSTR_SECRET_KEY`, or null after saying
/// why there is none. A key nobody chose is never invented.
pub fn readSecret(
    gpa: std.mem.Allocator,
    verb: []const u8,
    flag: ?[]const u8,
    err: *std.Io.Writer,
) !?keys.SecretKey {
    const raw = flag orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.print("deed {s}: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n", .{verb});
        return null;
    };
    return keyinput.secretKey(gpa, raw) catch {
        try err.print("deed {s}: not a secret key (want nsec1... or 64 hex characters)\n", .{verb});
        return null;
    };
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 1 and cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    if (args.len == 0) {
        try err.writeAll("deed curl: needs a URL (see 'deed curl help')\n");
        return cli.exit_usage;
    }

    var parsed = parseArgs(gpa, args) catch |e| switch (e) {
        error.SecNeedsValue => {
            try err.writeAll("deed curl: --sec needs a key\n");
            return cli.exit_usage;
        },
        error.NoUrl => {
            try err.writeAll("deed curl: no URL among the arguments\n");
            return cli.exit_usage;
        },
        error.NotAbsoluteUrl => {
            try err.writeAll("deed curl: the URL must start with http:// or https:// so it can be signed as written\n");
            return cli.exit_usage;
        },
        error.OutOfMemory => return e,
    };
    defer parsed.deinit(gpa);

    const sk = (try readSecret(gpa, "curl", parsed.sec, err)) orelse return cli.exit_usage;
    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();
    const keypair = try signer.keyPairFromSecretKey(sk);

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const auth = try nip98.authHeader(gpa, signer, keypair, now, parsed.url, parsed.method, parsed.body, null);
    defer gpa.free(auth);
    const header = try std.fmt.allocPrint(gpa, "Authorization: {s}", .{auth});
    defer gpa.free(header);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ "curl", "-H", header });
    try argv.appendSlice(gpa, parsed.forward);

    return exec(io, argv.items, err);
}

/// Runs `argv` with the terminal as its streams and returns its exit status.
fn exec(io: std.Io, argv: []const []const u8, err: *std.Io.Writer) !u8 {
    var child = std.process.spawn(io, .{ .argv = argv }) catch |e| {
        if (e == error.FileNotFound) {
            try err.writeAll("deed curl: curl is not installed, or is not on the PATH\n");
        } else {
            try err.print("deed curl: could not run curl: {s}\n", .{@errorName(e)});
        }
        return cli.exit_fail;
    };
    const term = child.wait(io) catch |e| {
        try err.print("deed curl: waiting for curl failed: {s}\n", .{@errorName(e)});
        return cli.exit_fail;
    };
    return switch (term) {
        .exited => |code| code,
        else => blk: {
            try err.writeAll("deed curl: curl was stopped by a signal\n");
            break :blk cli.exit_fail;
        },
    };
}

// ---- tests ---------------------------------------------------------------

const testing = std.testing;
const Io = std.Io;
const http = std.http;

/// A loopback server for tests that records what one request carried: its
/// method, target, Authorization header and body. It answers every request
/// with `status` and `reply`.
pub const CaptureServer = struct {
    server: Io.net.Server,
    connections: usize,
    task: Io.Future(void),
    status: http.Status,
    reply: []const u8,

    method: [16]u8 = undefined,
    method_len: usize = 0,
    auth: [4096]u8 = undefined,
    auth_len: usize = 0,
    content_type: [128]u8 = undefined,
    content_type_len: usize = 0,
    body: [4096]u8 = undefined,
    body_len: usize = 0,

    pub fn start(self: *CaptureServer, io: Io, status: http.Status, reply: []const u8, connections: usize) !void {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        self.* = .{
            .server = try address.listen(io, .{ .reuse_address = true }),
            .connections = connections,
            .task = undefined,
            .status = status,
            .reply = reply,
        };
        errdefer self.server.deinit(io);
        self.task = try io.concurrent(serve, .{ self, io });
    }

    pub fn stop(self: *CaptureServer, io: Io) void {
        self.task.cancel(io);
        self.server.deinit(io);
    }

    pub fn url(self: *const CaptureServer, buf: []u8, path: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.server.socket.address.ip4.port, path });
    }

    pub fn sentMethod(self: *const CaptureServer) []const u8 {
        return self.method[0..self.method_len];
    }
    pub fn sentAuth(self: *const CaptureServer) []const u8 {
        return self.auth[0..self.auth_len];
    }
    pub fn sentContentType(self: *const CaptureServer) []const u8 {
        return self.content_type[0..self.content_type_len];
    }
    pub fn sentBody(self: *const CaptureServer) []const u8 {
        return self.body[0..self.body_len];
    }

    fn serve(self: *CaptureServer, io: Io) void {
        for (0..self.connections) |_| {
            const conn = self.server.accept(io) catch return;
            defer conn.close(io);
            self.handle(io, conn) catch {};
        }
    }

    fn handle(self: *CaptureServer, io: Io, conn: Io.net.Stream) !void {
        var rbuf: [8192]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var r = conn.reader(io, &rbuf);
        var w = conn.writer(io, &wbuf);
        var s = http.Server.init(&r.interface, &w.interface);
        var req = try s.receiveHead();

        const m = @tagName(req.head.method);
        @memcpy(self.method[0..m.len], m);
        self.method_len = m.len;
        self.auth_len = 0;
        self.content_type_len = 0;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
                const n = @min(h.value.len, self.auth.len);
                @memcpy(self.auth[0..n], h.value[0..n]);
                self.auth_len = n;
            } else if (std.ascii.eqlIgnoreCase(h.name, "content-type")) {
                const n = @min(h.value.len, self.content_type.len);
                @memcpy(self.content_type[0..n], h.value[0..n]);
                self.content_type_len = n;
            }
        }
        self.body_len = 0;
        if (req.head.method.requestHasBody()) {
            var scratch: [1024]u8 = undefined;
            const reader = req.readerExpectNone(&scratch);
            self.body_len = reader.readSliceShort(&self.body) catch 0;
        }
        try req.respond(self.reply, .{ .status = self.status, .keep_alive = false });
    }
};

test "the method, URL and body are read out of curl's arguments" {
    const gpa = testing.allocator;

    {
        var p = try parseArgs(gpa, &.{"https://example.com/a?b=1"});
        defer p.deinit(gpa);
        try testing.expectEqualStrings("GET", p.method);
        try testing.expectEqualStrings("https://example.com/a?b=1", p.url);
        try testing.expect(p.body == null);
    }
    {
        var p = try parseArgs(gpa, &.{ "-s", "-d", "a=1", "-d", "b=2", "https://example.com/x" });
        defer p.deinit(gpa);
        try testing.expectEqualStrings("POST", p.method);
        try testing.expectEqualStrings("a=1&b=2", p.body.?);
        try testing.expectEqual(@as(usize, 6), p.forward.len);
    }
    {
        var p = try parseArgs(gpa, &.{ "https://example.com/x", "-XPUT", "--data-raw", "@not-a-file" });
        defer p.deinit(gpa);
        try testing.expectEqualStrings("PUT", p.method);
        try testing.expectEqualStrings("@not-a-file", p.body.?);
    }
    {
        // A value that looks like a URL is a value, and the first plain
        // argument is the URL.
        var p = try parseArgs(gpa, &.{ "-H", "Referer: http://other.example/", "-sSL", "--request", "DELETE", "http://localhost:8080/r" });
        defer p.deinit(gpa);
        try testing.expectEqualStrings("DELETE", p.method);
        try testing.expectEqualStrings("http://localhost:8080/r", p.url);
        try testing.expect(p.body == null);
    }
    {
        var p = try parseArgs(gpa, &.{ "--url", "https://example.com/u", "--json", "{\"a\":1}" });
        defer p.deinit(gpa);
        try testing.expectEqualStrings("POST", p.method);
        try testing.expectEqualStrings("https://example.com/u", p.url);
        try testing.expectEqualStrings("{\"a\":1}", p.body.?);
    }
    {
        var p = try parseArgs(gpa, &.{ "-I", "https://example.com/" });
        defer p.deinit(gpa);
        try testing.expectEqualStrings("HEAD", p.method);
    }
    {
        // -G moves the data to the query string: a GET with no body.
        var p = try parseArgs(gpa, &.{ "-G", "-d", "q=1", "https://example.com/" });
        defer p.deinit(gpa);
        try testing.expectEqualStrings("GET", p.method);
        try testing.expect(p.body == null);
    }
    {
        // Bodies deed cannot read in full are not hashed.
        var f = try parseArgs(gpa, &.{ "-d", "@body.json", "https://example.com/" });
        defer f.deinit(gpa);
        try testing.expectEqualStrings("POST", f.method);
        try testing.expect(f.body == null);
        var u = try parseArgs(gpa, &.{ "--data-urlencode", "a=b c", "https://example.com/" });
        defer u.deinit(gpa);
        try testing.expect(u.body == null);
        var t = try parseArgs(gpa, &.{ "-T", "file.bin", "https://example.com/f" });
        defer t.deinit(gpa);
        try testing.expectEqualStrings("PUT", t.method);
        try testing.expect(t.body == null);
    }
}

test "--sec is deed's and is not passed on" {
    const gpa = testing.allocator;
    var p = try parseArgs(gpa, &.{ "--sec", "abc", "-s", "https://example.com/" });
    defer p.deinit(gpa);
    try testing.expectEqualStrings("abc", p.sec.?);
    try testing.expectEqual(@as(usize, 2), p.forward.len);
    try testing.expectEqualStrings("-s", p.forward[0]);

    try testing.expectError(error.SecNeedsValue, parseArgs(gpa, &.{"--sec"}));
}

test "a command line with no usable URL is refused" {
    const gpa = testing.allocator;
    try testing.expectError(error.NoUrl, parseArgs(gpa, &.{ "-s", "-o", "out" }));
    try testing.expectError(error.NotAbsoluteUrl, parseArgs(gpa, &.{"example.com/x"}));
    try testing.expectError(error.NotAbsoluteUrl, parseArgs(gpa, &.{"ftp://example.com/x"}));
}

pub const test_secret = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";

test "help prints the usage and no key is needed" {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(cli.exit_ok, try run(testing.allocator, testing.io, &.{"help"}, &out.writer, &err.writer));
    try testing.expect(std.mem.startsWith(u8, out.written(), "deed curl:"));
}

fn curlExists(io: Io) bool {
    var child = std.process.spawn(io, .{
        .argv = &.{ "curl", "--version" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    _ = child.wait(io) catch return false;
    return true;
}

/// Checks that what the server received carries a header that verifies for
/// this request and was signed by the test key.
pub fn expectSigned(io: Io, header: []const u8, url: []const u8, method: []const u8, body: ?[]const u8) !void {
    const gpa = testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const now = Io.Timestamp.now(io, .real).toSeconds();
    const pk = try nip98.verifyHeader(gpa, signer, header, .{
        .url = url,
        .method = method,
        .body = body,
        .now = now,
    });
    const sk = try nostr.hex.decodeFixed(32, test_secret);
    const kp = try signer.keyPairFromSecretKey(sk);
    try testing.expectEqualSlices(u8, &kp.public_key, &pk);
}

test "curl reaches the server with a header that verifies" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const io = testing.io;
    if (!curlExists(io)) return error.SkipZigTest;

    var srv: CaptureServer = undefined;
    try srv.start(io, .ok, "fine", 2);
    defer srv.stop(io);

    var ub: [64]u8 = undefined;
    const url = try srv.url(&ub, "/thing?x=1");

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();

    // A plain GET: no payload tag is checked.
    var code = try run(testing.allocator, io, &.{ "--sec", test_secret, "-s", "-o", "/dev/null", url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqualStrings("GET", srv.sentMethod());
    try expectSigned(io, srv.sentAuth(), url, "GET", null);

    // An inline body is hashed, and the method follows from -d.
    code = try run(testing.allocator, io, &.{ "--sec", test_secret, "-s", "-o", "/dev/null", "-d", "hello=world", url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqualStrings("POST", srv.sentMethod());
    try testing.expectEqualStrings("hello=world", srv.sentBody());
    try expectSigned(io, srv.sentAuth(), url, "POST", "hello=world");
    try testing.expectEqualStrings("", err.written());
}

test "curl's exit status is passed back" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const io = testing.io;
    if (!curlExists(io)) return error.SkipZigTest;

    var srv: CaptureServer = undefined;
    try srv.start(io, .not_found, "no", 1);
    defer srv.stop(io);
    var ub: [64]u8 = undefined;
    const url = try srv.url(&ub, "/missing");

    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    // --fail makes curl exit 22 on a 404.
    const code = try run(testing.allocator, io, &.{ "--sec", test_secret, "-s", "--fail", "-o", "/dev/null", url }, &out.writer, &err.writer);
    try testing.expectEqual(@as(u8, 22), code);
}
