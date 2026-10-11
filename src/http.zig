//! A small HTTP client over `std.http.Client`, for the verbs that talk to a
//! web server rather than a relay: NIP-11 documents, NIP-05 lookups, and later
//! NIP-98 and NIP-86 calls and blossom.
//!
//! What it adds to std, and why:
//!
//!  - An overall deadline. std has none, and a name lookup, a TLS handshake or
//!    a server that stops sending each wait forever. The request runs as a
//!    concurrent task beside a timer, and whichever finishes first wins.
//!  - A size cap on the response, enforced as bytes arrive rather than after.
//!  - Redirects followed by hand, so every hop is checked: a hop may never
//!    leave https for http, and a hop to another origin drops the credentials.
//!  - https only. Plain http is allowed for a loopback host, or when the
//!    caller says so with `allow_http`.
//!  - Optionally, `deny_private`: the host is resolved here, refused if any
//!    answer is a loopback, private, link-local, CGNAT, multicast or similar
//!    address, and the connection goes to the address that was checked, so a
//!    second lookup cannot answer differently. Every redirect hop is checked.
//!  - Errors in one small set, each with a plain sentence (`describe`).
//!
//! The status is returned, never turned into an error: a 404 with a body is
//! an answer, and a caller like `deed curl` wants it.

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const Uri = std.Uri;
const http = std.http;

pub const Method = http.Method;
pub const Header = http.Header;

pub const Error = error{
    /// The URL does not parse, or has no host.
    InvalidUrl,
    /// The scheme is neither http nor https.
    UnsupportedScheme,
    /// Plain http to a host that is not loopback, without `allow_http`, or a
    /// redirect from https to http.
    InsecureScheme,
    /// A header name or value that could split the request.
    InvalidHeader,
    /// A body was given for a method that carries none.
    BodyNotAllowed,
    TooManyRedirects,
    /// A redirect with no usable Location.
    RedirectInvalid,
    /// A redirect that would need the request body sent again from a stream.
    RedirectNeedsResend,
    ResponseTooLarge,
    /// The server compressed the body although `identity` was asked for.
    UnsupportedEncoding,
    TimedOut,
    HostNotFound,
    ConnectionRefused,
    ConnectFailed,
    TlsFailed,
    /// `deny_private` is set and the host resolves to a loopback, private,
    /// link-local or otherwise non-public address.
    PrivateAddress,
    /// The connection broke or the server's reply was not HTTP.
    RequestFailed,
    /// The writer that receives the body failed.
    SinkFailed,
    /// The runtime cannot run the request beside its timer.
    ConcurrencyUnavailable,
    OutOfMemory,
    Canceled,
};

/// What goes in the request body.
pub const Body = union(enum) {
    none,
    bytes: []const u8,
    /// Exactly `len` bytes read from `reader`. Not resendable, so a redirect
    /// that needs them again fails with `RedirectNeedsResend`.
    stream: struct { reader: *Io.Reader, len: u64 },
};

/// Stands in for DNS: fills `out` with the addresses of `host` (port set to
/// `port`) and returns how many, or null when the name is unknown. For tests.
pub const Resolver = *const fn (host: []const u8, port: u16, out: *[16]Io.net.IpAddress) ?usize;

pub const Options = struct {
    method: Method = .GET,
    /// Sent as given (Accept, Authorization, ...). Authorization, Cookie and
    /// Proxy-Authorization are dropped when a redirect leaves the origin.
    headers: []const Header = &.{},
    body: Body = .none,
    content_type: ?[]const u8 = null,
    user_agent: []const u8 = "deed",
    /// For the whole exchange, redirects included. 0 means no deadline.
    timeout_ms: u64 = 15_000,
    /// Most body bytes accepted.
    max_bytes: usize = 4 * 1024 * 1024,
    /// 0 treats every redirect as an error.
    max_redirects: u8 = 3,
    /// Permit plain http to any host. Loopback hosts never need it.
    allow_http: bool = false,
    /// Refuse a host that resolves to a loopback, private, link-local,
    /// unique-local, CGNAT, unspecified or multicast address (IPv4-mapped
    /// forms included), on the first request and on every redirect hop, and
    /// connect to the address that passed. For URLs that come from untrusted
    /// data, where a crafted name could otherwise reach the local network.
    deny_private: bool = false,
    /// Replaces DNS. Setting it also makes the connection go to the address
    /// it returned. For tests.
    resolver: ?Resolver = null,
};

/// A response held in memory.
pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn ok(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn deinit(self: *Response, gpa: std.mem.Allocator) void {
        gpa.free(self.body);
        self.* = undefined;
    }
};

/// Requests `url` and returns the status and the body, which the caller owns.
pub fn fetch(gpa: std.mem.Allocator, io: Io, url: []const u8, opts: Options) Error!Response {
    var sink: Io.Writer.Allocating = .init(gpa);
    errdefer sink.deinit();
    const status = try fetchTo(gpa, io, url, opts, &sink.writer);
    return .{ .status = status, .body = sink.toOwnedSlice() catch return error.OutOfMemory };
}

const Arrival = union(enum) {
    done: Error!u16,
    timer: Io.Cancelable!void,
};

/// Requests `url` and streams the body to `sink`, returning the status. The
/// sink may already hold part of a body when this fails, for a body that
/// arrives and then runs past `max_bytes` or the deadline.
pub fn fetchTo(gpa: std.mem.Allocator, io: Io, url: []const u8, opts: Options, sink: *Io.Writer) Error!u16 {
    if (opts.timeout_ms == 0) return run(gpa, io, url, opts, sink);

    var buf: [2]Arrival = undefined;
    var sel = Io.Select(Arrival).init(io, &buf);
    // `concurrent`, never `async`: past its limit `async` runs inline, and an
    // inline request is the unbounded wait this exists to prevent.
    sel.concurrent(.done, run, .{ gpa, io, url, opts, sink }) catch return error.ConcurrencyUnavailable;
    sel.concurrent(.timer, Io.sleep, .{ io, Io.Duration.fromMilliseconds(@intCast(opts.timeout_ms)), .awake }) catch {
        while (sel.cancel()) |_| {}
        return error.ConcurrencyUnavailable;
    };

    const first = sel.await() catch |e| {
        while (sel.cancel()) |_| {}
        return switch (e) {
            error.Canceled => error.Canceled,
        };
    };
    // Cancelling joins the other task, so nothing runs against `sink` or
    // `url` once this returns.
    while (sel.cancel()) |_| {}
    return switch (first) {
        .done => |r| r,
        .timer => error.TimedOut,
    };
}

fn run(gpa: std.mem.Allocator, io: Io, url: []const u8, o: Options, sink: *Io.Writer) Error!u16 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for (o.headers) |h| try checkHeader(h);
    if (o.content_type) |ct| try checkValue(ct);
    try checkValue(o.user_agent);

    var client: http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    var uri = Uri.parse(url) catch return error.InvalidUrl;
    const origin = try originOf(arena, uri);
    var method = o.method;
    var body = o.body;
    var hops: u8 = 0;

    while (true) {
        try checkScheme(uri, o.allow_http);
        if (body != .none and !method.requestHasBody()) return error.BodyNotAllowed;

        const same_origin = try originMatches(arena, uri, origin);
        var extra: std.ArrayList(Header) = .empty;
        for (o.headers) |h| {
            if (!same_origin and isCredential(h.name)) continue;
            try extra.append(arena, h);
        }

        const pinned: ?*http.Client.Connection = if (o.deny_private or o.resolver != null)
            try pinConnection(&client, io, uri, o)
        else
            null;
        var req = client.request(method, uri, .{
            .connection = pinned,
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{
                .accept_encoding = .{ .override = "identity" },
                .user_agent = .{ .override = o.user_agent },
                .content_type = if (o.content_type) |ct| .{ .override = ct } else .default,
            },
            .extra_headers = extra.items,
        }) catch |e| {
            if (pinned) |c| {
                c.closing = true;
                client.connection_pool.release(c, io);
            }
            return mapError(e);
        };
        defer req.deinit();

        sendRequest(&req, method, body) catch |e| return mapError(e);

        var response = req.receiveHead(&.{}) catch |e| return mapError(e);
        const status = @intFromEnum(response.head.status);

        if (isRedirect(response.head.status)) {
            if (hops >= o.max_redirects) return error.TooManyRedirects;
            hops += 1;
            const location = response.head.location orelse return error.RedirectInvalid;
            const dest = try arena.alloc(u8, location.len);
            @memcpy(dest, location);
            var aux: []u8 = dest;
            const next = uri.resolveInPlace(dest.len, &aux) catch return error.RedirectInvalid;

            // A 303, and a 301 or 302 answering a POST, turn into a GET with
            // no body. A 307 or 308 repeats the request as it was.
            switch (response.head.status) {
                .see_other => {
                    method = .GET;
                    body = .none;
                },
                .moved_permanently, .found => if (method == .POST) {
                    method = .GET;
                    body = .none;
                },
                else => {},
            }
            if (body == .stream) return error.RedirectNeedsResend;
            // Resolved against the previous URI before the check, so a
            // relative Location cannot dodge it.
            if (std.ascii.eqlIgnoreCase(uri.scheme, "https") and std.ascii.eqlIgnoreCase(next.scheme, "http"))
                return error.InsecureScheme;
            uri = next;
            continue;
        }

        if (response.head.content_encoding != .identity) return error.UnsupportedEncoding;
        if (response.head.content_length) |n| {
            if (n > o.max_bytes) return error.ResponseTooLarge;
        }

        var transfer: [1024]u8 = undefined;
        const reader = response.reader(&transfer);
        try drain(reader, sink, o.max_bytes, &response);
        return status;
    }
}

/// Resolves the host of `uri`, applies `deny_private`, and opens a connection
/// to one of the addresses that was checked. TLS still verifies the name.
fn pinConnection(client: *http.Client, io: Io, uri: Uri, o: Options) Error!*http.Client.Connection {
    var host_buf: [Io.net.HostName.max_len]u8 = undefined;
    const raw = (uri.getHost(&host_buf) catch return error.InvalidUrl).bytes;
    const host = if (raw.len >= 2 and raw[0] == '[' and raw[raw.len - 1] == ']') raw[1 .. raw.len - 1] else raw;
    const port = portOf(uri);
    const protocol: http.Client.Protocol = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) .tls else .plain;

    var addrs: [16]Io.net.IpAddress = undefined;
    var n: usize = 0;
    if (Io.net.IpAddress.parse(host, port)) |a| {
        addrs[0] = a;
        n = 1;
    } else |_| if (o.resolver) |r| {
        n = r(host, port, &addrs) orelse return error.HostNotFound;
    } else {
        n = try lookupAddresses(io, host, port, &addrs);
    }
    if (n == 0) return error.HostNotFound;
    if (o.deny_private) {
        for (addrs[0..n]) |a| if (isPrivateAddress(a)) return error.PrivateAddress;
    }

    // request() prepares the certificate bundle, but only after the
    // connection it is handed exists, and a TLS connection needs it first.
    if (protocol == .tls) try prepareTls(client, io);

    var last: Error = error.ConnectFailed;
    for (addrs[0..n]) |a| {
        var text_buf: [48]u8 = undefined;
        const text = addressText(&text_buf, a);
        return client.connectTcpOptions(.{
            .host = .{ .bytes = text },
            .port = port,
            .protocol = protocol,
            .proxied_host = .{ .bytes = host },
            .proxied_port = port,
        }) catch |e| {
            last = mapError(e);
            if (last == error.Canceled or last == error.OutOfMemory) return last;
            continue;
        };
    }
    return last;
}

fn lookupAddresses(io: Io, host: []const u8, port: u16, out: *[16]Io.net.IpAddress) Error!usize {
    const name = Io.net.HostName.init(host) catch return error.InvalidUrl;
    var qbuf: [32]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&qbuf);
    var future = io.async(Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = port } });
    var n: usize = 0;
    while (queue.getOne(io)) |r| switch (r) {
        .address => |a| {
            if (n < out.len) {
                out[n] = a;
                n += 1;
            }
        },
        .canonical_name => {},
    } else |e| switch (e) {
        error.Canceled => {
            future.cancel(io) catch {};
            return error.Canceled;
        },
        error.Closed => {},
    }
    future.await(io) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => if (n == 0) return error.HostNotFound,
    };
    return n;
}

fn prepareTls(client: *http.Client, io: Io) Error!void {
    {
        client.ca_bundle_lock.lockShared(io) catch return error.Canceled;
        defer client.ca_bundle_lock.unlockShared(io);
        if (client.now != null) return;
    }
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(client.allocator);
    const now = Io.Clock.real.now(io);
    bundle.rescan(client.allocator, io, now) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => return error.TlsFailed,
    };
    client.ca_bundle_lock.lock(io) catch return error.Canceled;
    defer client.ca_bundle_lock.unlock(io);
    client.now = now;
    std.mem.swap(std.crypto.Certificate.Bundle, &client.ca_bundle, &bundle);
}

/// A literal the connect path parses back to the same address, without the
/// port and without brackets.
fn addressText(buf: *[48]u8, a: Io.net.IpAddress) []const u8 {
    switch (a) {
        .ip4 => |v| return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3] }) catch unreachable,
        .ip6 => |v| {
            var w: Io.Writer = .fixed(buf);
            for (0..8) |i| {
                if (i != 0) w.writeByte(':') catch unreachable;
                const g = std.mem.readInt(u16, v.bytes[i * 2 ..][0..2], .big);
                w.print("{x}", .{g}) catch unreachable;
            }
            return w.buffered();
        },
    }
}

/// True for an address a public name should never lead to: loopback, private
/// (10/8, 172.16/12, 192.168/16), link-local, unique-local, CGNAT,
/// unspecified, multicast and reserved ranges, and the IPv4-mapped, NAT64 and
/// 6to4 forms that carry one of those.
pub fn isPrivateAddress(a: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |v| isPrivate4(v.bytes),
        .ip6 => |v| isPrivate6(v.bytes),
    };
}

fn isPrivate4(b: [4]u8) bool {
    if (b[0] == 0 or b[0] == 10 or b[0] == 127) return true;
    if (b[0] == 169 and b[1] == 254) return true;
    if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return true;
    if (b[0] == 192 and b[1] == 168) return true;
    if (b[0] == 100 and b[1] >= 64 and b[1] <= 127) return true;
    return b[0] >= 224;
}

fn isPrivate6(b: [16]u8) bool {
    const zeros10 = [_]u8{0} ** 10;
    if (std.mem.eql(u8, b[0..10], &zeros10)) {
        // ::, ::1, ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible).
        if (b[10] == 0 and b[11] == 0) {
            if (std.mem.eql(u8, b[12..15], &[_]u8{ 0, 0, 0 })) return true;
            return isPrivate4(b[12..16].*);
        }
        if (b[10] == 0xff and b[11] == 0xff) return isPrivate4(b[12..16].*);
    }
    if (b[0] == 0x00 and b[1] == 0x64 and b[2] == 0xff and b[3] == 0x9b and
        std.mem.eql(u8, b[4..12], &[_]u8{0} ** 8)) return isPrivate4(b[12..16].*);
    if (b[0] == 0x20 and b[1] == 0x02) return isPrivate4(b[2..6].*);
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true;
    if ((b[0] & 0xfe) == 0xfc) return true;
    return b[0] == 0xff;
}

fn sendRequest(req: *http.Client.Request, method: Method, body: Body) !void {
    if (!method.requestHasBody()) return req.sendBodiless();
    const len: u64 = switch (body) {
        .none => 0,
        .bytes => |b| b.len,
        .stream => |s| s.len,
    };
    req.transfer_encoding = .{ .content_length = len };
    var buffer: [1024]u8 = undefined;
    var bw = try req.sendBody(&buffer);
    switch (body) {
        .none => {},
        .bytes => |b| try bw.writer.writeAll(b),
        .stream => |s| s.reader.streamExact64(&bw.writer, s.len) catch return error.WriteFailed,
    }
    try bw.end();
    try req.connection.?.flush();
}

/// Copies the body to `sink`, never taking in more than `max` bytes.
fn drain(reader: *Io.Reader, sink: *Io.Writer, max: usize, response: *http.Client.Response) Error!void {
    var total: usize = 0;
    while (true) {
        if (total == max) {
            // Full. One more byte means the body is over the cap; the end of
            // the stream means it fit exactly.
            _ = reader.peekByte() catch |e| switch (e) {
                error.EndOfStream => return,
                error.ReadFailed => return bodyFailure(response),
            };
            return error.ResponseTooLarge;
        }
        const n = reader.stream(sink, .limited(max - total)) catch |e| switch (e) {
            error.EndOfStream => return,
            error.ReadFailed => return bodyFailure(response),
            error.WriteFailed => return error.SinkFailed,
        };
        total += n;
    }
}

fn bodyFailure(response: *http.Client.Response) Error {
    _ = response;
    return error.RequestFailed;
}

fn isRedirect(s: http.Status) bool {
    return switch (s) {
        .moved_permanently, .found, .see_other, .temporary_redirect, .permanent_redirect => true,
        else => false,
    };
}

fn isCredential(name: []const u8) bool {
    const names = [_][]const u8{ "authorization", "cookie", "proxy-authorization" };
    for (names) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    return false;
}

fn checkValue(v: []const u8) Error!void {
    for (v) |c| if (c == '\r' or c == '\n' or c == 0) return error.InvalidHeader;
}

fn checkHeader(h: Header) Error!void {
    if (h.name.len == 0 or std.mem.indexOfScalar(u8, h.name, ':') != null) return error.InvalidHeader;
    try checkValue(h.name);
    try checkValue(h.value);
}

const Origin = struct {
    https: bool,
    host: []const u8,
    port: u16,
};

fn hostText(arena: std.mem.Allocator, uri: Uri) Error![]const u8 {
    var buf: [Io.net.HostName.max_len]u8 = undefined;
    const h = uri.getHost(&buf) catch return error.InvalidUrl;
    return arena.dupe(u8, h.bytes);
}

fn portOf(uri: Uri) u16 {
    return uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
}

fn originOf(arena: std.mem.Allocator, uri: Uri) Error!Origin {
    return .{
        .https = std.ascii.eqlIgnoreCase(uri.scheme, "https"),
        .host = try hostText(arena, uri),
        .port = portOf(uri),
    };
}

fn originMatches(arena: std.mem.Allocator, uri: Uri, o: Origin) Error!bool {
    const other = try originOf(arena, uri);
    return other.https == o.https and other.port == o.port and std.ascii.eqlIgnoreCase(other.host, o.host);
}

fn checkScheme(uri: Uri, allow_http: bool) Error!void {
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedScheme;
    if (allow_http) return;
    var buf: [Io.net.HostName.max_len]u8 = undefined;
    const h = uri.getHost(&buf) catch return error.InvalidUrl;
    if (!isLoopbackHost(h.bytes)) return error.InsecureScheme;
}

/// True for `localhost`, an address in 127.0.0.0/8, and `::1`.
pub fn isLoopbackHost(name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, "localhost")) return true;
    var t = name;
    if (t.len >= 2 and t[0] == '[' and t[t.len - 1] == ']') t = t[1 .. t.len - 1];
    const addr = Io.net.IpAddress.parse(t, 0) catch return false;
    return switch (addr) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, a.bytes[0..15], &[_]u8{0} ** 15) and a.bytes[15] == 1,
    };
}

fn mapError(e: anyerror) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.UnsupportedUriScheme => error.UnsupportedScheme,
        error.UriMissingHost => error.InvalidUrl,
        error.ConnectionRefused => error.ConnectionRefused,
        error.UnknownHostName,
        error.TemporaryNameServerFailure,
        error.NameServerFailure,
        error.HostLacksNetworkAddresses,
        => error.HostNotFound,
        error.CertificateBundleLoadFailure,
        error.TlsInitializationFailed,
        => error.TlsFailed,
        error.HttpContentEncodingUnsupported => error.UnsupportedEncoding,
        else => if (std.mem.startsWith(u8, @errorName(e), "Tls") or
            std.mem.startsWith(u8, @errorName(e), "Certificate"))
            error.TlsFailed
        else if (isConnectName(@errorName(e)))
            error.ConnectFailed
        else
            error.RequestFailed,
    };
}

fn isConnectName(name: []const u8) bool {
    const names = [_][]const u8{
        "NetworkUnreachable",       "ConnectionTimedOut",    "AddressUnavailable",
        "AddressFamilyUnsupported", "ConnectionResetByPeer", "HostUnreachable",
        "NetworkDown",              "SystemResources",       "ProcessFdQuotaExceeded",
        "SystemFdQuotaExceeded",    "AccessDenied",          "ProtocolUnsupportedBySystem",
        "SocketModeUnsupported",    "OptionUnsupported",
    };
    for (names) |n| if (std.mem.eql(u8, name, n)) return true;
    return false;
}

/// A sentence for an error, for a message of the form `<url>: <sentence>`.
pub fn describe(e: Error) []const u8 {
    return switch (e) {
        error.InvalidUrl => "not a valid URL",
        error.UnsupportedScheme => "only http and https URLs are supported",
        error.InsecureScheme => "refusing plain http (https is required unless the host is local)",
        error.InvalidHeader => "a header contains a line break or is empty",
        error.BodyNotAllowed => "this method carries no body",
        error.TooManyRedirects => "redirected more often than allowed",
        error.RedirectInvalid => "redirected without a usable Location",
        error.RedirectNeedsResend => "redirected, and the body cannot be sent again",
        error.ResponseTooLarge => "the response is larger than the size limit",
        error.UnsupportedEncoding => "the server compressed the response",
        error.TimedOut => "timed out",
        error.HostNotFound => "could not find the host",
        error.ConnectionRefused => "connection refused",
        error.ConnectFailed => "could not connect",
        error.TlsFailed => "the TLS handshake failed",
        error.PrivateAddress => "the host resolves to a local or private address",
        error.RequestFailed => "the connection broke or the reply was not HTTP",
        error.SinkFailed => "could not write the response",
        error.ConcurrencyUnavailable => "cannot run the request with a deadline here",
        error.OutOfMemory => "out of memory",
        error.Canceled => "canceled",
    };
}

// ---- tests ---------------------------------------------------------------

/// A server on loopback for tests: each connection is one request, answered
/// from `routes`, and then the connection ends.
pub const TestServer = struct {
    pub const Route = struct {
        /// The request path, without the query.
        path: []const u8,
        status: http.Status = .ok,
        body: []const u8 = "",
        /// When set, the body is this many 'a' bytes instead.
        fill: usize = 0,
        location: ?[]const u8 = null,
        /// Waits this long before answering.
        delay_ms: u64 = 0,
        /// Answers `yes` or `no` for whether an Authorization header came in.
        echo_auth: bool = false,
    };

    server: Io.net.Server,
    routes: []const Route,
    connections: usize,
    task: Io.Future(void),

    pub fn start(self: *TestServer, io: Io, routes: []const Route, connections: usize) !void {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        self.* = .{
            .server = try address.listen(io, .{ .reuse_address = true }),
            .routes = routes,
            .connections = connections,
            .task = undefined,
        };
        errdefer self.server.deinit(io);
        self.task = try io.concurrent(serve, .{ self, io });
    }

    pub fn stop(self: *TestServer, io: Io) void {
        self.task.cancel(io);
        self.server.deinit(io);
    }

    pub fn port(self: *const TestServer) u16 {
        return self.server.socket.address.ip4.port;
    }

    /// `http://127.0.0.1:<port><path>` in `buf`.
    pub fn url(self: *const TestServer, buf: []u8, path: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.port(), path });
    }

    fn serve(self: *TestServer, io: Io) void {
        for (0..self.connections) |_| {
            const conn = self.server.accept(io) catch return;
            defer conn.close(io);
            self.handle(io, conn) catch {};
        }
    }

    fn handle(self: *TestServer, io: Io, conn: Io.net.Stream) !void {
        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var r = conn.reader(io, &rbuf);
        var w = conn.writer(io, &wbuf);
        var s = http.Server.init(&r.interface, &w.interface);
        var req = try s.receiveHead();

        var target = req.head.target;
        if (std.mem.indexOfScalar(u8, target, '?')) |q| target = target[0..q];

        for (self.routes) |route| {
            if (!std.mem.eql(u8, route.path, target)) continue;
            if (route.delay_ms != 0) try io.sleep(.fromMilliseconds(@intCast(route.delay_ms)), .awake);

            var has_auth = false;
            var it = req.iterateHeaders();
            while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "authorization")) has_auth = true;
            }

            var extra: [1]Header = undefined;
            var n: usize = 0;
            if (route.location) |loc| {
                extra[n] = .{ .name = "Location", .value = loc };
                n += 1;
            }
            var content: []const u8 = route.body;
            if (route.echo_auth) content = if (has_auth) "yes" else "no";
            if (route.fill != 0) {
                const big = try std.heap.page_allocator.alloc(u8, route.fill);
                defer std.heap.page_allocator.free(big);
                @memset(big, 'a');
                try req.respond(big, .{ .status = route.status, .keep_alive = false, .extra_headers = extra[0..n] });
                return;
            }
            try req.respond(content, .{ .status = route.status, .keep_alive = false, .extra_headers = extra[0..n] });
            return;
        }
        try req.respond("not found", .{ .status = .not_found, .keep_alive = false });
    }
};

/// Not `std.testing.allocator`: a request that times out is cancelled, and
/// the stack capture that allocator does can swallow the cancel on macOS,
/// which makes the join wait forever.
pub const TestAllocator = std.heap.DebugAllocator(.{ .stack_trace_frames = 0 });

test "a GET returns the status and the body" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/hello", .body = "{\"ok\":true}" }}, 1);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    var res = try fetch(gpa, io, try srv.url(&buf, "/hello"), .{});
    defer res.deinit(gpa);
    try std.testing.expect(res.ok());
    try std.testing.expectEqualStrings("{\"ok\":true}", res.body);
}

test "an error status is returned, not raised" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{}, 1);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    var res = try fetch(gpa, io, try srv.url(&buf, "/missing"), .{});
    defer res.deinit(gpa);
    try std.testing.expectEqual(@as(u16, 404), res.status);
    try std.testing.expect(!res.ok());
}

test "a response over the size cap is refused, and one at the cap is kept" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/big", .fill = 100_000 }}, 3);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    const url = try srv.url(&buf, "/big");
    try std.testing.expectError(error.ResponseTooLarge, fetch(gpa, io, url, .{ .max_bytes = 1000 }));
    try std.testing.expectError(error.ResponseTooLarge, fetch(gpa, io, url, .{ .max_bytes = 99_999 }));
    var exact = try fetch(gpa, io, url, .{ .max_bytes = 100_000 });
    defer exact.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 100_000), exact.body.len);
}

test "the deadline ends a server that never answers" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/slow", .delay_ms = 20_000 }}, 1);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    const started = Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(
        error.TimedOut,
        fetch(gpa, io, try srv.url(&buf, "/slow"), .{ .timeout_ms = 300 }),
    );
    const took = started.untilNow(io).raw.toMilliseconds();
    try std.testing.expect(took < 5000);
}

test "a redirect is followed within the limit and refused past it" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{
        .{ .path = "/a", .status = .found, .location = "/b" },
        .{ .path = "/b", .body = "arrived" },
        .{ .path = "/loop", .status = .found, .location = "/loop" },
    }, 8);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    var res = try fetch(gpa, io, try srv.url(&buf, "/a"), .{});
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("arrived", res.body);

    try std.testing.expectError(error.TooManyRedirects, fetch(gpa, io, try srv.url(&buf, "/a"), .{ .max_redirects = 0 }));
    try std.testing.expectError(error.TooManyRedirects, fetch(gpa, io, try srv.url(&buf, "/loop"), .{}));
}

test "a redirect to plain http on another host is refused" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/away", .status = .found, .location = "http://example.com/steal" }}, 1);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.InsecureScheme, fetch(gpa, io, try srv.url(&buf, "/away"), .{}));
}

test "plain http to a host that is not loopback needs allow_http" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    try std.testing.expectError(error.InsecureScheme, fetch(gpa, io, "http://example.com/", .{}));
    try std.testing.expectError(error.UnsupportedScheme, fetch(gpa, io, "ftp://example.com/", .{}));
    try std.testing.expectError(error.InvalidUrl, fetch(gpa, io, "not a url", .{}));
}

test "credentials are dropped when a redirect leaves the origin" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    var other: [64]u8 = undefined;
    // The same server under another name: a different origin as far as the
    // client can tell, and still loopback, so plain http is allowed.
    const same_port = try std.fmt.bufPrint(&other, "http://localhost:{d}/echo", .{0});
    _ = same_port;
    try srv.start(io, &.{.{ .path = "/echo", .echo_auth = true }}, 3);
    defer srv.stop(io);

    var loc: [64]u8 = undefined;
    const to_name = try std.fmt.bufPrint(&loc, "http://localhost:{d}/echo", .{srv.port()});
    var routes = [_]TestServer.Route{
        .{ .path = "/hop", .status = .found, .location = to_name },
        .{ .path = "/echo", .echo_auth = true },
    };
    srv.routes = &routes;

    const auth = [_]Header{.{ .name = "Authorization", .value = "Nostr abc" }};
    var buf: [64]u8 = undefined;

    var direct = try fetch(gpa, io, try srv.url(&buf, "/echo"), .{ .headers = &auth });
    defer direct.deinit(gpa);
    try std.testing.expectEqualStrings("yes", direct.body);

    var hopped = try fetch(gpa, io, try srv.url(&buf, "/hop"), .{ .headers = &auth });
    defer hopped.deinit(gpa);
    try std.testing.expectEqualStrings("no", hopped.body);
}

test "a header that could split the request is refused" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    const bad = [_]Header{.{ .name = "Accept", .value = "x\r\nX-Evil: 1" }};
    try std.testing.expectError(error.InvalidHeader, fetch(gpa, io, "http://127.0.0.1:1/", .{ .headers = &bad }));
}

test "a POST sends its body" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/post", .body = "got it" }}, 2);
    defer srv.stop(io);

    var buf: [64]u8 = undefined;
    var res = try fetch(gpa, io, try srv.url(&buf, "/post"), .{
        .method = .POST,
        .body = .{ .bytes = "{\"a\":1}" },
        .content_type = "application/json",
    });
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("got it", res.body);

    try std.testing.expectError(error.BodyNotAllowed, fetch(gpa, io, try srv.url(&buf, "/post"), .{
        .body = .{ .bytes = "x" },
    }));
}

test "loopback hosts" {
    try std.testing.expect(isLoopbackHost("localhost"));
    try std.testing.expect(isLoopbackHost("127.0.0.1"));
    try std.testing.expect(isLoopbackHost("127.1.2.3"));
    try std.testing.expect(isLoopbackHost("[::1]"));
    try std.testing.expect(isLoopbackHost("::1"));
    try std.testing.expect(!isLoopbackHost("example.com"));
    try std.testing.expect(!isLoopbackHost("128.0.0.1"));
    try std.testing.expect(!isLoopbackHost("localhost.example.com"));
}

fn ip(text: []const u8) Io.net.IpAddress {
    return Io.net.IpAddress.parse(text, 80) catch unreachable;
}

test "private, loopback and reserved addresses are denied, public ones are not" {
    const denied = [_][]const u8{
        "127.0.0.1",       "127.9.9.9",          "10.0.0.1",        "172.16.0.1",
        "172.31.255.1",    "192.168.1.1",        "169.254.169.254", "100.64.0.1",
        "100.127.0.1",     "0.0.0.0",            "224.0.0.1",       "255.255.255.255",
        "::",              "::1",                "fe80::1",         "febf::1",
        "fc00::1",         "fd12:3456::1",       "ff02::1",         "::ffff:127.0.0.1",
        "::ffff:10.1.2.3", "::ffff:192.168.0.1", "64:ff9b::7f00:1", "2002:c0a8:0101::1",
    };
    for (denied) |t| try std.testing.expect(isPrivateAddress(ip(t)));
    const allowed = [_][]const u8{
        "1.1.1.1",     "8.8.8.8",     "172.15.0.1",      "172.32.0.1",     "100.63.0.1",
        "100.128.0.1", "193.168.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "fec0::1",
    };
    for (allowed) |t| try std.testing.expect(!isPrivateAddress(ip(t)));
}

test "address text parses back to the same address" {
    var buf: [48]u8 = undefined;
    for ([_][]const u8{ "1.2.3.4", "2606:4700::1111", "::1" }) |t| {
        const a = ip(t);
        const text = addressText(&buf, a);
        try std.testing.expect(a.eql(&(try Io.net.IpAddress.parse(text, 80))));
    }
}

fn resolveFake(host: []const u8, port: u16, out: *[16]Io.net.IpAddress) ?usize {
    if (std.mem.eql(u8, host, "rebind.test")) {
        out[0] = Io.net.IpAddress.parse("93.184.216.34", port) catch unreachable;
        out[1] = Io.net.IpAddress.parse("192.168.1.10", port) catch unreachable;
        return 2;
    }
    if (std.mem.eql(u8, host, "loop.test")) {
        out[0] = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
        return 1;
    }
    if (std.mem.eql(u8, host, "mapped.test")) {
        out[0] = Io.net.IpAddress.parse("::ffff:10.0.0.5", port) catch unreachable;
        return 1;
    }
    return null;
}

test "deny_private refuses a name that resolves to a private address" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();
    for ([_][]const u8{ "https://rebind.test/x", "https://loop.test/x", "https://mapped.test/x", "https://127.0.0.1/x", "https://[::1]/x", "https://10.0.0.1/x" }) |url| {
        try std.testing.expectError(error.PrivateAddress, fetch(gpa, io, url, .{ .deny_private = true, .resolver = resolveFake }));
    }
    try std.testing.expectError(error.HostNotFound, fetch(gpa, io, "https://nowhere.test/x", .{ .deny_private = true, .resolver = resolveFake }));
}

test "a resolver makes the connection go to the address it returned" {
    const io = std.testing.io;
    var da: TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the request leaked");
    const gpa = da.allocator();

    var srv: TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/hello", .body = "pinned" }}, 1);
    defer srv.stop(io);

    const R = struct {
        var port: u16 = 0;
        fn resolve(host: []const u8, _: u16, out: *[16]Io.net.IpAddress) ?usize {
            if (!std.mem.eql(u8, host, "pinned.test")) return null;
            out[0] = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
            return 1;
        }
    };
    R.port = srv.port();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://pinned.test:{d}/hello", .{srv.port()});
    var res = try fetch(gpa, io, url, .{ .allow_http = true, .resolver = R.resolve });
    defer res.deinit(gpa);
    try std.testing.expectEqualStrings("pinned", res.body);
}
