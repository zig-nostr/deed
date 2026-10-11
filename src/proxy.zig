//! Proxies: which one a URL goes through, and opening a tunnel through it.
//!
//! The proxy comes from, in order: `--proxy <url>` before the verb, then
//! `DEED_PROXY`, then the conventional variables, `https_proxy` or
//! `http_proxy` by the target's scheme and then `all_proxy` (each lowercase
//! first, then uppercase). `NO_PROXY` (or `no_proxy`) excludes hosts from all
//! of them. A host on this machine skips the conventional variables, which
//! are often set for a whole desktop, but not `--proxy` or `DEED_PROXY`.
//!
//! Three kinds are understood:
//!
//!  - `http://host:port`: an https target goes through an HTTP CONNECT
//!    tunnel, and a plain http target is forwarded with an absolute URL.
//!  - `socks5h://host:port`: SOCKS5, with the name sent to the proxy and
//!    resolved there. This is the one for Tor, where a .onion name means
//!    nothing to the local resolver.
//!  - `socks5://host:port`: SOCKS5, with the name resolved here and the
//!    address sent.
//!
//! `user:password@` in the URL is sent as Basic proxy authorization for HTTP
//! and as the SOCKS5 username and password. Percent escapes are decoded.

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const Uri = std.Uri;

pub const Kind = enum { http, socks5, socks5h };

pub const Proxy = struct {
    kind: Kind,
    /// A name or an address, without brackets.
    host: []const u8,
    port: u16,
    user: ?[]const u8 = null,
    password: ?[]const u8 = null,

    /// True when the proxy, not this machine, resolves the target's name.
    pub fn resolvesNames(self: Proxy) bool {
        return self.kind != .socks5;
    }
};

pub const ParseError = error{ InvalidProxy, OutOfMemory };

/// Reads a proxy URL. A URL without a scheme is taken as http. The decoded
/// credentials are allocated from `arena`.
pub fn parse(arena: std.mem.Allocator, text: []const u8) ParseError!Proxy {
    const full = if (std.mem.indexOf(u8, text, "://") == null)
        try std.fmt.allocPrint(arena, "http://{s}", .{text})
    else
        text;
    const uri = Uri.parse(full) catch return error.InvalidProxy;

    const kind: Kind = if (std.ascii.eqlIgnoreCase(uri.scheme, "http"))
        .http
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "socks5"))
        .socks5
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "socks5h"))
        .socks5h
    else
        return error.InvalidProxy;

    const host_c = uri.host orelse return error.InvalidProxy;
    var host = try host_c.toRawMaybeAlloc(arena);
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    if (host.len == 0 or host.len > 255) return error.InvalidProxy;

    const path = try uri.path.toRawMaybeAlloc(arena);
    if (!(path.len == 0 or std.mem.eql(u8, path, "/"))) return error.InvalidProxy;
    if (uri.query != null or uri.fragment != null) return error.InvalidProxy;

    const port: u16 = uri.port orelse switch (kind) {
        .http => 80,
        .socks5, .socks5h => 1080,
    };
    if (port == 0) return error.InvalidProxy;

    var p: Proxy = .{ .kind = kind, .host = host, .port = port };
    if (uri.user) |u| p.user = try u.toRawMaybeAlloc(arena);
    if (uri.password) |pw| p.password = try pw.toRawMaybeAlloc(arena);
    // SOCKS5 carries each in one length byte.
    if (lenOf(p.user) > 255 or lenOf(p.password) > 255) return error.InvalidProxy;
    return p;
}

fn lenOf(s: ?[]const u8) usize {
    return if (s) |v| v.len else 0;
}

/// Where a chosen proxy URL came from, for messages.
pub const Choice = struct {
    url: []const u8,
    /// `--proxy`, `DEED_PROXY`, or the variable it was read from.
    name: []const u8,
    /// True for `--proxy` and `DEED_PROXY`, which a person sets for deed in
    /// particular; false for the conventional variables.
    explicit: bool,
};

pub const Config = struct {
    /// `--proxy` or `DEED_PROXY`.
    explicit: ?Choice = null,
    http: ?Choice = null,
    https: ?Choice = null,
    all: ?Choice = null,
    no_proxy: ?[]const u8 = null,

    /// The configuration for this process: `flag` is the value of `--proxy`,
    /// if one was given. A test build reads no variables, so a proxy set in
    /// the shell running the tests cannot reroute them.
    pub fn fromEnv(flag: ?[]const u8) Config {
        var c: Config = .{};
        if (flag) |f| c.explicit = .{ .url = f, .name = "--proxy", .explicit = true };
        if (builtin.is_test) return c;
        if (c.explicit == null) {
            if (getenv("DEED_PROXY")) |v| c.explicit = .{ .url = v, .name = "DEED_PROXY", .explicit = true };
        }
        c.https = envChoice(&.{ "https_proxy", "HTTPS_PROXY" });
        c.http = envChoice(&.{ "http_proxy", "HTTP_PROXY" });
        c.all = envChoice(&.{ "all_proxy", "ALL_PROXY" });
        c.no_proxy = getenv("no_proxy") orelse getenv("NO_PROXY");
        return c;
    }

    /// The proxy a connection to `host` (a name or an address, brackets
    /// allowed) on `port` goes through, or null to connect directly. `secure`
    /// is true for https and wss.
    pub fn select(self: *const Config, secure: bool, host: []const u8, port: u16) ?Choice {
        if (self.no_proxy) |list| {
            if (excluded(list, host, port)) return null;
        }
        if (self.explicit) |e| return e;
        if (isLocalHost(host)) return null;
        const specific = if (secure) self.https else self.http;
        return specific orelse self.all;
    }
};

/// The configuration `verbs.dispatch` sets for the run. Null in tests, and
/// whenever nothing set it, which means no proxy.
pub var global: ?Config = null;

fn getenv(name: [:0]const u8) ?[]const u8 {
    const v = std.c.getenv(name) orelse return null;
    const s = std.mem.span(v);
    return if (std.mem.trim(u8, s, " \t").len == 0) null else s;
}

fn envChoice(names: []const [:0]const u8) ?Choice {
    for (names) |n| if (getenv(n)) |v| return .{ .url = v, .name = n, .explicit = false };
    return null;
}

fn unbracket(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}

/// `localhost`, a name under `.localhost`, and loopback addresses.
pub fn isLocalHost(host_in: []const u8) bool {
    var host = unbracket(host_in);
    if (host.len > 0 and host[host.len - 1] == '.') host = host[0 .. host.len - 1];
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (host.len > ".localhost".len and std.ascii.endsWithIgnoreCase(host, ".localhost")) return true;
    const addr = Io.net.IpAddress.parse(host, 0) catch return false;
    return switch (addr) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| std.mem.eql(u8, a.bytes[0..15], &[_]u8{0} ** 15) and a.bytes[15] == 1,
    };
}

/// True when `NO_PROXY`'s `list` names `host`. Entries are comma or space
/// separated: `*` for everything, a name that matches itself and every name
/// under it (`example.com` and `.example.com` both match
/// `relay.example.com`), an address, an address range like `10.0.0.0/8`, and
/// any of those with `:port` to match only that port.
pub fn excluded(list: []const u8, host_in: []const u8, port: u16) bool {
    var host = unbracket(host_in);
    if (host.len > 0 and host[host.len - 1] == '.') host = host[0 .. host.len - 1];
    const host_ip: ?Io.net.IpAddress = Io.net.IpAddress.parse(host, 0) catch null;

    var it = std.mem.tokenizeAny(u8, list, ", \t");
    while (it.next()) |raw| {
        if (std.mem.eql(u8, raw, "*")) return true;
        var entry = raw;
        // A trailing :port, unless the entry is a bare IPv6 address.
        if (std.mem.lastIndexOfScalar(u8, entry, ':')) |c| {
            const bare_v6 = entry[0] != '[' and std.mem.indexOfScalar(u8, entry[0..c], ':') != null;
            if (!bare_v6) {
                const want = std.fmt.parseInt(u16, entry[c + 1 ..], 10) catch continue;
                if (want != port) continue;
                entry = entry[0..c];
            }
        }
        entry = unbracket(entry);
        if (std.mem.indexOfScalar(u8, entry, '/')) |slash| {
            const ip = host_ip orelse continue;
            const net = Io.net.IpAddress.parse(entry[0..slash], 0) catch continue;
            const bits = std.fmt.parseInt(u8, entry[slash + 1 ..], 10) catch continue;
            if (inRange(ip, net, bits)) return true;
            continue;
        }
        if (std.mem.startsWith(u8, entry, "*.")) entry = entry[2..] else if (std.mem.startsWith(u8, entry, ".")) entry = entry[1..];
        if (entry.len > 0 and entry[entry.len - 1] == '.') entry = entry[0 .. entry.len - 1];
        if (entry.len == 0) continue;
        if (host_ip) |ip| {
            if (Io.net.IpAddress.parse(entry, 0)) |e| {
                if (sameAddress(ip, e)) return true;
                continue;
            } else |_| {}
        }
        if (std.ascii.eqlIgnoreCase(host, entry)) return true;
        if (host.len > entry.len and host[host.len - entry.len - 1] == '.' and
            std.ascii.endsWithIgnoreCase(host, entry)) return true;
    }
    return false;
}

fn addressBytes(a: Io.net.IpAddress, buf: *[16]u8) []const u8 {
    switch (a) {
        .ip4 => |v| {
            buf[0..4].* = v.bytes;
            return buf[0..4];
        },
        .ip6 => |v| {
            buf.* = v.bytes;
            return buf[0..16];
        },
    }
}

fn sameAddress(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    var ab: [16]u8 = undefined;
    var bb: [16]u8 = undefined;
    return std.mem.eql(u8, addressBytes(a, &ab), addressBytes(b, &bb));
}

fn inRange(a: Io.net.IpAddress, net: Io.net.IpAddress, bits: u8) bool {
    var ab: [16]u8 = undefined;
    var nb: [16]u8 = undefined;
    const x = addressBytes(a, &ab);
    const y = addressBytes(net, &nb);
    if (x.len != y.len or bits > x.len * 8) return false;
    var left = bits;
    for (x, y) |p, q| {
        if (left == 0) return true;
        const mask: u8 = if (left >= 8) 0xff else ~(@as(u8, 0xff) >> @as(u3, @intCast(left)));
        if ((p & mask) != (q & mask)) return false;
        left -= @min(left, 8);
    }
    return true;
}

// ---- tunnels -------------------------------------------------------------

pub const TunnelError = error{
    /// The proxy would not connect to the target, or does not allow it.
    ProxyRefused,
    /// The proxy wants credentials, or did not accept the ones given.
    ProxyAuthFailed,
    /// The proxy's reply was not the protocol, or it hung up mid-reply.
    ProxyProtocol,
    /// Reading from the proxy failed; the stream's own error says why.
    ReadFailed,
    /// Writing to the proxy failed; the stream's own error says why.
    WriteFailed,
};

/// Asks the proxy, over `r` and `w`, for a byte stream to `host:port`. For
/// `.socks5`, `host` must already be an address. On success the next bytes
/// on `r` and `w` belong to the target, and nothing of the target's has been
/// consumed from `r`.
pub fn open(r: *Io.Reader, w: *Io.Writer, p: Proxy, host: []const u8, port: u16) TunnelError!void {
    return switch (p.kind) {
        .http => connectTunnel(r, w, p, host, port),
        .socks5, .socks5h => socks5(r, w, p, host, port),
    };
}

/// Writes `host:port` as a request target, bracketing an IPv6 address.
pub fn writeAuthority(w: *Io.Writer, host: []const u8, port: u16) Io.Writer.Error!void {
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        try w.print("[{s}]:{d}", .{ host, port });
    } else {
        try w.print("{s}:{d}", .{ host, port });
    }
}

/// Writes a `Proxy-Authorization` header line when the proxy has credentials.
pub fn writeAuthorization(w: *Io.Writer, p: Proxy) Io.Writer.Error!void {
    if (p.user == null and p.password == null) return;
    var raw_buf: [512]u8 = undefined;
    const empty: []const u8 = "";
    const raw = std.fmt.bufPrint(&raw_buf, "{s}:{s}", .{ p.user orelse empty, p.password orelse empty }) catch unreachable;
    var enc_buf: [std.base64.standard.Encoder.calcSize(512)]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&enc_buf, raw);
    try w.print("Proxy-Authorization: Basic {s}\r\n", .{enc});
}

fn connectTunnel(r: *Io.Reader, w: *Io.Writer, p: Proxy, host: []const u8, port: u16) TunnelError!void {
    try w.writeAll("CONNECT ");
    try writeAuthority(w, host, port);
    try w.writeAll(" HTTP/1.1\r\nHost: ");
    try writeAuthority(w, host, port);
    try w.writeAll("\r\n");
    try writeAuthorization(w, p);
    try w.writeAll("\r\n");
    try w.flush();

    const status_line = try line(r);
    // "HTTP/1.x NNN reason"
    if (status_line.len < 12 or !std.mem.startsWith(u8, status_line, "HTTP/1.") or status_line[8] != ' ')
        return error.ProxyProtocol;
    const status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.ProxyProtocol;
    // The rest of the head, up to the empty line, and not a byte further.
    var lines: usize = 0;
    while (true) : (lines += 1) {
        if (lines > 100) return error.ProxyProtocol;
        if ((try line(r)).len == 0) break;
    }
    if (status == 407) return error.ProxyAuthFailed;
    if (status < 200 or status > 299) return error.ProxyRefused;
}

/// One line of an HTTP head, without its line ending.
fn line(r: *Io.Reader) TunnelError![]const u8 {
    const l = r.takeDelimiterInclusive('\n') catch |e| return switch (e) {
        error.ReadFailed => error.ReadFailed,
        error.EndOfStream, error.StreamTooLong => error.ProxyProtocol,
    };
    var s = l[0 .. l.len - 1];
    if (s.len > 0 and s[s.len - 1] == '\r') s = s[0 .. s.len - 1];
    return s;
}

fn take(r: *Io.Reader, n: usize) TunnelError![]const u8 {
    return r.take(n) catch |e| return switch (e) {
        error.ReadFailed => error.ReadFailed,
        error.EndOfStream => error.ProxyProtocol,
    };
}

fn socks5(r: *Io.Reader, w: *Io.Writer, p: Proxy, host: []const u8, port: u16) TunnelError!void {
    const has_auth = p.user != null or p.password != null;
    // Offer no authentication, and username/password when there are some.
    if (has_auth) try w.writeAll(&.{ 5, 2, 0, 2 }) else try w.writeAll(&.{ 5, 1, 0 });
    try w.flush();
    const choice = try take(r, 2);
    if (choice[0] != 5) return error.ProxyProtocol;
    switch (choice[1]) {
        0 => {},
        2 => {
            if (!has_auth) return error.ProxyAuthFailed;
            const empty: []const u8 = "";
            const u = p.user orelse empty;
            const pw = p.password orelse empty;
            try w.writeAll(&.{ 1, @intCast(u.len) });
            try w.writeAll(u);
            try w.writeByte(@intCast(pw.len));
            try w.writeAll(pw);
            try w.flush();
            const verdict = try take(r, 2);
            if (verdict[0] != 1) return error.ProxyProtocol;
            if (verdict[1] != 0) return error.ProxyAuthFailed;
        },
        // None of the offered methods is acceptable: it wants credentials.
        0xff => return error.ProxyAuthFailed,
        else => return error.ProxyProtocol,
    }

    try w.writeAll(&.{ 5, 1, 0 });
    if (Io.net.IpAddress.parse(unbracket(host), 0)) |a| switch (a) {
        .ip4 => |v| {
            try w.writeByte(1);
            try w.writeAll(&v.bytes);
        },
        .ip6 => |v| {
            try w.writeByte(4);
            try w.writeAll(&v.bytes);
        },
    } else |_| {
        if (host.len == 0 or host.len > 255) return error.ProxyRefused;
        try w.writeAll(&.{ 3, @intCast(host.len) });
        try w.writeAll(host);
    }
    var port_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_bytes, port, .big);
    try w.writeAll(&port_bytes);
    try w.flush();

    const head = try take(r, 4);
    if (head[0] != 5) return error.ProxyProtocol;
    const rep = head[1];
    const atyp = head[3];
    // The bound address and port, read and dropped.
    const rest: usize = switch (atyp) {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => (try take(r, 1))[0] + @as(usize, 2),
        else => return error.ProxyProtocol,
    };
    _ = try take(r, rest);
    if (rep != 0) return error.ProxyRefused;
}

// ---- tests ---------------------------------------------------------------

const testing = std.testing;

test "a proxy URL is read with its kind, port and credentials" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try parse(arena, "socks5h://127.0.0.1:9050");
    try testing.expectEqual(Kind.socks5h, a.kind);
    try testing.expectEqualStrings("127.0.0.1", a.host);
    try testing.expectEqual(@as(u16, 9050), a.port);
    try testing.expect(a.user == null);
    try testing.expect(a.resolvesNames());

    const b = try parse(arena, "http://us%40er:p%3Ass@proxy.corp:3128/");
    try testing.expectEqual(Kind.http, b.kind);
    try testing.expectEqualStrings("proxy.corp", b.host);
    try testing.expectEqualStrings("us@er", b.user.?);
    try testing.expectEqualStrings("p:ss", b.password.?);

    const c = try parse(arena, "proxy.corp:8080");
    try testing.expectEqual(Kind.http, c.kind);
    try testing.expectEqual(@as(u16, 8080), c.port);

    const d = try parse(arena, "socks5://[::1]");
    try testing.expectEqualStrings("::1", d.host);
    try testing.expectEqual(@as(u16, 1080), d.port);
    try testing.expect(!d.resolvesNames());
}

test "a proxy URL that cannot be used is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{
        "https://proxy:443",    "socks4://proxy:1080", "ftp://proxy",
        "socks5h://",           "http://proxy:99999",  "http://proxy:0",
        "http://proxy:80/path", "http://proxy?x=1",    "",
        "socks5h://proxy:12ab",
    }) |t| try testing.expectError(error.InvalidProxy, parse(arena, t));
}

test "NO_PROXY names, suffixes, addresses, ranges and ports" {
    try testing.expect(excluded("*", "anything.example", 443));
    try testing.expect(excluded("example.com", "example.com", 443));
    try testing.expect(excluded("example.com", "relay.example.com", 443));
    try testing.expect(excluded(".example.com", "relay.EXAMPLE.com", 443));
    try testing.expect(excluded("*.example.com", "relay.example.com", 443));
    try testing.expect(!excluded("example.com", "badexample.com", 443));
    try testing.expect(!excluded("relay.example.com", "example.com", 443));
    try testing.expect(excluded("foo, 10.0.0.0/8", "10.2.3.4", 443));
    try testing.expect(!excluded("10.0.0.0/8", "11.2.3.4", 443));
    try testing.expect(excluded("192.168.1.0/24", "192.168.1.77", 80));
    try testing.expect(excluded("::1", "[::1]", 80));
    try testing.expect(excluded("fd00::/8", "fd12::1", 80));
    try testing.expect(excluded("example.com:8443", "example.com", 8443));
    try testing.expect(!excluded("example.com:8443", "example.com", 443));
    try testing.expect(!excluded("", "example.com", 443));
}

test "selection: the explicit proxy wins, NO_PROXY excludes, local hosts skip the variables" {
    const cfg: Config = .{
        .https = .{ .url = "http://corp:3128", .name = "https_proxy", .explicit = false },
        .all = .{ .url = "socks5h://all:1080", .name = "all_proxy", .explicit = false },
        .no_proxy = "internal.example",
    };
    try testing.expectEqualStrings("http://corp:3128", cfg.select(true, "relay.example", 443).?.url);
    try testing.expectEqualStrings("socks5h://all:1080", cfg.select(false, "relay.example", 80).?.url);
    try testing.expect(cfg.select(true, "api.internal.example", 443) == null);
    try testing.expect(cfg.select(true, "localhost", 443) == null);
    try testing.expect(cfg.select(false, "127.0.0.1", 80) == null);

    var tor = cfg;
    tor.explicit = .{ .url = "socks5h://127.0.0.1:9050", .name = "--proxy", .explicit = true };
    try testing.expectEqualStrings("--proxy", tor.select(true, "relay.example", 443).?.name);
    try testing.expect(tor.select(true, "127.0.0.1", 443).?.explicit);
    try testing.expect(tor.select(true, "api.internal.example", 443) == null);

    const none: Config = .{};
    try testing.expect(none.select(true, "relay.example", 443) == null);
}

test "a CONNECT tunnel asks for the target and stops at the end of the reply" {
    var out_buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&out_buf);
    var r: Io.Reader = .fixed("HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nTLS-BYTES");
    try open(&r, &w, .{ .kind = .http, .host = "p", .port = 1, .user = "u", .password = "pw" }, "example.com", 443);
    try testing.expectEqualStrings(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dTpwdw==\r\n\r\n",
        w.buffered(),
    );
    try testing.expectEqualStrings("TLS-BYTES", r.buffered());

    var w2: Io.Writer = .fixed(&out_buf);
    var r2: Io.Reader = .fixed("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
    try testing.expectError(error.ProxyAuthFailed, open(&r2, &w2, .{ .kind = .http, .host = "p", .port = 1 }, "::1", 443));
    try testing.expect(std.mem.startsWith(u8, w2.buffered(), "CONNECT [::1]:443 HTTP/1.1\r\n"));

    var w3: Io.Writer = .fixed(&out_buf);
    var r3: Io.Reader = .fixed("HTTP/1.1 403 Forbidden\r\n\r\n");
    try testing.expectError(error.ProxyRefused, open(&r3, &w3, .{ .kind = .http, .host = "p", .port = 1 }, "x", 443));

    var w4: Io.Writer = .fixed(&out_buf);
    var r4: Io.Reader = .fixed("SSH-2.0-nope\r\n");
    try testing.expectError(error.ProxyProtocol, open(&r4, &w4, .{ .kind = .http, .host = "p", .port = 1 }, "x", 443));
}

test "a SOCKS5h tunnel sends the name, and SOCKS5 with credentials authenticates" {
    var out_buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&out_buf);
    var r: Io.Reader = .fixed(&[_]u8{ 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
    try open(&r, &w, .{ .kind = .socks5h, .host = "p", .port = 1 }, "abc.onion", 443);
    try testing.expectEqualSlices(u8, &([_]u8{ 5, 1, 0, 5, 1, 0, 3, 9 } ++ "abc.onion".* ++ [_]u8{ 1, 187 }), w.buffered());

    var w2: Io.Writer = .fixed(&out_buf);
    var r2: Io.Reader = .fixed(&[_]u8{ 5, 2, 1, 0, 5, 0, 0, 4 } ++ [_]u8{0} ** 18);
    try open(&r2, &w2, .{ .kind = .socks5, .host = "p", .port = 1, .user = "al", .password = "pw" }, "10.0.0.1", 80);
    try testing.expectEqualSlices(u8, &[_]u8{ 5, 2, 0, 2, 1, 2, 'a', 'l', 2, 'p', 'w', 5, 1, 0, 1, 10, 0, 0, 1, 0, 80 }, w2.buffered());

    var w3: Io.Writer = .fixed(&out_buf);
    var r3: Io.Reader = .fixed(&[_]u8{ 5, 2, 1, 1 });
    try testing.expectError(error.ProxyAuthFailed, open(&r3, &w3, .{ .kind = .socks5, .host = "p", .port = 1, .user = "al", .password = "bad" }, "10.0.0.1", 80));

    var w4: Io.Writer = .fixed(&out_buf);
    var r4: Io.Reader = .fixed(&[_]u8{ 5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 });
    try testing.expectError(error.ProxyRefused, open(&r4, &w4, .{ .kind = .socks5h, .host = "p", .port = 1 }, "x.example", 443));

    var w5: Io.Writer = .fixed(&out_buf);
    var r5: Io.Reader = .fixed(&[_]u8{ 5, 0xff });
    try testing.expectError(error.ProxyAuthFailed, open(&r5, &w5, .{ .kind = .socks5h, .host = "p", .port = 1 }, "x.example", 443));
}
