//! Reaching a set of relays at once, under one deadline.
//!
//! `nostr.relay.dial` takes no deadline of its own: a relay that accepts the
//! connection and then never answers the websocket upgrade would hold it, and
//! the process, forever. So every dial runs concurrently, a timer runs beside
//! them, and whatever is still dialling when the timer fires is cancelled. A
//! cancelled dial stops where it is and frees what it allocated.
//!
//! The one step a cancel cannot cut short is the name lookup, which is a plain
//! libc call: a resolver that hangs still holds its dial until it returns.
//!
//! Proxies. A relay whose host a proxy covers (see `proxy.Config.select`) is
//! reached through it: a tunnel is opened to the relay's host and port, with
//! CONNECT for an http:// proxy and SOCKS5 otherwise, and the dial then runs
//! over that stream, TLS included for wss://. With socks5h:// and http:// the
//! proxy resolves the relay's name, so nothing is looked up here. The tunnel
//! runs inside the same task as the rest of the dial, so the same deadline
//! bounds it and the same cancel ends it. A proxy that is set and cannot be
//! used fails the dial: a relay is never dialled around it. NO_PROXY is the
//! way to reach a host directly.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");

const proxy = @import("proxy.zig");
const http = @import("http.zig");

const Io = std.Io;
const relay = nostr.relay;

/// How long a relay gets to accept the connection, finish TLS and answer the
/// websocket upgrade. A relay that needs longer than this to say hello is not
/// one a command line should be waiting on.
pub const default_timeout_ms: i64 = 5_000;

/// The most relays one run will dial.
pub const max_relays = 32;

pub const Outcome = union(enum) {
    connected: *relay.Relay,
    /// The dial failed on its own, before the deadline.
    failed: anyerror,
    /// Still dialling when the deadline passed.
    timed_out,
};

const DialResult = anyerror!*relay.Relay;

const Finished = struct {
    index: usize,
    result: DialResult,
};

const Arrival = union(enum) {
    dial: Finished,
    timer: Io.Cancelable!void,
};

fn dialOne(gpa: std.mem.Allocator, io: Io, url: []const u8, via: ?proxy.Choice, index: usize) Finished {
    const result: DialResult = if (via) |choice| through(gpa, io, url, choice) else relay.dial(gpa, io, url);
    return .{ .index = index, .result = result };
}

/// Errors a dial through a proxy adds to those of a direct one.
pub const ProxyError = error{
    /// The proxy URL is not one deed can use.
    InvalidProxy,
    /// The proxy itself could not be reached.
    ProxyConnectFailed,
    /// The proxy would not connect to the relay.
    ProxyRefused,
    /// The proxy wants credentials, or refused the ones in its URL.
    ProxyAuthFailed,
    /// The proxy's reply was not understood, or it hung up.
    ProxyFailed,
    /// With socks5://, the relay's name did not resolve here.
    HostNotFound,
    OutOfMemory,
    Canceled,
};

/// Dials `url` through the proxy `choice` names.
fn through(gpa: std.mem.Allocator, io: Io, url: []const u8, choice: proxy.Choice) anyerror!*relay.Relay {
    const parsed = try relay.parseUrl(url);
    // Room for the URL with a scheme added and its decoded credentials.
    var mem: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem);
    const p = proxy.parse(fba.allocator(), choice.url) catch return error.InvalidProxy;
    const tcp = try tunnel(io, p, parsed.host, parsed.port);
    var diagnostic: relay.DialDiagnostic = .{};
    return relay.dialOverDiagnosed(gpa, io, url, tcp, &diagnostic);
}

/// A TCP stream to `host:port` through `p`, ready for the relay's first
/// byte. The caller owns it.
///
/// Takes no deadline of its own, like the dial it is part of: a cancel ends
/// the connect to the proxy or the wait for its answer, and the stream is
/// closed. A name lookup (the proxy's own name, or the relay's with
/// socks5://) is the one step a cancel cannot cut short.
pub fn tunnel(io: Io, p: proxy.Proxy, host: []const u8, port: u16) ProxyError!Io.net.Stream {
    var target: []const u8 = host;
    var text_buf: [48]u8 = undefined;
    if (!p.resolvesNames()) {
        if (Io.net.IpAddress.parse(host, port)) |_| {} else |_| {
            var addrs: [16]Io.net.IpAddress = undefined;
            const n = http.lookupAddresses(io, host, port, &addrs) catch |e| return switch (e) {
                error.Canceled => error.Canceled,
                error.OutOfMemory => error.OutOfMemory,
                else => error.HostNotFound,
            };
            if (n == 0) return error.HostNotFound;
            target = http.addressText(&text_buf, addrs[0]);
        }
    }

    const stream = http.connectProxy(io, p) catch |e| return switch (e) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        else => error.ProxyConnectFailed,
    };
    errdefer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    proxy.open(&sr.interface, &sw.interface, p, target, port) catch |e| {
        // A cancel surfaces as a read or write that failed. It has to come
        // back as itself, or the deadline's join would wait on a task that
        // never noticed it.
        if (sr.err) |re| if (re == error.Canceled) return error.Canceled;
        if (sw.err) |we| if (we == error.Canceled) return error.Canceled;
        return switch (e) {
            error.ProxyRefused => error.ProxyRefused,
            error.ProxyAuthFailed => error.ProxyAuthFailed,
            error.ProxyProtocol, error.ReadFailed, error.WriteFailed => error.ProxyFailed,
        };
    };
    // The relay speaks only after the client has, so anything already read
    // past the proxy's answer is not the relay's, and the stream is handed on
    // without this reader's buffer.
    if (sr.interface.bufferedLen() != 0) return error.ProxyFailed;
    return stream;
}

/// Dials every one of `urls` at once and writes url `i`'s outcome to `out[i]`.
///
/// Returns once every dial has finished or `timeout_ms` has passed, whichever
/// comes first. Every `connected` relay belongs to the caller.
pub fn all(gpa: std.mem.Allocator, io: Io, urls: []const []const u8, timeout_ms: i64, out: []Outcome) void {
    std.debug.assert(urls.len <= max_relays);
    std.debug.assert(out.len >= urls.len);
    for (out[0..urls.len]) |*o| o.* = .timed_out;
    const cfg: ?*const proxy.Config = if (proxy.global) |*g| g else null;

    // One slot per task that can finish, or `cancel` below deadlocks waiting
    // for room to put a result.
    var buf: [max_relays + 1]Arrival = undefined;
    var sel = Io.Select(Arrival).init(io, &buf);

    var pending: usize = 0;
    for (urls, 0..) |url, i| {
        const via: ?proxy.Choice = if (cfg) |c| proxied(c, url) else null;
        // `concurrent`, never `async`: past its limit `async` runs the task
        // inline, and an inline dial is exactly the unbounded wait this avoids.
        sel.concurrent(.dial, dialOne, .{ gpa, io, url, via, i }) catch |e| {
            out[i] = .{ .failed = e };
            continue;
        };
        pending += 1;
    }

    if (pending > 0) {
        // Should the timer fail to start, the dials are only as bounded as
        // they were before this existed, which still beats not dialling.
        sel.concurrent(.timer, Io.sleep, .{ io, .fromMilliseconds(timeout_ms), .awake }) catch {};
    }

    while (pending > 0) {
        const arrival = sel.await() catch break;
        switch (arrival) {
            .dial => |f| {
                out[f.index] = if (f.result) |r| .{ .connected = r } else |e| .{ .failed = e };
                pending -= 1;
            },
            .timer => break,
        }
    }

    // Whatever is left missed the deadline. Cancelling joins each task, and a
    // dial that happened to finish in the same instant is kept rather than
    // thrown away: it is a live connection, and the caller asked for one.
    while (sel.cancel()) |late| switch (late) {
        .dial => |f| if (f.result) |r| {
            out[f.index] = .{ .connected = r };
        } else |_| {},
        .timer => {},
    };
}

/// The proxy `url` would go through, if it parses as a relay URL at all. One
/// that does not is left for the dial to refuse in its own words.
fn proxied(cfg: *const proxy.Config, url: []const u8) ?proxy.Choice {
    const parsed = relay.parseUrl(url) catch return null;
    return cfg.select(parsed.secure, parsed.host, parsed.port);
}

/// Sets `proxy.global` for a test; `restore` puts back what was there.
const GlobalProxy = struct {
    saved: ?proxy.Config,

    fn set(cfg: proxy.Config) GlobalProxy {
        const g: GlobalProxy = .{ .saved = proxy.global };
        proxy.global = cfg;
        return g;
    }

    fn restore(self: GlobalProxy) void {
        proxy.global = self.saved;
    }
};

fn deinitAll(out: []const Outcome) void {
    for (out) |o| switch (o) {
        .connected => |r| r.deinit(),
        else => {},
    };
}

test "a relay is reached by name through a CONNECT or a SOCKS5 proxy, and NO_PROXY goes around it" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the dials leaked");
    const gpa = da.allocator();

    for ([_]testrelay.Tunnel.Kind{ .connect, .socks5 }, [_][]const u8{ "http://", "socks5h://" }, [_][]const u8{ "", "name " }) |kind, scheme, prefix| {
        var live: testrelay.Relay = undefined;
        try live.start(io, .accept);
        defer live.stop(io);
        var tun: testrelay.Tunnel = undefined;
        try tun.start(io, kind, 1);
        defer tun.stop(io);

        var pb: [64]u8 = undefined;
        const g = GlobalProxy.set(.{ .explicit = .{ .url = try tun.url(&pb, scheme), .name = "--proxy", .explicit = true } });
        defer g.restore();

        // No resolver knows this name: only a proxy that resolves it can.
        var ub: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&ub, "ws://relay.example.test:{d}", .{live.port()});
        var out: [1]Outcome = undefined;
        all(gpa, io, &.{url}, 2000, &out);
        defer deinitAll(&out);
        try std.testing.expect(out[0] == .connected);
        var want: [64]u8 = undefined;
        try std.testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{s}relay.example.test:{d}", .{ prefix, live.port() }), tun.asked());
    }

    // NO_PROXY: dialled directly, and the proxy (nothing listens there) is
    // never tried.
    var live: testrelay.Relay = undefined;
    try live.start(io, .accept);
    defer live.stop(io);
    const g = GlobalProxy.set(.{ .explicit = .{ .url = "socks5h://127.0.0.1:1", .name = "--proxy", .explicit = true }, .no_proxy = "example.com, 127.0.0.1" });
    defer g.restore();
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, live.port());
    var out: [1]Outcome = undefined;
    all(gpa, io, &.{url}, 2000, &out);
    defer deinitAll(&out);
    try std.testing.expect(out[0] == .connected);
}

test "a proxy that is set and cannot be used fails the dial, and nothing goes around it" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the dials leaked");
    const gpa = da.allocator();

    // A live relay a direct dial would reach.
    var live: testrelay.Relay = undefined;
    try live.start(io, .accept);
    defer live.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, live.port());

    // Bound and closed again, so nothing listens there.
    var closed = try testrelay.listen(io);
    var pb: [64]u8 = undefined;
    const dead = try std.fmt.bufPrint(&pb, "http://127.0.0.1:{d}", .{closed.socket.address.ip4.port});
    closed.deinit(io);

    {
        const g = GlobalProxy.set(.{ .explicit = .{ .url = dead, .name = "--proxy", .explicit = true } });
        defer g.restore();
        var out: [1]Outcome = undefined;
        const started = Io.Timestamp.now(io, .awake).toMilliseconds();
        all(gpa, io, &.{url}, 3000, &out);
        const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
        defer deinitAll(&out);
        // Windows retries a refused connect for about two seconds.
        if (builtin.os.tag == .windows) {
            try std.testing.expect(out[0] == .timed_out or (out[0] == .failed and out[0].failed == error.ProxyConnectFailed));
        } else {
            try std.testing.expect(out[0] == .failed and out[0].failed == error.ProxyConnectFailed);
            try std.testing.expect(took < 3_000);
        }
    }

    // One from the conventional variables is not gone around either. (A
    // relay on this machine skips those, so this one has a name.)
    {
        const g = GlobalProxy.set(.{ .all = .{ .url = dead, .name = "ALL_PROXY", .explicit = false } });
        defer g.restore();
        var nb: [64]u8 = undefined;
        const named = try std.fmt.bufPrint(&nb, "ws://relay.example.test:{d}", .{live.port()});
        var out: [1]Outcome = undefined;
        all(gpa, io, &.{named}, 3000, &out);
        defer deinitAll(&out);
        try std.testing.expect(out[0] != .connected);
        if (out[0] == .failed) try std.testing.expect(out[0].failed == error.ProxyConnectFailed);
    }

    {
        const g = GlobalProxy.set(.{ .explicit = .{ .url = "ftp://127.0.0.1:21", .name = "--proxy", .explicit = true } });
        defer g.restore();
        var out: [1]Outcome = undefined;
        all(gpa, io, &.{url}, 2000, &out);
        defer deinitAll(&out);
        try std.testing.expect(out[0] == .failed and out[0].failed == error.InvalidProxy);
    }
}

test "a proxy that never answers is cancelled at the deadline, mid-tunnel" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the dials leaked");
    const gpa = da.allocator();

    // Listening and never accepting: the kernel completes the handshake from
    // its backlog, and the tunnel request then waits for an answer.
    var silent = try testrelay.listen(io);
    defer silent.deinit(io);

    for ([_][]const u8{ "http://", "socks5h://" }) |scheme| {
        var pb: [64]u8 = undefined;
        const g = GlobalProxy.set(.{ .explicit = .{
            .url = try std.fmt.bufPrint(&pb, "{s}127.0.0.1:{d}", .{ scheme, silent.socket.address.ip4.port }),
            .name = "--proxy",
            .explicit = true,
        } });
        defer g.restore();
        var out: [1]Outcome = undefined;
        const started = Io.Timestamp.now(io, .awake).toMilliseconds();
        all(gpa, io, &.{"wss://relay.example.test"}, 300, &out);
        const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
        defer deinitAll(&out);
        try std.testing.expect(out[0] == .timed_out);
        try std.testing.expect(took < 3_000);
    }
}

test "a silent relay times out, a closed port fails, and a live relay connects, all at once" {
    const io = std.testing.io;
    const testrelay = @import("testrelay.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the dials leaked");
    const gpa = da.allocator();

    // Listening, and never accepting: the kernel completes the TCP handshake
    // from its backlog, so the dial sends its upgrade and waits for an answer
    // that never comes.
    var silent = try testrelay.listen(io);
    defer silent.deinit(io);

    // Bound and closed again, so nothing is listening there.
    var closed = try testrelay.listen(io);
    const closed_port = closed.socket.address.ip4.port;
    closed.deinit(io);

    var live: testrelay.Relay = undefined;
    try live.start(io, .accept);
    defer live.stop(io);

    var urls_buf: [3][40]u8 = undefined;
    const urls = [_][]const u8{
        try testrelay.url(&urls_buf[0], silent.socket.address.ip4.port),
        try testrelay.url(&urls_buf[1], closed_port),
        try testrelay.url(&urls_buf[2], live.port()),
    };

    var out: [3]Outcome = undefined;
    const started = Io.Timestamp.now(io, .awake).toMilliseconds();
    all(gpa, io, &urls, 300, &out);
    const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
    defer for (out) |o| switch (o) {
        .connected => |r| r.deinit(),
        else => {},
    };

    try std.testing.expect(out[0] == .timed_out);
    // Windows retries a refused connect for about two seconds before it
    // gives up, so there the closed port runs into the deadline instead.
    if (builtin.os.tag == .windows) {
        try std.testing.expect(out[1] == .failed or out[1] == .timed_out);
    } else {
        try std.testing.expect(out[1] == .failed);
    }
    try std.testing.expect(out[2] == .connected);
    // Bounded by the deadline, not by the slowest relay.
    try std.testing.expect(took < 3_000);
}

/// A dial error in words a person can act on. Errors without a better
/// description keep their name.
pub fn describe(e: anyerror) []const u8 {
    const name = @errorName(e);
    const eql = std.mem.eql;
    const starts = std.mem.startsWith;
    if (eql(u8, name, "ConnectionRefused")) return "connection refused";
    if (eql(u8, name, "UnknownHostName") or eql(u8, name, "HostLacksNetworkAddresses") or
        eql(u8, name, "NameServerFailure") or eql(u8, name, "TemporaryNameServerFailure") or
        eql(u8, name, "NoAddressFound")) return "host not found";
    if (eql(u8, name, "NetworkUnreachable") or eql(u8, name, "HostUnreachable") or
        eql(u8, name, "AddressUnavailable")) return "network unreachable";
    if (eql(u8, name, "ConnectionTimedOut") or eql(u8, name, "Timeout")) return "timed out";
    if (eql(u8, name, "ConnectionResetByPeer") or eql(u8, name, "EndOfStream") or eql(u8, name, "BrokenPipe")) return "connection closed by the relay";
    if (eql(u8, name, "HandshakeFailed")) return "not a websocket relay (the upgrade was refused)";
    if (eql(u8, name, "SyntaxError") or eql(u8, name, "InvalidResponse") or eql(u8, name, "UnexpectedFrame")) return "the relay's reply was not understood";
    if (eql(u8, name, "InvalidUrl") or eql(u8, name, "UnsupportedScheme")) return "not a usable relay URL";
    if (eql(u8, name, "HostNotFound")) return "host not found";
    if (eql(u8, name, "InvalidProxy")) return "the proxy URL is not usable (use http://, socks5:// or socks5h:// with a host and port)";
    if (eql(u8, name, "ProxyConnectFailed")) return "could not connect to the proxy (relays are not dialled around it; list a host in NO_PROXY to reach it directly)";
    if (eql(u8, name, "ProxyRefused")) return "the proxy would not connect to the relay";
    if (eql(u8, name, "ProxyAuthFailed")) return "the proxy refused the credentials, or wants some";
    if (eql(u8, name, "ProxyFailed")) return "the proxy's reply was not understood, or it closed the connection";
    if (starts(u8, name, "Tls") or starts(u8, name, "Certificate")) return "could not set up a secure connection";
    return name;
}

test "common dial errors are put in words" {
    try std.testing.expectEqualStrings("connection refused", describe(error.ConnectionRefused));
    try std.testing.expectEqualStrings("the relay's reply was not understood", describe(error.SyntaxError));
    try std.testing.expectEqualStrings("could not set up a secure connection", describe(error.TlsAlertBadCertificate));
    try std.testing.expectEqualStrings("OutOfMemory", describe(error.OutOfMemory));
    try std.testing.expect(std.mem.startsWith(u8, describe(error.ProxyConnectFailed), "could not connect to the proxy"));
}
