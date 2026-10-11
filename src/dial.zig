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
//! Proxies. `nostr.relay.dial` opens its own TCP connection and takes no
//! stream from outside, so a relay connection cannot go through a proxy yet.
//! It never goes around one quietly either: when `--proxy` or `DEED_PROXY`
//! names one for a relay's host, the dial fails with `ProxyUnsupported` and
//! says so, because whoever set it (a Tor user, say) asked for nothing to
//! leave directly. A proxy found only in HTTPS_PROXY, HTTP_PROXY or ALL_PROXY,
//! which are often set for a whole desktop and which deed ignored before, gets
//! a warning on stderr and the relay is dialled directly. NO_PROXY excludes a
//! relay from either.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");

const proxy = @import("proxy.zig");

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

const DialResult = @typeInfo(@TypeOf(relay.dial)).@"fn".return_type.?;

const Finished = struct {
    index: usize,
    result: DialResult,
};

const Arrival = union(enum) {
    dial: Finished,
    timer: Io.Cancelable!void,
};

fn dialOne(gpa: std.mem.Allocator, io: Io, url: []const u8, index: usize) Finished {
    return .{ .index = index, .result = relay.dial(gpa, io, url) };
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
        if (cfg) |c| if (proxied(c, url)) |choice| {
            if (choice.explicit) {
                out[i] = .{ .failed = error.ProxyUnsupported };
                continue;
            }
            warnDirect(choice);
        };
        // `concurrent`, never `async`: past its limit `async` runs the task
        // inline, and an inline dial is exactly the unbounded wait this avoids.
        sel.concurrent(.dial, dialOne, .{ gpa, io, url, i }) catch |e| {
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

var warned = std.atomic.Value(bool).init(false);

/// Once a run: a proxy from the conventional variables does not cover relays.
fn warnDirect(choice: proxy.Choice) void {
    if (warned.swap(true, .monotonic)) return;
    std.debug.print(
        "deed: warning: relay connections cannot go through a proxy yet; relays are dialled directly, not through the proxy in {s} (set NO_PROXY to the relay hosts to silence this, or use --proxy to refuse direct relay connections)\n",
        .{choice.name},
    );
}

test "a relay that a proxy given with --proxy would carry is refused, not dialled around it" {
    const io = std.testing.io;
    var da: @import("testrelay.zig").DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the dials leaked");
    const gpa = da.allocator();

    const saved = proxy.global;
    defer proxy.global = saved;
    proxy.global = .{
        .explicit = .{ .url = "socks5h://127.0.0.1:9", .name = "--proxy", .explicit = true },
        .no_proxy = "127.0.0.1",
    };

    const urls = [_][]const u8{ "wss://relay.example", "not a relay url", "ws://127.0.0.1:1" };
    var out: [3]Outcome = undefined;
    all(gpa, io, &urls, 2000, &out);
    defer for (out) |o| switch (o) {
        .connected => |r| r.deinit(),
        else => {},
    };
    try std.testing.expect(out[0] == .failed and out[0].failed == error.ProxyUnsupported);
    // Left to the dial: an unparseable URL, and a host NO_PROXY excludes.
    try std.testing.expect(out[1] == .failed and out[1].failed != error.ProxyUnsupported);
    try std.testing.expect(out[2] != .failed or out[2].failed != error.ProxyUnsupported);
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
    if (eql(u8, name, "ProxyUnsupported")) return "not dialled: a proxy is set and relay connections cannot go through one yet (add the relay's host to NO_PROXY to connect directly)";
    if (starts(u8, name, "Tls") or starts(u8, name, "Certificate")) return "could not set up a secure connection";
    return name;
}

test "common dial errors are put in words" {
    try std.testing.expectEqualStrings("connection refused", describe(error.ConnectionRefused));
    try std.testing.expectEqualStrings("the relay's reply was not understood", describe(error.SyntaxError));
    try std.testing.expectEqualStrings("could not set up a secure connection", describe(error.TlsAlertBadCertificate));
    try std.testing.expectEqualStrings("OutOfMemory", describe(error.OutOfMemory));
}
