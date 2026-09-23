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

const std = @import("std");
const nostr = @import("nostr");

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

    // One slot per task that can finish, or `cancel` below deadlocks waiting
    // for room to put a result.
    var buf: [max_relays + 1]Arrival = undefined;
    var sel = Io.Select(Arrival).init(io, &buf);

    var pending: usize = 0;
    for (urls, 0..) |url, i| {
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
    try std.testing.expect(out[1] == .failed);
    try std.testing.expect(out[2] == .connected);
    // Bounded by the deadline, not by the slowest relay.
    try std.testing.expect(took < 3_000);
}
