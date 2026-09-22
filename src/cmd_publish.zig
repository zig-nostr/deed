//! `deed publish`: offer signed events to relays.
//!
//! Reads events the way every other verb reads its records, so the thing that
//! made them is somebody else's business: `deed event -c "hi" | deed publish
//! wss://...` is the ordinary path, and a file of events works the same way.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");

const relay = nostr.relay;

/// An event too big for this is one no relay would take either.
const max_record_bytes = 1 << 20;

/// How long one relay gets to say yes or no.
///
/// A relay that accepts the frame and never answers is the case this exists
/// for. nak forces the same shape with a 7 second deadline on the OK and ten
/// seconds around the whole flow; this is the middle of those.
const ok_timeout_ms: i64 = 8_000;

pub const usage =
    \\deed publish: offer signed events to relays
    \\
    \\Usage:
    \\  deed publish <relay-url>... [<event-json>...]
    \\
    \\Reads events as newline-delimited JSON on stdin when given no event
    \\arguments, and offers each to every relay named.
    \\
    \\  deed event -c "hello" | deed publish wss://relay.example
    \\
    \\Every relay's answer is reported on stderr. Exits 0 when at least one
    \\relay accepted an event, because an event one relay holds is published;
    \\exits 1 when none did, and 2 when the command made no sense.
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);

    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed publish: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        // A relay URL is a relay URL; anything else is an event.
        if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try urls.append(gpa, a);
        } else {
            try positionals.append(gpa, a);
        }
    }

    if (urls.items.len == 0) {
        try err.writeAll("deed publish: name at least one relay to publish to\n");
        return cli.exit_usage;
    }

    // Dialled BEFORE anything is read, so a run that cannot reach a single
    // relay says so without having consumed the events it was given. nak orders
    // it the same way, for the sharper version of the reason: there, signing
    // costs a round trip to a remote signer, and burning one to then discover
    // no relay is reachable is a bad trade.
    var conns: [32]?*relay.Relay = @splat(null);
    const n = @min(urls.items.len, conns.len);
    defer for (conns[0..n]) |maybe| {
        if (maybe) |r| {
            r.shutdown(io);
            r.deinit();
        }
    };

    var live: usize = 0;
    for (urls.items[0..n], 0..) |url, i| {
        conns[i] = relay.dial(gpa, io, url) catch |e| {
            try err.print("deed publish: {s}: {s}\n", .{ url, @errorName(e) });
            continue;
        };
        live += 1;
    }
    if (live == 0) {
        try err.writeAll("deed publish: no relay could be reached\n");
        return cli.exit_fail;
    }

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    var accepted_any = false;
    var offered: usize = 0;
    var refusals: usize = 0;

    while (try input.next()) |record| {
        const json = switch (record) {
            .line => |l| std.mem.trim(u8, l, " \t"),
            .too_long => {
                try err.print("deed publish: skipped an event longer than {d} bytes\n", .{max_record_bytes});
                refusals += 1;
                continue;
            },
        };

        var parsed = nostr.event.fromJson(gpa, json) catch |e| {
            try err.print("deed publish: not an event: {s}\n", .{@errorName(e)});
            refusals += 1;
            continue;
        };
        defer parsed.deinit();
        offered += 1;

        for (conns[0..n], 0..) |maybe, i| {
            const r = maybe orelse continue;
            const url = urls.items[i];
            r.publish(parsed.value) catch |e| {
                try err.print("deed publish: {s}: {s}\n", .{ url, @errorName(e) });
                refusals += 1;
                continue;
            };
            if (awaitOk(r, parsed.value.id, io, err, url)) accepted_any = true else refusals += 1;
        }
    }

    if (offered == 0) {
        try err.writeAll("deed publish: nothing to publish\n");
        return cli.exit_fail;
    }
    // An event one relay holds is published. nak draws the line in the same
    // place: it fails only when every relay failed, because a run that reported
    // failure after reaching the network would have scripts retrying something
    // that already happened.
    if (!accepted_any) return cli.exit_fail;
    if (refusals > 0) try err.print("deed publish: {d} relay answers were not an acceptance\n", .{refusals});
    return cli.exit_ok;
}

/// Waits for this relay's answer about this event.
///
/// Other messages keep arriving on the same socket while this waits, so
/// anything that is not the OK being waited for is passed over rather than
/// treated as an answer.
fn awaitOk(
    r: *relay.Relay,
    id: [32]u8,
    io: std.Io,
    err: *std.Io.Writer,
    url: []const u8,
) bool {
    _ = io;
    const deadline = std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(ok_timeout_ms), .clock = .awake } };
    while (true) {
        var msg = (r.receiveTimeout(deadline) catch {
            try_print(err, "deed publish: {s}: gave up waiting for an answer\n", .{url});
            return false;
        }) orelse {
            try_print(err, "deed publish: {s}: closed before answering\n", .{url});
            return false;
        };
        defer msg.deinit();
        switch (msg.value) {
            .ok => |o| {
                if (!std.mem.eql(u8, &o.event_id, &id)) continue;
                if (o.accepted) {
                    try_print(err, "deed publish: {s}: accepted\n", .{url});
                    return true;
                }
                try_print(err, "deed publish: {s}: refused: {s}\n", .{ url, o.message });
                return false;
            },
            .notice => |notice| try_print(err, "deed publish: {s}: notice: {s}\n", .{ url, notice.message }),
            else => {},
        }
    }
}

/// Writing a progress line must never be the thing that fails a publish.
fn try_print(w: *std.Io.Writer, comptime fmt: []const u8, args: anytype) void {
    w.print(fmt, args) catch {};
}
