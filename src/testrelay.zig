//! A relay for tests: it listens on loopback, answers the websocket upgrade,
//! and then does what its mode says. Nothing outside tests uses it.
//!
//! It is real enough to dial. The client side of every test that uses it is
//! the same `nostr.relay.dial` a user's run goes through, over a real socket.

const std = @import("std");
const nostr = @import("nostr");

const Io = std.Io;
const ws = nostr.websocket;

pub const Mode = enum {
    /// OK true to every EVENT, EOSE to every REQ.
    accept,
    /// OK false to every EVENT, with a reason.
    refuse,
    /// OK true to every EVENT, saying it already had it.
    duplicate,
    /// Answers the upgrade and then never sends another byte.
    silent,
    /// Never answers an EVENT, and sends a NOTICE every 100 ms for four
    /// seconds, so a wait that restarts on every message outlasts a test that
    /// expects it to end sooner, and fails it rather than hanging it.
    chatty,
    /// Sends twenty notices as soon as it is connected, and never answers.
    notice_burst,
    /// Sends pong frames back to back, and never answers.
    pongs,
    /// Answers the upgrade and never reads again, so what is sent to it
    /// fills the socket and the sender's write waits.
    deaf,
    /// OK true to every EVENT, then closes the connection.
    close_after_ok,
    /// An OK true about some other event, then OK false about this one.
    stale_ok,
    /// A notice, then OK true, both carrying C0, DEL and C1 controls.
    hostile_accept,
    /// A ping, then OK true.
    ping_then_ok,
    /// Seventy notices, then OK true.
    notices_then_ok,
    /// OK true, then a ping and a close frame, and the connection ends.
    ping_then_close,
    /// OK true to the first EVENT on a connection. On the second, it closes
    /// the connection without answering.
    close_on_second_event,
    /// Never reads, and sends pings back to back. The answering pongs fill
    /// the socket, so the reader writing them waits, holding the connection's
    /// write lock.
    pings_deaf,
    /// Twenty notices, then OK true, then the connection ends.
    notices_then_close,
    /// Sends a message the parser has no case for before each OK true.
    unreadable_first,
    /// Refuses every EVENT with a reason carrying a terminal escape and a
    /// newline followed by a line that claims the event was accepted.
    hostile,
};

/// The allocator a test hands to anything that dials.
///
/// Still leak-checked, but it captures no stack traces. On macOS capturing one
/// takes a lock that notices a pending cancel and swallows it, so a dial that
/// is cancelled while it allocates never finds out and never returns, and the
/// test hangs instead of failing. `std.testing.allocator` captures them.
pub const DialAllocator = std.heap.DebugAllocator(.{ .stack_trace_frames = 0 });

/// A loopback listener on a port the kernel picks.
pub fn listen(io: Io) !Io.net.Server {
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    return address.listen(io, .{ .reuse_address = true });
}

/// `ws://127.0.0.1:<port>`, written into `buf`.
pub fn url(buf: []u8, port: u16) ![]const u8 {
    return std.fmt.bufPrint(buf, "ws://127.0.0.1:{d}", .{port});
}

pub const Relay = struct {
    server: Io.net.Server,
    mode: Mode,
    /// EVENT messages this relay has received, across every connection.
    events: std.atomic.Value(usize) = .init(0),
    /// Set by `close_after_ok` once it has answered, to end the connection.
    closing: bool = false,
    /// Connections served before the task returns.
    connections: usize = 1,
    task: Io.Future(void),

    /// Starts serving in the background. `self` must not move until `stop`.
    pub fn start(self: *Relay, io: Io, mode: Mode) !void {
        return self.startFor(io, mode, 1);
    }

    /// Like `start`, serving `connections` connections one after another.
    /// Only for a relay whose earlier connections end on their own: see
    /// `serve` for why a cancel must never land in the middle of one.
    pub fn startFor(self: *Relay, io: Io, mode: Mode, connections: usize) !void {
        self.* = .{ .server = try listen(io), .mode = mode, .connections = connections, .task = undefined };
        errdefer self.server.deinit(io);
        if (mode == .deaf or mode == .pings_deaf) {
            // A small window, inherited by the connection it accepts, so what
            // is sent to it fills the sender's socket after a few hundred
            // kilobytes however large the system's defaults are.
            const size: c_int = 4096;
            try std.posix.setsockopt(self.server.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&size));
        }
        self.task = try io.concurrent(serve, .{ self, io });
    }

    pub fn stop(self: *Relay, io: Io) void {
        self.task.cancel(io);
        self.server.deinit(io);
    }

    pub fn port(self: *const Relay) u16 {
        return self.server.socket.address.ip4.port;
    }

    /// One connection, then done. A loop back to `accept` would be the one
    /// place a cancel could be lost: a cancel that lands while the connection
    /// is being read comes back as a read error, and once a task has seen its
    /// cancel, a blocking call it makes afterwards can no longer be woken, so
    /// `stop` would wait on that `accept` forever.
    fn serve(self: *Relay, io: Io) void {
        for (0..self.connections) |_| {
            const conn = self.server.accept(io) catch return;
            defer conn.close(io);
            self.handle(io, conn) catch {};
        }
    }

    fn handle(self: *Relay, io: Io, conn: Io.net.Stream) !void {
        // Not `std.testing.allocator`, for the reason `DialAllocator` gives:
        // this task is cancelled when the test stops the relay, and a cancel
        // swallowed by a stack capture would leave `stop` waiting forever.
        const gpa = std.heap.page_allocator;
        self.closing = false;
        var rbuf: [8192]u8 = undefined;
        var wbuf: [8192]u8 = undefined;
        var r = conn.reader(io, &rbuf);
        var w = conn.writer(io, &wbuf);

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        while (std.mem.indexOf(u8, req.items, "\r\n\r\n") == null) {
            try r.interface.fillMore();
            const got = r.interface.buffered();
            try req.appendSlice(gpa, got);
            r.interface.toss(got.len);
        }
        const prefix = "Sec-WebSocket-Key: ";
        const ks = (std.mem.indexOf(u8, req.items, prefix) orelse return error.NoKey) + prefix.len;
        const ke = std.mem.indexOfPos(u8, req.items, ks, "\r\n") orelse return error.NoKey;
        const accept_key = ws.acceptKey(req.items[ks..ke]);
        try w.interface.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept_key});
        try w.interface.flush();

        switch (self.mode) {
            .chatty => {
                for (0..40) |_| {
                    try io.sleep(.fromMilliseconds(100), .awake);
                    try sendText(&w.interface, "[\"NOTICE\",\"still here\"]");
                }
                return;
            },
            .notice_burst => for (0..20) |_| try sendText(&w.interface, "[\"NOTICE\",\"again\"]"),
            .pongs => while (true) {
                try w.interface.writeAll(&.{ 0x8A, 0x00 });
                try w.interface.flush();
            },
            .deaf => while (true) try io.sleep(.fromMilliseconds(1000), .awake),
            // The largest a ping may carry, so the pongs echoing it fill the
            // socket within a fraction of a second rather than many.
            .pings_deaf => while (true) {
                try w.interface.writeAll(&(.{ 0x89, 125 } ++ .{'p'} ** 125));
                try w.interface.flush();
            },
            else => {},
        }

        var frames: std.ArrayList(u8) = .empty;
        defer frames.deinit(gpa);
        var seen: usize = 0;
        while (true) {
            if (self.closing) return;
            // Not `readSliceShort`: it blocks until its destination is full,
            // so a frame smaller than the buffer would never surface.
            r.interface.fillMore() catch return;
            const avail = r.interface.buffered();
            try frames.appendSlice(gpa, avail);
            r.interface.toss(avail.len);
            while (try ws.decodeFrame(frames.items)) |f| {
                if (f.opcode == .close) return;
                if (f.opcode == .text) try self.answer(gpa, &w.interface, f.payload, &seen);
                if (self.closing) return;
                const n = f.frame_len;
                std.mem.copyForwards(u8, frames.items, frames.items[n..]);
                frames.shrinkRetainingCapacity(frames.items.len - n);
            }
        }
    }

    fn answer(self: *Relay, gpa: std.mem.Allocator, w: *Io.Writer, payload: []const u8, seen: *usize) !void {
        if (self.mode == .silent) return;
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, payload, .{});
        defer parsed.deinit();
        const items = parsed.value.array.items;
        const kind = items[0].string;
        var text: [512]u8 = undefined;
        if (std.mem.eql(u8, kind, "REQ")) {
            try sendText(w, try std.fmt.bufPrint(&text, "[\"EOSE\",\"{s}\"]", .{items[1].string}));
        } else if (std.mem.eql(u8, kind, "EVENT")) {
            _ = self.events.fetchAdd(1, .monotonic);
            seen.* += 1;
            const id = items[1].object.get("id").?.string;
            switch (self.mode) {
                .accept => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id})),
                .refuse => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",false,\"invalid: test refusal\"]", .{id})),
                .duplicate => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"duplicate: already have it\"]", .{id})),
                .hostile => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",false,\"invalid: \\u001b[31mred\\ndeed publish: {s}: ws://x: accepted\"]", .{ id, id })),
                .close_after_ok => {
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                    self.closing = true;
                },
                .stale_ok => {
                    try sendText(w, "[\"OK\",\"" ++ "00" ** 32 ++ "\",true,\"\"]");
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",false,\"invalid: not this one\"]", .{id}));
                },
                .hostile_accept => {
                    try sendText(w, "[\"NOTICE\",\"\\u001bbad\\u007f\\u009b31m\"]");
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"note\\u001b[2J\\u009b2J\\u007f\"]", .{id}));
                },
                .ping_then_ok => {
                    try w.writeAll(&.{ 0x89, 0x00 });
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                },
                .notices_then_ok => {
                    for (0..70) |_| try sendText(w, "[\"NOTICE\",\"busy\"]");
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                },
                .notices_then_close => {
                    for (0..20) |_| try sendText(w, "[\"NOTICE\",\"again\"]");
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                    self.closing = true;
                },
                .ping_then_close => {
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                    try w.writeAll(&.{ 0x89, 0x00, 0x88, 0x00 });
                    try w.flush();
                    self.closing = true;
                },
                .close_on_second_event => {
                    if (seen.* >= 2) {
                        self.closing = true;
                    } else {
                        try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                    }
                },
                .unreadable_first => {
                    try sendText(w, "[\"COUNT\",\"x\",{\"count\":1}]");
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                },
                .silent, .chatty, .notice_burst, .pongs, .deaf, .pings_deaf => {},
            }
        }
    }
};

/// One unmasked server text frame.
fn sendText(w: *Io.Writer, text: []const u8) !void {
    if (text.len < 126) {
        try w.writeAll(&.{ 0x81, @intCast(text.len) });
    } else {
        try w.writeAll(&.{ 0x81, 126, @intCast(text.len >> 8), @intCast(text.len & 0xff) });
    }
    try w.writeAll(text);
    try w.flush();
}
