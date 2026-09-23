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
    /// Never answers an EVENT, and sends a NOTICE every 100 ms, so a wait
    /// that restarts on every message would never end.
    chatty,
    /// Sends a message the parser has no case for before each OK true.
    unreadable_first,
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
    task: Io.Future(void),

    /// Starts serving in the background. `self` must not move until `stop`.
    pub fn start(self: *Relay, io: Io, mode: Mode) !void {
        self.* = .{ .server = try listen(io), .mode = mode, .task = undefined };
        errdefer self.server.deinit(io);
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
        const conn = self.server.accept(io) catch return;
        defer conn.close(io);
        self.handle(io, conn) catch {};
    }

    fn handle(self: *Relay, io: Io, conn: Io.net.Stream) !void {
        // Not `std.testing.allocator`, for the reason `DialAllocator` gives:
        // this task is cancelled when the test stops the relay, and a cancel
        // swallowed by a stack capture would leave `stop` waiting forever.
        const gpa = std.heap.page_allocator;
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

        if (self.mode == .chatty) {
            while (true) {
                try io.sleep(.fromMilliseconds(100), .awake);
                try sendText(&w.interface, "[\"NOTICE\",\"still here\"]");
            }
        }

        var frames: std.ArrayList(u8) = .empty;
        defer frames.deinit(gpa);
        while (true) {
            // Not `readSliceShort`: it blocks until its destination is full,
            // so a frame smaller than the buffer would never surface.
            r.interface.fillMore() catch return;
            const avail = r.interface.buffered();
            try frames.appendSlice(gpa, avail);
            r.interface.toss(avail.len);
            while (try ws.decodeFrame(frames.items)) |f| {
                if (f.opcode == .close) return;
                if (f.opcode == .text) try self.answer(gpa, &w.interface, f.payload);
                const n = f.frame_len;
                std.mem.copyForwards(u8, frames.items, frames.items[n..]);
                frames.shrinkRetainingCapacity(frames.items.len - n);
            }
        }
    }

    fn answer(self: *Relay, gpa: std.mem.Allocator, w: *Io.Writer, payload: []const u8) !void {
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
            const id = items[1].object.get("id").?.string;
            switch (self.mode) {
                .accept => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id})),
                .refuse => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",false,\"invalid: test refusal\"]", .{id})),
                .duplicate => try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"duplicate: already have it\"]", .{id})),
                .unreadable_first => {
                    try sendText(w, "[\"COUNT\",\"x\",{\"count\":1}]");
                    try sendText(w, try std.fmt.bufPrint(&text, "[\"OK\",\"{s}\",true,\"\"]", .{id}));
                },
                .silent, .chatty => {},
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
