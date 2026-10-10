//! The relay behind `deed serve`: a websocket server over a local event store.
//!
//! Each connection gets two tasks. The reader takes frames off the socket,
//! answers them, and is the only code that changes that connection's
//! subscriptions. The writer drains a queue of frames onto the socket. Nothing
//! else writes to a socket, so a client that stops reading slows down nobody
//! but itself: an event published elsewhere is offered to its queue without
//! waiting, and a queue that grows past `Limits.queue_hard` gets the
//! connection dropped rather than the publisher held.
//!
//! Every way out of a connection goes through the socket. A slow consumer, a
//! handshake that never finishes and a server that is stopping all shut the
//! socket down, which wakes whichever task is blocked on it.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");

const Io = std.Io;
const ws = nostr.websocket;
const message = nostr.message;
const event = nostr.event;
const keys = nostr.keys;
const hex = nostr.hex;
const nip77 = nostr.nip77;
const Event = event.Event;
const Filter = nostr.filter.Filter;
const Store = nostr.store.Store;

pub const Limits = struct {
    /// The largest message a client may send, in bytes, after reassembly.
    max_message_len: usize = 512 * 1024,
    /// Open subscriptions per connection.
    max_subscriptions: usize = 64,
    /// Filters in one REQ or COUNT.
    max_filters: usize = 32,
    /// The most stored events one filter is answered with.
    max_limit: u32 = 10_000,
    /// Bytes queued for one connection before its own replies wait for the
    /// client to read.
    queue_soft: usize = 1 << 20,
    /// Bytes queued for one connection before it is dropped as too slow.
    queue_hard: usize = 4 << 20,
    /// Connections open at once.
    max_connections: usize = 1024,
    /// Open NIP-77 reconciliations per connection.
    max_neg_sessions: usize = 8,
    /// Stored events one reconciliation may cover.
    max_neg_items: usize = 500_000,
    /// The largest negentropy message the relay produces, before hex.
    neg_frame_limit: u64 = 500_000,
    /// How long a client has to finish the HTTP request.
    handshake_timeout_ms: i64 = 10_000,
    /// The largest HTTP request head accepted.
    max_head_len: usize = 16 * 1024,
};

pub const Options = struct {
    address: Io.net.IpAddress,
    /// The host as it was given, for the URL that is printed and for the
    /// NIP-42 relay tag. Empty means the address itself.
    hostname: []const u8 = "",
    auth_required: bool = false,
    limits: Limits = .{},
    /// Where connections and errors are logged, or null for silence.
    log: ?*Io.Writer = null,
};

/// The NIPs the relay answers, as the NIP-11 document lists them.
pub const supported_nips = [_]u16{ 1, 9, 11, 40, 42, 45, 70, 77 };

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    store: *Store,
    opts: Options,
    listener: Io.net.Server,
    url_buf: [320]u8 = undefined,
    url_len: usize = 0,
    accept_task: Io.Future(void) = undefined,
    group: Io.Group = .init,
    mu: Io.Mutex = .init,
    conns: std.ArrayList(*Conn) = .empty,
    log_mu: Io.Mutex = .init,
    /// Event JSON fanned out to subscriptions, counted for tests.
    fanned: std.atomic.Value(u64) = .init(0),
    /// Connections dropped for reading too slowly.
    dropped: std.atomic.Value(u64) = .init(0),

    /// Starts listening and accepting in the background. `self` must not move
    /// until `stop`. `store` must outlive the server.
    pub fn start(self: *Server, gpa: std.mem.Allocator, io: Io, store: *Store, opts: Options) !void {
        self.* = .{
            .gpa = gpa,
            .io = io,
            .store = store,
            .opts = opts,
            .listener = try opts.address.listen(io, .{ .reuse_address = true }),
        };
        errdefer self.listener.deinit(io);
        const host = if (opts.hostname.len > 0) opts.hostname else blk: {
            var tmp: [64]u8 = undefined;
            const s = switch (opts.address) {
                .ip4 => |a| std.fmt.bufPrint(&tmp, "{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }) catch unreachable,
                .ip6 => "[::1]",
            };
            break :blk s;
        };
        const bracket = std.mem.indexOfScalar(u8, host, ':') != null and host[0] != '[';
        const u = if (bracket)
            try std.fmt.bufPrint(&self.url_buf, "ws://[{s}]:{d}", .{ host, self.port() })
        else
            try std.fmt.bufPrint(&self.url_buf, "ws://{s}:{d}", .{ host, self.port() });
        self.url_len = u.len;
        self.accept_task = try io.concurrent(acceptLoop, .{self});
    }

    /// The port the kernel bound, which differs from the one asked for when
    /// that was 0.
    pub fn port(self: *const Server) u16 {
        return self.listener.socket.address.getPort();
    }

    /// `ws://host:port`.
    pub fn url(self: *const Server) []const u8 {
        return self.url_buf[0..self.url_len];
    }

    /// Stops accepting, ends every connection and waits for them.
    pub fn stop(self: *Server) void {
        _ = self.accept_task.cancel(self.io);
        self.group.cancel(self.io);
        self.listener.deinit(self.io);
        self.conns.deinit(self.gpa);
    }

    /// How many connections are open.
    pub fn connectionCount(self: *Server) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.conns.items.len;
    }

    fn log(self: *Server, comptime fmt: []const u8, args: anytype) void {
        const w = self.opts.log orelse return;
        // A write to stderr is a cancelation point, and a cancel it took would
        // come back as `WriteFailed` and be lost. Logging never takes one.
        const old = self.io.swapCancelProtection(.blocked);
        defer _ = self.io.swapCancelProtection(old);
        self.log_mu.lockUncancelable(self.io);
        defer self.log_mu.unlock(self.io);
        w.print("deed serve: " ++ fmt ++ "\n", args) catch {};
        w.flush() catch {};
    }

    /// One task, accepting. Each connection runs in `group`, so `stop` can end
    /// them all at once.
    fn acceptLoop(self: *Server) void {
        while (true) {
            const stream = self.listener.accept(self.io) catch |e| switch (e) {
                error.Canceled, error.SocketNotListening => return,
                else => {
                    self.log("accept failed: {s}", .{@errorName(e)});
                    // Out of descriptors, most likely. Give the open
                    // connections a moment to close some.
                    self.io.sleep(.fromMilliseconds(50), .awake) catch return;
                    continue;
                },
            };
            self.group.concurrent(self.io, connMain, .{ self, stream }) catch |e| {
                self.log("cannot serve a connection: {s}", .{@errorName(e)});
                stream.close(self.io);
            };
        }
    }

    fn register(self: *Server, c: *Conn) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.conns.items.len >= self.opts.limits.max_connections) return false;
        self.conns.append(self.gpa, c) catch return false;
        return true;
    }

    fn unregister(self: *Server, c: *Conn) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        for (self.conns.items, 0..) |x, i| if (x == c) {
            _ = self.conns.swapRemove(i);
            return;
        };
    }

    /// Offers `ev` to every subscription that matches it, on every
    /// connection. Never waits on a client.
    fn fanout(self: *Server, ev: Event) void {
        const json = event.toJson(self.gpa, ev) catch return;
        defer self.gpa.free(json);
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        for (self.conns.items) |c| {
            c.sub_mu.lockUncancelable(self.io);
            defer c.sub_mu.unlock(self.io);
            var it = c.subs.iterator();
            while (it.next()) |entry| {
                if (!anyMatches(entry.value_ptr.filters, ev)) continue;
                const frame = eventFrame(self.gpa, entry.key_ptr.*, json) catch continue;
                _ = self.fanned.fetchAdd(1, .monotonic);
                c.offer(frame);
            }
        }
    }
};

const Sub = struct {
    /// The REQ this subscription came from. Its arena holds the filters and
    /// the subscription id.
    parsed: message.ParsedClientMessage,
    filters: []const Filter,
};

const Neg = struct {
    storage: nip77.Storage,
    responder: nip77.Responder,
};

const Conn = struct {
    server: *Server,
    gpa: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    peer_buf: [64]u8 = undefined,
    peer_len: usize = 0,

    // The queue the writer drains. Guarded by `q_mu`.
    q_mu: Io.Mutex = .init,
    q_data: Io.Condition = .init,
    q_space: Io.Condition = .init,
    q_items: std.ArrayList([]u8) = .empty,
    q_bytes: usize = 0,
    /// Write what is queued, then stop.
    closing: bool = false,
    /// Stop now.
    dead: bool = false,
    slow: bool = false,

    handshake_done: Io.Event = .unset,
    writer_done: Io.Event = .unset,

    // Subscriptions. The reader changes them, fan-out reads them; both under
    // `sub_mu`.
    sub_mu: Io.Mutex = .init,
    subs: std.StringHashMapUnmanaged(Sub) = .empty,

    // The reader's alone.
    negs: std.StringHashMapUnmanaged(*Neg) = .empty,
    signer: keys.Signer,
    challenge: [32]u8 = undefined,
    authed: ?[32]u8 = null,
    host_buf: [256]u8 = undefined,
    host_len: usize = 0,

    fn peer(c: *const Conn) []const u8 {
        return c.peer_buf[0..c.peer_len];
    }

    fn deinit(c: *Conn) void {
        for (c.q_items.items) |f| c.gpa.free(f);
        c.q_items.deinit(c.gpa);
        var it = c.subs.valueIterator();
        while (it.next()) |s| s.parsed.deinit();
        c.subs.deinit(c.gpa);
        var nit = c.negs.iterator();
        while (nit.next()) |e| {
            c.gpa.free(e.key_ptr.*);
            e.value_ptr.*.storage.deinit(c.gpa);
            c.gpa.destroy(e.value_ptr.*);
        }
        c.negs.deinit(c.gpa);
        c.signer.deinit();
    }

    /// Ends the connection now: the writer stops and the reader's socket
    /// read returns.
    fn kill(c: *Conn) void {
        c.q_mu.lockUncancelable(c.io);
        c.dead = true;
        c.q_data.broadcast(c.io);
        c.q_space.broadcast(c.io);
        c.q_mu.unlock(c.io);
        c.stream.shutdown(c.io, .both) catch {};
    }

    /// Queues a frame without waiting. Takes `frame`. A connection whose
    /// queue is already past `queue_hard` is dropped instead.
    fn offer(c: *Conn, frame: []u8) void {
        c.q_mu.lockUncancelable(c.io);
        if (c.dead or c.closing) {
            c.q_mu.unlock(c.io);
            c.gpa.free(frame);
            return;
        }
        if (c.q_bytes + frame.len > c.server.opts.limits.queue_hard) {
            c.dead = true;
            c.slow = true;
            c.q_data.broadcast(c.io);
            c.q_space.broadcast(c.io);
            c.q_mu.unlock(c.io);
            c.gpa.free(frame);
            _ = c.server.dropped.fetchAdd(1, .monotonic);
            c.stream.shutdown(c.io, .both) catch {};
            return;
        }
        c.q_items.append(c.gpa, frame) catch {
            c.q_mu.unlock(c.io);
            c.gpa.free(frame);
            return;
        };
        c.q_bytes += frame.len;
        c.q_data.signal(c.io);
        c.q_mu.unlock(c.io);
    }

    /// Queues a frame of the reader's own, waiting while the queue is past
    /// `queue_soft`: a client that asked for a lot and reads slowly holds up
    /// its own answers and nothing else. Takes `frame`.
    fn push(c: *Conn, frame: []u8) SendError!void {
        c.q_mu.lockUncancelable(c.io);
        defer c.q_mu.unlock(c.io);
        while (c.q_bytes >= c.server.opts.limits.queue_soft and !c.dead) {
            c.q_space.wait(c.io, &c.q_mu) catch |e| {
                c.gpa.free(frame);
                return e;
            };
        }
        if (c.dead) {
            c.gpa.free(frame);
            return error.Gone;
        }
        c.q_items.append(c.gpa, frame) catch |e| {
            c.gpa.free(frame);
            return e;
        };
        c.q_bytes += frame.len;
        c.q_data.signal(c.io);
    }

    fn sendPayload(c: *Conn, opcode: ws.Opcode, payload: []const u8) SendError!void {
        const frame = try buildFrame(c.gpa, opcode, &.{payload});
        return c.push(frame);
    }

    /// Sends an encoded message and frees it.
    fn sendOwned(c: *Conn, payload: []u8) SendError!void {
        defer c.gpa.free(payload);
        return c.sendPayload(.text, payload);
    }

    fn notice(c: *Conn, text: []const u8) SendError!void {
        return c.sendOwned(try message.encodeNotice(c.gpa, text));
    }

    fn ok(c: *Conn, id: [32]u8, accepted: bool, text: []const u8) SendError!void {
        return c.sendOwned(try message.encodeOk(c.gpa, id, accepted, text));
    }

    fn closed(c: *Conn, sub: []const u8, text: []const u8) SendError!void {
        return c.sendOwned(try message.encodeClosed(c.gpa, sub, text));
    }

    fn negErr(c: *Conn, sub: []const u8, text: []const u8) SendError!void {
        return c.sendOwned(try message.encodeNegErr(c.gpa, sub, text));
    }

    /// Sends a close frame with `code` and `reason`, logs it, and asks the
    /// writer to finish.
    fn closeWith(c: *Conn, code: u16, reason: []const u8) SendError!void {
        var payload: [125]u8 = undefined;
        std.mem.writeInt(u16, payload[0..2], code, .big);
        const n = @min(reason.len, payload.len - 2);
        @memcpy(payload[2..][0..n], reason[0..n]);
        if (code != 1000) c.server.log("{s}: closed: {s}", .{ c.peer(), reason });
        try c.sendPayload(.close, payload[0 .. 2 + n]);
    }

    fn needsAuth(c: *const Conn) bool {
        return c.server.opts.auth_required and c.authed == null;
    }
};

const SendError = error{ OutOfMemory, Canceled, Gone };

/// One connection, start to finish.
fn connMain(server: *Server, stream: Io.net.Stream) Io.Cancelable!void {
    const io = server.io;
    const gpa = server.gpa;
    const c = gpa.create(Conn) catch {
        stream.close(io);
        return;
    };
    c.* = .{ .server = server, .gpa = gpa, .io = io, .stream = stream, .signer = keys.Signer.init() };
    defer {
        c.deinit();
        gpa.destroy(c);
        stream.close(io);
    }
    c.peer_len = if (std.fmt.bufPrint(&c.peer_buf, "{f}", .{stream.socket.address})) |s| s.len else |_| 0;
    io.random(&c.challenge);

    var writer = io.concurrent(writerMain, .{c}) catch |e| {
        server.log("{s}: cannot start a writer: {s}", .{ c.peer(), @errorName(e) });
        return;
    };

    var registered = false;
    const result = serveConn(c, &registered);
    if (registered) server.unregister(c);

    // The writer may still be waiting for the handshake.
    c.handshake_done.set(io);
    c.q_mu.lockUncancelable(io);
    c.closing = true;
    c.q_data.broadcast(io);
    c.q_mu.unlock(io);

    const canceled = if (result) |_| false else |e| e == error.Canceled;
    if (canceled or c.dead) {
        c.kill();
        writer.cancel(io) catch {};
    } else {
        // Give what is queued, a close frame most likely, a moment to go
        // out, then take the socket down whatever the client is doing.
        const deadline: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(2_000), .clock = .awake } };
        const until = deadline.toDeadline(io);
        while (!c.writer_done.isSet()) {
            c.writer_done.waitTimeout(io, until) catch |e| switch (e) {
                error.Canceled => {
                    c.kill();
                    writer.cancel(io) catch {};
                    return error.Canceled;
                },
                error.Timeout => if (until.toDurationFromNow(io).?.raw.toNanoseconds() <= 0) break,
            };
        }
        c.stream.shutdown(io, .both) catch {};
        writer.await(io) catch {};
    }
    if (registered) {
        if (c.slow) {
            server.log("{s}: dropped: it was not reading fast enough", .{c.peer()});
        } else {
            server.log("{s}: disconnected", .{c.peer()});
        }
    }
    if (canceled) return error.Canceled;
}

/// The writer: waits for the handshake, then drains the queue onto the socket.
fn writerMain(c: *Conn) Io.Cancelable!void {
    const io = c.io;
    defer c.writer_done.set(io);

    const limit: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(c.server.opts.limits.handshake_timeout_ms), .clock = .awake } };
    const until = limit.toDeadline(io);
    while (!c.handshake_done.isSet()) {
        c.handshake_done.waitTimeout(io, until) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            error.Timeout => if (until.toDurationFromNow(io).?.raw.toNanoseconds() <= 0) {
                c.kill();
                return;
            },
        };
    }

    var wbuf: [16 * 1024]u8 = undefined;
    var w = c.stream.writer(io, &wbuf);
    var batch: std.ArrayList([]u8) = .empty;
    defer {
        for (batch.items) |f| c.gpa.free(f);
        batch.deinit(c.gpa);
    }
    while (true) {
        {
            c.q_mu.lockUncancelable(io);
            defer c.q_mu.unlock(io);
            while (c.q_items.items.len == 0 and !c.closing and !c.dead) {
                try c.q_data.wait(io, &c.q_mu);
            }
            if (c.dead or c.q_items.items.len == 0) return;
            std.mem.swap(std.ArrayList([]u8), &c.q_items, &batch);
        }
        var written: usize = 0;
        for (batch.items) |f| {
            w.interface.writeAll(f) catch return writeFailed(c, &w);
            written += f.len;
        }
        w.interface.flush() catch return writeFailed(c, &w);
        for (batch.items) |f| c.gpa.free(f);
        batch.clearRetainingCapacity();

        c.q_mu.lockUncancelable(io);
        c.q_bytes -= written;
        c.q_space.broadcast(io);
        c.q_mu.unlock(io);
    }
}

fn writeFailed(c: *Conn, w: *Io.net.Stream.Writer) Io.Cancelable!void {
    if (w.err) |e| if (e == error.Canceled) return error.Canceled;
    c.kill();
}

// -- the reader ---------------------------------------------------------------

fn serveConn(c: *Conn, registered: *bool) Io.Cancelable!void {
    const io = c.io;
    const gpa = c.gpa;
    var rbuf: [32 * 1024]u8 = undefined;
    var r = c.stream.reader(io, &rbuf);

    var recv: std.ArrayList(u8) = .empty;
    defer recv.deinit(gpa);

    // The request head.
    const limits = c.server.opts.limits;
    var head_end: usize = 0;
    while (true) {
        if (std.mem.indexOf(u8, recv.items, "\r\n\r\n")) |i| {
            head_end = i + 4;
            break;
        }
        if (recv.items.len > limits.max_head_len) {
            return httpReply(c, "431 Request Header Fields Too Large", "text/plain", "request head too large\n");
        }
        if (!(try fill(&r, &recv, gpa))) return;
    }
    const head = recv.items[0..head_end];

    const key = headerValue(head, "sec-websocket-key");
    const upgrade = headerValue(head, "upgrade");
    const is_ws = key != null and upgrade != null and std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade.?, " "), "websocket");
    if (!is_ws) return answerHttp(c, head);

    if (!c.server.register(c)) {
        return httpReply(c, "503 Service Unavailable", "text/plain", "too many connections\n");
    }
    registered.* = true;
    if (headerValue(head, "host")) |h| {
        const n = @min(h.len, c.host_buf.len);
        @memcpy(c.host_buf[0..n], h[0..n]);
        c.host_len = n;
    }

    const accept = ws.acceptKey(std.mem.trim(u8, key.?, " "));
    {
        var wbuf: [256]u8 = undefined;
        var w = c.stream.writer(io, &wbuf);
        w.interface.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept}) catch {
            if (w.err) |e| if (e == error.Canceled) return error.Canceled;
            return;
        };
        w.interface.flush() catch {
            if (w.err) |e| if (e == error.Canceled) return error.Canceled;
            return;
        };
    }
    c.handshake_done.set(io);
    c.server.log("{s}: connected", .{c.peer()});

    // Whatever followed the head is the first of the frames.
    std.mem.copyForwards(u8, recv.items, recv.items[head_end..]);
    recv.shrinkRetainingCapacity(recv.items.len - head_end);

    if (c.server.opts.auth_required) {
        var hexbuf: [64]u8 = undefined;
        const ch = std.fmt.bufPrint(&hexbuf, "{x}", .{&c.challenge}) catch unreachable;
        const payload = message.encodeAuthChallenge(gpa, ch) catch return;
        c.sendOwned(payload) catch |e| return goneOrCanceled(e);
    }

    readFrames(c, &r, &recv) catch |e| return goneOrCanceled(e);
}

fn goneOrCanceled(e: anyerror) Io.Cancelable!void {
    if (e == error.Canceled) return error.Canceled;
}

/// Reads more bytes into `recv`. False at the end of the stream or on a read
/// error; a cancel is passed on.
fn fill(r: *Io.net.Stream.Reader, recv: *std.ArrayList(u8), gpa: std.mem.Allocator) Io.Cancelable!bool {
    r.interface.fillMore() catch {
        if (r.err) |e| if (e == error.Canceled) return error.Canceled;
        return false;
    };
    const got = r.interface.buffered();
    recv.appendSlice(gpa, got) catch return false;
    r.interface.toss(got.len);
    return true;
}

const FrameHeader = struct {
    fin: bool,
    rsv: u3,
    opcode: u4,
    masked: bool,
    len: u64,
    header_len: usize,
};

/// The header at the front of `buf`, or null if it has not all arrived. Read
/// before the payload, so an oversized frame is refused before it is buffered.
fn peekHeader(buf: []const u8) ?FrameHeader {
    if (buf.len < 2) return null;
    var h: FrameHeader = .{
        .fin = buf[0] & 0x80 != 0,
        .rsv = @intCast((buf[0] >> 4) & 0x7),
        .opcode = @intCast(buf[0] & 0x0f),
        .masked = buf[1] & 0x80 != 0,
        .len = buf[1] & 0x7f,
        .header_len = 2,
    };
    if (h.len == 126) {
        if (buf.len < 4) return null;
        h.len = std.mem.readInt(u16, buf[2..4], .big);
        h.header_len = 4;
    } else if (h.len == 127) {
        if (buf.len < 10) return null;
        h.len = std.mem.readInt(u64, buf[2..10], .big);
        h.header_len = 10;
    }
    if (h.masked) h.header_len += 4;
    if (buf.len < h.header_len) return null;
    return h;
}

const ReadError = SendError;

fn readFrames(c: *Conn, r: *Io.net.Stream.Reader, recv: *std.ArrayList(u8)) ReadError!void {
    const gpa = c.gpa;
    const max = c.server.opts.limits.max_message_len;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    var in_msg = false;

    while (true) {
        var start: usize = 0;
        while (true) {
            const avail = recv.items[start..];
            const h = peekHeader(avail) orelse break;
            if (!h.masked) return c.closeWith(1002, "a frame from a client must be masked");
            if (h.rsv != 0) return c.closeWith(1002, "reserved bits are set");
            if (h.len > max) return c.closeWith(1009, "message too big");
            const total = h.header_len + @as(usize, @intCast(h.len));
            if (avail.len < total) break;
            const f = (ws.decodeFrame(recv.items[start .. start + total]) catch
                return c.closeWith(1002, "the frame could not be read")) orelse unreachable;
            start += total;

            switch (f.opcode) {
                .ping => {
                    if (!f.fin or f.payload.len > 125) return c.closeWith(1002, "a control frame was too long or fragmented");
                    try c.sendPayload(.pong, f.payload);
                },
                .pong => {},
                .close => {
                    const code: u16 = if (f.payload.len >= 2) std.mem.readInt(u16, f.payload[0..2], .big) else 1000;
                    var reply: [2]u8 = undefined;
                    std.mem.writeInt(u16, &reply, code, .big);
                    try c.sendPayload(.close, &reply);
                    return;
                },
                .text => {
                    if (in_msg) return c.closeWith(1002, "a new message began inside another");
                    if (f.fin) {
                        try handleText(c, f.payload);
                    } else {
                        in_msg = true;
                        msg.clearRetainingCapacity();
                        try msg.appendSlice(gpa, f.payload);
                    }
                },
                .continuation => {
                    if (!in_msg) return c.closeWith(1002, "a continuation with no message to continue");
                    if (msg.items.len + f.payload.len > max) return c.closeWith(1009, "message too big");
                    try msg.appendSlice(gpa, f.payload);
                    if (f.fin) {
                        in_msg = false;
                        try handleText(c, msg.items);
                        msg.clearRetainingCapacity();
                        if (msg.capacity > 64 * 1024) msg.clearAndFree(gpa);
                    }
                },
                .binary => return c.closeWith(1003, "binary messages are not supported"),
                else => return c.closeWith(1002, "unknown opcode"),
            }
        }
        if (start > 0) {
            std.mem.copyForwards(u8, recv.items, recv.items[start..]);
            recv.shrinkRetainingCapacity(recv.items.len - start);
        }
        if (recv.capacity > 2 * max and recv.items.len < 64 * 1024) {
            const keep = try gpa.dupe(u8, recv.items);
            recv.clearAndFree(gpa);
            recv.* = .fromOwnedSlice(keep);
        }
        if (!(try fill(r, recv, gpa))) return;
    }
}

// -- messages -----------------------------------------------------------------

fn handleText(c: *Conn, text: []const u8) SendError!void {
    var parsed = message.parseClientMessage(c.gpa, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidMessage => return refuseUnreadable(c, text),
    };
    var kept = false;
    defer if (!kept) parsed.deinit();
    switch (parsed.value) {
        .event => |ev| try onEvent(c, ev),
        .req => |q| kept = try onReq(c, parsed, q.subscription_id, q.filters),
        .close => |q| onClose(c, q.subscription_id),
        .count => |q| try onCount(c, q.subscription_id, q.filters),
        .auth => |ev| try onAuth(c, ev),
        .neg_open => |q| try onNegOpen(c, q.sub_id, q.filter, q.initial_hex),
        .neg_msg => |q| try onNegMsg(c, q.sub_id, q.hex),
        .neg_close => |q| onNegClose(c, q.sub_id),
    }
}

/// A message the parser could not read. An EVENT whose id can still be found
/// gets an OK false, because a publisher waits for one; anything else gets a
/// notice.
fn refuseUnreadable(c: *Conn, text: []const u8) SendError!void {
    var arena = std.heap.ArenaAllocator.init(c.gpa);
    defer arena.deinit();
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), text, .{}) catch
        return c.notice("invalid: not JSON");
    if (v == .array and v.array.items.len >= 2 and v.array.items[0] == .string) {
        const items = v.array.items;
        if (std.mem.eql(u8, items[0].string, "EVENT") and items[1] == .object) {
            if (items[1].object.get("id")) |idv| if (idv == .string) {
                if (hex.decodeFixed(32, idv.string)) |id| {
                    return c.ok(id, false, "invalid: the event is malformed");
                } else |_| {}
            };
        }
        if (std.mem.eql(u8, items[0].string, "REQ") or std.mem.eql(u8, items[0].string, "COUNT")) {
            if (items[1] == .string and items[1].string.len > 0 and items[1].string.len <= message.max_subscription_id_len) {
                return c.closed(items[1].string, "invalid: the subscription could not be read");
            }
        }
    }
    return c.notice("invalid: the message could not be read");
}

fn onEvent(c: *Conn, ev: Event) SendError!void {
    if (c.needsAuth()) return c.ok(ev.id, false, "auth-required: this relay takes events only after AUTH");
    if (ev.kind == nostr.nip42.kind) return c.ok(ev.id, false, "invalid: an AUTH event goes in an AUTH message");
    const id = try event.computeId(c.gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    if (!std.mem.eql(u8, &id, &ev.id)) return c.ok(ev.id, false, "invalid: the id does not match the event");
    if (!c.signer.verifyId(ev.sig, ev.id, ev.pubkey)) return c.ok(ev.id, false, "invalid: the signature does not verify");
    // NIP-40: an event that has already expired is not taken.
    if (expiration(ev)) |at| if (at <= nowSeconds(c.io)) {
        return c.ok(ev.id, false, "invalid: the event has expired");
    };
    // NIP-70: a protected event is taken only from its own author.
    if (isProtected(ev)) {
        const a = c.authed orelse return c.ok(ev.id, false, "auth-required: a protected event needs its author to AUTH");
        if (!std.mem.eql(u8, &a, &ev.pubkey)) return c.ok(ev.id, false, "restricted: a protected event is taken only from its author");
    }

    const result = c.server.store.ingest(c.gpa, ev, .{}) catch |e| {
        if (e == error.OutOfMemory) return error.OutOfMemory;
        c.server.log("the store could not take an event: {s}", .{@errorName(e)});
        return c.ok(ev.id, false, "error: the store could not take it");
    };
    switch (result) {
        .added, .replaced => {
            c.server.fanout(ev);
            try c.ok(ev.id, true, "");
        },
        .ephemeral => {
            c.server.fanout(ev);
            try c.ok(ev.id, true, "");
        },
        .duplicate => try c.ok(ev.id, true, "duplicate: already have this event"),
        .stale => try c.ok(ev.id, false, "duplicate: a newer version of this event is already stored"),
        .deleted => try c.ok(ev.id, false, "blocked: this event was deleted by its author"),
        .invalid => try c.ok(ev.id, false, "invalid: the signature does not verify"),
    }
}

/// Registers the subscription, then sends what is stored. In that order, so
/// an event stored while the query runs is either in the results or fanned
/// out to the subscription, never neither. Returns true when the
/// subscription keeps `parsed`.
fn onReq(c: *Conn, parsed: message.ParsedClientMessage, sub_id: []const u8, filters: []const Filter) SendError!bool {
    const limits = c.server.opts.limits;
    if (c.needsAuth()) {
        try c.closed(sub_id, "auth-required: this relay answers only after AUTH");
        return false;
    }
    if (filters.len == 0) {
        try c.closed(sub_id, "invalid: a REQ needs at least one filter");
        return false;
    }
    if (filters.len > limits.max_filters) {
        var buf: [96]u8 = undefined;
        try c.closed(sub_id, std.fmt.bufPrint(&buf, "invalid: too many filters, at most {d}", .{limits.max_filters}) catch unreachable);
        return false;
    }

    var old: ?Sub = null;
    {
        c.sub_mu.lockUncancelable(c.io);
        defer c.sub_mu.unlock(c.io);
        if (c.subs.fetchRemove(sub_id)) |kv| {
            old = kv.value;
        } else if (c.subs.count() >= limits.max_subscriptions) {
            c.sub_mu.unlock(c.io);
            defer c.sub_mu.lockUncancelable(c.io);
            var buf: [96]u8 = undefined;
            try c.closed(sub_id, std.fmt.bufPrint(&buf, "blocked: too many subscriptions, at most {d}", .{limits.max_subscriptions}) catch unreachable);
            return false;
        }
        try c.subs.put(c.gpa, sub_id, .{ .parsed = parsed, .filters = filters });
    }
    if (old) |*o| o.parsed.deinit();

    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    defer seen.deinit(c.gpa);
    for (filters) |f| {
        var q = f;
        q.limit = @min(f.limit orelse limits.max_limit, limits.max_limit);
        if (q.limit.? == 0) continue;
        var res = c.server.store.query(c.gpa, q) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            c.server.log("a query failed: {s}", .{@errorName(e)});
            try c.closed(sub_id, "error: the store could not answer");
            dropSub(c, sub_id);
            return true;
        };
        defer res.deinit();
        for (res.events) |ev| {
            if (filters.len > 1) {
                const gop = try seen.getOrPut(c.gpa, ev.id);
                if (gop.found_existing) continue;
            }
            if (expiration(ev)) |at| if (at <= nowSeconds(c.io)) continue;
            const json = try event.toJson(c.gpa, ev);
            defer c.gpa.free(json);
            try c.push(try eventFrame(c.gpa, sub_id, json));
        }
    }
    try c.sendOwned(try message.encodeEose(c.gpa, sub_id));
    return true;
}

/// Removes a subscription that `onReq` registered but could not answer. The
/// caller's `parsed` is the subscription's, so it is freed here.
fn dropSub(c: *Conn, sub_id: []const u8) void {
    c.sub_mu.lockUncancelable(c.io);
    const kv = c.subs.fetchRemove(sub_id);
    c.sub_mu.unlock(c.io);
    if (kv) |x| {
        var p = x.value.parsed;
        p.deinit();
    }
}

fn onClose(c: *Conn, sub_id: []const u8) void {
    c.sub_mu.lockUncancelable(c.io);
    const kv = c.subs.fetchRemove(sub_id);
    c.sub_mu.unlock(c.io);
    if (kv) |x| {
        var p = x.value.parsed;
        p.deinit();
    }
}

fn onCount(c: *Conn, sub_id: []const u8, filters: []const Filter) SendError!void {
    if (c.needsAuth()) return c.closed(sub_id, "auth-required: this relay answers only after AUTH");
    if (filters.len == 0) return c.closed(sub_id, "invalid: a COUNT needs at least one filter");
    if (filters.len > c.server.opts.limits.max_filters) return c.closed(sub_id, "invalid: too many filters");
    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    defer seen.deinit(c.gpa);
    var n: u64 = 0;
    for (filters) |f| {
        var q = f;
        q.limit = null;
        const items = c.server.store.syncItems(c.gpa, q, .{ .max_items = c.server.opts.limits.max_neg_items }) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            if (e == error.TooManyItems) return c.closed(sub_id, "blocked: too many events match, narrow the filter");
            return c.closed(sub_id, "error: the store could not answer");
        };
        defer c.gpa.free(items);
        if (filters.len == 1) {
            n = items.len;
            break;
        }
        for (items) |it| {
            const gop = try seen.getOrPut(c.gpa, it.id);
            if (!gop.found_existing) n += 1;
        }
    }
    return c.sendOwned(try message.encodeCountReply(c.gpa, sub_id, n, null));
}

fn onAuth(c: *Conn, ev: Event) SendError!void {
    if (ev.kind != nostr.nip42.kind) return c.ok(ev.id, false, "invalid: an AUTH event has kind 22242");
    const now = nowSeconds(c.io);
    if (ev.created_at < now - 600 or ev.created_at > now + 600) {
        return c.ok(ev.id, false, "invalid: the AUTH event is more than ten minutes from now");
    }
    var want: [64]u8 = undefined;
    const challenge = std.fmt.bufPrint(&want, "{x}", .{&c.challenge}) catch unreachable;
    const got_challenge = tagValue(ev, "challenge") orelse return c.ok(ev.id, false, "invalid: the AUTH event has no challenge tag");
    if (!std.mem.eql(u8, got_challenge, challenge)) return c.ok(ev.id, false, "invalid: the challenge does not match");
    const relay_tag = tagValue(ev, "relay") orelse return c.ok(ev.id, false, "invalid: the AUTH event has no relay tag");
    if (!relayMatches(c, relay_tag)) return c.ok(ev.id, false, "invalid: the relay tag names another relay");
    const id = try event.computeId(c.gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    if (!std.mem.eql(u8, &id, &ev.id)) return c.ok(ev.id, false, "invalid: the id does not match the event");
    if (!c.signer.verifyId(ev.sig, ev.id, ev.pubkey)) return c.ok(ev.id, false, "invalid: the signature does not verify");
    c.authed = ev.pubkey;
    var pk: [64]u8 = undefined;
    c.server.log("{s}: authenticated as {s}", .{ c.peer(), std.fmt.bufPrint(&pk, "{x}", .{&ev.pubkey}) catch unreachable });
    return c.ok(ev.id, true, "");
}

/// Whether a NIP-42 relay tag names this relay: the URL the client dialled
/// (its Host header) or the one the server prints, with or without a trailing
/// slash, ignoring case.
fn relayMatches(c: *const Conn, tag: []const u8) bool {
    var t = tag;
    while (t.len > 0 and t[t.len - 1] == '/') t = t[0 .. t.len - 1];
    if (std.ascii.startsWithIgnoreCase(t, "ws://")) {
        t = t["ws://".len..];
    } else if (std.ascii.startsWithIgnoreCase(t, "wss://")) {
        t = t["wss://".len..];
    } else return false;
    const host = c.host_buf[0..c.host_len];
    if (host.len > 0 and std.ascii.eqlIgnoreCase(t, host)) return true;
    const printed = c.server.url()["ws://".len..];
    return std.ascii.eqlIgnoreCase(t, printed);
}

fn onNegOpen(c: *Conn, sub_id: []const u8, f: Filter, initial_hex: []const u8) SendError!void {
    const limits = c.server.opts.limits;
    if (c.needsAuth()) return c.negErr(sub_id, "auth-required: this relay answers only after AUTH");
    onNegClose(c, sub_id);
    if (c.negs.count() >= limits.max_neg_sessions) return c.negErr(sub_id, "blocked: too many reconciliations open at once");

    const neg = try c.gpa.create(Neg);
    var owned = false;
    defer if (!owned) c.gpa.destroy(neg);
    neg.storage = nip77.Storage.fromStore(c.gpa, c.server.store, f, .{ .max_items = limits.max_neg_items }) catch |e| {
        if (e == error.TooManyItems) return c.negErr(sub_id, "blocked: too many events match, narrow the filter");
        if (e == error.OutOfMemory) return error.OutOfMemory;
        return c.negErr(sub_id, "error: the store could not answer");
    };
    var storage_owned = false;
    defer if (!storage_owned) neg.storage.deinit(c.gpa);
    if (neg.storage.size() > limits.max_neg_items) return c.negErr(sub_id, "blocked: too many events match, narrow the filter");
    neg.responder = nip77.Responder.init(&neg.storage, .{ .frame_size_limit = limits.neg_frame_limit }) catch
        return c.negErr(sub_id, "error: the reconciliation could not start");

    const reply = respond(c, neg, initial_hex) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return c.negErr(sub_id, "invalid: the negentropy message could not be read"),
    };
    defer c.gpa.free(reply);

    const key = try c.gpa.dupe(u8, sub_id);
    c.negs.put(c.gpa, key, neg) catch |e| {
        c.gpa.free(key);
        return e;
    };
    owned = true;
    storage_owned = true;
    try c.sendOwned(try message.encodeNegMsg(c.gpa, sub_id, reply));
}

/// The responder's hex reply to a hex message. The caller owns it.
fn respond(c: *Conn, neg: *Neg, msg_hex: []const u8) ![]u8 {
    const msg = try nip77.fromHex(c.gpa, msg_hex);
    defer c.gpa.free(msg);
    const reply = try neg.responder.reconcile(c.gpa, msg);
    defer c.gpa.free(reply);
    return nip77.toHex(c.gpa, reply);
}

fn onNegMsg(c: *Conn, sub_id: []const u8, msg_hex: []const u8) SendError!void {
    const neg = c.negs.get(sub_id) orelse return c.negErr(sub_id, "closed: no reconciliation is open under this id");
    const reply = respond(c, neg, msg_hex) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            onNegClose(c, sub_id);
            return c.negErr(sub_id, "invalid: the negentropy message could not be read");
        },
    };
    defer c.gpa.free(reply);
    try c.sendOwned(try message.encodeNegMsg(c.gpa, sub_id, reply));
}

fn onNegClose(c: *Conn, sub_id: []const u8) void {
    const kv = c.negs.fetchRemove(sub_id) orelse return;
    c.gpa.free(kv.key);
    kv.value.storage.deinit(c.gpa);
    c.gpa.destroy(kv.value);
}

// -- HTTP ---------------------------------------------------------------------

/// A plain HTTP request: the NIP-11 document when asked for it, a line of
/// text otherwise.
fn answerHttp(c: *Conn, head: []const u8) Io.Cancelable!void {
    const accept = headerValue(head, "accept") orelse "";
    if (std.mem.startsWith(u8, head, "OPTIONS ")) {
        return httpReply(c, "204 No Content", "text/plain", "");
    }
    if (std.ascii.indexOfIgnoreCase(accept, "application/nostr+json") != null) {
        const doc = infoDocument(c.gpa, c.server) catch return;
        defer c.gpa.free(doc);
        return httpReply(c, "200 OK", "application/nostr+json", doc);
    }
    return httpReply(c, "200 OK", "text/plain; charset=utf-8", "deed serve: a nostr relay. Connect with a websocket, or ask with Accept: application/nostr+json for its NIP-11 document.\n");
}

fn httpReply(c: *Conn, status: []const u8, content_type: []const u8, body: []const u8) Io.Cancelable!void {
    var wbuf: [1024]u8 = undefined;
    var w = c.stream.writer(c.io, &wbuf);
    w.interface.print(
        "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nConnection: close\r\n\r\n",
        .{ status, content_type, body.len },
    ) catch return httpFailed(&w);
    w.interface.writeAll(body) catch return httpFailed(&w);
    w.interface.flush() catch return httpFailed(&w);
}

fn httpFailed(w: *Io.net.Stream.Writer) Io.Cancelable!void {
    if (w.err) |e| if (e == error.Canceled) return error.Canceled;
}

/// The NIP-11 relay information document.
pub fn infoDocument(gpa: std.mem.Allocator, server: *const Server) ![]u8 {
    const l = server.opts.limits;
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"name\":\"deed serve\",\"description\":\"a local relay for development and testing\",\"software\":\"https://github.com/zig-nostr/deed\",\"version\":\"");
    try w.writeAll(@import("main.zig").version);
    try w.writeAll("\",\"supported_nips\":[");
    for (supported_nips, 0..) |n, i| {
        if (i > 0) try w.writeByte(',');
        try w.print("{d}", .{n});
    }
    try w.print(
        "],\"limitation\":{{\"max_message_length\":{d},\"max_subscriptions\":{d},\"max_filters\":{d},\"max_limit\":{d},\"default_limit\":{d},\"auth_required\":{},\"payment_required\":false,\"restricted_writes\":{}}}}}",
        .{ l.max_message_len, l.max_subscriptions, l.max_filters, l.max_limit, l.max_limit, server.opts.auth_required, server.opts.auth_required },
    );
    return out.toOwnedSlice();
}

/// The value of the header `name` (lowercase) in a request head, trimmed.
fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

// -- helpers ------------------------------------------------------------------

/// One unmasked server frame holding the concatenation of `parts`.
fn buildFrame(gpa: std.mem.Allocator, opcode: ws.Opcode, parts: []const []const u8) ![]u8 {
    var len: usize = 0;
    for (parts) |p| len += p.len;
    var head: [10]u8 = undefined;
    head[0] = 0x80 | @as(u8, @intFromEnum(opcode));
    var hl: usize = 2;
    if (len < 126) {
        head[1] = @intCast(len);
    } else if (len <= 0xffff) {
        head[1] = 126;
        std.mem.writeInt(u16, head[2..4], @intCast(len), .big);
        hl = 4;
    } else {
        head[1] = 127;
        std.mem.writeInt(u64, head[2..10], len, .big);
        hl = 10;
    }
    const out = try gpa.alloc(u8, hl + len);
    @memcpy(out[0..hl], head[0..hl]);
    var at = hl;
    for (parts) |p| {
        @memcpy(out[at..][0..p.len], p);
        at += p.len;
    }
    return out;
}

/// The frame `["EVENT",<sub_id>,<event json>]`.
fn eventFrame(gpa: std.mem.Allocator, sub_id: []const u8, json: []const u8) ![]u8 {
    var sub: std.ArrayList(u8) = .empty;
    defer sub.deinit(gpa);
    try appendJsonString(&sub, gpa, sub_id);
    return buildFrame(gpa, .text, &.{ "[\"EVENT\",", sub.items, ",", json, "]" });
}

fn appendJsonString(list: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    try list.append(gpa, '"');
    for (s) |b| switch (b) {
        '"' => try list.appendSlice(gpa, "\\\""),
        '\\' => try list.appendSlice(gpa, "\\\\"),
        '\n' => try list.appendSlice(gpa, "\\n"),
        '\r' => try list.appendSlice(gpa, "\\r"),
        '\t' => try list.appendSlice(gpa, "\\t"),
        else => if (b < 0x20) {
            try list.print(gpa, "\\u{x:0>4}", .{b});
        } else try list.append(gpa, b),
    };
    try list.append(gpa, '"');
}

fn anyMatches(filters: []const Filter, ev: Event) bool {
    for (filters) |f| {
        if (!f.matches(ev)) continue;
        if (f.search) |s| if (std.ascii.indexOfIgnoreCase(ev.content, s) == null) continue;
        return true;
    }
    return false;
}

fn tagValue(ev: Event, name: []const u8) ?[]const u8 {
    for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], name)) return t[1];
    }
    return null;
}

fn expiration(ev: Event) ?i64 {
    const v = tagValue(ev, "expiration") orelse return null;
    return std.fmt.parseInt(i64, v, 10) catch null;
}

fn isProtected(ev: Event) bool {
    for (ev.tags) |t| {
        if (t.len == 1 and std.mem.eql(u8, t[0], "-")) return true;
    }
    return false;
}

fn nowSeconds(io: Io) i64 {
    return Io.Timestamp.now(io, .real).toSeconds();
}

// -- preloading ---------------------------------------------------------------

pub const Preloaded = struct {
    stored: usize = 0,
    /// Lines that were not events, or whose id or signature was wrong.
    rejected: usize = 0,
};

/// Reads newline-delimited events from `reader`, verifies each and stores the
/// good ones. A bad line is reported on `err` with its number and skipped.
pub fn preload(gpa: std.mem.Allocator, store: *Store, reader: *Io.Reader, name: []const u8, err: *Io.Writer) !Preloaded {
    var signer = keys.Signer.init();
    defer signer.deinit();
    var out: Preloaded = .{};
    var batch: std.ArrayList(event.Parsed) = .empty;
    defer {
        for (batch.items) |*p| p.deinit();
        batch.deinit(gpa);
    }
    // The parsed events borrow their strings from the text they were parsed
    // from, and the reader reuses its buffer for the next line, so each line
    // is copied here first and kept until its batch is stored.
    var lines = std.heap.ArenaAllocator.init(gpa);
    defer lines.deinit();
    var line_no: usize = 0;
    while (true) {
        const line = reader.takeDelimiter('\n') catch |e| switch (e) {
            error.StreamTooLong => {
                line_no += 1;
                out.rejected += 1;
                try err.print("deed serve: {s}:{d}: the line is too long\n", .{ name, line_no });
                _ = reader.discardDelimiterInclusive('\n') catch break;
                continue;
            },
            else => return e,
        } orelse break;
        line_no += 1;
        const body = std.mem.trim(u8, line, " \t\r");
        if (body.len == 0) continue;
        const copy = try lines.allocator().dupe(u8, body);
        var p = event.fromJson(gpa, copy) catch {
            out.rejected += 1;
            try err.print("deed serve: {s}:{d}: not an event\n", .{ name, line_no });
            continue;
        };
        if (!(try event.verify(gpa, signer, p.value))) {
            p.deinit();
            out.rejected += 1;
            try err.print("deed serve: {s}:{d}: the id or signature is wrong\n", .{ name, line_no });
            continue;
        }
        batch.append(gpa, p) catch |e| {
            p.deinit();
            return e;
        };
        if (batch.items.len >= 512) {
            out.stored += try flushBatch(gpa, store, &batch);
            _ = lines.reset(.retain_capacity);
        }
    }
    out.stored += try flushBatch(gpa, store, &batch);
    return out;
}

fn flushBatch(gpa: std.mem.Allocator, store: *Store, batch: *std.ArrayList(event.Parsed)) !usize {
    if (batch.items.len == 0) return 0;
    const evs = try gpa.alloc(Event, batch.items.len);
    defer gpa.free(evs);
    const results = try gpa.alloc(nostr.store.IngestResult, batch.items.len);
    defer gpa.free(results);
    for (batch.items, evs) |p, *e| e.* = p.value;
    try store.ingestBatch(gpa, evs, .{}, results);
    var n: usize = 0;
    for (results) |r| {
        if (r == .added or r == .replaced) n += 1;
    }
    for (batch.items) |*p| p.deinit();
    batch.clearRetainingCapacity();
    return n;
}

// -- tests --------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

/// A store in a fresh temporary directory.
pub const TestStore = struct {
    tmp: testing.TmpDir,
    store: Store,

    pub fn init(self: *TestStore) !void {
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try self.tmp.dir.realPath(testing.io, &buf);
        var zbuf: [std.fs.max_path_bytes + 16]u8 = undefined;
        const z = try std.fmt.bufPrintZ(&zbuf, "{s}/events.mdb", .{buf[0..n]});
        self.store = try Store.open(z, .{ .map_size = 64 << 20 });
    }

    pub fn deinit(self: *TestStore) void {
        self.store.deinit();
        self.tmp.cleanup();
    }
};

/// A started server on a port the kernel picks, over its own store.
pub const TestServer = struct {
    da: testrelay.DialAllocator,
    ts: TestStore,
    server: Server,

    pub fn start(self: *TestServer, opts: struct { auth_required: bool = false, limits: Limits = .{} }) !void {
        self.da = .init;
        try self.ts.init();
        errdefer self.ts.deinit();
        try self.server.start(self.da.allocator(), testing.io, &self.ts.store, .{
            .address = .{ .ip4 = .loopback(0) },
            .auth_required = opts.auth_required,
            .limits = opts.limits,
        });
    }

    pub fn stop(self: *TestServer) void {
        self.server.stop();
        self.ts.deinit();
        if (self.da.deinit() == .leak) @panic("the relay leaked");
    }
};

/// A websocket client that can send anything, malformed frames included.
const RawClient = struct {
    gpa: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    rbuf: [16 * 1024]u8,
    buf: std.ArrayList(u8),
    last: std.ArrayList(u8),

    const Frame = struct { opcode: ws.Opcode, payload: []const u8 };

    fn connect(gpa: std.mem.Allocator, port: u16) !*RawClient {
        const io = testing.io;
        const self = try gpa.create(RawClient);
        errdefer gpa.destroy(self);
        const addr = try Io.net.IpAddress.parse("127.0.0.1", port);
        self.* = .{ .gpa = gpa, .io = io, .stream = try addr.connect(io, .{ .mode = .stream }), .reader = undefined, .rbuf = undefined, .buf = .empty, .last = .empty };
        self.reader = self.stream.reader(io, &self.rbuf);
        try self.writeAll("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        while (std.mem.indexOf(u8, self.buf.items, "\r\n\r\n") == null) {
            if (!try self.more()) return error.EndOfStream;
        }
        const end = std.mem.indexOf(u8, self.buf.items, "\r\n\r\n").? + 4;
        if (!std.mem.startsWith(u8, self.buf.items, "HTTP/1.1 101")) return error.HandshakeFailed;
        self.consume(end);
        return self;
    }

    fn deinit(self: *RawClient) void {
        self.stream.close(self.io);
        self.buf.deinit(self.gpa);
        self.last.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    fn writeAll(self: *RawClient, bytes: []const u8) !void {
        var wbuf: [4096]u8 = undefined;
        var w = self.stream.writer(self.io, &wbuf);
        try w.interface.writeAll(bytes);
        try w.interface.flush();
    }

    fn sendFrame(self: *RawClient, opcode: ws.Opcode, payload: []const u8) !void {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.gpa);
        try ws.appendClientFrame(&list, self.gpa, opcode, payload, .{ 1, 2, 3, 4 });
        try self.writeAll(list.items);
    }

    fn send(self: *RawClient, msg: []const u8) !void {
        return self.sendFrame(.text, msg);
    }

    fn more(self: *RawClient) !bool {
        self.reader.interface.fillMore() catch return false;
        const got = self.reader.interface.buffered();
        try self.buf.appendSlice(self.gpa, got);
        self.reader.interface.toss(got.len);
        return true;
    }

    fn consume(self: *RawClient, n: usize) void {
        std.mem.copyForwards(u8, self.buf.items, self.buf.items[n..]);
        self.buf.shrinkRetainingCapacity(self.buf.items.len - n);
    }

    /// The next frame, or null when the connection ends. Its payload is good
    /// until the next call.
    fn next(self: *RawClient) !?Frame {
        while (true) {
            if (try ws.decodeFrame(self.buf.items)) |f| {
                self.last.clearRetainingCapacity();
                try self.last.appendSlice(self.gpa, f.payload);
                self.consume(f.frame_len);
                return .{ .opcode = f.opcode, .payload = self.last.items };
            }
            if (!try self.more()) return null;
        }
    }

    /// The next text message.
    fn text(self: *RawClient) ![]const u8 {
        while (try self.next()) |f| {
            if (f.opcode == .text) return f.payload;
            if (f.opcode == .close) return error.Closed;
        }
        return error.EndOfStream;
    }
};

fn makeEvent(arena: std.mem.Allocator, signer: keys.Signer, kp: keys.KeyPair, kind: u16, created_at: i64, content: []const u8) !Event {
    return event.create(arena, signer, kp, created_at, kind, &.{}, content, null);
}

fn testKey(signer: keys.Signer, n: u8) !keys.KeyPair {
    var sk: [32]u8 = @splat(0);
    sk[31] = n;
    return signer.keyPairFromSecretKey(sk);
}

test "a REQ gets what is stored, then EOSE, then what arrives live" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 1);

    var pub_client = try RawClient.connect(gpa, ts.server.port());
    defer pub_client.deinit();
    const first = try makeEvent(arena, signer, kp, 1, 1_700_000_000, "stored");
    try pub_client.send(try message.encodeEvent(arena, first));
    try testing.expect(std.mem.indexOf(u8, try pub_client.text(), "true") != null);

    var sub = try RawClient.connect(gpa, ts.server.port());
    defer sub.deinit();
    try sub.send("[\"REQ\",\"s\",{\"kinds\":[1]}]");
    try testing.expect(std.mem.indexOf(u8, try sub.text(), "\"stored\"") != null);
    try testing.expectEqualStrings("[\"EOSE\",\"s\"]", try sub.text());

    const second = try makeEvent(arena, signer, kp, 1, 1_700_000_001, "live");
    try pub_client.send(try message.encodeEvent(arena, second));
    const live = try sub.text();
    try testing.expect(std.mem.startsWith(u8, live, "[\"EVENT\",\"s\","));
    try testing.expect(std.mem.indexOf(u8, live, "\"live\"") != null);
    try testing.expect(std.mem.indexOf(u8, try pub_client.text(), "true") != null);

    // After CLOSE nothing more arrives for it; a COUNT still answers.
    try sub.send("[\"CLOSE\",\"s\"]");
    const third = try makeEvent(arena, signer, kp, 1, 1_700_000_002, "after");
    try pub_client.send(try message.encodeEvent(arena, third));
    _ = try pub_client.text();
    try sub.send("[\"COUNT\",\"c\",{\"kinds\":[1]}]");
    try testing.expectEqualStrings("[\"COUNT\",\"c\",{\"count\":3}]", try sub.text());
}

test "COUNT counts across filters once per event" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = try testKey(signer, 1);
    const b = try testKey(signer, 2);

    var cl = try RawClient.connect(gpa, ts.server.port());
    defer cl.deinit();
    for (0..5) |i| {
        try cl.send(try message.encodeEvent(arena, try makeEvent(arena, signer, a, 1, 1_700_000_000 + @as(i64, @intCast(i)), "a")));
        _ = try cl.text();
    }
    for (0..3) |i| {
        try cl.send(try message.encodeEvent(arena, try makeEvent(arena, signer, b, 7, 1_700_000_000 + @as(i64, @intCast(i)), "b")));
        _ = try cl.text();
    }
    try cl.send("[\"COUNT\",\"x\",{\"kinds\":[1]}]");
    try testing.expectEqualStrings("[\"COUNT\",\"x\",{\"count\":5}]", try cl.text());
    try cl.send("[\"COUNT\",\"y\",{\"kinds\":[1,7]},{\"kinds\":[7]}]");
    try testing.expectEqualStrings("[\"COUNT\",\"y\",{\"count\":8}]", try cl.text());
}

test "a bad signature, a bad id and a malformed event are refused with OK false" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 1);

    var cl = try RawClient.connect(gpa, ts.server.port());
    defer cl.deinit();

    var bad_sig = try makeEvent(arena, signer, kp, 1, 1_700_000_000, "x");
    bad_sig.sig[0] ^= 1;
    try cl.send(try message.encodeEvent(arena, bad_sig));
    var reply = try cl.text();
    try testing.expect(std.mem.indexOf(u8, reply, "false,\"invalid: the signature does not verify\"") != null);

    var bad_id = try makeEvent(arena, signer, kp, 1, 1_700_000_000, "y");
    bad_id.content = "z";
    try cl.send(try message.encodeEvent(arena, bad_id));
    reply = try cl.text();
    try testing.expect(std.mem.indexOf(u8, reply, "false,\"invalid: the id does not match") != null);

    try cl.send("[\"EVENT\",{\"id\":\"" ++ "ab" ** 32 ++ "\",\"kind\":\"one\"}]");
    reply = try cl.text();
    try testing.expectEqualStrings("[\"OK\",\"" ++ "ab" ** 32 ++ "\",false,\"invalid: the event is malformed\"]", reply);

    // Nothing was stored.
    try cl.send("[\"COUNT\",\"n\",{}]");
    try testing.expectEqualStrings("[\"COUNT\",\"n\",{\"count\":0}]", try cl.text());
}

test "replaceable events keep the newest, and a duplicate is said to be one" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 3);

    var cl = try RawClient.connect(gpa, ts.server.port());
    defer cl.deinit();
    const old = try makeEvent(arena, signer, kp, 0, 1_700_000_000, "{\"name\":\"old\"}");
    const new = try makeEvent(arena, signer, kp, 0, 1_700_000_100, "{\"name\":\"new\"}");
    try cl.send(try message.encodeEvent(arena, new));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "true") != null);
    try cl.send(try message.encodeEvent(arena, old));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "false,\"duplicate:") != null);
    try cl.send(try message.encodeEvent(arena, new));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "true,\"duplicate:") != null);
    try cl.send("[\"REQ\",\"p\",{\"kinds\":[0]}]");
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "new") != null);
    try testing.expectEqualStrings("[\"EOSE\",\"p\"]", try cl.text());
}

test "with auth required, nothing is answered until a valid AUTH" {
    var ts: TestServer = undefined;
    try ts.start(.{ .auth_required = true });
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 4);

    var cl = try RawClient.connect(gpa, ts.server.port());
    defer cl.deinit();
    var parsed = try message.parseRelayMessage(gpa, try cl.text());
    defer parsed.deinit();
    const challenge = try arena.dupe(u8, parsed.value.auth.challenge);

    try cl.send("[\"REQ\",\"s\",{}]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"CLOSED\",\"s\",\"auth-required:"));
    const ev = try makeEvent(arena, signer, kp, 1, nowSeconds(testing.io), "hi");
    try cl.send(try message.encodeEvent(arena, ev));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "false,\"auth-required:") != null);
    try cl.send("[\"COUNT\",\"c\",{}]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"CLOSED\",\"c\",\"auth-required:"));

    const now = nowSeconds(testing.io);
    // The wrong challenge, then the wrong relay, then the right one.
    const wrong = try nostr.nip42.authEvent(arena, signer, kp, ts.server.url(), "nope", now, null);
    try cl.send(try message.encodeAuth(arena, wrong));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "false,\"invalid: the challenge") != null);
    const elsewhere = try nostr.nip42.authEvent(arena, signer, kp, "wss://relay.example", challenge, now, null);
    try cl.send(try message.encodeAuth(arena, elsewhere));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "false,\"invalid: the relay tag") != null);
    const good = try nostr.nip42.authEvent(arena, signer, kp, ts.server.url(), challenge, now, null);
    try cl.send(try message.encodeAuth(arena, good));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "true") != null);

    try cl.send(try message.encodeEvent(arena, ev));
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "true") != null);
    try cl.send("[\"REQ\",\"s\",{}]");
    try testing.expect(std.mem.indexOf(u8, try cl.text(), "\"hi\"") != null);
    try testing.expectEqualStrings("[\"EOSE\",\"s\"]", try cl.text());
}

test "negentropy against the library initiator finds both sides' differences" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 5);

    // The relay holds 0..300; the client holds 200..350.
    var all: std.ArrayList(Event) = .empty;
    for (0..350) |i| try all.append(arena, try makeEvent(arena, signer, kp, 1, 1_700_000_000 + @as(i64, @intCast(i)), "n"));
    var results: [300]nostr.store.IngestResult = undefined;
    try ts.ts.store.ingestBatch(gpa, all.items[0..300], .{}, &results);

    var items: std.ArrayList(nip77.Item) = .empty;
    for (all.items[200..]) |ev| try items.append(arena, .{ .created_at = @intCast(ev.created_at), .id = ev.id });
    var storage = try nip77.Storage.fromSlice(gpa, items.items);
    defer storage.deinit(gpa);
    var init = try nip77.Initiator.init(&storage, .{});
    const first = try init.initiate(gpa);
    defer gpa.free(first);
    const first_hex = try nip77.toHex(gpa, first);
    defer gpa.free(first_hex);

    var cl = try RawClient.connect(gpa, ts.server.port());
    defer cl.deinit();
    try cl.send(try message.encodeNegOpen(arena, "n", .{ .kinds = &.{1} }, first_hex));

    var have: usize = 0;
    var need: usize = 0;
    while (true) {
        var parsed = try message.parseRelayMessage(gpa, try cl.text());
        defer parsed.deinit();
        const reply = try nip77.fromHex(gpa, parsed.value.neg_msg.hex);
        defer gpa.free(reply);
        var r = try init.reconcile(gpa, reply);
        defer r.deinit(gpa);
        have += r.have.len;
        need += r.need.len;
        const next = r.message orelse break;
        const next_hex = try nip77.toHex(gpa, next);
        defer gpa.free(next_hex);
        try cl.send(try message.encodeNegMsg(arena, "n", next_hex));
    }
    try cl.send(try message.encodeNegClose(arena, "n"));
    try testing.expectEqual(@as(usize, 50), have);
    try testing.expectEqual(@as(usize, 200), need);

    // A message for a closed session is an error, not a crash.
    try cl.send(try message.encodeNegMsg(arena, "n", "61"));
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"NEG-ERR\",\"n\",\"closed:"));
}

test "a hundred subscriptions over four connections each get a live event" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 6);

    var clients: [4]*RawClient = undefined;
    for (&clients, 0..) |*cl, n| {
        cl.* = try RawClient.connect(gpa, ts.server.port());
        for (0..25) |i| {
            const req = try std.fmt.allocPrint(arena, "[\"REQ\",\"s{d}-{d}\",{{\"kinds\":[1]}}]", .{ n, i });
            try cl.*.send(req);
            try testing.expect(std.mem.startsWith(u8, try cl.*.text(), "[\"EOSE\""));
        }
    }
    defer for (clients) |cl| cl.deinit();

    var publisher = try RawClient.connect(gpa, ts.server.port());
    defer publisher.deinit();
    try publisher.send(try message.encodeEvent(arena, try makeEvent(arena, signer, kp, 1, 1_700_000_000, "all")));
    try testing.expect(std.mem.indexOf(u8, try publisher.text(), "true") != null);
    for (clients) |cl| {
        for (0..25) |_| try testing.expect(std.mem.indexOf(u8, try cl.text(), "\"all\"") != null);
    }
    try testing.expectEqual(@as(u64, 100), ts.server.fanned.load(.monotonic));

    // Past the limit, a new subscription is refused.
    var limited: TestServer = undefined;
    try limited.start(.{ .limits = .{ .max_subscriptions = 2 } });
    defer limited.stop();
    var cl = try RawClient.connect(limited.da.allocator(), limited.server.port());
    defer cl.deinit();
    try cl.send("[\"REQ\",\"a\",{}]");
    _ = try cl.text();
    try cl.send("[\"REQ\",\"b\",{}]");
    _ = try cl.text();
    try cl.send("[\"REQ\",\"c\",{}]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"CLOSED\",\"c\",\"blocked: too many subscriptions"));
    // Replacing one that exists is not a new one.
    try cl.send("[\"REQ\",\"a\",{\"kinds\":[1]}]");
    try testing.expectEqualStrings("[\"EOSE\",\"a\"]", try cl.text());
}

test "unreadable JSON gets a notice and the connection stays" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    var cl = try RawClient.connect(ts.da.allocator(), ts.server.port());
    defer cl.deinit();
    try cl.send("{not json");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"NOTICE\",\"invalid:"));
    try cl.send("[\"WHAT\",1]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"NOTICE\",\"invalid:"));
    try cl.send("[\"REQ\",\"s\",{\"kinds\":\"no\"}]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"CLOSED\",\"s\",\"invalid:"));
    // Still answering, ping included.
    try cl.sendFrame(.ping, "hello");
    const pong = (try cl.next()).?;
    try testing.expectEqual(ws.Opcode.pong, pong.opcode);
    try testing.expectEqualStrings("hello", pong.payload);
    try cl.send("[\"REQ\",\"t\",{}]");
    try testing.expectEqualStrings("[\"EOSE\",\"t\"]", try cl.text());
    // No filters matches nothing, rather than everything.
    try cl.send("[\"REQ\",\"z\"]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"CLOSED\",\"z\",\"invalid:"));
    try cl.send("[\"COUNT\",\"z\"]");
    try testing.expect(std.mem.startsWith(u8, try cl.text(), "[\"CLOSED\",\"z\",\"invalid:"));
}

test "a fragmented message is reassembled" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    var cl = try RawClient.connect(ts.da.allocator(), ts.server.port());
    defer cl.deinit();
    // FIN clear on the first part, then a continuation with FIN set.
    try cl.writeAll(&.{ 0x01, 0x80 | 6, 0, 0, 0, 0 });
    try cl.writeAll("[\"REQ\"");
    try cl.writeAll(&.{ 0x80, 0x80 | 8, 0, 0, 0, 0 });
    try cl.writeAll(",\"f\",{}]");
    try testing.expectEqualStrings("[\"EOSE\",\"f\"]", try cl.text());
}

test "an unmasked frame and a binary frame each end the connection with a close" {
    var ts: TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    {
        var cl = try RawClient.connect(ts.da.allocator(), ts.server.port());
        defer cl.deinit();
        try cl.writeAll(&.{ 0x81, 2, '[', ']' });
        const f = (try cl.next()).?;
        try testing.expectEqual(ws.Opcode.close, f.opcode);
        try testing.expectEqual(@as(u16, 1002), std.mem.readInt(u16, f.payload[0..2], .big));
        try testing.expect((try cl.next()) == null);
    }
    {
        var cl = try RawClient.connect(ts.da.allocator(), ts.server.port());
        defer cl.deinit();
        try cl.sendFrame(.binary, "xyz");
        const f = (try cl.next()).?;
        try testing.expectEqual(ws.Opcode.close, f.opcode);
        try testing.expectEqual(@as(u16, 1003), std.mem.readInt(u16, f.payload[0..2], .big));
    }
}

test "an oversized message is refused before it is read" {
    var ts: TestServer = undefined;
    try ts.start(.{ .limits = .{ .max_message_len = 1024 } });
    defer ts.stop();
    var cl = try RawClient.connect(ts.da.allocator(), ts.server.port());
    defer cl.deinit();
    // Only the header of a 10 MB frame is sent: the answer comes anyway.
    try cl.writeAll(&.{ 0x81, 0x80 | 127, 0, 0, 0, 0, 0, 0x98, 0x96, 0x80, 1, 2, 3, 4 });
    const f = (try cl.next()).?;
    try testing.expectEqual(ws.Opcode.close, f.opcode);
    try testing.expectEqual(@as(u16, 1009), std.mem.readInt(u16, f.payload[0..2], .big));
    try testing.expect((try cl.next()) == null);
}

test "a client that stops reading is dropped, and the publisher is not held up" {
    var ts: TestServer = undefined;
    try ts.start(.{ .limits = .{ .queue_hard = 256 * 1024, .queue_soft = 64 * 1024 } });
    defer ts.stop();
    const gpa = ts.da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 7);

    var sleeper = try RawClient.connect(gpa, ts.server.port());
    defer sleeper.deinit();
    try sleeper.send("[\"REQ\",\"all\",{}]");
    _ = try sleeper.text();

    var publisher = try RawClient.connect(gpa, ts.server.port());
    defer publisher.deinit();
    const big = try arena.alloc(u8, 60 * 1024);
    @memset(big, 'x');
    // Enough to fill the sleeper's socket buffers and then its queue.
    var i: usize = 0;
    while (ts.server.dropped.load(.monotonic) == 0) : (i += 1) {
        if (i == 2000) return error.NeverDropped;
        try publisher.send(try message.encodeEvent(arena, try makeEvent(arena, signer, kp, 1, 1_700_000_000 + @as(i64, @intCast(i)), big)));
        try testing.expect(std.mem.indexOf(u8, try publisher.text(), "true") != null);
    }
    // The publisher still gets answers.
    try publisher.send("[\"COUNT\",\"c\",{}]");
    try testing.expect(std.mem.startsWith(u8, try publisher.text(), "[\"COUNT\""));
}

test "the NIP-11 document is served to a request that asks for it" {
    var ts: TestServer = undefined;
    try ts.start(.{ .auth_required = true });
    defer ts.stop();
    const io = testing.io;
    const addr = try Io.net.IpAddress.parse("127.0.0.1", ts.server.port());
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [256]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\n\r\n");
    try w.interface.flush();
    var rbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    while (true) {
        r.interface.fillMore() catch break;
        try got.appendSlice(testing.allocator, r.interface.buffered());
        r.interface.toss(r.interface.buffered().len);
    }
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, got.items, "Content-Type: application/nostr+json") != null);
    const body = got.items[std.mem.indexOf(u8, got.items, "\r\n\r\n").? + 4 ..];
    var doc = try std.json.parseFromSlice(std.json.Value, testing.allocator, body, .{});
    defer doc.deinit();
    try testing.expectEqualStrings("deed serve", doc.value.object.get("name").?.string);
    const nips = doc.value.object.get("supported_nips").?.array.items;
    try testing.expectEqual(@as(i64, 77), nips[nips.len - 1].integer);
    try testing.expect(doc.value.object.get("limitation").?.object.get("auth_required").?.bool);
}

test "a connection that never finishes its request is closed" {
    var ts: TestServer = undefined;
    try ts.start(.{ .limits = .{ .handshake_timeout_ms = 100 } });
    defer ts.stop();
    const io = testing.io;
    const addr = try Io.net.IpAddress.parse("127.0.0.1", ts.server.port());
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.writeAll("GET / HTTP/1.1\r\n");
    try w.interface.flush();
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    try testing.expectError(error.EndOfStream, r.interface.fillMore());
}

test "preload stores good lines and reports bad ones by number" {
    var tstore: TestStore = undefined;
    try tstore.init();
    defer tstore.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer, 8);
    const good = try event.toJson(arena, try makeEvent(arena, signer, kp, 1, 1_700_000_000, "one"));
    var tampered = try makeEvent(arena, signer, kp, 1, 1_700_000_001, "two");
    tampered.content = "three";
    const bad = try event.toJson(arena, tampered);
    const second = try event.toJson(arena, try makeEvent(arena, signer, kp, 1, 1_700_000_002, "four"));
    const text = try std.fmt.allocPrint(arena, "{s}\nnot json\n\n{s}\n{s}\n", .{ good, bad, second });
    // A window smaller than the text, so the reader reuses its buffer and an
    // event that kept pointing into it would be stored corrupted.
    var source: Io.Reader = .fixed(text);
    var window: [1024]u8 = undefined;
    var limited = source.limited(.unlimited, &window);
    const reader = &limited.interface;
    var eb: [512]u8 = undefined;
    var err: Io.Writer = .fixed(&eb);
    const got = try preload(testing.allocator, &tstore.store, reader, "events.jsonl", &err);
    try testing.expectEqual(@as(usize, 2), got.stored);
    try testing.expectEqual(@as(usize, 2), got.rejected);
    try testing.expect(std.mem.indexOf(u8, err.buffered(), "events.jsonl:2: not an event") != null);
    try testing.expect(std.mem.indexOf(u8, err.buffered(), "events.jsonl:4: the id or signature is wrong") != null);
    try testing.expectEqual(@as(usize, 2), try tstore.store.eventCount());
    // What was stored still verifies.
    var res = try tstore.store.query(testing.allocator, .{});
    defer res.deinit();
    for (res.events) |ev| try testing.expect(try event.verify(arena, signer, ev));
}
