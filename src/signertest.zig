//! A remote signer for tests: the library's `signer.serve` on an in-memory
//! relay, behind every verb that takes `--sec`. Nothing outside tests uses it.
//!
//! `Rig.install` makes `signing.open` reach this signer for any `bunker://`
//! URI instead of dialling the relays it names, so a test runs a verb exactly
//! as a person would, with `--sec <rig.uri()>`, and the request really goes
//! out as a sealed kind 24133 event, is answered by the bunker, and comes back
//! through the same NIP-46 client a run uses.

const std = @import("std");
const nostr = @import("nostr");
const signing = @import("signing.zig");
const testrelay = @import("testrelay.zig");

const Io = std.Io;
const keys = nostr.keys;
const event = nostr.event;
const filter = nostr.filter;
const nip46 = nostr.nip46;
const relay = nostr.relay;
const websocket = nostr.websocket;
const signer_mod = nostr.signer;

/// An in-memory relay. Each `Peer` is one connection's byte stream: what a
/// peer publishes reaches every other peer whose subscription `p`-tags the
/// event, as server frames, and a read waits for those frames, honours its
/// deadline, and ends at EOF once the hub closes. The waits are futex waits,
/// so they are cancelation points like a socket read.
pub const Hub = struct {
    gpa: std.mem.Allocator,
    io: Io,
    lock: Io.Mutex = .init,
    /// Bumped on every delivery and on close; readers wait on it.
    seq: std.atomic.Value(u32) = .init(0),
    peers: [8]*Peer = undefined,
    peer_count: usize = 0,
    closed: bool = false,

    pub const Peer = struct {
        hub: *Hub,
        inbox: std.ArrayList(u8) = .empty,
        /// The `#p` value of the peer's subscription, once it has one.
        p_filter: ?[64]u8 = null,

        pub fn read(self: *Peer, buffer: []u8, deadline: ?Io.Clock.Timestamp) !usize {
            const hub = self.hub;
            while (true) {
                const seen = hub.seq.load(.acquire);
                {
                    hub.lock.lockUncancelable(hub.io);
                    defer hub.lock.unlock(hub.io);
                    if (self.inbox.items.len > 0) {
                        const n = @min(buffer.len, self.inbox.items.len);
                        @memcpy(buffer[0..n], self.inbox.items[0..n]);
                        self.inbox.replaceRangeAssumeCapacity(0, n, &.{});
                        return n;
                    }
                    if (hub.closed) return 0;
                }
                const timeout: Io.Timeout = if (deadline) |d| .{ .deadline = d } else .none;
                try hub.io.futexWaitTimeout(u32, &hub.seq.raw, seen, timeout);
                if (deadline) |d| {
                    const now = Io.Clock.Timestamp.now(hub.io, d.clock);
                    if (now.raw.nanoseconds >= d.raw.nanoseconds) return error.Timeout;
                }
            }
        }

        pub fn writeAll(self: *Peer, bytes: []const u8) !void {
            const hub = self.hub;
            const copy = try hub.gpa.dupe(u8, bytes);
            defer hub.gpa.free(copy);
            var offset: usize = 0;
            while (try websocket.decodeFrame(copy[offset..])) |frame| {
                offset += frame.frame_len;
                const text = frame.payload;
                if (std.mem.startsWith(u8, text, "[\"REQ\"")) {
                    const marker = "\"#p\":[\"";
                    const at = std.mem.indexOf(u8, text, marker) orelse continue;
                    const start = at + marker.len;
                    hub.lock.lockUncancelable(hub.io);
                    defer hub.lock.unlock(hub.io);
                    self.p_filter = text[start..][0..64].*;
                } else if (std.mem.startsWith(u8, text, "[\"EVENT\",")) {
                    try hub.broadcast(self, text["[\"EVENT\",".len .. text.len - 1]);
                }
            }
        }
    };

    fn add(self: *Hub) !*Peer {
        const peer = try self.gpa.create(Peer);
        peer.* = .{ .hub = self };
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.peers[self.peer_count] = peer;
        self.peer_count += 1;
        return peer;
    }

    fn deinit(self: *Hub) void {
        for (self.peers[0..self.peer_count]) |peer| {
            peer.inbox.deinit(self.gpa);
            self.gpa.destroy(peer);
        }
    }

    fn broadcast(self: *Hub, from: *Peer, event_json: []const u8) !void {
        const text = try std.fmt.allocPrint(self.gpa, "[\"EVENT\",\"sub\",{s}]", .{event_json});
        defer self.gpa.free(text);
        var frame: std.ArrayList(u8) = .empty;
        defer frame.deinit(self.gpa);
        try appendServerText(&frame, self.gpa, text);

        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.peers[0..self.peer_count]) |peer| {
            if (peer == from) continue;
            const p = peer.p_filter orelse continue;
            var needle: [80]u8 = undefined;
            const tag = std.fmt.bufPrint(&needle, "[\"p\",\"{s}\"", .{&p}) catch unreachable;
            if (std.mem.indexOf(u8, event_json, tag) == null) continue;
            try peer.inbox.appendSlice(self.gpa, frame.items);
        }
        _ = self.seq.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.seq.raw, std.math.maxInt(u32));
    }

    /// Ends every peer's stream, so readers see EOF and return.
    fn close(self: *Hub) void {
        {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            self.closed = true;
        }
        _ = self.seq.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.seq.raw, std.math.maxInt(u32));
    }

    /// Waits until `peer` has subscribed, so nothing published before then
    /// is lost.
    fn awaitSubscribed(self: *Hub, peer: *Peer) !void {
        for (0..2000) |_| {
            {
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                if (peer.p_filter != null) return;
            }
            try self.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.NeverSubscribed;
    }
};

fn appendServerText(list: *std.ArrayList(u8), gpa: std.mem.Allocator, text: []const u8) !void {
    try list.append(gpa, 0x81);
    if (text.len <= 125) {
        try list.append(gpa, @intCast(text.len));
    } else if (text.len <= 0xffff) {
        try list.append(gpa, 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext, @intCast(text.len), .big);
        try list.appendSlice(gpa, &ext);
    } else {
        try list.append(gpa, 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, &ext, text.len, .big);
        try list.appendSlice(gpa, &ext);
    }
    try list.appendSlice(gpa, text);
}

pub const TestConn = relay.Connection(*Hub.Peer);

/// How the signer behaves.
pub const Mode = enum {
    /// Answers everything, as `signer.serve` does with an approve-all policy.
    serve,
    /// Lets a client connect, then refuses every request that uses the key.
    reject,
    /// Never answers anything.
    silent,
    /// Sends `auth_url` before each answer to `sign_event`, then answers.
    auth_url,
};

const url = "wss://hub.test";

pub const Rig = struct {
    gpa: std.mem.Allocator,
    io: Io,
    ctx: keys.Signer,
    hub: Hub,
    /// The key the signer signs with, and the one clients talk to. They
    /// differ, so a test sees which one an answer carries.
    user: keys.KeyPair,
    remote: keys.KeyPair,
    clients: nip46.AuthorizedClients = .{},
    seen: signer_mod.SeenRequests = .{},
    bunker: nip46.Bunker = undefined,
    signer_conn: TestConn = undefined,
    client_conns: [6]TestConn = undefined,
    client_count: usize = 0,
    serving: ?Io.Future(anyerror!void) = null,
    /// Overrides the per-request deadline of every session opened.
    timeout_ms: ?u32 = null,
    /// The link `Mode.auth_url` sends.
    auth_link: []const u8 = "https://signer.test/approve",
    uri_buf: [256]u8 = undefined,
    uri_len: usize = 0,

    /// Starts the signer. `self` must not move until `deinit`.
    pub fn init(self: *Rig, gpa: std.mem.Allocator, io: Io, mode: Mode) !void {
        const ctx = keys.Signer.init();
        self.* = .{
            .gpa = gpa,
            .io = io,
            .ctx = ctx,
            .hub = .{ .gpa = gpa, .io = io },
            .user = try ctx.keyPairFromSecretKey([_]u8{0x07} ** 32),
            .remote = try ctx.keyPairFromSecretKey([_]u8{0x09} ** 32),
        };
        self.bunker = .{
            .signer = ctx,
            .user = self.user,
            .remote = self.remote,
            .secret = "s3cret",
            .policy = if (mode == .reject) .{ .decideFn = &refuseKeyWork } else nip46.approveAll(),
            .clients = &self.clients,
        };
        const text = try nip46.buildBunkerUri(gpa, self.remote.public_key, &.{url}, "s3cret");
        defer gpa.free(text);
        @memcpy(self.uri_buf[0..text.len], text);
        self.uri_len = text.len;

        self.signer_conn = TestConn.init(gpa, io, try self.hub.add());
        switch (mode) {
            .silent => {},
            .serve, .reject => {
                self.serving = try io.concurrent(serveTask, .{self});
                try self.hub.awaitSubscribed(self.signer_conn.stream);
            },
            .auth_url => {
                self.serving = try io.concurrent(scriptedTask, .{self});
                try self.hub.awaitSubscribed(self.signer_conn.stream);
            },
        }
        signing.test_relays = .{ .ctx = self, .start = start };
    }

    pub fn deinit(self: *Rig) void {
        signing.test_relays = null;
        self.hub.close();
        if (self.serving) |*s| s.await(self.io) catch {};
        for (self.client_conns[0..self.client_count]) |*c| c.deinit();
        self.signer_conn.deinit();
        self.hub.deinit();
        self.ctx.deinit();
    }

    /// The `bunker://` URI naming this signer.
    pub fn uri(self: *const Rig) []const u8 {
        return self.uri_buf[0..self.uri_len];
    }

    /// The signer stops answering, as one whose device went to sleep.
    pub fn silence(self: *Rig) void {
        if (self.serving) |*s| s.cancel(self.io) catch {};
        self.serving = null;
    }

    fn start(ctx: *anyopaque, gpa: std.mem.Allocator, io: Io, verb: []const u8, uri_text: []const u8, options: signing.StartOptions, err: *Io.Writer) anyerror!?signing.Signer {
        const self: *Rig = @ptrCast(@alignCast(ctx));
        const conn = &self.client_conns[self.client_count];
        conn.* = TestConn.init(self.gpa, io, try self.hub.add());
        self.client_count += 1;
        var opts = options;
        if (self.timeout_ms) |t| opts.timeout_ms = t;
        const conns = [1]*TestConn{conn};
        const urls = [1][]const u8{url};
        return signing.start(*TestConn, gpa, io, verb, uri_text, &conns, &urls, false, opts, err);
    }

    fn serveTask(self: *Rig) anyerror!void {
        return signer_mod.serve(self.gpa, self.io, &self.signer_conn, &self.bunker, self.remote, url, &self.seen);
    }

    /// The bunker's answers, with an `auth_url` sent ahead of each
    /// `sign_event` answer.
    fn scriptedTask(self: *Rig) anyerror!void {
        const gpa = self.gpa;
        const conn = &self.signer_conn;
        var mine = std.fmt.bytesToHex(self.remote.public_key, .lower);
        const kinds = [_]u16{nip46.kind};
        const p_values = [_][]const u8{&mine};
        const tag_filters = [_]filter.TagFilter{.{ .letter = 'p', .values = &p_values }};
        try conn.subscribe("s", &.{.{ .kinds = &kinds, .tags = &tag_filters }});
        while (try conn.receive()) |msg_const| {
            var msg = msg_const;
            defer msg.deinit();
            const ev = switch (msg.value) {
                .event => |e| e.event,
                else => continue,
            };
            const plaintext = try nip46.open(gpa, self.ctx, self.remote.secret_key, ev);
            defer gpa.free(plaintext);
            var req = try nip46.parseRequest(gpa, plaintext);
            defer req.deinit();
            const now = Io.Timestamp.now(self.io, .real).toSeconds();
            if (std.mem.eql(u8, req.value.method, "sign_event")) {
                try self.reply(ev.pubkey, .{ .id = req.value.id, .result = "auth_url", .err = self.auth_link }, now);
            }
            var answer = try self.bunker.handle(gpa, self.io, req.value, ev.pubkey);
            defer answer.deinit();
            try self.reply(ev.pubkey, answer.value, now);
        }
    }

    fn reply(self: *Rig, to: [32]u8, response: nip46.Response, now: i64) !void {
        const body = try response.toJson(self.gpa);
        defer self.gpa.free(body);
        var sealed = try nip46.seal(self.gpa, self.io, self.ctx, self.remote, to, body, now);
        defer sealed.deinit();
        try self.signer_conn.publish(sealed.event);
    }
};

/// Connecting and saying who the user is are allowed; anything that uses the
/// key is not.
fn refuseKeyWork(_: ?*anyopaque, request: *const nip46.Request, _: [32]u8) nip46.Decision {
    const method = nip46.Method.fromString(request.method) orelse return .reject;
    return switch (method) {
        .connect, .ping, .get_public_key => .approve,
        else => .reject,
    };
}

/// The approval link lines a session printed, for the test to read.
pub const Notices = struct {
    var lock: std.atomic.Value(bool) = .init(false);
    var buf: [8192]u8 = undefined;
    var len: usize = 0;

    pub fn begin() void {
        len = 0;
        signing.test_notice = record;
    }

    pub fn end() void {
        signing.test_notice = null;
    }

    pub fn text() []const u8 {
        while (lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
        defer lock.store(false, .release);
        return buf[0..len];
    }

    fn record(line: []const u8) void {
        while (lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
        defer lock.store(false, .release);
        const n = @min(line.len, buf.len - len);
        @memcpy(buf[len..][0..n], line[0..n]);
        len += n;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const cmd_event = @import("cmd_event.zig");
const cmd_crypt = @import("cmd_crypt.zig");
const cmd_post = @import("cmd_post.zig");
const cmd_profile = @import("cmd_profile.zig");
const auth = @import("auth.zig");
const relayset = @import("relayset.zig");
const cli = @import("cli.zig");

const Ran = struct { code: u8, out: []const u8, err: []const u8 };

/// Runs a verb with the rig's allocator, keeping its output in `arena`.
fn runVerb(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    comptime run: anytype,
    args: []const []const u8,
) !Ran {
    var out: Io.Writer.Allocating = .init(arena);
    var err: Io.Writer.Allocating = .init(arena);
    const code = try run(gpa, testing.io, args, &out.writer, &err.writer);
    return .{ .code = code, .out = out.written(), .err = err.written() };
}

fn has(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

/// The event on the first line of `text`, checked to verify and to be by
/// `author`.
fn expectSignedBy(arena: std.mem.Allocator, text: []const u8, author: [32]u8) !event.Event {
    const line = std.mem.trimEnd(u8, text, "\n");
    var parsed = try event.fromJson(arena, line);
    _ = &parsed;
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    try testing.expectEqualSlices(u8, &author, &parsed.value.pubkey);
    try testing.expect(try event.verify(arena, ctx, parsed.value));
    return parsed.value;
}

test "event: signed by the remote user key, and it verifies" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rig: Rig = undefined;
    try rig.init(gpa, testing.io, .serve);
    defer rig.deinit();

    const r = try runVerb(gpa, arena, cmd_event.run, &.{ "--sec", rig.uri(), "-k", "1", "-c", "signed far away" });
    try testing.expectEqual(cli.exit_ok, r.code);
    const ev = try expectSignedBy(arena, r.out, rig.user.public_key);
    try testing.expectEqualStrings("signed far away", ev.content);
    // The user key, not the key the signer talks with.
    try testing.expect(!std.mem.eql(u8, &ev.pubkey, &rig.remote.public_key));
}

test "encrypt: NIP-44 by the remote signer opens with the peer's local key, and NIP-04 as well" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rig: Rig = undefined;
    try rig.init(gpa, testing.io, .serve);
    defer rig.deinit();

    const peer_sec = "33" ** 32;
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    const peer = try ctx.keyPairFromSecretKey([_]u8{0x33} ** 32);
    const peer_hex = std.fmt.bytesToHex(peer.public_key, .lower);
    const user_hex = std.fmt.bytesToHex(rig.user.public_key, .lower);

    for ([_]bool{ false, true }) |legacy| {
        // `--nip04` last, or nothing: NIP-44 is the default.
        const flags: []const []const u8 = if (legacy) &.{"--nip04"} else &.{};
        const sealed = try runVerb(gpa, arena, runEncrypt, try cat(arena, &.{ "--sec", rig.uri(), "--to", &peer_hex, "meet at noon" }, flags));
        try testing.expectEqual(cli.exit_ok, sealed.code);
        const payload = std.mem.trimEnd(u8, sealed.out, "\n");
        try testing.expectEqual(legacy, has(payload, "?iv="));

        const opened = try runVerb(gpa, arena, runDecrypt, try cat(arena, &.{ "--sec", peer_sec, "--from", &user_hex, payload }, flags));
        try testing.expectEqual(cli.exit_ok, opened.code);
        try testing.expectEqualStrings("meet at noon\n", opened.out);

        // And back the other way: the remote signer reads what it wrote.
        const back = try runVerb(gpa, arena, runDecrypt, try cat(arena, &.{ "--sec", rig.uri(), "--from", &peer_hex, payload }, flags));
        try testing.expectEqual(cli.exit_ok, back.code);
        try testing.expectEqualStrings("meet at noon\n", back.out);
    }
}

fn cat(arena: std.mem.Allocator, a: []const []const u8, b: []const []const u8) ![]const []const u8 {
    return std.mem.concat(arena, []const u8, &.{ a, b });
}

fn runEncrypt(gpa: std.mem.Allocator, io: Io, args: []const []const u8, out: *Io.Writer, err: *Io.Writer) !u8 {
    return cmd_crypt.run(gpa, io, .encrypt, args, out, err);
}

fn runDecrypt(gpa: std.mem.Allocator, io: Io, args: []const []const u8, out: *Io.Writer, err: *Io.Writer) !u8 {
    return cmd_crypt.run(gpa, io, .decrypt, args, out, err);
}

test "post and profile set: signed through the remote signer" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rig: Rig = undefined;
    try rig.init(gpa, testing.io, .serve);
    defer rig.deinit();

    const note = try runVerb(gpa, arena, cmd_post.run, &.{ "hello from afar", "--sec", rig.uri(), "--dry-run" });
    try testing.expectEqual(cli.exit_ok, note.code);
    const ev = try expectSignedBy(arena, note.out, rig.user.public_key);
    try testing.expectEqual(@as(u16, 1), ev.kind);
    try testing.expectEqualStrings("hello from afar", ev.content);

    const profile = try runVerb(gpa, arena, cmd_profile.run, &.{ "set", "--sec", rig.uri(), "--name", "far", "--force-new", "--dry-run" });
    try testing.expectEqual(cli.exit_ok, profile.code);
    const meta = try expectSignedBy(arena, profile.out, rig.user.public_key);
    try testing.expectEqual(@as(u16, 0), meta.kind);
    try testing.expect(has(meta.content, "\"name\":\"far\""));
}

test "a NIP-42 answer is signed by the remote signer, and the relay lets the reader in" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    var rig: Rig = undefined;
    try rig.init(gpa, io, .serve);
    defer rig.deinit();

    var sink: Io.Writer.Allocating = .init(arena);
    const opts = (try auth.resolve(gpa, io, .{ .auth = true, .sec = rig.uri() }, "req", &sink.writer)).?;
    defer opts.deinit(gpa);
    try testing.expect(opts.keypair == null);

    var ans = try auth.answer(gpa, io, opts, "wss://relay.test/", "c-9");
    defer ans.deinit();
    try testing.expectEqual(@as(u16, 22242), ans.event.kind);
    try testing.expectEqualStrings("wss://relay.test/", ans.event.tags[0][1]);
    try testing.expectEqualStrings("c-9", ans.event.tags[1][1]);
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    try testing.expectEqualSlices(u8, &rig.user.public_key, &ans.event.pubkey);
    try testing.expect(try event.verify(arena, ctx, ans.event));

    // A relay that keeps its events behind NIP-42 serves them once answered.
    var ev_ctx = keys.Signer.init();
    defer ev_ctx.deinit();
    const kp = try ev_ctx.keyPairFromSecretKey([_]u8{0x51} ** 32);
    const members = try event.toJson(arena, try event.create(arena, ev_ctx, kp, 1_700_000_000, 1, &.{}, "members only", null));
    var script: relayset.AuthRelay = .{ .want_url = undefined, .event = members };
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, relayset.AuthRelay.handle, &script);
    defer r.stop(io);
    var buf: [40]u8 = undefined;
    const relay_url = try testrelay.url(&buf, r.port());
    script.want_url = relay_url;

    const filters = [_]filter.Filter{.{ .kinds = &.{1} }};
    var out: Io.Writer.Allocating = .init(arena);
    var err: Io.Writer.Allocating = .init(arena);
    const outcome = try relayset.query(gpa, io, &.{relay_url}, &filters, &out.writer, &err.writer, .{ .deadline_ms = 5_000, .auth = opts });
    try testing.expectEqual(@as(usize, 1), outcome.events);
    try testing.expectEqual(@as(usize, 1), script.auths);
    try testing.expect(has(out.written(), "members only"));
}

test "a refused request exits 1 with one line saying so" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rig: Rig = undefined;
    try rig.init(gpa, testing.io, .reject);
    defer rig.deinit();

    const r = try runVerb(gpa, arena, cmd_event.run, &.{ "--sec", rig.uri(), "-c", "no" });
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqual(@as(usize, 0), r.out.len);
    try testing.expectEqualStrings("deed event: the remote signer refused the request\n", r.err);

    const p = try runVerb(gpa, arena, cmd_post.run, &.{ "no", "--sec", rig.uri(), "--dry-run" });
    try testing.expectEqual(cli.exit_fail, p.code);
    try testing.expectEqualStrings("deed post: the remote signer refused the request\n", p.err);
}

test "a signer that never answers is bounded by the deadline, at connect and later" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    {
        var rig: Rig = undefined;
        try rig.init(gpa, io, .silent);
        defer rig.deinit();
        rig.timeout_ms = 300;
        const started = Io.Timestamp.now(io, .awake).toMilliseconds();
        const r = try runVerb(gpa, arena, cmd_event.run, &.{ "--sec", rig.uri(), "-c", "anyone?" });
        const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
        try testing.expectEqual(cli.exit_fail, r.code);
        try testing.expectEqualStrings("deed event: the remote signer did not answer in time\n", r.err);
        try testing.expect(took >= 250 and took < 5_000);
    }
    {
        // Connected, then gone quiet: the request after that waits its
        // deadline and no longer.
        var rig: Rig = undefined;
        try rig.init(gpa, io, .serve);
        defer rig.deinit();
        rig.timeout_ms = 300;
        var sink: Io.Writer.Allocating = .init(arena);
        var s = (try signing.open(gpa, io, "event", rig.uri(), &sink.writer)).?;
        defer s.deinit();
        rig.silence();
        const started = Io.Timestamp.now(io, .awake).toMilliseconds();
        try testing.expectError(error.Timeout, s.sign(arena, 1_700_000_000, 1, &.{}, "late"));
        try testing.expect(Io.Timestamp.now(io, .awake).toMilliseconds() - started < 5_000);
        try testing.expectEqual(cli.exit_fail, try signing.report("event", error.Timeout, &sink.writer));
        try testing.expectEqualStrings("deed event: the remote signer did not answer in time\n", sink.written());
    }
}

test "an approval link is shown only when it is plain https" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct { link: []const u8, shown: bool }{
        .{ .link = "https://signer.test/approve?id=1", .shown = true },
        .{ .link = "http://signer.test/approve", .shown = false },
        .{ .link = "https://signer.test/\x1b[2Japprove", .shown = false },
        .{ .link = "javascript:alert(1)", .shown = false },
    };
    for (cases) |c| {
        var rig: Rig = undefined;
        try rig.init(gpa, testing.io, .auth_url);
        rig.auth_link = c.link;
        defer rig.deinit();
        Notices.begin();
        defer Notices.end();

        const r = try runVerb(gpa, arena, cmd_event.run, &.{ "--sec", rig.uri(), "-c", "approve me" });
        // The request still completes once the signer answers.
        try testing.expectEqual(cli.exit_ok, r.code);
        _ = try expectSignedBy(arena, r.out, rig.user.public_key);
        const said = Notices.text();
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "\n"));
        try testing.expectEqual(c.shown, has(said, c.link));
        if (!c.shown) try testing.expect(has(said, "not shown"));
    }

    try testing.expect(signing.isShowableUrl("https://a.example/x"));
    try testing.expect(!signing.isShowableUrl("https://"));
    try testing.expect(!signing.isShowableUrl("https://a.example/ x"));
    try testing.expect(!signing.isShowableUrl("https://a.example/\xc2\x9b"));
}

test "a wrong connect secret ends the run with one line" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rig: Rig = undefined;
    try rig.init(gpa, testing.io, .serve);
    defer rig.deinit();
    const wrong = try std.mem.replaceOwned(u8, arena, rig.uri(), "s3cret", "guess");
    const r = try runVerb(gpa, arena, cmd_event.run, &.{ "--sec", wrong, "-c", "x" });
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, r.err, "\n"));
    try testing.expect(has(r.err, "refused the connection"));
}

test "a client key kept per signer is reused, and the file is owner-only" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &path_buf);
    const path = try std.fs.path.join(gpa, &.{ path_buf[0..dir_len], "clients" });
    defer gpa.free(path);

    const signer_a = [_]u8{0xaa} ** 32;
    const signer_b = [_]u8{0xbb} ** 32;
    const first = try signing.clientKeyFor(gpa, io, path, signer_a);
    try testing.expect(!first.remembered);
    const again = try signing.clientKeyFor(gpa, io, path, signer_a);
    try testing.expect(again.remembered);
    try testing.expectEqualSlices(u8, &first.key, &again.key);
    const other = try signing.clientKeyFor(gpa, io, path, signer_b);
    try testing.expect(!other.remembered);
    try testing.expect(!std.mem.eql(u8, &first.key, &other.key));

    if (@import("builtin").os.tag != .windows) {
        const st = try Io.Dir.cwd().statFile(io, path, .{});
        try testing.expectEqual(@as(u32, 0), @as(u32, @intCast(st.permissions.toMode() & 0o077)));
    }
}
