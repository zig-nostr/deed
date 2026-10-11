//! Who signs: a secret key held here, or a remote signer reached over NIP-46.
//!
//! Every verb that signs or encrypts as the user takes `--sec` (or
//! `$NOSTR_SECRET_KEY`), and that text may be a `bunker://` URI as well as a
//! key. A `Signer` hides the difference: it gives the user's pubkey, signs
//! events, and NIP-44 or NIP-04 encrypts and decrypts, either with the key in
//! hand or by asking the signer that holds it.
//!
//! A remote signer is reached the way NIP-46 says: deed dials the relays the
//! URI names, runs one reader per relay, sends `connect` with the URI's
//! secret, and asks for the user's pubkey. Every request after that is a round
//! trip through a relay, under a deadline (`request_timeout_ms`), so a signer
//! that never answers ends the run with a message rather than holding it.
//! Ctrl-C ends the wait at any point: nothing is written while a request is
//! out.
//!
//! The session needs a key of its own, the client key. By default it is made
//! fresh for each run, so a signer that asks before trusting a new client asks
//! on every run. Setting `$DEED_BUNKER_CLIENT_KEYS` to a file path keeps one
//! client key per signer pubkey in that file (owner-only, created on first
//! use), and a signer that already trusts that client is not asked again.
//!
//! When the signer answers a request with an approval link (`auth_url`), the
//! link is shown on stderr, and only when it is an https URL made of plain
//! printable characters. Anything else is not shown, and the message says so.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const keyinput = @import("keyinput.zig");
const dial = @import("dial.zig");

const Io = std.Io;
const keys = nostr.keys;
const event = nostr.event;
const nip04 = nostr.nip04;
const nip44 = nostr.nip44;
const nip46 = nostr.nip46;
const nip46_client = nostr.nip46_client;
const nip98 = nostr.nip98;
const relay = nostr.relay;
const hex = nostr.hex;

/// The deadline on each request to a remote signer. A person may be
/// approving it on another device, so it is generous.
pub const request_timeout_ms: u32 = 60_000;

/// Names a file that keeps a client key per remote signer.
pub const client_keys_env = "DEED_BUNKER_CLIENT_KEYS";

/// The most a client keys file may hold.
const max_client_keys_bytes = 64 * 1024;

/// Whether `text` is a remote signer URI rather than a key.
pub const isBunkerUri = keyinput.isBunkerUri;

pub const Method = enum { nip44_encrypt, nip44_decrypt, nip04_encrypt, nip04_decrypt };

/// A remote signer session, behind a pointer so the transport can differ
/// between a run (live relays) and a test (an in-memory hub).
pub const Remote = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    user: [32]u8,

    pub const VTable = struct {
        sign: *const fn (ptr: *anyopaque, template: nip46_client.Template) anyerror!event.Parsed,
        /// The answer is the session's, and is given back with `free`.
        peer: *const fn (ptr: *anyopaque, method: Method, peer: [32]u8, text: []const u8) anyerror![]u8,
        free: *const fn (ptr: *anyopaque, bytes: []u8) void,
        close: *const fn (ptr: *anyopaque) void,
    };
};

pub const Signer = struct {
    /// A signing context for local work: signing with a local key, and the
    /// throwaway key below. Owned.
    ctx: keys.Signer,
    backend: union(enum) {
        local: keys.KeyPair,
        remote: Remote,
    },
    /// The key pair a library helper that signs with a key pair is given. The
    /// user's own for a local key. For a remote signer, a throwaway: the
    /// helper builds the event, and `finish` has the signer sign it as the
    /// user.
    helper: keys.KeyPair,

    /// A signer over a secret key held here.
    pub fn initLocal(io: Io, sk: keys.SecretKey) !Signer {
        var ctx = try keys.Signer.initRandomized(io);
        errdefer ctx.deinit();
        const kp = try ctx.keyPairFromSecretKey(sk);
        return .{ .ctx = ctx, .backend = .{ .local = kp }, .helper = kp };
    }

    /// A signer over a remote session. Takes ownership of it.
    pub fn initRemote(io: Io, remote: Remote) !Signer {
        var ctx = keys.Signer.initRandomized(io) catch |e| {
            remote.vtable.close(remote.ptr);
            return e;
        };
        const helper = ctx.generateKeyPair(io) catch |e| {
            ctx.deinit();
            remote.vtable.close(remote.ptr);
            return e;
        };
        return .{ .ctx = ctx, .backend = .{ .remote = remote }, .helper = helper };
    }

    /// Ends a remote session (its readers and its connections) and wipes the
    /// keys.
    pub fn deinit(self: *Signer) void {
        switch (self.backend) {
            .local => |*kp| std.crypto.secureZero(u8, &kp.secret_key),
            .remote => |r| r.vtable.close(r.ptr),
        }
        std.crypto.secureZero(u8, &self.helper.secret_key);
        self.ctx.deinit();
        self.* = undefined;
    }

    pub fn isRemote(self: *const Signer) bool {
        return self.backend == .remote;
    }

    /// The user's key pair, when the key is held here.
    pub fn keyPair(self: *const Signer) ?keys.KeyPair {
        return switch (self.backend) {
            .local => |kp| kp,
            .remote => null,
        };
    }

    /// The user's pubkey.
    pub fn publicKey(self: *const Signer) [32]u8 {
        return switch (self.backend) {
            .local => |kp| kp.public_key,
            .remote => |r| r.user,
        };
    }

    /// Signs an event by the user. `tags` and `content` are borrowed by the
    /// result, as with `event.create`.
    pub fn sign(
        self: *Signer,
        a: std.mem.Allocator,
        created_at: i64,
        kind: u16,
        tags: []const event.Tag,
        content: []const u8,
    ) !event.Event {
        switch (self.backend) {
            .local => |kp| return event.create(a, self.ctx, kp, created_at, kind, tags, content, null),
            .remote => |r| {
                var signed = try r.vtable.sign(r.ptr, .{ .kind = kind, .content = content, .tags = tags, .created_at = created_at });
                defer signed.deinit();
                // The client checked the answer against the template, so the
                // fields are the ones passed in, and they outlive the arena.
                return .{
                    .id = signed.value.id,
                    .pubkey = signed.value.pubkey,
                    .created_at = created_at,
                    .kind = kind,
                    .tags = tags,
                    .content = content,
                    .sig = signed.value.sig,
                };
            },
        }
    }

    /// An event a library helper built and signed with `helper`, as the user
    /// signs it: the same event for a local key, re-signed by the remote
    /// signer otherwise.
    pub fn finish(self: *Signer, a: std.mem.Allocator, ev: event.Event) !event.Event {
        return switch (self.backend) {
            .local => ev,
            .remote => self.sign(a, ev.created_at, ev.kind, ev.tags, ev.content),
        };
    }

    /// Signs an event whose id was already found by proof of work. A local key
    /// signs the id; a remote signer is sent the fields, which give the same
    /// id, and the answer is checked to carry it.
    pub fn signMined(self: *Signer, a: std.mem.Allocator, ev: event.Event) !event.Event {
        switch (self.backend) {
            .local => |kp| {
                var out = ev;
                out.sig = try self.ctx.signId(ev.id, kp, null);
                return out;
            },
            .remote => {
                const signed = try self.sign(a, ev.created_at, ev.kind, ev.tags, ev.content);
                if (!std.mem.eql(u8, &signed.id, &ev.id)) return error.WrongSigner;
                return signed;
            },
        }
    }

    /// A NIP-98 `Authorization` value for one HTTP request, signed by the
    /// user. `body`, when given, is hashed into the `payload` tag. Owned.
    pub fn httpAuthHeader(
        self: *Signer,
        gpa: std.mem.Allocator,
        created_at: i64,
        url: []const u8,
        method: []const u8,
        body: ?[]const u8,
    ) ![]u8 {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const payload: ?[32]u8 = if (body) |b| nip98.payloadHash(b) else null;
        const built = try nip98.authEvent(a, self.ctx, self.helper, created_at, url, method, payload, null);
        return nip98.encodeHeader(gpa, try self.finish(a, built));
    }

    /// NIP-44 or NIP-04 work between the user and `peer`. Owned result; the
    /// result of a decrypt is plaintext, so the caller zeroes it.
    pub fn crypt(self: *Signer, gpa: std.mem.Allocator, io: Io, method: Method, peer: [32]u8, text: []const u8) ![]u8 {
        switch (self.backend) {
            .local => |kp| return switch (method) {
                .nip44_encrypt => nip44.encrypt(gpa, io, self.ctx, kp.secret_key, peer, text),
                .nip44_decrypt => nip44.decrypt(gpa, self.ctx, kp.secret_key, peer, text),
                .nip04_encrypt => nip04.encrypt(gpa, io, self.ctx, kp.secret_key, peer, text),
                .nip04_decrypt => nip04.decrypt(gpa, self.ctx, kp.secret_key, peer, text),
            },
            .remote => |r| {
                // Copied into the caller's allocator, which may be an arena,
                // and the session's copy zeroed and freed.
                const got = try r.vtable.peer(r.ptr, method, peer, text);
                defer r.vtable.free(r.ptr, got);
                return gpa.dupe(u8, got);
            },
        }
    }
};

/// One line for a remote signer's failure, or null for an error that is not
/// one of its own.
pub fn describe(e: anyerror) ?[]const u8 {
    return switch (e) {
        error.Rejected => "the remote signer refused the request",
        error.Timeout => "the remote signer did not answer in time",
        error.WrongSigner, error.BadSignature => "the remote signer answered with an event that is not the one asked for",
        error.UnexpectedResult => "the remote signer gave an answer that does not fit the request",
        error.PublishFailed, error.NoRelays => "the request could not be sent to any of the signer's relays",
        error.NotConnected => "the remote signer is not connected",
        error.TooManyPending => "too many requests are waiting on the remote signer",
        else => null,
    };
}

/// Says why a signing step failed on `err` and returns the exit code, when
/// the failure is a remote signer's. Any other error is returned.
pub fn report(verb: []const u8, e: anyerror, err: *Io.Writer) !u8 {
    if (e == error.Canceled) return e;
    const why = describe(e) orelse return e;
    try err.print("deed {s}: {s}\n", .{ verb, why });
    return 1;
}

/// The signer `text` names: a secret key (nsec, hex, ncryptsec) or a
/// `bunker://` URI. Null after one line on `err` saying why there is none.
pub fn open(gpa: std.mem.Allocator, io: Io, verb: []const u8, text: []const u8, err: *Io.Writer) !?Signer {
    if (isBunkerUri(text)) return openRemote(gpa, io, verb, std.mem.trim(u8, text, " \t\r\n"), .{}, err);
    var sk = keyinput.secretKeyForRemoteVerb(gpa, verb, text, err) catch |e| switch (e) {
        error.BadKey => return null,
        else => return e,
    };
    defer std.crypto.secureZero(u8, &sk);
    return Signer.initLocal(io, sk) catch |e| switch (e) {
        error.InvalidSecretKey => {
            try err.print("deed {s}: that secret key is out of range\n", .{verb});
            return null;
        },
        else => return e,
    };
}

/// The signer named by `flag`, or `$NOSTR_SECRET_KEY` when there is no flag.
/// Null after one line saying there is neither (a usage error). One that is
/// named and cannot be had fails with `error.BadKey` after one line saying why.
/// A key nobody chose is never invented.
pub fn fromFlag(gpa: std.mem.Allocator, io: Io, verb: []const u8, flag: ?[]const u8, err: *Io.Writer) !?Signer {
    const raw = flag orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.print("deed {s}: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n", .{verb});
        return null;
    };
    return (try open(gpa, io, verb, raw, err)) orelse error.BadKey;
}

pub const RemoteOptions = struct {
    timeout_ms: u32 = request_timeout_ms,
    dial_timeout_ms: i64 = dial.default_timeout_ms,
    /// The client keys file. Null reads `$DEED_BUNKER_CLIENT_KEYS`.
    client_keys_path: ?[]const u8 = null,
};

/// Dials the relays a `bunker://` URI names and connects to the signer.
pub fn openRemote(gpa: std.mem.Allocator, io: Io, verb: []const u8, uri: []const u8, options: RemoteOptions, err: *Io.Writer) !?Signer {
    var parsed = nip46.parseBunkerUri(gpa, uri) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            try err.print("deed {s}: not a bunker URI (want bunker://<pubkey>?relay=wss://...&secret=...)\n", .{verb});
            return null;
        },
    };
    defer {
        if (parsed.value.secret) |s| std.crypto.secureZero(u8, @constCast(s));
        parsed.deinit();
    }
    const urls = parsed.value.relays;
    if (urls.len == 0) {
        try err.print("deed {s}: the bunker URI names no relay\n", .{verb});
        return null;
    }
    if (urls.len > dial.max_relays) {
        try err.print("deed {s}: the bunker URI names more than {d} relays\n", .{ verb, dial.max_relays });
        return null;
    }

    var client_key: ?keys.SecretKey = null;
    defer if (client_key) |*k| std.crypto.secureZero(u8, k);
    var remembered = false;
    if (options.client_keys_path orelse getEnv(client_keys_env)) |path| {
        const got = clientKeyFor(gpa, io, path, parsed.value.remote_signer_pubkey) catch |e| {
            try err.print("deed {s}: cannot use the client key file {s}: {s}\n", .{ verb, path, @errorName(e) });
            return null;
        };
        client_key = got.key;
        remembered = got.remembered;
    }

    if (builtin.is_test) {
        if (test_relays) |t| return t.start(t.ctx, gpa, io, verb, uri, .{
            .timeout_ms = options.timeout_ms,
            .client_key = client_key,
            .remembered = remembered,
        }, err);
    }

    var outcomes: [dial.max_relays]dial.Outcome = undefined;
    dial.all(gpa, io, urls, options.dial_timeout_ms, outcomes[0..urls.len]);
    var conns: [dial.max_relays]*relay.Relay = undefined;
    var live: [dial.max_relays][]const u8 = undefined;
    var count: usize = 0;
    for (outcomes[0..urls.len], urls) |o, u| switch (o) {
        .connected => |r| {
            conns[count] = r;
            live[count] = u;
            count += 1;
        },
        else => {},
    };
    if (count == 0) {
        try err.print("deed {s}: could not reach any of the remote signer's relays\n", .{verb});
        return null;
    }
    return start(*relay.Relay, gpa, io, verb, uri, conns[0..count], live[0..count], true, .{
        .timeout_ms = options.timeout_ms,
        .client_key = client_key,
        .remembered = remembered,
    }, err);
}

/// Tests only: stands in for dialling the relays a URI names, so a test can
/// put a signer on an in-memory relay behind every verb that takes `--sec`.
pub const TestRelays = struct {
    ctx: *anyopaque,
    start: *const fn (ctx: *anyopaque, gpa: std.mem.Allocator, io: Io, verb: []const u8, uri: []const u8, options: StartOptions, err: *Io.Writer) anyerror!?Signer,
};
pub var test_relays: ?TestRelays = null;

/// Tests only: where the approval link lines go in place of stderr.
pub var test_notice: ?*const fn (line: []const u8) void = null;

pub const StartOptions = struct {
    timeout_ms: u32 = request_timeout_ms,
    client_key: ?keys.SecretKey = null,
    /// The client key is one the signer may already trust, so ask for the
    /// pubkey before presenting the URI's secret, which may have been used.
    remembered: bool = false,
};

/// Connects to the signer over `conns`, which are already dialled, and
/// returns a signer that owns the session. With `owns_conns`, the
/// connections are closed and freed with it, and on every failure here.
pub fn start(
    comptime Conn: type,
    gpa: std.mem.Allocator,
    io: Io,
    verb: []const u8,
    uri: []const u8,
    conns: []const Conn,
    urls: []const []const u8,
    owns_conns: bool,
    options: StartOptions,
    err: *Io.Writer,
) !?Signer {
    const S = Session(Conn);
    const session = S.create(gpa, io, verb, uri, conns, urls, owns_conns, options) catch |e| {
        try err.print("deed {s}: cannot start a session with the remote signer: {s}\n", .{ verb, @errorName(e) });
        return null;
    };
    session.connect(options.remembered) catch |e| {
        session.destroy();
        if (e == error.Canceled) return e;
        if (e == error.Rejected) {
            try err.print("deed {s}: the remote signer refused the connection (a wrong or already used secret?)\n", .{verb});
        } else if (describe(e)) |why| {
            try err.print("deed {s}: {s}\n", .{ verb, why });
        } else {
            try err.print("deed {s}: cannot connect to the remote signer: {s}\n", .{ verb, dial.describe(e) });
        }
        return null;
    };
    return try Signer.initRemote(io, session.remote());
}

/// A NIP-46 session over connections of type `Conn`, with one reader task per
/// connection.
pub fn Session(comptime Conn: type) type {
    return struct {
        const Self = @This();
        const Client = nip46_client.Client(Conn);
        const Reading = Io.Future(@typeInfo(@TypeOf(Client.run)).@"fn".return_type.?);
        const max = nip46_client.max_relays;

        gpa: std.mem.Allocator,
        io: Io,
        /// The client's own context, shared by its readers and requests.
        ctx: keys.Signer,
        client: *Client,
        verb: []const u8,
        conns: [max]Conn = undefined,
        urls: [max][]u8 = undefined,
        readers: [max]?Reading = [_]?Reading{null} ** max,
        count: usize = 0,
        owns_conns: bool,
        user: [32]u8 = undefined,

        fn create(
            gpa: std.mem.Allocator,
            io: Io,
            verb: []const u8,
            uri: []const u8,
            conns: []const Conn,
            urls: []const []const u8,
            owns_conns: bool,
            options: StartOptions,
        ) !*Self {
            const n = @min(conns.len, max);
            if (owns_conns) for (conns[n..]) |c| closeConn(io, c);
            errdefer if (owns_conns) for (conns[0..n]) |c| closeConn(io, c);

            var owned: [max][]u8 = undefined;
            var copied: usize = 0;
            errdefer for (owned[0..copied]) |u| gpa.free(u);
            for (urls[0..n]) |u| {
                owned[copied] = try gpa.dupe(u8, u);
                copied += 1;
            }

            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{
                .gpa = gpa,
                .io = io,
                .ctx = try keys.Signer.initRandomized(io),
                .client = undefined,
                .verb = verb,
                .owns_conns = owns_conns,
            };
            errdefer self.ctx.deinit();
            self.client = try Client.initBunker(gpa, io, self.ctx, uri, .{
                .timeout_ms = options.timeout_ms,
                .client_secret_key = options.client_key,
                .on_auth_url = .{ .context = self, .onAuthUrl = &onAuthUrl },
            });
            @memcpy(self.conns[0..n], conns[0..n]);
            @memcpy(self.urls[0..n], owned[0..n]);
            self.count = n;
            return self;
        }

        /// Attaches every connection, starts its reader, and connects.
        fn connect(self: *Self, remembered: bool) !void {
            var attached: usize = 0;
            for (self.conns[0..self.count], self.urls[0..self.count], 0..) |c, u, i| {
                self.client.attach(c) catch continue;
                // `concurrent`, never `async`: an inline reader would never
                // return, and the run would hang in it.
                self.readers[i] = self.io.concurrent(Client.run, .{ self.client, c, u }) catch continue;
                attached += 1;
            }
            if (attached == 0) return error.NoRelays;

            if (remembered) {
                if (self.client.getPublicKey()) |pk| {
                    self.user = pk;
                    return;
                } else |e| switch (e) {
                    error.Rejected => {},
                    else => return e,
                }
            }
            try self.client.connect();
            self.user = self.client.userPubkey() orelse return error.NotConnected;
        }

        /// Stops the readers, then frees the client and the connections.
        fn destroy(self: *Self) void {
            const io = self.io;
            for (self.conns[0..self.count], 0..) |c, i| {
                if (self.readers[i]) |*r| {
                    // A live relay's socket is shut first, so a reader inside
                    // a read wakes whether or not the cancel reaches it.
                    if (self.owns_conns) shutdownConn(io, c);
                    _ = r.cancel(io) catch {};
                }
            }
            self.client.deinit();
            for (self.conns[0..self.count], self.urls[0..self.count]) |c, u| {
                if (self.owns_conns) closeConn(io, c);
                self.gpa.free(u);
            }
            self.ctx.deinit();
            self.gpa.destroy(self);
        }

        fn remote(self: *Self) Remote {
            return .{ .ptr = self, .vtable = &vtable, .user = self.user };
        }

        const vtable: Remote.VTable = .{ .sign = sign, .peer = peer, .free = free, .close = close };

        fn sign(ptr: *anyopaque, template: nip46_client.Template) anyerror!event.Parsed {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return self.client.signEvent(template);
        }

        fn peer(ptr: *anyopaque, method: Method, pk: [32]u8, text: []const u8) anyerror![]u8 {
            const self: *Self = @ptrCast(@alignCast(ptr));
            return switch (method) {
                .nip44_encrypt => self.client.nip44Encrypt(pk, text),
                .nip44_decrypt => self.client.nip44Decrypt(pk, text),
                .nip04_encrypt => self.client.nip04Encrypt(pk, text),
                .nip04_decrypt => self.client.nip04Decrypt(pk, text),
            };
        }

        fn free(ptr: *anyopaque, bytes: []u8) void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            std.crypto.secureZero(u8, bytes);
            self.gpa.free(bytes);
        }

        fn close(ptr: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.destroy();
        }

        fn onAuthUrl(context: ?*anyopaque, request_id: []const u8, url: []const u8) void {
            _ = request_id;
            const self: *Self = @ptrCast(@alignCast(context.?));
            var buf: [4096]u8 = undefined;
            const line = authUrlLine(&buf, self.verb, url);
            if (builtin.is_test) if (test_notice) |f| return f(line);
            // On a reader's thread, so straight to stderr under its lock
            // rather than through the run's buffered writer.
            std.debug.print("{s}", .{line});
        }

        fn closeConn(io: Io, c: Conn) void {
            if (Conn == *relay.Relay) {
                c.shutdown(io);
                c.deinit();
            }
        }

        fn shutdownConn(io: Io, c: Conn) void {
            if (Conn == *relay.Relay) c.shutdown(io);
        }
    };
}

/// The line that tells the person about an approval link: the link when it
/// may be shown, and that one came otherwise.
pub fn authUrlLine(buf: []u8, verb: []const u8, url: []const u8) []const u8 {
    const shown = if (isShowableUrl(url))
        std.fmt.bufPrint(buf, "deed {s}: the remote signer asks you to approve this at {s}\n", .{ verb, url })
    else
        std.fmt.bufPrint(buf, "deed {s}: the remote signer sent an approval link that is not a plain https URL, so it is not shown\n", .{verb});
    return shown catch "deed: the remote signer sent an approval link too long to show\n";
}

/// An approval link is shown only when it is https and every byte is a
/// printable ASCII character, so it cannot move the cursor, clear the screen
/// or pass itself off as something deed said.
pub fn isShowableUrl(url: []const u8) bool {
    if (!keyinput.hasPrefix(url, "https://") or url.len <= "https://".len) return false;
    for (url) |c| if (c <= 0x20 or c >= 0x7f) return false;
    return true;
}

const ClientKey = struct { key: keys.SecretKey, remembered: bool };

/// The client key kept for `signer` in the file at `path`, one
/// `<signer pubkey hex> <client secret hex>` line per signer. A signer with no
/// line gets a fresh key, written back before it is used. The file is
/// owner-only, and one that others can read is refused.
pub fn clientKeyFor(gpa: std.mem.Allocator, io: Io, path: []const u8, signer: [32]u8) !ClientKey {
    const cwd = Io.Dir.cwd();
    var text: []u8 = &.{};
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    if (cwd.readFileAlloc(io, path, gpa, .limited(max_client_keys_bytes))) |t| {
        text = t;
        if (builtin.os.tag != .windows) {
            const st = try cwd.statFile(io, path, .{});
            if (st.permissions.toMode() & 0o077 != 0) return error.ReadableByOthers;
        }
    } else |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    }

    const want = std.fmt.bytesToHex(signer, .lower);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const who = fields.next() orelse continue;
        const secret = fields.next() orelse continue;
        if (!std.ascii.eqlIgnoreCase(who, &want)) continue;
        const key = hex.decodeFixed(32, secret) catch return error.NotAClientKeyFile;
        return .{ .key = key, .remembered = true };
    }

    var key: keys.SecretKey = undefined;
    var ctx = try keys.Signer.initRandomized(io);
    defer ctx.deinit();
    var kp = try ctx.generateKeyPair(io);
    defer std.crypto.secureZero(u8, &kp.secret_key);
    key = kp.secret_key;
    errdefer std.crypto.secureZero(u8, &key);

    var secret_hex = std.fmt.bytesToHex(key, .lower);
    defer std.crypto.secureZero(u8, &secret_hex);
    const sep: []const u8 = if (text.len > 0 and text[text.len - 1] != '\n') "\n" else "";
    const updated = try std.mem.concat(gpa, u8, &.{ text, sep, &want, " ", &secret_hex, "\n" });
    defer {
        std.crypto.secureZero(u8, updated);
        gpa.free(updated);
    }
    // Whole, to a fresh owner-only file beside it, then renamed over it.
    if (std.fs.path.dirname(path)) |parent| try cwd.createDirPath(io, parent);
    const tmp = try std.mem.concat(gpa, u8, &.{ path, ".tmp" });
    defer gpa.free(tmp);
    cwd.deleteFile(io, tmp) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
    try cwd.writeFile(io, .{
        .sub_path = tmp,
        .data = updated,
        .flags = .{
            .exclusive = true,
            .permissions = if (builtin.os.tag == .windows) .default_file else Io.File.Permissions.fromMode(0o600),
        },
    });
    try cwd.rename(tmp, cwd, path, io);
    return .{ .key = key, .remembered = false };
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}
