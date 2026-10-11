//! NIP-42: answering a relay that asks who is reading or writing.
//!
//! A relay that keeps some events behind authentication sends a challenge,
//! `["AUTH", <challenge>]`, and refuses what needs it with a reason starting
//! `auth-required:`. The answer is a `kind:22242` event, signed by the caller's
//! key, naming the relay and echoing the challenge.
//!
//! `--auth` turns that on for `req`, `fetch` and `publish`. Without it deed
//! signs nothing it was not asked to sign: a key handed to a verb that only
//! reads is not a key that verb should use on its own.

const std = @import("std");
const nostr = @import("nostr");
const keyinput = @import("keyinput.zig");
const signing = @import("signing.zig");

const keys = nostr.keys;
const nip42 = nostr.nip42;

/// What a run that may authenticate needs.
pub const Options = struct {
    /// The key answers are signed with, when it is held here.
    keypair: ?keys.KeyPair = null,
    /// The remote signer that signs them otherwise.
    remote: ?*signing.Signer = null,
    /// `deinit` ends the remote signer's session and frees it: set when
    /// `resolve` opened it, and not when a verb lends its own.
    owns_remote: bool = false,
    /// Wait for the relay's challenge, and answer it, before asking anything.
    /// For relays that send no `auth-required:` refusal and quietly answer an
    /// unauthenticated reader with less.
    force_pre_auth: bool = false,

    pub fn deinit(self: Options, gpa: std.mem.Allocator) void {
        if (!self.owns_remote) return;
        if (self.remote) |r| {
            r.deinit();
            gpa.destroy(r);
        }
    }
};

/// The flags as they were given, before the key is read.
pub const Flags = struct {
    auth: bool = false,
    force_pre_auth: bool = false,
    sec: ?[]const u8 = null,

    /// Takes `args[i.*]` when it is one of the auth flags, moving `i` past a
    /// value. Returns `.missing_value` for `--sec` at the end of the line.
    pub fn take(self: *Flags, args: []const []const u8, i: *usize) enum { taken, not_mine, missing_value } {
        const a = args[i.*];
        if (std.mem.eql(u8, a, "--auth")) {
            self.auth = true;
            return .taken;
        }
        if (std.mem.eql(u8, a, "--force-pre-auth")) {
            self.force_pre_auth = true;
            return .taken;
        }
        if (std.mem.eql(u8, a, "--sec")) {
            if (i.* + 1 >= args.len) return .missing_value;
            i.* += 1;
            self.sec = args[i.*];
            return .taken;
        }
        return .not_mine;
    }
};

/// The text for a verb's usage, one line per flag, to follow a line of its
/// options.
pub const usage_lines = "\n" ++
    \\      --auth           answer a relay's NIP-42 challenge when it asks,
    \\                       and try once more
    \\      --force-pre-auth wait for the challenge and answer it before
    \\                       asking anything (implies --auth)
    \\      --sec <key>      the key to authenticate with: nsec1...,
    \\                       ncryptsec1..., bunker://... or 64 hex characters.
    \\                       $NOSTR_SECRET_KEY is read when --sec is absent
    \\
;

pub const ResolveError = error{
    /// Nothing was said to the caller yet: the flags made no sense.
    Usage,
    /// The key could not be read.
    BadKey,
};

/// Turns the flags into options, reading the key. Null when `--auth` was not
/// given. Says what is wrong on `err` before failing. A `bunker://` URI
/// connects to the remote signer here, so a signer that cannot be reached
/// ends the run before any relay is asked; the caller deinits the options.
pub fn resolve(gpa: std.mem.Allocator, io: std.Io, flags: Flags, verb: []const u8, err: *std.Io.Writer) !?Options {
    if (!flags.auth and !flags.force_pre_auth) {
        if (flags.sec != null) {
            try err.print("deed {s}: --sec is for --auth, which was not given\n", .{verb});
            return ResolveError.Usage;
        }
        return null;
    }
    const raw = flags.sec orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.print("deed {s}: --auth needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n", .{verb});
        return ResolveError.Usage;
    };
    if (keyinput.isBunkerUri(raw)) {
        const remote = try gpa.create(signing.Signer);
        errdefer gpa.destroy(remote);
        remote.* = (try signing.open(gpa, io, verb, raw, err)) orelse return ResolveError.BadKey;
        return .{ .remote = remote, .owns_remote = true, .force_pre_auth = flags.force_pre_auth };
    }
    var sk = keyinput.secretKeyForRemoteVerb(gpa, verb, raw, err) catch |e| switch (e) {
        error.BadKey => return ResolveError.BadKey,
        else => |other| return other,
    };
    defer std.crypto.secureZero(u8, &sk);
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(sk) catch {
        try err.print("deed {s}: not a secret key (want nsec1..., ncryptsec1..., bunker://... or 64 hex characters)\n", .{verb});
        return ResolveError.BadKey;
    };
    return .{ .keypair = kp, .force_pre_auth = flags.force_pre_auth };
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

/// Whether a refusal is a relay asking for authentication.
pub fn isAuthRequired(reason: []const u8) bool {
    return std.mem.startsWith(u8, reason, "auth-required:");
}

/// The `["AUTH", <event>]` text answering `challenge` from the relay dialled
/// as `url`, and the answering event's id, which the relay's OK will name.
///
/// The `relay` tag is `url` exactly as it was dialled: a relay checks it
/// against its own address, and one rewritten here (a slash added, the case
/// of the host changed) is a mismatch to some of them.
pub const Answer = struct {
    id: [32]u8,
    event: nostr.event.Event,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Answer) void {
        self.arena.deinit();
    }
};

pub fn answer(gpa: std.mem.Allocator, io: std.Io, opts: Options, url: []const u8, challenge: []const u8) !Answer {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    // One per answer. Answers are rare and come from more than one thread, and
    // a context of its own is the plain way to keep them apart.
    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const a = arena.allocator();
    const relay_url = try a.dupe(u8, url);
    const text = try a.dupe(u8, challenge);
    if (opts.remote) |remote| {
        // The tags `nip42.authEvent` builds, signed by the remote signer.
        const tags = try a.alloc(nostr.event.Tag, 2);
        tags[0] = try a.dupe([]const u8, &.{ "relay", relay_url });
        tags[1] = try a.dupe([]const u8, &.{ "challenge", text });
        const ev = try remote.sign(a, now, nip42.kind, tags, "");
        return .{ .id = ev.id, .event = ev, .arena = arena };
    }
    const kp = opts.keypair orelse return error.NoKey;
    const ev = try nip42.authEvent(a, signer, kp, relay_url, text, now, null);
    return .{ .id = ev.id, .event = ev, .arena = arena };
}

test "the answer names the dialled relay exactly, echoes the challenge, and verifies" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);

    var ans = try answer(gpa, io, .{ .keypair = kp }, "wss://Relay.Example/path", "c-1");
    defer ans.deinit();
    try std.testing.expectEqual(@as(u16, 22242), ans.event.kind);
    try std.testing.expectEqualStrings("wss://Relay.Example/path", ans.event.tags[0][1]);
    try std.testing.expectEqualStrings("relay", ans.event.tags[0][0]);
    try std.testing.expectEqualStrings("challenge", ans.event.tags[1][0]);
    try std.testing.expectEqualStrings("c-1", ans.event.tags[1][1]);
    try std.testing.expect(try nostr.event.verify(gpa, signer, ans.event));
}

test "the flags are taken, and a key is needed only when --auth is given" {
    var buf: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&buf);
    const gpa = std.testing.allocator;

    var f: Flags = .{};
    const args = [_][]const u8{ "--auth", "--sec", "11" ** 32, "-k" };
    var i: usize = 0;
    try std.testing.expect(f.take(&args, &i) == .taken);
    i += 1;
    try std.testing.expect(f.take(&args, &i) == .taken);
    try std.testing.expectEqual(@as(usize, 2), i);
    i += 1;
    try std.testing.expect(f.take(&args, &i) == .not_mine);
    const opts = (try resolve(gpa, std.testing.io, f, "req", &err)).?;
    try std.testing.expect(!opts.force_pre_auth);

    try std.testing.expectEqual(@as(?Options, null), try resolve(gpa, std.testing.io, .{}, "req", &err));
    try std.testing.expectError(ResolveError.Usage, resolve(gpa, std.testing.io, .{ .sec = "11" ** 32 }, "req", &err));
    try std.testing.expectError(ResolveError.BadKey, resolve(gpa, std.testing.io, .{ .auth = true, .sec = "nope" }, "req", &err));

    var g: Flags = .{};
    const short = [_][]const u8{"--sec"};
    i = 0;
    try std.testing.expect(g.take(&short, &i) == .missing_value);
}

test "only an auth-required: reason asks for authentication" {
    try std.testing.expect(isAuthRequired("auth-required: log in first"));
    try std.testing.expect(!isAuthRequired("restricted: not for you"));
    try std.testing.expect(!isAuthRequired("Auth-required: wrong case"));
}
