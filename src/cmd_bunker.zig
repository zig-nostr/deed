//! `deed bunker`: a NIP-46 remote signer.
//!
//! It holds a key and answers signing requests for the clients it trusts, over
//! the relays it is given, until it is stopped. The protocol is the library's:
//! `nostr.signer.serve` runs the request loop on one connection and
//! `nip46.Bunker` answers each request. What lives here is everything a
//! daemon adds around that: who is trusted, one connection per relay that
//! comes back when it drops, a watch for connections that went quiet, and a
//! way to stop that does not wait on any of them.
//!
//! Who is trusted is decided before anything touches the key. A client is
//! served when its pubkey was given with `--authorized-keys`, or once it has
//! connected with a secret: the one in the printed URI, or one given with
//! `--authorized-secrets`. Anybody else gets an error response, including for
//! `ping` and `get_public_key`, which the library would otherwise answer for a
//! stranger. There are no prompts, because nobody is there to answer one.
//!
//! The URI's own secret is good for one client. Whoever presents it first is
//! remembered by pubkey, the secret is replaced, and the new URI is printed. A
//! URI copied out of a terminal, a log or a screenshot stops being a way in as
//! soon as the client it was meant for has used it.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const dial = @import("dial.zig");
const qr = @import("qr.zig");

const Io = std.Io;
const keys = nostr.keys;
const nip46 = nostr.nip46;
const hex = nostr.hex;
const relay = nostr.relay;

/// Shown beside the name in `deed help`.
pub const summary = "run a NIP-46 remote signer";

pub const ready = true;

pub const usage =
    \\deed bunker: run a NIP-46 remote signer
    \\
    \\Usage:
    \\  deed bunker [options] <relay>...
    \\  deed bunker connect <nostrconnect://…> [options] [<relay>...]
    \\
    \\Holds a key and signs with it for the clients it trusts, over the relays
    \\given. Prints a bunker:// URI on stdout for a client to connect with, logs
    \\every request to stderr (the method and the client's pubkey, never its
    \\content), and runs until interrupted.
    \\
    \\The key to sign with comes from $NOSTR_SECRET_KEY, or from the --persist
    \\file once it holds one. --sec works too, but the command line of a
    \\process that runs for days can be read by every user of the machine
    \\(ps), so a key given there is not kept secret.
    \\
    \\Options:
    \\  --sec <key>                    the key to sign with, in any form
    \\                                 `deed event` takes; see above for why
    \\                                 $NOSTR_SECRET_KEY is the better way
    \\  -k, --authorized-keys <pubkey> a client served without a secret,
    \\                                 repeatable
    \\  --authorized-secrets-file <path>
    \\                                 secrets that authorize the client that
    \\                                 presents one, one a line; the file must be
    \\                                 readable by its owner only
    \\  -s, --authorized-secrets <s>   one such secret on the command line,
    \\                                 repeatable; visible to other users like
    \\                                 --sec, so prefer the file
    \\  --persist <path>               keep the key, the relays and the authorized
    \\                                 clients in this file across restarts
    \\  --qrcode                       print the URI as a QR code too, on stderr
    \\
    \\Who is served:
    \\  Only authorized clients. A client is authorized when its pubkey was
    \\  given with --authorized-keys, or when it connects with a secret: the one
    \\  in the printed URI, or one given with --authorized-secrets. Every other
    \\  request is answered with an error. Nothing is asked interactively.
    \\
    \\  The URI's secret is good for one client. Once a client has used it, it
    \\  is replaced and the new URI is printed. With --authorized-keys and no
    \\  --authorized-secrets the URI carries no secret, and only those keys are
    \\  served.
    \\
    \\  With --persist, a client that connected with a secret is remembered and
    \\  does not need one again after a restart. A client that logs out is
    \\  forgotten, and needs a secret to connect again. To stop serving one,
    \\  take its pubkey out of the file. The file is written readable by its owner only,
    \\  and refused if anybody else can read it. It holds the key in the form it
    \\  was given, so give an ncryptsec to keep it encrypted there.
    \\
    \\connect:
    \\  Answers a nostrconnect:// URI shown by a client, on the relays it names
    \\  and any given here, and then serves that client.
    \\
    \\  NOSTR_SECRET_KEY=ncryptsec1… deed bunker wss://relay.example
    \\  deed bunker --persist ~/.config/deed/bunker.json --qrcode wss://relay.example
    \\  NOSTR_SECRET_KEY=ncryptsec1… deed bunker connect 'nostrconnect://…'
    \\
;

/// Relays one bunker listens on at most.
const max_relays = dial.max_relays;

/// The first wait before dialling a relay again, and the longest. Doubling in
/// between, and back to the first once a connection has held for a while.
const min_backoff_ms: i64 = 1_000;
const max_backoff_ms: i64 = 60_000;
/// A connection that lasted this long was a working one, so the next drop
/// starts the backoff over rather than continuing it.
const stable_ms: i64 = 60_000;

/// How often the main loop looks at the stop flag, the printed URI and the
/// persist file. Also how quickly a stop is noticed.
const poll_ms: i64 = 100;

/// Bytes of randomness in a generated secret, written out as hex.
const secret_bytes = 16;

/// The persist file is a key and a list of pubkeys: anything larger is not one.
const max_persist_bytes = 1 << 20;

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var parsed = (try parseArgs(arena, args, out, err)) orelse return cli.exit_usage;
    if (parsed.help) return cli.exit_ok;

    const config = (try resolve(arena, io, &parsed, getEnv("NOSTR_SECRET_KEY"), err)) orelse return parsed.failure;

    var daemon = Daemon.init(gpa, io, &config, out, err) catch |e| {
        try err.print("deed bunker: could not start: {s}\n", .{@errorName(e)});
        return cli.exit_fail;
    };
    defer daemon.deinit();

    installStopSignals();
    daemon.run();
    return cli.exit_ok;
}

fn isCancel(e: anyerror) bool {
    return e == error.Canceled;
}

// ---------------------------------------------------------------------------
// Arguments and the persist file
// ---------------------------------------------------------------------------

const Parsed = struct {
    help: bool = false,
    sec: ?[]const u8 = null,
    relays: std.ArrayList([]const u8) = .empty,
    authorized_keys: std.ArrayList([32]u8) = .empty,
    authorized_secrets: std.ArrayList([]const u8) = .empty,
    authorized_secrets_files: std.ArrayList([]const u8) = .empty,
    persist: ?[]const u8 = null,
    qrcode: bool = false,
    invite: ?nip46.NostrConnectUri = null,
    /// The exit code for a failure found after parsing.
    failure: u8 = cli.exit_usage,
};

/// Reads the command line. Null after printing why it could not.
fn parseArgs(arena: std.mem.Allocator, args: []const []const u8, out: *Io.Writer, err: *Io.Writer) !?Parsed {
    var p = Parsed{};
    var i: usize = 0;
    if (args.len > 0 and std.mem.eql(u8, args[0], "connect")) {
        if (args.len < 2) {
            try err.writeAll("deed bunker connect: needs the nostrconnect:// URI the client shows\n");
            return null;
        }
        if (cli.isOneOf(args[1], &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            p.help = true;
            return p;
        }
        const parsed = nip46.parseNostrConnectUri(arena, args[1]) catch {
            try err.writeAll("deed bunker connect: not a nostrconnect:// URI with a client pubkey and a secret\n");
            return null;
        };
        p.invite = parsed.value;
        i = 2;
    }
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            p.help = true;
            return p;
        }
        if (std.mem.eql(u8, a, "--qrcode")) {
            p.qrcode = true;
            continue;
        }
        const takes_value = cli.isOneOf(a, &.{ "--sec", "-k", "--authorized-keys", "-s", "--authorized-secrets", "--authorized-secrets-file", "--persist" });
        if (!takes_value) {
            if (std.mem.startsWith(u8, a, "-")) {
                try err.print("deed bunker: unknown option '{s}'\n", .{a});
                return null;
            }
            _ = relay.parseUrl(a) catch {
                try err.print("deed bunker: '{s}' is not a relay URL (want ws:// or wss://)\n", .{a});
                return null;
            };
            try appendUnique([]const u8, arena, &p.relays, a);
            continue;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed bunker: '{s}' needs a value\n", .{a});
            return null;
        }
        const v = args[i];
        if (std.mem.eql(u8, a, "--sec")) {
            p.sec = v;
        } else if (cli.isOneOf(a, &.{ "-k", "--authorized-keys" })) {
            const pk = keyinput.publicKey(arena, v) catch {
                try err.print("deed bunker: '{s}' is not a public key (want npub1… or 64 hex characters)\n", .{v});
                return null;
            };
            try appendUnique([32]u8, arena, &p.authorized_keys, pk);
        } else if (cli.isOneOf(a, &.{ "-s", "--authorized-secrets" })) {
            if (v.len == 0) {
                try err.writeAll("deed bunker: an authorized secret cannot be empty\n");
                return null;
            }
            try appendUnique([]const u8, arena, &p.authorized_secrets, v);
        } else if (std.mem.eql(u8, a, "--authorized-secrets-file")) {
            if (v.len == 0) {
                try err.writeAll("deed bunker: --authorized-secrets-file needs a path, and it was empty\n");
                return null;
            }
            try appendUnique([]const u8, arena, &p.authorized_secrets_files, v);
        } else if (std.mem.eql(u8, a, "--persist")) {
            if (v.len == 0) {
                try err.writeAll("deed bunker: --persist needs a path, and it was empty\n");
                return null;
            }
            p.persist = v;
        }
    }
    return p;
}

fn appendUnique(comptime T: type, gpa: std.mem.Allocator, list: *std.ArrayList(T), item: T) !void {
    for (list.items) |have| {
        const same = if (T == []const u8) std.mem.eql(u8, have, item) else std.mem.eql(u8, &have, &item);
        if (same) return;
    }
    try list.append(gpa, item);
}

/// What the persist file holds. Pubkeys as hex, so the file can be read and
/// edited by hand.
const Stored = struct {
    sec: ?[]const u8 = null,
    relays: []const []const u8 = &.{},
    authorized_keys: []const []const u8 = &.{},
    authorized_secrets: []const []const u8 = &.{},
};

/// Everything a daemon is started with.
pub const Config = struct {
    keypair: keys.KeyPair,
    /// The key as it was given, for the persist file.
    sec_text: []const u8,
    relays: []const []const u8,
    authorized_keys: []const [32]u8,
    authorized_secrets: []const []const u8,
    /// Whether to generate a single-use secret for the printed URI.
    fresh_secret: bool,
    qrcode: bool = false,
    /// Where `persist_path` is resolved from. Null is the working directory.
    persist_dir: ?Io.Dir = null,
    persist_path: ?[]const u8 = null,
    invite: ?nip46.NostrConnectUri = null,
};

/// Merges the command line with the environment and the persist file. Null
/// after printing why it could not, with `p.failure` set to the exit code.
fn resolve(arena: std.mem.Allocator, io: Io, p: *Parsed, env_sec: ?[]const u8, err: *Io.Writer) !?Config {
    var stored = Stored{};
    var persist_path: ?[]const u8 = null;
    if (p.persist) |raw| {
        const full = expandHome(arena, raw, getEnv("HOME")) catch |e| switch (e) {
            error.OutOfMemory => return e,
            error.NoHome => {
                try err.print("deed bunker: cannot use {s}: HOME is not set, so there is no ~ to expand\n", .{raw});
                return null;
            },
            error.OtherUser => {
                try err.print("deed bunker: cannot use {s}: only ~ and ~/ are expanded, so write the path out in full\n", .{raw});
                return null;
            },
        };
        persist_path = full;
        stored = loadStored(arena, io, Io.Dir.cwd(), full) catch |e| {
            p.failure = cli.exit_fail;
            try err.print("deed bunker: cannot use {s}: {s}\n", .{ full, describeLoad(e) });
            return null;
        };
    }

    // The key: the flag, then the environment, then the file.
    const given = p.sec orelse env_sec;
    const sec_text = given orelse stored.sec orelse {
        try err.writeAll("deed bunker: needs a secret key: set $NOSTR_SECRET_KEY, use a --persist file that holds one, or pass --sec\n");
        return null;
    };
    var signer = keys.Signer.init();
    defer signer.deinit();
    const sk = keyinput.secretKey(arena, sec_text) catch {
        p.failure = cli.exit_fail;
        try err.writeAll("deed bunker: not a secret key\n");
        return null;
    };
    const keypair = signer.keyPairFromSecretKey(sk) catch {
        p.failure = cli.exit_fail;
        try err.writeAll("deed bunker: not a valid secret key\n");
        return null;
    };
    if (given != null) {
        if (stored.sec) |kept| {
            // A file remembers which clients may use ONE key. Pointing it at
            // another would hand that key to clients nobody authorized for it.
            const kept_sk = keyinput.secretKey(arena, kept) catch {
                p.failure = cli.exit_fail;
                try err.print("deed bunker: {s} holds something that is not a secret key\n", .{persist_path.?});
                return null;
            };
            if (!std.mem.eql(u8, &kept_sk, &sk)) {
                p.failure = cli.exit_fail;
                try err.print("deed bunker: {s} belongs to a different key; give it the same --sec, or use another file\n", .{persist_path.?});
                return null;
            }
        }
    }

    // Relays given on the command line replace the remembered ones.
    var relays: std.ArrayList([]const u8) = .empty;
    if (p.relays.items.len > 0) {
        for (p.relays.items) |r| try appendUnique([]const u8, arena, &relays, r);
    } else {
        for (stored.relays) |r| {
            _ = relay.parseUrl(r) catch continue;
            try appendUnique([]const u8, arena, &relays, r);
        }
    }
    if (p.invite) |inv| {
        for (inv.relays) |r| {
            _ = relay.parseUrl(r) catch continue;
            try appendUnique([]const u8, arena, &relays, r);
        }
    }
    if (relays.items.len == 0) {
        try err.writeAll("deed bunker: needs at least one relay to listen on\n");
        return null;
    }
    if (relays.items.len > max_relays) {
        try err.print("deed bunker: at most {d} relays\n", .{max_relays});
        return null;
    }

    var authorized: std.ArrayList([32]u8) = .empty;
    for (p.authorized_keys.items) |k| try appendUnique([32]u8, arena, &authorized, k);
    for (stored.authorized_keys) |h| {
        const k = hex.decodeFixed(32, h) catch continue;
        try appendUnique([32]u8, arena, &authorized, k);
    }
    // A client that invited this signer is the one being connected to.
    if (p.invite) |inv| try appendUnique([32]u8, arena, &authorized, inv.client_pubkey);

    var secrets: std.ArrayList([]const u8) = .empty;
    for (p.authorized_secrets.items) |s| try appendUnique([]const u8, arena, &secrets, s);
    for (p.authorized_secrets_files.items) |raw| {
        const full = expandHome(arena, raw, getEnv("HOME")) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => raw,
        };
        const n = secrets.items.len;
        loadSecrets(arena, io, Io.Dir.cwd(), full, &secrets) catch |e| {
            p.failure = cli.exit_fail;
            try err.print("deed bunker: cannot use {s}: {s}\n", .{ full, describeSecrets(e) });
            return null;
        };
        if (secrets.items.len == n) {
            p.failure = cli.exit_fail;
            try err.print("deed bunker: {s} holds no secret\n", .{full});
            return null;
        }
    }
    for (stored.authorized_secrets) |s| {
        if (s.len > 0) try appendUnique([]const u8, arena, &secrets, s);
    }

    // No URI secret when only named keys are to be served, or when this run is
    // answering one client's invitation.
    const keys_only = p.authorized_keys.items.len > 0 and secrets.items.len == 0;
    return .{
        .keypair = keypair,
        .sec_text = sec_text,
        .relays = relays.items,
        .authorized_keys = authorized.items,
        .authorized_secrets = secrets.items,
        .fresh_secret = !keys_only and p.invite == null,
        .qrcode = p.qrcode,
        .persist_path = persist_path,
        .invite = p.invite,
    };
}

const LoadError = error{ OutOfMemory, ReadableByOthers, NotAPersistFile, Unreadable };

fn describeLoad(e: LoadError) []const u8 {
    return switch (e) {
        error.OutOfMemory => "out of memory",
        error.ReadableByOthers => "other users can read it, and it holds a key; make it readable by its owner only (chmod 600)",
        error.NotAPersistFile => "it is not a bunker persist file",
        error.Unreadable => "it cannot be read",
    };
}

const SecretsError = error{ OutOfMemory, ReadableByOthers, NotFound, Unreadable };

fn describeSecrets(e: SecretsError) []const u8 {
    return switch (e) {
        error.OutOfMemory => "out of memory",
        error.ReadableByOthers => "other users can read it, and it holds secrets; make it readable by its owner only (chmod 600)",
        error.NotFound => "there is no such file",
        error.Unreadable => "it cannot be read",
    };
}

/// Adds the secrets in the file at `path`, one a line. Blank lines and the
/// spaces around a secret are left out.
fn loadSecrets(arena: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, into: *std.ArrayList([]const u8)) SecretsError!void {
    const text = dir.readFileAlloc(io, path, arena, .limited(max_persist_bytes)) catch |e| switch (e) {
        error.FileNotFound => return error.NotFound,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unreadable,
    };
    if (builtin.os.tag != .windows) {
        const st = dir.statFile(io, path, .{}) catch return error.Unreadable;
        if (st.permissions.toMode() & 0o077 != 0) return error.ReadableByOthers;
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const secret = std.mem.trim(u8, line, " \t\r");
        if (secret.len > 0) try appendUnique([]const u8, arena, into, secret);
    }
}

/// Reads the persist file, or an empty one if there is none yet.
fn loadStored(arena: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8) LoadError!Stored {
    const text = dir.readFileAlloc(io, path, arena, .limited(max_persist_bytes)) catch |e| switch (e) {
        error.FileNotFound => return .{},
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.NotAPersistFile,
        else => return error.Unreadable,
    };
    if (builtin.os.tag != .windows) {
        const st = dir.statFile(io, path, .{}) catch return error.Unreadable;
        if (st.permissions.toMode() & 0o077 != 0) return error.ReadableByOthers;
    }
    return std.json.parseFromSliceLeaky(Stored, arena, text, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.NotAPersistFile,
    };
}

/// Writes the persist file whole: to a fresh owner-only file beside it, then
/// renamed over it, so a crash mid-write leaves the old one rather than half
/// of the new one.
///
/// Windows has no mode bits: the file takes the access list of its directory,
/// which under the user's profile is already private to that user.
fn saveStored(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, stored: Stored) !void {
    const text = try std.json.Stringify.valueAlloc(gpa, stored, .{ .whitespace = .indent_2 });
    defer gpa.free(text);
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    const tmp = try std.mem.concat(gpa, u8, &.{ path, ".tmp" });
    defer gpa.free(tmp);
    dir.deleteFile(io, tmp) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
    try dir.writeFile(io, .{
        .sub_path = tmp,
        .data = text,
        .flags = .{
            .exclusive = true,
            .permissions = if (builtin.os.tag == .windows) .default_file else Io.File.Permissions.fromMode(0o600),
        },
    });
    try dir.rename(tmp, dir, path, io);
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

/// `~` and `~/rest` become the home directory and `home/rest`.
fn expandHome(gpa: std.mem.Allocator, path: []const u8, home: ?[]const u8) error{ OutOfMemory, NoHome, OtherUser }![]u8 {
    if (path.len == 0 or path[0] != '~') return gpa.dupe(u8, path);
    if (path.len > 1 and path[1] != '/') return error.OtherUser;
    const h = home orelse return error.NoHome;
    return std.mem.concat(gpa, u8, &.{ h, path[1..] });
}

// ---------------------------------------------------------------------------
// Stopping
// ---------------------------------------------------------------------------

/// Set by SIGINT or SIGTERM. A flag and nothing else, because a signal handler
/// may do almost nothing safely; the main loop looks at it.
var stop_signal = std.atomic.Value(bool).init(false);

fn onStopSignal(_: std.posix.SIG) callconv(.c) void {
    stop_signal.store(true, .release);
}

/// SIGINT and SIGTERM end the run cleanly. A second one ends it at once: the
/// handler resets itself, so somebody pressing Ctrl-C again is not kept
/// waiting on a stop that is stuck.
///
/// Windows: Ctrl-C ends the process the way it ends every other verb.
fn installStopSignals() void {
    if (builtin.os.tag != .windows) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = onStopSignal },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESETHAND,
        };
        std.posix.sigaction(.INT, &act, null);
        std.posix.sigaction(.TERM, &act, null);
    }
}

// ---------------------------------------------------------------------------
// Who is trusted
// ---------------------------------------------------------------------------

/// Equality that does not stop at the first differing byte, for secrets a
/// stranger may guess at as often as they like.
fn secretEql(want: []const u8, got: []const u8) bool {
    if (want.len != got.len) return false;
    var diff: u8 = 0;
    for (want, got) |a, b| diff |= a ^ b;
    return diff == 0;
}

/// What every relay's worker shares: who is trusted, the URI's secret, and
/// the library's records of who connected and which requests were answered.
///
/// Locked with a spin, as the library's own shared records are: decisions are
/// human-paced and the critical sections are short scans.
const Trust = struct {
    gpa: std.mem.Allocator,
    io: Io,
    lock: std.atomic.Value(bool) = .init(false),
    /// Pubkeys served without a secret: the flags, the persist file, and
    /// every client that has connected with a secret since.
    authorized: std.ArrayList([32]u8) = .empty,
    /// Secrets that authorize whoever presents them. Never changes.
    secrets: []const []const u8,
    /// The URI's secret, hex, good for one client. Null when the URI has none.
    fresh: ?[secret_bytes * 2]u8 = null,
    /// The URI changed and should be printed again.
    uri_due: bool = false,
    /// `authorized` changed and the persist file should be written.
    dirty: bool = false,
    clients: nip46.AuthorizedClients = .{},
    seen: nostr.signer.SeenRequests = .{},

    fn acquire(self: *Trust) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.Thread.yield() catch {};
    }

    fn release(self: *Trust) void {
        self.lock.store(false, .release);
    }

    fn isAuthorizedLocked(self: *const Trust, client: [32]u8) bool {
        for (self.authorized.items) |k| {
            if (std.mem.eql(u8, &k, &client)) return true;
        }
        return false;
    }

    fn forgetLocked(self: *Trust, client: [32]u8) void {
        var i: usize = 0;
        while (i < self.authorized.items.len) {
            if (std.mem.eql(u8, &self.authorized.items[i], &client)) {
                _ = self.authorized.orderedRemove(i);
                self.dirty = true;
            } else i += 1;
        }
    }

    fn policy(self: *Trust) nip46.Policy {
        return .{ .ctx = self, .decideFn = &decide };
    }

    /// The library asks this before every request it would answer. A client
    /// already trusted gets whatever it asks; anybody else may only `connect`,
    /// and only with a secret that is good.
    fn decide(ctx: ?*anyopaque, request: *const nip46.Request, client: [32]u8) nip46.Decision {
        const self: *Trust = @ptrCast(@alignCast(ctx.?));
        const method = nip46.Method.fromString(request.method) orelse return .reject;
        self.acquire();
        defer self.release();
        if (self.isAuthorizedLocked(client)) {
            // The library revokes the session; this forgets the client too,
            // so it cannot come back with a bare `connect`, and the persist
            // file stops naming it.
            if (method == .logout) self.forgetLocked(client);
            return .approve;
        }
        if (method != .connect) return .reject;

        const got = if (request.params.len >= 2) request.params[1] else "";
        if (got.len == 0) return .reject;
        var good = false;
        for (self.secrets) |s| good = secretEql(s, got) or good;
        var used_fresh = false;
        if (self.fresh) |*f| {
            if (secretEql(f, got)) {
                good = true;
                used_fresh = true;
            }
        }
        if (!good) return .reject;
        self.authorized.append(self.gpa, client) catch return .reject;
        self.dirty = true;
        if (used_fresh) {
            // Spent. A new one goes in the next printed URI.
            self.fresh = newSecret(self.io) catch null;
            self.uri_due = true;
        }
        return .approve;
    }
};

fn newSecret(io: Io) ![secret_bytes * 2]u8 {
    var raw: [secret_bytes]u8 = undefined;
    try io.randomSecure(&raw);
    return std.fmt.bytesToHex(raw, .lower);
}

// ---------------------------------------------------------------------------
// The daemon
// ---------------------------------------------------------------------------

/// One bunker: a worker per relay, and the main loop that watches them.
pub const Daemon = struct {
    gpa: std.mem.Allocator,
    io: Io,
    config: *const Config,
    out: *Io.Writer,
    err: *Io.Writer,
    /// Serializes everything written to `err`, which every worker logs to.
    log_lock: std.atomic.Value(bool) = .init(false),
    trust: Trust,
    /// Set once the run is ending. Workers stop starting anything new.
    stopping: std.atomic.Value(bool) = .init(false),
    /// Asks the main loop to stop, from a test or anything else in-process.
    stop_requested: std.atomic.Value(bool) = .init(false),
    /// The live connection of each relay, so a stop or the liveness watch
    /// can reach a reader blocked inside it. Under `slots_lock`.
    slots_lock: std.atomic.Value(bool) = .init(false),
    live: []?*relay.Relay,
    pinged_ms: []i64,
    /// The event that accepts a nostrconnect invitation, sent once per relay.
    accept: ?nip46.SealedEvent = null,
    accept_sent: []bool,
    workers: []?Io.Future(void),

    pub fn init(gpa: std.mem.Allocator, io: Io, config: *const Config, out: *Io.Writer, err: *Io.Writer) !Daemon {
        const n = config.relays.len;
        const live = try gpa.alloc(?*relay.Relay, n);
        errdefer gpa.free(live);
        @memset(live, null);
        const pinged = try gpa.alloc(i64, n);
        errdefer gpa.free(pinged);
        @memset(pinged, 0);
        const accept_sent = try gpa.alloc(bool, n);
        errdefer gpa.free(accept_sent);
        @memset(accept_sent, false);
        const workers = try gpa.alloc(?Io.Future(void), n);
        errdefer gpa.free(workers);
        @memset(workers, null);

        var trust = Trust{ .gpa = gpa, .io = io, .secrets = config.authorized_secrets };
        errdefer trust.authorized.deinit(gpa);
        try trust.authorized.appendSlice(gpa, config.authorized_keys);
        // Known before they ask, so a named key is served without `connect`.
        for (config.authorized_keys) |k| trust.clients.authorize(k);
        if (config.fresh_secret) trust.fresh = try newSecret(io);
        // Written at once, so the key and relays are there for the next run
        // even if no client ever connects.
        trust.dirty = config.persist_path != null;

        var accept: ?nip46.SealedEvent = null;
        if (config.invite) |inv| {
            var signer = try keys.Signer.initRandomized(io);
            defer signer.deinit();
            const id = try newSecret(io);
            const now = Io.Timestamp.now(io, .real).toSeconds();
            accept = try nip46.acceptNostrConnect(gpa, io, signer, config.keypair, inv, &id, now);
        }

        return .{
            .gpa = gpa,
            .io = io,
            .config = config,
            .out = out,
            .err = err,
            .trust = trust,
            .live = live,
            .pinged_ms = pinged,
            .accept = accept,
            .accept_sent = accept_sent,
            .workers = workers,
        };
    }

    pub fn deinit(self: *Daemon) void {
        if (self.accept) |*a| a.deinit();
        self.trust.authorized.deinit(self.gpa);
        self.gpa.free(self.workers);
        self.gpa.free(self.accept_sent);
        self.gpa.free(self.pinged_ms);
        self.gpa.free(self.live);
    }

    /// Asks a running `run` to return.
    pub fn requestStop(self: *Daemon) void {
        self.stop_requested.store(true, .release);
    }

    fn stopAsked(self: *Daemon) bool {
        return self.stop_requested.load(.acquire) or stop_signal.load(.acquire);
    }

    fn isStopping(self: *Daemon) bool {
        return self.stopping.load(.acquire);
    }

    fn lockLog(self: *Daemon) void {
        while (self.log_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.Thread.yield() catch {};
    }

    fn unlockLog(self: *Daemon) void {
        self.log_lock.store(false, .release);
    }

    fn log(self: *Daemon, comptime fmt: []const u8, args: anytype) void {
        self.lockLog();
        defer self.unlockLog();
        self.err.print("deed bunker: " ++ fmt ++ "\n", args) catch {};
        self.err.flush() catch {};
    }

    /// Prints the URI on stdout, and as a QR code on stderr when asked.
    fn printUri(self: *Daemon) void {
        self.trust.acquire();
        const fresh = self.trust.fresh;
        self.trust.release();
        const secret: ?[]const u8 = if (fresh) |*f| f else null;
        const uri = nip46.buildBunkerUri(self.gpa, self.config.keypair.public_key, self.config.relays, secret) catch {
            self.log("out of memory building the URI", .{});
            return;
        };
        defer self.gpa.free(uri);
        self.out.print("{s}\n", .{uri}) catch {};
        self.out.flush() catch {};
        if (!self.config.qrcode) return;
        var code = qr.encode(self.gpa, uri, .medium, null) catch |e| {
            self.log("no QR code: {s}", .{@errorName(e)});
            return;
        };
        defer code.deinit(self.gpa);
        self.lockLog();
        defer self.unlockLog();
        qr.render(&code, self.err) catch {};
        self.err.flush() catch {};
    }

    /// Writes the persist file, if there is one and something changed.
    fn saveIfDirty(self: *Daemon) void {
        const path = self.config.persist_path orelse return;
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();

        self.trust.acquire();
        const due = self.trust.dirty;
        self.trust.dirty = false;
        const authorized = a.dupe([32]u8, self.trust.authorized.items) catch null;
        self.trust.release();
        if (!due) return;
        const list = authorized orelse return self.saveFailed(error.OutOfMemory);

        const hexes = a.alloc([]const u8, list.len) catch return self.saveFailed(error.OutOfMemory);
        for (list, hexes) |k, *h| h.* = hex.encode(a, &k) catch return self.saveFailed(error.OutOfMemory);
        const stored = Stored{
            .sec = self.config.sec_text,
            .relays = self.config.relays,
            .authorized_keys = hexes,
            .authorized_secrets = self.config.authorized_secrets,
        };
        saveStored(a, self.io, self.config.persist_dir orelse Io.Dir.cwd(), path, stored) catch |e| self.saveFailed(e);
    }

    fn saveFailed(self: *Daemon, e: anyerror) void {
        // Tried again on the next change rather than in a loop: a disk that
        // is full now would only fill the log.
        self.log("could not write {s}: {s}", .{ self.config.persist_path.?, @errorName(e) });
    }

    /// Runs until `requestStop`, SIGINT or SIGTERM, then stops every worker
    /// and returns.
    pub fn run(self: *Daemon) void {
        const me = std.fmt.bytesToHex(self.config.keypair.public_key, .lower);
        self.log("signing as {s}", .{&me});
        if (self.config.invite) |inv| {
            const them = std.fmt.bytesToHex(inv.client_pubkey, .lower);
            self.log("answering the invitation from {s}", .{&them});
        }
        self.printUri();
        self.saveIfDirty();

        for (self.config.relays, 0..) |url, i| {
            // `concurrent`, not `async`: past its limit `async` runs the task
            // inline, and a worker never returns on its own.
            self.workers[i] = self.io.concurrent(worker, .{ self, i }) catch |e| blk: {
                self.log("{s}: could not start: {s}", .{ url, @errorName(e) });
                break :blk null;
            };
        }

        var last_watch = Io.Timestamp.now(self.io, .awake).toMilliseconds();
        while (!self.stopAsked()) {
            self.io.sleep(.fromMilliseconds(poll_ms), .awake) catch break;
            self.housekeeping();
            const now = Io.Timestamp.now(self.io, .awake).toMilliseconds();
            if (now - last_watch >= nostr.liveness.tick_ms) {
                last_watch = now;
                self.watch(now);
            }
        }
        self.stop();
    }

    fn housekeeping(self: *Daemon) void {
        self.trust.acquire();
        const due = self.trust.uri_due;
        self.trust.uri_due = false;
        self.trust.release();
        if (due) self.printUri();
        self.saveIfDirty();
    }

    /// Stops every worker. Each is woken two ways, because either alone can
    /// miss: the socket under it is shut down, which ends a read that is
    /// waiting on a relay, and its task is cancelled, which ends a dial or a
    /// wait between dials. The shutdown is what makes this safe even where a
    /// cancel gets swallowed on its way through a request, since every read
    /// after it returns at once.
    fn stop(self: *Daemon) void {
        self.stopping.store(true, .release);
        self.acquireSlots();
        for (self.live) |maybe| {
            if (maybe) |r| r.shutdown(self.io);
        }
        self.releaseSlots();
        for (self.workers) |*w| {
            if (w.*) |*f| f.cancel(self.io);
            w.* = null;
        }
        self.housekeeping();
        self.log("stopped", .{});
    }

    fn acquireSlots(self: *Daemon) void {
        while (self.slots_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.Thread.yield() catch {};
    }

    fn releaseSlots(self: *Daemon) void {
        self.slots_lock.store(false, .release);
    }

    /// Pings a connection that has gone quiet, and cuts one that stayed quiet,
    /// so its worker's blocked read returns and it dials again. A worker
    /// cannot notice this itself: it is the thread waiting on the dead peer.
    fn watch(self: *Daemon, now_ms: i64) void {
        self.acquireSlots();
        defer self.releaseSlots();
        for (self.live, 0..) |maybe, i| {
            const r = maybe orelse continue;
            const since: ?i64 = if (self.pinged_ms[i] == 0) null else now_ms - self.pinged_ms[i];
            switch (nostr.liveness.action(r.idleMs(self.io), since)) {
                .leave_it => {},
                .ping => {
                    r.ping(self.io) catch {};
                    self.pinged_ms[i] = now_ms;
                },
                .give_up => {
                    self.log("{s}: silent for too long, reconnecting", .{self.config.relays[i]});
                    r.shutdown(self.io);
                    self.pinged_ms[i] = 0;
                },
            }
        }
    }

    /// Makes `r` reachable by `stop` and `watch`. False when the run is
    /// already stopping, in which case the caller must not serve on it.
    ///
    /// The check and the publish are one critical section, and `stop` raises
    /// its flag before it takes the lock: so either `stop` finds this
    /// connection and shuts it down, or this finds the flag. Never neither.
    fn register(self: *Daemon, index: usize, r: *relay.Relay) bool {
        self.acquireSlots();
        defer self.releaseSlots();
        if (self.isStopping()) return false;
        self.live[index] = r;
        self.pinged_ms[index] = 0;
        return true;
    }

    fn unregister(self: *Daemon, index: usize) void {
        self.acquireSlots();
        defer self.releaseSlots();
        self.live[index] = null;
        self.pinged_ms[index] = 0;
    }

    /// Waits `ms`, in short steps so a stop is noticed without a cancel.
    /// False when the run is stopping or the wait was cancelled.
    fn pause(self: *Daemon, ms: i64) bool {
        var left = ms;
        while (left > 0) {
            if (self.isStopping()) return false;
            const step = @min(left, poll_ms);
            self.io.sleep(.fromMilliseconds(step), .awake) catch return false;
            left -= step;
        }
        return !self.isStopping();
    }
};

const Ended = enum { dropped, stopped };

/// One relay, for the whole run: connect, serve until the connection ends,
/// wait, and connect again.
fn worker(d: *Daemon, index: usize) void {
    const url = d.config.relays[index];
    // Its own context: the library keeps one per thread that signs.
    var signer = keys.Signer.initRandomized(d.io) catch keys.Signer.init();
    defer signer.deinit();
    var bunker = nip46.Bunker.initSingleKey(signer, d.config.keypair, d.trust.policy(), &d.trust.clients);

    var backoff = min_backoff_ms;
    while (!d.isStopping()) {
        const started = Io.Timestamp.now(d.io, .awake).toMilliseconds();
        if (serveOnce(d, index, &bunker) == .stopped) return;
        if (d.isStopping()) return;
        if (Io.Timestamp.now(d.io, .awake).toMilliseconds() - started >= stable_ms) backoff = min_backoff_ms;
        d.log("{s}: trying again in {d}s", .{ url, @divTrunc(backoff, 1000) });
        if (!d.pause(backoff)) return;
        backoff = @min(backoff * 2, max_backoff_ms);
    }
}

/// One connection's life. A cancel is never swallowed: it ends the worker
/// rather than letting it go on to another blocking call it could not be
/// woken from.
fn serveOnce(d: *Daemon, index: usize, bunker: *nip46.Bunker) Ended {
    const url = d.config.relays[index];
    var outcome: [1]dial.Outcome = undefined;
    dial.all(d.gpa, d.io, &.{url}, dial.default_timeout_ms, &outcome);
    const conn = switch (outcome[0]) {
        .connected => |r| r,
        .failed => |e| {
            if (isCancel(e)) return .stopped;
            d.log("{s}: could not connect: {s}", .{ url, @errorName(e) });
            return .dropped;
        },
        .timed_out => {
            d.log("{s}: no answer within {d}s", .{ url, @divTrunc(dial.default_timeout_ms, 1000) });
            return .dropped;
        },
    };
    defer conn.deinit();
    if (!d.register(index, conn)) return .stopped;
    defer d.unregister(index);
    d.log("{s}: connected, listening for requests", .{url});

    if (d.accept) |*a| {
        if (!d.accept_sent[index]) {
            conn.publish(a.event) catch |e| {
                if (isCancel(e)) return .stopped;
                d.log("{s}: could not answer the invitation: {s}", .{ url, @errorName(e) });
                return .dropped;
            };
            d.accept_sent[index] = true;
        }
    }

    nostr.signer.serve(d.gpa, d.io, conn, bunker, d.config.keypair, url, &d.trust.seen) catch |e| {
        if (isCancel(e)) return .stopped;
        if (!d.isStopping()) d.log("{s}: {s}", .{ url, @errorName(e) });
        return .dropped;
    };
    if (!d.isStopping()) d.log("{s}: the relay closed the connection", .{url});
    return .dropped;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");
const event = nostr.event;

/// A client of the bunker, scripted into a test relay: when the bunker
/// subscribes, the relay delivers the planned requests to it, and every event
/// the bunker publishes is decrypted with whichever client it is addressed to.
const Script = struct {
    io: Io,
    signer: keys.Signer,
    bunker_pubkey: [32]u8 = undefined,
    clients: []const keys.KeyPair,
    /// Sent in order when the bunker subscribes: which client, and what.
    plan: []const Planned = &.{},
    lock: std.atomic.Value(bool) = .init(false),
    replies: [16]Reply = undefined,
    count: std.atomic.Value(usize) = .init(0),

    const Planned = struct { client: usize, request: nip46.Request };
    const Reply = struct { client: usize, json: []u8 };

    /// The relay's allocator, for the reason `testrelay.Relay.handle` gives.
    const gpa = std.heap.page_allocator;

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        const self: *Script = @ptrCast(@alignCast(ctx.?));
        if (std.mem.startsWith(u8, frame, "[\"REQ\"")) {
            const now = Io.Timestamp.now(self.io, .real).toSeconds();
            for (self.plan) |p| {
                const body = try p.request.toJson(gpa);
                defer gpa.free(body);
                var sealed = try nip46.seal(gpa, self.io, self.signer, self.clients[p.client], self.bunker_pubkey, body, now);
                defer sealed.deinit();
                const ev = try event.toJson(gpa, sealed.event);
                defer gpa.free(ev);
                const msg = try std.fmt.allocPrint(gpa, "[\"EVENT\",\"{s}\",{s}]", .{ nostr.signer.subscription_id, ev });
                defer gpa.free(msg);
                try testrelay.sendText(w, msg);
            }
            return;
        }
        const prefix = "[\"EVENT\",";
        if (!std.mem.startsWith(u8, frame, prefix)) return;
        var parsed = try event.fromJson(gpa, frame[prefix.len .. frame.len - 1]);
        defer parsed.deinit();
        const ev = parsed.value;
        // Whoever the reply is p-tagged to.
        for (self.clients, 0..) |c, i| {
            const want = std.fmt.bytesToHex(c.public_key, .lower);
            var addressed = false;
            for (ev.tags) |t| {
                if (t.len >= 2 and std.mem.eql(u8, t[0], "p") and std.mem.eql(u8, t[1], &want)) addressed = true;
            }
            if (!addressed) continue;
            const plain = try nip46.open(gpa, self.signer, c.secret_key, ev);
            while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
            defer self.lock.store(false, .release);
            const n = self.count.load(.monotonic);
            if (n >= self.replies.len) {
                gpa.free(plain);
                return;
            }
            self.replies[n] = .{ .client = i, .json = plain };
            self.count.store(n + 1, .release);
            return;
        }
    }

    fn deinit(self: *Script) void {
        for (self.replies[0..self.count.load(.acquire)]) |r| gpa.free(r.json);
    }

    /// The reply to request `id`, parsed. The caller deinits it.
    fn reply(self: *Script, test_gpa: std.mem.Allocator, id: []const u8) !nip46.ParsedResponse {
        for (self.replies[0..self.count.load(.acquire)]) |r| {
            var parsed = try nip46.parseResponse(test_gpa, r.json);
            if (std.mem.eql(u8, parsed.value.id, id)) return parsed;
            parsed.deinit();
        }
        return error.NoReply;
    }
};

const Harness = struct {
    da: testrelay.DialAllocator = .init,
    signer: keys.Signer,
    user: keys.KeyPair,
    clients: [3]keys.KeyPair,
    relay: testrelay.Relay = undefined,
    url_buf: [40]u8 = undefined,
    relays: [1][]const u8 = undefined,
    out: Io.Writer.Allocating = undefined,
    err: Io.Writer.Allocating = undefined,
    script: Script = undefined,

    fn init(self: *Harness) !void {
        self.* = .{ .signer = keys.Signer.init(), .user = undefined, .clients = undefined };
        var sk = [_]u8{0} ** 32;
        sk[31] = 7;
        self.user = try self.signer.keyPairFromSecretKey(sk);
        for (&self.clients, 0..) |*c, i| {
            sk[31] = @intCast(20 + i);
            c.* = try self.signer.keyPairFromSecretKey(sk);
        }
        self.script = .{ .io = testing.io, .signer = self.signer, .clients = &self.clients };
        self.script.bunker_pubkey = self.user.public_key;
        try self.relay.startCustom(testing.io, Script.handle, &self.script);
        self.relays[0] = try testrelay.url(&self.url_buf, self.relay.port());
        self.out = .init(self.da.allocator());
        self.err = .init(self.da.allocator());
    }

    fn deinit(self: *Harness) void {
        self.relay.stop(testing.io);
        self.script.deinit();
        self.out.deinit();
        self.err.deinit();
        self.signer.deinit();
        if (self.da.deinit() == .leak) @panic("the bunker leaked");
    }

    fn config(self: *Harness) Config {
        return .{
            .keypair = self.user,
            .sec_text = "unused",
            .relays = &self.relays,
            .authorized_keys = &.{},
            .authorized_secrets = &.{},
            .fresh_secret = true,
        };
    }

    /// The secret in the first URI the daemon printed.
    fn uriSecret(self: *Harness, buf: []u8) ![]const u8 {
        const text = self.out.written();
        const line = text[0 .. std.mem.indexOfScalar(u8, text, '\n') orelse return error.NoUri];
        var parsed = try nip46.parseBunkerUri(testing.allocator, line);
        defer parsed.deinit();
        const s = parsed.value.secret orelse return error.NoSecret;
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }

    /// Runs the daemon until the script has `want` replies or ten seconds
    /// pass, then stops it.
    fn runUntil(self: *Harness, d: *Daemon, want: usize) !void {
        var fut = try testing.io.concurrent(Daemon.run, .{d});
        const started = Io.Timestamp.now(testing.io, .awake).toMilliseconds();
        while (self.script.count.load(.acquire) < want) {
            if (Io.Timestamp.now(testing.io, .awake).toMilliseconds() - started > 10_000) break;
            try testing.io.sleep(.fromMilliseconds(20), .awake);
        }
        d.requestStop();
        fut.await(testing.io);
        try testing.expectEqual(want, self.script.count.load(.acquire));
    }
};

fn template(comptime content: []const u8) []const u8 {
    return "{\"kind\":1,\"content\":\"" ++ content ++ "\",\"tags\":[],\"created_at\":1700000000}";
}

test "a client that connects with the URI's secret gets an event signed by the user key" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();

    const config = h.config();
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();
    // The URI is printed again once `run` starts; printing it here first is
    // how the test learns the secret before the relay hands the bunker anything.
    d.printUri();
    var sbuf: [64]u8 = undefined;
    const secret = try h.uriSecret(&sbuf);

    const pk_hex = std.fmt.bytesToHex(h.user.public_key, .lower);
    const plan = [_]Script.Planned{
        .{ .client = 0, .request = .{ .id = "c1", .method = "connect", .params = &.{ &pk_hex, secret } } },
        .{ .client = 0, .request = .{ .id = "s1", .method = "sign_event", .params = &.{template("signed remotely")} } },
        // The secret was spent on the first client, so a second one cannot
        // use it.
        .{ .client = 1, .request = .{ .id = "c2", .method = "connect", .params = &.{ &pk_hex, secret } } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 3);

    var connected = try h.script.reply(testing.allocator, "c1");
    defer connected.deinit();
    try testing.expectEqualStrings("", connected.value.err);
    try testing.expectEqualStrings("ack", connected.value.result);

    var signed = try h.script.reply(testing.allocator, "s1");
    defer signed.deinit();
    try testing.expectEqualStrings("", signed.value.err);
    var ev = try event.fromJson(testing.allocator, signed.value.result);
    defer ev.deinit();
    try testing.expectEqualSlices(u8, &h.user.public_key, &ev.value.pubkey);
    try testing.expectEqualStrings("signed remotely", ev.value.content);
    try testing.expect(try event.verify(testing.allocator, h.signer, ev.value));

    var second = try h.script.reply(testing.allocator, "c2");
    defer second.deinit();
    try testing.expect(second.value.err.len > 0);

    // And a fresh URI was printed in place of the spent one.
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, h.out.written(), "bunker://"));
}

test "a client nobody authorized is refused, whatever it asks" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();

    const config = h.config();
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();

    const pk_hex = std.fmt.bytesToHex(h.user.public_key, .lower);
    const plan = [_]Script.Planned{
        .{ .client = 0, .request = .{ .id = "s1", .method = "sign_event", .params = &.{template("not yours")} } },
        .{ .client = 0, .request = .{ .id = "p1", .method = "ping", .params = &.{} } },
        .{ .client = 0, .request = .{ .id = "g1", .method = "get_public_key", .params = &.{} } },
        .{ .client = 0, .request = .{ .id = "c1", .method = "connect", .params = &.{&pk_hex} } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 4);

    for ([_][]const u8{ "s1", "p1", "g1", "c1" }) |id| {
        var r = try h.script.reply(testing.allocator, id);
        defer r.deinit();
        try testing.expect(r.value.err.len > 0);
        try testing.expectEqualStrings("", r.value.result);
    }
    // Nothing of a request's content reaches the log.
    try testing.expect(std.mem.indexOf(u8, h.err.written(), "not yours") == null);
}

test "a wrong secret is refused and does not connect the client" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();

    const secrets = [_][]const u8{"the-right-one"};
    var config = h.config();
    config.authorized_secrets = &secrets;
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();

    const pk_hex = std.fmt.bytesToHex(h.user.public_key, .lower);
    const plan = [_]Script.Planned{
        .{ .client = 0, .request = .{ .id = "c1", .method = "connect", .params = &.{ &pk_hex, "the-wrong-one" } } },
        .{ .client = 0, .request = .{ .id = "s1", .method = "sign_event", .params = &.{template("no")} } },
        // A secret given with --authorized-secrets is good for more than one
        // client.
        .{ .client = 1, .request = .{ .id = "c2", .method = "connect", .params = &.{ &pk_hex, "the-right-one" } } },
        .{ .client = 2, .request = .{ .id = "c3", .method = "connect", .params = &.{ &pk_hex, "the-right-one" } } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 4);

    var wrong = try h.script.reply(testing.allocator, "c1");
    defer wrong.deinit();
    try testing.expect(wrong.value.err.len > 0);
    var after = try h.script.reply(testing.allocator, "s1");
    defer after.deinit();
    try testing.expect(after.value.err.len > 0);
    for ([_][]const u8{ "c2", "c3" }) |id| {
        var right = try h.script.reply(testing.allocator, id);
        defer right.deinit();
        try testing.expectEqualStrings("ack", right.value.result);
    }
}

test "an authorized key is served without connecting, and others still are not" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();

    const authorized = [_][32]u8{h.clients[0].public_key};
    var config = h.config();
    config.authorized_keys = &authorized;
    config.fresh_secret = false;
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();

    const plan = [_]Script.Planned{
        .{ .client = 0, .request = .{ .id = "s1", .method = "sign_event", .params = &.{template("named")} } },
        .{ .client = 1, .request = .{ .id = "s2", .method = "sign_event", .params = &.{template("stranger")} } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 2);

    var named = try h.script.reply(testing.allocator, "s1");
    defer named.deinit();
    try testing.expectEqualStrings("", named.value.err);
    var stranger = try h.script.reply(testing.allocator, "s2");
    defer stranger.deinit();
    try testing.expect(stranger.value.err.len > 0);
    // Keys only: the URI carries no secret.
    try testing.expect(std.mem.indexOf(u8, h.out.written(), "secret=") == null);
}

test "connect answers a nostrconnect invitation with its secret, then serves that client" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();

    const invite = nip46.NostrConnectUri{
        .client_pubkey = h.clients[0].public_key,
        .relays = &h.relays,
        .secret = "invitation-secret",
    };
    const authorized = [_][32]u8{h.clients[0].public_key};
    var config = h.config();
    config.invite = invite;
    config.authorized_keys = &authorized;
    config.fresh_secret = false;
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();

    const plan = [_]Script.Planned{
        .{ .client = 0, .request = .{ .id = "s1", .method = "sign_event", .params = &.{template("invited")} } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 2);

    // The acceptance carries the invitation's secret as its result.
    var accepted = false;
    for (h.script.replies[0..h.script.count.load(.acquire)]) |r| {
        var parsed = try nip46.parseResponse(testing.allocator, r.json);
        defer parsed.deinit();
        if (std.mem.eql(u8, parsed.value.result, "invitation-secret")) accepted = true;
    }
    try testing.expect(accepted);
    var signed = try h.script.reply(testing.allocator, "s1");
    defer signed.deinit();
    try testing.expectEqualStrings("", signed.value.err);
}

test "a stop ends a worker that is waiting to dial again" {
    // Nothing listens at this port, so the worker fails, logs and waits out
    // its backoff. The stop has to end that wait, not sit through it.
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the bunker leaked");
    const gpa = da.allocator();

    var closed = try testrelay.listen(testing.io);
    const port = closed.socket.address.ip4.port;
    closed.deinit(testing.io);
    var url_buf: [40]u8 = undefined;
    const relays = [_][]const u8{try testrelay.url(&url_buf, port)};

    var signer = keys.Signer.init();
    defer signer.deinit();
    var sk = [_]u8{0} ** 32;
    sk[31] = 9;
    const config = Config{
        .keypair = try signer.keyPairFromSecretKey(sk),
        .sec_text = "unused",
        .relays = &relays,
        .authorized_keys = &.{},
        .authorized_secrets = &.{},
        .fresh_secret = false,
    };
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    var d = try Daemon.init(gpa, testing.io, &config, &out.writer, &err.writer);
    defer d.deinit();

    var fut = try testing.io.concurrent(Daemon.run, .{&d});
    try testing.io.sleep(.fromMilliseconds(300), .awake);
    const started = Io.Timestamp.now(testing.io, .awake).toMilliseconds();
    d.requestStop();
    fut.await(testing.io);
    try testing.expect(Io.Timestamp.now(testing.io, .awake).toMilliseconds() - started < 2_000);
    try testing.expect(std.mem.indexOf(u8, err.written(), "stopped") != null);
}

test "the persist file round-trips, is owner-only, and is refused when others can read it" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const stored = Stored{
        .sec = "nsec1example",
        .relays = &.{"wss://relay.example"},
        .authorized_keys = &.{"ab" ** 32},
        .authorized_secrets = &.{"s3cret"},
    };
    try saveStored(gpa, io, tmp.dir, "dir/bunker.json", stored);
    // Written again over itself, the way every change is saved.
    try saveStored(gpa, io, tmp.dir, "dir/bunker.json", stored);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const back = try loadStored(arena_state.allocator(), io, tmp.dir, "dir/bunker.json");
    try testing.expectEqualStrings("nsec1example", back.sec.?);
    try testing.expectEqualStrings("wss://relay.example", back.relays[0]);
    try testing.expectEqualStrings("ab" ** 32, back.authorized_keys[0]);
    try testing.expectEqualStrings("s3cret", back.authorized_secrets[0]);

    // No file yet is an empty one, not an error.
    const none = try loadStored(arena_state.allocator(), io, tmp.dir, "missing.json");
    try testing.expect(none.sec == null);

    if (builtin.os.tag == .windows) return;
    const st = try tmp.dir.statFile(io, "dir/bunker.json", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
    try tmp.dir.setFilePermissions(io, "dir/bunker.json", .fromMode(0o644), .{});
    try testing.expectError(error.ReadableByOthers, loadStored(arena_state.allocator(), io, tmp.dir, "dir/bunker.json"));
}

test "a client that connected with a secret is remembered in the persist file" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const secrets = [_][]const u8{"remember-me"};
    var config = h.config();
    config.authorized_secrets = &secrets;
    config.persist_dir = tmp.dir;
    config.persist_path = "bunker.json";
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();

    const pk_hex = std.fmt.bytesToHex(h.user.public_key, .lower);
    const plan = [_]Script.Planned{
        .{ .client = 1, .request = .{ .id = "c1", .method = "connect", .params = &.{ &pk_hex, "remember-me" } } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 1);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const back = try loadStored(arena_state.allocator(), testing.io, tmp.dir, "bunker.json");
    const want = std.fmt.bytesToHex(h.clients[1].public_key, .lower);
    try testing.expectEqual(@as(usize, 1), back.authorized_keys.len);
    try testing.expectEqualStrings(&want, back.authorized_keys[0]);
    try testing.expectEqualStrings(h.relays[0], back.relays[0]);
}

test "a client that logs out needs a secret again, and is forgotten by the persist file" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const gpa = h.da.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const secrets = [_][]const u8{"come-in"};
    var config = h.config();
    config.authorized_secrets = &secrets;
    config.persist_dir = tmp.dir;
    config.persist_path = "bunker.json";
    var d = try Daemon.init(gpa, testing.io, &config, &h.out.writer, &h.err.writer);
    defer d.deinit();

    const pk_hex = std.fmt.bytesToHex(h.user.public_key, .lower);
    const plan = [_]Script.Planned{
        .{ .client = 0, .request = .{ .id = "c1", .method = "connect", .params = &.{ &pk_hex, "come-in" } } },
        .{ .client = 0, .request = .{ .id = "o1", .method = "logout", .params = &.{} } },
        .{ .client = 0, .request = .{ .id = "c2", .method = "connect", .params = &.{&pk_hex} } },
        .{ .client = 0, .request = .{ .id = "s1", .method = "sign_event", .params = &.{template("after logout")} } },
    };
    h.script.plan = &plan;
    try h.runUntil(&d, 4);

    var out = try h.script.reply(testing.allocator, "o1");
    defer out.deinit();
    try testing.expectEqualStrings("ack", out.value.result);
    for ([_][]const u8{ "c2", "s1" }) |id| {
        var r = try h.script.reply(testing.allocator, id);
        defer r.deinit();
        try testing.expect(r.value.err.len > 0);
    }

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const back = try loadStored(arena_state.allocator(), testing.io, tmp.dir, "bunker.json");
    try testing.expectEqual(@as(usize, 0), back.authorized_keys.len);
}

test "the command line is checked before anything starts" {
    const gpa = testing.allocator;
    const Case = struct { args: []const []const u8, code: u8, says: []const u8 };
    const sec = "0000000000000000000000000000000000000000000000000000000000000001";
    const cases = [_]Case{
        .{ .args = &.{ "--sec", sec }, .code = cli.exit_usage, .says = "at least one relay" },
        .{ .args = &.{"wss://relay.example"}, .code = cli.exit_usage, .says = "needs a secret key" },
        .{ .args = &.{ "--sec", sec, "https://relay.example" }, .code = cli.exit_usage, .says = "not a relay URL" },
        .{ .args = &.{ "--sec", sec, "-k", "nope", "wss://relay.example" }, .code = cli.exit_usage, .says = "not a public key" },
        .{ .args = &.{ "--sec", sec, "--bogus", "wss://relay.example" }, .code = cli.exit_usage, .says = "unknown option" },
        .{ .args = &.{ "--sec", "nope", "wss://relay.example" }, .code = cli.exit_fail, .says = "not a secret key" },
        .{ .args = &.{"connect"}, .code = cli.exit_usage, .says = "nostrconnect" },
        .{ .args = &.{ "connect", "bunker://x" }, .code = cli.exit_usage, .says = "not a nostrconnect" },
    };
    for (cases) |c| {
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err: Io.Writer.Allocating = .init(gpa);
        defer err.deinit();
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var code: u8 = cli.exit_usage;
        if (try parseArgs(arena, c.args, &out.writer, &err.writer)) |parsed| {
            var p = parsed;
            if (try resolve(arena, testing.io, &p, null, &err.writer)) |_| {
                code = cli.exit_ok;
            } else code = p.failure;
        }
        try testing.expectEqual(c.code, code);
        try testing.expect(std.mem.indexOf(u8, err.written(), c.says) != null);
    }
}

test "secrets can come from an owner-only file, and the usage does not put the key on the command line" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "secrets",
        .data = "first\n\n  second \r\nfirst\n",
        .flags = .{ .permissions = if (builtin.os.tag == .windows) .default_file else Io.File.Permissions.fromMode(0o600) },
    });
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root);
    const path = try std.fmt.allocPrint(gpa, "{s}/secrets", .{root[0..root_len]});
    defer gpa.free(path);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const sec = "0000000000000000000000000000000000000000000000000000000000000001";
    var p = (try parseArgs(arena, &.{ "--authorized-secrets-file", path, "wss://relay.example" }, &out.writer, &err.writer)) orelse return error.TestUnexpectedResult;
    const config = (try resolve(arena, io, &p, sec, &err.writer)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), config.authorized_secrets.len);
    try testing.expectEqualStrings("first", config.authorized_secrets[0]);
    try testing.expectEqualStrings("second", config.authorized_secrets[1]);

    if (builtin.os.tag != .windows) {
        try tmp.dir.setFilePermissions(io, "secrets", .fromMode(0o644), .{});
        var q = (try parseArgs(arena, &.{ "--authorized-secrets-file", path, "wss://relay.example" }, &out.writer, &err.writer)) orelse return error.TestUnexpectedResult;
        try testing.expect((try resolve(arena, io, &q, sec, &err.writer)) == null);
        try testing.expectEqual(cli.exit_fail, q.failure);
        try testing.expect(std.mem.indexOf(u8, err.written(), "other users can read it") != null);
    }

    // The examples take the key from the environment, never from --sec.
    var ex = std.mem.splitSequence(u8, usage, "\n");
    while (ex.next()) |line| {
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "deed bunker ")) {
            try testing.expect(std.mem.indexOf(u8, line, "--sec") == null);
        }
    }
}

test "help is printed and nothing starts" {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(cli.exit_ok, try run(testing.allocator, testing.io, &.{"--help"}, &out.writer, &err.writer));
    try testing.expect(std.mem.indexOf(u8, out.written(), "deed bunker") != null);
}
