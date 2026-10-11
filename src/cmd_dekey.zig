//! `deed dekey`: NIP-4E decoupled encryption keys.
//!
//! A person's messages can be encrypted to a key that is not their identity
//! key, so a leaked or delegated identity key does not open their history. The
//! key is announced in a kind 10044 event (`n` tag: its public half). Every
//! device that wants it announces itself with a kind 4454 event (`client`: its
//! name, `P`: a device key of its own), and a device that already has the key
//! answers with a kind 4455 event (`p`: the new device, `P`: itself) holding
//! the key encrypted with NIP-44 between the two device keys.
//!
//! It prints the public half of the key on stdout. It does not encrypt or
//! decrypt messages.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const relayset = @import("relayset.zig");
const cmd_publish = @import("cmd_publish.zig");

const hex = nostr.hex;
const keys = nostr.keys;
const nip44 = nostr.nip44;
const filter = nostr.filter;
const Event = nostr.event.Event;
const Io = std.Io;

pub const summary = "set up and share a NIP-4E decoupled encryption key";

pub const ready = true;

pub const usage =
    \\deed dekey: set up and share a NIP-4E decoupled encryption key
    \\
    \\Usage:
    \\  deed dekey [options]
    \\
    \\Checks whether you have announced a decoupled encryption key (kind 10044).
    \\
    \\  - None yet: makes one, keeps it in --dir, and announces its public key.
    \\  - Announced, and this machine has it: nothing to do but share it.
    \\  - Announced, and this machine does not: announces this machine as a
    \\    device (kind 4454) and looks for a key message (kind 4455) another
    \\    device has sent it. A key that arrives is checked against the
    \\    announced public key, kept, and the announcement and the message are
    \\    deleted (kind 5).
    \\  - With the key in hand: lists devices that announced themselves and were
    \\    sent no key. --authorize-all sends it to each, encrypted to that
    \\    device (NIP-44). --reject-all, or neither flag, sends it to none; this
    \\    verb never asks a question, so without --authorize-all nothing is
    \\    sent, and the devices waiting are named on stderr.
    \\
    \\Prints the public key of the decoupled encryption key, as 64 hex
    \\characters, once this machine holds the secret half. When it does not,
    \\prints nothing, says so on stderr, and exits 0.
    \\
    \\Options:
    \\      --sec <key>        your identity key, as nsec1..., ncryptsec1... or 64
    \\                         hex characters. Falls back to $NOSTR_SECRET_KEY
    \\      --device <name>    the name other devices show for this one
    \\                         (default: deed@<this machine's name>)
    \\      --rotate           make a new key even though one is announced. Devices
    \\                         then have to be sent the new one
    \\      --authorize-all    send the key to every device waiting for it
    \\                         (also --yolo)
    \\      --reject-all       send it to none (the default)
    \\  -r, --relay <url>      where to look and publish (repeatable; a bare ws://
    \\                         or wss:// argument works too). With none, your
    \\                         own write relays are looked up through DEED_RELAYS
    \\      --dir <path>       where the device key and the decoupled keys are
    \\                         kept (default: ~/.config/deed/dekey)
    \\      --timeout <ms>     give up on relays still answering (default 30000)
    \\
    \\Files in --dir hold secret keys, and are created readable by you only.
    \\Only the announcements and key messages your own key published are read;
    \\a key message from any other author is ignored.
    \\
    \\Exits: 0 on success, including when this machine does not hold the key yet;
    \\1 if the key is wrong, a relay refused, or nothing could be reached; 2 if
    \\the command line was not understood.
    \\
;

/// Events held in memory, parsed from the lines a query printed, and how
/// complete the answer was.
const Events = struct {
    parsed: std.ArrayList(nostr.event.Parsed) = .empty,
    outcome: relayset.Outcome = .{},

    /// Whether every relay asked was reached and said it had sent all it had.
    /// Nothing found in a smaller answer than this proves nothing.
    fn complete(self: Events) bool {
        return self.outcome.dialled > 0 and self.outcome.unreachable_count == 0 and self.outcome.complete == self.outcome.dialled;
    }

    fn deinit(self: *Events, gpa: std.mem.Allocator) void {
        for (self.parsed.items) |*p| p.deinit();
        self.parsed.deinit(gpa);
    }
};

fn collect(
    gpa: std.mem.Allocator,
    io: Io,
    urls: []const []const u8,
    f: filter.Filter,
    timeout_ms: i64,
    err: *Io.Writer,
) !Events {
    var buf: Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    var events: Events = .{};
    events.outcome = try relayset.query(gpa, io, urls, &.{f}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
    });
    errdefer events.deinit(gpa);
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var p = nostr.event.fromJson(gpa, line) catch continue;
        events.parsed.append(gpa, p) catch |e| {
            p.deinit();
            return e;
        };
    }
    return events;
}

fn tagValue(ev: Event, name: []const u8) ?[]const u8 {
    for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], name)) return t[1];
    }
    return null;
}

fn tagPubkey(ev: Event, name: []const u8) ?[32]u8 {
    const v = tagValue(ev, name) orelse return null;
    return hex.decodeFixed(32, v) catch null;
}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

/// A secret key stored as 64 hex characters, or null when there is no file.
fn readKeyFile(io: Io, dir: Io.Dir, path: []const u8) !?keys.SecretKey {
    var buf: [256]u8 = undefined;
    const text = dir.readFile(io, path, &buf) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => |other| return other,
    };
    const t = std.mem.trim(u8, text, " \t\r\n");
    return hex.decodeFixed(32, t) catch error.BadKeyFile;
}

fn processId() u64 {
    if (builtin.os.tag == .windows) return std.os.windows.GetCurrentProcessId();
    return @intCast(std.c.getpid());
}

/// Writes `secret` to `path`, readable by this user only, through a file of
/// its own that is then renamed into place.
fn writeKeyFile(gpa: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, secret: keys.SecretKey) !void {
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp-{d}-{s}", .{ path, processId(), &std.fmt.bytesToHex(raw, .lower) });
    defer gpa.free(tmp);
    errdefer dir.deleteFile(io, tmp) catch {};
    const text = std.fmt.bytesToHex(secret, .lower);
    try dir.writeFile(io, .{
        .sub_path = tmp,
        .data = &text,
        .flags = .{
            .exclusive = true,
            .permissions = if (builtin.os.tag == .windows) .default_file else Io.File.Permissions.fromMode(0o600),
        },
    });
    try dir.rename(tmp, dir, path, io);
}

// ---------------------------------------------------------------------------
// The verb
// ---------------------------------------------------------------------------

const Config = struct {
    sec: ?[]const u8 = null,
    device: ?[]const u8 = null,
    rotate: bool = false,
    authorize_all: bool = false,
    reject_all: bool = false,
    dir: ?[]const u8 = null,
    timeout_ms: i64 = 30_000,
};

/// What `run` needs once it has its arguments: separate so a test can hand it
/// a directory handle.
const Session = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    signer: keys.Signer,
    user: keys.KeyPair,
    dir: Io.Dir,
    urls: []const []const u8,
    cfg: Config,
    device_name: []const u8,
    err: *Io.Writer,

    fn now(self: *const Session) i64 {
        return Io.Timestamp.now(self.io, .real).toSeconds();
    }

    /// Signs an event with the identity key and offers it to the relays.
    /// Returns it when at least one accepted it.
    fn publish(self: *Session, kind: u16, tags: []const nostr.event.Tag, content: []const u8) !?Event {
        const ev = try nostr.event.create(self.arena, self.signer, self.user, self.now(), kind, tags, content, null);
        const ok = try cmd_publish.publishOne(self.gpa, self.io, "dekey", self.urls, ev, @min(cmd_publish.default_timeout_ms, self.cfg.timeout_ms), self.err);
        return if (ok) ev else null;
    }

    fn delete(self: *Session, what: []const u8, id: [32]u8) !void {
        const id_hex = try hex.encode(self.arena, &id);
        const tags = [_]nostr.event.Tag{&.{ "e", id_hex }};
        if (try self.publish(5, try self.arena.dupe(nostr.event.Tag, &tags), "") != null) {
            try self.err.print("deed dekey: deleted {s}\n", .{what});
        } else {
            try self.err.print("deed dekey: could not delete {s}\n", .{what});
        }
    }
};

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    var cfg: Config = .{};
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--rotate")) {
            cfg.rotate = true;
        } else if (cli.isOneOf(a, &.{ "--authorize-all", "--yolo" })) {
            cfg.authorize_all = true;
        } else if (std.mem.eql(u8, a, "--reject-all")) {
            cfg.reject_all = true;
        } else if (cli.isOneOf(a, &.{ "--sec", "--device", "--dir", "--timeout", "-r", "--relay" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed dekey: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (std.mem.eql(u8, a, "--sec")) {
                cfg.sec = args[i];
            } else if (std.mem.eql(u8, a, "--device")) {
                cfg.device = args[i];
            } else if (std.mem.eql(u8, a, "--dir")) {
                cfg.dir = args[i];
            } else if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try urls.append(gpa, args[i]);
            } else {
                cfg.timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch {
                    try err.print("deed dekey: '{s}' is not a number of milliseconds\n", .{args[i]});
                    return cli.exit_fail;
                };
            }
        } else if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try urls.append(gpa, a);
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed dekey: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else {
            try err.print("deed dekey: unexpected argument '{s}'\n", .{a});
            return cli.exit_usage;
        }
    }
    if (cfg.authorize_all and cfg.reject_all) {
        try err.writeAll("deed dekey: --authorize-all and --reject-all contradict each other\n");
        return cli.exit_usage;
    }

    const raw_sec = cfg.sec orelse envSecret() orelse {
        try err.writeAll("deed dekey: needs your secret key: pass --sec or set $NOSTR_SECRET_KEY\n");
        return cli.exit_usage;
    };
    const user_sec = keyinput.secretKeyForVerb(gpa, "dekey", raw_sec, err) catch |e| switch (e) {
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };

    var dir_owned: ?[]u8 = null;
    defer if (dir_owned) |d| gpa.free(d);
    const dir_path: []const u8 = cfg.dir orelse blk: {
        const home = std.c.getenv("HOME") orelse {
            try err.writeAll("deed dekey: no home directory to keep keys in: pass --dir\n");
            return cli.exit_usage;
        };
        dir_owned = try std.fs.path.join(gpa, &.{ std.mem.span(home), ".config", "deed", "dekey" });
        break :blk dir_owned.?;
    };
    try Io.Dir.cwd().createDirPath(io, dir_path);
    var dir = try Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();
    const user = signer.keyPairFromSecretKey(user_sec) catch {
        try err.writeAll("deed dekey: not a usable secret key\n");
        return cli.exit_fail;
    };

    var followed: ?outbox.Urls = null;
    defer if (followed) |*f| f.deinit();
    if (urls.items.len == 0) {
        followed = try outbox.followWriteRelays(gpa, io, "dekey", user.public_key, &.{}, null, cfg.timeout_ms, err) orelse return cli.exit_usage;
        for (followed.?.urls) |u| try urls.append(gpa, u);
    }

    const device_name = cfg.device orelse try defaultDeviceName(arena_state.allocator());
    var session: Session = .{
        .gpa = gpa,
        .arena = arena_state.allocator(),
        .io = io,
        .signer = signer,
        .user = user,
        .dir = dir,
        .urls = urls.items,
        .cfg = cfg,
        .device_name = device_name,
        .err = err,
    };
    return go(&session, out);
}

fn envSecret() ?[]const u8 {
    const v = std.c.getenv("NOSTR_SECRET_KEY") orelse return null;
    const s = std.mem.span(v);
    return if (s.len == 0) null else s;
}

fn defaultDeviceName(arena: std.mem.Allocator) ![]const u8 {
    if (builtin.os.tag != .windows) {
        var buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        if (std.posix.gethostname(&buf)) |name| {
            if (name.len > 0) return std.fmt.allocPrint(arena, "deed@{s}", .{name});
        } else |_| {}
    }
    return "deed@unknown";
}

const Held = struct { secret: keys.SecretKey, public: keys.PublicKey };

fn encKeyPath(arena: std.mem.Allocator, user: [32]u8, epub: [32]u8) ![]const u8 {
    const u = try hex.encode(arena, &user);
    const e = try hex.encode(arena, &epub);
    return std.fmt.allocPrint(arena, "p/{s}/e/{s}", .{ u, e });
}

fn newestKind(events: Events, kind: u16) ?Event {
    var best: ?Event = null;
    for (events.parsed.items) |p| {
        if (p.value.kind != kind) continue;
        if (best == null or p.value.created_at > best.?.created_at) best = p.value;
    }
    return best;
}

fn newestFirst(_: void, a: Event, b: Event) bool {
    if (a.created_at != b.created_at) return a.created_at > b.created_at;
    return std.mem.order(u8, &a.id, &b.id) == .lt;
}

fn eventsOfKind(arena: std.mem.Allocator, events: Events, kind: u16) ![]Event {
    var list: std.ArrayList(Event) = .empty;
    for (events.parsed.items) |p| if (p.value.kind == kind) try list.append(arena, p.value);
    std.mem.sort(Event, list.items, {}, newestFirst);
    return list.items;
}

/// Everything after the arguments are understood.
fn go(self: *Session, out: *Io.Writer) !u8 {
    const arena = self.arena;
    const err = self.err;
    const io = self.io;
    const user_pub = self.user.public_key;

    // This machine's own key, made the first time.
    const device_sec: keys.SecretKey = (readKeyFile(io, self.dir, "device-key") catch {
        try err.writeAll("deed dekey: the device key file in --dir is not a key; remove it to make a new one\n");
        return cli.exit_fail;
    }) orelse blk: {
        const kp = try self.signer.generateKeyPair(io);
        try writeKeyFile(self.gpa, io, self.dir, "device-key", kp.secret_key);
        try err.writeAll("deed dekey: made a device key for this machine\n");
        break :blk kp.secret_key;
    };
    const device_kp = self.signer.keyPairFromSecretKey(device_sec) catch {
        try err.writeAll("deed dekey: the device key file in --dir is not a usable key\n");
        return cli.exit_fail;
    };
    const device_hex = try hex.encode(arena, &device_kp.public_key);

    // What the relays hold of yours: the announcement, devices, key messages.
    var all = try collect(self.gpa, io, self.urls, .{
        .authors = &.{user_pub},
        .kinds = &.{ 10044, 4454, 4455 },
    }, self.cfg.timeout_ms, err);
    defer all.deinit(self.gpa);
    if (all.outcome.dialled == 0) {
        try err.writeAll("deed dekey: no relay answered\n");
        return cli.exit_fail;
    }

    const announcement = newestKind(all, 10044);
    var epub: [32]u8 = undefined;
    if (announcement) |a| {
        epub = tagPubkey(a, "n") orelse {
            try err.writeAll("deed dekey: your kind 10044 event has no usable 'n' tag\n");
            return cli.exit_fail;
        };
    }
    // Events newer than this are the ones that count: the previous
    // announcement's time, so a rotation reaches devices that asked
    // under the old key.
    const since: i64 = if (announcement) |a| a.created_at else 0;

    var held: ?Held = null;
    if (announcement == null or self.cfg.rotate) {
        // "No announcement" is only believed from a complete answer. A new
        // announcement replaces the old one on the relays, so making one while
        // a relay that holds the real one was out of reach would lose it.
        if (!all.complete()) {
            try err.writeAll("deed dekey: not every relay was reached and finished answering, so I cannot tell whether a key is already announced; not making a new one\n");
            return cli.exit_fail;
        }
        const kp = try self.signer.generateKeyPair(io);
        const path = try encKeyPath(arena, user_pub, kp.public_key);
        try writeKeyFile(self.gpa, io, self.dir, path, kp.secret_key);
        epub = kp.public_key;
        const epub_hex = try hex.encode(arena, &epub);
        try err.print("deed dekey: made a decoupled encryption key, public key {s}\n", .{epub_hex});
        const tags = try arena.dupe(nostr.event.Tag, &.{try arena.dupe([]const u8, &.{ "n", epub_hex })});
        if (try self.publish(10044, tags, "") == null) {
            try err.print("deed dekey: could not announce it (kind 10044); the key is kept in {s}\n", .{path});
            return cli.exit_fail;
        }
        held = .{ .secret = kp.secret_key, .public = epub };
    } else {
        const path = try encKeyPath(arena, user_pub, epub);
        const local = readKeyFile(io, self.dir, path) catch {
            try err.print("deed dekey: {s} in --dir is not a key\n", .{path});
            return cli.exit_fail;
        };
        if (local) |secret| {
            const kp = self.signer.keyPairFromSecretKey(secret) catch {
                try err.print("deed dekey: {s} in --dir is not a usable key\n", .{path});
                return cli.exit_fail;
            };
            if (!std.mem.eql(u8, &kp.public_key, &epub)) {
                try err.print("deed dekey: the key kept in {s} does not match the announced public key\n", .{path});
                return cli.exit_fail;
            }
            held = .{ .secret = secret, .public = epub };
        } else {
            held = try requestKey(self, &all, device_sec, device_kp.public_key, device_hex, epub, since, path);
        }
    }

    const key = held orelse {
        try err.print("deed dekey: the decoupled encryption secret key is not on this machine; another device has to send it to {s}\n", .{self.device_name});
        return cli.exit_ok;
    };

    try shareKey(self, &all, key, device_sec, device_kp.public_key, device_hex, since);

    const epub_out = try hex.encode(arena, &key.public);
    try out.print("{s}\n", .{epub_out});
    return cli.exit_ok;
}

/// Announces this machine as a device, if it has not been, and looks for a
/// key message addressed to it. A key that arrives is kept only when it is the
/// announced one.
fn requestKey(
    self: *Session,
    all: *const Events,
    device_sec: keys.SecretKey,
    device_pub: keys.PublicKey,
    device_hex: []const u8,
    epub: [32]u8,
    since: i64,
    path: []const u8,
) !?Held {
    const arena = self.arena;
    const err = self.err;

    var ours: ?Event = null;
    for (try eventsOfKind(arena, all.*, 4454)) |ev| {
        const p = tagPubkey(ev, "P") orelse continue;
        if (std.mem.eql(u8, &p, &device_pub)) {
            ours = ev;
            break;
        }
    }
    if (ours == null) {
        const tags = try arena.dupe(nostr.event.Tag, &.{
            try arena.dupe([]const u8, &.{ "client", self.device_name }),
            try arena.dupe([]const u8, &.{ "P", device_hex }),
        });
        ours = try self.publish(4454, tags, "");
        if (ours == null) {
            try err.writeAll("deed dekey: could not announce this device (kind 4454)\n");
            return null;
        }
        try err.print("deed dekey: announced {s} as a device; another device has to send it the key\n", .{self.device_name});
    } else {
        try err.writeAll("deed dekey: this device is already announced\n");
    }

    for (try eventsOfKind(arena, all.*, 4455)) |msg| {
        if (msg.created_at <= since) continue;
        const to = tagPubkey(msg, "p") orelse continue;
        if (!std.mem.eql(u8, &to, &device_pub)) continue;
        const sender = tagPubkey(msg, "P") orelse continue;
        const ck = nip44.conversationKey(self.signer, device_sec, sender) catch continue;
        const plain = nip44.decryptWithConversationKey(self.gpa, ck, msg.content) catch continue;
        defer self.gpa.free(plain);
        const candidate = hex.decodeFixed(32, plain) catch continue;
        const kp = self.signer.keyPairFromSecretKey(candidate) catch continue;
        // Only the announced key is kept; anything else is stale, and would be
        // handed on to other devices.
        if (!std.mem.eql(u8, &kp.public_key, &epub)) continue;
        try writeKeyFile(self.gpa, self.io, self.dir, path, candidate);
        try err.writeAll("deed dekey: received the decoupled encryption key from another device\n");
        if (ours) |o| try self.delete("this device's announcement (kind 4454)", o.id);
        try self.delete("the key message (kind 4455)", msg.id);
        return .{ .secret = candidate, .public = kp.public_key };
    }
    return null;
}

/// Sends the key to the devices that announced themselves and were sent
/// nothing yet, when told to. Otherwise names them.
fn shareKey(
    self: *Session,
    all: *const Events,
    key: Held,
    device_sec: keys.SecretKey,
    device_pub: keys.PublicKey,
    device_hex: []const u8,
    since: i64,
) !void {
    const arena = self.arena;
    const err = self.err;

    var sent: std.ArrayList([32]u8) = .empty;
    for (try eventsOfKind(arena, all.*, 4455)) |msg| {
        if (msg.created_at <= since) continue;
        if (tagPubkey(msg, "p")) |to| try sent.append(arena, to);
    }
    var seen: std.ArrayList([32]u8) = .empty;
    const key_hex = try hex.encode(arena, &key.secret);

    for (try eventsOfKind(arena, all.*, 4454)) |dev| {
        if (dev.created_at <= since) continue;
        const their = tagPubkey(dev, "P") orelse continue;
        if (std.mem.eql(u8, &their, &device_pub)) continue;
        // A device whose clock runs ahead of this one is not trusted yet.
        if (self.now() < dev.created_at) continue;
        const name = tagValue(dev, "client") orelse continue;
        if (contains(sent.items, their) or contains(seen.items, their)) continue;
        try seen.append(arena, their);

        const shown = try cleanLine(arena, name);
        if (!self.cfg.authorize_all) {
            const why = if (self.cfg.reject_all) "skipped" else "waiting; run again with --authorize-all to send it the key";
            try err.print("deed dekey: device {s} ({s}): {s}\n", .{ shown, try hex.encode(arena, &their), why });
            continue;
        }
        const ct = nip44.encrypt(self.gpa, self.io, self.signer, device_sec, their, key_hex) catch {
            try err.print("deed dekey: could not encrypt the key for {s}\n", .{shown});
            continue;
        };
        defer self.gpa.free(ct);
        const tags = try arena.dupe(nostr.event.Tag, &.{
            try arena.dupe([]const u8, &.{ "p", try hex.encode(arena, &their) }),
            try arena.dupe([]const u8, &.{ "P", device_hex }),
        });
        if (try self.publish(4455, tags, ct) != null) {
            try err.print("deed dekey: sent the key to {s}\n", .{shown});
        } else {
            try err.print("deed dekey: could not send the key to {s}\n", .{shown});
        }
    }
}

fn contains(list: []const [32]u8, one: [32]u8) bool {
    for (list) |l| if (std.mem.eql(u8, &l, &one)) return true;
    return false;
}

/// A device name is whatever its owner typed, and arrives from a relay.
fn cleanLine(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    const copy = try arena.dupe(u8, text);
    for (copy) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = ' ';
    };
    return copy;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");
const filterflags = @import("filterflags.zig");

/// A relay that keeps what it is sent and answers REQs from it.
const Memory = struct {
    arena: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(std.heap.page_allocator),
    events: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Memory) void {
        self.arena.deinit();
    }

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        const self: *Memory = @ptrCast(@alignCast(ctx.?));
        const a = self.arena.allocator();
        const event_prefix = "[\"EVENT\",";
        if (std.mem.startsWith(u8, frame, event_prefix)) {
            const json = try a.dupe(u8, frame[event_prefix.len .. frame.len - 1]);
            const parsed = try nostr.event.fromJson(a, json);
            const id_hex = try hex.encode(a, &parsed.value.id);
            try self.events.append(a, json);
            var buf: [200]u8 = undefined;
            try testrelay.sendText(w, try std.fmt.bufPrint(&buf, "[\"OK\",\"{s}\",true,\"\"]", .{id_hex}));
            return;
        }
        if (!std.mem.startsWith(u8, frame, "[\"REQ\"")) return;
        const root = try std.json.parseFromSliceLeaky(std.json.Value, a, frame, .{});
        const sub = root.array.items[1].string;
        var sink: Io.Writer.Allocating = .init(a);
        for (root.array.items[2..]) |fv| {
            const f = try filterflags.fromValue(a, "test", fv, &sink.writer);
            for (self.events.items) |json| {
                const parsed = try nostr.event.fromJson(a, json);
                if (!f.matches(parsed.value)) continue;
                const line = try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ sub, json });
                try testrelay.sendText(w, line);
            }
        }
        var buf: [100]u8 = undefined;
        try testrelay.sendText(w, try std.fmt.bufPrint(&buf, "[\"EOSE\",\"{s}\"]", .{sub}));
    }

    fn count(self: *Memory, a: std.mem.Allocator, kind: u16) !usize {
        var n: usize = 0;
        for (self.events.items) |json| {
            const parsed = try nostr.event.fromJson(a, json);
            if (parsed.value.kind == kind) n += 1;
        }
        return n;
    }

    fn first(self: *Memory, a: std.mem.Allocator, kind: u16) !?Event {
        for (self.events.items) |json| {
            const parsed = try nostr.event.fromJson(a, json);
            if (parsed.value.kind == kind) return parsed.value;
        }
        return null;
    }
};

const Rig = struct {
    arena: std.heap.ArenaAllocator,
    signer: keys.Signer,
    memory: Memory = .{},
    relay: testrelay.Relay = undefined,
    url_buf: [40]u8 = undefined,
    url: []const u8 = "",
    user: keys.KeyPair,
    tmp: std.testing.TmpDir,
    dir_path: []const u8 = "",

    fn start(rig: *Rig) !void {
        const io = testing.io;
        try rig.relay.startFor(io, .custom, 30);
        rig.relay.custom = Memory.handle;
        rig.relay.custom_ctx = &rig.memory;
        rig.url = try testrelay.url(&rig.url_buf, rig.relay.port());
        rig.dir_path = try std.fmt.allocPrint(rig.arena.allocator(), ".zig-cache/tmp/{s}", .{rig.tmp.sub_path});
    }

    fn stop(rig: *Rig) void {
        rig.relay.stop(testing.io);
        rig.memory.deinit();
        rig.signer.deinit();
        rig.tmp.cleanup();
        rig.arena.deinit();
    }

    fn put(rig: *Rig, kp: keys.KeyPair, at: i64, kind: u16, tags: []const nostr.event.Tag, content: []const u8) !Event {
        const a = rig.arena.allocator();
        const ev = try nostr.event.create(a, rig.signer, kp, at, kind, tags, content, null);
        try rig.memory.events.append(rig.memory.arena.allocator(), try nostr.event.toJson(rig.memory.arena.allocator(), ev));
        return ev;
    }

    fn tag(rig: *Rig, parts: []const []const u8) !nostr.event.Tag {
        return rig.arena.allocator().dupe([]const u8, parts);
    }

    fn hexOf(rig: *Rig, bytes: *const [32]u8) ![]const u8 {
        return hex.encode(rig.arena.allocator(), bytes);
    }

    fn run(rig: *Rig, extra: []const []const u8, out: *Io.Writer.Allocating, err: *Io.Writer.Allocating) !u8 {
        const a = rig.arena.allocator();
        const sec = try rig.hexOf(&rig.user.secret_key);
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(a, &.{ "--sec", sec, "--dir", rig.dir_path, "--device", "test device", "--relay", rig.url, "--timeout", "5000" });
        try args.appendSlice(a, extra);
        return @import("cmd_dekey.zig").run(testing.allocator, testing.io, args.items, &out.writer, &err.writer);
    }
};

fn newRig() !Rig {
    var signer = try keys.Signer.initRandomized(testing.io);
    errdefer signer.deinit();
    return .{
        .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
        .signer = signer,
        .user = try signer.keyPairFromSecretKey([_]u8{0x81} ** 32),
        .tmp = testing.tmpDir(.{}),
    };
}

test "a first run makes a key, keeps it, and announces its public half once" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    _ = da.allocator();
    var rig = try newRig();
    defer rig.stop();
    try rig.start();
    const a = rig.arena.allocator();

    var out: Io.Writer.Allocating = .init(a);
    var err: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{}, &out, &err));
    const printed = std.mem.trimEnd(u8, out.written(), "\n");
    try testing.expectEqual(@as(usize, 64), printed.len);

    const announced = (try rig.memory.first(a, 10044)).?;
    try testing.expectEqualStrings(printed, tagValue(announced, "n").?);
    try testing.expectEqualSlices(u8, &rig.user.public_key, &announced.pubkey);

    // The secret is on disk under the user and key, and matches the public half.
    const path = try encKeyPath(a, rig.user.public_key, tagPubkey(announced, "n").?);
    const stored = (try readKeyFile(testing.io, rig.tmp.dir, path)).?;
    const kp = try rig.signer.keyPairFromSecretKey(stored);
    try testing.expectEqualSlices(u8, &kp.public_key, &(tagPubkey(announced, "n").?));
    if (builtin.os.tag != .windows) {
        const st = try rig.tmp.dir.statFile(testing.io, path, .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);
    }

    // Again: the same key, and nothing new announced.
    var out2: Io.Writer.Allocating = .init(a);
    var err2: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{}, &out2, &err2));
    try testing.expectEqualStrings(printed, std.mem.trimEnd(u8, out2.written(), "\n"));
    try testing.expectEqual(@as(usize, 1), try rig.memory.count(a, 10044));

    // --rotate makes another.
    var out3: Io.Writer.Allocating = .init(a);
    var err3: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{"--rotate"}, &out3, &err3));
    try testing.expect(!std.mem.eql(u8, printed, std.mem.trimEnd(u8, out3.written(), "\n")));
    try testing.expectEqual(@as(usize, 2), try rig.memory.count(a, 10044));
}

test "a new device announces itself, takes the key it is sent, and cleans up" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    _ = da.allocator();
    var rig = try newRig();
    defer rig.stop();
    try rig.start();
    const a = rig.arena.allocator();
    const io = testing.io;

    // The key, announced long ago, and the first device that holds it.
    const e_kp = try rig.signer.keyPairFromSecretKey([_]u8{0x82} ** 32);
    const first_dev = try rig.signer.keyPairFromSecretKey([_]u8{0x83} ** 32);
    const this_dev = try rig.signer.keyPairFromSecretKey([_]u8{0x84} ** 32);
    const e_hex = try rig.hexOf(&e_kp.public_key);
    _ = try rig.put(rig.user, 1000, 10044, &.{try rig.tag(&.{ "n", e_hex })}, "");

    // This machine already has a device key; the first device has sent it the key.
    try writeKeyFile(testing.allocator, io, rig.tmp.dir, "device-key", this_dev.secret_key);
    const e_secret_hex = try rig.hexOf(&e_kp.secret_key);
    const sealed = try nip44.encrypt(a, io, rig.signer, first_dev.secret_key, this_dev.public_key, e_secret_hex);
    const msg = try rig.put(rig.user, 2000, 4455, &.{
        try rig.tag(&.{ "p", try rig.hexOf(&this_dev.public_key) }),
        try rig.tag(&.{ "P", try rig.hexOf(&first_dev.public_key) }),
    }, sealed);

    var out: Io.Writer.Allocating = .init(a);
    var err: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{}, &out, &err));
    try testing.expectEqualStrings(e_hex, std.mem.trimEnd(u8, out.written(), "\n"));

    const path = try encKeyPath(a, rig.user.public_key, e_kp.public_key);
    const stored = (try readKeyFile(io, rig.tmp.dir, path)).?;
    try testing.expectEqualSlices(u8, &e_kp.secret_key, &stored);

    // It announced itself, and then deleted that announcement and the message.
    const announced = (try rig.memory.first(a, 4454)).?;
    try testing.expectEqualStrings("test device", tagValue(announced, "client").?);
    try testing.expectEqualStrings(try rig.hexOf(&this_dev.public_key), tagValue(announced, "P").?);
    try testing.expectEqual(@as(usize, 2), try rig.memory.count(a, 5));
    var deleted_msg = false;
    for (rig.memory.events.items) |json| {
        const parsed = try nostr.event.fromJson(a, json);
        if (parsed.value.kind == 5 and std.mem.eql(u8, tagValue(parsed.value, "e").?, try rig.hexOf(&msg.id))) deleted_msg = true;
    }
    try testing.expect(deleted_msg);
}

test "a message that carries some other key is not kept" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    _ = da.allocator();
    var rig = try newRig();
    defer rig.stop();
    try rig.start();
    const a = rig.arena.allocator();
    const io = testing.io;

    const e_kp = try rig.signer.keyPairFromSecretKey([_]u8{0x82} ** 32);
    const stale = try rig.signer.keyPairFromSecretKey([_]u8{0x85} ** 32);
    const first_dev = try rig.signer.keyPairFromSecretKey([_]u8{0x83} ** 32);
    const this_dev = try rig.signer.keyPairFromSecretKey([_]u8{0x84} ** 32);
    _ = try rig.put(rig.user, 1000, 10044, &.{try rig.tag(&.{ "n", try rig.hexOf(&e_kp.public_key) })}, "");
    try writeKeyFile(testing.allocator, io, rig.tmp.dir, "device-key", this_dev.secret_key);
    const sealed = try nip44.encrypt(a, io, rig.signer, first_dev.secret_key, this_dev.public_key, try rig.hexOf(&stale.secret_key));
    _ = try rig.put(rig.user, 2000, 4455, &.{
        try rig.tag(&.{ "p", try rig.hexOf(&this_dev.public_key) }),
        try rig.tag(&.{ "P", try rig.hexOf(&first_dev.public_key) }),
    }, sealed);

    var out: Io.Writer.Allocating = .init(a);
    var err: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{}, &out, &err));
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expect(std.mem.indexOf(u8, err.written(), "not on this machine") != null);
    try testing.expectEqual(@as(usize, 0), try rig.memory.count(a, 5));
}

test "a device waiting for the key is named, and sent it only when authorized" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    _ = da.allocator();
    var rig = try newRig();
    defer rig.stop();
    try rig.start();
    const a = rig.arena.allocator();
    const io = testing.io;

    const e_kp = try rig.signer.keyPairFromSecretKey([_]u8{0x82} ** 32);
    const this_dev = try rig.signer.keyPairFromSecretKey([_]u8{0x84} ** 32);
    const phone = try rig.signer.keyPairFromSecretKey([_]u8{0x86} ** 32);
    _ = try rig.put(rig.user, 1000, 10044, &.{try rig.tag(&.{ "n", try rig.hexOf(&e_kp.public_key) })}, "");
    try writeKeyFile(testing.allocator, io, rig.tmp.dir, "device-key", this_dev.secret_key);
    try writeKeyFile(testing.allocator, io, rig.tmp.dir, try encKeyPath(a, rig.user.public_key, e_kp.public_key), e_kp.secret_key);
    _ = try rig.put(rig.user, 2000, 4454, &.{
        try rig.tag(&.{ "client", "phone\x1b[31m" }),
        try rig.tag(&.{ "P", try rig.hexOf(&phone.public_key) }),
    }, "");

    // Without the flag: named, not sent, and no escape reaches the terminal.
    var out: Io.Writer.Allocating = .init(a);
    var err: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{}, &out, &err));
    try testing.expectEqualStrings(try rig.hexOf(&e_kp.public_key), std.mem.trimEnd(u8, out.written(), "\n"));
    try testing.expect(std.mem.indexOf(u8, err.written(), "phone [31m") != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "--authorize-all") != null);
    try testing.expect(std.mem.indexOfScalar(u8, err.written(), 0x1b) == null);
    try testing.expectEqual(@as(usize, 0), try rig.memory.count(a, 4455));

    var out_r: Io.Writer.Allocating = .init(a);
    var err_r: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{"--reject-all"}, &out_r, &err_r));
    try testing.expectEqual(@as(usize, 0), try rig.memory.count(a, 4455));

    // Authorized: one key message, to the phone, that the phone can open.
    var out2: Io.Writer.Allocating = .init(a);
    var err2: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{"--authorize-all"}, &out2, &err2));
    try testing.expectEqual(@as(usize, 1), try rig.memory.count(a, 4455));
    const sent = (try rig.memory.first(a, 4455)).?;
    try testing.expectEqualStrings(try rig.hexOf(&phone.public_key), tagValue(sent, "p").?);
    try testing.expectEqualStrings(try rig.hexOf(&this_dev.public_key), tagValue(sent, "P").?);
    const opened = try nip44.decrypt(a, rig.signer, phone.secret_key, this_dev.public_key, sent.content);
    try testing.expectEqualStrings(try rig.hexOf(&e_kp.secret_key), opened);

    // A second run does not send it again.
    var out3: Io.Writer.Allocating = .init(a);
    var err3: Io.Writer.Allocating = .init(a);
    try testing.expectEqual(cli.exit_ok, try rig.run(&.{"--yolo"}, &out3, &err3));
    try testing.expectEqual(@as(usize, 1), try rig.memory.count(a, 4455));
}

test "a relay that cannot be reached never leads to a new key" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    _ = da.allocator();
    var rig = try newRig();
    defer rig.stop();
    try rig.start();
    const a = rig.arena.allocator();

    // Nothing listens on port 1.
    var out: Io.Writer.Allocating = .init(a);
    var err: Io.Writer.Allocating = .init(a);
    const sec = try rig.hexOf(&rig.user.secret_key);
    const code = try run(testing.allocator, testing.io, &.{ "--sec", sec, "--dir", rig.dir_path, "--relay", "ws://127.0.0.1:1", "--timeout", "2000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expectEqual(@as(usize, 0), try rig.memory.count(a, 10044));

    // One relay answers and another does not: still no new key.
    var out2: Io.Writer.Allocating = .init(a);
    var err2: Io.Writer.Allocating = .init(a);
    const mixed = try run(testing.allocator, testing.io, &.{ "--sec", sec, "--dir", rig.dir_path, "--relay", rig.url, "--relay", "ws://127.0.0.1:1", "--timeout", "2000" }, &out2.writer, &err2.writer);
    try testing.expectEqual(cli.exit_fail, mixed);
    try testing.expect(std.mem.indexOf(u8, err2.written(), "not making a new one") != null);
    try testing.expectEqual(@as(usize, 0), try rig.memory.count(a, 10044));
}

test "arguments that make no sense are refused" {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{ "--authorize-all", "--reject-all" }, &out.writer, &err.writer));
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{"--bogus"}, &out.writer, &err.writer));
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{"--sec"}, &out.writer, &err.writer));
}
