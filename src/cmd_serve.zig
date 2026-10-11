//! `deed serve`: a relay on this machine, for development and tests.
//!
//! The relay itself is in `relayserver.zig`. This file reads the flags, finds
//! a store for it, loads any events it was given, prints the URL, and stops
//! it on SIGINT or SIGTERM (Ctrl-C or Ctrl-Break on Windows).

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const storepath = @import("storepath.zig");
const relayserver = @import("relayserver.zig");

const Io = std.Io;
const Store = nostr.store.Store;

/// Shown beside the name in `deed help`.
pub const summary = "run a relay on this machine, for development and tests";

pub const ready = true;

/// 10547 is the port other local test relays already use, so an existing
/// script finds this one without a change.
pub const default_port: u16 = 10547;

pub const usage =
    \\deed serve: run a relay on this machine, for development and tests
    \\
    \\Usage:
    \\  deed serve [--hostname <host>] [--port <n>] [--store <path>]
    \\             [--events <file>] [--auth-required]
    \\             [--allow-origin <origin>]...
    \\
    \\Options:
    \\      --hostname <host>  the address to listen on (default 127.0.0.1);
    \\                         an IP address, or localhost. Any address other
    \\                         than 127.0.0.1 or localhost exposes the relay to
    \\                         other machines on that network; --auth-required
    \\                         and --allow-origin are the controls
    \\      --port <n>         the port (default 10547); 0 lets the system pick
    \\      --store <path>     keep events in the store at this path, which
    \\                         outlives the relay (default: a store in a
    \\                         temporary directory, removed when it stops)
    \\      --events <file>    load these events first, one JSON event per
    \\                         line; each is verified, and a bad line is
    \\                         reported on stderr and skipped
    \\      --auth-required    send a NIP-42 challenge on connect and answer
    \\                         nothing until the client has authenticated
    \\      --allow-origin <origin>  let a browser page from this origin (for
    \\                         example http://localhost:3000) connect; give it
    \\                         more than once, or * for any page. Without it a
    \\                         websocket request that carries an Origin header
    \\                         is refused, so a page you happen to have open
    \\                         cannot reach the relay. Clients that are not
    \\                         browsers send no Origin and are not affected.
    \\
    \\Once it is listening, the relay prints its URL on stdout, so a script can
    \\read it:
    \\
    \\  deed serve --port 0 | head -1
    \\
    \\Connections and errors are logged on stderr. It runs until SIGINT or
    \\SIGTERM.
    \\
    \\It speaks NIP-01 (every event's id and signature is checked before it
    \\is stored; replaceable and addressable events keep the newest), NIP-09
    \\deletions, NIP-11 (the document is served to an HTTP request with
    \\Accept: application/nostr+json), NIP-40 expiration, NIP-42 AUTH,
    \\NIP-45 COUNT, NIP-70 protected events and NIP-77 negentropy.
    \\
    \\Limits: a message is at most 512 KiB, a connection holds at most 64
    \\subscriptions, a REQ carries at most 32 filters, and a filter is answered
    \\with at most 10000 stored events. A client that stops reading while
    \\events are sent to it is disconnected once 4 MiB are waiting for it,
    \\so it never holds up anybody else.
    \\
    \\With --store, every accepted event is synced to disk before it is
    \\acknowledged. The temporary store skips that, since it does not outlive
    \\the relay anyway.
    \\
    \\Exits: 0 when stopped by a signal, 1 when the relay could not start, and
    \\2 when the command made no sense.
    \\
;

const Parsed = struct {
    hostname: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    store: ?[]const u8 = null,
    events: ?[]const u8 = null,
    auth_required: bool = false,
    origins: [max_origins][]const u8 = undefined,
    origin_count: usize = 0,
};

const max_origins = 16;

/// Reads the arguments. Null after printing the help, an error after saying
/// what was wrong.
fn parse(args: []const []const u8, out: *Io.Writer, err: *Io.Writer) !?Parsed {
    var p: Parsed = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return null;
        }
        if (std.mem.eql(u8, a, "--auth-required")) {
            p.auth_required = true;
            continue;
        }
        if (cli.isOneOf(a, &.{ "--hostname", "--port", "--store", "--events", "--allow-origin" })) {
            i += 1;
            if (i == args.len) {
                try err.print("deed serve: {s} needs a value\n", .{a});
                return error.Usage;
            }
            const v = args[i];
            if (std.mem.eql(u8, a, "--hostname")) {
                p.hostname = v;
            } else if (std.mem.eql(u8, a, "--port")) {
                p.port = std.fmt.parseInt(u16, v, 10) catch {
                    try err.print("deed serve: --port needs a number from 0 to 65535, not '{s}'\n", .{v});
                    return error.Usage;
                };
            } else if (std.mem.eql(u8, a, "--allow-origin")) {
                if (p.origin_count == max_origins) {
                    try err.print("deed serve: --allow-origin can be given at most {d} times\n", .{max_origins});
                    return error.Usage;
                }
                p.origins[p.origin_count] = v;
                p.origin_count += 1;
            } else if (std.mem.eql(u8, a, "--store")) {
                p.store = v;
            } else {
                p.events = v;
            }
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed serve: unknown option '{s}'\n", .{a});
        } else {
            try err.print("deed serve: takes no arguments, and was given '{s}'\n", .{a});
        }
        return error.Usage;
    }
    return p;
}

/// The address `hostname` names: an IP address, or localhost.
fn address(hostname: []const u8, port: u16) ?Io.net.IpAddress {
    if (std.ascii.eqlIgnoreCase(hostname, "localhost")) return .{ .ip4 = .loopback(port) };
    var h = hostname;
    if (h.len >= 2 and h[0] == '[' and h[h.len - 1] == ']') h = h[1 .. h.len - 1];
    return Io.net.IpAddress.parse(h, port) catch null;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    const p = (parse(args, out, err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        else => return e,
    }) orelse return cli.exit_ok;

    const addr = address(p.hostname, p.port) orelse {
        try err.print("deed serve: --hostname needs an IP address or localhost, not '{s}'\n", .{p.hostname});
        return cli.exit_usage;
    };

    // The store: the one named, or a fresh one in a temporary directory.
    var temp_dir: ?[]u8 = null;
    defer if (temp_dir) |d| {
        Io.Dir.cwd().deleteTree(io, d) catch {};
        gpa.free(d);
    };
    var store: Store = undefined;
    if (p.store) |path| {
        store = (try storepath.open(gpa, io, "serve", path, .create, err)) orelse return cli.exit_fail;
    } else {
        const dir = makeTempDir(gpa, io) catch |e| {
            try err.print("deed serve: cannot make a temporary directory for the store: {s}\n", .{@errorName(e)});
            return cli.exit_fail;
        };
        temp_dir = dir;
        const file = try std.fmt.allocPrintSentinel(gpa, "{s}{c}events.mdb", .{ dir, std.fs.path.sep }, 0);
        defer gpa.free(file);
        store = Store.open(file, .{ .durability = .no_sync }) catch |e| {
            try err.print("deed serve: cannot open a store in {s}: {s}\n", .{ dir, @errorName(e) });
            return cli.exit_fail;
        };
    }
    defer store.deinit();

    if (p.events) |path| {
        const file = Io.Dir.cwd().openFile(io, path, .{}) catch |e| {
            try err.print("deed serve: cannot open {s}: {s}\n", .{ path, @errorName(e) });
            return cli.exit_fail;
        };
        defer file.close(io);
        const buf = try gpa.alloc(u8, 1 << 20);
        defer gpa.free(buf);
        var reader = file.readerStreaming(io, buf);
        const got = relayserver.preload(gpa, &store, &reader.interface, path, err) catch |e| {
            try err.print("deed serve: cannot read {s}: {s}\n", .{ path, @errorName(e) });
            return cli.exit_fail;
        };
        try err.print("deed serve: loaded {d} events from {s}", .{ got.stored, path });
        if (got.rejected > 0) try err.print(", {d} lines rejected", .{got.rejected});
        try err.writeAll("\n");
        try err.flush();
    }

    var server: relayserver.Server = undefined;
    server.start(gpa, io, &store, .{
        .address = addr,
        .hostname = p.hostname,
        .auth_required = p.auth_required,
        .allow_origins = p.origins[0..p.origin_count],
        .log = err,
    }) catch |e| {
        try err.print("deed serve: cannot listen on {s}:{d}: {s}\n", .{ p.hostname, p.port, @errorName(e) });
        return cli.exit_fail;
    };

    signals.install();
    defer signals.restore();

    try out.print("{s}\n", .{server.url()});
    try out.flush();
    {
        // Logging shares `err` with the relay's tasks from here on.
        server.log_mu.lockUncancelable(io);
        defer server.log_mu.unlock(io);
        try err.print("deed serve: listening on {s}{s}\n", .{ server.url(), if (p.auth_required) ", auth required" else "" });
        try err.flush();
    }

    while (!signals.stopping.load(.acquire)) {
        io.sleep(.fromMilliseconds(100), .awake) catch break;
    }
    server.stop();
    try err.writeAll("deed serve: stopped\n");
    return cli.exit_ok;
}

/// A new directory under the system's temporary directory. The caller owns
/// the path.
fn makeTempDir(gpa: std.mem.Allocator, io: Io) ![]u8 {
    const base = tempBase();
    var rand: [8]u8 = undefined;
    io.random(&rand);
    const dir = try std.fmt.allocPrint(gpa, "{s}{c}deed-serve-{x}", .{ base, std.fs.path.sep, &rand });
    errdefer gpa.free(dir);
    // Only its owner may open it: the store holds whatever is published.
    const perms: Io.File.Permissions = if (builtin.os.tag == .windows) .default_dir else Io.File.Permissions.fromMode(0o700);
    try Io.Dir.cwd().createDir(io, dir, perms);
    return dir;
}

fn tempBase() []const u8 {
    const names: []const [*:0]const u8 = if (builtin.os.tag == .windows) &.{ "TEMP", "TMP" } else &.{"TMPDIR"};
    for (names) |n| {
        if (std.c.getenv(n)) |v| {
            var s: []const u8 = std.mem.span(v);
            while (s.len > 1 and (s[s.len - 1] == '/' or s[s.len - 1] == '\\')) s = s[0 .. s.len - 1];
            if (s.len > 0) return s;
        }
    }
    return if (builtin.os.tag == .windows) "." else "/tmp";
}

/// SIGINT and SIGTERM, or a console Ctrl-C on Windows, set a flag that the
/// main loop checks. Nothing else happens in the handler.
const signals = struct {
    var stopping: std.atomic.Value(bool) = .init(false);

    const posix = std.posix;
    const watched = if (builtin.os.tag == .windows) [_]u8{} else [_]posix.SIG{ .INT, .TERM };
    var previous: [watched.len]posix.Sigaction = undefined;

    fn onSignal(_: posix.SIG) callconv(.c) void {
        stopping.store(true, .release);
    }

    const win = struct {
        extern "kernel32" fn SetConsoleCtrlHandler(handler: *const fn (u32) callconv(.winapi) c_int, add: c_int) callconv(.winapi) c_int;
    };

    fn onCtrl(_: u32) callconv(.winapi) c_int {
        stopping.store(true, .release);
        return 1;
    }

    fn install() void {
        stopping.store(false, .release);
        if (builtin.os.tag == .windows) {
            _ = win.SetConsoleCtrlHandler(onCtrl, 1);
            return;
        }
        const act: posix.Sigaction = .{
            .handler = .{ .handler = onSignal },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        for (watched, 0..) |s, i| posix.sigaction(s, &act, &previous[i]);
    }

    fn restore() void {
        if (builtin.os.tag == .windows) {
            _ = win.SetConsoleCtrlHandler(onCtrl, 0);
            return;
        }
        for (watched, 0..) |s, i| posix.sigaction(s, &previous[i], null);
    }
};

// -- tests --------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

fn runServe(args: []const []const u8, ob: []u8, eb: []u8) !struct { code: u8, out: []const u8, err: []const u8 } {
    var out: Io.Writer = .fixed(ob);
    var err: Io.Writer = .fixed(eb);
    const code = try run(testing.allocator, testing.io, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

test "flags that make no sense exit 2 and say why" {
    var ob: [4096]u8 = undefined;
    var eb: [256]u8 = undefined;
    var r = try runServe(&.{ "--port", "70000" }, &ob, &eb);
    try testing.expectEqual(cli.exit_usage, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "--port") != null);
    r = try runServe(&.{"--frobnicate"}, &ob, &eb);
    try testing.expectEqual(cli.exit_usage, r.code);
    r = try runServe(&.{ "--hostname", "relay.example" }, &ob, &eb);
    try testing.expectEqual(cli.exit_usage, r.code);
    r = try runServe(&.{"--store"}, &ob, &eb);
    try testing.expectEqual(cli.exit_usage, r.code);
    r = try runServe(&.{"--help"}, &ob, &eb);
    try testing.expectEqual(cli.exit_ok, r.code);
}

test "hostnames: IP addresses and localhost" {
    try testing.expect(address("localhost", 1) != null);
    try testing.expect(address("0.0.0.0", 1) != null);
    try testing.expect(address("::1", 1) != null);
    try testing.expect(address("[::1]", 1) != null);
    try testing.expect(address("example.com", 1) == null);
}

test "deed publish and deed req against the relay: publish, then query back" {
    var ts: relayserver.TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    var sk: [32]u8 = @splat(0);
    sk[31] = 9;
    const kp = try signer.keyPairFromSecretKey(sk);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, ts.server.url());
    for (0..3) |i| {
        const ev = try nostr.event.create(arena, signer, kp, 1_700_000_000 + @as(i64, @intCast(i)), 1, &.{}, "from deed publish", null);
        try argv.append(arena, try nostr.event.toJson(arena, ev));
    }
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    {
        var ob: [8192]u8 = undefined;
        var eb: [4096]u8 = undefined;
        var out: Io.Writer = .fixed(&ob);
        var err: Io.Writer = .fixed(&eb);
        const code = try @import("cmd_publish.zig").run(da.allocator(), testing.io, argv.items, &out, &err);
        try testing.expectEqual(cli.exit_ok, code);
        try testing.expectEqual(@as(usize, 3), std.mem.count(u8, out.buffered(), "\n"));
    }
    {
        var ob: [8192]u8 = undefined;
        var eb: [4096]u8 = undefined;
        var out: Io.Writer = .fixed(&ob);
        var err: Io.Writer = .fixed(&eb);
        const code = try @import("cmd_req.zig").runWith(da.allocator(), testing.io, &.{ "-k", "1", ts.server.url() }, null, &out, &err);
        try testing.expectEqual(cli.exit_ok, code);
        try testing.expectEqual(@as(usize, 3), std.mem.count(u8, out.buffered(), "from deed publish"));
    }
}

test "the library client subscribes and receives what another connection publishes" {
    var ts: relayserver.TestServer = undefined;
    try ts.start(.{});
    defer ts.stop();
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the client leaked");
    const gpa = da.allocator();
    const io = testing.io;

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();
    var sk: [32]u8 = @splat(0);
    sk[31] = 10;
    const kp = try signer.keyPairFromSecretKey(sk);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const sub = try nostr.relay.dial(gpa, io, ts.server.url());
    defer sub.deinit();
    try sub.subscribe("live", &.{.{ .kinds = &.{1} }});
    {
        var m = (try sub.receive()).?;
        defer m.deinit();
        try testing.expect(m.value == .eose);
    }

    const publisher = try nostr.relay.dial(gpa, io, ts.server.url());
    defer publisher.deinit();
    const ev = try nostr.event.create(arena_state.allocator(), signer, kp, 1_700_000_000, 1, &.{}, "live one", null);
    try publisher.publish(ev);
    {
        var m = (try publisher.receive()).?;
        defer m.deinit();
        try testing.expect(m.value.ok.accepted);
    }
    var m = (try sub.receive()).?;
    defer m.deinit();
    try testing.expectEqualStrings("live", m.value.event.subscription_id);
    try testing.expectEqualStrings("live one", m.value.event.event.content);
}

test "the temporary store directory is private to its owner" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const dir = try makeTempDir(testing.allocator, testing.io);
    defer testing.allocator.free(dir);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const st = try Io.Dir.cwd().statFile(testing.io, dir, .{});
    try testing.expectEqual(@as(u32, 0), @as(u32, @intCast(st.permissions.toMode() & 0o077)));
}
