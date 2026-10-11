//! The table of verbs, and the dispatch, per-verb help and top-level usage
//! that are derived from it.
//!
//! Adding or finishing a verb never edits this file for anything but a new
//! row. A verb that lives in `cmd_<name>.zig` exports `summary`, `usage`,
//! `ready` and `run`, and its row is `fromModule`. To build one of the
//! pre-registered stubs, replace the body of its own file and set `ready`.

const std = @import("std");
const cli = @import("cli.zig");
const proxy = @import("proxy.zig");

const cmd_decode = @import("cmd_decode.zig");
const cmd_encode = @import("cmd_encode.zig");
const cmd_crypt = @import("cmd_crypt.zig");
const cmd_event = @import("cmd_event.zig");
const cmd_key = @import("cmd_key.zig");
const cmd_fetch = @import("cmd_fetch.zig");
const cmd_publish = @import("cmd_publish.zig");
const cmd_req = @import("cmd_req.zig");
const cmd_verify = @import("cmd_verify.zig");

pub const RunFn = *const fn (
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) anyerror!u8;

pub const Verb = struct {
    name: []const u8,
    /// One line, shown in `deed help`.
    summary: []const u8,
    /// What `deed help <name>` prints.
    usage: []const u8,
    run: RunFn,
    /// False hides the verb from `deed help`. It still dispatches.
    ready: bool,
};

/// A row for a verb whose file exports `summary`, `usage`, `ready` and `run`.
fn fromModule(comptime name: []const u8, comptime m: type) Verb {
    return .{ .name = name, .summary = m.summary, .usage = m.usage, .run = m.run, .ready = m.ready };
}

fn runEncode(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) anyerror!u8 {
    _ = io;
    return cmd_encode.run(gpa, args, out, err);
}

fn runEncrypt(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) anyerror!u8 {
    return cmd_crypt.run(gpa, io, .encrypt, args, out, err);
}

fn runDecrypt(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) anyerror!u8 {
    return cmd_crypt.run(gpa, io, .decrypt, args, out, err);
}

/// Every verb, in the order `deed help` lists them.
pub const table = [_]Verb{
    .{ .name = "key", .summary = "generate, public, encrypt and decrypt with a password, validate, expand, mnemonics", .usage = cmd_key.usage, .run = cmd_key.run, .ready = true },
    .{ .name = "event", .summary = "build an event and sign it", .usage = cmd_event.usage, .run = cmd_event.run, .ready = true },
    .{ .name = "decode", .summary = "turn a NIP-19 code into the fields it carries", .usage = cmd_decode.usage, .run = cmd_decode.run, .ready = true },
    .{ .name = "encode", .summary = "build a NIP-19 code out of its parts", .usage = cmd_encode.usage, .run = runEncode, .ready = true },
    .{ .name = "encrypt", .summary = "encrypt a message to someone, NIP-44, or NIP-04 with --nip04", .usage = cmd_crypt.encrypt_usage, .run = runEncrypt, .ready = true },
    .{ .name = "decrypt", .summary = "decrypt a message from someone, NIP-44, or NIP-04 with --nip04", .usage = cmd_crypt.decrypt_usage, .run = runDecrypt, .ready = true },
    .{ .name = "req", .summary = "build a subscription, and run it", .usage = cmd_req.usage, .run = cmd_req.run, .ready = true },
    .{ .name = "fetch", .summary = "get the events a code names", .usage = cmd_fetch.usage, .run = cmd_fetch.run, .ready = true },
    .{ .name = "publish", .summary = "offer signed events to relays", .usage = cmd_publish.usage, .run = cmd_publish.run, .ready = true },
    .{ .name = "verify", .summary = "check that events are correctly signed", .usage = cmd_verify.usage, .run = cmd_verify.run, .ready = true },
    // Pre-registered, each in its own file. Not listed until `ready`.
    fromModule("filter", @import("cmd_filter.zig")),
    fromModule("count", @import("cmd_count.zig")),
    fromModule("kind", @import("cmd_kind.zig")),
    fromModule("relay", @import("cmd_relay.zig")),
    fromModule("relays", @import("cmd_relays.zig")),
    fromModule("gift", @import("cmd_gift.zig")),
    fromModule("bunker", @import("cmd_bunker.zig")),
    fromModule("serve", @import("cmd_serve.zig")),
    fromModule("sync", @import("cmd_sync.zig")),
    fromModule("curl", @import("cmd_curl.zig")),
    fromModule("admin", @import("cmd_admin.zig")),
    fromModule("blossom", @import("cmd_blossom.zig")),
    fromModule("post", @import("cmd_post.zig")),
    fromModule("profile", @import("cmd_profile.zig")),
    fromModule("store", @import("cmd_store.zig")),
    fromModule("spell", @import("cmd_spell.zig")),
    fromModule("mcp", @import("cmd_mcp.zig")),
    fromModule("outbox", @import("cmd_outbox.zig")),
    fromModule("nsite", @import("cmd_nsite.zig")),
    fromModule("nip", @import("cmd_nip.zig")),
    fromModule("group", @import("cmd_group.zig")),
    fromModule("podcast", @import("cmd_podcast.zig")),
    fromModule("validate", @import("cmd_validate.zig")),
    fromModule("dekey", @import("cmd_dekey.zig")),
    fromModule("git", @import("cmd_git.zig")),
};

const name_width = 10;

fn commandLines() []const u8 {
    comptime {
        var s: []const u8 = "";
        for (table) |v| {
            if (!v.ready) continue;
            s = s ++ "  " ++ v.name ++ " " ** (name_width - v.name.len) ++ v.summary ++ "\n";
        }
        return s;
    }
}

/// The text of `deed help`: the ready verbs, in table order.
pub const usage =
    "deed: the nostr command line\n" ++
    "\n" ++
    "Usage:\n" ++
    "  deed [--proxy <url>] <command> [arguments]\n" ++
    "\n" ++
    "Commands:\n" ++
    commandLines() ++
    "\n" ++
    "  help      this text, or `deed help <command>` (also -h, --help)\n" ++
    "  version   the version (also -V, --version)\n" ++
    "\n" ++
    "Every verb that takes events reads them as newline-delimited JSON on\n" ++
    "stdin when given no positional arguments, so verbs compose:\n" ++
    "\n" ++
    "  cat notes.jsonl | deed verify\n" ++
    "\n" ++
    "--proxy <url> sends web requests through an http://, socks5:// or\n" ++
    "socks5h:// proxy (socks5h for Tor). Without it, DEED_PROXY, then\n" ++
    "HTTPS_PROXY, HTTP_PROXY and ALL_PROXY are used, minus NO_PROXY.\n" ++
    "\n" ++
    "Exit codes: 0 success, 1 the command ran and failed, 2 the command was\n" ++
    "not understood.\n";

pub fn find(name: []const u8) ?*const Verb {
    for (&table) |*v| {
        if (std.mem.eql(u8, v.name, name)) return v;
    }
    return null;
}

/// Runs the verb named by `args[0]`, or the built-in help and version.
pub fn dispatch(
    gpa: std.mem.Allocator,
    io: std.Io,
    version: []const u8,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var argv = args;
    var flag: ?[]const u8 = null;
    if (argv.len > 0 and std.mem.eql(u8, argv[0], "--proxy")) {
        if (argv.len < 2) {
            try err.writeAll("deed: --proxy needs a URL, like socks5h://127.0.0.1:9050\n");
            return cli.exit_usage;
        }
        flag = argv[1];
        argv = argv[2..];
    } else if (argv.len > 0 and std.mem.startsWith(u8, argv[0], "--proxy=")) {
        flag = argv[0]["--proxy=".len..];
        argv = argv[1..];
    }
    if (flag) |f| {
        var buf: [2048]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        _ = proxy.parse(fba.allocator(), f) catch {
            try err.print("deed: --proxy: '{s}' is not a usable proxy URL (use http://, socks5:// or socks5h:// with a host and port)\n", .{f});
            return cli.exit_usage;
        };
    }
    // For this run only: a test that dispatches must not leave a proxy behind
    // for the next one.
    proxy.global = proxy.Config.fromEnv(flag);
    defer proxy.global = null;

    if (argv.len == 0) {
        try err.writeAll(usage);
        return cli.exit_usage;
    }

    const name = argv[0];
    const rest = argv[1..];

    if (cli.isOneOf(name, &.{ "help", "-h", "--help" })) {
        if (rest.len != 0) return helpFor(rest[0], out, err);
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    if (cli.isOneOf(name, &.{ "version", "-V", "--version" })) {
        try out.print("deed {s}\n", .{version});
        return cli.exit_ok;
    }
    if (find(name)) |v| return v.run(gpa, io, rest, out, err);

    try err.print("deed: unknown command '{s}'\nRun `deed help` for the list.\n", .{name});
    return cli.exit_usage;
}

pub fn helpFor(topic: []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !u8 {
    if (find(topic)) |v| {
        try out.writeAll(v.usage);
        return cli.exit_ok;
    }
    // Both are listed as commands one line above the sentence promising help
    // for any of them, so asking about either has to answer rather than refuse.
    if (cli.isOneOf(topic, &.{ "help", "version" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    try err.print("deed: no help for '{s}'\n", .{topic});
    return cli.exit_usage;
}

test "names are unique and every row is complete" {
    for (table, 0..) |v, i| {
        try std.testing.expect(v.name.len > 0 and v.name.len < name_width);
        try std.testing.expect(v.usage.len > 0);
        for (table[i + 1 ..]) |w| try std.testing.expect(!std.mem.eql(u8, v.name, w.name));
    }
}

test "the usage lists exactly the ready verbs" {
    for (table) |v| {
        var needle: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&needle, "\n  {s} ", .{v.name});
        try std.testing.expectEqual(v.ready, std.mem.indexOf(u8, usage, line) != null);
    }
}

test "every ready verb's usage states its exit codes" {
    for (table) |v| {
        if (!v.ready) continue;
        std.testing.expect(std.mem.indexOf(u8, v.usage, "Exits:") != null) catch |e| {
            std.debug.print("deed {s}: the usage has no 'Exits:' line\n", .{v.name});
            return e;
        };
    }
}

test "--proxy before the verb is checked and then left out of its arguments" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&ob);
    var err: std.Io.Writer = .fixed(&eb);
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try std.testing.expectEqual(cli.exit_usage, try dispatch(gpa, io, "0", &.{ "--proxy", "ftp://x:1", "version" }, &out, &err));
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "not a usable proxy URL") != null);
    try std.testing.expectEqual(cli.exit_usage, try dispatch(gpa, io, "0", &.{"--proxy"}, &out, &err));

    try std.testing.expectEqual(cli.exit_ok, try dispatch(gpa, io, "0", &.{ "--proxy", "socks5h://127.0.0.1:9050", "version" }, &out, &err));
    try std.testing.expectEqual(cli.exit_ok, try dispatch(gpa, io, "0", &.{ "--proxy=http://proxy.corp:3128", "version" }, &out, &err));
    try std.testing.expectEqualStrings("deed 0\ndeed 0\n", out.buffered());
    // Nothing is left set for whatever runs next.
    try std.testing.expect(proxy.global == null);
}
