//! `deed encode`: build a NIP-19 code out of its parts.
//!
//! The inverse of `deed decode`, and deliberately strict about its input: it
//! takes raw hex, because a verb whose whole job is producing bech32 should
//! not quietly accept bech32 and hand it back.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");

const nip19 = nostr.nip19;
const hex = nostr.hex;

pub const usage =
    \\deed encode: build a NIP-19 code out of its parts
    \\
    \\Usage:
    \\  deed encode npub <pubkey-hex>
    \\  deed encode nsec <seckey-hex>
    \\  deed encode note <id-hex>
    \\  deed encode nprofile <pubkey-hex> [--relay <url>]...
    \\  deed encode nevent <id-hex> [--relay <url>]... [--author <hex>] [--kind <n>]
    \\  deed encode naddr <identifier> --pubkey <hex> --kind <n> [--relay <url>]...
    \\
    \\Every key or id is 64 hex characters. --relay may be repeated.
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try out.writeAll(usage);
        return cli.exit_usage;
    }
    const kind = args[0];
    if (cli.isOneOf(kind, &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }

    var opts = Options{};
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);
    defer opts.relays.deinit(gpa);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        // A single dash introduces an option too. Testing only for `--` let
        // `-x` fall through to the positionals, where it came back as "takes
        // one positional argument" and pointed at the wrong word. Every other
        // verb tests for one dash.
        if (std.mem.startsWith(u8, a, "-")) {
            if (!cli.isOneOf(a, &.{ "--relay", "--author", "--pubkey", "--kind" })) {
                try err.print("deed encode: unknown option '{s}'\n", .{a});
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed encode: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            const v = args[i];
            if (std.mem.eql(u8, a, "--relay")) {
                try opts.relays.append(gpa, v);
            } else if (std.mem.eql(u8, a, "--author")) {
                opts.author = v;
            } else if (std.mem.eql(u8, a, "--pubkey")) {
                opts.pubkey = v;
            } else if (std.mem.eql(u8, a, "--kind")) {
                opts.kind = std.fmt.parseInt(u32, v, 10) catch {
                    try err.print("deed encode: '{s}' is not a kind number\n", .{v});
                    return cli.exit_usage;
                };
            }
            continue;
        }
        try positionals.append(gpa, a);
    }

    const code = build(gpa, kind, positionals.items, opts) catch |e| {
        try err.print("deed encode: {s}\n", .{explain(e, kind)});
        // cli.zig fixes what the two codes mean, and scripts branch on them: 2
        // when the command was not understood and nothing was attempted, 1 when
        // it ran and failed. Every `BuildError` is a malformed command line. A
        // hex string that will not parse is the other kind: the command was
        // understood and the value in it was wrong.
        return switch (e) {
            error.UnknownKind,
            error.MissingArgument,
            error.TooManyArguments,
            error.MissingPubkey,
            error.MissingKind,
            => cli.exit_usage,
            else => cli.exit_fail,
        };
    };
    defer gpa.free(code);

    try out.print("{s}\n", .{code});
    return cli.exit_ok;
}

const Options = struct {
    relays: std.ArrayList([]const u8) = .empty,
    author: ?[]const u8 = null,
    pubkey: ?[]const u8 = null,
    kind: ?u32 = null,
};

const BuildError = error{
    UnknownKind,
    MissingArgument,
    TooManyArguments,
    MissingPubkey,
    MissingKind,
};

fn explain(e: anyerror, kind: []const u8) []const u8 {
    return switch (e) {
        error.UnknownKind => "unknown code type (want npub, nsec, note, nprofile, nevent or naddr)",
        error.MissingArgument => if (std.mem.eql(u8, kind, "naddr"))
            "naddr needs an identifier"
        else
            "needs 64 hex characters",
        error.TooManyArguments => "takes one positional argument",
        error.MissingPubkey => "naddr needs --pubkey",
        error.MissingKind => "naddr needs --kind",
        error.InvalidHex => "not hex, or not 64 characters",
        else => @errorName(e),
    };
}

/// Caller owns the returned code.
fn build(
    gpa: std.mem.Allocator,
    kind: []const u8,
    positionals: []const []const u8,
    opts: Options,
) ![]u8 {
    if (positionals.len == 0) return BuildError.MissingArgument;
    if (positionals.len > 1) return BuildError.TooManyArguments;
    const arg = positionals[0];
    const relays = opts.relays.items;

    if (std.mem.eql(u8, kind, "npub")) return nip19.encodeNpub(gpa, try hex.decodeFixed(32, arg));
    if (std.mem.eql(u8, kind, "nsec")) return nip19.encodeNsec(gpa, try hex.decodeFixed(32, arg));
    if (std.mem.eql(u8, kind, "note")) return nip19.encodeNote(gpa, try hex.decodeFixed(32, arg));
    if (std.mem.eql(u8, kind, "nprofile")) {
        return nip19.encodeNprofile(gpa, try hex.decodeFixed(32, arg), relays);
    }
    if (std.mem.eql(u8, kind, "nevent")) {
        const author = if (opts.author) |a| try hex.decodeFixed(32, a) else null;
        return nip19.encodeNevent(gpa, try hex.decodeFixed(32, arg), relays, author, opts.kind);
    }
    if (std.mem.eql(u8, kind, "naddr")) {
        const pk = opts.pubkey orelse return BuildError.MissingPubkey;
        const k = opts.kind orelse return BuildError.MissingKind;
        return nip19.encodeNaddr(gpa, arg, try hex.decodeFixed(32, pk), k, relays);
    }
    return BuildError.UnknownKind;
}

test "npub round-trips through decode" {
    const gpa = std.testing.allocator;
    const code = try build(gpa, "npub", &.{"abababababababababababababababababababababababababababababababab"}, .{});
    defer gpa.free(code);
    try std.testing.expect(std.mem.startsWith(u8, code, "npub1"));
    try std.testing.expectEqual([_]u8{0xab} ** 32, try nip19.decodeNpub(gpa, code));
}

test "naddr insists on the parts it cannot invent" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(BuildError.MissingPubkey, build(gpa, "naddr", &.{"slug"}, .{}));
    try std.testing.expectError(BuildError.MissingKind, build(gpa, "naddr", &.{"slug"}, .{
        .pubkey = "abababababababababababababababababababababababababababababababab",
    }));
}

test "an unknown code type is a usage error, not a crash" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(BuildError.UnknownKind, build(gpa, "nwhat", &.{"ab"}, .{}));
}

const Run = struct { code: u8, out: []const u8, err: []const u8 };

fn runEncode(args: []const []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    const code = try run(std.testing.allocator, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

const hex32 = "abababababababababababababababababababababababababababababababab";

test "encode says 2 when the command line is wrong and 1 when the value is" {
    // cli.zig calls these part of the interface, so scripts branch on them.
    // Every malformed command line is 2; only a value that will not parse is 1.
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;

    const unknown_kind = try runEncode(&.{ "nwhat", hex32 }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, unknown_kind.code);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const missing = try runEncode(&.{"npub"}, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_usage, missing.code);

    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const too_many = try runEncode(&.{ "npub", hex32, hex32 }, &ob3, &eb3);
    try std.testing.expectEqual(cli.exit_usage, too_many.code);

    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const no_pubkey = try runEncode(&.{ "naddr", "slug", "--kind", "30023" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_usage, no_pubkey.code);

    // The command was understood; the hex in it was not a key.
    var ob5: [1024]u8 = undefined;
    var eb5: [1024]u8 = undefined;
    const bad_hex = try runEncode(&.{ "npub", "not-hex" }, &ob5, &eb5);
    try std.testing.expectEqual(cli.exit_fail, bad_hex.code);
}

test "a single-dash argument is an option, not a positional" {
    // `-x` used to fall through to the positionals and come back as "takes one
    // positional argument", which points at the wrong word entirely.
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runEncode(&.{ "npub", hex32, "-x" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "unknown option") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "-x") != null);
}

test "encode answers --help wherever it appears" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runEncode(&.{ "npub", "--help" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "deed encode") != null);
}

test "every code type it lists, it builds" {
    // The usage names six. Only npub was covered before.
    const cases = [_]struct { args: []const []const u8, prefix: []const u8 }{
        .{ .args = &.{ "npub", hex32 }, .prefix = "npub1" },
        .{ .args = &.{ "nsec", hex32 }, .prefix = "nsec1" },
        .{ .args = &.{ "note", hex32 }, .prefix = "note1" },
        .{ .args = &.{ "nprofile", hex32 }, .prefix = "nprofile1" },
        .{ .args = &.{ "nevent", hex32 }, .prefix = "nevent1" },
        .{ .args = &.{ "naddr", "slug", "--pubkey", hex32, "--kind", "30023" }, .prefix = "naddr1" },
    };
    for (cases) |c| {
        var ob: [2048]u8 = undefined;
        var eb: [1024]u8 = undefined;
        const r = try runEncode(c.args, &ob, &eb);
        try std.testing.expectEqual(cli.exit_ok, r.code);
        try std.testing.expect(std.mem.startsWith(u8, r.out, c.prefix));
    }
}
