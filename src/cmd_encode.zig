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
        if (std.mem.startsWith(u8, a, "--")) {
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
            } else {
                try err.print("deed encode: unknown option '{s}'\n", .{a});
                return cli.exit_usage;
            }
            continue;
        }
        try positionals.append(gpa, a);
    }

    const code = build(gpa, kind, positionals.items, opts) catch |e| {
        try err.print("deed encode: {s}\n", .{explain(e, kind)});
        return if (e == error.UnknownKind) cli.exit_usage else cli.exit_fail;
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
