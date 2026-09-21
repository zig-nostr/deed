//! `deed key`: make a key, or derive the public one from it.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");

const keys = nostr.keys;
const nip19 = nostr.nip19;
const hex = nostr.hex;

pub const usage =
    \\deed key: make a key, or derive the public one from it
    \\
    \\Usage:
    \\  deed key generate [--hex]
    \\  deed key public <secret-key> [--hex]
    \\
    \\<secret-key> is a SECRET key, as nsec1… or as 64 hex characters. A bare
    \\64-character hex string is read as a secret key, never as a public one.
    \\Pasting a public key here derives a different, wrong npub without
    \\complaining.
    \\
    \\Keys print as bech32 (nsec/npub) unless --hex is given.
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try out.writeAll(usage);
        return cli.exit_usage;
    }
    const sub = args[0];
    if (cli.isOneOf(sub, &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, sub, "generate")) return generate(gpa, io, args[1..], out, err);
    if (std.mem.eql(u8, sub, "public")) return public(gpa, args[1..], out, err);

    try err.print("deed key: unknown subcommand '{s}'\n", .{sub});
    return cli.exit_usage;
}

fn generate(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var as_hex = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--hex")) {
            as_hex = true;
            continue;
        }
        try err.print("deed key generate: unknown option '{s}'\n", .{a});
        return cli.exit_usage;
    }

    // Randomized rather than plain `init`: this context mints a key that is
    // meant to hold value, so it gets the side-channel hardening.
    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(io);

    const text = if (as_hex)
        try hex.encode(gpa, &kp.secret_key)
    else
        try nip19.encodeNsec(gpa, kp.secret_key);
    defer gpa.free(text);

    try out.print("{s}\n", .{text});
    return cli.exit_ok;
}

fn public(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var as_hex = false;
    var secret: ?[]const u8 = null;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--hex")) {
            as_hex = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed key public: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        if (secret != null) {
            try err.writeAll("deed key public: takes one key\n");
            return cli.exit_usage;
        }
        secret = a;
    }

    const raw = secret orelse {
        try err.writeAll("deed key public: needs a secret key\n");
        return cli.exit_usage;
    };

    const sk = keyinput.secretKey(gpa, raw) catch {
        try err.writeAll("deed key public: not a secret key (want nsec1… or 64 hex characters)\n");
        return cli.exit_fail;
    };

    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(sk);

    const text = if (as_hex)
        try hex.encode(gpa, &kp.public_key)
    else
        try nip19.encodeNpub(gpa, kp.public_key);
    defer gpa.free(text);

    try out.print("{s}\n", .{text});
    return cli.exit_ok;
}
