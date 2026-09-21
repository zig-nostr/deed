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

// Secret key 1 derives the secp256k1 generator point, and secret key 2 derives
// 2G. Both are fixed by the curve rather than by any implementation, so they are
// answers this code does not get a vote on. That is the point of using them:
// deriving the expectation from the same function under test would pass just as
// happily if the function returned the secret key instead.
const sk_one = "0000000000000000000000000000000000000000000000000000000000000001";
const pk_one = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const nsec_one = "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl";
const npub_one = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d";
const sk_two = "0000000000000000000000000000000000000000000000000000000000000002";
const pk_two = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

const Run = struct { code: u8, out: []const u8, err: []const u8 };

fn runKey(args: []const []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    const code = try run(std.testing.allocator, std.testing.io, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

test "key public derives the public key the curve says it should" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "public", sk_one, "--hex" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(pk_one ++ "\n", r.out);
    try std.testing.expectEqualStrings("", r.err);
}

test "and for a second vector, so a constant is not being echoed back" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "public", sk_two, "--hex" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(pk_two ++ "\n", r.out);
}

test "the secret key never reaches the output" {
    // The mistake worth guarding: printing the secret where the public key
    // belongs looks like success, and nothing else here would notice.
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    for ([_][]const u8{ sk_one, nsec_one }) |form| {
        const r = try runKey(&.{ "public", form }, &ob, &eb);
        try std.testing.expectEqual(cli.exit_ok, r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.out, sk_one) == null);
        try std.testing.expect(std.mem.indexOf(u8, r.out, nsec_one) == null);
        try std.testing.expect(std.mem.indexOf(u8, r.err, sk_one) == null);
        try std.testing.expect(std.mem.indexOf(u8, r.err, nsec_one) == null);
    }
}

test "an nsec and its hex are the same key" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const from_hex = try runKey(&.{ "public", sk_one }, &ob, &eb);
    try std.testing.expectEqualStrings(npub_one ++ "\n", from_hex.out);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const from_nsec = try runKey(&.{ "public", nsec_one }, &ob2, &eb2);
    try std.testing.expectEqualStrings(npub_one ++ "\n", from_nsec.out);
}

test "key generate makes a key, and a different one each time" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const first = try runKey(&.{"generate"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, first.code);
    try std.testing.expect(std.mem.startsWith(u8, first.out, "nsec1"));

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const second = try runKey(&.{"generate"}, &ob2, &eb2);
    try std.testing.expect(!std.mem.eql(u8, first.out, second.out));

    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const as_hex = try runKey(&.{ "generate", "--hex" }, &ob3, &eb3);
    try std.testing.expectEqual(@as(usize, 65), as_hex.out.len); // 64 + newline
    for (as_hex.out[0..64]) |c| try std.testing.expect(std.ascii.isHex(c));
}

test "the ways of asking wrongly are told apart" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;

    // No key at all is a usage error: nothing was attempted.
    const missing = try runKey(&.{"public"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, missing.code);
    try std.testing.expectEqualStrings("", missing.out);
    try std.testing.expect(missing.err.len > 0);

    // A key that cannot be read is a failure: it was attempted and did not work.
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const unreadable = try runKey(&.{ "public", "not-a-key" }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_fail, unreadable.code);
    try std.testing.expectEqualStrings("", unreadable.out);

    // An unknown subcommand is a usage error.
    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const unknown = try runKey(&.{"halve"}, &ob3, &eb3);
    try std.testing.expectEqual(cli.exit_usage, unknown.code);

    // So is an option the subcommand does not take.
    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const bad_opt = try runKey(&.{ "public", sk_one, "--octal" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_usage, bad_opt.code);
}

test "help is printed on stdout and succeeds" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{"--help"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "deed key") != null);
    try std.testing.expectEqualStrings("", r.err);
}
