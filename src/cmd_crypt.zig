//! `deed encrypt` and `deed decrypt`: NIP-44 payloads.
//!
//! One file for both, because they are the same command run in opposite
//! directions: the conversation key is symmetric, so the only thing that
//! differs is which way the bytes travel and what the peer flag is called.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");

const keys = nostr.keys;
const nip44 = nostr.nip44;

/// NIP-44 caps a plaintext at 65535 bytes and a payload is base64 of a little
/// more than that, so nothing legitimate comes close to this.
const max_record_bytes = 1 << 20;

pub const Direction = enum {
    encrypt,
    decrypt,

    fn verb(self: Direction) []const u8 {
        return switch (self) {
            .encrypt => "encrypt",
            .decrypt => "decrypt",
        };
    }

    /// Both name the counterparty's public key, since the conversation key
    /// is symmetric, but `--to` and `--from` are what each direction reads like.
    fn peerFlag(self: Direction) []const u8 {
        return switch (self) {
            .encrypt => "--to",
            .decrypt => "--from",
        };
    }
};

pub const encrypt_usage =
    \\deed encrypt: encrypt a message to someone, with NIP-44
    \\
    \\Usage:
    \\  deed encrypt --to <pubkey> [--sec <key>] [<message>...]
    \\
    \\Options:
    \\  --to <pubkey>   recipient, as npub1… or 64 hex characters
    \\  --sec <key>     your secret key, as nsec1… or 64 hex characters.
    \\                  Falls back to $NOSTR_SECRET_KEY.
    \\
    \\Reads messages one per line on stdin when given no arguments, and prints
    \\one base64 payload per line. A message containing newlines has to be
    \\passed as an argument, since on stdin a newline ends the message.
    \\
    \\  deed encrypt --to npub1… --sec nsec1… "meet at six"
    \\
;

pub const decrypt_usage =
    \\deed decrypt: decrypt a NIP-44 payload from someone
    \\
    \\Usage:
    \\  deed decrypt --from <pubkey> [--sec <key>] [<payload>...]
    \\
    \\Options:
    \\  --from <pubkey> sender, as npub1… or 64 hex characters
    \\  --sec <key>     your secret key, as nsec1… or 64 hex characters.
    \\                  Falls back to $NOSTR_SECRET_KEY.
    \\
    \\Reads payloads one per line on stdin when given no arguments. Prints each
    \\plaintext on its own line, so a plaintext that itself contains newlines
    \\spans several lines of output.
    \\
    \\  deed decrypt --from npub1… --sec nsec1… "AiJ…"
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: Direction,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var raw_sec: ?[]const u8 = null;
    var raw_peer: ?[]const u8 = null;
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(switch (dir) {
                .encrypt => encrypt_usage,
                .decrypt => decrypt_usage,
            });
            return cli.exit_ok;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            const is_sec = std.mem.eql(u8, a, "--sec");
            const is_peer = std.mem.eql(u8, a, dir.peerFlag());
            if (!is_sec and !is_peer) {
                try err.print("deed {s}: unknown option '{s}'\n", .{ dir.verb(), a });
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed {s}: '{s}' needs a value\n", .{ dir.verb(), a });
                return cli.exit_usage;
            }
            if (is_sec) raw_sec = args[i] else raw_peer = args[i];
            continue;
        }
        try positionals.append(gpa, a);
    }

    const sec_text = raw_sec orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.print(
            "deed {s}: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n",
            .{dir.verb()},
        );
        return cli.exit_usage;
    };
    const peer_text = raw_peer orelse {
        try err.print("deed {s}: needs {s}\n", .{ dir.verb(), dir.peerFlag() });
        return cli.exit_usage;
    };

    const sk = keyinput.secretKey(gpa, sec_text) catch {
        try err.print(
            "deed {s}: not a secret key (want nsec1… or 64 hex characters)\n",
            .{dir.verb()},
        );
        return cli.exit_fail;
    };
    const peer = keyinput.publicKey(gpa, peer_text) catch {
        try err.print(
            "deed {s}: {s} is not a public key (want npub1… or 64 hex characters)\n",
            .{ dir.verb(), dir.peerFlag() },
        );
        return cli.exit_fail;
    };

    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();

    // Derived once and reused: the conversation key depends only on the pair,
    // so a thousand messages cost one ECDH rather than a thousand. The *nonce*
    // is the part that must never be reused, and it is drawn fresh inside the
    // loop below.
    const conversation_key = nip44.conversationKey(signer, sk, peer) catch |e| {
        try err.print("deed {s}: {s}\n", .{ dir.verb(), reason(e) });
        return cli.exit_fail;
    };

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    var stdin_reader = std.Io.File.stdin().reader(io, stdin_buf);
    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    var failures: usize = 0;
    while (try input.next()) |record| {
        const text = switch (record) {
            .line => |l| l,
            .too_long => {
                try err.print(
                    "deed {s}: skipped a record longer than {d} bytes\n",
                    .{ dir.verb(), max_record_bytes },
                );
                failures += 1;
                continue;
            },
        };
        const result = switch (dir) {
            .encrypt => blk: {
                var nonce: [32]u8 = undefined;
                io.randomSecure(&nonce) catch return error.RandomFailed;
                break :blk nip44.encryptWithConversationKey(gpa, conversation_key, text, nonce);
            },
            .decrypt => nip44.decryptWithConversationKey(gpa, conversation_key, text),
        } catch |e| {
            try err.print("deed {s}: {s}\n", .{ dir.verb(), reason(e) });
            failures += 1;
            continue;
        };
        defer gpa.free(result);
        try out.print("{s}\n", .{result});
    }

    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

fn reason(e: anyerror) []const u8 {
    return switch (e) {
        // The one worth spelling out: an operator who sees this needs to know
        // it is either the wrong counterparty or a payload somebody edited,
        // and that in neither case is there a plaintext to recover.
        error.InvalidMac => "authentication failed: wrong key, or the payload was altered",
        error.InvalidPayload => "not a NIP-44 payload",
        error.InvalidPadding => "payload padding is malformed",
        error.MessageEmpty => "nothing to encrypt",
        error.MessageTooLong => "too long: NIP-44 allows 65535 bytes",
        error.InvalidPublicKey => "that public key is not a point on the curve",
        error.InvalidSecretKey => "that secret key is out of range",
        error.RandomFailed => "could not draw a nonce from the system",
        else => @errorName(e),
    };
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

test "the conversation key is the same from either side" {
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();

    const a = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
    const b = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);

    const ka = try nip44.conversationKey(signer, a.secret_key, b.public_key);
    const kb = try nip44.conversationKey(signer, b.secret_key, a.public_key);
    try std.testing.expectEqual(ka, kb);

    // Which is the property the two verbs rely on: encrypt with one, decrypt
    // with the other.
    const payload = try nip44.encryptWithConversationKey(gpa, ka, "meet at six", [_]u8{0x33} ** 32);
    defer gpa.free(payload);
    const plain = try nip44.decryptWithConversationKey(gpa, kb, payload);
    defer gpa.free(plain);
    try std.testing.expectEqualStrings("meet at six", plain);
}

test "a third party cannot read it" {
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();

    const a = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
    const b = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    const c = try signer.keyPairFromSecretKey([_]u8{0x44} ** 32);

    const ka = try nip44.conversationKey(signer, a.secret_key, b.public_key);
    const payload = try nip44.encryptWithConversationKey(gpa, ka, "private", [_]u8{0x55} ** 32);
    defer gpa.free(payload);

    const kc = try nip44.conversationKey(signer, c.secret_key, a.public_key);
    try std.testing.expectError(
        error.InvalidMac,
        nip44.decryptWithConversationKey(gpa, kc, payload),
    );
}
