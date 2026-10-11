//! `deed encrypt` and `deed decrypt`: NIP-44 payloads, or NIP-04 with `--nip04`.
//!
//! One file for both, because they are the same command run in opposite
//! directions: the conversation key is symmetric, so the only thing that
//! differs is which way the bytes travel and what the peer flag is called.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const signing = @import("signing.zig");

const keys = nostr.keys;
const nip44 = nostr.nip44;
const nip04 = nostr.nip04;

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
    \\  deed encrypt --to <pubkey> [--sec <key>] [--nip04] [<message>...]
    \\
    \\Options:
    \\  --to <pubkey>   recipient, as npub1… or 64 hex characters
    \\  --sec <key>     your secret key, as nsec1…, ncryptsec1… or 64 hex
    \\                  characters, or a remote signer as bunker://…
    \\                  Falls back to $NOSTR_SECRET_KEY.
    \\  --nip04         use legacy NIP-04 (payload ends in ?iv=…) instead of
    \\                  NIP-44. It has no authentication; use it only to talk
    \\                  to older clients.
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
    \\  deed decrypt --from <pubkey> [--sec <key>] [--nip04] [<payload>...]
    \\
    \\Options:
    \\  --from <pubkey> sender, as npub1… or 64 hex characters
    \\  --sec <key>     your secret key, as nsec1…, ncryptsec1… or 64 hex
    \\                  characters, or a remote signer as bunker://…
    \\                  Falls back to $NOSTR_SECRET_KEY.
    \\  --nip04         the payload is legacy NIP-04. A wrong key or an altered
    \\                  payload is only noticed when the padding turns out
    \\                  malformed, so a successful decrypt proves nothing.
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
    var legacy = false;
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
        // Everything after `--` is a message, whatever it starts with. Without
        // this there was no way to encrypt a line beginning with a hyphen: it
        // came back as an unknown option, which is a refusal to carry somebody's
        // words on account of their first character.
        if (std.mem.eql(u8, a, "--")) {
            i += 1;
            while (i < args.len) : (i += 1) try positionals.append(gpa, args[i]);
            break;
        }
        if (std.mem.eql(u8, a, "--nip04")) {
            legacy = true;
            continue;
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

    const peer = keyinput.publicKey(gpa, peer_text) catch {
        try err.print(
            "deed {s}: {s} is not a public key (want npub1… or 64 hex characters)\n",
            .{ dir.verb(), dir.peerFlag() },
        );
        return cli.exit_fail;
    };

    var signer = (try signing.open(gpa, io, dir.verb(), sec_text, err)) orelse return cli.exit_fail;
    defer signer.deinit();

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    // Streaming for the reason `main` gives for the writers: a positional
    // read starts at byte 0 of the file behind the descriptor and re-reads
    // records an earlier reader on the same descriptor already consumed.
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
    var input = cli.Input.init(positionals.items, &stdin_reader.interface);
    return cryptAll(gpa, io, dir, legacy, &signer, peer, &input, out, err);
}

/// Encrypts or decrypts every record of `input` and prints one result per
/// line. Returns the exit code.
fn cryptAll(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: Direction,
    legacy: bool,
    signer: *signing.Signer,
    peer: keys.PublicKey,
    input: *cli.Input,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    // Derived once and reused: the conversation key depends only on the pair,
    // so a thousand messages cost one ECDH rather than a thousand. The *nonce*
    // is the part that must never be reused, and it is drawn fresh inside the
    // loop below. A remote signer holds the key, so it does this itself, once
    // per message.
    var conversation_key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &conversation_key);
    if (signer.keyPair()) |kp| {
        if (legacy) {
            conversation_key = nip04Key(signer.ctx, kp.secret_key, peer) catch |e| {
                try err.print("deed {s}: {s}\n", .{ dir.verb(), reason(e) });
                return cli.exit_fail;
            };
        } else {
            conversation_key = nip44.conversationKey(signer.ctx, kp.secret_key, peer) catch |e| {
                try err.print("deed {s}: {s}\n", .{ dir.verb(), reason(e) });
                return cli.exit_fail;
            };
        }
    }

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
        const result = if (signer.isRemote()) remote: {
            const method: signing.Method = switch (dir) {
                .encrypt => if (legacy) .nip04_encrypt else .nip44_encrypt,
                .decrypt => if (legacy) .nip04_decrypt else .nip44_decrypt,
            };
            // A signer that refused or went quiet will do the same for the
            // next message, so the run ends here.
            break :remote signer.crypt(gpa, io, method, peer, text) catch |e|
                return signing.report(dir.verb(), e, err);
        } else switch (dir) {
            .encrypt => blk: {
                if (legacy) {
                    var iv: [16]u8 = undefined;
                    io.randomSecure(&iv) catch return error.RandomFailed;
                    break :blk nip04.encryptWithIv(gpa, conversation_key, iv, text);
                }
                var nonce: [32]u8 = undefined;
                io.randomSecure(&nonce) catch return error.RandomFailed;
                break :blk nip44.encryptWithConversationKey(gpa, conversation_key, text, nonce);
            },
            .decrypt => if (legacy)
                nip04.decryptWithKey(gpa, conversation_key, text)
            else
                nip44.decryptWithConversationKey(gpa, conversation_key, text),
        } catch |e| {
            try err.print("deed {s}: {s}\n", .{ dir.verb(), reason(e) });
            failures += 1;
            continue;
        };
        defer {
            std.crypto.secureZero(u8, result);
            gpa.free(result);
        }
        try out.print("{s}\n", .{result});
    }

    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

/// The NIP-04 key is the raw x coordinate of the shared point, symmetric like
/// the NIP-44 conversation key, so it is derived once per run as well.
fn nip04Key(signer: keys.Signer, sk: keys.SecretKey, peer: keys.PublicKey) ![32]u8 {
    return signer.sharedSecretX(sk, peer) catch |e| switch (e) {
        error.InvalidPublicKey => error.InvalidPublicKey,
        else => error.InvalidSecretKey,
    };
}

fn reason(e: anyerror) []const u8 {
    return switch (e) {
        // The one worth spelling out: an operator who sees this needs to know
        // it is either the wrong counterparty or a payload somebody edited,
        // and that in neither case is there a plaintext to recover.
        error.InvalidMac => "authentication failed: wrong key, or the payload was altered",
        error.InvalidPayload => "not a NIP-44 or NIP-04 payload (check --nip04)",
        error.InvalidIv => "the NIP-04 iv is not 16 bytes",
        error.InvalidPadding => "payload padding is malformed (with NIP-04 this is also what a wrong key looks like)",
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

test "nip04 round trip through the shared key" {
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
    const b = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);

    const ka = try nip04Key(signer, a.secret_key, b.public_key);
    const kb = try nip04Key(signer, b.secret_key, a.public_key);
    try std.testing.expectEqual(ka, kb);

    const payload = try nip04.encryptWithIv(gpa, ka, [_]u8{0x07} ** 16, "meet at six");
    defer gpa.free(payload);
    try std.testing.expect(std.mem.indexOf(u8, payload, "?iv=") != null);
    const plain = try nip04.decryptWithKey(gpa, kb, payload);
    defer gpa.free(plain);
    try std.testing.expectEqualStrings("meet at six", plain);
}

test "nip04 reads a payload made by nak" {
    // Throwaway keys, made for this test with nak v0.21.2:
    //   nak encrypt --nip04 --sec <a> --to <b-pub> "meet at six, bring tea"
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a_pub = try keyinput.publicKey(gpa, "6118e5c17cdac8bda27716e8bfea58a3e30693abd41c022b7a17e154a36863fb");
    const b_sec = try keyinput.secretKey(gpa, "9224f7229d4d67810b092013af790316598058bc71ae99b19fb291b4ad82b381");
    const key = try nip04Key(signer, b_sec, a_pub);
    const plain = try nip04.decryptWithKey(
        gpa,
        key,
        "fRKqmHQB1Z3qiWiu61VqB0tIcIRy24QiyXA0Puk/hVs=?iv=BHNqG8pTFSZUNkhBK/LtDQ==",
    );
    defer gpa.free(plain);
    try std.testing.expectEqualStrings("meet at six, bring tea", plain);
}

test "nip04 with the wrong key or a mangled payload does not yield the plaintext" {
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
    const b = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    const c = try signer.keyPairFromSecretKey([_]u8{0x44} ** 32);
    const ka = try nip04Key(signer, a.secret_key, b.public_key);
    const kc = try nip04Key(signer, c.secret_key, a.public_key);
    const payload = try nip04.encryptWithIv(gpa, ka, [_]u8{0x07} ** 16, "private");
    defer gpa.free(payload);

    if (nip04.decryptWithKey(gpa, kc, payload)) |p| {
        defer gpa.free(p);
        try std.testing.expect(!std.mem.eql(u8, p, "private"));
    } else |_| {}
    try std.testing.expectError(error.InvalidPayload, nip04.decryptWithKey(gpa, ka, "no-iv-here"));
}
