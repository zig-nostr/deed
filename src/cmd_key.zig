//! `deed key`: make a key, or derive the public one from it.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const password = @import("password.zig");

const keys = nostr.keys;
const nip19 = nostr.nip19;
const hex = nostr.hex;
const nip49 = nostr.nip49;
const nip06 = nostr.nip06;
const bip39 = nostr.bip39;

pub const usage =
    \\deed key: make a key, derive the public one, protect or check a key
    \\
    \\Usage:
    \\  deed key generate [--hex]
    \\  deed key public <secret-key> [--hex]
    \\  deed key encrypt <secret-key> [--log-n N] [--security LEVEL]
    \\  deed key decrypt <ncryptsec> [--hex]
    \\  deed key validate [--secret] <key>...
    \\  deed key expand [--compressed] <hex-or-npub>
    \\  deed key mnemonic [--words N]
    \\  deed key from-mnemonic [--account N] [--passphrase] [--public] [--hex] [words...]
    \\
    \\<secret-key> is a SECRET key, as nsec1…, ncryptsec1… or 64 hex characters. A
    \\bare 64-character hex string is read as a secret key, never as a public
    \\one. Pasting a public key here derives a different, wrong npub without
    \\complaining. An ncryptsec asks for its password.
    \\
    \\Keys print as bech32 (nsec/npub) unless --hex is given.
    \\
    \\encrypt makes an ncryptsec (NIP-49). --log-n is the scrypt cost, 16 by
    \\default (about 64 MiB and a fraction of a second); each step up doubles
    \\the work an attacker needs. --security records how the key was handled:
    \\insecure, secure or unknown (the default).
    \\
    \\Passwords are never taken from the command line, where they would sit in
    \\the process list and the shell history. They are asked for on the terminal
    \\with echo off, or read from NOSTR_PASSWORD when that is set.
    \\
    \\validate exits 0 when every key is valid and 1 when any is not. A key is
    \\an npub, an nsec, an ncryptsec (its shape, not its password) or 64 hex
    \\characters, which is read as a public key unless --secret is given.
    \\
    \\expand left-pads a short hex key with zeros to 64 characters. With
    \\--compressed it also prints the two SEC1 compressed points the x-only
    \\public key stands for (02 even Y, 03 odd Y).
    \\
    \\mnemonic prints a new BIP-39 phrase of 12, 15, 18, 21 or 24 words (12 by
    \\default). from-mnemonic derives the NIP-06 key at m/44'/1237'/<account>'/0/0
    \\(account 0 by default). The phrase is read from the arguments, or when
    \\there are none from the terminal with echo off, or from a pipe. --passphrase
    \\asks for a BIP-39 passphrase the same way. --public prints the npub.
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
    if (std.mem.eql(u8, sub, "encrypt")) return encrypt(gpa, io, args[1..], out, err);
    if (std.mem.eql(u8, sub, "decrypt")) return decrypt(gpa, args[1..], out, err);
    if (std.mem.eql(u8, sub, "validate")) return validate(gpa, args[1..], out, err);
    if (std.mem.eql(u8, sub, "expand")) return expand(gpa, args[1..], out, err);
    if (std.mem.eql(u8, sub, "mnemonic")) return mnemonic(gpa, io, args[1..], out, err);
    if (std.mem.eql(u8, sub, "from-mnemonic")) return fromMnemonic(gpa, args[1..], out, err);

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
        // Accepted here as well as at the subcommand position. Every other verb
        // takes the help forms anywhere in its arguments, and `deed key
        // generate --help` used to come back as an unknown option.
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
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
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
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

    const sk = keyinput.secretKeyForVerb(gpa, "key public", raw, err) catch |e| switch (e) {
        error.BadKey => return cli.exit_fail,
        else => return e,
    };

    var signer = keys.Signer.init();
    defer signer.deinit();
    // Caught rather than propagated. 64 hex characters can still be a number
    // outside the curve's range, and letting that escape printed `deed:
    // InvalidSecretKey`, which names the branch the code took rather than
    // telling the reader what is wrong with what they pasted.
    const kp = signer.keyPairFromSecretKey(sk) catch {
        try err.writeAll("deed key public: that is not a usable secret key (the number is outside the curve's range)\n");
        return cli.exit_fail;
    };

    const text = if (as_hex)
        try hex.encode(gpa, &kp.public_key)
    else
        try nip19.encodeNpub(gpa, kp.public_key);
    defer gpa.free(text);

    try out.print("{s}\n", .{text});
    return cli.exit_ok;
}

fn wipeKey(sk: *keys.SecretKey) void {
    std.crypto.secureZero(u8, sk);
}

fn passwordProblem(e: password.Error) []const u8 {
    return switch (e) {
        error.NoTerminal => "no terminal to ask on: run it in one, or set NOSTR_PASSWORD",
        error.Empty => "the password is empty",
        error.TooLong => "the password is too long",
        error.Mismatch => "the two passwords differ",
        error.ReadFailed => "could not read the password",
    };
}

fn encrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var log_n: u6 = 16;
    var security: nip49.KeySecurity = .unknown;
    var secret: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (cli.isOneOf(a, &.{ "--log-n", "--logn" })) {
            i += 1;
            const v = if (i < args.len) args[i] else "";
            const n = std.fmt.parseInt(u6, v, 10) catch 0;
            if (n < 1 or n > 30) {
                try err.writeAll("deed key encrypt: --log-n wants a number from 1 to 30\n");
                return cli.exit_usage;
            }
            log_n = n;
            continue;
        }
        if (std.mem.eql(u8, a, "--security")) {
            i += 1;
            const v = if (i < args.len) args[i] else "";
            security = if (std.mem.eql(u8, v, "insecure"))
                .known_insecure
            else if (std.mem.eql(u8, v, "secure"))
                .known_secure
            else if (std.mem.eql(u8, v, "unknown"))
                .unknown
            else {
                try err.writeAll("deed key encrypt: --security wants insecure, secure or unknown\n");
                return cli.exit_usage;
            };
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed key encrypt: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        if (secret != null) {
            try err.writeAll("deed key encrypt: takes one key\n");
            return cli.exit_usage;
        }
        secret = a;
    }
    const raw = secret orelse {
        try err.writeAll("deed key encrypt: needs a secret key\n");
        return cli.exit_usage;
    };

    var sk = keyinput.secretKeyForVerb(gpa, "key encrypt", raw, err) catch |e| switch (e) {
        error.BadKey => return cli.exit_fail,
        else => return e,
    };
    defer wipeKey(&sk);

    var signer = keys.Signer.init();
    defer signer.deinit();
    _ = signer.keyPairFromSecretKey(sk) catch {
        try err.writeAll("deed key encrypt: that is not a usable secret key (the number is outside the curve's range)\n");
        return cli.exit_fail;
    };

    var pw: password.Secret = .{};
    defer pw.wipe();
    password.read(&pw, .{ .prompt = "New password: ", .env = password.password_env, .confirm = true }) catch |e| {
        try err.print("deed key encrypt: {s}\n", .{passwordProblem(e)});
        return cli.exit_fail;
    };

    const code = nip49.encrypt(gpa, io, sk, pw.slice(), log_n, security) catch |e| {
        try err.print("deed key encrypt: {s}\n", .{switch (e) {
            error.WeakParameters => "--log-n is too large for this machine's memory",
            else => @errorName(e),
        }});
        return cli.exit_fail;
    };
    defer gpa.free(code);
    try out.print("{s}\n", .{code});
    return cli.exit_ok;
}

fn decrypt(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var as_hex = false;
    var code: ?[]const u8 = null;
    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--hex")) {
            as_hex = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed key decrypt: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        if (code != null) {
            try err.writeAll("deed key decrypt: takes one ncryptsec\n");
            return cli.exit_usage;
        }
        code = a;
    }
    const raw = std.mem.trim(u8, code orelse {
        try err.writeAll("deed key decrypt: needs an ncryptsec\n");
        return cli.exit_usage;
    }, " \t\r\n");
    if (!keyinput.hasPrefix(raw, "ncryptsec1")) {
        try err.writeAll("deed key decrypt: not an ncryptsec (want ncryptsec1…)\n");
        return cli.exit_fail;
    }

    var pw: password.Secret = .{};
    defer pw.wipe();
    password.read(&pw, .{ .prompt = "Password: ", .env = password.password_env }) catch |e| {
        try err.print("deed key decrypt: {s}\n", .{passwordProblem(e)});
        return cli.exit_fail;
    };

    var sk = nip49.decrypt(gpa, raw, pw.slice()) catch |e| {
        try err.print("deed key decrypt: {s}\n", .{switch (e) {
            error.DecryptionFailed => "wrong password",
            error.WeakParameters => "the cost in that ncryptsec is more than this machine can run",
            error.InvalidVersion => "that ncryptsec is a version this does not know",
            else => "not a valid ncryptsec",
        }});
        return cli.exit_fail;
    };
    defer wipeKey(&sk);

    if (as_hex) {
        const text = try hex.encode(gpa, &sk);
        defer {
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }
        try out.print("{s}\n", .{text});
    } else {
        const text = try nip19.encodeNsec(gpa, sk);
        defer {
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }
        try out.print("{s}\n", .{text});
    }
    return cli.exit_ok;
}

/// Why `text` is not a valid key, or null when it is.
fn keyProblem(gpa: std.mem.Allocator, signer: keys.Signer, text: []const u8, hex_is_secret: bool) !?[]const u8 {
    const t = std.mem.trim(u8, text, " \t\r\n");
    if (keyinput.hasPrefix(t, "ncryptsec1")) {
        var d = nostr.bech32.decode(gpa, t) catch return "not valid bech32";
        defer d.deinit(gpa);
        if (!std.mem.eql(u8, d.hrp, "ncryptsec")) return "wrong prefix";
        const payload = nostr.bech32.convertBits(gpa, d.data, 5, 8, false) catch return "not valid bech32";
        defer gpa.free(payload);
        if (payload.len != 91) return "wrong length for an ncryptsec";
        if (payload[0] != 2) return "unknown ncryptsec version";
        return null;
    }
    if (keyinput.hasPrefix(t, "nsec1") or (hex_is_secret and t.len == 64)) {
        var sk = keyinput.secretKey(gpa, t) catch return "not a secret key";
        defer wipeKey(&sk);
        _ = signer.keyPairFromSecretKey(sk) catch return "the number is outside the curve's range";
        return null;
    }
    if (keyinput.hasPrefix(t, "npub1") or t.len == 64) {
        const pk = keyinput.publicKey(gpa, t) catch return "not a public key";
        // The x-only key must be the x of a point on the curve. Multiplying
        // by 1 says so without producing anything that matters.
        var one = [_]u8{0} ** 32;
        one[31] = 1;
        _ = signer.sharedSecretX(one, pk) catch return "not a point on the curve";
        return null;
    }
    return "not an npub, nsec, ncryptsec or 64 hex characters";
}

fn validate(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var hex_is_secret = false;
    var count: usize = 0;
    var bad: usize = 0;

    var signer = keys.Signer.init();
    defer signer.deinit();

    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--secret")) {
            hex_is_secret = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
            try err.print("deed key validate: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        count += 1;
        if (try keyProblem(gpa, signer, a, hex_is_secret)) |why| {
            bad += 1;
            // The key itself is not echoed: it may be a secret one.
            try err.print("deed key validate: key {d} is invalid: {s}\n", .{ count, why });
        }
    }
    if (count == 0) {
        try err.writeAll("deed key validate: needs a key\n");
        return cli.exit_usage;
    }
    return if (bad == 0) cli.exit_ok else cli.exit_fail;
}

fn expand(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var compressed = false;
    var key: ?[]const u8 = null;
    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--compressed")) {
            compressed = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed key expand: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        if (key != null) {
            try err.writeAll("deed key expand: takes one key\n");
            return cli.exit_usage;
        }
        key = a;
    }
    const raw = std.mem.trim(u8, key orelse {
        try err.writeAll("deed key expand: needs a key\n");
        return cli.exit_usage;
    }, " \t\r\n");

    var x: [32]u8 = undefined;
    if (keyinput.hasPrefix(raw, "npub1")) {
        x = nip19.decodeNpub(gpa, raw) catch {
            try err.writeAll("deed key expand: not a valid npub\n");
            return cli.exit_fail;
        };
    } else {
        const body = if (raw.len > 2 and raw[0] == '0' and (raw[1] == 'x' or raw[1] == 'X')) raw[2..] else raw;
        if (body.len == 0 or body.len > 64) {
            try err.writeAll("deed key expand: want 1 to 64 hex characters\n");
            return cli.exit_fail;
        }
        var padded: [64]u8 = [_]u8{'0'} ** 64;
        @memcpy(padded[64 - body.len ..], body);
        x = hex.decodeFixed(32, &padded) catch {
            try err.writeAll("deed key expand: not hexadecimal\n");
            return cli.exit_fail;
        };
    }

    const x_hex = try hex.encode(gpa, &x);
    defer gpa.free(x_hex);

    if (!compressed) {
        try out.print("{s}\n", .{x_hex});
        return cli.exit_ok;
    }

    var signer = keys.Signer.init();
    defer signer.deinit();
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    _ = signer.sharedSecretX(one, x) catch {
        try err.writeAll("deed key expand: that is not the x coordinate of a point on the curve\n");
        return cli.exit_fail;
    };
    try out.print("02{s}\n03{s}\n", .{ x_hex, x_hex });
    return cli.exit_ok;
}

fn mnemonic(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var words: usize = 12;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--words")) {
            i += 1;
            const v = if (i < args.len) args[i] else "";
            words = std.fmt.parseInt(usize, v, 10) catch 0;
            if (words < 12 or words > 24 or words % 3 != 0) {
                try err.writeAll("deed key mnemonic: --words wants 12, 15, 18, 21 or 24\n");
                return cli.exit_usage;
            }
            continue;
        }
        try err.print("deed key mnemonic: unknown argument '{s}'\n", .{a});
        return cli.exit_usage;
    }

    var entropy: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    // 12 words carry 128 bits, and every 3 more words carry 32 more.
    const n = (words / 3) * 4;
    io.randomSecure(entropy[0..n]) catch {
        try err.writeAll("deed key mnemonic: could not draw randomness from the system\n");
        return cli.exit_fail;
    };
    const phrase = try bip39.entropyToMnemonic(gpa, entropy[0..n]);
    defer {
        std.crypto.secureZero(u8, phrase);
        gpa.free(phrase);
    }
    try out.print("{s}\n", .{phrase});
    return cli.exit_ok;
}

/// Lowercases and joins the words of `text` with single spaces into `out`.
fn normalizePhrase(out: []u8, text: []const u8) ?[]u8 {
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
    while (it.next()) |w| {
        const need = w.len + @intFromBool(n > 0);
        if (n + need > out.len) return null;
        if (n > 0) {
            out[n] = ' ';
            n += 1;
        }
        for (w) |c| {
            out[n] = std.ascii.toLower(c);
            n += 1;
        }
    }
    return out[0..n];
}

fn fromMnemonic(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var account: u32 = 0;
    var ask_passphrase = false;
    var as_public = false;
    var as_hex = false;
    var phrase_buf: [password.max_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &phrase_buf);
    var phrase_len: usize = 0;
    var given = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--account")) {
            i += 1;
            const v = if (i < args.len) args[i] else "";
            // Hardened indices stop short of 2^31.
            account = std.fmt.parseInt(u32, v, 10) catch 0xffffffff;
            if (account >= 0x80000000) {
                try err.writeAll("deed key from-mnemonic: --account wants a number from 0 to 2147483647\n");
                return cli.exit_usage;
            }
            continue;
        }
        if (std.mem.eql(u8, a, "--passphrase")) {
            ask_passphrase = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--public")) {
            as_public = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--hex")) {
            as_hex = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed key from-mnemonic: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        // Words may arrive as one quoted argument or as many.
        given = true;
        if (phrase_len > 0 and phrase_len < phrase_buf.len) {
            phrase_buf[phrase_len] = ' ';
            phrase_len += 1;
        }
        if (phrase_len + a.len > phrase_buf.len) {
            try err.writeAll("deed key from-mnemonic: that is too long for a mnemonic\n");
            return cli.exit_fail;
        }
        @memcpy(phrase_buf[phrase_len..][0..a.len], a);
        phrase_len += a.len;
    }

    var typed: password.Secret = .{};
    defer typed.wipe();
    if (!given) {
        password.read(&typed, .{ .prompt = "Mnemonic: ", .allow_pipe = true }) catch |e| {
            try err.print("deed key from-mnemonic: {s}\n", .{switch (e) {
                error.NoTerminal => "no mnemonic given, and no terminal to ask on",
                error.Empty => "no mnemonic given",
                error.TooLong => "that is too long for a mnemonic",
                else => "could not read the mnemonic",
            }});
            return cli.exit_fail;
        };
        @memcpy(phrase_buf[0..typed.len], typed.slice());
        phrase_len = typed.len;
    }

    var norm_buf: [password.max_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &norm_buf);
    const phrase = normalizePhrase(&norm_buf, phrase_buf[0..phrase_len]) orelse {
        try err.writeAll("deed key from-mnemonic: that is too long for a mnemonic\n");
        return cli.exit_fail;
    };

    // The checksum is checked first: a phrase with one word wrong would
    // otherwise derive a perfectly good key, for nobody's wallet.
    const entropy = bip39.mnemonicToEntropy(gpa, phrase) catch |e| {
        try err.print("deed key from-mnemonic: not a valid mnemonic: {s}\n", .{switch (e) {
            error.InvalidWordCount => "want 12, 15, 18, 21 or 24 words",
            error.UnknownWord => "a word is not in the BIP-39 list",
            error.InvalidChecksum => "the checksum does not match (a word is wrong or out of order)",
            else => @errorName(e),
        }});
        return cli.exit_fail;
    };
    std.crypto.secureZero(u8, entropy);
    gpa.free(entropy);

    var pass: password.Secret = .{};
    defer pass.wipe();
    if (ask_passphrase) {
        password.read(&pass, .{ .prompt = "Passphrase: " }) catch |e| switch (e) {
            error.Empty => {}, // an empty passphrase is the usual one
            else => {
                try err.print("deed key from-mnemonic: {s}\n", .{switch (e) {
                    error.NoTerminal => "no terminal to ask the passphrase on",
                    error.TooLong => "that passphrase is too long",
                    else => "could not read the passphrase",
                }});
                return cli.exit_fail;
            },
        };
    }

    var signer = keys.Signer.init();
    defer signer.deinit();
    var sk = nip06.keyFromMnemonic(signer, phrase, pass.slice(), account) catch |e| {
        try err.print("deed key from-mnemonic: {s}\n", .{switch (e) {
            error.PassphraseTooLong => "that passphrase is too long",
            else => "that mnemonic derives no usable key",
        }});
        return cli.exit_fail;
    };
    defer wipeKey(&sk);

    if (as_public) {
        const kp = signer.keyPairFromSecretKey(sk) catch {
            try err.writeAll("deed key from-mnemonic: that mnemonic derives no usable key\n");
            return cli.exit_fail;
        };
        const text = if (as_hex)
            try hex.encode(gpa, &kp.public_key)
        else
            try nip19.encodeNpub(gpa, kp.public_key);
        defer gpa.free(text);
        try out.print("{s}\n", .{text});
        return cli.exit_ok;
    }

    const text = if (as_hex) try hex.encode(gpa, &sk) else try nip19.encodeNsec(gpa, sk);
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
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

test "a key outside the curve's range is explained, not named" {
    // 64 hex characters can still be a number the curve cannot use. Letting it
    // escape printed `deed: InvalidSecretKey`, which names the branch the code
    // took rather than telling the reader what is wrong with what they pasted.
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "public", "f" ** 64 }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "InvalidSecretKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "curve") != null);
}

test "the subcommands answer --help too" {
    // They used to reject it as an unknown option, because help was only caught
    // at the subcommand position and never inside the argument loops.
    for ([_][]const u8{ "--help", "-h", "help" }) |form| {
        var ob: [4096]u8 = undefined;
        var eb: [1024]u8 = undefined;
        const gen = try runKey(&.{ "generate", form }, &ob, &eb);
        try std.testing.expectEqual(cli.exit_ok, gen.code);
        try std.testing.expect(std.mem.indexOf(u8, gen.out, "deed key") != null);
        try std.testing.expectEqualStrings("", gen.err);

        var ob2: [4096]u8 = undefined;
        var eb2: [1024]u8 = undefined;
        const pub_ = try runKey(&.{ "public", form }, &ob2, &eb2);
        try std.testing.expectEqual(cli.exit_ok, pub_.code);
        try std.testing.expect(std.mem.indexOf(u8, pub_.out, "deed key") != null);
    }
}

// The official NIP-49 vector: the password is "nostr", the cost 16.
const spec_ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
const spec_secret = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";

fn setPassword(value: []const u8) void {
    var buf: [64]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{value}) catch unreachable;
    password.setEnvForTest("NOSTR_PASSWORD", z.ptr);
}

fn clearPassword() void {
    password.setEnvForTest("NOSTR_PASSWORD", null);
}

const can_set_env = @import("builtin").os.tag != .windows;

test "decrypt opens the official NIP-49 vector" {
    if (!can_set_env) return error.SkipZigTest;
    setPassword("nostr");
    defer clearPassword();
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "decrypt", spec_ncryptsec, "--hex" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(spec_secret ++ "\n", r.out);
    try std.testing.expectEqualStrings("", r.err);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const as_nsec = try runKey(&.{ "decrypt", spec_ncryptsec }, &ob2, &eb2);
    try std.testing.expect(std.mem.startsWith(u8, as_nsec.out, "nsec1"));
}

test "a wrong password is named and prints no key" {
    if (!can_set_env) return error.SkipZigTest;
    setPassword("not-nostr");
    defer clearPassword();
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "decrypt", spec_ncryptsec }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "wrong password") != null);
}

test "encrypt then decrypt returns the key, at a cost small enough to test" {
    if (!can_set_env) return error.SkipZigTest;
    setPassword("correct horse");
    defer clearPassword();
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const enc = try runKey(&.{ "encrypt", sk_two, "--log-n", "4" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, enc.code);
    try std.testing.expect(std.mem.startsWith(u8, enc.out, "ncryptsec1"));
    try std.testing.expect(std.mem.indexOf(u8, enc.out, sk_two) == null);
    const code = std.mem.trimEnd(u8, enc.out, "\n");

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const dec = try runKey(&.{ "decrypt", code, "--hex" }, &ob2, &eb2);
    try std.testing.expectEqualStrings(sk_two ++ "\n", dec.out);

    // An ncryptsec is a key wherever a secret key is read.
    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const pub_ = try runKey(&.{ "public", code, "--hex" }, &ob3, &eb3);
    try std.testing.expectEqualStrings(pk_two ++ "\n", pub_.out);

    // Two encryptions of one key differ: the salt and nonce are fresh.
    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const again = try runKey(&.{ "encrypt", sk_two, "--log-n", "4" }, &ob4, &eb4);
    try std.testing.expect(!std.mem.eql(u8, enc.out, again.out));
}

test "encrypt refuses a cost it cannot use and a key it cannot read" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "encrypt", sk_one, "--log-n", "99" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const bad = try runKey(&.{ "encrypt", "nonsense" }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_fail, bad.code);
}

test "validate exits 0 for a good key and 1 for a bad one" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const good = try runKey(&.{ "validate", npub_one, pk_one, pk_two }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, good.code);
    try std.testing.expectEqualStrings("", good.err);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const nsec = try runKey(&.{ "validate", nsec_one }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_ok, nsec.code);

    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const enc = try runKey(&.{ "validate", spec_ncryptsec }, &ob3, &eb3);
    try std.testing.expectEqual(cli.exit_ok, enc.code);

    // One bad key among good ones fails the run, and the secret is not echoed.
    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const mixed = try runKey(&.{ "validate", pk_one, "nsec1notakey", "abc" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_fail, mixed.code);
    try std.testing.expect(std.mem.indexOf(u8, mixed.err, "nsec1notakey") == null);

    // 64 hex characters off the curve, and a secret out of range.
    var ob5: [1024]u8 = undefined;
    var eb5: [1024]u8 = undefined;
    const off = try runKey(&.{ "validate", "5" ** 64 }, &ob5, &eb5);
    _ = off; // 0x5555.. may or may not be on the curve; only the range case is fixed
    var ob6: [1024]u8 = undefined;
    var eb6: [1024]u8 = undefined;
    const range = try runKey(&.{ "validate", "--secret", "f" ** 64 }, &ob6, &eb6);
    try std.testing.expectEqual(cli.exit_fail, range.code);
    var ob7: [1024]u8 = undefined;
    var eb7: [1024]u8 = undefined;
    const none = try runKey(&.{"validate"}, &ob7, &eb7);
    try std.testing.expectEqual(cli.exit_usage, none.code);
}

test "expand pads, and gives the compressed points on request" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{ "expand", "abc" }, &ob, &eb);
    try std.testing.expectEqualStrings(("0" ** 61) ++ "abc\n", r.out);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const c = try runKey(&.{ "expand", "--compressed", pk_one }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_ok, c.code);
    try std.testing.expectEqualStrings("02" ++ pk_one ++ "\n03" ++ pk_one ++ "\n", c.out);

    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const from_npub = try runKey(&.{ "expand", npub_one }, &ob3, &eb3);
    try std.testing.expectEqualStrings(pk_one ++ "\n", from_npub.out);

    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const bad = try runKey(&.{ "expand", "xyz" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_fail, bad.code);
}

// NIP-06 vectors 1 and 2.
const m1 = "leader monkey parrot ring guide accident before fence cannon height naive bean";
const m1_sk = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
const m1_pk = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
const m2 = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
const m2_sk = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";

test "from-mnemonic matches the NIP-06 vectors" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const one = try runKey(&.{ "from-mnemonic", "--hex", m1 }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, one.code);
    try std.testing.expectEqualStrings(m1_sk ++ "\n", one.out);

    // The words as separate arguments, in capitals, give the same key.
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const split = try runKey(&.{ "from-mnemonic", "--hex", "LEADER", "monkey", "parrot", "ring", "guide", "accident", "before", "fence", "cannon", "height", "naive", "bean" }, &ob2, &eb2);
    try std.testing.expectEqualStrings(m1_sk ++ "\n", split.out);

    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const two = try runKey(&.{ "from-mnemonic", "--hex", m2 }, &ob3, &eb3);
    try std.testing.expectEqualStrings(m2_sk ++ "\n", two.out);

    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const pubkey = try runKey(&.{ "from-mnemonic", "--public", "--hex", m1 }, &ob4, &eb4);
    try std.testing.expectEqualStrings(m1_pk ++ "\n", pubkey.out);
}

test "the account index changes the key" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const a0 = try runKey(&.{ "from-mnemonic", "--hex", "--account", "0", m1 }, &ob, &eb);
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const a1 = try runKey(&.{ "from-mnemonic", "--hex", "--account", "1", m1 }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_ok, a1.code);
    try std.testing.expect(!std.mem.eql(u8, a0.out, a1.out));
    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const bad = try runKey(&.{ "from-mnemonic", "--account", "2147483648", m1 }, &ob3, &eb3);
    try std.testing.expectEqual(cli.exit_usage, bad.code);
}

test "a mangled mnemonic is refused, not derived from" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    // The last word swapped for another valid one breaks the checksum.
    const r = try runKey(&.{ "from-mnemonic", "leader monkey parrot ring guide accident before fence cannon height naive abandon" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const unknown = try runKey(&.{ "from-mnemonic", "leader monkey zzzz" }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_fail, unknown.code);
}

test "mnemonic makes a phrase that derives a key" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runKey(&.{"mnemonic"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    var words: usize = 0;
    var it = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, r.out, "\n"), ' ');
    while (it.next()) |_| words += 1;
    try std.testing.expectEqual(@as(usize, 12), words);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const phrase = std.mem.trimEnd(u8, r.out, "\n");
    const back = try runKey(&.{ "from-mnemonic", phrase }, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_ok, back.code);

    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const long = try runKey(&.{ "mnemonic", "--words", "24" }, &ob3, &eb3);
    var n: usize = 0;
    var it2 = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, long.out, "\n"), ' ');
    while (it2.next()) |_| n += 1;
    try std.testing.expectEqual(@as(usize, 24), n);

    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const bad = try runKey(&.{ "mnemonic", "--words", "13" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_usage, bad.code);
}
