//! Reading a key from a human.
//!
//! Every verb that takes a key takes it in every form a person might have it
//! in. This lives in one file so that adding a form (a bunker URL, a key
//! file) teaches every verb at once, rather than leaving one behind.

const std = @import("std");
const nostr = @import("nostr");

const keys = nostr.keys;
const nip19 = nostr.nip19;
const hex = nostr.hex;
const nip49 = nostr.nip49;
const password = @import("password.zig");

pub const Error = error{
    UnrecognizedKey,
    /// An ncryptsec whose password was wrong, or that could not be read.
    WrongPassword,
    /// No password could be had: no terminal, nothing typed, no variable.
    NoPassword,
};

/// Whether `s` starts with `prefix`, ignoring ASCII case. Bech32 allows a
/// code to be all lowercase or all uppercase (a QR code carries the uppercase
/// form), and only a mix is invalid. This sniffs the entity; the decoder keeps
/// the job of refusing a mix.
pub fn hasPrefix(s: []const u8, prefix: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(s, prefix);
}

/// Strips a leading `nostr:` (any case, URI schemes are case-insensitive).
/// Returns a slice into `s`.
pub fn stripUri(s: []const u8) []const u8 {
    const scheme = "nostr:";
    if (hasPrefix(s, scheme)) return s[scheme.len..];
    return s;
}

/// Where an ncryptsec's password comes from: the terminal, or
/// `NOSTR_PASSWORD` when that is set.
const TerminalPassword = struct {
    fn get(_: TerminalPassword, out: *password.Secret) password.Error!void {
        return password.read(out, .{ .prompt = "Password: ", .env = password.password_env });
    }
};

/// A secret key as `nsec1...`, as 64 hex characters, or as an `ncryptsec1...`
/// (NIP-49), whose password is asked for on the terminal.
///
/// Says nothing: the caller says what went wrong, in one line, and the error
/// tells a wrong password and a missing one from a bad key. A verb that
/// reports on its own writer uses `secretKeyForVerb`, which says it for it.
pub fn secretKey(gpa: std.mem.Allocator, s: []const u8) !keys.SecretKey {
    return secretKeyWith(gpa, s, TerminalPassword{});
}

/// `secretKeyWith` for a verb that reports on `err`: one line saying what is
/// wrong with the key, never two. Fails with `error.BadKey` after saying it.
///
/// A `bunker://` URI is refused here with its own line: a verb that comes
/// this way needs the key itself, and the verbs a remote signer can serve read
/// their key through `signing.open`, which takes one.
pub fn secretKeyOrSay(gpa: std.mem.Allocator, verb: []const u8, s: []const u8, source: anytype, err: *std.Io.Writer) !keys.SecretKey {
    if (isBunkerUri(s)) {
        try err.print("deed {s}: a remote signer (bunker://) cannot be used here, this needs the secret key itself\n", .{verb});
        return error.BadKey;
    }
    return secretKeyWith(gpa, s, source) catch |e| {
        switch (e) {
            Error.WrongPassword => try err.print("deed {s}: wrong password for that ncryptsec\n", .{verb}),
            Error.NoPassword => try err.print("deed {s}: an ncryptsec needs a password: run on a terminal, or set {s}\n", .{ verb, password.password_env }),
            else => try err.print("deed {s}: not a secret key (want nsec1..., ncryptsec1... or 64 hex characters)\n", .{verb}),
        }
        return error.BadKey;
    };
}

/// Whether `s` is a NIP-46 `bunker://` URI rather than a key.
pub fn isBunkerUri(s: []const u8) bool {
    return hasPrefix(std.mem.trim(u8, s, " \t\r\n"), "bunker://");
}

/// `secretKeyOrSay`, asking for an ncryptsec's password where `secretKey` does.
pub fn secretKeyForVerb(gpa: std.mem.Allocator, verb: []const u8, s: []const u8, err: *std.Io.Writer) !keys.SecretKey {
    return secretKeyOrSay(gpa, verb, s, TerminalPassword{}, err);
}

/// `secretKey` with the password source passed in, so a test can supply one.
pub fn secretKeyWith(gpa: std.mem.Allocator, s: []const u8, source: anytype) !keys.SecretKey {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (hasPrefix(t, "nsec1")) return nip19.decodeNsec(gpa, t);
    if (hasPrefix(t, "ncryptsec1")) {
        var pw: password.Secret = .{};
        defer pw.wipe();
        source.get(&pw) catch return Error.NoPassword;
        return nip49.decrypt(gpa, t, pw.slice()) catch |e| switch (e) {
            error.DecryptionFailed => Error.WrongPassword,
            else => Error.UnrecognizedKey,
        };
    }
    if (t.len == 64) return hex.decodeFixed(32, t);
    return Error.UnrecognizedKey;
}

/// A public key as `npub1...` or as 64 hex characters.
pub fn publicKey(gpa: std.mem.Allocator, s: []const u8) !keys.PublicKey {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (hasPrefix(t, "npub1")) return nip19.decodeNpub(gpa, t);
    if (t.len == 64) return hex.decodeFixed(32, t);
    return Error.UnrecognizedKey;
}

test "hex and bech32 secret keys agree" {
    const gpa = std.testing.allocator;
    const raw = [_]u8{0x11} ** 32;
    const as_hex = try hex.encode(gpa, &raw);
    defer gpa.free(as_hex);
    const as_nsec = try nip19.encodeNsec(gpa, raw);
    defer gpa.free(as_nsec);

    try std.testing.expectEqual(raw, try secretKey(gpa, as_hex));
    try std.testing.expectEqual(raw, try secretKey(gpa, as_nsec));
}

test "an unrecognized key is refused rather than guessed at" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(Error.UnrecognizedKey, secretKey(gpa, "not-a-key"));
}

test "the entity prefix and the nostr: scheme match in either case" {
    try std.testing.expect(hasPrefix("npub1abc", "npub1"));
    try std.testing.expect(hasPrefix("NPUB1ABC", "npub1"));
    try std.testing.expect(!hasPrefix("nsec1abc", "npub1"));
    try std.testing.expect(!hasPrefix("np", "npub1"));
    try std.testing.expectEqualStrings("npub1abc", stripUri("nostr:npub1abc"));
    try std.testing.expectEqualStrings("NPUB1ABC", stripUri("NOSTR:NPUB1ABC"));
    try std.testing.expectEqualStrings("NPUB1ABC", stripUri("NPUB1ABC"));
}

test "an uppercase nsec or npub is a key, and a mixed-case one is not" {
    const gpa = std.testing.allocator;
    const raw = [_]u8{0x22} ** 32;
    const nsec = try nip19.encodeNsec(gpa, raw);
    defer gpa.free(nsec);
    const npub = try nip19.encodeNpub(gpa, raw);
    defer gpa.free(npub);
    const nsec_up = try std.ascii.allocUpperString(gpa, nsec);
    defer gpa.free(nsec_up);
    const npub_up = try std.ascii.allocUpperString(gpa, npub);
    defer gpa.free(npub_up);

    try std.testing.expectEqual(raw, try secretKey(gpa, nsec_up));
    try std.testing.expectEqual(try publicKey(gpa, npub), try publicKey(gpa, npub_up));

    const mixed = try gpa.dupe(u8, npub);
    defer gpa.free(mixed);
    mixed[0] = 'N';
    try std.testing.expectError(error.MixedCase, publicKey(gpa, mixed));
}

test {
    _ = password;
}

const FixedPassword = struct {
    text: []const u8,
    fn get(self: FixedPassword, out: *password.Secret) password.Error!void {
        return password.fromText(out, self.text);
    }
};

const NoTerminal = struct {
    fn get(_: NoTerminal, _: *password.Secret) password.Error!void {
        return password.Error.NoTerminal;
    }
};

// The official NIP-49 vector: password "nostr", log_n 16.
const spec_ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
const spec_secret_hex = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";

test "an ncryptsec is read with its password, wherever a secret key is" {
    const gpa = std.testing.allocator;
    const want = try hex.decodeFixed(32, spec_secret_hex);
    try std.testing.expectEqual(want, try secretKeyWith(gpa, spec_ncryptsec, FixedPassword{ .text = "nostr" }));
}

test "a wrong password and a missing one are told apart from a bad key" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(Error.WrongPassword, secretKeyWith(gpa, spec_ncryptsec, FixedPassword{ .text = "nostR" }));
    try std.testing.expectError(Error.NoPassword, secretKeyWith(gpa, spec_ncryptsec, NoTerminal{}));
    try std.testing.expectError(Error.UnrecognizedKey, secretKeyWith(gpa, "ncryptsec1qqqq", FixedPassword{ .text = "nostr" }));
}

test "a wrong password is one line, and a bad key is one line" {
    const gpa = std.testing.allocator;
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try std.testing.expectError(error.BadKey, secretKeyOrSay(gpa, "post", spec_ncryptsec, FixedPassword{ .text = "nostR" }, &w));
    try std.testing.expectEqualStrings("deed post: wrong password for that ncryptsec\n", w.buffered());
    var w2: std.Io.Writer = .fixed(&buf);
    try std.testing.expectError(error.BadKey, secretKeyOrSay(gpa, "post", "nope", NoTerminal{}, &w2));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, w2.buffered(), "\n"));
}

test "a bunker URI is refused, in one line, where the key itself is needed" {
    const gpa = std.testing.allocator;
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try std.testing.expectError(error.BadKey, secretKeyOrSay(gpa, "key encrypt", "bunker://" ++ "ab" ** 32 ++ "?relay=wss://r.example", NoTerminal{}, &w));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, w.buffered(), "\n"));
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "remote signer") != null);
}

test "nsec and hex never ask for a password" {
    const gpa = std.testing.allocator;
    const raw = [_]u8{0x33} ** 32;
    const nsec = try nip19.encodeNsec(gpa, raw);
    defer gpa.free(nsec);
    try std.testing.expectEqual(raw, try secretKeyWith(gpa, nsec, NoTerminal{}));
    try std.testing.expectEqual(raw, try secretKeyWith(gpa, "33" ** 32, NoTerminal{}));
}
