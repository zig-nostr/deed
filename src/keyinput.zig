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

pub const Error = error{UnrecognizedKey};

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

/// A secret key as `nsec1…` or as 64 hex characters.
pub fn secretKey(gpa: std.mem.Allocator, s: []const u8) !keys.SecretKey {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (hasPrefix(t, "nsec1")) return nip19.decodeNsec(gpa, t);
    if (t.len == 64) return hex.decodeFixed(32, t);
    return Error.UnrecognizedKey;
}

/// A public key as `npub1…` or as 64 hex characters.
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
