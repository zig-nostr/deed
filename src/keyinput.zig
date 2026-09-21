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

/// A secret key as `nsec1…` or as 64 hex characters.
pub fn secretKey(gpa: std.mem.Allocator, s: []const u8) !keys.SecretKey {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (std.mem.startsWith(u8, t, "nsec1")) return nip19.decodeNsec(gpa, t);
    if (t.len == 64) return hex.decodeFixed(32, t);
    return Error.UnrecognizedKey;
}

/// A public key as `npub1…` or as 64 hex characters.
pub fn publicKey(gpa: std.mem.Allocator, s: []const u8) !keys.PublicKey {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (std.mem.startsWith(u8, t, "npub1")) return nip19.decodeNpub(gpa, t);
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
