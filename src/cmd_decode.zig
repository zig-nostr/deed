//! `deed decode`: turn a NIP-19 code into the fields it carries.
//!
//! One JSON object per input, so a list of codes decodes to a stream a
//! consumer can read line by line.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");

const nip19 = nostr.nip19;
const hex = nostr.hex;
const json = @import("jsonout.zig");

/// A bech32 code no longer than this is every code anybody mints; the limit
/// exists so a pipe of the wrong thing fails rather than buffers forever.
const max_record_bytes = 64 * 1024;

pub const usage =
    \\deed decode: turn a NIP-19 code into the fields it carries
    \\
    \\Usage:
    \\  deed decode [<code>...]
    \\
    \\Accepts npub, nsec, note, nprofile, nevent, naddr and nrelay, with or
    \\without a leading `nostr:`. Reads codes one per line on stdin when given
    \\no arguments. Prints one JSON object per code.
    \\
    \\  deed decode npub1…            {"pubkey":"…"}
    \\  deed decode nevent1…          {"id":"…","relays":[…],"kind":1}
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);

    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed decode: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        try positionals.append(gpa, a);
    }

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    var stdin_reader = std.Io.File.stdin().reader(io, stdin_buf);
    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    var failures: usize = 0;
    while (try input.next()) |record| {
        const code = switch (record) {
            .line => |l| l,
            .too_long => {
                try err.print(
                    "deed decode: skipped a code longer than {d} bytes\n",
                    .{max_record_bytes},
                );
                failures += 1;
                continue;
            },
        };
        const line = decodeOne(gpa, code) catch |e| {
            try err.print("deed decode: {s}: {s}\n", .{ code, reason(e) });
            failures += 1;
            continue;
        };
        defer gpa.free(line);
        try out.print("{s}\n", .{line});
    }

    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

fn reason(e: anyerror) []const u8 {
    return switch (e) {
        error.InvalidPrefix => "not a code deed knows",
        error.WrongLength => "wrong length for its prefix",
        error.InvalidTlv => "malformed contents",
        // The rest of what bech32 decoding can say. Without these the raw Zig
        // error name reaches the reader, which names the branch taken rather
        // than the thing to do about it.
        error.InvalidChar => "not bech32: it uses a character the alphabet does not",
        error.InvalidChecksum => "the checksum does not match, so it is mistyped or truncated",
        error.InvalidLength => "too short to be a code",
        error.MixedCase => "upper and lower case mixed, which bech32 does not allow",
        error.NoSeparator => "no '1' between the prefix and the data",
        else => @errorName(e),
    };
}

/// Decodes one code into a JSON object. Caller owns the returned bytes.
fn decodeOne(gpa: std.mem.Allocator, raw: []const u8) ![]u8 {
    // `nostr:npub1…` and `npub1…` are the same code wearing different clothes.
    const code = nip19.fromNostrUri(std.mem.trim(u8, raw, " \t\r\n"));

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    try buf.append(gpa, '{');

    if (std.mem.startsWith(u8, code, "npub1")) {
        try appendHexField(&buf, gpa, "pubkey", &try nip19.decodeNpub(gpa, code), true);
    } else if (std.mem.startsWith(u8, code, "nsec1")) {
        try appendHexField(&buf, gpa, "seckey", &try nip19.decodeNsec(gpa, code), true);
    } else if (std.mem.startsWith(u8, code, "note1")) {
        try appendHexField(&buf, gpa, "id", &try nip19.decodeNote(gpa, code), true);
    } else if (std.mem.startsWith(u8, code, "nprofile1")) {
        var p = try nip19.decodeNprofile(gpa, code);
        defer p.deinit(gpa);
        try appendHexField(&buf, gpa, "pubkey", &p.pubkey, true);
        try appendRelays(&buf, gpa, p.relays, false);
    } else if (std.mem.startsWith(u8, code, "nevent1")) {
        var p = try nip19.decodeNevent(gpa, code);
        defer p.deinit(gpa);
        try appendHexField(&buf, gpa, "id", &p.id, true);
        try appendRelays(&buf, gpa, p.relays, false);
        if (p.author) |a| try appendHexField(&buf, gpa, "author", &a, false);
        if (p.kind) |k| try appendIntField(&buf, gpa, "kind", k, false);
    } else if (std.mem.startsWith(u8, code, "naddr1")) {
        var p = try nip19.decodeNaddr(gpa, code);
        defer p.deinit(gpa);
        try appendStringField(&buf, gpa, "identifier", p.identifier, true);
        try appendHexField(&buf, gpa, "pubkey", &p.pubkey, false);
        try appendIntField(&buf, gpa, "kind", p.kind, false);
        try appendRelays(&buf, gpa, p.relays, false);
    } else if (std.mem.startsWith(u8, code, "nrelay1")) {
        const url = try nip19.decodeNrelay(gpa, code);
        defer gpa.free(url);
        try appendStringField(&buf, gpa, "url", url, true);
    } else {
        return error.InvalidPrefix;
    }

    try buf.append(gpa, '}');
    return buf.toOwnedSlice(gpa);
}

fn comma(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, first: bool) !void {
    if (!first) try buf.append(gpa, ',');
}

fn appendStringField(
    buf: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    name: []const u8,
    value: []const u8,
    first: bool,
) !void {
    try comma(buf, gpa, first);
    try json.appendString(buf, gpa, name);
    try buf.append(gpa, ':');
    try json.appendString(buf, gpa, value);
}

fn appendHexField(
    buf: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    name: []const u8,
    bytes: []const u8,
    first: bool,
) !void {
    const h = try hex.encode(gpa, bytes);
    defer gpa.free(h);
    try appendStringField(buf, gpa, name, h, first);
}

fn appendIntField(
    buf: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    name: []const u8,
    value: u32,
    first: bool,
) !void {
    try comma(buf, gpa, first);
    try json.appendString(buf, gpa, name);
    try buf.print(gpa, ":{d}", .{value});
}

fn appendRelays(
    buf: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    relays: []const []const u8,
    first: bool,
) !void {
    // Always emitted, even when empty: a consumer indexing `.relays` should
    // find a list rather than have to test for the key.
    try comma(buf, gpa, first);
    try json.appendString(buf, gpa, "relays");
    try buf.appendSlice(gpa, ":[");
    for (relays, 0..) |r, i| {
        if (i != 0) try buf.append(gpa, ',');
        try json.appendString(buf, gpa, r);
    }
    try buf.append(gpa, ']');
}

test "npub decodes to its pubkey" {
    const gpa = std.testing.allocator;
    const pk = [_]u8{0xab} ** 32;
    const npub = try nip19.encodeNpub(gpa, pk);
    defer gpa.free(npub);

    const got = try decodeOne(gpa, npub);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(
        "{\"pubkey\":\"abababababababababababababababababababababababababababababababab\"}",
        got,
    );
}

test "a nostr: URI decodes the same as the bare code" {
    const gpa = std.testing.allocator;
    const npub = try nip19.encodeNpub(gpa, [_]u8{0x01} ** 32);
    defer gpa.free(npub);
    const uri = try nip19.toNostrUri(gpa, npub);
    defer gpa.free(uri);

    const a = try decodeOne(gpa, npub);
    defer gpa.free(a);
    const b = try decodeOne(gpa, uri);
    defer gpa.free(b);
    try std.testing.expectEqualStrings(a, b);
}

test "nevent carries its optional fields only when present" {
    const gpa = std.testing.allocator;
    const bare = try nip19.encodeNevent(gpa, [_]u8{0x02} ** 32, &.{}, null, null);
    defer gpa.free(bare);
    const got = try decodeOne(gpa, bare);
    defer gpa.free(got);
    try std.testing.expect(std.mem.indexOf(u8, got, "\"relays\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "author") == null);
    try std.testing.expect(std.mem.indexOf(u8, got, "kind") == null);

    const full = try nip19.encodeNevent(
        gpa,
        [_]u8{0x02} ** 32,
        &.{"wss://relay.example"},
        [_]u8{0x03} ** 32,
        1,
    );
    defer gpa.free(full);
    const got2 = try decodeOne(gpa, full);
    defer gpa.free(got2);
    try std.testing.expect(std.mem.indexOf(u8, got2, "\"kind\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, got2, "wss://relay.example") != null);
}

test "an unknown prefix is refused" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidPrefix, decodeOne(gpa, "nwhat1abc"));
}
