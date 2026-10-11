//! `deed decode`: turn a NIP-19 code into the fields it carries.
//!
//! One JSON object per input, so a list of codes decodes to a stream a
//! consumer can read line by line.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");

const nip19 = nostr.nip19;
const hex = nostr.hex;
const json = @import("jsonout.zig");
const http = @import("http.zig");

const nip05 = nostr.nip05;

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
    \\without a leading `nostr:`, in lower case or all upper case (the form a
    \\QR code carries). Reads codes one per line on stdin when given no
    \\arguments. Prints one JSON object per code.
    \\
    \\A NIP-05 identifier (name@domain, or a bare domain, which means _@domain)
    \\is looked up over https and prints what an nprofile would: the pubkey and
    \\the relays the domain lists for it. A redirect is an error, as NIP-05
    \\requires. A domain on this machine (localhost, 127.x.x.x, ::1) is asked
    \\over plain http.
    \\
    \\  deed decode npub1...            {"pubkey":"..."}
    \\  deed decode nevent1...          {"id":"...","relays":[...],"kind":1}
    \\  deed decode bob@example.com   {"pubkey":"...","relays":[...]}
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
    // Streaming for the reason `main` gives for the writers: a positional
    // read starts at byte 0 of the file behind the descriptor and re-reads
    // records an earlier reader on the same descriptor already consumed.
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    var failures: usize = 0;
    while (try input.next()) |record| {
        const code = switch (record) {
            // Trimmed here rather than in `Input`: surrounding space around
            // a code is noise, and `deed encrypt` needs the same bytes it was given.
            .line => |l| std.mem.trim(u8, l, " \t"),
            .too_long => {
                try err.print(
                    "deed decode: skipped a code longer than {d} bytes\n",
                    .{max_record_bytes},
                );
                failures += 1;
                continue;
            },
        };
        const line = decodeOne(gpa, io, code) catch |e| {
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
        // NIP-05.
        error.EmptyName => "the name before @ is empty",
        error.NameTooLong => "the name is too long",
        error.InvalidNameChar => "the name may only use a-z, 0-9, - _ and .",
        error.EmptyDomain => "no domain",
        error.DomainTooLong => "the domain is too long",
        error.InvalidDomain => "not a valid domain",
        error.NameNotFound => "the domain does not list that name",
        error.InvalidPubkey => "the domain lists a pubkey that is not 64 lower case hex characters",
        error.InvalidJson => "the domain's reply is not JSON in the NIP-05 shape",
        error.BadStatus => "the domain answered with an HTTP error",
        error.TooManyRedirects => "the domain redirected, which NIP-05 does not allow",
        error.InsecureScheme, error.UnsupportedScheme, error.InvalidUrl, error.InvalidHeader, error.BodyNotAllowed, error.RedirectInvalid, error.RedirectNeedsResend, error.ResponseTooLarge, error.UnsupportedEncoding, error.TimedOut, error.HostNotFound, error.ConnectionRefused, error.ConnectFailed, error.TlsFailed, error.RequestFailed, error.SinkFailed, error.ConcurrencyUnavailable => |h| http.describe(h),
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
fn decodeOne(gpa: std.mem.Allocator, io: std.Io, raw: []const u8) ![]u8 {
    // `nostr:npub1...` and `npub1...` are the same code wearing different clothes.
    const code = keyinput.stripUri(std.mem.trim(u8, raw, " \t\r\n"));

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    try buf.append(gpa, '{');

    if (isNip05(code)) {
        var r = try resolveNip05(gpa, io, code);
        defer r.deinit();
        try appendHexField(&buf, gpa, "pubkey", &r.pubkey, true);
        try appendRelays(&buf, gpa, r.relays, false);
    } else if (keyinput.hasPrefix(code, "npub1")) {
        try appendHexField(&buf, gpa, "pubkey", &try nip19.decodeNpub(gpa, code), true);
    } else if (keyinput.hasPrefix(code, "nsec1")) {
        try appendHexField(&buf, gpa, "seckey", &try nip19.decodeNsec(gpa, code), true);
    } else if (keyinput.hasPrefix(code, "note1")) {
        try appendHexField(&buf, gpa, "id", &try nip19.decodeNote(gpa, code), true);
    } else if (keyinput.hasPrefix(code, "nprofile1")) {
        var p = try nip19.decodeNprofile(gpa, code);
        defer p.deinit(gpa);
        try appendHexField(&buf, gpa, "pubkey", &p.pubkey, true);
        try appendRelays(&buf, gpa, p.relays, false);
    } else if (keyinput.hasPrefix(code, "nevent1")) {
        var p = try nip19.decodeNevent(gpa, code);
        defer p.deinit(gpa);
        try appendHexField(&buf, gpa, "id", &p.id, true);
        try appendRelays(&buf, gpa, p.relays, false);
        if (p.author) |a| try appendHexField(&buf, gpa, "author", &a, false);
        if (p.kind) |k| try appendIntField(&buf, gpa, "kind", k, false);
    } else if (keyinput.hasPrefix(code, "naddr1")) {
        var p = try nip19.decodeNaddr(gpa, code);
        defer p.deinit(gpa);
        try appendStringField(&buf, gpa, "identifier", p.identifier, true);
        try appendHexField(&buf, gpa, "pubkey", &p.pubkey, false);
        try appendIntField(&buf, gpa, "kind", p.kind, false);
        try appendRelays(&buf, gpa, p.relays, false);
    } else if (keyinput.hasPrefix(code, "nrelay1")) {
        const url = try nip19.decodeNrelay(gpa, code);
        defer gpa.free(url);
        try appendStringField(&buf, gpa, "url", url, true);
    } else {
        return error.InvalidPrefix;
    }

    try buf.append(gpa, '}');
    return buf.toOwnedSlice(gpa);
}

/// True when `text` is written like a NIP-05 identifier rather than a bech32
/// code. Bech32 never holds an `@`, a `.` or a `:`, so any of them settles it.
pub fn isNip05(text: []const u8) bool {
    return std.mem.indexOfAny(u8, text, "@.:") != null;
}

/// How long a lookup may take, and the most a reply may weigh. The file on a
/// large domain can list thousands of names; this is far past any real one.
const nip05_timeout_ms = 10_000;
const nip05_max_bytes = 1024 * 1024;

pub const Nip05Error = nip05.ParseError || nip05.ResponseError || http.Error || error{BadStatus};

/// Resolves `name@domain` (or a bare `domain`) over HTTPS. The result owns its
/// memory: `deinit` it. Other verbs that accept an identifier call this.
///
/// NIP-05 says to ignore redirects, so a redirect fails the lookup. A domain
/// on this machine is asked over plain http, so a local server can be tried
/// without a certificate.
pub fn resolveNip05(gpa: std.mem.Allocator, io: std.Io, text: []const u8) Nip05Error!nip05.Resolved {
    const id = try nip05.parseIdentifier(text);
    const https_url = try nip05.wellKnownUrl(gpa, &id);
    defer gpa.free(https_url);

    var host = id.domain();
    if (std.mem.lastIndexOfScalar(u8, host, ':')) |i| host = host[0..i];
    const url = if (http.isLoopbackHost(host))
        try std.fmt.allocPrint(gpa, "http{s}", .{https_url["https".len..]})
    else
        try gpa.dupe(u8, https_url);
    defer gpa.free(url);

    var res = try http.fetch(gpa, io, url, .{
        .headers = &.{.{ .name = "Accept", .value = "application/json" }},
        .timeout_ms = nip05_timeout_ms,
        .max_bytes = nip05_max_bytes,
        .max_redirects = 0,
    });
    defer res.deinit(gpa);
    if (!res.ok()) return error.BadStatus;
    return nip05.parseResponse(gpa, res.body, id.name());
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
    const io = std.testing.io;
    const pk = [_]u8{0xab} ** 32;
    const npub = try nip19.encodeNpub(gpa, pk);
    defer gpa.free(npub);

    const got = try decodeOne(gpa, io, npub);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(
        "{\"pubkey\":\"abababababababababababababababababababababababababababababababab\"}",
        got,
    );
}

test "a nostr: URI decodes the same as the bare code" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const npub = try nip19.encodeNpub(gpa, [_]u8{0x01} ** 32);
    defer gpa.free(npub);
    const uri = try nip19.toNostrUri(gpa, npub);
    defer gpa.free(uri);

    const a = try decodeOne(gpa, io, npub);
    defer gpa.free(a);
    const b = try decodeOne(gpa, io, uri);
    defer gpa.free(b);
    try std.testing.expectEqualStrings(a, b);
}

test "nevent carries its optional fields only when present" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const bare = try nip19.encodeNevent(gpa, [_]u8{0x02} ** 32, &.{}, null, null);
    defer gpa.free(bare);
    const got = try decodeOne(gpa, io, bare);
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
    const got2 = try decodeOne(gpa, io, full);
    defer gpa.free(got2);
    try std.testing.expect(std.mem.indexOf(u8, got2, "\"kind\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, got2, "wss://relay.example") != null);
}

test "an unknown prefix is refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    try std.testing.expectError(error.InvalidPrefix, decodeOne(gpa, io, "nwhat1abc"));
}

test "an uppercase code, with either scheme case, decodes like the lowercase one" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const id = [_]u8{0x05} ** 32;
    const hints = [_][]const u8{"wss://relay.example"};
    const codes = [_][]u8{
        try nip19.encodeNpub(gpa, id),
        try nip19.encodeNsec(gpa, id),
        try nip19.encodeNote(gpa, id),
        try nip19.encodeNprofile(gpa, id, &hints),
        try nip19.encodeNevent(gpa, id, &hints, id, 1),
        try nip19.encodeNaddr(gpa, "slug", id, 30023, &hints),
        try nip19.encodeNrelay(gpa, "wss://relay.example"),
    };
    defer for (codes) |c| gpa.free(c);

    for (codes) |lower| {
        const want = try decodeOne(gpa, io, lower);
        defer gpa.free(want);
        const upper = try std.ascii.allocUpperString(gpa, lower);
        defer gpa.free(upper);
        const forms = [_][]const u8{ "", "NOSTR:", "nostr:" };
        for (forms) |scheme| {
            const input = try std.fmt.allocPrint(gpa, "{s}{s}", .{ scheme, upper });
            defer gpa.free(input);
            const got = try decodeOne(gpa, io, input);
            defer gpa.free(got);
            try std.testing.expectEqualStrings(want, got);
        }
        const loud = try std.fmt.allocPrint(gpa, "NOSTR:{s}", .{lower});
        defer gpa.free(loud);
        const got = try decodeOne(gpa, io, loud);
        defer gpa.free(got);
        try std.testing.expectEqualStrings(want, got);
    }
}

test "a code that mixes cases is still refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const npub = try nip19.encodeNpub(gpa, [_]u8{0x06} ** 32);
    defer gpa.free(npub);
    npub[0] = 'N';
    try std.testing.expectError(error.MixedCase, decodeOne(gpa, io, npub));
}

const pk_hex = "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9";

fn nostrJson(comptime relays: []const u8) []const u8 {
    return "{\"names\":{\"bob\":\"" ++ pk_hex ++ "\",\"_\":\"" ++ pk_hex ++ "\"}," ++
        "\"relays\":{\"" ++ pk_hex ++ "\":" ++ relays ++ "}}";
}

test "a NIP-05 identifier resolves to the shape of an nprofile" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the lookup leaked");
    const gpa = da.allocator();

    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{
        .path = "/.well-known/nostr.json",
        .body = comptime nostrJson("[\"wss://r1.example\",\"wss://r2.example\"]"),
    }}, 2);
    defer srv.stop(io);

    var ib: [64]u8 = undefined;
    const named = try std.fmt.bufPrint(&ib, "Bob@127.0.0.1:{d}", .{srv.port()});
    const got = try decodeOne(gpa, io, named);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(
        "{\"pubkey\":\"" ++ pk_hex ++ "\",\"relays\":[\"wss://r1.example\",\"wss://r2.example\"]}",
        got,
    );

    // The same pubkey and relays an nprofile with those fields decodes to.
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, pk_hex);
    const hints = [_][]const u8{ "wss://r1.example", "wss://r2.example" };
    const nprofile = try nip19.encodeNprofile(gpa, pk, &hints);
    defer gpa.free(nprofile);
    const via_code = try decodeOne(gpa, io, nprofile);
    defer gpa.free(via_code);
    try std.testing.expectEqualStrings(via_code, got);

    // A bare domain means the root name.
    var bb: [64]u8 = undefined;
    const bare = try std.fmt.bufPrint(&bb, "127.0.0.1:{d}", .{srv.port()});
    const root = try decodeOne(gpa, io, bare);
    defer gpa.free(root);
    try std.testing.expectEqualStrings(got, root);
}

test "a NIP-05 lookup fails on a missing name, a redirect and an HTTP error" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the lookup leaked");
    const gpa = da.allocator();

    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{
        .path = "/.well-known/nostr.json",
        .body = comptime nostrJson("[]"),
    }}, 1);
    defer srv.stop(io);

    var ib: [64]u8 = undefined;
    const nobody = try std.fmt.bufPrint(&ib, "nobody@127.0.0.1:{d}", .{srv.port()});
    try std.testing.expectError(error.NameNotFound, decodeOne(gpa, io, nobody));

    var redirecting: http.TestServer = undefined;
    try redirecting.start(io, &.{.{
        .path = "/.well-known/nostr.json",
        .status = .found,
        .location = "/elsewhere",
    }}, 1);
    defer redirecting.stop(io);
    const moved = try std.fmt.bufPrint(&ib, "bob@127.0.0.1:{d}", .{redirecting.port()});
    try std.testing.expectError(error.TooManyRedirects, decodeOne(gpa, io, moved));

    var empty: http.TestServer = undefined;
    try empty.start(io, &.{}, 1);
    defer empty.stop(io);
    const gone = try std.fmt.bufPrint(&ib, "bob@127.0.0.1:{d}", .{empty.port()});
    try std.testing.expectError(error.BadStatus, decodeOne(gpa, io, gone));
}

test "an identifier that is not valid is refused before any request" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidNameChar, decodeOne(gpa, io, "B ob@example.com"));
    try std.testing.expectError(error.EmptyName, decodeOne(gpa, io, "@example.com"));
    try std.testing.expect(isNip05("bob@example.com"));
    try std.testing.expect(isNip05("example.com"));
    try std.testing.expect(!isNip05("npub1abc"));
}
