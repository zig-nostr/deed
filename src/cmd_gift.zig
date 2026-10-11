//! `deed gift`: NIP-59 gift wraps and NIP-17 private messages.
//!
//! Three subcommands. `wrap` and `unwrap` move one event in and out of a
//! kind 1059 envelope; `dm` builds a whole NIP-17 message. None of them
//! touch the network: the wraps come out on stdout one per line, and
//! publishing is `deed publish` reading them back in.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const signing = @import("signing.zig");

const keys = nostr.keys;
const event = nostr.event;
const nip59 = nostr.nip59;
const nip44 = nostr.nip44;
const hex = nostr.hex;

/// A wrap is a few kilobytes and a message at most 65535 bytes of NIP-44
/// plaintext inside two layers of base64, so nothing legitimate nears this.
const max_record_bytes = 1 << 20;

/// Shown beside the name in `deed help` once `ready` is true.
pub const summary = "wrap, unwrap and send private messages (NIP-59, NIP-17)";

/// False keeps the verb out of `deed help`.
pub const ready = true;

pub const usage =
    \\deed gift: wrap, unwrap and send private messages (NIP-59, NIP-17)
    \\
    \\Usage:
    \\  deed gift wrap   --to <pubkey> [--sec <key>]
    \\  deed gift unwrap [--sec <key>] [--json]
    \\  deed gift dm     --to <pubkey>... [--sec <key>] [<message>...]
    \\
    \\Options:
    \\  --to <pubkey>   recipient, as npub1... or 64 hex characters. dm takes it
    \\                  more than once.
    \\  --sec <key>     your secret key: nsec1..., ncryptsec1..., bunker://... or
    \\                  64 hex characters; $NOSTR_SECRET_KEY is read when --sec
    \\                  is absent. A remote signer signs and encrypts the seal;
    \\                  the wrap is signed by a one-time key made here.
    \\  --json          unwrap: print {"sender":...,"rumor":...} instead of the
    \\                  rumor alone
    \\
    \\wrap reads one event per line on stdin and treats its kind, tags, content
    \\and created_at as the rumor (an id, pubkey or sig on it is ignored; the
    \\author becomes you). It prints one kind 1059 wrap per line.
    \\
    \\unwrap reads kind 1059 wraps on stdin, one per line, and prints the rumor
    \\inside each. The sender proven by the seal goes to stderr as "sender: <hex>",
    \\or into the output with --json. A wrap that fails says which check it
    \\failed (the wrap, the seal, the rumor or the sender) and nothing else.
    \\
    \\dm builds a NIP-17 chat message (kind 14) for every --to, plus a copy to
    \\you so your other clients can show it, and prints the wraps one per line.
    \\Messages are read one per line on stdin when none are given as arguments.
    \\Nothing is sent: pipe the output into deed publish.
    \\
    \\  deed gift dm --to npub1... --sec nsec1... "see you at six" | deed publish wss://relay.example
    \\
;

const Sub = enum { wrap, unwrap, dm };

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    // Streaming for the reason `main` gives for the writers.
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
    return runWith(gpa, io, args, &stdin_reader.interface, out, err);
}

fn runWith(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    stdin: *std.Io.Reader,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed gift: needs wrap, unwrap or dm (see 'deed help gift')\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    const sub: Sub = if (std.mem.eql(u8, args[0], "wrap"))
        .wrap
    else if (std.mem.eql(u8, args[0], "unwrap"))
        .unwrap
    else if (std.mem.eql(u8, args[0], "dm"))
        .dm
    else {
        try err.print("deed gift: unknown subcommand '{s}' (want wrap, unwrap or dm)\n", .{args[0]});
        return cli.exit_usage;
    };
    const name = @tagName(sub);

    var raw_sec: ?[]const u8 = null;
    var tos: std.ArrayList([]const u8) = .empty;
    defer tos.deinit(gpa);
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);
    var as_json = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--")) {
            i += 1;
            while (i < args.len) : (i += 1) try positionals.append(gpa, args[i]);
            break;
        }
        if (std.mem.eql(u8, a, "--json") and sub == .unwrap) {
            as_json = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            const is_sec = std.mem.eql(u8, a, "--sec");
            const is_to = std.mem.eql(u8, a, "--to") and sub != .unwrap;
            if (!is_sec and !is_to) {
                try err.print("deed gift {s}: unknown option '{s}'\n", .{ name, a });
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed gift {s}: '{s}' needs a value\n", .{ name, a });
                return cli.exit_usage;
            }
            if (is_sec) raw_sec = args[i] else try tos.append(gpa, args[i]);
            continue;
        }
        try positionals.append(gpa, a);
    }

    // Only dm takes its input as arguments; wrap and unwrap read events, which
    // are never passed on the command line.
    if (sub != .dm and positionals.items.len != 0) {
        try err.print("deed gift {s}: reads stdin and takes no arguments\n", .{name});
        return cli.exit_usage;
    }
    if (sub != .unwrap and tos.items.len == 0) {
        try err.print("deed gift {s}: needs --to\n", .{name});
        return cli.exit_usage;
    }
    if (sub == .wrap and tos.items.len != 1) {
        try err.writeAll("deed gift wrap: takes exactly one --to\n");
        return cli.exit_usage;
    }
    const sec_text = raw_sec orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.print(
            "deed gift {s}: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n",
            .{name},
        );
        return cli.exit_usage;
    };
    var recipients: std.ArrayList(keys.PublicKey) = .empty;
    defer recipients.deinit(gpa);
    for (tos.items) |t| {
        const pk = keyinput.publicKey(gpa, t) catch {
            try err.print(
                "deed gift {s}: --to is not a public key (want npub1... or 64 hex characters)\n",
                .{name},
            );
            return cli.exit_fail;
        };
        try recipients.append(gpa, pk);
    }

    const verb: []const u8 = switch (sub) {
        .wrap => "gift wrap",
        .unwrap => "gift unwrap",
        .dm => "gift dm",
    };
    var signer = (try signing.open(gpa, io, verb, sec_text, err)) orelse return cli.exit_fail;
    defer signer.deinit();

    var input = cli.Input.init(positionals.items, stdin);
    var failures: usize = 0;
    while (try input.next()) |record| {
        const text = switch (record) {
            .line => |l| l,
            .too_long => {
                try err.print(
                    "deed gift {s}: skipped a record longer than {d} bytes\n",
                    .{ name, max_record_bytes },
                );
                failures += 1;
                continue;
            },
        };
        if (text.len == 0) continue;
        const ok = switch (sub) {
            .wrap => doWrap(gpa, io, &signer, recipients.items[0], text, out, err),
            .unwrap => doUnwrap(gpa, io, &signer, text, as_json, out, err),
            .dm => doDm(gpa, io, &signer, recipients.items, text, out, err),
        } catch |e| switch (e) {
            error.OutOfMemory, error.Canceled => return e,
            // A signer that refused or went quiet will do the same for the
            // next record, so the run ends here.
            else => if (signing.describe(e) != null) return signing.report(verb, e, err) else blk: {
                try err.print("deed gift {s}: {s}\n", .{ name, reason(e) });
                break :blk false;
            },
        };
        if (!ok) failures += 1;
    }
    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

const RumorInput = struct {
    kind: u16,
    created_at: ?i64 = null,
    tags: []const []const []const u8 = &.{},
    content: []const u8 = "",
};

fn doWrap(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: *signing.Signer,
    to: keys.PublicKey,
    text: []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const input = std.json.parseFromSliceLeaky(RumorInput, a, text, .{ .ignore_unknown_fields = true }) catch {
        try err.writeAll("deed gift wrap: not an event\n");
        return false;
    };
    const created_at = input.created_at orelse std.Io.Timestamp.now(io, .real).toSeconds();
    const rumor = try nip59.Rumor.init(a, signer.publicKey(), created_at, input.kind, input.tags, input.content);

    const sealed = try seal(a, io, signer, to, rumor);
    var wrapped = try nip59.wrap(gpa, io, signer.ctx, sealed, to, &.{});
    defer wrapped.deinit();
    try printEvent(gpa, out, wrapped.event);
    return true;
}

fn doUnwrap(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: *signing.Signer,
    text: []const u8,
    as_json: bool,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !bool {
    var parsed = event.fromJson(gpa, text) catch {
        try err.writeAll("deed gift unwrap: not an event\n");
        return false;
    };
    defer parsed.deinit();
    var opened = if (signer.keyPair()) |kp|
        try nip59.unwrap(gpa, signer.ctx, kp.secret_key, parsed.value)
    else
        try unwrapRemote(gpa, io, signer, parsed.value);
    defer opened.deinit();

    const rumor_json = try nip59.rumorToJson(gpa, opened.rumor);
    defer gpa.free(rumor_json);
    var sender_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&sender_hex, "{x}", .{opened.sender}) catch unreachable;
    if (as_json) {
        try out.print("{{\"sender\":\"{s}\",\"rumor\":{s}}}\n", .{ sender_hex, rumor_json });
    } else {
        try out.print("{s}\n", .{rumor_json});
        try err.print("sender: {s}\n", .{sender_hex});
    }
    return true;
}

fn doDm(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: *signing.Signer,
    to: []const keys.PublicKey,
    text: []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !bool {
    _ = err;
    if (signer.keyPair()) |me| {
        var dm = try nip59.privateDirectMessage(gpa, io, signer.ctx, me, to, text, null, null);
        defer dm.deinit();
        for (dm.wraps) |w| try printEvent(gpa, out, w);
        return true;
    }

    // The same message `privateDirectMessage` builds, with each seal made by
    // the remote signer: a kind 14 rumor with one `p` tag per distinct
    // recipient, wrapped to each of them and to the sender.
    if (to.len == 0) return error.NoRecipients;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const me = signer.publicKey();

    var targets: std.ArrayList(keys.PublicKey) = .empty;
    var tags: std.ArrayList(event.Tag) = .empty;
    for (to) |pk| {
        if (contains(targets.items, pk)) continue;
        try targets.append(a, pk);
        const fields = try a.alloc([]const u8, 2);
        fields[0] = "p";
        fields[1] = try hex.encode(a, &pk);
        try tags.append(a, fields);
    }
    if (!contains(targets.items, me)) try targets.append(a, me);

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const rumor = try nip59.Rumor.init(a, me, now, 14, tags.items, text);
    for (targets.items) |pk| {
        const sealed = try seal(a, io, signer, pk, rumor);
        var wrapped = try nip59.wrap(gpa, io, signer.ctx, sealed, pk, &.{});
        defer wrapped.deinit();
        try printEvent(gpa, out, wrapped.event);
    }
    return true;
}

fn contains(list: []const keys.PublicKey, pk: keys.PublicKey) bool {
    for (list) |x| if (std.mem.eql(u8, &x, &pk)) return true;
    return false;
}

/// The kind 13 seal of `rumor` to `to`, signed by the user, allocated from
/// `a`. A local key goes through `nip59.seal`; a remote signer encrypts the
/// rumor and signs the seal itself, so the user's key never leaves it.
fn seal(a: std.mem.Allocator, io: std.Io, signer: *signing.Signer, to: keys.PublicKey, rumor: nip59.Rumor) !event.Event {
    if (signer.keyPair()) |me| {
        const sealed = try nip59.seal(a, io, signer.ctx, me, to, rumor);
        return sealed.event;
    }
    const rumor_json = try nip59.rumorToJson(a, rumor);
    const ciphertext = try signer.crypt(a, io, .nip44_encrypt, to, rumor_json);
    return signer.sign(a, try randomPastTimestamp(io), 13, &.{}, ciphertext);
}

/// Up to two days before now, never now itself, as NIP-59 asks of a seal.
fn randomPastTimestamp(io: std.Io) !i64 {
    var buf: [8]u8 = undefined;
    io.randomSecure(&buf) catch return error.RandomFailed;
    const r = std.mem.readInt(u64, &buf, .little);
    const two_days: u64 = 2 * 24 * 60 * 60;
    const offset: i64 = 1 + @as(i64, @intCast(r % two_days));
    return std.Io.Timestamp.now(io, .real).toSeconds() - offset;
}

/// What `nip59.unwrap` checks, in its order, with both decrypts done by the
/// remote signer.
fn unwrapRemote(gpa: std.mem.Allocator, io: std.Io, signer: *signing.Signer, wrap: event.Event) !nip59.Unwrapped {
    if (wrap.kind != 1059 and wrap.kind != 21059) return error.WrongKind;
    if (!try event.verify(gpa, signer.ctx, wrap)) return error.InvalidWrapSignature;

    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();

    const seal_json = try signer.crypt(a, io, .nip44_decrypt, wrap.pubkey, wrap.content);
    const seal_value = std.json.parseFromSliceLeaky(std.json.Value, a, seal_json, .{}) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return error.InvalidSeal,
    };
    const sealed = event.fromValueLeaky(a, seal_value) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return error.InvalidSeal,
    };
    if (sealed.kind != 13) return error.WrongKind;
    if (sealed.tags.len != 0) return error.InvalidSeal;
    if (!try event.verify(a, signer.ctx, sealed)) return error.InvalidSealSignature;

    const rumor_json = try signer.crypt(a, io, .nip44_decrypt, sealed.pubkey, sealed.content);
    const wire = std.json.parseFromSliceLeaky(WireRumor, a, rumor_json, .{ .ignore_unknown_fields = true }) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return error.InvalidRumor,
    };
    const rumor: nip59.Rumor = .{
        .id = hex.decodeFixed(32, wire.id) catch return error.InvalidRumor,
        .pubkey = hex.decodeFixed(32, wire.pubkey) catch return error.InvalidRumor,
        .created_at = wire.created_at,
        .kind = wire.kind,
        .tags = wire.tags,
        .content = wire.content,
    };
    if (!try rumor.idMatches(a)) return error.RumorIdMismatch;
    if (!std.mem.eql(u8, &rumor.pubkey, &sealed.pubkey)) return error.SenderMismatch;
    return .{ .arena = arena, .rumor = rumor, .sender = sealed.pubkey };
}

const WireRumor = struct {
    id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    kind: u16,
    tags: []const []const []const u8,
    content: []const u8,
};

fn printEvent(gpa: std.mem.Allocator, out: *std.Io.Writer, ev: event.Event) !void {
    const json = try event.toJson(gpa, ev);
    defer gpa.free(json);
    try out.print("{s}\n", .{json});
}

/// Names the check that failed and nothing from inside the envelope.
fn reason(e: anyerror) []const u8 {
    return switch (e) {
        error.WrongKind => "not a gift wrap (kind 1059), or it does not hold a seal",
        error.InvalidWrapSignature => "the wrap's id or signature is invalid",
        error.InvalidSealSignature => "the seal's id or signature is invalid",
        error.InvalidSeal => "the wrap does not hold a well-formed seal",
        error.InvalidRumor => "the seal does not hold a well-formed rumor",
        error.RumorIdMismatch => "the rumor's id does not match its contents",
        error.SenderMismatch => "the rumor claims a different author than the seal's signer",
        error.InvalidMac => "could not decrypt: this wrap is not addressed to that key, or it was altered",
        error.InvalidPayload, error.InvalidPadding => "could not decrypt: malformed ciphertext",
        error.NoRecipients => "needs at least one --to",
        error.MessageEmpty => "nothing to send",
        error.MessageTooLong => "too long: NIP-44 allows 65535 bytes",
        error.InvalidPublicKey => "that public key is not a point on the curve",
        error.InvalidSecretKey => "that secret key is out of range",
        error.RandomFailed => "could not draw randomness from the system",
        else => @errorName(e),
    };
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

const a_sec = "4730316ccd61d3e724f6732bde7039975f9d62977c4148f060b5b79d0da30122";
const a_pub = "6118e5c17cdac8bda27716e8bfea58a3e30693abd41c022b7a17e154a36863fb";
const b_sec = "9224f7229d4d67810b092013af790316598058bc71ae99b19fb291b4ad82b381";
const b_pub = "9c9fe0a462f5e8d9655244ac4c7c0866d9c044a387884559124e011f3754c5ab";
const c_sec = "1111111111111111111111111111111111111111111111111111111111111111";

const Ran = struct { code: u8, out: []const u8, err: []const u8 };

fn runGift(arena: std.mem.Allocator, args: []const []const u8, stdin_text: []const u8) !Ran {
    return runGiftWith(testing.allocator, arena, args, stdin_text);
}

fn runGiftWith(gpa: std.mem.Allocator, arena: std.mem.Allocator, args: []const []const u8, stdin_text: []const u8) !Ran {
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    var reader: std.Io.Reader = .fixed(stdin_text);
    const code = try runWith(gpa, testing.io, args, &reader, &out.writer, &err.writer);
    return .{ .code = code, .out = out.written(), .err = err.written() };
}

fn has(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

test "wrap then unwrap returns the rumor and proves the sender" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const note = "{\"kind\":14,\"created_at\":1700000000,\"tags\":[[\"p\",\"" ++ b_pub ++ "\"]],\"content\":\"hi \\\"b\\\"\"}\n";
    const wrapped = try runGift(arena, &.{ "wrap", "--to", b_pub, "--sec", a_sec }, note);
    try testing.expectEqual(@as(u8, 0), wrapped.code);
    try testing.expect(has(wrapped.out, "\"kind\":1059"));

    const opened = try runGift(arena, &.{ "unwrap", "--sec", b_sec }, wrapped.out);
    try testing.expectEqual(@as(u8, 0), opened.code);
    try testing.expect(has(opened.out, "\"kind\":14"));
    try testing.expect(has(opened.out, "\"created_at\":1700000000"));
    try testing.expect(has(opened.out, "hi \\\"b\\\""));
    try testing.expect(has(opened.out, "\"pubkey\":\"" ++ a_pub ++ "\""));
    try testing.expect(has(opened.err, "sender: " ++ a_pub));

    const as_json = try runGift(arena, &.{ "unwrap", "--sec", b_sec, "--json" }, wrapped.out);
    try testing.expect(std.mem.startsWith(u8, as_json.out, "{\"sender\":\"" ++ a_pub ++ "\",\"rumor\":{"));
    try testing.expectEqual(@as(usize, 0), as_json.err.len);
}

test "a third key cannot open a wrap" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const wrapped = try runGift(arena, &.{ "wrap", "--to", b_pub, "--sec", a_sec }, "{\"kind\":1,\"content\":\"x\"}\n");
    const r = try runGift(arena, &.{ "unwrap", "--sec", c_sec }, wrapped.out);
    try testing.expectEqual(@as(u8, 1), r.code);
    try testing.expectEqual(@as(usize, 0), r.out.len);
    try testing.expect(has(r.err, "could not decrypt"));
}

test "a tampered wrap is rejected and says which check failed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const wrapped = try runGift(arena, &.{ "wrap", "--to", b_pub, "--sec", a_sec }, "{\"kind\":1,\"content\":\"x\"}\n");
    const bad = try arena.dupe(u8, wrapped.out);
    // Flip a character inside the ciphertext: the id no longer matches.
    const at = std.mem.indexOf(u8, bad, "\"content\":\"").? + 20;
    bad[at] = if (bad[at] == 'A') 'B' else 'A';
    const r = try runGift(arena, &.{ "unwrap", "--sec", b_sec }, bad);
    try testing.expectEqual(@as(u8, 1), r.code);
    try testing.expectEqual(@as(usize, 0), r.out.len);
    try testing.expect(has(r.err, "wrap's id or signature"));

    const not_wrap = try runGift(arena, &.{ "unwrap", "--sec", b_sec }, "{\"kind\":1,\"content\":\"x\"}\n");
    try testing.expectEqual(@as(u8, 1), not_wrap.code);
}

test "dm wraps once per recipient plus one to self" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sent = try runGift(arena, &.{ "dm", "--to", b_pub, "--to", c_pub_hex, "--sec", a_sec, "see you at six" }, "");
    try testing.expectEqual(@as(u8, 0), sent.code);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, sent.out, "\n"), '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        n += 1;
        try testing.expect(has(line, "\"kind\":1059"));
    }
    try testing.expectEqual(@as(usize, 3), n);

    // The first wrap is for b, and b reads a kind 14 from a.
    const first = sent.out[0..std.mem.indexOfScalar(u8, sent.out, '\n').?];
    const opened = try runGift(arena, &.{ "unwrap", "--sec", b_sec }, first);
    try testing.expectEqual(@as(u8, 0), opened.code);
    try testing.expect(has(opened.out, "\"kind\":14"));
    try testing.expect(has(opened.out, "see you at six"));
    try testing.expect(has(opened.err, "sender: " ++ a_pub));
}

// The public key of c_sec, worked out once with nak.
const c_pub_hex = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

test "unwrap opens a wrap made by nak" {
    // Made with nak v0.21.2 and the throwaway keys above:
    //   nak event -k 14 -c "hello from nak" --sec <a> | nak gift wrap --sec <a> -p <b-pub>
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const r = try runGift(arena, &.{ "unwrap", "--sec", b_sec }, nak_wrap);
    try testing.expectEqual(@as(u8, 0), r.code);
    try testing.expect(has(r.out, "\"content\":\"hello from nak\""));
    try testing.expect(has(r.err, "sender: " ++ a_pub));
}

test "wrap refuses missing or repeated flags" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(@as(u8, 2), (try runGift(arena, &.{ "wrap", "--sec", a_sec }, "")).code);
    try testing.expectEqual(@as(u8, 2), (try runGift(arena, &.{ "wrap", "--to", b_pub, "--to", b_pub, "--sec", a_sec }, "")).code);
    try testing.expectEqual(@as(u8, 2), (try runGift(arena, &.{"nope"}, "")).code);
}

const nak_wrap =
    \\{"kind":1059,"id":"ac33c696c5c3113cca78ccb69b618daf31c19179549a23ac737a4480c9687a5e","pubkey":"0b060aaffb2765be6ef02c578522a5af0289a5101baef2fa15c7c47eed451e83","created_at":1791557850,"tags":[["p","9c9fe0a462f5e8d9655244ac4c7c0866d9c044a387884559124e011f3754c5ab"]],"content":"Aq1U9qozrK/nG0HNKPnDvLm7/an4cZig+buAD0rAmmwUC7Mq66fVTqVbxUaVWjVggtqnif3zXfd8hklGYlUUNJ3TxS5XFOLh+09uNhcR+tNdAC2rRahWR2kFMEtVtVnnfFgm6ZqFhNBF62eVVM42oRyGZgFKMBZYaRLrbWMPZTMiFW8u6EOHkUbRJwnzCdFeFdu95+oldQc5hPnqkx9cyNR56igdVCMg1VitRGZHVotoRhMHqsAZ+t8cqavDy98tNBwYg2LxPeQSJCTL4ck+JqW6NnBCoh2imOW9TBRYnvYNzGvvPAiQmxMhAXVJg9GZS/1Ci5edYybqzowqT0ta5pjWTAClswlSqBfdz9omajCWZEu0laIGp65M/mMSXkJ27HMkCvXyfyLnSAL8Nldb7d3dVE8TInHgqKScZdoEcELMrusR40siNC3A/NHR4WGsTBrB2uZ/MjdZqtBjKpgV7HkqwwqNgECFY0S1e8VV3Jie4HsFQ1UbDF698vt2FaGMPOyQlSUjzwOa9HLAiBcu2Cb2CoU9FcC5SqcaDjAZQxLhUytby/Z5Yl0XaOkiWaYTjPz+PB7dwbDGPaRqXuxtPaHre1qslH0LG3kFps3bswtidAmA+FXUUVZh/tJYOw8c7FnVUda4apl5iIWQe+BDj34lDtfCnMaWdaOKZgcoRjyc2kA6PljK1IS0XLb+OgTABUR3s2mSSySeFU7dZq9Qmz8h7+RJ2mxnmmTAcF/D1xiyYo6kWY9dMLTSlQ4gaNKonFM0y+dCIPeARL8uI4pQslHNLWcMh4QJIlxE7KJGgoGVY/q1XeSkJUfZU2kTheVJCK5/FiQocIBqI3ReueS0lG7soheFTVuO7UlfVFSI885K1pHCwUYk+wDEC24J8L4AE3scG44Pah0g63H/yf+mhXOfoTPgogjOeXdwr6JDjZioDopzYLopZMe6EYBVeMnULEQzqLsPKC0J49YCWl9uyQvnMMiuRAXGIXE+c+M7D8DAbFU+m0RJ656SVh3XtHwiqJQdMaTfYn3BjWfjxGfRwBkUglT4q9cCfBKyIwAzCB+bWnET/hOHyJ/s0pqBms+J2NEvXaXt0AVxN+FIadRgeC1MFhj1Fi0I9b81GwpLPaKW3VBliGakS3zi933nCcIatvlbYX1LZoXdWGUIyOwrLF8smCmu9yS4+5AbMU//d4AYK+x37TaOgCl4ry92yYmM3CZNMzSQ+fhhYnUOT4ZqRX3huNcm21g+qYmPqIqdMls9AVf99YCxOHgN0+vTQ8UG5At8","sig":"c9803af581610ad4b8f9136d44a91571f628f14a11c49a83e9d208f2fa4462481cc661cdf4ee0d568bfbead79602f1468b640433be4d89a7e5599fc440bd14dc"}
;

test "a dm made through a remote signer opens for the recipient, from the user" {
    const testrelay = @import("testrelay.zig");
    const signertest = @import("signertest.zig");
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the remote signer leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rig: signertest.Rig = undefined;
    try rig.init(gpa, testing.io, .serve);
    defer rig.deinit();
    const user_hex = std.fmt.bytesToHex(rig.user.public_key, .lower);

    const sent = try runGiftWith(gpa, arena, &.{ "dm", "--to", b_pub, "--sec", rig.uri(), "see you at six" }, "");
    try testing.expectEqual(@as(u8, 0), sent.code);
    const first_end = std.mem.indexOfScalar(u8, sent.out, '\n').?;
    const to_b = sent.out[0..first_end];
    const to_self = std.mem.trimEnd(u8, sent.out[first_end + 1 ..], "\n");
    try testing.expect(has(to_self, "\"kind\":1059"));

    const opened = try runGiftWith(gpa, arena, &.{ "unwrap", "--sec", b_sec }, to_b);
    try testing.expectEqual(@as(u8, 0), opened.code);
    try testing.expect(has(opened.out, "\"kind\":14"));
    try testing.expect(has(opened.out, "see you at six"));
    try testing.expect(has(opened.err, try std.fmt.allocPrint(arena, "sender: {s}", .{&user_hex})));

    // The copy to self opens through the remote signer too.
    const mine = try runGiftWith(gpa, arena, &.{ "unwrap", "--sec", rig.uri() }, to_self);
    try testing.expectEqual(@as(u8, 0), mine.code);
    try testing.expect(has(mine.out, "see you at six"));
}
