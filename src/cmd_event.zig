//! `deed event`: build an event and sign it.
//!
//! The verb the tool is named after: what comes out is a deed, a signed record
//! of something done. Publishing it is a separate verb, so this one stays
//! usable offline and its output stays inspectable before it leaves the
//! machine.
//!
//! Two ways in, and they compose. With nothing on stdin it builds exactly one
//! event from the flags. With drafts on stdin it signs each of them in turn,
//! with the flags acting as overrides, so a draft is a template and the flags
//! are what varies.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");

const keys = nostr.keys;
const event = nostr.event;

/// A draft larger than this is not a draft anybody typed.
const max_record_bytes = 1 << 20;

/// The separator inside a `--tag` value, for tags with more than two elements.
///
/// A semicolon rather than a comma: relay hints and `a` coordinates are the
/// values that most often need a third element, and commas turn up inside
/// those far more readily than semicolons do.
const tag_separator = ';';

pub const usage =
    \\deed event: build an event and sign it
    \\
    \\Usage:
    \\  deed event [-] [--sec <key>] [-c <content>] [-k <kind>] [-t <tag>]... [--created-at <n>]
    \\
    \\Options:
    \\  --sec <key>          secret key, as nsec1… or 64 hex characters.
    \\                       Falls back to $NOSTR_SECRET_KEY.
    \\  -c, --content <text> event content (default: empty)
    \\  -k, --kind <n>       event kind (default: 1)
    \\  -t, --tag <name>=<v> add a tag, repeatable. Use ';' between values for a
    \\                       tag with more than two elements:
    \\                         -t 'e=<id>;wss://relay.example;reply'
    \\                       A bare name with no '=' makes a one-element tag.
    \\  --created-at <n>     unix seconds (default: now)
    \\
    \\A lone `-` reads drafts as newline-delimited JSON on stdin, signs each
    \\one, and applies the flags above as overrides. Unknown fields in a draft
    \\are ignored, so a whole event can be piped back in to be re-signed. One
    \\signed event is printed per line.
    \\
    \\The `-` is required rather than inferred. Every other verb reads stdin
    \\when it has nothing else to work on, because it has nothing to do without
    \\input; this one has a complete default, so guessing at stdin would let a
    \\script sign whatever happened to be on the other end of the pipe.
    \\
    \\  deed event -c "hello" --sec nsec1…
    \\  echo '{"kind":1,"content":"hi"}' | deed event - --sec nsec1…
    \\
;

const Overrides = struct {
    sec: ?[]const u8 = null,
    content: ?[]const u8 = null,
    kind: ?u16 = null,
    created_at: ?i64 = null,
    tags: std.ArrayList([]const []const u8) = .empty,
    tags_given: bool = false,
};

/// The fields a draft may carry. Everything is optional and everything else in
/// the object is ignored, so piping a complete event back in re-signs it
/// rather than failing on `id` and `sig`.
const Draft = struct {
    kind: ?u16 = null,
    content: ?[]const u8 = null,
    tags: ?[]const []const []const u8 = null,
    created_at: ?i64 = null,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var ov = Overrides{};
    defer {
        for (ov.tags.items) |t| gpa.free(t);
        ov.tags.deinit(gpa);
    }

    var read_stdin = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        // The one positional: `-`, meaning "drafts are coming on stdin".
        if (std.mem.eql(u8, a, "-")) {
            read_stdin = true;
            continue;
        }
        const needs_value = cli.isOneOf(a, &.{
            "--sec", "-c", "--content", "-k", "--kind", "-t", "--tag", "--created-at",
        });
        if (!needs_value) {
            try err.print("deed event: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed event: '{s}' needs a value\n", .{a});
            return cli.exit_usage;
        }
        const v = args[i];

        if (std.mem.eql(u8, a, "--sec")) {
            ov.sec = v;
        } else if (cli.isOneOf(a, &.{ "-c", "--content" })) {
            ov.content = v;
        } else if (cli.isOneOf(a, &.{ "-k", "--kind" })) {
            ov.kind = std.fmt.parseInt(u16, v, 10) catch {
                try err.print("deed event: '{s}' is not a kind number\n", .{v});
                return cli.exit_usage;
            };
        } else if (cli.isOneOf(a, &.{ "-t", "--tag" })) {
            ov.tags_given = true;
            try ov.tags.append(gpa, try parseTag(gpa, v));
        } else if (std.mem.eql(u8, a, "--created-at")) {
            ov.created_at = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed event: '{s}' is not a unix timestamp\n", .{v});
                return cli.exit_usage;
            };
        }
    }

    // The key is the one thing with no default. Asking for it by flag or by
    // environment and refusing to invent one is the whole point: an event
    // signed by a key the caller did not choose is worse than no event.
    const raw_sec = ov.sec orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.writeAll("deed event: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n");
        return cli.exit_usage;
    };
    const sk = keyinput.secretKey(gpa, raw_sec) catch {
        try err.writeAll("deed event: not a secret key (want nsec1… or 64 hex characters)\n");
        return cli.exit_fail;
    };

    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();
    const keypair = try signer.keyPairFromSecretKey(sk);

    if (!read_stdin) {
        try emit(gpa, io, signer, keypair, Draft{}, ov, out);
        return cli.exit_ok;
    }

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    var stdin_reader = std.Io.File.stdin().reader(io, stdin_buf);
    var input = cli.Input.init(&.{}, &stdin_reader.interface);

    var failures: usize = 0;
    while (try input.next()) |record| {
        const json = switch (record) {
            .line => |l| l,
            .too_long => {
                try err.print(
                    "deed event: skipped a draft longer than {d} bytes\n",
                    .{max_record_bytes},
                );
                failures += 1;
                continue;
            },
        };
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const draft = std.json.parseFromSliceLeaky(
            Draft,
            arena.allocator(),
            json,
            .{ .ignore_unknown_fields = true },
        ) catch |e| {
            try err.print("deed event: not a draft: {s}\n", .{@errorName(e)});
            failures += 1;
            continue;
        };
        try emit(gpa, io, signer, keypair, draft, ov, out);
    }

    // An empty pipe is not a request to invent an event: `deed req … | deed
    // event -` that receives nothing should produce nothing, and say so by
    // succeeding rather than by complaining.
    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

fn emit(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    draft: Draft,
    ov: Overrides,
    out: *std.Io.Writer,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const kind = ov.kind orelse draft.kind orelse 1;
    const content = ov.content orelse draft.content orelse "";
    const created_at = ov.created_at orelse draft.created_at orelse
        std.Io.Timestamp.now(io, .real).toSeconds();

    // Tags replace rather than merge. Merging would mean a draft's `e` tag and
    // a flag's `e` tag both landing, which is a different event than either
    // side asked for and impossible to undo from the command line.
    const tags: []const event.Tag = if (ov.tags_given)
        ov.tags.items
    else if (draft.tags) |t|
        t
    else
        &.{};

    const ev = try event.create(a, signer, keypair, created_at, kind, tags, content, null);
    const json = try event.toJson(a, ev);
    try out.print("{s}\n", .{json});
}

/// `name=v1;v2` becomes `["name","v1","v2"]`; a bare `name` becomes `["name"]`.
/// Caller owns the returned slice; its elements borrow `spec`.
fn parseTag(gpa: std.mem.Allocator, spec: []const u8) ![]const []const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    errdefer parts.deinit(gpa);

    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse {
        try parts.append(gpa, spec);
        return parts.toOwnedSlice(gpa);
    };
    try parts.append(gpa, spec[0..eq]);
    var it = std.mem.splitScalar(u8, spec[eq + 1 ..], tag_separator);
    while (it.next()) |v| try parts.append(gpa, v);
    return parts.toOwnedSlice(gpa);
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

test "a two-element tag" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "e=abc");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("e", t[0]);
    try std.testing.expectEqualStrings("abc", t[1]);
}

test "extra values after the separator" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "e=abc;wss://relay.example;reply");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 4), t.len);
    try std.testing.expectEqualStrings("wss://relay.example", t[2]);
    try std.testing.expectEqualStrings("reply", t[3]);
}

test "a bare name is a one-element tag" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "-");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 1), t.len);
    try std.testing.expectEqualStrings("-", t[0]);
}

test "an empty value is still a value" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "d=");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("", t[1]);
}
