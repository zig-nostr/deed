//! `deed verify`: check that events are correctly signed.
//!
//! Silent when every event checks out, because a verb in a pipeline that
//! prints on success is a verb whose output has to be filtered back out. The
//! answer is the exit code; the failures go to stderr with the id that failed.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");

const keys = nostr.keys;
const event = nostr.event;
const hex = nostr.hex;

/// An event that will not fit here is one no relay would carry either.
const max_record_bytes = 1 << 20;

pub const usage =
    \\deed verify: check that events are correctly signed
    \\
    \\Usage:
    \\  deed verify [<event-json>...]
    \\
    \\Reads events as newline-delimited JSON on stdin when given no arguments.
    \\Prints nothing when every event is valid and exits 0; reports each failure
    \\on stderr and exits 1.
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
            try err.print("deed verify: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        try positionals.append(gpa, a);
    }

    // The reader is a plain `var` and is never moved. A `File.Reader` holds
    // interior pointers, so stashing one in an optional and taking a pointer
    // into that hands the stream a location it may no longer own.
    //
    // `Input` decides whether stdin is read at all: positional arguments win,
    // so a caller who never meant to pipe anything is never left blocking on
    // a terminal.
    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    // Streaming for the reason `main` gives for the writers: a positional
    // read starts at byte 0 of the file behind the descriptor and re-reads
    // records an earlier reader on the same descriptor already consumed.
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);

    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    var signer = keys.Signer.init();
    defer signer.deinit();

    var failures: usize = 0;
    while (try input.next()) |record| {
        const json = switch (record) {
            // Trimmed here rather than in `Input`: surrounding space around
            // an event is noise, and `deed encrypt` needs the same bytes it was given.
            .line => |l| std.mem.trim(u8, l, " \t"),
            .too_long => {
                try err.print(
                    "deed verify: skipped an event longer than {d} bytes\n",
                    .{max_record_bytes},
                );
                failures += 1;
                continue;
            },
        };
        var parsed = event.fromJson(gpa, json) catch |e| {
            try err.print("deed verify: not an event: {s}\n", .{@errorName(e)});
            failures += 1;
            continue;
        };
        defer parsed.deinit();

        // `event.verify` recomputes the id from the event's own fields before
        // checking the signature, so a forged id fails here too.
        if (!try event.verify(gpa, signer, parsed.value)) {
            const id = try hex.encode(gpa, &parsed.value.id);
            defer gpa.free(id);
            try err.print("deed verify: bad signature: {s}\n", .{id});
            failures += 1;
        }
    }

    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

const Run = struct { code: u8, out: []const u8, err: []const u8 };

/// Runs `verify` over records given as positional arguments.
///
/// Positionals only, deliberately: `Input` reads stdin exactly when there are
/// none, and a test that took that branch would block on the test runner's own
/// stdin. The stdin contract is `cli.Input`'s to prove, and it does.
fn runVerify(args: []const []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    const code = try run(std.testing.allocator, std.testing.io, args, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    signed: []const u8,
    /// Content changed, id left alone: the id no longer describes the event.
    content_tampered: []const u8,
    /// Content changed AND the id recomputed to match, signature untouched: the
    /// event is internally consistent and the signature covers a different id.
    id_reforged: []const u8,

    fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        var signer = try keys.Signer.initRandomized(std.testing.io);
        defer signer.deinit();
        const kp = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
        const tags = [_]event.Tag{};
        const ev = try event.create(a, signer, kp, 1700000000, 1, &tags, "hello", null);

        var tampered = ev;
        tampered.content = "goodbye";

        var reforged = tampered;
        reforged.id = try event.computeId(a, ev.pubkey, ev.created_at, ev.kind, &tags, "goodbye");

        // Every allocation has to happen before the arena is copied into the
        // returned struct. Struct literal fields are evaluated in source order,
        // so writing `.arena = arena` first copies the arena's state as it
        // stands at that moment, and the allocations in the fields after it land
        // in the original, which `init` then drops on return. They are still
        // allocated and no longer reachable from the copy that gets deinited.
        const signed = try event.toJson(a, ev);
        const content_tampered = try event.toJson(a, tampered);
        const id_reforged = try event.toJson(a, reforged);

        return .{
            .arena = arena,
            .signed = signed,
            .content_tampered = content_tampered,
            .id_reforged = id_reforged,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
    }
};

test "a correctly signed event verifies, and says nothing at all" {
    var f = try Fixture.init();
    defer f.deinit();
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runVerify(&.{f.signed}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    // Silence is the contract: a verb that prints on success is one whose output
    // has to be filtered back out of a pipeline.
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expectEqualStrings("", r.err);
}

test "an event whose id does not describe its contents is refused" {
    var f = try Fixture.init();
    defer f.deinit();
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runVerify(&.{f.content_tampered}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(r.err.len > 0);
}

test "an event whose id was recomputed to fit the tampering is still refused" {
    // The one that matters. This event is internally consistent: its id is the
    // correct hash of its own fields. Only the signature gives it away, because
    // it covers the id the author actually signed. A verifier that checked the
    // id and stopped, or checked the signature against the id in the record
    // without recomputing, would accept this.
    var f = try Fixture.init();
    defer f.deinit();
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runVerify(&.{f.id_reforged}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
}

test "every bad record is reported, and one bad record fails the run" {
    var f = try Fixture.init();
    defer f.deinit();
    var ob: [1024]u8 = undefined;
    var eb: [4096]u8 = undefined;
    const r = try runVerify(
        &.{ f.signed, f.content_tampered, f.signed, f.id_reforged },
        &ob,
        &eb,
    );
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, r.err, "\n"));
}

test "something that is not an event is a failure, not a crash" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runVerify(&.{"{\"not\":\"an event\"}"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "not an event") != null);

    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const r2 = try runVerify(&.{"this is not json"}, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_fail, r2.code);
}

test "an unknown option is a usage error, not a bad record" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runVerify(&.{"--deeply"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    try std.testing.expectEqualStrings("", r.out);
}

test "help is printed on stdout and succeeds" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runVerify(&.{"--help"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "deed verify") != null);
    try std.testing.expectEqualStrings("", r.err);
}
