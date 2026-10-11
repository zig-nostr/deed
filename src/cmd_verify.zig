//! `deed verify`: check that events are correctly signed.
//!
//! Silent when every event checks out, because a verb in a pipeline that
//! prints on success is a verb whose output has to be filtered back out. The
//! answer is the exit code; the failures go to stderr with the id that failed.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const parallel = @import("parallel.zig");

const keys = nostr.keys;
const event = nostr.event;

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
    \\Exits: 0 when every event is valid; 1 if any is not; 2 if the command line
    \\was not understood.
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

    var ctx: Ctx = .{ .signer = keys.Signer.init(), .err = err };
    defer ctx.signer.deinit();

    // Records are gathered into chunks. A stream that ends inside the first
    // chunk is verified right here on this thread, so a lone event pays for no
    // thread at all. Past that, chunks go to a pool with one worker per core
    // and come back in input order, so the failures read exactly as they would
    // from a single thread.
    var local = Chunk.init(gpa);
    defer local.deinit();
    var pool: ?*Pool = null;
    defer if (pool) |p| p.deinit(Chunk.deinitPtr);

    var read_error: ?anyerror = null;
    var eof = false;
    while (!eof) {
        local.reset();
        while (local.entries.items.len < chunk_records and local.bytes.items.len < chunk_bytes) {
            const record = input.next() catch |e| {
                read_error = e;
                eof = true;
                break;
            } orelse {
                eof = true;
                break;
            };
            switch (record) {
                // Trimmed here rather than in `Input`: surrounding space around
                // an event is noise, and `deed encrypt` needs the same bytes it was given.
                .line => |l| try local.add(std.mem.trim(u8, l, " \t")),
                .too_long => try local.addTooLong(),
            }
        }
        if (local.entries.items.len == 0) break;
        try local.outcomes.resize(gpa, local.entries.items.len);

        if (pool == null and eof) {
            Ctx.process(&ctx, &local);
            try ctx.deliver(&local);
            break;
        }
        if (pool == null) pool = try Pool.init(gpa, io, &ctx, .{}, Chunk.init);
        const slot = try pool.?.acquire();
        std.mem.swap(Chunk, slot, &local);
        try pool.?.submit();
    }
    if (pool) |p| try p.finish();
    if (read_error) |e| return e;

    return if (ctx.failures == 0) cli.exit_ok else cli.exit_fail;
}

/// A chunk closes at this many records or bytes, whichever comes first. About
/// a millisecond or two of work: long enough to amortize the hand-off, short
/// enough that every core has a chunk to chew on.
const chunk_records = 64;
const chunk_bytes = 256 * 1024;

const Outcome = struct {
    const Tag = enum { ok, too_long, not_event, bad_signature, out_of_memory };
    tag: Tag = .ok,
    /// Static, from `@errorName`.
    error_name: []const u8 = "",
    id: [64]u8 = undefined,
};

const Entry = struct { start: usize, len: usize, too_long: bool };

/// A batch of records and, once processed, what became of each.
const Chunk = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,
    entries: std.ArrayList(Entry) = .empty,
    outcomes: std.ArrayList(Outcome) = .empty,
    /// Scratch for parsing; reset after every record.
    arena: std.heap.ArenaAllocator,

    fn init(gpa: std.mem.Allocator) Chunk {
        return .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    fn deinit(self: *Chunk) void {
        self.bytes.deinit(self.gpa);
        self.entries.deinit(self.gpa);
        self.outcomes.deinit(self.gpa);
        self.arena.deinit();
    }

    fn deinitPtr(self: *Chunk) void {
        self.deinit();
    }

    fn reset(self: *Chunk) void {
        self.bytes.clearRetainingCapacity();
        self.entries.clearRetainingCapacity();
        self.outcomes.clearRetainingCapacity();
    }

    fn add(self: *Chunk, json: []const u8) !void {
        try self.entries.append(self.gpa, .{ .start = self.bytes.items.len, .len = json.len, .too_long = false });
        try self.bytes.appendSlice(self.gpa, json);
    }

    fn addTooLong(self: *Chunk) !void {
        try self.entries.append(self.gpa, .{ .start = self.bytes.items.len, .len = 0, .too_long = true });
    }
};

const Ctx = struct {
    signer: keys.Signer,
    err: *std.Io.Writer,
    failures: usize = 0,

    /// Parses and verifies every record of the chunk. Runs on any thread: the
    /// signer's context is only read, and everything else is the chunk's own.
    pub fn process(self: *Ctx, chunk: *Chunk) void {
        const a = chunk.arena.allocator();
        for (chunk.entries.items, chunk.outcomes.items) |entry, *out| {
            out.* = .{};
            if (entry.too_long) {
                out.tag = .too_long;
                continue;
            }
            defer _ = chunk.arena.reset(.retain_capacity);
            const json = chunk.bytes.items[entry.start..][0..entry.len];
            const parsed = event.fromJson(a, json) catch |e| {
                out.tag = .not_event;
                out.error_name = @errorName(e);
                continue;
            };
            // `event.verify` recomputes the id from the event's own fields before
            // checking the signature, so a forged id fails here too.
            const good = event.verify(a, self.signer, parsed.value) catch {
                out.tag = .out_of_memory;
                continue;
            };
            if (!good) {
                out.tag = .bad_signature;
                out.id = std.fmt.bytesToHex(parsed.value.id, .lower);
            }
        }
    }

    /// Reports the chunk's failures, in record order, on the caller's thread.
    pub fn deliver(self: *Ctx, chunk: *Chunk) !void {
        for (chunk.outcomes.items) |out| switch (out.tag) {
            .ok => {},
            .too_long => {
                try self.err.print(
                    "deed verify: skipped an event longer than {d} bytes\n",
                    .{max_record_bytes},
                );
                self.failures += 1;
            },
            .not_event => {
                try self.err.print("deed verify: not an event: {s}\n", .{out.error_name});
                self.failures += 1;
            },
            .bad_signature => {
                try self.err.print("deed verify: bad signature: {s}\n", .{out.id});
                self.failures += 1;
            },
            .out_of_memory => return error.OutOfMemory,
        };
    }
};

const Pool = parallel.Ordered(Chunk, Ctx);

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

test "ten thousand mixed records report in input order and match one thread" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    const tags = [_]event.Tag{};

    const total = 10_000;
    const records = try a.alloc([]const u8, total);
    var expected: std.ArrayList(u8) = .empty;
    const garbage = "this is not json";
    const garbage_name = if (event.fromJson(a, garbage)) |_| unreachable else |e| @errorName(e);

    for (records, 0..) |*rec, i| {
        const content = try std.fmt.allocPrint(a, "note {d}", .{i});
        const ev = try event.create(a, signer, kp, 1700000000 + @as(i64, @intCast(i)), 1, &tags, content, null);
        switch (i % 5) {
            1 => {
                var bad = ev;
                bad.content = "tampered";
                rec.* = try event.toJson(a, bad);
                try expected.print(a, "deed verify: bad signature: {s}\n", .{std.fmt.bytesToHex(ev.id, .lower)});
            },
            3 => {
                rec.* = garbage;
                try expected.print(a, "deed verify: not an event: {s}\n", .{garbage_name});
            },
            else => rec.* = try event.toJson(a, ev),
        }
    }

    // The parallel run, through the real entry point.
    const err_buf = try a.alloc(u8, expected.items.len + 1024);
    var ob: [64]u8 = undefined;
    const r = try runVerify(records, &ob, err_buf);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expectEqualStrings(expected.items, r.err);

    // And one thread, record by record, which is what the old loop did.
    var single_err: std.Io.Writer.Allocating = .init(a);
    var ctx: Ctx = .{ .signer = signer, .err = &single_err.writer };
    var chunk = Chunk.init(gpa);
    defer chunk.deinit();
    for (records) |rec| {
        chunk.reset();
        try chunk.add(rec);
        try chunk.outcomes.resize(gpa, 1);
        ctx.process(&chunk);
        try ctx.deliver(&chunk);
    }
    try std.testing.expectEqualStrings(single_err.written(), r.err);
}

test "an over-long record is attributed among its neighbours" {
    var f = try Fixture.init();
    defer f.deinit();
    var eb: [4096]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    var ctx: Ctx = .{ .signer = keys.Signer.init(), .err = &err };
    defer ctx.signer.deinit();
    var chunk = Chunk.init(std.testing.allocator);
    defer chunk.deinit();
    try chunk.add(f.signed);
    try chunk.addTooLong();
    try chunk.add(f.content_tampered);
    try chunk.outcomes.resize(std.testing.allocator, 3);
    ctx.process(&chunk);
    try ctx.deliver(&chunk);
    const lines = err.buffered();
    try std.testing.expect(std.mem.startsWith(u8, lines, "deed verify: skipped an event longer than"));
    try std.testing.expect(std.mem.indexOf(u8, lines, "bad signature") != null);
    try std.testing.expectEqual(@as(usize, 2), ctx.failures);
}
