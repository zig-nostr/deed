//! `deed store`: look after a local event store.
//!
//! Every other verb that takes `--store` only puts events in or reads them
//! back. This one is for the file itself: what is in it, a copy of it as text,
//! loading a copy back, keeping it to a size, and removing one event.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const filterflags = @import("filterflags.zig");
const storepath = @import("storepath.zig");

const event = nostr.event;
const filter = nostr.filter;
const hex = nostr.hex;
const keys = nostr.keys;
const Store = nostr.store.Store;

/// Shown beside the name in `deed help`.
pub const summary = "inspect, export, import and trim a local event store";

pub const ready = true;

pub const usage =
    \\deed store: inspect, export, import and trim a local event store
    \\
    \\Usage:
    \\  deed store stats  --store <path> [--top <n>] [--json]
    \\  deed store export --store <path> [filter options]
    \\  deed store import --store <path>
    \\  deed store prune  --store <path> --max <n>
    \\  deed store delete <id> --store <path>
    \\
    \\stats    How many events the store holds, how many of each kind (the
    \\         ten most common, or --top), the oldest and newest created_at,
    \\         and the size of the file on disk. --json prints one object.
    \\export   Every stored event that matches, newest first, one JSON event
    \\         per line on stdout. Takes the filter options of `deed req`:
    \\         -k, -a, -i, -e, -p, -d, -h, -t, -T, --search, -l, -s and -u. As in
    \\         `deed req`, -h <value> is the h tag; a bare -h at the end is help.
    \\         The long forms --kind, --author, --id, --tag, --limit, --since
    \\         and --until work too.
    \\import   Reads one JSON event per line on stdin and stores them. Each
    \\         event is verified first; a line that is not an event, or whose
    \\         id or signature is wrong, is reported on stderr with its line
    \\         number and not stored. A count is printed on stderr, and the
    \\         exit status is 1 when any line was rejected.
    \\prune    Keeps the newest n events and removes the rest.
    \\delete   Removes the event with this id (64 hex characters or note1...).
    \\
    \\Everything but import needs a store that already exists. import creates
    \\one, and the directories above it, the first time.
    \\
    \\Exits: 0 on success; 1 if the store cannot be read or a line was rejected; 2
    \\if the command line was not understood.
;

/// An event that will not fit here is one no relay would carry either.
const max_record_bytes = 1 << 20;

/// How many events are read, or written, in one go.
const page_size = 512;

const Sub = enum { stats, @"export", import, prune, delete };

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed store: needs stats, export, import, prune or delete\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    const sub = std.meta.stringToEnum(Sub, args[0]) orelse {
        try err.print("deed store: unknown subcommand '{s}'\n", .{args[0]});
        return cli.exit_usage;
    };

    var flags: filterflags.Flags = .{};
    var store_path: ?[]const u8 = null;
    var json = false;
    var top: usize = 10;
    var max: ?usize = null;
    var id_arg: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        // `-h <value>` is the h tag filter; alone at the end it asks for help.
        if (cli.isOneOf(a, &.{ "help", "--help" }) or (std.mem.eql(u8, a, "-h") and i + 1 >= args.len)) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--json")) {
            if (sub != .stats) {
                try err.print("deed store {s}: unknown option '--json'\n", .{@tagName(sub)});
                return cli.exit_usage;
            }
            json = true;
            continue;
        }
        if (!std.mem.startsWith(u8, a, "-")) {
            if (sub != .delete or id_arg != null) {
                try err.print("deed store {s}: unexpected argument '{s}'\n", .{ @tagName(sub), a });
                return cli.exit_usage;
            }
            id_arg = a;
            continue;
        }
        const is_filter = sub == .@"export" and filterflags.isFilterFlag(a);
        const known = is_filter or std.mem.eql(u8, a, "--store") or
            (sub == .stats and std.mem.eql(u8, a, "--top")) or
            (sub == .prune and std.mem.eql(u8, a, "--max"));
        if (!known) {
            try err.print("deed store {s}: unknown option '{s}'\n", .{ @tagName(sub), a });
            return cli.exit_usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed store {s}: '{s}' needs a value\n", .{ @tagName(sub), a });
            return cli.exit_usage;
        }
        const v = args[i];
        if (is_filter) {
            flags.accept(gpa, "store", a, v, err) catch |e| switch (e) {
                error.BadValue => return cli.exit_fail,
                else => return e,
            };
        } else if (std.mem.eql(u8, a, "--store")) {
            store_path = v;
        } else {
            const n = std.fmt.parseInt(usize, v, 10) catch {
                try err.print("deed store {s}: '{s}' is not a number\n", .{ @tagName(sub), v });
                return cli.exit_fail;
            };
            if (std.mem.eql(u8, a, "--top")) top = n else max = n;
        }
    }

    const path = store_path orelse {
        try err.print("deed store {s}: needs --store <path>\n", .{@tagName(sub)});
        return cli.exit_usage;
    };
    switch (sub) {
        .prune => if (max == null) {
            try err.writeAll("deed store prune: needs --max <n>\n");
            return cli.exit_usage;
        },
        .delete => if (id_arg == null) {
            try err.writeAll("deed store delete: needs an event id\n");
            return cli.exit_usage;
        },
        else => {},
    }

    const mode: storepath.Mode = if (sub == .import) .create else .existing;
    var st = (try storepath.open(gpa, io, "store", path, mode, err)) orelse return cli.exit_fail;
    var st_open = true;
    defer if (st_open) st.deinit();

    switch (sub) {
        .stats => return stats(gpa, io, &st, path, top, json, out, err),
        .@"export" => return exportEvents(gpa, &st, flags.finish(), out, err),
        .import => {
            const stdin_buf = try gpa.alloc(u8, max_record_bytes);
            defer gpa.free(stdin_buf);
            // Streaming, for the reason `verify` gives.
            var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
            return importEvents(gpa, io, &st, &stdin_reader.interface, err);
        },
        .prune => {
            const evicted = st.evictToCap(gpa, max.?) catch |e| return storeFailed(err, "prune", e);
            const kept = st.eventCount() catch |e| return storeFailed(err, "prune", e);
            try err.print("deed store: removed {d}, kept {d}\n", .{ evicted, kept });
            return cli.exit_ok;
        },
        .delete => {
            const id = filterflags.idOrKey(gpa, id_arg.?) orelse {
                try err.print("deed store delete: '{s}' is not an event id\n", .{id_arg.?});
                return cli.exit_fail;
            };
            st.deinit();
            st_open = false;
            return deleteEvent(gpa, io, path, id, err);
        },
    }
}

fn storeFailed(err: *std.Io.Writer, what: []const u8, e: anyerror) !u8 {
    try err.print("deed store {s}: the store could not answer: {s}\n", .{ what, @errorName(e) });
    return cli.exit_fail;
}

// -- paging -------------------------------------------------------------------

/// Walks the events a filter matches, newest first, a page at a time, so a
/// store of any size is read in bounded memory.
///
/// Pages are cut by `until`, which is inclusive, so events sharing the
/// boundary second are seen twice. The ids already handed out at that second
/// are kept, and the next page asks for that many more and skips them.
const Pager = struct {
    gpa: std.mem.Allocator,
    store: *Store,
    base: filter.Filter,
    /// How many more may be handed out, when the filter had a limit.
    left: ?u32,
    until: ?i64,
    seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    result: ?nostr.store.QueryResult = null,
    page: std.ArrayList(event.Event) = .empty,
    done: bool = false,

    fn init(gpa: std.mem.Allocator, store: *Store, f: filter.Filter) Pager {
        return .{ .gpa = gpa, .store = store, .base = f, .left = f.limit, .until = f.until };
    }

    fn deinit(self: *Pager) void {
        if (self.result) |*r| r.deinit();
        self.seen.deinit(self.gpa);
        self.page.deinit(self.gpa);
    }

    /// The next page of events, or null when there are no more. The slice is
    /// good until the next call.
    fn next(self: *Pager) !?[]const event.Event {
        while (!self.done) {
            if (self.left) |l| if (l == 0) {
                self.done = true;
                break;
            };
            var f = self.base;
            f.until = self.until;
            const ask: u32 = @intCast(@min(page_size + self.seen.count(), std.math.maxInt(u32)));
            f.limit = ask;
            if (self.result) |*r| r.deinit();
            self.result = null;
            self.result = try self.store.query(self.gpa, f);
            const events = self.result.?.events;
            if (events.len < ask) self.done = true;
            if (events.len == 0) break;

            self.page.clearRetainingCapacity();
            for (events) |ev| {
                if (self.until != null and ev.created_at == self.until.? and self.seen.contains(ev.id)) continue;
                if (self.left) |*l| {
                    if (l.* == 0) break;
                    l.* -= 1;
                }
                try self.page.append(self.gpa, ev);
            }

            const last = events[events.len - 1].created_at;
            self.seen.clearRetainingCapacity();
            for (events) |ev| {
                if (ev.created_at == last) try self.seen.put(self.gpa, ev.id, {});
            }
            self.until = last;
            if (self.page.items.len > 0) return self.page.items;
        }
        return null;
    }
};

// -- export -------------------------------------------------------------------

fn exportEvents(gpa: std.mem.Allocator, st: *Store, f: filter.Filter, out: *std.Io.Writer, err: *std.Io.Writer) !u8 {
    var pager = Pager.init(gpa, st, f);
    defer pager.deinit();
    while (pager.next() catch |e| return storeFailed(err, "export", e)) |page| {
        for (page) |ev| {
            const json = try event.toJson(gpa, ev);
            defer gpa.free(json);
            try out.print("{s}\n", .{json});
        }
    }
    return cli.exit_ok;
}

// -- stats --------------------------------------------------------------------

const KindCount = struct { kind: u16, count: usize };

fn moreCommon(_: void, a: KindCount, b: KindCount) bool {
    if (a.count != b.count) return a.count > b.count;
    return a.kind < b.kind;
}

fn stats(
    gpa: std.mem.Allocator,
    io: std.Io,
    st: *Store,
    path: []const u8,
    top: usize,
    json: bool,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    const total = st.eventCount() catch |e| return storeFailed(err, "stats", e);

    var counts: std.AutoHashMapUnmanaged(u16, usize) = .empty;
    defer counts.deinit(gpa);
    var newest: ?i64 = null;
    var oldest: ?i64 = null;

    var pager = Pager.init(gpa, st, .{});
    defer pager.deinit();
    while (pager.next() catch |e| return storeFailed(err, "stats", e)) |page| {
        for (page) |ev| {
            if (newest == null) newest = ev.created_at;
            oldest = ev.created_at;
            const slot = try counts.getOrPut(gpa, ev.kind);
            if (!slot.found_existing) slot.value_ptr.* = 0;
            slot.value_ptr.* += 1;
        }
    }

    var list: std.ArrayList(KindCount) = .empty;
    defer list.deinit(gpa);
    var it = counts.iterator();
    while (it.next()) |kv| try list.append(gpa, .{ .kind = kv.key_ptr.*, .count = kv.value_ptr.* });
    std.mem.sort(KindCount, list.items, {}, moreCommon);
    const shown = list.items[0..@min(top, list.items.len)];

    const bytes = fileSize(gpa, io, path);

    if (json) {
        try out.print("{{\"events\":{d},\"kinds\":[", .{total});
        for (shown, 0..) |k, n| {
            if (n > 0) try out.writeAll(",");
            try out.print("{{\"kind\":{d},\"count\":{d}}}", .{ k.kind, k.count });
        }
        try out.writeAll("],\"oldest\":");
        if (oldest) |t| try out.print("{d}", .{t}) else try out.writeAll("null");
        try out.writeAll(",\"newest\":");
        if (newest) |t| try out.print("{d}", .{t}) else try out.writeAll("null");
        try out.writeAll(",\"bytes\":");
        if (bytes) |b| try out.print("{d}", .{b}) else try out.writeAll("null");
        try out.writeAll("}\n");
        return cli.exit_ok;
    }

    try out.print("events  {d}\n", .{total});
    if (oldest) |t| try out.print("oldest  {d}\n", .{t});
    if (newest) |t| try out.print("newest  {d}\n", .{t});
    if (bytes) |b| try out.print("bytes   {d}\n", .{b});
    for (shown) |k| try out.print("kind {d}  {d}\n", .{ k.kind, k.count });
    return cli.exit_ok;
}

fn fileSize(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?u64 {
    const full = fullPath(gpa, path) catch return null;
    defer gpa.free(full);
    const stat = std.Io.Dir.cwd().statFile(io, full, .{}) catch return null;
    return stat.size;
}

/// `path` with a leading `~` made the home directory, as `storepath` does.
fn fullPath(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0 or path[0] != '~') return gpa.dupe(u8, path);
    if (path.len > 1 and path[1] != '/') return gpa.dupe(u8, path);
    const home = std.c.getenv("HOME") orelse return gpa.dupe(u8, path);
    return std.mem.concat(gpa, u8, &.{ std.mem.span(home), path[1..] });
}

// -- import -------------------------------------------------------------------

const Batch = struct {
    parsed: std.ArrayList(event.Parsed) = .empty,
    lines: std.ArrayList(usize) = .empty,
    events: std.ArrayList(event.Event) = .empty,
    results: std.ArrayList(nostr.store.IngestResult) = .empty,

    fn deinit(self: *Batch, gpa: std.mem.Allocator) void {
        self.clear();
        self.parsed.deinit(gpa);
        self.lines.deinit(gpa);
        self.events.deinit(gpa);
        self.results.deinit(gpa);
    }

    fn clear(self: *Batch) void {
        for (self.parsed.items) |*p| p.deinit();
        self.parsed.clearRetainingCapacity();
        self.lines.clearRetainingCapacity();
        self.events.clearRetainingCapacity();
    }
};

const Tally = struct {
    stored: usize = 0,
    duplicate: usize = 0,
    skipped: usize = 0,
    rejected: usize = 0,
};

fn flush(
    gpa: std.mem.Allocator,
    st: *Store,
    signer: keys.Signer,
    b: *Batch,
    tally: *Tally,
    err: *std.Io.Writer,
) !bool {
    if (b.parsed.items.len == 0) return true;
    for (b.parsed.items) |p| try b.events.append(gpa, p.value);
    try b.results.resize(gpa, b.events.items.len);
    st.ingestBatch(gpa, b.events.items, .{ .verify_with = signer }, b.results.items) catch |e| {
        try err.print("deed store import: the store refused the batch: {s}\n", .{@errorName(e)});
        return false;
    };
    for (b.results.items, b.lines.items) |r, line| switch (r) {
        .added, .replaced => tally.stored += 1,
        .duplicate => tally.duplicate += 1,
        .invalid => {
            try err.print("deed store import: line {d}: bad id or signature\n", .{line});
            tally.rejected += 1;
        },
        else => tally.skipped += 1,
    };
    b.clear();
    return true;
}

/// Reads events as JSON lines from `reader` and stores the ones that verify.
/// Nothing unverified reaches the store.
fn importEvents(gpa: std.mem.Allocator, io: std.Io, st: *Store, reader: *std.Io.Reader, err: *std.Io.Writer) !u8 {
    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();

    var batch: Batch = .{};
    defer batch.deinit(gpa);
    var tally: Tally = .{};
    // A value may span lines, so the number reported is the line it began on.
    var input = cli.Input.initJson(&.{}, reader);

    while (try input.next()) |record| {
        const line_no = input.start_line;
        const text = switch (record) {
            .line => |l| std.mem.trim(u8, l, " \t\r"),
            .too_long => {
                try err.print("deed store import: line {d}: longer than {d} bytes\n", .{ line_no, max_record_bytes });
                tally.rejected += 1;
                continue;
            },
        };
        if (text.len == 0) continue;
        const parsed = event.fromJson(gpa, text) catch |e| {
            try err.print("deed store import: line {d}: not an event: {s}\n", .{ line_no, @errorName(e) });
            tally.rejected += 1;
            continue;
        };
        try batch.parsed.append(gpa, parsed);
        try batch.lines.append(gpa, line_no);
        if (batch.parsed.items.len >= page_size) {
            if (!try flush(gpa, st, signer, &batch, &tally, err)) return cli.exit_fail;
        }
    }
    if (!try flush(gpa, st, signer, &batch, &tally, err)) return cli.exit_fail;

    try err.print(
        "deed store: imported {d}, already there {d}, not kept {d}, rejected {d}\n",
        .{ tally.stored, tally.duplicate, tally.skipped, tally.rejected },
    );
    return if (tally.rejected == 0) cli.exit_ok else cli.exit_fail;
}

// -- delete -------------------------------------------------------------------

/// Removes the event in place, in one write transaction: the record, its
/// index entries, and nothing else the store holds. Another process writing
/// to the store at the same time waits for it rather than losing its writes.
fn deleteEvent(gpa: std.mem.Allocator, io: std.Io, path: []const u8, id: [32]u8, err: *std.Io.Writer) !u8 {
    var st = (try storepath.open(gpa, io, "store", path, .existing, err)) orelse return cli.exit_fail;
    defer st.deinit();
    const removed = st.remove(gpa, id) catch |e| return storeFailed(err, "delete", e);
    if (!removed) {
        const text = try hex.encode(gpa, &id);
        defer gpa.free(text);
        try err.print("deed store delete: no event {s} in the store\n", .{text});
        return cli.exit_fail;
    }
    try err.writeAll("deed store: removed 1\n");
    return cli.exit_ok;
}

// -- tests --------------------------------------------------------------------

const testing = std.testing;

const Run = struct { code: u8, out: []u8, err: []u8 };

fn runStore(args: []const []const u8) !Run {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var eb: std.Io.Writer.Allocating = .init(testing.allocator);
    defer eb.deinit();
    const code = try run(testing.allocator, testing.io, args, &out.writer, &eb.writer);
    return .{
        .code = code,
        .out = try testing.allocator.dupe(u8, out.written()),
        .err = try testing.allocator.dupe(u8, eb.written()),
    };
}

fn freeRun(r: Run) void {
    testing.allocator.free(r.out);
    testing.allocator.free(r.err);
}

const Dir = struct {
    tmp: testing.TmpDir,
    root: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn init(self: *Dir) !void {
        self.* = .{ .tmp = testing.tmpDir(.{}) };
        self.len = try self.tmp.dir.realPath(testing.io, &self.root);
    }

    fn deinit(self: *Dir) void {
        self.tmp.cleanup();
    }

    fn path(self: *Dir, buf: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.root[0..self.len], name });
    }
};

/// Fills the store at `path` with `n` notes at times 1000, 1001, ... and
/// returns their ids in that order. Caller frees.
fn seed(path: []const u8, n: usize, kind_of: *const fn (usize) u16) ![][32]u8 {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    var ids = try testing.allocator.alloc([32]u8, n);
    errdefer testing.allocator.free(ids);
    var st = (try storepath.open(testing.allocator, testing.io, "store", path, .create, &sink.writer)) orelse return error.TestUnexpectedResult;
    defer st.deinit();
    for (0..n) |i| {
        var text: [32]u8 = undefined;
        const content = try std.fmt.bufPrint(&text, "note number {d}", .{i});
        const ev = try event.create(arena.allocator(), signer, kp, @intCast(1000 + i), kind_of(i), &.{}, content, null);
        ids[i] = ev.id;
        _ = try st.ingest(testing.allocator, ev, .{});
    }
    return ids;
}

fn kindOne(_: usize) u16 {
    return 1;
}

fn mixedKinds(i: usize) u16 {
    return if (i % 3 == 0) 7 else 1;
}

test "stats on an empty store counts nothing and has no times" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    testing.allocator.free(try seed(p, 0, kindOne));

    const r = try runStore(&.{ "stats", "--store", p, "--json" });
    defer freeRun(r);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expect(std.mem.startsWith(u8, r.out, "{\"events\":0,\"kinds\":[],\"oldest\":null,\"newest\":null,\"bytes\":"));

    const plain = try runStore(&.{ "stats", "--store", p });
    defer freeRun(plain);
    try testing.expectEqual(cli.exit_ok, plain.code);
    try testing.expect(std.mem.startsWith(u8, plain.out, "events  0\n"));
}

test "stats counts by kind, most common first, and finds both ends" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    testing.allocator.free(try seed(p, 9, mixedKinds));

    const r = try runStore(&.{ "stats", "--store", p, "--json", "--top", "1" });
    defer freeRun(r);
    try testing.expect(std.mem.startsWith(u8, r.out, "{\"events\":9,\"kinds\":[{\"kind\":1,\"count\":6}],\"oldest\":1000,\"newest\":1008,\"bytes\":"));
}

test "export then import into a fresh store gives the same events" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var b2: [std.fs.max_path_bytes]u8 = undefined;
    const p1 = try d.path(&b1, "a.mdb");
    const p2 = try d.path(&b2, "b/c/fresh.mdb");
    // More than a page, so the paging is part of what is compared.
    testing.allocator.free(try seed(p1, page_size + 40, mixedKinds));

    const first = try runStore(&.{ "export", "--store", p1 });
    defer freeRun(first);
    try testing.expectEqual(cli.exit_ok, first.code);
    try testing.expectEqual(@as(usize, page_size + 40), std.mem.count(u8, first.out, "\n"));
    try testing.expect(std.mem.indexOf(u8, first.out, "note number 551") != null);

    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    {
        var st = (try storepath.open(testing.allocator, testing.io, "store", p2, .create, &sink.writer)) orelse return error.TestUnexpectedResult;
        defer st.deinit();
        var reader: std.Io.Reader = .fixed(first.out);
        const code = try importEvents(testing.allocator, testing.io, &st, &reader, &sink.writer);
        try testing.expectEqual(cli.exit_ok, code);
    }
    try testing.expect(std.mem.indexOf(u8, sink.written(), "imported 552, already there 0, not kept 0, rejected 0") != null);

    const second = try runStore(&.{ "export", "--store", p2 });
    defer freeRun(second);
    try testing.expectEqualStrings(first.out, second.out);

    // Newest first.
    const nl = std.mem.indexOfScalar(u8, first.out, '\n').?;
    try testing.expect(std.mem.indexOf(u8, first.out[0..nl], "note number 551") != null);
}

test "export takes the filter flags, and a limit stops it" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    testing.allocator.free(try seed(p, 9, mixedKinds));

    const sevens = try runStore(&.{ "export", "--store", p, "-k", "7" });
    defer freeRun(sevens);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, sevens.out, "\n"));

    const two = try runStore(&.{ "export", "--store", p, "-l", "2", "-s", "1003" });
    defer freeRun(two);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, two.out, "\n"));
    try testing.expect(std.mem.indexOf(u8, two.out, "note number 8") != null);
}

test "events sharing one second are exported once each across a page boundary" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");

    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x33} ** 32);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    {
        var st = (try storepath.open(testing.allocator, testing.io, "store", p, .create, &sink.writer)) orelse return error.TestUnexpectedResult;
        defer st.deinit();
        for (0..page_size + 30) |i| {
            var text: [32]u8 = undefined;
            const content = try std.fmt.bufPrint(&text, "same second {d}", .{i});
            _ = try st.ingest(testing.allocator, try event.create(arena.allocator(), signer, kp, 5000, 1, &.{}, content, null), .{});
        }
    }
    const r = try runStore(&.{ "export", "--store", p });
    defer freeRun(r);
    try testing.expectEqual(@as(usize, page_size + 30), std.mem.count(u8, r.out, "\n"));
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(testing.allocator);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, r.out, "\n"), '\n');
    while (lines.next()) |l| try seen.put(testing.allocator, l, {});
    try testing.expectEqual(@as(u32, page_size + 30), seen.count());
}

test "a tampered event is rejected with its line number, the rest are kept" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var b2: [std.fs.max_path_bytes]u8 = undefined;
    const p1 = try d.path(&b1, "a.mdb");
    const p2 = try d.path(&b2, "b.mdb");
    testing.allocator.free(try seed(p1, 3, kindOne));

    const good = try runStore(&.{ "export", "--store", p1 });
    defer freeRun(good);
    // Line 2 gets different content under the same id and signature, line 4
    // is not JSON at all, and line 3 is blank.
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, good.out, "\n"), '\n');
    const l1 = lines.next().?;
    const l2 = lines.next().?;
    const l3 = lines.next().?;
    const forged = try std.mem.replaceOwned(u8, testing.allocator, l2, "note number", "forged note");
    defer testing.allocator.free(forged);
    const input = try std.fmt.allocPrint(testing.allocator, "{s}\n{s}\n\n{s}\nnot json\n", .{ l1, forged, l3 });
    defer testing.allocator.free(input);

    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    var st = (try storepath.open(testing.allocator, testing.io, "store", p2, .create, &sink.writer)) orelse return error.TestUnexpectedResult;
    defer st.deinit();
    var reader: std.Io.Reader = .fixed(input);
    const code = try importEvents(testing.allocator, testing.io, &st, &reader, &sink.writer);
    try testing.expectEqual(cli.exit_fail, code);
    const said = sink.written();
    try testing.expect(std.mem.indexOf(u8, said, "line 2: bad id or signature") != null);
    try testing.expect(std.mem.indexOf(u8, said, "line 5: not an event") != null);
    try testing.expect(std.mem.indexOf(u8, said, "imported 2, already there 0, not kept 0, rejected 2") != null);
    try testing.expectEqual(@as(usize, 2), try st.eventCount());
    try testing.expect(!(try st.hasEvent(try idOfLine(l2))));
}

fn idOfLine(line: []const u8) ![32]u8 {
    var p = try event.fromJson(testing.allocator, line);
    defer p.deinit();
    return p.value.id;
}

test "importing the same events again reports them as already there" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    testing.allocator.free(try seed(p, 3, kindOne));
    const all = try runStore(&.{ "export", "--store", p });
    defer freeRun(all);

    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    var st = (try storepath.open(testing.allocator, testing.io, "store", p, .create, &sink.writer)) orelse return error.TestUnexpectedResult;
    defer st.deinit();
    var reader: std.Io.Reader = .fixed(all.out);
    try testing.expectEqual(cli.exit_ok, try importEvents(testing.allocator, testing.io, &st, &reader, &sink.writer));
    try testing.expect(std.mem.indexOf(u8, sink.written(), "imported 0, already there 3") != null);
}

test "prune keeps the newest n" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    const ids = try seed(p, 10, kindOne);
    defer testing.allocator.free(ids);

    const r = try runStore(&.{ "prune", "--store", p, "--max", "4" });
    defer freeRun(r);
    try testing.expectEqual(cli.exit_ok, r.code);
    try testing.expectEqualStrings("deed store: removed 6, kept 4\n", r.err);
    try testing.expectEqualStrings("", r.out);

    const left = try runStore(&.{ "export", "--store", p });
    defer freeRun(left);
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, left.out, "\n"));
    for (ids[6..]) |id| {
        const text = try hex.encode(testing.allocator, &id);
        defer testing.allocator.free(text);
        try testing.expect(std.mem.indexOf(u8, left.out, text) != null);
    }
}

test "delete removes one event and keeps the others" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    const ids = try seed(p, 5, kindOne);
    defer testing.allocator.free(ids);
    const victim = try hex.encode(testing.allocator, &ids[2]);
    defer testing.allocator.free(victim);

    const r = try runStore(&.{ "delete", victim, "--store", p });
    defer freeRun(r);
    try testing.expectEqual(cli.exit_ok, r.code);

    const left = try runStore(&.{ "export", "--store", p });
    defer freeRun(left);
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, left.out, "\n"));
    try testing.expect(std.mem.indexOf(u8, left.out, victim) == null);

    const again = try runStore(&.{ "delete", victim, "--store", p });
    defer freeRun(again);
    try testing.expectEqual(cli.exit_fail, again.code);
    try testing.expect(std.mem.indexOf(u8, again.err, "no event") != null);
}

test "delete keeps what the store holds besides events" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "s.mdb");
    const ids = try seed(p, 3, kindOne);
    defer testing.allocator.free(ids);
    const z = try testing.allocator.dupeZ(u8, p);
    defer testing.allocator.free(z);
    {
        var st = try Store.open(z, .{});
        defer st.deinit();
        try st.put("app:setting", "kept");
    }
    const victim = try hex.encode(testing.allocator, &ids[1]);
    defer testing.allocator.free(victim);
    const r = try runStore(&.{ "delete", victim, "--store", p });
    defer freeRun(r);
    try testing.expectEqual(cli.exit_ok, r.code);

    var st = try Store.open(z, .{});
    defer st.deinit();
    const got = (try st.get(testing.allocator, "app:setting")) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("kept", got);
    try testing.expectEqual(@as(usize, 2), try st.eventCount());
}

test "usage mistakes exit 2 and touch nothing" {
    const none = try runStore(&.{});
    defer freeRun(none);
    try testing.expectEqual(cli.exit_usage, none.code);

    const unknown = try runStore(&.{"shred"});
    defer freeRun(unknown);
    try testing.expectEqual(cli.exit_usage, unknown.code);

    const no_store = try runStore(&.{"stats"});
    defer freeRun(no_store);
    try testing.expectEqual(cli.exit_usage, no_store.code);

    const no_max = try runStore(&.{ "prune", "--store", "x.mdb" });
    defer freeRun(no_max);
    try testing.expectEqual(cli.exit_usage, no_max.code);

    const helped = try runStore(&.{"store-help-is-not-a-verb"});
    defer freeRun(helped);
    try testing.expectEqual(cli.exit_usage, helped.code);

    const h = try runStore(&.{"help"});
    defer freeRun(h);
    try testing.expectEqual(cli.exit_ok, h.code);
    try testing.expectEqualStrings(usage, h.out);
}

test "a missing store is named and not created" {
    var d: Dir = undefined;
    try d.init();
    defer d.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try d.path(&buf, "typo/s.mdb");
    const r = try runStore(&.{ "stats", "--store", p });
    defer freeRun(r);
    try testing.expectEqual(cli.exit_fail, r.code);
    try testing.expect(std.mem.indexOf(u8, r.err, "there is no store at ") != null);
}

test "export takes -h <value> as the h tag and a bare -h as help" {
    const help = try runStore(&.{ "export", "-h" });
    defer freeRun(help);
    try testing.expectEqual(cli.exit_ok, help.code);
    try testing.expectEqualStrings(usage, help.out);

    const tag = try runStore(&.{ "export", "--store", "/nonexistent/dir/s.mdb", "-h", "group" });
    defer freeRun(tag);
    try testing.expectEqual(cli.exit_fail, tag.code);
    try testing.expectEqualStrings("", tag.out);
}
