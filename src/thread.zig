//! Assembling a conversation from the events that make it up.
//!
//! The reading of the tags follows the way a mature web client does it: a note's
//! parent is its marked `reply` e tag, else the last e tag that is not a
//! mention (the positional form older clients wrote); its root is the marked
//! `root` e tag, else the first e tag that is not a mention. A NIP-22 comment
//! keeps its parent in a lowercase `e` and its root in an uppercase `E`. The
//! replies to a root are asked for with two filters: kind 1 with `#e` and
//! comments with `#E`. This goes one step further than asking for the root
//! alone: it also asks for the replies to each reply found, down to a bounded
//! depth, because a client that marked only the parent leaves the root unnamed.
//!
//! Nothing here dials. Where events come from is a `Fetcher`, so the same walk
//! reads relays, or a local store with the network off.

const std = @import("std");
const nostr = @import("nostr");

const filter = nostr.filter;
const hex = nostr.hex;
const Event = nostr.event.Event;

pub const kind_note: u16 = 1;
pub const kind_comment: u16 = 1111;

/// Ids named in one filter. Relays refuse a filter with too many values.
const chunk = 100;

pub const Options = struct {
    /// How many steps up from the start, and how many levels of replies below
    /// the root, are followed.
    max_depth: u32 = 10,
    /// The most events a thread holds, the start and every ancestor included.
    limit: u32 = 500,
};

pub const Fetcher = struct {
    ctx: *anyopaque,
    /// Writes every event answering any of `filters` to `out`, one JSON object
    /// per line.
    run: *const fn (ctx: *anyopaque, filters: []const filter.Filter, out: *std.Io.Writer) anyerror!void,
    /// Told the root's author once the root is known, so a fetcher that has to
    /// choose relays can choose them by who wrote it.
    root_found: ?*const fn (ctx: *anyopaque, author: [32]u8) anyerror!void = null,
};

fn tagName(t: nostr.event.Tag, name: []const u8) bool {
    return t.len >= 2 and std.mem.eql(u8, t[0], name);
}

fn marker(t: nostr.event.Tag) []const u8 {
    return if (t.len >= 4) t[3] else "";
}

fn idOf(t: nostr.event.Tag) ?[32]u8 {
    if (t.len < 2) return null;
    return hex.decodeFixed(32, t[1]) catch null;
}

/// The event this one replies to, if it names one.
pub fn parentOf(ev: Event) ?[32]u8 {
    if (ev.kind == kind_comment) {
        for (ev.tags) |t| if (tagName(t, "e")) if (idOf(t)) |id| return id;
        for (ev.tags) |t| if (tagName(t, "E")) if (idOf(t)) |id| return id;
        return null;
    }
    if (ev.kind != kind_note) return null;
    for (ev.tags) |t| {
        if (tagName(t, "e") and std.mem.eql(u8, marker(t), "reply")) if (idOf(t)) |id| return id;
    }
    var found: ?[32]u8 = null;
    for (ev.tags) |t| {
        if (!tagName(t, "e") or std.mem.eql(u8, marker(t), "mention")) continue;
        if (idOf(t)) |id| found = id;
    }
    return found;
}

/// The event this one says starts the conversation, if it names one.
pub fn rootOf(ev: Event) ?[32]u8 {
    if (ev.kind == kind_comment) {
        for (ev.tags) |t| if (tagName(t, "E")) if (idOf(t)) |id| return id;
        return null;
    }
    if (ev.kind != kind_note) return null;
    for (ev.tags) |t| {
        if (tagName(t, "e") and std.mem.eql(u8, marker(t), "root")) if (idOf(t)) |id| return id;
    }
    for (ev.tags) |t| {
        if (!tagName(t, "e") or std.mem.eql(u8, marker(t), "mention")) continue;
        if (idOf(t)) |id| return id;
    }
    return null;
}

pub const Thread = struct {
    gpa: std.mem.Allocator,
    items: std.ArrayList(nostr.event.Parsed) = .empty,
    index: std.AutoHashMapUnmanaged([32]u8, usize) = .empty,
    signer: nostr.keys.Signer,
    /// Lines a fetcher wrote that were not a correctly signed event.
    rejected: usize = 0,
    start: ?usize = null,
    root: ?usize = null,

    pub fn init(gpa: std.mem.Allocator) Thread {
        return .{ .gpa = gpa, .signer = nostr.keys.Signer.init() };
    }

    pub fn deinit(self: *Thread) void {
        for (self.items.items) |*p| p.deinit();
        self.items.deinit(self.gpa);
        self.index.deinit(self.gpa);
        self.signer.deinit();
    }

    pub fn event(self: *const Thread, i: usize) Event {
        return self.items.items[i].value;
    }

    /// Runs the fetcher and keeps what is new. Returns the index of the first
    /// new event; those added are `[returned, items.len)`.
    fn gather(self: *Thread, fetcher: Fetcher, filters: []const filter.Filter, cap: usize) !usize {
        const first = self.items.items.len;
        var buf: std.Io.Writer.Allocating = .init(self.gpa);
        defer buf.deinit();
        try fetcher.run(fetcher.ctx, filters, &buf.writer);
        var lines = std.mem.splitScalar(u8, buf.written(), '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (self.items.items.len - first >= cap) break;
            var parsed = nostr.event.fromJson(self.gpa, line) catch {
                self.rejected += 1;
                continue;
            };
            errdefer parsed.deinit();
            if (self.index.contains(parsed.value.id) or
                !(nostr.event.verify(self.gpa, self.signer, parsed.value) catch false))
            {
                if (!self.index.contains(parsed.value.id)) self.rejected += 1;
                parsed.deinit();
                continue;
            }
            try self.items.append(self.gpa, parsed);
            try self.index.put(self.gpa, parsed.value.id, self.items.items.len - 1);
        }
        return first;
    }

    fn room(self: *const Thread, opts: Options) usize {
        return if (self.items.items.len >= opts.limit) 0 else opts.limit - self.items.items.len;
    }
};

/// Finds `start`, walks up to the top of its conversation, then collects the
/// replies below. Returns with `start` null when nothing named it.
pub fn assemble(gpa: std.mem.Allocator, fetcher: Fetcher, start_id: [32]u8, opts: Options) !Thread {
    var t = Thread.init(gpa);
    errdefer t.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The start event.
    {
        defer _ = arena_state.reset(.retain_capacity);
        const ids = try arena.dupe([32]u8, &.{start_id});
        const filters = [_]filter.Filter{.{ .ids = ids }};
        _ = try t.gather(fetcher, &filters, 1);
    }
    const start = t.index.get(start_id) orelse return t;
    t.start = start;

    // Up. The parent and the named root are asked together, since a parent
    // that is missing leaves the root as the next best thing to climb to.
    var chain: std.ArrayList(usize) = .empty;
    defer chain.deinit(gpa);
    try chain.append(gpa, start);
    var cur = start;
    var steps: u32 = 0;
    while (steps < opts.max_depth) : (steps += 1) {
        const ev = t.event(cur);
        const parent = parentOf(ev);
        const root = rootOf(ev);
        if (parent == null and root == null) break;
        var want: [2][32]u8 = undefined;
        var n: usize = 0;
        for ([_]?[32]u8{ parent, root }) |maybe| {
            const id = maybe orelse continue;
            if (n == 1 and std.mem.eql(u8, &want[0], &id)) continue;
            want[n] = id;
            n += 1;
        }
        var next: ?usize = null;
        for (want[0..n]) |id| {
            if (t.index.get(id)) |known| {
                next = known;
                break;
            }
        }
        if (next == null) {
            defer _ = arena_state.reset(.retain_capacity);
            const ids = try arena.dupe([32]u8, want[0..n]);
            const filters = [_]filter.Filter{.{ .ids = ids }};
            _ = try t.gather(fetcher, &filters, t.room(opts));
            for (want[0..n]) |id| {
                if (t.index.get(id)) |found| {
                    next = found;
                    break;
                }
            }
        }
        const up = next orelse break;
        // Back at something already on the way up: a loop, and the top of it
        // is as far as this goes.
        if (std.mem.indexOfScalar(usize, chain.items, up) != null) break;
        try chain.append(gpa, up);
        cur = up;
    }
    t.root = cur;
    if (fetcher.root_found) |cb| try cb(fetcher.ctx, t.event(cur).pubkey);

    // Down. Every event on the way up is asked about too, so the siblings of
    // the start are found even when a client left the root out of its tags.
    // So are the parent and root the top event names but nobody had: its
    // other replies are still the rest of the conversation.
    var frontier: std.ArrayList([32]u8) = .empty;
    defer frontier.deinit(gpa);
    for (chain.items) |i| try frontier.append(gpa, t.event(i).id);
    const top = t.event(cur);
    for ([_]?[32]u8{ parentOf(top), rootOf(top) }) |maybe| {
        const id = maybe orelse continue;
        if (!t.index.contains(id)) try frontier.append(gpa, id);
    }
    var level: u32 = 0;
    while (level < opts.max_depth and frontier.items.len > 0 and t.room(opts) > 0) : (level += 1) {
        const first_new = t.items.items.len;
        var at: usize = 0;
        while (at < frontier.items.len and t.room(opts) > 0) : (at += chunk) {
            defer _ = arena_state.reset(.retain_capacity);
            const part = frontier.items[at..@min(at + chunk, frontier.items.len)];
            const values = try arena.alloc([]const u8, part.len);
            for (part, values) |id, *v| v.* = try hex.encode(arena, &id);
            const e_tags = try arena.dupe(filter.TagFilter, &.{.{ .letter = 'e', .values = values }});
            const big_e_tags = try arena.dupe(filter.TagFilter, &.{.{ .letter = 'E', .values = values }});
            const limit: u32 = @intCast(@min(t.room(opts), std.math.maxInt(u32)));
            const filters = [_]filter.Filter{
                .{ .kinds = &.{ kind_note, kind_comment }, .tags = e_tags, .limit = limit },
                .{ .kinds = &.{kind_comment}, .tags = big_e_tags, .limit = limit },
            };
            _ = try t.gather(fetcher, &filters, t.room(opts));
        }
        frontier.clearRetainingCapacity();
        var i = first_new;
        while (i < t.items.items.len) : (i += 1) try frontier.append(gpa, t.event(i).id);
    }
    return t;
}

pub const Row = struct { index: usize, depth: u32 };

fn byTime(t: *const Thread, a: usize, b: usize) bool {
    const x = t.event(a);
    const y = t.event(b);
    if (x.created_at != y.created_at) return x.created_at < y.created_at;
    return std.mem.order(u8, &x.id, &y.id) == .lt;
}

/// The thread, root first and then by `created_at`, oldest first. Depth is how
/// many replies lie between an event and the root; an event whose parent was
/// not found hangs from the root.
pub fn flat(gpa: std.mem.Allocator, t: *const Thread) ![]Row {
    const n = t.items.items.len;
    const root = t.root orelse return gpa.alloc(Row, 0);
    const depths = try depthsOf(gpa, t, root);
    defer gpa.free(depths);
    const order = try gpa.alloc(usize, n);
    defer gpa.free(order);
    for (order, 0..) |*o, i| o.* = i;
    std.mem.sort(usize, order, t, struct {
        fn less(th: *const Thread, a: usize, b: usize) bool {
            return byTime(th, a, b);
        }
    }.less);
    const rows = try gpa.alloc(Row, n);
    rows[0] = .{ .index = root, .depth = 0 };
    var k: usize = 1;
    for (order) |i| {
        if (i == root) continue;
        rows[k] = .{ .index = i, .depth = depths[i] };
        k += 1;
    }
    return rows;
}

/// The thread as a tree, depth first, each event's replies oldest first.
pub fn tree(gpa: std.mem.Allocator, t: *const Thread) ![]Row {
    const n = t.items.items.len;
    const root = t.root orelse return gpa.alloc(Row, 0);
    const parent = try parentsOf(gpa, t, root);
    defer gpa.free(parent);
    // Children of each node, oldest first, by sorting every sibling set once.
    const order = try gpa.alloc(usize, n);
    defer gpa.free(order);
    for (order, 0..) |*o, i| o.* = i;
    std.mem.sort(usize, order, t, struct {
        fn less(th: *const Thread, a: usize, b: usize) bool {
            return byTime(th, a, b);
        }
    }.less);

    var rows: std.ArrayList(Row) = .empty;
    errdefer rows.deinit(gpa);
    const Frame = struct { node: usize, depth: u32 };
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(gpa);
    const seen = try gpa.alloc(bool, n);
    defer gpa.free(seen);
    @memset(seen, false);
    try stack.append(gpa, .{ .node = root, .depth = 0 });
    while (stack.pop()) |f| {
        if (seen[f.node]) continue;
        seen[f.node] = true;
        try rows.append(gpa, .{ .index = f.node, .depth = f.depth });
        // Pushed newest first so the oldest is popped first.
        var j = order.len;
        while (j > 0) {
            j -= 1;
            const c = order[j];
            if (c != root and parent[c] == f.node and !seen[c]) try stack.append(gpa, .{ .node = c, .depth = f.depth + 1 });
        }
    }
    // A loop among parents leaves its members unreached; they hang from the root.
    for (order) |c| if (!seen[c]) try rows.append(gpa, .{ .index = c, .depth = 1 });
    return rows.toOwnedSlice(gpa);
}

/// Each event's parent within the thread. The root's is itself, and an event
/// whose parent is not in the thread, or names itself, gets the root.
fn parentsOf(gpa: std.mem.Allocator, t: *const Thread, root: usize) ![]usize {
    const parent = try gpa.alloc(usize, t.items.items.len);
    for (parent, 0..) |*p, i| {
        p.* = root;
        if (i == root) continue;
        if (parentOf(t.event(i))) |id| {
            if (t.index.get(id)) |pi| if (pi != i) {
                p.* = pi;
            };
        }
    }
    return parent;
}

fn depthsOf(gpa: std.mem.Allocator, t: *const Thread, root: usize) ![]u32 {
    const n = t.items.items.len;
    const parent = try parentsOf(gpa, t, root);
    defer gpa.free(parent);
    const depths = try gpa.alloc(u32, n);
    for (depths, 0..) |*d, i| {
        // Climb, never more than n steps: a loop gives up and counts as 1.
        var steps: u32 = 0;
        var at = i;
        while (at != root and steps <= n) : (steps += 1) at = parent[at];
        d.* = if (at == root) steps else 1;
    }
    return depths;
}

const testing = std.testing;

fn testNote(a: std.mem.Allocator, signer: nostr.keys.Signer, kp: nostr.keys.KeyPair, at: i64, kind: u16, tags: []const nostr.event.Tag) !Event {
    return nostr.event.create(a, signer, kp, at, kind, tags, "x", null);
}

test "a marked reply names its parent and root, an unmarked list is read by position" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var signer = try nostr.keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x61} ** 32);
    const r = "11" ** 32;
    const m = "22" ** 32;
    const p = "33" ** 32;

    const marked = try testNote(a, signer, kp, 1, 1, &.{ &.{ "e", r, "", "root" }, &.{ "e", m, "", "mention" }, &.{ "e", p, "", "reply" } });
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, p)), &parentOf(marked).?);
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, r)), &rootOf(marked).?);

    const positional = try testNote(a, signer, kp, 2, 1, &.{ &.{ "e", r }, &.{ "e", p } });
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, p)), &parentOf(positional).?);
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, r)), &rootOf(positional).?);

    const only_root = try testNote(a, signer, kp, 3, 1, &.{&.{ "e", r, "", "root" }});
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, r)), &parentOf(only_root).?);

    const comment = try testNote(a, signer, kp, 4, 1111, &.{ &.{ "E", r }, &.{ "e", p } });
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, p)), &parentOf(comment).?);
    try testing.expectEqualSlices(u8, &(try hex.decodeFixed(32, r)), &rootOf(comment).?);

    const bare = try testNote(a, signer, kp, 5, 1, &.{});
    try testing.expect(parentOf(bare) == null and rootOf(bare) == null);
    const junk = try testNote(a, signer, kp, 6, 1, &.{&.{ "e", "nothex" }});
    try testing.expect(parentOf(junk) == null);
}
