//! The flags that describe a NIP-01 filter, shared by every verb that builds
//! one: `-k -a -i -e -p -t -l -s -u` and their long forms.
//!
//! A verb keeps its own loop over the arguments, handles the flags that are
//! its own, and hands the rest to `Flags`. Error text names the verb, so each
//! one still reads as its own.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");

const filter = nostr.filter;
const hex = nostr.hex;

pub const max_values = 64;

/// Ids and authors may be many: a list of ids read from another command is
/// the ordinary way to ask for them. A verb that sends them splits them across
/// filters, see `chunk_size`.
pub const max_keys = 2048;

/// Relays commonly refuse a filter naming more ids or authors than this, so a
/// request with more is sent as several filters of at most this many.
pub const chunk_size = 500;

/// The most filters one filter is split into. Two lists that both pass
/// `chunk_size` multiply, so a request needing more than this is refused.
pub const max_pieces = 16;

/// What a repeated flag collects. Fixed, because a command line naming more
/// than this many tag values is a file being piped in by the wrong route.
pub fn Collected(comptime T: type) type {
    return CollectedN(T, max_values);
}

pub fn CollectedN(comptime T: type, comptime n: usize) type {
    return struct {
        items: [n]T = undefined,
        len: usize = 0,

        pub fn push(self: *@This(), v: T) bool {
            if (self.len >= self.items.len) return false;
            self.items[self.len] = v;
            self.len += 1;
            return true;
        }
        pub fn slice(self: *const @This()) ?[]const T {
            return if (self.len == 0) null else self.items[0..self.len];
        }
    };
}

/// A 32-byte key or id, as `npub1…`/`note1…`/`nsec1…` or 64 hex characters.
pub fn idOrKey(gpa: std.mem.Allocator, s: []const u8) ?[32]u8 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (t.len == 64) return hex.decodeFixed(32, t) catch null;
    if (keyinput.hasPrefix(t, "npub1")) return nostr.nip19.decodeNpub(gpa, t) catch null;
    if (keyinput.hasPrefix(t, "note1")) return nostr.nip19.decodeNote(gpa, t) catch null;
    return null;
}

pub const ParseError = error{ Usage, BadValue };

/// The flags that take a value and describe a filter.
pub const value_flags = [_][]const u8{
    "-k",      "--kind",   "-a",      "--author", "-i",      "--id",
    "-e",      "-p",       "-t",      "-l",       "--limit", "-s",
    "--since", "-u",       "--until", "-d",       "-h",      "-T",
    "--tag",   "--search",
};

/// True when `a` is one of the filter flags (all of which take a value).
pub fn isFilterFlag(a: []const u8) bool {
    return cli.isOneOf(a, &value_flags);
}

/// One `#x` constraint value, before values are grouped by letter.
const TagPair = struct { letter: u8, value: []const u8 };

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn nowSeconds() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Timestamp.now(io, .real).toSeconds();
}

/// A point in time, as unix seconds. Takes a plain number of seconds, `now`,
/// a span back from `now` (`90s`, `30m`, `2h`, `3d`, `1w`), a date
/// (`2026-10-01`, midnight UTC) or a UTC date and time
/// (`2026-10-01T12:30:00Z`, seconds and the `Z` optional).
pub fn parseTime(v: []const u8, now: i64) ?i64 {
    if (v.len == 0) return null;
    if (std.fmt.parseInt(i64, v, 10)) |n| return n else |_| {}
    if (std.mem.eql(u8, v, "now")) return now;

    const unit = v[v.len - 1];
    const per: ?i64 = switch (unit) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        'w' => 604800,
        else => null,
    };
    if (per) |p| {
        const n = std.fmt.parseInt(i64, v[0 .. v.len - 1], 10) catch return null;
        if (n < 0) return null;
        const span = std.math.mul(i64, n, p) catch return null;
        return now - span;
    }

    // YYYY-MM-DD, then optionally T or space, HH:MM, optionally :SS, optionally Z.
    if (v.len < 10 or v[4] != '-' or v[7] != '-') return null;
    const y = std.fmt.parseInt(i64, v[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(i64, v[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, v[8..10], 10) catch return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31) return null;
    var secs: i64 = daysFromCivil(y, mo, d) * 86400;
    var rest = v[10..];
    if (rest.len > 0 and rest[rest.len - 1] == 'Z') rest = rest[0 .. rest.len - 1];
    if (rest.len == 0) return secs;
    if (rest[0] != 'T' and rest[0] != ' ') return null;
    rest = rest[1..];
    if (rest.len != 5 and rest.len != 8) return null;
    if (rest[2] != ':' or (rest.len == 8 and rest[5] != ':')) return null;
    const hh = std.fmt.parseInt(i64, rest[0..2], 10) catch return null;
    const mm = std.fmt.parseInt(i64, rest[3..5], 10) catch return null;
    const ss: i64 = if (rest.len == 8) (std.fmt.parseInt(i64, rest[6..8], 10) catch return null) else 0;
    if (hh > 23 or mm > 59 or ss > 60) return null;
    secs += hh * 3600 + mm * 60 + ss;
    return secs;
}

/// Everything the filter flags collect while a command line is read.
///
/// `finish` returns a filter whose slices point into this struct, so it must
/// stay where it is for as long as that filter is used.
pub const Flags = struct {
    ids: CollectedN([32]u8, max_keys) = .{},
    authors: CollectedN([32]u8, max_keys) = .{},
    kinds: Collected(u16) = .{},
    tag_pairs: Collected(TagPair) = .{},
    tag_filters: [max_values]filter.TagFilter = undefined,
    tag_values: [max_values][]const u8 = undefined,
    search: ?[]const u8 = null,
    limit: ?u32 = null,
    since: ?i64 = null,
    until: ?i64 = null,

    /// True when any flag has been taken.
    pub fn any(self: *const Flags) bool {
        return self.ids.len + self.authors.len + self.kinds.len + self.tag_pairs.len > 0 or
            self.search != null or self.limit != null or self.since != null or self.until != null;
    }

    fn tooMany(verb: []const u8, what: []const u8, max: usize, err: *std.Io.Writer) !void {
        try err.print("deed {s}: too many {s} (at most {d}); pass the rest in a JSON filter\n", .{ verb, what, max });
        return ParseError.BadValue;
    }

    fn pushTag(self: *Flags, verb: []const u8, letter: u8, v: []const u8, err: *std.Io.Writer) !void {
        if (!self.tag_pairs.push(.{ .letter = letter, .value = v })) {
            try err.print("deed {s}: too many tag values\n", .{verb});
            return ParseError.BadValue;
        }
    }

    /// Takes one flag, `flag`, with its value `v`. `flag` must satisfy
    /// `isFilterFlag`. `verb` names the command in the message a bad value
    /// earns, which is written to `err`.
    pub fn accept(
        self: *Flags,
        gpa: std.mem.Allocator,
        verb: []const u8,
        flag: []const u8,
        v: []const u8,
        err: *std.Io.Writer,
    ) !void {
        const a = flag;
        if (cli.isOneOf(a, &.{ "-k", "--kind" })) {
            const n = std.fmt.parseInt(u16, v, 10) catch {
                try err.print("deed {s}: '{s}' is not a kind number\n", .{ verb, v });
                return ParseError.BadValue;
            };
            if (!self.kinds.push(n)) return tooMany(verb, "kinds", self.kinds.items.len, err);
        } else if (cli.isOneOf(a, &.{ "-a", "--author" })) {
            const k = idOrKey(gpa, v) orelse {
                try err.print("deed {s}: '{s}' is not a key\n", .{ verb, v });
                return ParseError.BadValue;
            };
            if (!self.authors.push(k)) return tooMany(verb, "authors", self.authors.items.len, err);
        } else if (cli.isOneOf(a, &.{ "-i", "--id" })) {
            const k = idOrKey(gpa, v) orelse {
                try err.print("deed {s}: '{s}' is not an id\n", .{ verb, v });
                return ParseError.BadValue;
            };
            if (!self.ids.push(k)) return tooMany(verb, "ids", self.ids.items.len, err);
        } else if (a.len == 2 and std.mem.indexOfScalar(u8, "eptdh", a[1]) != null and a[0] == '-') {
            try self.pushTag(verb, a[1], v, err);
        } else if (cli.isOneOf(a, &.{ "-T", "--tag" })) {
            if (v.len < 2 or v[1] != '=' or !std.ascii.isAlphabetic(v[0])) {
                try err.print("deed {s}: '{s}' is not a tag like x=value\n", .{ verb, v });
                return ParseError.BadValue;
            }
            try self.pushTag(verb, v[0], v[2..], err);
        } else if (std.mem.eql(u8, a, "--search")) {
            self.search = v;
        } else if (cli.isOneOf(a, &.{ "-l", "--limit" })) {
            self.limit = std.fmt.parseInt(u32, v, 10) catch {
                try err.print("deed {s}: '{s}' is not a limit\n", .{ verb, v });
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-s", "--since" })) {
            self.since = parseTime(v, nowSeconds()) orelse {
                try err.print("deed {s}: '{s}' is not a time (unix seconds, 2h, 3d, 2026-10-01)\n", .{ verb, v });
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-u", "--until" })) {
            self.until = parseTime(v, nowSeconds()) orelse {
                try err.print("deed {s}: '{s}' is not a time (unix seconds, 2h, 3d, 2026-10-01)\n", .{ verb, v });
                return ParseError.BadValue;
            };
        }
    }

    /// The filter the flags described.
    pub fn finish(self: *Flags) filter.Filter {
        var f = filter.Filter{};
        f.limit = self.limit;
        f.since = self.since;
        f.until = self.until;
        f.search = self.search;
        f.ids = self.ids.slice();
        f.authors = self.authors.slice();
        f.kinds = self.kinds.slice();

        // Grouped by letter. `e`, `p` and `t` come first, in that order, so the
        // filter reads the same whatever order the flags came in; any other
        // letter follows in the order it was first named.
        const pairs = self.tag_pairs.items[0..self.tag_pairs.len];
        var letters: [max_values]u8 = undefined;
        var n_letters: usize = 0;
        for ("ept") |c| {
            for (pairs) |p| if (p.letter == c) {
                letters[n_letters] = c;
                n_letters += 1;
                break;
            };
        }
        for (pairs) |p| {
            if (std.mem.indexOfScalar(u8, letters[0..n_letters], p.letter) == null) {
                letters[n_letters] = p.letter;
                n_letters += 1;
            }
        }
        var used: usize = 0;
        for (letters[0..n_letters], 0..) |c, i| {
            const start = used;
            for (pairs) |p| if (p.letter == c) {
                self.tag_values[used] = p.value;
                used += 1;
            };
            self.tag_filters[i] = .{ .letter = c, .values = self.tag_values[start..used] };
        }
        if (n_letters > 0) f.tags = self.tag_filters[0..n_letters];
        return f;
    }
};

/// `filters` with any filter that names more than `chunk_size` ids or authors
/// replaced by several that together name the same ones, so that no relay
/// refuses the request for its size and no id is dropped. The result lives in
/// `arena`; filters that need no splitting are copied as they are.
pub fn splitLarge(arena: std.mem.Allocator, filters: []const filter.Filter) error{ OutOfMemory, TooManyFilters }![]filter.Filter {
    var out: std.ArrayList(filter.Filter) = .empty;
    for (filters) |f| {
        const n_ids = if (f.ids) |v| v.len else 0;
        const n_authors = if (f.authors) |v| v.len else 0;
        if (n_ids <= chunk_size and n_authors <= chunk_size) {
            try out.append(arena, f);
            continue;
        }
        const id_chunks = @max(1, (n_ids + chunk_size - 1) / chunk_size);
        const author_chunks = @max(1, (n_authors + chunk_size - 1) / chunk_size);
        // Ids and authors in one filter are an AND, so a list is split only
        // into chunks that each stand alone, and the other list is repeated
        // whole in every piece. When both are long that is a product.
        if (id_chunks * author_chunks > max_pieces) return error.TooManyFilters;
        for (0..id_chunks) |ci| {
            for (0..author_chunks) |ca| {
                var piece = f;
                if (f.ids) |v| piece.ids = v[ci * chunk_size .. @min(v.len, (ci + 1) * chunk_size)];
                if (f.authors) |v| piece.authors = v[ca * chunk_size .. @min(v.len, (ca + 1) * chunk_size)];
                try out.append(arena, piece);
            }
        }
    }
    return out.toOwnedSlice(arena);
}

/// Reads one filter object, as JSON text, into a `Filter` whose slices live in
/// `arena`. Unknown keys are ignored. Errors are written to `err`, naming `verb`.
pub fn parseJson(
    arena: std.mem.Allocator,
    verb: []const u8,
    text: []const u8,
    err: *std.Io.Writer,
) !filter.Filter {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch {
        try err.print("deed {s}: the filter is not valid JSON\n", .{verb});
        return ParseError.BadValue;
    };
    return fromValue(arena, verb, root, err);
}

fn badField(err: *std.Io.Writer, verb: []const u8, key: []const u8) !filter.Filter {
    try err.print("deed {s}: the filter's \"{s}\" is not valid\n", .{ verb, key });
    return ParseError.BadValue;
}

pub fn fromValue(
    arena: std.mem.Allocator,
    verb: []const u8,
    root: std.json.Value,
    err: *std.Io.Writer,
) !filter.Filter {
    if (root != .object) {
        try err.print("deed {s}: a filter is a JSON object\n", .{verb});
        return ParseError.BadValue;
    }
    var f = filter.Filter{};
    var tags: std.ArrayList(filter.TagFilter) = .empty;
    var it = root.object.iterator();
    while (it.next()) |kv| {
        const key = kv.key_ptr.*;
        const val = kv.value_ptr.*;
        if (std.mem.eql(u8, key, "ids") or std.mem.eql(u8, key, "authors")) {
            if (val != .array) return badField(err, verb, key);
            const out = try arena.alloc([32]u8, val.array.items.len);
            for (val.array.items, 0..) |item, i| {
                if (item != .string) return badField(err, verb, key);
                out[i] = idOrKey(arena, item.string) orelse return badField(err, verb, key);
            }
            if (key[0] == 'i') f.ids = out else f.authors = out;
        } else if (std.mem.eql(u8, key, "kinds")) {
            if (val != .array) return badField(err, verb, key);
            const out = try arena.alloc(u16, val.array.items.len);
            for (val.array.items, 0..) |item, i| {
                if (item != .integer) return badField(err, verb, key);
                out[i] = std.math.cast(u16, item.integer) orelse return badField(err, verb, key);
            }
            f.kinds = out;
        } else if (std.mem.eql(u8, key, "since") or std.mem.eql(u8, key, "until")) {
            if (val != .integer) return badField(err, verb, key);
            if (key[0] == 's') f.since = val.integer else f.until = val.integer;
        } else if (std.mem.eql(u8, key, "limit")) {
            if (val != .integer) return badField(err, verb, key);
            f.limit = std.math.cast(u32, val.integer) orelse return badField(err, verb, key);
        } else if (std.mem.eql(u8, key, "search")) {
            if (val != .string) return badField(err, verb, key);
            f.search = val.string;
        } else if (key.len == 2 and key[0] == '#' and std.ascii.isAlphabetic(key[1])) {
            if (val != .array) return badField(err, verb, key);
            const out = try arena.alloc([]const u8, val.array.items.len);
            for (val.array.items, 0..) |item, i| {
                if (item != .string) return badField(err, verb, key);
                out[i] = item.string;
            }
            try tags.append(arena, .{ .letter = key[1], .values = out });
        }
    }
    if (tags.items.len > 0) f.tags = tags.items;
    return f;
}

/// `over` laid on `base`: every field `over` sets replaces the one in `base`,
/// and a tag letter `over` names replaces that letter's values. Slices of the
/// result live in `arena` or in the inputs.
pub fn overlay(arena: std.mem.Allocator, base: filter.Filter, over: filter.Filter) !filter.Filter {
    var f = base;
    if (over.ids) |v| f.ids = v;
    if (over.authors) |v| f.authors = v;
    if (over.kinds) |v| f.kinds = v;
    if (over.since) |v| f.since = v;
    if (over.until) |v| f.until = v;
    if (over.limit) |v| f.limit = v;
    if (over.search) |v| f.search = v;
    if (over.tags) |ot| {
        var list: std.ArrayList(filter.TagFilter) = .empty;
        if (base.tags) |bt| for (bt) |t| {
            var replaced = false;
            for (ot) |o| if (o.letter == t.letter) {
                replaced = true;
            };
            if (!replaced) try list.append(arena, t);
        };
        try list.appendSlice(arena, ot);
        f.tags = list.items;
    }
    return f;
}

test "more than a relay takes of ids or authors is split across filters, losing none" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ids = try arena.alloc([32]u8, 1200);
    for (ids, 0..) |*id, i| id.* = [_]u8{0} ** 31 ++ [_]u8{@truncate(i)};
    const small = filter.Filter{ .kinds = &.{1} };
    const big = filter.Filter{ .ids = ids, .limit = 7 };
    const out = try splitLarge(arena, &.{ small, big });
    try std.testing.expectEqual(@as(usize, 4), out.len);
    try std.testing.expectEqual(@as(usize, 500), out[1].ids.?.len);
    try std.testing.expectEqual(@as(usize, 500), out[2].ids.?.len);
    try std.testing.expectEqual(@as(usize, 200), out[3].ids.?.len);
    try std.testing.expectEqual(@as(?u32, 7), out[3].limit);
    const exact = try splitLarge(arena, &.{.{ .ids = ids[0..500] }});
    try std.testing.expectEqual(@as(usize, 1), exact.len);
}

test "splitting keeps the other list whole and caps the number of pieces" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ids = try arena.alloc([32]u8, 2048);
    const authors = try arena.alloc([32]u8, 400);
    for (ids, 0..) |*id, i| id.* = [_]u8{0} ** 30 ++ [_]u8{ @truncate(i >> 8), @truncate(i) };
    for (authors, 0..) |*id, i| id.* = [_]u8{1} ** 30 ++ [_]u8{ @truncate(i >> 8), @truncate(i) };
    // One list over the chunk size: it is split, the other is kept whole.
    const one = try splitLarge(arena, &.{.{ .ids = ids, .authors = authors }});
    try std.testing.expectEqual(@as(usize, 5), one.len);
    for (one) |p| try std.testing.expectEqual(@as(usize, 400), p.authors.?.len);
    // Both over it: a product of chunks, within the cap.
    const both = try splitLarge(arena, &.{.{ .ids = ids[0..1200], .authors = ids[0..1200] }});
    try std.testing.expectEqual(@as(usize, 9), both.len);
    // 2048 x 2048 would be 25 pieces.
    try std.testing.expectError(error.TooManyFilters, splitLarge(arena, &.{.{ .ids = ids, .authors = ids }}));
}

test "filterflags: repeated flags collect and the filter points at them" {
    var flags: Flags = .{};
    var eb: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    try flags.accept(std.testing.allocator, "x", "-k", "1", &err);
    try flags.accept(std.testing.allocator, "x", "--kind", "6", &err);
    try flags.accept(std.testing.allocator, "x", "-t", "nostr", &err);
    try flags.accept(std.testing.allocator, "x", "-l", "5", &err);
    const f = flags.finish();
    try std.testing.expectEqual(@as(usize, 2), f.kinds.?.len);
    try std.testing.expectEqual(@as(u32, 5), f.limit.?);
    try std.testing.expectEqual(@as(u8, 't'), f.tags.?[0].letter);
}

test "filterflags: a bad value names the verb that was asked" {
    var flags: Flags = .{};
    var eb: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    try std.testing.expectError(
        ParseError.BadValue,
        flags.accept(std.testing.allocator, "count", "-k", "many", &err),
    );
    try std.testing.expectEqualStrings("deed count: 'many' is not a kind number\n", err.buffered());
}

test "filterflags: only the filter flags are claimed" {
    try std.testing.expect(isFilterFlag("--author"));
    try std.testing.expect(!isFilterFlag("--store"));
    try std.testing.expect(!isFilterFlag("--bare"));
}

test "filterflags: generic tags, d, h and search reach the filter, e p t first" {
    var flags: Flags = .{};
    var eb: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    const gpa = std.testing.allocator;
    try flags.accept(gpa, "x", "-T", "r=wss://a", &err);
    try flags.accept(gpa, "x", "-d", "slug", &err);
    try flags.accept(gpa, "x", "-h", "grp", &err);
    try flags.accept(gpa, "x", "--tag", "r=wss://b", &err);
    try flags.accept(gpa, "x", "-t", "zig", &err);
    try flags.accept(gpa, "x", "--search", "best nostr", &err);
    const f = flags.finish();
    try std.testing.expectEqualStrings("best nostr", f.search.?);
    const t = f.tags.?;
    try std.testing.expectEqual(@as(usize, 4), t.len);
    try std.testing.expectEqual(@as(u8, 't'), t[0].letter);
    try std.testing.expectEqual(@as(u8, 'r'), t[1].letter);
    try std.testing.expectEqual(@as(usize, 2), t[1].values.len);
    try std.testing.expectEqualStrings("wss://b", t[1].values[1]);
    try std.testing.expectEqual(@as(u8, 'd'), t[2].letter);
    try std.testing.expectEqual(@as(u8, 'h'), t[3].letter);

    // And it goes on the wire as `#r`, `#d`, `#h` and `search`.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try f.appendJson(&list, gpa);
    try std.testing.expectEqualStrings(
        "{\"#t\":[\"zig\"],\"#r\":[\"wss://a\",\"wss://b\"],\"#d\":[\"slug\"],\"#h\":[\"grp\"],\"search\":\"best nostr\"}",
        list.items,
    );
}

test "filterflags: a malformed --tag is refused" {
    var flags: Flags = .{};
    var eb: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    try std.testing.expectError(ParseError.BadValue, flags.accept(std.testing.allocator, "x", "-T", "rx", &err));
    try std.testing.expectError(ParseError.BadValue, flags.accept(std.testing.allocator, "x", "--tag", "1=x", &err));
}

test "filterflags: times take seconds, spans and dates" {
    try std.testing.expectEqual(@as(?i64, 1700000000), parseTime("1700000000", 5));
    try std.testing.expectEqual(@as(?i64, 1000), parseTime("now", 1000));
    try std.testing.expectEqual(@as(?i64, 1000 - 7200), parseTime("2h", 1000));
    try std.testing.expectEqual(@as(?i64, 1000000 - 3 * 86400), parseTime("3d", 1000000));
    try std.testing.expectEqual(@as(?i64, 1000000 - 90), parseTime("90s", 1000000));
    try std.testing.expectEqual(@as(?i64, 0), parseTime("1970-01-01", 5));
    try std.testing.expectEqual(@as(?i64, 1790812800), parseTime("2026-10-01", 5));
    try std.testing.expectEqual(@as(?i64, 1790812800 + 12 * 3600 + 30 * 60), parseTime("2026-10-01T12:30:00Z", 5));
    try std.testing.expectEqual(@as(?i64, 1790812800 + 12 * 3600 + 30 * 60), parseTime("2026-10-01T12:30", 5));
    try std.testing.expect(parseTime("yesterday", 5) == null);
    try std.testing.expect(parseTime("2026-13-01", 5) == null);
    try std.testing.expect(parseTime("", 5) == null);
}

test "filterflags: --since accepts a span and refuses nonsense" {
    var flags: Flags = .{};
    var eb: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    try flags.accept(std.testing.allocator, "x", "-s", "1h", &err);
    try std.testing.expect(flags.since.? > 1700000000);
    try std.testing.expectError(ParseError.BadValue, flags.accept(std.testing.allocator, "req", "-u", "soon", &err));
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "'soon' is not a time") != null);
}

test "filterflags: a JSON filter is read, and flags overlay it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var eb: [256]u8 = undefined;
    var err: std.Io.Writer = .fixed(&eb);
    const base = try parseJson(arena, "x", "{\"kinds\":[1,6],\"#t\":[\"a\"],\"#p\":[\"b\"],\"since\":5,\"limit\":3,\"search\":\"q\",\"extra\":1}", &err);
    try std.testing.expectEqual(@as(usize, 2), base.kinds.?.len);
    try std.testing.expectEqual(@as(i64, 5), base.since.?);
    try std.testing.expectEqualStrings("q", base.search.?);

    var flags: Flags = .{};
    try flags.accept(std.testing.allocator, "x", "-t", "z", &err);
    try flags.accept(std.testing.allocator, "x", "-u", "9", &err);
    const merged = try overlay(arena, base, flags.finish());
    try std.testing.expectEqual(@as(i64, 9), merged.until.?);
    try std.testing.expectEqual(@as(i64, 5), merged.since.?);
    // `t` is replaced, `p` is kept.
    var list: std.ArrayList(u8) = .empty;
    try merged.appendJson(&list, arena);
    try std.testing.expect(std.mem.indexOf(u8, list.items, "\"#t\":[\"z\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, list.items, "\"#p\":[\"b\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, list.items, "\"#t\":[\"a\"]") == null);

    try std.testing.expectError(ParseError.BadValue, parseJson(arena, "x", "{\"kinds\":[\"a\"]}", &err));
    try std.testing.expectError(ParseError.BadValue, parseJson(arena, "x", "[1]", &err));
    try std.testing.expectError(ParseError.BadValue, parseJson(arena, "x", "{", &err));
}
