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

/// What a repeated flag collects. Fixed, because a command line naming more
/// than this many authors is a file being piped in by the wrong route.
pub fn Collected(comptime T: type) type {
    return struct {
        items: [max_values]T = undefined,
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
    "-k",      "--kind", "-a",      "--author", "-i",      "--id",
    "-e",      "-p",     "-t",      "-l",       "--limit", "-s",
    "--since", "-u",     "--until",
};

/// True when `a` is one of the filter flags (all of which take a value).
pub fn isFilterFlag(a: []const u8) bool {
    return cli.isOneOf(a, &value_flags);
}

/// Everything the filter flags collect while a command line is read.
///
/// `finish` returns a filter whose slices point into this struct, so it must
/// stay where it is for as long as that filter is used.
pub const Flags = struct {
    ids: Collected([32]u8) = .{},
    authors: Collected([32]u8) = .{},
    kinds: Collected(u16) = .{},
    e_tags: Collected([]const u8) = .{},
    p_tags: Collected([]const u8) = .{},
    t_tags: Collected([]const u8) = .{},
    tag_filters: [3]filter.TagFilter = undefined,
    limit: ?u32 = null,
    since: ?i64 = null,
    until: ?i64 = null,

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
            _ = self.kinds.push(n);
        } else if (cli.isOneOf(a, &.{ "-a", "--author" })) {
            const k = idOrKey(gpa, v) orelse {
                try err.print("deed {s}: '{s}' is not a key\n", .{ verb, v });
                return ParseError.BadValue;
            };
            _ = self.authors.push(k);
        } else if (cli.isOneOf(a, &.{ "-i", "--id" })) {
            const k = idOrKey(gpa, v) orelse {
                try err.print("deed {s}: '{s}' is not an id\n", .{ verb, v });
                return ParseError.BadValue;
            };
            _ = self.ids.push(k);
        } else if (std.mem.eql(u8, a, "-e")) {
            _ = self.e_tags.push(v);
        } else if (std.mem.eql(u8, a, "-p")) {
            _ = self.p_tags.push(v);
        } else if (std.mem.eql(u8, a, "-t")) {
            _ = self.t_tags.push(v);
        } else if (cli.isOneOf(a, &.{ "-l", "--limit" })) {
            self.limit = std.fmt.parseInt(u32, v, 10) catch {
                try err.print("deed {s}: '{s}' is not a limit\n", .{ verb, v });
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-s", "--since" })) {
            self.since = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed {s}: '{s}' is not a unix timestamp\n", .{ verb, v });
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-u", "--until" })) {
            self.until = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed {s}: '{s}' is not a unix timestamp\n", .{ verb, v });
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
        f.ids = self.ids.slice();
        f.authors = self.authors.slice();
        f.kinds = self.kinds.slice();

        var tag_len: usize = 0;
        if (self.e_tags.slice()) |v| {
            self.tag_filters[tag_len] = .{ .letter = 'e', .values = v };
            tag_len += 1;
        }
        if (self.p_tags.slice()) |v| {
            self.tag_filters[tag_len] = .{ .letter = 'p', .values = v };
            tag_len += 1;
        }
        if (self.t_tags.slice()) |v| {
            self.tag_filters[tag_len] = .{ .letter = 't', .values = v };
            tag_len += 1;
        }
        if (tag_len > 0) f.tags = self.tag_filters[0..tag_len];
        return f;
    }
};

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
