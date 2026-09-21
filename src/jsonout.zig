//! Writing JSON strings.
//!
//! The library has this (`nostr/src/json.zig`) but does not export it from
//! `root.zig`, and widening a pre-1.0 library's public API is not this
//! package's call to make. If `nostr` ever exports its escaper, delete this
//! file and import that one, because the behaviour is meant to be identical.
//!
//! Correctness matters here rather than speed: the strings that pass through
//! are relay URLs and `naddr` identifiers lifted out of codes that arrived
//! from strangers, so any byte at all can show up.

const std = @import("std");

/// Appends `s` as a quoted, RFC 8259-escaped JSON string.
pub fn appendString(
    list: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    s: []const u8,
) std.mem.Allocator.Error!void {
    try list.append(gpa, '"');
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(gpa, "\\\""),
            '\\' => try list.appendSlice(gpa, "\\\\"),
            '\n' => try list.appendSlice(gpa, "\\n"),
            '\r' => try list.appendSlice(gpa, "\\r"),
            '\t' => try list.appendSlice(gpa, "\\t"),
            0x08 => try list.appendSlice(gpa, "\\b"),
            0x0C => try list.appendSlice(gpa, "\\f"),
            else => |b| {
                if (b < 0x20) {
                    try list.print(gpa, "\\u{x:0>4}", .{b});
                } else {
                    try list.append(gpa, b);
                }
            },
        }
    }
    try list.append(gpa, '"');
}

test "quotes and backslashes are escaped" {
    const gpa = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendString(&buf, gpa, "a\"b\\c");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\"", buf.items);
}

test "control characters become \\u escapes" {
    const gpa = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendString(&buf, gpa, "a\x01b");
    try std.testing.expectEqualStrings("\"a\\u0001b\"", buf.items);
}

test "utf-8 passes through untouched" {
    const gpa = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendString(&buf, gpa, "héllo");
    try std.testing.expectEqualStrings("\"héllo\"", buf.items);
}
