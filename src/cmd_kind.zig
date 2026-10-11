//! `deed kind`: what a kind number means, and the other way round.

const std = @import("std");
const cli = @import("cli.zig");
const kinds = @import("kinds.zig");

pub const summary = "look up an event kind by number or name";

pub const ready = true;

pub const usage =
    \\deed kind: look up an event kind by number or name
    \\
    \\Usage:
    \\  deed kind [<number|name>...]
    \\
    \\Prints one JSON object per kind: its number, name, description, the NIP
    \\that defines it, and how a relay stores it (regular, replaceable,
    \\ephemeral or addressable). A number the NIPs do not name still gets its
    \\class, with the other fields null. With no arguments, lists every kind
    \\deed knows, one per line.
    \\
    \\  deed kind 7
    \\  deed kind text-note
    \\
    \\Exits: 0 on success; 1 if a name is unknown; 2 if the command line was not
    \\understood.
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    _ = gpa;
    _ = io;
    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed kind: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
    }

    if (args.len == 0) {
        for (kinds.table) |e| try line(out, e);
        return cli.exit_ok;
    }

    var failures: usize = 0;
    for (args) |a| {
        const n = kinds.parse(a) orelse {
            try err.print("deed kind: '{s}' is not a kind number or a name deed knows\n", .{a});
            failures += 1;
            continue;
        };
        try line(out, kinds.byNumber(n) orelse .{ .kind = n, .name = "", .description = "", .nip = "" });
    }
    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

fn line(out: *std.Io.Writer, e: kinds.Info) !void {
    try out.print("{{\"kind\":{d},\"name\":", .{e.kind});
    try field(out, e.name);
    try out.writeAll(",\"description\":");
    try field(out, e.description);
    try out.writeAll(",\"nip\":");
    try field(out, e.nip);
    try out.print(",\"class\":\"{s}\"}}\n", .{e.class().label()});
}

/// A string, or null when there is nothing to say.
fn field(out: *std.Io.Writer, s: []const u8) !void {
    if (s.len == 0) return out.writeAll("null");
    try std.json.Stringify.value(s, .{}, out);
}

fn runKind(args: []const []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !u8 {
    return run(std.testing.allocator, std.testing.io, args, out, err);
}

test "a number prints its entry" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try runKind(&.{"7"}, &out.writer, &err.writer));
    try std.testing.expectEqualStrings(
        "{\"kind\":7,\"name\":\"reaction\",\"description\":\"A reaction to an event.\",\"nip\":\"25\",\"class\":\"regular\"}\n",
        out.written(),
    );
}

test "a name finds its number, and an unnamed number still has a class" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try runKind(&.{ "relay-list", "29999" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"kind\":10002,") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"class\":\"replaceable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "{\"kind\":29999,\"name\":null,\"description\":null,\"nip\":null,\"class\":\"ephemeral\"}") != null);
}

test "an unknown name fails" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_fail, try runKind(&.{"nope"}, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "'nope'") != null);
}

test "no arguments lists every kind, one per line" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try runKind(&.{}, &out.writer, &err.writer));
    try std.testing.expectEqual(kinds.table.len, std.mem.count(u8, out.written(), "\n"));
}
