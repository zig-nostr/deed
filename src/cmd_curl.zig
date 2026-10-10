//! deed curl: not built yet. The unit that builds it replaces this file's body,
//! sets `ready` to true, and fills in `summary` and `usage`.

const std = @import("std");
const cli = @import("cli.zig");

/// Shown beside the name in `deed help` once `ready` is true.
pub const summary = "(not built yet)";

/// False keeps the verb out of `deed help`.
pub const ready = false;

pub const usage =
    \\deed curl: not built yet
    \\
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
    _ = args;
    _ = out;
    try err.writeAll("deed: curl is not built yet\n");
    return cli.exit_usage;
}
