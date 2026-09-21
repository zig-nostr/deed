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
    var stdin_reader = std.Io.File.stdin().reader(io, stdin_buf);

    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    var signer = keys.Signer.init();
    defer signer.deinit();

    var failures: usize = 0;
    while (try input.next()) |record| {
        const json = switch (record) {
            .line => |l| l,
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
