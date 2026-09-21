//! deed: the nostr command line.
//!
//! A deed is two things at once: a signed instrument, and a thing done. So is
//! a nostr event.

const std = @import("std");
const cli = @import("cli.zig");
const cmd_decode = @import("cmd_decode.zig");
const cmd_encode = @import("cmd_encode.zig");
const cmd_crypt = @import("cmd_crypt.zig");
const cmd_event = @import("cmd_event.zig");
const cmd_key = @import("cmd_key.zig");
const cmd_verify = @import("cmd_verify.zig");

pub const version = "0.1.0";

const usage =
    \\deed: the nostr command line
    \\
    \\Usage:
    \\  deed <command> [arguments]
    \\
    \\Commands:
    \\  key       make a key, or derive the public one from it
    \\  event     build an event and sign it
    \\  decode    turn a NIP-19 code into the fields it carries
    \\  encode    build a NIP-19 code out of its parts
    \\  encrypt   encrypt a message to someone, with NIP-44
    \\  decrypt   decrypt a NIP-44 payload from someone
    \\  verify    check that events are correctly signed
    \\
    \\  help      this text, or `deed help <command>`
    \\  version   the version
    \\
    \\Every verb that takes events reads them as newline-delimited JSON on
    \\stdin when given no positional arguments, so verbs compose:
    \\
    \\  cat notes.jsonl | deed verify
    \\
    \\Exit codes: 0 success, 1 the command ran and failed, 2 the command was
    \\not understood.
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.skip(); // argv[0]
    while (it.next()) |a| try argv.append(gpa, a);

    var out_buf: [16 * 1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    var err_buf: [4 * 1024]u8 = undefined;
    var stderr = std.Io.File.stderr().writer(io, &err_buf);

    const code = run(gpa, io, argv.items, &stdout.interface, &stderr.interface) catch |e| blk: {
        // `deed decode … | head -1` closes the pipe on purpose, and every other
        // filter goes quiet when its reader leaves rather than complaining that
        // it did. deed cannot die of SIGPIPE the way they do, because the I/O
        // implementation underneath installs a handler of its own, so it
        // reports the status that death reads as instead. A write that failed
        // for any other reason, a full disk being the likely one, is a real
        // failure and is still said out loud.
        if (e == error.WriteFailed) {
            if (stdout.err) |write_err| {
                if (write_err == error.BrokenPipe) break :blk cli.exit_broken_pipe;
                // `WriteFailed` names the branch taken rather than what went
                // wrong. The file writer underneath kept the real one, and a
                // full disk is worth saying by name.
                stderr.interface.print("deed: {s}\n", .{@errorName(write_err)}) catch {};
                break :blk cli.exit_fail;
            }
        }
        stderr.interface.print("deed: {s}\n", .{@errorName(e)}) catch {};
        break :blk cli.exit_fail;
    };

    // Flush before exiting: `std.process.exit` does not unwind, so anything
    // still buffered would simply be lost.
    stdout.interface.flush() catch {};
    stderr.interface.flush() catch {};

    // The flush is where a reader that left during the last write is noticed,
    // since that write may never have reached the pipe before now.
    const final = if (code == cli.exit_ok and brokenPipe(&stdout))
        cli.exit_broken_pipe
    else
        code;
    std.process.exit(final);
}

/// True when writing to `w` failed because the far end of the pipe is gone.
///
/// `std.Io.Writer` reports every failure as `WriteFailed`; the file writer
/// underneath keeps the real one, which is the only place the difference
/// between a reader that left and a disk that filled up survives.
fn brokenPipe(w: *const std.Io.File.Writer) bool {
    const e = w.err orelse return false;
    return e == error.BrokenPipe;
}

fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len == 0) {
        try out.writeAll(usage);
        return cli.exit_usage;
    }

    const verb = args[0];
    const rest = args[1..];

    if (cli.isOneOf(verb, &.{ "help", "-h", "--help" })) {
        if (rest.len != 0) return helpFor(rest[0], out, err);
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    if (cli.isOneOf(verb, &.{ "version", "-V", "--version" })) {
        try out.print("deed {s}\n", .{version});
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, verb, "key")) return cmd_key.run(gpa, io, rest, out, err);
    if (std.mem.eql(u8, verb, "event")) return cmd_event.run(gpa, io, rest, out, err);
    if (std.mem.eql(u8, verb, "decode")) return cmd_decode.run(gpa, io, rest, out, err);
    if (std.mem.eql(u8, verb, "encode")) return cmd_encode.run(gpa, rest, out, err);
    if (std.mem.eql(u8, verb, "encrypt")) return cmd_crypt.run(gpa, io, .encrypt, rest, out, err);
    if (std.mem.eql(u8, verb, "decrypt")) return cmd_crypt.run(gpa, io, .decrypt, rest, out, err);
    if (std.mem.eql(u8, verb, "verify")) return cmd_verify.run(gpa, io, rest, out, err);

    try err.print("deed: unknown command '{s}'\nRun `deed help` for the list.\n", .{verb});
    return cli.exit_usage;
}

fn helpFor(topic: []const u8, out: *std.Io.Writer, err: *std.Io.Writer) !u8 {
    if (std.mem.eql(u8, topic, "key")) {
        try out.writeAll(cmd_key.usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, topic, "event")) {
        try out.writeAll(cmd_event.usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, topic, "decode")) {
        try out.writeAll(cmd_decode.usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, topic, "encode")) {
        try out.writeAll(cmd_encode.usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, topic, "encrypt")) {
        try out.writeAll(cmd_crypt.encrypt_usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, topic, "decrypt")) {
        try out.writeAll(cmd_crypt.decrypt_usage);
        return cli.exit_ok;
    }
    if (std.mem.eql(u8, topic, "verify")) {
        try out.writeAll(cmd_verify.usage);
        return cli.exit_ok;
    }
    try err.print("deed: no help for '{s}'\n", .{topic});
    return cli.exit_usage;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("cli.zig");
    _ = @import("keyinput.zig");
    _ = @import("jsonout.zig");
    _ = @import("cmd_crypt.zig");
    _ = @import("cmd_event.zig");
    _ = @import("cmd_decode.zig");
    _ = @import("cmd_encode.zig");
}
