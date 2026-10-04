//! The Windows console and UTF-8.
//!
//! deed writes UTF-8 and nothing else: JSON, NIP-19 codes and the ellipses in
//! its help text. A Windows console decodes what it is given with its own code
//! page (437 or 850 on most machines), so without this, `deed help event`
//! prints `nsec1ΓÇª`. Switching the console to UTF-8 for the length of the run
//! fixes that, and putting it back afterwards leaves the user's shell as it was.
//!
//! The code page belongs to the console, not to a handle, so every process
//! attached to it shares one. That is why a page is only switched for the
//! standard handle that is the console itself: in `deed key generate | deed
//! event`, only the second deed writes to the console, so only it switches the
//! output page, and the first one exiting early cannot switch it back under the
//! second one's output. The cost is that a deed whose stdout is redirected
//! prints its stderr with the console's own page.
//!
//! Ctrl-C ends a run (`req --stream` has no other way to stop) without reaching
//! the end of `main`, so a console control handler puts the pages back then
//! too. Everything here is a no-op off Windows.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

const utf8: u32 = 65001;

const kernel32 = struct {
    const std_input: u32 = @bitCast(@as(i32, -10));
    const std_output: u32 = @bitCast(@as(i32, -11));

    extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn GetConsoleMode(handle: ?*anyopaque, mode: *u32) callconv(.winapi) c_int;
    extern "kernel32" fn GetConsoleCP() callconv(.winapi) u32;
    extern "kernel32" fn GetConsoleOutputCP() callconv(.winapi) u32;
    extern "kernel32" fn SetConsoleCP(cp: u32) callconv(.winapi) c_int;
    extern "kernel32" fn SetConsoleOutputCP(cp: u32) callconv(.winapi) c_int;
    extern "kernel32" fn SetConsoleCtrlHandler(
        handler: *const fn (u32) callconv(.winapi) c_int,
        add: c_int,
    ) callconv(.winapi) c_int;
};

/// The code pages to put back, 0 where nothing was changed.
const Saved = struct {
    input: u32 = 0,
    output: u32 = 0,
};

/// What `useUtf8` changed. Written once before the control handler is
/// installed, and only read after that.
var saved: Saved = .{};

/// Which pages to switch, given whether stdin and stdout are the console and
/// the pages in force now. A page of 0 means there is no console; one already
/// UTF-8 needs nothing.
fn plan(stdin_is_console: bool, stdout_is_console: bool, input: u32, output: u32) Saved {
    return .{
        .input = if (stdin_is_console and input != 0 and input != utf8) input else 0,
        .output = if (stdout_is_console and output != 0 and output != utf8) output else 0,
    };
}

/// Switches the console to UTF-8 where deed reads from it or writes to it.
pub fn useUtf8() void {
    if (comptime !is_windows) return;
    var want = plan(
        isConsole(kernel32.std_input),
        isConsole(kernel32.std_output),
        kernel32.GetConsoleCP(),
        kernel32.GetConsoleOutputCP(),
    );
    // Only what was actually changed is put back.
    if (want.input != 0 and kernel32.SetConsoleCP(utf8) == 0) want.input = 0;
    if (want.output != 0 and kernel32.SetConsoleOutputCP(utf8) == 0) want.output = 0;
    saved = want;
    if (saved.input != 0 or saved.output != 0) _ = kernel32.SetConsoleCtrlHandler(onControl, 1);
}

/// Puts back the pages `useUtf8` changed. Safe to call more than once.
pub fn restore() void {
    if (comptime !is_windows) return;
    if (saved.input != 0) _ = kernel32.SetConsoleCP(saved.input);
    if (saved.output != 0) _ = kernel32.SetConsoleOutputCP(saved.output);
}

fn isConsole(which: u32) bool {
    var mode: u32 = 0;
    return kernel32.GetConsoleMode(kernel32.GetStdHandle(which), &mode) != 0;
}

/// Runs on a thread of its own on Ctrl-C, Ctrl-Break or a closing window.
/// Returning 0 passes the event on, so the default handler still ends the run.
fn onControl(_: u32) callconv(.winapi) c_int {
    restore();
    return 0;
}

test "off Windows the console is left alone" {
    if (is_windows) return error.SkipZigTest;
    useUtf8();
    try std.testing.expectEqual(Saved{}, saved);
    restore();
}

test "a page is switched only for the handle that is the console" {
    // Both are the console: both pages switch, and the old ones are kept.
    try std.testing.expectEqual(Saved{ .input = 437, .output = 850 }, plan(true, true, 437, 850));
    // `deed key generate | deed event`: the first one writes into a pipe and
    // must leave the output page to the one that writes to the console.
    try std.testing.expectEqual(Saved{ .input = 437 }, plan(true, false, 437, 437));
    // And the second one reads from a pipe.
    try std.testing.expectEqual(Saved{ .output = 437 }, plan(false, true, 437, 437));
    // Already UTF-8, or no console at all: nothing to change or put back.
    try std.testing.expectEqual(Saved{}, plan(true, true, utf8, utf8));
    try std.testing.expectEqual(Saved{}, plan(true, true, 0, 0));
}
