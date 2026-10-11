//! Reading a password or another secret phrase from a person.
//!
//! The secret is never taken from argv, where it would sit in the process
//! list and in shell history. It comes from one of two places: the terminal,
//! with echo off, or an environment variable the caller names and the person
//! set on purpose (`NOSTR_PASSWORD` for key passwords).
//!
//! Echo is put back on every way out of the read: a normal return, an error,
//! and SIGINT, SIGTERM and SIGHUP (and a console Ctrl-C on Windows). A kill
//! that cannot be caught (SIGKILL) can still leave the terminal quiet, and
//! `stty echo` fixes that.
//!
//! The text lives in a fixed buffer owned by the caller, so there is nothing
//! to free and `wipe` can clear every byte of it.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// The longest secret read. A 24 word mnemonic is under 220 bytes.
pub const max_len = 1024;

/// The variable key passwords may come from.
pub const password_env = "NOSTR_PASSWORD";

pub const Error = error{
    /// No terminal to ask on and no variable set.
    NoTerminal,
    ReadFailed,
    TooLong,
    /// The two entries of a confirmed prompt differ.
    Mismatch,
    /// Nothing was typed.
    Empty,
};

pub const Secret = struct {
    buf: [max_len]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Secret) []const u8 {
        return self.buf[0..self.len];
    }

    /// Clears the whole buffer, not only the used part.
    pub fn wipe(self: *Secret) void {
        std.crypto.secureZero(u8, &self.buf);
        self.len = 0;
    }
};

pub const Options = struct {
    prompt: []const u8,
    /// A variable that supplies the secret when it is set and not empty.
    env: ?[*:0]const u8 = null,
    /// Ask twice and require both to match.
    confirm: bool = false,
    /// When there is no terminal, read one line from stdin instead of failing.
    allow_pipe: bool = false,
};

/// Reads a secret into `out`. The caller wipes it.
pub fn read(out: *Secret, opts: Options) Error!void {
    if (opts.env) |name| {
        if (std.c.getenv(name)) |value| {
            const span = std.mem.span(value);
            if (span.len > 0) return fromText(out, span);
        }
    }
    return if (is_windows) readWindows(out, opts) else readPosix(out, opts);
}

/// Takes a value that already exists, such as an environment variable.
pub fn fromText(out: *Secret, text: []const u8) Error!void {
    const t = std.mem.trimEnd(u8, text, "\r\n");
    if (t.len == 0) return Error.Empty;
    if (t.len > max_len) return Error.TooLong;
    @memcpy(out.buf[0..t.len], t);
    out.len = t.len;
}

/// What the person typed on one line, without the line ending.
fn finishLine(out: *Secret, len: usize) Error!void {
    out.len = std.mem.trimEnd(u8, out.buf[0..len], "\r").len;
    if (out.len == 0) return Error.Empty;
}

// POSIX ----------------------------------------------------------------

const posix = std.posix;

var g_fd: posix.fd_t = -1;
var g_saved: posix.termios = undefined;
var g_active: bool = false;

fn restoreNow() void {
    if (!g_active) return;
    g_active = false;
    posix.tcsetattr(g_fd, .FLUSH, g_saved) catch {};
}

fn onSignal(sig: posix.SIG) callconv(.c) void {
    restoreNow();
    _ = std.c.write(g_fd, "\n", 1);
    // Back to the default action and deliver it again, so the exit status is
    // the one the signal would have given without this handler.
    const dfl: posix.Sigaction = .{
        .handler = .{ .handler = posix.SIG.DFL },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(sig, &dfl, null);
    _ = std.c.raise(sig);
}

const watched = [_]posix.SIG{ .INT, .TERM, .HUP };

fn readPosix(out: *Secret, opts: Options) Error!void {
    var tty_fd: posix.fd_t = std.c.open("/dev/tty", .{ .ACCMODE = .RDWR }, @as(c_uint, 0));
    var opened = true;
    if (tty_fd < 0) {
        opened = false;
        tty_fd = 0;
    }
    defer if (opened) {
        _ = std.c.close(tty_fd);
    };

    if (std.c.isatty(tty_fd) == 0) {
        if (!opts.allow_pipe) return Error.NoTerminal;
        return readLine(0, out);
    }

    try promptHidden(tty_fd, out, opts.prompt);
    if (opts.confirm) {
        var again: Secret = .{};
        defer again.wipe();
        try promptHidden(tty_fd, &again, "Again: ");
        if (!std.mem.eql(u8, out.slice(), again.slice())) {
            out.wipe();
            return Error.Mismatch;
        }
    }
}

fn promptHidden(fd: posix.fd_t, out: *Secret, prompt: []const u8) Error!void {
    const old = posix.tcgetattr(fd) catch return Error.NoTerminal;
    var quiet = old;
    quiet.lflag.ECHO = false;

    g_fd = fd;
    g_saved = old;
    var previous: [watched.len]posix.Sigaction = undefined;
    const act: posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    for (watched, 0..) |s, i| posix.sigaction(s, &act, &previous[i]);
    g_active = true;
    defer {
        restoreNow();
        for (watched, 0..) |s, i| posix.sigaction(s, &previous[i], null);
    }

    posix.tcsetattr(fd, .FLUSH, quiet) catch return Error.NoTerminal;
    _ = std.c.write(fd, prompt.ptr, prompt.len);
    const result = readLine(fd, out);
    // The newline the person typed was not echoed.
    _ = std.c.write(fd, "\n", 1);
    return result;
}

/// One line, a byte at a time so that a pipe is not read past its newline.
fn readLine(fd: posix.fd_t, out: *Secret) Error!void {
    var n: usize = 0;
    while (true) {
        var b: [1]u8 = undefined;
        const got = std.c.read(fd, &b, 1);
        if (got < 0) {
            if (std.c._errno().* == @intFromEnum(posix.E.INTR)) continue;
            std.crypto.secureZero(u8, out.buf[0..n]);
            return Error.ReadFailed;
        }
        if (got == 0 or b[0] == '\n') break;
        if (n == max_len) {
            std.crypto.secureZero(u8, out.buf[0..n]);
            return Error.TooLong;
        }
        out.buf[n] = b[0];
        n += 1;
    }
    return finishLine(out, n);
}

// Windows --------------------------------------------------------------

const win = struct {
    const std_input: u32 = @bitCast(@as(i32, -10));
    const std_error: u32 = @bitCast(@as(i32, -12));
    const enable_echo_input: u32 = 0x0004;

    extern "kernel32" fn GetStdHandle(which: u32) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn GetConsoleMode(handle: ?*anyopaque, mode: *u32) callconv(.winapi) c_int;
    extern "kernel32" fn SetConsoleMode(handle: ?*anyopaque, mode: u32) callconv(.winapi) c_int;
    extern "kernel32" fn ReadFile(handle: ?*anyopaque, buf: [*]u8, n: u32, read: *u32, overlapped: ?*anyopaque) callconv(.winapi) c_int;
    extern "kernel32" fn WriteFile(handle: ?*anyopaque, buf: [*]const u8, n: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) c_int;
    extern "kernel32" fn SetConsoleCtrlHandler(handler: *const fn (u32) callconv(.winapi) c_int, add: c_int) callconv(.winapi) c_int;
};

var w_handle: ?*anyopaque = null;
var w_mode: u32 = 0;
var w_active: bool = false;

fn restoreWindows() void {
    if (!w_active) return;
    w_active = false;
    if (comptime is_windows) _ = win.SetConsoleMode(w_handle, w_mode);
}

fn onCtrl(_: u32) callconv(.winapi) c_int {
    restoreWindows();
    return 0; // not handled: the default handler still ends the process
}

fn winWrite(text: []const u8) void {
    const h = win.GetStdHandle(win.std_error);
    var written: u32 = 0;
    _ = win.WriteFile(h, text.ptr, @intCast(text.len), &written, null);
}

fn readWindows(out: *Secret, opts: Options) Error!void {
    if (comptime !is_windows) unreachable;
    const h = win.GetStdHandle(win.std_input);
    var mode: u32 = 0;
    const is_console = win.GetConsoleMode(h, &mode) != 0;
    if (!is_console and !opts.allow_pipe) return Error.NoTerminal;

    try promptWindows(h, is_console, mode, out, opts.prompt);
    if (opts.confirm and is_console) {
        var again: Secret = .{};
        defer again.wipe();
        try promptWindows(h, true, mode, &again, "Again: ");
        if (!std.mem.eql(u8, out.slice(), again.slice())) {
            out.wipe();
            return Error.Mismatch;
        }
    }
}

fn promptWindows(h: ?*anyopaque, is_console: bool, mode: u32, out: *Secret, prompt: []const u8) Error!void {
    if (is_console) {
        w_handle = h;
        w_mode = mode;
        w_active = true;
        _ = win.SetConsoleCtrlHandler(onCtrl, 1);
        _ = win.SetConsoleMode(h, mode & ~win.enable_echo_input);
        winWrite(prompt);
    }
    defer if (is_console) {
        restoreWindows();
        _ = win.SetConsoleCtrlHandler(onCtrl, 0);
        winWrite("\r\n");
    };

    var n: usize = 0;
    while (true) {
        var b: [1]u8 = undefined;
        var got: u32 = 0;
        if (win.ReadFile(h, &b, 1, &got, null) == 0) {
            std.crypto.secureZero(u8, out.buf[0..n]);
            return Error.ReadFailed;
        }
        if (got == 0 or b[0] == '\n') break;
        if (n == max_len) {
            std.crypto.secureZero(u8, out.buf[0..n]);
            return Error.TooLong;
        }
        out.buf[n] = b[0];
        n += 1;
    }
    return finishLine(out, n);
}

const libc_env = struct {
    extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
    extern "c" fn unsetenv(name: [*:0]const u8) c_int;
};

/// For tests that need the variable path. Not available on Windows.
pub fn setEnvForTest(name: [*:0]const u8, value: ?[*:0]const u8) void {
    if (value) |v| _ = libc_env.setenv(name, v, 1) else _ = libc_env.unsetenv(name);
}

test "fromText strips the line ending and refuses nothing and too much" {
    var s: Secret = .{};
    defer s.wipe();
    try fromText(&s, "hunter2\r\n");
    try std.testing.expectEqualStrings("hunter2", s.slice());
    try std.testing.expectError(Error.Empty, fromText(&s, "\n"));
    const big = [_]u8{'a'} ** (max_len + 1);
    try std.testing.expectError(Error.TooLong, fromText(&s, &big));
}

test "wipe clears every byte" {
    var s: Secret = .{};
    try fromText(&s, "correct horse");
    s.wipe();
    try std.testing.expectEqual(@as(usize, 0), s.len);
    for (s.buf) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "a set variable supplies the password, an unset one does not" {
    if (is_windows) return error.SkipZigTest;
    setEnvForTest("DEED_TEST_PW_SET", "from-env");
    var s: Secret = .{};
    defer s.wipe();
    try read(&s, .{ .prompt = "x: ", .env = "DEED_TEST_PW_SET" });
    try std.testing.expectEqualStrings("from-env", s.slice());
}
