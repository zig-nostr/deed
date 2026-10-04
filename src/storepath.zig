//! Opening the store a `--store` path names.
//!
//! LMDB turns every reason it could not open a file into one status, and the
//! library reports that as `error.Lmdb`, which tells the reader nothing they can
//! act on. So when an open fails this looks at the path itself and says what is
//! wrong with it.

const std = @import("std");
const builtin = @import("builtin");
const nostr = @import("nostr");

pub const Mode = enum {
    /// Create the store when it is missing, and every directory above it.
    create,
    /// Open only a store that already exists. A run that only reads should
    /// not leave an empty store, or directories, behind a mistyped path.
    existing,
};

/// Opens the store at `path`, or writes one line to `err` saying why it could
/// not and returns null. A leading `~` is the home directory: a quoted `~` is
/// never expanded by the shell, and creating a directory literally named `~`
/// is never what was meant.
pub fn open(
    gpa: std.mem.Allocator,
    io: std.Io,
    verb: []const u8,
    path: []const u8,
    mode: Mode,
    err: *std.Io.Writer,
) !?nostr.store.Store {
    return openWithHome(gpa, io, verb, path, getHome(), mode, err);
}

fn openWithHome(
    gpa: std.mem.Allocator,
    io: std.Io,
    verb: []const u8,
    path: []const u8,
    home: ?[]const u8,
    mode: Mode,
    err: *std.Io.Writer,
) !?nostr.store.Store {
    if (path.len == 0) {
        try err.print("deed {s}: --store needs a path, and it was empty\n", .{verb});
        return null;
    }
    const full = expandHome(gpa, path, home) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.NoHome => {
            try err.print("deed {s}: cannot open the store at {s}: HOME is not set, so there is no ~ to expand\n", .{ verb, path });
            return null;
        },
        error.OtherUser => {
            try err.print("deed {s}: cannot open the store at {s}: only ~ and ~/ are expanded, so write that path out in full\n", .{ verb, path });
            return null;
        },
    };
    defer gpa.free(full);

    const cwd = std.Io.Dir.cwd();
    switch (mode) {
        .create => if (std.fs.path.dirname(full)) |parent| {
            cwd.createDirPath(io, parent) catch |e| {
                try err.print("deed {s}: cannot create the directory {s} for the store: {s}\n", .{ verb, parent, whyNotCreated(e) });
                return null;
            };
        },
        .existing => if (cwd.statFile(io, full, .{})) |_| {} else |e| switch (e) {
            error.FileNotFound => {
                if (fileInTheWay(io, full)) {
                    try err.print("deed {s}: cannot open the store at {s}: a part of the path is a file, not a directory\n", .{ verb, full });
                } else {
                    try err.print("deed {s}: there is no store at {s}\n", .{ verb, full });
                }
                return null;
            },
            // Anything else is described below, once the open has failed too.
            else => {},
        },
    }

    const z = try gpa.dupeZ(u8, full);
    defer gpa.free(z);
    if (nostr.store.Store.open(z, .{})) |st| return st else |e| switch (e) {
        error.OutOfMemory => return e,
        error.CorruptRecord => {
            try err.print("deed {s}: cannot open the store at {s}: it holds a damaged record\n", .{ verb, full });
            return null;
        },
        error.Lmdb => {
            try err.print("deed {s}: cannot open the store at {s}: {s}\n", .{ verb, full, whyNotOpened(io, full) });
            return null;
        },
    }
}

fn getHome() ?[]const u8 {
    const value = std.c.getenv("HOME") orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

/// Whether the nearest part of `full` that exists is a file rather than a
/// directory. Some systems report a path through a file as not found rather
/// than as not a directory, and "there is no store" would hide the real fault.
fn fileInTheWay(io: std.Io, full: []const u8) bool {
    var p = full;
    while (std.fs.path.dirname(p)) |parent| : (p = parent) {
        const stat = std.Io.Dir.cwd().statFile(io, parent, .{}) catch |e| switch (e) {
            error.FileNotFound => continue,
            error.NotDir => return true,
            else => return false,
        };
        return stat.kind != .directory;
    }
    return false;
}

/// `~` and `~/rest` become the home directory and `home/rest`. Any other path
/// comes back as it was. The caller frees the result.
fn expandHome(gpa: std.mem.Allocator, path: []const u8, home: ?[]const u8) error{ OutOfMemory, NoHome, OtherUser }![]u8 {
    if (path.len == 0 or path[0] != '~') return gpa.dupe(u8, path);
    if (path.len > 1 and path[1] != '/') return error.OtherUser;
    const h = home orelse return error.NoHome;
    return std.mem.concat(gpa, u8, &.{ h, path[1..] });
}

fn whyNotCreated(e: std.Io.Dir.CreateDirPathError) []const u8 {
    return switch (e) {
        error.AccessDenied, error.PermissionDenied => "permission denied",
        error.NotDir, error.PathAlreadyExists => "a part of it is a file, not a directory",
        error.ReadOnlyFileSystem => "the file system is read-only",
        error.NoSpaceLeft => "the disk is full",
        error.NameTooLong => "the path is too long",
        else => @errorName(e),
    };
}

/// Why LMDB could not open `full`, found by asking the file system directly.
/// LMDB keeps a second file beside the store, `<path>-lock`, and needs to
/// read and write both.
fn whyNotOpened(io: std.Io, full: []const u8) []const u8 {
    const cwd = std.Io.Dir.cwd();
    const parent = std.fs.path.dirname(full) orelse ".";
    const stat = cwd.statFile(io, full, .{}) catch |e| return switch (e) {
        error.FileNotFound => whyNoNewFile(io, parent, "no permission to create the store in its directory") orelse "LMDB could not create it",
        error.NotDir => "a part of the path is a file, not a directory",
        error.AccessDenied, error.PermissionDenied => "permission denied on a directory above it",
        else => @errorName(e),
    };
    if (stat.kind == .directory) return "it is a directory, and a store is a single file";
    cwd.access(io, full, .{ .read = true, .write = true }) catch |e| return switch (e) {
        error.AccessDenied, error.PermissionDenied => "no permission to read and write it",
        error.ReadOnlyFileSystem => "it is on a read-only file system",
        else => @errorName(e),
    };

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.fmt.bufPrint(&buf, "{s}-lock", .{full})) |lock| {
        if (cwd.access(io, lock, .{ .read = true, .write = true })) |_| {} else |e| switch (e) {
            error.FileNotFound => if (whyNoNewFile(io, parent, "no permission to create its lock file in its directory")) |why| return why,
            error.AccessDenied, error.PermissionDenied => return "no permission to read and write its lock file",
            error.ReadOnlyFileSystem => return "its lock file is on a read-only file system",
            else => {},
        }
    } else |_| {}
    return unknown;
}

const unknown = "LMDB could not open it, so it is probably not a store";

/// Why a file that does not exist yet could not be made in `parent`, or null
/// when nothing about `parent` explains it.
fn whyNoNewFile(io: std.Io, parent: []const u8, denied: []const u8) ?[]const u8 {
    std.Io.Dir.cwd().access(io, parent, .{ .write = true }) catch |e| return switch (e) {
        error.AccessDenied, error.PermissionDenied => denied,
        error.ReadOnlyFileSystem => "its directory is on a read-only file system",
        error.FileNotFound => "its directory does not exist",
        else => @errorName(e),
    };
    return null;
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

/// A temporary directory, its absolute path, and somewhere for messages.
const Fixture = struct {
    tmp: testing.TmpDir,
    root_buf: [std.fs.max_path_bytes]u8 = undefined,
    root_len: usize = 0,
    err_buf: [512]u8 = undefined,
    err: std.Io.Writer = undefined,

    fn init(self: *Fixture) !void {
        self.* = .{ .tmp = testing.tmpDir(.{}) };
        self.root_len = try self.tmp.dir.realPath(testing.io, &self.root_buf);
        self.err = .fixed(&self.err_buf);
    }

    fn deinit(self: *Fixture) void {
        self.tmp.cleanup();
    }

    fn path(self: *Fixture, buf: []u8, rest: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.root_buf[0..self.root_len], rest });
    }

    fn open(self: *Fixture, p: []const u8, mode: Mode) !?nostr.store.Store {
        return openWithHome(testing.allocator, testing.io, "req", p, null, mode, &self.err);
    }

    fn said(self: *Fixture, words: []const u8) !void {
        const text = self.err.buffered();
        if (std.mem.indexOf(u8, text, words) == null) {
            std.debug.print("expected the message to say \"{s}\", it said: {s}\n", .{ words, text });
            return error.TestUnexpectedResult;
        }
    }

    fn exists(self: *Fixture, rest: []const u8) bool {
        _ = self.tmp.dir.statFile(testing.io, rest, .{}) catch return false;
        return true;
    }
};

fn runningAsRoot() bool {
    return std.c.geteuid() == 0;
}

test "a store under directories that do not exist yet is created, directories and all" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try f.path(&buf, "a/b/c/store.mdb");

    var st = (try f.open(p, .create)) orelse return error.TestUnexpectedResult;
    st.deinit();
    try testing.expect(f.exists("a/b/c/store.mdb"));
    try testing.expectEqualStrings("", f.err.buffered());
}

test "a relative path with .. in it is created where it points" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    // tmpDir lives under the working directory, so this path is relative.
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try std.fmt.bufPrint(&buf, ".zig-cache/tmp/{s}/x/../y/store.mdb", .{&f.tmp.sub_path});

    var st = (try f.open(p, .create)) orelse return error.TestUnexpectedResult;
    st.deinit();
    try testing.expect(f.exists("y/store.mdb"));
}

test "a run that only reads leaves nothing behind a path with no store" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try f.path(&buf, "typo/store.mdb");

    try testing.expect(try f.open(p, .existing) == null);
    try f.said("there is no store at ");
    try testing.expect(!f.exists("typo"));
}

test "a directory where the store should be is named as one" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try f.tmp.dir.createDir(testing.io, "d", .default_dir);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try f.path(&buf, "d");

    try testing.expect(try f.open(p, .create) == null);
    try f.said("it is a directory, and a store is a single file");
}

test "a file in the way of a directory is named as one" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = "file", .data = "x" });
    var buf: [std.fs.max_path_bytes]u8 = undefined;

    try testing.expect(try f.open(try f.path(&buf, "file/sub/store.mdb"), .create) == null);
    try f.said("cannot create the directory ");
    try f.said("a part of it is a file, not a directory");

    f.err = .fixed(&f.err_buf);
    try testing.expect(try f.open(try f.path(&buf, "file/store.mdb"), .existing) == null);
    try f.said("a part of the path is a file, not a directory");
}

test "a file that is not a store is not opened, and not overwritten" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    const text = "these are my notes, not a database\n" ** 200;
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = "notes.txt", .data = text });
    var buf: [std.fs.max_path_bytes]u8 = undefined;

    try testing.expect(try f.open(try f.path(&buf, "notes.txt"), .create) == null);
    try f.said("probably not a store");
    var read_buf: [text.len + 1]u8 = undefined;
    try testing.expectEqualStrings(text, try f.tmp.dir.readFile(testing.io, "notes.txt", &read_buf));
}

test "a directory that cannot be written is named as the reason" {
    // Windows has no mode bits to take away.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (runningAsRoot()) return error.SkipZigTest;
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try f.tmp.dir.createDir(testing.io, "locked", .default_dir);
    try f.tmp.dir.setFilePermissions(testing.io, "locked", .fromMode(0o555), .{});
    defer f.tmp.dir.setFilePermissions(testing.io, "locked", .fromMode(0o755), .{}) catch {};
    var buf: [std.fs.max_path_bytes]u8 = undefined;

    // A directory below it has to be made, and cannot be.
    try testing.expect(try f.open(try f.path(&buf, "locked/sub/store.mdb"), .create) == null);
    try f.said("cannot create the directory ");
    try f.said("permission denied");

    // The directory exists, and the store file cannot be made in it.
    f.err = .fixed(&f.err_buf);
    try testing.expect(try f.open(try f.path(&buf, "locked/store.mdb"), .create) == null);
    try f.said("no permission to create the store in its directory");
}

test "a store that cannot be read and written is named as the reason" {
    // Windows has no mode bits to take away.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (runningAsRoot()) return error.SkipZigTest;
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const p = try f.path(&buf, "store.mdb");
    var st = (try f.open(p, .create)) orelse return error.TestUnexpectedResult;
    st.deinit();
    try f.tmp.dir.setFilePermissions(testing.io, "store.mdb", .fromMode(0o444), .{});

    try testing.expect(try f.open(p, .existing) == null);
    try f.said("no permission to read and write it");
}

test "~ is the home directory, and nothing else is touched" {
    const gpa = testing.allocator;
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "~", .want = "/home/me" },
        .{ .in = "~/.deed/db", .want = "/home/me/.deed/db" },
        .{ .in = "./~/db", .want = "./~/db" },
        .{ .in = "a/~/db", .want = "a/~/db" },
        .{ .in = "../db", .want = "../db" },
    };
    for (cases) |c| {
        const got = try expandHome(gpa, c.in, "/home/me");
        defer gpa.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
    try testing.expectError(error.OtherUser, expandHome(gpa, "~bob/db", "/home/me"));
    try testing.expectError(error.NoHome, expandHome(gpa, "~/db", null));
}

test "a quoted ~ opens under the home directory, not in a directory named ~" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    var st = (try openWithHome(testing.allocator, testing.io, "req", "~/deed/store.mdb", f.root_buf[0..f.root_len], .create, &f.err)) orelse
        return error.TestUnexpectedResult;
    st.deinit();
    try testing.expect(f.exists("deed/store.mdb"));
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, "~", .{}));
}

test "an empty path is refused rather than opened" {
    var f: Fixture = undefined;
    try f.init();
    defer f.deinit();
    try testing.expect(try f.open("", .create) == null);
    try f.said("--store needs a path");
}
