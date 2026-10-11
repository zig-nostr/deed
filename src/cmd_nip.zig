//! `deed nip`: list the NIPs, or print one.
//!
//! The text comes from the NIPs repository on raw.githubusercontent.com, the
//! README for the list and `<NN>.md` for a NIP. Each file is kept in the user
//! cache directory and reused for a day. `--refresh` fetches it again. When
//! the network fails and an older copy is on disk, the old copy is used and
//! stderr says so.

const std = @import("std");
const builtin = @import("builtin");
const cli = @import("cli.zig");
const http = @import("http.zig");

const Io = std.Io;

/// Shown beside the name in `deed help`.
pub const summary = "list the NIPs, or print one by number";

pub const ready = true;

pub const usage =
    \\deed nip: list the NIPs, or print one
    \\
    \\Usage:
    \\  deed nip [--refresh] [<number>]
    \\
    \\With no number, prints each NIP with its title, one per line. With a
    \\number, prints that NIP's text. The number may be written 29, 029, nip29,
    \\NIP-29, and a NIP with a letter in its number is written as it is: C0.
    \\
    \\  deed nip
    \\  deed nip 29
    \\
    \\The files come from the NIPs repository on GitHub and are kept in the
    \\user cache directory for a day. If GitHub cannot be reached, a copy kept
    \\earlier is used and stderr says it is old.
    \\
    \\Options:
    \\      --refresh   fetch again even if a recent copy is kept
    \\
    \\The address can be changed with $DEED_NIPS_URL (default
    \\https://raw.githubusercontent.com/nostr-protocol/nips/master).
    \\
    \\Exits 0 on success, 1 when the text could not be had or there is no such
    \\NIP, and 2 when the command made no sense.
    \\
;

pub const default_base = "https://raw.githubusercontent.com/nostr-protocol/nips/master";

/// A copy kept for longer than this is fetched again.
pub const fresh_seconds: i64 = 24 * 60 * 60;

const max_readme_bytes = 2 * 1024 * 1024;
const max_nip_bytes = 1024 * 1024;

pub const Config = struct {
    base: []const u8 = default_base,
    /// Where files are kept. Null keeps nothing.
    cache_dir: ?[]const u8 = null,
    timeout_ms: u64 = 15_000,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    const cache = cacheDir(gpa) catch null;
    defer if (cache) |c| gpa.free(c);
    return runWith(gpa, io, args, out, err, .{
        .base = getEnv("DEED_NIPS_URL") orelse default_base,
        .cache_dir = cache,
    });
}

pub fn runWith(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
    cfg: Config,
) !u8 {
    var refresh = false;
    var number: ?[]const u8 = null;
    for (args) |a| {
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--refresh")) {
            refresh = true;
        } else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
            try err.print("deed nip: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (number == null) {
            number = a;
        } else {
            try err.writeAll("deed nip: takes one NIP number\n");
            return cli.exit_usage;
        }
    }

    if (number) |n| {
        var name_buf: [8]u8 = undefined;
        const name = normalize(&name_buf, n) orelse {
            try err.print("deed nip: '{s}' is not a NIP number\n", .{n});
            return cli.exit_usage;
        };
        var file_buf: [16]u8 = undefined;
        const file = std.fmt.bufPrint(&file_buf, "{s}.md", .{name}) catch unreachable;
        const text = (try load(gpa, io, cfg, file, max_nip_bytes, refresh, err)) orelse return cli.exit_fail;
        defer gpa.free(text);
        try out.writeAll(text);
        if (text.len == 0 or text[text.len - 1] != '\n') try out.writeByte('\n');
        return cli.exit_ok;
    }

    const readme = (try load(gpa, io, cfg, "README.md", max_readme_bytes, refresh, err)) orelse return cli.exit_fail;
    defer gpa.free(readme);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, readme, '\n');
    while (lines.next()) |line| {
        const item = parseListLine(line) orelse continue;
        try out.print("{s}  {s}\n", .{ item.number, item.title });
        count += 1;
    }
    if (count == 0) {
        try err.writeAll("deed nip: the README lists no NIPs\n");
        return cli.exit_fail;
    }
    return cli.exit_ok;
}

/// `29`, `029`, `nip29`, `NIP-29`, `c0` become `29`, `29`, `29`, `29`, `C0`.
/// Null for anything that could not be a file name in the repository.
fn normalize(buf: []u8, raw: []const u8) ?[]const u8 {
    var s = raw;
    if (s.len >= 3 and std.ascii.eqlIgnoreCase(s[0..3], "nip")) {
        s = s[3..];
        if (s.len > 0 and s[0] == '-') s = s[1..];
    }
    if (s.len == 0 or s.len > 4) return null;
    for (s) |c| if (!std.ascii.isAlphanumeric(c)) return null;
    var all_digits = true;
    for (s) |c| if (!std.ascii.isDigit(c)) {
        all_digits = false;
    };
    if (all_digits) {
        // The files are named with two digits at least: 01, 29, 100 is not a
        // NIP yet, but would be named as written.
        var t = std.mem.trimStart(u8, s, "0");
        if (t.len == 0) t = "0";
        if (t.len == 1) return std.fmt.bufPrint(buf, "0{s}", .{t}) catch null;
        return std.fmt.bufPrint(buf, "{s}", .{t}) catch null;
    }
    for (s, 0..) |c, i| buf[i] = std.ascii.toUpper(c);
    return buf[0..s.len];
}

const Item = struct { number: []const u8, title: []const u8 };

/// A line of the README's list: `- [NIP-01: Basic protocol flow](01.md)`.
fn parseListLine(line: []const u8) ?Item {
    const head = "- [NIP-";
    if (!std.mem.startsWith(u8, line, head)) return null;
    const rest = line[head.len..];
    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    const close = std.mem.indexOf(u8, rest, "](") orelse return null;
    if (close < colon) return null;
    const number = rest[0..colon];
    if (number.len == 0 or number.len > 4) return null;
    for (number) |c| if (!std.ascii.isAlphanumeric(c)) return null;
    return .{ .number = number, .title = std.mem.trim(u8, rest[colon + 1 .. close], " ") };
}

/// The name `file` is kept under: the base address is part of it, so a copy
/// fetched from one base is never served for another.
fn cacheName(buf: []u8, base: []const u8, file: []const u8) ![]const u8 {
    const h = std.hash.Wyhash.hash(0, std.mem.trimEnd(u8, base, "/"));
    return std.fmt.bufPrint(buf, "{x:0>16}-{s}", .{ h, file });
}

/// The text of `file`: from the cache when it is recent, otherwise from the
/// network, otherwise from an old copy. Null after saying why there is none.
fn load(
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    file: []const u8,
    max_bytes: usize,
    refresh: bool,
    err: *Io.Writer,
) !?[]u8 {
    const now = Io.Timestamp.now(io, .real).toSeconds();
    var stale: ?[]u8 = null;
    defer if (stale) |s| gpa.free(s);

    if (cfg.cache_dir) |dir| {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        var name_buf: [64]u8 = undefined;
        const name = cacheName(&name_buf, cfg.base, file) catch "";
        if (std.fmt.bufPrint(&path_buf, "{s}{c}{s}", .{ dir, std.fs.path.sep, name })) |path| {
            const cwd = Io.Dir.cwd();
            if (cwd.statFile(io, path, .{})) |st| {
                if (cwd.readFileAlloc(io, path, gpa, .limited(max_bytes))) |text| {
                    const age = now - st.mtime.toSeconds();
                    if (!refresh and age >= 0 and age < fresh_seconds) return text;
                    stale = text;
                } else |_| {}
            } else |_| {}
        } else |_| {}
    }

    const url = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ std.mem.trimEnd(u8, cfg.base, "/"), file });
    defer gpa.free(url);

    var failure_buf: [64]u8 = undefined;
    var failure: []const u8 = undefined;
    if (http.fetch(gpa, io, url, .{ .timeout_ms = cfg.timeout_ms, .max_bytes = max_bytes })) |r| {
        var res = r;
        if (res.ok()) {
            defer res.deinit(gpa);
            keep(gpa, io, cfg, file, res.body);
            return try gpa.dupe(u8, res.body);
        }
        const status = res.status;
        res.deinit(gpa);
        if (status == 404) {
            try err.print("deed nip: there is no {s} in the NIPs repository\n", .{file});
            return null;
        }
        failure = std.fmt.bufPrint(&failure_buf, "the server answered {d}", .{status}) catch "the server refused";
    } else |e| {
        failure = http.describe(e);
        if (e == error.OutOfMemory) return e;
    }

    if (stale) |s| {
        try err.print("deed nip: could not fetch {s} ({s}); using an older copy\n", .{ file, failure });
        const text = s;
        stale = null;
        return text;
    }
    try err.print("deed nip: could not fetch {s}: {s}\n", .{ url, failure });
    return null;
}

/// Writes `body` to the cache, whole or not at all. A cache that cannot be
/// written is no reason to fail a command that has its text.
fn keep(gpa: std.mem.Allocator, io: Io, cfg: Config, file: []const u8, body: []const u8) void {
    const dir = cfg.cache_dir orelse return;
    const cwd = Io.Dir.cwd();
    cwd.createDirPath(io, dir) catch return;
    var name_buf: [64]u8 = undefined;
    const name = cacheName(&name_buf, cfg.base, file) catch return;
    const path = std.fmt.allocPrint(gpa, "{s}{c}{s}", .{ dir, std.fs.path.sep, name }) catch return;
    defer gpa.free(path);
    const tmp = std.fmt.allocPrint(gpa, "{s}.tmp", .{path}) catch return;
    defer gpa.free(tmp);
    cwd.writeFile(io, .{ .sub_path = tmp, .data = body }) catch return;
    cwd.rename(tmp, cwd, path, io) catch cwd.deleteFile(io, tmp) catch {};
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

/// The directory this verb keeps files in, owned by the caller. Null when the
/// system names no home.
fn cacheDir(gpa: std.mem.Allocator) !?[]u8 {
    if (builtin.os.tag == .windows) {
        const base = getEnv("LOCALAPPDATA") orelse return null;
        return try std.fs.path.join(gpa, &.{ base, "deed", "nips" });
    }
    if (getEnv("XDG_CACHE_HOME")) |x| {
        if (std.fs.path.isAbsolute(x)) return try std.fs.path.join(gpa, &.{ x, "deed", "nips" });
    }
    const home = getEnv("HOME") orelse return null;
    if (builtin.os.tag == .macos) return try std.fs.path.join(gpa, &.{ home, "Library", "Caches", "deed", "nips" });
    return try std.fs.path.join(gpa, &.{ home, ".cache", "deed", "nips" });
}

// ---- tests ---------------------------------------------------------------

const fake_readme =
    \\# NIPs
    \\
    \\## List
    \\
    \\- [NIP-01: Basic protocol flow description](01.md)
    \\- [NIP-29: Relay-based Groups](29.md)
    \\- [NIP-C0: Code Snippets](C0.md)
    \\
    \\| kind | description |
    \\| 1 | note |
    \\
;

const fake_nip29 = "NIP-29\n======\n\nRelay-based Groups\n";

test "numbers are normalized to file names" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("29", normalize(&buf, "29").?);
    try std.testing.expectEqualStrings("29", normalize(&buf, "029").?);
    try std.testing.expectEqualStrings("29", normalize(&buf, "nip29").?);
    try std.testing.expectEqualStrings("29", normalize(&buf, "NIP-29").?);
    try std.testing.expectEqualStrings("01", normalize(&buf, "1").?);
    try std.testing.expectEqualStrings("C0", normalize(&buf, "c0").?);
    try std.testing.expect(normalize(&buf, "../x") == null);
    try std.testing.expect(normalize(&buf, "") == null);
    try std.testing.expect(normalize(&buf, "12345") == null);
}

const Fixture = struct {
    tmp: std.testing.TmpDir,
    root: [std.fs.max_path_bytes]u8 = undefined,
    root_len: usize = 0,

    fn init(self: *Fixture) !void {
        self.* = .{ .tmp = std.testing.tmpDir(.{}) };
        self.root_len = try self.tmp.dir.realPath(std.testing.io, &self.root);
    }

    fn cache(self: *Fixture) []const u8 {
        return self.root[0..self.root_len];
    }
};

test "no argument lists the NIPs, one number and title per line" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/README.md", .body = fake_readme }}, 1);
    defer srv.stop(io);
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.tmp.cleanup();

    var base_buf: [64]u8 = undefined;
    const base = try srv.url(&base_buf, "");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try runWith(gpa, io, &.{}, &out.writer, &err.writer, .{ .base = base, .cache_dir = fx.cache() });
    try std.testing.expectEqual(cli.exit_ok, code);
    try std.testing.expectEqualStrings(
        "01  Basic protocol flow description\n29  Relay-based Groups\nC0  Code Snippets\n",
        out.written(),
    );
    try std.testing.expectEqualStrings("", err.written());
}

test "a number prints that NIP, and a second run is served from the cache" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    // One connection only: a second fetch would find nobody to answer it.
    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/29.md", .body = fake_nip29 }}, 1);
    defer srv.stop(io);
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.tmp.cleanup();

    var base_buf: [64]u8 = undefined;
    const cfg: Config = .{ .base = try srv.url(&base_buf, ""), .cache_dir = fx.cache(), .timeout_ms = 2_000 };
    for (0..2) |_| {
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err: Io.Writer.Allocating = .init(gpa);
        defer err.deinit();
        const code = try runWith(gpa, io, &.{"nip29"}, &out.writer, &err.writer, cfg);
        try std.testing.expectEqual(cli.exit_ok, code);
        try std.testing.expectEqualStrings(fake_nip29, out.written());
        try std.testing.expectEqualStrings("", err.written());
    }
}

test "--refresh fetches again, and an unreachable server falls back to the old copy" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/29.md", .body = "new text\n" }}, 1);
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.tmp.cleanup();
    var base_buf: [64]u8 = undefined;
    const base = try gpa.dupe(u8, try srv.url(&base_buf, ""));
    defer gpa.free(base);
    var name_buf: [64]u8 = undefined;
    try fx.tmp.dir.writeFile(io, .{ .sub_path = try cacheName(&name_buf, base, "29.md"), .data = "old text\n" });
    const cfg: Config = .{ .base = base, .cache_dir = fx.cache(), .timeout_ms = 2_000 };

    {
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err: Io.Writer.Allocating = .init(gpa);
        defer err.deinit();
        _ = try runWith(gpa, io, &.{ "--refresh", "29" }, &out.writer, &err.writer, cfg);
        try std.testing.expectEqualStrings("new text\n", out.written());
    }
    srv.stop(io);
    {
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err: Io.Writer.Allocating = .init(gpa);
        defer err.deinit();
        const code = try runWith(gpa, io, &.{ "--refresh", "29" }, &out.writer, &err.writer, cfg);
        try std.testing.expectEqual(cli.exit_ok, code);
        try std.testing.expectEqualStrings("new text\n", out.written());
        try std.testing.expect(std.mem.indexOf(u8, err.written(), "older copy") != null);
    }
}

test "a NIP that does not exist fails, and a bad number is a usage error" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var srv: http.TestServer = undefined;
    try srv.start(io, &.{}, 1);
    defer srv.stop(io);

    var base_buf: [64]u8 = undefined;
    const cfg: Config = .{ .base = try srv.url(&base_buf, ""), .timeout_ms = 2_000 };
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_fail, try runWith(gpa, io, &.{"999"}, &out.writer, &err.writer, cfg));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "no 999.md") != null);
    try std.testing.expectEqual(cli.exit_usage, try runWith(gpa, io, &.{"../etc"}, &out.writer, &err.writer, cfg));
    try std.testing.expectEqualStrings("", out.written());
}

test "changing the base address does not serve the copy kept for the old one" {
    const io = std.testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var one: http.TestServer = undefined;
    try one.start(io, &.{.{ .path = "/29.md", .body = "from one\n" }}, 1);
    defer one.stop(io);
    var two: http.TestServer = undefined;
    try two.start(io, &.{.{ .path = "/29.md", .body = "from two\n" }}, 1);
    defer two.stop(io);
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.tmp.cleanup();

    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    const bases = [_][]const u8{ try one.url(&b1, ""), try two.url(&b2, "") };
    const want = [_][]const u8{ "from one\n", "from two\n" };
    for (bases, want) |base, text| {
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err: Io.Writer.Allocating = .init(gpa);
        defer err.deinit();
        const code = try runWith(gpa, io, &.{"29"}, &out.writer, &err.writer, .{ .base = base, .cache_dir = fx.cache(), .timeout_ms = 2_000 });
        try std.testing.expectEqual(cli.exit_ok, code);
        try std.testing.expectEqualStrings(text, out.written());
    }
}
