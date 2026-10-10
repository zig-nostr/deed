//! `deed profile`: read a profile, or change one.
//!
//! A profile is a kind 0 event whose content is a JSON object, and it is
//! replaceable: publishing a new one throws the old one away. So `set` never
//! builds a profile from the flags alone. It reads the current one first, changes
//! only the fields it was told to, keeps every other field exactly as it found
//! it (a client may have put fields here that this tool has never heard of), and
//! refuses to write at all when it could not read the current one.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const keyinput = @import("keyinput.zig");
const post = @import("cmd_post.zig");
const outbox = @import("outbox.zig");
const storepath = @import("storepath.zig");

const event = nostr.event;
const nip19 = nostr.nip19;

/// Shown beside the name in `deed help`.
pub const summary = "show a profile, or change your own";

pub const ready = true;

pub const usage =
    \\deed profile: show a profile, or change your own
    \\
    \\Usage:
    \\  deed profile [options] <npub|nprofile|hex> [<relay-url>...]
    \\  deed profile set [options] [<relay-url>...]
    \\
    \\Show fetches the newest kind 0 event from the relays named (and the relays an
    \\nprofile carries), checks its signature, and prints its fields. With --store
    \\and no relay it reads the store alone; with both, what the relays send is kept
    \\in the store as well. With neither, it asks the relays that person writes to,
    \\found through the relays in DEED_RELAYS or given with --relay.
    \\
    \\Options for show:
    \\      --json           print the verified kind 0 event instead of the fields
    \\  -r, --relay <url>  where to look up that person's relay list when no relay
    \\                     is named, repeatable (and DEED_RELAYS)
    \\      --store <path>   a local store to read from, or to keep what arrives in
    \\      --timeout <ms>   how long the relays get (default 10000)
    \\
    \\Set reads your current profile from the relays, changes the fields given,
    \\keeps every other field as it was, signs the result with --sec and publishes
    \\it to the same relays. With no relay named it uses the relays you write to,
    \\found through the relays in DEED_RELAYS or given with --relay. It prints the event
    \\if a relay accepted it.
    \\
    \\Options for set:
    \\      --sec <key>        secret key, as nsec1... or 64 hex characters.
    \\                         Falls back to $NOSTR_SECRET_KEY.
    \\      --name <text>      --about <text>   --picture <url>   --banner <url>
    \\      --nip05 <name>     --lud16 <addr>   --website <url>
    \\      --metadata <json>  a JSON object of fields to set, applied before the
    \\                         flags above, which win
    \\      --force-new        publish a profile built from only these flags when
    \\                         none could be read back. Without it, a profile that
    \\                         could not be read is never written over.
    \\  -r, --relay <url>   where to look up your relay list when no relay is
    \\                         named, repeatable (and DEED_RELAYS)
    \\      --confirm          ask on the terminal before publishing
    \\      --dry-run          print the signed event and publish nothing
    \\      --timeout <ms>     how long the relays get (default 10000)
    \\
    \\  deed profile npub1... wss://relay.example
    \\  deed profile set --sec nsec1... --about "hello" wss://relay.example
    \\
    \\Exits 0 on success, 1 when the profile was not found or not published, and
    \\2 when the command made no sense.
    \\
;

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    if (args.len > 0 and std.mem.eql(u8, args[0], "set")) return runSet(gpa, io, args[1..], out, err);
    return runShow(gpa, io, args, out, err);
}

// ---------------------------------------------------------------------------
// Show
// ---------------------------------------------------------------------------

const timeout_default = post.default_timeout_ms;

fn runShow(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var code: ?[]const u8 = null;
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);
    var bootstrap: std.ArrayList([]const u8) = .empty;
    defer bootstrap.deinit(gpa);
    var store_path: ?[]const u8 = null;
    var as_json = false;
    var timeout_ms: i64 = timeout_default;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--json")) {
            as_json = true;
        } else if (cli.isOneOf(a, &.{ "--store", "--timeout", "-r", "--relay" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed profile: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try bootstrap.append(gpa, args[i]);
            } else if (std.mem.eql(u8, a, "--store")) {
                store_path = args[i];
            } else {
                timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch 0;
                if (timeout_ms <= 0) {
                    try err.print("deed profile: --timeout needs a number of milliseconds, not '{s}'\n", .{args[i]});
                    return cli.exit_usage;
                }
            }
        } else if (post.isRelayUrl(a)) {
            try urls.append(gpa, a);
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed profile: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (code == null) {
            code = a;
        } else {
            try err.writeAll("deed profile: takes one person\n");
            return cli.exit_usage;
        }
    }

    const raw = code orelse {
        try err.writeAll("deed profile: needs an npub, an nprofile or a hex public key\n");
        return cli.exit_usage;
    };

    var hints: [][]u8 = &.{};
    defer {
        for (hints) |h| gpa.free(h);
        gpa.free(hints);
    }
    var pubkey: [32]u8 = undefined;
    const s = keyinput.stripUri(std.mem.trim(u8, raw, " \t\r\n"));
    if (keyinput.hasPrefix(s, "nprofile1")) {
        const p = nip19.decodeNprofile(gpa, s) catch {
            try err.print("deed profile: {s}: not a profile code\n", .{raw});
            return cli.exit_fail;
        };
        pubkey = p.pubkey;
        hints = p.relays;
    } else {
        pubkey = keyinput.publicKey(gpa, s) catch {
            try err.print("deed profile: {s}: not an npub, nprofile or hex public key\n", .{raw});
            return cli.exit_fail;
        };
    }
    for (hints) |h| {
        var seen = false;
        for (urls.items) |u| {
            if (std.mem.eql(u8, u, h)) seen = true;
        }
        if (!seen) try urls.append(gpa, h);
    }

    var authors = [1][32]u8{pubkey};
    const kinds = [1]u16{0};
    const f: nostr.filter.Filter = .{ .authors = &authors, .kinds = &kinds, .limit = 1 };

    var parsed: ?event.Parsed = null;
    defer if (parsed) |*p| p.deinit();

    // Neither a relay nor a store: follow the person to the relays they write to.
    var followed: ?outbox.Urls = null;
    defer if (followed) |*fu| fu.deinit();
    if (urls.items.len == 0 and store_path == null) {
        followed = (try outbox.followWriteRelays(gpa, io, "profile", pubkey, bootstrap.items, null, timeout_ms, err)) orelse return cli.exit_usage;
        try urls.appendSlice(gpa, followed.?.urls[0..@min(followed.?.urls.len, dial.max_relays)]);
    }

    if (urls.items.len == 0) {
        const path = store_path orelse {
            try err.writeAll("deed profile: name a relay to look in, or a --store to read from\n");
            return cli.exit_usage;
        };
        var st = (try storepath.open(gpa, io, "profile", path, .existing, err)) orelse return cli.exit_fail;
        defer st.deinit();
        var result = st.query(gpa, f) catch |e| {
            try err.print("deed profile: the store could not answer: {s}\n", .{@errorName(e)});
            return cli.exit_fail;
        };
        defer result.deinit();
        for (result.events) |ev| {
            if (!(event.verify(gpa, nostr.keys.Signer.init(), ev) catch false)) continue;
            const json = try event.toJson(gpa, ev);
            defer gpa.free(json);
            var p = try event.fromJson(gpa, json);
            if (parsed) |*cur| {
                if (post.newerThan(p.value, cur.value)) {
                    cur.deinit();
                    parsed = p;
                } else p.deinit();
            } else parsed = p;
        }
    } else {
        var store: ?nostr.store.Store = null;
        defer if (store) |*st| st.deinit();
        if (store_path) |path| {
            store = (try storepath.open(gpa, io, "profile", path, .create, err)) orelse return cli.exit_fail;
        }
        const found = try post.fetchNewest(gpa, io, urls.items, f, timeout_ms, if (store) |*st| st else null, err);
        if (found.dialled == 0) {
            try err.writeAll("deed profile: no relay answered\n");
            return cli.exit_fail;
        }
        parsed = found.parsed;
    }

    const p = parsed orelse {
        try err.writeAll("deed profile: no profile found\n");
        return cli.exit_fail;
    };

    if (as_json) {
        const json = try event.toJson(gpa, p.value);
        defer gpa.free(json);
        try out.print("{s}\n", .{json});
        return cli.exit_ok;
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const npub = try nip19.encodeNpub(arena_state.allocator(), pubkey);
    writeFields(arena_state.allocator(), out, npub, p.value.content) catch |e| switch (e) {
        error.NotAProfile => {
            try err.writeAll("deed profile: that profile's content is not a JSON object\n");
            return cli.exit_fail;
        },
        else => return e,
    };
    return cli.exit_ok;
}

/// The fields people look for first, in the order they are shown. Anything else
/// the profile carries follows them.
const known_fields = [_][]const u8{
    "name", "display_name", "about", "picture", "banner", "nip05", "lud16", "lud06", "website",
};

fn writeFields(a: std.mem.Allocator, out: *std.Io.Writer, npub: []const u8, content: []const u8) !void {
    const obj = try parseObject(a, content);
    try out.print("{s}\n", .{npub});
    for (known_fields) |k| {
        if (obj.get(k)) |v| try writeField(a, out, k, v);
    }
    var it = obj.iterator();
    while (it.next()) |kv| {
        var known = false;
        for (known_fields) |k| {
            if (std.mem.eql(u8, k, kv.key_ptr.*)) known = true;
        }
        if (!known) try writeField(a, out, kv.key_ptr.*, kv.value_ptr.*);
    }
}

fn writeField(a: std.mem.Allocator, out: *std.Io.Writer, key: []const u8, v: std.json.Value) !void {
    switch (v) {
        .string => |s| try out.print("{s}: {s}\n", .{ key, s }),
        .number_string => |s| try out.print("{s}: {s}\n", .{ key, s }),
        else => {
            const text = try std.json.Stringify.valueAlloc(a, v, .{});
            try out.print("{s}: {s}\n", .{ key, text });
        },
    }
}

// ---------------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------------

const Field = struct { key: []const u8, value: []const u8 };

const field_flags = [_]struct { flag: []const u8, key: []const u8 }{
    .{ .flag = "--name", .key = "name" },
    .{ .flag = "--about", .key = "about" },
    .{ .flag = "--picture", .key = "picture" },
    .{ .flag = "--banner", .key = "banner" },
    .{ .flag = "--nip05", .key = "nip05" },
    .{ .flag = "--lud16", .key = "lud16" },
    .{ .flag = "--website", .key = "website" },
};

const MergeError = error{ NotAProfile, BadMetadata } || std.mem.Allocator.Error;

fn parseObject(a: std.mem.Allocator, text: []const u8) MergeError!std.json.ObjectMap {
    // Numbers stay as written, so a field this tool does not understand comes
    // back out byte for byte rather than reformatted.
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{ .parse_numbers = false }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NotAProfile,
    };
    return switch (v) {
        .object => |o| o,
        else => error.NotAProfile,
    };
}

/// The content of the new profile: `current` (null when starting fresh) with the
/// fields of `metadata` set, then `fields` set over them. Every other field of
/// `current` is carried over unchanged, in its original order.
pub fn mergeProfile(
    a: std.mem.Allocator,
    current: ?[]const u8,
    metadata: ?[]const u8,
    fields: []const Field,
) MergeError![]u8 {
    var obj: std.json.ObjectMap = if (current) |c| try parseObject(a, c) else .empty;
    if (metadata) |m| {
        const extra = parseObject(a, m) catch |e| switch (e) {
            error.NotAProfile => return error.BadMetadata,
            else => return e,
        };
        var it = extra.iterator();
        while (it.next()) |kv| try obj.put(a, kv.key_ptr.*, kv.value_ptr.*);
    }
    for (fields) |f| try obj.put(a, f.key, .{ .string = f.value });
    return std.json.Stringify.valueAlloc(a, std.json.Value{ .object = obj }, .{});
}

fn runSet(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var urls: std.ArrayList([]const u8) = .empty;
    defer urls.deinit(gpa);
    var bootstrap: std.ArrayList([]const u8) = .empty;
    defer bootstrap.deinit(gpa);
    var fields: std.ArrayList(Field) = .empty;
    defer fields.deinit(gpa);
    var sec: ?[]const u8 = null;
    var metadata: ?[]const u8 = null;
    var force_new = false;
    var confirm = false;
    var dry_run = false;
    var timeout_ms: i64 = timeout_default;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--force-new")) {
            force_new = true;
        } else if (std.mem.eql(u8, a, "--confirm")) {
            confirm = true;
        } else if (std.mem.eql(u8, a, "--dry-run")) {
            dry_run = true;
        } else if (post.isRelayUrl(a)) {
            try urls.append(gpa, a);
        } else {
            var flag_key: ?[]const u8 = null;
            for (field_flags) |ff| {
                if (std.mem.eql(u8, ff.flag, a)) flag_key = ff.key;
            }
            if (flag_key == null and !cli.isOneOf(a, &.{ "--sec", "--metadata", "--timeout", "-r", "--relay" })) {
                try err.print("deed profile set: unknown option '{s}'\n", .{a});
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed profile set: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            const v = args[i];
            if (flag_key) |k| {
                // The last one given wins, so a flag can be repeated to correct it.
                var replaced = false;
                for (fields.items) |*f| {
                    if (std.mem.eql(u8, f.key, k)) {
                        f.value = v;
                        replaced = true;
                    }
                }
                if (!replaced) try fields.append(gpa, .{ .key = k, .value = v });
            } else if (std.mem.eql(u8, a, "--sec")) {
                sec = v;
            } else if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try bootstrap.append(gpa, v);
            } else if (std.mem.eql(u8, a, "--metadata")) {
                metadata = v;
            } else {
                timeout_ms = std.fmt.parseInt(i64, v, 10) catch 0;
                if (timeout_ms <= 0) {
                    try err.print("deed profile set: --timeout needs a number of milliseconds, not '{s}'\n", .{v});
                    return cli.exit_usage;
                }
            }
        }
    }

    if (fields.items.len == 0 and metadata == null) {
        try err.writeAll("deed profile set: nothing to change: give at least one field or --metadata\n");
        return cli.exit_usage;
    }
    const sk = (try post.readSecret(gpa, "profile set", sec, err)) orelse return cli.exit_usage;

    // Checked here, before any relay is asked, so a bad --metadata costs nothing.
    {
        var probe = std.heap.ArenaAllocator.init(gpa);
        defer probe.deinit();
        _ = mergeProfile(probe.allocator(), null, metadata, &.{}) catch |e| switch (e) {
            error.BadMetadata => {
                try err.writeAll("deed profile set: --metadata must be a JSON object\n");
                return cli.exit_usage;
            },
            else => return e,
        };
    }

    var tty: ?post.Tty = null;
    defer if (tty) |*t| t.close();
    if (confirm and !dry_run) {
        tty = post.Tty.open(io) orelse {
            try err.writeAll("deed profile set: --confirm needs a terminal to ask on, and there is none\n");
            return cli.exit_fail;
        };
    }

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const keypair = try signer.keyPairFromSecretKey(sk);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No relay named: the relays you write to, which also holds your current
    // profile. The read below still decides whether anything is written.
    var followed: ?outbox.Urls = null;
    defer if (followed) |*fu| fu.deinit();
    if (urls.items.len == 0 and !(dry_run and force_new)) {
        followed = (try outbox.followWriteRelays(gpa, io, "profile set", keypair.public_key, bootstrap.items, null, timeout_ms, err)) orelse return cli.exit_usage;
        const take = @min(followed.?.urls.len, dial.max_relays);
        try urls.appendSlice(gpa, followed.?.urls[0..take]);
    }

    // The read comes first and decides everything after it.
    var current: ?event.Parsed = null;
    defer if (current) |*p| p.deinit();
    if (urls.items.len > 0) {
        var authors = [1][32]u8{keypair.public_key};
        const kinds = [1]u16{0};
        const found = try post.fetchNewest(gpa, io, urls.items, .{ .authors = &authors, .kinds = &kinds, .limit = 1 }, timeout_ms, null, err);
        current = found.parsed;
        if (current == null and !force_new) {
            if (found.dialled == 0) {
                try err.writeAll("deed profile set: no relay answered, so the current profile could not be read. Nothing was written\n");
            } else {
                try err.writeAll("deed profile set: no current profile was found on those relays. Nothing was written, because a profile published now would replace one this run could not see. Use --force-new only if there really is none\n");
            }
            return cli.exit_fail;
        }
    }

    const merged = mergeProfile(arena, if (current) |c| c.value.content else null, metadata, fields.items) catch |e| switch (e) {
        error.NotAProfile => {
            try err.writeAll("deed profile set: the current profile's content is not a JSON object, so it is left alone\n");
            return cli.exit_fail;
        },
        error.BadMetadata => {
            try err.writeAll("deed profile set: --metadata must be a JSON object\n");
            return cli.exit_usage;
        },
        else => return e,
    };

    // A replacement has to be newer than what it replaces, or relays keep the
    // old one when both land in the same second.
    var created_at = std.Io.Timestamp.now(io, .real).toSeconds();
    if (current) |c| created_at = @max(created_at, c.value.created_at + 1);
    const ev = try event.create(arena, signer, keypair, created_at, 0, &.{}, merged, null);
    const wire = try event.toJson(arena, ev);

    if (dry_run) {
        try out.print("{s}\n", .{wire});
        return cli.exit_ok;
    }
    if (tty) |*t| {
        if (!try t.confirm(merged, urls.items.len)) {
            try err.writeAll("deed profile set: not published, not confirmed\n");
            return cli.exit_fail;
        }
    }
    const accepted = try post.publishEvent(gpa, io, urls.items, ev, timeout_ms, "profile set", err);
    if (accepted == 0) {
        try err.writeAll("deed profile set: not published, no relay accepted it\n");
        return cli.exit_fail;
    }
    try out.print("{s}\n", .{wire});
    return cli.exit_ok;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "a merge changes the fields it was given and keeps every other one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const current =
        \\{"name":"old","custom_flag":{"nested":[1,2.50,true]},"lud06":"lnurl1abc","big":12345678901234567890,"about":"hi"}
    ;
    const merged = try mergeProfile(a, current, null, &.{.{ .key = "name", .value = "new" }});
    try testing.expectEqualStrings(
        \\{"name":"new","custom_flag":{"nested":[1,2.50,true]},"lud06":"lnurl1abc","big":12345678901234567890,"about":"hi"}
    , merged);
}

test "metadata is applied first and the named flags win over it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const merged = try mergeProfile(a, "{\"name\":\"a\",\"x\":1}", "{\"name\":\"b\",\"y\":2}", &.{.{ .key = "name", .value = "c" }});
    try testing.expectEqualStrings("{\"name\":\"c\",\"x\":1,\"y\":2}", merged);
}

test "a current profile that is not an object is refused rather than replaced" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try testing.expectError(error.NotAProfile, mergeProfile(a, "not json", null, &.{}));
    try testing.expectError(error.NotAProfile, mergeProfile(a, "[1]", null, &.{}));
    try testing.expectError(error.BadMetadata, mergeProfile(a, null, "[1]", &.{}));
}

const Fixture = struct {
    sk: [32]u8 = [_]u8{0x44} ** 32,

    fn profileJson(self: Fixture, a: std.mem.Allocator, io: std.Io, content: []const u8) ![]const u8 {
        return post.signedJson(a, io, self.sk, 0, &.{}, content, 1_700_000_000);
    }
};

test "set refuses when the current profile was not read, and writes nothing" {
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the profile verb leaked");
    const gpa = da.allocator();

    var script = post.Script{};
    var relay: testrelay.Relay = undefined;
    try relay.startFor(io, .custom, 3);
    relay.custom = post.Script.handle;
    relay.custom_ctx = &script;
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    const code = try run(gpa, io, &.{ "set", "--sec", "44" ** 32, "--name", "me", url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_fail, code);
    try testing.expectEqual(@as(usize, 0), script.events);
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expect(std.mem.indexOf(u8, err.written(), "Nothing was written") != null);

    // With --force-new the same call goes through, from the flags alone.
    err.clearRetainingCapacity();
    const forced = try run(gpa, io, &.{ "set", "--sec", "44" ** 32, "--name", "me", "--force-new", url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, forced);
    try testing.expectEqual(@as(usize, 1), script.events);
    try testing.expect(std.mem.indexOf(u8, out.written(), "{\\\"name\\\":\\\"me\\\"}") != null);
}

test "a scripted round trip: set reads, merges, publishes, and keeps the unknown field" {
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the profile verb leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const fx = Fixture{};
    const current = try fx.profileJson(a, io, "{\"name\":\"old\",\"mystery\":{\"k\":[1,2]},\"about\":\"keep me\"}");

    var script = post.Script{ .serve = current };
    var relay: testrelay.Relay = undefined;
    try relay.startFor(io, .custom, 2);
    relay.custom = post.Script.handle;
    relay.custom_ctx = &script;
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    const code = try run(gpa, io, &.{ "set", "--sec", "44" ** 32, "--name", "new", url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expectEqual(@as(usize, 1), script.events);

    var sent = try event.fromJson(gpa, std.mem.trimEnd(u8, out.written(), "\n"));
    defer sent.deinit();
    try testing.expectEqual(@as(u16, 0), sent.value.kind);
    try testing.expectEqualStrings(
        "{\"name\":\"new\",\"mystery\":{\"k\":[1,2]},\"about\":\"keep me\"}",
        sent.value.content,
    );
    // Newer than what it replaces.
    try testing.expect(sent.value.created_at > 1_700_000_000);
    try testing.expect(std.mem.indexOf(u8, script.got[0..script.got_len], "mystery") != null);
}

test "show prints the fields, known ones first, and --json prints the event" {
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the profile verb leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const fx = Fixture{};
    const current = try fx.profileJson(a, io, "{\"zzz\":3,\"about\":\"hello\",\"name\":\"ann\"}");
    var parsed = try event.fromJson(a, current);
    defer parsed.deinit();
    const npub = try nip19.encodeNpub(a, parsed.value.pubkey);

    var script = post.Script{ .serve = current };
    var relay: testrelay.Relay = undefined;
    try relay.startFor(io, .custom, 2);
    relay.custom = post.Script.handle;
    relay.custom_ctx = &script;
    defer relay.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    const code = try run(gpa, io, &.{ npub, url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    const want = try std.fmt.allocPrint(a, "{s}\nname: ann\nabout: hello\nzzz: 3\n", .{npub});
    try testing.expectEqualStrings(want, out.written());

    out.clearRetainingCapacity();
    const as_json = try run(gpa, io, &.{ npub, url, "--json", "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, as_json);
    try testing.expectEqualStrings(current, std.mem.trimEnd(u8, out.written(), "\n"));
}

test "with no relay and no store, show follows the person to the relays they write to" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    const testrelay = @import("testrelay.zig");
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the profile verb leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const fx = Fixture{};
    var home_script = post.Script{ .serve = try fx.profileJson(a, io, "{\"name\":\"followed\"}") };
    var home: testrelay.Relay = undefined;
    try home.startCustom(io, post.Script.handle, &home_script);
    defer home.stop(io);
    var home_buf: [40]u8 = undefined;
    const home_url = try testrelay.url(&home_buf, home.port());

    const tags = [_]event.Tag{&.{ "r", home_url, "write" }};
    var dir_script: outbox.Script = .{ .list = try post.signedJson(a, io, fx.sk, 10002, &tags, "", 1_700_000_000) };
    var directory: testrelay.Relay = undefined;
    try outbox.startScript(&directory, io, &dir_script, 1);
    defer directory.stop(io);
    var dir_buf: [40]u8 = undefined;
    const dir_url = try testrelay.url(&dir_buf, directory.port());

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(fx.sk);
    const npub = try nip19.encodeNpub(a, kp.public_key);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ npub, "--relay", dir_url, "--timeout", "5000" }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expect(std.mem.indexOf(u8, out.written(), "followed") != null);
}
