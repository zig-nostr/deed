//! `deed group`: read and write NIP-29 relay-based groups.
//!
//! A group lives on one relay and is named `relay'group-id`. The relay signs
//! the group's own state: kind 39000 is the metadata, 39001 the admins, 39002
//! the members, each addressed by the group id in its `d` tag. Messages are
//! kind 9 with an `h` tag, and everything else a member or admin does is an
//! ordinary event carrying the same `h` tag: 9021 asks to join, 9022 leaves,
//! 9000 to 9009 are moderation.
//!
//! Reads go through the same machinery as `deed req`, so every event printed
//! has been checked and matches the question asked. Writes are signed here
//! and offered to the group's relay, and an event is printed only if the relay
//! accepted it. A relay that answers with `auth-required:` is answered with
//! NIP-42 when `--auth` is given, and the event is offered once more.

const std = @import("std");
const nostr = @import("nostr");
const auth = @import("auth.zig");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const http = @import("http.zig");
const keyinput = @import("keyinput.zig");
const post = @import("cmd_post.zig");
const relayset = @import("relayset.zig");

const Io = std.Io;
const event = nostr.event;
const filter = nostr.filter;
const hex = nostr.hex;
const nip19 = nostr.nip19;
const nip11 = nostr.nip11;

/// Shown beside the name in `deed help`.
pub const summary = "read and write NIP-29 groups: info, chat, join, moderation";

pub const ready = true;

pub const default_timeout_ms: i64 = 10_000;

pub const usage =
    \\deed group: read and write NIP-29 relay-based groups
    \\
    \\Usage:
    \\  deed group info <group> [--events]
    \\  deed group members <group> [--events]
    \\  deed group admins <group> [--events]
    \\  deed group chat <group> [--limit <n>]
    \\  deed group chat <group> --send <text>
    \\  deed group join <group> [--code <invite>] [--reason <text>]
    \\  deed group leave <group> [--reason <text>]
    \\
    \\Moderation, for admins:
    \\  deed group put-user <group> --pubkey <key> [--role <name>]...
    \\  deed group remove-user <group> <pubkey>
    \\  deed group delete-event <group> --event <id>
    \\  deed group create-group <group>
    \\  deed group delete-group <group>
    \\  deed group create-invite <group> [--code <invite>]
    \\
    \\A group is written relay'group-id, as in wss://groups.example'pizza. The
    \\scheme may be left off (wss:// is used, ws:// for a local address), and
    \\host/group-id and a naddr1 code with a relay hint are understood too.
    \\
    \\info prints one JSON object built from the group's metadata, admins and
    \\members. members prints one public key per line, admins one line per admin
    \\with the roles after the key. With --events, those three print the signed
    \\events the relay sent instead. chat prints the newest kind 9 messages,
    \\oldest first, as one event per line.
    \\
    \\The group's state (kinds 39000, 39001 and 39002) counts only when the
    \\relay's own key signed it. That key is the `self` field of the relay's
    \\NIP-11 document, or its `pubkey` field when `self` is absent; events from
    \\any other key are dropped. A relay that states neither, or whose document
    \\cannot be read, is still read, with a warning, and info then carries
    \\"verified":false. Text the relay supplies is printed with control
    \\characters escaped.
    \\
    \\Everything that writes is signed with --sec (or $NOSTR_SECRET_KEY), offered
    \\to the group's relay, and printed only if the relay accepted it. Every
    \\event that is read has had its signature checked.
    \\
    \\Options:
    \\      --timeout <ms>   how long the relay gets to answer (default 10000)
    \\      --limit <n>      most messages to read (default 50)
    \\      --events         print the signed events, not a summary
++ auth.usage_lines ++
    \\
    \\Exits 0 on success, 1 when the relay could not be reached, had nothing,
    \\or refused, and 2 when the command made no sense.
    \\
;

const Cmd = enum {
    info,
    members,
    admins,
    chat,
    join,
    leave,
    put_user,
    remove_user,
    delete_event,
    create_group,
    delete_group,
    create_invite,
};

const names = [_]struct { []const u8, Cmd }{
    .{ "info", .info },
    .{ "members", .members },
    .{ "admins", .admins },
    .{ "chat", .chat },
    .{ "join", .join },
    .{ "leave", .leave },
    .{ "put-user", .put_user },
    .{ "remove-user", .remove_user },
    .{ "delete-event", .delete_event },
    .{ "create-group", .create_group },
    .{ "delete-group", .delete_group },
    .{ "create-invite", .create_invite },
};

const Flag = enum { timeout, limit, send, pubkey, role, event, code, reason, events };

fn allowed(cmd: Cmd, f: Flag) bool {
    if (f == .timeout) return true;
    return switch (cmd) {
        .info, .members, .admins => f == .events,
        .chat => f == .limit or f == .send,
        .join => f == .code or f == .reason,
        .leave => f == .reason,
        .put_user => f == .pubkey or f == .role,
        .remove_user => f == .pubkey,
        .delete_event => f == .event,
        .create_invite => f == .code,
        .create_group, .delete_group => false,
    };
}

const Options = struct {
    timeout_ms: i64 = default_timeout_ms,
    limit: u32 = 50,
    send: ?[]const u8 = null,
    pubkey: ?[]const u8 = null,
    event: ?[]const u8 = null,
    code: ?[]const u8 = null,
    reason: ?[]const u8 = null,
    events: bool = false,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    if (args.len == 0) {
        try err.writeAll("deed group: say what to do: info, members, admins, chat, join, leave, ...\nRun `deed help group` for the list.\n");
        return cli.exit_usage;
    }
    if (cli.isOneOf(args[0], &.{ "help", "-h", "--help" })) {
        try out.writeAll(usage);
        return cli.exit_ok;
    }
    var cmd: ?Cmd = null;
    for (names) |n| if (std.mem.eql(u8, n[0], args[0])) {
        cmd = n[1];
    };
    const c = cmd orelse {
        try err.print("deed group: unknown subcommand '{s}'\nRun `deed help group` for the list.\n", .{args[0]});
        return cli.exit_usage;
    };

    var opts = Options{};
    var auth_flags: auth.Flags = .{};
    var roles: std.ArrayList([]const u8) = .empty;
    defer roles.deinit(gpa);
    var address: ?[]const u8 = null;
    var extra: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        switch (auth_flags.take(args, &i)) {
            .taken => continue,
            .missing_value => {
                try err.print("deed group: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            },
            .not_mine => {},
        }
        const flag: ?Flag = if (std.mem.eql(u8, a, "--timeout")) .timeout else if (std.mem.eql(u8, a, "--limit")) .limit else if (std.mem.eql(u8, a, "--send")) .send else if (std.mem.eql(u8, a, "--pubkey")) .pubkey else if (std.mem.eql(u8, a, "--role")) .role else if (std.mem.eql(u8, a, "--event")) .event else if (std.mem.eql(u8, a, "--code")) .code else if (std.mem.eql(u8, a, "--reason")) .reason else if (std.mem.eql(u8, a, "--events")) .events else null;
        if (flag) |f| {
            if (!allowed(c, f)) {
                try err.print("deed group {s}: '{s}' does not apply here\n", .{ args[0], a });
                return cli.exit_usage;
            }
            if (f == .events) {
                opts.events = true;
                continue;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed group: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            const v = args[i];
            switch (f) {
                .timeout => {
                    opts.timeout_ms = std.fmt.parseInt(i64, v, 10) catch 0;
                    if (opts.timeout_ms <= 0) {
                        try err.print("deed group: --timeout needs a number of milliseconds, not '{s}'\n", .{v});
                        return cli.exit_usage;
                    }
                },
                .limit => {
                    opts.limit = std.fmt.parseInt(u32, v, 10) catch 0;
                    if (opts.limit == 0) {
                        try err.print("deed group: --limit needs a number above zero, not '{s}'\n", .{v});
                        return cli.exit_usage;
                    }
                },
                .send => opts.send = v,
                .pubkey => opts.pubkey = v,
                .role => try roles.append(gpa, v),
                .event => opts.event = v,
                .code => opts.code = v,
                .reason => opts.reason = v,
                .events => unreachable,
            }
        } else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
            try err.print("deed group: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else if (address == null) {
            address = a;
        } else if (extra == null and c == .remove_user) {
            extra = a;
        } else {
            try err.print("deed group {s}: unexpected argument '{s}'\n", .{ args[0], a });
            return cli.exit_usage;
        }
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw_address = address orelse {
        try err.print("deed group {s}: name the group, as relay'group-id\n", .{args[0]});
        return cli.exit_usage;
    };
    const group = parseAddress(arena, raw_address) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.NoRelayHint => {
            try err.writeAll("deed group: that naddr names no relay; write the group as relay'group-id\n");
            return cli.exit_usage;
        },
        else => {
            try err.print("deed group: '{s}' is not a group: write relay'group-id\n", .{raw_address});
            return cli.exit_usage;
        },
    };

    switch (c) {
        .info, .members, .admins => {
            const auth_opts = auth.resolve(gpa, auth_flags, "group", err) catch |e| switch (e) {
                error.Usage => return cli.exit_usage,
                error.BadKey => return cli.exit_fail,
                else => |other| return other,
            };
            return readState(gpa, io, c, group, opts, auth_opts, out, err);
        },
        .chat => if (opts.send == null) {
            const auth_opts = auth.resolve(gpa, auth_flags, "group", err) catch |e| switch (e) {
                error.Usage => return cli.exit_usage,
                error.BadKey => return cli.exit_fail,
                else => |other| return other,
            };
            return readChat(gpa, io, group, opts, auth_opts, out, err);
        },
        else => {},
    }

    // Everything left signs something.
    if (extra != null) opts.pubkey = extra;
    const kind_and_tags = (try buildWrite(arena, io, c, group, opts, roles.items, gpa, err)) orelse return cli.exit_usage;

    const sk = (post.readSecret(gpa, "group", auth_flags.sec, err) catch |e| switch (e) {
        error.BadKey => return cli.exit_fail,
        else => return e,
    }) orelse return cli.exit_usage;
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const keypair = try signer.keyPairFromSecretKey(sk);
    const auth_opts: ?auth.Options = if (auth_flags.auth or auth_flags.force_pre_auth)
        .{ .keypair = keypair, .force_pre_auth = auth_flags.force_pre_auth }
    else
        null;

    const now = Io.Timestamp.now(io, .real).toSeconds();
    const ev = try event.create(arena, signer, keypair, now, kind_and_tags.kind, kind_and_tags.tags, kind_and_tags.content, null);
    const accepted = try publishOne(gpa, io, group.relay, ev, auth_opts, opts.timeout_ms, err);
    if (!accepted) return cli.exit_fail;
    const wire = try event.toJson(arena, ev);
    try out.print("{s}\n", .{wire});
    return cli.exit_ok;
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

pub const Group = struct {
    /// A ws:// or wss:// URL.
    relay: []const u8,
    id: []const u8,
};

pub const AddressError = error{ BadAddress, NoRelayHint, OutOfMemory };

/// `relay'id`, `host/id`, or an naddr. Everything returned lives in `arena`.
pub fn parseAddress(arena: std.mem.Allocator, raw: []const u8) AddressError!Group {
    const s = std.mem.trim(u8, stripNostrUri(raw), " \t\r\n");
    if (keyinput.hasPrefix(s, "naddr1")) {
        var ptr = nip19.decodeNaddr(arena, s) catch return error.BadAddress;
        defer ptr.deinit(arena);
        if (ptr.kind != 39000) return error.BadAddress;
        if (ptr.relays.len == 0) return error.NoRelayHint;
        const id = try arena.dupe(u8, ptr.identifier);
        if (!validId(id)) return error.BadAddress;
        return .{ .relay = try relayUrl(arena, ptr.relays[0]), .id = id };
    }

    var relay_part: []const u8 = undefined;
    var id: []const u8 = undefined;
    if (std.mem.indexOfScalar(u8, s, '\'')) |q| {
        relay_part = s[0..q];
        id = s[q + 1 ..];
    } else {
        // host/id, with or without a scheme.
        const after_scheme = if (std.mem.indexOf(u8, s, "://")) |p| p + 3 else 0;
        const slash = std.mem.indexOfScalarPos(u8, s, after_scheme, '/') orelse return error.BadAddress;
        relay_part = s[0..slash];
        id = std.mem.trimEnd(u8, s[slash + 1 ..], "/");
    }
    if (!validId(id)) return error.BadAddress;
    return .{ .relay = try relayUrl(arena, relay_part), .id = try arena.dupe(u8, id) };
}

fn stripNostrUri(s: []const u8) []const u8 {
    return keyinput.stripUri(s);
}

/// Group ids are letters, digits, `-` and `_` (NIP-29 asks for lowercase).
fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > 128) return false;
    for (id) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) return false;
    }
    return true;
}

fn relayUrl(arena: std.mem.Allocator, part: []const u8) AddressError![]const u8 {
    const t = std.mem.trimEnd(u8, part, "/");
    if (std.mem.startsWith(u8, t, "wss://") or std.mem.startsWith(u8, t, "ws://")) {
        if (std.mem.indexOfScalar(u8, t, '/')) |first| if (t.len <= first + 3) return error.BadAddress;
        return try arena.dupe(u8, t);
    }
    if (t.len == 0 or std.mem.indexOf(u8, t, "://") != null) return error.BadAddress;
    // The host without its port, to tell a local address from a public one.
    var host = t;
    if (std.mem.startsWith(u8, host, "[")) {
        if (std.mem.indexOfScalar(u8, host, ']')) |e| host = host[0 .. e + 1];
    } else if (std.mem.lastIndexOfScalar(u8, host, ':')) |c| {
        host = host[0..c];
    }
    const scheme = if (http.isLoopbackHost(host)) "ws://" else "wss://";
    return std.mem.concat(arena, u8, &.{ scheme, t });
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

const kind_metadata: u16 = 39000;
const kind_admins: u16 = 39001;
const kind_members: u16 = 39002;
const kind_chat: u16 = 9;

/// Asks one relay one question and returns the verified events it sent, which
/// the caller owns. Null after saying why the relay could not be asked.
fn fetch(
    gpa: std.mem.Allocator,
    io: Io,
    url: []const u8,
    f: filter.Filter,
    timeout_ms: i64,
    auth_opts: ?auth.Options,
    err: *Io.Writer,
) !?std.ArrayList(event.Parsed) {
    var buf: Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    const o = try relayset.query(gpa, io, &.{url}, &.{f}, &buf.writer, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
        .auth = auth_opts,
    });
    if (o.dialled == 0) {
        try err.print("deed group: could not reach {s}\n", .{url});
        return null;
    }
    var list: std.ArrayList(event.Parsed) = .empty;
    errdefer freeAll(gpa, &list);
    var lines = std.mem.splitScalar(u8, buf.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const p = event.fromJson(gpa, line) catch continue;
        try list.append(gpa, p);
    }
    return list;
}

/// Where the relay says its own key is: `self` in its NIP-11 document, or
/// `pubkey` when `self` is missing. Null when it states neither, or the
/// document cannot be had or read. Only a cancel is an error.
fn relayKey(gpa: std.mem.Allocator, io: Io, relay: []const u8, timeout_ms: i64) error{ Canceled, OutOfMemory }!?[32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const url = if (info_url_override) |u| u else nip11.httpUrl(arena, relay) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    var res = http.fetch(gpa, io, url, .{
        .headers = &.{.{ .name = nip11.accept_header_name, .value = nip11.accept_header_value }},
        .timeout_ms = @intCast(@max(timeout_ms, 1)),
        .max_bytes = 1024 * 1024,
        .allow_http = std.mem.startsWith(u8, relay, "ws://"),
    }) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer res.deinit(gpa);
    if (!res.ok()) return null;
    var info = nip11.parse(gpa, res.body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidJson => return null,
    };
    defer info.deinit();
    const stated = info.self orelse info.pubkey orelse return null;
    var key: [32]u8 = undefined;
    if (stated.len != 64) return null;
    _ = std.fmt.hexToBytes(&key, stated) catch return null;
    return key;
}

/// Test seam: where the NIP-11 document is fetched from instead of beside
/// the relay's own address.
var info_url_override: ?[]const u8 = null;

/// Drops, and frees, the events not signed by `key`. Returns how many.
fn keepSignedBy(list: *std.ArrayList(event.Parsed), key: [32]u8) usize {
    var dropped: usize = 0;
    var w: usize = 0;
    for (list.items) |*p| {
        if (std.mem.eql(u8, &p.value.pubkey, &key)) {
            list.items[w] = p.*;
            w += 1;
        } else {
            p.deinit();
            dropped += 1;
        }
    }
    list.shrinkRetainingCapacity(w);
    return dropped;
}

fn freeAll(gpa: std.mem.Allocator, list: *std.ArrayList(event.Parsed)) void {
    for (list.items) |*p| p.deinit();
    list.deinit(gpa);
}

fn newest(list: []const event.Parsed, kind: u16) ?event.Event {
    var best: ?event.Event = null;
    for (list) |p| {
        if (p.value.kind != kind) continue;
        if (best == null or post.newerThan(p.value, best.?)) best = p.value;
    }
    return best;
}

fn tagValue(ev: event.Event, name: []const u8) ?[]const u8 {
    for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], name)) return t[1];
    }
    return null;
}

fn hasFlagTag(ev: event.Event, name: []const u8) bool {
    for (ev.tags) |t| {
        if (t.len >= 1 and std.mem.eql(u8, t[0], name)) return true;
    }
    return false;
}

fn readState(
    gpa: std.mem.Allocator,
    io: Io,
    cmd: Cmd,
    group: Group,
    opts: Options,
    auth_opts: ?auth.Options,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    const d_values = [_][]const u8{group.id};
    const tag_filters = [_]filter.TagFilter{.{ .letter = 'd', .values = &d_values }};
    const kinds = switch (cmd) {
        .info => &[_]u16{ kind_metadata, kind_admins, kind_members },
        .members => &[_]u16{kind_members},
        else => &[_]u16{kind_admins},
    };
    var list = (try fetch(gpa, io, group.relay, .{ .kinds = kinds, .tags = &tag_filters }, opts.timeout_ms, auth_opts, err)) orelse return cli.exit_fail;
    defer freeAll(gpa, &list);

    var verified = false;
    if (try relayKey(gpa, io, group.relay, opts.timeout_ms)) |key| {
        verified = true;
        const dropped = keepSignedBy(&list, key);
        if (dropped > 0) try err.print("deed group: {s}: ignored {d} event(s) not signed by the relay's own key\n", .{ group.relay, dropped });
    } else {
        try err.print("deed group: {s} does not state its own key in its NIP-11 document (or it could not be read); the group state is unverified\n", .{group.relay});
    }

    const meta = newest(list.items, kind_metadata);
    const admins = newest(list.items, kind_admins);
    const members = newest(list.items, kind_members);

    if (cmd == .info and meta == null) {
        try err.print("deed group: {s} sent no metadata for '{s}'; the group may not exist, or may be hidden\n", .{ group.relay, group.id });
        return cli.exit_fail;
    }
    if (cmd == .members and members == null) {
        try err.print("deed group: {s} sent no member list for '{s}'\n", .{ group.relay, group.id });
        return cli.exit_fail;
    }
    if (cmd == .admins and admins == null) {
        try err.print("deed group: {s} sent no admin list for '{s}'\n", .{ group.relay, group.id });
        return cli.exit_fail;
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    if (opts.events) {
        const shown = [_]?event.Event{ meta, admins, members };
        for (shown) |maybe| {
            const ev = maybe orelse continue;
            if (cmd == .members and ev.kind != kind_members) continue;
            if (cmd == .admins and ev.kind != kind_admins) continue;
            try out.print("{s}\n", .{try event.toJson(arena, ev)});
        }
        return cli.exit_ok;
    }

    switch (cmd) {
        .members => {
            for (members.?.tags) |t| {
                if (t.len >= 2 and std.mem.eql(u8, t[0], "p")) {
                    try relayset.writeEscaped(out, t[1]);
                    try out.writeByte('\n');
                }
            }
        },
        .admins => {
            for (admins.?.tags) |t| {
                if (t.len < 2 or !std.mem.eql(u8, t[0], "p")) continue;
                try relayset.writeEscaped(out, t[1]);
                for (t[2..]) |role| {
                    try out.writeByte(' ');
                    try relayset.writeEscaped(out, role);
                }
                try out.writeByte('\n');
            }
        },
        else => try writeInfo(arena, out, group, meta.?, admins, members, verified),
    }
    return cli.exit_ok;
}

const Admin = struct { pubkey: []const u8, roles: []const []const u8 };

fn writeInfo(
    arena: std.mem.Allocator,
    out: *Io.Writer,
    group: Group,
    meta: event.Event,
    admins: ?event.Event,
    members: ?event.Event,
    verified: bool,
) !void {
    var admin_list: std.ArrayList(Admin) = .empty;
    if (admins) |ev| for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], "p")) try admin_list.append(arena, .{ .pubkey = t[1], .roles = t[2..] });
    };
    var member_list: std.ArrayList([]const u8) = .empty;
    if (members) |ev| for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], "p")) try member_list.append(arena, t[1]);
    };
    const info = .{
        .relay = group.relay,
        .id = group.id,
        .name = tagValue(meta, "name"),
        .about = tagValue(meta, "about"),
        .picture = tagValue(meta, "picture"),
        .private = hasFlagTag(meta, "private"),
        .closed = hasFlagTag(meta, "closed"),
        .restricted = hasFlagTag(meta, "restricted"),
        .hidden = hasFlagTag(meta, "hidden"),
        .admins = admin_list.items,
        .members = member_list.items,
        .verified = verified,
    };
    const text = try std.json.Stringify.valueAlloc(arena, info, .{});
    try out.print("{s}\n", .{text});
}

fn readChat(
    gpa: std.mem.Allocator,
    io: Io,
    group: Group,
    opts: Options,
    auth_opts: ?auth.Options,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    const h_values = [_][]const u8{group.id};
    const tag_filters = [_]filter.TagFilter{.{ .letter = 'h', .values = &h_values }};
    var list = (try fetch(gpa, io, group.relay, .{
        .kinds = &.{kind_chat},
        .tags = &tag_filters,
        .limit = opts.limit,
    }, opts.timeout_ms, auth_opts, err)) orelse return cli.exit_fail;
    defer freeAll(gpa, &list);

    std.mem.sort(event.Parsed, list.items, {}, olderFirst);
    const skip = list.items.len -| opts.limit;
    for (list.items[skip..]) |p| {
        const json = try event.toJson(gpa, p.value);
        defer gpa.free(json);
        try out.print("{s}\n", .{json});
    }
    return cli.exit_ok;
}

fn olderFirst(_: void, a: event.Parsed, b: event.Parsed) bool {
    if (a.value.created_at != b.value.created_at) return a.value.created_at < b.value.created_at;
    return std.mem.order(u8, &a.value.id, &b.value.id) == .lt;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

const Draft = struct {
    kind: u16,
    tags: []const event.Tag,
    content: []const u8,
};

fn mkTag(a: std.mem.Allocator, parts: []const []const u8) !event.Tag {
    return a.dupe([]const u8, parts);
}

/// The event a writing subcommand signs, or null after saying what is
/// missing.
fn buildWrite(
    arena: std.mem.Allocator,
    io: Io,
    cmd: Cmd,
    group: Group,
    opts: Options,
    roles: []const []const u8,
    gpa: std.mem.Allocator,
    err: *Io.Writer,
) !?Draft {
    var tags: std.ArrayList(event.Tag) = .empty;
    try tags.append(arena, try mkTag(arena, &.{ "h", group.id }));
    var content: []const u8 = opts.reason orelse "";
    var kind: u16 = 0;
    switch (cmd) {
        .chat => {
            kind = kind_chat;
            content = opts.send.?;
            if (std.mem.trim(u8, content, " \t\r\n").len == 0) {
                try err.writeAll("deed group chat: nothing to send\n");
                return null;
            }
        },
        .join => {
            kind = 9021;
            if (opts.code) |code| try tags.append(arena, try mkTag(arena, &.{ "code", code }));
        },
        .leave => kind = 9022,
        .put_user => {
            kind = 9000;
            const pk = (try pubkeyHex(arena, gpa, opts.pubkey, "put-user", err)) orelse return null;
            var parts: std.ArrayList([]const u8) = .empty;
            try parts.appendSlice(arena, &.{ "p", pk });
            try parts.appendSlice(arena, roles);
            try tags.append(arena, parts.items);
        },
        .remove_user => {
            kind = 9001;
            const pk = (try pubkeyHex(arena, gpa, opts.pubkey, "remove-user", err)) orelse return null;
            try tags.append(arena, try mkTag(arena, &.{ "p", pk }));
        },
        .delete_event => {
            kind = 9005;
            const raw = opts.event orelse {
                try err.writeAll("deed group delete-event: name the event with --event\n");
                return null;
            };
            const id = @import("filterflags.zig").idOrKey(gpa, raw) orelse {
                try err.print("deed group delete-event: '{s}' is not an event id\n", .{raw});
                return null;
            };
            try tags.append(arena, try mkTag(arena, &.{ "e", try hex.encode(arena, &id) }));
        },
        .create_group => kind = 9007,
        .delete_group => kind = 9008,
        .create_invite => {
            kind = 9009;
            const code = opts.code orelse blk: {
                // A code nobody can guess is the point of an invite.
                var raw: [12]u8 = undefined;
                io.random(&raw);
                break :blk try hex.encode(arena, &raw);
            };
            try tags.append(arena, try mkTag(arena, &.{ "code", code }));
        },
        .info, .members, .admins => unreachable,
    }
    return .{ .kind = kind, .tags = tags.items, .content = content };
}

fn pubkeyHex(arena: std.mem.Allocator, gpa: std.mem.Allocator, raw: ?[]const u8, verb: []const u8, err: *Io.Writer) !?[]const u8 {
    const s = raw orelse {
        try err.print("deed group {s}: name the user with --pubkey\n", .{verb});
        return null;
    };
    const pk = keyinput.publicKey(gpa, s) catch {
        try err.print("deed group {s}: '{s}' is not a public key (want npub1... or 64 hex characters)\n", .{ verb, s });
        return null;
    };
    return try hex.encode(arena, &pk);
}

/// Offers `ev` to the one relay at `url` and says whether it accepted. When
/// the relay refuses with `auth-required:` and `auth_opts` is set, its NIP-42
/// challenge is answered and the event is offered once more.
fn publishOne(
    gpa: std.mem.Allocator,
    io: Io,
    url: []const u8,
    ev: event.Event,
    auth_opts: ?auth.Options,
    timeout_ms: i64,
    err: *Io.Writer,
) !bool {
    const id = try hex.encode(gpa, &ev.id);
    defer gpa.free(id);

    var dialled: [1]dial.Outcome = undefined;
    dial.all(gpa, io, &.{url}, @min(dial.default_timeout_ms, timeout_ms), &dialled);
    const conn = switch (dialled[0]) {
        .connected => |r| r,
        .failed => |e| {
            try err.print("deed group: {s}: {s}: could not connect: {s}\n", .{ id, url, @errorName(e) });
            return false;
        },
        .timed_out => {
            try err.print("deed group: {s}: {s}: did not answer the connection in time\n", .{ id, url });
            return false;
        },
    };
    defer {
        conn.shutdown(io);
        conn.deinit();
    }

    const deadline = Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake });
    const timeout: Io.Timeout = .{ .deadline = deadline };

    var challenge: ?[]u8 = null;
    defer if (challenge) |c| gpa.free(c);
    var auth_id: ?[32]u8 = null;
    var authed = false;
    var wants_resend = false;
    var resent = false;

    if (auth_opts) |ao| if (ao.force_pre_auth) {
        // Wait for the relay's challenge before offering anything.
        const wait = Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(@min(timeout_ms, 3_000)), .clock = .awake });
        while (true) {
            var msg = (conn.receiveTimeout(.{ .deadline = wait }) catch |e| {
                if (isCancel(e)) return error.Canceled;
                break;
            }) orelse break;
            defer msg.deinit();
            switch (msg.value) {
                .auth => |a| {
                    try setChallenge(gpa, &challenge, a.challenge);
                    auth_id = try answerChallenge(gpa, io, conn, ao, url, a.challenge);
                    authed = false;
                    // Its verdict on us comes next.
                    while (true) {
                        var reply = (conn.receiveTimeout(.{ .deadline = wait }) catch |e| {
                            if (isCancel(e)) return error.Canceled;
                            break;
                        }) orelse break;
                        defer reply.deinit();
                        if (reply.value == .ok and std.mem.eql(u8, &reply.value.ok.event_id, &auth_id.?)) {
                            authed = reply.value.ok.accepted;
                            break;
                        }
                    }
                    break;
                },
                else => {},
            }
        }
    };

    conn.publishTimeout(ev, timeout) catch |e| {
        try err.print("deed group: {s}: {s}: could not send: {s}\n", .{ id, url, @errorName(e) });
        return false;
    };

    while (true) {
        var msg = (conn.receiveTimeout(timeout) catch |e| {
            if (e == error.Timeout) {
                try err.print("deed group: {s}: {s}: no answer in time\n", .{ id, url });
            } else {
                try err.print("deed group: {s}: {s}: {s}\n", .{ id, url, @errorName(e) });
            }
            return false;
        }) orelse {
            try err.print("deed group: {s}: {s}: the relay closed the connection\n", .{ id, url });
            return false;
        };
        defer msg.deinit();
        switch (msg.value) {
            .auth => |a| if (auth_opts) |ao| {
                try setChallenge(gpa, &challenge, a.challenge);
                auth_id = try answerChallenge(gpa, io, conn, ao, url, a.challenge);
                authed = false;
            },
            .notice => |n| {
                try err.print("deed group: {s}: notice: ", .{url});
                try relayset.writeEscaped(err, n.message);
                try err.writeByte('\n');
            },
            .ok => |o| {
                if (std.mem.eql(u8, &o.event_id, &ev.id)) {
                    if (o.accepted) {
                        try err.print("deed group: {s}: {s}: accepted\n", .{ id, url });
                        return true;
                    }
                    if (auth_opts != null and !resent and auth.isAuthRequired(o.message)) {
                        if (authed) {
                            resent = true;
                            try resend(conn, ev, timeout);
                        } else {
                            wants_resend = true;
                        }
                        continue;
                    }
                    try err.print("deed group: {s}: {s}: refused: ", .{ id, url });
                    try relayset.writeEscaped(err, o.message);
                    try err.writeByte('\n');
                    return false;
                }
                if (auth_id) |aid| if (std.mem.eql(u8, &o.event_id, &aid)) {
                    if (!o.accepted) {
                        try err.print("deed group: {s}: authentication refused: ", .{url});
                        try relayset.writeEscaped(err, o.message);
                        try err.writeByte('\n');
                        return false;
                    }
                    authed = true;
                    if (wants_resend and !resent) {
                        resent = true;
                        wants_resend = false;
                        try resend(conn, ev, timeout);
                    }
                };
            },
            else => {},
        }
    }
}

/// A cancel is never a reason to stop waiting quietly: it goes up.
fn isCancel(e: anyerror) bool {
    return e == error.Canceled;
}

fn resend(conn: *nostr.relay.Relay, ev: event.Event, timeout: Io.Timeout) !void {
    try conn.publishTimeout(ev, timeout);
}

fn setChallenge(gpa: std.mem.Allocator, slot: *?[]u8, text: []const u8) !void {
    if (slot.*) |old| gpa.free(old);
    slot.* = try gpa.dupe(u8, text);
}

/// Signs and sends the answer to `challenge`, returning the id its OK names.
fn answerChallenge(gpa: std.mem.Allocator, io: Io, conn: *nostr.relay.Relay, ao: auth.Options, url: []const u8, challenge: []const u8) !?[32]u8 {
    var a = try auth.answer(gpa, io, ao, url, challenge);
    defer a.deinit();
    try conn.authenticate(a.event);
    return a.id;
}

// ---- tests ---------------------------------------------------------------

const testrelay = @import("testrelay.zig");

const test_secret = [_]u8{0x31} ** 32;
const relay_secret = [_]u8{0x32} ** 32;

fn signedBy(arena: std.mem.Allocator, io: Io, secret: [32]u8, at: i64, kind: u16, tags: []const event.Tag, content: []const u8) ![]const u8 {
    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(secret);
    const ev = try event.create(arena, signer, kp, at, kind, tags, content, null);
    return event.toJson(arena, ev);
}

fn mk(arena: std.mem.Allocator, parts: []const []const u8) !event.Tag {
    return mkTag(arena, parts);
}

const test_pk_a = "1111111111111111111111111111111111111111111111111111111111111111";
const test_pk_b = "2222222222222222222222222222222222222222222222222222222222222222";

/// A relay that serves `serve` to every REQ, then EOSE, and answers EVENT
/// frames. With `need_auth` it refuses the first EVENT with `auth-required:`
/// and a challenge until it is told who is asking.
const Script = struct {
    serve: []const []const u8 = &.{},
    need_auth: bool = false,
    authed: bool = false,
    want_url: []const u8 = "",
    refuse: bool = false,
    events: usize = 0,
    auths: usize = 0,
    last_kind: u32 = 0,
    last_tags: [8][2][64]u8 = undefined,
    h_seen: bool = false,
    last_content: [128]u8 = undefined,
    last_content_len: usize = 0,

    const chal = "chal-group";

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        const self: *Script = @ptrCast(@alignCast(ctx.?));
        const a = std.heap.page_allocator;
        var parsed = try std.json.parseFromSlice(std.json.Value, a, frame, .{});
        defer parsed.deinit();
        const items = parsed.value.array.items;
        const verb = items[0].string;
        if (std.mem.eql(u8, verb, "REQ")) {
            const sub = items[1].string;
            for (self.serve) |ev| {
                const m = try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ sub, ev });
                defer a.free(m);
                try testrelay.sendText(w, m);
            }
            const eose = try std.fmt.allocPrint(a, "[\"EOSE\",\"{s}\"]", .{sub});
            defer a.free(eose);
            try testrelay.sendText(w, eose);
        } else if (std.mem.eql(u8, verb, "EVENT")) {
            const obj = items[1].object;
            const id = obj.get("id").?.string;
            self.events += 1;
            self.last_kind = @intCast(obj.get("kind").?.integer);
            for (obj.get("tags").?.array.items) |tg| {
                const pair = tg.array.items;
                if (std.mem.eql(u8, pair[0].string, "h") and pair.len >= 2) self.h_seen = true;
            }
            const content = obj.get("content").?.string;
            self.last_content_len = @min(content.len, self.last_content.len);
            @memcpy(self.last_content[0..self.last_content_len], content[0..self.last_content_len]);
            if (self.need_auth and !self.authed) {
                try testrelay.sendText(w, "[\"AUTH\",\"" ++ chal ++ "\"]");
                const no = try std.fmt.allocPrint(a, "[\"OK\",\"{s}\",false,\"auth-required: members only\"]", .{id});
                defer a.free(no);
                try testrelay.sendText(w, no);
                return;
            }
            const ok = try std.fmt.allocPrint(a, "[\"OK\",\"{s}\",{s},\"{s}\"]", .{
                id,
                if (self.refuse) "false" else "true",
                if (self.refuse) "blocked: not a member" else "",
            });
            defer a.free(ok);
            try testrelay.sendText(w, ok);
        } else if (std.mem.eql(u8, verb, "AUTH")) {
            self.auths += 1;
            const obj = items[1].object;
            const id = obj.get("id").?.string;
            var relay_ok = false;
            var chal_ok = false;
            for (obj.get("tags").?.array.items) |tg| {
                const pair = tg.array.items;
                if (std.mem.eql(u8, pair[0].string, "relay")) relay_ok = std.mem.eql(u8, pair[1].string, self.want_url);
                if (std.mem.eql(u8, pair[0].string, "challenge")) chal_ok = std.mem.eql(u8, pair[1].string, chal);
            }
            const good = relay_ok and chal_ok;
            if (good) self.authed = true;
            const ok = try std.fmt.allocPrint(a, "[\"OK\",\"{s}\",{s},\"\"]", .{ id, if (good) "true" else "false" });
            defer a.free(ok);
            try testrelay.sendText(w, ok);
        }
    }
};

const Harness = struct {
    da: testrelay.DialAllocator = .init,
    arena_state: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(std.heap.page_allocator),
    relay: testrelay.Relay = undefined,
    url_buf: [40]u8 = undefined,
    url: []const u8 = "",
    address: []const u8 = "",
    /// The NIP-11 document the relay serves. Null: one that names the relay's
    /// own key in `self`.
    doc: ?[]const u8 = null,
    info: http.TestServer = undefined,
    info_url_buf: [64]u8 = undefined,

    fn start(self: *Harness, io: Io, script: *Script) !void {
        return self.startFor(io, script, 1);
    }

    /// `connections` runs against the relay, one after another.
    fn startFor(self: *Harness, io: Io, script: *Script, connections: usize) !void {
        try self.relay.startFor(io, .custom, connections);
        self.relay.custom = Script.handle;
        self.relay.custom_ctx = script;
        self.url = try testrelay.url(&self.url_buf, self.relay.port());
        script.want_url = self.url;
        self.address = try std.fmt.allocPrint(self.arena_state.allocator(), "{s}'pizza", .{self.url});

        const body = self.doc orelse blk: {
            var signer = try nostr.keys.Signer.initRandomized(io);
            defer signer.deinit();
            const kp = try signer.keyPairFromSecretKey(relay_secret);
            const pk = try hex.encode(self.arena_state.allocator(), &kp.public_key);
            break :blk try std.fmt.allocPrint(self.arena_state.allocator(), "{{\"name\":\"t\",\"self\":\"{s}\"}}", .{pk});
        };
        const routes = try self.arena_state.allocator().dupe(http.TestServer.Route, &.{.{ .path = "/", .body = body }});
        try self.info.start(io, routes, 8);
        info_url_override = try self.info.url(&self.info_url_buf, "/");
    }

    fn finish(self: *Harness, io: Io) void {
        info_url_override = null;
        self.info.stop(io);
        self.relay.stop(io);
        self.arena_state.deinit();
        if (self.da.deinit() == .leak) @panic("the group verb leaked");
    }
};

fn serveGroupState(arena: std.mem.Allocator, io: Io) ![]const []const u8 {
    const events = try arena.alloc([]const u8, 4);
    events[0] = try signedBy(arena, io, relay_secret, 1_700_000_100, kind_metadata, &.{
        try mk(arena, &.{ "d", "pizza" }),
        try mk(arena, &.{ "name", "Pizza Lovers" }),
        try mk(arena, &.{ "about", "toppings" }),
        try mk(arena, &.{"closed"}),
    }, "");
    // An older metadata event must lose to the one above.
    events[1] = try signedBy(arena, io, relay_secret, 1_700_000_000, kind_metadata, &.{
        try mk(arena, &.{ "d", "pizza" }),
        try mk(arena, &.{ "name", "Old Name" }),
    }, "");
    events[2] = try signedBy(arena, io, relay_secret, 1_700_000_100, kind_admins, &.{
        try mk(arena, &.{ "d", "pizza" }),
        try mk(arena, &.{ "p", test_pk_a, "ceo", "moderator" }),
    }, "");
    events[3] = try signedBy(arena, io, relay_secret, 1_700_000_100, kind_members, &.{
        try mk(arena, &.{ "d", "pizza" }),
        try mk(arena, &.{ "p", test_pk_a }),
        try mk(arena, &.{ "p", test_pk_b }),
    }, "");
    return events;
}

test "addresses: relay'id, host/id, naddr, and what is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var g = try parseAddress(a, "groups.example.com'pizza");
    try std.testing.expectEqualStrings("wss://groups.example.com", g.relay);
    try std.testing.expectEqualStrings("pizza", g.id);
    g = try parseAddress(a, "wss://groups.example.com'_");
    try std.testing.expectEqualStrings("wss://groups.example.com", g.relay);
    try std.testing.expectEqualStrings("_", g.id);
    g = try parseAddress(a, "127.0.0.1:7777'pizza");
    try std.testing.expectEqualStrings("ws://127.0.0.1:7777", g.relay);
    g = try parseAddress(a, "wisp.chat/rootstock");
    try std.testing.expectEqualStrings("wss://wisp.chat", g.relay);
    try std.testing.expectEqualStrings("rootstock", g.id);

    const pk = [_]u8{7} ** 32;
    const naddr = try nip19.encodeNaddr(a, "pizza", pk, 39000, &.{"wss://r.example"});
    g = try parseAddress(a, naddr);
    try std.testing.expectEqualStrings("wss://r.example", g.relay);
    try std.testing.expectEqualStrings("pizza", g.id);
    const bare = try nip19.encodeNaddr(a, "pizza", pk, 39000, &.{});
    try std.testing.expectError(error.NoRelayHint, parseAddress(a, bare));
    const wrong_kind = try nip19.encodeNaddr(a, "pizza", pk, 30023, &.{"wss://r.example"});
    try std.testing.expectError(error.BadAddress, parseAddress(a, wrong_kind));

    try std.testing.expectError(error.BadAddress, parseAddress(a, "groups.example.com"));
    try std.testing.expectError(error.BadAddress, parseAddress(a, "groups.example.com'"));
    try std.testing.expectError(error.BadAddress, parseAddress(a, "'pizza"));
    try std.testing.expectError(error.BadAddress, parseAddress(a, "groups.example.com'pi zza"));
}

test "info, members and admins read the relay's signed group state" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{};
    script.serve = try serveGroupState(h.arena_state.allocator(), io);
    try h.startFor(io, &script, 4);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();

    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "info", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, out.written(), .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try std.testing.expectEqualStrings("Pizza Lovers", o.get("name").?.string);
    try std.testing.expectEqualStrings("toppings", o.get("about").?.string);
    try std.testing.expect(o.get("closed").?.bool);
    try std.testing.expect(!o.get("private").?.bool);
    try std.testing.expectEqual(@as(usize, 1), o.get("admins").?.array.items.len);
    try std.testing.expectEqualStrings("ceo", o.get("admins").?.array.items[0].object.get("roles").?.array.items[0].string);
    try std.testing.expectEqual(@as(usize, 2), o.get("members").?.array.items.len);

    out.clearRetainingCapacity();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "members", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expectEqualStrings(test_pk_a ++ "\n" ++ test_pk_b ++ "\n", out.written());

    out.clearRetainingCapacity();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "admins", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expectEqualStrings(test_pk_a ++ " ceo moderator\n", out.written());

    out.clearRetainingCapacity();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "admins", h.address, "--events", "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"kind\":39001") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out.written(), "\n"));
}

test "info on a group the relay knows nothing about fails and says so" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{};
    try h.start(io, &script);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_fail, try run(gpa, io, &.{ "info", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expectEqualStrings("", out.written());
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "no metadata") != null);
}

test "chat prints verified messages of this group, oldest first, and drops the rest" {
    const io = std.testing.io;
    var h: Harness = .{};
    const arena = h.arena_state.allocator();
    var script: Script = .{};
    const served = try arena.alloc([]const u8, 5);
    served[0] = try signedBy(arena, io, test_secret, 1_700_000_300, 9, &.{try mk(arena, &.{ "h", "pizza" })}, "third");
    served[1] = try signedBy(arena, io, test_secret, 1_700_000_100, 9, &.{try mk(arena, &.{ "h", "pizza" })}, "first");
    served[2] = try signedBy(arena, io, test_secret, 1_700_000_200, 9, &.{try mk(arena, &.{ "h", "pizza" })}, "second");
    // Another group's message, and a note: neither answers the question.
    served[3] = try signedBy(arena, io, test_secret, 1_700_000_150, 9, &.{try mk(arena, &.{ "h", "sushi" })}, "elsewhere");
    served[4] = try signedBy(arena, io, test_secret, 1_700_000_160, 1, &.{try mk(arena, &.{ "h", "pizza" })}, "a note");
    script.serve = served;
    try h.startFor(io, &script, 2);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "chat", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    const text = out.written();
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, text, "\n"));
    const first = std.mem.indexOf(u8, text, "\"first\"").?;
    const second = std.mem.indexOf(u8, text, "\"second\"").?;
    const third = std.mem.indexOf(u8, text, "\"third\"").?;
    try std.testing.expect(first < second and second < third);
    try std.testing.expect(std.mem.indexOf(u8, text, "elsewhere") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "a note") == null);

    // --limit keeps the newest.
    out.clearRetainingCapacity();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "chat", h.address, "--limit", "2", "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"first\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"third\"") != null);
}

test "chat --send publishes a kind 9 with the group's h tag, and prints it" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{};
    try h.start(io, &script);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "chat", h.address, "--send", "hello pizza", "--sec", "3131313131313131313131313131313131313131313131313131313131313131", "--timeout", "3000" }, &out.writer, &err.writer);
    try std.testing.expectEqual(cli.exit_ok, code);
    try std.testing.expectEqual(@as(u32, 9), script.last_kind);
    try std.testing.expect(script.h_seen);
    try std.testing.expectEqualStrings("hello pizza", script.last_content[0..script.last_content_len]);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"hello pizza\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "accepted") != null);
}

test "a refused event is reported and not printed" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{ .refuse = true };
    try h.start(io, &script);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "join", h.address, "--sec", "3131313131313131313131313131313131313131313131313131313131313131", "--timeout", "3000" }, &out.writer, &err.writer);
    try std.testing.expectEqual(cli.exit_fail, code);
    try std.testing.expectEqual(@as(u32, 9021), script.last_kind);
    try std.testing.expectEqualStrings("", out.written());
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "not a member") != null);
}

test "join and leave send kinds 9021 and 9022, and moderation sends 9000 to 9009" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{};
    try h.startFor(io, &script, 8);
    defer h.finish(io);
    const gpa = h.da.allocator();

    const sec = "3131313131313131313131313131313131313131313131313131313131313131";
    const Case = struct { args: []const []const u8, kind: u32 };
    const cases = [_]Case{
        .{ .args = &.{ "join", "--reason", "hi" }, .kind = 9021 },
        .{ .args = &.{"leave"}, .kind = 9022 },
        .{ .args = &.{ "put-user", "--pubkey", test_pk_a, "--role", "moderator" }, .kind = 9000 },
        .{ .args = &.{ "remove-user", test_pk_b }, .kind = 9001 },
        .{ .args = &.{ "delete-event", "--event", test_pk_b }, .kind = 9005 },
        .{ .args = &.{"create-group"}, .kind = 9007 },
        .{ .args = &.{"delete-group"}, .kind = 9008 },
        .{ .args = &.{"create-invite"}, .kind = 9009 },
    };
    for (cases) |c| {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, c.args[0]);
        try argv.append(gpa, h.address);
        try argv.appendSlice(gpa, c.args[1..]);
        try argv.appendSlice(gpa, &.{ "--sec", sec, "--timeout", "3000" });

        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var err: Io.Writer.Allocating = .init(gpa);
        defer err.deinit();
        script.h_seen = false;
        try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, argv.items, &out.writer, &err.writer));
        try std.testing.expectEqual(c.kind, script.last_kind);
        try std.testing.expect(script.h_seen);
        try std.testing.expect(out.written().len > 0);
    }
}

test "with --auth a relay that asks who is writing is answered and the event offered again" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{ .need_auth = true };
    try h.start(io, &script);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "chat", h.address, "--send", "let me in", "--auth", "--sec", "3131313131313131313131313131313131313131313131313131313131313131", "--timeout", "5000" }, &out.writer, &err.writer);
    try std.testing.expectEqual(cli.exit_ok, code);
    try std.testing.expectEqual(@as(usize, 1), script.auths);
    try std.testing.expectEqual(@as(usize, 2), script.events);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "let me in") != null);
}

test "without --auth the auth-required refusal is the end of it" {
    const io = std.testing.io;
    var h: Harness = .{};
    var script: Script = .{ .need_auth = true };
    try h.start(io, &script);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try run(gpa, io, &.{ "chat", h.address, "--send", "let me in", "--sec", "3131313131313131313131313131313131313131313131313131313131313131", "--timeout", "3000" }, &out.writer, &err.writer);
    try std.testing.expectEqual(cli.exit_fail, code);
    try std.testing.expectEqual(@as(usize, 0), script.auths);
    try std.testing.expectEqualStrings("", out.written());
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "auth-required") != null);
}

test "reading from a relay that wants auth answers it with --auth" {
    const io = std.testing.io;
    var h: Harness = .{};
    const arena = h.arena_state.allocator();
    var script: Script = .{};
    script.serve = &.{try signedBy(arena, io, test_secret, 1_700_000_100, 9, &.{try mk(arena, &.{ "h", "pizza" })}, "hi")};
    try h.start(io, &script);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    // --sec without --auth is refused rather than ignored.
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{ "chat", h.address, "--sec", "3131313131313131313131313131313131313131313131313131313131313131" }, &out.writer, &err.writer));
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "chat", h.address, "--auth", "--sec", "3131313131313131313131313131313131313131313131313131313131313131", "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"hi\"") != null);
}

test "usage errors" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{}, &out.writer, &err.writer));
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{"bogus"}, &out.writer, &err.writer));
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{"info"}, &out.writer, &err.writer));
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{ "info", "nonsense" }, &out.writer, &err.writer));
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{ "info", "r.example'x", "--send", "no" }, &out.writer, &err.writer));
    try std.testing.expectEqual(cli.exit_usage, try run(gpa, io, &.{ "put-user", "r.example'x", "--sec", "3131313131313131313131313131313131313131313131313131313131313131" }, &out.writer, &err.writer));
}

test "state signed by any key but the relay's own is dropped" {
    const io = std.testing.io;
    var h: Harness = .{};
    const arena = h.arena_state.allocator();
    var script: Script = .{};
    const good = try serveGroupState(arena, io);
    const forged = try signedBy(arena, io, test_secret, 1_800_000_000, kind_metadata, &.{
        try mk(arena, &.{ "d", "pizza" }),
        try mk(arena, &.{ "name", "Forged" }),
    }, "");
    const served = try arena.alloc([]const u8, good.len + 1);
    @memcpy(served[0..good.len], good);
    served[good.len] = forged;
    script.serve = served;
    try h.startFor(io, &script, 1);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "info", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "Pizza Lovers") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "Forged") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"verified\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "ignored 1 event") != null);
}

test "a relay that states no key of its own is read with a warning and marked unverified" {
    const io = std.testing.io;
    var h: Harness = .{ .doc = "{\"name\":\"anon\"}" };
    var script: Script = .{};
    script.serve = try serveGroupState(h.arena_state.allocator(), io);
    try h.startFor(io, &script, 1);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "info", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"verified\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "unverified") != null);
}

test "control characters in what the relay supplies are escaped when printed" {
    const io = std.testing.io;
    var h: Harness = .{};
    const arena = h.arena_state.allocator();
    var script: Script = .{};
    const served = try arena.alloc([]const u8, 1);
    served[0] = try signedBy(arena, io, relay_secret, 1_700_000_100, kind_admins, &.{
        try mk(arena, &.{ "d", "pizza" }),
        try mk(arena, &.{ "p", "ab\x1b[2Jcd", "ro\x07le" }),
    }, "");
    script.serve = served;
    try h.startFor(io, &script, 1);
    defer h.finish(io);
    const gpa = h.da.allocator();

    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    try std.testing.expectEqual(cli.exit_ok, try run(gpa, io, &.{ "admins", h.address, "--timeout", "3000" }, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOfScalar(u8, out.written(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out.written(), 0x07) == null);
    try std.testing.expectEqualStrings("ab\\x1b[2Jcd ro\\x07le\n", out.written());
}
