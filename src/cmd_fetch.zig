//! `deed fetch`: get the events a code names.
//!
//! A NIP-19 code often carries relay hints, which is the difference between
//! this and `req`: the code says where to look, so the reader does not have to.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const outbox = @import("outbox.zig");
const relayset = @import("relayset.zig");
const auth = @import("auth.zig");
const storepath = @import("storepath.zig");

const nip19 = nostr.nip19;
const filter = nostr.filter;
const hex = nostr.hex;

pub const usage =
    \\deed fetch: get the events a code names
    \\
    \\Usage:
    \\  deed fetch <code> [<relay-url>...]
    \\
    \\Accepts note, nevent, naddr, nprofile and npub, with or without a leading
    \\`nostr:`, in lower case or all upper case. A code carrying relay hints is
    \\looked for at those relays as well as any named here.
    \\
    \\A code with no hints, and no relay named, is looked for at the author's own
    \\write relays: their relay list is first asked of the relays in DEED_RELAYS or
    \\given with --relay. A note or event id with no hints has no author to follow,
    \\so it still needs a relay named.
    \\
    \\Options:
    \\  -r, --relay <url>    where to look up the author's relay list, for a code
    \\                       with no hints, repeatable (and DEED_RELAYS)
    \\      --store <path>   keep every event this receives in a local store
    \\      --timeout <ms>   give up on relays still answering (default 30000)
++ auth.usage_lines ++
    \\
    \\A relay that has not accepted the connection within five seconds, or
    \\within --timeout if that is shorter, is named on stderr and left out.
    \\Looking up a relay's name is the one step that cannot be cut short.
    \\
    \\A store is one file, with a -lock file beside it. --store creates them, and
    \\any directories above them, the first time.
    \\
    \\A bare npub fetches that person's profile rather than everything they have
    \\ever written, which is what `npub` on its own can sensibly mean.
    \\
;

/// What a code resolves to: a question, and where to ask it.
const Target = struct {
    filter: filter.Filter,
    hints: []const []const u8,
};

pub fn run(
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
    var timeout_ms: i64 = 30_000;
    var auth_flags: auth.Flags = .{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        switch (auth_flags.take(args, &i)) {
            .taken => continue,
            .missing_value => {
                try err.print("deed fetch: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            },
            .not_mine => {},
        }
        if (std.mem.startsWith(u8, a, "-")) {
            if (!cli.isOneOf(a, &.{ "--store", "--timeout", "-r", "--relay" })) {
                try err.print("deed fetch: unknown option '{s}'\n", .{a});
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed fetch: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
                try bootstrap.append(gpa, args[i]);
            } else if (std.mem.eql(u8, a, "--store")) store_path = args[i] else {
                timeout_ms = std.fmt.parseInt(i64, args[i], 10) catch {
                    try err.print("deed fetch: '{s}' is not a number of milliseconds\n", .{args[i]});
                    return cli.exit_fail;
                };
            }
            continue;
        }
        if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try urls.append(gpa, a);
        } else if (code == null) {
            code = a;
        } else {
            try err.writeAll("deed fetch: takes one code\n");
            return cli.exit_usage;
        }
    }

    const raw = code orelse {
        try err.writeAll("deed fetch: needs a code to fetch\n");
        return cli.exit_usage;
    };
    const auth_opts = auth.resolve(gpa, auth_flags, "fetch", err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };

    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d_values: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;

    var target = resolve(gpa, raw, &ids, &authors, &kinds, &d_values, &tags) catch {
        try err.print("deed fetch: {s}: not a code deed can look up\n", .{raw});
        return cli.exit_fail;
    };
    defer target.deinit(gpa);

    for (target.hints) |h| try urls.append(gpa, h);

    var store: ?nostr.store.Store = null;
    defer if (store) |*st| st.deinit();
    if (store_path) |path| {
        store = (try storepath.open(gpa, io, "fetch", path, .create, err)) orelse return cli.exit_fail;
    }

    // No relay named and none in the code: follow the author to the relays they
    // write to. A code that names no author has nowhere to follow.
    var followed: ?outbox.Urls = null;
    defer if (followed) |*f| f.deinit();
    if (urls.items.len == 0) {
        if (target.filter.authors == null) {
            try err.writeAll("deed fetch: that code carries no relay hints and names no author, so name a relay to look in\n");
            return cli.exit_usage;
        }
        try outbox.appendEnvBootstrap(gpa, &bootstrap);
        if (bootstrap.items.len == 0) {
            try err.writeAll("deed fetch: that code carries no relay hints, so name a relay to look in, or name a relay (with --relay, or DEED_RELAYS) to find the author's relays through\n");
            return cli.exit_usage;
        }
        followed = try outbox.writeRelays(gpa, io, target.filter.authors.?[0], .{
            .bootstrap = bootstrap.items,
            .store = if (store) |*st| st else null,
        }, err);
        if (followed.?.urls.len == 0) {
            try err.writeAll("deed fetch: found no relays the author writes to, so name a relay to look in\n");
            return cli.exit_fail;
        }
        for (followed.?.urls) |u| try urls.append(gpa, u);
    }

    const outcome = try relayset.query(gpa, io, urls.items, &.{target.filter}, out, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
        .store = if (store) |*st| st else null,
        .auth = auth_opts,
    });

    if (outcome.store_failed) return cli.exit_fail;
    if (outcome.dialled == 0) {
        try err.writeAll("deed fetch: no relay answered\n");
        return cli.exit_fail;
    }
    // Nothing found is not a failure of the command. The code may name an event
    // no relay asked has, which is a true answer.
    return cli.exit_ok;
}

const Resolved = struct {
    filter: filter.Filter,
    hints: []const []const u8,
    owned: ?[][]u8 = null,
    /// `naddr` carries a `d` value the decoder allocates, and the filter points
    /// straight at it, so it has to outlive the query and be freed with the
    /// rest. Freeing only the relays leaked one string per naddr fetched.
    owned_identifier: ?[]u8 = null,

    fn deinit(self: *Resolved, gpa: std.mem.Allocator) void {
        if (self.owned) |list| {
            for (list) |r| gpa.free(r);
            gpa.free(list);
        }
        if (self.owned_identifier) |d| gpa.free(d);
    }
};

/// Turns a code into the question to ask and the relays the code names.
fn resolve(
    gpa: std.mem.Allocator,
    raw: []const u8,
    ids: *[1][32]u8,
    authors: *[1][32]u8,
    kinds: *[1]u16,
    d_values: *[1][]const u8,
    tags: *[1]filter.TagFilter,
) !Resolved {
    const s = keyinput.stripUri(raw);

    if (keyinput.hasPrefix(s, "nevent1")) {
        const p = try nip19.decodeNevent(gpa, s);
        ids[0] = p.id;
        return .{ .filter = .{ .ids = ids[0..1] }, .hints = p.relays, .owned = p.relays };
    }
    if (keyinput.hasPrefix(s, "note1")) {
        ids[0] = try nip19.decodeNote(gpa, s);
        return .{ .filter = .{ .ids = ids[0..1] }, .hints = &.{} };
    }
    if (keyinput.hasPrefix(s, "naddr1")) {
        const p = try nip19.decodeNaddr(gpa, s);
        authors[0] = p.pubkey;
        kinds[0] = @intCast(p.kind);
        d_values[0] = p.identifier;
        tags[0] = .{ .letter = 'd', .values = d_values[0..1] };
        return .{
            .filter = .{ .authors = authors[0..1], .kinds = kinds[0..1], .tags = tags[0..1] },
            .hints = p.relays,
            .owned = p.relays,
            .owned_identifier = p.identifier,
        };
    }
    if (keyinput.hasPrefix(s, "nprofile1")) {
        const p = try nip19.decodeNprofile(gpa, s);
        authors[0] = p.pubkey;
        kinds[0] = 0;
        return .{
            .filter = .{ .authors = authors[0..1], .kinds = kinds[0..1] },
            .hints = p.relays,
            .owned = p.relays,
        };
    }
    if (keyinput.hasPrefix(s, "npub1")) {
        authors[0] = try nip19.decodeNpub(gpa, s);
        // Kind 0, not everything. A bare npub names a person, and the thing a
        // person's code most usefully resolves to is who they say they are.
        // nak defaults the same way.
        kinds[0] = 0;
        return .{ .filter = .{ .authors = authors[0..1], .kinds = kinds[0..1] }, .hints = &.{} };
    }
    if (s.len == 64) {
        ids[0] = try hex.decodeFixed(32, s);
        return .{ .filter = .{ .ids = ids[0..1] }, .hints = &.{} };
    }
    return error.InvalidPrefix;
}

const testing = std.testing;

fn resolveFor(s: []const u8, bufs: anytype) !Resolved {
    return resolve(testing.allocator, s, bufs.ids, bufs.authors, bufs.kinds, bufs.d, bufs.tags);
}

test "a note code asks for that event by id" {
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;

    const id = [_]u8{0xab} ** 32;
    const note = try nip19.encodeNote(testing.allocator, id);
    defer testing.allocator.free(note);

    var r = try resolveFor(note, .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags });
    defer r.deinit(testing.allocator);
    try testing.expect(r.filter.ids != null);
    try testing.expectEqualSlices(u8, &id, &r.filter.ids.?[0]);
    try testing.expectEqual(@as(usize, 0), r.hints.len);
}

test "an npub asks for a profile, not for everything they ever wrote" {
    // The default that makes a bare npub useful. Without it the code would ask
    // a relay for every event one person has ever published, which is a
    // different and much ruder question.
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;

    const pk = [_]u8{0xcd} ** 32;
    const npub = try nip19.encodeNpub(testing.allocator, pk);
    defer testing.allocator.free(npub);

    var r = try resolveFor(npub, .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags });
    defer r.deinit(testing.allocator);
    try testing.expect(r.filter.ids == null);
    try testing.expectEqualSlices(u8, &pk, &r.filter.authors.?[0]);
    try testing.expectEqual(@as(u16, 0), r.filter.kinds.?[0]);
}

test "an nevent carries its relay hints out of the code" {
    // The whole reason `fetch` is not just `req` with an id: the code says
    // where to look.
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;

    const id = [_]u8{0x11} ** 32;
    const hints = [_][]const u8{ "wss://one.example", "wss://two.example" };
    const code = try nip19.encodeNevent(testing.allocator, id, &hints, null, null);
    defer testing.allocator.free(code);

    var r = try resolveFor(code, .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags });
    defer r.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &id, &r.filter.ids.?[0]);
    try testing.expectEqual(@as(usize, 2), r.hints.len);
    try testing.expectEqualStrings("wss://one.example", r.hints[0]);
}

test "an naddr asks by author, kind and d tag together" {
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;

    const pk = [_]u8{0x22} ** 32;
    const code = try nip19.encodeNaddr(testing.allocator, "my-article", pk, 30023, &.{});
    defer testing.allocator.free(code);

    var r = try resolveFor(code, .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags });
    defer r.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &pk, &r.filter.authors.?[0]);
    try testing.expectEqual(@as(u16, 30023), r.filter.kinds.?[0]);
    try testing.expectEqual(@as(u8, 'd'), r.filter.tags.?[0].letter);
    try testing.expectEqualStrings("my-article", r.filter.tags.?[0].values[0]);
}

test "a nostr: prefix is stripped, and nonsense is refused" {
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;
    const bufs = .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags };

    const id = [_]u8{0x33} ** 32;
    const note = try nip19.encodeNote(testing.allocator, id);
    defer testing.allocator.free(note);
    const prefixed = try std.fmt.allocPrint(testing.allocator, "nostr:{s}", .{note});
    defer testing.allocator.free(prefixed);

    var r = try resolveFor(prefixed, bufs);
    defer r.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &id, &r.filter.ids.?[0]);

    try testing.expectError(error.InvalidPrefix, resolveFor("not-a-code", bufs));
}

test "an uppercase code resolves like the lowercase one, with or without NOSTR:" {
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;
    const bufs = .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags };

    const key = [_]u8{0x44} ** 32;
    const hints = [_][]const u8{"wss://one.example"};
    const codes = [_][]u8{
        try nip19.encodeNote(testing.allocator, key),
        try nip19.encodeNevent(testing.allocator, key, &hints, null, null),
        try nip19.encodeNaddr(testing.allocator, "my-article", key, 30023, &.{}),
        try nip19.encodeNprofile(testing.allocator, key, &hints),
        try nip19.encodeNpub(testing.allocator, key),
    };
    defer for (codes) |c| testing.allocator.free(c);

    for (codes) |lower| {
        var want = try resolveFor(lower, bufs);
        defer want.deinit(testing.allocator);
        const want_hints = want.hints.len;
        const want_id: ?[32]u8 = if (want.filter.ids) |v| v[0] else null;
        const want_author: ?[32]u8 = if (want.filter.authors) |v| v[0] else null;

        const upper = try std.ascii.allocUpperString(testing.allocator, lower);
        defer testing.allocator.free(upper);
        const forms = [_][]const u8{ "", "NOSTR:" };
        for (forms) |scheme| {
            const input = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ scheme, upper });
            defer testing.allocator.free(input);
            var got = try resolveFor(input, bufs);
            defer got.deinit(testing.allocator);
            try testing.expectEqual(want_hints, got.hints.len);
            try testing.expectEqual(want_id, if (got.filter.ids) |v| v[0] else null);
            try testing.expectEqual(want_author, if (got.filter.authors) |v| v[0] else null);
        }
    }
}

test "64 hex characters are taken as an event id" {
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;

    var r = try resolveFor("ab" ** 32, .{ .ids = &ids, .authors = &authors, .kinds = &kinds, .d = &d, .tags = &tags });
    defer r.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &([_]u8{0xab} ** 32), &r.filter.ids.?[0]);
}

const testrelay = @import("testrelay.zig");

test "a bare npub is followed to the relays its author writes to" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x51} ** 32);

    // The relay the author writes to holds their profile.
    const profile = try nostr.event.create(arena, signer, kp, 1_700_000_000, 0, &.{}, "{\"name\":\"followed\"}", null);
    var home: testrelay.Relay = undefined;
    try home.start(io, .serve);
    home.serving = &.{try nostr.event.toJson(arena, profile)};
    defer home.stop(io);
    var home_buf: [40]u8 = undefined;
    const home_url = try testrelay.url(&home_buf, home.port());

    // The bootstrap relay holds only their relay list, naming that one.
    const tags = [_]nostr.event.Tag{&.{ "r", home_url, "write" }};
    const list = try nostr.event.create(arena, signer, kp, 1_700_000_050, 10002, &tags, "", null);
    var script: outbox.Script = .{ .list = try nostr.event.toJson(arena, list) };
    var directory: testrelay.Relay = undefined;
    try outbox.startScript(&directory, io, &script, 1);
    defer directory.stop(io);
    var dir_buf: [40]u8 = undefined;
    const dir_url = try testrelay.url(&dir_buf, directory.port());

    const npub = try nip19.encodeNpub(arena, kp.public_key);
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try run(gpa, io, &.{ npub, "--relay", dir_url }, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    try testing.expect(std.mem.indexOf(u8, out.written(), "followed") != null);

    // With nothing to ask, it says what would help instead of guessing.
    var out2: std.Io.Writer.Allocating = .init(arena);
    var err2: std.Io.Writer.Allocating = .init(arena);
    const none = try run(gpa, io, &.{npub}, &out2.writer, &err2.writer);
    try testing.expectEqual(cli.exit_usage, none);
    try testing.expect(std.mem.indexOf(u8, err2.written(), "DEED_RELAYS") != null);
    try testing.expect(std.mem.indexOf(u8, err2.written(), "--relay") != null);
}
