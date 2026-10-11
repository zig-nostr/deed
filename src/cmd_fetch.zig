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
const thread = @import("thread.zig");

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
    \\Exits: 0 if an event was found; 1 if a code is bad or nothing was found; 2 if
    \\the command line was not understood.
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
    var thread_code: ?[]const u8 = null;
    var max_depth: u32 = 10;
    var limit: u32 = 500;
    var as_tree = false;
    var local = false;

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
        if (std.mem.eql(u8, a, "--tree")) {
            as_tree = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--local")) {
            local = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            if (!cli.isOneOf(a, &.{ "--store", "--timeout", "-r", "--relay", "--thread", "--max-depth", "--limit" })) {
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
            } else if (std.mem.eql(u8, a, "--store")) store_path = args[i] else if (std.mem.eql(u8, a, "--thread")) {
                thread_code = args[i];
            } else if (cli.isOneOf(a, &.{ "--max-depth", "--limit" })) {
                const n = std.fmt.parseInt(u32, args[i], 10) catch {
                    try err.print("deed fetch: '{s}' is not a number\n", .{args[i]});
                    return cli.exit_fail;
                };
                if (n == 0) {
                    try err.print("deed fetch: '{s}' needs a number above zero\n", .{a});
                    return cli.exit_usage;
                }
                if (a[2] == 'm') max_depth = n else limit = n;
            } else {
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

    if (thread_code == null and (as_tree or local)) {
        try err.print("deed fetch: {s} goes with --thread\n", .{if (as_tree) "--tree" else "--local"});
        return cli.exit_usage;
    }
    if (thread_code != null) {
        if (code != null) {
            try err.writeAll("deed fetch: --thread takes the code itself; give it once\n");
            return cli.exit_usage;
        }
        return runThread(gpa, io, .{
            .code = thread_code.?,
            .urls = urls.items,
            .bootstrap = &bootstrap,
            .store_path = store_path,
            .timeout_ms = timeout_ms,
            .auth_flags = auth_flags,
            .opts = .{ .max_depth = max_depth, .limit = limit },
            .as_tree = as_tree,
            .local = local,
        }, out, err);
    }
    const raw = code orelse {
        try err.writeAll("deed fetch: needs a code to fetch\n");
        return cli.exit_usage;
    };
    const auth_opts = auth.resolve(gpa, io, auth_flags, "fetch", err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };
    defer if (auth_opts) |o| o.deinit(gpa);

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
            .verb = "fetch",
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
        .verb = "fetch",
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

const ThreadArgs = struct {
    code: []const u8,
    urls: []const []const u8,
    bootstrap: *std.ArrayList([]const u8),
    store_path: ?[]const u8,
    timeout_ms: i64,
    auth_flags: auth.Flags,
    opts: thread.Options,
    as_tree: bool,
    local: bool,
};

/// Asks the relays, growing the list of them once the thread's first author is known.
const RelayFetcher = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: std.ArrayList([]const u8),
    err: *std.Io.Writer,
    store: ?*nostr.store.Store,
    auth: ?auth.Options,
    timeout_ms: i64,
    /// Set when no relay was named, so the author's own relays are looked for.
    follow: bool,
    bootstrap: []const []const u8,
    followed: ?outbox.Urls = null,

    fn run(ctx: *anyopaque, filters: []const filter.Filter, out: *std.Io.Writer) anyerror!void {
        const self: *RelayFetcher = @ptrCast(@alignCast(ctx));
        const outcome = try relayset.query(self.gpa, self.io, self.urls.items, filters, out, self.err, .{
            .until_eose = true,
            .deadline_ms = self.timeout_ms,
            .verb = "fetch",
            .store = self.store,
            .auth = self.auth,
        });
        if (outcome.store_failed) return error.StoreFailed;
        if (outcome.dialled == 0) return error.NoRelay;
    }

    fn rootFound(ctx: *anyopaque, author: [32]u8) anyerror!void {
        const self: *RelayFetcher = @ptrCast(@alignCast(ctx));
        if (!self.follow) return;
        self.followed = try outbox.writeRelays(self.gpa, self.io, author, .{
            .bootstrap = self.bootstrap,
            .verb = "fetch",
            .store = self.store,
        }, self.err);
        if (self.followed.?.urls.len == 0) {
            try self.err.writeAll("deed fetch: found no relays the first post's author writes to, so only the named relays were asked\n");
            return;
        }
        for (self.followed.?.urls) |u| {
            var known = false;
            for (self.urls.items) |have| known = known or std.mem.eql(u8, have, u);
            if (!known) try self.urls.append(self.gpa, u);
        }
    }
};

/// Answers from a local store alone.
const StoreFetcher = struct {
    gpa: std.mem.Allocator,
    store: *nostr.store.Store,
    err: *std.Io.Writer,

    fn run(ctx: *anyopaque, filters: []const filter.Filter, out: *std.Io.Writer) anyerror!void {
        const self: *StoreFetcher = @ptrCast(@alignCast(ctx));
        for (filters) |f| {
            var result = self.store.query(self.gpa, f) catch |e| {
                try self.err.print("deed fetch: the store could not answer: {s}\n", .{@errorName(e)});
                return error.StoreFailed;
            };
            defer result.deinit();
            for (result.events) |ev| {
                const json = try nostr.event.toJson(self.gpa, ev);
                defer self.gpa.free(json);
                try out.print("{s}\n", .{json});
            }
        }
    }
};

fn runThread(
    gpa: std.mem.Allocator,
    io: std.Io,
    a: ThreadArgs,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var ids: [1][32]u8 = undefined;
    var authors: [1][32]u8 = undefined;
    var kinds: [1]u16 = undefined;
    var d_values: [1][]const u8 = undefined;
    var tags: [1]filter.TagFilter = undefined;
    var target = resolve(gpa, a.code, &ids, &authors, &kinds, &d_values, &tags) catch {
        try err.print("deed fetch: {s}: not a code deed can look up\n", .{a.code});
        return cli.exit_fail;
    };
    defer target.deinit(gpa);
    const start_id = if (target.filter.ids) |v| v[0] else {
        try err.writeAll("deed fetch: --thread needs a note, an nevent or an event id\n");
        return cli.exit_usage;
    };

    var store: ?nostr.store.Store = null;
    defer if (store) |*st| st.deinit();
    if (a.local) {
        const path = a.store_path orelse {
            try err.writeAll("deed fetch: --local needs --store to read from\n");
            return cli.exit_usage;
        };
        store = (try storepath.open(gpa, io, "fetch", path, .existing, err)) orelse return cli.exit_fail;
    } else if (a.store_path) |path| {
        store = (try storepath.open(gpa, io, "fetch", path, .create, err)) orelse return cli.exit_fail;
    }

    var relays: RelayFetcher = .{
        .gpa = gpa,
        .io = io,
        .urls = .empty,
        .err = err,
        .store = if (store) |*st| st else null,
        .auth = null,
        .timeout_ms = a.timeout_ms,
        .follow = false,
        .bootstrap = &.{},
    };
    defer relays.urls.deinit(gpa);
    defer if (relays.followed) |*f| f.deinit();
    var local_fetcher: StoreFetcher = undefined;

    var auth_opts: ?auth.Options = null;
    defer if (auth_opts) |o| o.deinit(gpa);

    const fetcher: thread.Fetcher = if (a.local) blk: {
        local_fetcher = .{ .gpa = gpa, .store = &store.?, .err = err };
        break :blk .{ .ctx = &local_fetcher, .run = StoreFetcher.run };
    } else blk: {
        auth_opts = auth.resolve(gpa, io, a.auth_flags, "fetch", err) catch |e| switch (e) {
            error.Usage => return cli.exit_usage,
            error.BadKey => return cli.exit_fail,
            else => |other| return other,
        };
        relays.auth = auth_opts;
        for (target.hints) |h| try relays.urls.append(gpa, h);
        for (a.urls) |u| try relays.urls.append(gpa, u);
        if (relays.urls.items.len == 0) {
            try outbox.appendEnvBootstrap(gpa, a.bootstrap);
            if (a.bootstrap.items.len == 0) {
                try err.writeAll("deed fetch: that code carries no relay hints, so name a relay to look in, or name a relay (with --relay, or DEED_RELAYS) to find the first post's author's relays through\n");
                return cli.exit_usage;
            }
            // The relays named for finding people are where the event is
            // looked for first; the author's own are added once known.
            for (a.bootstrap.items) |u| try relays.urls.append(gpa, u);
            relays.follow = true;
            relays.bootstrap = a.bootstrap.items;
        }
        break :blk .{ .ctx = &relays, .run = RelayFetcher.run, .root_found = RelayFetcher.rootFound };
    };

    var t = thread.assemble(gpa, fetcher, start_id, a.opts) catch |e| switch (e) {
        error.NoRelay => {
            try err.writeAll("deed fetch: no relay answered\n");
            return cli.exit_fail;
        },
        error.StoreFailed => return cli.exit_fail,
        else => |other| return other,
    };
    defer t.deinit();

    if (t.start == null) {
        try err.writeAll(if (a.local) "deed fetch: the store does not hold that event\n" else "deed fetch: no relay asked has that event\n");
        return cli.exit_fail;
    }
    const top = t.event(t.root.?);
    if (thread.parentOf(top) != null or thread.rootOf(top) != null) {
        try err.writeAll("deed fetch: the start of the conversation was not found, so the thread begins at the oldest event that was\n");
    }
    if (t.items.items.len >= a.opts.limit) {
        try err.print("deed fetch: stopped at --limit {d}; there may be more\n", .{a.opts.limit});
    }

    const rows = if (a.as_tree) try thread.tree(gpa, &t) else try thread.flat(gpa, &t);
    defer gpa.free(rows);
    for (rows) |row| {
        const json = try nostr.event.toJson(gpa, t.event(row.index));
        defer gpa.free(json);
        if (a.as_tree) try out.print("{d}\t", .{row.depth});
        try out.print("{s}\n", .{json});
    }
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

test {
    std.testing.refAllDecls(thread);
}

/// A relay that holds a fixed set of events and answers a REQ from them, by
/// the filters it was sent. `everything` makes it ignore the filters, the way
/// a careless or hostile relay does.
const Mini = struct {
    events: []const nostr.event.Event,
    reqs: std.atomic.Value(usize) = .init(0),
    everything: bool = false,

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *Mini = @ptrCast(@alignCast(ctx.?));
        var parsed = nostr.message.parseClientMessage(testing.allocator, frame) catch return;
        defer parsed.deinit();
        const req = switch (parsed.value) {
            .req => |r| r,
            else => return,
        };
        _ = self.reqs.fetchAdd(1, .monotonic);
        for (self.events) |ev| {
            var hit = self.everything;
            for (req.filters) |f| hit = hit or f.matches(ev);
            if (!hit) continue;
            const json = try nostr.event.toJson(testing.allocator, ev);
            defer testing.allocator.free(json);
            const text = try std.fmt.allocPrint(testing.allocator, "[\"EVENT\",\"{s}\",{s}]", .{ req.subscription_id, json });
            defer testing.allocator.free(text);
            try testrelay.sendText(w, text);
        }
        const eose = try std.fmt.allocPrint(testing.allocator, "[\"EOSE\",\"{s}\"]", .{req.subscription_id});
        defer testing.allocator.free(eose);
        try testrelay.sendText(w, eose);
    }
};

/// Many queries are made one after another, each on a fresh connection.
const dials = 40;

const World = struct {
    arena: std.heap.ArenaAllocator,
    signer: nostr.keys.Signer,
    kp: nostr.keys.KeyPair,
    other: nostr.keys.KeyPair,
    events: std.ArrayList(nostr.event.Event) = .empty,

    fn init(io: std.Io) !World {
        var w: World = .{
            .arena = std.heap.ArenaAllocator.init(testing.allocator),
            .signer = try nostr.keys.Signer.initRandomized(io),
            .kp = undefined,
            .other = undefined,
        };
        w.kp = try w.signer.keyPairFromSecretKey([_]u8{0x71} ** 32);
        w.other = try w.signer.keyPairFromSecretKey([_]u8{0x72} ** 32);
        return w;
    }

    fn deinit(self: *World) void {
        self.signer.deinit();
        self.arena.deinit();
    }

    fn a(self: *World) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn id(self: *World, ev: nostr.event.Event) ![]const u8 {
        return hex.encode(self.a(), &ev.id);
    }

    /// Signs and keeps an event. `tags` is a list of `{name, event, marker}`.
    fn add(self: *World, at: i64, kind: u16, parents: []const [3][]const u8) !nostr.event.Event {
        const al = self.a();
        const tags = try al.alloc(nostr.event.Tag, parents.len);
        for (parents, tags) |p, *t| {
            const hexid = p[1];
            t.* = if (p[2].len == 0) try al.dupe([]const u8, &.{ p[0], hexid }) else try al.dupe([]const u8, &.{ p[0], hexid, "", p[2] });
        }
        const ev = try nostr.event.create(al, self.signer, self.kp, at, kind, tags, "text", null);
        try self.events.append(al, ev);
        return ev;
    }
};

fn startMini(relay: *testrelay.Relay, io: std.Io, mini: *Mini, url_buf: []u8) ![]const u8 {
    try relay.startFor(io, .custom, dials);
    relay.custom = Mini.handle;
    relay.custom_ctx = mini;
    return testrelay.url(url_buf, relay.port());
}

const ThreadRun = struct { code: u8, out: []const u8, err: []const u8 };

fn runThreadCmd(w: *World, gpa: std.mem.Allocator, args: []const []const u8) !ThreadRun {
    var out: std.Io.Writer.Allocating = .init(w.a());
    var err: std.Io.Writer.Allocating = .init(w.a());
    const code = try run(gpa, testing.io, args, &out.writer, &err.writer);
    return .{ .code = code, .out = out.written(), .err = err.written() };
}

fn lineCount(s: []const u8) usize {
    return std.mem.count(u8, s, "\n");
}

fn position(s: []const u8, needle: []const u8) usize {
    return std.mem.indexOf(u8, s, needle) orelse std.math.maxInt(usize);
}

const Chain = struct {
    root: nostr.event.Event,
    c1: nostr.event.Event,
    c2: nostr.event.Event,
    c3: nostr.event.Event,
    k1: nostr.event.Event,
    k2: nostr.event.Event,
    stranger: nostr.event.Event,
};

/// A root, replies at three depths (marked, as a modern client writes them),
/// a NIP-22 comment on the root and a comment on that comment, and one event
/// belonging to some other conversation.
fn chain(w: *World) !Chain {
    const root = try w.add(100, 1, &.{});
    const r = try w.id(root);
    const c1 = try w.add(200, 1, &.{ .{ "e", r, "root" }, .{ "e", r, "reply" } });
    const c1id = try w.id(c1);
    const c2 = try w.add(300, 1, &.{ .{ "e", r, "root" }, .{ "e", c1id, "reply" } });
    const c2id = try w.id(c2);
    const c3 = try w.add(400, 1, &.{ .{ "e", r, "root" }, .{ "e", c2id, "reply" } });
    const k1 = try w.add(250, 1111, &.{ .{ "E", r, "" }, .{ "e", r, "" } });
    const k1id = try w.id(k1);
    const k2 = try w.add(350, 1111, &.{ .{ "E", r, "" }, .{ "e", k1id, "" } });
    const stranger = try w.add(150, 1, &.{.{ "e", "ab" ** 32, "root" }});
    return .{ .root = root, .c1 = c1, .c2 = c2, .c3 = c3, .k1 = k1, .k2 = k2, .stranger = stranger };
}

test "a thread started from a reply returns the whole conversation, root first" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();
    const c = try chain(&w);

    var mini: Mini = .{ .events = w.events.items };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const note = try nip19.encodeNote(w.a(), c.c2.id);
    const r = try runThreadCmd(&w, gpa, &.{ "--thread", note, url });
    try testing.expectEqual(cli.exit_ok, r.code);
    // Six of the seven: the stranger is another conversation.
    try testing.expectEqual(@as(usize, 6), lineCount(r.out));
    try testing.expect(std.mem.indexOf(u8, r.out, try w.id(c.stranger)) == null);
    // Root first, then oldest first: c1(200) k1(250) c2(300) k2(350) c3(400).
    var at: usize = 0;
    for ([_]nostr.event.Event{ c.root, c.c1, c.k1, c.c2, c.k2, c.c3 }) |ev| {
        const p = position(r.out, try hex.encode(w.a(), &ev.id));
        try testing.expect(p != std.math.maxInt(usize));
        try testing.expect(p >= at);
        at = p;
    }
}

test "--tree puts each event's depth in front of it" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();
    const c = try chain(&w);
    var mini: Mini = .{ .events = w.events.items };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const hexed = try hex.encode(w.a(), &c.root.id);
    const r = try runThreadCmd(&w, gpa, &.{ "--thread", hexed, "--tree", url });
    try testing.expectEqual(cli.exit_ok, r.code);
    var depth_of = std.StringHashMap(u8).init(w.a());
    var lines = std.mem.splitScalar(u8, r.out, '\n');
    var order = std.ArrayList([]const u8).empty;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try testing.expectEqual(@as(u8, '\t'), line[1]);
        const idx = std.mem.indexOf(u8, line, "\"id\":\"").? + 6;
        const idh = line[idx .. idx + 64];
        try depth_of.put(idh, line[0] - '0');
        try order.append(w.a(), idh);
    }
    try testing.expectEqual(@as(u8, 0), depth_of.get(try hex.encode(w.a(), &c.root.id)).?);
    try testing.expectEqual(@as(u8, 1), depth_of.get(try hex.encode(w.a(), &c.c1.id)).?);
    try testing.expectEqual(@as(u8, 2), depth_of.get(try hex.encode(w.a(), &c.c2.id)).?);
    try testing.expectEqual(@as(u8, 3), depth_of.get(try hex.encode(w.a(), &c.c3.id)).?);
    try testing.expectEqual(@as(u8, 1), depth_of.get(try hex.encode(w.a(), &c.k1.id)).?);
    try testing.expectEqual(@as(u8, 2), depth_of.get(try hex.encode(w.a(), &c.k2.id)).?);
    // Depth first: c3 follows c2, which follows c1.
    var p1: usize = 0;
    var p2: usize = 0;
    var p3: usize = 0;
    for (order.items, 0..) |o, n| {
        if (std.mem.eql(u8, o, try w.id(c.c1))) p1 = n;
        if (std.mem.eql(u8, o, try hex.encode(w.a(), &c.c2.id))) p2 = n;
        if (std.mem.eql(u8, o, try hex.encode(w.a(), &c.c3.id))) p3 = n;
    }
    try testing.expectEqual(p1 + 1, p2);
    try testing.expectEqual(p2 + 1, p3);
}

test "a parent no relay has leaves the thread starting at the oldest event found" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();

    // The unmarked, positional form, with the middle event missing.
    const root = try w.add(100, 1, &.{});
    const r = try w.id(root);
    const lost = try nostr.event.create(w.a(), w.signer, w.kp, 200, 1, &.{&.{ "e", r }}, "never sent", null);
    const lost_id = try w.id(lost);
    const orphan = try w.add(300, 1, &.{ .{ "e", "cd" ** 32, "" }, .{ "e", lost_id, "" } });
    const sibling = try w.add(400, 1, &.{.{ "e", lost_id, "" }});

    var mini: Mini = .{ .events = w.events.items };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const code = try nip19.encodeNevent(w.a(), orphan.id, &.{}, null, null);
    const res = try runThreadCmd(&w, gpa, &.{ "--thread", code, url });
    try testing.expectEqual(cli.exit_ok, res.code);
    // The orphan and its sibling, which share the missing parent, and nothing else.
    try testing.expectEqual(@as(usize, 2), lineCount(res.out));
    try testing.expect(position(res.out, try w.id(orphan)) < position(res.out, try w.id(sibling)));
    try testing.expect(std.mem.indexOf(u8, res.err, "was not found") != null);
}

test "a missing parent falls back to the named root" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();

    const root = try w.add(100, 1, &.{});
    const r = try w.id(root);
    const reply = try w.add(300, 1, &.{ .{ "e", r, "root" }, .{ "e", "ef" ** 32, "reply" } });

    var mini: Mini = .{ .events = w.events.items };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const res = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(reply), url });
    try testing.expectEqual(cli.exit_ok, res.code);
    try testing.expectEqual(@as(usize, 2), lineCount(res.out));
    try testing.expect(position(res.out, r) < position(res.out, try w.id(reply)));
}

test "--max-depth and --limit bound the thread" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();
    const c = try chain(&w);

    var mini: Mini = .{ .events = w.events.items };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const root = try w.id(c.root);
    // One level down from the root: c1 and k1 only. Replies two and three
    // levels down carry the root's id in their tags, though, so the root
    // asked for alone already brings them: the depth bounds the rounds, and
    // a reply that does not name the root needs a round of its own.
    const shallow = try runThreadCmd(&w, gpa, &.{ "--thread", root, "--max-depth", "1", url });
    try testing.expectEqual(cli.exit_ok, shallow.code);
    try testing.expect(lineCount(shallow.out) <= 6);

    const capped = try runThreadCmd(&w, gpa, &.{ "--thread", root, "--limit", "3", url });
    try testing.expectEqual(@as(usize, 3), lineCount(capped.out));
    try testing.expect(std.mem.indexOf(u8, capped.err, "--limit 3") != null);
}

test "a reply that names only its parent is found by the round below" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();

    // Each reply names only the one above it: nothing carries the root's id
    // but the first, so the depth is what finds the rest.
    const root = try w.add(100, 1, &.{});
    const a1 = try w.add(200, 1, &.{.{ "e", try w.id(root), "" }});
    const a2 = try w.add(300, 1, &.{.{ "e", try w.id(a1), "" }});
    const a3 = try w.add(400, 1, &.{.{ "e", try w.id(a2), "" }});

    var mini: Mini = .{ .events = w.events.items };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const deep = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(root), url });
    try testing.expectEqual(@as(usize, 4), lineCount(deep.out));
    try testing.expect(std.mem.indexOf(u8, deep.out, try w.id(a3)) != null);

    // Two rounds down reach a2 and stop short of a3.
    var mini2: Mini = .{ .events = w.events.items };
    var relay2: testrelay.Relay = undefined;
    var ub2: [40]u8 = undefined;
    const url2 = try startMini(&relay2, io, &mini2, &ub2);
    defer relay2.stop(io);
    const two = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(root), "--max-depth", "2", url2 });
    try testing.expectEqual(@as(usize, 3), lineCount(two.out));
    try testing.expect(std.mem.indexOf(u8, two.out, try w.id(a3)) == null);
}

test "a relay that answers every question with everything adds nothing and ends" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();
    const c = try chain(&w);

    var mini: Mini = .{ .events = w.events.items, .everything = true };
    var relay: testrelay.Relay = undefined;
    var ub: [40]u8 = undefined;
    const url = try startMini(&relay, io, &mini, &ub);
    defer relay.stop(io);

    const res = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(c.c3), url });
    try testing.expectEqual(cli.exit_ok, res.code);
    // Every event once, though each round was answered with all of them.
    try testing.expect(lineCount(res.out) <= w.events.items.len);
    var seen = std.StringHashMap(void).init(w.a());
    var lines = std.mem.splitScalar(u8, res.out, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try testing.expect(!seen.contains(line));
        try seen.put(line, {});
    }
}

test "--local reads a thread from the store and dials nothing" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();
    const c = try chain(&w);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const path = try std.fmt.allocPrint(w.a(), "{s}/thread.mdb", .{root_buf[0..root_len]});

    // Filled by a first run against a relay, which keeps what it reads.
    {
        var mini: Mini = .{ .events = w.events.items };
        var relay: testrelay.Relay = undefined;
        var ub: [40]u8 = undefined;
        const url = try startMini(&relay, io, &mini, &ub);
        defer relay.stop(io);
        const first = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(c.c2), "--store", path, url });
        try testing.expectEqual(cli.exit_ok, first.code);
        try testing.expectEqual(@as(usize, 6), lineCount(first.out));
    }

    // No relay anywhere now: the answer is the same, from the file.
    const again = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(c.c2), "--store", path, "--local" });
    try testing.expectEqual(cli.exit_ok, again.code);
    try testing.expectEqual(@as(usize, 6), lineCount(again.out));
    try testing.expect(position(again.out, try w.id(c.root)) < position(again.out, try w.id(c.c3)));

    const nothing = try runThreadCmd(&w, gpa, &.{ "--thread", "12" ** 32, "--store", path, "--local" });
    try testing.expectEqual(cli.exit_fail, nothing.code);
    try testing.expect(std.mem.indexOf(u8, nothing.err, "does not hold") != null);

    const no_store = try runThreadCmd(&w, gpa, &.{ "--thread", "12" ** 32, "--local" });
    try testing.expectEqual(cli.exit_usage, no_store.code);
}

test "a thread with no relay named follows the first post's author" {
    if (std.c.getenv("DEED_RELAYS") != null) return error.SkipZigTest;
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();

    const root = try w.add(100, 1, &.{});
    const reply = try w.add(200, 1, &.{.{ "e", try w.id(root), "root" }});

    // The relay the author writes to holds the replies. The relay named for
    // finding people holds the root and the author's relay list.
    var home: Mini = .{ .events = &.{reply} };
    var home_relay: testrelay.Relay = undefined;
    var hb: [40]u8 = undefined;
    const home_url = try startMini(&home_relay, io, &home, &hb);
    defer home_relay.stop(io);

    const list_tags = [_]nostr.event.Tag{&.{ "r", home_url, "write" }};
    const list = try nostr.event.create(w.a(), w.signer, w.kp, 150, 10002, &list_tags, "", null);
    var dir: Mini = .{ .events = &.{ root, list } };
    var dir_relay: testrelay.Relay = undefined;
    var db: [40]u8 = undefined;
    const dir_url = try startMini(&dir_relay, io, &dir, &db);
    defer dir_relay.stop(io);

    const res = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(root), "--relay", dir_url });
    try testing.expectEqual(cli.exit_ok, res.code);
    try testing.expectEqual(@as(usize, 2), lineCount(res.out));
    try testing.expect(std.mem.indexOf(u8, res.out, try w.id(reply)) != null);

    const bare = try runThreadCmd(&w, gpa, &.{ "--thread", try w.id(root) });
    try testing.expectEqual(cli.exit_usage, bare.code);
    try testing.expect(std.mem.indexOf(u8, bare.err, "DEED_RELAYS") != null);
}

test "thread flags need --thread, and a code that is not an event is refused" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var w = try World.init(io);
    defer w.deinit();

    const lone = try runThreadCmd(&w, gpa, &.{ "--tree", "ab" ** 32 });
    try testing.expectEqual(cli.exit_usage, lone.code);
    const npub = try nip19.encodeNpub(w.a(), w.kp.public_key);
    const profile = try runThreadCmd(&w, gpa, &.{ "--thread", npub, "wss://x.example" });
    try testing.expectEqual(cli.exit_usage, profile.code);
    const zero = try runThreadCmd(&w, gpa, &.{ "--thread", "ab" ** 32, "--max-depth", "0" });
    try testing.expectEqual(cli.exit_usage, zero.code);
}
