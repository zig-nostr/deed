//! `deed fetch`: get the events a code names.
//!
//! A NIP-19 code often carries relay hints, which is the difference between
//! this and `req`: the code says where to look, so the reader does not have to.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const relayset = @import("relayset.zig");

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
    \\`nostr:`. A code carrying relay hints is looked for at those relays as
    \\well as any named here.
    \\
    \\Options:
    \\      --store <path>   keep every event this receives in a local store
    \\      --timeout <ms>   give up on relays still answering (default 30000)
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
    var store_path: ?[]const u8 = null;
    var timeout_ms: i64 = 30_000;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.startsWith(u8, a, "-")) {
            if (!cli.isOneOf(a, &.{ "--store", "--timeout" })) {
                try err.print("deed fetch: unknown option '{s}'\n", .{a});
                return cli.exit_usage;
            }
            i += 1;
            if (i >= args.len) {
                try err.print("deed fetch: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (std.mem.eql(u8, a, "--store")) store_path = args[i] else {
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
    if (urls.items.len == 0) {
        // A bare npub or note carries no hints, and this verb does not go
        // looking for the author's relay list to find some: that is a second
        // round trip with its own caching question, and doing it badly is worse
        // than saying plainly that it is not done.
        try err.writeAll("deed fetch: that code carries no relay hints, so name a relay to look in\n");
        return cli.exit_usage;
    }

    var store: ?nostr.store.Store = null;
    defer if (store) |*st| st.deinit();
    if (store_path) |path| {
        const z = try gpa.dupeZ(u8, path);
        defer gpa.free(z);
        store = nostr.store.Store.open(z, .{}) catch |e| {
            try err.print("deed fetch: cannot open the store at {s}: {s}\n", .{ path, @errorName(e) });
            return cli.exit_fail;
        };
    }

    const outcome = try relayset.query(gpa, io, urls.items, &.{target.filter}, out, err, .{
        .until_eose = true,
        .deadline_ms = timeout_ms,
        .poll_ms = 100,
        .store = if (store) |*st| st else null,
    });

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
    const s = if (std.mem.startsWith(u8, raw, "nostr:")) raw["nostr:".len..] else raw;

    if (std.mem.startsWith(u8, s, "nevent1")) {
        const p = try nip19.decodeNevent(gpa, s);
        ids[0] = p.id;
        return .{ .filter = .{ .ids = ids[0..1] }, .hints = p.relays, .owned = p.relays };
    }
    if (std.mem.startsWith(u8, s, "note1")) {
        ids[0] = try nip19.decodeNote(gpa, s);
        return .{ .filter = .{ .ids = ids[0..1] }, .hints = &.{} };
    }
    if (std.mem.startsWith(u8, s, "naddr1")) {
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
    if (std.mem.startsWith(u8, s, "nprofile1")) {
        const p = try nip19.decodeNprofile(gpa, s);
        authors[0] = p.pubkey;
        kinds[0] = 0;
        return .{
            .filter = .{ .authors = authors[0..1], .kinds = kinds[0..1] },
            .hints = p.relays,
            .owned = p.relays,
        };
    }
    if (std.mem.startsWith(u8, s, "npub1")) {
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
