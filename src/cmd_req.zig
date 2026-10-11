//! `deed req`: build a subscription, and run it.
//!
//! With no relay arguments it prints the REQ envelope and stops, which makes
//! the filter itself inspectable before anybody dials anything. nak does the
//! same and it is the right default for a tool whose whole point is that you
//! can see what it is about to send.

const std = @import("std");
const nostr = @import("nostr");
const auth = @import("auth.zig");
const cli = @import("cli.zig");
const filterflags = @import("filterflags.zig");
const outbox = @import("outbox.zig");
const relayset = @import("relayset.zig");
const storepath = @import("storepath.zig");

const filter = nostr.filter;
const message = nostr.message;

/// Shown beside the name in `deed help`.
pub const summary = "build a subscription, and run it";

pub const ready = true;

pub const usage =
    \\deed req: build a subscription, and run it
    \\
    \\Usage:
    \\  deed req [options] [<filter-json>...] [-] [<relay-url>...]
    \\
    \\Options:
    \\  -k, --kind <n>       event kind, repeatable
    \\  -a, --author <key>   author, as npub1… or 64 hex characters, repeatable
    \\  -i, --id <id>        event id, as note1… or 64 hex characters, repeatable
    \\  -e <id>              an `e` tag value, repeatable
    \\  -p <key>             a `p` tag value, repeatable
    \\  -t <topic>           a `t` tag value, repeatable
    \\  -d <name>            a `d` tag value, repeatable
    \\  -h <name>            an `h` tag value, repeatable
    \\  -T, --tag <x=value>  a tag value under any one-letter name, repeatable
    \\      --search <text>  a NIP-50 search, for relays that support it
    \\  -l, --limit <n>      how many events to ask each relay for
    \\  -s, --since <time>   events at or after: unix seconds, 2h, 3d, 2026-10-01
    \\  -u, --until <time>   events at or before: the same forms as --since
    \\      --bare           print the filter alone, without the REQ envelope
    \\      --ids-only       print each event's id and nothing else
    \\      --paginate       ask again for older events until a page comes back empty
    \\      --paginate-interval <t>  wait between pages (default 0; 500, 500ms, 2s)
    \\      --store <path>   keep every event this receives in a local store
    \\      --local          answer from the store alone, dialling nothing
    \\      --stream         keep reading after the relays have sent what they hold
    \\      --timeout <ms>   give up on relays still answering (default 30000)
++ auth.usage_lines ++
    \\
    \\A filter can also be given as JSON: as an argument that starts with {, or
    \\on stdin when a lone - is given (one object, several, or an array of them).
    \\Stdin is read only for that -, never on its own, so a caller that leaves a
    \\pipe open cannot stall a request; reading it gives up after --timeout. Flags are laid over each JSON filter: a field a flag sets replaces
    \\the one in the JSON. Several filters make one subscription.
    \\More than 500 ids or authors in a filter go out as several filters in the
    \\same REQ, so none is dropped.
    \\
    \\With --paginate, --limit is the total across all pages, not a page size.
    \\Each page asks for events older than the oldest one seen so far, and an
    \\event two pages return is printed once. --paginate cannot be combined
    \\with --stream or --local, and --ids-only cannot be combined with --stream.
    \\
    \\A relay that has not accepted the connection within five seconds, or
    \\within --timeout if that is shorter, is named on stderr and left out.
    \\Looking up a relay's name is the one step that cannot be cut short.
    \\
    \\A store is one file, with a -lock file beside it. --store creates them, and
    \\any directories above them, the first time; --local reads only a store that
    \\already exists.
    \\
    \\Given no relay, it prints what it would send and stops, so a filter can be
    \\read before it is asked of anybody:
    \\
    \\  deed req -k 1 -l 5
    \\  ["REQ","deed",{"kinds":[1],"limit":5}]
    \\
    \\Exits: 0 on success; 1 if a value or a filter is bad, a store cannot be
    \\read, or no relay answered; 2 if the command line was not understood.
    \\
;

/// The filter a run is about, and the relays to ask.
pub const Request = struct {
    filter: filter.Filter,
    relays: []const []const u8,
    bare: bool,
    store_path: ?[]const u8 = null,
    stream: bool = false,
    local: bool = false,
    timeout_ms: i64 = default_timeout_ms,
    ids_only: bool = false,
    paginate: bool = false,
    paginate_interval_ms: i64 = 0,
    auth: auth.Flags = .{},
    /// A lone `-` was given: read filters from stdin.
    stdin: bool = false,
    /// Ask each author's own write relays.
    outbox: bool = false,
    outbox_per_pubkey: u32 = 3,
    /// Relays to find relay lists through, for `outbox`.
    bootstrap: []const []const u8 = &.{},
};

/// How long a run waits on relays still answering, once they are reached.
/// Reaching them has its own, shorter bound (`dial.default_timeout_ms`).
///
/// Thirty seconds: long enough for a slow relay on a slow link, short enough
/// that a script does not hang on one gone quiet.
pub const default_timeout_ms: i64 = 30_000;

/// The most events one page asks for. Relays commonly cap a page lower than
/// this, which is why a short page does not end a paginated run: only an
/// empty one does.
const page_size: u32 = 500;

/// The most JSON read from stdin.
const max_stdin_bytes = 1 << 20;

const Collected = filterflags.Collected;

pub const ParseError = filterflags.ParseError;

/// A duration in milliseconds: a bare number, or one followed by `ms`, `s` or `m`.
fn parseInterval(v: []const u8) ?i64 {
    var digits = v;
    var mult: i64 = 1;
    if (std.mem.endsWith(u8, v, "ms")) {
        digits = v[0 .. v.len - 2];
    } else if (std.mem.endsWith(u8, v, "s")) {
        digits = v[0 .. v.len - 1];
        mult = 1000;
    } else if (std.mem.endsWith(u8, v, "m")) {
        digits = v[0 .. v.len - 1];
        mult = 60_000;
    }
    const n = std.fmt.parseInt(i64, digits, 10) catch return null;
    if (n < 0) return null;
    return std.math.mul(i64, n, mult) catch null;
}

/// Reads the flags into a filter. The relays are whatever is left over, except
/// an argument that starts with `{`, which is a filter in JSON and goes to
/// `jsons`.
///
/// The filter's slices point into `flags`, which the caller keeps alive.
pub fn parse(
    gpa: std.mem.Allocator,
    args: []const []const u8,
    flags: *filterflags.Flags,
    relays: *Collected([]const u8),
    jsons: *Collected([]const u8),
    bootstrap: *Collected([]const u8),
    err: *std.Io.Writer,
) !?Request {
    var bare = false;
    var stream = false;
    var local = false;
    var ids_only = false;
    var paginate = false;
    var paginate_interval_ms: i64 = 0;
    var store_path: ?[]const u8 = null;
    var timeout_ms: i64 = default_timeout_ms;
    var auth_flags: auth.Flags = .{};
    var from_stdin = false;
    var use_outbox = false;
    var per_pubkey: u32 = 3;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "--help" })) return null;
        // `-h` names the `h` tag when a value follows, and asks for help alone.
        if (std.mem.eql(u8, a, "-h") and i + 1 >= args.len) return null;
        switch (auth_flags.take(args, &i)) {
            .taken => continue,
            .missing_value => {
                try err.print("deed req: '{s}' needs a value\n", .{a});
                return ParseError.Usage;
            },
            .not_mine => {},
        }
        if (std.mem.eql(u8, a, "-")) {
            from_stdin = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--bare")) {
            bare = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--stream")) {
            stream = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--local")) {
            local = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--ids-only")) {
            ids_only = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--paginate")) {
            paginate = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--outbox")) {
            use_outbox = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "{")) {
            if (!jsons.push(a)) {
                try err.writeAll("deed req: too many filters\n");
                return ParseError.Usage;
            }
            continue;
        }
        if (!std.mem.startsWith(u8, a, "-")) {
            if (!relays.push(a)) {
                try err.writeAll("deed req: too many relays\n");
                return ParseError.Usage;
            }
            continue;
        }

        const takes_value = filterflags.isFilterFlag(a) or
            cli.isOneOf(a, &.{ "--store", "--timeout", "--paginate-interval", "-n", "--outbox-relays-per-pubkey", "-r", "--relay" });
        if (!takes_value) {
            try err.print("deed req: unknown option '{s}'\n", .{a});
            return ParseError.Usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed req: '{s}' needs a value\n", .{a});
            return ParseError.Usage;
        }
        const v = args[i];

        if (filterflags.isFilterFlag(a)) {
            try flags.accept(gpa, "req", a, v, err);
        } else if (std.mem.eql(u8, a, "--store")) {
            store_path = v;
        } else if (std.mem.eql(u8, a, "--timeout")) {
            timeout_ms = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed req: '{s}' is not a number of milliseconds\n", .{v});
                return ParseError.BadValue;
            };
        } else if (cli.isOneOf(a, &.{ "-n", "--outbox-relays-per-pubkey" })) {
            per_pubkey = std.fmt.parseInt(u32, v, 10) catch 0;
            if (per_pubkey == 0) {
                try err.print("deed req: '{s}' is not a number of relays, at least 1\n", .{v});
                return ParseError.BadValue;
            }
        } else if (cli.isOneOf(a, &.{ "-r", "--relay" })) {
            if (!bootstrap.push(v)) {
                try err.writeAll("deed req: too many --relay values\n");
                return ParseError.Usage;
            }
        } else if (std.mem.eql(u8, a, "--paginate-interval")) {
            paginate_interval_ms = parseInterval(v) orelse {
                try err.print("deed req: '{s}' is not a duration like 500, 500ms or 2s\n", .{v});
                return ParseError.BadValue;
            };
        }
    }

    if (paginate and (stream or local)) {
        try err.writeAll("deed req: --paginate cannot be combined with --stream or --local\n");
        return ParseError.Usage;
    }
    if (ids_only and stream) {
        try err.writeAll("deed req: --ids-only cannot be combined with --stream\n");
        return ParseError.Usage;
    }

    if (use_outbox and (stream or local or paginate)) {
        try err.writeAll("deed req: --outbox cannot be combined with --stream, --paginate or --local\n");
        return ParseError.Usage;
    }

    return .{
        .filter = flags.finish(),
        .relays = relays.slice() orelse &.{},
        .bare = bare,
        .store_path = store_path,
        .stream = stream,
        .local = local,
        .timeout_ms = timeout_ms,
        .ids_only = ids_only,
        .paginate = paginate,
        .paginate_interval_ms = paginate_interval_ms,
        .auth = auth_flags,
        .stdin = from_stdin,
        .outbox = use_outbox,
        .outbox_per_pubkey = per_pubkey,
        .bootstrap = bootstrap.slice() orelse &.{},
    };
}

/// The subscription id every run uses.
///
/// Fixed rather than random: one subscription per process, closed when the
/// process ends, so a unique id would buy nothing and would make the envelope
/// this prints different every time it is run, which is worse for a tool whose
/// output people paste into issues.
pub const subscription_id = "deed";

/// The end of the JSON value that starts at `text[0]`, which must be `{` or `[`.
fn valueEnd(text: []const u8) ?usize {
    var depth: usize = 0;
    var in_string = false;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (in_string) {
            if (c == '\\') {
                i += 1;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                depth -= 1;
                if (depth == 0) return i + 1;
            },
            else => {},
        }
    }
    return null;
}

/// Reads every top-level JSON value in `text`: an object is one filter, an
/// array is a list of them. Slices of the filters live in `arena`.
pub fn parseJsonFilters(
    arena: std.mem.Allocator,
    verb: []const u8,
    text: []const u8,
    list: *std.ArrayList(filter.Filter),
    err: *std.Io.Writer,
) !void {
    var rest = std.mem.trim(u8, text, " \t\r\n,");
    while (rest.len > 0) {
        if (rest[0] != '{' and rest[0] != '[') {
            try err.print("deed {s}: the filter is not valid JSON\n", .{verb});
            return ParseError.BadValue;
        }
        const end = valueEnd(rest) orelse {
            try err.print("deed {s}: the filter is not valid JSON\n", .{verb});
            return ParseError.BadValue;
        };
        const piece = rest[0..end];
        if (piece[0] == '{') {
            try list.append(arena, try filterflags.parseJson(arena, verb, piece, err));
        } else {
            const v = std.json.parseFromSliceLeaky(std.json.Value, arena, piece, .{}) catch {
                try err.print("deed {s}: the filter is not valid JSON\n", .{verb});
                return ParseError.BadValue;
            };
            for (v.array.items) |item| {
                try list.append(arena, try filterflags.fromValue(arena, verb, item, err));
            }
        }
        rest = std.mem.trim(u8, rest[end..], " \t\r\n,");
    }
}

const StdinArrival = union(enum) {
    read: anyerror![]u8,
    timer: std.Io.Cancelable!void,
};

fn readAll(arena: std.mem.Allocator, r: *std.Io.Reader) anyerror![]u8 {
    return r.allocRemaining(arena, .limited(max_stdin_bytes));
}

/// All of `r`, or `error.Timeout` when it has not ended within `timeout_ms`.
fn readStdin(arena: std.mem.Allocator, io: std.Io, r: *std.Io.Reader, timeout_ms: i64) ![]u8 {
    var buf: [2]StdinArrival = undefined;
    var sel = std.Io.Select(StdinArrival).init(io, &buf);
    var result: anyerror![]u8 = error.Timeout;
    var started = false;
    if (sel.concurrent(.read, readAll, .{ arena, r })) {
        started = true;
        sel.concurrent(.timer, std.Io.sleep, .{ io, .fromMilliseconds(timeout_ms), .awake }) catch {};
        if (sel.await()) |first| switch (first) {
            .read => |v| result = v,
            .timer => {},
        } else |_| {}
    } else |_| {
        // No second thread to read on: read inline, as unbounded as before.
        result = readAll(arena, r);
    }
    if (started) {
        while (sel.cancel()) |late| switch (late) {
            .read => |v| if (v) |text| {
                result = text;
            } else |_| {},
            .timer => {},
        };
    }
    return result;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var buf: [4096]u8 = undefined;
    // Streaming for the reason `main` gives for the writers. Stdin is read
    // only for an explicit `-`, once the command line has been understood.
    var reader = std.Io.File.stdin().readerStreaming(io, &buf);
    return runWith(gpa, io, args, &reader.interface, out, err);
}

/// `run`, with the stdin to read a JSON filter from given (or none).
pub fn runWith(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    stdin: ?*std.Io.Reader,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var flags: filterflags.Flags = .{};
    var relays: Collected([]const u8) = .{};
    var jsons: Collected([]const u8) = .{};
    var bootstrap: Collected([]const u8) = .{};

    const req = parse(gpa, args, &flags, &relays, &jsons, &bootstrap, err) catch |e| {
        return switch (e) {
            ParseError.Usage => cli.exit_usage,
            ParseError.BadValue => cli.exit_fail,
            else => return e,
        };
    } orelse {
        try out.writeAll(usage);
        return cli.exit_ok;
    };

    // The filters: JSON given as arguments and, with `-`, on stdin; else the
    // flags alone. Flags lay over whichever JSON there was.
    var filters: std.ArrayList(filter.Filter) = .empty;
    var parsed_ok = true;
    parseAll: {
        for (jsons.items[0..jsons.len]) |text| {
            parseJsonFilters(arena, "req", text, &filters, err) catch |e| switch (e) {
                ParseError.BadValue => {
                    parsed_ok = false;
                    break :parseAll;
                },
                else => return e,
            };
        }
        if (req.stdin) if (stdin) |r| {
            const text = readStdin(arena, io, r, req.timeout_ms) catch |e| switch (e) {
                error.OutOfMemory => return e,
                error.StreamTooLong => {
                    try err.print("deed req: the filter on stdin is longer than {d} bytes\n", .{max_stdin_bytes});
                    return cli.exit_fail;
                },
                error.Timeout => {
                    try err.print("deed req: nothing ended the filter on stdin within {d} ms\n", .{req.timeout_ms});
                    return cli.exit_fail;
                },
                else => {
                    try err.print("deed req: stdin could not be read: {s}\n", .{@errorName(e)});
                    return cli.exit_fail;
                },
            };
            parseJsonFilters(arena, "req", text, &filters, err) catch |e| switch (e) {
                ParseError.BadValue => {
                    parsed_ok = false;
                    break :parseAll;
                },
                else => return e,
            };
        };
    }
    if (!parsed_ok) return cli.exit_fail;
    if (filters.items.len == 0) {
        try filters.append(arena, req.filter);
    } else if (flags.any()) {
        for (filters.items) |*f| f.* = try filterflags.overlay(arena, f.*, req.filter);
    }
    // A long list of ids goes out as several filters in the one REQ, never cut.
    const unsplit = filters.items;
    filters.items = try filterflags.splitLarge(arena, filters.items);

    // Answered from what is already kept, without dialling. This is the half
    // that makes keeping worth doing: a store nothing reads back is a log.
    if (req.local) {
        const path = req.store_path orelse {
            try err.writeAll("deed req: --local needs --store to read from\n");
            return cli.exit_usage;
        };
        var st = (try storepath.open(gpa, io, "req", path, .existing, err)) orelse return cli.exit_fail;
        defer st.deinit();

        // Each filter the caller wrote is answered whole: its pieces are run,
        // merged newest first, and cut to that filter's own limit.
        var results: std.ArrayList(nostr.store.QueryResult) = .empty;
        defer {
            for (results.items) |*r| r.deinit();
            results.deinit(gpa);
        }
        var merged: std.ArrayList(nostr.event.Event) = .empty;
        defer merged.deinit(gpa);
        var seen = std.AutoHashMap([32]u8, void).init(gpa);
        defer seen.deinit();
        for (unsplit) |whole| {
            const pieces = try filterflags.splitLarge(arena, &.{whole});
            const first = merged.items.len;
            var mark = std.AutoHashMap([32]u8, void).init(gpa);
            defer mark.deinit();
            for (pieces) |f| {
                const result = st.query(gpa, f) catch |e| {
                    try err.print("deed req: the store could not answer: {s}\n", .{@errorName(e)});
                    return cli.exit_fail;
                };
                try results.append(gpa, result);
                for (result.events) |ev| {
                    if ((try mark.fetchPut(ev.id, {})) != null) continue;
                    try merged.append(gpa, ev);
                }
            }
            std.mem.sort(nostr.event.Event, merged.items[first..], {}, newestFirst);
            if (whole.limit) |lim| {
                if (merged.items.len - first > lim) merged.shrinkRetainingCapacity(first + lim);
            }
        }
        std.mem.sort(nostr.event.Event, merged.items, {}, newestFirst);
        for (merged.items) |ev| {
            if ((try seen.fetchPut(ev.id, {})) != null) continue;
            if (req.ids_only) {
                try printId(gpa, out, ev.id);
                continue;
            }
            const json = try nostr.event.toJson(gpa, ev);
            defer gpa.free(json);
            try out.print("{s}\n", .{json});
        }
        return cli.exit_ok;
    }

    // No relay named: say what would be sent, and stop. The filter is the thing
    // worth seeing before it is asked of anybody.
    if (req.relays.len == 0 and !req.outbox) {
        if (req.bare) {
            for (filters.items) |f| {
                var list: std.ArrayList(u8) = .empty;
                defer list.deinit(gpa);
                try f.appendJson(&list, gpa);
                try out.print("{s}\n", .{list.items});
            }
        } else {
            const text = try message.encodeReq(gpa, subscription_id, filters.items);
            defer gpa.free(text);
            try out.print("{s}\n", .{text});
        }
        return cli.exit_ok;
    }

    const auth_opts = auth.resolve(gpa, req.auth, "req", err) catch |e| switch (e) {
        error.Usage => return cli.exit_usage,
        error.BadKey => return cli.exit_fail,
        else => |other| return other,
    };

    var store: ?nostr.store.Store = null;
    defer if (store) |*st| st.deinit();
    if (req.store_path) |path| {
        store = (try storepath.open(gpa, io, "req", path, .create, err)) orelse return cli.exit_fail;
    }
    const store_ptr: ?*nostr.store.Store = if (store) |*st| st else null;

    if (req.outbox) {
        if (try outboxRun(gpa, io, req, auth_opts, filters.items, store_ptr, out, err)) |code| return code;
    }

    if (req.relays.len == 0) {
        try err.writeAll("deed req: no relay to ask: name one\n");
        return cli.exit_usage;
    }

    if (req.paginate or req.ids_only) {
        return pages(gpa, io, req, auth_opts, filters.items, store_ptr, out, err);
    }

    const outcome = try relayset.query(gpa, io, req.relays, filters.items, out, err, .{
        .until_eose = !req.stream,
        .deadline_ms = req.timeout_ms,
        .store = store_ptr,
        .auth = auth_opts,
    });

    // Reaching no relay at all is a failed run. Reaching some is not: the
    // events that arrived are real, and every relay that did not answer was
    // named on stderr as it failed.
    if (outcome.store_failed) return cli.exit_fail;
    if (outcome.dialled == 0) {
        try err.writeAll("deed req: no relay answered\n");
        return cli.exit_fail;
    }
    return cli.exit_ok;
}

fn newestFirst(_: void, a: nostr.event.Event, b: nostr.event.Event) bool {
    if (a.created_at != b.created_at) return a.created_at > b.created_at;
    return std.mem.lessThan(u8, &a.id, &b.id);
}

/// One relay, and the part of the question it is asked.
const Task = struct {
    urls: []const []const u8,
    filters: []const filter.Filter,
    out: std.Io.Writer.Allocating,
    err: std.Io.Writer.Allocating,
    outcome: relayset.Outcome = .{},
    failed: bool = false,
};

fn runTask(gpa: std.mem.Allocator, io: std.Io, t: *Task, deadline_ms: i64, auth_opts: ?auth.Options) void {
    t.outcome = relayset.query(gpa, io, t.urls, t.filters, &t.out.writer, &t.err.writer, .{
        .until_eose = true,
        .deadline_ms = deadline_ms,
        .auth = auth_opts,
    }) catch {
        t.failed = true;
        return;
    };
}

/// How many relays are asked at once.
const wave_size = 16;

/// Asks each author's own write relays for that author. Returns null when no
/// filter names an author, so the caller carries on with the relays it was
/// given.
///
/// Relay lists come from `lookupMany`, one request per bootstrap relay. Each
/// relay is then asked only about the authors who write there, all relays at
/// once in waves, and what comes back is checked by the same code a plain run
/// uses, merged by id, stored when asked, and printed once.
fn outboxRun(
    gpa: std.mem.Allocator,
    io: std.Io,
    req: Request,
    auth_opts: ?auth.Options,
    filters: []const filter.Filter,
    store: ?*nostr.store.Store,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !?u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var index = std.AutoHashMap([32]u8, usize).init(a);
    var authors: std.ArrayList([32]u8) = .empty;
    for (filters) |f| {
        for (f.authors orelse continue) |pk| {
            if (index.contains(pk)) continue;
            try index.put(pk, authors.items.len);
            try authors.append(a, pk);
        }
    }
    if (authors.items.len == 0) return null;

    var boot: std.ArrayList([]const u8) = .empty;
    try boot.appendSlice(a, req.bootstrap);
    try outbox.appendEnvBootstrap(a, &boot);
    if (boot.items.len == 0) try boot.appendSlice(a, req.relays);
    if (boot.items.len == 0) {
        try err.writeAll("deed req: --outbox needs a relay to find relay lists through: name one (with --relay, DEED_RELAYS, or as an argument)\n");
        return cli.exit_usage;
    }

    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    var lists = try outbox.lookupMany(gpa, io, authors.items, .{
        .bootstrap = boot.items,
        .store = store,
        .timeout_ms = @min(req.timeout_ms, 10_000),
    }, err);
    defer lists.deinit();

    // relay -> the authors who write there
    const Group = struct { url: []const u8, member: []bool };
    var groups: std.ArrayList(Group) = .empty;
    var by_url: std.StringHashMap(usize) = .init(a);
    const reached = try a.alloc(bool, authors.items.len);
    @memset(reached, false);
    for (authors.items, 0..) |pk, ai| {
        const entry = lists.find(pk) orelse continue;
        var taken: u32 = 0;
        for (entry.relays) |r| {
            if (!r.write) continue;
            if (taken >= req.outbox_per_pubkey) break;
            const url = std.mem.trimEnd(u8, r.url, "/");
            const gop = try by_url.getOrPut(url);
            if (!gop.found_existing) {
                gop.value_ptr.* = groups.items.len;
                const member = try a.alloc(bool, authors.items.len);
                @memset(member, false);
                try groups.append(a, .{ .url = try a.dupe(u8, url), .member = member });
            }
            const g = groups.items[gop.value_ptr.*];
            if (!g.member[ai]) {
                g.member[ai] = true;
                taken += 1;
                reached[ai] = true;
            }
        }
    }

    var tasks: std.ArrayList(*Task) = .empty;
    defer for (tasks.items) |t| {
        t.out.deinit();
        t.err.deinit();
    };

    for (groups.items) |g| {
        const sub = try subsetFilters(a, filters, index, g.member, false);
        if (sub.len == 0) continue;
        const t = try a.create(Task);
        const urls = try a.alloc([]const u8, 1);
        urls[0] = g.url;
        t.* = .{ .urls = urls, .filters = sub, .out = .init(gpa), .err = .init(gpa) };
        try tasks.append(a, t);
    }

    // Authors nobody could place, and filters that name no author, go where
    // the caller said.
    var unplaced: usize = 0;
    for (reached) |r| {
        if (!r) unplaced += 1;
    }
    const rest = try subsetFilters(a, filters, index, reached, true);
    if (rest.len > 0) {
        if (req.relays.len > 0) {
            const t = try a.create(Task);
            t.* = .{ .urls = req.relays, .filters = rest, .out = .init(gpa), .err = .init(gpa) };
            try tasks.append(a, t);
        } else if (unplaced > 0) {
            try err.print("deed req: {d} authors have no known relay and none was named, so they are not asked\n", .{unplaced});
        }
    }

    var seen = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen.deinit();
    var kept: std.ArrayList(nostr.event.Parsed) = .empty;
    defer {
        for (kept.items) |*p| p.deinit();
        kept.deinit(gpa);
    }
    var relays_answered: usize = 0;
    var relays_asked: usize = 0;

    var wave: usize = 0;
    while (wave < tasks.items.len) : (wave += wave_size) {
        const left = req.timeout_ms - (std.Io.Timestamp.now(io, .awake).toMilliseconds() - started);
        if (left <= 0) {
            try err.writeAll("deed req: --timeout ran out before every relay was asked\n");
            break;
        }
        const end = @min(wave + wave_size, tasks.items.len);
        var group: std.Io.Group = .init;
        for (tasks.items[wave..end]) |t| {
            group.concurrent(io, runTask, .{ gpa, io, t, left, auth_opts }) catch runTask(gpa, io, t, left, auth_opts);
        }
        try group.await(io);
        for (tasks.items[wave..end]) |t| {
            relays_asked += t.urls.len;
            relays_answered += t.outcome.dialled;
            if (t.err.written().len > 0) try err.writeAll(t.err.written());
            var lines = std.mem.splitScalar(u8, t.out.written(), '\n');
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                var parsed = nostr.event.fromJson(gpa, line) catch continue;
                if ((try seen.fetchPut(parsed.value.id, {})) != null) {
                    parsed.deinit();
                    continue;
                }
                try kept.append(gpa, parsed);
            }
        }
    }

    if (store) |st| {
        var at: usize = 0;
        while (at < kept.items.len) {
            const n = @min(kept.items.len - at, 512);
            var events: [512]nostr.event.Event = undefined;
            var outcomes: [512]nostr.store.IngestResult = undefined;
            for (kept.items[at .. at + n], 0..) |p, i| events[i] = p.value;
            st.ingestBatch(gpa, events[0..n], .{}, outcomes[0..n]) catch {
                try err.writeAll("deed req: the store could not take the events\n");
                return cli.exit_fail;
            };
            at += n;
        }
    }
    for (kept.items) |p| {
        if (req.ids_only) {
            try printId(gpa, out, p.value.id);
            continue;
        }
        const json = try nostr.event.toJson(gpa, p.value);
        defer gpa.free(json);
        try out.print("{s}\n", .{json});
    }

    const placed = authors.items.len - unplaced;
    try err.print("deed req: reached {d} of {d} authors through their own relays ({d} of {d} relays answered)", .{ placed, authors.items.len, relays_answered, relays_asked });
    if (unplaced > 0) try err.print("; {d} had no known relay", .{unplaced});
    try err.writeAll("\n");

    if (relays_answered == 0) {
        try err.writeAll("deed req: no relay answered\n");
        return cli.exit_fail;
    }
    return cli.exit_ok;
}

/// The filters narrowed to the authors flagged in `member`. A filter with no
/// authors is kept whole only when `with_authorless` (it belongs to the relays
/// the caller named, not to anyone's own). A filter whose authors all fall
/// outside `member` is dropped.
fn subsetFilters(
    a: std.mem.Allocator,
    filters: []const filter.Filter,
    index: std.AutoHashMap([32]u8, usize),
    member: []const bool,
    with_authorless: bool,
) ![]filter.Filter {
    var list: std.ArrayList(filter.Filter) = .empty;
    for (filters) |f| {
        const as = f.authors orelse {
            if (with_authorless) try list.append(a, f);
            continue;
        };
        var keep: std.ArrayList([32]u8) = .empty;
        for (as) |pk| {
            const i = index.get(pk) orelse continue;
            // `rest` passes the reached flags: it wants the ones that are not.
            if (member[i] != with_authorless) try keep.append(a, pk);
        }
        if (keep.items.len == 0) continue;
        var nf = f;
        nf.authors = keep.items;
        try list.append(a, nf);
    }
    return list.items;
}

fn printId(gpa: std.mem.Allocator, out: *std.Io.Writer, id: [32]u8) !void {
    const h = try nostr.hex.encode(gpa, &id);
    defer gpa.free(h);
    try out.print("{s}\n", .{h});
}

/// Asks the relays page by page, or once when only the ids are wanted.
///
/// Each page is a whole `relayset.query` whose output is read back to learn the
/// oldest `created_at` it held, so the next page can ask for everything before
/// it. A page that adds nothing new ends the run, which also stops a relay that
/// ignores `until` from being asked the same thing forever.
fn pages(
    gpa: std.mem.Allocator,
    io: std.Io,
    req: Request,
    auth_opts: ?auth.Options,
    filters: []const filter.Filter,
    store: ?*nostr.store.Store,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var remaining: ?u64 = if (req.paginate) (if (filters[0].limit) |l| l else null) else null;
    var cursor: ?i64 = null;

    var seen = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen.deinit();
    const page_filters = try gpa.alloc(filter.Filter, filters.len);
    defer gpa.free(page_filters);

    while (true) {
        for (filters, page_filters) |f, *pf| {
            pf.* = f;
            if (req.paginate) {
                if (cursor) |c| pf.until = if (f.until) |u| @min(u, c) else c;
                const want: u64 = @min(remaining orelse page_size, page_size);
                pf.limit = @intCast(want);
            }
        }

        var capture: std.Io.Writer.Allocating = .init(gpa);
        defer capture.deinit();
        const outcome = try relayset.query(gpa, io, req.relays, page_filters, &capture.writer, err, .{
            .until_eose = true,
            .deadline_ms = req.timeout_ms,
            .store = store,
            .auth = auth_opts,
        });
        if (outcome.store_failed) return cli.exit_fail;
        if (outcome.dialled == 0) {
            try err.writeAll("deed req: no relay answered\n");
            return cli.exit_fail;
        }

        var fresh: usize = 0;
        var oldest: ?i64 = null;
        var lines = std.mem.splitScalar(u8, capture.written(), '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var parsed = nostr.event.fromJson(gpa, line) catch continue;
            defer parsed.deinit();
            const ev = parsed.value;
            oldest = if (oldest) |o| @min(o, ev.created_at) else ev.created_at;
            if (remaining) |r| if (r == 0) continue;
            if ((try seen.fetchPut(ev.id, {})) != null) continue;
            if (req.ids_only) {
                try printId(gpa, out, ev.id);
            } else {
                try out.print("{s}\n", .{line});
            }
            fresh += 1;
            if (remaining) |*r| r.* -= 1;
        }

        if (!req.paginate or fresh == 0) break;
        if (remaining) |r| if (r == 0) break;
        const next = (oldest orelse break) - 1;
        // Below every filter's `since`, nothing is left to ask for.
        var any_left = false;
        for (filters) |f| {
            if (f.since == null or f.since.? <= next) any_left = true;
        }
        if (!any_left) break;
        cursor = next;
        if (req.paginate_interval_ms > 0) {
            try std.Io.sleep(io, .fromMilliseconds(req.paginate_interval_ms), .awake);
        }
    }
    return cli.exit_ok;
}

const Run = struct { code: u8, out: []const u8, err: []const u8 };

fn runReq(args: []const []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    const code = try runWith(std.testing.allocator, std.testing.io, args, null, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

test "a filter with no relay is printed rather than sent" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "-l", "5" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("[\"REQ\",\"deed\",{\"kinds\":[1],\"limit\":5}]\n", r.out);
    try std.testing.expectEqualStrings("", r.err);
}

test "--bare drops the envelope and keeps the filter" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "--bare" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("{\"kinds\":[1]}\n", r.out);
}

test "a repeated flag collects rather than replaces" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "-k", "6", "-k", "16", "--bare" }, &ob, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[1,6,16]}\n", r.out);
}

test "an author is taken as an npub or as hex, and means the same thing" {
    const hex_key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const npub = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d";

    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const from_hex = try runReq(&.{ "-a", hex_key, "--bare" }, &ob, &eb);

    var ob2: [4096]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const from_npub = try runReq(&.{ "-a", npub, "--bare" }, &ob2, &eb2);

    try std.testing.expectEqualStrings(from_hex.out, from_npub.out);
    // And what goes on the wire is hex, which is what a relay reads.
    try std.testing.expect(std.mem.indexOf(u8, from_hex.out, hex_key) != null);
}

test "an uppercase npub or note is taken the same as a lowercase one" {
    const gpa = std.testing.allocator;
    const key = [_]u8{0x55} ** 32;
    const npub = try nostr.nip19.encodeNpub(gpa, key);
    defer gpa.free(npub);
    const note = try nostr.nip19.encodeNote(gpa, key);
    defer gpa.free(note);
    const npub_up = try std.ascii.allocUpperString(gpa, npub);
    defer gpa.free(npub_up);
    const note_up = try std.ascii.allocUpperString(gpa, note);
    defer gpa.free(note_up);

    try std.testing.expectEqual(key, filterflags.idOrKey(gpa, npub_up).?);
    try std.testing.expectEqual(key, filterflags.idOrKey(gpa, note_up).?);

    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const lower = try runReq(&.{ "-a", npub, "--bare" }, &ob, &eb);
    var ob2: [4096]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const upper = try runReq(&.{ "-a", npub_up, "--bare" }, &ob2, &eb2);
    try std.testing.expectEqualStrings(lower.out, upper.out);
}

test "tag filters land under their own letter" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-t", "zig", "-t", "nostr", "--bare" }, &ob, &eb);
    try std.testing.expectEqualStrings("{\"#t\":[\"zig\",\"nostr\"]}\n", r.out);
}

test "an empty filter is a legal subscription, not an error" {
    // `{}` asks a relay for everything. It is a thing somebody may genuinely
    // want to see the envelope for, so printing it beats refusing it.
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{"--bare"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings("{}\n", r.out);
}

test "the exit codes say which kind of wrong it was" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    // A value that will not parse: the command ran and the value was bad.
    const bad_value = try runReq(&.{ "-k", "notanumber" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, bad_value.code);
    try std.testing.expectEqualStrings("", bad_value.out);

    // A flag nobody knows: the command was not understood.
    var ob2: [1024]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    const unknown = try runReq(&.{"--nope"}, &ob2, &eb2);
    try std.testing.expectEqual(cli.exit_usage, unknown.code);

    // A flag with nothing after it.
    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    const dangling = try runReq(&.{"-k"}, &ob3, &eb3);
    try std.testing.expectEqual(cli.exit_usage, dangling.code);

    // A key that is neither hex nor bech32.
    var ob4: [1024]u8 = undefined;
    var eb4: [1024]u8 = undefined;
    const bad_key = try runReq(&.{ "-a", "alice" }, &ob4, &eb4);
    try std.testing.expectEqual(cli.exit_fail, bad_key.code);
}

test "help is printed on stdout and succeeds" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{"--help"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.out, "deed req") != null);
}

test "--local reads only a store that exists, and creates nothing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(std.testing.io, &root);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/typo/store.mdb", .{root[0..root_len]});

    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "--store", path, "--local" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "there is no store at ") != null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "typo", .{}));
}

test "--store creates the directories a new store needs" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/a/b/store.mdb", .{root[0..root_len]});

    // A closed port: the store is opened before any relay is dialled, and the
    // refused dial ends the run at once.
    var closed = try testrelay.listen(io);
    const port = closed.socket.address.ip4.port;
    closed.deinit(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, port);

    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-k", "1", "--store", path, url }, &ob, &eb);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "the store") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "no relay answered") != null);
    _ = try tmp.dir.statFile(io, "a/b/store.mdb", .{});
}

fn runReqStdin(args: []const []const u8, stdin: []const u8, out_buf: []u8, err_buf: []u8) !Run {
    var out: std.Io.Writer = .fixed(out_buf);
    var err: std.Io.Writer = .fixed(err_buf);
    var reader: std.Io.Reader = .fixed(stdin);
    const code = try runWith(std.testing.allocator, std.testing.io, args, &reader, &out, &err);
    return .{ .code = code, .out = out.buffered(), .err = err.buffered() };
}

test "--local with a split filter is cut to the limit and printed newest first" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/s.mdb", .{root[0..root_len]});

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp_a = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
    const kp_b = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);
    {
        var err_buf: [256]u8 = undefined;
        var err: std.Io.Writer = .fixed(&err_buf);
        var st = (try storepath.open(std.testing.allocator, io, "req", path, .create, &err)).?;
        defer st.deinit();
        for (0..15) |i| {
            const t: i64 = @intCast(1000 + 2 * i);
            _ = try st.putEvent(std.testing.allocator, try nostr.event.create(a, signer, kp_a, t, 1, &.{}, "a", null));
            _ = try st.putEvent(std.testing.allocator, try nostr.event.create(a, signer, kp_b, t + 1, 1, &.{}, "b", null));
        }
    }

    // A is in the first chunk of authors, B in the second.
    var json: std.ArrayList(u8) = .empty;
    try json.appendSlice(a, "{\"kinds\":[1],\"authors\":[");
    for (0..600) |i| {
        if (i > 0) try json.append(a, ',');
        var pk: [32]u8 = [_]u8{0} ** 32;
        if (i == 0) pk = kp_a.public_key else if (i == 550) pk = kp_b.public_key else {
            pk[30] = @truncate(i >> 8);
            pk[31] = @truncate(i);
            pk[0] = 0x77;
        }
        try json.print(a, "\"{x}\"", .{&pk});
    }
    try json.appendSlice(a, "]}");

    var ob: [16384]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReqStdin(&.{ "-l", "10", "--store", path, "--local", "-" }, json.items, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    var lines = std.mem.splitScalar(u8, r.out, '\n');
    var count: usize = 0;
    var prev: i64 = std.math.maxInt(i64);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try nostr.event.fromJson(std.testing.allocator, line);
        defer parsed.deinit();
        try std.testing.expect(parsed.value.created_at < prev);
        prev = parsed.value.created_at;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 10), count);
    try std.testing.expectEqual(@as(i64, 1020), prev);
}

test "search, generic tags, d and h land in the filter" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "--search", "best nostr", "-T", "r=wss://x", "-d", "slug", "-h", "grp", "-t", "zig", "--bare" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(
        "{\"#t\":[\"zig\"],\"#r\":[\"wss://x\"],\"#d\":[\"slug\"],\"#h\":[\"grp\"],\"search\":\"best nostr\"}\n",
        r.out,
    );
}

test "-h alone is help, and -h with a value is the h tag" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const help = try runReq(&.{"-h"}, &ob, &eb);
    try std.testing.expect(std.mem.indexOf(u8, help.out, "deed req") != null);
    var ob2: [4096]u8 = undefined;
    const tag = try runReq(&.{ "-h", "g", "--bare" }, &ob2, &eb);
    try std.testing.expectEqualStrings("{\"#h\":[\"g\"]}\n", tag.out);
}

test "a time can be a span or a date" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "-s", "2026-10-01", "-u", "1790899200", "--bare" }, &ob, &eb);
    try std.testing.expectEqualStrings("{\"since\":1790812800,\"until\":1790899200}\n", r.out);
    var ob2: [1024]u8 = undefined;
    const bad = try runReq(&.{ "-s", "lately" }, &ob2, &eb);
    try std.testing.expectEqual(cli.exit_fail, bad.code);
}

test "filters given as JSON arguments are printed as one REQ, with flags laid over" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try runReq(&.{ "{\"kinds\":[1],\"limit\":2}", "{\"kinds\":[7]}", "-l", "9" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expectEqualStrings(
        "[\"REQ\",\"deed\",{\"kinds\":[1],\"limit\":9},{\"kinds\":[7],\"limit\":9}]\n",
        r.out,
    );
    var ob2: [4096]u8 = undefined;
    const bare = try runReq(&.{ "{\"kinds\":[1]}", "{\"kinds\":[7]}", "--bare" }, &ob2, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[1]}\n{\"kinds\":[7]}\n", bare.out);
}

test "a filter on stdin is read, several are kept, and a bad one is refused" {
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const one = try runReqStdin(&.{ "-", "--bare" }, "{\"kinds\": [1],\n \"#t\": [\"a\"]}\n", &ob, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[1],\"#t\":[\"a\"]}\n", one.out);

    var ob2: [4096]u8 = undefined;
    const many = try runReqStdin(&.{ "-", "-l", "4" }, "{\"kinds\":[1]}\n{\"kinds\":[7]}\n", &ob2, &eb);
    try std.testing.expectEqualStrings("[\"REQ\",\"deed\",{\"kinds\":[1],\"limit\":4},{\"kinds\":[7],\"limit\":4}]\n", many.out);

    var ob3: [4096]u8 = undefined;
    const array = try runReqStdin(&.{ "-", "--bare" }, "[{\"kinds\":[1]},{\"kinds\":[7]}]", &ob3, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[1]}\n{\"kinds\":[7]}\n", array.out);

    var ob4: [4096]u8 = undefined;
    const bad = try runReqStdin(&.{ "-", "--bare" }, "{\"kinds\": nope}\n", &ob4, &eb);
    try std.testing.expectEqual(cli.exit_fail, bad.code);
    try std.testing.expect(std.mem.indexOf(u8, bad.err, "deed req: the filter is not valid JSON") != null);

    // Without a lone -, stdin is not read at all, whatever is on it.
    var ob5: [4096]u8 = undefined;
    const args_win = try runReqStdin(&.{ "{\"kinds\":[2]}", "--bare" }, "{\"kinds\":[9]}", &ob5, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[2]}\n", args_win.out);
    var ob6: [4096]u8 = undefined;
    const flags_only = try runReqStdin(&.{ "-k", "7", "--bare" }, "{\"kinds\":[9]}", &ob6, &eb);
    try std.testing.expectEqualStrings("{\"kinds\":[7]}\n", flags_only.out);
}

/// A reader whose input never ends: it waits, as a pipe nobody closes does.
const Stuck = struct {
    io: std.Io,
    interface: std.Io.Reader,

    fn init(io: std.Io, buf: []u8) Stuck {
        return .{ .io = io, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    fn stream(r: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Stuck = @alignCast(@fieldParentPtr("interface", r));
        while (true) self.io.sleep(.fromMilliseconds(50), .awake) catch return error.ReadFailed;
    }
};

test "a stdin that never ends is given up on at --timeout, not waited for" {
    const io = std.testing.io;
    var buf: [64]u8 = undefined;
    var stuck = Stuck.init(io, &buf);
    var out_buf: [256]u8 = undefined;
    var err_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var err: std.Io.Writer = .fixed(&err_buf);
    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const code = try runWith(std.testing.allocator, io, &.{ "-", "--timeout", "300" }, &stuck.interface, &out, &err);
    const took = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;
    try std.testing.expectEqual(cli.exit_fail, code);
    try std.testing.expect(took < 3_000);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "within 300 ms") != null);
}

test "--auth answers a relay that holds events behind NIP-42, and --sec needs --auth" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var script: relayset.AuthRelay = .{ .want_url = undefined, .event = try relayset.testEvent(arena, io, "members only") };
    var r: testrelay.Relay = undefined;
    try r.startCustom(io, relayset.AuthRelay.handle, &script);
    defer r.stop(io);
    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, r.port());
    script.want_url = url;

    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const sec = "44" ** 32;
    const code = try runWith(da.allocator(), io, &.{ "-k", "1", "--auth", "--sec", sec, url }, null, &out.writer, &err.writer);
    try std.testing.expectEqual(cli.exit_ok, code);
    try std.testing.expectEqual(@as(usize, 1), script.auths);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "members only") != null);

    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    try std.testing.expectEqual(cli.exit_usage, (try runReq(&.{ "--sec", sec, url }, &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_usage, (try runReq(&.{"--sec"}, &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_fail, (try runReq(&.{ "--auth", "--sec", "nope", url }, &ob, &eb)).code);
}

test "repeated -i is never truncated: 100 ids go in one filter, 1200 in three" {
    const gpa = std.testing.allocator;
    for ([_]usize{ 100, 1200 }) |n| {
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(gpa);
        var store: std.ArrayList([]u8) = .empty;
        defer {
            for (store.items) |b| gpa.free(b);
            store.deinit(gpa);
        }
        try args.append(gpa, "--bare");
        for (0..n) |k| {
            const id = try std.fmt.allocPrint(gpa, "{x:0>64}", .{k + 1});
            try store.append(gpa, id);
            try args.append(gpa, "-i");
            try args.append(gpa, id);
        }
        const ob = try gpa.alloc(u8, 1 << 20);
        defer gpa.free(ob);
        var eb: [1024]u8 = undefined;
        const r = try runReq(args.items, ob, &eb);
        try std.testing.expectEqual(cli.exit_ok, r.code);
        try std.testing.expectEqual(@as(usize, if (n == 100) 1 else 3), std.mem.count(u8, r.out, "\n"));
        // Every id is somewhere in what would be sent.
        for (store.items) |id| try std.testing.expect(std.mem.indexOf(u8, r.out, id) != null);
    }
}

test "more ids than a command line can hold is refused, not cut" {
    const gpa = std.testing.allocator;
    const n = filterflags.max_keys + 1;
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(gpa);
    const id = "ab" ** 32;
    for (0..n) |_| {
        try args.append(gpa, "-i");
        try args.append(gpa, id);
    }
    var ob: [64]u8 = undefined;
    var eb: [256]u8 = undefined;
    const r = try runReq(args.items, &ob, &eb);
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expect(std.mem.indexOf(u8, r.err, "too many ids") != null);
}

test "combining flags that cannot go together is a usage error" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    try std.testing.expectEqual(cli.exit_usage, (try runReq(&.{ "--paginate", "--stream" }, &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_usage, (try runReq(&.{ "--ids-only", "--stream" }, &ob, &eb)).code);
    try std.testing.expectEqual(cli.exit_fail, (try runReq(&.{ "--paginate-interval", "soon" }, &ob, &eb)).code);
}

test "an interval is milliseconds, or carries its unit" {
    try std.testing.expectEqual(@as(?i64, 250), parseInterval("250"));
    try std.testing.expectEqual(@as(?i64, 250), parseInterval("250ms"));
    try std.testing.expectEqual(@as(?i64, 2000), parseInterval("2s"));
    try std.testing.expectEqual(@as(?i64, 60000), parseInterval("1m"));
    try std.testing.expect(parseInterval("-1") == null);
    try std.testing.expect(parseInterval("x") == null);
}

const testrelay = @import("testrelay.zig");

/// A relay that holds a fixed run of events, newest first, and answers a REQ
/// the way a relay should: nothing newer than `until`, no more than `limit`
/// (and no more than `max_page`), then EOSE.
const PageRelay = struct {
    events: []const []const u8,
    times: []const i64,
    max_page: usize = 1000,
    ignore_until: bool = false,
    reqs: std.atomic.Value(usize) = .init(0),

    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
        const self: *PageRelay = @ptrCast(@alignCast(ctx.?));
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const v = try std.json.parseFromSliceLeaky(std.json.Value, a, frame, .{});
        const items = v.array.items;
        if (!std.mem.eql(u8, items[0].string, "REQ")) return;
        _ = self.reqs.fetchAdd(1, .monotonic);
        const f = items[2].object;
        var until: i64 = std.math.maxInt(i64);
        if (!self.ignore_until) if (f.get("until")) |u| {
            until = u.integer;
        };
        var limit: usize = self.max_page;
        if (f.get("limit")) |l| limit = @min(limit, @as(usize, @intCast(l.integer)));
        var sent: usize = 0;
        for (self.events, self.times) |e, t| {
            if (t > until) continue;
            if (sent >= limit) break;
            const msg = try std.fmt.allocPrint(a, "[\"EVENT\",\"{s}\",{s}]", .{ items[1].string, e });
            try testrelay.sendText(w, msg);
            sent += 1;
        }
        try testrelay.sendText(w, try std.fmt.allocPrint(a, "[\"EOSE\",\"{s}\"]", .{items[1].string}));
    }
};

/// Seven signed kind-1 events at 700, 600 ... 100.
const Held = struct {
    arena: std.heap.ArenaAllocator,
    json: [7][]const u8 = undefined,
    times: [7]i64 = undefined,

    fn init() !Held {
        var h: Held = .{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator) };
        errdefer h.arena.deinit();
        const a = h.arena.allocator();
        var signer = try nostr.keys.Signer.initRandomized(std.testing.io);
        defer signer.deinit();
        const kp = try signer.keyPairFromSecretKey([_]u8{0x11} ** 32);
        for (0..7) |i| {
            const t: i64 = @intCast((7 - i) * 100);
            const content = try std.fmt.allocPrint(a, "n{d}", .{t});
            const ev = try nostr.event.create(a, signer, kp, t, 1, &.{}, content, null);
            h.json[i] = try nostr.event.toJson(a, ev);
            h.times[i] = t;
        }
        return h;
    }
};

/// Runs `req` against a paging relay that serves `pages` connections, and
/// returns the output and how many REQs the relay saw.
fn pagedRun(held: *const Held, relay_cfg: PageRelay, pages_n: usize, args: []const []const u8, ob: []u8, eb: []u8) !struct { run: Run, reqs: usize } {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();

    var state = relay_cfg;
    state.events = &held.json;
    state.times = &held.times;
    var relay: testrelay.Relay = undefined;
    try relay.startFor(io, .custom, pages_n);
    relay.custom = PageRelay.handle;
    relay.custom_ctx = &state;
    defer relay.stop(io);

    var url_buf: [40]u8 = undefined;
    const url = try testrelay.url(&url_buf, relay.port());
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, args);
    try argv.append(gpa, url);

    var out: std.Io.Writer = .fixed(ob);
    var err: std.Io.Writer = .fixed(eb);
    const code = try runWith(gpa, io, argv.items, null, &out, &err);
    return .{ .run = .{ .code = code, .out = out.buffered(), .err = err.buffered() }, .reqs = state.reqs.load(.monotonic) };
}

fn countLines(s: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, '\n');
    while (it.next()) |l| {
        if (l.len > 0) n += 1;
    }
    return n;
}

test "--paginate walks back in time until a page is empty" {
    var held = try Held.init();
    defer held.arena.deinit();
    var ob: [8192]u8 = undefined;
    var eb: [1024]u8 = undefined;
    // Pages of three over seven events: 3, 3, 1, then an empty page.
    const r = try pagedRun(&held, .{ .events = &.{}, .times = &.{}, .max_page = 3 }, 4, &.{ "-k", "1", "--paginate" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.run.code);
    try std.testing.expectEqual(@as(usize, 4), r.reqs);
    try std.testing.expectEqual(@as(usize, 7), countLines(r.run.out));
    // Newest first, every one once.
    var it = std.mem.splitScalar(u8, r.run.out, '\n');
    var want: i64 = 700;
    while (it.next()) |l| {
        if (l.len == 0) continue;
        var buf: [16]u8 = undefined;
        const needle = try std.fmt.bufPrint(&buf, "\"n{d}\"", .{want});
        try std.testing.expect(std.mem.indexOf(u8, l, needle) != null);
        want -= 100;
    }
}

test "--paginate treats --limit as the total across pages" {
    var held = try Held.init();
    defer held.arena.deinit();
    var ob: [8192]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try pagedRun(&held, .{ .events = &.{}, .times = &.{}, .max_page = 3 }, 2, &.{ "-k", "1", "--paginate", "-l", "5" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.run.code);
    try std.testing.expectEqual(@as(usize, 2), r.reqs);
    try std.testing.expectEqual(@as(usize, 5), countLines(r.run.out));
    try std.testing.expect(std.mem.indexOf(u8, r.run.out, "\"n300\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.run.out, "\"n200\"") == null);
}

test "--paginate stops at once when the whole limit fits in a page" {
    var held = try Held.init();
    defer held.arena.deinit();
    var ob: [8192]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try pagedRun(&held, .{ .events = &.{}, .times = &.{} }, 1, &.{ "--paginate", "-l", "4" }, &ob, &eb);
    try std.testing.expectEqual(@as(usize, 1), r.reqs);
    try std.testing.expectEqual(@as(usize, 4), countLines(r.run.out));
}

test "--paginate stops when --since is reached" {
    var held = try Held.init();
    defer held.arena.deinit();
    var ob: [8192]u8 = undefined;
    var eb: [1024]u8 = undefined;
    // Page one holds 700..500 and the next page would start below 450.
    const r = try pagedRun(&held, .{ .events = &.{}, .times = &.{}, .max_page = 3 }, 1, &.{ "--paginate", "-s", "500" }, &ob, &eb);
    try std.testing.expectEqual(@as(usize, 1), r.reqs);
    try std.testing.expectEqual(@as(usize, 3), countLines(r.run.out));
}

test "--paginate prints an event once even when the relay ignores until" {
    var held = try Held.init();
    defer held.arena.deinit();
    var ob: [8192]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try pagedRun(&held, .{ .events = &.{}, .times = &.{}, .max_page = 3, .ignore_until = true }, 2, &.{"--paginate"}, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.run.code);
    try std.testing.expectEqual(@as(usize, 2), r.reqs);
    try std.testing.expectEqual(@as(usize, 3), countLines(r.run.out));
}

test "--ids-only prints ids and nothing else" {
    var held = try Held.init();
    defer held.arena.deinit();
    var ob: [8192]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const r = try pagedRun(&held, .{ .events = &.{}, .times = &.{} }, 1, &.{ "--ids-only", "-l", "2" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_ok, r.run.code);
    try std.testing.expectEqual(@as(usize, 2), countLines(r.run.out));
    var it = std.mem.splitScalar(u8, r.run.out, '\n');
    while (it.next()) |l| {
        if (l.len == 0) continue;
        try std.testing.expectEqual(@as(usize, 64), l.len);
        _ = try nostr.hex.decodeFixed(32, l);
    }
}

test "--outbox asks each author's own relay, and the named relay for the author with no list" {
    const io = std.testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("the run leaked");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const ka = try signer.keyPairFromSecretKey([_]u8{0x61} ** 32);
    const kb = try signer.keyPairFromSecretKey([_]u8{0x62} ** 32);
    const kc = try signer.keyPairFromSecretKey([_]u8{0x63} ** 32);

    const ev_a = try nostr.event.toJson(arena, try nostr.event.create(arena, signer, ka, 1_700_000_100, 1, &.{}, "from a", null));
    const ev_b = try nostr.event.toJson(arena, try nostr.event.create(arena, signer, kb, 1_700_000_200, 1, &.{}, "from b", null));
    const ev_c = try nostr.event.toJson(arena, try nostr.event.create(arena, signer, kc, 1_700_000_300, 1, &.{}, "from c", null));

    // Each home relay holds its own author's note and also, wrongly, the
    // other's: only the first may come out of it.
    var home_a: testrelay.Relay = undefined;
    try home_a.start(io, .serve);
    home_a.serving = &.{ ev_a, ev_b };
    defer home_a.stop(io);
    var home_b: testrelay.Relay = undefined;
    try home_b.start(io, .serve);
    home_b.serving = &.{ev_b};
    defer home_b.stop(io);
    var named: testrelay.Relay = undefined;
    try named.start(io, .serve);
    named.serving = &.{ev_c};
    defer named.stop(io);
    var ba: [40]u8 = undefined;
    var bb: [40]u8 = undefined;
    var bn: [40]u8 = undefined;
    const url_a = try testrelay.url(&ba, home_a.port());
    const url_b = try testrelay.url(&bb, home_b.port());
    const url_n = try testrelay.url(&bn, named.port());

    const list_a = try nostr.event.create(arena, signer, ka, 1_700_000_050, 10002, &.{&.{ "r", url_a, "write" }}, "", null);
    const list_b = try nostr.event.create(arena, signer, kb, 1_700_000_050, 10002, &.{&.{ "r", url_b, "write" }}, "", null);
    var script: outbox.Script = .{
        .list = try nostr.event.toJson(arena, list_a),
        .list2 = try nostr.event.toJson(arena, list_b),
    };
    var directory: testrelay.Relay = undefined;
    try outbox.startScript(&directory, io, &script, 2);
    defer directory.stop(io);
    var bd: [40]u8 = undefined;
    const url_d = try testrelay.url(&bd, directory.port());

    const ha = try nostr.hex.encode(arena, &ka.public_key);
    const hb = try nostr.hex.encode(arena, &kb.public_key);
    const hc = try nostr.hex.encode(arena, &kc.public_key);
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try runWith(gpa, io, &.{ "--outbox", "-k", "1", "-a", ha, "-a", hb, "-a", hc, "--relay", url_d, "--timeout", "5000", url_n }, null, &out.writer, &err.writer);
    try std.testing.expectEqual(cli.exit_ok, code);
    try std.testing.expectEqual(@as(usize, 3), countLines(out.written()));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "from a") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "from b") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "from c") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "reached 2 of 3 authors") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "1 had no known relay") != null);
}

test "--outbox with no relay to look through is a usage error, and cannot stream" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    const pk = "61" ** 32;
    const r = try runReq(&.{ "--outbox", "-a", pk, "--stream" }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r.code);
    const r2 = try runReq(&.{ "--outbox", "-a", pk }, &ob, &eb);
    try std.testing.expectEqual(cli.exit_usage, r2.code);
}
