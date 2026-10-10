//! `deed event`: build an event and sign it.
//!
//! The verb the tool is named after: what comes out is a deed, a signed record
//! of something done. Publishing it is a separate verb, so this one stays
//! usable offline and its output stays inspectable before it leaves the
//! machine.
//!
//! Two ways in, and they compose. With nothing on stdin it builds exactly one
//! event from the flags. With drafts on stdin it signs each of them in turn,
//! with the flags acting as overrides, so a draft is a template and the flags
//! are what varies.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const keyinput = @import("keyinput.zig");
const kinds = @import("kinds.zig");
const cmd_publish = @import("cmd_publish.zig");
const parallel = @import("parallel.zig");

const keys = nostr.keys;
const event = nostr.event;
const nip13 = nostr.nip13;
const nip19 = nostr.nip19;
const hex = nostr.hex;

/// The most leading zero bits an event id can have.
const max_pow_bits = 256;

/// A draft larger than this is not a draft anybody typed.
const max_record_bytes = 1 << 20;

/// The most a `@file` content may hold.
const max_content_bytes = 8 << 20;

/// The separator inside a `--tag` value, for tags with more than two elements.
///
/// A semicolon rather than a comma: relay hints and `a` coordinates are the
/// values that most often need a third element, and commas turn up inside
/// those far more readily than semicolons do.
const tag_separator = ';';

pub const usage =
    \\deed event: build an event and sign it
    \\
    \\Usage:
    \\  deed event [-] [<relay-url>...] [--sec <key>] [-c <content>] [-k <kind>] [-t <tag>]...
    \\             [-e <id>] [-p <pubkey>] [-d <d>] [-h <h>] [-a <address>]
    \\             [--created-at <n>] [--pow <bits>] [--pow-threads <n>] [--pow-timeout <s>]
    \\             [--envelope] [--nevent] [--confirm]
    \\
    \\Options:
    \\  --sec <key>          secret key, as nsec1… or 64 hex characters.
    \\                       Falls back to $NOSTR_SECRET_KEY.
    \\  -c, --content <text> event content (default: empty). `@path` reads the
    \\                       content from that file; `@@text` is a literal
    \\                       `@text`.
    \\  -k, --kind <n>       event kind, by number or by name such as
    \\                       text-note or reaction (default: 1). See `deed kind`.
    \\  -t, --tag <name>=<v> add a tag, repeatable. Use ';' between values for a
    \\                       tag with more than two elements:
    \\                         -t 'e=<id>;wss://relay.example;reply'
    \\                       A bare name with no '=' makes a one-element tag.
    \\  -e <id>              add an e tag: a hex id, note1… or nevent1…
    \\  -p <pubkey>          add a p tag: hex, npub1… or nprofile1…
    \\  -d <d>               add a d tag
    \\  -h <h>               add an h tag
    \\  -a <address>         add an a tag: kind:pubkey:d, an naddr1…, or a bare
    \\                       pubkey (taken as <kind>:<pubkey>:<-d value>)
    \\  --created-at <n>     unix seconds (default: now)
    \\  --pow <bits>         proof of work (NIP-13): search for a nonce until the
    \\                       event id has at least <bits> leading zero bits, and
    \\                       add a ["nonce", n, <bits>] tag. Any nonce tag given
    \\                       with -t is replaced. 0 (the default) does no work and
    \\                       adds no tag. Up to 256. Each extra bit doubles the
    \\                       expected work.
    \\  --pow-threads <n>    threads to search with (default: the CPU count).
    \\  --pow-timeout <s>    give up on an event after <s> seconds, sign nothing
    \\                       for it, and exit 1. Applies to each event separately.
    \\                       Default: no limit.
    \\  --envelope           print ["EVENT",{…}] instead of the bare event
    \\  --nevent             print an nevent1… line after each event
    \\  --confirm            ask on the terminal before publishing; refuses when
    \\                       there is no terminal
    \\
    \\Tags are added in the order the flags were given.
    \\
    \\Naming one or more relay URLs (wss:// or ws://) signs the event and then
    \\publishes it, exactly as `deed publish` does, and prints only the events
    \\a relay accepted. Every relay's answer is on stderr, and the exit code is
    \\`deed publish`'s.
    \\
    \\A lone `-` reads drafts as newline-delimited JSON on stdin, signs each
    \\one, and applies the flags above as overrides. Unknown fields in a draft
    \\are ignored, so a whole event can be piped back in to be re-signed. One
    \\signed event is printed per line.
    \\
    \\The `-` is required rather than inferred. Every other verb reads stdin
    \\when it has nothing else to work on, because it has nothing to do without
    \\input; this one has a complete default, so guessing at stdin would let a
    \\script sign whatever happened to be on the other end of the pipe.
    \\
    \\  deed event -c "hello" --sec nsec1…
    \\  deed event -k reaction -e <id> -p <pubkey> -c "+" wss://relay.example
    \\  echo '{"kind":1,"content":"hi"}' | deed event - --sec nsec1…
    \\
;

/// A tag shortcut flag, kept raw until every flag has been read: an `-a` with
/// a bare pubkey needs the final kind and `-d`.
const Shortcut = struct {
    flag: u8,
    value: []const u8,
};

const Overrides = struct {
    sec: ?[]const u8 = null,
    content: ?[]const u8 = null,
    kind: ?u16 = null,
    created_at: ?i64 = null,
    /// Every tag from every flag, in the order given. Borrows the run's arena.
    tags: []const event.Tag = &.{},
    tags_given: bool = false,
    envelope: bool = false,
    nevent: bool = false,
    confirm: bool = false,
    relays: []const []const u8 = &.{},
    /// Leading zero bits to mine into each event id. 0 mines nothing.
    pow: u32 = 0,
    /// Search threads. Null until `run` has read every flag, then the CPU count.
    pow_threads: ?u32 = null,
    /// Per-event search deadline in milliseconds. Null means no limit.
    pow_timeout_ms: ?u64 = null,
};

/// The fields a draft may carry. Everything is optional and everything else in
/// the object is ignored, so piping a complete event back in re-signs it
/// rather than failing on `id` and `sig`.
const Draft = struct {
    kind: ?u16 = null,
    content: ?[]const u8 = null,
    tags: ?[]const []const []const u8 = null,
    created_at: ?i64 = null,
};

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var ov = Overrides{};
    var relays: std.ArrayList([]const u8) = .empty;
    // Where each flag-made tag sits among all of them, so `-t` and the
    // shortcuts keep the order they were typed in.
    var order: std.ArrayList(Shortcut) = .empty;

    var read_stdin = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        // The one positional: `-`, meaning "drafts are coming on stdin".
        if (std.mem.eql(u8, a, "-")) {
            read_stdin = true;
            continue;
        }
        if (std.mem.startsWith(u8, a, "wss://") or std.mem.startsWith(u8, a, "ws://")) {
            try relays.append(arena, a);
            continue;
        }
        if (std.mem.eql(u8, a, "--envelope")) {
            ov.envelope = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--nevent")) {
            ov.nevent = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--confirm")) {
            ov.confirm = true;
            continue;
        }
        const needs_value = cli.isOneOf(a, &.{
            "--sec", "-c", "--content", "-k", "--kind", "-t",    "--tag",         "--created-at",
            "-e",    "-p", "-d",        "-h", "-a",     "--pow", "--pow-threads", "--pow-timeout",
        });
        if (!needs_value) {
            try err.print("deed event: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        }
        i += 1;
        if (i >= args.len) {
            try err.print("deed event: '{s}' needs a value\n", .{a});
            return cli.exit_usage;
        }
        const v = args[i];

        if (std.mem.eql(u8, a, "--sec")) {
            ov.sec = v;
        } else if (cli.isOneOf(a, &.{ "-c", "--content" })) {
            ov.content = v;
        } else if (cli.isOneOf(a, &.{ "-k", "--kind" })) {
            const n = kinds.parse(v) orelse {
                try err.print("deed event: '{s}' is not a kind number or a kind name (see `deed kind`)\n", .{v});
                return cli.exit_usage;
            };
            ov.kind = std.math.cast(u16, n) orelse {
                try err.print("deed event: kind {d} is above 65535\n", .{n});
                return cli.exit_usage;
            };
        } else if (cli.isOneOf(a, &.{ "-t", "--tag" })) {
            ov.tags_given = true;
            try order.append(arena, .{ .flag = 't', .value = v });
        } else if (std.mem.eql(u8, a, "--created-at")) {
            ov.created_at = std.fmt.parseInt(i64, v, 10) catch {
                try err.print("deed event: '{s}' is not a unix timestamp\n", .{v});
                return cli.exit_usage;
            };
        } else if (std.mem.eql(u8, a, "--pow")) {
            const bits = std.fmt.parseInt(u32, v, 10) catch null;
            if (bits == null or bits.? > max_pow_bits) {
                try err.print("deed event: --pow needs a number of bits from 0 to {d}, not '{s}'\n", .{ max_pow_bits, v });
                return cli.exit_usage;
            }
            ov.pow = bits.?;
        } else if (std.mem.eql(u8, a, "--pow-threads")) {
            const n = std.fmt.parseInt(u32, v, 10) catch null;
            if (n == null or n.? == 0) {
                try err.print("deed event: --pow-threads needs a number of threads of at least 1, not '{s}'\n", .{v});
                return cli.exit_usage;
            }
            ov.pow_threads = n.?;
        } else if (std.mem.eql(u8, a, "--pow-timeout")) {
            const secs = std.fmt.parseInt(u32, v, 10) catch null;
            if (secs == null or secs.? == 0) {
                try err.print("deed event: --pow-timeout needs a number of seconds of at least 1, not '{s}'\n", .{v});
                return cli.exit_usage;
            }
            ov.pow_timeout_ms = @as(u64, secs.?) * std.time.ms_per_s;
        } else {
            ov.tags_given = true;
            try order.append(arena, .{ .flag = a[1], .value = v });
        }
    }

    if (ov.pow_threads == null) {
        ov.pow_threads = std.math.cast(u32, parallel.cpuCount()) orelse 1;
    }

    if (ov.confirm and relays.items.len == 0) {
        try err.writeAll("deed event: --confirm is for publishing: name a relay to publish to\n");
        return cli.exit_usage;
    }
    if (relays.items.len > 0 and relays.items.len > @import("dial.zig").max_relays) {
        try err.print("deed event: name at most {d} relays\n", .{@import("dial.zig").max_relays});
        return cli.exit_usage;
    }
    ov.relays = relays.items;

    // Resolved after every flag is in: a bare-pubkey `-a` wants the final
    // kind and `-d`.
    var d_value: []const u8 = "";
    for (order.items) |s| if (s.flag == 'd') {
        d_value = s.value;
    };
    var built: std.ArrayList(event.Tag) = .empty;
    for (order.items) |s| {
        const t = shortcutTag(arena, s, ov.kind orelse 1, d_value) catch |e| {
            try err.print("deed event: -{c} '{s}': {s}\n", .{ s.flag, s.value, shortcutReason(e) });
            return cli.exit_usage;
        };
        try built.append(arena, t);
    }
    ov.tags = built.items;

    if (ov.content) |c| ov.content = resolveContent(arena, io, c, err) catch |e| switch (e) {
        error.ReadFailed => return cli.exit_fail,
        else => return e,
    };

    // The key is the one thing with no default. Asking for it by flag or by
    // environment and refusing to invent one is the whole point: an event
    // signed by a key the caller did not choose is worse than no event.
    const raw_sec = ov.sec orelse getEnv("NOSTR_SECRET_KEY") orelse {
        try err.writeAll("deed event: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n");
        return cli.exit_usage;
    };
    const sk = keyinput.secretKey(gpa, raw_sec) catch {
        try err.writeAll("deed event: not a secret key (want nsec1… or 64 hex characters)\n");
        return cli.exit_fail;
    };

    var signer = try keys.Signer.initRandomized(io);
    defer signer.deinit();
    const keypair = try signer.keyPairFromSecretKey(sk);

    // With relays, events are held until every draft is signed, then offered
    // together. Without, they are printed as they are made.
    var pending: std.ArrayList([]const u8) = .empty;
    var sink = Sink{ .gpa = gpa, .ov = ov, .out = out, .pending = if (relays.items.len > 0) &pending else null };

    var failures: usize = 0;
    if (!read_stdin) {
        emit(gpa, io, signer, keypair, Draft{}, ov, &sink) catch |e| switch (e) {
            error.PowTimeout, error.PowFailed => return reportPow(err, e, ov),
            else => return e,
        };
    } else {
        const stdin_buf = try gpa.alloc(u8, max_record_bytes);
        defer gpa.free(stdin_buf);
        // Streaming for the reason `main` gives for the writers: a positional
        // read starts at byte 0 of the file behind the descriptor and re-reads
        // records an earlier reader on the same descriptor already consumed.
        var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
        var input = cli.Input.init(&.{}, &stdin_reader.interface);

        while (try input.next()) |record| {
            const json = switch (record) {
                // Trimmed here rather than in `Input`: surrounding space around
                // a draft is noise, and `deed encrypt` needs the same bytes it was given.
                .line => |l| std.mem.trim(u8, l, " \t"),
                .too_long => {
                    try err.print(
                        "deed event: skipped a draft longer than {d} bytes\n",
                        .{max_record_bytes},
                    );
                    failures += 1;
                    continue;
                },
            };
            var draft_arena = std.heap.ArenaAllocator.init(gpa);
            defer draft_arena.deinit();
            const draft = std.json.parseFromSliceLeaky(
                Draft,
                draft_arena.allocator(),
                json,
                .{ .ignore_unknown_fields = true },
            ) catch |e| {
                try err.print("deed event: not a draft: {s}\n", .{@errorName(e)});
                failures += 1;
                continue;
            };
            emit(gpa, io, signer, keypair, draft, ov, &sink) catch |e| switch (e) {
                error.PowTimeout, error.PowFailed => {
                    _ = try reportPow(err, e, ov);
                    failures += 1;
                    continue;
                },
                else => return e,
            };
        }
    }

    if (relays.items.len > 0 and pending.items.len > 0) {
        defer {
            for (pending.items) |p| gpa.free(p);
            pending.deinit(gpa);
        }
        if (ov.confirm and !try confirmed(io, pending.items, relays.items, err)) return cli.exit_fail;

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, relays.items);
        try argv.appendSlice(gpa, pending.items);

        var accepted: std.Io.Writer.Allocating = .init(gpa);
        defer accepted.deinit();
        const code = try cmd_publish.run(gpa, io, argv.items, &accepted.writer, err);
        var lines = std.mem.splitScalar(u8, accepted.written(), '\n');
        while (lines.next()) |l| {
            if (l.len == 0) continue;
            try sink.print(l);
        }
        if (failures != 0 and code == cli.exit_ok) return cli.exit_fail;
        return code;
    }

    // An empty pipe is not a request to invent an event: `cat drafts.jsonl |
    // deed event -` that receives nothing should produce nothing, and say so by
    // succeeding rather than by complaining.
    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

/// Where signed events go: straight to the output, or held for publishing.
const Sink = struct {
    gpa: std.mem.Allocator,
    ov: Overrides,
    out: *std.Io.Writer,
    pending: ?*std.ArrayList([]const u8),

    fn add(self: *Sink, json: []const u8) !void {
        if (self.pending) |p| {
            const copy = try self.gpa.dupe(u8, json);
            errdefer self.gpa.free(copy);
            try p.append(self.gpa, copy);
        } else {
            try self.print(json);
        }
    }

    /// One event as the caller asked to see it.
    fn print(self: *Sink, json: []const u8) !void {
        if (self.ov.envelope) {
            try self.out.print("[\"EVENT\",{s}]\n", .{json});
        } else {
            try self.out.print("{s}\n", .{json});
        }
        if (self.ov.nevent) {
            var parsed = try event.fromJson(self.gpa, json);
            defer parsed.deinit();
            const ev = parsed.value;
            const code = try nip19.encodeNevent(self.gpa, ev.id, self.ov.relays, ev.pubkey, ev.kind);
            defer self.gpa.free(code);
            try self.out.print("{s}\n", .{code});
        }
        try self.out.flush();
    }
};

/// Asks on the controlling terminal. False means do not publish.
fn confirmed(
    io: std.Io,
    pending: []const []const u8,
    relays: []const []const u8,
    err: *std.Io.Writer,
) !bool {
    const tty = std.Io.Dir.cwd().openFile(io, "/dev/tty", .{ .mode = .read_write }) catch {
        try err.writeAll("deed event: --confirm needs a terminal and there is none; nothing was published\n");
        return false;
    };
    defer tty.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = tty.writerStreaming(io, &wbuf);
    for (pending) |p| try w.interface.print("{s}\n", .{p});
    try w.interface.print("Publish {d} event(s) to {d} relay(s)? [y/N] ", .{ pending.len, relays.len });
    try w.interface.flush();
    var rbuf: [256]u8 = undefined;
    var r = tty.readerStreaming(io, &rbuf);
    const answer = (r.interface.takeDelimiter('\n') catch null) orelse "";
    const t = std.mem.trim(u8, answer, " \t\r");
    if (std.ascii.eqlIgnoreCase(t, "y") or std.ascii.eqlIgnoreCase(t, "yes")) return true;
    try err.writeAll("deed event: not confirmed; nothing was published\n");
    return false;
}

/// `@path` is the file's bytes, `@@text` is `@text`, anything else as given.
fn resolveContent(arena: std.mem.Allocator, io: std.Io, c: []const u8, err: *std.Io.Writer) ![]const u8 {
    if (std.mem.startsWith(u8, c, "@@")) return c[1..];
    if (!std.mem.startsWith(u8, c, "@")) return c;
    const path = c[1..];
    return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_content_bytes)) catch |e| {
        try err.print("deed event: cannot read {s}: {s}\n", .{ path, @errorName(e) });
        return error.ReadFailed;
    };
}

const ShortcutError = error{ BadId, BadPubkey, BadAddress, OutOfMemory };

fn shortcutReason(e: ShortcutError) []const u8 {
    return switch (e) {
        error.BadId => "not an event id (want 64 hex characters, note1… or nevent1…)",
        error.BadPubkey => "not a public key (want 64 hex characters, npub1… or nprofile1…)",
        error.BadAddress => "not an address (want kind:pubkey:d, naddr1… or a public key)",
        error.OutOfMemory => "out of memory",
    };
}

fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn lower(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    return std.ascii.allocLowerString(arena, s);
}

fn pubkeyHex(arena: std.mem.Allocator, v: []const u8) ShortcutError![]const u8 {
    const s = keyinput.stripUri(v);
    if (isHex64(s)) return lower(arena, s);
    if (keyinput.hasPrefix(s, "npub1")) {
        const pk = nip19.decodeNpub(arena, s) catch return error.BadPubkey;
        return hex.encode(arena, &pk) catch error.OutOfMemory;
    }
    if (keyinput.hasPrefix(s, "nprofile1")) {
        const p = nip19.decodeNprofile(arena, s) catch return error.BadPubkey;
        return hex.encode(arena, &p.pubkey) catch error.OutOfMemory;
    }
    return error.BadPubkey;
}

fn shortcutTag(arena: std.mem.Allocator, s: Shortcut, kind: u32, d_value: []const u8) ShortcutError!event.Tag {
    switch (s.flag) {
        't' => return parseTag(arena, s.value),
        'd', 'h' => return tagOf(arena, &.{ if (s.flag == 'd') "d" else "h", s.value }),
        'p' => return tagOf(arena, &.{ "p", try pubkeyHex(arena, s.value) }),
        'e' => {
            const v = keyinput.stripUri(s.value);
            if (isHex64(v)) return tagOf(arena, &.{ "e", try lower(arena, v) });
            if (keyinput.hasPrefix(v, "note1")) {
                const id = nip19.decodeNote(arena, v) catch return error.BadId;
                return tagOf(arena, &.{ "e", hex.encode(arena, &id) catch return error.OutOfMemory });
            }
            if (keyinput.hasPrefix(v, "nevent1")) {
                const p = nip19.decodeNevent(arena, v) catch return error.BadId;
                const id = hex.encode(arena, &p.id) catch return error.OutOfMemory;
                if (p.relays.len > 0) return tagOf(arena, &.{ "e", id, p.relays[0] });
                return tagOf(arena, &.{ "e", id });
            }
            return error.BadId;
        },
        'a' => {
            const v = keyinput.stripUri(s.value);
            if (keyinput.hasPrefix(v, "naddr1")) {
                const p = nip19.decodeNaddr(arena, v) catch return error.BadAddress;
                const pk = hex.encode(arena, &p.pubkey) catch return error.OutOfMemory;
                const addr = std.fmt.allocPrint(arena, "{d}:{s}:{s}", .{ p.kind, pk, p.identifier }) catch return error.OutOfMemory;
                if (p.relays.len > 0) return tagOf(arena, &.{ "a", addr, p.relays[0] });
                return tagOf(arena, &.{ "a", addr });
            }
            if (std.mem.indexOfScalar(u8, v, ':') != null) {
                var it = std.mem.splitScalar(u8, v, ':');
                const k = it.next() orelse return error.BadAddress;
                const pk = it.next() orelse return error.BadAddress;
                _ = std.fmt.parseInt(u32, k, 10) catch return error.BadAddress;
                if (!isHex64(pk)) return error.BadAddress;
                return tagOf(arena, &.{ "a", v });
            }
            const pk = pubkeyHex(arena, v) catch return error.BadAddress;
            const addr = std.fmt.allocPrint(arena, "{d}:{s}:{s}", .{ kind, pk, d_value }) catch return error.OutOfMemory;
            return tagOf(arena, &.{ "a", addr });
        },
        else => unreachable,
    }
}

fn tagOf(arena: std.mem.Allocator, parts: []const []const u8) ShortcutError!event.Tag {
    return arena.dupe([]const u8, parts) catch error.OutOfMemory;
}

fn emit(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    draft: Draft,
    ov: Overrides,
    sink: *Sink,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const kind = ov.kind orelse draft.kind orelse 1;
    const content = ov.content orelse draft.content orelse "";
    const created_at = ov.created_at orelse draft.created_at orelse
        std.Io.Timestamp.now(io, .real).toSeconds();

    // Tags replace rather than merge. Merging would mean a draft's `e` tag and
    // a flag's `e` tag both landing, which is a different event than either
    // side asked for and impossible to undo from the command line.
    const tags: []const event.Tag = if (ov.tags_given)
        ov.tags
    else if (draft.tags) |t|
        t
    else
        &.{};

    if (ov.pow == 0) {
        const ev = try event.create(a, signer, keypair, created_at, kind, tags, content, null);
        const json = try event.toJson(a, ev);
        try sink.add(json);
        return;
    }

    // Mined first, then signed: the search fixes the id, and the signature is
    // over the id. `toJson` copies everything out of the mining arena, so the
    // deferred deinit is safe.
    var mined = nip13.mine(gpa, io, .{
        .pubkey = keypair.public_key,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
    }, .{
        .target = ov.pow,
        .threads = ov.pow_threads orelse 1,
        .timeout_ms = ov.pow_timeout_ms,
    }) catch |e| return switch (e) {
        error.Timeout => error.PowTimeout,
        error.OutOfMemory => error.OutOfMemory,
        else => error.PowFailed,
    };
    defer mined.deinit();

    var ev = mined.event;
    ev.sig = signer.signId(ev.id, keypair, null) catch return error.PowFailed;
    const json = try event.toJson(a, ev);
    try sink.add(json);
}

/// Prints why an event was not made and returns the exit code for it.
fn reportPow(err: *std.Io.Writer, e: anyerror, ov: Overrides) !u8 {
    switch (e) {
        error.PowTimeout => try err.print(
            "deed event: no nonce reached {d} leading zero bits within {d} seconds; nothing was signed\n",
            .{ ov.pow, (ov.pow_timeout_ms orelse 0) / std.time.ms_per_s },
        ),
        else => try err.print(
            "deed event: proof of work failed at {d} leading zero bits; nothing was signed\n",
            .{ov.pow},
        ),
    }
    return cli.exit_fail;
}

/// `name=v1;v2` becomes `["name","v1","v2"]`; a bare `name` becomes `["name"]`.
/// Caller owns the returned slice; its elements borrow `spec`.
fn parseTag(gpa: std.mem.Allocator, spec: []const u8) ![]const []const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    errdefer parts.deinit(gpa);

    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse {
        try parts.append(gpa, spec);
        return parts.toOwnedSlice(gpa);
    };
    try parts.append(gpa, spec[0..eq]);
    var it = std.mem.splitScalar(u8, spec[eq + 1 ..], tag_separator);
    while (it.next()) |v| try parts.append(gpa, v);
    return parts.toOwnedSlice(gpa);
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

test "a two-element tag" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "e=abc");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("e", t[0]);
    try std.testing.expectEqualStrings("abc", t[1]);
}

test "extra values after the separator" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "e=abc;wss://relay.example;reply");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 4), t.len);
    try std.testing.expectEqualStrings("wss://relay.example", t[2]);
    try std.testing.expectEqualStrings("reply", t[3]);
}

test "a bare name is a one-element tag" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "-");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 1), t.len);
    try std.testing.expectEqualStrings("-", t[0]);
}

test "an empty value is still a value" {
    const gpa = std.testing.allocator;
    const t = try parseTag(gpa, "d=");
    defer gpa.free(t);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("", t[1]);
}

// ---------------------------------------------------------------------------
// Tests of the command itself.
// ---------------------------------------------------------------------------

const testrelay = @import("testrelay.zig");

const test_sec = "1111111111111111111111111111111111111111111111111111111111111111";
const test_pk = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const test_id = "aa" ** 32;

const Ran = struct { code: u8, out: []const u8, err: []const u8 };

fn runEvent(arena: std.mem.Allocator, args: []const []const u8) !Ran {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("event leaked");
    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    const code = try run(da.allocator(), std.testing.io, args, &out.writer, &err.writer);
    return .{ .code = code, .out = out.written(), .err = err.written() };
}

fn parsedTags(arena: std.mem.Allocator, line: []const u8) ![]const []const []const u8 {
    const Shape = struct { tags: []const []const []const u8 };
    const v = try std.json.parseFromSliceLeaky(Shape, arena, line, .{ .ignore_unknown_fields = true });
    return v.tags;
}

fn has(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "tag flags become tags, in the order given" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();

    const r = try runEvent(arena, &.{
        "--sec", test_sec, "-d", "slug",  "-e", test_id,
        "-p",    test_pk,  "-h", "group", "-a", "30023:" ++ test_pk ++ ":slug",
        "-t",    "x=1;2",  "-k", "30023",
    });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    const tags = try parsedTags(arena, r.out);
    try std.testing.expectEqual(@as(usize, 6), tags.len);
    try std.testing.expectEqualStrings("d", tags[0][0]);
    try std.testing.expectEqualStrings("slug", tags[0][1]);
    try std.testing.expectEqualStrings("e", tags[1][0]);
    try std.testing.expectEqualStrings(test_id, tags[1][1]);
    try std.testing.expectEqualStrings("p", tags[2][0]);
    try std.testing.expectEqualStrings("h", tags[3][0]);
    try std.testing.expectEqualStrings("a", tags[4][0]);
    try std.testing.expectEqualStrings("30023:" ++ test_pk ++ ":slug", tags[4][1]);
    try std.testing.expectEqual(@as(usize, 3), tags[5].len);
}

test "bech32 pointers and a bare pubkey address resolve to tags" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();

    const npub = try nip19.encodeNpub(arena, [_]u8{0xaa} ** 32);
    const note = try nip19.encodeNote(arena, [_]u8{0xbb} ** 32);
    const r = try runEvent(arena, &.{
        "--sec", test_sec, "-p", npub, "-e", note, "-d", "x", "-a", test_pk, "-k", "30023",
    });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    const tags = try parsedTags(arena, r.out);
    try std.testing.expectEqualStrings("aa" ** 32, tags[0][1]);
    try std.testing.expectEqualStrings("bb" ** 32, tags[1][1]);
    try std.testing.expectEqualStrings("30023:" ++ test_pk ++ ":x", tags[3][1]);
}

test "a bad pointer is a usage error" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const r = try runEvent(arena, &.{ "--sec", test_sec, "-e", "nope" });
    try std.testing.expectEqual(cli.exit_usage, r.code);
    try std.testing.expect(has(r.err, "not an event id"));
}

test "kind by name, and an unknown name is refused" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const ok = try runEvent(arena, &.{ "--sec", test_sec, "-k", "reaction", "-c", "+" });
    try std.testing.expectEqual(cli.exit_ok, ok.code);
    try std.testing.expect(has(ok.out, "\"kind\":7,"));
    const bad = try runEvent(arena, &.{ "--sec", test_sec, "-k", "nonsense" });
    try std.testing.expectEqual(cli.exit_usage, bad.code);
}

test "content from a file, and @@ for a literal @" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "body.txt", .data = "from a file\n" });
    const dir = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const path = try std.fmt.allocPrint(arena, "@{s}/body.txt", .{dir});

    const f = try runEvent(arena, &.{ "--sec", test_sec, "-c", path });
    try std.testing.expectEqual(cli.exit_ok, f.code);
    try std.testing.expect(has(f.out, "\"content\":\"from a file\\n\""));

    const lit = try runEvent(arena, &.{ "--sec", test_sec, "-c", "@@alice hi" });
    try std.testing.expect(has(lit.out, "\"content\":\"@alice hi\""));

    const missing = try runEvent(arena, &.{ "--sec", test_sec, "-c", "@/no/such/file" });
    try std.testing.expectEqual(cli.exit_fail, missing.code);
}

test "--envelope wraps the event, and --nevent adds a code" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const r = try runEvent(arena, &.{ "--sec", test_sec, "--envelope", "--nevent", "-c", "hi" });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.startsWith(u8, r.out, "[\"EVENT\",{\"id\":"));
    try std.testing.expect(has(r.out, "}]\nnevent1"));
}

fn acceptAll(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
    _ = ctx;
    try reply(frame, true, "", w);
}

fn rejectAll(ctx: ?*anyopaque, frame: []const u8, w: *std.Io.Writer) anyerror!void {
    _ = ctx;
    try reply(frame, false, "blocked: not today", w);
}

fn reply(frame: []const u8, ok: bool, why: []const u8, w: *std.Io.Writer) !void {
    const marker = "[\"EVENT\",{\"id\":\"";
    if (!std.mem.startsWith(u8, frame, marker)) return;
    const id = frame[marker.len..][0..64];
    var buf: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "[\"OK\",\"{s}\",{s},\"{s}\"]", .{ id, if (ok) "true" else "false", why });
    try testrelay.sendText(w, text);
}

test "an event is published to a relay that accepts it" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const io = std.testing.io;

    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, acceptAll, null);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, relay.port());

    const r = try runEvent(arena, &.{ url, "--sec", test_sec, "-c", "to a relay", "--envelope", "--nevent" });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(std.mem.startsWith(u8, r.out, "[\"EVENT\",{\"id\":"));
    try std.testing.expect(has(r.out, "\"content\":\"to a relay\""));
    try std.testing.expect(has(r.out, "}]\nnevent1"));
    try std.testing.expect(has(r.err, ": accepted"));
}

test "an event a relay rejects is not printed" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const io = std.testing.io;

    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, rejectAll, null);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, relay.port());

    const r = try runEvent(arena, &.{ "--sec", test_sec, "-c", "refused", url, "--nevent" });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(has(r.err, "blocked: not today"));
}

test "--confirm without a relay is a usage error" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const r = try runEvent(arena, &.{ "--sec", test_sec, "--confirm" });
    try std.testing.expectEqual(cli.exit_usage, r.code);
}

test "pow: difficulty 8 to 12 gives an id with those bits, a nonce tag, and a valid signature" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();

    var bits: u32 = 8;
    while (bits <= 12) : (bits += 1) {
        const pow = try std.fmt.allocPrint(arena, "{d}", .{bits});
        const r = try runEvent(arena, &.{ "--sec", test_sec, "-c", "mined", "--pow", pow, "--created-at", "1700000000" });
        try std.testing.expectEqual(cli.exit_ok, r.code);

        var parsed = try event.fromJson(std.testing.allocator, std.mem.trimEnd(u8, r.out, "\n"));
        defer parsed.deinit();
        const ev = parsed.value;
        try std.testing.expect(nip13.difficulty(ev.id) >= bits);
        try std.testing.expectEqual(@as(?u32, bits), nip13.committedTarget(ev));
        const nonce = ev.tags[ev.tags.len - 1];
        try std.testing.expectEqual(@as(usize, 3), nonce.len);
        try std.testing.expectEqualStrings("nonce", nonce[0]);
        _ = try std.fmt.parseInt(u64, nonce[1], 10);
        try std.testing.expectEqualStrings(pow, nonce[2]);
        try std.testing.expect(try event.verify(std.testing.allocator, signer, ev));
    }
}

test "pow: --pow 0 mines nothing and changes nothing" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();

    const plain = try runEvent(arena, &.{ "--sec", test_sec, "-c", "same", "--created-at", "1700000000" });
    const zero = try runEvent(arena, &.{ "--sec", test_sec, "-c", "same", "--created-at", "1700000000", "--pow", "0" });
    try std.testing.expectEqual(cli.exit_ok, plain.code);
    try std.testing.expectEqual(cli.exit_ok, zero.code);
    try std.testing.expect(!has(zero.out, "nonce"));

    var a = try event.fromJson(std.testing.allocator, std.mem.trimEnd(u8, plain.out, "\n"));
    defer a.deinit();
    var b = try event.fromJson(std.testing.allocator, std.mem.trimEnd(u8, zero.out, "\n"));
    defer b.deinit();
    try std.testing.expectEqualSlices(u8, &a.value.id, &b.value.id);
    try std.testing.expectEqual(a.value.tags.len, b.value.tags.len);
}

test "pow: several threads find a valid nonce" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const r = try runEvent(arena, &.{ "--sec", test_sec, "-c", "threads", "--pow", "12", "--pow-threads", "4" });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    var parsed = try event.fromJson(std.testing.allocator, std.mem.trimEnd(u8, r.out, "\n"));
    defer parsed.deinit();
    try std.testing.expect(nip13.difficulty(parsed.value.id) >= 12);
}

test "pow: bad values are usage errors" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const bad = [_][2][]const u8{
        .{ "--pow", "257" },
        .{ "--pow", "soon" },
        .{ "--pow", "-1" },
        .{ "--pow-threads", "0" },
        .{ "--pow-timeout", "0" },
        .{ "--pow-timeout", "later" },
    };
    for (bad) |b| {
        const r = try runEvent(arena, &.{ "--sec", test_sec, b[0], b[1] });
        try std.testing.expectEqual(cli.exit_usage, r.code);
        try std.testing.expectEqualStrings("", r.out);
    }
}

test "pow: a search past its timeout exits 1 and signs nothing" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const r = try runEvent(arena, &.{ "--sec", test_sec, "-c", "too hard", "--pow", "256", "--pow-timeout", "1" });
    try std.testing.expectEqual(cli.exit_fail, r.code);
    try std.testing.expectEqualStrings("", r.out);
    try std.testing.expect(has(r.err, "nothing was signed"));
}

test "pow: a mined event is published to a relay that accepts it" {
    var st = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer st.deinit();
    const arena = st.allocator();
    const io = std.testing.io;

    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, acceptAll, null);
    defer relay.stop(io);
    var buf: [40]u8 = undefined;
    const url = try testrelay.url(&buf, relay.port());

    const r = try runEvent(arena, &.{ url, "--sec", test_sec, "-c", "mined and sent", "--pow", "8", "--envelope" });
    try std.testing.expectEqual(cli.exit_ok, r.code);
    try std.testing.expect(has(r.out, "\"nonce\",\""));
    try std.testing.expect(has(r.err, ": accepted"));
}
