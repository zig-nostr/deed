//! `deed mcp`: deed's tools over the Model Context Protocol, on stdio.
//!
//! The wire is JSON-RPC 2.0, one message per line. stdout carries nothing but
//! protocol messages; every log line goes to stderr.
//!
//! Each tool calls the verb of the same name in this process, with an argument
//! list built from the tool's structured arguments, so a tool and the command
//! line can never disagree about what a filter or a code means. Nothing is
//! spawned. Because the arguments are built here, the caller cannot reach an
//! option the tool does not offer: every value that could be read as a flag is
//! refused, a relay must be a ws:// or wss:// URL, and the store a tool reads
//! is the one named when the server was started.
//!
//! Every call has a deadline, taken from the tool's `timeout_ms` and clamped,
//! and relays are asked at once by the verbs, so one slow relay costs the
//! deadline and no more. Results are capped, with a note saying so.
//!
//! Tools that publish exist only when the server was started with
//! `--allow-publish` and a signing key. The key is read at start-up and never
//! appears in a tool's arguments or results.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const dial = @import("dial.zig");
const kinds = @import("kinds.zig");
const keyinput = @import("keyinput.zig");
const cmd_post = @import("cmd_post.zig");
const cmd_decode = @import("cmd_decode.zig");
const cmd_encode = @import("cmd_encode.zig");
const cmd_verify = @import("cmd_verify.zig");
const cmd_req = @import("cmd_req.zig");
const cmd_fetch = @import("cmd_fetch.zig");
const cmd_count = @import("cmd_count.zig");
const cmd_relay = @import("cmd_relay.zig");
const cmd_relays = @import("cmd_relays.zig");
const cmd_kind = @import("cmd_kind.zig");

const Io = std.Io;
const Json = std.json.Value;
const Allocator = std.mem.Allocator;
const event = nostr.event;

pub const summary = "serve deed's tools to MCP clients over stdio";

pub const ready = true;

pub const usage =
    \\deed mcp: serve deed's tools to MCP clients over stdio
    \\
    \\Usage:
    \\  deed mcp [--store <path>] [--allow-publish [--sec <key>]]
    \\
    \\Speaks the Model Context Protocol (JSON-RPC 2.0, one message per line)
    \\on stdin and stdout, for an MCP client to start as a subprocess. Logs go
    \\to stderr.
    \\
    \\Tools, always: decode, encode, verify, req, fetch, count, relay_info,
    \\relays, kind. Events that arrive from relays are checked before they are
    \\returned. encode never builds an nsec, and decode refuses one.
    \\
    \\Options:
    \\      --store <path>     a local store; adds the store_query tool, which
    \\                         reads it and nothing else
    \\      --allow-publish    add publish_note and publish_event. Needs a
    \\                         signing key, from --sec or $NOSTR_SECRET_KEY
    \\                         (nsec1..., 64 hex characters or ncryptsec1...)
    \\      --sec <key>        the key to sign with
    \\
    \\Without --allow-publish the publishing tools are not listed and cannot be
    \\called. The key is never accepted as a tool argument and never returned.
    \\Every call has a deadline (its timeout_ms, at most 30000), and results
    \\are capped at 256 KiB with a note saying so.
    \\
    \\  {"mcpServers":{"deed":{"command":"deed","args":["mcp"]}}}
    \\
;

/// The protocol versions this server speaks, newest first. A client that asks
/// for one of them gets it; any other request is answered with the newest.
const protocol_versions = [_][]const u8{ "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };

/// The most a tool's result text holds before it is cut.
const max_result_bytes = 256 * 1024;
/// The most of a verb's stderr that rides along with a result.
const max_notes_bytes = 4 * 1024;
/// The longest request line read.
const max_line_bytes = 1 << 20;
/// Relays one call may name.
const max_tool_relays = 8;

const default_timeout_ms: i64 = 10_000;
const min_timeout_ms: i64 = 100;
const max_timeout_ms: i64 = 30_000;
const default_limit: i64 = 20;
const max_limit: i64 = 200;

const max_content_bytes = 256 * 1024;
const max_tags = 512;

pub const Config = struct {
    /// The store `store_query` reads. Null leaves the tool out.
    store_path: ?[]const u8 = null,
    /// The key that signs what the publishing tools publish. Null leaves
    /// those tools out.
    secret: ?nostr.keys.SecretKey = null,
};

const Handler = *const fn (s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) anyerror!bool;

const Tool = struct {
    name: []const u8,
    description: []const u8,
    /// A JSON Schema object, as text.
    schema: []const u8,
    handle: Handler,
    /// Reaches relays, or a store, or signs.
    needs: enum { none, store, signer } = .none,
    /// Talks to hosts outside this machine.
    open_world: bool = true,
};

const relays_schema =
    \\{"type":"array","items":{"type":"string"},"maxItems":8,"description":"relay URLs, ws:// or wss://"}
;

const tools = [_]Tool{
    .{
        .name = "decode",
        .description = "Turn a NIP-19 code (npub, note, nprofile, nevent, naddr, nrelay) or a NIP-05 identifier (name@domain) into the fields it carries. Refuses an nsec.",
        .schema =
        \\{"type":"object","properties":{"input":{"type":"string","description":"the code or identifier"}},"required":["input"]}
        ,
        .handle = toolDecode,
    },
    .{
        .name = "encode",
        .description = "Build a NIP-19 code (npub, note, nprofile, nevent, naddr) from raw hex parts. Never builds an nsec.",
        .schema =
        \\{"type":"object","properties":{"type":{"type":"string","enum":["npub","note","nprofile","nevent","naddr"]},"value":{"type":"string","description":"64 hex characters (the pubkey or id); for naddr, the d-tag identifier"},"relays":
        ++ relays_schema ++
            \\,"author":{"type":"string","description":"nevent: author pubkey, 64 hex characters"},"kind":{"type":"integer","description":"nevent, naddr: the event kind"},"pubkey":{"type":"string","description":"naddr: the author, 64 hex characters"}},"required":["type","value"]}
        ,
        .handle = toolEncode,
        .open_world = false,
    },
    .{
        .name = "verify",
        .description = "Check that an event's id and Schnorr signature are correct. Offline.",
        .schema =
        \\{"type":"object","properties":{"event":{"type":"object","description":"the event, as in NIP-01"}},"required":["event"]}
        ,
        .handle = toolVerify,
        .open_world = false,
    },
    .{
        .name = "req",
        .description = "Ask relays for events matching a filter and return them, one JSON event per line. Every event's signature is checked before it is returned. Bounded by limit and timeout_ms.",
        .schema =
        \\{"type":"object","properties":{"filter":{"type":"object","description":"a NIP-01 filter: ids, authors, kinds, since, until, #e, #p, search"},"relays":
        ++ relays_schema ++
            \\,"limit":{"type":"integer","minimum":1,"maximum":200,"default":20},"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["relays"]}
        ,
        .handle = toolReq,
    },
    .{
        .name = "fetch",
        .description = "Fetch the events a NIP-19 code names (note, nevent, naddr, nprofile, npub). Relay hints inside the code are used; relays named here are asked as well.",
        .schema =
        \\{"type":"object","properties":{"code":{"type":"string"},"relays":
        ++ relays_schema ++
            \\,"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["code"]}
        ,
        .handle = toolFetch,
    },
    .{
        .name = "count",
        .description = "Count the events that match a filter on each relay (NIP-45).",
        .schema =
        \\{"type":"object","properties":{"filter":{"type":"object"},"relays":
        ++ relays_schema ++
            \\,"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["relays"]}
        ,
        .handle = toolCount,
    },
    .{
        .name = "relay_info",
        .description = "Fetch relays' NIP-11 information documents.",
        .schema =
        \\{"type":"object","properties":{"relays":
        ++ relays_schema ++
            \\,"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["relays"]}
        ,
        .handle = toolRelayInfo,
    },
    .{
        .name = "relays",
        .description = "Show the relays a person reads from and writes to (NIP-65), looked up at the relays named.",
        .schema =
        \\{"type":"object","properties":{"pubkey":{"type":"string","description":"npub, nprofile or 64 hex characters"},"relays":
        ++ relays_schema ++
            \\,"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["pubkey","relays"]}
        ,
        .handle = toolRelays,
    },
    .{
        .name = "kind",
        .description = "Say what an event kind means: its name, description, defining NIP and storage class. With no argument, lists every kind deed knows.",
        .schema =
        \\{"type":"object","properties":{"kind":{"type":["integer","string"],"description":"a number or a name such as text-note"}}}
        ,
        .handle = toolKind,
        .open_world = false,
    },
    .{
        .name = "store_query",
        .description = "Query the local event store this server was started with. Reads that store and nothing else.",
        .schema =
        \\{"type":"object","properties":{"filter":{"type":"object"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":20}}}
        ,
        .handle = toolStoreQuery,
        .needs = .store,
        .open_world = false,
    },
    .{
        .name = "publish_note",
        .description = "Sign a kind 1 text note with the server's key and offer it to the relays named. Returns the event and the relays that accepted it.",
        .schema =
        \\{"type":"object","properties":{"content":{"type":"string"},"relays":
        ++ relays_schema ++
            \\,"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["content","relays"]}
        ,
        .handle = toolPublishNote,
        .needs = .signer,
    },
    .{
        .name = "publish_event",
        .description = "Sign an event with the server's key and offer it to the relays named. Returns the event and the relays that accepted it. Replaceable, addressable and deletion kinds are refused, because publishing one over data that was not read first can destroy it.",
        .schema =
        \\{"type":"object","properties":{"kind":{"type":"integer","minimum":0,"maximum":65535},"content":{"type":"string"},"tags":{"type":"array","items":{"type":"array","items":{"type":"string"}}},"created_at":{"type":"integer"},"relays":
        ++ relays_schema ++
            \\,"timeout_ms":{"type":"integer","minimum":100,"maximum":30000,"default":10000}},"required":["kind","relays"]}
        ,
        .handle = toolPublishEvent,
        .needs = .signer,
    },
};

fn listed(cfg: Config, t: Tool) bool {
    return switch (t.needs) {
        .none => true,
        .store => cfg.store_path != null,
        .signer => cfg.secret != null,
    };
}

// ---------------------------------------------------------------------------
// The verb
// ---------------------------------------------------------------------------

pub fn run(
    gpa: Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !u8 {
    var cfg: Config = .{};
    var allow_publish = false;
    var sec_flag: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--allow-publish")) {
            allow_publish = true;
        } else if (cli.isOneOf(a, &.{ "--store", "--sec" })) {
            i += 1;
            if (i >= args.len) {
                try err.print("deed mcp: '{s}' needs a value\n", .{a});
                return cli.exit_usage;
            }
            if (std.mem.eql(u8, a, "--store")) cfg.store_path = args[i] else sec_flag = args[i];
        } else {
            try err.print("deed mcp: unknown argument '{s}'\n", .{a});
            return cli.exit_usage;
        }
    }

    if (allow_publish) {
        if (sec_flag) |s| if (keyinput.hasPrefix(s, "bunker://")) {
            try err.writeAll("deed mcp: publishing signs with a local key; a bunker URL is not supported here\n");
            return cli.exit_usage;
        };
        cfg.secret = (cmd_post.readSecret(gpa, "mcp", sec_flag, err) catch |e| switch (e) {
            error.BadKey => return cli.exit_fail,
            else => return e,
        }) orelse return cli.exit_usage;
    }
    defer if (cfg.secret) |*k| std.crypto.secureZero(u8, k);

    const buf = try gpa.alloc(u8, max_line_bytes);
    defer gpa.free(buf);
    // Streaming, for the reason `main` gives for its writers.
    var stdin = Io.File.stdin().readerStreaming(io, buf);
    return serve(gpa, io, cfg, &stdin.interface, out, err);
}

const Server = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    err: *Io.Writer,
};

/// Answers the requests on `in` until it ends. One reply is written and
/// flushed per request that has an id.
pub fn serve(gpa: Allocator, io: Io, cfg: Config, in: *Io.Reader, out: *Io.Writer, err: *Io.Writer) !u8 {
    var s: Server = .{ .gpa = gpa, .io = io, .cfg = cfg, .err = err };
    var count: usize = 0;
    for (tools) |t| {
        if (listed(cfg, t)) count += 1;
    }
    try err.print("deed mcp: serving {d} tools on stdio\n", .{count});
    try err.flush();

    while (true) {
        const line = in.takeDelimiter('\n') catch |e| switch (e) {
            error.StreamTooLong => {
                _ = in.discardDelimiterInclusive('\n') catch 0;
                try replyError(out, null, -32700, "Parse error: the message is too long");
                continue;
            },
            error.ReadFailed => return cli.exit_fail,
        } orelse break;
        const text = std.mem.trim(u8, line, " \t\r");
        if (text.len == 0) continue;
        try handleLine(&s, text, out);
    }
    try err.writeAll("deed mcp: input closed, stopping\n");
    try err.flush();
    return cli.exit_ok;
}

fn handleLine(s: *Server, text: []const u8, out: *Io.Writer) !void {
    var arena_state = std.heap.ArenaAllocator.init(s.gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const msg = std.json.parseFromSliceLeaky(Json, a, text, .{}) catch {
        return replyError(out, null, -32700, "Parse error");
    };
    if (msg != .object) {
        return replyError(out, null, -32600, "Invalid Request: a message is a JSON object, and batches are not supported");
    }
    const obj = msg.object;

    // A response to a request this server never made, or a notification:
    // nothing is sent back for either.
    const method_v = obj.get("method") orelse return;
    const id = obj.get("id");
    if (id == null) return;
    const id_v = id.?;
    if (id_v != .integer and id_v != .string and id_v != .number_string) {
        return replyError(out, null, -32600, "Invalid Request: id must be a string or an integer");
    }
    if (method_v != .string) return replyError(out, id_v, -32600, "Invalid Request: method must be a string");
    const method = method_v.string;
    const params: Json = obj.get("params") orelse .null;

    if (std.mem.eql(u8, method, "initialize")) {
        return initialize(s, a, id_v, params, out);
    } else if (std.mem.eql(u8, method, "ping")) {
        return replyResult(out, id_v, "{}");
    } else if (std.mem.eql(u8, method, "tools/list")) {
        return toolsList(s, a, id_v, out);
    } else if (std.mem.eql(u8, method, "tools/call")) {
        return toolsCall(s, a, id_v, params, out);
    }
    var buf: [256]u8 = undefined;
    const m = std.fmt.bufPrint(&buf, "Method not found: {s}", .{method[0..@min(method.len, 100)]}) catch "Method not found";
    return replyError(out, id_v, -32601, m);
}

fn initialize(s: *Server, a: Allocator, id: Json, params: Json, out: *Io.Writer) !void {
    _ = s;
    var version: []const u8 = protocol_versions[0];
    if (params == .object) if (params.object.get("protocolVersion")) |pv| if (pv == .string) {
        for (protocol_versions) |v| {
            if (std.mem.eql(u8, v, pv.string)) version = v;
        }
    };
    var w: Io.Writer.Allocating = .init(a);
    try w.writer.print(
        "{{\"protocolVersion\":\"{s}\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}}," ++
            "\"serverInfo\":{{\"name\":\"deed\",\"title\":\"deed\",\"version\":\"{s}\"}}," ++
            "\"instructions\":\"Nostr tools: decode and encode NIP-19 codes, verify events, ask relays, look up relay lists and kinds. " ++
            "Relays are named by the caller; there is no built-in list.\"}}",
        .{ version, @import("main.zig").version },
    );
    try replyResult(out, id, w.written());
}

fn toolsList(s: *Server, a: Allocator, id: Json, out: *Io.Writer) !void {
    var w: Io.Writer.Allocating = .init(a);
    const ww = &w.writer;
    try ww.writeAll("{\"tools\":[");
    var first = true;
    for (tools) |t| {
        if (!listed(s.cfg, t)) continue;
        if (!first) try ww.writeByte(',');
        first = false;
        try ww.writeAll("{\"name\":");
        try std.json.Stringify.value(t.name, .{}, ww);
        try ww.writeAll(",\"description\":");
        try std.json.Stringify.value(t.description, .{}, ww);
        try ww.writeAll(",\"inputSchema\":");
        try ww.writeAll(t.schema);
        const writes = t.needs == .signer;
        try ww.print(",\"annotations\":{{\"readOnlyHint\":{s},\"destructiveHint\":false,\"idempotentHint\":{s},\"openWorldHint\":{s}}}}}", .{
            if (writes) "false" else "true",
            if (writes) "false" else "true",
            if (t.open_world) "true" else "false",
        });
    }
    try ww.writeAll("]}");
    try replyResult(out, id, w.written());
}

fn toolsCall(s: *Server, a: Allocator, id: Json, params: Json, out: *Io.Writer) !void {
    if (params != .object) return replyError(out, id, -32602, "Invalid params: expected an object with a tool name");
    const name_v = params.object.get("name") orelse return replyError(out, id, -32602, "Invalid params: name is required");
    if (name_v != .string) return replyError(out, id, -32602, "Invalid params: name must be a string");
    const args: Json = params.object.get("arguments") orelse .{ .object = .empty };
    if (args != .object) return replyError(out, id, -32602, "Invalid params: arguments must be an object");

    const tool = for (tools) |t| {
        if (listed(s.cfg, t) and std.mem.eql(u8, t.name, name_v.string)) break t;
    } else {
        var buf: [256]u8 = undefined;
        const m = std.fmt.bufPrint(&buf, "Unknown tool: {s}", .{name_v.string[0..@min(name_v.string.len, 100)]}) catch "Unknown tool";
        return replyError(out, id, -32602, m);
    };

    var text: Io.Writer.Allocating = .init(a);
    const ok = tool.handle(s, a, args, &text) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => blk: {
            text.clearRetainingCapacity();
            try text.writer.print("{s} failed: {s}", .{ tool.name, @errorName(e) });
            break :blk false;
        },
    };
    s.err.print("deed mcp: {s}: {s}\n", .{ tool.name, if (ok) "ok" else "failed" }) catch {};
    s.err.flush() catch {};

    var w: Io.Writer.Allocating = .init(a);
    try w.writer.writeAll("{\"content\":[{\"type\":\"text\",\"text\":");
    try std.json.Stringify.value(cap(a, text.written(), max_result_bytes), .{}, &w.writer);
    try w.writer.print("}}],\"isError\":{s}}}", .{if (ok) "false" else "true"});
    try replyResult(out, id, w.written());
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

fn writeId(out: *Io.Writer, id: ?Json) !void {
    if (id) |v| try std.json.Stringify.value(v, .{}, out) else try out.writeAll("null");
}

fn replyResult(out: *Io.Writer, id: Json, result: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(out, id);
    try out.writeAll(",\"result\":");
    try out.writeAll(result);
    try out.writeAll("}\n");
    try out.flush();
}

fn replyError(out: *Io.Writer, id: ?Json, code: i32, message: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(out, id);
    try out.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
    try std.json.Stringify.value(message, .{}, out);
    try out.writeAll("}}\n");
    try out.flush();
}

/// `text`, or its first `limit` bytes cut at a line and followed by a note.
fn cap(a: Allocator, text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;
    var end = limit;
    if (std.mem.lastIndexOfScalar(u8, text[0..end], '\n')) |nl| {
        if (nl > limit / 2) end = nl;
    }
    // Never cut inside a UTF-8 sequence.
    while (end > 0 and end < text.len and (text[end] & 0xC0) == 0x80) end -= 1;
    return std.fmt.allocPrint(
        a,
        "{s}\n[truncated: {d} of {d} bytes shown; narrow the filter or lower limit]",
        .{ text[0..end], end, text.len },
    ) catch text[0..end];
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn fail(out: *Io.Writer.Allocating, msg: []const u8) !bool {
    out.clearRetainingCapacity();
    try out.writer.writeAll(msg);
    return false;
}

fn failf(out: *Io.Writer.Allocating, comptime fmt: []const u8, args: anytype) !bool {
    out.clearRetainingCapacity();
    try out.writer.print(fmt, args);
    return false;
}

fn field(args: Json, name: []const u8) ?Json {
    if (args != .object) return null;
    const v = args.object.get(name) orelse return null;
    return if (v == .null) null else v;
}

fn strArg(args: Json, name: []const u8) ?[]const u8 {
    const v = field(args, name) orelse return null;
    return if (v == .string) v.string else null;
}

fn intArg(args: Json, name: []const u8) ?i64 {
    const v = field(args, name) orelse return null;
    return switch (v) {
        .integer => |n| n,
        .float => |f| if (f == @floor(f) and @abs(f) < 1e15) @as(i64, @intFromFloat(f)) else null,
        else => null,
    };
}

fn clamped(args: Json, name: []const u8, default: i64, lo: i64, hi: i64) i64 {
    return std.math.clamp(intArg(args, name) orelse default, lo, hi);
}

fn timeoutMs(args: Json) i64 {
    return clamped(args, "timeout_ms", default_timeout_ms, min_timeout_ms, max_timeout_ms);
}

fn num(a: Allocator, n: i64) ![]const u8 {
    return std.fmt.allocPrint(a, "{d}", .{n});
}

/// Text that is safe to hand a verb as a positional argument: not empty, not
/// something a verb would read as an option, and free of control characters.
fn plain(s: []const u8) bool {
    if (s.len == 0 or s.len > 4096 or s[0] == '-') return false;
    for (s) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

fn isWsUrl(s: []const u8) bool {
    if (!(std.mem.startsWith(u8, s, "wss://") or std.mem.startsWith(u8, s, "ws://"))) return false;
    if (s.len > 512) return false;
    for (s) |c| if (c <= 0x20 or c == 0x7f) return false;
    return true;
}

/// The strings of an array argument, or null when it is absent. A wrong shape
/// is `error.BadArgument`.
fn stringList(a: Allocator, args: Json, name: []const u8) !?[]const []const u8 {
    const v = field(args, name) orelse return null;
    if (v != .array) return error.BadArgument;
    var list: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |item| {
        if (item != .string) return error.BadArgument;
        try list.append(a, item.string);
    }
    return list.items;
}

/// The relay URLs of the call, checked. Null after saying what is wrong.
fn relayList(a: Allocator, args: Json, out: *Io.Writer.Allocating, required: bool) !?[]const []const u8 {
    const list = (stringList(a, args, "relays") catch {
        _ = try fail(out, "relays must be an array of strings");
        return null;
    }) orelse &[_][]const u8{};
    if (required and list.len == 0) {
        _ = try fail(out, "relays is required: name at least one ws:// or wss:// relay");
        return null;
    }
    if (list.len > max_tool_relays) {
        _ = try failf(out, "name at most {d} relays", .{max_tool_relays});
        return null;
    }
    for (list) |u| if (!isWsUrl(u)) {
        _ = try failf(out, "'{s}' is not a ws:// or wss:// relay URL", .{u[0..@min(u.len, 100)]});
        return null;
    };
    return list;
}

fn jsonArg(a: Allocator, args: Json, name: []const u8, out: *Io.Writer.Allocating) !?[]const u8 {
    const v = field(args, name) orelse return try a.dupe(u8, "{}");
    if (v != .object) {
        _ = try failf(out, "{s} must be an object", .{name});
        return null;
    }
    return try std.json.Stringify.valueAlloc(a, v, .{});
}

// ---------------------------------------------------------------------------
// Running a verb
// ---------------------------------------------------------------------------

const VerbFn = *const fn (Allocator, Io, []const []const u8, *Io.Writer, *Io.Writer) anyerror!u8;

const Captured = struct {
    code: u8,
    out: []const u8,
    err: []const u8,
};

fn capture(s: *Server, a: Allocator, runner: VerbFn, argv: []const []const u8) !Captured {
    var o: Io.Writer.Allocating = .init(a);
    var e: Io.Writer.Allocating = .init(a);
    const code = try runner(s.gpa, s.io, argv, &o.writer, &e.writer);
    return .{ .code = code, .out = o.written(), .err = std.mem.trim(u8, e.written(), "\n ") };
}

/// Writes what a verb produced as the tool's text. Success is its stdout and
/// whatever it said on stderr; failure is its stderr.
fn present(a: Allocator, c: Captured, out: *Io.Writer.Allocating) !bool {
    const w = &out.writer;
    if (c.code != cli.exit_ok) {
        try w.writeAll(if (c.err.len > 0) cap(a, c.err, max_notes_bytes) else if (c.out.len > 0) c.out else "failed with no message");
        return false;
    }
    if (c.out.len == 0) try w.writeAll("(no results)") else try w.writeAll(std.mem.trimEnd(u8, c.out, "\n"));
    if (c.err.len > 0) {
        try w.writeAll("\n\nnotes:\n");
        try w.writeAll(cap(a, c.err, max_notes_bytes));
    }
    return true;
}

fn encodeRunner(gpa: Allocator, io: Io, args: []const []const u8, out: *Io.Writer, err: *Io.Writer) anyerror!u8 {
    _ = io;
    return cmd_encode.run(gpa, args, out, err);
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

fn toolDecode(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const input = std.mem.trim(u8, strArg(args, "input") orelse return fail(out, "input is required"), " \t\r\n");
    if (!plain(input)) return fail(out, "input must be a NIP-19 code or a NIP-05 identifier");
    if (keyinput.hasPrefix(keyinput.stripUri(input), "nsec1")) {
        return fail(out, "refusing to decode a secret key");
    }
    return present(a, try capture(s, a, cmd_decode.run, &.{input}), out);
}

fn toolEncode(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const kind = strArg(args, "type") orelse return fail(out, "type is required");
    const ok_kind = for ([_][]const u8{ "npub", "note", "nprofile", "nevent", "naddr" }) |k| {
        if (std.mem.eql(u8, k, kind)) break true;
    } else false;
    if (!ok_kind) return fail(out, "type must be one of npub, note, nprofile, nevent, naddr");
    const value = strArg(args, "value") orelse return fail(out, "value is required");
    if (!std.mem.eql(u8, kind, "naddr") and !plain(value)) return fail(out, "value must be 64 hex characters");
    if (std.mem.eql(u8, kind, "naddr") and (value.len > 1024 or (value.len > 0 and value[0] == '-'))) {
        return fail(out, "value, the identifier, cannot start with '-'");
    }

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ kind, value });
    const relays = (try relayList(a, args, out, false)) orelse return false;
    for (relays) |r| try argv.appendSlice(a, &.{ "--relay", r });
    if (strArg(args, "author")) |v| {
        if (!plain(v)) return fail(out, "author must be 64 hex characters");
        try argv.appendSlice(a, &.{ "--author", v });
    }
    if (strArg(args, "pubkey")) |v| {
        if (!plain(v)) return fail(out, "pubkey must be 64 hex characters");
        try argv.appendSlice(a, &.{ "--pubkey", v });
    }
    if (intArg(args, "kind")) |k| try argv.appendSlice(a, &.{ "--kind", try num(a, k) });
    return present(a, try capture(s, a, encodeRunner, argv.items), out);
}

fn toolVerify(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const ev = field(args, "event") orelse return fail(out, "event is required");
    const text: []const u8 = switch (ev) {
        .object => try std.json.Stringify.valueAlloc(a, ev, .{}),
        .string => |t| std.mem.trim(u8, t, " \t\r\n"),
        else => return fail(out, "event must be an object"),
    };
    if (text.len == 0 or text[0] != '{') return fail(out, "event must be a JSON object");
    const c = try capture(s, a, cmd_verify.run, &.{text});
    const w = &out.writer;
    switch (c.code) {
        cli.exit_ok => try w.writeAll("{\"valid\":true}"),
        cli.exit_fail => {
            try w.writeAll("{\"valid\":false,\"detail\":");
            try std.json.Stringify.value(cap(a, c.err, max_notes_bytes), .{}, w);
            try w.writeByte('}');
        },
        else => return present(a, c, out),
    }
    return true;
}

fn toolReq(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const filter_json = (try jsonArg(a, args, "filter", out)) orelse return false;
    const relays = (try relayList(a, args, out, true)) orelse return false;
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(a, filter_json);
    try argv.appendSlice(a, relays);
    try argv.appendSlice(a, &.{ "-l", try num(a, clamped(args, "limit", default_limit, 1, max_limit)) });
    try argv.appendSlice(a, &.{ "--timeout", try num(a, timeoutMs(args)) });
    return present(a, try capture(s, a, cmd_req.run, argv.items), out);
}

fn toolFetch(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const code = std.mem.trim(u8, strArg(args, "code") orelse return fail(out, "code is required"), " \t\r\n");
    if (!plain(code)) return fail(out, "code must be a NIP-19 code");
    if (keyinput.hasPrefix(keyinput.stripUri(code), "nsec1")) return fail(out, "refusing to handle a secret key");
    const relays = (try relayList(a, args, out, false)) orelse return false;
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(a, code);
    try argv.appendSlice(a, relays);
    try argv.appendSlice(a, &.{ "--timeout", try num(a, timeoutMs(args)) });
    return present(a, try capture(s, a, cmd_fetch.run, argv.items), out);
}

fn toolCount(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const filter_json = (try jsonArg(a, args, "filter", out)) orelse return false;
    const relays = (try relayList(a, args, out, true)) orelse return false;
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(a, filter_json);
    try argv.appendSlice(a, relays);
    try argv.appendSlice(a, &.{ "--timeout", try num(a, timeoutMs(args)) });
    return present(a, try capture(s, a, cmd_count.run, argv.items), out);
}

fn toolRelayInfo(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const list = (stringList(a, args, "relays") catch return fail(out, "relays must be an array of strings")) orelse
        return fail(out, "relays is required");
    if (list.len == 0 or list.len > max_tool_relays) return failf(out, "name between 1 and {d} relays", .{max_tool_relays});
    for (list) |r| if (!plain(r) or std.mem.indexOfScalar(u8, r, ' ') != null) return failf(out, "'{s}' is not a relay", .{r[0..@min(r.len, 100)]});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ "--timeout", try num(a, @divTrunc(timeoutMs(args) + 999, 1000)) });
    try argv.appendSlice(a, list);
    return present(a, try capture(s, a, cmd_relay.run, argv.items), out);
}

fn toolRelays(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const pk = std.mem.trim(u8, strArg(args, "pubkey") orelse return fail(out, "pubkey is required"), " \t\r\n");
    if (!plain(pk)) return fail(out, "pubkey must be an npub, an nprofile or 64 hex characters");
    const relays = (try relayList(a, args, out, true)) orelse return false;
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ "--json", pk });
    try argv.appendSlice(a, relays);
    try argv.appendSlice(a, &.{ "--timeout", try num(a, timeoutMs(args)) });
    return present(a, try capture(s, a, cmd_relays.run, argv.items), out);
}

fn toolKind(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    var argv: std.ArrayList([]const u8) = .empty;
    if (field(args, "kind")) |k| switch (k) {
        .integer => |n| try argv.append(a, try num(a, n)),
        .string => |t| {
            if (!plain(t)) return fail(out, "kind must be a number or a name");
            try argv.append(a, t);
        },
        else => return fail(out, "kind must be a number or a name"),
    };
    return present(a, try capture(s, a, cmd_kind.run, argv.items), out);
}

fn toolStoreQuery(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const path = s.cfg.store_path orelse return fail(out, "no store was named when the server started");
    const filter_json = (try jsonArg(a, args, "filter", out)) orelse return false;
    const argv = [_][]const u8{
        filter_json, "--local", "--store", path, "-l", try num(a, clamped(args, "limit", default_limit, 1, max_limit)),
    };
    return present(a, try capture(s, a, cmd_req.run, &argv), out);
}

fn toolPublishNote(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const content = strArg(args, "content") orelse return fail(out, "content is required");
    return publish(s, a, args, 1, &.{}, content, null, out);
}

fn toolPublishEvent(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const kind_n = intArg(args, "kind") orelse return fail(out, "kind is required");
    if (kind_n < 0 or kind_n > 65535) return fail(out, "kind must be from 0 to 65535");
    const kind: u16 = @intCast(kind_n);
    if (kinds.classOf(kind) != .regular and kinds.classOf(kind) != .ephemeral) {
        return fail(out, "refused: replaceable and addressable kinds replace what a relay holds, and that has to be read first; use a command line for those");
    }
    if (kind == 5) return fail(out, "refused: deletion requests are not offered as a tool");
    const content = strArg(args, "content") orelse "";

    var tags: std.ArrayList(event.Tag) = .empty;
    if (field(args, "tags")) |tv| {
        if (tv != .array) return fail(out, "tags must be an array of arrays of strings");
        if (tv.array.items.len > max_tags) return failf(out, "at most {d} tags", .{max_tags});
        for (tv.array.items) |row| {
            if (row != .array or row.array.items.len == 0) return fail(out, "each tag is a non-empty array of strings");
            var parts: std.ArrayList([]const u8) = .empty;
            for (row.array.items) |p| {
                if (p != .string) return fail(out, "each tag is a non-empty array of strings");
                try parts.append(a, p.string);
            }
            try tags.append(a, parts.items);
        }
    }
    return publish(s, a, args, kind, tags.items, content, intArg(args, "created_at"), out);
}

fn publish(
    s: *Server,
    a: Allocator,
    args: Json,
    kind: u16,
    tags: []const event.Tag,
    content: []const u8,
    created_at: ?i64,
    out: *Io.Writer.Allocating,
) !bool {
    const sk = s.cfg.secret orelse return fail(out, "no signing key");
    if (content.len > max_content_bytes) return failf(out, "content is longer than {d} bytes", .{max_content_bytes});
    if (std.mem.trim(u8, content, " \t\r\n").len == 0 and kind == 1) return fail(out, "nothing to post");
    const relays = (try relayList(a, args, out, true)) orelse return false;

    var signer = try nostr.keys.Signer.initRandomized(s.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(sk);
    const at = created_at orelse Io.Timestamp.now(s.io, .real).toSeconds();
    const ev = try event.create(a, signer, kp, at, kind, tags, content, null);
    const wire = try event.toJson(a, ev);
    const id = try nostr.hex.encode(a, &ev.id);

    var answers: Io.Writer.Allocating = .init(a);
    const accepted = try cmd_post.publishEvent(s.gpa, s.io, relays, ev, timeoutMs(args), "mcp", &answers.writer);
    if (accepted == 0) return failf(out, "not published: no relay accepted event {s}", .{id});

    // Only the relays that said yes are reported. Their answers are read back
    // out of the shared publisher's report: "deed mcp: <id>: <url>: accepted".
    const w = &out.writer;
    try w.print("{{\"accepted\":true,\"id\":\"{s}\",\"relays\":[", .{id});
    const prefix = try std.fmt.allocPrint(a, "deed mcp: {s}: ", .{id});
    var first = true;
    var lines = std.mem.splitScalar(u8, answers.written(), '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const rest = line[prefix.len..];
        const at_ok = std.mem.indexOf(u8, rest, ": accepted") orelse continue;
        const url = rest[0..at_ok];
        if (!isWsUrl(url)) continue;
        if (!first) try w.writeByte(',');
        first = false;
        try std.json.Stringify.value(url, .{}, w);
    }
    try w.writeAll("],\"event\":");
    try w.writeAll(wire);
    try w.writeByte('}');
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const testrelay = @import("testrelay.zig");

/// Plays an MCP client: sends `requests` (one per line), and returns the
/// server's replies.
fn converse(gpa: Allocator, cfg: Config, requests: []const u8) ![]u8 {
    var reader: Io.Reader = .fixed(requests);
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const code = try serve(gpa, testing.io, cfg, &reader, &out.writer, &err.writer);
    try testing.expectEqual(cli.exit_ok, code);
    // Logs are on stderr, never in the protocol stream.
    try testing.expect(std.mem.indexOf(u8, err.written(), "deed mcp: ") != null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "deed mcp:") == null);
    return gpa.dupe(u8, out.written());
}

fn has(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

fn callLine(a: Allocator, id: u32, name: []const u8, arguments: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"tools/call\",\"params\":{{\"name\":\"{s}\",\"arguments\":{s}}}}}\n", .{ id, name, arguments });
}

const init_line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n" ++
    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

/// The one reply with `"id":N`, as a line.
fn replyFor(all: []const u8, id: u32, buf: []u8) ?[]const u8 {
    const want = std.fmt.bufPrint(buf, "\"id\":{d},", .{id}) catch return null;
    var lines = std.mem.splitScalar(u8, all, '\n');
    while (lines.next()) |l| if (has(l, want)) return l;
    return null;
}

test "initialize negotiates, a notification gets no reply, tools/list lists the read tools" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    const got = try converse(gpa, .{}, init_line ++
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n");
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    const init_reply = replyFor(got, 1, &b).?;
    try testing.expect(has(init_reply, "\"protocolVersion\":\"2025-06-18\""));
    try testing.expect(has(init_reply, "\"tools\":{"));
    try testing.expect(has(init_reply, "\"name\":\"deed\""));
    // Three requests with ids, one notification: three replies.
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, got, "\n"));

    const list = replyFor(got, 2, &b).?;
    for ([_][]const u8{ "decode", "encode", "verify", "req", "fetch", "count", "relay_info", "relays", "kind" }) |n| {
        var key: [64]u8 = undefined;
        try testing.expect(has(list, try std.fmt.bufPrint(&key, "\"name\":\"{s}\"", .{n})));
    }
    // No store, no signer: neither of those groups is offered.
    try testing.expect(!has(list, "store_query"));
    try testing.expect(!has(list, "publish_note"));
    try testing.expect(!has(list, "publish_event"));
    try testing.expect(has(replyFor(got, 3, &b).?, "\"result\":{}"));
}

test "an unknown version is answered with the newest this server speaks" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const got = try converse(gpa, .{}, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}\n");
    defer gpa.free(got);
    try testing.expect(has(got, "\"id\":\"a\""));
    try testing.expect(has(got, "\"protocolVersion\":\"" ++ protocol_versions[0] ++ "\""));
}

test "malformed JSON-RPC gets the standard errors and the server carries on" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    const got = try converse(gpa, .{},
        \\{not json
        \\[1,2]
        \\"just a string"
        \\{"jsonrpc":"2.0","id":7,"method":"nope/nothing"}
        \\{"jsonrpc":"2.0","id":8,"method":42}
        \\{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}
        \\{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"arguments":{}}}
        \\{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"decode","arguments":[]}}
        \\{"jsonrpc":"2.0","id":11,"method":"ping"}
        \\
    );
    defer gpa.free(got);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, got, "\n"), '\n');
    const want = [_][]const u8{
        "\"id\":null,\"error\":{\"code\":-32700",
        "\"id\":null,\"error\":{\"code\":-32600",
        "\"id\":null,\"error\":{\"code\":-32600",
        "\"id\":7,\"error\":{\"code\":-32601",
        "\"id\":8,\"error\":{\"code\":-32600",
        "\"id\":null,\"error\":{\"code\":-32600",
        "\"id\":9,\"error\":{\"code\":-32602",
        "\"id\":10,\"error\":{\"code\":-32602",
        "\"id\":11,\"result\":{}",
    };
    for (want) |w| try testing.expect(has(lines.next() orelse return error.MissingReply, w));
    try testing.expect(lines.next() == null);
}

test "an unknown tool is a protocol error naming it" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const line = try callLine(gpa, 4, "levitate", "{}");
    defer gpa.free(line);
    const got = try converse(gpa, .{}, line);
    defer gpa.free(got);
    try testing.expect(has(got, "\"error\":{\"code\":-32602"));
    try testing.expect(has(got, "Unknown tool: levitate"));
}

test "encode then decode round trips, and decode refuses a secret key" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    const enc = try callLine(gpa, 1, "encode", "{\"type\":\"npub\",\"value\":\"" ++ "11" ** 32 ++ "\"}");
    defer gpa.free(enc);
    const got = try converse(gpa, .{}, enc);
    defer gpa.free(got);
    try testing.expect(has(got, "\"isError\":false"));
    const at = std.mem.indexOf(u8, got, "npub1").?;
    const npub = got[at..][0..std.mem.indexOfScalar(u8, got[at..], '"').?];

    const dec_args = try std.fmt.allocPrint(gpa, "{{\"input\":\"{s}\"}}", .{npub});
    defer gpa.free(dec_args);
    const dec = try callLine(gpa, 2, "decode", dec_args);
    defer gpa.free(dec);
    const nsec = try callLine(gpa, 3, "decode", "{\"input\":\"nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\"}");
    defer gpa.free(nsec);
    const two = try std.mem.concat(gpa, u8, &.{ dec, nsec });
    defer gpa.free(two);
    const got2 = try converse(gpa, .{}, two);
    defer gpa.free(got2);
    var b: [32]u8 = undefined;
    const d = replyFor(got2, 2, &b).?;
    try testing.expect(has(d, "\"isError\":false"));
    try testing.expect(has(d, "11" ** 32));
    const n = replyFor(got2, 3, &b).?;
    try testing.expect(has(n, "\"isError\":true"));
    try testing.expect(has(n, "refusing to decode a secret key"));
}

test "a value that would be read as a flag is refused" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const l1 = try callLine(gpa, 1, "decode", "{\"input\":\"--help\"}");
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "req", "{\"relays\":[\"--store\"]}");
    defer gpa.free(l2);
    const l3 = try callLine(gpa, 3, "fetch", "{\"code\":\"-r\"}");
    defer gpa.free(l3);
    const l4 = try callLine(gpa, 4, "req", "{\"relays\":[\"https://x.example\"]}");
    defer gpa.free(l4);
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2, l3, l4 });
    defer gpa.free(all);
    const got = try converse(gpa, .{}, all);
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, got, "\"isError\":true"));
}

test "verify tells a good event from a tampered one" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const ev = try cmd_post.signedJson(gpa, testing.io, [_]u8{0x21} ** 32, 1, &.{}, "genuine", 1_700_000_000);
    defer gpa.free(ev);
    const bad = try std.mem.replaceOwned(u8, gpa, ev, "genuine", "forged!");
    defer gpa.free(bad);

    const good_args = try std.fmt.allocPrint(gpa, "{{\"event\":{s}}}", .{ev});
    defer gpa.free(good_args);
    const bad_args = try std.fmt.allocPrint(gpa, "{{\"event\":{s}}}", .{bad});
    defer gpa.free(bad_args);
    const l1 = try callLine(gpa, 1, "verify", good_args);
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "verify", bad_args);
    defer gpa.free(l2);
    const l3 = try callLine(gpa, 3, "verify", "{\"event\":\"nonsense\"}");
    defer gpa.free(l3);
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2, l3 });
    defer gpa.free(all);
    const got = try converse(gpa, .{}, all);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    try testing.expect(has(replyFor(got, 1, &b).?, "{\\\"valid\\\":true}"));
    try testing.expect(has(replyFor(got, 2, &b).?, "{\\\"valid\\\":false"));
    try testing.expect(has(replyFor(got, 3, &b).?, "\"isError\":true"));
}

test "kind answers for a number and for a name" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const l1 = try callLine(gpa, 1, "kind", "{\"kind\":7}");
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "kind", "{\"kind\":\"text-note\"}");
    defer gpa.free(l2);
    const l3 = try callLine(gpa, 3, "kind", "{\"kind\":\"no-such-kind\"}");
    defer gpa.free(l3);
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2, l3 });
    defer gpa.free(all);
    const got = try converse(gpa, .{}, all);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    try testing.expect(has(replyFor(got, 1, &b).?, "reaction"));
    try testing.expect(has(replyFor(got, 2, &b).?, "\\\"kind\\\":1,"));
    try testing.expect(has(replyFor(got, 3, &b).?, "\"isError\":true"));
}

test "req returns the events a scripted relay serves, checked, within the deadline" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    const ev = try cmd_post.signedJson(gpa, io, [_]u8{0x33} ** 32, 1, &.{}, "from the relay", 1_700_000_000);
    defer gpa.free(ev);
    var script = cmd_post.Script{ .serve = ev };
    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, cmd_post.Script.handle, &script);
    defer relay.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, relay.port());

    const args = try std.fmt.allocPrint(gpa, "{{\"filter\":{{\"kinds\":[1]}},\"relays\":[\"{s}\"],\"limit\":5,\"timeout_ms\":5000}}", .{url});
    defer gpa.free(args);
    const line = try callLine(gpa, 1, "req", args);
    defer gpa.free(line);
    const got = try converse(gpa, .{}, line);
    defer gpa.free(got);
    try testing.expect(has(got, "\"isError\":false"));
    try testing.expect(has(got, "from the relay"));
}

test "a relay that never answers costs the deadline and the server answers the next call" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var relay: testrelay.Relay = undefined;
    try relay.start(io, .silent);
    defer relay.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, relay.port());

    const args = try std.fmt.allocPrint(gpa, "{{\"relays\":[\"{s}\"],\"timeout_ms\":300}}", .{url});
    defer gpa.free(args);
    const l1 = try callLine(gpa, 1, "req", args);
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "kind", "{\"kind\":1}");
    defer gpa.free(l2);
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2 });
    defer gpa.free(all);
    const got = try converse(gpa, .{}, all);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    try testing.expect(replyFor(got, 1, &b) != null);
    try testing.expect(has(replyFor(got, 2, &b).?, "\"isError\":false"));
}

test "a long result is cut at a line with a note" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const text = "line one\nline two\nline three\n";
    const cut = cap(a, text, 20);
    try testing.expect(std.mem.startsWith(u8, cut, "line one\nline two\n[truncated"));
    try testing.expectEqualStrings(text, cap(a, text, 100));
}

test "publishing tools exist only with a signer, and never take a key" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    const sk: nostr.keys.SecretKey = [_]u8{0x44} ** 32;
    const lines = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
    const with = try converse(gpa, .{ .secret = sk }, lines);
    defer gpa.free(with);
    try testing.expect(has(with, "\"name\":\"publish_note\""));
    try testing.expect(has(with, "\"name\":\"publish_event\""));
    try testing.expect(!has(with, "\"sec\""));
    try testing.expect(!has(with, "secret"));
    try testing.expect(!has(with, "nsec\""));

    // Without the signer the same call is an unknown tool.
    const l = try callLine(gpa, 2, "publish_note", "{\"content\":\"x\",\"relays\":[\"ws://127.0.0.1:1\"]}");
    defer gpa.free(l);
    const without = try converse(gpa, .{}, l);
    defer gpa.free(without);
    try testing.expect(has(without, "Unknown tool: publish_note"));
}

test "publish_note signs with the server's key and reports the relay that accepted" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var script = cmd_post.Script{};
    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, cmd_post.Script.handle, &script);
    defer relay.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, relay.port());

    const args = try std.fmt.allocPrint(gpa, "{{\"content\":\"hello mcp\",\"relays\":[\"{s}\"],\"timeout_ms\":5000}}", .{url});
    defer gpa.free(args);
    const line = try callLine(gpa, 1, "publish_note", args);
    defer gpa.free(line);
    const got = try converse(gpa, .{ .secret = [_]u8{0x44} ** 32 }, line);
    defer gpa.free(got);
    try testing.expect(has(got, "\"isError\":false"));
    try testing.expect(has(got, "\\\"accepted\\\":true"));
    try testing.expect(has(got, url));
    try testing.expectEqual(@as(usize, 1), script.events);
    try testing.expect(has(script.got[0..script.got_len], "hello mcp"));
}

test "publish_event refuses kinds that replace, and a relay that refuses reports no success" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var script = cmd_post.Script{ .refuse = true };
    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, cmd_post.Script.handle, &script);
    defer relay.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, relay.port());

    const a1 = try std.fmt.allocPrint(gpa, "{{\"kind\":3,\"relays\":[\"{s}\"]}}", .{url});
    defer gpa.free(a1);
    const a2 = try std.fmt.allocPrint(gpa, "{{\"kind\":7,\"content\":\"+\",\"tags\":[[\"e\",\"{s}\"]],\"relays\":[\"{s}\"],\"timeout_ms\":3000}}", .{ "ab" ** 32, url });
    defer gpa.free(a2);
    const l1 = try callLine(gpa, 1, "publish_event", a1);
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "publish_event", a2);
    defer gpa.free(l2);
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2 });
    defer gpa.free(all);
    const got = try converse(gpa, .{ .secret = [_]u8{0x44} ** 32 }, all);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    try testing.expect(has(replyFor(got, 1, &b).?, "refused: replaceable"));
    const r2 = replyFor(got, 2, &b).?;
    try testing.expect(has(r2, "\"isError\":true"));
    try testing.expect(has(r2, "no relay accepted"));
    try testing.expect(!has(r2, "\\\"accepted\\\":true"));
}
