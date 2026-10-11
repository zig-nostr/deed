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
    \\  deed mcp [--store <path>] [--allow-local] [--allow-publish [--sec <key>]]
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
    \\      --allow-local      let relay_info reach loopback and private
    \\                         addresses, for a relay on this machine or LAN
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
const protocol_versions = [_][]const u8{ "2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };

/// The newest revision that is legacy: it opens with `initialize`. This is
/// what an `initialize` that names no known version is answered with, since
/// 2026-07-28 and later have no handshake (Versioning and Compatibility,
/// "Backward Compatibility with Initialization-Based Versions").
const newest_legacy_version = "2025-11-25";

/// The first revision with per-request metadata and no handshake.
const modern_version = "2026-07-28";

/// `_meta` keys reserved by the revision (Base Protocol, "General fields",
/// "_meta", "Per-request protocol fields").
const meta_version = "io.modelcontextprotocol/protocolVersion";
const meta_caps = "io.modelcontextprotocol/clientCapabilities";
const meta_server_info = "io.modelcontextprotocol/serverInfo";

/// Error code for an unsupported version (Base Protocol, "Error Codes":
/// `UnsupportedProtocolVersion`). -32020 to -32099 belong to the spec.
const err_unsupported_version = -32022;

/// How long a client may keep a tools/list or server/discover result
/// (Caching utility: `ttlMs`, `cacheScope`). The tool set is fixed for the
/// life of the process and depends on how it was started, so it is private.
const instructions_json = "\"Nostr tools: decode and encode NIP-19 codes, verify events, ask relays, look up relay lists and kinds. " ++
    "Relays are named by the caller; there is no built-in list.\"";

const cache_fields = ",\"ttlMs\":3600000,\"cacheScope\":\"private\"";

/// The most a tool's result text holds before it is cut.
const max_result_bytes = 256 * 1024;
/// The most of a verb's stderr that rides along with a result.
const max_notes_bytes = 4 * 1024;
/// The longest request line read.
const max_line_bytes = 1 << 20;
/// Relays one call may name.
const max_tool_relays = 8;
/// How deeply a tool's arguments may nest.
const max_json_depth = 32;

const default_timeout_ms: i64 = 10_000;
const min_timeout_ms: i64 = 100;
const max_timeout_ms: i64 = 30_000;
const default_limit: i64 = 20;
const max_limit: i64 = 200;

const max_content_bytes = 256 * 1024;
const max_tags = 512;

/// The kinds publish_event signs, and nothing else. A signature is a
/// credential: some kinds act for the key rather than say something, and a
/// relay that answers OK false has still been handed the signed event, so the
/// list names what is safe instead of what is not.
const publishable_kinds = [_]u16{
    // A text note: the same thing publish_note signs.
    1,
    // A repost of a kind 1 note. It points at a note that already exists.
    6,
    // A reaction to an event.
    7,
    // A generic repost of an event of any other kind.
    16,
    // A comment (NIP-22).
    1111,
    // A highlight (NIP-84): a quote from a piece of content.
    9802,
};

/// Tags whose meaning belongs to an authentication or a deletion-like event:
/// NIP-42 AUTH (relay, challenge), NIP-62 request to vanish (relay), and
/// NIP-98 HTTP auth (u, method, payload). Refused on every kind, so an event
/// signed here never carries what a careless verifier would check.
const refused_tags = [_][]const u8{ "challenge", "relay", "u", "method", "payload" };

/// How far created_at may be from now, either way.
const max_clock_skew_s: i64 = 300;

pub const Config = struct {
    /// The store `store_query` reads. Null leaves the tool out.
    store_path: ?[]const u8 = null,
    /// The key that signs what the publishing tools publish. Null leaves
    /// those tools out.
    secret: ?nostr.keys.SecretKey = null,
    /// relay_info may reach loopback and private addresses.
    allow_local: bool = false,
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
        .description = "Fetch relays' NIP-11 information documents. Relays are ws:// or wss:// URLs on public addresses.",
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
        .description = "Sign an event with the server's key and offer it to the relays named. Returns the event and the relays that accepted it. Only kinds 1 (note), 6 and 16 (repost), 7 (reaction), 1111 (comment) and 9802 (highlight) are signed; created_at must be within five minutes of now, and challenge, relay, u, method and payload tags are refused.",
        .schema =
        \\{"type":"object","properties":{"kind":{"type":"integer","enum":[1,6,7,16,1111,9802]},"content":{"type":"string"},"tags":{"type":"array","items":{"type":"array","items":{"type":"string"}}},"created_at":{"type":"integer","description":"unix seconds, within 300 of now; defaults to now"},"relays":
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
        } else if (std.mem.eql(u8, a, "--allow-local")) {
            cfg.allow_local = true;
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
        const raw = sec_flag orelse envSecret() orelse {
            try err.writeAll("deed mcp: needs a secret key: pass --sec or set $NOSTR_SECRET_KEY\n");
            return cli.exit_usage;
        };
        cfg.secret = keyinput.secretKeyForVerb(gpa, "mcp", raw, err) catch |e| switch (e) {
            error.BadKey => return cli.exit_fail,
            else => return e,
        };
    }
    defer if (cfg.secret) |*k| std.crypto.secureZero(u8, k);

    const buf = try gpa.alloc(u8, max_line_bytes);
    defer gpa.free(buf);
    // Streaming, for the reason `main` gives for its writers.
    var stdin = Io.File.stdin().readerStreaming(io, buf);
    return serve(gpa, io, cfg, &stdin.interface, out, err);
}

fn envSecret() ?[]const u8 {
    const value = std.c.getenv("NOSTR_SECRET_KEY") orelse return null;
    const span = std.mem.span(value);
    return if (span.len == 0) null else span;
}

const Server = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    err: *Io.Writer,
    /// Set per request: it carried 2026-07-28 or later metadata, so the
    /// result gets `resultType` and `serverInfo`. The protocol keeps no
    /// state between requests (Base Protocol, "Statelessness").
    modern: bool = false,
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

    // A request that carries per-request metadata speaks the revision with no
    // handshake (Versioning and Compatibility, "Protocol Version
    // Negotiation"); one without it is served the legacy way, so a dual-era
    // server answers `initialize` clients as before ("Backward Compatibility
    // with Initialization-Based Versions"). The two are told apart per
    // request, never per connection.
    s.modern = false;
    var requested: ?[]const u8 = null;
    if (params == .object) if (params.object.get("_meta")) |meta| if (meta == .object) {
        if (meta.object.get(meta_version)) |pv| {
            if (pv != .string) return replyError(out, id_v, -32602, "Invalid params: " ++ meta_version ++ " must be a string");
            requested = pv.string;
        }
    };
    if (std.mem.eql(u8, method, "server/discover") and requested == null) {
        // Base Protocol, "Per-request protocol fields": a request missing a
        // required field is malformed.
        return replyError(out, id_v, -32602, "Invalid params: _meta must carry " ++ meta_version ++ " and " ++ meta_caps);
    }
    if (requested) |rv| {
        var known = false;
        for (protocol_versions) |v| known = known or std.mem.eql(u8, v, rv);
        if (!known) return unsupportedVersion(a, id_v, rv, out);
        if (std.mem.eql(u8, rv, modern_version)) {
            const meta = params.object.get("_meta").?.object;
            const caps = meta.get(meta_caps) orelse
                return replyError(out, id_v, -32602, "Invalid params: _meta must carry " ++ meta_caps);
            if (caps != .object) return replyError(out, id_v, -32602, "Invalid params: " ++ meta_caps ++ " must be an object");
            s.modern = true;
        }
    }

    if (s.modern) {
        // Removed by this revision: `initialize`, `notifications/initialized`
        // and `ping` (Key Changes, major changes 2 and 5). They fall through
        // to "Method not found" below.
        if (std.mem.eql(u8, method, "server/discover")) {
            return discover(s, a, id_v, out);
        } else if (std.mem.eql(u8, method, "tools/list")) {
            return toolsList(s, a, id_v, out);
        } else if (std.mem.eql(u8, method, "tools/call")) {
            return toolsCall(s, a, id_v, params, out);
        }
    } else if (std.mem.eql(u8, method, "server/discover")) {
        // Legacy versions named in _meta have no such method, but a client
        // probing with one is still told what this server speaks.
        return discover(s, a, id_v, out);
    } else if (std.mem.eql(u8, method, "initialize")) {
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
    var version: []const u8 = newest_legacy_version;
    if (params == .object) if (params.object.get("protocolVersion")) |pv| if (pv == .string) {
        for (protocol_versions[1..]) |v| {
            if (std.mem.eql(u8, v, pv.string)) version = v;
        }
    };
    var w: Io.Writer.Allocating = .init(a);
    try w.writer.print(
        "{{\"protocolVersion\":\"{s}\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}}," ++
            "\"serverInfo\":{{\"name\":\"deed\",\"title\":\"deed\",\"version\":\"{s}\"}}," ++
            "\"instructions\":" ++ instructions_json ++ "}}",
        .{ version, @import("main.zig").version },
    );
    try replyResult(out, id, w.written());
}

/// UnsupportedProtocolVersionError (Versioning and Compatibility, "Protocol
/// Version Negotiation"): the versions this server speaks, and the one asked.
fn unsupportedVersion(a: Allocator, id: Json, requested: []const u8, out: *Io.Writer) !void {
    _ = a;
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(out, id);
    try out.writeAll(",\"error\":{\"code\":-32022,\"message\":\"Unsupported protocol version\",\"data\":{\"supported\":[");
    for (protocol_versions, 0..) |v, i| {
        if (i != 0) try out.writeByte(',');
        try std.json.Stringify.value(v, .{}, out);
    }
    try out.writeAll("],\"requested\":");
    try std.json.Stringify.value(requested[0..@min(requested.len, 64)], .{}, out);
    try out.writeAll("}}}\n");
    try out.flush();
}

/// `server/discover` (Discovery): supported versions, capabilities, identity.
fn discover(s: *Server, a: Allocator, id: Json, out: *Io.Writer) !void {
    var w: Io.Writer.Allocating = .init(a);
    try w.writer.writeAll("{\"supportedVersions\":[");
    for (protocol_versions, 0..) |v, i| {
        if (i != 0) try w.writer.writeByte(',');
        try std.json.Stringify.value(v, .{}, &w.writer);
    }
    try w.writer.writeAll("],\"capabilities\":{\"tools\":{\"listChanged\":false}},\"instructions\":" ++ instructions_json ++ cache_fields ++ "}");
    try replyOk(s, a, out, id, w.written());
}

/// The legacy and the modern answer share one reply path: the modern one adds
/// `resultType` ("Base Protocol", "ResultType") and the server's identity
/// ("Per-response protocol fields").
fn replyOk(s: *Server, a: Allocator, out: *Io.Writer, id: Json, result: []const u8) !void {
    if (!s.modern) return replyResult(out, id, result);
    std.debug.assert(result.len >= 2 and result[0] == '{' and result[result.len - 1] == '}');
    var w: Io.Writer.Allocating = .init(a);
    try w.writer.writeAll("{\"resultType\":\"complete\"");
    if (result.len > 2) {
        try w.writer.writeByte(',');
        try w.writer.writeAll(result[1 .. result.len - 1]);
    }
    try w.writer.print(",\"_meta\":{{\"" ++ meta_server_info ++ "\":{{\"name\":\"deed\",\"version\":\"{s}\"}}}}}}", .{@import("main.zig").version});
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
    // Caching: tools/list results carry a freshness hint in this revision.
    try ww.writeAll(if (s.modern) "]" ++ cache_fields ++ "}" else "]}");
    try replyOk(s, a, out, id, w.written());
}

fn toolsCall(s: *Server, a: Allocator, id: Json, params: Json, out: *Io.Writer) !void {
    if (params != .object) return replyError(out, id, -32602, "Invalid params: expected an object with a tool name");
    const name_v = params.object.get("name") orelse return replyError(out, id, -32602, "Invalid params: name is required");
    if (name_v != .string) return replyError(out, id, -32602, "Invalid params: name must be a string");
    const args: Json = params.object.get("arguments") orelse .{ .object = .empty };
    if (args != .object) return replyError(out, id, -32602, "Invalid params: arguments must be an object");
    // Arguments are written back out as JSON for the verbs, and the writer
    // allows 256 levels at most. A filter or an event needs a handful.
    if (!shallow(args, max_json_depth)) {
        return replyError(out, id, -32602, "Invalid params: arguments are nested too deeply");
    }

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
    try replyOk(s, a, out, id, w.written());
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

/// True when `v` nests no deeper than `left` levels. The walk stops at the
/// limit, so a deep value costs no more stack than a shallow one.
fn shallow(v: Json, left: usize) bool {
    switch (v) {
        .array => |arr| {
            if (left == 0) return false;
            for (arr.items) |item| if (!shallow(item, left - 1)) return false;
        },
        .object => |obj| {
            if (left == 0) return false;
            for (obj.values()) |item| if (!shallow(item, left - 1)) return false;
        },
        else => {},
    }
    return true;
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

/// `n` as an argument for a verb. Never negative: a verb would read "-1" as
/// an option, so every number a tool passes on is checked here as well as by
/// the tool.
fn num(a: Allocator, n: i64) ![]const u8 {
    if (n < 0) return error.BadArgument;
    return std.fmt.allocPrint(a, "{d}", .{n});
}

const kind_range_message = "kind must be a number from 0 to 65535";

/// The `kind` argument when it is a number, checked against the range of
/// kinds. Null when absent or not a number; `error.BadArgument` when out of
/// range.
fn kindArg(args: Json) !?u16 {
    const n = intArg(args, "kind") orelse {
        // A float that is not a whole number is not a kind either.
        if (field(args, "kind")) |v| if (v == .float) return error.BadArgument;
        return null;
    };
    if (n < 0 or n > 65535) return error.BadArgument;
    return @intCast(n);
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

/// The host of a ws:// or wss:// URL, without brackets, port or a trailing
/// dot. Null when there is none, or when the URL carries a user name.
fn relayHost(url: []const u8) ?[]const u8 {
    const after = (std.mem.indexOf(u8, url, "://") orelse return null) + 3;
    const rest = url[after..];
    const authority = rest[0 .. std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len];
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return null;
    var host = authority;
    if (std.mem.startsWith(u8, authority, "[")) {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        host = authority[1..close];
    } else if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
    }
    host = std.mem.trimEnd(u8, host, ".");
    return if (host.len == 0) null else host;
}

/// True for a host name, or an address, that is not this machine, a private
/// network, or link-local. A number written any way but four plain decimal
/// parts is not public either: a resolver reads "127.1" and "2130706433" as
/// loopback.
fn publicHost(host: []const u8) bool {
    if (std.mem.indexOfScalar(u8, host, ':') != null) {
        const ip6 = Io.net.Ip6Address.parse(host, 0) catch return false;
        return publicIp6(ip6.bytes);
    }
    for ([_][]const u8{ "localhost", ".localhost", ".local", ".internal", ".home.arpa" }) |name| {
        if (name[0] == '.') {
            if (std.ascii.endsWithIgnoreCase(host, name)) return false;
        } else if (std.ascii.eqlIgnoreCase(host, name)) return false;
    }
    const last = host[if (std.mem.lastIndexOfScalar(u8, host, '.')) |dot| dot + 1 else 0..];
    const numeric = std.ascii.startsWithIgnoreCase(host, "0x") or
        for (last) |c| {
            if (!std.ascii.isDigit(c)) break false;
        } else true;
    if (!numeric) return true;
    const ip4 = Io.net.Ip4Address.parse(host, 0) catch return false;
    return publicIp4(ip4.bytes);
}

fn publicIp4(b: [4]u8) bool {
    return !(b[0] == 0 or b[0] == 10 or b[0] == 127 or b[0] >= 224 or
        (b[0] == 100 and b[1] & 0xc0 == 64) or
        (b[0] == 169 and b[1] == 254) or
        (b[0] == 172 and b[1] & 0xf0 == 16) or
        (b[0] == 192 and b[1] == 0 and b[2] == 0) or
        (b[0] == 192 and b[1] == 168) or
        (b[0] == 198 and b[1] & 0xfe == 18));
}

fn publicIp6(b: [16]u8) bool {
    // ::/96 holds :: and ::1 and the old IPv4-compatible form.
    if (std.mem.allEqual(u8, b[0..12], 0)) return false;
    // ::ffff:0:0/96 (IPv4-mapped) and 64:ff9b::/96 (NAT64) carry an IPv4
    // address, which decides.
    const mapped = std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;
    const nat64 = std.mem.eql(u8, b[0..12], &[_]u8{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 });
    if (mapped or nat64) return publicIp4(b[12..16].*);
    // Unique local fc00::/7, link-local and site-local fe80::/9, multicast.
    if (b[0] & 0xfe == 0xfc or b[0] == 0xff or (b[0] == 0xfe and b[1] & 0x80 == 0x80)) return false;
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

/// Keeps what is written to it up to a number of lines and of bytes. Past
/// either, a `.stop` writer fails the write, which ends the verb writing to it
/// and closes every connection that verb holds; a `.drop` writer throws the
/// rest away and carries on.
const Bounded = struct {
    a: Allocator,
    list: std.ArrayList(u8) = .empty,
    max_lines: usize = std.math.maxInt(usize),
    max_bytes: usize,
    on_full: enum { stop, drop },
    lines: usize = 0,
    full: bool = false,
    writer: Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *Bounded = @alignCast(@fieldParentPtr("writer", w));
        for (data[0 .. data.len - 1]) |d| try self.put(d);
        const last = data[data.len - 1];
        for (0..splat) |_| try self.put(last);
        var n: usize = last.len * splat;
        for (data[0 .. data.len - 1]) |d| n += d.len;
        return n;
    }

    fn put(self: *Bounded, bytes: []const u8) Io.Writer.Error!void {
        const room = self.max_bytes -| self.list.items.len;
        var take: usize = 0;
        while (take < bytes.len and take < room and self.lines < self.max_lines) : (take += 1) {
            if (bytes[take] == '\n') self.lines += 1;
        }
        self.list.appendSlice(self.a, bytes[0..take]) catch return error.WriteFailed;
        if (take < bytes.len) {
            self.full = true;
            if (self.on_full == .stop) return error.WriteFailed;
        }
    }
};

fn capture(s: *Server, a: Allocator, runner: VerbFn, argv: []const []const u8) !Captured {
    return captureLines(s, a, runner, argv, null);
}

/// Runs a verb, keeping at most `max_lines` lines of what it prints. A verb
/// stopped at that limit, or at the size limit, counts as a success with a
/// note saying where it stopped: what it printed before is good.
fn captureLines(s: *Server, a: Allocator, runner: VerbFn, argv: []const []const u8, max_lines: ?usize) !Captured {
    var o: Bounded = .{ .a = a, .max_bytes = 2 * max_result_bytes, .on_full = .stop };
    if (max_lines) |n| o.max_lines = n;
    var e: Bounded = .{ .a = a, .max_bytes = 2 * max_notes_bytes, .on_full = .drop };
    var code = runner(s.gpa, s.io, argv, &o.writer, &e.writer) catch |err| switch (err) {
        error.WriteFailed => if (o.full) cli.exit_ok else return err,
        else => return err,
    };
    var notes = std.mem.trim(u8, e.list.items, "\n ");
    if (o.full) {
        code = cli.exit_ok;
        const why = if (o.lines >= o.max_lines)
            try std.fmt.allocPrint(a, "stopped at the limit of {d} events", .{o.lines})
        else
            try std.fmt.allocPrint(a, "stopped after {d} bytes", .{o.list.items.len});
        notes = if (notes.len == 0) why else try std.mem.concat(a, u8, &.{ notes, "\n", why });
    }
    return .{ .code = code, .out = o.list.items, .err = notes };
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
    const event_kind = kindArg(args) catch return fail(out, kind_range_message);
    if (event_kind) |k| try argv.appendSlice(a, &.{ "--kind", try num(a, k) });
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
    const limit = clamped(args, "limit", default_limit, 1, max_limit);
    try argv.appendSlice(a, &.{ "-l", try num(a, limit) });
    try argv.appendSlice(a, &.{ "--timeout", try num(a, timeoutMs(args)) });
    // The limit goes in the filter, and a relay may ignore it, so it is also
    // where collecting stops.
    return present(a, try captureLines(s, a, cmd_req.run, argv.items, @intCast(limit)), out);
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
    // The verb turns ws:// into http:// and wss:// into https:// itself, so
    // the caller never names an HTTP URL, and with it an arbitrary endpoint.
    const list = (try relayList(a, args, out, true)) orelse return false;
    for (list) |r| {
        const host = relayHost(r) orelse return failf(out, "'{s}' is not a ws:// or wss:// relay URL", .{r[0..@min(r.len, 100)]});
        if (!s.cfg.allow_local and !publicHost(host)) {
            return failf(out, "'{s}' is a local or private address; start the server with --allow-local to ask one", .{r[0..@min(r.len, 100)]});
        }
    }
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
        .integer, .float => {
            const n = (kindArg(args) catch return fail(out, kind_range_message)) orelse return fail(out, kind_range_message);
            try argv.append(a, try num(a, n));
        },
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
    const limit = clamped(args, "limit", default_limit, 1, max_limit);
    const argv = [_][]const u8{
        filter_json, "--local", "--store", path, "-l", try num(a, limit),
    };
    return present(a, try captureLines(s, a, cmd_req.run, &argv, @intCast(limit)), out);
}

fn toolPublishNote(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const content = strArg(args, "content") orelse return fail(out, "content is required");
    return publish(s, a, args, 1, &.{}, content, null, out);
}

fn toolPublishEvent(s: *Server, a: Allocator, args: Json, out: *Io.Writer.Allocating) !bool {
    const kind_n = intArg(args, "kind") orelse return fail(out, "kind is required");
    if (kind_n < 0 or kind_n > 65535) return fail(out, "kind must be from 0 to 65535");
    const kind: u16 = @intCast(kind_n);
    if (std.mem.indexOfScalar(u16, &publishable_kinds, kind) == null) {
        return failf(out, "refused: kind {d} is not one this server signs; it signs kinds 1, 6, 7, 16, 1111 and 9802", .{kind});
    }
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
            for (refused_tags) |name| if (std.mem.eql(u8, parts.items[0], name)) {
                return failf(out, "refused: a {s} tag belongs to an authentication or deletion event", .{name});
            };
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
    const now = Io.Timestamp.now(s.io, .real).toSeconds();
    if (created_at) |t| if (t < now - max_clock_skew_s or t > now + max_clock_skew_s) {
        return failf(out, "created_at must be within {d} seconds of now", .{max_clock_skew_s});
    };
    if (content.len > max_content_bytes) return failf(out, "content is longer than {d} bytes", .{max_content_bytes});
    if (std.mem.trim(u8, content, " \t\r\n").len == 0 and kind == 1) return fail(out, "nothing to post");
    const relays = (try relayList(a, args, out, true)) orelse return false;

    var signer = try nostr.keys.Signer.initRandomized(s.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey(sk);
    const at = created_at orelse now;
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
    try testing.expect(has(got, "\"protocolVersion\":\"" ++ newest_legacy_version ++ "\""));
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
    try testing.expect(has(replyFor(got, 1, &b).?, "refused: kind 3"));
    const r2 = replyFor(got, 2, &b).?;
    try testing.expect(has(r2, "\"isError\":true"));
    try testing.expect(has(r2, "no relay accepted"));
    try testing.expect(!has(r2, "\\\"accepted\\\":true"));
}

/// Asks publish_event for `kind_args` against a relay that refuses every
/// event, and checks that the call is refused before anything is signed.
fn refusedBeforeSigning(kind_args: []const u8, want: []const u8) !void {
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
    const a1 = try std.fmt.allocPrint(gpa, "{{{s},\"relays\":[\"{s}\"],\"timeout_ms\":3000}}", .{ kind_args, url });
    defer gpa.free(a1);
    const l1 = try callLine(gpa, 1, "publish_event", a1);
    defer gpa.free(l1);
    const got = try converse(gpa, .{ .secret = [_]u8{0x44} ** 32 }, l1);
    defer gpa.free(got);
    // A relay that answers OK false has still seen the signed event, so the
    // refusal has to come before the relay is offered anything.
    try testing.expectEqual(@as(usize, 0), script.events);
    try testing.expect(has(got, "\"isError\":true"));
    try testing.expect(has(got, want));
}

test "publish_event refuses a NIP-42 AUTH event for another relay" {
    try refusedBeforeSigning("\"kind\":22242,\"tags\":[[\"relay\",\"wss://victim.example\"],[\"challenge\",\"c\"]]", "refused: kind 22242");
}

test "publish_event refuses a NIP-62 request to vanish" {
    try refusedBeforeSigning("\"kind\":62,\"tags\":[[\"relay\",\"ALL_RELAYS\"]]", "refused: kind 62");
}

test "publish_event refuses NIP-98 and NIP-46 kinds" {
    try refusedBeforeSigning("\"kind\":27235,\"tags\":[[\"u\",\"https://x.example\"],[\"method\",\"GET\"]]", "refused: kind 27235");
    try refusedBeforeSigning("\"kind\":24133,\"content\":\"x\"", "refused: kind 24133");
}

test "publish_event refuses auth tags on an allowed kind" {
    try refusedBeforeSigning("\"kind\":1,\"content\":\"hi\",\"tags\":[[\"challenge\",\"c\"]]", "refused: a challenge tag");
    try refusedBeforeSigning("\"kind\":1,\"content\":\"hi\",\"tags\":[[\"relay\",\"wss://victim.example\"]]", "refused: a relay tag");
}

test "publish_event refuses a created_at far from now" {
    try refusedBeforeSigning("\"kind\":1,\"content\":\"hi\",\"created_at\":1000", "created_at must be within");
    try refusedBeforeSigning("\"kind\":1,\"content\":\"hi\",\"created_at\":99999999999", "created_at must be within");
}

test "a filter or event nested past the limit is refused, not a crash" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const deep_open = "[" ** 300;
    const deep_close = "]" ** 300;
    const l1 = try callLine(gpa, 1, "req", "{\"filter\":{\"x\":" ++ deep_open ++ deep_close ++ "},\"relays\":[\"ws://127.0.0.1:1\"]}");
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "verify", "{\"event\":{\"x\":" ++ deep_open ++ deep_close ++ "}}");
    defer gpa.free(l2);
    const l3 = try callLine(gpa, 3, "count", "{\"filter\":{\"x\":" ++ deep_open ++ deep_close ++ "},\"relays\":[\"ws://127.0.0.1:1\"]}");
    defer gpa.free(l3);
    const l4 = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}\n";
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2, l3, l4 });
    defer gpa.free(all);
    const got = try converse(gpa, .{}, all);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    for ([_]u32{ 1, 2, 3 }) |id| {
        const r = replyFor(got, id, &b).?;
        try testing.expect(has(r, "\"error\":{\"code\":-32602"));
        try testing.expect(has(r, "nested too deeply"));
    }
    try testing.expect(has(replyFor(got, 4, &b).?, "\"result\":{}"));
}

test "relay_info takes ws:// and wss:// relays only, and no local or private address" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const refused = [_][]const u8{
        "http://127.0.0.1:1",
        "https://relay.example",
        "relay.example",
        "ws://127.0.0.1:1",
        "wss://localhost",
        "wss://LOCALHOST.:443/",
        "wss://app.localhost",
        "wss://10.1.2.3",
        "wss://172.16.0.1",
        "wss://192.168.1.1",
        "wss://169.254.169.254",
        "wss://100.64.0.1",
        "wss://0.0.0.0",
        "wss://user@127.0.0.1",
        "wss://2130706433",
        "wss://127.1",
        "wss://0x7f000001",
        "wss://[::1]",
        "wss://[fd00::1]:8080",
        "wss://[fe80::1]",
        "wss://[::ffff:127.0.0.1]",
        "wss://printer.local",
    };
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(gpa);
    for (refused, 1..) |r, id| {
        const args = try std.fmt.allocPrint(gpa, "{{\"relays\":[\"{s}\"],\"timeout_ms\":300}}", .{r});
        defer gpa.free(args);
        const l = try callLine(gpa, @intCast(id), "relay_info", args);
        defer gpa.free(l);
        try all.appendSlice(gpa, l);
    }
    const got = try converse(gpa, .{}, all.items);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    for (refused, 1..) |r, id| {
        const reply = replyFor(got, @intCast(id), &b).?;
        testing.expect(has(reply, "\"isError\":true") and
            (has(reply, "is not a ws:// or wss:// relay URL") or has(reply, "local or private address"))) catch |e| {
            std.debug.print("not refused: {s}: {s}\n", .{ r, reply });
            return e;
        };
    }
}

test "relay_info reaches a local relay when the server allows it" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const http = @import("http.zig");
    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/", .body = "{\"name\":\"local relay\"}" }}, 1);
    defer srv.stop(io);
    const args = try std.fmt.allocPrint(gpa, "{{\"relays\":[\"ws://127.0.0.1:{d}\"],\"timeout_ms\":3000}}", .{srv.port()});
    defer gpa.free(args);
    const l = try callLine(gpa, 1, "relay_info", args);
    defer gpa.free(l);
    const got = try converse(gpa, .{ .allow_local = true }, l);
    defer gpa.free(got);
    try testing.expect(has(got, "\"isError\":false"));
    try testing.expect(has(got, "local relay"));
}

test "public hosts and addresses pass the relay_info check" {
    for ([_][]const u8{ "relay.example", "nos.lol", "1.2.3.4", "8.8.8.8", "2001:db8::1", "1relay.example" }) |h| {
        try testing.expect(publicHost(h));
    }
    try testing.expectEqualStrings("relay.example", relayHost("wss://relay.example:443/path").?);
    try testing.expectEqualStrings("::1", relayHost("wss://[::1]:80").?);
    try testing.expect(relayHost("wss://u@relay.example") == null);
}

test "a negative or out of range number is refused before it reaches a verb" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const l1 = try callLine(gpa, 1, "kind", "{\"kind\":-1}");
    defer gpa.free(l1);
    const l2 = try callLine(gpa, 2, "kind", "{\"kind\":70000}");
    defer gpa.free(l2);
    const l3 = try callLine(gpa, 3, "encode", "{\"type\":\"naddr\",\"value\":\"x\",\"pubkey\":\"" ++ "11" ** 32 ++ "\",\"kind\":-30023}");
    defer gpa.free(l3);
    const l4 = try callLine(gpa, 4, "kind", "{\"kind\":-1.0}");
    defer gpa.free(l4);
    const all = try std.mem.concat(gpa, u8, &.{ l1, l2, l3, l4 });
    defer gpa.free(all);
    const got = try converse(gpa, .{}, all);
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    for ([_]u32{ 1, 2, 3, 4 }) |id| {
        const r = replyFor(got, id, &b).?;
        try testing.expect(has(r, "\"isError\":true"));
        try testing.expect(has(r, "kind must be a number from 0 to 65535"));
    }
}

/// A relay that ignores `limit`: every REQ gets all of `events` and no EOSE.
const Flood = struct {
    events: []const []const u8,
    fn handle(ctx: ?*anyopaque, frame: []const u8, w: *Io.Writer) anyerror!void {
        const self: *Flood = @ptrCast(@alignCast(ctx.?));
        if (!std.mem.startsWith(u8, frame, "[\"REQ\"")) return;
        var line: [8192]u8 = undefined;
        for (self.events) |ev| {
            try testrelay.sendText(w, try std.fmt.bufPrint(&line, "[\"EVENT\",\"deed\",{s}]", .{ev}));
        }
    }
};

test "req stops at its limit when a relay ignores it, without waiting for the deadline" {
    const io = testing.io;
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var evs: [40][]const u8 = undefined;
    for (&evs, 0..) |*e, i| {
        e.* = try cmd_post.signedJson(a, io, [_]u8{0x33} ** 32, 1, &.{}, try std.fmt.allocPrint(a, "flood {d}", .{i}), 1_700_000_000 + @as(i64, @intCast(i)));
    }
    var flood = Flood{ .events = &evs };
    var relay: testrelay.Relay = undefined;
    try relay.startCustom(io, Flood.handle, &flood);
    defer relay.stop(io);
    var ub: [40]u8 = undefined;
    const url = try testrelay.url(&ub, relay.port());

    const args = try std.fmt.allocPrint(gpa, "{{\"filter\":{{\"kinds\":[1]}},\"relays\":[\"{s}\"],\"limit\":3,\"timeout_ms\":8000}}", .{url});
    defer gpa.free(args);
    const line = try callLine(gpa, 1, "req", args);
    defer gpa.free(line);
    const started = Io.Timestamp.now(io, .awake).toMilliseconds();
    const got = try converse(gpa, .{}, line);
    defer gpa.free(got);
    const took = Io.Timestamp.now(io, .awake).toMilliseconds() - started;
    try testing.expect(has(got, "\"isError\":false"));
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, got, "flood "));
    try testing.expect(has(got, "stopped at the limit of 3 events"));
    try testing.expect(took < 4000);
}

/// `_meta` for a 2026-07-28 request.
const modern_meta = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"," ++
    "\"io.modelcontextprotocol/clientInfo\":{\"name\":\"t\",\"version\":\"0\"},\"io.modelcontextprotocol/clientCapabilities\":{}}";

test "2026-07-28: discover, list and call need no handshake" {
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

    const call = try std.fmt.allocPrint(gpa, "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"req\",{s}," ++
        "\"arguments\":{{\"filter\":{{\"kinds\":[1]}},\"relays\":[\"{s}\"],\"limit\":5,\"timeout_ms\":5000}}}}}}\n", .{ modern_meta, url });
    defer gpa.free(call);
    const decode = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"kind\"," ++ modern_meta ++ ",\"arguments\":{\"kind\":1}}}\n";
    const reqs = try std.mem.concat(gpa, u8, &.{
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{" ++ modern_meta ++ "}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{" ++ modern_meta ++ "}}\n",
        call,
        decode,
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\",\"params\":{" ++ modern_meta ++ "}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"initialize\",\"params\":{" ++ modern_meta ++ "}}\n",
    });
    defer gpa.free(reqs);
    const got = try converse(gpa, .{}, reqs);
    defer gpa.free(got);
    var b: [32]u8 = undefined;

    const d = replyFor(got, 1, &b).?;
    try testing.expect(has(d, "\"resultType\":\"complete\""));
    try testing.expect(has(d, "\"supportedVersions\":[\"2026-07-28\",\"2025-11-25\""));
    try testing.expect(has(d, "\"capabilities\":{\"tools\""));
    try testing.expect(has(d, "\"io.modelcontextprotocol/serverInfo\":{\"name\":\"deed\""));
    try testing.expect(has(d, "\"ttlMs\":"));
    try testing.expect(has(d, "\"cacheScope\":\"private\""));

    const l = replyFor(got, 2, &b).?;
    try testing.expect(has(l, "\"resultType\":\"complete\""));
    try testing.expect(has(l, "\"name\":\"decode\""));
    try testing.expect(has(l, "\"ttlMs\":"));

    const r = replyFor(got, 3, &b).?;
    try testing.expect(has(r, "\"resultType\":\"complete\""));
    try testing.expect(has(r, "\"isError\":false"));
    try testing.expect(has(r, "from the relay"));
    try testing.expect(has(replyFor(got, 4, &b).?, "\"resultType\":\"complete\""));

    // ping and initialize no longer exist in this revision.
    try testing.expect(has(replyFor(got, 5, &b).?, "-32601"));
    try testing.expect(has(replyFor(got, 6, &b).?, "-32601"));
}

test "2026-07-28: a bad version or missing metadata is refused with the spec's errors" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const got = try converse(gpa, .{}, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"1900-01-01\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"server/discover\"}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}\n");
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    const u = replyFor(got, 1, &b).?;
    try testing.expect(has(u, "\"code\":-32022"));
    try testing.expect(has(u, "\"supported\":[\"2026-07-28\""));
    try testing.expect(has(u, "\"requested\":\"1900-01-01\""));
    try testing.expect(has(replyFor(got, 2, &b).?, "-32602"));
    try testing.expect(has(replyFor(got, 3, &b).?, "-32602"));
}

test "the handshake still works beside 2026-07-28, and initialize never selects it" {
    var da: testrelay.DialAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();
    const got = try converse(gpa, .{}, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2026-07-28\"}}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n");
    defer gpa.free(got);
    var b: [32]u8 = undefined;
    try testing.expect(has(replyFor(got, 1, &b).?, "\"protocolVersion\":\"2025-11-25\""));
    const l = replyFor(got, 2, &b).?;
    try testing.expect(has(l, "\"name\":\"decode\""));
    try testing.expect(!has(l, "resultType"));
}
