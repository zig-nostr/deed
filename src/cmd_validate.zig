//! `deed validate`: check events against a registry-of-kinds schema.
//!
//! The schema is the YAML file nostr-protocol/registry-of-kinds publishes:
//! for each kind, what the content must be, which tags are required, and what
//! each tag's items must look like. The rules are applied over the small
//! slice of YAML that file is written in. See `usage` for what is and is not
//! checked.

const std = @import("std");
const nostr = @import("nostr");
const cli = @import("cli.zig");
const http = @import("http.zig");
const relayset = @import("relayset.zig");
const cmd_nip = @import("cmd_nip.zig");

pub const summary = "check events against a registry-of-kinds schema";

pub const ready = true;

pub const default_schema_url = "https://raw.githubusercontent.com/nostr-protocol/registry-of-kinds/refs/heads/master/schema.yaml";

pub const usage =
    \\deed validate: check events against a registry-of-kinds schema
    \\
    \\Usage:
    \\  deed validate [--refresh] [--schema <url|path>] [<event-json>...]
    \\
    \\Reads events as newline-delimited JSON on stdin when given no arguments.
    \\An event that passes is printed to stdout as it was given. One that fails
    \\is not, and its reason goes to stderr as `line N: <reason>`. The exit
    \\status is 1 when any event failed, and 0 when all passed.
    \\
    \\  deed event -k 1 -p not_a_pubkey | deed validate
    \\
    \\Options:
    \\      --schema <url|path>   the schema to use: an http(s) URL or a file. A
    \\                            file is read from disk and needs no network.
    \\                            The default is the registry-of-kinds
    \\                            schema.yaml, fetched from
    \\                            raw.githubusercontent.com
    \\      --refresh             fetch a schema URL again even if a copy kept
    \\                            less than 24 hours ago exists
    \\
    \\A schema fetched from a URL is kept in the user cache directory for 24
    \\hours. If the URL cannot be reached, an older kept copy is used with a
    \\warning, so a copy fetched once keeps working offline.
    \\
    \\What is checked, for the event's kind:
    \\  content   by the kind's content type
    \\  tags      each tag against the specs with its name or prefix; one spec
    \\            must accept it. Tags with no spec for the kind fall back to
    \\            the schema's generic_tags. Missing items, items with leading
    \\            or trailing whitespace, and a `d` tag on a kind that is not
    \\            addressable are refused. Kinds listing `required` tags, and
    \\            addressable kinds needing a `d` tag, must have them
    \\A kind the schema does not list passes.
    \\
    \\Value types checked: id, pubkey, addr, kind, relay, json, constrained,
    \\hex (with min and max), lowercase, timestamp, imeta, empty, free. The
    \\types url, giturl, date and geohash are not checked, and neither are
    \\unknown types. `empty` is not enforced either.
    \\
    \\The schema is read with a built-in reader for the YAML subset the
    \\registry file uses: block mappings and lists, anchors and aliases on
    \\values, quoted and plain scalars, comments, and empty [] and {}. Flow
    \\collections with content, multi-line scalars and merge keys are refused
    \\with the line they appear on. Only the structure the validator uses is
    \\read from the schema; the other fields are ignored.
    \\
    \\This does not check ids or signatures: use `deed verify` for that.
    \\
;

// ---------------------------------------------------------------------------
// A reader for the YAML subset the schema is written in
// ---------------------------------------------------------------------------

const Node = union(enum) {
    /// A scalar. `quoted` scalars are never read as booleans.
    scalar: struct { text: []const u8, quoted: bool },
    map: []const MapEntry,
    seq: []const *Node,
    null_value,
};

const MapEntry = struct { key: []const u8, value: *Node };

const Line = struct {
    indent: usize,
    text: []const u8,
    number: usize,
};

const YamlError = error{ BadYaml, OutOfMemory };

const Yaml = struct {
    arena: std.mem.Allocator,
    lines: []Line,
    pos: usize = 0,
    anchors: std.StringHashMapUnmanaged(*Node) = .empty,
    /// Where it went wrong, for the message.
    fail_line: usize = 0,
    fail_why: []const u8 = "",

    fn fail(self: *Yaml, line: usize, why: []const u8) YamlError {
        self.fail_line = line;
        self.fail_why = why;
        return error.BadYaml;
    }

    fn node(self: *Yaml, n: Node) !*Node {
        const p = try self.arena.create(Node);
        p.* = n;
        return p;
    }

    fn parseBlock(self: *Yaml, indent: usize) YamlError!*Node {
        if (isDash(self.lines[self.pos].text)) return self.parseSeq(indent);
        return self.parseMap(indent);
    }

    fn parseSeq(self: *Yaml, n: usize) YamlError!*Node {
        var items: std.ArrayList(*Node) = .empty;
        while (self.pos < self.lines.len and self.lines[self.pos].indent == n and isDash(self.lines[self.pos].text)) {
            const line = &self.lines[self.pos];
            var skip: usize = 1;
            while (skip < line.text.len and line.text[skip] == ' ') skip += 1;
            const rest = line.text[skip..];
            if (rest.len == 0) {
                self.pos += 1;
                if (self.pos < self.lines.len and self.lines[self.pos].indent > n) {
                    try items.append(self.arena, try self.parseBlock(self.lines[self.pos].indent));
                } else {
                    try items.append(self.arena, try self.node(.null_value));
                }
            } else if (rest[0] == '*') {
                try items.append(self.arena, try self.alias(rest, line.number));
                self.pos += 1;
            } else if (rest[0] == '&' or rest[0] == '[' or rest[0] == '{' or rest[0] == '|' or rest[0] == '>') {
                if (std.mem.eql(u8, rest, "[]")) {
                    try items.append(self.arena, try self.node(.{ .seq = &.{} }));
                    self.pos += 1;
                } else return self.fail(line.number, "unsupported YAML in a list item");
            } else if (splitKey(rest) != null) {
                // `- key: value`: the mapping starts where the key does.
                line.indent = n + skip;
                line.text = rest;
                try items.append(self.arena, try self.parseMap(n + skip));
            } else {
                try items.append(self.arena, try self.node(try self.scalar(rest, line.number)));
                self.pos += 1;
            }
        }
        return self.node(.{ .seq = try items.toOwnedSlice(self.arena) });
    }

    fn parseMap(self: *Yaml, n: usize) YamlError!*Node {
        var entries: std.ArrayList(MapEntry) = .empty;
        while (self.pos < self.lines.len) {
            const line = self.lines[self.pos];
            if (line.indent < n) break;
            if (line.indent > n) return self.fail(line.number, "unexpected indentation");
            if (isDash(line.text)) break;
            const kv = splitKey(line.text) orelse return self.fail(line.number, "expected `key: value`");
            self.pos += 1;
            var rest = kv.rest;
            var anchor: ?[]const u8 = null;
            if (rest.len > 0 and rest[0] == '&') {
                const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
                anchor = rest[1..end];
                rest = std.mem.trim(u8, rest[end..], " ");
            }
            const value: *Node = blk: {
                if (rest.len == 0) {
                    if (self.pos < self.lines.len and self.lines[self.pos].indent > n)
                        break :blk try self.parseBlock(self.lines[self.pos].indent);
                    if (self.pos < self.lines.len and self.lines[self.pos].indent == n and isDash(self.lines[self.pos].text))
                        break :blk try self.parseSeq(n);
                    break :blk try self.node(.null_value);
                }
                if (rest[0] == '*') break :blk try self.alias(rest, line.number);
                if (std.mem.eql(u8, rest, "[]")) break :blk try self.node(.{ .seq = &.{} });
                if (std.mem.eql(u8, rest, "{}")) break :blk try self.node(.{ .map = &.{} });
                if (rest[0] == '[' or rest[0] == '{' or rest[0] == '|' or rest[0] == '>')
                    return self.fail(line.number, "unsupported YAML (flow collection or multi-line scalar)");
                break :blk try self.node(try self.scalar(rest, line.number));
            };
            if (anchor) |a| try self.anchors.put(self.arena, a, value);
            try entries.append(self.arena, .{ .key = kv.key, .value = value });
        }
        return self.node(.{ .map = try entries.toOwnedSlice(self.arena) });
    }

    fn alias(self: *Yaml, text: []const u8, number: usize) YamlError!*Node {
        const name = std.mem.trim(u8, text[1..], " ");
        return self.anchors.get(name) orelse self.fail(number, "alias to an anchor not defined above it");
    }

    fn scalar(self: *Yaml, text: []const u8, number: usize) YamlError!Node {
        const t = std.mem.trim(u8, text, " ");
        if (t.len >= 2 and t[0] == '\'') {
            if (t[t.len - 1] != '\'') return self.fail(number, "unterminated quote");
            return .{ .scalar = .{ .text = try std.mem.replaceOwned(u8, self.arena, t[1 .. t.len - 1], "''", "'"), .quoted = true } };
        }
        if (t.len >= 2 and t[0] == '"') {
            if (t[t.len - 1] != '"') return self.fail(number, "unterminated quote");
            var buf: std.ArrayList(u8) = .empty;
            var i: usize = 1;
            while (i < t.len - 1) : (i += 1) {
                if (t[i] == '\\' and i + 1 < t.len - 1) {
                    i += 1;
                    try buf.append(self.arena, switch (t[i]) {
                        'n' => '\n',
                        't' => '\t',
                        else => t[i],
                    });
                } else try buf.append(self.arena, t[i]);
            }
            return .{ .scalar = .{ .text = try buf.toOwnedSlice(self.arena), .quoted = true } };
        }
        return .{ .scalar = .{ .text = t, .quoted = false } };
    }
};

fn isDash(text: []const u8) bool {
    return text.len > 0 and text[0] == '-' and (text.len == 1 or text[1] == ' ');
}

/// `key: rest`, with the key bare or quoted. Null when the text is not a
/// mapping entry (a plain scalar like `podcast:guid` has a colon and no entry).
fn splitKey(text: []const u8) ?struct { key: []const u8, rest: []const u8 } {
    if (text.len == 0) return null;
    var key_end: usize = undefined;
    var key: []const u8 = undefined;
    if (text[0] == '"' or text[0] == '\'') {
        const close = std.mem.indexOfScalarPos(u8, text, 1, text[0]) orelse return null;
        key = text[1..close];
        key_end = close + 1;
        if (key_end >= text.len or text[key_end] != ':') return null;
    } else {
        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            if (text[i] == ':' and (i + 1 == text.len or text[i + 1] == ' ')) break;
        } else return null;
        key = std.mem.trim(u8, text[0..i], " ");
        key_end = i;
    }
    const after = text[key_end + 1 ..];
    if (after.len > 0 and after[0] != ' ') return null;
    return .{ .key = key, .rest = std.mem.trim(u8, after, " ") };
}

/// Removes a trailing comment: a `#` at the start of the text or after a
/// space, outside a quoted scalar.
fn stripComment(text: []const u8) []const u8 {
    var quote: u8 = 0;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        const starts_token = i == 0 or text[i - 1] == ' ';
        if (quote != 0) {
            if (c == quote) quote = 0;
        } else if ((c == '\'' or c == '"') and starts_token) {
            quote = c;
        } else if (c == '#' and starts_token) {
            return text[0..i];
        }
    }
    return text;
}

// ---------------------------------------------------------------------------
// The schema
// ---------------------------------------------------------------------------

const ContentSpec = struct {
    type: []const u8 = "",
    required: bool = false,
    min: usize = 0,
    max: usize = 0,
    either: []const []const u8 = &.{},
    next: ?*const ContentSpec = null,
    variadic: bool = false,
};

const TagSpec = struct {
    name: []const u8 = "",
    prefix: []const u8 = "",
    next: ?*const ContentSpec = null,
};

const KindSchema = struct {
    content: ContentSpec = .{},
    required: []const []const u8 = &.{},
    tags: []const TagSpec = &.{},
};

pub const Schema = struct {
    arena: std.heap.ArenaAllocator,
    kinds: std.AutoHashMapUnmanaged(u16, KindSchema) = .empty,
    generic: std.StringHashMapUnmanaged(ContentSpec) = .empty,

    pub fn deinit(self: *Schema) void {
        self.arena.deinit();
    }
};

pub const ParseFailure = struct {
    line: usize = 0,
    why: []const u8 = "",
};

/// Reads schema text. On failure `failure` says where, as text that does not
/// outlive `text`.
pub fn parseSchema(gpa: std.mem.Allocator, text: []const u8, failure: *ParseFailure) !Schema {
    var schema: Schema = .{ .arena = std.heap.ArenaAllocator.init(gpa) };
    errdefer schema.arena.deinit();
    const a = schema.arena.allocator();

    var lines: std.ArrayList(Line) = .empty;
    var number: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        number += 1;
        const no_cr = std.mem.trimEnd(u8, raw, "\r");
        var indent: usize = 0;
        while (indent < no_cr.len and no_cr[indent] == ' ') indent += 1;
        if (indent < no_cr.len and no_cr[indent] == '\t') {
            failure.* = .{ .line = number, .why = "tab used for indentation" };
            return error.BadSchema;
        }
        const body = std.mem.trimEnd(u8, stripComment(no_cr[indent..]), " ");
        if (body.len == 0 or std.mem.eql(u8, body, "---")) continue;
        try lines.append(a, .{ .indent = indent, .text = body, .number = number });
    }

    var y: Yaml = .{ .arena = a, .lines = lines.items };
    const root = blk: {
        if (lines.items.len == 0) break :blk try y.node(.null_value);
        break :blk y.parseBlock(lines.items[0].indent) catch |e| switch (e) {
            error.BadYaml => {
                failure.* = .{ .line = y.fail_line, .why = y.fail_why };
                return error.BadSchema;
            },
            else => |other| return other,
        };
    };
    if (y.pos < y.lines.len) {
        failure.* = .{ .line = y.lines[y.pos].number, .why = "unexpected indentation" };
        return error.BadSchema;
    }

    const top = switch (root.*) {
        .map => |m| m,
        else => &[_]MapEntry{},
    };
    for (top) |entry| {
        if (std.mem.eql(u8, entry.key, "generic_tags")) {
            for (asMap(entry.value)) |g| try schema.generic.put(a, g.key, try buildSpec(a, g.value));
        } else if (std.mem.eql(u8, entry.key, "kinds")) {
            for (asMap(entry.value)) |k| {
                const kind = std.fmt.parseInt(u16, k.key, 10) catch continue;
                try schema.kinds.put(a, kind, try buildKind(a, k.value));
            }
        }
    }
    return schema;
}

fn asMap(n: *const Node) []const MapEntry {
    return switch (n.*) {
        .map => |m| m,
        else => &.{},
    };
}

fn asSeq(n: *const Node) []const *Node {
    return switch (n.*) {
        .seq => |s| s,
        else => &.{},
    };
}

fn asText(n: *const Node) []const u8 {
    return switch (n.*) {
        .scalar => |s| s.text,
        else => "",
    };
}

fn asBool(n: *const Node) bool {
    return switch (n.*) {
        .scalar => |s| !s.quoted and std.mem.eql(u8, s.text, "true"),
        else => false,
    };
}

fn asCount(n: *const Node) usize {
    return std.fmt.parseInt(usize, asText(n), 10) catch 0;
}

fn buildSpec(a: std.mem.Allocator, n: *const Node) std.mem.Allocator.Error!ContentSpec {
    var spec: ContentSpec = .{};
    for (asMap(n)) |e| {
        if (std.mem.eql(u8, e.key, "type")) {
            spec.type = asText(e.value);
        } else if (std.mem.eql(u8, e.key, "required")) {
            spec.required = asBool(e.value);
        } else if (std.mem.eql(u8, e.key, "min")) {
            spec.min = asCount(e.value);
        } else if (std.mem.eql(u8, e.key, "max")) {
            spec.max = asCount(e.value);
        } else if (std.mem.eql(u8, e.key, "variadic")) {
            spec.variadic = asBool(e.value);
        } else if (std.mem.eql(u8, e.key, "either")) {
            var list: std.ArrayList([]const u8) = .empty;
            for (asSeq(e.value)) |v| try list.append(a, asText(v));
            spec.either = try list.toOwnedSlice(a);
        } else if (std.mem.eql(u8, e.key, "next")) {
            if (e.value.* == .map) {
                const next = try a.create(ContentSpec);
                next.* = try buildSpec(a, e.value);
                spec.next = next;
            }
        }
    }
    return spec;
}

fn buildKind(a: std.mem.Allocator, n: *const Node) std.mem.Allocator.Error!KindSchema {
    var k: KindSchema = .{};
    for (asMap(n)) |e| {
        if (std.mem.eql(u8, e.key, "content")) {
            k.content = try buildSpec(a, e.value);
        } else if (std.mem.eql(u8, e.key, "required")) {
            var list: std.ArrayList([]const u8) = .empty;
            for (asSeq(e.value)) |v| try list.append(a, asText(v));
            k.required = try list.toOwnedSlice(a);
        } else if (std.mem.eql(u8, e.key, "tags")) {
            var list: std.ArrayList(TagSpec) = .empty;
            for (asSeq(e.value)) |t| {
                var ts: TagSpec = .{};
                for (asMap(t)) |f| {
                    if (std.mem.eql(u8, f.key, "name")) {
                        ts.name = asText(f.value);
                    } else if (std.mem.eql(u8, f.key, "prefix")) {
                        ts.prefix = asText(f.value);
                    } else if (std.mem.eql(u8, f.key, "next") and f.value.* == .map) {
                        const next = try a.create(ContentSpec);
                        next.* = try buildSpec(a, f.value);
                        ts.next = next;
                    }
                }
                try list.append(a, ts);
            }
            k.tags = try list.toOwnedSlice(a);
        }
    }
    return k;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn isHex(s: []const u8) bool {
    if (s.len % 2 != 0) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn isUnsigned(s: []const u8, comptime T: type) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    _ = std.fmt.parseInt(T, s, 10) catch return false;
    return true;
}

fn isSpaceRune(c: u21) bool {
    return switch (c) {
        0x09...0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

/// Whether `s` has no whitespace at either end, as Go's unicode.IsSpace sees it.
fn isTrimmed(s: []const u8) bool {
    if (s.len == 0) return true;
    const first_len = std.unicode.utf8ByteSequenceLength(s[0]) catch 1;
    if (first_len <= s.len) {
        if (std.unicode.utf8Decode(s[0..first_len]) catch null) |c| if (isSpaceRune(c)) return false;
    }
    var start = s.len - 1;
    while (start > 0 and s[start] & 0xc0 == 0x80 and s.len - start < 4) start -= 1;
    if (std.unicode.utf8Decode(s[start..]) catch null) |c| if (isSpaceRune(c)) return false;
    return true;
}

/// Writes why `value` is not a good `spec.type` and returns false, or returns
/// true. Types the validator does not know pass.
fn checkType(gpa: std.mem.Allocator, w: *std.Io.Writer, spec: *const ContentSpec, value: []const u8) !bool {
    const t = spec.type;
    if (std.mem.eql(u8, t, "id")) {
        if (value.len != 64) return fail(w, "needed 64 hex chars");
        if (!isHex(value)) return fail(w, "not hex");
    } else if (std.mem.eql(u8, t, "pubkey")) {
        if (value.len != 64 or !isHex(value)) {
            try w.writeAll("pubkey should be 64-char hex, got '");
            try writeShown(w, value);
            try w.writeAll("'");
            return false;
        }
    } else if (std.mem.eql(u8, t, "addr")) {
        var parts = std.mem.splitScalar(u8, value, ':');
        const kind = parts.next() orelse "";
        const pk = parts.next() orelse "";
        if (!isUnsigned(kind, u16) or pk.len != 64 or !isHex(pk)) return fail(w, "not a kind:pubkey:identifier address");
    } else if (std.mem.eql(u8, t, "kind")) {
        if (!isUnsigned(value, u16)) return fail(w, "not an unsigned integer");
    } else if (std.mem.eql(u8, t, "relay")) {
        const host = if (std.mem.startsWith(u8, value, "wss://")) value[6..] else if (std.mem.startsWith(u8, value, "ws://")) value[5..] else "";
        if (host.len == 0) return fail(w, "must be ws or wss URL");
    } else if (std.mem.eql(u8, t, "json")) {
        if (!try std.json.validate(gpa, value)) return fail(w, "invalid json");
    } else if (std.mem.eql(u8, t, "constrained")) {
        for (spec.either) |allowed| if (std.mem.eql(u8, allowed, value)) return true;
        return fail(w, "not in allowed list");
    } else if (std.mem.eql(u8, t, "hex")) {
        if (spec.min > 0 and value.len < spec.min) {
            try w.print("hex value too short: {d} < {d}", .{ value.len, spec.min });
            return false;
        }
        if (spec.max > 0 and value.len > spec.max) {
            try w.print("hex value too long: {d} > {d}", .{ value.len, spec.max });
            return false;
        }
        if (!isHex(value)) return fail(w, "not hex");
    } else if (std.mem.eql(u8, t, "lowercase")) {
        for (value) |c| if (std.ascii.isUpper(c)) return fail(w, "not lowercase");
    } else if (std.mem.eql(u8, t, "timestamp")) {
        if (!isUnsigned(value, u64)) return fail(w, "not an unsigned integer");
    } else if (std.mem.eql(u8, t, "imeta")) {
        return checkImeta(w, value);
    }
    return true;
}

fn fail(w: *std.Io.Writer, why: []const u8) !bool {
    try w.writeAll(why);
    return false;
}

fn writeShown(w: *std.Io.Writer, text: []const u8) !void {
    try w.writeAll(text);
}

fn checkImeta(w: *std.Io.Writer, value: []const u8) !bool {
    const sp = std.mem.indexOfScalar(u8, value, ' ') orelse return fail(w, "not a space-separated keyval");
    const key = value[0..sp];
    const val = value[sp + 1 ..];
    const is = std.mem.eql;
    if (is(u8, key, "url") or is(u8, key, "fallback") or is(u8, key, "thumb") or is(u8, key, "image")) {
        const ok = std.mem.startsWith(u8, val, "http://") or std.mem.startsWith(u8, val, "https://") or std.mem.startsWith(u8, val, "data:");
        if (!ok) {
            try w.print("invalid {s} URL", .{key});
            return false;
        }
    } else if (is(u8, key, "magnet")) {
        if (!std.mem.startsWith(u8, val, "magnet:")) return fail(w, "invalid magnet URI");
    } else if (is(u8, key, "x") or is(u8, key, "ox")) {
        if (val.len != 64) return fail(w, "SHA-256 must be 64 hex chars");
        if (!isHex(val)) return fail(w, "not hex");
    } else if (is(u8, key, "dim")) {
        var parts = std.mem.splitScalar(u8, val, 'x');
        const width = parts.next() orelse "";
        const height = parts.next() orelse return fail(w, "dim must be WxH format");
        if (parts.next() != null) return fail(w, "dim must be WxH format");
        if (!isUnsigned(width, u32)) return fail(w, "invalid width in dim");
        if (!isUnsigned(height, u32)) return fail(w, "invalid height in dim");
    } else if (is(u8, key, "size")) {
        if (!isUnsigned(val, u64)) return fail(w, "invalid size");
    } else if (is(u8, key, "m")) {
        if (std.mem.indexOfScalar(u8, val, '/') == null) return fail(w, "invalid MIME type");
    }
    return true;
}

/// Where a tag failed, and why. `why` is filled by `checkTag`.
const TagFailure = struct { item: usize };

/// Checks `tag[index..]` against `spec`. Null when it passes; otherwise the
/// failing item, with the reason written to `w`.
fn checkNext(gpa: std.mem.Allocator, w: *std.Io.Writer, tag: []const []const u8, index: usize, spec: *const ContentSpec) !?TagFailure {
    if (tag.len <= index) {
        if (spec.required) {
            try w.print("invalid tag '{s}', missing index {d}", .{ tag[0], index });
            return .{ .item = index };
        }
        return null;
    }
    if (!isTrimmed(tag[index])) {
        try w.writeAll("value has dangling space");
        return .{ .item = index };
    }
    if (tag[index].len == 0 and !spec.required) {
        // An empty item is fine where nothing is required.
    } else {
        var why: std.Io.Writer.Allocating = .init(gpa);
        defer why.deinit();
        if (!try checkType(gpa, &why.writer, spec, tag[index])) {
            try w.print("invalid {s} value '{s}' at tag '{s}', index {d}: {s}", .{ spec.type, tag[index], tag[0], index, why.written() });
            return .{ .item = index };
        }
    }
    if (spec.variadic) {
        var sub = spec.*;
        sub.required = false;
        return checkNext(gpa, w, tag, index + 1, &sub);
    }
    if (spec.next) |next| return checkNext(gpa, w, tag, index + 1, next);
    return null;
}

/// Whether `kind` is addressable (NIP-01).
fn isAddressable(kind: u16) bool {
    return kind >= 30000 and kind < 40000;
}

/// Checks one event. Returns true when it passes; otherwise writes the reason
/// to `w` and returns false.
pub fn validateEvent(gpa: std.mem.Allocator, schema: *const Schema, ev: nostr.event.Event, w: *std.Io.Writer) !bool {
    const sch = schema.kinds.get(ev.kind) orelse return true;

    {
        var why: std.Io.Writer.Allocating = .init(gpa);
        defer why.deinit();
        if (!try checkType(gpa, &why.writer, &sch.content, ev.content)) {
            try w.print("content: {s}", .{why.written()});
            return false;
        }
    }

    var required: std.ArrayList([]const u8) = .empty;
    defer required.deinit(gpa);
    try required.appendSlice(gpa, sch.required);
    var needs_d = isAddressable(ev.kind);

    tags: for (ev.tags, 0..) |tag, ti| {
        if (tag.len == 0) {
            try w.writeAll("empty tag");
            return false;
        }
        if (std.mem.eql(u8, tag[0], "d")) {
            if (!isAddressable(ev.kind)) {
                try w.writeAll("non-addressable event can't have a 'd' tag");
                return false;
            }
            needs_d = false;
        }
        for (required.items, 0..) |name, idx| {
            if (std.mem.eql(u8, name, tag[0])) {
                _ = required.swapRemove(idx);
                break;
            }
        }

        var last: ?struct { item: usize, why: []u8 } = null;
        defer if (last) |l| gpa.free(l.why);
        var validated = false;
        for (sch.tags) |ts| {
            const matches = std.mem.eql(u8, ts.name, tag[0]) or (ts.prefix.len > 0 and std.mem.startsWith(u8, tag[0], ts.prefix));
            if (!matches) continue;
            const next = ts.next orelse continue;
            validated = true;
            var why: std.Io.Writer.Allocating = .init(gpa);
            defer why.deinit();
            if (try checkNext(gpa, &why.writer, tag, 1, next)) |f| {
                if (last) |l| gpa.free(l.why);
                last = .{ .item = f.item, .why = try gpa.dupe(u8, why.written()) };
                continue;
            }
            continue :tags;
        }
        if (last) |l| {
            try w.print("tag[{d}][{d}]: {s}", .{ ti, l.item, l.why });
            return false;
        }
        if (!validated) {
            if (schema.generic.getPtr(tag[0])) |g| {
                var why: std.Io.Writer.Allocating = .init(gpa);
                defer why.deinit();
                if (try checkNext(gpa, &why.writer, tag, 1, g)) |f| {
                    try w.print("tag[{d}][{d}]: {s}", .{ ti, f.item, why.written() });
                    return false;
                }
            }
        }
    }

    if (required.items.len > 0) {
        try w.writeAll("missing tags: [");
        for (required.items, 0..) |name, n| {
            if (n > 0) try w.writeByte(' ');
            try w.writeAll(name);
        }
        try w.writeByte(']');
        return false;
    }
    if (needs_d) {
        try w.writeAll("missing tags: [d]");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// The verb
// ---------------------------------------------------------------------------

const max_record_bytes = 1 << 20;
const max_schema_bytes = 16 * 1024 * 1024;

pub const Config = struct {
    /// Where fetched schemas are kept. Null keeps nothing.
    cache_dir: ?[]const u8 = null,
    timeout_ms: u64 = 15_000,
};

/// A kept copy this old is fetched again.
const fresh_seconds: i64 = 24 * 60 * 60;

fn cacheFile(gpa: std.mem.Allocator, cfg: Config, source: []const u8) ?[]u8 {
    const dir = cfg.cache_dir orelse return null;
    const h = std.hash.Wyhash.hash(0, source);
    return std.fmt.allocPrint(gpa, "{s}{c}{x:0>16}-schema.yaml", .{ dir, std.fs.path.sep, h }) catch null;
}

fn loadSchemaText(gpa: std.mem.Allocator, io: std.Io, source: []const u8, cfg: Config, refresh: bool, err: *std.Io.Writer) !?[]u8 {
    if (std.mem.startsWith(u8, source, "http://") or std.mem.startsWith(u8, source, "https://")) {
        const cwd = std.Io.Dir.cwd();
        const path = cacheFile(gpa, cfg, source);
        defer if (path) |p| gpa.free(p);
        var stale: ?[]u8 = null;
        defer if (stale) |t| gpa.free(t);
        if (path) |p| {
            if (cwd.statFile(io, p, .{})) |st| {
                if (cwd.readFileAlloc(io, p, gpa, .limited(max_schema_bytes))) |text| {
                    const age = std.Io.Timestamp.now(io, .real).toSeconds() - st.mtime.toSeconds();
                    if (!refresh and age >= 0 and age < fresh_seconds) return text;
                    stale = text;
                } else |_| {}
            } else |_| {}
        }

        var failure_buf: [64]u8 = undefined;
        var failure: []const u8 = undefined;
        if (http.fetch(gpa, io, source, .{ .max_bytes = max_schema_bytes, .timeout_ms = cfg.timeout_ms })) |r| {
            var res = r;
            defer res.deinit(gpa);
            if (res.ok()) {
                if (path) |p| keepCopy(gpa, io, cfg, p, res.body);
                return try gpa.dupe(u8, res.body);
            }
            failure = std.fmt.bufPrint(&failure_buf, "the server answered {d}", .{res.status}) catch "the server refused";
        } else |e| {
            if (e == error.OutOfMemory) return e;
            failure = http.describe(e);
        }
        if (stale) |t| {
            try err.print("deed validate: {s}: {s}; using an older copy\n", .{ source, failure });
            stale = null;
            return t;
        }
        try err.print("deed validate: {s}: {s}\n", .{ source, failure });
        return null;
    }
    return std.Io.Dir.cwd().readFileAlloc(io, source, gpa, .limited(max_schema_bytes)) catch |e| {
        try err.print("deed validate: {s}: {s}\n", .{ source, @errorName(e) });
        return null;
    };
}

/// Writes the copy whole or not at all. A cache that cannot be written is no
/// reason to fail a run that has its schema.
fn keepCopy(gpa: std.mem.Allocator, io: std.Io, cfg: Config, path: []const u8, body: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, cfg.cache_dir orelse return) catch return;
    const tmp = std.fmt.allocPrint(gpa, "{s}.tmp", .{path}) catch return;
    defer gpa.free(tmp);
    cwd.writeFile(io, .{ .sub_path = tmp, .data = body }) catch return;
    cwd.rename(tmp, cwd, path, io) catch cwd.deleteFile(io, tmp) catch {};
}

/// Validates every record `input` yields. Valid events go to `out` as they
/// were written; the reason for each other goes to `err`. Returns how many
/// records failed.
pub fn validateRecords(
    gpa: std.mem.Allocator,
    schema: *const Schema,
    input: *cli.Input,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !usize {
    var failures: usize = 0;
    var number: usize = 0;
    while (try input.next()) |record| {
        number += 1;
        const line = switch (record) {
            .line => |l| std.mem.trim(u8, l, " \t"),
            .too_long => {
                try err.print("deed validate: line {d}: too long to read\n", .{number});
                failures += 1;
                continue;
            },
        };
        if (line.len == 0) continue;
        var parsed = nostr.event.fromJson(gpa, line) catch |e| {
            try err.print("deed validate: line {d}: invalid event JSON: {s}\n", .{ number, @errorName(e) });
            failures += 1;
            continue;
        };
        defer parsed.deinit();

        var why: std.Io.Writer.Allocating = .init(gpa);
        defer why.deinit();
        if (try validateEvent(gpa, schema, parsed.value, &why.writer)) {
            try out.print("{s}\n", .{line});
            try out.flush();
        } else {
            try err.print("deed validate: line {d}: schema validation failed: ", .{number});
            try relayset.writeEscaped(err, why.written());
            try err.writeByte('\n');
            failures += 1;
        }
    }
    return failures;
}

pub fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    const cache = cmd_nip.cacheDirFor(gpa, "schemas") catch null;
    defer if (cache) |c| gpa.free(c);
    return runWith(gpa, io, args, out, err, .{ .cache_dir = cache });
}

pub fn runWith(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    cfg: Config,
) !u8 {
    var refresh = false;
    var source: []const u8 = default_schema_url;
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (cli.isOneOf(a, &.{ "help", "-h", "--help" })) {
            try out.writeAll(usage);
            return cli.exit_ok;
        }
        if (std.mem.eql(u8, a, "--refresh")) {
            refresh = true;
        } else if (std.mem.eql(u8, a, "--schema")) {
            i += 1;
            if (i >= args.len) {
                try err.writeAll("deed validate: '--schema' needs a value\n");
                return cli.exit_usage;
            }
            source = args[i];
        } else if (std.mem.startsWith(u8, a, "-")) {
            try err.print("deed validate: unknown option '{s}'\n", .{a});
            return cli.exit_usage;
        } else {
            try positionals.append(gpa, a);
        }
    }

    const text = (try loadSchemaText(gpa, io, source, cfg, refresh, err)) orelse return cli.exit_fail;
    defer gpa.free(text);
    var failure: ParseFailure = .{};
    var schema = parseSchema(gpa, text, &failure) catch |e| switch (e) {
        error.BadSchema => {
            try err.print("deed validate: {s}: line {d}: {s}\n", .{ source, failure.line, failure.why });
            return cli.exit_fail;
        },
        else => |other| return other,
    };
    defer schema.deinit();

    const stdin_buf = try gpa.alloc(u8, max_record_bytes);
    defer gpa.free(stdin_buf);
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, stdin_buf);
    var input = cli.Input.init(positionals.items, &stdin_reader.interface);

    const failures = try validateRecords(gpa, &schema, &input, out, err);
    return if (failures == 0) cli.exit_ok else cli.exit_fail;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// The registry's shapes in small: anchors and aliases for tag specs, a quoted
/// key, a quoted scalar, a list item that opens a mapping, an empty `tags`,
/// comments, and nested `next` chains.
const test_schema =
    \\# a comment
    \\_profile: &profile
    \\  type: pubkey
    \\  required: true
    \\  next:
    \\    type: relay
    \\    next:
    \\      type: free  # petname
    \\
    \\_ptag: &ptag
    \\  name: p
    \\  next: *profile
    \\
    \\generic_tags:
    \\  t:
    \\    type: lowercase
    \\    required: true
    \\  expiration:
    \\    type: timestamp
    \\    required: true
    \\
    \\kinds:
    \\  0:
    \\    description: User Metadata
    \\    content:
    \\      type: json
    \\    tags: []
    \\
    \\  1:
    \\    content:
    \\      type: free
    \\    multiple:
    \\      - p
    \\    tags:
    \\      - *ptag
    \\      -
    \\        name: e
    \\        next:
    \\          type: id
    \\          required: true
    \\          next:
    \\            type: constrained
    \\            either:
    \\             - reply
    \\             - '#'
    \\      - name: "g"
    \\        next:
    \\          type: hex
    \\          min: 4
    \\          max: 8
    \\      - name: imeta
    \\        next:
    \\          type: imeta
    \\          required: true
    \\          variadic: true
    \\
    \\  5:
    \\    required:
    \\      - e
    \\      - k
    \\    content:
    \\      type: empty
    \\    tags:
    \\      - name: e
    \\        next:
    \\          type: id
    \\          required: true
    \\      - name: k
    \\        next:
    \\          type: kind
    \\          required: true
    \\
    \\  30023:
    \\    content:
    \\      type: free
    \\    tags: []
    \\
;

fn mkEvent(arena: std.mem.Allocator, signer: nostr.keys.Signer, kp: nostr.keys.KeyPair, kind: u16, tags: []const nostr.event.Tag, content: []const u8) !nostr.event.Event {
    return nostr.event.create(arena, signer, kp, 1_700_000_000, kind, tags, content, null);
}

/// The reason `ev` is refused, or null when it passes.
fn reason(arena: std.mem.Allocator, schema: *const Schema, ev: nostr.event.Event) !?[]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    if (try validateEvent(testing.allocator, schema, ev, &w.writer)) return null;
    return w.written();
}

test "tags, content and required tags are checked against the schema" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failure: ParseFailure = .{};
    var schema = try parseSchema(testing.allocator, test_schema, &failure);
    defer schema.deinit();
    var signer = try nostr.keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x71} ** 32);
    const pk = "ab" ** 32;
    const id = "cd" ** 32;

    // Passes: a p tag through its alias, with and without the optional items.
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", pk }}, "hi")) == null);
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", pk, "wss://r.example", "pet" }}, "hi")) == null);

    // An example event with a malformed pubkey tag.
    const bad_p = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", "not_a_pubkey" }}, ""))).?;
    try testing.expectEqualStrings("tag[0][1]: invalid pubkey value 'not_a_pubkey' at tag 'p', index 1: pubkey should be 64-char hex, got 'not_a_pubkey'", bad_p);

    // A later item, a missing required item, a dangling space.
    const bad_relay = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", pk, "https://r.example" }}, ""))).?;
    try testing.expect(std.mem.indexOf(u8, bad_relay, "tag[0][2]: invalid relay value") != null);
    const short = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{"p"}}, ""))).?;
    try testing.expectEqualStrings("tag[0][1]: invalid tag 'p', missing index 1", short);
    const spaced = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", pk, "wss://r.example ", "x" }}, ""))).?;
    try testing.expectEqualStrings("tag[0][2]: value has dangling space", spaced);

    // Constrained values, including a quoted one, and hex length bounds.
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "e", id, "reply" }}, "")) == null);
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "e", id, "#" }}, "")) == null);
    const bad_marker = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "e", id, "mention" }}, ""))).?;
    try testing.expect(std.mem.endsWith(u8, bad_marker, "not in allowed list"));
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "g", "abcd" }}, "")) == null);
    const long_hex = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "g", "abcdabcdab" }}, ""))).?;
    try testing.expect(std.mem.endsWith(u8, long_hex, "hex value too long: 10 > 8"));

    // A variadic imeta runs the same check over every item.
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "imeta", "url https://x.example/a.png", "m image/png", "dim 10x20" }}, "")) == null);
    const bad_imeta = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "imeta", "url https://x.example/a.png", "dim 10" }}, ""))).?;
    try testing.expect(std.mem.endsWith(u8, bad_imeta, "dim must be WxH format"));

    // Generic tags apply when the kind has no spec for the tag.
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "t", "nostr" }}, "")) == null);
    const upper = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "t", "Nostr" }}, ""))).?;
    try testing.expectEqualStrings("tag[0][1]: invalid lowercase value 'Nostr' at tag 't', index 1: not lowercase", upper);
    const bad_exp = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "expiration", "-5" }}, ""))).?;
    try testing.expect(std.mem.indexOf(u8, bad_exp, "invalid timestamp") != null);
    // A tag nothing describes passes.
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "zzz", "anything" }}, "")) == null);
}

test "content types, required tags, d tags and unknown kinds" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failure: ParseFailure = .{};
    var schema = try parseSchema(testing.allocator, test_schema, &failure);
    defer schema.deinit();
    var signer = try nostr.keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x72} ** 32);
    const id = "cd" ** 32;

    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 0, &.{}, "{\"name\":\"x\"}")) == null);
    const bad_json = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 0, &.{}, "{nope"))).?;
    try testing.expectEqualStrings("content: invalid json", bad_json);

    // Required tags are reported in the order the checker removes them from the list.
    const none = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 5, &.{}, ""))).?;
    try testing.expectEqualStrings("missing tags: [e k]", none);
    const only_e = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 5, &.{&.{ "e", id }}, ""))).?;
    try testing.expectEqualStrings("missing tags: [k]", only_e);
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 5, &.{ &.{ "e", id }, &.{ "k", "1" } }, "")) == null);

    // d tags: refused on a regular kind, required on an addressable one.
    const d_on_regular = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{ "d", "x" }}, ""))).?;
    try testing.expectEqualStrings("non-addressable event can't have a 'd' tag", d_on_regular);
    const no_d = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 30023, &.{}, ""))).?;
    try testing.expectEqualStrings("missing tags: [d]", no_d);
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 30023, &.{&.{ "d", "x" }}, "")) == null);

    const empty = (try reason(arena, &schema, try mkEvent(arena, signer, kp, 1, &.{&.{}}, ""))).?;
    try testing.expectEqualStrings("empty tag", empty);
    // A kind the schema does not list passes whatever it carries.
    try testing.expect(try reason(arena, &schema, try mkEvent(arena, signer, kp, 4242, &.{&.{ "d", "x" }}, "anything")) == null);
}

test "records are checked one by one: passes are echoed, failures explained, status 1" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var failure: ParseFailure = .{};
    var schema = try parseSchema(testing.allocator, test_schema, &failure);
    defer schema.deinit();
    var signer = try nostr.keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x73} ** 32);

    const good = try nostr.event.toJson(arena, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", "ab" ** 32 }}, "hello"));
    const bad = try nostr.event.toJson(arena, try mkEvent(arena, signer, kp, 1, &.{&.{ "p", "nope\x1b[2J" }}, "hello"));

    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    var input = cli.Input.init(&.{ good, bad, "{not json", good }, null);
    const failures = try validateRecords(testing.allocator, &schema, &input, &out.writer, &err.writer);
    try testing.expectEqual(@as(usize, 2), failures);

    const expected = try std.fmt.allocPrint(arena, "{s}\n{s}\n", .{ good, good });
    try testing.expectEqualStrings(expected, out.written());
    try testing.expect(std.mem.indexOf(u8, err.written(), "deed validate: line 2: schema validation failed: tag[0][1]: invalid pubkey value") != null);
    try testing.expect(std.mem.indexOf(u8, err.written(), "deed validate: line 3: invalid event JSON") != null);
    // The reason quotes a value the event's author chose: no raw escape reaches the terminal.
    try testing.expect(std.mem.indexOfScalar(u8, err.written(), 0x1b) == null);
}

test "a schema that is not in the supported YAML subset is refused with its line" {
    var failure: ParseFailure = .{};
    try testing.expectError(error.BadSchema, parseSchema(testing.allocator, "kinds:\n  1:\n    either: [a, b]\n", &failure));
    try testing.expectEqual(@as(usize, 3), failure.line);
    try testing.expectError(error.BadSchema, parseSchema(testing.allocator, "kinds:\n\t1: x\n", &failure));
    try testing.expectEqual(@as(usize, 2), failure.line);
    try testing.expectError(error.BadSchema, parseSchema(testing.allocator, "a: *missing\n", &failure));
}

test "the schema is read from a file, and help and bad options are answered" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "schema.yaml", .data = test_schema });
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/schema.yaml", .{tmp.sub_path});

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = try nostr.keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x74} ** 32);
    const bad = try nostr.event.toJson(arena, try mkEvent(arena, signer, kp, 1, &.{&.{ "t", "UP" }}, ""));
    const good = try nostr.event.toJson(arena, try mkEvent(arena, signer, kp, 1, &.{&.{ "t", "up" }}, ""));

    var out: std.Io.Writer.Allocating = .init(arena);
    var err: std.Io.Writer.Allocating = .init(arena);
    try testing.expectEqual(cli.exit_fail, try run(testing.allocator, testing.io, &.{ "--schema", path, bad }, &out.writer, &err.writer));
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expectEqual(cli.exit_ok, try run(testing.allocator, testing.io, &.{ "--schema", path, good }, &out.writer, &err.writer));
    try testing.expectEqualStrings(good, std.mem.trimEnd(u8, out.written(), "\n"));

    try testing.expectEqual(cli.exit_fail, try run(testing.allocator, testing.io, &.{ "--schema", "no/such/file.yaml", good }, &out.writer, &err.writer));
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{"--bogus"}, &out.writer, &err.writer));
    try testing.expectEqual(cli.exit_usage, try run(testing.allocator, testing.io, &.{"--schema"}, &out.writer, &err.writer));
}

test "a schema fetched from a URL is kept for a day, refreshed on request, and used offline" {
    const io = testing.io;
    var da: http.TestAllocator = .init;
    defer if (da.deinit() == .leak) @panic("leaked");
    const gpa = da.allocator();

    var srv: http.TestServer = undefined;
    try srv.start(io, &.{.{ .path = "/schema.yaml", .body = test_schema }}, 2);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &root);
    const cfg: Config = .{ .cache_dir = root[0..n], .timeout_ms = 2_000 };

    var url_buf: [64]u8 = undefined;
    const url = try gpa.dupe(u8, try srv.url(&url_buf, "/schema.yaml"));
    defer gpa.free(url);

    var signer = try nostr.keys.Signer.initRandomized(io);
    defer signer.deinit();
    const kp = try signer.keyPairFromSecretKey([_]u8{0x74} ** 32);
    const good = try nostr.event.toJson(gpa, try mkEvent(gpa, signer, kp, 1, &.{&.{ "t", "up" }}, ""));
    defer gpa.free(good);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    // Two fetches are possible; the second run must not use one.
    try testing.expectEqual(cli.exit_ok, try runWith(gpa, io, &.{ "--schema", url, good }, &out.writer, &err.writer, cfg));
    try testing.expectEqual(cli.exit_ok, try runWith(gpa, io, &.{ "--schema", url, good }, &out.writer, &err.writer, cfg));
    try testing.expectEqualStrings("", err.written());
    // --refresh uses the second connection.
    try testing.expectEqual(cli.exit_ok, try runWith(gpa, io, &.{ "--refresh", "--schema", url, good }, &out.writer, &err.writer, cfg));
    srv.stop(io);
    // The server is gone: the kept copy still works, with a warning.
    try testing.expectEqual(cli.exit_ok, try runWith(gpa, io, &.{ "--refresh", "--schema", url, good }, &out.writer, &err.writer, cfg));
    try testing.expect(std.mem.indexOf(u8, err.written(), "older copy") != null);
}
