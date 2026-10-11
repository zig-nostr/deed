//! Shared plumbing: exit codes, small argument helpers, and the pipeline
//! contract every verb obeys.

const std = @import("std");

/// Exit codes. Scripts branch on these, so they are part of the interface and
/// not free to drift.
pub const exit_ok: u8 = 0;
/// The command was understood and ran, and something went wrong: unparseable
/// input, a bad signature, a relay that would not answer.
pub const exit_fail: u8 = 1;
/// The command was not understood: unknown verb, unknown flag, missing
/// argument. Nothing was attempted.
pub const exit_usage: u8 = 2;
/// The far end of the output pipe went away, as in `deed decode ... | head -1`.
/// 128 + SIGPIPE, which is the status a shell shows for a filter whose reader
/// left. deed reports the number rather than dying of the signal, because the
/// I/O implementation it runs on installs a SIGPIPE handler of its own.
pub const exit_broken_pipe: u8 = 141;

/// True when `arg` matches any of `options`.
pub fn isOneOf(arg: []const u8, options: []const []const u8) bool {
    for (options) |o| {
        if (std.mem.eql(u8, arg, o)) return true;
    }
    return false;
}

/// One record, or the fact that one was too long to read.
pub const Record = union(enum) {
    /// A record. One read from stdin borrows the reader's buffer and is only
    /// valid until the following call, so a caller that needs to keep one has
    /// to copy it.
    line: []const u8,
    /// A record longer than the buffer could hold. Its bytes are gone and the
    /// stream is positioned at the start of the next record, so a verb that
    /// reports this one and carries on loses it alone.
    too_long,
};

/// Reads the records a verb operates on.
///
/// The contract, written once here so that no verb has to invent its own: a
/// verb takes its inputs as positional arguments, and when given none, reads
/// them as newline-delimited records on stdin. That is the whole reason
/// `deed event - | deed verify` composes without either side knowing the other
/// exists.
///
/// Positional arguments *win* rather than merge. A verb handed both would
/// otherwise quietly process input the caller never mentioned.
pub const Input = struct {
    positionals: []const []const u8,
    index: usize = 0,
    stdin: ?*std.Io.Reader,
    mode: Mode = .lines,
    /// The line a stdin record started on, counting from 1 and counting empty
    /// lines. 0 for a positional argument, which has no line.
    start_line: usize = 0,
    /// The line the next unread stdin byte is on.
    line_no: usize = 1,

    pub const Mode = enum {
        /// One record per line. For verbs whose records are free text.
        lines,
        /// One record per JSON value, separated by any whitespace: one per
        /// line, pretty-printed over many lines, or several on one line.
        json,
    };

    pub fn init(positionals: []const []const u8, stdin: ?*std.Io.Reader) Input {
        return .{
            .positionals = positionals,
            .stdin = if (positionals.len == 0) stdin else null,
        };
    }

    /// Like `init`, for verbs whose records are JSON values (events, filters,
    /// drafts). A value may span lines, and values may share one.
    pub fn initJson(positionals: []const []const u8, stdin: ?*std.Io.Reader) Input {
        var i = init(positionals, stdin);
        i.mode = .json;
        return i;
    }

    /// The next record, or null at the end.
    pub fn next(self: *Input) !?Record {
        if (self.index < self.positionals.len) {
            self.start_line = 0;
            defer self.index += 1;
            return .{ .line = self.positionals[self.index] };
        }
        const r = self.stdin orelse return null;
        if (self.mode == .json) return self.nextJson(r);
        while (true) {
            self.start_line = self.line_no;
            self.line_no += 1;
            // `takeDelimiter` treats end-of-stream as a final delimiter and
            // returns null only when nothing is left at all. That is exactly
            // the record semantics we want (a last line with no trailing
            // newline is still a line), and hand-rolling it around
            // `takeDelimiterExclusive` got it wrong in both directions.
            const line = (r.takeDelimiter('\n') catch |e| switch (e) {
                // One record too big for the buffer is no reason to lose the
                // records behind it, and letting this error out does exactly
                // that: it ends the stream, and everything still queued goes
                // with it, none of it malformed. Skip to the next delimiter
                // and hand back a `too_long` instead, so an over-long record
                // fails the way every other bad record already does.
                error.StreamTooLong => {
                    if (r.discardDelimiterInclusive('\n')) |_| {} else |skip_err| {
                        // No delimiter behind it, so the over-long record ran
                        // to the end of the stream and nothing is left.
                        if (skip_err != error.EndOfStream) return skip_err;
                        self.stdin = null;
                    }
                    return .too_long;
                },
                else => |other| return other,
            }) orelse {
                self.stdin = null;
                return null;
            };
            // Only the line ending comes off, never the reader's own bytes.
            //
            // This used to trim spaces and tabs from both ends of every record,
            // which is harmless for a code or a JSON object and silent data
            // loss for a message: `printf '  hello  '` piped into
            // `deed encrypt` encrypted `hello`, and nothing said so. A record
            // is whatever sat between two newlines, and what to do about the
            // whitespace in it is the verb's business, not this one's.
            const body = if (std.mem.endsWith(u8, line, "\r")) line[0 .. line.len - 1] else line;
            // A truly empty line separates records and is not one. A line of
            // spaces IS one, because for `deed encrypt` it is a message
            // somebody chose to send.
            if (body.len == 0) continue;
            return .{ .line = body };
        }
    }

    fn nextJson(self: *Input, r: *std.Io.Reader) !?Record {
        // Whitespace between values separates them and is not one.
        while (true) {
            const buf = r.buffered();
            var i: usize = 0;
            while (i < buf.len and Scan.isSpace(buf[i])) : (i += 1) {
                if (buf[i] == '\n') self.line_no += 1;
            }
            r.toss(i);
            if (i < buf.len) break;
            r.fillMore() catch |e| switch (e) {
                error.EndOfStream => {
                    self.stdin = null;
                    return null;
                },
                else => |other| return other,
            };
        }
        self.start_line = self.line_no;

        var st: Scan = .{};
        var scanned: usize = 0;
        // Past the buffer a value cannot be held, so the rest of it is read
        // and thrown away, still tracking where it ends: memory stays at the
        // buffer size however long the value is.
        var discarding = false;
        while (true) {
            const buf = r.buffered();
            while (scanned < buf.len) {
                const end = switch (st.step(buf[scanned])) {
                    .more => {
                        scanned += 1;
                        continue;
                    },
                    .end_incl => scanned + 1,
                    .end_excl => scanned,
                };
                self.line_no += countNewlines(buf[0..end]);
                if (discarding) {
                    r.toss(end);
                    return .too_long;
                }
                const rec = try r.take(end);
                return .{ .line = std.mem.trimEnd(u8, rec, "\r\n") };
            }
            if (!discarding and buf.len == r.buffer.len) discarding = true;
            if (discarding) {
                self.line_no += countNewlines(buf);
                r.toss(buf.len);
                scanned = 0;
            }
            r.fillMore() catch |e| switch (e) {
                error.EndOfStream => {
                    // The stream ended inside the value. A bare scalar at the
                    // very end is complete; anything else is left for the
                    // parser to refuse.
                    if (discarding) {
                        self.stdin = null;
                        return .too_long;
                    }
                    const rec = try r.take(r.bufferedLen());
                    return .{ .line = std.mem.trimEnd(u8, rec, "\r\n") };
                },
                else => |other| return other,
            };
        }
    }
};

/// Tracks where one JSON value ends without parsing it, so a value can be
/// cut out of the stream in bounded memory and handed to the real parser.
const Scan = struct {
    depth: u32 = 0,
    started: bool = false,
    scalar: bool = false,
    in_str: bool = false,
    esc: bool = false,
    nl: bool = false,

    const Step = enum { more, end_incl, end_excl };

    fn isSpace(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\r' or c == '\n';
    }

    fn step(s: *Scan, c: u8) Step {
        if (!s.started) {
            s.started = true;
            switch (c) {
                '{', '[' => s.depth = 1,
                '"' => s.in_str = true,
                else => s.scalar = true,
            }
            return .more;
        }
        // A bare word runs to the end of its line, so a stray line of prose is
        // one bad value and not one per word.
        if (s.scalar) return if (c == '\n' or c == '\r') .end_excl else .more;
        if (s.in_str) {
            if (s.esc) {
                s.esc = false;
                return .more;
            }
            switch (c) {
                '\\' => s.esc = true,
                '"' => {
                    s.in_str = false;
                    if (s.depth == 0) return .end_incl;
                },
                // A raw newline cannot be inside a JSON string, so a string
                // still open at one is malformed. Ending the value here keeps
                // one stray quote from swallowing the rest of the stream.
                '\n' => return .end_excl,
                else => {},
            }
            return .more;
        }
        // The same recovery for an unclosed brace: a `{` in the first column
        // of a line starts a new value, since nesting is indented.
        if (s.nl) {
            if (c == '{') return .end_excl;
            if (c != '\r') s.nl = false;
        }
        switch (c) {
            '"' => s.in_str = true,
            '{', '[' => s.depth += 1,
            '}', ']' => {
                s.depth -|= 1;
                if (s.depth == 0) return .end_incl;
            },
            '\n' => s.nl = true,
            else => {},
        }
        return .more;
    }
};

fn countNewlines(bytes: []const u8) usize {
    return std.mem.count(u8, bytes, "\n");
}

test "positional arguments win over stdin" {
    var input = Input.init(&.{ "a", "b" }, null);
    try std.testing.expectEqualStrings("a", (try input.next()).?.line);
    try std.testing.expectEqualStrings("b", (try input.next()).?.line);
    try std.testing.expect((try input.next()) == null);
}

test "no positionals and no stdin yields nothing" {
    var input = Input.init(&.{}, null);
    try std.testing.expect((try input.next()) == null);
}

test "a record is handed back as it was written" {
    // `deed encrypt` takes a record as the MESSAGE. This used to trim spaces and
    // tabs off both ends of every record, so `printf '  hello  '` piped in
    // encrypted `hello` and nothing said so: the reader's own words, altered on
    // the way to being sealed.
    var source: std.Io.Reader = .fixed("  hello  \nplain\n\ttabbed\t\n");
    var window: [64]u8 = undefined;
    var limited = source.limited(.unlimited, &window);
    var input = Input.init(&.{}, &limited.interface);

    try std.testing.expectEqualStrings("  hello  ", (try input.next()).?.line);
    try std.testing.expectEqualStrings("plain", (try input.next()).?.line);
    try std.testing.expectEqualStrings("\ttabbed\t", (try input.next()).?.line);
    try std.testing.expect((try input.next()) == null);
}

test "a line ending comes off, and an empty line is still a separator" {
    // CRLF is the one thing that is not the reader's bytes: it is how the line
    // ended, not part of what they wrote.
    var source: std.Io.Reader = .fixed("one\r\n\ntwo\r\n");
    var window: [64]u8 = undefined;
    var limited = source.limited(.unlimited, &window);
    var input = Input.init(&.{}, &limited.interface);

    try std.testing.expectEqualStrings("one", (try input.next()).?.line);
    try std.testing.expectEqualStrings("two", (try input.next()).?.line);
    try std.testing.expect((try input.next()) == null);
}

test "a line of spaces is a record, not a separator" {
    // For `deed encrypt` it is a message somebody chose to send. Only a truly
    // empty line separates.
    var source: std.Io.Reader = .fixed("   \n");
    var window: [64]u8 = undefined;
    var limited = source.limited(.unlimited, &window);
    var input = Input.init(&.{}, &limited.interface);
    try std.testing.expectEqualStrings("   ", (try input.next()).?.line);
}

test "a record too long to hold does not take the stream with it" {
    // A 32-byte window over input whose second record is far longer than it.
    const data = "aa\n" ++ ("x" ** 200) ++ "\nbb\ncc\n";
    var source: std.Io.Reader = .fixed(data);
    var window: [32]u8 = undefined;
    var limited = source.limited(.unlimited, &window);
    var input = Input.init(&.{}, &limited.interface);

    try std.testing.expectEqualStrings("aa", (try input.next()).?.line);
    try std.testing.expect(std.meta.activeTag((try input.next()).?) == .too_long);
    // The records behind it are the whole point: they used to go missing.
    try std.testing.expectEqualStrings("bb", (try input.next()).?.line);
    try std.testing.expectEqualStrings("cc", (try input.next()).?.line);
    try std.testing.expect((try input.next()) == null);
}

test "an over-long record with nothing behind it ends the stream" {
    const data = "aa\n" ++ ("x" ** 200);
    var source: std.Io.Reader = .fixed(data);
    var window: [32]u8 = undefined;
    var limited = source.limited(.unlimited, &window);
    var input = Input.init(&.{}, &limited.interface);

    try std.testing.expectEqualStrings("aa", (try input.next()).?.line);
    try std.testing.expect(std.meta.activeTag((try input.next()).?) == .too_long);
    try std.testing.expect((try input.next()) == null);
}

test "isOneOf matches exactly" {
    try std.testing.expect(isOneOf("--help", &.{ "-h", "--help" }));
    try std.testing.expect(!isOneOf("--hel", &.{ "-h", "--help" }));
}
