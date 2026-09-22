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
/// The far end of the output pipe went away, as in `deed decode … | head -1`.
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

    pub fn init(positionals: []const []const u8, stdin: ?*std.Io.Reader) Input {
        return .{
            .positionals = positionals,
            .stdin = if (positionals.len == 0) stdin else null,
        };
    }

    /// The next record, or null at the end.
    pub fn next(self: *Input) !?Record {
        if (self.index < self.positionals.len) {
            defer self.index += 1;
            return .{ .line = self.positionals[self.index] };
        }
        const r = self.stdin orelse return null;
        while (true) {
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
};

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
