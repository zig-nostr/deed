//! Asking a set of relays one question, and collecting what comes back.
//!
//! Shared by `req` and `fetch`, because they differ in how the question is
//! built and not at all in how it is asked.
//!
//! A command line is a SHORT-LIVED process, which changes the shape of this
//! from what a long-running client does. There is no reconnect, no backoff and
//! no liveness tracking: a relay that will not answer inside the deadline is a
//! relay this run does without, and the run says so on stderr rather than
//! waiting for it.

const std = @import("std");
const nostr = @import("nostr");

const filter = nostr.filter;
const message = nostr.message;
const relay = nostr.relay;

pub const Options = struct {
    /// Stop once every relay that answered has sent EOSE.
    ///
    /// A relay sends EOSE when it has finished replaying what it has stored,
    /// so this is the difference between "everything you have" and "everything
    /// you have, and then whatever arrives while I wait".
    until_eose: bool = true,
    /// The whole run gives up here, whatever the relays are doing.
    ///
    /// nak has no equivalent and this is a deliberate difference. Its per-relay
    /// select waits on EOSE, a close or an event and nothing else, so a relay
    /// that accepts a subscription and then says nothing holds the process open
    /// for as long as somebody lets it (go-nostr's pool.go:677-729, no timer in
    /// that select). That is survivable at an interactive prompt and not
    /// survivable in a script, which is where a command line spends most of its
    /// life.
    deadline_ms: i64,
    /// How long one read may block before the loop moves to the next relay.
    /// Short, because it is a round-robin across relays rather than a wait.
    poll_ms: i64,
    /// Every event that arrives is written here before it is printed.
    store: ?*nostr.store.Store = null,
};

pub const Outcome = struct {
    /// Relays that answered the dial.
    dialled: usize = 0,
    /// Relays that could not be reached at all.
    unreachable_count: usize = 0,
    /// Distinct events printed.
    events: usize = 0,
    /// Relays that reached EOSE before the deadline.
    complete: usize = 0,
};

const max_relays = 32;

/// Whether an event answers any of the questions this run asked.
///
/// A relay is not obliged to be honest about what it sends, and a subscription
/// is not a promise. Without this a relay could answer `-k 1` with anything it
/// liked and the output would carry it.
fn matchesAny(filters: []const filter.Filter, ev: nostr.event.Event) bool {
    for (filters) |f| {
        if (f.matches(ev)) return true;
    }
    return false;
}

/// The subscription every run uses. One per process, closed by the process.
pub const subscription_id = "deed";

/// Dials `urls`, asks each the same question, and prints every distinct event
/// as one line of JSON.
///
/// Events are deduplicated across relays by id: the same note held by four
/// relays is one line, which is what makes piping this into `deed verify`
/// mean something.
pub fn query(
    gpa: std.mem.Allocator,
    io: std.Io,
    urls: []const []const u8,
    filters: []const filter.Filter,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    opts: Options,
) !Outcome {
    var result = Outcome{};

    var relays: [max_relays]?*relay.Relay = @splat(null);
    var done: [max_relays]bool = @splat(false);
    const n = @min(urls.len, max_relays);

    defer for (relays[0..n]) |maybe| {
        if (maybe) |r| {
            r.shutdown(io);
            r.deinit();
        }
    };

    for (urls[0..n], 0..) |url, i| {
        const r = relay.dial(gpa, io, url) catch |e| {
            // Named, not swallowed. A run that quietly asked three relays
            // instead of four looks like the fourth had nothing.
            try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
            result.unreachable_count += 1;
            done[i] = true;
            continue;
        };
        r.subscribe(subscription_id, filters) catch |e| {
            try err.print("deed: {s}: {s}\n", .{ url, @errorName(e) });
            r.shutdown(io);
            r.deinit();
            result.unreachable_count += 1;
            done[i] = true;
            continue;
        };
        relays[i] = r;
        result.dialled += 1;
    }
    if (result.dialled == 0) return result;

    var seen = std.AutoHashMap([32]u8, void).init(gpa);
    defer seen.deinit();

    var signer = nostr.keys.Signer.init();
    defer signer.deinit();

    // `.awake` is this standard library's monotonic clock: it cannot go
    // backwards when somebody adjusts the system time mid-run, which `.real`
    // can, and a deadline that can move backwards is not one.
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    while (true) {
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        if (started.durationTo(now).raw.toMilliseconds() >= opts.deadline_ms) {
            try err.writeAll("deed: gave up waiting for the relays still answering\n");
            break;
        }

        var any_live = false;
        for (relays[0..n], 0..) |maybe, i| {
            const r = maybe orelse continue;
            if (done[i]) continue;
            any_live = true;

            var msg = (r.receiveTimeout(std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(opts.poll_ms), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => continue,
                else => {
                    // A relay that drops mid-answer is a relay this run does
                    // without. The events it already sent are still good.
                    try err.print("deed: a relay stopped answering: {s}\n", .{@errorName(e)});
                    done[i] = true;
                    continue;
                },
            }) orelse {
                done[i] = true;
                continue;
            };
            defer msg.deinit();

            switch (msg.value) {
                .event => |e| {
                    if (seen.contains(e.event.id)) continue;
                    // Checked before it is trusted. A relay can send anything,
                    // including an event nobody signed or one that answers a
                    // question this run did not ask. nak verifies by default and
                    // drops both (go-nostr relay.go:399-410), and a tool whose
                    // output people pipe into other tools has to do the same:
                    // this is the last point where a forgery can be stopped.
                    if (!(nostr.event.verify(gpa, signer, e.event) catch false)) {
                        try err.print("deed: a relay sent an event that is not correctly signed\n", .{});
                        continue;
                    }
                    if (!matchesAny(filters, e.event)) {
                        try err.print("deed: a relay sent an event nobody asked for\n", .{});
                        continue;
                    }
                    try seen.put(e.event.id, {});
                    if (opts.store) |s| {
                        // Written before it is printed, so a run interrupted
                        // partway through still kept what it had already read.
                        // `ingest` checks the signature, so a relay cannot put
                        // something into the store by claiming it.
                        _ = s.ingest(gpa, e.event, .{}) catch {};
                    }
                    const json = try nostr.event.toJson(gpa, e.event);
                    defer gpa.free(json);
                    try out.print("{s}\n", .{json});
                    result.events += 1;
                },
                .eose => {
                    result.complete += 1;
                    if (opts.until_eose) done[i] = true;
                },
                .closed => |c| {
                    try err.print("deed: a relay closed the subscription: {s}\n", .{c.message});
                    done[i] = true;
                },
                .notice => |notice| try err.print("deed: notice: {s}\n", .{notice.message}),
                // A relay asking for NIP-42 is asking for a signature this verb
                // was not given a key for. Saying so beats looking like a relay
                // with nothing to say.
                .auth => try err.print("deed: a relay wants authentication, which this verb cannot give it\n", .{}),
                .ok => {},
            }
        }
        if (!any_live) break;
    }

    return result;
}

test {
    // Forces this file to be analysed. `_ = @import("relayset.zig")` alone
    // imports it without ever compiling a function body nobody references, so
    // the build would go green over code that does not compile.
    std.testing.refAllDecls(@This());
}
