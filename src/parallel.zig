//! An ordered worker pool.
//!
//! The caller fills chunks, the pool processes them on N threads, and the
//! results come back to the caller's thread in the order the chunks were
//! submitted. Memory is bounded by a fixed window of in-flight chunks: when the
//! window is full, `acquire` waits for the oldest one and delivers it first.
//!
//! The pool owns no data. A `Chunk` is whatever the caller needs to carry a
//! batch of inputs and their results, and it is reused across the run, so
//! steady state allocates nothing here.
//!
//! `Ctx` supplies two functions:
//!
//!   fn process(ctx: *Ctx, chunk: *Chunk) void   // on a worker thread
//!   fn deliver(ctx: *Ctx, chunk: *Chunk) !void  // on the caller's thread, in order
//!
//! `process` cannot fail; it records failures in the chunk. `deliver` can, and
//! an error from it cancels the run and comes back from `acquire` or `finish`.

const std = @import("std");

pub const Options = struct {
    /// Worker threads. Zero means one per CPU.
    workers: usize = 0,
    /// Chunks that may be in flight at once. Zero means three per worker.
    window: usize = 0,
};

pub const Error = error{Canceled};

pub fn cpuCount() usize {
    return std.Thread.getCpuCount() catch 1;
}

pub fn Ordered(comptime Chunk: type, comptime Ctx: type) type {
    return struct {
        const Self = @This();

        const State = enum { free, ready, busy, done };

        const Slot = struct {
            chunk: Chunk,
            state: State = .free,
        };

        gpa: std.mem.Allocator,
        io: std.Io,
        ctx: *Ctx,
        slots: []Slot,
        threads: []std.Thread,
        started: usize = 0,

        mutex: std.Io.Mutex = .init,
        work_cond: std.Io.Condition = .init,
        done_cond: std.Io.Condition = .init,

        /// Sequence numbers: `submitted` chunks have been handed over, workers
        /// have claimed up to `claimed`, the caller has delivered up to `delivered`.
        /// A chunk lives in slot `seq % slots.len`.
        submitted: u64 = 0,
        claimed: u64 = 0,
        delivered: u64 = 0,
        shutdown: bool = false,

        /// `init_chunk` builds one empty chunk per slot; `deinit_chunk` frees it.
        pub fn init(
            gpa: std.mem.Allocator,
            io: std.Io,
            ctx: *Ctx,
            options: Options,
            comptime init_chunk: fn (std.mem.Allocator) Chunk,
        ) !*Self {
            const n = if (options.workers == 0) cpuCount() else options.workers;
            const window = if (options.window == 0) @max(n * 3, 2) else @max(options.window, 1);

            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const slots = try gpa.alloc(Slot, window);
            errdefer gpa.free(slots);
            const threads = try gpa.alloc(std.Thread, n);
            errdefer gpa.free(threads);

            for (slots) |*s| s.* = .{ .chunk = init_chunk(gpa) };
            self.* = .{ .gpa = gpa, .io = io, .ctx = ctx, .slots = slots, .threads = threads };

            // A spawn that fails leaves the pool smaller, and a pool of none
            // processes chunks on the caller's thread. Slower, never wrong.
            while (self.started < n) {
                self.threads[self.started] = std.Thread.spawn(.{}, worker, .{self}) catch break;
                self.started += 1;
            }
            return self;
        }

        /// Stops the workers and frees the pool. Chunks still in flight are
        /// dropped undelivered.
        pub fn deinit(self: *Self, comptime deinit_chunk: fn (*Chunk) void) void {
            self.mutex.lockUncancelable(self.io);
            self.shutdown = true;
            self.work_cond.broadcast(self.io);
            self.mutex.unlock(self.io);
            for (self.threads[0..self.started]) |t| t.join();
            for (self.slots) |*s| deinit_chunk(&s.chunk);
            const gpa = self.gpa;
            gpa.free(self.threads);
            gpa.free(self.slots);
            gpa.destroy(self);
        }

        fn worker(self: *Self) void {
            const io = self.io;
            self.mutex.lockUncancelable(io);
            while (true) {
                if (self.shutdown) break;
                if (self.claimed < self.submitted) {
                    const seq = self.claimed;
                    self.claimed += 1;
                    const slot = &self.slots[@intCast(seq % self.slots.len)];
                    slot.state = .busy;
                    self.mutex.unlock(io);
                    self.ctx.process(&slot.chunk);
                    self.mutex.lockUncancelable(io);
                    slot.state = .done;
                    self.done_cond.broadcast(io);
                    continue;
                }
                self.work_cond.waitUncancelable(io, &self.mutex);
            }
            self.mutex.unlock(io);
        }

        /// The oldest undelivered chunk, once it is done. Null when none is
        /// outstanding.
        fn deliverOldest(self: *Self, wait: bool) !bool {
            const io = self.io;
            if (self.delivered == self.submitted) return false;
            const slot = &self.slots[@intCast(self.delivered % self.slots.len)];
            try self.mutex.lock(io);
            while (slot.state != .done) {
                if (!wait) {
                    self.mutex.unlock(io);
                    return false;
                }
                self.done_cond.wait(io, &self.mutex) catch |e| {
                    self.mutex.unlock(io);
                    return e;
                };
            }
            self.mutex.unlock(io);
            // Delivered whether or not it succeeds: a failed delivery ends the run.
            self.delivered += 1;
            const result = self.ctx.deliver(&slot.chunk);
            slot.state = .free;
            try result;
            return true;
        }

        /// An empty chunk to fill. Waits, delivering finished chunks in order,
        /// while the window is full.
        pub fn acquire(self: *Self) !*Chunk {
            // Hand back whatever is already finished so output keeps flowing.
            while (try self.deliverOldest(false)) {}
            while (self.submitted - self.delivered >= self.slots.len) {
                _ = try self.deliverOldest(true);
            }
            return &self.slots[@intCast(self.submitted % self.slots.len)].chunk;
        }

        /// Hands the chunk from the last `acquire` to the workers.
        pub fn submit(self: *Self) !void {
            const io = self.io;
            const slot = &self.slots[@intCast(self.submitted % self.slots.len)];
            if (self.started == 0) {
                self.ctx.process(&slot.chunk);
                slot.state = .done;
                self.submitted += 1;
                self.claimed += 1;
                return;
            }
            try self.mutex.lock(io);
            slot.state = .ready;
            self.submitted += 1;
            self.work_cond.signal(io);
            self.mutex.unlock(io);
        }

        /// Delivers every chunk still in flight, in order.
        pub fn finish(self: *Self) !void {
            while (self.delivered != self.submitted) _ = try self.deliverOldest(true);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests

const TestChunk = struct {
    values: [8]u32 = undefined,
    len: usize = 0,
};

const TestCtx = struct {
    out: std.ArrayList(u32) = .empty,
    gpa: std.mem.Allocator,
    fail_after: usize = std.math.maxInt(usize),
    delivered: usize = 0,

    pub fn process(_: *TestCtx, chunk: *TestChunk) void {
        for (chunk.values[0..chunk.len]) |*v| {
            // Uneven work, so later chunks routinely finish before earlier ones.
            var x: u32 = v.*;
            var i: u32 = 0;
            while (i < (v.* % 7) * 2000) : (i += 1) x = x *% 1664525 +% 1013904223;
            std.mem.doNotOptimizeAway(x);
            v.* = v.* * 2;
        }
    }

    pub fn deliver(self: *TestCtx, chunk: *TestChunk) !void {
        if (self.delivered >= self.fail_after) return error.TestFailure;
        self.delivered += 1;
        try self.out.appendSlice(self.gpa, chunk.values[0..chunk.len]);
    }
};

fn testInit(_: std.mem.Allocator) TestChunk {
    return .{};
}
fn testDeinit(_: *TestChunk) void {}

fn runTest(workers: usize, window: usize, total: u32, fail_after: usize) !TestCtx {
    const gpa = std.testing.allocator;
    var ctx: TestCtx = .{ .gpa = gpa, .fail_after = fail_after };
    errdefer ctx.out.deinit(gpa);
    const pool = try Ordered(TestChunk, TestCtx).init(gpa, std.testing.io, &ctx, .{
        .workers = workers,
        .window = window,
    }, testInit);
    defer pool.deinit(testDeinit);

    var n: u32 = 0;
    while (n < total) {
        const chunk = try pool.acquire();
        chunk.len = 0;
        while (chunk.len < chunk.values.len and n < total) : (n += 1) {
            chunk.values[chunk.len] = n;
            chunk.len += 1;
        }
        try pool.submit();
    }
    try pool.finish();
    return ctx;
}

test "results come back in submission order" {
    var ctx = try runTest(4, 6, 5000, std.math.maxInt(usize));
    defer ctx.out.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5000), ctx.out.items.len);
    for (ctx.out.items, 0..) |v, i| try std.testing.expectEqual(@as(u32, @intCast(i)) * 2, v);
}

test "a window of one still works" {
    var ctx = try runTest(3, 1, 100, std.math.maxInt(usize));
    defer ctx.out.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 100), ctx.out.items.len);
}

test "no input delivers nothing" {
    var ctx = try runTest(2, 4, 0, std.math.maxInt(usize));
    defer ctx.out.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), ctx.out.items.len);
}

test "a failing delivery cancels the run and surfaces its error" {
    const r = runTest(4, 6, 5000, 3);
    try std.testing.expectError(error.TestFailure, r);
}
