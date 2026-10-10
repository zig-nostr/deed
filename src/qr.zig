//! QR codes, for showing a `bunker://` URI to a phone.
//!
//! A small encoder for exactly what deed needs: byte mode, error correction
//! level L or M, versions 1 through 40, and a terminal rendering. A connection
//! URI is a few hundred bytes of ASCII, so byte mode is the only one worth
//! carrying, and level M is what `deed bunker --qrcode` prints: it survives a
//! smudged screen or a glare spot, and still fits two relays and a secret in a
//! code small enough for a terminal.
//!
//! The steps follow ISO/IEC 18004: build the bit stream, split it into blocks,
//! append Reed-Solomon error correction to each, interleave, place the
//! codewords around the function patterns, then try all eight masks and keep
//! the one with the lowest penalty.

const std = @import("std");

pub const Ecc = enum {
    low,
    medium,

    /// The two bits the format information carries for this level.
    fn formatBits(self: Ecc) u32 {
        return switch (self) {
            .low => 1,
            .medium => 0,
        };
    }
};

pub const Error = error{ DataTooLong, OutOfMemory };

pub const min_version = 1;
pub const max_version = 40;

/// Error correction codewords per block, by level and version (index 0 unused).
const ecc_per_block = [2][41]u8{
    .{ 0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 },
    .{ 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28 },
};

/// Error correction blocks, by level and version (index 0 unused).
const ecc_blocks = [2][41]u8{
    .{ 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25 },
    .{ 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49 },
};

/// A finished symbol: `size` by `size` modules, true for dark.
pub const Code = struct {
    version: u8,
    size: usize,
    mask: u3,
    modules: []bool,

    pub fn deinit(self: *Code, gpa: std.mem.Allocator) void {
        gpa.free(self.modules);
        self.* = undefined;
    }

    /// Whether the module at column `x`, row `y` is dark.
    pub fn get(self: *const Code, x: usize, y: usize) bool {
        return self.modules[y * self.size + x];
    }
};

/// Encodes `data` in byte mode at level `ecc`, in the smallest version that
/// holds it. `mask` forces one of the eight masks; null picks the one with the
/// lowest penalty, as the standard says to.
pub fn encode(gpa: std.mem.Allocator, data: []const u8, ecc: Ecc, mask: ?u3) Error!Code {
    const version = pickVersion(data.len, ecc) orelse return Error.DataTooLong;
    const codewords = try dataCodewords(gpa, data, version, ecc);
    defer gpa.free(codewords);
    const all = try addEccAndInterleave(gpa, codewords, version, ecc);
    defer gpa.free(all);

    var m = try Matrix.init(gpa, version);
    defer m.deinit(gpa);
    m.drawFunctionPatterns(ecc);
    m.drawCodewords(all);

    const chosen: u3 = mask orelse blk: {
        var best: u3 = 0;
        var best_score: u64 = std.math.maxInt(u64);
        var k: u4 = 0;
        while (k < 8) : (k += 1) {
            const candidate: u3 = @intCast(k);
            m.applyMask(candidate);
            m.drawFormatBits(ecc, candidate);
            const score = m.penalty();
            if (score < best_score) {
                best = candidate;
                best_score = score;
            }
            // XOR again to undo it.
            m.applyMask(candidate);
        }
        break :blk best;
    };
    m.applyMask(chosen);
    m.drawFormatBits(ecc, chosen);

    const modules = m.modules;
    m.modules = &.{};
    return .{ .version = version, .size = m.size, .mask = chosen, .modules = modules };
}

fn sizeOf(version: u8) usize {
    return @as(usize, version) * 4 + 17;
}

/// Data and error correction modules together: everything that is not a
/// function pattern or format/version information.
fn rawDataModules(version: u8) usize {
    const v: usize = version;
    var result: usize = (16 * v + 128) * v + 64;
    if (v >= 2) {
        const num_align = v / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if (v >= 7) result -= 36;
    }
    return result;
}

fn numDataCodewords(version: u8, ecc: Ecc) usize {
    const e = @intFromEnum(ecc);
    return rawDataModules(version) / 8 - @as(usize, ecc_per_block[e][version]) * ecc_blocks[e][version];
}

fn countBits(version: u8) usize {
    return if (version <= 9) 8 else 16;
}

fn pickVersion(len: usize, ecc: Ecc) ?u8 {
    var v: u8 = min_version;
    while (v <= max_version) : (v += 1) {
        const cb = countBits(v);
        if (len >= (@as(usize, 1) << @intCast(cb))) continue;
        const needed = 4 + cb + 8 * len;
        if (needed <= numDataCodewords(v, ecc) * 8) return v;
    }
    return null;
}

const BitBuffer = struct {
    bytes: []u8,
    len: usize = 0,

    fn append(self: *BitBuffer, value: usize, n: usize) void {
        var i = n;
        while (i > 0) {
            i -= 1;
            const bit: u8 = @intCast((value >> @intCast(i)) & 1);
            self.bytes[self.len >> 3] |= bit << @intCast(7 - (self.len & 7));
            self.len += 1;
        }
    }
};

/// The data codewords: mode, count, the bytes, the terminator and the padding.
fn dataCodewords(gpa: std.mem.Allocator, data: []const u8, version: u8, ecc: Ecc) Error![]u8 {
    const capacity = numDataCodewords(version, ecc);
    const out = try gpa.alloc(u8, capacity);
    @memset(out, 0);
    var bb = BitBuffer{ .bytes = out };
    bb.append(0b0100, 4);
    bb.append(data.len, countBits(version));
    for (data) |b| bb.append(b, 8);
    const capacity_bits = capacity * 8;
    bb.append(0, @min(4, capacity_bits - bb.len));
    bb.append(0, (8 - bb.len % 8) % 8);
    var pad: u8 = 0xEC;
    while (bb.len < capacity_bits) : (pad ^= 0xEC ^ 0x11) bb.append(pad, 8);
    return out;
}

fn gfMultiply(x: u8, y: u8) u8 {
    var z: u16 = 0;
    var i: u4 = 8;
    while (i > 0) {
        i -= 1;
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((@as(u16, y) >> i) & 1) * x;
    }
    return @intCast(z);
}

/// The generator polynomial of `degree`, leading coefficient dropped.
fn rsDivisor(degree: usize, out: []u8) void {
    @memset(out[0..degree], 0);
    out[degree - 1] = 1;
    var root: u8 = 1;
    for (0..degree) |_| {
        for (0..degree) |j| {
            out[j] = gfMultiply(out[j], root);
            if (j + 1 < degree) out[j] ^= out[j + 1];
        }
        root = gfMultiply(root, 0x02);
    }
}

fn rsRemainder(data: []const u8, divisor: []const u8, out: []u8) void {
    const degree = divisor.len;
    @memset(out[0..degree], 0);
    for (data) |b| {
        const factor = b ^ out[0];
        std.mem.copyForwards(u8, out[0 .. degree - 1], out[1..degree]);
        out[degree - 1] = 0;
        for (0..degree) |i| out[i] ^= gfMultiply(divisor[i], factor);
    }
}

fn addEccAndInterleave(gpa: std.mem.Allocator, data: []const u8, version: u8, ecc: Ecc) Error![]u8 {
    const e = @intFromEnum(ecc);
    const num_blocks: usize = ecc_blocks[e][version];
    const block_ecc_len: usize = ecc_per_block[e][version];
    const raw_codewords = rawDataModules(version) / 8;
    const num_short = num_blocks - raw_codewords % num_blocks;
    const short_len = raw_codewords / num_blocks;

    // Every block laid out at the long length, a short block's extra data slot
    // left empty and skipped when interleaving.
    const stride = short_len + 1;
    const blocks = try gpa.alloc(u8, num_blocks * stride);
    defer gpa.free(blocks);
    @memset(blocks, 0);

    var divisor: [30]u8 = undefined;
    rsDivisor(block_ecc_len, &divisor);

    var k: usize = 0;
    for (0..num_blocks) |i| {
        const dat_len = short_len - block_ecc_len + @intFromBool(i >= num_short);
        const dat = data[k .. k + dat_len];
        k += dat_len;
        const block = blocks[i * stride ..][0..stride];
        @memcpy(block[0..dat_len], dat);
        var rem: [30]u8 = undefined;
        rsRemainder(dat, divisor[0..block_ecc_len], &rem);
        @memcpy(block[stride - block_ecc_len ..], rem[0..block_ecc_len]);
    }
    std.debug.assert(k == data.len);

    const out = try gpa.alloc(u8, raw_codewords);
    var n: usize = 0;
    for (0..stride) |i| {
        for (0..num_blocks) |j| {
            if (i != short_len - block_ecc_len or j >= num_short) {
                out[n] = blocks[j * stride + i];
                n += 1;
            }
        }
    }
    std.debug.assert(n == raw_codewords);
    return out;
}

const Matrix = struct {
    version: u8,
    size: usize,
    modules: []bool,
    is_function: []bool,

    fn init(gpa: std.mem.Allocator, version: u8) Error!Matrix {
        const size = sizeOf(version);
        const modules = try gpa.alloc(bool, size * size);
        errdefer gpa.free(modules);
        const is_function = try gpa.alloc(bool, size * size);
        @memset(modules, false);
        @memset(is_function, false);
        return .{ .version = version, .size = size, .modules = modules, .is_function = is_function };
    }

    fn deinit(self: *Matrix, gpa: std.mem.Allocator) void {
        gpa.free(self.modules);
        gpa.free(self.is_function);
    }

    fn at(self: *const Matrix, x: usize, y: usize) bool {
        return self.modules[y * self.size + x];
    }

    fn setFunction(self: *Matrix, x: usize, y: usize, dark: bool) void {
        self.modules[y * self.size + x] = dark;
        self.is_function[y * self.size + x] = true;
    }

    fn drawFunctionPatterns(self: *Matrix, ecc: Ecc) void {
        const size = self.size;
        for (0..size) |i| {
            self.setFunction(6, i, i % 2 == 0);
            self.setFunction(i, 6, i % 2 == 0);
        }
        self.drawFinder(3, 3);
        self.drawFinder(size - 4, 3);
        self.drawFinder(3, size - 4);

        var positions: [7]usize = undefined;
        const align_pos = alignmentPositions(self.version, &positions);
        const n = align_pos.len;
        for (0..n) |i| {
            for (0..n) |j| {
                const corner = (i == 0 and j == 0) or (i == 0 and j == n - 1) or (i == n - 1 and j == 0);
                if (!corner) self.drawAlignment(align_pos[i], align_pos[j]);
            }
        }
        // Reserved now, overwritten once the mask is known.
        self.drawFormatBits(ecc, 0);
        self.drawVersion();
    }

    fn drawFinder(self: *Matrix, cx: usize, cy: usize) void {
        var dy: i32 = -4;
        while (dy <= 4) : (dy += 1) {
            var dx: i32 = -4;
            while (dx <= 4) : (dx += 1) {
                const dist = @max(@abs(dx), @abs(dy));
                const x = @as(i32, @intCast(cx)) + dx;
                const y = @as(i32, @intCast(cy)) + dy;
                if (x < 0 or y < 0 or x >= self.size or y >= self.size) continue;
                self.setFunction(@intCast(x), @intCast(y), dist != 2 and dist != 4);
            }
        }
    }

    fn drawAlignment(self: *Matrix, cx: usize, cy: usize) void {
        var dy: i32 = -2;
        while (dy <= 2) : (dy += 1) {
            var dx: i32 = -2;
            while (dx <= 2) : (dx += 1) {
                const x: usize = @intCast(@as(i32, @intCast(cx)) + dx);
                const y: usize = @intCast(@as(i32, @intCast(cy)) + dy);
                self.setFunction(x, y, @max(@abs(dx), @abs(dy)) != 1);
            }
        }
    }

    fn drawFormatBits(self: *Matrix, ecc: Ecc, mask: u3) void {
        const data: u32 = (ecc.formatBits() << 3) | mask;
        var rem: u32 = data;
        for (0..10) |_| rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        const bits = ((data << 10) | rem) ^ 0x5412;
        const bit = struct {
            fn f(b: u32, i: usize) bool {
                return (b >> @intCast(i)) & 1 != 0;
            }
        }.f;
        const size = self.size;
        // Beside the top left finder.
        for (0..6) |i| self.setFunction(8, i, bit(bits, i));
        self.setFunction(8, 7, bit(bits, 6));
        self.setFunction(8, 8, bit(bits, 7));
        self.setFunction(7, 8, bit(bits, 8));
        for (9..15) |i| self.setFunction(14 - i, 8, bit(bits, i));
        // The copy split between the other two finders.
        for (0..8) |i| self.setFunction(size - 1 - i, 8, bit(bits, i));
        for (8..15) |i| self.setFunction(8, size - 15 + i, bit(bits, i));
        // Always dark.
        self.setFunction(8, size - 8, true);
    }

    fn drawVersion(self: *Matrix) void {
        if (self.version < 7) return;
        var rem: u32 = self.version;
        for (0..12) |_| rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        const bits = (@as(u32, self.version) << 12) | rem;
        for (0..18) |i| {
            const dark = (bits >> @intCast(i)) & 1 != 0;
            const a = self.size - 11 + i % 3;
            const b = i / 3;
            self.setFunction(a, b, dark);
            self.setFunction(b, a, dark);
        }
    }

    /// Places the codewords in the two-column zigzag, right to left.
    fn drawCodewords(self: *Matrix, data: []const u8) void {
        const size = self.size;
        var i: usize = 0;
        var right: isize = @intCast(size - 1);
        while (right >= 1) : (right -= 2) {
            if (right == 6) right = 5;
            const r: usize = @intCast(right);
            for (0..size) |vert| {
                for (0..2) |j| {
                    const x = r - j;
                    const upward = ((r + 1) & 2) == 0;
                    const y = if (upward) size - 1 - vert else vert;
                    if (self.is_function[y * size + x]) continue;
                    if (i < data.len * 8) {
                        self.modules[y * size + x] = (data[i >> 3] >> @intCast(7 - (i & 7))) & 1 != 0;
                        i += 1;
                    }
                    // Remainder bits stay light.
                }
            }
        }
    }

    fn applyMask(self: *Matrix, mask: u3) void {
        const size = self.size;
        for (0..size) |y| {
            for (0..size) |x| {
                const invert = switch (mask) {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    7 => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                const idx = y * size + x;
                if (invert and !self.is_function[idx]) self.modules[idx] = !self.modules[idx];
            }
        }
    }

    /// The standard's four penalty rules. Lower is easier to scan.
    fn penalty(self: *const Matrix) u64 {
        const size = self.size;
        var score: u64 = 0;

        // Rule 1: five or more of one color in a row or column.
        for (0..2) |dir| {
            for (0..size) |a| {
                var run: usize = 1;
                for (1..size) |b| {
                    const prev = if (dir == 0) self.at(b - 1, a) else self.at(a, b - 1);
                    const cur = if (dir == 0) self.at(b, a) else self.at(a, b);
                    if (cur == prev) {
                        run += 1;
                    } else {
                        if (run >= 5) score += 3 + (run - 5);
                        run = 1;
                    }
                }
                if (run >= 5) score += 3 + (run - 5);
            }
        }

        // Rule 2: two by two blocks of one color.
        for (0..size - 1) |y| {
            for (0..size - 1) |x| {
                const c = self.at(x, y);
                if (c == self.at(x + 1, y) and c == self.at(x, y + 1) and c == self.at(x + 1, y + 1)) score += 3;
            }
        }

        // Rule 3: a finder-like 1:1:3:1:1 run with four light modules on
        // either side.
        const pattern_a = [11]bool{ true, false, true, true, true, false, true, false, false, false, false };
        const pattern_b = [11]bool{ false, false, false, false, true, false, true, true, true, false, true };
        for (0..2) |dir| {
            for (0..size) |a| {
                if (size < 11) break;
                for (0..size - 10) |b| {
                    var match_a = true;
                    var match_b = true;
                    for (0..11) |k| {
                        const v = if (dir == 0) self.at(b + k, a) else self.at(a, b + k);
                        if (v != pattern_a[k]) match_a = false;
                        if (v != pattern_b[k]) match_b = false;
                    }
                    if (match_a) score += 40;
                    if (match_b) score += 40;
                }
            }
        }

        // Rule 4: how far the share of dark modules is from half.
        var dark: usize = 0;
        for (self.modules) |m| dark += @intFromBool(m);
        const total = size * size;
        const diff = if (dark * 20 > total * 10) dark * 20 - total * 10 else total * 10 - dark * 20;
        const k = (diff + total - 1) / total - 1;
        score += k * 10;
        return score;
    }
};

/// The centres of the alignment patterns on each axis, written into `buf`.
fn alignmentPositions(version: u8, buf: *[7]usize) []const usize {
    if (version == 1) return buf[0..0];
    const v: usize = version;
    const num_align = v / 7 + 2;
    const step = (v * 8 + num_align * 3 + 5) / (num_align * 4 - 4) * 2;
    buf[0] = 6;
    var pos = sizeOf(version) - 7;
    var i = num_align - 1;
    while (i >= 1) : (i -= 1) {
        buf[i] = pos;
        pos -= step;
    }
    return buf[0..num_align];
}

/// Draws `code` with Unicode half blocks, two module rows per text line, and
/// a four module quiet zone.
///
/// Light modules are drawn and dark ones left as the background, which is what
/// a terminal with a dark background needs to show dark modules on light. No
/// escape sequences, so it reads the same in a log or a console that does not
/// understand them.
pub fn render(code: *const Code, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const quiet = 4;
    const full = code.size + 2 * quiet;
    const light = struct {
        fn f(c: *const Code, x: usize, y: usize) bool {
            if (x < quiet or y < quiet) return true;
            if (x >= c.size + quiet or y >= c.size + quiet) return true;
            return !c.get(x - quiet, y - quiet);
        }
    }.f;
    var y: usize = 0;
    while (y < full) : (y += 2) {
        for (0..full) |x| {
            const top = light(code, x, y);
            const bottom = if (y + 1 < full) light(code, x, y + 1) else false;
            const glyph = if (top and bottom)
                "\u{2588}"
            else if (top)
                "\u{2580}"
            else if (bottom)
                "\u{2584}"
            else
                " ";
            try w.writeAll(glyph);
        }
        try w.writeByte('\n');
    }
}

const testing = std.testing;

test "Reed-Solomon matches the worked 1-M example" {
    // "HELLO WORLD" at 1-M in alphanumeric mode, the example most QR
    // tutorials walk through: these sixteen data codewords carry ten error
    // correction codewords that are known.
    const data = [_]u8{ 32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17 };
    var divisor: [10]u8 = undefined;
    rsDivisor(10, &divisor);
    var rem: [10]u8 = undefined;
    rsRemainder(&data, &divisor, &rem);
    try testing.expectEqualSlices(u8, &.{ 196, 35, 39, 119, 235, 215, 231, 226, 93, 23 }, &rem);
}

test "the block tables agree with the codeword totals" {
    // Every version's data and error correction codewords add up to its raw
    // codewords, for both levels, and the published totals hold where they
    // are easy to check.
    try testing.expectEqual(@as(usize, 26), rawDataModules(1) / 8);
    try testing.expectEqual(@as(usize, 242), rawDataModules(8) / 8);
    try testing.expectEqual(@as(usize, 3706), rawDataModules(40) / 8);
    try testing.expectEqual(@as(usize, 16), numDataCodewords(1, .medium));
    try testing.expectEqual(@as(usize, 2334), numDataCodewords(40, .medium));
    try testing.expectEqual(@as(usize, 2956), numDataCodewords(40, .low));
}

test "the smallest version that holds the data is picked" {
    // Byte mode capacities at level M: 14 bytes in version 1, 26 in 2, and
    // 2331 in 40, minus the mode and count overhead.
    try testing.expectEqual(@as(?u8, 1), pickVersion(14, .medium));
    try testing.expectEqual(@as(?u8, 2), pickVersion(15, .medium));
    try testing.expectEqual(@as(?u8, 40), pickVersion(2331, .medium));
    try testing.expectEqual(@as(?u8, null), pickVersion(2332, .medium));
}

test "alignment pattern centres follow the published table" {
    var buf: [7]usize = undefined;
    try testing.expectEqualSlices(usize, &.{ 6, 22, 38 }, alignmentPositions(7, &buf));
    try testing.expectEqualSlices(usize, &.{ 6, 26, 48, 70 }, alignmentPositions(15, &buf));
    try testing.expectEqualSlices(usize, &.{ 6, 34, 60, 86, 112, 138 }, alignmentPositions(32, &buf));
    try testing.expectEqualSlices(usize, &.{ 6, 30, 58, 86, 114, 142, 170 }, alignmentPositions(40, &buf));
}

test "format information is the published codeword for each level and mask" {
    // Level M with each mask, from the standard's table, read back from the
    // row beside the top left finder (most significant bit first).
    const expected = [8]u15{
        0b101010000010010, 0b101000100100101, 0b101111001111100, 0b101101101001011,
        0b100010111111001, 0b100000011001110, 0b100111110010111, 0b100101010100000,
    };
    for (expected, 0..) |want, mask| {
        var code = try encode(testing.allocator, "deed", .medium, @intCast(mask));
        defer code.deinit(testing.allocator);
        var got: u15 = 0;
        for ([_]usize{ 0, 1, 2, 3, 4, 5, 7, 8 }) |x| got = (got << 1) | @intFromBool(code.get(x, 8));
        for ([_]usize{ 7, 5, 4, 3, 2, 1, 0 }) |y| got = (got << 1) | @intFromBool(code.get(8, y));
        try testing.expectEqual(want, got);
    }
}

test "version information is the published codeword" {
    // Version 7's 18-bit version information, 000111110010010100, sits in a
    // 6 by 3 block above the bottom left finder, least significant bit first.
    var data: [110]u8 = undefined;
    @memset(&data, 'a');
    var code = try encode(testing.allocator, &data, .medium, null);
    defer code.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 7), code.version);
    var got: u18 = 0;
    var i: usize = 18;
    while (i > 0) {
        i -= 1;
        got = (got << 1) | @intFromBool(code.get(i / 3, code.size - 11 + i % 3));
    }
    try testing.expectEqual(@as(u18, 0b000111110010010100), got);
}

test "a bunker URI matches the code another encoder drew for it" {
    // Drawn by an independent encoder, at level L: version 6, mask 0. Every module has to
    // agree, so this covers the bit stream, the block split and interleave,
    // Reed-Solomon, placement, masking and the format information at once.
    const uri = "bunker://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798?relay=ws%3A%2F%2F127.0.0.1%3A18778&secret=sVgahVvchdOK";
    const expected = [_][]const u8{
        "11111110011010011111001100011001101111111",
        "10000010001111111111001101011111001000001",
        "10111010101010100000000010101001001011101",
        "10111010000011110011100110011001001011101",
        "10111010011001110001100110111101101011101",
        "10000010010101010001000101010101101000001",
        "11111110101010101010101010101010101111111",
        "00000000100001110101110101001111000000000",
        "11101111111101010110111101111100111000100",
        "10001100010000000110111000101100101100101",
        "10100010001011000110010001000110001100001",
        "10000101111111110110011011011101100000000",
        "10111111000100011000011001101000111000001",
        "10001000000101001110111001100101101000011",
        "10010110001001000110001001000000000011011",
        "00001000110101000101110101001100000011000",
        "11111110110001100100111001100100111101011",
        "11011001111000100100101001100100111101101",
        "10100110011001101100101010100100000101001",
        "00010100001101111100110101011100100010010",
        "10010110110010101100111101100110001000000",
        "01011100000111001100110001000100001001101",
        "01010011111111101000110001101110001111111",
        "11011101101011001100011101000111111001011",
        "10011111111101101100111001100100011001001",
        "10001100000000101100111000100100011100001",
        "01100011100011001100110001000000110101101",
        "11110001110000010110010111000110100010011",
        "10001111101000010100010011100110111001011",
        "00011101111100001100111110100110001001111",
        "10110111110000101110001000100110011000111",
        "01111001010101001110010001110100000101010",
        "10111110110011100100111011101100111111001",
        "00000000100011100100111011101100100011011",
        "11111110100000101010011000100111101010011",
        "10000010111111100111011001110101100011011",
        "10111010100010100101110001100000111111011",
        "10111010001111111100110001000101110110110",
        "10111010100110101000011000001111110011000",
        "10000010110011110111110111101100100110010",
        "11111110101101110110011011001101110001011",
    };
    var code = try encode(testing.allocator, uri, .low, 0);
    defer code.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 6), code.version);
    try testing.expectEqual(expected.len, code.size);
    for (expected, 0..) |row, y| {
        for (row, 0..) |c, x| try testing.expectEqual(c == '1', code.get(x, y));
    }
}

test "a URI at level M matches another encoder, mask choice included" {
    // Drawn by a second independent encoder at level M. Version 9 splits its
    // data into three short blocks and two long ones, so this covers the
    // uneven interleave that version 6 at level L never reaches. The mask is
    // left to the penalty rules, and they have to land on the same one.
    const uri = "bunker://deed.example/signer?relay=wss://relay.example.org&relay=wss://another.example.net&secret=abcdefghijklmnopqrstuvwxyz&name=a-signer-for-a-test-of-the-encoder";
    const expected = [_][]const u8{
        "11111110100101011101110101111110100011000010001111111",
        "10000010111000111010000110010110101100010011001000001",
        "10111010011001101111011110100101110110110001001011101",
        "10111010111011010101000000001111011110100110101011101",
        "10111010001101101110111011111001110001111010001011101",
        "10000010011001101010100010001111100101111110001000001",
        "11111110101010101010101010101010101010101010101111111",
        "00000000111101011000001110001011110110101011000000000",
        "10110111001001101100101111111101000100011110101001011",
        "00000100000100101011011111111111000001010111000110001",
        "00001110111001001111110111010010111010011110011001010",
        "10010100111011010111010100000111101010000001010010000",
        "01101111001001110011000001110000000011000111101011110",
        "00100101001111010100101001011011110100100001110101011",
        "01010010011010101011110110001001000101100110010101111",
        "11000100000001010100001011000110110000111001000001000",
        "00010011010000101110010011001011101100100100010000011",
        "01111001000010000011010001010101101100001100011011100",
        "11101010111001100010110001110000010111100000001101100",
        "00111100100000001100110001101001011011001101011111101",
        "01101111100000011111001001101100001101111111110101100",
        "00110001111100111101100101000110100111000110000011011",
        "10111010101001110011001001100111101010011011011110110",
        "01100000011100001110111000011101110010010100110010011",
        "11101111110011111010110111111011001111000010111110110",
        "11001000101110101101011110001101010101101001100011111",
        "01001010100011100101110010101111010100111011101010011",
        "11101000101101001110001010001010010001111110100011001",
        "10011111111110010010000111111011011001110100111110010",
        "00000101000010110010100110101101111010001100111001000",
        "11101110011011101010011000011001111111110000100101100",
        "10111000110111100011100111110100011011011111001010100",
        "10001011011101110110111101010100011101111101101010111",
        "10111001000111010101011101000011000111000010011111111",
        "10001111110011111000100110101001001000010110100011000",
        "00101101011000001111100011111110110011100000110010011",
        "01001010001101010110010001000001011111000110010101110",
        "01011000101011111101001010000001011101110001001001001",
        "10001010000100100011010010010011001110111010011111011",
        "10110001001111110100011111100100100000011111111011000",
        "00011111101111011010111101110100110001000100000110001",
        "10011000101101000000001110101100101100011101100100000",
        "11011111100001100110101001001001011010100100010111000",
        "01100000101111011110010110110011000110011111101011111",
        "00010010110110100101011011111100000101011001111110110",
        "00000000100110001000111010001111100101000110100011101",
        "11111110100001010010100110101111001010010111101010010",
        "10000010110000101101111110001010011011010101100010011",
        "10111010010010111000010111111110000010000111111110101",
        "10111010111010001000110111110001110111110000000110001",
        "10111010101000110100011111111011000011110010001101100",
        "10000010000010010011100000010101100001111101100010010",
        "11111110110000101010011100011110110000010111011000010",
    };
    var code = try encode(testing.allocator, uri, .medium, null);
    defer code.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 9), code.version);
    try testing.expectEqual(@as(u3, 3), code.mask);
    try testing.expectEqual(expected.len, code.size);
    for (expected, 0..) |row, y| {
        for (row, 0..) |c, x| try testing.expectEqual(c == '1', code.get(x, y));
    }
}

test "a URI too long for any version is refused" {
    const big = try testing.allocator.alloc(u8, 3000);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    try testing.expectError(Error.DataTooLong, encode(testing.allocator, big, .medium, null));
}

test "rendering draws two module rows per line inside a quiet zone" {
    var code = try encode(testing.allocator, "bunker://x", .medium, null);
    defer code.deinit(testing.allocator);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try render(&code, &aw.writer);
    const text = aw.written();
    const full = code.size + 8;
    try testing.expectEqual((full + 1) / 2, std.mem.count(u8, text, "\n"));
    // The first line is all quiet zone, so all light.
    const first = text[0..std.mem.indexOfScalar(u8, text, '\n').?];
    try testing.expectEqual(full, std.mem.count(u8, first, "\u{2588}"));
}
