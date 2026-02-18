// SIMD-accelerated IP checksum — replaces libdnet's ip_cksum_add()
//
// Uses Zig's @Vector type for auto-vectorization to SSE2/AVX2.
// Falls back to scalar 64-bit accumulation on non-x86 platforms.
//
// ABI: exactly matches `int ip_cksum_add(const void *buf, size_t len, int cksum)`

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

/// Number of u16 elements per SIMD vector (256-bit / 16-bit = 16 lanes)
const simd_lanes = 16;
const SimdVec = @Vector(simd_lanes, u16);
/// Accumulator uses u32 to avoid overflow within a SIMD block
const AccVec = @Vector(simd_lanes, u32);

inline fn simdSum(data: SimdVec) u32 {
    // Widen to u32, then reduce
    const wide: AccVec = @as(AccVec, data);
    return @reduce(.Add, wide);
}

export fn ip_cksum_add(buf: [*]const u8, len: usize, cksum: c_int) callconv(.c) c_int {
    const is_x86 = comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86);

    if (is_x86) {
        return simdChecksumAdd(buf, len, cksum);
    } else {
        return scalarChecksumAdd(buf, len, cksum);
    }
}

/// SIMD path: process 32 bytes (16 x u16) per iteration using @Vector.
inline fn simdChecksumAdd(buf: [*]const u8, len: usize, cksum: c_int) c_int {
    var sum: u64 = @intCast(@as(u32, @bitCast(cksum)));
    var offset: usize = 0;
    const bytes_per_simd = simd_lanes * 2; // 32 bytes

    // SIMD loop: 32 bytes at a time
    while (offset + bytes_per_simd <= len) {
        const chunk: *const [bytes_per_simd]u8 = @ptrCast(buf + offset);
        const vec: SimdVec = @bitCast(chunk.*);
        sum += simdSum(vec);
        offset += bytes_per_simd;
    }

    // Scalar tail: remaining u16 words
    const sp: [*]const u16 = @ptrCast(@alignCast(buf));
    const total_words = len / 2;
    var word_offset = offset / 2;
    while (word_offset < total_words) {
        sum += sp[word_offset];
        word_offset += 1;
    }

    // Odd trailing byte
    if (len & 1 != 0) {
        const last_byte: u16 = @as(u16, buf[len - 1]) << 8;
        sum += std.mem.nativeToBig(u16, last_byte);
    }

    // Fold 64-bit sum to 32-bit (matching original int return type)
    sum = (sum >> 32) + (sum & 0xFFFFFFFF);
    sum = (sum >> 32) + (sum & 0xFFFFFFFF);

    return @bitCast(@as(u32, @truncate(sum)));
}

/// Scalar fallback: 64-bit accumulation, unrolled 8x.
inline fn scalarChecksumAdd(buf: [*]const u8, len: usize, cksum: c_int) c_int {
    var sum: u64 = @intCast(@as(u32, @bitCast(cksum)));
    const sp: [*]const u16 = @ptrCast(@alignCast(buf));
    const words = len / 2;

    var i: usize = 0;
    // Unrolled loop: 8 words at a time
    const unroll = 8;
    const bulk = words - (words % unroll);
    while (i < bulk) {
        comptime var j: usize = 0;
        inline while (j < unroll) : (j += 1) {
            sum += sp[i + j];
        }
        i += unroll;
    }
    // Remainder
    while (i < words) : (i += 1) {
        sum += sp[i];
    }

    if (len & 1 != 0) {
        const last_byte: u16 = @as(u16, buf[len - 1]) << 8;
        sum += std.mem.nativeToBig(u16, last_byte);
    }

    // Fold to 32-bit
    sum = (sum >> 32) + (sum & 0xFFFFFFFF);
    sum = (sum >> 32) + (sum & 0xFFFFFFFF);

    return @bitCast(@as(u32, @truncate(sum)));
}
