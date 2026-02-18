// SIMD-accelerated IP checksum — Phase 1 placeholder
// This file will be replaced with the full SIMD implementation in Phase 1.
// For now, it verifies the Zig toolchain produces a linkable .o file.

const std = @import("std");

/// C-ABI compatible ip_cksum_add replacement.
/// Computes a partial internet checksum over `len` bytes of `buf`,
/// adding to an existing partial `cksum`.
export fn ip_cksum_add(buf: [*]const u8, len: usize, cksum: c_int) callconv(.c) c_int {
    var sum: u32 = @intCast(@as(u32, @bitCast(cksum)));
    const sp: [*]const u16 = @ptrCast(@alignCast(buf));
    const words = len / 2;

    var i: usize = 0;
    while (i < words) : (i += 1) {
        sum += sp[i];
    }

    if (len & 1 != 0) {
        // Odd byte: match the C version's htons(*(u_char *)sp << 8)
        const last_byte: u16 = @as(u16, buf[len - 1]) << 8;
        sum += std.mem.nativeToBig(u16, last_byte);
    }

    return @bitCast(@as(u32, sum));
}
