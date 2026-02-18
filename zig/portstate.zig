// Compact bitset-based port state tracker.
// 65536 ports × 3 bits = 24576 bytes (~24KB, fits L1 cache).
//
// Port states: 0=unknown, 1=open, 2=closed, 3=filtered,
//              4=unfiltered, 5=open|filtered, 6=closed|filtered
//
// C ABI exports:
//   portstate_create()          — allocate and zero-initialize
//   portstate_set(h, port, st)  — set state for port
//   portstate_get(h, port)      — get state for port
//   portstate_count(h, st)      — count ports in given state
//   portstate_destroy(h)        — free

const std = @import("std");

const BITSET_SIZE: usize = 24576; // ceil(65536 * 3 / 8)

const PortState = struct {
    bits: *[BITSET_SIZE]u8,
};

export fn portstate_create() callconv(.c) ?*anyopaque {
    const allocator = std.heap.c_allocator;
    const ps = allocator.create(PortState) catch return null;
    const bits = allocator.create([BITSET_SIZE]u8) catch {
        allocator.destroy(ps);
        return null;
    };
    @memset(bits, 0);
    ps.* = PortState{ .bits = bits };
    return @ptrCast(ps);
}

export fn portstate_set(handle: ?*anyopaque, port: u16, state: u8) callconv(.c) void {
    const ps: *PortState = @ptrCast(@alignCast(handle orelse return));
    const buf = ps.bits;
    const bit_pos: usize = @as(usize, port) * 3;
    const byte_idx = bit_pos / 8;
    const bit_off: u3 = @intCast(bit_pos % 8);
    const val: u8 = state & 0x07;

    if (bit_off <= 5) {
        // All 3 bits fit in one byte
        const mask: u8 = @as(u8, 0x07) << bit_off;
        buf[byte_idx] = (buf[byte_idx] & ~mask) | (val << bit_off);
    } else {
        // Bits span two bytes — use u16 for the operation
        const wide_off: u4 = @intCast(bit_pos % 8);
        var word: u16 = @as(u16, buf[byte_idx]) | (@as(u16, buf[byte_idx + 1]) << 8);
        const wmask: u16 = @as(u16, 0x07) << wide_off;
        word = (word & ~wmask) | (@as(u16, val) << wide_off);
        buf[byte_idx] = @truncate(word);
        buf[byte_idx + 1] = @truncate(word >> 8);
    }
}

export fn portstate_get(handle: ?*anyopaque, port: u16) callconv(.c) u8 {
    const ps: *PortState = @ptrCast(@alignCast(handle orelse return 0));
    const buf = ps.bits;
    const bit_pos: usize = @as(usize, port) * 3;
    const byte_idx = bit_pos / 8;
    const bit_off: u3 = @intCast(bit_pos % 8);

    if (bit_off <= 5) {
        return (buf[byte_idx] >> bit_off) & 0x07;
    } else {
        const low_bits: u3 = @intCast(8 - @as(u4, bit_off));
        const low: u8 = buf[byte_idx] >> bit_off;
        const high: u8 = buf[byte_idx + 1] << @intCast(low_bits);
        return (low | high) & 0x07;
    }
}

export fn portstate_count(handle: ?*anyopaque, state: u8) callconv(.c) u32 {
    const ps: *PortState = @ptrCast(@alignCast(handle orelse return 0));
    const buf = ps.bits;
    const target = state & 0x07;
    var count: u32 = 0;

    for (0..65536) |port| {
        const bit_pos: usize = port * 3;
        const byte_idx = bit_pos / 8;
        const bit_off: u3 = @intCast(bit_pos % 8);

        const val: u8 = if (bit_off <= 5)
            (buf[byte_idx] >> bit_off) & 0x07
        else blk: {
            const low: u8 = buf[byte_idx] >> bit_off;
            const high: u8 = buf[byte_idx + 1] << @intCast(8 - @as(u4, bit_off));
            break :blk (low | high) & 0x07;
        };

        if (val == target) count += 1;
    }
    return count;
}

export fn portstate_destroy(handle: ?*anyopaque) callconv(.c) void {
    const ps: *PortState = @ptrCast(@alignCast(handle orelse return));
    const allocator = std.heap.c_allocator;
    allocator.destroy(ps.bits);
    allocator.destroy(ps);
}
