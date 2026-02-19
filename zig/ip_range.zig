const std = @import("std");

const LANES: u32 = 8;
const LaneVec = @Vector(LANES, u32);
const lane_offsets: LaneVec = .{ 0, 1, 2, 3, 4, 5, 6, 7 };

inline fn cidrMask(prefix_len: u8) u32 {
    if (prefix_len == 0) return 0;
    if (prefix_len >= 32) return 0xFFFF_FFFF;
    const shift: u5 = @intCast(32 - prefix_len);
    return @as(u32, 0xFFFF_FFFF) << shift;
}

inline fn cidrTotal(prefix_len: u8) u64 {
    if (prefix_len >= 32) return 1;
    const shift: u6 = @intCast(32 - prefix_len);
    return @as(u64, 1) << shift;
}

inline fn loadVec8(ptr: [*]const u32, count: u32) LaneVec {
    var tmp: [LANES]u32 = [_]u32{0} ** LANES;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        tmp[i] = ptr[i];
    }
    return @bitCast(tmp);
}

inline fn storeVec8(ptr: [*]u32, vec: LaneVec, count: u32) void {
    const tmp: [LANES]u32 = @bitCast(vec);
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        ptr[i] = tmp[i];
    }
}

// Expand a CIDR range (e.g., 192.168.1.0/24) into individual IPs.
// Writes up to max_ips IPs into out_ips buffer. Returns number of IPs written.
export fn ip_range_expand_cidr(base_ip: u32, prefix_len: u8, out_ips: [*]u32, max_ips: u32) callconv(.c) u32 {
    if (prefix_len > 32) return 0;

    const mask = cidrMask(prefix_len);
    const net_base = base_ip & mask;
    const total = cidrTotal(prefix_len);
    const to_write_u64 = @min(total, @as(u64, max_ips));
    const to_write: u32 = @intCast(to_write_u64);

    var produced: u32 = 0;
    while (produced + LANES <= to_write) : (produced += LANES) {
        const base_vec = @as(LaneVec, @splat(net_base +% produced));
        const ip_vec = base_vec + lane_offsets;
        storeVec8(out_ips + produced, ip_vec, LANES);
    }

    if (produced < to_write) {
        const rem = to_write - produced;
        const base_vec = @as(LaneVec, @splat(net_base +% produced));
        const ip_vec = base_vec + lane_offsets;
        storeVec8(out_ips + produced, ip_vec, rem);
    }

    return to_write;
}

// Expand a CIDR range and call a callback for each batch of 8 IPs.
// This avoids needing a huge output buffer for /8 ranges.
export fn ip_range_iterate_cidr(
    base_ip: u32,
    prefix_len: u8,
    ctx: ?*anyopaque,
    callback: *const fn (?*anyopaque, [*]const u32, u32) callconv(.c) void,
) callconv(.c) u32 {
    if (prefix_len > 32) return 0;

    const mask = cidrMask(prefix_len);
    const net_base = base_ip & mask;
    const total = cidrTotal(prefix_len);

    var processed: u64 = 0;
    var batch: [LANES]u32 = undefined;

    while (processed < total) {
        const remaining = total - processed;
        const take_u64 = @min(@as(u64, LANES), remaining);
        const take: u32 = @intCast(take_u64);
        const offset: u32 = @intCast(processed);

        const base_vec = @as(LaneVec, @splat(net_base +% offset));
        const ip_vec = base_vec + lane_offsets;
        storeVec8(&batch, ip_vec, take);

        callback(ctx, &batch, take);
        processed += take;
    }

    return if (processed > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(processed);
}

// Check if an IP falls within a CIDR range. Uses branchless comparison.
export fn ip_range_contains(base_ip: u32, prefix_len: u8, test_ip: u32) callconv(.c) bool {
    if (prefix_len > 32) return false;

    const mask = cidrMask(prefix_len);
    return ((base_ip ^ test_ip) & mask) == 0;
}

// Batch check: test N IPs against a single CIDR. Returns bitmask of matches.
export fn ip_range_contains_batch(base_ip: u32, prefix_len: u8, test_ips: [*]const u32, count: u32) callconv(.c) u64 {
    if (prefix_len > 32) return 0;

    const limit: u32 = @min(count, 64);
    const mask = cidrMask(prefix_len);
    const net_masked = base_ip & mask;
    const mask_vec = @as(LaneVec, @splat(mask));
    const net_vec = @as(LaneVec, @splat(net_masked));

    var bits: u64 = 0;
    var idx: u32 = 0;

    while (idx < limit) : (idx += LANES) {
        const remain = limit - idx;
        const take: u32 = @min(remain, LANES);

        const ip_vec = loadVec8(test_ips + idx, take);
        const masked_vec = ip_vec & mask_vec;
        const cmp_vec: @Vector(LANES, bool) = masked_vec == net_vec;

        var lane: u32 = 0;
        while (lane < take) : (lane += 1) {
            if (cmp_vec[lane]) {
                bits |= (@as(u64, 1) << @intCast(idx + lane));
            }
        }
    }

    return bits;
}
