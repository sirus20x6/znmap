const std = @import("std");

const PREFIX_VEC_LANES = 9;
const SCAN_LANES = 16;

const PrefixVec = @Vector(PREFIX_VEC_LANES, u32);
const ScanVec = @Vector(SCAN_LANES, u8);

const BannerPrefix = struct {
    id: i32,
    prefix: []const u8,
    prefix4: u32,
};

inline fn pack4(bytes: []const u8) u32 {
    var v: u32 = 0;
    var i: usize = 0;
    const n = if (bytes.len < 4) bytes.len else 4;
    while (i < n) : (i += 1) {
        v |= @as(u32, bytes[i]) << @intCast(i * 8);
    }
    return v;
}

const banner_table = [_]BannerPrefix{
    .{ .id = 0, .prefix = "SSH-", .prefix4 = pack4("SSH-") },
    .{ .id = 1, .prefix = "HTTP/", .prefix4 = pack4("HTTP/") },
    .{ .id = 2, .prefix = "220 ", .prefix4 = pack4("220 ") },
    .{ .id = 3, .prefix = "* OK ", .prefix4 = pack4("* OK ") },
    .{ .id = 4, .prefix = "+OK ", .prefix4 = pack4("+OK ") },
    .{ .id = 5, .prefix = "RFB ", .prefix4 = pack4("RFB ") },
    .{ .id = 6, .prefix = "\x16\x03", .prefix4 = pack4("\x16\x03") },
    .{ .id = 7, .prefix = "<?xml", .prefix4 = pack4("<?xml") },
    .{ .id = 8, .prefix = "\x00\x00\x00", .prefix4 = pack4("\x00\x00\x00") },
};

const banner_prefix4_vec: PrefixVec = blk: {
    var tmp: [PREFIX_VEC_LANES]u32 = undefined;
    for (banner_table, 0..) |entry, i| {
        tmp[i] = entry.prefix4;
    }
    break :blk tmp;
};

fn verifyAt(haystack: []const u8, needle: []const u8, at: usize) bool {
    if (at + needle.len > haystack.len) return false;
    return std.mem.eql(u8, haystack[at .. at + needle.len], needle);
}

// Check if buffer starts with any known service banner prefix.
// Returns the banner_id (index into built-in table) or -1 if no match.
// This is a fast pre-filter — if it returns >= 0, the caller can skip regex.
export fn banner_match_prefix(buf: [*]const u8, len: u32) callconv(.c) i32 {
    if (len == 0) return -1;

    const buf_len = @as(usize, len);
    const slice = buf[0..buf_len];
    const key = pack4(slice);

    const key_vec: PrefixVec = @splat(key);
    const eq_mask = banner_prefix4_vec == key_vec;

    inline for (banner_table, 0..) |entry, i| {
        if (eq_mask[i] and slice.len >= entry.prefix.len and std.mem.eql(u8, slice[0..entry.prefix.len], entry.prefix)) {
            return entry.id;
        }
    }

    return -1;
}

// Search for a short pattern (up to 16 bytes) anywhere in a buffer using SIMD.
// Returns offset of first match, or -1 if not found.
export fn banner_search(
    haystack: [*]const u8,
    haystack_len: u32,
    needle: [*]const u8,
    needle_len: u32,
) callconv(.c) i32 {
    const h_len = @as(usize, haystack_len);
    const n_len = @as(usize, needle_len);
    if (n_len == 0 or n_len > 16 or n_len > h_len) return -1;

    const h = haystack[0..h_len];
    const n = needle[0..n_len];

    const first = n[0];
    const first_vec: ScanVec = @splat(first);

    var i: usize = 0;
    while (i + SCAN_LANES <= h_len) : (i += SCAN_LANES) {
        const chunk: ScanVec = h[i..][0..SCAN_LANES].*;
        const mask = chunk == first_vec;
        if (@reduce(.Or, mask)) {
            inline for (0..SCAN_LANES) |lane| {
                const at = i + lane;
                if (mask[lane] and verifyAt(h, n, at)) {
                    return @intCast(at);
                }
            }
        }
    }

    const last_start = h_len - n_len;
    var j: usize = i;
    if (j > last_start) j = last_start;
    while (j <= last_start) : (j += 1) {
        if (h[j] == first and verifyAt(h, n, j)) return @intCast(j);
    }

    return -1;
}

// Batch prefix match: check N buffers against the banner table.
// Writes results into out_ids array. Returns count of matches (non-negative results).
export fn banner_match_batch(
    bufs: [*]const [*]const u8,
    lens: [*]const u32,
    count: u32,
    out_ids: [*]i32,
) callconv(.c) u32 {
    var matches: u32 = 0;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const id = banner_match_prefix(bufs[i], lens[i]);
        out_ids[i] = id;
        if (id >= 0) matches += 1;
    }
    return matches;
}
