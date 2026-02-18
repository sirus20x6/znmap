// Service probe pre-filter — skips PCRE2 calls for obviously non-matching patterns.
//
// Extracts literal byte prefixes from regex patterns at load time.
// Before invoking pcre2_match(), the caller checks if the response buffer
// contains the literal prefix. Only patterns whose literals appear in
// the response are sent to PCRE2.
//
// C ABI exports:
//   probe_filter_init()  — create a filter context
//   probe_filter_add()   — register a pattern with an index
//   probe_filter_check() — check if a buffer might match pattern at index
//   probe_filter_free()  — destroy the filter context

const std = @import("std");

const MAX_PREFIX_LEN = 32;
const MAX_PATTERNS = 16384;

const PatternInfo = struct {
    prefix: [MAX_PREFIX_LEN]u8 = undefined,
    prefix_len: u16 = 0,
    case_insensitive: bool = false,
    anchored: bool = false, // pattern starts with ^
};

const FilterContext = struct {
    patterns: [MAX_PATTERNS]PatternInfo = undefined,
    count: u32 = 0,
};

/// Extract literal prefix from a regex pattern string.
/// Returns the number of bytes extracted (0 if no useful literal prefix).
fn extractLiteralPrefix(regex: [*]const u8, regex_len: usize, out: *[MAX_PREFIX_LEN]u8, anchored: *bool) u16 {
    var i: usize = 0;
    var out_len: u16 = 0;
    anchored.* = false;

    if (regex_len == 0) return 0;

    // Skip leading ^
    if (regex[0] == '^') {
        anchored.* = true;
        i = 1;
    }

    while (i < regex_len and out_len < MAX_PREFIX_LEN) {
        const c = regex[i];

        // Stop at regex metacharacters
        switch (c) {
            '.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '$' => break,
            '\\' => {
                // Handle common escapes
                if (i + 1 >= regex_len) break;
                const next = regex[i + 1];
                switch (next) {
                    // Character class escapes — not a literal
                    'd', 'D', 'w', 'W', 's', 'S', 'b', 'B' => break,
                    // Literal escapes
                    'n' => {
                        out[out_len] = '\n';
                        out_len += 1;
                        i += 2;
                    },
                    'r' => {
                        out[out_len] = '\r';
                        out_len += 1;
                        i += 2;
                    },
                    't' => {
                        out[out_len] = '\t';
                        out_len += 1;
                        i += 2;
                    },
                    'x' => {
                        // \xNN hex escape
                        if (i + 3 < regex_len) {
                            const h1 = hexVal(regex[i + 2]);
                            const h2 = hexVal(regex[i + 3]);
                            if (h1 != null and h2 != null) {
                                out[out_len] = (@as(u8, h1.?) << 4) | @as(u8, h2.?);
                                out_len += 1;
                                i += 4;
                            } else break;
                        } else break;
                    },
                    else => {
                        // Escaped literal (e.g., \., \\, \/)
                        out[out_len] = next;
                        out_len += 1;
                        i += 2;
                    },
                }
            },
            else => {
                out[out_len] = c;
                out_len += 1;
                i += 1;
            },
        }
    }

    return out_len;
}

fn hexVal(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @truncate(c - '0');
    if (c >= 'a' and c <= 'f') return @truncate(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @truncate(c - 'A' + 10);
    return null;
}

/// Case-insensitive byte comparison.
inline fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c | 0x20 else c;
}

/// Search for prefix in buffer (case-sensitive or case-insensitive).
/// If anchored, only checks the start of the buffer.
fn bufferContainsPrefix(buf: [*]const u8, buf_len: usize, info: *const PatternInfo) bool {
    const plen = info.prefix_len;
    if (plen == 0) return true; // No prefix to filter on — must run PCRE2
    if (buf_len < plen) return false;

    if (info.anchored) {
        // Only check start of buffer
        if (info.case_insensitive) {
            for (0..plen) |j| {
                if (toLower(buf[j]) != toLower(info.prefix[j])) return false;
            }
        } else {
            for (0..plen) |j| {
                if (buf[j] != info.prefix[j]) return false;
            }
        }
        return true;
    }

    // Unanchored: scan for prefix anywhere in buffer
    const limit = buf_len - plen + 1;
    if (info.case_insensitive) {
        for (0..limit) |i| {
            var matched = true;
            for (0..plen) |j| {
                if (toLower(buf[i + j]) != toLower(info.prefix[j])) {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
    } else {
        // Use memchr for the first byte as a fast scan
        var pos: usize = 0;
        while (pos < limit) {
            if (buf[pos] == info.prefix[0]) {
                var matched = true;
                for (1..plen) |j| {
                    if (buf[pos + j] != info.prefix[j]) {
                        matched = false;
                        break;
                    }
                }
                if (matched) return true;
            }
            pos += 1;
        }
    }
    return false;
}

// ===================== C ABI Exports =====================

/// Create a new filter context. Returns opaque pointer.
export fn probe_filter_init() callconv(.c) ?*anyopaque {
    const allocator = std.heap.c_allocator;
    const ctx = allocator.create(FilterContext) catch return null;
    ctx.* = FilterContext{};
    return @ptrCast(ctx);
}

/// Register a regex pattern at the given index.
/// `regex` is the regex string, `regex_len` is its length.
/// `case_insensitive` mirrors the 'i' flag from nmap-service-probes.
/// Returns 0 on success, -1 on error.
export fn probe_filter_add(
    handle: ?*anyopaque,
    index: c_uint,
    regex: [*]const u8,
    regex_len: usize,
    case_insensitive: c_int,
) callconv(.c) c_int {
    const ctx: *FilterContext = @ptrCast(@alignCast(handle orelse return -1));
    if (index >= MAX_PATTERNS) return -1;

    var info = &ctx.patterns[index];
    info.case_insensitive = (case_insensitive != 0);
    info.prefix_len = extractLiteralPrefix(regex, regex_len, &info.prefix, &info.anchored);

    if (index >= ctx.count) {
        ctx.count = index + 1;
    }
    return 0;
}

/// Check if the buffer might match the pattern at `index`.
/// Returns 1 if the buffer should be tested with PCRE2, 0 if it can be skipped.
export fn probe_filter_check(
    handle: ?*anyopaque,
    index: c_uint,
    buf: [*]const u8,
    buf_len: usize,
) callconv(.c) c_int {
    const ctx: *FilterContext = @ptrCast(@alignCast(handle orelse return 1));
    if (index >= ctx.count) return 1; // Unknown pattern — be safe, don't skip

    const info = &ctx.patterns[index];
    return if (bufferContainsPrefix(buf, buf_len, info)) 1 else 0;
}

/// Destroy the filter context and free memory.
export fn probe_filter_free(handle: ?*anyopaque) callconv(.c) void {
    const ctx: *FilterContext = @ptrCast(@alignCast(handle orelse return));
    const allocator = std.heap.c_allocator;
    allocator.destroy(ctx);
}
