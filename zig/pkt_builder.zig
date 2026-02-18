// pkt_builder.zig — High-performance raw packet construction with inline checksums
//
// Builds complete IP/TCP, IP/UDP, and IP/ICMP packets in a single pass,
// computing IP header and transport-layer pseudo-header checksums with the same
// SIMD @Vector approach used in checksum.zig — no separate checksum pass.
//
// ABI: C-compatible exports callable from tcpip.cc once integration is wired.
//
// Memory model: caller supplies an output buffer (out_buf/out_len).  The
// functions return the number of bytes written, or -1 on error (buffer too
// small).  No heap allocation occurs inside these functions.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

// ---------------------------------------------------------------------------
// SIMD checksum primitives (mirrors checksum.zig, inlined here to avoid
// cross-compilation unit dependencies when used as a standalone .o)
// ---------------------------------------------------------------------------

const simd_lanes = 16; // 16 × u16 = 256-bit vectors (AVX2 / 2×SSE2 lanes)
const SimdVec = @Vector(simd_lanes, u16);
const AccVec = @Vector(simd_lanes, u32);

/// Widen a u16 SIMD vector to u32 and horizontally reduce.
inline fn simdSum(v: SimdVec) u32 {
    const wide: AccVec = v;
    return @reduce(.Add, wide);
}

/// RFC 1071 ones'-complement sum over arbitrary byte slice.
/// Returns the raw 32-bit accumulated sum (NOT yet folded/complemented).
/// Caller must fold and complement before storing into a checksum field.
fn checksumAccumulate(data: []const u8) u64 {
    const is_x86 = comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86);
    var sum: u64 = 0;
    var offset: usize = 0;
    const len = data.len;

    if (is_x86) {
        // SIMD path: 32 bytes (16 × u16) per iteration
        const bytes_per_iter = simd_lanes * 2;
        while (offset + bytes_per_iter <= len) {
            const chunk: *const [bytes_per_iter]u8 = @ptrCast(data[offset..][0..bytes_per_iter]);
            const vec: SimdVec = @bitCast(chunk.*);
            sum += simdSum(vec);
            offset += bytes_per_iter;
        }
    }

    // Scalar tail (or full scalar path on non-x86)
    const words = (len - offset) / 2;
    const word_ptr: [*]const u16 = @ptrCast(@alignCast(data[offset..].ptr));
    var wi: usize = 0;
    while (wi < words) : (wi += 1) {
        sum += word_ptr[wi];
    }
    offset += words * 2;

    // Odd trailing byte — placed in the high byte of the final u16 (network order)
    if (offset < len) {
        const last: u16 = @as(u16, data[offset]) << 8;
        sum += last;
    }

    return sum;
}

/// Fold a 64-bit accumulated sum to 16-bit ones'-complement checksum.
inline fn checksumFold(sum64: u64) u16 {
    var s = sum64;
    s = (s >> 32) + (s & 0xFFFF_FFFF);
    s = (s >> 16) + (s & 0xFFFF);
    s = (s >> 16) + (s & 0xFFFF);
    return @truncate(s);
}

/// Complete RFC 1071 checksum: accumulate, fold, ones'-complement.
inline fn checksum(data: []const u8) u16 {
    return ~checksumFold(checksumAccumulate(data));
}

// ---------------------------------------------------------------------------
// Packet structure constants (network byte order, packed)
// ---------------------------------------------------------------------------

// IP header (no options) — 20 bytes
// Offsets within the 20-byte IPv4 header:
//   0:  version+IHL (1B)
//   1:  TOS         (1B)
//   2:  total len   (2B, BE)
//   4:  ID          (2B, BE)
//   6:  flags+frag  (2B, BE)
//   8:  TTL         (1B)
//   9:  protocol    (1B)
//  10:  checksum    (2B)
//  12:  src addr    (4B)
//  16:  dst addr    (4B)

const IP_HDR_LEN: u16 = 20;
const TCP_HDR_LEN: u16 = 20;
const UDP_HDR_LEN: u16 = 8;
const ICMP_HDR_MIN: u16 = 8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

// Default values matching nmap's existing behaviour
const DEFAULT_TTL: u8 = 64;
const DEFAULT_TOS: u8 = 0x00;
const DEFAULT_WINDOW: u16 = 1024;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write a big-endian u16 into buf[offset..offset+2].
inline fn writeU16Be(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @truncate(val >> 8);
    buf[offset + 1] = @truncate(val);
}

/// Write a big-endian u32 into buf[offset..offset+4].
inline fn writeU32Be(buf: []u8, offset: usize, val: u32) void {
    buf[offset] = @truncate(val >> 24);
    buf[offset + 1] = @truncate(val >> 16);
    buf[offset + 2] = @truncate(val >> 8);
    buf[offset + 3] = @truncate(val);
}

/// Fill the 20-byte IPv4 header at buf[0..20] and compute its checksum.
/// Returns the computed header checksum (already stored in buf[10..12]).
fn writeIpHeader(
    buf: []u8, // must be >= 20 bytes
    total_len: u16, // IP total length (header + payload)
    proto: u8,
    ttl: u8,
    tos: u8,
    ip_id: u16,
    src_ip: u32, // already in network byte order
    dst_ip: u32, // already in network byte order
) void {
    // version=4, IHL=5 (no options)
    buf[0] = 0x45;
    buf[1] = tos;
    writeU16Be(buf, 2, total_len);
    writeU16Be(buf, 4, ip_id);
    writeU16Be(buf, 6, 0); // flags=0, frag offset=0
    buf[8] = ttl;
    buf[9] = proto;
    writeU16Be(buf, 10, 0); // checksum placeholder
    // src/dst already big-endian (from in_addr.s_addr)
    buf[12] = @truncate(src_ip);
    buf[13] = @truncate(src_ip >> 8);
    buf[14] = @truncate(src_ip >> 16);
    buf[15] = @truncate(src_ip >> 24);
    buf[16] = @truncate(dst_ip);
    buf[17] = @truncate(dst_ip >> 8);
    buf[18] = @truncate(dst_ip >> 16);
    buf[19] = @truncate(dst_ip >> 24);

    // IP header checksum over the 20 bytes (checksum field is 0 during computation)
    const ck = checksum(buf[0..IP_HDR_LEN]);
    writeU16Be(buf, 10, ck);
}

/// Compute the IPv4 pseudo-header checksum contribution.
/// Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + transport_len(2) = 12 bytes.
/// Returns the 64-bit running sum (not yet folded) to be combined with the
/// transport header + payload sum.
fn pseudoHeaderSum(src_ip: u32, dst_ip: u32, proto: u8, transport_len: u16) u64 {
    // Lay the 12-byte pseudo-header into a small stack buffer and accumulate.
    var ph: [12]u8 = undefined;
    // src addr (network byte order, stored as-is from in_addr.s_addr which is BE)
    ph[0] = @truncate(src_ip);
    ph[1] = @truncate(src_ip >> 8);
    ph[2] = @truncate(src_ip >> 16);
    ph[3] = @truncate(src_ip >> 24);
    // dst addr
    ph[4] = @truncate(dst_ip);
    ph[5] = @truncate(dst_ip >> 8);
    ph[6] = @truncate(dst_ip >> 16);
    ph[7] = @truncate(dst_ip >> 24);
    ph[8] = 0; // zero
    ph[9] = proto;
    ph[10] = @truncate(transport_len >> 8);
    ph[11] = @truncate(transport_len);
    return checksumAccumulate(&ph);
}

/// Fold a 64-bit sum and return ones'-complement (RFC 1071 final step).
inline fn finalizeChecksum(sum64: u64) u16 {
    return ~checksumFold(sum64);
}

// ---------------------------------------------------------------------------
// Exported C ABI functions
// ---------------------------------------------------------------------------

/// Build a complete IP + TCP packet into out_buf.
///
/// Parameters:
///   dst_ip, src_ip   — IPv4 addresses as u32 in *network* byte order
///                      (i.e., the raw in_addr.s_addr value).
///   sport, dport     — source/destination port in host byte order.
///   seq, ack         — TCP sequence/acknowledgment in host byte order.
///   flags            — TCP flags byte (TH_SYN etc.).
///   window           — TCP window in host byte order (0 → 1024).
///   payload, payload_len — application data (may be NULL/0).
///   out_buf          — caller-supplied output buffer.
///   out_len          — size of out_buf in bytes.
///
/// Returns total packet length on success, -1 if out_buf is too small.
export fn pkt_build_tcp(
    dst_ip: u32,
    src_ip: u32,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: ?[*]const u8,
    payload_len: u32,
    out_buf: [*]u8,
    out_len: u32,
) callconv(.c) i32 {
    const tcp_total: u32 = TCP_HDR_LEN + payload_len;
    const ip_total: u32 = IP_HDR_LEN + tcp_total;

    if (out_len < ip_total) return -1;

    const buf = out_buf[0..ip_total];

    // --- IP header ---
    writeIpHeader(
        buf[0..IP_HDR_LEN],
        @truncate(ip_total),
        IPPROTO_TCP,
        DEFAULT_TTL,
        DEFAULT_TOS,
        0x0000, // ip_id=0; caller can overwrite if needed
        src_ip,
        dst_ip,
    );

    // --- TCP header at buf[20..40] ---
    const th = buf[IP_HDR_LEN..];
    writeU16Be(th, 0, sport);   // th_sport
    writeU16Be(th, 2, dport);   // th_dport
    writeU32Be(th, 4, seq);     // th_seq
    writeU32Be(th, 8, ack);     // th_ack
    // data offset = 5 (20 bytes / 4), no reserved bits
    th[12] = 0x50;              // th_off=5, th_x2=0
    th[13] = flags;             // th_flags
    const win: u16 = if (window != 0) window else DEFAULT_WINDOW;
    writeU16Be(th, 14, win);    // th_win
    writeU16Be(th, 16, 0);      // th_sum = 0 (placeholder)
    writeU16Be(th, 18, 0);      // th_urp = 0

    // --- Payload copy ---
    if (payload_len > 0) {
        const pay = payload orelse return -1;
        @memcpy(buf[IP_HDR_LEN + TCP_HDR_LEN ..][0..payload_len], pay[0..payload_len]);
    }

    // --- TCP checksum: pseudo-header + TCP header + payload ---
    var sum: u64 = pseudoHeaderSum(src_ip, dst_ip, IPPROTO_TCP, @truncate(tcp_total));
    sum += checksumAccumulate(buf[IP_HDR_LEN..][0..tcp_total]);
    const tcp_ck = finalizeChecksum(sum);
    writeU16Be(th, 16, tcp_ck);

    return @intCast(ip_total);
}

/// Build a complete IP + UDP packet into out_buf.
///
/// Parameters follow the same conventions as pkt_build_tcp.
/// Returns total packet length on success, -1 if out_buf is too small.
export fn pkt_build_udp(
    dst_ip: u32,
    src_ip: u32,
    sport: u16,
    dport: u16,
    payload: ?[*]const u8,
    payload_len: u32,
    out_buf: [*]u8,
    out_len: u32,
) callconv(.c) i32 {
    const udp_total: u32 = UDP_HDR_LEN + payload_len;
    const ip_total: u32 = IP_HDR_LEN + udp_total;

    if (out_len < ip_total) return -1;

    const buf = out_buf[0..ip_total];

    // --- IP header ---
    writeIpHeader(
        buf[0..IP_HDR_LEN],
        @truncate(ip_total),
        IPPROTO_UDP,
        DEFAULT_TTL,
        DEFAULT_TOS,
        0x0000,
        src_ip,
        dst_ip,
    );

    // --- UDP header at buf[20..28] ---
    const uh = buf[IP_HDR_LEN..];
    writeU16Be(uh, 0, sport);                         // uh_sport
    writeU16Be(uh, 2, dport);                         // uh_dport
    writeU16Be(uh, 4, @truncate(udp_total));           // uh_ulen
    writeU16Be(uh, 6, 0);                             // uh_sum = 0 placeholder

    // --- Payload copy ---
    if (payload_len > 0) {
        const pay = payload orelse return -1;
        @memcpy(buf[IP_HDR_LEN + UDP_HDR_LEN ..][0..payload_len], pay[0..payload_len]);
    }

    // --- UDP checksum: pseudo-header + UDP header + payload ---
    // RFC 768: if computed checksum is 0, transmit as 0xFFFF.
    var sum: u64 = pseudoHeaderSum(src_ip, dst_ip, IPPROTO_UDP, @truncate(udp_total));
    sum += checksumAccumulate(buf[IP_HDR_LEN..][0..udp_total]);
    var udp_ck = finalizeChecksum(sum);
    if (udp_ck == 0) udp_ck = 0xFFFF;
    writeU16Be(uh, 6, udp_ck);

    return @intCast(ip_total);
}

/// Build a complete IP + ICMP packet into out_buf.
///
/// Supported type/code combinations (matching nmap's build_icmp_raw):
///   type=8, code=0  — Echo Request         (icmplen = 8)
///   type=13, code=0 — Timestamp Request    (icmplen = 20)
///   type=17, code=0 — Address Mask Request (icmplen = 12)
///
/// id, seq — ICMP identifier/sequence in host byte order.
/// Returns total packet length on success, -1 on error.
export fn pkt_build_icmp(
    dst_ip: u32,
    src_ip: u32,
    icmp_type: u8,
    code: u8,
    id: u16,
    seq: u16,
    payload: ?[*]const u8,
    payload_len: u32,
    out_buf: [*]u8,
    out_len: u32,
) callconv(.c) i32 {
    // Determine ICMP header size for this type (bytes before optional payload)
    const icmp_hdr_size: u32 = switch (icmp_type) {
        8 => 8,   // Echo: type(1)+code(1)+cksum(2)+id(2)+seq(2)
        13 => 20, // Timestamp: +originate(4)+receive(4)+transmit(4)
        17 => 12, // Address Mask: +mask(4)
        else => return -1,
    };

    const icmp_total: u32 = icmp_hdr_size + payload_len;
    const ip_total: u32 = IP_HDR_LEN + icmp_total;

    if (out_len < ip_total) return -1;

    const buf = out_buf[0..ip_total];

    // --- IP header ---
    writeIpHeader(
        buf[0..IP_HDR_LEN],
        @truncate(ip_total),
        IPPROTO_ICMP,
        DEFAULT_TTL,
        DEFAULT_TOS,
        0x0000,
        src_ip,
        dst_ip,
    );

    // --- ICMP header at buf[20..] ---
    const ih = buf[IP_HDR_LEN..];

    // Zero out the entire ICMP region first (handles timestamp/mask padding)
    @memset(ih[0..icmp_total], 0);

    // Common fields: type, code, checksum(0), id, seq
    ih[0] = icmp_type;
    ih[1] = code;
    writeU16Be(ih, 2, 0);   // checksum placeholder
    writeU16Be(ih, 4, id);
    writeU16Be(ih, 6, seq);

    // Payload appended after the ICMP-type-specific header fields
    if (payload_len > 0) {
        const pay = payload orelse return -1;
        const pay_offset = icmp_hdr_size; // payload starts right after ICMP header
        @memcpy(ih[pay_offset..][0..payload_len], pay[0..payload_len]);
    }

    // --- ICMP checksum: covers header + payload (no pseudo-header for ICMP) ---
    const icmp_ck = checksum(ih[0..icmp_total]);
    writeU16Be(ih, 2, icmp_ck);

    return @intCast(ip_total);
}
