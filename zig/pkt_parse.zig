const std = @import("std");

pub const TcpParseResult = extern struct {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload_offset: u16,
    payload_len: u16,
};

pub const UdpParseResult = extern struct {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    payload_offset: u16,
    payload_len: u16,
};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const MIN_IPV4_HDR_LEN: u16 = 20;
const MIN_TCP_HDR_LEN: u16 = 20;
const UDP_HDR_LEN: u16 = 8;

const Vec2U16 = @Vector(2, u16);
const Vec2U32 = @Vector(2, u32);
const Vec4U32 = @Vector(4, u32);

inline fn ntoh16x2(v: Vec2U16) Vec2U16 {
    const bytes: @Vector(4, u8) = @bitCast(v);
    const shuffled = @shuffle(u8, bytes, bytes, @Vector(4, i32){ 1, 0, 3, 2 });
    return @bitCast(shuffled);
}

inline fn ntoh32x2(v: Vec2U32) Vec2U32 {
    const bytes: @Vector(8, u8) = @bitCast(v);
    const shuffled = @shuffle(u8, bytes, bytes, @Vector(8, i32){ 3, 2, 1, 0, 7, 6, 5, 4 });
    return @bitCast(shuffled);
}

inline fn ntoh16(v: u16) u16 {
    return ntoh16x2(Vec2U16{ v, 0 })[0];
}

inline fn ntoh32(v: u32) u32 {
    return ntoh32x2(Vec2U32{ v, 0 })[0];
}

inline fn loadRawU16(pkt: [*]const u8, offset: usize) u16 {
    return @as(*align(1) const u16, @ptrCast(pkt + offset)).*;
}

inline fn loadRawU32(pkt: [*]const u8, offset: usize) u32 {
    return @as(*align(1) const u32, @ptrCast(pkt + offset)).*;
}

inline fn loadBeU16(pkt: [*]const u8, offset: usize) u16 {
    return ntoh16(loadRawU16(pkt, offset));
}

inline fn loadBeU32(pkt: [*]const u8, offset: usize) u32 {
    return ntoh32(loadRawU32(pkt, offset));
}

inline fn csumWord(pkt: [*]const u8, offset: usize) u32 {
    return (@as(u32, pkt[offset]) << 8) | @as(u32, pkt[offset + 1]);
}

fn ipv4HeaderChecksumValid(pkt: [*]const u8, ihl_bytes: u16) bool {
    var sum: u32 = 0;
    var off: usize = 0;
    while (off < ihl_bytes) : (off += 2) {
        sum += csumWord(pkt, off);
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return sum == 0xFFFF;
}

const Ipv4Meta = struct {
    ihl_bytes: u16,
    total_len: u16,
};

fn parseAndValidateIpv4(pkt: [*]const u8, pkt_len: u32, proto: u8) ?Ipv4Meta {
    if (pkt_len < MIN_IPV4_HDR_LEN) return null;

    const ver_ihl = pkt[0];
    const version = ver_ihl >> 4;
    const ihl_words = ver_ihl & 0x0F;
    if (version != 4 or ihl_words < 5) return null;

    const ihl_bytes: u16 = @as(u16, ihl_words) * 4;
    if (pkt_len < ihl_bytes) return null;

    const total_len = loadBeU16(pkt, 2);
    if (total_len < ihl_bytes or total_len > pkt_len) return null;
    if (pkt[9] != proto) return null;
    if (!ipv4HeaderChecksumValid(pkt, ihl_bytes)) return null;

    return .{
        .ihl_bytes = ihl_bytes,
        .total_len = total_len,
    };
}

fn packetBaseChecks(pkt: [*]const u8, pkt_len: u32) bool {
    if (pkt_len < MIN_IPV4_HDR_LEN) return false;
    const ver_ihl = pkt[0];
    const version = ver_ihl >> 4;
    const ihl_words = ver_ihl & 0x0F;
    if (version != 4 or ihl_words < 5) return false;
    const ihl_bytes: u16 = @as(u16, ihl_words) * 4;
    if (pkt_len < ihl_bytes) return false;
    const total_len = loadBeU16(pkt, 2);
    if (total_len < ihl_bytes or total_len > pkt_len) return false;
    return true;
}

fn checksum4x20(p0: [*]const u8, p1: [*]const u8, p2: [*]const u8, p3: [*]const u8) [4]bool {
    var sums: Vec4U32 = @splat(0);

    inline for (0..10) |w| {
        const off = w * 2;
        const words = Vec4U32{
            csumWord(p0, off),
            csumWord(p1, off),
            csumWord(p2, off),
            csumWord(p3, off),
        };
        sums += words;
    }

    var ok = [4]bool{ false, false, false, false };
    inline for (0..4) |lane| {
        var s = sums[lane];
        s = (s & 0xFFFF) + (s >> 16);
        s = (s & 0xFFFF) + (s >> 16);
        ok[lane] = (s == 0xFFFF);
    }
    return ok;
}

export fn pkt_parse_tcp(pkt: [*]const u8, pkt_len: u32, out: *TcpParseResult) callconv(.c) c_int {
    const ip = parseAndValidateIpv4(pkt, pkt_len, IPPROTO_TCP) orelse return -1;

    const tcp_off: u16 = ip.ihl_bytes;
    if (ip.total_len < tcp_off + MIN_TCP_HDR_LEN) return -1;

    const data_off_words = pkt[tcp_off + 12] >> 4;
    if (data_off_words < 5) return -1;
    const tcp_hdr_len: u16 = @as(u16, data_off_words) * 4;
    if (ip.total_len < tcp_off + tcp_hdr_len) return -1;

    const payload_offset: u16 = tcp_off + tcp_hdr_len;
    const payload_len: u16 = ip.total_len - payload_offset;

    out.src_ip = loadBeU32(pkt, 12);
    out.dst_ip = loadBeU32(pkt, 16);
    out.src_port = loadBeU16(pkt, tcp_off + 0);
    out.dst_port = loadBeU16(pkt, tcp_off + 2);
    out.seq = loadBeU32(pkt, tcp_off + 4);
    out.ack = loadBeU32(pkt, tcp_off + 8);
    out.flags = pkt[tcp_off + 13];
    out.window = loadBeU16(pkt, tcp_off + 14);
    out.payload_offset = payload_offset;
    out.payload_len = payload_len;
    return 0;
}

export fn pkt_parse_udp(pkt: [*]const u8, pkt_len: u32, out: *UdpParseResult) callconv(.c) c_int {
    const ip = parseAndValidateIpv4(pkt, pkt_len, IPPROTO_UDP) orelse return -1;

    const udp_off: u16 = ip.ihl_bytes;
    if (ip.total_len < udp_off + UDP_HDR_LEN) return -1;

    const udp_len = loadBeU16(pkt, udp_off + 4);
    if (udp_len < UDP_HDR_LEN) return -1;
    if (udp_off + udp_len > ip.total_len) return -1;

    const payload_offset: u16 = udp_off + UDP_HDR_LEN;
    const payload_len: u16 = udp_len - UDP_HDR_LEN;

    out.src_ip = loadBeU32(pkt, 12);
    out.dst_ip = loadBeU32(pkt, 16);
    out.src_port = loadBeU16(pkt, udp_off + 0);
    out.dst_port = loadBeU16(pkt, udp_off + 2);
    out.payload_offset = payload_offset;
    out.payload_len = payload_len;
    return 0;
}

export fn pkt_validate_batch(pkts: [*]const [*]const u8, lens: [*]const u32, count: u32) callconv(.c) u64 {
    const n: u32 = if (count > 64) 64 else count;
    var valid_mask: u64 = 0;
    var i: u32 = 0;

    while (i + 4 <= n) : (i += 4) {
        const p0 = pkts[i + 0];
        const p1 = pkts[i + 1];
        const p2 = pkts[i + 2];
        const p3 = pkts[i + 3];

        const l0 = lens[i + 0];
        const l1 = lens[i + 1];
        const l2 = lens[i + 2];
        const l3 = lens[i + 3];

        const h0 = (l0 >= MIN_IPV4_HDR_LEN) and (p0[0] == 0x45);
        const h1 = (l1 >= MIN_IPV4_HDR_LEN) and (p1[0] == 0x45);
        const h2 = (l2 >= MIN_IPV4_HDR_LEN) and (p2[0] == 0x45);
        const h3 = (l3 >= MIN_IPV4_HDR_LEN) and (p3[0] == 0x45);

        const t0 = if (h0) loadBeU16(p0, 2) else 0;
        const t1 = if (h1) loadBeU16(p1, 2) else 0;
        const t2 = if (h2) loadBeU16(p2, 2) else 0;
        const t3 = if (h3) loadBeU16(p3, 2) else 0;

        const b0 = h0 and (t0 >= MIN_IPV4_HDR_LEN) and (t0 <= l0);
        const b1 = h1 and (t1 >= MIN_IPV4_HDR_LEN) and (t1 <= l1);
        const b2 = h2 and (t2 >= MIN_IPV4_HDR_LEN) and (t2 <= l2);
        const b3 = h3 and (t3 >= MIN_IPV4_HDR_LEN) and (t3 <= l3);

        if (b0 and b1 and b2 and b3) {
            const ok = checksum4x20(p0, p1, p2, p3);
            if (ok[0]) valid_mask |= (@as(u64, 1) << @intCast(i + 0));
            if (ok[1]) valid_mask |= (@as(u64, 1) << @intCast(i + 1));
            if (ok[2]) valid_mask |= (@as(u64, 1) << @intCast(i + 2));
            if (ok[3]) valid_mask |= (@as(u64, 1) << @intCast(i + 3));
        } else {
            if (b0 and ipv4HeaderChecksumValid(p0, MIN_IPV4_HDR_LEN)) valid_mask |= (@as(u64, 1) << @intCast(i + 0));
            if (b1 and ipv4HeaderChecksumValid(p1, MIN_IPV4_HDR_LEN)) valid_mask |= (@as(u64, 1) << @intCast(i + 1));
            if (b2 and ipv4HeaderChecksumValid(p2, MIN_IPV4_HDR_LEN)) valid_mask |= (@as(u64, 1) << @intCast(i + 2));
            if (b3 and ipv4HeaderChecksumValid(p3, MIN_IPV4_HDR_LEN)) valid_mask |= (@as(u64, 1) << @intCast(i + 3));
        }
    }

    while (i < n) : (i += 1) {
        const pkt = pkts[i];
        const pkt_len = lens[i];
        if (packetBaseChecks(pkt, pkt_len) and ipv4HeaderChecksumValid(pkt, MIN_IPV4_HDR_LEN)) {
            valid_mask |= (@as(u64, 1) << @intCast(i));
        }
    }

    return valid_mask;
}
