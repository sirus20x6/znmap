const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const ETH_P_ALL: u16 = 0x0003;
const TPACKET_ALIGNMENT: u32 = 16;
const TP_STATUS_USER: u32 = 1;
const TP_STATUS_KERNEL: u32 = 0;

const tpacket_req = extern struct {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
};

const tpacket2_hdr = extern struct {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [4]u8,
};

const tpacket_stats = extern struct {
    tp_packets: u32,
    tp_drops: u32,
};

const sockaddr_ll = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

pub const PktMmapRing = struct {
    fd: c_int,
    ring_buf: [*]u8,
    ring_size: usize,
    frame_size: u32,
    frame_count: u32,
    head: u32,
    stats_received: u64,
    stats_dropped: u64,
};

fn isPowerOf2(x: u32) bool {
    return x != 0 and (x & (x - 1)) == 0;
}

fn gcd(a: usize, b: usize) usize {
    var x = a;
    var y = b;
    while (y != 0) {
        const t = x % y;
        x = y;
        y = t;
    }
    return x;
}

fn lcm(a: usize, b: usize) ?usize {
    if (a == 0 or b == 0) return null;
    const g = gcd(a, b);
    const q = a / g;
    return std.math.mul(usize, q, b) catch null;
}

fn htons(v: u16) u16 {
    return @byteSwap(v);
}

fn fdArg(fd: c_int) usize {
    return @as(usize, @bitCast(@as(isize, fd)));
}

fn isOk(rc: usize) bool {
    return posix.errno(rc) == .SUCCESS;
}

fn closeFd(fd: c_int) void {
    _ = linux.syscall1(.close, fdArg(fd));
}

fn munmapRing(ptr: [*]u8, len: usize) void {
    _ = linux.syscall2(.munmap, @intFromPtr(ptr), len);
}

fn currentHdr(ring: *PktMmapRing) *align(1) tpacket2_hdr {
    const off = @as(usize, ring.head) * @as(usize, ring.frame_size);
    return @as(*align(1) tpacket2_hdr, @ptrCast(ring.ring_buf + off));
}

export fn pkt_mmap_init(interface: [*:0]const u8, ring_size: u32, frame_size: u32) callconv(.c) ?*PktMmapRing {
    if (!isPowerOf2(ring_size)) return null;
    if (frame_size < @sizeOf(tpacket2_hdr)) return null;
    if (frame_size % TPACKET_ALIGNMENT != 0) return null;

    const page_size = std.heap.pageSize();
    const block_size = lcm(page_size, @as(usize, frame_size)) orelse return null;
    if (block_size == 0 or block_size > std.math.maxInt(u32)) return null;

    const frames_per_block = block_size / @as(usize, frame_size);
    if (frames_per_block == 0) return null;
    if (@mod(@as(usize, ring_size), frames_per_block) != 0) return null;

    const block_nr_usize = @as(usize, ring_size) / frames_per_block;
    if (block_nr_usize == 0 or block_nr_usize > std.math.maxInt(u32)) return null;

    const total_size = std.math.mul(usize, @as(usize, ring_size), @as(usize, frame_size)) catch return null;

    const sock_rc = linux.syscall3(
        .socket,
        @as(usize, @intCast(linux.AF.PACKET)),
        @as(usize, @intCast(linux.SOCK.RAW)),
        @as(usize, @intCast(htons(ETH_P_ALL))),
    );
    if (!isOk(sock_rc)) return null;
    const fd: c_int = @intCast(@as(isize, @bitCast(sock_rc)));

    errdefer closeFd(fd);

    const version: u32 = @intFromEnum(linux.tpacket_versions.V2);
    const set_ver_rc = linux.syscall5(
        .setsockopt,
        fdArg(fd),
        @as(usize, @bitCast(@as(isize, linux.SOL.PACKET))),
        linux.PACKET.VERSION,
        @intFromPtr(&version),
        @sizeOf(u32),
    );
    if (!isOk(set_ver_rc)) return null;

    var req = tpacket_req{
        .tp_block_size = @intCast(block_size),
        .tp_block_nr = @intCast(block_nr_usize),
        .tp_frame_size = frame_size,
        .tp_frame_nr = ring_size,
    };

    const set_ring_rc = linux.syscall5(
        .setsockopt,
        fdArg(fd),
        @as(usize, @bitCast(@as(isize, linux.SOL.PACKET))),
        linux.PACKET.RX_RING,
        @intFromPtr(&req),
        @sizeOf(tpacket_req),
    );
    if (!isOk(set_ring_rc)) return null;

    const ifindex = std.c.if_nametoindex(interface);
    if (ifindex <= 0) return null;

    var sll = sockaddr_ll{
        .sll_family = @intCast(linux.AF.PACKET),
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = ifindex,
        .sll_hatype = 0,
        .sll_pkttype = 0,
        .sll_halen = 0,
        .sll_addr = [_]u8{0} ** 8,
    };

    const bind_rc = linux.syscall3(
        .bind,
        fdArg(fd),
        @intFromPtr(&sll),
        @sizeOf(sockaddr_ll),
    );
    if (!isOk(bind_rc)) return null;

    const map_flags: u32 = @bitCast(linux.MAP{ .TYPE = .SHARED });
    const mmap_rc = linux.syscall6(
        .mmap,
        0,
        total_size,
        linux.PROT.READ | linux.PROT.WRITE,
        map_flags,
        fdArg(fd),
        0,
    );
    if (!isOk(mmap_rc)) return null;

    const ring_ptr: [*]u8 = @ptrFromInt(mmap_rc);

    const ring = std.heap.c_allocator.create(PktMmapRing) catch {
        munmapRing(ring_ptr, total_size);
        return null;
    };

    ring.* = .{
        .fd = fd,
        .ring_buf = ring_ptr,
        .ring_size = total_size,
        .frame_size = frame_size,
        .frame_count = ring_size,
        .head = 0,
        .stats_received = 0,
        .stats_dropped = 0,
    };

    return ring;
}

export fn pkt_mmap_recv(ring: *PktMmapRing, len: *u32) callconv(.c) ?[*]const u8 {
    const hdr = currentHdr(ring);
    const status_ptr = @as(*align(1) volatile u32, @ptrCast(&hdr.tp_status));
    if ((status_ptr.* & TP_STATUS_USER) == 0) return null;

    len.* = hdr.tp_snaplen;
    const off = @as(usize, ring.head) * @as(usize, ring.frame_size);
    const data_off = @as(usize, hdr.tp_mac);
    return ring.ring_buf + off + data_off;
}

export fn pkt_mmap_release(ring: *PktMmapRing) callconv(.c) void {
    const hdr = currentHdr(ring);
    const status_ptr = @as(*align(1) volatile u32, @ptrCast(&hdr.tp_status));
    status_ptr.* = TP_STATUS_KERNEL;
    ring.head = (ring.head + 1) & (ring.frame_count - 1);
}

export fn pkt_mmap_fd(ring: *PktMmapRing) callconv(.c) c_int {
    return ring.fd;
}

export fn pkt_mmap_stats(ring: *PktMmapRing, received: *u64, dropped: *u64) callconv(.c) void {
    var kstats = tpacket_stats{ .tp_packets = 0, .tp_drops = 0 };
    var optlen: u32 = @sizeOf(tpacket_stats);

    const rc = linux.syscall5(
        .getsockopt,
        fdArg(ring.fd),
        @as(usize, @bitCast(@as(isize, linux.SOL.PACKET))),
        linux.PACKET.STATISTICS,
        @intFromPtr(&kstats),
        @intFromPtr(&optlen),
    );

    if (isOk(rc) and optlen >= @sizeOf(tpacket_stats)) {
        ring.stats_received += kstats.tp_packets;
        ring.stats_dropped += kstats.tp_drops;
    }

    received.* = ring.stats_received;
    dropped.* = ring.stats_dropped;
}

export fn pkt_mmap_destroy(ring: *PktMmapRing) callconv(.c) void {
    munmapRing(ring.ring_buf, ring.ring_size);
    closeFd(ring.fd);
    std.heap.c_allocator.destroy(ring);
}
