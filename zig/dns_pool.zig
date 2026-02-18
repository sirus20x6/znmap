// Batch DNS reverse-lookup pool with round-robin server distribution.
//
// Provides a connection-pooled PTR resolver for nmap's mass reverse DNS.
// Sends batches of queries across multiple UDP sockets, collects responses
// with poll()-based timeout.
//
// C ABI exports:
//   dns_pool_create(max_servers)
//   dns_pool_add_server(handle, ip, ip_len, port)
//   dns_pool_resolve_batch(handle, queries, num, results, timeout_ms)
//   dns_pool_destroy(handle)

const std = @import("std");
const posix = std.posix;

// ===================== DNS Wire Format =====================

const DNS_HDR_SIZE = 12;
const MAX_NAME_LEN = 255;
const MAX_PACKET = 512;
const MAX_SERVERS = 8;
const MAX_BATCH = 4096;

fn buildPtrQuery(buf: *[MAX_PACKET]u8, txid: u16, addr: [*]const u8, addr_len: u8) ?usize {
    var pos: usize = 0;

    // DNS header: txid, flags=0x0100 (standard query, recursion desired), qdcount=1
    buf[0] = @truncate(txid >> 8);
    buf[1] = @truncate(txid);
    buf[2] = 0x01;
    buf[3] = 0x00; // flags: RD=1
    buf[4] = 0x00;
    buf[5] = 0x01; // qdcount=1
    buf[6] = 0x00;
    buf[7] = 0x00; // ancount=0
    buf[8] = 0x00;
    buf[9] = 0x00; // nscount=0
    buf[10] = 0x00;
    buf[11] = 0x00; // arcount=0
    pos = DNS_HDR_SIZE;

    // Build reverse name: x.x.x.x.in-addr.arpa for IPv4
    if (addr_len == 4) {
        // Reverse octets
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            const octet = addr[i];
            var tmp: [4]u8 = undefined;
            const len = fmtU8(octet, &tmp);
            buf[pos] = @intCast(len);
            pos += 1;
            for (0..len) |j| {
                buf[pos] = tmp[j];
                pos += 1;
            }
        }
        // in-addr.arpa
        const suffix = [_][]const u8{ "in-addr", "arpa" };
        for (suffix) |label| {
            buf[pos] = @intCast(label.len);
            pos += 1;
            for (label) |c| {
                buf[pos] = c;
                pos += 1;
            }
        }
    } else if (addr_len == 16) {
        // IPv6: nibble-reversed .ip6.arpa
        var i: usize = 16;
        while (i > 0) {
            i -= 1;
            const lo: u8 = addr[i] & 0x0f;
            const hi: u8 = addr[i] >> 4;
            // Low nibble first
            buf[pos] = 1;
            pos += 1;
            buf[pos] = hexChar(lo);
            pos += 1;
            // High nibble
            buf[pos] = 1;
            pos += 1;
            buf[pos] = hexChar(hi);
            pos += 1;
        }
        const suffix = [_][]const u8{ "ip6", "arpa" };
        for (suffix) |label| {
            buf[pos] = @intCast(label.len);
            pos += 1;
            for (label) |c| {
                buf[pos] = c;
                pos += 1;
            }
        }
    } else {
        return null;
    }

    buf[pos] = 0; // root label
    pos += 1;
    // QTYPE = PTR (12)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x0c;
    pos += 2;
    // QCLASS = IN (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;

    return pos;
}

fn hexChar(nibble: u8) u8 {
    return if (nibble < 10) '0' + nibble else 'a' + nibble - 10;
}

fn fmtU8(val: u8, buf: *[4]u8) usize {
    if (val >= 100) {
        buf[0] = '0' + val / 100;
        buf[1] = '0' + (val / 10) % 10;
        buf[2] = '0' + val % 10;
        return 3;
    } else if (val >= 10) {
        buf[0] = '0' + val / 10;
        buf[1] = '0' + val % 10;
        return 2;
    } else {
        buf[0] = '0' + val;
        return 1;
    }
}

/// Parse a DNS name from a response packet, handling compression pointers.
fn parseDnsName(pkt: []const u8, start: usize, out: *[256]u8) ?u16 {
    var pos = start;
    var out_pos: u16 = 0;
    var jumps: u8 = 0;
    var end_pos: ?usize = null;

    while (pos < pkt.len) {
        const len_byte = pkt[pos];
        if (len_byte == 0) {
            if (end_pos == null) end_pos = pos + 1;
            break;
        }
        if ((len_byte & 0xC0) == 0xC0) {
            // Compression pointer
            if (pos + 1 >= pkt.len) return null;
            if (end_pos == null) end_pos = pos + 2;
            const offset = (@as(u16, len_byte & 0x3F) << 8) | @as(u16, pkt[pos + 1]);
            pos = offset;
            jumps += 1;
            if (jumps > 10) return null; // loop protection
            continue;
        }
        const label_len: usize = len_byte;
        pos += 1;
        if (pos + label_len > pkt.len) return null;
        if (out_pos > 0 and out_pos < 255) {
            out[out_pos] = '.';
            out_pos += 1;
        }
        for (0..label_len) |i| {
            if (out_pos >= 255) break;
            out[out_pos] = pkt[pos + i];
            out_pos += 1;
        }
        pos += label_len;
    }
    out[out_pos] = 0;
    return out_pos;
}

/// Parse DNS response, extract PTR record hostname.
fn parsePtrResponse(pkt: []const u8, out_hostname: *[256]u8) ?u16 {
    if (pkt.len < DNS_HDR_SIZE) return null;

    const flags = (@as(u16, pkt[2]) << 8) | @as(u16, pkt[3]);
    if (flags & 0x8000 == 0) return null; // not a response
    const rcode = flags & 0x000F;
    if (rcode != 0) return null; // error

    const qdcount = (@as(u16, pkt[4]) << 8) | @as(u16, pkt[5]);
    const ancount = (@as(u16, pkt[6]) << 8) | @as(u16, pkt[7]);
    if (ancount == 0) return null;

    // Skip question section
    var pos: usize = DNS_HDR_SIZE;
    for (0..qdcount) |_| {
        while (pos < pkt.len) {
            const b = pkt[pos];
            if (b == 0) {
                pos += 1;
                break;
            }
            if ((b & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += 1 + @as(usize, b);
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer records, look for PTR (type 12)
    for (0..ancount) |_| {
        if (pos >= pkt.len) return null;
        // Skip name
        while (pos < pkt.len) {
            const b = pkt[pos];
            if (b == 0) {
                pos += 1;
                break;
            }
            if ((b & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += 1 + @as(usize, b);
        }
        if (pos + 10 > pkt.len) return null;
        const rtype = (@as(u16, pkt[pos]) << 8) | @as(u16, pkt[pos + 1]);
        const rdlen = (@as(u16, pkt[pos + 8]) << 8) | @as(u16, pkt[pos + 9]);
        pos += 10;

        if (rtype == 12) { // PTR
            return parseDnsName(pkt, pos, out_hostname);
        }
        pos += rdlen;
    }
    return null;
}

// ===================== Pool Structures =====================

const ServerInfo = struct {
    addr_buf: [128]u8 align(4), // sockaddr storage
    addrlen: std.posix.socklen_t,
    fd: std.posix.fd_t,

    fn getSockaddr(self: *const ServerInfo) *const std.posix.sockaddr {
        return @ptrCast(&self.addr_buf);
    }
};

const Pool = struct {
    servers: [MAX_SERVERS]ServerInfo,
    num_servers: u32,
};

// ===================== C ABI Types =====================

pub const DnsQuery = extern struct {
    addr: [16]u8,
    addr_len: u8,
    id: u32,
};

pub const DnsResult = extern struct {
    id: u32,
    hostname: [256]u8,
    hostname_len: u16,
    status: u8, // 0=success, 1=nxdomain, 2=timeout, 3=error
};

// ===================== C ABI Exports =====================

export fn dns_pool_create(max_servers: u32) callconv(.c) ?*anyopaque {
    _ = max_servers;
    const allocator = std.heap.c_allocator;
    const pool = allocator.create(Pool) catch return null;
    pool.* = Pool{
        .servers = undefined,
        .num_servers = 0,
    };
    return @ptrCast(pool);
}

export fn dns_pool_add_server(
    handle: ?*anyopaque,
    ip_addr: [*]const u8,
    ip_len: u32,
    port: u16,
) callconv(.c) c_int {
    const pool: *Pool = @ptrCast(@alignCast(handle orelse return -1));
    if (pool.num_servers >= MAX_SERVERS) return -1;

    const idx = pool.num_servers;
    var srv = &pool.servers[idx];

    @memset(&srv.addr_buf, 0);
    if (ip_len == 4) {
        const sa4: *std.posix.sockaddr.in = @ptrCast(@alignCast(&srv.addr_buf));
        sa4.* = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = undefined,
        };
        @memcpy(@as(*[4]u8, @ptrCast(&sa4.addr)), ip_addr[0..4]);
        srv.addrlen = @sizeOf(std.posix.sockaddr.in);
        srv.fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK, 0) catch return -1;
    } else if (ip_len == 16) {
        const sa6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&srv.addr_buf));
        sa6.* = .{
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = undefined,
            .scope_id = 0,
        };
        @memcpy(&sa6.addr, ip_addr[0..16]);
        srv.addrlen = @sizeOf(std.posix.sockaddr.in6);
        srv.fd = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK, 0) catch return -1;
    } else {
        return -1;
    }

    pool.num_servers = idx + 1;
    return 0;
}

export fn dns_pool_resolve_batch(
    handle: ?*anyopaque,
    queries: [*]const DnsQuery,
    num_queries: u32,
    results: [*]DnsResult,
    timeout_ms: u32,
) callconv(.c) u32 {
    const pool: *Pool = @ptrCast(@alignCast(handle orelse return 0));
    if (pool.num_servers == 0 or num_queries == 0) return 0;

    const num: usize = @min(num_queries, MAX_BATCH);
    var resolved: u32 = 0;

    // Initialize all results as timeout
    for (0..num) |i| {
        results[i] = DnsResult{
            .id = queries[i].id,
            .hostname = undefined,
            .hostname_len = 0,
            .status = 2, // timeout
        };
    }

    // txid → query index mapping (txid = index + 1)
    // Send all queries round-robin across servers
    for (0..num) |i| {
        const srv_idx = i % pool.num_servers;
        const srv = &pool.servers[srv_idx];
        const txid: u16 = @intCast((i + 1) & 0xFFFF);

        var pkt_buf: [MAX_PACKET]u8 = undefined;
        const pkt_len = buildPtrQuery(&pkt_buf, txid, @ptrCast(&queries[i].addr), queries[i].addr_len) orelse continue;

        _ = std.posix.sendto(srv.fd, pkt_buf[0..pkt_len], 0, srv.getSockaddr(), srv.addrlen) catch continue;
    }

    // Poll for responses
    var pollfds: [MAX_SERVERS]std.posix.pollfd = undefined;
    for (0..pool.num_servers) |s| {
        pollfds[s] = .{
            .fd = pool.servers[s].fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        };
    }

    const deadline_ms: i64 = @intCast(timeout_ms);
    var elapsed_ms: i64 = 0;
    var recv_buf: [MAX_PACKET]u8 = undefined;

    while (elapsed_ms < deadline_ms and resolved < num) {
        const remaining: i32 = @intCast(@max(1, deadline_ms - elapsed_ms));
        const start = std.time.milliTimestamp();

        const ready = std.posix.poll(pollfds[0..pool.num_servers], remaining) catch break;
        elapsed_ms += std.time.milliTimestamp() - start;

        if (ready == 0) break; // timeout

        for (0..pool.num_servers) |s| {
            if (pollfds[s].revents & std.posix.POLL.IN != 0) {
                // Read responses
                while (true) {
                    const n = std.posix.recvfrom(pool.servers[s].fd, &recv_buf, 0, null, null) catch break;

                    if (n < DNS_HDR_SIZE) continue;
                    const pkt = recv_buf[0..n];
                    const txid = (@as(u16, pkt[0]) << 8) | @as(u16, pkt[1]);
                    const idx: usize = @as(usize, txid) - 1;
                    if (idx >= num) continue;

                    const flags = (@as(u16, pkt[2]) << 8) | @as(u16, pkt[3]);
                    const rcode = flags & 0x000F;

                    if (rcode != 0) {
                        results[idx].status = 1; // nxdomain or error
                        resolved += 1;
                        continue;
                    }

                    var hostname: [256]u8 = undefined;
                    if (parsePtrResponse(pkt, &hostname)) |hlen| {
                        @memcpy(results[idx].hostname[0..hlen], hostname[0..hlen]);
                        results[idx].hostname[hlen] = 0;
                        results[idx].hostname_len = hlen;
                        results[idx].status = 0; // success
                    } else {
                        results[idx].status = 3; // parse error
                    }
                    resolved += 1;
                }
                pollfds[s].revents = 0;
            }
        }
    }

    return resolved;
}

export fn dns_pool_destroy(handle: ?*anyopaque) callconv(.c) void {
    const pool: *Pool = @ptrCast(@alignCast(handle orelse return));
    for (0..pool.num_servers) |i| {
        std.posix.close(pool.servers[i].fd);
    }
    std.heap.c_allocator.destroy(pool);
}
