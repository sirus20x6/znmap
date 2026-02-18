#ifndef ZIG_PKT_BUILDER_H
#define ZIG_PKT_BUILDER_H

/*
 * pkt_builder.h — C declarations for zig/pkt_builder.zig
 *
 * High-performance raw packet construction with inline SIMD checksum
 * computation.  All three functions build a complete IPv4 + transport-layer
 * packet into a caller-supplied buffer in a single pass.
 *
 * IP/transport checksums are computed inline during header construction —
 * no separate checksum pass is required.
 *
 * Address conventions
 * -------------------
 * dst_ip / src_ip are passed as uint32_t in *network* byte order, i.e.
 * the raw value of in_addr.s_addr.  This matches how nmap stores addresses
 * internally and avoids unnecessary byte-swapping.
 *
 * Port, sequence, window, id, seq are all in *host* byte order; the
 * implementation converts them to network order internally.
 *
 * Return value
 * ------------
 * All functions return the total number of bytes written into out_buf on
 * success, or -1 if out_buf is too small to hold the complete packet.
 * No heap allocation is performed.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pkt_build_tcp — build IP + TCP packet
 *
 * @dst_ip       destination IPv4 address (network byte order)
 * @src_ip       source IPv4 address      (network byte order)
 * @sport        source port              (host byte order)
 * @dport        destination port         (host byte order)
 * @seq          TCP sequence number      (host byte order)
 * @ack          TCP acknowledgment num   (host byte order)
 * @flags        TCP flags (TH_SYN etc.)
 * @window       TCP window size          (host byte order; 0 → 1024)
 * @payload      application data         (may be NULL if payload_len == 0)
 * @payload_len  length of payload in bytes
 * @out_buf      output buffer supplied by the caller
 * @out_len      size of out_buf in bytes
 *
 * Returns total packet length or -1 on error.
 */
int32_t pkt_build_tcp(
    uint32_t dst_ip,
    uint32_t src_ip,
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    uint32_t ack,
    uint8_t  flags,
    uint16_t window,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_buf,
    uint32_t out_len
);

/*
 * pkt_build_udp — build IP + UDP packet
 *
 * @dst_ip       destination IPv4 address (network byte order)
 * @src_ip       source IPv4 address      (network byte order)
 * @sport        source port              (host byte order)
 * @dport        destination port         (host byte order)
 * @payload      application data         (may be NULL if payload_len == 0)
 * @payload_len  length of payload in bytes
 * @out_buf      output buffer supplied by the caller
 * @out_len      size of out_buf in bytes
 *
 * Returns total packet length or -1 on error.
 * UDP checksum of 0 is remapped to 0xFFFF per RFC 768.
 */
int32_t pkt_build_udp(
    uint32_t dst_ip,
    uint32_t src_ip,
    uint16_t sport,
    uint16_t dport,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_buf,
    uint32_t out_len
);

/*
 * pkt_build_icmp — build IP + ICMP packet
 *
 * Supported type/code pairs (matching nmap's build_icmp_raw):
 *   type=8,  code=0  — Echo Request         (8-byte ICMP header)
 *   type=13, code=0  — Timestamp Request    (20-byte ICMP header)
 *   type=17, code=0  — Address Mask Request (12-byte ICMP header)
 *
 * @dst_ip       destination IPv4 address (network byte order)
 * @src_ip       source IPv4 address      (network byte order)
 * @icmp_type    ICMP type field
 * @code         ICMP code field
 * @id           ICMP identifier          (host byte order)
 * @seq          ICMP sequence number     (host byte order)
 * @payload      additional data after ICMP header (may be NULL)
 * @payload_len  length of payload in bytes
 * @out_buf      output buffer supplied by the caller
 * @out_len      size of out_buf in bytes
 *
 * Returns total packet length or -1 on error.
 */
int32_t pkt_build_icmp(
    uint32_t dst_ip,
    uint32_t src_ip,
    uint8_t  icmp_type,
    uint8_t  code,
    uint16_t id,
    uint16_t seq,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_buf,
    uint32_t out_len
);

/*
 * pkt_build_tcp6 — build IPv6 + TCP packet
 *
 * @dst_ip       destination IPv6 address (pointer to 16 bytes, network byte order)
 * @src_ip       source IPv6 address      (pointer to 16 bytes, network byte order)
 * @sport        source port              (host byte order)
 * @dport        destination port         (host byte order)
 * @seq          TCP sequence number      (host byte order)
 * @ack          TCP acknowledgment num   (host byte order)
 * @flags        TCP flags (TH_SYN etc.)
 * @window       TCP window size          (host byte order; 0 → 1024)
 * @payload      application data         (may be NULL if payload_len == 0)
 * @payload_len  length of payload in bytes
 * @out_buf      output buffer supplied by the caller
 * @out_len      size of out_buf in bytes
 *
 * Returns total packet length or -1 on error.
 */
int32_t pkt_build_tcp6(
    const uint8_t *dst_ip,
    const uint8_t *src_ip,
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    uint32_t ack,
    uint8_t  flags,
    uint16_t window,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_buf,
    uint32_t out_len
);

/*
 * pkt_build_udp6 — build IPv6 + UDP packet
 *
 * @dst_ip       destination IPv6 address (pointer to 16 bytes, network byte order)
 * @src_ip       source IPv6 address      (pointer to 16 bytes, network byte order)
 * @sport        source port              (host byte order)
 * @dport        destination port         (host byte order)
 * @payload      application data         (may be NULL if payload_len == 0)
 * @payload_len  length of payload in bytes
 * @out_buf      output buffer supplied by the caller
 * @out_len      size of out_buf in bytes
 *
 * Returns total packet length or -1 on error.
 * UDP checksum of 0 is remapped to 0xFFFF per RFC 2460.
 */
int32_t pkt_build_udp6(
    const uint8_t *dst_ip,
    const uint8_t *src_ip,
    uint16_t sport,
    uint16_t dport,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_buf,
    uint32_t out_len
);

/*
 * pkt_build_icmp6 — build IPv6 + ICMPv6 packet
 *
 * Supported type/code pairs:
 *   type=128, code=0 — Echo Request  (8-byte ICMPv6 header)
 *   type=129, code=0 — Echo Reply    (8-byte ICMPv6 header)
 *
 * Unlike IPv4 ICMP, ICMPv6 checksum includes the IPv6 pseudo-header.
 *
 * @dst_ip       destination IPv6 address (pointer to 16 bytes, network byte order)
 * @src_ip       source IPv6 address      (pointer to 16 bytes, network byte order)
 * @icmp_type    ICMPv6 type field
 * @code         ICMPv6 code field
 * @id           ICMPv6 identifier        (host byte order)
 * @seq          ICMPv6 sequence number   (host byte order)
 * @payload      additional data after ICMPv6 header (may be NULL)
 * @payload_len  length of payload in bytes
 * @out_buf      output buffer supplied by the caller
 * @out_len      size of out_buf in bytes
 *
 * Returns total packet length or -1 on error.
 */
int32_t pkt_build_icmp6(
    const uint8_t *dst_ip,
    const uint8_t *src_ip,
    uint8_t  icmp_type,
    uint8_t  code,
    uint16_t id,
    uint16_t seq,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_buf,
    uint32_t out_len
);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_PKT_BUILDER_H */
