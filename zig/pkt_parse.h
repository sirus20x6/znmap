#ifndef ZIG_PKT_PARSE_H
#define ZIG_PKT_PARSE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TcpParseResult {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  flags;
    uint16_t window;
    uint16_t payload_offset;
    uint16_t payload_len;
} TcpParseResult;

typedef struct UdpParseResult {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t payload_offset;
    uint16_t payload_len;
} UdpParseResult;

int pkt_parse_tcp(const uint8_t *pkt, uint32_t pkt_len, TcpParseResult *out);
int pkt_parse_udp(const uint8_t *pkt, uint32_t pkt_len, UdpParseResult *out);
uint64_t pkt_validate_batch(const uint8_t *const *pkts, const uint32_t *lens, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif
