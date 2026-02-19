#ifndef ZIG_IP_RANGE_H
#define ZIG_IP_RANGE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Expand a CIDR range (e.g., 192.168.1.0/24) into individual IPs.
// Writes up to max_ips IPs into out_ips buffer. Returns number of IPs written.
uint32_t ip_range_expand_cidr(uint32_t base_ip, uint8_t prefix_len, uint32_t *out_ips, uint32_t max_ips);

// Expand a CIDR range and call a callback for each batch of 8 IPs.
// This avoids needing a huge output buffer for /8 ranges.
uint32_t ip_range_iterate_cidr(
    uint32_t base_ip,
    uint8_t prefix_len,
    void *ctx,
    void (*callback)(void *ctx, const uint32_t *ips, uint32_t count));

// Check if an IP falls within a CIDR range. Uses branchless comparison.
bool ip_range_contains(uint32_t base_ip, uint8_t prefix_len, uint32_t test_ip);

// Batch check: test N IPs against a single CIDR. Returns bitmask of matches.
uint64_t ip_range_contains_batch(uint32_t base_ip, uint8_t prefix_len, const uint32_t *test_ips, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_IP_RANGE_H */
