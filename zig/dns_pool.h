#ifndef ZIG_DNS_POOL_H
#define ZIG_DNS_POOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t addr[16];   /* IPv4 (4 bytes) or IPv6 (16 bytes) */
    uint8_t addr_len;   /* 4 for IPv4, 16 for IPv6 */
    uint32_t id;        /* caller-assigned ID, passed through to result */
} DnsQuery;

typedef struct {
    uint32_t id;          /* matches query ID */
    uint8_t hostname[256]; /* null-terminated hostname */
    uint16_t hostname_len;
    uint8_t status;       /* 0=success, 1=nxdomain, 2=timeout, 3=error */
} DnsResult;

/* Create a DNS resolver pool. */
void *dns_pool_create(uint32_t max_servers);

/* Add a DNS server. ip_addr is 4 bytes (IPv4) or 16 bytes (IPv6). */
int dns_pool_add_server(void *handle, const uint8_t *ip_addr,
                        uint32_t ip_len, uint16_t port);

/* Send batch of PTR queries, collect responses within timeout.
 * Returns number of queries resolved. */
uint32_t dns_pool_resolve_batch(void *handle,
                                const DnsQuery *queries, uint32_t num_queries,
                                DnsResult *results, uint32_t timeout_ms);

/* Destroy the pool and close all sockets. */
void dns_pool_destroy(void *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_DNS_POOL_H */
