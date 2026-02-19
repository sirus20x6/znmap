#ifndef NMAP_ZIG_PKT_MMAP_H
#define NMAP_ZIG_PKT_MMAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PktMmapRing PktMmapRing;

PktMmapRing *pkt_mmap_init(const char *interface, uint32_t ring_size, uint32_t frame_size);
const uint8_t *pkt_mmap_recv(PktMmapRing *ring, uint32_t *len);
void pkt_mmap_release(PktMmapRing *ring);
int pkt_mmap_fd(PktMmapRing *ring);
void pkt_mmap_stats(PktMmapRing *ring, uint64_t *received, uint64_t *dropped);
void pkt_mmap_destroy(PktMmapRing *ring);

#ifdef __cplusplus
}
#endif

#endif
