#ifndef ZIG_BANNER_MATCH_H
#define ZIG_BANNER_MATCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t banner_match_prefix(const uint8_t *buf, uint32_t len);

int32_t banner_search(
    const uint8_t *haystack,
    uint32_t haystack_len,
    const uint8_t *needle,
    uint32_t needle_len
);

uint32_t banner_match_batch(
    const uint8_t *const *bufs,
    const uint32_t *lens,
    uint32_t count,
    int32_t *out_ids
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZIG_BANNER_MATCH_H */
