/*
 * probe_filter.h — C interface to Zig-based service probe pre-filter.
 *
 * Skips PCRE2 calls for patterns whose literal prefix doesn't appear
 * in the response buffer.
 */

#ifndef ZIG_PROBE_FILTER_H
#define ZIG_PROBE_FILTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new filter context. Returns NULL on failure. */
void *probe_filter_init(void);

/* Register a regex pattern at the given index.
 * regex/regex_len: the raw regex string (not the m// wrapper).
 * case_insensitive: nonzero if the 'i' flag is set.
 * Returns 0 on success, -1 on error. */
int probe_filter_add(void *handle, unsigned int index,
                     const unsigned char *regex, size_t regex_len,
                     int case_insensitive);

/* Check if buf (of buf_len bytes) might match pattern at index.
 * Returns 1 if PCRE2 should be called, 0 if the pattern can be skipped. */
int probe_filter_check(void *handle, unsigned int index,
                       const unsigned char *buf, size_t buf_len);

/* Destroy the filter context. */
void probe_filter_free(void *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_PROBE_FILTER_H */
