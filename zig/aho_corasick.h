/*
 * aho_corasick.h — C interface to Zig-based Aho-Corasick multi-pattern automaton.
 *
 * Usage:
 *   1. ac_create()         — allocate automaton
 *   2. ac_add_pattern()    — register each literal byte pattern with an ID
 *   3. ac_build()          — finalize (build failure links; must be called once)
 *   4. ac_search()         — scan a response buffer, retrieve matching IDs
 *   5. ac_destroy()        — free all resources
 *
 * The automaton scans the input buffer exactly once (O(n + m + z) where n is
 * the text length, m is the total pattern length, and z is the output size),
 * making it significantly faster than sequential per-pattern prefix scans for
 * large pattern sets.
 */

#ifndef ZIG_AHO_CORASICK_H
#define ZIG_AHO_CORASICK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ac_create - Allocate and return a new, empty Aho-Corasick automaton.
 *
 * Returns an opaque handle, or NULL on allocation failure.
 */
void *ac_create(void);

/**
 * ac_add_pattern - Register a byte pattern with an application-level ID.
 *
 * @handle:      Automaton returned by ac_create().
 * @pattern_ptr: Pointer to the raw byte pattern.
 * @pattern_len: Length of the pattern in bytes.
 * @pattern_id:  Caller-supplied ID returned by ac_search() on a match.
 *               Multiple patterns may share the same ID.
 *
 * Must be called before ac_build().
 * Returns 0 on success, -1 on error (allocation failure or called after build).
 */
int ac_add_pattern(void *handle,
                   const unsigned char *pattern_ptr, size_t pattern_len,
                   uint32_t pattern_id);

/**
 * ac_build - Finalize the automaton by computing failure links.
 *
 * Must be called once after all ac_add_pattern() calls and before ac_search().
 * Calling ac_build() a second time is a no-op (returns 0).
 * Returns 0 on success, -1 on allocation failure.
 */
int ac_build(void *handle);

/**
 * ac_search - Scan a text buffer for all registered patterns.
 *
 * @handle:      Built automaton (ac_build() must have been called).
 * @text_ptr:    Pointer to the byte buffer to scan.
 * @text_len:    Length of the buffer in bytes.
 * @results_ptr: Caller-allocated array to receive matching pattern IDs.
 * @max_results: Capacity of results_ptr (in uint32_t elements).
 *
 * Returns the number of pattern IDs written into results_ptr.  If more
 * patterns match than max_results allows, excess matches are silently dropped.
 * Returns 0 if the automaton has not been built yet.
 *
 * The same pattern_id may appear multiple times if the corresponding pattern
 * matches at multiple positions, or if multiple patterns share an ID.
 */
uint32_t ac_search(void *handle,
                   const unsigned char *text_ptr, size_t text_len,
                   uint32_t *results_ptr, uint32_t max_results);

/**
 * ac_destroy - Free the automaton and all associated memory.
 *
 * After this call the handle is invalid and must not be used.
 */
void ac_destroy(void *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_AHO_CORASICK_H */
