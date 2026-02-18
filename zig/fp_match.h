/*
 * fp_match.h -- C declarations for the Zig SIMD OS fingerprint distance
 * calculator (zig/fp_match.zig).
 *
 * Two functions are exported:
 *
 *   fp_distance_batch  — compute distance from one observed fingerprint to
 *                        every reference in a packed flat database.
 *
 *   fp_find_best       — SIMD argmin over the resulting score array.
 *
 * Database layout (reference_db):
 *   For each reference r in [0 .. num_refs):
 *     reference_db[r * stride + 0           .. num_values-1]  = means[]
 *     reference_db[r * stride + num_values  .. stride-1]      = inv_variances[]
 *   where stride >= 2 * num_values.
 *
 *   inv_variances[i] = 1.0f / variance[i]  (caller precomputes to avoid
 *   division in the hot inner loop).  When variance is zero (or the
 *   FPModel default 0.01), pass 1.0f/0.01f = 100.0f.
 *
 * Scores are raw Mahalanobis-style values; lower == closer match.
 */

#ifndef ZIG_FP_MATCH_H
#define ZIG_FP_MATCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * fp_distance_batch - batch distance from one observed FP to num_refs refs.
 *
 * @param observed_values  Feature vector of the observed fingerprint (f32[]).
 * @param num_values       Dimensionality: number of features per fingerprint.
 * @param reference_db     Packed flat database (see layout above).
 * @param num_refs         Number of reference fingerprints.
 * @param stride           Elements per reference entry (>= 2 * num_values).
 * @param scores           Caller-allocated output array of num_refs floats.
 * @return Number of scores written, or 0 on invalid arguments.
 */
uint32_t fp_distance_batch(
    const float *observed_values,
    uint32_t     num_values,
    const float *reference_db,
    uint32_t     num_refs,
    uint32_t     stride,
    float       *scores
);

/**
 * fp_find_best - return index of the minimum (best match) score.
 *
 * Uses SIMD min-reduction for speed.  Ties are broken by returning
 * the first (lowest-index) occurrence.
 *
 * @param scores      Array of float scores from fp_distance_batch.
 * @param num_scores  Number of elements.
 * @return Index of the minimum element, or 0 if num_scores == 0.
 */
uint32_t fp_find_best(
    const float *scores,
    uint32_t     num_scores
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZIG_FP_MATCH_H */
