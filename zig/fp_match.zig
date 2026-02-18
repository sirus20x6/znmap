// SIMD-accelerated OS fingerprint distance calculator.
//
// Targets the hot inner loop in FPEngine.cc's novelty_of() and the outer
// loop in osscan.cc's match_fingerprint() that scores every reference entry.
//
// The core computation is a weighted squared-distance (approximated
// Mahalanobis distance):
//
//   novelty = sqrt( sum_i( (obs[i] - ref_mean[i])^2 / variance[i] ) )
//
// When comparing one observed fingerprint against many reference entries,
// the per-reference loop is a bottleneck: thousands of float multiplies per
// reference, thousands of references in the database.
//
// This module lifts that pattern into two C-callable functions:
//
//   fp_distance_batch() — vectorized distance from one observed FP to N refs
//   fp_find_best()      — SIMD argmin over the resulting score array
//
// Both functions use @Vector (Zig's portable SIMD) so the compiler emits
// SSE2/AVX/AVX2 instructions automatically on x86-64 and NEON on aarch64.
//
// C ABI exports:
//   fp_distance_batch(observed, num_values, reference_db, num_refs, stride,
//                     scores) -> u32
//   fp_find_best(scores, num_scores) -> u32

const std = @import("std");
const math = std.math;

// ---------------------------------------------------------------------------
// SIMD configuration
// ---------------------------------------------------------------------------

// 8 f32 lanes = 256-bit AVX register.  Works equally well as 128-bit SSE2
// (compiler just uses 2 registers), so this is safe without feature checks.
const LANES = 8;
const Vec = @Vector(LANES, f32);

// A zero and positive-infinity vector, used for min reduction.
const VEC_ZERO = @as(Vec, @splat(0.0));
const VEC_INF = @as(Vec, @splat(math.inf(f32)));

// ---------------------------------------------------------------------------
// Distance kernel (per reference, vectorized over features)
// ---------------------------------------------------------------------------

// Compute the weighted sum-of-squared-differences between `obs` (length
// `n`) and `ref` (same length), scaled by `inv_var` (precomputed 1/variance).
//
// Returns:  sqrt( sum_i( (obs[i] - ref[i])^2 * inv_var[i] ) )
//
// We pass inv_var (precomputed reciprocal of variance) so the inner loop is
// only multiply/add — no division.  The caller packs the database as
// interleaved [mean, inv_var] pairs, or as separate flat arrays.
//
// This inline helper is called once per reference fingerprint.
inline fn distanceSqrtVec(
    obs: [*]const f32,
    ref: [*]const f32,
    inv_var: [*]const f32,
    n: u32,
) f32 {
    var accum: Vec = VEC_ZERO;
    var i: u32 = 0;

    // Vectorized main loop — LANES elements per iteration.
    const bulk = n - (n % LANES);
    while (i < bulk) : (i += LANES) {
        const o: Vec = obs[i..][0..LANES].*;
        const r: Vec = ref[i..][0..LANES].*;
        const iv: Vec = inv_var[i..][0..LANES].*;
        const d: Vec = o - r;
        accum += d * d * iv;
    }

    // Scalar tail for remaining elements.
    var scalar_sum: f32 = @reduce(.Add, accum);
    while (i < n) : (i += 1) {
        const d = obs[i] - ref[i];
        scalar_sum += d * d * inv_var[i];
    }

    return @sqrt(scalar_sum);
}

// ---------------------------------------------------------------------------
// Public C ABI exports
// ---------------------------------------------------------------------------

/// Compute normalized distance from one observed fingerprint to each reference
/// in a packed flat database.
///
/// Parameters:
///   observed_values  — observed FP feature vector, `num_values` f32 elements
///   num_values       — dimensionality of each fingerprint vector
///   reference_db     — packed flat array of reference data.
///                      Layout: for each reference r in [0..num_refs):
///                        reference_db[r * stride + 0 .. num_values-1]  = means
///                        reference_db[r * stride + num_values .. stride-1] = inv_variances
///                      i.e. stride >= 2 * num_values
///   num_refs         — number of reference fingerprints in database
///   stride           — elements per reference (must be >= 2*num_values)
///   scores           — output array, caller-allocated, num_refs f32 elements
///
/// Returns number of scores written (== num_refs on success, 0 on error).
///
/// Distances are raw Mahalanobis-style values; lower == closer match.
/// sqrt() is applied so values are in the same units as the feature space.
export fn fp_distance_batch(
    observed_values: [*]const f32,
    num_values: u32,
    reference_db: [*]const f32,
    num_refs: u32,
    stride: u32,
    scores: [*]f32,
) callconv(.c) u32 {
    if (num_values == 0 or num_refs == 0 or stride < 2 * num_values) return 0;

    const means_offset: u32 = 0;
    const inv_var_offset: u32 = num_values;

    var r: u32 = 0;
    while (r < num_refs) : (r += 1) {
        const base = reference_db + @as(usize, r) * @as(usize, stride);
        const ref_means = base + means_offset;
        const ref_inv_var = base + inv_var_offset;
        scores[r] = distanceSqrtVec(observed_values, ref_means, ref_inv_var, num_values);
    }

    return num_refs;
}

/// Find the index of the lowest (best / closest) score using SIMD min-reduction.
///
/// Parameters:
///   scores      — array of f32 distance scores (from fp_distance_batch)
///   num_scores  — number of elements
///
/// Returns index of the minimum element.
/// If num_scores == 0, returns 0.
export fn fp_find_best(
    scores: [*]const f32,
    num_scores: u32,
) callconv(.c) u32 {
    if (num_scores == 0) return 0;

    // --- Phase 1: SIMD min-scan to find the minimum value ---
    var min_vec: Vec = VEC_INF;
    var i: u32 = 0;
    const bulk = num_scores - (num_scores % LANES);

    while (i < bulk) : (i += LANES) {
        const chunk: Vec = scores[i..][0..LANES].*;
        min_vec = @min(min_vec, chunk);
    }

    var global_min: f32 = @reduce(.Min, min_vec);

    // Scalar tail
    while (i < num_scores) : (i += 1) {
        if (scores[i] < global_min) global_min = scores[i];
    }

    // --- Phase 2: linear scan to find first index with that minimum ---
    // (SIMD comparison to find the position)
    i = 0;
    const target: Vec = @as(Vec, @splat(global_min));

    while (i + LANES <= num_scores) : (i += LANES) {
        const chunk: Vec = scores[i..][0..LANES].*;
        const mask = chunk == target;
        // Check if any lane matched
        const any = @reduce(.Or, mask);
        if (any) {
            // Find the first lane that matched
            inline for (0..LANES) |lane| {
                if (mask[lane]) return i + @as(u32, lane);
            }
        }
    }

    // Scalar tail
    while (i < num_scores) : (i += 1) {
        if (scores[i] == global_min) return i;
    }

    return 0; // unreachable in practice
}

// ---------------------------------------------------------------------------
// Tests (run with `zig test zig/fp_match.zig`)
// ---------------------------------------------------------------------------

test "fp_find_best basic" {
    var scores = [_]f32{ 3.0, 1.5, 4.0, 0.5, 2.0 };
    const best = fp_find_best(&scores, scores.len);
    try std.testing.expectEqual(@as(u32, 3), best);
}

test "fp_find_best single" {
    var scores = [_]f32{42.0};
    try std.testing.expectEqual(@as(u32, 0), fp_find_best(&scores, 1));
}

test "fp_find_best zero" {
    var scores = [_]f32{1.0};
    try std.testing.expectEqual(@as(u32, 0), fp_find_best(&scores, 0));
}

test "fp_distance_batch correctness" {
    // observed: [1, 0, 0, 0, 0, 0, 0, 0]  (8 features)
    // ref 0: mean=[1,0,0,0,0,0,0,0], inv_var=[1,1,1,1,1,1,1,1]  -> distance=0
    // ref 1: mean=[0,0,0,0,0,0,0,0], inv_var=[1,1,1,1,1,1,1,1]  -> distance=1
    const num_values: u32 = 8;
    const stride: u32 = 16; // 8 means + 8 inv_vars

    var db = [_]f32{
        // ref 0: means
        1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        // ref 0: inv_vars (all 1.0 -> variance=1.0)
        1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
        // ref 1: means
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        // ref 1: inv_vars
        1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    };

    var obs = [_]f32{ 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };
    var scores = [_]f32{ 0.0, 0.0 };

    const n = fp_distance_batch(&obs, num_values, &db, 2, stride, &scores);
    try std.testing.expectEqual(@as(u32, 2), n);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), scores[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 1.0), scores[1], 1e-6);

    const best = fp_find_best(&scores, 2);
    try std.testing.expectEqual(@as(u32, 0), best);
}

test "fp_distance_batch error cases" {
    var obs = [_]f32{1.0};
    var db = [_]f32{ 1.0, 1.0 };
    var scores = [_]f32{0.0};

    // stride < 2*num_values -> error
    const n = fp_distance_batch(&obs, 1, &db, 1, 1, &scores);
    try std.testing.expectEqual(@as(u32, 0), n);
}

test "fp_distance_batch non-uniform variance" {
    // 4 features: obs=[2,2,2,2], ref_mean=[0,0,0,0]
    // inv_var=[1,0.5,0.25,0.1]
    // sum = 4*1 + 4*0.5 + 4*0.25 + 4*0.1 = 4+2+1+0.4 = 7.4
    // distance = sqrt(7.4)
    const num_values: u32 = 4;
    const stride: u32 = 8;

    var db = [_]f32{
        0.0,  0.0,  0.0,  0.0,
        1.0,  0.5,  0.25, 0.1,
    };
    var obs = [_]f32{ 2.0, 2.0, 2.0, 2.0 };
    var scores = [_]f32{0.0};

    const n = fp_distance_batch(&obs, num_values, &db, 1, stride, &scores);
    try std.testing.expectEqual(@as(u32, 1), n);
    const expected = @sqrt(@as(f32, 7.4));
    try std.testing.expectApproxEqAbs(expected, scores[0], 1e-5);
}
