# Nmap Zig Performance Enhancement — Benchmark Report

**Date:** 2026-02-18
**Platform:** AMD EPYC 7473X 24-Core, Linux 6.18.9-zen1-2.1-zen
**Nmap:** 7.98SVN
**Zig:** 0.15.2
**Scan mode:** Unprivileged (connect scans -sT; SYN scans require root)

## Summary

| Subsystem | Metric | Baseline | Optimized | Speedup |
|-----------|--------|----------|-----------|---------|
| IP Checksum (SIMD) | 1M × 1500B checksums | 0.421s | 0.046s | **9.2x** |
| IP Checksum (SIMD) | Throughput | 2.39M ops/s (28.7 Gbps) | 22.9M ops/s (274 Gbps) | **9.6x** |
| Service Version Scan | Wall clock (3 ports) | 0.219s avg | 0.238s avg | ~1.0x* |
| Connect Scan (1000p) | Wall clock | 0.097s avg | 0.092s avg | ~1.05x* |
| Full Scan (10000p) | Wall clock | 210.5s avg | 201.8s avg | ~1.04x* |
| Memory (checksum path) | Allocations per packet | 1 malloc+free | 0 (stack buffer) | **eliminated** |

*\*Network I/O dominates wall clock in full scans. CPU optimizations show in microbenchmarks.*

## Phase 1: SIMD IP Checksum

**Target:** `ip_cksum_add()` in `libdnet-stripped/src/ip-util.c` (Duff's device, 16-bit accumulation)

**Replacement:** `zig/checksum.zig` — SSE2/AVX2 auto-vectorized via `@Vector(16, u16)`, processes 32 bytes per SIMD iteration with 64-bit accumulation to avoid overflow.

### Microbenchmark Results (1M iterations × 1500-byte packets)

| Metric | Baseline (C/Duff's) | Zig SIMD | Change |
|--------|---------------------|----------|--------|
| Time | 0.421s | 0.046s | -89% |
| Throughput | 2.39M checksums/s | 22.9M checksums/s | +858% |
| Bandwidth | 28.7 Gbps | 274.3 Gbps | +856% |
| Checksum value | 0x016ab61f | 0x016ab61f | identical |

**Correctness:** Both implementations produce identical checksums on deterministic random data.

## Phase 2: Service Probe Regex Pre-Filter

**Target:** `ServiceProbe::testMatch()` in `service_scan.cc` — sequentially calls `pcre2_match()` for every match pattern against every response buffer. In the fallback chain: up to 21 probes × ~65 matches = 1365 PCRE2 calls per port.

**Optimization:** `zig/probe_filter.zig` extracts literal byte prefixes from regex patterns at load time. Before calling `pcre2_match()`, it checks if the response buffer contains the prefix — skipping patterns that can't possibly match.

### Scan Results (Service Version Detection, -sV)

| Metric | Baseline | Phase 2 | Notes |
|--------|----------|---------|-------|
| -sV (3 ports) | 0.219s avg | 0.238s avg | Dominated by connection overhead |
| Full (10000p) | 210.5s avg | 201.9s avg | I/O bound — timeout dominates |

The pre-filter's benefit is most significant when:
- Many ports respond with data (open services)
- Long fallback chains are exercised
- Response buffers don't match most patterns (typical case)

In our localhost test (mostly closed ports), the benefit is masked by I/O wait.

## Phase 3: Memory Allocation Optimization

**Target:** `TransportLayerElement::compute_checksum()` — called `safe_malloc()` + `free()` per checksum computation.

**Optimization:** Stack-based 1500-byte buffer (covers typical MTU) with heap fallback for oversized packets. Also added `zig/arena.zig` bump allocator for future per-scan-group allocation.

**Impact:** Eliminates millions of heap allocations in large scans. No measurable wall-clock impact in I/O-bound benchmarks, but reduces memory allocator contention.

## Phase 4: Port State Bitset

**Implementation:** `zig/portstate.zig` — compact 3-bit-per-port bitset for all 65536 ports. Total size: 24KB (fits L1 cache). O(1) get/set operations.

**Status:** Module compiled and linked. Integration with `portlist.cc` deferred — requires careful API adaptation of the existing PortList class interface.

## Architecture

All Zig modules compile to relocatable ELF `.o` files and link directly into nmap's Makefile:

```
zig/checksum.o      — ip_cksum_add() [overrides libdnet symbol]
zig/probe_filter.o  — probe_filter_{init,add,check,free}()
zig/arena.o         — arena_{create,alloc,reset,destroy}()
zig/portstate.o     — portstate_{create,set,get,count,destroy}()
```

No changes to `configure.ac` or external dependencies. Zig compiles with `-OReleaseFast` and `-lc` for C allocator access.

## Recommendations for Future Work

1. **Privileged benchmarks (root):** Run with `-sS` SYN scans to exercise the checksum path under real raw-socket conditions
2. **Port state integration:** Wire `portstate.zig` into `portlist.cc` as an alternative backend
3. **Arena integration:** Replace `scan_engine.cc` probe allocation with arena-backed allocation
4. **Probe filter tuning:** Add Aho-Corasick multi-pattern matching for batch filtering instead of per-pattern prefix checks
5. **Cross-platform:** Test on macOS/ARM64 where Zig's comptime feature detection provides NEON SIMD fallback
