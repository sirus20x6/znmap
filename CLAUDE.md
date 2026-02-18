# Nmap Zig Performance Enhancement

## Project
Incremental replacement of CPU-intensive C hot paths in nmap with Zig implementations for measurable performance gains. Zig compiles to `.o`/`.a` with C ABI and links into the existing Makefile — no big-bang rewrite.

## Zig Version
0.15.2 (installed via pacman)

## Build Strategy
- Zig source files live in `zig/` subdirectory at repo root
- Each Zig module compiles to a `.o` via `zig build-obj`
- Object files link into nmap's existing Makefile at the final link step
- Every Zig function must `export` C-compatible symbols matching the originals

## Scope
- IP checksum SIMD optimization (Phase 1)
- Service probe regex pre-filter (Phase 2)
- Arena memory allocator (Phase 3)
- Port state bitset optimization (Phase 4)
- NO JSON output or test framework work in scope

## Git Workflow
- One branch per phase: `phase/N-name`
- Sub-agents: up to 5 per phase batch

## Benchmarks
- All benchmark data saved to `benchmarks/` directory as `.txt` files
- Benchmark script: `benchmarks/run_bench.sh`
- All scans run against localhost/loopback for reproducibility

## Key Files
| File | Role |
|---|---|
| `libdnet-stripped/src/ip-util.c:169-217` | Current checksum (Phase 1) |
| `service_scan.cc:521-574` | testMatch() PCRE2 loop (Phase 2) |
| `libnetutil/TransportLayerElement.cc:96-127` | Malloc-per-checksum (Phase 3) |
| `scan_engine.cc` | Probe list allocation (Phase 3) |
| `portlist.cc` | Port state storage (Phase 4) |
| `Makefile.in:115,128-132` | Object list and link command |
