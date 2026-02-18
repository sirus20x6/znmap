#!/usr/bin/env bash
# Nmap Zig Performance Enhancement — Benchmark Suite
# All scans against localhost/loopback for reproducibility.
# Runs privileged scans if root, falls back to connect scans if not.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NMAP="${SCRIPT_DIR}/../nmap"
OUTFILE="${1:-${SCRIPT_DIR}/results.txt}"
ITERATIONS="${2:-3}"

if [[ ! -x "$NMAP" ]]; then
    echo "ERROR: nmap binary not found at $NMAP — run 'make' first." >&2
    exit 1
fi

IS_ROOT=0
[[ $EUID -eq 0 ]] && IS_ROOT=1

{
echo "=== Nmap Benchmark Suite ==="
echo "Date: $(date -Iseconds)"
echo "Nmap: $($NMAP --version | head -1)"
echo "Kernel: $(uname -r)"
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "Iterations per test: $ITERATIONS"
echo "Running as root: $IS_ROOT"
echo ""

run_bench() {
    local name="$1"
    shift
    echo "--- $name ---"
    echo "Command: $*"

    for i in $(seq 1 "$ITERATIONS"); do
        local start_ns end_ns elapsed
        start_ns=$(date +%s%N)
        "$@" >/dev/null 2>&1 || true
        end_ns=$(date +%s%N)
        elapsed=$(echo "scale=4; ($end_ns - $start_ns) / 1000000000" | bc)
        echo "  Run $i: wall=${elapsed}s"
    done
    echo ""
}

if [[ $IS_ROOT -eq 1 ]]; then
    run_bench "SYN scan (1000 ports)" "$NMAP" -sS -p1-1000 127.0.0.1
    run_bench "Service version scan" "$NMAP" -sV -p22,80,443 127.0.0.1
    run_bench "Full scan (10000 ports)" "$NMAP" -sS -sV -O -p1-10000 127.0.0.1
else
    echo "NOTE: Running unprivileged — using connect scans (-sT) instead of SYN scans (-sS)"
    echo ""
    run_bench "Connect scan (1000 ports)" "$NMAP" -sT -p1-1000 127.0.0.1
    run_bench "Service version scan" "$NMAP" -sV -p22,80,443 127.0.0.1
    run_bench "Full connect scan (10000 ports)" "$NMAP" -sT -sV -p1-10000 127.0.0.1
fi

# Checksum microbenchmark (doesn't need root)
CKSUM_BENCH="${SCRIPT_DIR}/checksum_bench"
if [[ -x "$CKSUM_BENCH" ]]; then
    run_bench "Checksum microbenchmark" "$CKSUM_BENCH"
else
    echo "--- Checksum microbenchmark ---"
    echo "  SKIPPED: $CKSUM_BENCH not found"
    echo ""
fi

echo "=== Benchmark complete ==="
} 2>&1 | tee "$OUTFILE"

echo "Results saved to: $OUTFILE"
