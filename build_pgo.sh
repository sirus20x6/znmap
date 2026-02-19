#!/usr/bin/env bash
set -euo pipefail
#
# build_pgo.sh — Profile-Guided Optimization build for nmap
#
# Two-stage build:
#   1. Instrument: compile with -fprofile-generate, run a training scan
#   2. Optimize:   recompile with -fprofile-use using collected profile data
#
# Usage: ./build_pgo.sh [training-target]
#   training-target defaults to 127.0.0.1

TRAINING_TARGET="${1:-127.0.0.1}"
SRCDIR="$(cd "$(dirname "$0")" && pwd)"
PROFDIR="$SRCDIR/builddir-pgo-profile"
BUILDDIR_GEN="$SRCDIR/builddir-pgo-gen"
BUILDDIR_USE="$SRCDIR/builddir-pgo"

echo "=== Stage 1: Instrumented build ==="
rm -rf "$BUILDDIR_GEN" "$PROFDIR"
mkdir -p "$PROFDIR"

# Configure with profile generation
meson setup "$BUILDDIR_GEN" "$SRCDIR" \
  --buildtype=release \
  -Dc_args="-fprofile-generate=$PROFDIR" \
  -Dcpp_args="-fprofile-generate=$PROFDIR" \
  -Dc_link_args="-fprofile-generate=$PROFDIR" \
  -Dcpp_link_args="-fprofile-generate=$PROFDIR"

meson compile -C "$BUILDDIR_GEN"

echo "=== Stage 1: Training scan ==="
# Run a representative training workload
"$BUILDDIR_GEN/nmap" -sT -sV -O \
  -p 1-1024,3306,5432,6379,8080,8443,9090,27017 \
  --min-rate 1000 \
  --max-retries 1 \
  "$TRAINING_TARGET" || true

# Also run a UDP + script scan for coverage of those paths
"$BUILDDIR_GEN/nmap" -sT \
  -p 80,443 \
  --script=http-headers,ssl-cert \
  "$TRAINING_TARGET" || true

echo "=== Stage 2: Optimized build ==="
rm -rf "$BUILDDIR_USE"

# Configure with profile use
meson setup "$BUILDDIR_USE" "$SRCDIR" \
  --buildtype=release \
  -Dc_args="-fprofile-use=$PROFDIR -fprofile-correction" \
  -Dcpp_args="-fprofile-use=$PROFDIR -fprofile-correction" \
  -Dc_link_args="-fprofile-use=$PROFDIR" \
  -Dcpp_link_args="-fprofile-use=$PROFDIR"

meson compile -C "$BUILDDIR_USE"

echo ""
echo "=== PGO build complete ==="
echo "Binary: $BUILDDIR_USE/nmap"
ls -lh "$BUILDDIR_USE/nmap"

# Compare sizes
if [ -f "$SRCDIR/builddir/nmap" ]; then
  NORMAL_SIZE=$(stat -c%s "$SRCDIR/builddir/nmap")
  PGO_SIZE=$(stat -c%s "$BUILDDIR_USE/nmap")
  echo "Normal build: $(numfmt --to=iec $NORMAL_SIZE)"
  echo "PGO build:    $(numfmt --to=iec $PGO_SIZE)"
fi

echo ""
echo "To install: sudo cp $BUILDDIR_USE/nmap /usr/local/bin/nmap"
echo "To set capabilities: sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/nmap"
