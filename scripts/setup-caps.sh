#!/usr/bin/env bash
# Grant nmap raw socket capabilities so it can run SYN scans, OS detection,
# and other privileged operations without sudo.
#
# Usage: sudo ./scripts/setup-caps.sh [/path/to/nmap]
#
# This sets cap_net_raw and cap_net_admin on the nmap binary.
# Zenmap (a Python wrapper) inherits these when it invokes nmap.
set -euo pipefail

NMAP_BIN="${1:-}"

if [[ -z "$NMAP_BIN" ]]; then
    # Auto-detect: prefer the dev build, fall back to system
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [[ -x "$SCRIPT_DIR/../nmap" ]]; then
        NMAP_BIN="$SCRIPT_DIR/../nmap"
    elif [[ -x /usr/bin/nmap ]]; then
        NMAP_BIN="/usr/bin/nmap"
    else
        echo "Usage: sudo $0 /path/to/nmap" >&2
        exit 1
    fi
fi

NMAP_BIN="$(realpath "$NMAP_BIN")"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must be run as root (sudo)." >&2
    exit 1
fi

if [[ ! -x "$NMAP_BIN" ]]; then
    echo "ERROR: $NMAP_BIN is not an executable." >&2
    exit 1
fi

echo "Setting capabilities on: $NMAP_BIN"
setcap 'cap_net_raw,cap_net_admin+eip' "$NMAP_BIN"
echo "Done. Verifying..."
getcap "$NMAP_BIN"
echo ""
echo "nmap can now run privileged scans (-sS, -O, etc.) without sudo."
echo "Zenmap will also work without sudo since it invokes nmap."
