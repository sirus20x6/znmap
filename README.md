# znmap

A performance-focused fork of [Nmap](https://nmap.org) with Zig SIMD acceleration, modern C++23 codebase, and a Meson build system.

## What's Different

znmap replaces CPU-intensive C hot paths with Zig SIMD implementations, modernizes the C++ codebase to C++23, and strips ~670K lines of legacy autoconf/bundled library code. The result is a faster, leaner scanner that links against system libraries and builds with Meson.

### Zig SIMD Modules (12)

| Module | Purpose |
|---|---|
| `zig/checksum.zig` | SIMD IP checksum |
| `zig/probe_filter.zig` | Service probe regex pre-filter |
| `zig/arena.zig` | Bump allocator for scan-lifetime memory |
| `zig/portstate.zig` | 3-bit-per-port bitset for port state storage |
| `zig/aho_corasick.zig` | Aho-Corasick automaton with sparse goto tables |
| `zig/dns_pool.zig` | DNS resolver pool with TCP fallback |
| `zig/fp_match.zig` | SIMD OS fingerprint matcher |
| `zig/pkt_builder.zig` | IPv4/IPv6 packet construction |
| `zig/pkt_parse.zig` | SIMD TCP/UDP header extraction + batch validation |
| `zig/ip_range.zig` | SIMD CIDR range expansion + batch containment check |
| `zig/banner_match.zig` | SIMD service banner pre-filter (before PCRE2 fallback) |
| `zig/pkt_mmap.zig` | Zero-copy PACKET_MMAP ring buffer for packet capture |

### Performance Enhancements

- **io_uring nsock engine** -- highest-priority async I/O backend using liburing for batched submission
- **PACKET_MMAP** -- zero-copy packet capture via kernel shared-memory ring buffer
- **LTO** -- link-time optimization enabled by default (cross-TU inlining, dead code elimination)
- **PGO** -- profile-guided optimization build script (`./build_pgo.sh`)
- **Async PostgreSQL writes** -- background writer thread for scan-to-database output
- **Batch PG inserts** -- multi-row VALUES for port insertion
- **Per-host congestion control** -- adaptive cwnd per target
- **Global rate-limit backoff** -- detects ISP/firewall rate limiting, backs off automatically
- **Pipeline threading** -- parallelized service version detection

### Scan Features

- **PostgreSQL live output** (`--pg-dsn`) -- stream scan results directly to PostgreSQL
- **Port-level dedup** (`--pg-skip-recent`) -- skip re-inserting unchanged ports from recent scans
- **Live progress tracking** -- query `SELECT hosts_done FROM nmap_live.runs WHERE end_time IS NULL`
- **HTTP/2 ALPN detection** -- identifies h2 support during SSL service probes
- **Partial results on host timeout** -- report what was found before timeout
- **Multicast discovery** (`--multicast-discovery`) -- IPv6 link-local neighbor discovery
- **Config file** (`~/.nmaprc` / `--no-nmaprc`) -- persistent default options

### Codebase Modernization

- **C++23** -- `std::format`, `std::print`, `std::span`, `std::ranges`, `std::optional`, `unique_ptr`, structured bindings, if-init
- **Meson build** -- replaced ~260K lines of autoconf/automake with a 280-line `meson.build`
- **System libraries** -- links against system libpcap, openssl, libssh2, zlib, pcre2, lua5.4, libpq, liburing
- **Removed bundled copies** of libpcap, libpcre, libssh2, libz, liblua (~320K lines)
- **Removed** ncat, nping, Windows/macOS platform code, legacy todo/ docs

## Requirements

- Linux (x86_64)
- GCC 15+ or Clang 19+ (C++23 support)
- Zig 0.15+
- System packages: `libpcap`, `openssl`, `libssh2`, `zlib`, `pcre2`, `lua5.4`, `libpq`, `liburing`

### Arch Linux

```bash
pacman -S libpcap openssl libssh2 zlib pcre2 lua54 postgresql-libs liburing zig meson
```

### Debian/Ubuntu

```bash
apt install libpcap-dev libssl-dev libssh2-1-dev zlib1g-dev libpcre2-dev liblua5.4-dev libpq-dev liburing-dev meson
# Install zig 0.15+ separately from https://ziglang.org
```

## Building

### Standard build

```bash
meson setup builddir
meson compile -C builddir
```

### Release build with LTO (default)

```bash
meson setup builddir --buildtype=release
meson compile -C builddir
```

### Profile-guided optimization

```bash
./build_pgo.sh              # builds, trains on localhost scan, rebuilds
./build_pgo.sh 10.0.0.0/24  # train on a real target range
```

### Install

```bash
sudo cp builddir/znmap /usr/local/bin/znmap
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/znmap
```

## Usage

znmap is command-compatible with nmap:

```bash
# Basic scan
znmap -sS -p 1-1024 target

# Service detection with HTTP/2
znmap -sV -p 443 target

# Scan to PostgreSQL
znmap -sS -sU -p 22,80,443 --pg-dsn 'postgresql:///security' target

# Skip recently-scanned hosts (default: 90 days)
znmap --pg-dsn '...' --pg-skip-recent 7776000 -iL targets.txt

# Use config file defaults
echo '--min-rate 5000' >> ~/.nmaprc
znmap -sS target
```

### PostgreSQL Schema

```bash
psql postgresql:///security < pg_schema.sql
```

Monitor scan progress:

```sql
SELECT id, hosts_done, hosts_total, now() - start_time AS elapsed
FROM nmap_live.runs WHERE end_time IS NULL;
```

## Architecture

```
znmap
 |-- meson.build              # Build system (280 lines, replaces autoconf)
 |-- zig/                     # 12 SIMD modules (.zig -> .o, linked at final step)
 |-- nsock/src/               # Async I/O library (epoll, io_uring, poll, select)
 |-- nbase/                   # Base utility library
 |-- libnetutil/              # Network packet classes
 |-- libdnet-stripped/        # Bundled libdnet (Linux network interface access)
 |-- liblinear/               # Bundled liblinear (OS fingerprint classification)
 |-- pg_output.cc             # Async PostgreSQL output with background writer thread
 |-- scan_engine.cc           # Core scan engine with rate-limit backoff
 |-- service_scan.cc          # Service/version detection with ALPN
 `-- build_pgo.sh             # Profile-guided optimization build script
```

## License

znmap is based on Nmap, which is released under the [Nmap Public Source License](https://nmap.org/npsl/). See [LICENSE](LICENSE) for details.
