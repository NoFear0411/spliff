# spliff

**eBPF-based SSL/TLS Traffic Sniffer**

[![Version](https://img.shields.io/badge/version-0.9.8-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![C Standard](https://img.shields.io/badge/C-C23-orange.svg)](CMakeLists.txt)

Capture and inspect decrypted HTTPS traffic in real-time without MITM proxies. spliff uses eBPF uprobes to hook SSL/TLS library functions, intercepting data after decryption but before it reaches the application.

**The project is entirely coded by Claude Opus and the goal is to build a full EDR/XDR open-source agent/platform with the help of AI**

## Features

### SSL/TLS Library Support
- **OpenSSL**: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`, `SSL_connect`
- **BoringSSL** ⚠️: Experimental support for Chrome/Chromium/Brave/ (see [Known Limitations](#known-limitations))
- **GnuTLS**: `gnutls_record_recv`, `gnutls_record_send`, `gnutls_handshake`
- **NSS/NSPR**: `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send`, `SSL_ForceHandshake`
- **WolfSSL**: `wolfSSL_read`, `wolfSSL_write`

### HTTP Protocol Support
| Protocol | Parser  | Features |
|----------|---------|----------|
| HTTP/1.1 | llhttp  | Full header parsing, chunked transfer encoding, body aggregation, request-response correlation |
| HTTP/2   | nghttp2 | Frame parsing, HPACK decompression, stream tracking, mid-stream recovery, multiplexed request/response correlation |

### Dynamic Flow Pool Architecture (v0.9.8)
- **On-Demand Allocation**: Flow contexts allocated via jemalloc as needed (no pre-allocated pool)
- **Incremental Hash Tables**: Cookie and shadow indexes grow automatically at 75% load factor
- **Zero Latency Spikes**: Incremental migration (8 entries/op) avoids stop-the-world rehashing
- **Generation Counters**: Safe pointer validation across worker threads (catches stale/reused flows)
- **Inflight Event Counting**: Reference counting prevents use-after-free during flow cleanup
- **Deferred Free**: 2-second grace period ensures safe memory reclamation

### Centralized Session Statistics (v0.9.7)
- **Unified Shutdown Report**: All subsystem metrics collected and displayed from one place
- **Production-Grade Metrics**: Full pipeline visibility in every build (no debug flag required)
- **Per-Worker Breakdown**: Individual event counts, retry stats, CPU efficiency
- **Flow Pool Analytics**: Active count, peak, cookie/shadow index hit rates, promotion rate
- **XDP Classification**: Packet counts, flow classification, sockops, correlation success rate
- **SSL Probe Counters**: Total SSL_read/SSL_write interceptions

<details>
<summary>Sample Session Statistics Output</summary>

```
============================================
           Session Statistics
============================================

  Application Layer (SSL/TLS)
  ----------------------------------------------
  Events:      50 captured -> 50 processed
  Output:      18 messages (1.8 KB)

  Workers (16)
  ----------------------------------------------
  Worker  1: 3 events
  Worker  2: 6 events
  Worker  3: 2 events
  Worker  7: 7 events
  Worker  9: 8 events
  Worker 10: 5 events
  Worker 12: 4 events
  Worker 14: 3 events
  Worker 15: 12 events
  CPU: Good (NAPI-style, 4338 sleep cycles)

  Flow Pool
  ----------------------------------------------
  Active:      5 flows, peak 6
  Throughput:  12 allocs, 7 frees
  Cookie index: 1 entries, 36 hits (81.8%), 8 misses
  Shadow index: 0 entries, 19 hits, 2 promotions
  Promotion:    16.7% of flows got socket_cookie

  Network Layer (XDP)
  ----------------------------------------------
  Packets:     124 processed (91 TCP)
  Connections: 8 tracked, 8 classified
  Correlation: 100.0% socket cookie success
  Classified:  8 flows
  Ambiguous:   12 (deeper inspection needed)
  Terminated:  7 (FIN/RST)
  Cache hits:  0 (fast-path gatekeeper)
  Cookie miss: 0 (correlation gaps)

  Sockops (cookie caching)
  ----------------------------------------------
  Events:  8 (active: 8, passive: 0)
  Cleanup: 0

  SSL Probes
  ----------------------------------------------
  SSL_read/SSL_write intercepted: 50

============================================
```
</details>

### Embedded BPF Skeleton (v0.9.6)
- **Single Binary Deployment**: BPF bytecode embedded directly via `bpftool gen skeleton`
- **No External Files**: No separate .bpf.o file needed - binary is self-contained
- **Strip-Safe**: Debug symbols can be removed without breaking BPF loading
- **Tamper-Resistant**: Embedded bytecode cannot be modified separately

### Modular Protocol Architecture (v0.9.5+)
- **Unified Protocol Entry Points**: `http1_try_process_event()` and `http2_try_process_event()`
- **Vectorscan Protocol Detection**: O(n) NFA-based pattern matching for HTTP identification
- **Clean Orchestration**: main.c reduced to ~50 lines of protocol routing logic
- **Enterprise-Grade Separation**: Each protocol handler returns `true` if processed, enabling fallback chain

### Flow Pool Architecture (v0.9.3+, dynamic since v0.9.8)
- **Dynamic Flow Context**: On-demand allocation via jemalloc with cache-line alignment
- **Zero-Copy Correlation**: Socket cookie index + shadow index (pid, ssl_ctx) for O(1) lookup
- **Incremental Resizing**: Hash tables grow without latency spikes (8 entries migrated per operation)
- **Per-Flow HTTP/2 Streams**: 64-stream pool per flow with O(1) free-list allocation
- **Worker Affinity**: Atomic CAS claim ensures single-writer guarantee per flow
- **Generation + Inflight Safety**: Stale pointer detection and reference-counted deferred free
- **HPACK Corruption Detection**: Connection-fatal flag per RFC 7540 Section 4.3
- **Ghost Stream Reaping**: 10-second timeout for idle stream cleanup
- **Pool Statistics**: Centralized shutdown report with active count, peak, index hit rates
- **BPF Map Warm-up**: Direct iteration of BPF flow_states for accurate pre-existing connection correlation

### Dynamic Process Monitoring (v0.9.0+)
- **EDR-Style Process Scanning**: Discovers SSL libraries in running processes via `/proc/PID/maps`
- **Runtime Browser Detection**: Detects Chrome/Chromium/Brave/ at startup (experimental)
- **BoringSSL Binary Scanning**: Heuristic function offset detection for stripped binaries
- **Process Lifecycle Events**: BPF tracepoints for `sched_process_exec` and `sched_process_fork`
- **Deduplication**: Path-based caching prevents duplicate probe attachment

### XDP Packet-Level Tracking (v0.8.0+)
- **High-Performance Flow Tracking**: XDP programs at network interface level
- **Auto-Attach**: Discovers and attaches to all suitable interfaces (physical/virtual)
- **Protocol Detection**: TLS, HTTP/2, HTTP/1.x classification at packet level
- **sock_ops Cookie Caching**: "Golden Thread" correlation between packets and SSL sessions
- **Dual Warm-up Strategy** (v0.9.3):
  - BPF map warm-up: iterates `flow_states` for real socket cookies
  - Netlink warm-up: seeds `flow_cookie_map` via SOCK_DIAG for XDP visibility
- **XDP Statistics**: Full session metrics (packets, flows, classification, sockops, gatekeeper hits)

### BPF-Level Filtering (v0.7.0+)
- **Socket Family Detection**: Filters AF_UNIX (IPC) at kernel level
- **CO-RE BTF Access**: Walks `task_struct → files_struct → socket → sock → skc_family`
- **SSL Session Tracking**: Maps SSL* to file descriptors for socket lookup
- **NSS SSL Verification**: Filters non-SSL NSPR file descriptors

### Multi-Threaded Architecture (v0.6.0+)
- **Lock-Free Event Processing**: Dispatcher → Worker threads with SPSC ring buffers
- **Connection Affinity**: Same (pid, ssl_ctx) always routes to same worker
- **Per-Worker State**: Isolated HTTP/2 sessions, ALPN cache, pending bodies
- **Serialized Output**: Dedicated output thread prevents interleaved lines
- **Adaptive Wait**: spin → yield → eventfd for efficient CPU usage

### Advanced Capabilities
- **ALPN Detection**: Hooks ALPN negotiation for definitive HTTP/1.1 vs HTTP/2 detection
- **ALPN Display**: Shows negotiated protocol (e.g., `ALPN:h2`, `ALPN:http/1.1`)
- **Request-Response Correlation**: Responses show associated request URL (both HTTP/1.1 and HTTP/2)
- **Body Decompression**: gzip, deflate, zstd, brotli (automatic)
- **File Signature Detection**: 50+ formats via magic bytes (images, video, audio, archives, documents)
- **TLS Handshake Tracking**: Optional display of handshake events with latency
- **Dynamic Library Discovery**: Finds SSL libraries via `/proc/PID/maps` (supports Flatpak/Snap)
- **Process Tree Filtering**: Filter by PID, parent PID, or process name

## Requirements

- Linux kernel 5.x+ with BTF support
- Root privileges (for eBPF)
- clang (for BPF compilation)

### Dependencies

| Library | Purpose | Package (Fedora) | Package (Debian/Ubuntu) |
|---------|---------|------------------|-------------------------|
| libbpf | eBPF CO-RE loader | libbpf-devel | libbpf-dev |
| libelf | ELF parsing | elfutils-libelf-devel | libelf-dev |
| zlib-ng | SIMD gzip decompression | zlib-ng-devel | (build from source) |
| llhttp | HTTP/1.1 parsing | llhttp-devel | libllhttp-dev |
| nghttp2 | HTTP/2 parsing | nghttp2-devel | libnghttp2-dev |
| ck | Lock-free data structures | ck-devel | libck-dev |
| libxdp | XDP program loading | libxdp-devel | libxdp-dev |
| liburcu | Read-Copy-Update | userspace-rcu-devel | liburcu-dev |
| jemalloc | Memory allocator | jemalloc-devel | libjemalloc-dev |
| vectorscan | O(n) protocol detection | vectorscan-devel | (build from source) |
| pcre2 | Pattern matching fallback | pcre2-devel | libpcre2-dev |
| zstd | zstd decompression | libzstd-devel | libzstd-dev |
| brotli | brotli decompression | brotli-devel | libbrotli-dev |

### Quick Install (Fedora)
```bash
sudo dnf install libbpf-devel elfutils-libelf-devel zlib-ng-devel \
    llhttp-devel nghttp2-devel ck-devel libxdp-devel userspace-rcu-devel \
    jemalloc-devel vectorscan-devel pcre2-devel libzstd-devel brotli-devel clang
```

### Quick Install (Debian/Ubuntu)
```bash
sudo apt install libbpf-dev libelf-dev zlib1g-dev \
    libllhttp-dev libnghttp2-dev libck-dev libxdp-dev liburcu-dev \
    libjemalloc-dev libpcre2-dev libzstd-dev libbrotli-dev clang

# vectorscan and zlib-ng: check your distro repos first, otherwise build from source:
# - https://github.com/VectorCamp/vectorscan
# - https://github.com/zlib-ng/zlib-ng
```

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/NoFear0411/spliff.git
cd spliff

# Build (debug mode with sanitizers)
make

# Or build optimized release
make release

# Install system-wide
sudo make install
```

### Build Options

| Target | Description |
|--------|-------------|
| `make` / `make debug` | Debug build with sanitizers (ASan, UBSan) |
| `make release` | Optimized, stripped binary |
| `make relsan` | Optimized with sanitizers (for testing) |
| `make test` | Build and run tests |
| `make docs` | Generate Doxygen API documentation |
| `make clean` | Remove build artifacts |
| `make install` | Install to /usr/local/bin |
| `make package-deb` | Create Debian package |
| `make package-rpm` | Create RPM package |

### API Documentation

Generate comprehensive API documentation with Doxygen:

```bash
# Generate HTML documentation
make docs

# View documentation
xdg-open build/docs/html/index.html
```

Documentation includes:
- Architecture overview with ASCII diagrams
- Thread model and data flow documentation
- Lock-free data structure explanations
- Per-module API reference with parameters and return values

### CMake Options

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_SANITIZERS=OFF \
    -DENABLE_ZSTD=ON \
    -DENABLE_BROTLI=ON \
    -DUSE_VECTORSCAN=ON \
    -DUSE_ZLIB_NG=ON
cmake --build build
```

| Option | Default | Description |
|--------|---------|-------------|
| `USE_VECTORSCAN` | ON | Use vectorscan for O(n) protocol detection |
| `USE_ZLIB_NG` | ON | Use zlib-ng for SIMD-accelerated compression |
| `ENABLE_LTO` | ON | Link Time Optimization (5-10% faster, smaller binary) |
| `ENABLE_ZSTD` | ON | Enable zstd decompression |
| `ENABLE_BROTLI` | ON | Enable brotli decompression |
| `ENABLE_SANITIZERS` | OFF | Enable AddressSanitizer/UBSan (debug builds) |

## Usage

```bash
# Basic usage (captures all SSL traffic)
sudo ./spliff

# Filter by process
sudo ./spliff -p 1234                    # By PID
sudo ./spliff -p 1234,5678               # Multiple PIDs
sudo ./spliff --comm curl                # By process name or path
sudo ./spliff --ppid 1234                # By parent PID (captures all children)

# Filter by SSL library
sudo ./spliff --openssl                  # OpenSSL only
sudo ./spliff --gnutls                   # GnuTLS only
sudo ./spliff --nss                      # NSS only

# Output options
sudo ./spliff -b                         # Show request/response bodies
sudo ./spliff -x                         # Hexdump body with file signatures
sudo ./spliff -c                         # Compact mode (hide headers)
sudo ./spliff -l                         # Show latency (SSL operation time)
sudo ./spliff -H                         # Show TLS handshake events
sudo ./spliff -C                         # Disable colored output

# Threading options
sudo ./spliff -t 4                       # Use 4 worker threads
sudo ./spliff -t 0                       # Auto (default): max(1, CPUs-3), capped at 16

# Browser-specific (IPC filtering is automatic)
sudo ./spliff --comm firefox             # Firefox traffic
sudo ./spliff --nss --ppid 1234          # NSS traffic from Firefox children

# Debugging
sudo ./spliff -d                         # Debug mode (verbose output)
sudo ./spliff --show-libs                # Show all discovered SSL libraries
```

## Example Output

### HTTP/2 Request/Response (with XDP Correlation)
```
15:11:59.346 → GET https://api.example.com/users ALPN:h2 192.0.2.10:48372 → 198.51.100.25:443 curl (403410) [63.1us] [stream 1]
  user-agent: curl/8.15.0
  accept: application/json

15:11:59.639 ← 200 https://api.example.com/users ALPN:h2 application/json (1247 bytes) 192.0.2.10:48372 → 198.51.100.25:443 curl (403410) [294.29ms] [stream 1]
  date: Mon, 27 Jan 2026 11:11:59 GMT
  content-type: application/json
  content-length: 1247
─── Body ───
{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}
────────────
```

### HTTP/1.1 Request/Response (with XDP Correlation)
```
15:12:05.592 → GET https://httpbin.org/get ALPN:http/1.1 192.0.2.10:52418 → 203.0.113.50:443 curl (403422) [31.9us]
  Host: httpbin.org
  User-Agent: curl/8.15.0
  Accept: */*

15:12:05.883 ← 200 https://httpbin.org/get ALPN:http/1.1 application/json (298 bytes) 192.0.2.10:52418 → 203.0.113.50:443 curl (403422) [291.3ms]
  Date: Mon, 27 Jan 2026 11:12:05 GMT
  Content-Type: application/json
  Content-Length: 298
─── Body (298 bytes) ───
{"args":{},"headers":{"Accept":"*/*","Host":"httpbin.org"},"origin":"192.0.2.10","url":"https://httpbin.org/get"}
────────────
```

### TLS Handshake (with -H flag)
```
15:12:05.100 🔒 TLS handshake 192.0.2.10:52418 → 203.0.113.50:443 [12.45ms] curl (403422)
```

### XDP Attachment Status (startup)
```
[XDP] Attached to 2 interfaces (native: 1, SKB fallback: 1)
  ✓ eth0 (native mode)
  ✓ wlan0 (SKB mode - driver doesn't support native)
```

## Architecture

spliff uses eBPF uprobes to intercept decrypted SSL/TLS data, XDP for packet-level flow tracking,
and sock_ops for socket cookie correlation ("Golden Thread"). A multi-threaded dispatcher routes
events to worker threads via lock-free SPSC queues, with per-flow state managed in a dynamic pool
with dual-index lookup.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and data flow.

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0.5.x | HTTP/1.1 + HTTP/2 + Multi-library support | ✅ Complete |
| v0.6.x | Multi-threaded event processing | ✅ Complete |
| v0.7.x | BPF-level IPC filtering + Unified display | ✅ Complete |
| v0.8.x | XDP packet-level flow tracking + sock_ops | ✅ Complete |
| v0.9.0-0.9.4 | Dynamic process monitoring + Shared Pool Architecture | ✅ Complete |
| v0.9.5 | Modular Protocol Architecture + Vectorscan detection | ✅ Complete |
| v0.9.6 | Embedded BPF Skeleton + XDP-SSL correlation fix + Thread cleanup | ✅ Complete |
| v0.9.7 | Centralized session statistics + Production-grade shutdown metrics | ✅ Complete |
| v0.9.8 | Dynamic flow pool + Generation safety + Mandatory libs + Scanner dedup | ✅ **Current** |
| v0.10.0 | Asynchronous logging + ZSTD decompression pipeline | 🔄 Next |
| v0.11.0 | HTTP/3 + QUIC protocol support (ngtcp2/nghttp3) | Planned |
| v1.0.0 | WebSocket support + Production hardening | Planned |
| v1.1.0+ | EDR agent mode + Event streaming | Planned |

### Near-Term Goals (v0.10.x - v1.0)
- **BPF/XDP Improvements**: IPv6 correlation, expanded ring buffers, atomic state machine
- **Plain HTTP Capture**: XDP payload extraction for unencrypted traffic
- **WebSocket Support**: Frame parsing and message reconstruction
- **Enhanced Display**: XDP flow metrics in output, connection timeline

### Long-Term Vision (EDR/XDR Platform)
- **Agent Mode**: Daemonized operation with configuration management
- **Event Streaming**: NATS.io, Kafka, or custom protocol for centralized collection
- **Behavioral Analysis**: ML-based anomaly detection on traffic patterns
- **Threat Intel Integration**: IOC matching, signature-based detection
- **Multi-Protocol Support**: DNS, SMTP, database protocols

See [docs/](docs/) for detailed implementation plans.

## Known Limitations

See [ISSUES.md](ISSUES.md) for known limitations, open bugs, and workarounds.

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

## Contributing

Contributions are welcome! Before contributing:

1. Review [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system diagrams and data flow
2. Review [docs/CODE-MAP.md](docs/CODE-MAP.md) for comprehensive code-level documentation
3. Check [CHANGELOG.md](CHANGELOG.md) for recent changes and version history
4. See [docs/EDR_XDR_ROADMAP.md](docs/EDR_XDR_ROADMAP.md) for long-term vision

The codebase follows C23 standards with strict compiler warnings (`-Wall -Wextra -Wpedantic`).

## License

GPL-3.0-only - See [LICENSE](LICENSE) for details.

BPF code (`src/bpf/spliff.bpf.c`) is licensed under GPL-2.0-only (Linux kernel requirement).

## Acknowledgments

### Core Libraries
- [libbpf](https://github.com/libbpf/libbpf) - eBPF CO-RE library for portable BPF programs
- [libelf](https://sourceware.org/elfutils/) - ELF binary parsing for library discovery
- [libxdp](https://github.com/xdp-project/xdp-tools) - XDP program loading and management

### Protocol Parsing
- [llhttp](https://github.com/nodejs/llhttp) - HTTP/1.1 parser from Node.js
- [nghttp2](https://github.com/nghttp2/nghttp2) - HTTP/2 library with HPACK compression
- [vectorscan](https://github.com/VectorCamp/vectorscan) - O(n) pattern matching (Hyperscan fork)
- [PCRE2](https://github.com/PCRE2Project/pcre2) - Perl Compatible Regular Expressions

### Concurrency & Memory
- [Concurrency Kit](https://github.com/concurrencykit/ck) - Lock-free data structures (SPSC rings)
- [liburcu](https://liburcu.org/) - Userspace Read-Copy-Update
- [jemalloc](https://github.com/jemalloc/jemalloc) - Memory allocator

### Compression
- [zlib-ng](https://github.com/zlib-ng/zlib-ng) - SIMD-optimized gzip/deflate decompression
- [zstd](https://github.com/facebook/zstd) - Zstandard compression by Facebook
- [brotli](https://github.com/google/brotli) - Brotli compression by Google

### Documentation
- [Doxygen](https://www.doxygen.nl/) - API documentation generation

### Technical Resources
- [Linux kernel BPF documentation](https://docs.kernel.org/bpf/) - Official BPF docs
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - Hands-on XDP programming
- [RFC 7540](https://datatracker.ietf.org/doc/html/rfc7540) - HTTP/2 specification
- [RFC 7541](https://datatracker.ietf.org/doc/html/rfc7541) - HPACK header compression

### Development
- [Claude](https://www.anthropic.com/claude) by Anthropic - AI assistant that wrote this codebase
- [Claude Code](https://claude.ai/code) - CLI tool for AI-assisted development
