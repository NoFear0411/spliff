# spliff

**eBPF-based SSL/TLS Traffic Sniffer**

[![Version](https://img.shields.io/badge/version-0.10.1-blue.svg)](CHANGELOG.md)
[![Release](https://github.com/NoFear0411/spliff/actions/workflows/release.yml/badge.svg)](https://github.com/NoFear0411/spliff/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-green.svg)](LICENSE)
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

### Flow Correlation & Thread Safety
- **Dual-Index Flow Lookup**: O(1) correlation via socket cookie index + shadow index (pid, ssl_ctx)
- **IPv6 Full Correlation**: Zero-collision 40-byte flow keys with separate BPF maps
- **Dynamic Flow Pool**: On-demand allocation via jemalloc with cache-line alignment
- **Generation Counters**: Safe pointer validation across worker threads
- **RCU-Safe Memory**: liburcu `call_rcu()` for safe deferred hash table frees
- **Reference Counting**: Atomic ref_count lifecycle prevents use-after-free during cleanup (v0.10.0)

### XDP Packet-Level Tracking
- **High-Performance Flow Tracking**: XDP programs at network interface level
- **Auto-Attach**: Discovers and attaches to all suitable interfaces (native with SKB fallback)
- **Protocol Detection**: TLS, HTTP/2, HTTP/1.x classification at packet level
- **sock_ops Cookie Caching**: "Golden Thread" correlation between packets and SSL sessions
- **Dual Warm-up Strategy**: BPF map + Netlink SOCK_DIAG for pre-existing connections

### Multi-Threaded Architecture
- **SPMC Ring Transport**: Vyukov-style single-producer multi-consumer ring with mirrored buffer zero-copy (v0.10.0)
- **Connection Affinity**: `hash(pid, ssl_ctx)` routes to consistent worker with MPSC overflow (v0.10.0)
- **Backpressure Control**: Four-level hysteresis state machine (NORMAL→WARN→CRITICAL→SHED) (v0.10.0)
- **Per-Flow HTTP/2 Sessions**: 64-stream pool per flow with O(1) free-list allocation
- **Async MPSC Logger**: Lock-free logging pipeline with eventfd notification
- **Deferred Display Queue**: Waits for XDP correlation before display (100ms timeout)
- **Streaming Decompression**: Per-flow gzip/zstd/brotli with bomb protection (>1000:1 ratio reject) (v0.10.0)

### BPF-Level Filtering
- **Socket Family Detection**: Filters AF_UNIX (IPC) at kernel level
- **Dynamic cgroup2 Detection**: Parses `/proc/mounts` for any cgroup2 mount
- **SSL Session Tracking**: Maps SSL* to file descriptors for socket lookup
- **NSS SSL Verification**: Filters non-SSL NSPR file descriptors

### Dynamic Process Monitoring
- **EDR-Style Process Scanning**: Discovers SSL libraries via `/proc/PID/maps`
- **Runtime Browser Detection**: Detects Chrome/Chromium/Brave (experimental)
- **Process Lifecycle Events**: BPF tracepoints for exec, fork, and exit
- **Embedded BPF Skeleton**: Single binary deployment with embedded bytecode

### Session Statistics
- **Unified Shutdown Report**: All subsystem metrics collected at exit
- **Production-Grade Visibility**: Full pipeline metrics in every build
- **XDP Classification**: Packets, flows, correlation success rate

<details>
<summary>Sample Session Statistics Output</summary>

```
============================================
           Session Statistics
============================================

  Application Layer (SSL/TLS)
  ----------------------------------------------
  Events:      131 captured -> 216 processed
  Output:      0 messages (0 B)

  Async Logger
  ----------------------------------------------
  Messages: 36 (8.9 KB)
  Batches:  34 (avg 1.1 msgs/batch)

  Workers (16)
  ----------------------------------------------
  Worker  1: 1 events
  Worker  2: 8 events
  Worker  4: 6 events
  Worker  5: 1 events
  Worker  6: 152 events
  Worker  7: 10 events
  Worker  8: 1 events
  Worker  9: 24 events
  Worker 11: 1 events
  Worker 14: 4 events
  Worker 15: 8 events
  CPU: Good (NAPI-style, 12162 sleep cycles)

  Flow Pool
  ----------------------------------------------
  Active:      9 flows, peak 9
  Throughput:  15 allocs, 6 frees
  Cookie index: 3 entries, 193 hits (95.5%), 9 misses
  Shadow index: 2 entries, 14 hits, 0 promotions
  Promotion:    0.0% of flows got socket_cookie

  Network Layer (XDP)
  ----------------------------------------------
  Packets:     205 processed (177 TCP)
  Connections: 9 tracked, 9 classified
  Correlation: 100.0% socket cookie success
  Classified:  9 flows
  Ambiguous:   76 (deeper inspection needed)
  Terminated:  6 (FIN/RST)
  Cache hits:  0 (fast-path gatekeeper)
  Cookie miss: 0 (correlation gaps)

  Sockops (cookie caching)
  ----------------------------------------------
  Events:  5 (active: 5, passive: 0)
  Cleanup: 0

  SSL Probes
  ----------------------------------------------
  SSL_read/SSL_write intercepted: 41

============================================
```
</details>

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
| `make tests` | Build and run all 17 test suites |
| `make test-ring` | Ring transport tests only (5 suites) |
| `make test-protocol` | Protocol parser tests only (4 suites) |
| `make test-flow` | Flow context tests only (2 suites) |
| `make test-content` | Decompression tests only (2 suites) |
| `make test-memory` | Memory infrastructure tests only (1 suite) |
| `make test-util` | Utility tests only (3 suites) |
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

### Testing

Build and run the full test suite (17 suites):

```bash
# Build and run all tests
make tests

# Or run individual module groups
make test-ring        # Ring transport tests (5 suites)
make test-protocol    # Protocol parser tests (4 suites)
make test-flow        # Flow context tests (2 suites)
make test-content     # Decompression tests (2 suites)
make test-memory      # Memory tests (1 suite)
make test-util        # Utility tests (3 suites)
```

| Test Suite | Module | Coverage |
|------------|--------|----------|
| test_http1 | protocol | HTTP/1.x request/response parsing with llhttp |
| test_http2 | protocol | HTTP/2 preface, frames, validation with nghttp2 |
| test_detector | protocol | Vectorscan protocol detection patterns |
| test_websocket | protocol | RFC 6455 frame parsing, masking, fragmentation |
| test_flow_context | flow | Dual-index correlation, flow pools, stream management |
| test_flow_refcount | flow | Reference counting lifecycle (v0.10.0) |
| test_spmc_ring | ring | SPMC ring buffer operations (v0.10.0) |
| test_concurrent | ring | Multi-threaded ring stress tests (v0.10.0) |
| test_affinity | ring | Affinity routing and MPSC overflow (v0.10.0) |
| test_backpressure | ring | Four-level hysteresis state machine (v0.10.0) |
| test_worker_dequeue | ring | Three-phase consumption + adaptive polling (v0.10.0) |
| test_decompressor | content | gzip, deflate, zstd, brotli per-transaction |
| test_stream_decompressor | content | Streaming decompression + bomb protection (v0.10.0) |
| test_mirrored_buffer | memory | Mirrored virtual memory buffers (v0.10.0) |
| test_safe_str | util | Memory-safe string operations |
| test_display | util | Color output, latency formatting, timestamps |
| test_xdp | util | XDP event structure validation |

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
04:35:19.750 → GET https://httpbin.org/bytes/16384 ALPN:h2 curl (855771) [stream 1] #648f
              |- 192.168.50.245:42696 → 44.197.91.61:443 [XDP:TLS][App:H2] ✓✓ (wlp0s20f3)
04:35:20.363 ← 200 https://httpbin.org/bytes/16384 ALPN:h2 application/octet-stream (16384 bytes) curl (855771) [614.81ms] [stream 1] #648f
              |- 44.197.91.61:443 → 192.168.50.245:42696 [XDP:TLS][App:H2] ✓✓ (wlp0s20f3)
```

### HTTP/1.1 Request/Response (with XDP Correlation)
```
04:35:45.555 → GET https://httpbin.org/get ALPN:http/1.1 curl (855994) [141.7us] #230f
              |- 192.168.50.245:52274 → 52.204.75.48:443 [XDP:TLS][App:H1] ✓✓ (wlp0s20f3)
04:35:45.860 ← 200 https://httpbin.org/get ALPN:http/1.1 application/json (256 bytes) curl (855994) [170.9us] #230f
              |- 52.204.75.48:443 → 192.168.50.245:52274 [XDP:TLS][App:H1] ✓✓ (wlp0s20f3)
```

### TLS Handshake (with -H flag)
```
15:12:05.100 🔒 TLS handshake 192.0.2.10:52418 → 203.0.113.50:443 [12.45ms] curl (403422)
```

### XDP Attachment Status (startup)
```
✓ XDP: enp0s20f0u2u4u2 [skb], wlp0s20f3 [skb], enp0s31f6 [skb]
```

## Architecture

spliff uses eBPF uprobes to intercept decrypted SSL/TLS data, XDP for packet-level flow tracking,
and sock_ops for socket cookie correlation ("Golden Thread"). A multi-threaded dispatcher routes
events to worker threads via lock-free SPSC queues, with per-flow state managed in a dynamic pool
with dual-index lookup.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and data flow.

## Roadmap

| Version | Theme | Key Deliverables | Status |
|---------|-------|------------------|--------|
| v0.1-0.8 | Core | Interception, XDP tracking, multi-threading | ✅ Complete |
| v0.9.11 | Stability | Lock-free architecture, thread safety, IPv6 | ✅ Complete |
| **v0.10.0** | Foundation | Omni-Ring memory, SPMC rings, refcounted flows, ZSTD streaming | ✅ **Current** |
| v0.11.0 | Protocols | Plain HTTP, WebSocket, gRPC, HTTP/3 + QUIC | Planned |
| v0.12.0 | Operations | Enhanced dispatcher, comprehensive metrics | Planned |
| v0.13.0+ | Hardening | Security mitigations, performance tuning | Planned |
| v1.0.0 | Release | Production-ready, stable API, all protocols | Target |
| v2.0+ | EDR | Agent mode, event streaming, threat intel | Future |

### Architecture Evolution (Omni-Ring)
The v0.10+ series implements the Omni-Ring architecture for production-grade performance:
- **Zero-Copy Buffers**: Mirrored virtual memory eliminates wrap-around branching
- **SPMC Workers**: Single-producer, multi-consumer rings with batch dequeue
- **Reference Counting**: Clean flow lifecycle without generation-based hacks
- **Multi-Protocol**: Unified detection/routing for HTTP/1, HTTP/2, HTTP/3, WebSocket, gRPC

See [docs/REFACTOR-PLAN.md](docs/REFACTOR-PLAN.md) for detailed implementation plan.

### Goals
- **Near-Term**: Omni-Ring foundation, plain HTTP capture, WebSocket integration
- **Mid-Term**: HTTP/3 + QUIC, comprehensive metrics, security hardening
- **Long-Term**: Agent mode, NATS/Kafka streaming, behavioral analysis, threat intel

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

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

AGPL-3.0-only - See [LICENSE](LICENSE) for details.

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
