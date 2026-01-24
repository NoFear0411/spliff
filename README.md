# spliff

**eBPF-based SSL/TLS Traffic Sniffer**

[![Version](https://img.shields.io/badge/version-0.9.3-blue.svg)](CHANGELOG.md)
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

### Shared Pool Architecture (v0.9.3+)
- **Unified Flow Context**: Pre-allocated pool of 8192 flow slots with dual-index lookup
- **Zero-Copy Correlation**: Socket cookie index + shadow index (pid, ssl_ctx) for O(1) lookup
- **Per-Flow HTTP/2 Streams**: 64-stream pool per flow with O(1) free-list allocation
- **Worker Affinity**: Atomic CAS claim ensures single-writer guarantee per flow
- **HPACK Corruption Detection**: Connection-fatal flag per RFC 7540 Section 4.3
- **Ghost Stream Reaping**: 10-second timeout for idle stream cleanup
- **Pool Statistics**: Runtime visibility into capacity, allocations, index hit rates
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
- **XDP Statistics**: Debug-mode metrics (packets, flows, gatekeeper hits)

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
| libbpf | eBPF loader | libbpf-devel | libbpf-dev |
| libelf | ELF parsing | elfutils-libelf-devel | libelf-dev |
| zlib | gzip decompression | zlib-devel | zlib1g-dev |
| llhttp | HTTP/1.1 parsing | llhttp-devel | libllhttp-dev |
| nghttp2 | HTTP/2 parsing | nghttp2-devel | libnghttp2-dev |
| ck | Lock-free data structures | ck-devel | libck-dev |
| libxdp | XDP program loading | libxdp-devel | libxdp-dev |
| liburcu | Read-Copy-Update | userspace-rcu-devel | liburcu-dev |
| jemalloc | Memory allocator | jemalloc-devel | libjemalloc-dev |
| pcre2 | Pattern matching | pcre2-devel | libpcre2-dev |
| zstd | zstd decompression | libzstd-devel | libzstd-dev |
| brotli | brotli decompression | brotli-devel | libbrotli-dev |

### Quick Install (Fedora)
```bash
sudo dnf install libbpf-devel elfutils-libelf-devel zlib-devel \
    llhttp-devel nghttp2-devel ck-devel libxdp-devel userspace-rcu-devel \
    jemalloc-devel pcre2-devel libzstd-devel brotli-devel clang
```

### Quick Install (Debian/Ubuntu)
```bash
sudo apt install libbpf-dev libelf-dev zlib1g-dev \
    libllhttp-dev libnghttp2-dev libck-dev libxdp-dev liburcu-dev \
    libjemalloc-dev libpcre2-dev libzstd-dev libbrotli-dev clang
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
    -DENABLE_BROTLI=ON
cmake --build build
```

## Usage

```bash
# Basic usage (captures all SSL traffic)
sudo ./spliff

# Filter by process
sudo ./spliff -p 1234                    # By PID
sudo ./spliff --comm curl                # By process name
sudo ./spliff --ppid 1234                # By parent PID (includes descendants)

# Filter by SSL library
sudo ./spliff --openssl                  # OpenSSL only
sudo ./spliff --gnutls                   # GnuTLS only
sudo ./spliff --nss                      # NSS only

# Output options
sudo ./spliff -c                         # Compact mode (one line per request)
sudo ./spliff -b                         # Show response bodies
sudo ./spliff -x                         # Hexdump body with file signatures
sudo ./spliff -l                         # Show latency
sudo ./spliff -H                         # Show TLS handshakes
sudo ./spliff -C                         # Disable colors

# Threading options
sudo ./spliff -t 4                       # Use 4 worker threads
sudo ./spliff --no-threading             # Single-threaded mode

# Browser-specific (IPC filtering is automatic)
sudo ./spliff --comm firefox             # Firefox traffic
sudo ./spliff --comm chrome              # Chrome traffic

# Debugging
sudo ./spliff -d                         # Debug mode (raw events)
sudo ./spliff --show-libs                # Show discovered SSL libraries
```

## Example Output

### HTTP/2 Request/Response
```
15:11:59.346 → GET https://ifconfig.io/ ALPN:h2 curl (403410) [63.1us] [stream 1]
  user-agent: curl/8.15.0
  accept: */*

15:11:59.639 ← 200 https://ifconfig.io/ ALPN:h2 text/plain; charset=utf-8 (15 bytes) curl (403410) [294.29ms] [stream 1]
  date: Mon, 12 Jan 2026 11:11:59 GMT
  content-type: text/plain; charset=utf-8
  content-length: 15
─── Body ───
203.0.113.42
────────────
```

### HTTP/1.1 Request/Response
```
15:12:05.592 → GET https://ifconfig.io/ ALPN:http/1.1 curl (403422) [31.9us]
  Host: ifconfig.io
  User-Agent: curl/8.15.0
  Accept: */*

15:12:05.883 ← 200 https://ifconfig.io/ ALPN:http/1.1 text/plain; charset=utf-8 (15 bytes) curl (403422) [462.5us]
  Date: Mon, 12 Jan 2026 11:12:05 GMT
  Content-Type: text/plain; charset=utf-8
  Content-Length: 15
─── Body (15 bytes) ───
203.0.113.42
────────────
```

### TLS Handshake (with -H flag)
```
15:12:05.100 🔒 TLS handshake complete [15.00ms] curl (403422)
```

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                    USER SPACE                                             │
│                                                                                           │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐    │
│  │                              Applications                                         │    │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐                 │    │
│  │   │  curl   │  │ Firefox │  │ Chrome  │  │  Brave  │  │  wget   │                 │    │
│  │   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘                 │    │
│  │        │            │            │            │            │                      │    │
│  │   ┌────▼────┐  ┌────▼────┐  ┌────▼────────────▼────┐  ┌────▼────┐                 │    │
│  │   │ OpenSSL │  │   NSS   │  │     BoringSSL ⚠️     │  │ GnuTLS  │  SSL Libraries  │    │
│  │   └────┬────┘  └────┬────┘  └──────────┬───────────┘  └────┬────┘                 │    │
│  │        │            │                  │                   │                      │    │
│  │        └────────────┴────────┬─────────┴───────────────────┘                      │    │
│  └──────────────────────────────┼────────────────────────────────────────────────────┘    │
│                                 │                                                         │
│                          ╔══════▼══════╗                                                  │
│                          ║ BPF Uprobes ║ ◄─── Dynamic attachment via /proc/PID/maps       │
│                          ╚══════╤══════╝      + BoringSSL binary scanning                 │
│                                 │                                                         │
│  ┌──────────────────────────────▼────────────────────────────────────────────────────┐    │
│  │                              spliff                                               │    │
│  │                                                                                   │    │
│  │  ┌──────────────────────────────────────────────────────────────────────────┐     │    │
│  │  │                        Ring Buffer Consumers                             │     │    │
│  │  │   ┌──────────────┐  ┌──────────────┐  ┌───────────────┐                  │     │    │
│  │  │   │ ssl_events   │  │ xdp_events   │  │ process_events│                  │     │    │
│  │  │   │ (TLS data)   │  │ (packets)    │  │ (exec/fork)   │                  │     │    │
│  │  │   └──────┬───────┘  └──────┬───────┘  └───────┬───────┘                  │     │    │
│  │  └──────────┼─────────────────┼──────────────────┼──────────────────────────┘     │    │
│  │             │                 │                  │                                │    │
│  │             └────────────┬────┴──────────────────┘                                │    │
│  │                          │    "Golden Thread" Correlation                         │    │
│  │                          │    (socket cookie links all three)                     │    │
│  │                          ▼                                                        │    │
│  │  ┌───────────────────────────────────────────────────────────────────────────┐    │    │
│  │  │   Dispatcher Thread                                                       │    │    │
│  │  │   ┌─────────────────────────────────────────────────────────────────────┐ │    │    │
│  │  │   │  flow_pool (8192 slots)     cookie_index     shadow_index           │ │    │    │
│  │  │   │  [ctx][ctx][ctx]...         cookie → id      (pid,ssl) → id         │ │    │    │
│  │  │   └─────────────────────────────────────────────────────────────────────┘ │    │    │
│  │  │   • Dual-index lookup: cookie_index (fast) or shadow_index (fallback)     │    │    │
│  │  │   • flow_get_or_create() allocates slot, flow_promote_cookie() on link    │    │    │
│  │  │   • Connection affinity: hash(pid, ssl_ctx) routes to consistent worker   │    │    │
│  │  └───────────┬───────────────────────────────────────────────────────────────┘    │    │
│  │              │ event + flow_context_t*                                            │    │
│  │      ┌───────┼───────┬───────────────┐                                            │    │
│  │      ▼       ▼       ▼               ▼                                            │    │
│  │  ┌───────┐┌───────┐┌───────┐    ┌───────┐   Lock-free SPSC queues                 │    │
│  │  │Worker0││Worker1││Worker2│... │WorkerN│   (Concurrency Kit)                     │    │
│  │  ├───────┤├───────┤├───────┤    ├───────┤                                         │    │
│  │  │ Claim ││ Claim ││ Claim │    │ Claim │   Worker claims flow via atomic CAS     │    │
│  │  │ flow  ││ flow  ││ flow  │    │ flow  │   on home_worker_id (single-writer)     │    │
│  │  └───┬───┘└───┬───┘└───┬───┘    └───┬───┘                                         │    │
│  │      │        │        │            │                                             │    │
│  │      └────────┴────────┴─────┬──────┘                                             │    │
│  │                              │        Per-FLOW state (flow_context_t):            │    │
│  │                              │        • nghttp2 session + HPACK inflater          │    │
│  │                              │        • streams[64] with O(1) free-list           │    │
│  │                              │        • llhttp parser + current transaction       │    │
│  │                              │        • ALPN, body buffers, hpack_corrupted       │    │
│  │                              ▼                                                    │    │
│  │              ┌───────────────────────────┐                                        │    │
│  │              │      Output Thread        │  Serialized stdout/file                │    │
│  │              │  • Body decompression     │  (no interleaving)                     │    │
│  │              │  • File signature detect  │                                        │    │
│  │              └───────────────────────────┘                                        │    │
│  └───────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                           │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│                                    KERNEL SPACE                                           │
│                                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐     │
│  │                           BPF Programs (CO-RE/BTF)                               │     │
│  │                                                                                  │     │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐     │     │
│  │  │                    XDP (eXpress Data Path)                              │     │     │
│  │  │                                                                         │     │     │
│  │  │   NIC ──► Packet ──► Flow State Machine ──► Protocol Classify           │     │     │
│  │  │           │         (SYN/DATA/FIN/RST)     (TLS/HTTP2/HTTP1)            │     │     │
│  │  │           ▼                                       │                     │     │     │
│  │  │      flow_states map                              ▼                     │     │     │
│  │  │           │                              xdp_events ring ──► userspace  │     │     │
│  │  │           │                                                             │     │     │
│  │  └───────────┼─────────────────────────────────────────────────────────────┘     │     │
│  │              │                                                                   │     │
│  │              │ lookup                                                            │     │
│  │              ▼                                                                   │     │
│  │  ╔═══════════════════════════════════════════════════════════════════════════╗   │     │
│  │  ║                    SOCKET COOKIE - "Golden Thread"                        ║   │     │
│  │  ║                                                                           ║   │     │
│  │  ║              ┌─────────────────┐       ┌─────────────────┐                ║   │     │
│  │  ║              │ flow_cookie_map │       │   ssl_to_fd     │                ║   │     │
│  │  ║              │ (5-tuple:cookie)│       │ (SSL*:fd:cookie)│                ║   │     │
│  │  ║              └────────┬────────┘       └────────┬────────┘                ║   │     │
│  │  ║                       │                         │                         ║   │     │
│  │  ║                       └────────────┬────────────┘                         ║   │     │
│  │  ║                                    │                                      ║   │     │
│  │  ║                           Socket Cookie (u64)                             ║   │     │
│  │  ║                      Links: Packets ↔ Sockets ↔ TLS Data                  ║   │     │
│  │  ║                                    │                                      ║   │     │
│  │  ╚════════════════════════════════════╪══════════════════════════════════════╝   │     │
│  │                 ┌─────────────────────┼─────────────────────┐                    │     │
│  │                 │                     │                     │                    │     │
│  │                 ▼                     ▼                     ▼                    │     │
│  │  ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐      │     │
│  │  │   sock_ops           │ │   Uprobes            │ │   (correlation)      │      │     │
│  │  │   (Socket Events)    │ │   (TLS Interception) │ │                      │      │     │
│  │  ├──────────────────────┤ ├──────────────────────┤ │  XDP packet metadata │      │     │
│  │  │ • ESTABLISHED_CB     │ │ • SSL_read/write     │ │  + sock state        │      │     │
│  │  │   → cache cookie     │ │   → decrypt data     │ │  + TLS plaintext     │      │     │
│  │  │ • STATE_CB           │ │ • SSL_set_fd         │ │  + PID/process       │      │     │
│  │  │   → cleanup on close │ │   → link SSL*→cookie │ │                      │      │     │
│  │  │                      │ │ • SSL_get_alpn       │ │  = Complete L7 view  │      │     │
│  │  │                      │ │   → protocol detect  │ │                      │      │     │
│  │  └──────────────────────┘ └──────────────────────┘ └──────────────────────┘      │     │
│  │                                                                                  │     │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │     │
│  │  │                    Tracepoints (Process Lifecycle)                     │      │     │
│  │  │                                                                        │      │     │
│  │  │   sched_process_exec ──► Detect new process ──► Dynamic probe attach   │      │     │
│  │  │   sched_process_fork ──► Track child processes                         │      │     │
│  │  │   sched_process_exit ──► Cleanup PID state ──► Free HTTP/2 sessions    │      │     │
│  │  │                                                                        │      │     │
│  │  └────────────────────────────────────────────────────────────────────────┘      │     │
│  │                                                                                  │     │
│  └──────────────────────────────────────────────────────────────────────────────────┘     │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### The "Golden Thread" – How Correlation Works

```
                            SOCKET COOKIE (u64)
                     ═══════════════════════════════
                     Unique per-TCP-connection identifier
                     generated by kernel, cached by sock_ops
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│      XDP      │   │   sock_ops    │   │    Uprobes    │
│   (packets)   │   │   (sockets)   │   │  (TLS data)   │
├───────────────┤   ├───────────────┤   ├───────────────┤
│ • Raw packets │   │ • TCP state   │   │ • Decrypted   │
│ • 5-tuple     │   │ • Connection  │   │   plaintext   │
│ • Flow state  │   │   lifecycle   │   │ • SSL context │
│ • Protocol ID │   │ • Cookie gen  │   │ • ALPN proto  │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        │                   │                   │
════════╪═══════════════════╪═══════════════════╪════════════════
        │    KERNEL SPACE   │                   │
────────┼───────────────────┼───────────────────┼────────────────
        │    USER SPACE     │                   │
        │                   │                   │
        │  ┌────────────────┴───────────────────┴──────────┐
        │  │           BPF RING BUFFERS                    │
        │  │  ssl_events    xdp_events    process_events   │
        │  └────────────────────┬──────────────────────────┘
        │                       │
        │                       ▼
        │  ┌────────────────────────────────────────────────────┐
        │  │              DISPATCHER THREAD                     │
        │  │                                                    │
        │  │  ┌──────────────────────────────────────────────┐  │
        │  │  │              DUAL-INDEX LOOKUP               │  │
        │  │  │                                              │  │
        │  │  │  1. cookie_index: cookie → flow_id (fast)    │  │
        │  │  │  2. shadow_index: (pid,ssl_ctx) → flow_id    │  │
        │  │  │                                              │  │
        └──┼──┼──► flow_promote_cookie() links cookie later  │  │
           │  └──────────────────────────────────────────────┘  │
           │                       │                            │
           │                       ▼                            │
           │  ┌──────────────────────────────────────────────┐  │
           │  │           flow_pool (8192 slots)             │  │
           │  │  ┌────────────────────────────────────────┐  │  │
           │  │  │           flow_context_t               │  │  │
           │  │  │  • socket_cookie, pid, ssl_ctx         │  │  │
           │  │  │  • home_worker_id (atomic ownership)   │  │  │
           │  │  │  • parser.h2 (nghttp2 + streams[64])   │  │  │
           │  │  │  • parser.h1 (llhttp + transaction)    │  │  │
           │  │  │  • alpn, last_activity_ms              │  │  │
           │  │  └────────────────────────────────────────┘  │  │
           │  └──────────────────────────────────────────────┘  │
           └────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │   UNIFIED PER-FLOW VIEW     │
                    │                             │
                    │  Packet  +  Socket  +  TLS  │
                    │  metadata   state    data   │
                    │                             │
                    │  → Complete L7 visibility   │
                    │  → PID + process name       │
                    │  → Request/response corr.   │
                    │  → Per-flow HTTP/2 streams  │
                    │  → Single-writer guarantee  │
                    └─────────────────────────────┘
```

**Why this matters:** Commercial EDRs typically only see packets OR decrypted TLS, not both
correlated to the same flow. The socket cookie is the "golden thread" that ties all three
data sources together, giving spliff complete visibility into what data went over which
connection from which process.

### Shared Pool Architecture (v0.9.2+)

```
┌──────────────────────────────────────────────────────────────────────┐
│                    SHARED POOL ARCHITECTURE                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │           flow_pool (8192 pre-allocated slots)                 │  │
│  │  ┌──────────┬──────────┬──────────┬──────────┬──────────┐      │  │
│  │  │ slot[0]  │ slot[1]  │ slot[2]  │ slot[3]  │   ...    │      │  │
│  │  │ active=1 │ active=1 │ active=0 │ active=1 │          │      │  │
│  │  │ cookie=A │ cookie=B │ (free)   │ cookie=0 │          │      │  │
│  │  │ pid=100  │ pid=200  │          │ pid=300  │          │      │  │
│  │  │ worker=2 │ worker=0 │          │ worker=1 │          │      │  │
│  │  └──────────┴──────────┴──────────┴──────────┴──────────┘      │  │
│  │       ▲           ▲                     ▲                      │  │
│  │   id=0        id=1                  id=3                       │  │
│  └────────────────────────────────────────────────────────────────┘  │
│              ▲                                   ▲                   │
│              │                                   │                   │
│  ┌───────────┴────────────┐        ┌─────────────┴───────────┐       │
│  │     cookie_index       │        │      shadow_index       │       │
│  │  key: socket_cookie    │        │  key: (pid, ssl_ctx)    │       │
│  │  value: flow_id (u32)  │        │  value: flow_id (u32)   │       │
│  │                        │        │                         │       │
│  │  cookie_A → 0          │        │  (100, ctx1) → 0        │       │
│  │  cookie_B → 1          │        │  (200, ctx2) → 1        │       │
│  │                        │        │  (300, ctx3) → 3        │       │
│  └────────────────────────┘        └─────────────────────────┘       │
│                                                                      │
│  Per-Flow State (flow_context_t):                                    │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ • socket_cookie, pid, ssl_ctx      │ • alpn[16]                │  │
│  │ • home_worker_id (atomic CAS)      │ • last_activity_ms        │  │
│  │ • parser.h2.session (nghttp2)      │ • parser.h2.streams[64]   │  │
│  │ • parser.h2.hpack_corrupted        │ • parser.h2.free_head     │  │
│  │ • parser.h1.llhttp + current_txn   │ • parser.h1.settings      │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  flow_transaction_t (per HTTP/2 stream):                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ stream_id │ state (RFC 7540) │ method, path, host, status      │  │
│  │ flags     │ last_active_ms   │ content_type, content_length    │  │
│  │ next_free │ body_buf, len    │ start_time_ns                   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

**Key design properties:**
- **Zero-copy**: Data never moves, only index entries change
- **Atomic handover**: 4-byte flow_id writes instead of struct copies
- **Predictable performance**: Pre-allocated pool, no malloc in hot path
- **Single-writer guarantee**: Atomic CAS on `home_worker_id` prevents races
- **O(1) stream allocation**: Free-list based pool for HTTP/2 streams

### Data Flow

1. **Startup** → Scan `/proc/PID/maps` for SSL libraries, attach uprobes, seed `flow_cookie_map` via SOCK_DIAG, init flow pool (8192 slots)
2. **Packet arrives** → XDP classifies protocol (TLS/HTTP2/HTTP1), tracks flow state, emits metadata
3. **TCP established** → sock_ops caches socket cookie in `flow_cookie_map` (5-tuple → cookie)
4. **SSL call** → Uprobe captures decrypted data, links SSL* → fd → socket cookie
5. **Flow lookup** → Dual-index lookup: cookie_index (fast) or shadow_index (pid, ssl_ctx)
6. **Worker claim** → Atomic CAS on `home_worker_id` ensures single-writer per flow, init parsers
7. **Processing** → Workers use per-flow `flow_context_t` with embedded HTTP/2 stream pool (64 streams)
8. **HTTP/2 streams** → O(1) allocation from free-list, per-stream body buffers, ghost stream timeout
9. **Output** → Serialized display with request/response correlation, ALPN indicator
10. **Cleanup** → Process exit triggers flow eviction, stream body buffer free, slot return to pool

## Project Structure

```
spliff/
├── CMakeLists.txt              # CMake build configuration
├── Makefile                    # Convenience wrapper for CMake
├── Doxyfile                    # Doxygen documentation config
├── CHANGELOG.md                # Version history
├── LICENSE                     # GPL-3.0 license
├── README.md                   # This file
├── docs/                       # Generated documentation (make docs)
│   ├── html/                   # HTML API documentation
│   └── man/                    # Man pages
├── src/
│   ├── main.c                  # Entry point, CLI, event loop, dynamic probe management
│   ├── include/
│   │   └── spliff.h            # Public header, shared types, version info
│   ├── bpf/
│   │   ├── spliff.bpf.c        # eBPF programs (XDP, sock_ops, uprobes, tracepoints)
│   │   ├── bpf_loader.c        # BPF program loader, XDP attach, library discovery
│   │   ├── bpf_loader.h        # BPF loader API
│   │   ├── probe_handler.c     # Event filtering and callback dispatch
│   │   ├── binary_scanner.c    # BoringSSL offset detection for stripped binaries
│   │   ├── boringssl_offsets.h # Known BoringSSL function offsets by build ID
│   │   └── vmlinux.h           # Kernel BTF type definitions
│   ├── protocol/
│   │   ├── http1.c             # HTTP/1.1 parser (llhttp)
│   │   ├── http2.c             # HTTP/2 parser (nghttp2 + HPACK)
│   │   └── websocket.c         # WebSocket frame parser (planned)
│   ├── content/
│   │   ├── decompressor.c      # gzip/brotli/zstd/deflate decompression
│   │   └── signatures.c        # File magic detection (50+ formats)
│   ├── output/
│   │   └── display.c           # Terminal output formatting, colors
│   ├── correlation/            # XDP-SSL correlation (v0.8.0+)
│   │   ├── flow_cache.c        # XDP flow cache, socket cookie lookup
│   │   ├── flow_cache.h        # Flow cache API
│   │   ├── flow_context.c      # Per-flow context management, stream pools
│   │   └── flow_context.h      # flow_context_t, flow_transaction_t types
│   ├── threading/              # Multi-threaded event processing
│   │   ├── threading.h         # Threading API, structures, constants
│   │   ├── dispatcher.c        # BPF ring consumer, worker routing
│   │   ├── worker.c            # Worker thread with adaptive wait (spin/yield/sleep)
│   │   ├── output.c            # Output serialization thread
│   │   ├── state.c             # Per-worker state management
│   │   ├── pool.c              # Lock-free object pool
│   │   └── manager.c           # Thread lifecycle management
│   └── util/
│       └── safe_str.c          # Safe string operations
├── tests/
│   ├── test_http1.c            # HTTP/1.1 parser tests
│   └── test_http2.c            # HTTP/2 parser tests
└── docs/
    ├── SHARED_POOL_ARCHITECTURE.md         # Shared Pool implementation plan
    ├── HTTP3_QUIC_IMPLEMENTATION_PLAN.md   # HTTP/3 planning
    ├── XDP_INTEGRATION_PLAN.md             # XDP planning
    └── EDR_XDR_ROADMAP.md                  # EDR/XDR roadmap
```

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0.5.x | HTTP/1.1 + HTTP/2 + Multi-library support | ✅ Complete |
| v0.6.x | Multi-threaded event processing | ✅ Complete |
| v0.7.x | BPF-level IPC filtering + Unified display | ✅ Complete |
| v0.8.x | XDP packet-level flow tracking + sock_ops | ✅ Complete |
| v0.9.x | Dynamic process monitoring + Shared Pool Architecture + Unified Transaction | ✅ **Current** |
| v0.10.0 | PCRE2-JIT pattern matching for plain HTTP | 🔄 Next |
| v0.11.0 | HTTP/3 + QUIC protocol support | Planned |
| v1.0.0 | WebSocket support + Enhanced display | Planned |
| v1.1.0 | EDR agent mode + Event streaming (NATS/Kafka) | Planned |
| v1.2.0 | Behavioral analysis + Threat detection | Planned |

### Near-Term Goals (v0.10.x - v1.0)
- **PCRE2-JIT Integration**: Pattern matching for ambiguous traffic classification
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

- **⚠️ Chrome/Chromium Support (Experimental)**: Support for Chrome, Chromium, Brave, browsers is **experimental and may be flaky**. These browsers use statically-linked BoringSSL with stripped debug symbols, making function offset detection unreliable:
  - Offsets vary between browser versions, builds, and distributions
  - No stable ABI - Google frequently changes internal structures
  - Detection relies on heuristic binary scanning that may fail or cause crashes
  - Recommended: Use Firefox (NSS) for reliable browser traffic capture
  - If Chrome capture is needed, expect occasional missed traffic or instability

- **First Request Timing**: Initial HTTP request from each process may lack XDP correlation data. Subsequent requests correlate correctly. Under high traffic, some request/response pairs may miss correlation due to race between SSL event and sockops `flow_cookie_map` population.
- **HTTP/2 Mid-Stream Capture**: Joining existing HTTP/2 connections may cause HPACK decode errors for first few responses (dynamic table not synchronized). Recovery is automatic; corrupted connections set `hpack_corrupted` flag per RFC 7540.
- **HTTP/2 Stream Limits**: Each flow supports up to 64 concurrent HTTP/2 streams. Streams exceeding this limit are dropped. Ghost streams (inactive >10s) are automatically reaped.
- **Multiple TLS Handshakes**: Some clients (e.g., curl) perform multiple TLS connections (initial + session resumption). Both handshakes are displayed when using `-H`.
- **NSS Library Detection**: Firefox and other NSS applications may use multiple NSPR layers. BPF-level filtering ensures only SSL traffic is captured.
- **Plain HTTP Capture**: Currently only captures TLS-encrypted traffic. Plain HTTP via XDP requires PCRE2-JIT classification (planned for v0.10.0).
- **QUIC/HTTP/3**: Not yet supported (planned for v0.11.0)
- **IPv6 XDP Correlation**: XDP flow tracking uses XOR-hashed IPv6 addresses; socket cookie correlation is optimized for IPv4.
- **XDP Native Mode**: Some network drivers don't support XDP native mode; spliff automatically falls back to SKB mode.
- **Kernel Requirements**: Requires Linux 5.x+ with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)

## Troubleshooting

### "Operation not permitted"
```bash
# spliff requires root for eBPF
sudo ./spliff
```

### "Failed to load BPF program"
```bash
# Check BTF support
ls /sys/kernel/btf/vmlinux

# If missing, your kernel may not support BTF
# Rebuild kernel with CONFIG_DEBUG_INFO_BTF=y
```

### No traffic captured
```bash
# Check if SSL libraries are found
sudo ./spliff --show-libs

# Try specific library flag
sudo ./spliff --openssl -d
```

### Firefox shows no traffic
```bash
# Firefox uses multiple processes - use process name filter
sudo ./spliff --comm firefox
```

### High CPU usage
```bash
# Use single-threaded mode for low-traffic scenarios
sudo ./spliff --no-threading

# Or limit worker threads
sudo ./spliff -t 2
```

## Contributing

Contributions are welcome! Please see the [CHANGELOG.md](CHANGELOG.md) for recent changes and coding style.

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
- [PCRE2](https://github.com/PCRE2Project/pcre2) - Perl Compatible Regular Expressions (pattern matching)

### Concurrency & Memory
- [Concurrency Kit](https://github.com/concurrencykit/ck) - Lock-free data structures (SPSC rings, spinlocks)
- [liburcu](https://liburcu.org/) - Userspace Read-Copy-Update (optional)
- [jemalloc](https://github.com/jemalloc/jemalloc) - Memory allocator (optional)

### Compression
- [zlib](https://zlib.net/) - gzip/deflate decompression
- [zstd](https://github.com/facebook/zstd) - Zstandard compression by Facebook
- [brotli](https://github.com/google/brotli) - Brotli compression by Google

### Documentation
- [Doxygen](https://www.doxygen.nl/) - API documentation generation

### Technical Resources
- [Linux kernel BPF documentation](https://docs.kernel.org/bpf/) - Official BPF docs
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - Hands-on XDP programming
- [BPF Performance Tools](https://www.brendangregg.com/bpf-performance-tools-book.html) by Brendan Gregg
- [RFC 7540](https://datatracker.ietf.org/doc/html/rfc7540) - HTTP/2 specification
- [RFC 7541](https://datatracker.ietf.org/doc/html/rfc7541) - HPACK header compression
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) - TLS 1.3 specification

### Development
- [Claude](https://www.anthropic.com/claude) by Anthropic - AI assistant that wrote this codebase
- [Claude Code](https://claude.ai/code) - CLI tool for AI-assisted development
