# spliff

**eBPF-based SSL/TLS Traffic Sniffer**

[![Version](https://img.shields.io/badge/version-0.7.1-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![C Standard](https://img.shields.io/badge/C-C23-orange.svg)](CMakeLists.txt)

Capture and inspect decrypted HTTPS traffic in real-time without MITM proxies. spliff uses eBPF uprobes to hook SSL/TLS library functions, intercepting data after decryption but before it reaches the application.

**The project is entirely coded by Claude Opus and the goal is to build a full EDR/XDR open-source agent/platform with the help of AI**

## Features

### SSL/TLS Library Support
- **OpenSSL** / **BoringSSL**: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`, `SSL_connect`
- **GnuTLS**: `gnutls_record_recv`, `gnutls_record_send`, `gnutls_handshake`
- **NSS/NSPR**: `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send`, `SSL_ForceHandshake`
- **WolfSSL**: `wolfSSL_read`, `wolfSSL_write`

### HTTP Protocol Support
| Protocol | Parser | Features |
|----------|--------|----------|
| HTTP/1.1 | llhttp | Full header parsing, chunked transfer encoding, body aggregation, request-response correlation |
| HTTP/2 | nghttp2 | Frame parsing, HPACK decompression, stream tracking, mid-stream recovery, multiplexed request/response correlation |

### Multi-Threaded Architecture (v0.6.0+)
- **Lock-Free Event Processing**: Dispatcher → Worker threads with SPSC ring buffers
- **Connection Affinity**: Same (pid, ssl_ctx) always routes to same worker
- **Per-Worker State**: Isolated HTTP/2 sessions, ALPN cache, pending bodies
- **Serialized Output**: Dedicated output thread prevents interleaved lines
- **Adaptive Wait**: spin → yield → eventfd for efficient CPU usage

### BPF-Level Filtering (v0.7.0+)
- **Socket Family Detection**: Filters AF_UNIX (IPC) at kernel level
- **CO-RE BTF Access**: Walks `task_struct → files_struct → socket → sock → skc_family`
- **SSL Session Tracking**: Maps SSL* to file descriptors for socket lookup
- **NSS SSL Verification**: Filters non-SSL NSPR file descriptors

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
| zstd | zstd decompression (optional) | libzstd-devel | libzstd-dev |
| brotli | brotli decompression (optional) | brotli-devel | libbrotli-dev |

### Quick Install (Fedora)
```bash
sudo dnf install libbpf-devel elfutils-libelf-devel zlib-devel \
    llhttp-devel nghttp2-devel ck-devel libzstd-devel brotli-devel clang
```

### Quick Install (Debian/Ubuntu)
```bash
sudo apt install libbpf-dev libelf-dev zlib1g-dev \
    libllhttp-dev libnghttp2-dev libck-dev libzstd-dev libbrotli-dev clang
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
| `make clean` | Remove build artifacts |
| `make install` | Install to /usr/local/bin |
| `make package-deb` | Create Debian package |
| `make package-rpm` | Create RPM package |

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
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User Space                                      │
│                                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                      │
│   │   curl      │    │   Firefox   │    │   Chrome    │                      │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                      │
│          │                  │                  │                             │
│   ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐                      │
│   │   OpenSSL   │    │    NSS      │    │  BoringSSL  │                      │
│   │ SSL_read()  │    │  PR_Read()  │    │ SSL_read()  │                      │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                      │
│          │                  │                  │                             │
│          └──────────────────┼──────────────────┘                             │
│                             │                                                │
│               ┌─────────────▼─────────────┐                                  │
│               │      eBPF Uprobes         │                                  │
│               │  (attached to SSL funcs)  │                                  │
│               └─────────────┬─────────────┘                                  │
│                             │                                                │
│               ┌─────────────▼─────────────┐                                  │
│               │         spliff            │                                  │
│               │  ┌─────────────────────┐  │                                  │
│               │  │   BPF Ring Buffer   │  │                                  │
│               │  └──────────┬──────────┘  │                                  │
│               │             │             │                                  │
│               │  ┌──────────▼──────────┐  │                                  │
│               │  │   Dispatcher Thread │  │  (polls ring, routes events)     │
│               │  └──────────┬──────────┘  │                                  │
│               │             │             │                                  │
│               │      ┌──────┴──────┐      │                                  │
│               │      ▼             ▼      │                                  │
│               │  ┌────────┐  ┌────────┐   │                                  │
│               │  │Worker 0│  │Worker N│   │  (per-worker state, lock-free)   │
│               │  │ HTTP/1 │  │ HTTP/2 │   │                                  │
│               │  │ HTTP/2 │  │ HTTP/1 │   │                                  │
│               │  └───┬────┘  └───┬────┘   │                                  │
│               │      │           │        │                                  │
│               │      └─────┬─────┘        │                                  │
│               │            ▼              │                                  │
│               │  ┌─────────────────────┐  │                                  │
│               │  │   Output Thread     │  │  (serializes to stdout)          │
│               │  └─────────────────────┘  │                                  │
│               └───────────────────────────┘                                  │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                              Kernel Space                                    │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                    eBPF Program (spliff.bpf.c)                       │   │
│   │                                                                      │   │
│   │   • Captures SSL_read/SSL_write arguments and return values          │   │
│   │   • Copies decrypted data to ring buffer                             │   │
│   │   • Tracks SSL context → file descriptor mapping                     │   │
│   │   • Socket family detection (AF_INET/AF_INET6 vs AF_UNIX)            │   │
│   │   • Filters IPC traffic at kernel level                              │   │
│   │   • ALPN protocol detection hooks                                    │   │
│   │                                                                      │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
spliff/
├── CMakeLists.txt              # CMake build configuration
├── Makefile                    # Convenience wrapper for CMake
├── CHANGELOG.md                # Version history
├── LICENSE                     # GPL-3.0 license
├── README.md                   # This file
├── src/
│   ├── main.c                  # Entry point, CLI parsing, event handling
│   ├── include/
│   │   └── spliff.h            # Public header, shared types
│   ├── bpf/
│   │   ├── spliff.bpf.c        # eBPF program (kernel space)
│   │   ├── bpf_loader.c        # BPF program loader
│   │   ├── probe_handler.c     # Event filtering and processing
│   │   └── vmlinux.h           # Kernel type definitions
│   ├── protocol/
│   │   ├── http1.c             # HTTP/1.1 parser (llhttp)
│   │   └── http2.c             # HTTP/2 parser (nghttp2)
│   ├── content/
│   │   ├── decompressor.c      # gzip/brotli/zstd decompression
│   │   └── signatures.c        # File magic detection
│   ├── output/
│   │   └── display.c           # Terminal output formatting
│   ├── threading/              # Multi-threaded event processing (v0.6.0+)
│   │   ├── threading.h         # Threading API and structures
│   │   ├── dispatcher.c        # BPF ring → worker dispatch
│   │   ├── worker.c            # Worker thread with adaptive wait
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
    ├── HTTP3_QUIC_IMPLEMENTATION_PLAN.md   # HTTP/3 planning
    ├── XDP_INTEGRATION_PLAN.md             # XDP planning
    └── EDR_XDR_ROADMAP.md                  # EDR/XDR roadmap
```

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0.5.x | HTTP/1.1 + HTTP/2 + Multi-library support | ✅ Complete |
| v0.6.x | Multi-threaded event processing | ✅ Complete |
| v0.7.x | BPF-level IPC filtering + Unified display | ✅ **Current** |
| v0.8.0 | HTTP/3 + QUIC protocol support | Planned |
| v0.9.0 | XDP packet capture integration | Planned |
| v1.0.0 | EDR agent mode + NATS.io streaming | Planned |

See [docs/](docs/) for detailed implementation plans.

## Known Limitations

- **HTTP/2 Mid-Stream Capture**: Joining existing HTTP/2 connections may cause HPACK decode errors for first few responses (dynamic table not synchronized). Recovery is automatic.
- **Multiple TLS Handshakes**: Some clients (e.g., curl) perform multiple TLS connections (initial + session resumption). Both handshakes are displayed when using `-H`.
- **NSS Library Detection**: Firefox and other NSS applications may use multiple NSPR layers. BPF-level filtering ensures only SSL traffic is captured.
- **QUIC/HTTP/3**: Not yet supported (planned for v0.8.0)
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

- [libbpf](https://github.com/libbpf/libbpf) - eBPF library
- [llhttp](https://github.com/nodejs/llhttp) - HTTP/1.1 parser
- [nghttp2](https://github.com/nghttp2/nghttp2) - HTTP/2 library
- [Concurrency Kit](https://github.com/concurrencykit/ck) - Lock-free data structures
