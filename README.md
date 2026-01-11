# spliff

**eBPF-based SSL/TLS Traffic Sniffer**

[![Version](https://img.shields.io/badge/version-0.5.3-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)
[![C Standard](https://img.shields.io/badge/C-C23-orange.svg)](CMakeLists.txt)

Capture and inspect decrypted HTTPS traffic in real-time without MITM proxies. spliff uses eBPF uprobes to hook SSL/TLS library functions, intercepting data after decryption but before it reaches the application.

## Features

### SSL/TLS Library Support
- **OpenSSL** / **BoringSSL**: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`
- **GnuTLS**: `gnutls_record_recv`, `gnutls_record_send`
- **NSS/NSPR**: `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send`
- **WolfSSL**: `wolfSSL_read`, `wolfSSL_write`

### HTTP Protocol Support
| Protocol | Parser | Features |
|----------|--------|----------|
| HTTP/1.1 | llhttp | Full header parsing, chunked transfer encoding, body aggregation |
| HTTP/2 | nghttp2 | Frame parsing, HPACK decompression, stream tracking, request/response correlation |

### Advanced Capabilities
- **ALPN Detection**: Hooks ALPN negotiation for definitive HTTP/1.1 vs HTTP/2 detection
- **Body Decompression**: gzip, deflate, zstd, brotli (automatic)
- **File Signature Detection**: 50+ formats via magic bytes (images, video, audio, archives, documents)
- **IPC Filtering**: Filter out browser internal traffic (`--filter-ipc`)
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
| zstd | zstd decompression (optional) | libzstd-devel | libzstd-dev |
| brotli | brotli decompression (optional) | brotli-devel | libbrotli-dev |

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

# Browser-specific
sudo ./spliff --comm firefox --filter-ipc    # Firefox without IPC noise
sudo ./spliff --comm chrome --filter-ipc     # Chrome without IPC noise

# Debugging
sudo ./spliff -d                         # Debug mode (raw events)
sudo ./spliff --show-libs                # Show discovered SSL libraries
```

## Example Output

```
[14:32:15.123] curl (1234) OpenSSL
  GET https://api.example.com/v1/users HTTP/2
  :authority: api.example.com
  :path: /v1/users
  accept: application/json
  user-agent: curl/8.0.1

[14:32:15.156] curl (1234) OpenSSL
  HTTP/2 200 OK (33ms)
  content-type: application/json
  content-length: 1234

  {"users": [...]}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              User Space                                  │
│                                                                         │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │   curl      │    │   Firefox   │    │   Chrome    │                │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                │
│          │                  │                  │                        │
│   ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐                │
│   │   OpenSSL   │    │    NSS      │    │  BoringSSL  │                │
│   │ SSL_read()  │    │  PR_Read()  │    │ SSL_read()  │                │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                │
│          │                  │                  │                        │
│          │    ┌─────────────┴─────────────┐    │                        │
│          │    │      eBPF Uprobes         │    │                        │
│          └────►  (attached to SSL funcs)  ◄────┘                        │
│               └─────────────┬─────────────┘                             │
│                             │                                           │
│               ┌─────────────▼─────────────┐                             │
│               │      spliff             │                             │
│               │  ┌─────────────────────┐  │                             │
│               │  │  HTTP/1.1 Parser    │  │                             │
│               │  │  (llhttp)           │  │                             │
│               │  ├─────────────────────┤  │                             │
│               │  │  HTTP/2 Parser      │  │                             │
│               │  │  (nghttp2 + HPACK)  │  │                             │
│               │  ├─────────────────────┤  │                             │
│               │  │  Decompressor       │  │                             │
│               │  │  (gzip/br/zstd)     │  │                             │
│               │  └─────────────────────┘  │                             │
│               └───────────────────────────┘                             │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                              Kernel Space                                │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                    eBPF Program (spliff.bpf.c)                 │  │
│   │                                                                  │  │
│   │   • Captures SSL_read/SSL_write arguments and return values     │  │
│   │   • Copies decrypted data to perf buffer                        │  │
│   │   • Tracks process/thread info                                  │  │
│   │   • Tracks SSL context for session correlation                  │  │
│   │                                                                  │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
spliff/
├── CMakeLists.txt          # CMake build configuration
├── Makefile                # Convenience wrapper for CMake
├── src/
│   ├── main.c              # Entry point, CLI parsing, event loop
│   ├── include/
│   │   └── spliff.h      # Public header, shared types
│   ├── bpf/
│   │   ├── spliff.bpf.c  # eBPF program (kernel space)
│   │   ├── bpf_loader.c    # BPF program loader
│   │   ├── probe_handler.c # Event filtering and processing
│   │   └── vmlinux.h       # Kernel type definitions
│   ├── protocol/
│   │   ├── http1.c         # HTTP/1.1 parser (llhttp)
│   │   └── http2.c         # HTTP/2 parser (nghttp2)
│   ├── content/
│   │   ├── decompressor.c  # gzip/brotli/zstd decompression
│   │   └── signatures.c    # File magic detection
│   ├── output/
│   │   └── display.c       # Terminal output formatting
│   └── util/
│       └── safe_str.c      # Safe string operations
├── tests/
│   ├── test_http1.c        # HTTP/1.1 parser tests
│   └── test_http2.c        # HTTP/2 parser tests
└── docs/
    ├── HTTP3_QUIC_IMPLEMENTATION_PLAN.md   # v0.6.0 planning
    ├── XDP_INTEGRATION_PLAN.md             # v0.7.0 planning
    └── EDR_XDR_ROADMAP.md                  # v0.8.0+ roadmap
```

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0.5.x | HTTP/1.1 + HTTP/2 + Multi-library support | **Current** |
| v0.6.0 | HTTP/3 + QUIC protocol support | Planned |
| v0.7.0 | XDP packet capture integration | Planned |
| v0.8.0 | NATS.io event streaming | Planned |
| v1.0.0 | EDR agent mode | Planned |

See [docs/](docs/) for detailed implementation plans.

## Known Limitations

- NSS captures all NSPR I/O (includes non-HTTP traffic, use `--filter-ipc`)
- Requires Linux kernel 5.x+ with BTF support
- QUIC/HTTP/3 not yet supported (planned for v0.6.0)

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
sudo ./spliff --comm firefox --filter-ipc
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
