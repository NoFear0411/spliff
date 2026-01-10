# sslsniff

eBPF-based SSL/TLS traffic sniffer for capturing decrypted HTTPS traffic.

sslsniff intercepts SSL library calls using eBPF uprobes to capture plaintext HTTP/1.1 and HTTP/2 traffic with full header parsing, body decompression, and smart content detection.

## Features

### SSL/TLS Library Support
- **OpenSSL**: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`
- **GnuTLS**: `gnutls_record_recv`, `gnutls_record_send`
- **NSS/NSPR**: `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send`, `SSL_ForceHandshake`
- **WolfSSL**: `wolfSSL_read`, `wolfSSL_write`

### ALPN Protocol Detection
Hook ALPN negotiation functions for definitive HTTP/1.1 vs HTTP/2 detection:
- OpenSSL: `SSL_get0_alpn_selected`
- GnuTLS: `gnutls_alpn_get_selected_protocol`
- NSS: `SSL_GetNextProto`
- WolfSSL: `wolfSSL_ALPN_GetProtocol`

### HTTP Protocol Support
- **HTTP/1.1**: Full header parsing via llhttp, chunked transfer encoding
- **HTTP/2**: Frame parsing via nghttp2 with full HPACK decompression
- Stream tracking with request/response correlation
- Mid-connection detection for late-joining sessions

### Body Handling
- **Decompression**: gzip, deflate (always), zstd, brotli (optional)
- **Content Detection**: 40+ file format signatures via magic bytes
- Smart text vs binary display
- Body accumulation for multi-packet responses

### Filtering
- Filter by PID(s): `-p 1234` or `-p 1234,5678`
- Filter by parent PID: `--ppid 1234` (traverses process tree)
- Filter by process name: `--comm curl` (checks executable path too)
- Filter by SSL library: `--openssl`, `--gnutls`, `--nss`
- Filter IPC traffic: `--filter-ipc` (reduces browser noise)

### Output Features
- Colored terminal output (disable with `-C`)
- Millisecond timestamps
- SSL operation latency (`-l`)
- TLS handshake events with duration (`-H`)
- Compact mode (`-c`) and body display (`-b`)
- Debug/hexdump mode (`-d`, `-x`)

### Advanced Features
- **Dynamic Library Discovery**: Finds SSL libraries via `/proc/PID/maps`
- **Container Support**: Works with Flatpak/Snap bundled libraries
- **Firefox Support**: Static paths for bundled NSS libraries
- **Connection Tracking**: Isolates sessions by `(PID, ssl_ctx)` tuple
- **Process Exit Cleanup**: BPF tracepoint cleans up when processes die

## Requirements

### System Requirements
- Linux kernel 5.x+ with BTF support (`/sys/kernel/btf/vmlinux`)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- x86_64 or aarch64 architecture

### Build Requirements
- CMake 3.20+
- Clang (for BPF compilation)
- C23-compatible compiler (GCC 14+ or Clang 16+)

## Dependencies

### Required

| Library | Purpose | Fedora/RHEL | Debian/Ubuntu |
|---------|---------|-------------|---------------|
| libbpf | BPF loading | `libbpf-devel` | `libbpf-dev` |
| libelf | ELF parsing | `elfutils-libelf-devel` | `libelf-dev` |
| zlib | gzip/deflate decompression | `zlib-devel` | `zlib1g-dev` |
| llhttp | HTTP/1.1 parsing | `llhttp-devel` | `libllhttp-dev` |
| nghttp2 | HTTP/2 parsing | `libnghttp2-devel` | `libnghttp2-dev` |
| clang | BPF compilation | `clang` | `clang` |

### Optional

| Library | Purpose | Fedora/RHEL | Debian/Ubuntu |
|---------|---------|-------------|---------------|
| libzstd | zstd decompression | `libzstd-devel` | `libzstd-dev` |
| libbrotli | brotli decompression | `brotli-devel` | `libbrotli-dev` |
| libasan | AddressSanitizer | `libasan` | `libasan6` |
| libubsan | UBSanitizer | `libubsan` | `libubsan1` |

### Install All Dependencies

**Fedora/RHEL:**
```bash
sudo dnf install libbpf-devel elfutils-libelf-devel zlib-devel \
    llhttp-devel libnghttp2-devel clang cmake \
    libzstd-devel brotli-devel
```

**Debian/Ubuntu:**
```bash
sudo apt install libbpf-dev libelf-dev zlib1g-dev \
    libllhttp-dev libnghttp2-dev clang cmake \
    libzstd-dev libbrotli-dev
```

## Building

### Using Makefile Wrapper (Recommended)

```bash
make              # Debug build with sanitizers
make release      # Optimized release build (stripped)
make relsan       # Release build with sanitizers (for testing)
make test         # Build and run tests
make clean        # Remove build artifacts
sudo make install # Install to /usr/local/bin
```

### Using CMake Directly

```bash
# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Release build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Install
sudo cmake --install build
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Debug | Build type (Debug/Release/RelWithSan) |
| `ENABLE_SANITIZERS` | ON | Enable ASan/UBSan in debug builds |
| `ENABLE_ZSTD` | ON | Enable zstd decompression |
| `ENABLE_BROTLI` | ON | Enable brotli decompression |

### Build Types

| Type | Optimization | Sanitizers | Debug Info | Stripped |
|------|--------------|------------|------------|----------|
| Debug | -O0 | Yes | Yes | No |
| Release | -O2 | No | No | Yes |
| RelWithSan | -O2 | Yes | Yes | No |

### Packaging

```bash
make package-deb  # Create Debian package
make package-rpm  # Create RPM package
```

## Usage

```
sslsniff v0.5.0 - SSL/TLS Traffic Sniffer

Usage: sslsniff [options]

Filtering:
  -p, --pid PID   Filter by PID(s), comma-separated
  --ppid PID      Filter by parent PID (captures all children)
  --comm NAME     Filter by process name or executable path

Library Selection:
  --openssl       Only attach to OpenSSL
  --gnutls        Only attach to GnuTLS
  --nss           Only attach to NSS

Display:
  -b              Show response/request bodies
  -c              Compact mode (hide headers)
  -l              Show latency (SSL operation time)
  -H              Show TLS handshake events
  -d              Debug mode (verbose output)
  -C              Disable colored output

Advanced:
  --filter-ipc    Filter out IPC/internal browser traffic
  --show-libs     Show all discovered SSL libraries

Other:
  -v, --version   Show version
  -h, --help      Show this help
```

## Examples

### Basic Usage

```bash
# Capture all HTTPS traffic
sudo sslsniff

# Capture traffic from a specific process
sudo sslsniff --comm curl

# Capture traffic from specific PIDs
sudo sslsniff -p 1234,5678

# Capture Firefox and all child processes
sudo sslsniff --ppid $(pgrep -f firefox) --nss
```

### Display Options

```bash
# Show request/response bodies
sudo sslsniff -b

# Show SSL operation latency
sudo sslsniff -l

# Show TLS handshake events
sudo sslsniff -H

# Compact mode (headers hidden)
sudo sslsniff -c

# Combine options
sudo sslsniff -b -l -H --comm curl
```

### Browser Traffic

```bash
# Firefox (uses NSS)
sudo sslsniff --nss --comm firefox

# Firefox with IPC filtering (cleaner output)
sudo sslsniff --nss --comm firefox --filter-ipc

# Chrome/Chromium (uses OpenSSL)
sudo sslsniff --openssl --comm chrome
```

### Library Discovery

```bash
# Show all discovered SSL libraries
sudo sslsniff --show-libs
```

## Output Examples

### HTTP/1.1 Request/Response

```
14:32:15.123 ← GET https://api.example.com/users HTTP/1.1 curl (12345)
  Host: api.example.com
  User-Agent: curl/8.0.0
  Accept: application/json

14:32:15.234 → 200 OK (application/json) [1234 bytes] [111ms] curl (12345)
  Content-Type: application/json
  Content-Encoding: gzip
  Content-Length: 567
```

### HTTP/2 with Body

```
14:32:15.345 ← GET https://example.com/data.json HTTP/2 curl (12345)
  :authority: example.com
  :path: /data.json
  accept: application/json

14:32:15.456 → 200 (application/json) [256 bytes] [H2 stream=1]
─── Body ───
{"status":"ok","data":[1,2,3]}
────────────
```

### TLS Handshake

```
14:32:15.100 🔒 TLS handshake complete [2.54ms] curl (12345)
```

### ALPN Detection

```
14:32:15.050 📋 ALPN: h2 selected curl (12345)
```

## File Signatures Supported

sslsniff detects 40+ binary file formats via magic bytes:

- **Images**: JPEG, PNG, GIF87/89, WebP, BMP, ICO, AVIF, HEIC
- **Video**: MP4, MOV, WebM, AVI, M4V, QuickTime
- **Audio**: MP3, OGG, FLAC, WAV, M4A
- **Archives**: ZIP, GZIP, ZSTD, 7-Zip, RAR, XZ, BZ2
- **Documents**: PDF
- **Fonts**: WOFF, WOFF2, TTF, OTF
- **Binary**: WebAssembly, ELF, Mach-O, Java class, SQLite

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              main.c                                  │
│           (CLI parsing, initialization, event loop, cleanup)         │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   bpf/        │       │   protocol/     │       │   output/       │
│ ───────────── │       │ ─────────────── │       │ ─────────────── │
│ bpf_loader    │──────▶│ http1 (llhttp)  │──────▶│ display         │
│ probe_handler │       │ http2 (nghttp2) │       │ (formatting)    │
│ sslsniff.bpf  │       └────────┬────────┘       └─────────────────┘
└───────────────┘                │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
             ┌─────────────┐           ┌─────────────┐
             │ decompressor│           │ signatures  │
             │ (content/)  │           │ (content/)  │
             └─────────────┘           └─────────────┘
```

## Known Limitations

- HPACK dynamic table not maintained (static table only)
- HTTP/2 CONTINUATION frames have basic support only
- NSS captures all NSPR I/O (use `--filter-ipc` to reduce noise)
- Requires kernel 5.x+ with BTF support
- HTTP/3 (QUIC) not yet supported

## Testing

```bash
# Build and run all tests
make test

# Run tests with verbose output
cd build && ctest --output-on-failure

# Run specific test
./build/test_http1
./build/test_http2
```

## License

- **Userspace code**: GPL-3.0-only
- **BPF kernel code**: GPL-2.0-only

```
sslsniff - eBPF-based SSL/TLS traffic sniffer
Copyright (C) 2025-2026 sslsniff authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### v0.5.0 (2026-01-10)
- ALPN protocol detection for all SSL libraries
- IPC/internal traffic filtering (`--filter-ipc`)
- Enhanced process scanner with `--show-libs`
- WolfSSL library support
- Firefox bundled library path discovery

### v0.4.0 (2026-01-09)
- Process exit handler for cleanup
- Dynamic library discovery via `/proc/PID/maps`
- SSL context connection tracking `(PID, ssl_ctx)`

### v0.3.0 (2026-01-09)
- CMake build system migration
- GPL-3.0 licensing with SPDX identifiers
- C23 standard with comprehensive safety fixes
- Fixed `--comm` and `--ppid` filters
- HTTP/2 mid-connection detection
- Security: Fixed command injection vulnerability

### v0.2.x (2026-01-08)
- TLS handshake detection (`-H`)
- Latency measurement (`-l`)
- NSS PR_Send/PR_Recv probes
- Multi-event body tracking

### v0.1.0 (2025-01-05)
- Initial release with OpenSSL, GnuTLS, NSS support
- HTTP/1.1 and HTTP/2 parsing
- Decompression and file signature detection

## Contributing

Contributions are welcome. Please ensure:
- Code follows the existing style (C23, GNU extensions)
- All tests pass (`make test`)
- No sanitizer warnings in debug builds
- Commits are signed off

## Related Projects

- [bcc](https://github.com/iovisor/bcc) - BPF Compiler Collection
- [libbpf](https://github.com/libbpf/libbpf) - BPF library
- [llhttp](https://github.com/nodejs/llhttp) - HTTP/1.1 parser
- [nghttp2](https://github.com/nghttp2/nghttp2) - HTTP/2 library
