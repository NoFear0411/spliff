# sslsniff - eBPF SSL/TLS Traffic Sniffer

**Version 0.3.0**

Capture and display decrypted HTTPS traffic using eBPF uprobes. Intercepts SSL/TLS library calls to show plaintext HTTP/1.1 and HTTP/2 traffic with full header parsing, body decompression, and smart content display.

## Features

### SSL/TLS Library Support
- **OpenSSL** - `SSL_read`/`SSL_write` and `SSL_read_ex`/`SSL_write_ex`
- **GnuTLS** - `gnutls_record_recv`/`gnutls_record_send`
- **NSS/NSPR** - `PR_Read`/`PR_Write`/`PR_Recv`/`PR_Send`

### Protocol Support
- **HTTP/1.1** - Full header parsing via llhttp, chunked transfer decoding, body aggregation
- **HTTP/2** - Full nghttp2 integration with HPACK decompression, stream tracking, frame reassembly

### Body Handling
- **Automatic decompression** - gzip, deflate, zstd (optional), brotli (optional)
- **Smart content display** - Shows text content, detects binary via magic bytes
- **40+ file signatures** - JPEG, PNG, GIF, WebP, PDF, MP4, ZIP, WASM, and more
- **Request/response correlation** - Links bodies to their originating requests

### Output Features
- **Colored output** - Requests (cyan), responses (green/yellow/red by status)
- **Timestamps** - Millisecond precision on all events
- **Latency measurement** - Shows request→response time for HTTP/1.1
- **Flexible filtering** - By PID, process name, parent PID, or SSL library

## Building

### Quick Start

```bash
# Configure and build
mkdir build && cd build
cmake ..
make

# Or use the Makefile wrapper
make          # Debug build with sanitizers
make release  # Optimized build (-O2, stripped)
```

### Build Options

```bash
# CMake options
cmake -DCMAKE_BUILD_TYPE=Release ..     # Release build
cmake -DENABLE_SANITIZERS=OFF ..        # Disable sanitizers
cmake -DENABLE_ZSTD=OFF ..              # Disable zstd support
cmake -DENABLE_BROTLI=OFF ..            # Disable brotli support

# Makefile wrapper targets
make          # Debug build with sanitizers
make release  # Optimized release build (stripped, no sanitizers)
make relsan   # Optimized build with sanitizers (for testing)
make clean    # Remove build artifacts
make package  # Create .deb package
make rpm      # Create .rpm package
```

### Dependencies

**Required:**
- CMake 3.20+
- clang (for BPF compilation)
- libbpf-dev (or libbpf-devel)
- libelf-dev (or elfutils-libelf-devel)
- zlib1g-dev (or zlib-devel)
- libllhttp-dev (or llhttp-devel) - HTTP/1.1 parsing
- libnghttp2-dev (or nghttp2-devel) - HTTP/2 parsing
- Linux kernel 5.x+ with BTF support

**Optional (auto-detected):**
- libzstd-dev - Enables zstd decompression
- libbrotli-dev - Enables brotli decompression
- libasan, libubsan - Sanitizers for debug builds

### Installing Dependencies

**Fedora/RHEL:**
```bash
sudo dnf install cmake clang libbpf-devel elfutils-libelf-devel zlib-devel \
    llhttp-devel libnghttp2-devel libasan libubsan
```

**Ubuntu/Debian:**
```bash
sudo apt install cmake clang libbpf-dev libelf-dev zlib1g-dev \
    libllhttp-dev libnghttp2-dev
```

## Usage

```bash
# Capture all SSL/TLS traffic (all libraries)
sudo ./sslsniff

# Filter by process name
sudo ./sslsniff --comm curl
sudo ./sslsniff --comm firefox

# Filter by PID(s)
sudo ./sslsniff -p 12345
sudo ./sslsniff -p 1234,5678,9012

# Filter by parent PID (useful for Firefox/Chrome with multiple processes)
sudo ./sslsniff --ppid 12345

# Specific SSL library only
sudo ./sslsniff --openssl
sudo ./sslsniff --nss --comm firefox
sudo ./sslsniff --gnutls

# Show response/request bodies
sudo ./sslsniff -b --comm curl

# Compact mode (headers hidden)
sudo ./sslsniff -c --comm curl

# Debug mode (show raw data hexdump)
sudo ./sslsniff -d --comm curl

# Combine options
sudo ./sslsniff --nss --ppid 12345 -b -c
```

## Command Line Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-p` | `--pid` | Filter by PID(s), comma-separated |
| | `--ppid` | Filter by parent PID (captures all children) |
| | `--comm` | Filter by process name (exact match) |
| | `--openssl` | Attach to OpenSSL only |
| | `--gnutls` | Attach to GnuTLS only |
| | `--nss` | Attach to NSS/NSPR only |
| `-b` | `--body` | Show request/response bodies |
| `-c` | `--compact` | Hide HTTP headers |
| `-d` | `--debug` | Show raw data hexdump |
| `-x` | `--hexdump` | Alias for --debug |
| `-C` | `--no-color` | Disable colored output |
| `-h` | `--help` | Show help message |

## Output Examples

### HTTP/1.1 Request/Response
```
14:32:15.123 ▶ GET https://api.example.com/users [HTTP/1.1] curl (PID 12345)
  Host: api.example.com
  User-Agent: curl/8.0.0
  Accept: application/json

14:32:15.234 ◀ 200 OK (application/json) [1234 bytes] [111ms] curl (PID 12345)
  Content-Type: application/json
  Content-Encoding: gzip
  Content-Length: 567
```

### HTTP/2 with Body Display
```
14:32:15.345 ▶ GET https://example.com/data.json [H2 stream=1] curl (PID 12345)
  :authority: example.com
  :path: /data.json
  accept: application/json

14:32:15.456 ◀ 200 (application/json) [256 bytes] [H2 stream=1]
14:32:15.456 ◀ BODY (application/json) [stream=1] ← GET example.com/data.json
  --- Body (256 bytes, was 512 gzip) ---
  {"status":"ok","data":[1,2,3]}
```

### Binary Content Detection
```
14:32:15.567 ◀ 200 (image/jpeg) [45678 bytes] [H2 stream=3]
14:32:15.567 ◀ BODY (image/jpeg) [stream=3] ← GET example.com/photo.jpg
  --- Body (45678 bytes) [JPEG image] ---
```

### TLS Handshake Detection
```
14:32:15.100 ◆ TLS HANDSHAKE curl (PID 12345) → api.example.com:443
```

## How It Works

1. **eBPF Uprobes** - Attaches to SSL library functions at runtime
2. **Plaintext Capture** - Intercepts data after decryption (read) and before encryption (write)
3. **Protocol Detection** - Identifies HTTP/1.1 vs HTTP/2 via connection preface
4. **Header Parsing** - Parses text headers (HTTP/1.1) or HPACK-compressed headers (HTTP/2)
5. **Body Handling** - Aggregates chunked/streamed data, decompresses, detects content type
6. **Smart Display** - Shows text content, summarizes binary with file type detection

## File Signature Detection

Binary content is identified by magic bytes before display. Supported formats:

| Category | Formats |
|----------|---------|
| Images | JPEG, PNG, GIF, WebP, BMP, ICO, AVIF, HEIC |
| Video | MP4, MOV, WebM, AVI, M4V |
| Audio | MP3, OGG, FLAC, WAV, M4A |
| Archives | ZIP, GZIP, ZSTD, 7-Zip, RAR, XZ, BZ2 |
| Documents | PDF |
| Fonts | WOFF, WOFF2, TTF, OTF |
| Binary | WebAssembly, ELF, Mach-O, Java class, SQLite |

## Known Limitations

- **HPACK Dynamic Table** - Not maintained across frames (static table + Huffman only)
- **NSS/Firefox** - Captures all NSPR I/O; internal IPC is filtered but some noise may appear
- **Mid-connection capture** - May miss initial frames if attached after connection established
- **HTTP/2 CONTINUATION** - Basic support only
- **Kernel requirement** - Needs BTF-enabled kernel (most distros 5.x+)

## Troubleshooting

### "Failed to load BPF object"
- Ensure kernel has BTF support: `ls /sys/kernel/btf/vmlinux`
- Check kernel version: `uname -r` (needs 5.x+)

### "Failed to attach uprobe"
- Verify library path exists: `ls /usr/lib/x86_64-linux-gnu/libssl.so*`
- Check library has symbols: `nm -D /usr/lib/x86_64-linux-gnu/libssl.so.3 | grep SSL_read`

### No output when traffic expected
- Verify process is using expected SSL library
- Try without filters first: `sudo ./sslsniff`
- Use `--debug` to see raw data

### Firefox showing garbage
- Use `--ppid` with main Firefox PID for cleaner output
- Internal IPC uses NSPR but isn't HTTP

## Requirements

- Linux kernel 5.x+ with BTF (`/sys/kernel/btf/vmlinux` must exist)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- x86_64 or aarch64 architecture

## Version History

### v0.3.0 (2026-01-09)
- Migrated to CMake build system
- Re-licensed under GPL-3.0 (GPL-2.0 for BPF code)
- C23 standard enforcement
- Fixed `--comm` filter to check executable path (Firefox child processes now work)
- Fixed `--ppid` filter to traverse full process tree
- Fixed HTTP/2 mid-connection detection
- Added `RelWithSan` build type (optimized + sanitizers)

### v0.2.6 (2026-01-08)
- Added NSS SSL_ForceHandshake probe for TLS handshake detection
- Fixed HTTP/2 session detection for multi-process browsers

### v0.2.0 (2026-01-07)
- Modular code architecture (split from monolithic single-file)
- Integrated llhttp library for HTTP/1.1 parsing
- Integrated nghttp2 library for HTTP/2 parsing
- Memory-safe string utilities (C23)

### v0.1.0 (2025-01-05)
- Initial stable release
- OpenSSL, GnuTLS, NSS support
- HTTP/1.1 and HTTP/2 parsing
- HPACK with Huffman decoding
- gzip/deflate/zstd/brotli decompression
- Smart body display with 40+ file signatures
- PID, PPID, and process name filtering
- Colored output with timestamps

## License

GPL-3.0-only (userspace code) / GPL-2.0-only (BPF kernel code)

See [LICENSE](LICENSE) for details.
