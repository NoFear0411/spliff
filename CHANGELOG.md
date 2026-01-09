# Changelog

All notable changes to sslsniff will be documented in this file.

## [0.4.0] - 2026-01-09

### Added
- **Process Exit Handler**: BPF tracepoint to cleanup sessions when processes die
  - Added `sched_process_exit` tracepoint handler in BPF
  - Added `http2_cleanup_pid()` to free HTTP/2 sessions and stream buffers
  - Added `cleanup_pending_bodies_pid()` to free HTTP/1.1 pending body buffers
  - Prevents memory leaks when monitored processes exit unexpectedly

- **Dynamic Library Discovery**: Find SSL libraries via `/proc/PID/maps`
  - Added `bpf_loader_discover_libraries()` to scan process memory maps
  - Added `bpf_loader_find_library_dynamic()` with fallback to static paths
  - Supports Flatpak/Snap containers and bundled SSL libraries
  - When `--pid` is specified, scans those PIDs for library paths

- **SSL Context Connection Tracking**: Track connections by `(PID, ssl_ctx)` tuple
  - Isolates HTTP/2 sessions per actual SSL connection
  - Supports multiple concurrent SSL connections per process (e.g., browser tabs)
  - Correctly tracks HTTP/1.1 body accumulation per connection

### Changed
- Library discovery now tries dynamic `/proc/maps` discovery before static paths
- Event structure includes `ssl_ctx` field for connection isolation

## [0.3.0] - 2026-01-09

### Changed
- **Build System**: Migrated from legacy Makefile to CMake
  - CMake 3.20+ required
  - Makefile retained as wrapper for backward compatibility
  - Added CPack support for .deb and .rpm packaging
- **License**: Re-licensed under GPL-3.0-only (GPL-2.0-only for BPF code)
- **C Standard**: Now requires C23 with GNU extensions

### Added
- `RelWithSan` build type: Optimized build (-O2) with sanitizers for testing
- SPDX license identifiers in all source files
- Proper CMake sanitizer detection (compile + link test)
- HTTP/2 unit tests (`tests/test_http2.c`) with 9 test cases
- `make test` target for running all tests

### Security
- **Fixed command injection vulnerability** in `bpf_loader_find_library()`
  - Removed unsafe popen() with shell command containing user input
  - Now uses direct filesystem search with input validation
- Added input validation for library names (alphanumeric, dots, dashes only)

### Code Quality
- Replaced all `atoi()` calls with `strtol()` + error checking
- Replaced `strtok()` with thread-safe `strtok_r()`
- Added `malloc()` return value checks (prevents NULL dereference)
- Fixed memory leak in `http2_cleanup()` (stream body buffers now freed)

### Fixed
- **--comm filter**: Now checks both process comm name AND executable path
  - Firefox child processes ("Web Content", "Socket Thread") now match `--comm firefox`
- **--ppid filter**: Now traverses full process tree (up to 5 levels)
  - Correctly captures grandchildren and deeper descendants
- **HTTP/2 mid-connection detection**: Recognizes HEADERS, WINDOW_UPDATE, DATA frames
  - Previously only detected SETTINGS frames on stream 0
- **HTTP/2 buffer corruption**: Fixed infinite buffering when joining mid-stream
  - Added frame header validation (length, type, stream ID sanity checks)
  - Added automatic recovery mechanism for corrupted state
  - Prevents buffer filling up and blocking all HTTP/2 traffic
- **Thread filtering**: Removed overly aggressive filtering of "Web Content", "Renderer"
  - These Firefox processes actually make HTTP requests
- **NSS non-HTTP traffic**: Filter out local file I/O captured by NSPR probes
  - ELF, Mach-O, SQLite, Java class files are silently skipped
  - Reduces noise from Firefox loading shared libraries via NSPR
- CMake sanitizer library detection (checks both compile and link)

## [0.2.6] - 2026-01-08

### Added
- NSS handshake probe (SSL_ForceHandshake in libssl3.so) for Firefox TLS handshake tracking

## [0.2.5] - 2026-01-08

### Added
- NSS PR_Send and PR_Recv probes for better NSPR socket I/O coverage
- Root privilege check at startup with helpful error message

## [0.2.4] - 2026-01-08

### Fixed
- TLS handshake events now display correctly
- Separate BPF map for handshake timestamps (fixes race with SSL read/write)
- Filter bypass for handshake events (buf_filled=0 was being filtered)
- Skip in-progress handshake events (SSL_ERROR_WANT_READ/WRITE)

### Added
- SSL_connect probe for client-side TLS handshakes

## [0.2.3] - 2026-01-08

### Added
- `-l` option: Show SSL operation latency in request/response output
- `-H` option: Show TLS handshake events with duration
- Handshake probes for OpenSSL (SSL_do_handshake) and GnuTLS (gnutls_handshake)

## [0.2.2] - 2026-01-08

### Fixed
- Multi-event body tracking for responses split across SSL_read events
- Process name resolution via /proc/PID/comm (fixes thread name display)
- Compressed body decompression for gzip/brotli/zstd chunked responses
- Header display in non-compact mode

## [0.2.1] - 2025-01-08

### Changed
- **HTTP/1.1 Parser**: Replaced custom parser with llhttp library
  - Uses HTTP_BOTH mode for automatic request/response detection
  - Automatic chunked transfer encoding decoding
  - Streaming callback architecture for robust parsing
- **Simplified main.c**: Unified request/response handling via `http1_parse()`

### Added
- `http1_parse()` API with integrated body handling
- `is_chunked`, `http_major`, `http_minor` fields in `http_message_t`
- Unit tests for HTTP/1.1 parser (`tests/test_http1.c`)
- llhttp as required dependency in Makefile

## [0.1.0] - 2025-01-05

### Added
- **SSL/TLS Library Support**
  - OpenSSL: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`
  - GnuTLS: `gnutls_record_recv`, `gnutls_record_send`
  - NSS/NSPR: `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send`

- **HTTP Protocol Support**
  - HTTP/1.1 full header parsing
  - HTTP/1.1 chunked transfer encoding
  - HTTP/1.1 body aggregation and buffering
  - HTTP/2 frame parsing (HEADERS, DATA, SETTINGS, WINDOW_UPDATE, etc.)
  - HTTP/2 HPACK header decompression
  - HTTP/2 Huffman decoding
  - HTTP/2 stream tracking with request/response correlation

- **Body Handling**
  - Automatic decompression: gzip, deflate
  - Optional decompression: zstd, brotli (compile-time)
  - Smart content display (text vs binary detection)
  - 40+ file signature detection via magic bytes
  - Request correlation for body display

- **Filtering Options**
  - Filter by PID(s): `-p 1234` or `-p 1234,5678`
  - Filter by parent PID: `--ppid 1234`
  - Filter by process name: `--comm curl`
  - Filter by SSL library: `--openssl`, `--gnutls`, `--nss`

- **Output Features**
  - Colored output (disable with `-C`)
  - Millisecond timestamps
  - Latency measurement for HTTP/1.1 (`-l`)
  - TLS handshake detection (`-H`)
  - Compact mode (`-c`)
  - Body display (`-b`)
  - Debug/hexdump mode (`-d`, `-x`)

- **Build System**
  - Auto-detection of Linux distribution
  - Auto-detection of optional libraries (zstd, brotli)
  - `make deps` for dependency installation
  - `make release` for optimized builds

### File Signatures Supported
Images: JPEG, PNG, GIF87/89, WebP, BMP, ICO, AVIF, HEIC
Video: MP4, MOV, WebM, AVI, M4V, QuickTime
Audio: MP3, OGG, FLAC, WAV, M4A
Archives: ZIP, GZIP, ZSTD, 7-Zip, RAR, XZ, BZ2
Documents: PDF
Fonts: WOFF, WOFF2, TTF, OTF
Binary: WebAssembly, ELF, Mach-O, Java class, SQLite

### Known Limitations
- HPACK dynamic table not maintained (static table only)
- HTTP/2 CONTINUATION frames have basic support only
- NSS captures all NSPR I/O (includes non-HTTP traffic)
- Requires kernel 5.x+ with BTF support

---

## Version Numbering

This project uses semantic versioning: MAJOR.MINOR.PATCH

- MAJOR: Incompatible changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes, backward compatible
