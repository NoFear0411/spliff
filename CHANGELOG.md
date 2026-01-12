# Changelog

All notable changes to spliff will be documented in this file.

## [0.8.0] - 2026-01-13

### Added
- **XDP Packet-Level Flow Tracking**: High-performance packet capture at network interface level
  - Auto-attaches to all suitable network interfaces (physical and virtual)
  - Native mode with automatic SKB fallback for unsupported drivers
  - Protocol detection: TLS, HTTP/2 preface, HTTP/1.x at packet level
  - Flow state machine tracks connection lifecycle (SYN, data, FIN/RST)

- **sock_ops Cookie Caching ("Golden Thread")**: Socket-to-packet correlation
  - `sock_ops` BPF program hooks TCP connection establishment events
  - Caches socket cookies at `ACTIVE_ESTABLISHED_CB` and `PASSIVE_ESTABLISHED_CB`
  - XDP reads cached cookies via `flow_cookie_map` for uprobe correlation
  - Enables linking packet-level data with SSL session data

- **Connection Warm-up**: Existing connection tracking at startup
  - Uses netlink `SOCK_DIAG` to enumerate existing TCP sockets
  - Seeds `flow_cookie_map` with connections established before attachment
  - Enables correlation with long-lived connections

- **XDP Statistics**: Debug-mode performance metrics
  - Packet counts (total, TCP)
  - Flow lifecycle (created, classified, ambiguous)
  - Gatekeeper hits, cookie failures, ringbuf drops
  - Displayed at shutdown with `-d` flag

### Technical Details
- BPF verifier compatibility: "check-pointer-first" pattern for bounds validation
  - Prevents Clang from inverting comparisons that do arithmetic on `pkt_end`
  - `asm volatile` barriers lock pointer arithmetic before comparisons
- New BPF maps: `flow_states`, `flow_cookie_map`, `xdp_events`, `xdp_stats_map`
- sock_ops replaces SK_LOOKUP (which doesn't support `bpf_get_socket_cookie`)
- Cgroup-based attachment for system-wide socket cookie tracking

## [0.7.1] - 2026-01-12

### Added
- **HTTP/1.1 Request-Response Correlation**: Responses now show associated request URL
  - Request cache tracks (pid, ssl_ctx) → (method, path, host) per connection
  - Response display includes URL from cached request for correlation
  - Both single-threaded and multi-threaded modes supported

- **ALPN Protocol Indicator**: Display shows negotiated protocol
  - Format: `ALPN:h2` or `ALPN:http/1.1`
  - Shown for both requests and responses
  - Uses actual ALPN from TLS negotiation when available

### Changed
- **Unified Display Format**: Consistent output regardless of HTTP version
  - Request: `→ METHOD https://host/path ALPN:protocol process (PID) [latency] [stream N]`
  - Response: `← STATUS https://host/path ALPN:protocol content-type (size) process (PID) [latency] [stream N]`
  - Arrow direction: `→` for outgoing requests, `←` for incoming responses

### Fixed
- **TLS Handshake Probe Duplication**: Removed redundant `SSL_do_handshake` probes
  - `SSL_connect` internally calls `SSL_do_handshake`, causing duplicate events
  - Now only attaches to `SSL_connect` for OpenSSL handshake detection
  - Note: Multiple handshakes per connection are still possible (session resumption)

## [0.7.0] - 2026-01-12

### Added
- **BPF-Level Socket Family Filtering**: Kernel-level IPC traffic elimination
  - CO-RE helper walks `task_struct → files_struct → fdtable → file → socket → sock → skc_family`
  - Filters AF_UNIX (IPC) traffic at BPF level before reaching userspace
  - Keeps only AF_INET/AF_INET6 (web) traffic for processing

- **SSL_set_fd Hook for OpenSSL**: Maps SSL* to OS file descriptor
  - Enables socket family lookup for OpenSSL connections
  - `tracked_sessions` map stores protocol type and socket family per connection
  - `ssl_to_fd` map tracks SSL context to fd mapping

- **NSS SSL Layer Verification**: Filters non-SSL PRFileDesc traffic
  - `SSL_ImportFD` hook tracks verified SSL connections
  - `is_nss_ssl_fd()` check in PR_Write/PR_Read exit probes
  - Eliminates Firefox IPC noise from non-SSL NSPR layers

- **Session Cleanup Hooks**: Prevents BPF map exhaustion
  - `SSL_free` (OpenSSL): Cleans up `tracked_sessions` and `ssl_to_fd`
  - `PR_Close` (NSS): Cleans up `nss_ssl_fds` and `tracked_sessions`
  - `gnutls_deinit` (GnuTLS): Cleans up `tracked_sessions`

### Changed
- **HPACK Mid-Stream Recovery**: Improved error handling strategy
  - Removed aggressive table reset that corrupted subsequent decodes
  - New approach: Skip first few errors, recreate inflater after 5+ persistent errors
  - Tracks `hpack_error_count` and `hpack_success_count` per connection
  - `mid_stream_joined` flag for detected mid-stream connections

- **IPC Filtering Always-On**: Removed `--filter-ipc` CLI option
  - BPF kernel-level filtering handles socket family checks
  - Userspace heuristics provide additional backup filtering
  - Simplifies user experience - optimal filtering is automatic

### Technical Details
- New BPF maps: `tracked_sessions`, `ssl_to_fd`, `ssl_fd_args_map`
- ALPN parsing in BPF: Routes connections to correct parser (llhttp vs nghttp2)
- Session state machine with protocol detection (PROTO_HTTP1, PROTO_HTTP2)

## [0.6.1] - 2026-01-12

### Fixed
- **Segmentation Fault in Multi-Threaded Mode**: Fixed format string mismatch in `output_write`
  - Format string had 14 `%s` specifiers but only 13 string arguments
  - `msg.pid` (uint32_t) was being interpreted as a pointer, causing SEGV

- **HTTP/2 Requests Displayed as Responses**: Fixed `event_type` not passed to HTTP/2 processor
  - `ssl_data_event_t.event_type` field now correctly set in all bpf_event initializers
  - Requests no longer misidentified as responses with status 0

- **HTTP/2 HPACK Error Recovery**: Reset dynamic table on decompression failure
  - Mid-stream capture causes HPACK dynamic table desync (unavoidable limitation)
  - On inflate error, now clears and reinitializes the HPACK dynamic table
  - Prevents cascading decode failures after joining existing connection

- **HTTP/2 Frame Validation**: Added frame type vs stream_id validation per RFC 7540
  - DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE, CONTINUATION require stream_id > 0
  - SETTINGS, PING, GOAWAY require stream_id == 0
  - WINDOW_UPDATE allowed on both connection (0) and streams

- **Suppress HPACK Decode Failures**: Skip display of responses with status=0
  - Status code 0 indicates HPACK decompression failed (mid-stream capture)
  - Prevents confusing "← 0" output in response display

### Changed
- Enhanced IPC/noise filtering for raw READ/WRITE events
  - Small writes (≤13 bytes) on HTTP/2 connections suppressed as control frames
  - Block-sized reads (4096, 8192, etc.) without HTTP signatures filtered
  - Common control frame sizes (4, 8, 9, 13 bytes) automatically suppressed

## [0.6.0] - 2026-01-11

### Added
- **Multi-Threaded Event Processing**: Complete lock-free threading infrastructure
  - Dispatcher thread polls BPF ring buffer and routes events to workers
  - Worker threads process HTTP/1.1 and HTTP/2 with per-worker isolated state
  - Output thread serializes formatted output to prevent interleaving
  - Connection affinity: `hash(pid, ssl_ctx) % num_workers` ensures same connection always routes to same worker
  - Auto-detects optimal worker count: `max(1, CPUs-3)` capped at 16 workers

- **Lock-Free Data Structures**: Uses Concurrency Kit (ck) library
  - SPSC rings for dispatcher→worker and worker→output communication
  - Lock-free object pools for event and output message allocation
  - Adaptive wait strategy: spin (1000 iters) → yield (10 iters) → eventfd sleep (10ms)

- **Per-Worker State Isolation**: Thread-safe protocol processing
  - Per-worker ALPN cache for protocol negotiation tracking
  - Per-worker pending body buffers for HTTP/1.1 response reassembly
  - Per-worker decompression buffers (eliminates static buffer races)
  - Per-worker HTTP/2 session and stream tracking

- **New CLI Options**:
  - `-t, --threads N`: Set worker thread count (0=auto, default: auto)
  - `--no-threading`: Disable multi-threading for single-threaded mode

### Changed
- CMake now shows CK library in dependencies and threading status in options
- Both HTTP/1.1 and HTTP/2 protocols use the threading infrastructure
- Graceful shutdown drains all queues before exiting
- Statistics printed at shutdown showing events processed/dropped per worker

### Dependencies
- New optional dependency: `ck` (Concurrency Kit) library
  - Fedora: `sudo dnf install ck-devel`
  - Ubuntu/Debian: `sudo apt install libck-dev`
  - Falls back to single-threaded mode if ck is not available

## [0.5.3] - 2026-01-11

### Added
- **Enhanced File Signature Detection**: Expanded from ~27 to ~50 web-relevant signatures
  - New formats: AVIF, HEIC, HEVC, M4A, M4B, 3GP, DASH, XZ, LZ4, BZIP2, FLV, TIFF, PSD, CUR
  - Container format variants: RAR5, ZIP empty/spanned archives, multiple MP3 frame sync patterns
  - Mach-O endianness variants, Android DEX files
  - ISO Base Media File Format (ISOBMFF) brand detection for MP4/MOV/HEIC/AVIF variants

- **File Class Categorization**: New `file_class_t` enum for semantic grouping
  - Categories: Image, Video, Audio, Archive, Document, Font, Executable, Database, Container
  - `signature_class_name()` API returns human-readable class names

- **"Most Specific Wins" Matching**: Signatures sorted by magic length at initialization
  - Uses qsort for automatic priority ordering (longest magic bytes first)
  - Prevents short signatures from shadowing more specific ones

- **Trailer Byte Validation**: Optional end-of-file signature verification
  - PNG (IEND chunk), GIF (00 3B), JPEG (EOI marker), PDF (%%EOF)
  - `signature_detect_full()` API with `validate_trailer` parameter
  - Shows "(trailer mismatch)" warning when validation fails

- **New CLI Option `-x`**: Hexdump body display with file signature detection
  - Shows detected file type, class, and size in body header
  - Always displays hex dump (16 bytes per line with ASCII)
  - Implies `-b` (show body)

### Changed
- `signature_result_t` struct provides full detection metadata: description, class, is_binary, trailer_valid, confidence
- Legacy `signature_detect()` API preserved for backward compatibility
- Signature initialization checks return value and warns on failure

## [0.5.1] - 2026-01-11

### Fixed
- **Firefox IPC Filtering**: Removed "Socket Thread" from IPC thread patterns
  - "Socket Thread" is Firefox's legitimate web traffic thread, not IPC
  - Fixes issue where `--filter-ipc` filtered out all Firefox web traffic

- **HTTP/2 Preface Detection**: Added partial preface pattern matching
  - Recognizes `"PRI "` prefix to avoid false IPC classification
  - Fixes HTTP/2 sessions being filtered before establishment

- **HTTP/2 Control Frame Suppression**: Suppress noisy control frames in release mode
  - Hides SETTINGS, WINDOW_UPDATE, PING, RST_STREAM, PRIORITY frames
  - Small writes (< 9 bytes) on active HTTP/2 sessions are suppressed
  - Debug mode (`-d`) preserves all raw events for protocol development

### Changed
- Test executables excluded from default build target (use `make test` to build and run)
- Added `debug_mode` to global config for conditional raw event display

### Removed
- Unused `is_verified_nss_ssl_fd()` function (cleanup)

## [0.5.0] - 2026-01-10

### Added
- **ALPN Protocol Detection**: Hook ALPN negotiation functions for definitive HTTP/1.1 vs HTTP/2 detection
  - OpenSSL: `SSL_get0_alpn_selected`
  - GnuTLS: `gnutls_alpn_get_selected_protocol`
  - NSS: `SSL_GetNextProto`
  - WolfSSL: `wolfSSL_ALPN_GetProtocol`
  - ALPN events display negotiated protocol before data transfer begins

- **IPC/Internal Traffic Filtering**: New `--filter-ipc` option to reduce browser noise
  - Content-based detection (HTTP signatures vs binary data ratio)
  - Known internal thread pattern filtering (Cache2 I/O, Timer, Socket Thread, etc.)
  - Filters non-HTTP traffic from multi-process browsers like Firefox

- **Enhanced Process Scanner**: Comprehensive SSL library discovery
  - Scans ALL running processes (removed early-exit limitation)
  - Tracks multiple unique library paths per type
  - New `--show-libs` option displays discovery statistics
  - Reports: processes scanned, SSL-enabled processes, unique paths found

- **WolfSSL Support**: Added support for wolfSSL library
  - Automatic discovery of `libwolfssl.so`
  - Hooks for `wolfSSL_read` and `wolfSSL_write`

- **Firefox Bundled Library Paths**: Static path discovery for Firefox's bundled NSS
  - `/usr/lib/firefox/`, `/usr/lib64/firefox/`
  - `/opt/firefox/`
  - `/snap/firefox/current/usr/lib/firefox/`

### Changed
- Library discovery now returns extended results with all unique paths per library type
- `lib_discovery_result_t` structure expanded with statistics and multi-path tracking

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
