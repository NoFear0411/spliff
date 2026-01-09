# sslsniff v0.3.0 - Technical Specifications

## Document Version
- **Version:** 3.0
- **Date:** 2026-01-09
- **Status:** v0.3.0 Released
- **License:** GPL-3.0-only (userspace) / GPL-2.0-only (BPF)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Current Architecture](#2-current-architecture)
3. [Module Reference](#3-module-reference)
4. [Build System](#4-build-system)
5. [Testing](#5-testing)
6. [Implementation Status](#6-implementation-status)
7. [Future Work](#7-future-work)
8. [Dependencies](#8-dependencies)
9. [API Reference](#9-api-reference)

---

## 1. Overview

### 1.1 Purpose

sslsniff is an eBPF-based SSL/TLS traffic sniffer that captures and decrypts HTTPS traffic by intercepting SSL library calls. It displays plaintext HTTP/1.1 and HTTP/2 traffic with full header parsing, body decompression, and smart content detection.

### 1.2 Key Features

| Feature | Description |
|---------|-------------|
| SSL/TLS Interception | OpenSSL, GnuTLS, NSS/NSPR library support |
| HTTP/1.1 Parsing | llhttp-based parser with chunked transfer decoding |
| HTTP/2 Parsing | nghttp2-based parser with full HPACK decompression |
| Body Handling | gzip, deflate, zstd, brotli decompression |
| Content Detection | 40+ file format signatures via magic bytes |
| Filtering | PID, PPID, process name, SSL library selection |
| Output | Colored terminal output with timestamps and latency |

### 1.3 Design Principles

- **Modular Architecture**: Separate modules for BPF, protocols, content, output
- **Library-Based Parsing**: Use battle-tested libraries (llhttp, nghttp2)
- **Memory Safety**: Bounded string operations, checked allocations
- **C23 Standard**: Modern C with GNU extensions for POSIX compatibility

---

## 2. Current Architecture

### 2.1 Directory Structure

```
sslsniff/
├── include/
│   └── sslsniff.h              # Public API, common types, version
├── src/
│   ├── main.c                  # Entry point, CLI, event loop (~800 lines)
│   ├── bpf/
│   │   ├── bpf_loader.c/.h     # BPF program loading, uprobe attachment
│   │   ├── probe_handler.c/.h  # Ring buffer handling, event filtering
│   │   ├── sslsniff.bpf.c      # eBPF kernel code (GPL-2.0)
│   │   └── vmlinux.h           # Kernel type definitions (BTF)
│   ├── protocol/
│   │   ├── http1.c/.h          # HTTP/1.1 parser (llhttp-based)
│   │   └── http2.c/.h          # HTTP/2 parser (nghttp2-based)
│   ├── content/
│   │   ├── decompressor.c/.h   # Compression handling
│   │   └── signatures.c/.h     # File format detection
│   ├── output/
│   │   └── display.c/.h        # Terminal output, formatting
│   └── util/
│       └── safe_str.c/.h       # Bounded string operations
├── tests/
│   ├── test_http1.c            # HTTP/1.1 parser unit tests (7 tests)
│   ├── test_http2.c            # HTTP/2 parser unit tests (8 tests)
│   └── test_common.c           # Shared test infrastructure
├── CMakeLists.txt              # CMake build configuration
├── Makefile                    # Convenience wrapper for CMake
├── README.md                   # User documentation
├── CHANGELOG.md                # Version history
├── SPECS.md                    # This document
└── LICENSE                     # GPL-3.0 license text
```

### 2.2 Component Diagram

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
│ bpf_loader    │──────▶│ http1 (llhttp) │──────▶│ display        │
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

### 2.3 Data Flow

1. **BPF Capture**: eBPF uprobes intercept SSL library calls
2. **Ring Buffer**: Captured data passed to userspace via BPF ring buffer
3. **Filtering**: Events filtered by PID/PPID/comm/library
4. **Protocol Detection**: HTTP/1.1 vs HTTP/2 detection
5. **Parsing**: llhttp or nghttp2 parses headers and body
6. **Decompression**: Body decompressed if needed (gzip/zstd/brotli)
7. **Display**: Formatted output to terminal

---

## 3. Module Reference

### 3.1 BPF Loader (`src/bpf/bpf_loader.c`)

Handles BPF program loading and uprobe attachment.

```c
/* Initialize loader */
int bpf_loader_init(bpf_loader_t *loader);

/* Load BPF object from file */
int bpf_loader_load(bpf_loader_t *loader, const char *filename);

/* Find SSL library path (safe, no shell injection) */
int bpf_loader_find_library(const char *name, char *path, size_t size);

/* Attach uprobe to symbol */
int bpf_loader_attach_uprobe(bpf_loader_t *loader, const char *lib,
                             const char *sym, const char *prog_name,
                             bool is_ret, bool debug);

/* Cleanup */
void bpf_loader_cleanup(bpf_loader_t *loader);
```

**Security Note**: `bpf_loader_find_library()` validates library names to prevent command injection (only alphanumeric, dots, dashes, underscores allowed).

### 3.2 Probe Handler (`src/bpf/probe_handler.c`)

Handles BPF ring buffer events and filtering.

```c
/* Initialize handler */
int probe_handler_init(probe_handler_t *handler);

/* Set filtering options */
void probe_handler_set_filter_comm(probe_handler_t *handler, const char *comm);
void probe_handler_set_filter_pids(probe_handler_t *handler, int *pids, int count);
void probe_handler_set_filter_ppid(probe_handler_t *handler, int ppid);

/* Setup ring buffer */
int probe_handler_setup_ringbuf(probe_handler_t *handler, struct bpf_object *obj);

/* Poll for events */
int probe_handler_poll(probe_handler_t *handler, int timeout_ms);

/* Cleanup */
void probe_handler_cleanup(probe_handler_t *handler);
```

**Filtering Features**:
- `--comm`: Checks both process comm name AND executable path
- `--ppid`: Traverses process tree up to 5 levels deep
- `--pid`: Supports comma-separated list of PIDs

### 3.3 HTTP/1.1 Parser (`src/protocol/http1.c`)

llhttp-based HTTP/1.1 parser.

```c
/* Initialize parser */
int http1_init(void);
void http1_cleanup(void);

/* Parse HTTP data */
int http1_parse(const uint8_t *data, size_t len, http_message_t *msg,
                uint8_t *body_buf, size_t body_buf_size, size_t *body_len);

/* Detection helpers */
bool http1_is_request(const uint8_t *data, size_t len);
bool http1_is_response(const uint8_t *data, size_t len);
```

**Features**:
- Uses `HTTP_BOTH` mode for automatic request/response detection
- Automatic chunked transfer encoding decoding
- Streaming callback architecture

### 3.4 HTTP/2 Parser (`src/protocol/http2.c`)

nghttp2-based HTTP/2 parser with full HPACK support.

```c
/* Initialize parser */
int http2_init(void);
void http2_cleanup(void);

/* Check for HTTP/2 preface */
bool http2_is_preface(const uint8_t *data, size_t len);

/* Check if PID has active session */
bool http2_has_session(uint32_t pid);

/* Process HTTP/2 frames */
void http2_process_frame(const uint8_t *data, int len, const ssl_data_event_t *event);

/* Stream management */
h2_stream_t *http2_get_stream(uint32_t pid, int32_t stream_id, bool create);
void http2_free_stream(uint32_t pid, int32_t stream_id);

/* Frame type name */
const char *http2_frame_name(int type);
```

**Features**:
- Full HPACK decompression via nghttp2
- Stream state tracking
- Request/response correlation
- Body accumulation with decompression
- Mid-connection detection (HEADERS, WINDOW_UPDATE, DATA frames)

### 3.5 Decompressor (`src/content/decompressor.c`)

Body decompression support.

```c
/* Initialize decompressor */
int decompressor_init(void);
void decompressor_cleanup(void);

/* Decompress body data */
int decompress_body(const uint8_t *input, size_t input_len,
                    const char *encoding,
                    uint8_t *output, size_t output_size);
```

**Supported Encodings**:
- gzip (always available via zlib)
- deflate (always available via zlib)
- zstd (optional, compile-time)
- brotli (optional, compile-time)

### 3.6 Signatures (`src/content/signatures.c`)

File format detection via magic bytes.

```c
/* Initialize signature database */
int signatures_init(void);
void signatures_cleanup(void);

/* Detect content type from body */
const char *signature_detect(const uint8_t *data, size_t len);

/* Check if content is binary */
bool signature_is_binary(const uint8_t *data, size_t len);
```

**Supported Formats** (40+):
- Images: JPEG, PNG, GIF, WebP, BMP, ICO, AVIF, HEIC
- Video: MP4, MOV, WebM, AVI, M4V
- Audio: MP3, OGG, FLAC, WAV, M4A
- Archives: ZIP, GZIP, ZSTD, 7-Zip, RAR, XZ, BZ2
- Documents: PDF
- Fonts: WOFF, WOFF2, TTF, OTF
- Binary: WebAssembly, ELF, Mach-O, Java class, SQLite

### 3.7 Display (`src/output/display.c`)

Terminal output formatting.

```c
/* Initialize display */
void display_init(bool use_colors);

/* Color helper */
const char *display_color(color_code_t code);

/* Display HTTP request */
void display_http_request(const http_message_t *msg, uint64_t delta_ns);

/* Display HTTP response */
void display_http_response(const http_message_t *msg, uint64_t delta_ns);

/* Display body content */
void display_body(const uint8_t *data, size_t len, const char *content_type);
```

### 3.8 Safe String (`src/util/safe_str.c`)

Bounded string operations.

```c
/* Safe string copy (always null-terminates) */
size_t safe_strcpy(char *dst, size_t dst_size, const char *src);

/* Safe memory copy */
size_t safe_memcpy(void *dst, size_t dst_size, const void *src, size_t src_size);
```

---

## 4. Build System

### 4.1 CMake Configuration

The project uses CMake 3.20+ as the primary build system.

**Key Settings**:
- C23 standard with GNU extensions
- Automatic dependency detection via pkg-config
- Optional features (zstd, brotli) auto-detected
- Sanitizers in debug builds (ASan, UBSan)
- CPack integration for packaging

### 4.2 Build Commands

```bash
# Using Makefile wrapper (recommended)
make              # Debug build with sanitizers
make release      # Optimized release build (stripped)
make relsan       # Release build with sanitizers
make test         # Build and run tests
make clean        # Remove build artifacts
make install      # Install to /usr/local/bin

# Direct CMake usage
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build

# Packaging
make package-deb  # Create Debian package
make package-rpm  # Create RPM package
```

### 4.3 CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Debug | Build type (Debug/Release/RelWithSan) |
| `ENABLE_SANITIZERS` | ON | Enable ASan/UBSan in debug builds |
| `ENABLE_ZSTD` | ON | Enable zstd decompression |
| `ENABLE_BROTLI` | ON | Enable brotli decompression |

### 4.4 Build Types

| Type       | Optimization | Sanitizers | Debug Info | Stripped |
|------------|--------------|------------|------------|----------|
| Debug      | -O0          | Yes        | Yes        | No       |
| Release    | -O2          | No         | No         | Yes      |
| RelWithSan | -O2          | Yes        | Yes        | No       |

---

## 5. Testing

### 5.1 Test Framework

Tests use a simple custom framework with colored output.

```c
#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)
```

### 5.2 Test Coverage

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_http1.c` | 7 | Request/response detection, parsing, chunked encoding |
| `test_http2.c` | 8 | Init/cleanup, preface detection, frame names, stream management |

### 5.3 Running Tests

```bash
# Build and run all tests
make test

# Run tests with verbose output
cd build && ctest --output-on-failure

# Run specific test
./build/test_http1
./build/test_http2
```

### 5.4 Test Output

```
=== HTTP/1.1 Parser Tests (llhttp) ===

TEST: http1_is_request... PASS
TEST: http1_is_response... PASS
TEST: http1_parse request... PASS
TEST: http1_parse response... PASS
TEST: http1_parse chunked response... PASS
TEST: HTTP_BOTH auto-detection... PASS
TEST: POST request with body... PASS

All tests passed!
```

---

## 6. Implementation Status

### 6.1 Completed Tasks

| Task | Description | Status |
|------|-------------|--------|
| Task 1 | Code Reorganization | ✅ Complete |
| Task 2 | HTTP/1.1 llhttp Integration | ✅ Complete |
| Task 3 | HTTP/2 nghttp2 Integration | ✅ Complete |
| Task 7 | CMake Build System | ✅ Complete |
| Task 9 | Code Quality & Safety | ✅ Complete |

### 6.2 Version History Summary

**v0.3.0 (2026-01-09)**:
- CMake build system migration
- GPL-3.0 licensing with SPDX identifiers
- C23 standard enforcement
- Fixed `--comm` filter (checks executable path)
- Fixed `--ppid` filter (traverses process tree)
- Fixed HTTP/2 mid-connection detection
- Security: Fixed command injection in library search
- Safety: Added malloc() checks, replaced atoi() with strtol()
- Added HTTP/2 unit tests

**v0.2.x (2026-01-08)**:
- TLS handshake detection (`-H` option)
- Latency measurement (`-l` option)
- NSS PR_Send/PR_Recv probes
- Multi-event body tracking
- Process name resolution fix

**v0.1.0 (2025-01-05)**:
- Initial release with OpenSSL, GnuTLS, NSS support
- HTTP/1.1 and HTTP/2 parsing
- gzip/deflate/zstd/brotli decompression
- File signature detection

### 6.3 Code Quality Improvements (v0.3.0)

| Issue             | Fix                                                    |
|-------------------|--------------------------------------------------------|
| Command injection | Removed popen() shell commands, added input validation |
| Integer overflow  | Replaced atoi() with strtol() + error checking         |
| Thread safety     | Replaced strtok() with strtok_r()                      |
| NULL dereference  | Added malloc() return value checks                     |
| Memory leak       | Fixed http2_cleanup() to free stream buffers           |

---

## 7. Future Work

### 7.1 Pending Tasks

| Task | Description | Priority |
|------|-------------|----------|
| Task 4 | HTTP/3 lsquic Integration | Low |
| Task 5 | Enhanced File Signatures | Low |
| Task 6 | Multi-threading Architecture | Medium |
| Task 8 | Output System Enhancements | Low |

### 7.2 HTTP/3 Notes

HTTP/3 requires:
1. QUIC interception (different from TCP-based SSL)
2. UDP socket handling (not currently captured)
3. QPACK header compression (via ls-qpack)
4. Connection ID tracking

### 7.3 Multi-threading Architecture

Proposed design:
- Dispatcher thread reads from BPF ring buffer
- Worker threads parse and decompress (flow affinity by PID)
- Output thread merges results in timestamp order
- Lock-free SPSC queues between threads

---

## 8. Dependencies

### 8.1 Required Dependencies

| Library | Version | Purpose | Fedora | Debian/Ubuntu |
|---------|---------|---------|--------|---------------|
| libbpf | 1.6.1+ | BPF loading | `libbpf-devel` | `libbpf-dev` |
| libelf | - | ELF parsing | `elfutils-libelf-devel` | `libelf-dev` |
| zlib | - | gzip/deflate | `zlib-devel` | `zlib1g-dev` |
| llhttp | 9.3.0+ | HTTP/1.1 parsing | `llhttp-devel` | `libllhttp-dev` |
| nghttp2 | 1.66.0+ | HTTP/2 parsing | `libnghttp2-devel` | `libnghttp2-dev` |
| clang | - | BPF compilation | `clang` | `clang` |

### 8.2 Optional Dependencies

| Library | Version | Purpose | Fedora | Debian/Ubuntu |
|---------|---------|---------|--------|---------------|
| libzstd | 1.5.7+ | zstd decompression | `libzstd-devel` | `libzstd-dev` |
| libbrotli | 1.2.0+ | brotli decompression | `brotli-devel` | `libbrotli-dev` |
| libasan | - | AddressSanitizer | `libasan` | `libasan6` |
| libubsan | - | UBSanitizer | `libubsan` | `libubsan1` |

### 8.3 System Requirements

- Linux kernel 5.x+ with BTF support (`/sys/kernel/btf/vmlinux`)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- x86_64 or aarch64 architecture

---

## 9. API Reference

### 9.1 Public Header (`include/sslsniff.h`)

```c
#define SSLSNIFF_VERSION "0.3.0"

/* Maximum sizes */
#define MAX_HEADER_NAME     256
#define MAX_HEADER_VALUE    4096
#define MAX_HEADERS         128
#define MAX_PATH_LEN        2048
#define MAX_METHOD_LEN      32
#define MAX_BODY_BUFFER     (1 << 20)  /* 1 MB */
#define TASK_COMM_LEN       16

/* Direction */
typedef enum {
    DIR_REQUEST = 0,
    DIR_RESPONSE = 1
} direction_t;

/* HTTP header */
typedef struct {
    char name[MAX_HEADER_NAME];
    char value[MAX_HEADER_VALUE];
} http_header_t;

/* Parsed HTTP message */
typedef struct {
    direction_t direction;

    /* Request fields */
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char authority[MAX_HEADER_VALUE];

    /* Response fields */
    int status_code;
    char status_text[64];

    /* Headers */
    http_header_t headers[MAX_HEADERS];
    int header_count;

    /* Body info */
    size_t content_length;
    char content_type[256];
    char content_encoding[64];

    /* HTTP/2 specific */
    int32_t stream_id;

    /* Metadata */
    uint32_t pid;
    char comm[TASK_COMM_LEN];
    uint64_t timestamp_ns;
} http_message_t;

/* Global configuration */
typedef struct {
    bool use_colors;
    bool show_body;
    bool compact_mode;
    bool show_latency;
    bool show_handshake;
    bool use_openssl;
    bool use_gnutls;
    bool use_nss;
} config_t;

extern config_t g_config;
```

### 9.2 Debug Macros

```c
#ifdef DEBUG
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_H2(fmt, ...)  fprintf(stderr, "[H2 DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) ((void)0)
#define DEBUG_H2(fmt, ...)  ((void)0)
#endif
```

---

## Appendix A: CLI Reference

```
sslsniff v0.3.0 - SSL/TLS Traffic Sniffer

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
  -b              Show request/response bodies
  -c              Compact mode (hide headers)
  -l              Show latency (SSL operation time)
  -H              Show TLS handshake events
  -d              Debug mode (verbose output)
  -C              Disable colored output

Other:
  -v, --version   Show version
  -h, --help      Show this help

Examples:
  sslsniff --comm curl         # Capture traffic from curl
  sslsniff -p 1234,5678        # Capture PIDs 1234 and 5678
  sslsniff --nss --ppid 1234   # NSS traffic from Firefox children
```

---

## Appendix B: Output Examples

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

---

*End of Specifications Document*
