# HTTP/3 + QUIC Implementation Plan

**Status:** Planning / Research Complete
**Target Version:** 0.6.0
**Last Updated:** 2026-01-11

---

## Executive Summary

This document outlines the implementation strategy for adding HTTP/3 and QUIC protocol support to sslsniff. HTTP/3 uses QUIC (UDP-based) instead of TCP+TLS, requiring significant architectural changes to the current session tracking model.

---

## Table of Contents

1. [Background](#1-background)
2. [Current Architecture](#2-current-architecture)
3. [Technical Challenges](#3-technical-challenges)
4. [Implementation Approach](#4-implementation-approach)
5. [Required Libraries](#5-required-libraries)
6. [Hook Points by QUIC Library](#6-hook-points-by-quic-library)
7. [Session Management Redesign](#7-session-management-redesign)
8. [Protocol Detection](#8-protocol-detection)
9. [User-Space Parser Integration](#9-user-space-parser-integration)
10. [Implementation Phases](#10-implementation-phases)
11. [Known Limitations](#11-known-limitations)
12. [References](#12-references)

---

## 1. Background

### What is HTTP/3?

HTTP/3 is the third major version of HTTP, standardized in RFC 9114. Key differences from HTTP/1.1 and HTTP/2:

| Feature | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---------|----------|--------|--------|
| Transport | TCP | TCP | QUIC (UDP) |
| Encryption | Optional (TLS) | Optional (TLS) | **Mandatory** (built-in) |
| Header Compression | None | HPACK | **QPACK** |
| Multiplexing | None | Yes (streams) | Yes (streams) |
| Head-of-line blocking | Yes | Partially | **No** |

### Why is HTTP/3 Different?

In HTTP/1.1 and HTTP/2, we hook SSL library functions (`SSL_read`, `SSL_write`) to capture plaintext after decryption. The transport (TCP) and encryption (TLS) are separate layers.

In HTTP/3, **QUIC merges transport and encryption**. The "TLS handshake" happens within QUIC packets, and encryption is per-packet, not per-stream. This means:

1. No separate `SSL_read`/`SSL_write` to hook
2. QUIC libraries handle both transport and crypto
3. Must hook QUIC-specific functions to get decrypted data

---

## 2. Current Architecture

### Session Tracking Model

```
Current Key: (PID, ssl_ctx)

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Process   │────▶│  SSL_ctx    │────▶│   Session   │
│   (PID)     │     │  (pointer)  │     │   State     │
└─────────────┘     └─────────────┘     └─────────────┘
```

- **PID**: Process identifier
- **ssl_ctx**: SSL structure pointer from OpenSSL/GnuTLS/NSS
- Works because: One SSL context = One TLS connection

### Event Flow

```
SSL Library Function (e.g., SSL_write)
        ↓ [uprobe]
eBPF Probe (sslsniff.bpf.c)
        ↓ [ring buffer]
User-space Handler (probe_handler.c)
        ↓ [callback]
Protocol Parser (http1.c / http2.c)
        ↓
Display Output (display.c)
```

### Existing Protocol Support

- `PROTO_HTTP1` - Full support via llhttp
- `PROTO_HTTP2` - Full support via nghttp2
- `PROTO_HTTP3` - **Declared but not implemented**

---

## 3. Technical Challenges

### 3.1 UDP vs TCP

| Aspect | TCP (Current) | UDP (QUIC) |
|--------|---------------|------------|
| Connection ID | Socket + SSL context | QUIC Connection ID |
| Ordering | Guaranteed | Per-stream only |
| Reliability | Built-in | QUIC handles it |
| Multiplexing | TCP connection = 1 stream | Multiple streams per connection |

**Impact**: Cannot use `ssl_ctx` pointer for session tracking.

### 3.2 QUIC Connection IDs

QUIC connections are identified by Connection IDs (CIDs), not socket addresses. CIDs can:
- Change during connection (connection migration)
- Be different for client→server vs server→client
- Be rotated for privacy

**Impact**: Need new session key model based on CIDs.

### 3.3 QPACK State

QPACK (RFC 9204) is HTTP/3's header compression, similar to HPACK but designed for out-of-order delivery.

**Critical**: QPACK uses a dynamic table that's built incrementally. If we miss the initial "Encoder Stream" packets, we cannot decode subsequent headers.

**Impact**: Must capture connection from the start, or accept partial decoding.

### 3.4 Multiple QUIC Implementations

| Library | Used By | Hooking Complexity |
|---------|---------|-------------------|
| quiche (Cloudflare) | curl, nginx | Medium (C API) |
| Chromium QUIC | Chrome, Electron | Hard (C++ internal) |
| lsquic (LiteSpeed) | LiteSpeed, H2O | Medium (C API) |
| msquic (Microsoft) | Windows, .NET | Medium (C API) |
| ngtcp2 | curl (alt), nghttpx | Medium (C API) |
| Go crypto/tls | Go apps | Hard (static, no symbols) |
| Quinn (Rust) | Rust apps | Hard (static, mangled) |

**Impact**: Need library-specific probes; cannot have one universal hook.

### 3.5 Static Linking

Many HTTP/3-capable applications (especially Go and Rust) statically link their QUIC implementation. This means:
- No `.so` files to probe
- Symbols may be stripped or mangled
- Must find offsets via `nm` or DWARF info

---

## 4. Implementation Approach

### Recommended: Hook QUIC Libraries at Stream Level

Hook QUIC library functions that handle **decrypted stream data**, similar to how we hook `SSL_read`/`SSL_write`.

```
Application
    ↓ (HTTP/3 request)
┌─────────────────────────────────────┐
│  QUIC Library (quiche, lsquic, etc) │
│  • Handles QUIC packets             │
│  • Decrypts data                    │
│  • Reassembles streams              │
└─────────────────────────────────────┘
    ↓ [HOOK HERE - stream read/write]
┌─────────────────────────────────────┐
│  sslsniff eBPF probe                │
│  • Capture decrypted HTTP/3 frames  │
│  • Extract Connection ID            │
│  • Submit to ring buffer            │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  User-space nghttp3 parser          │
│  • Parse HTTP/3 frames              │
│  • QPACK decompression              │
│  • Stream reassembly                │
└─────────────────────────────────────┘
```

### Why Not Hook Lower?

Hooking at the UDP socket level (`recvfrom`/`sendto`) gives us encrypted QUIC packets. We'd need to:
1. Reassemble QUIC packets
2. Decrypt them (need keys)
3. Handle QUIC flow control

This is essentially reimplementing QUIC—not practical.

---

## 5. Required Libraries

### Must Have

| Library | Purpose | Notes |
|---------|---------|-------|
| **nghttp3** | HTTP/3 frame parsing | Handles QPACK, streams, frames |

### Optional (for transport-level hooking)

| Library | Purpose | Notes |
|---------|---------|-------|
| ngtcp2 | QUIC packet parsing | If hooking raw QUIC |
| quictls | OpenSSL fork with QUIC | Alternative to ngtcp2 |

### nghttp3 Key Functions

```c
// Session management
nghttp3_conn_client_new() / nghttp3_conn_server_new()
nghttp3_conn_del()

// Data processing
nghttp3_conn_read_stream()    // Feed captured data
nghttp3_conn_writev_stream()  // For request building (if needed)

// Callbacks
nghttp3_callbacks.recv_header    // Header received
nghttp3_callbacks.recv_data      // Body data received
nghttp3_callbacks.end_stream     // Stream completed
```

---

## 6. Hook Points by QUIC Library

### 6.1 quiche (Cloudflare)

Used by: curl (with `--with-quiche`), nginx (quiche module)

```c
// Stream operations
quiche_conn_stream_recv()   // Read decrypted stream data
quiche_conn_stream_send()   // Write stream data

// Connection info
quiche_conn_trace_id()      // Get connection ID for tracking
```

**Library paths:**
- `/usr/lib/libquiche.so`
- `/usr/local/lib/libquiche.so`

### 6.2 lsquic (LiteSpeed)

Used by: LiteSpeed Web Server, H2O

```c
// Stream operations
lsquic_stream_read()
lsquic_stream_write()
lsquic_stream_readv()
lsquic_stream_writev()

// Connection info
lsquic_conn_id()
```

**Library paths:**
- `/usr/lib/liblsquic.so`
- `/usr/local/lib/liblsquic.so`

### 6.3 msquic (Microsoft)

Used by: .NET, Windows applications

```c
// Stream operations
MsQuicStreamReceive()
MsQuicStreamSend()

// Or the callback-based API
QUIC_STREAM_CALLBACK
```

**Library paths:**
- `/usr/lib/libmsquic.so`
- Windows: `msquic.dll`

### 6.4 ngtcp2

Used by: curl (with `--with-ngtcp2`), nghttpx

```c
// Stream operations
ngtcp2_conn_read_stream()
ngtcp2_conn_write_stream()

// Connection info
ngtcp2_conn_get_scid() / ngtcp2_conn_get_dcid()
```

**Library paths:**
- `/usr/lib/libngtcp2.so`
- `/usr/local/lib/libngtcp2.so`

### 6.5 Chromium QUIC (quiche - Google's version)

Used by: Chrome, Chromium, Electron apps

**Challenge**: C++ with complex class hierarchy

```cpp
// Potential hook points
quic::QuicStream::OnStreamFrame()
quic::QuicStream::WriteOrBufferData()
quic::QuicSpdyStream::OnBodyAvailable()
```

**Note**: Symbols are mangled. Need to find via:
```bash
nm -C /opt/google/chrome/chrome | grep QuicStream
```

### 6.6 Go Applications

Go's `crypto/tls` with QUIC support (Go 1.21+) or `quic-go` library.

**Challenge**: Statically linked, symbols stripped.

**Potential approach**:
- Use BTF/DWARF info if available
- Hook at syscall level and correlate
- May not be feasible without source modification

---

## 7. Session Management Redesign

### New Session Key Model

```
New Key: (PID, connection_id)

Where connection_id is:
- QUIC SCID (Source Connection ID) for client
- QUIC DCID (Destination Connection ID) for server
- Or: Hash of both for uniqueness
```

### Proposed Data Structures

```c
// New BPF map for QUIC connections
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct quic_conn_key);
    __type(value, struct quic_conn_info);
} quic_connections SEC(".maps");

struct quic_conn_key {
    uint32_t pid;
    uint8_t connection_id[20];  // Max QUIC CID length
    uint8_t cid_len;
};

struct quic_conn_info {
    uint64_t start_time_ns;
    uint32_t stream_count;
    uint8_t alpn[8];  // "h3" typically
};
```

### User-Space Session Structure

```c
typedef struct {
    uint32_t pid;
    uint8_t connection_id[20];
    uint8_t cid_len;

    nghttp3_conn *h3_conn;           // HTTP/3 session
    nghttp3_qpack_decoder *qpack;    // QPACK decoder

    // Stream tracking
    h3_stream_t streams[MAX_H3_STREAMS];
    size_t stream_count;

    // Encoder/decoder streams (QPACK)
    int64_t enc_stream_id;
    int64_t dec_stream_id;
    int64_t ctrl_stream_id;

} h3_connection_t;
```

---

## 8. Protocol Detection

### Enhanced Detection Function

```c
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_HTTP3
} protocol_t;

protocol_t detect_protocol(const uint8_t *data, size_t len,
                           const char *alpn_proto) {
    if (len < 4) return PROTO_UNKNOWN;

    // 1. Check ALPN first (most reliable)
    if (alpn_proto && alpn_proto[0]) {
        if (strcmp(alpn_proto, "h3") == 0 ||
            strncmp(alpn_proto, "h3-", 3) == 0) {
            return PROTO_HTTP3;
        }
        if (strcmp(alpn_proto, "h2") == 0) {
            return PROTO_HTTP2;
        }
        if (strcmp(alpn_proto, "http/1.1") == 0) {
            return PROTO_HTTP1;
        }
    }

    // 2. HTTP/2 Connection Preface
    if (len >= 24 && memcmp(data, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        return PROTO_HTTP2;
    }

    // 3. HTTP/2 Frame Header (9 bytes)
    if (len >= 9) {
        uint32_t frame_len = (data[0] << 16) | (data[1] << 8) | data[2];
        uint8_t frame_type = data[3];
        if (frame_len <= 16384 && frame_type <= 0x09) {
            return PROTO_HTTP2;
        }
    }

    // 4. HTTP/1.1 Methods and Responses
    if (memcmp(data, "GET ", 4) == 0 || memcmp(data, "POST", 4) == 0 ||
        memcmp(data, "PUT ", 4) == 0 || memcmp(data, "HEAD", 4) == 0 ||
        memcmp(data, "HTTP/", 5) == 0) {
        return PROTO_HTTP1;
    }

    // 5. HTTP/3 Frame Detection (after QUIC decryption)
    // HTTP/3 frames: DATA (0x00), HEADERS (0x01), SETTINGS (0x04), etc.
    // Variable-length integer encoding for type and length
    uint8_t frame_type = data[0];
    if (frame_type <= 0x0d || frame_type == 0x1f) {
        // Likely HTTP/3 frame type
        // Additional validation: check length encoding
        return PROTO_HTTP3;
    }

    return PROTO_UNKNOWN;
}
```

### HTTP/3 Frame Types

| Type | Name | Description |
|------|------|-------------|
| 0x00 | DATA | Body content |
| 0x01 | HEADERS | Request/response headers (QPACK encoded) |
| 0x03 | CANCEL_PUSH | Cancel server push |
| 0x04 | SETTINGS | Connection settings |
| 0x05 | PUSH_PROMISE | Server push promise |
| 0x07 | GOAWAY | Graceful shutdown |
| 0x0d | MAX_PUSH_ID | Max push ID |

---

## 9. User-Space Parser Integration

### nghttp3 Session Initialization

```c
#include <nghttp3/nghttp3.h>

static nghttp3_callbacks h3_callbacks = {
    .recv_header = on_h3_recv_header,
    .end_headers = on_h3_end_headers,
    .recv_data = on_h3_recv_data,
    .end_stream = on_h3_end_stream,
    .deferred_consume = on_h3_deferred_consume,
};

int h3_session_init(h3_connection_t *conn, bool is_server) {
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);

    // Create nghttp3 connection
    int rv;
    if (is_server) {
        rv = nghttp3_conn_server_new(&conn->h3_conn, &h3_callbacks,
                                     &settings, nghttp3_mem_default(), conn);
    } else {
        rv = nghttp3_conn_client_new(&conn->h3_conn, &h3_callbacks,
                                     &settings, nghttp3_mem_default(), conn);
    }

    if (rv != 0) {
        fprintf(stderr, "nghttp3_conn_new failed: %s\n",
                nghttp3_strerror(rv));
        return -1;
    }

    return 0;
}
```

### Processing Captured Data

```c
int process_h3_event(h3_connection_t *conn, int64_t stream_id,
                     const uint8_t *data, size_t len, bool fin) {
    ssize_t consumed = nghttp3_conn_read_stream(conn->h3_conn,
                                                 stream_id,
                                                 data, len,
                                                 fin ? 1 : 0);

    if (consumed < 0) {
        if (consumed == NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED) {
            // QPACK state out of sync - likely missed initial packets
            fprintf(stderr, "[WARN] QPACK decompression failed on stream %ld\n",
                    stream_id);
            return -1;
        }
        fprintf(stderr, "nghttp3_conn_read_stream error: %s\n",
                nghttp3_strerror((int)consumed));
        return -1;
    }

    return 0;
}
```

### Callback Implementations

```c
static int on_h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token,
                             nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                             uint8_t flags, void *user_data,
                             void *stream_user_data) {
    h3_connection_t *ctx = user_data;

    nghttp3_vec name_vec = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec value_vec = nghttp3_rcbuf_get_buf(value);

    printf("[H3][PID %u][Stream %ld] Header: %.*s: %.*s\n",
           ctx->pid, stream_id,
           (int)name_vec.len, name_vec.base,
           (int)value_vec.len, value_vec.base);

    // Store pseudo-headers
    if (name_vec.len > 0 && name_vec.base[0] == ':') {
        // :method, :path, :scheme, :authority, :status
        // Store in stream context
    }

    return 0;
}

static int on_h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                           const uint8_t *data, size_t datalen,
                           void *user_data, void *stream_user_data) {
    h3_connection_t *ctx = user_data;

    printf("[H3][PID %u][Stream %ld] Body: %zu bytes\n",
           ctx->pid, stream_id, datalen);

    // Process body (decompression, signature detection, etc.)

    return 0;
}
```

---

## 10. Implementation Phases

### Phase 1: Foundation (nghttp3 integration)

**Goals:**
- Add nghttp3 as a dependency
- Implement basic HTTP/3 frame parsing in user-space
- Add `src/protocol/http3.c` with session management
- Update protocol detection logic

**Files to create/modify:**
- `src/protocol/http3.c` (new)
- `src/protocol/http3.h` (new)
- `src/main.c` (protocol routing)
- `CMakeLists.txt` (nghttp3 dependency)

**Deliverable:** Can parse HTTP/3 frames if fed manually.

### Phase 2: quiche Support

**Goals:**
- Add eBPF probes for quiche library
- Hook `quiche_conn_stream_recv` and `quiche_conn_stream_send`
- Implement connection ID extraction
- Test with curl built with quiche

**Files to create/modify:**
- `src/bpf/sslsniff.bpf.c` (new probes)
- `src/bpf/bpf_loader.c` (quiche discovery)
- `src/protocol/http3.c` (session management)

**Deliverable:** Can capture HTTP/3 traffic from curl with quiche.

### Phase 3: Additional QUIC Libraries

**Goals:**
- Add probes for lsquic, msquic, ngtcp2
- Generalize connection ID tracking
- Handle library-specific quirks

**Deliverable:** Support for major QUIC implementations.

### Phase 4: Chromium Support (Optional)

**Goals:**
- Investigate Chromium's QUIC hooking
- Handle C++ name mangling
- May require per-version offsets

**Deliverable:** Chrome HTTP/3 capture (if feasible).

### Phase 5: Polish

**Goals:**
- QPACK dynamic table persistence
- Connection migration handling
- Performance optimization
- Documentation

---

## 11. Known Limitations

### Unavoidable

1. **Go applications**: Statically linked, stripped symbols - likely not hookable
2. **Rust applications**: Same issues as Go
3. **QPACK state loss**: If capture starts mid-connection, headers may not decode

### Design Decisions

1. **No raw QUIC packet parsing**: Too complex, requires crypto keys
2. **Library-specific probes**: No universal hook like `SSL_read`
3. **Connection ID tracking**: May lose track on migration

### Mitigations

- ALPN-based early detection (capture from connection start)
- Graceful degradation (show raw bytes if QPACK fails)
- Clear warnings when limitations apply

---

## 12. References

### Specifications

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) - QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) - Using TLS to Secure QUIC
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) - HTTP/3
- [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) - QPACK: Field Compression for HTTP/3

### Libraries

- [nghttp3](https://github.com/ngtcp2/nghttp3) - HTTP/3 library
- [ngtcp2](https://github.com/ngtcp2/ngtcp2) - QUIC library
- [quiche](https://github.com/cloudflare/quiche) - Cloudflare's QUIC implementation
- [lsquic](https://github.com/litespeedtech/lsquic) - LiteSpeed QUIC
- [msquic](https://github.com/microsoft/msquic) - Microsoft QUIC

### Tools

- `nm -C <binary>` - List symbols with demangling
- `readelf -s <binary>` - ELF symbol table
- `bpftool btf dump file <binary>` - BTF info

---

## Appendix A: Quick Reference

### Build with nghttp3

```bash
# Install nghttp3
git clone https://github.com/ngtcp2/nghttp3.git
cd nghttp3
autoreconf -fi
./configure --prefix=/usr/local
make && sudo make install

# Update sslsniff CMakeLists.txt
find_package(PkgConfig REQUIRED)
pkg_check_modules(NGHTTP3 REQUIRED libnghttp3)
target_link_libraries(sslsniff ${NGHTTP3_LIBRARIES})
```

### Test with curl + quiche

```bash
# Build curl with quiche support
git clone https://github.com/curl/curl.git
cd curl
./buildconf
./configure --with-quiche=/path/to/quiche
make

# Test HTTP/3
./src/curl --http3 https://cloudflare-quic.com/
```

---

*Document created: 2026-01-11*
*Author: sslsniff development*
