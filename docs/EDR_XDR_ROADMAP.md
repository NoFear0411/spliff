# sslsniff EDR/XDR Evolution Roadmap

**Status:** Strategic Planning
**Document Version:** 1.0
**Last Updated:** 2026-01-11

---

## Executive Summary

This document outlines the evolution of sslsniff from an SSL/TLS traffic inspection tool into a lightweight, high-performance EDR/XDR agent capable of:

- **Deep Packet Inspection** of encrypted traffic (pre-encryption interception)
- **Dual-view visibility** (network packets + decrypted content)
- **Real-time event streaming** via NATS.io to external processing platform
- **Minimal host footprint** - heavy processing offloaded to platform

### Design Philosophy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGENT/PLATFORM ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   HOST (Agent - sslsniff)              PLATFORM (Collector/Analyzer)        │
│   ════════════════════════             ═══════════════════════════════      │
│                                                                             │
│   Responsibilities:                    Responsibilities:                    │
│   • eBPF/XDP packet capture            • Heavy ML/classification            │
│   • SSL/TLS interception               • Correlation & enrichment           │
│   • Protocol parsing (H1/H2/H3)        • Threat detection rules             │
│   • Event serialization                • Historical analysis                │
│   • NATS streaming                     • Alerting & response                │
│                                        • Storage & retention                │
│                                        • Dashboard & reporting              │
│                                                                             │
│   CPU Target: < 5% idle                CPU Target: Scale horizontally       │
│   Memory: < 100MB                      Memory: As needed                    │
│   Latency: < 1ms event emit            Latency: Seconds acceptable          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [Version Roadmap](#1-version-roadmap)
2. [Current State (v0.5.x)](#2-current-state-v05x)
3. [HTTP/3 + QUIC (v0.6.0)](#3-http3--quic-v060)
4. [XDP Integration (v0.7.0)](#4-xdp-integration-v070)
5. [NATS.io Event Streaming (v0.8.0)](#5-natsio-event-streaming-v080)
6. [Traffic Classification (v0.9.0)](#6-traffic-classification-v090)
7. [EDR Agent Ready (v1.0.0)](#7-edr-agent-ready-v100)
8. [Platform Components](#8-platform-components)
9. [Event Schema Design](#9-event-schema-design)
10. [Security Considerations](#10-security-considerations)
11. [Performance Budgets](#11-performance-budgets)
12. [Dependencies](#12-dependencies)

---

## 1. Version Roadmap

```
Timeline (not to scale - versions, not dates)
═══════════════════════════════════════════════════════════════════════════════

v0.5.3 ──► v0.6.0 ──► v0.7.0 ──► v0.8.0 ──► v0.9.0 ──► v1.0.0
  │           │           │           │           │           │
  │           │           │           │           │           │
  ▼           ▼           ▼           ▼           ▼           ▼
┌─────┐   ┌─────┐     ┌─────┐     ┌─────┐     ┌─────┐     ┌─────┐
│CURR │   │H3/  │     │XDP  │     │NATS │     │CLASS│     │EDR  │
│STABLE│   │QUIC │     │PKT  │     │STREAM│    │ENGINE│    │READY│
└─────┘   └─────┘     └─────┘     └─────┘     └─────┘     └─────┘
   │           │           │           │           │           │
   │           │           │           │           │           │
   ▼           ▼           ▼           ▼           ▼           ▼
 H1/H2      + H3        + Packet    + Event     + Traffic   + Full
 TLS        QUIC        metadata    streaming   categories  agent
 uprobes    support     XDP/DPDK    NATS.io     basic DPI   mode
```

### Version Summary

| Version | Codename | Primary Feature | Agent Impact |
|---------|----------|-----------------|--------------|
| v0.5.x | Stable | HTTP/1 + HTTP/2 + TLS interception | Current baseline |
| v0.6.0 | Quiver | HTTP/3 + QUIC protocol support | +QUIC libraries |
| v0.7.0 | Falcon | XDP/AF_XDP/DPDK packet capture | +Packet visibility |
| v0.8.0 | Stream | NATS.io event streaming | +Network output |
| v0.9.0 | Sentinel | Traffic classification engine | +Categories |
| v1.0.0 | Guardian | EDR agent mode | Production ready |

---

## 2. Current State (v0.5.x)

### Capabilities
- eBPF uprobe-based SSL/TLS interception
- Auto-detection of SSL libraries (OpenSSL, BoringSSL, GnuTLS, NSS, WolfSSL)
- HTTP/1.1 parsing via llhttp
- HTTP/2 parsing via nghttp2 (HPACK decompression)
- ALPN-based protocol detection
- Per-process/container filtering
- JSON and text output formats

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         CURRENT v0.5.x                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   Process   │────►│  SSL_read/  │────►│   sslsniff  │       │
│  │  (Firefox,  │     │  SSL_write  │     │   eBPF      │       │
│  │   curl...)  │     │   uprobes   │     │   program   │       │
│  └─────────────┘     └─────────────┘     └──────┬──────┘       │
│                                                  │              │
│                                                  ▼              │
│                                          ┌─────────────┐       │
│                                          │  User-space │       │
│                                          │  H1/H2      │       │
│                                          │  parsing    │       │
│                                          └──────┬──────┘       │
│                                                  │              │
│                                                  ▼              │
│                                          ┌─────────────┐       │
│                                          │   stdout/   │       │
│                                          │   file      │       │
│                                          └─────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. HTTP/3 + QUIC (v0.6.0)

*See: `docs/HTTP3_QUIC_IMPLEMENTATION_PLAN.md`*

### New Capabilities
- QUIC library hooking (quiche, lsquic, msquic, ngtcp2)
- HTTP/3 parsing via nghttp3
- QPACK header decompression
- Connection ID-based session tracking
- Multi-path QUIC support

### Key Changes
```
┌─────────────────────────────────────────────────────────────────┐
│                         v0.6.0 ADDITIONS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NEW: QUIC library uprobes                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  quiche_conn_send/recv                                   │   │
│  │  lsquic_stream_read/write                                │   │
│  │  msquic: StreamReceive/StreamSend                        │   │
│  │  ngtcp2_conn_read_pkt/write_pkt                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  NEW: HTTP/3 parser                                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  nghttp3_conn_* APIs                                     │   │
│  │  QPACK encoder/decoder                                   │   │
│  │  Stream multiplexing                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  NEW: Session tracking by Connection ID                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  (PID, ssl_ctx) → (PID, connection_id)                   │   │
│  │  Survives IP migration                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. XDP Integration (v0.7.0)

*See: `docs/XDP_INTEGRATION_PLAN.md`*

### New Capabilities
- Packet-level visibility (encrypted wire format)
- Content-based protocol detection
- Dynamic Alt-Svc port learning
- Multi-mode deployment (kernel → XDP → AF_XDP → DPDK)
- TLS/QUIC fingerprinting (JA3/JA4)
- Flow metadata (timing, sizing, direction)

### Dual-View Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    v0.7.0 DUAL-VIEW VISIBILITY                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────┐     ┌───────────────────────┐       │
│  │     PACKET LAYER      │     │   APPLICATION LAYER   │       │
│  │     (XDP/DPDK)        │     │      (Uprobes)        │       │
│  ├───────────────────────┤     ├───────────────────────┤       │
│  │ • Encrypted packets   │     │ • Decrypted content   │       │
│  │ • Wire timing         │     │ • HTTP headers/body   │       │
│  │ • Packet sizes        │     │ • Cookies, tokens     │       │
│  │ • TLS record headers  │     │ • API payloads        │       │
│  │ • QUIC headers        │     │ • File transfers      │       │
│  │ • SNI, ALPN           │     │                       │       │
│  │ • JA3/JA4 fingerprint │     │                       │       │
│  └───────────┬───────────┘     └───────────┬───────────┘       │
│              │                             │                    │
│              └──────────────┬──────────────┘                    │
│                             ▼                                   │
│              ┌───────────────────────────────┐                  │
│              │      FLOW CORRELATION         │                  │
│              │  Match packets ↔ decrypted    │                  │
│              └───────────────────────────────┘                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. NATS.io Event Streaming (v0.8.0)

### Overview

NATS.io provides the event streaming backbone, enabling:
- Real-time event delivery to processing platform
- Minimal agent overhead (fire-and-forget publishing)
- Built-in clustering and failover
- Subject-based routing for event types

### NATS C Client Integration

Using [nats.c](https://github.com/nats-io/nats.c) - the official NATS C client library.

```c
// Core NATS integration structures
typedef struct {
    natsConnection *conn;
    natsOptions *opts;

    // Subject prefixes
    const char *subject_prefix;  // e.g., "sslsniff.events"

    // Agent identity
    char agent_id[64];           // Unique agent identifier
    char hostname[256];

    // Stats
    _Atomic uint64_t published;
    _Atomic uint64_t errors;
    _Atomic uint64_t bytes_sent;

    // Reconnection handling
    bool auto_reconnect;
    int max_reconnect_attempts;
    int reconnect_wait_ms;

} nats_publisher_t;

// Initialize NATS publisher
nats_publisher_t* nats_publisher_create(const nats_config_t *config) {
    nats_publisher_t *pub = calloc(1, sizeof(*pub));

    natsOptions_Create(&pub->opts);
    natsOptions_SetURL(pub->opts, config->url);

    // TLS configuration
    if (config->tls_enabled) {
        natsOptions_SetSecure(pub->opts, true);
        natsOptions_LoadCATrustedCertificates(pub->opts, config->ca_file);
        natsOptions_LoadCertificatesChain(pub->opts,
            config->cert_file, config->key_file);
    }

    // Authentication
    if (config->auth_token) {
        natsOptions_SetToken(pub->opts, config->auth_token);
    } else if (config->user && config->password) {
        natsOptions_SetUserInfo(pub->opts, config->user, config->password);
    } else if (config->nkey_file) {
        // NKey authentication
        natsOptions_SetNKey(pub->opts, config->nkey_pubkey,
            nkey_sign_callback, config->nkey_seed);
    } else if (config->jwt_file) {
        // JWT/NKey authentication
        natsOptions_SetUserCredentialsFromFiles(pub->opts,
            config->jwt_file, config->nkey_file);
    }

    // Reconnection settings
    natsOptions_SetMaxReconnect(pub->opts, config->max_reconnect);
    natsOptions_SetReconnectWait(pub->opts, config->reconnect_wait_ms);
    natsOptions_SetReconnectBufSize(pub->opts, config->reconnect_buf_size);

    // Callbacks
    natsOptions_SetDisconnectedCB(pub->opts, on_disconnected, pub);
    natsOptions_SetReconnectedCB(pub->opts, on_reconnected, pub);
    natsOptions_SetClosedCB(pub->opts, on_closed, pub);
    natsOptions_SetErrorHandler(pub->opts, on_error, pub);

    // Connect
    natsStatus s = natsConnection_Connect(&pub->conn, pub->opts);
    if (s != NATS_OK) {
        log_error("NATS connection failed: %s", natsStatus_GetText(s));
        nats_publisher_destroy(pub);
        return NULL;
    }

    // Generate agent ID
    generate_agent_id(pub->agent_id, sizeof(pub->agent_id));
    gethostname(pub->hostname, sizeof(pub->hostname));

    return pub;
}
```

### Event Publishing

```c
// Subject hierarchy for event routing
//
// sslsniff.{agent_id}.{event_type}.{protocol}
//
// Examples:
//   sslsniff.agent-1a2b3c.http.request
//   sslsniff.agent-1a2b3c.http.response
//   sslsniff.agent-1a2b3c.tls.handshake
//   sslsniff.agent-1a2b3c.flow.start
//   sslsniff.agent-1a2b3c.flow.end
//   sslsniff.agent-1a2b3c.packet.metadata

typedef enum {
    EVENT_HTTP_REQUEST,
    EVENT_HTTP_RESPONSE,
    EVENT_TLS_HANDSHAKE,
    EVENT_QUIC_HANDSHAKE,
    EVENT_FLOW_START,
    EVENT_FLOW_END,
    EVENT_FLOW_DATA,
    EVENT_PACKET_METADATA,
    EVENT_CLASSIFICATION,
    EVENT_ALERT,
} event_type_t;

// Publish event (non-blocking, fire-and-forget)
int nats_publish_event(nats_publisher_t *pub,
                       event_type_t type,
                       const void *data,
                       size_t len) {
    char subject[256];
    const char *type_str = event_type_to_string(type);

    snprintf(subject, sizeof(subject),
             "%s.%s.%s",
             pub->subject_prefix,
             pub->agent_id,
             type_str);

    natsStatus s = natsConnection_Publish(pub->conn, subject, data, len);

    if (s == NATS_OK) {
        atomic_fetch_add(&pub->published, 1);
        atomic_fetch_add(&pub->bytes_sent, len);
        return 0;
    } else {
        atomic_fetch_add(&pub->errors, 1);
        return -1;
    }
}

// Publish with headers (NATS 2.2+)
int nats_publish_event_with_headers(nats_publisher_t *pub,
                                     event_type_t type,
                                     const nats_headers_t *headers,
                                     const void *data,
                                     size_t len) {
    natsMsg *msg = NULL;
    char subject[256];

    snprintf(subject, sizeof(subject), "%s.%s.%s",
             pub->subject_prefix, pub->agent_id,
             event_type_to_string(type));

    natsMsg_Create(&msg, subject, NULL, data, len);

    // Add headers
    natsMsgHeader_Set(msg, "agent-id", pub->agent_id);
    natsMsgHeader_Set(msg, "hostname", pub->hostname);
    natsMsgHeader_Set(msg, "timestamp", get_iso_timestamp());

    if (headers) {
        for (int i = 0; i < headers->count; i++) {
            natsMsgHeader_Set(msg, headers->keys[i], headers->values[i]);
        }
    }

    natsStatus s = natsConnection_PublishMsg(pub->conn, msg);
    natsMsg_Destroy(msg);

    return (s == NATS_OK) ? 0 : -1;
}
```

### Buffering and Backpressure

```c
// Local buffer for network issues
typedef struct {
    ck_ring_t ring;
    ck_ring_buffer_t *buffer;
    size_t capacity;

    // Overflow handling
    _Atomic uint64_t dropped;
    overflow_policy_t policy;  // DROP_OLDEST, DROP_NEWEST, BLOCK

} event_buffer_t;

// Worker thread for async publishing
void* nats_publisher_thread(void *arg) {
    nats_publisher_ctx_t *ctx = arg;
    event_t *event;

    while (ctx->running) {
        // Adaptive wait (same pattern as XDP workers)
        if (!try_dequeue_event(ctx->buffer, &event)) {
            adaptive_wait(ctx);
            continue;
        }

        // Serialize event
        uint8_t buf[MAX_EVENT_SIZE];
        size_t len = serialize_event(event, buf, sizeof(buf));

        // Publish
        int rc = nats_publish_event(ctx->publisher, event->type, buf, len);

        if (rc != 0 && ctx->publisher->conn_status != NATS_CONN_STATUS_CONNECTED) {
            // Connection lost - buffer locally
            if (!event_buffer_push(ctx->overflow_buffer, event)) {
                // Overflow - apply policy
                handle_overflow(ctx, event);
            }
        }

        event_pool_release(ctx->pool, event);
    }

    return NULL;
}
```

### NATS JetStream for Persistence (Optional)

```c
// JetStream provides persistence and replay capability
typedef struct {
    jsCtx *js;
    const char *stream_name;
    const char *consumer_name;

} jetstream_ctx_t;

// Create stream for event persistence
int jetstream_create_stream(natsConnection *conn, const char *stream_name) {
    jsCtx *js = NULL;
    jsOptions jsOpts;
    jsStreamConfig cfg;
    jsStreamInfo *si = NULL;

    jsOptions_Init(&jsOpts);
    natsConnection_JetStream(&js, conn, &jsOpts);

    jsStreamConfig_Init(&cfg);
    cfg.Name = stream_name;
    cfg.Subjects = (const char*[]){"sslsniff.>", NULL};
    cfg.Storage = js_FileStorage;
    cfg.Retention = js_LimitsPolicy;
    cfg.MaxBytes = 10 * 1024 * 1024 * 1024LL;  // 10GB
    cfg.MaxAge = 7 * 24 * 60 * 60 * 1000000000LL;  // 7 days in ns
    cfg.Replicas = 3;  // For HA

    natsStatus s = js_AddStream(&si, js, &cfg, NULL, NULL);

    if (s == NATS_OK) {
        log_info("Created stream: %s", si->Config->Name);
        jsStreamInfo_Destroy(si);
    }

    return (s == NATS_OK) ? 0 : -1;
}

// Publish to JetStream with acknowledgment
int jetstream_publish_event(jetstream_ctx_t *ctx,
                            event_type_t type,
                            const void *data,
                            size_t len) {
    jsPubAck *ack = NULL;
    jsPubOptions pubOpts;
    char subject[256];

    jsPubOptions_Init(&pubOpts);
    pubOpts.MaxWait = 1000;  // 1 second timeout

    snprintf(subject, sizeof(subject), "sslsniff.events.%s",
             event_type_to_string(type));

    natsStatus s = js_Publish(&ack, ctx->js, subject, data, len, &pubOpts, NULL);

    if (s == NATS_OK) {
        // Event persisted with sequence number
        log_debug("Published seq=%lu", ack->Sequence);
        jsPubAck_Destroy(ack);
        return 0;
    }

    return -1;
}
```

### Architecture with NATS

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         v0.8.0 EVENT STREAMING                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         SSLSNIFF AGENT                               │   │
│  │                                                                      │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                           │   │
│  │  │  XDP/    │  │  Uprobe  │  │  Flow    │                           │   │
│  │  │  Packet  │  │  Content │  │  Tracker │                           │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘                           │   │
│  │       │             │             │                                  │   │
│  │       └─────────────┴─────────────┘                                  │   │
│  │                     │                                                │   │
│  │                     ▼                                                │   │
│  │       ┌───────────────────────────┐                                  │   │
│  │       │     Event Serializer      │                                  │   │
│  │       │  (MessagePack / FlatBuf)  │                                  │   │
│  │       └─────────────┬─────────────┘                                  │   │
│  │                     │                                                │   │
│  │                     ▼                                                │   │
│  │       ┌───────────────────────────┐                                  │   │
│  │       │    NATS Publisher         │                                  │   │
│  │       │    (Async, buffered)      │                                  │   │
│  │       └─────────────┬─────────────┘                                  │   │
│  │                     │                                                │   │
│  └─────────────────────┼────────────────────────────────────────────────┘   │
│                        │                                                    │
│                        │ NATS Protocol                                      │
│                        │ (TCP/TLS)                                          │
│                        ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       NATS SERVER/CLUSTER                            │   │
│  │                                                                      │   │
│  │   ┌─────────┐      ┌─────────┐      ┌─────────┐                     │   │
│  │   │  Node 1 │◄────►│  Node 2 │◄────►│  Node 3 │                     │   │
│  │   └─────────┘      └─────────┘      └─────────┘                     │   │
│  │                                                                      │   │
│  │   JetStream (optional - persistence)                                 │   │
│  │   ┌─────────────────────────────────────────────┐                   │   │
│  │   │  Stream: sslsniff-events                     │                   │   │
│  │   │  Retention: 7 days                           │                   │   │
│  │   │  Replicas: 3                                 │                   │   │
│  │   └─────────────────────────────────────────────┘                   │   │
│  │                                                                      │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                          │
│                    ┌────────────┴────────────┐                             │
│                    │                         │                             │
│                    ▼                         ▼                             │
│  ┌──────────────────────────┐  ┌──────────────────────────┐               │
│  │   CLASSIFICATION         │  │   STORAGE                │               │
│  │   PLATFORM               │  │   PLATFORM               │               │
│  │                          │  │                          │               │
│  │   • ML classifiers       │  │   • ClickHouse/TimescaleDB│              │
│  │   • Threat intel         │  │   • Elasticsearch        │               │
│  │   • Policy engine        │  │   • S3/Object storage    │               │
│  │   • Alert generation     │  │   • Long-term retention  │               │
│  │                          │  │                          │               │
│  └──────────────────────────┘  └──────────────────────────┘               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CLI Options for NATS

```
NATS Streaming Options:
  --nats-url <url>           NATS server URL (default: nats://localhost:4222)
  --nats-cluster <urls>      Comma-separated NATS cluster URLs
  --nats-token <token>       NATS authentication token
  --nats-user <user>         NATS username
  --nats-password <pass>     NATS password
  --nats-creds <file>        NATS credentials file (JWT+NKey)
  --nats-tls                 Enable TLS for NATS connection
  --nats-ca <file>           CA certificate for NATS TLS
  --nats-cert <file>         Client certificate for NATS TLS
  --nats-key <file>          Client key for NATS TLS
  --nats-subject <prefix>    Subject prefix (default: sslsniff.events)
  --nats-buffer-size <n>     Local buffer size in KB (default: 1024)
  --nats-jetstream           Use JetStream for persistence
  --nats-stream <name>       JetStream stream name
```

---

## 6. Traffic Classification (v0.9.0)

### Overview

Lightweight on-agent classification to reduce platform load and enable immediate actions.

### Classification Categories

```c
typedef enum {
    // Web traffic
    TRAFFIC_WEB_BROWSING,       // Normal web page loads
    TRAFFIC_WEB_API,            // REST/GraphQL API calls
    TRAFFIC_WEB_STREAMING,      // Video/audio streaming
    TRAFFIC_WEB_DOWNLOAD,       // Large file downloads
    TRAFFIC_WEB_UPLOAD,         // File uploads
    TRAFFIC_WEB_WEBSOCKET,      // WebSocket connections

    // Application protocols
    TRAFFIC_GRPC,               // gRPC over HTTP/2
    TRAFFIC_GRAPHQL,            // GraphQL queries
    TRAFFIC_JSONRPC,            // JSON-RPC

    // Security relevant
    TRAFFIC_AUTH,               // Login/authentication flows
    TRAFFIC_OAUTH,              // OAuth/OIDC flows
    TRAFFIC_CERT_PINNED,        // Certificate pinning detected

    // Suspicious patterns
    TRAFFIC_TUNNEL,             // Protocol tunneling
    TRAFFIC_ENCODED_PAYLOAD,    // Base64/hex encoded bodies
    TRAFFIC_OBFUSCATED,         // Suspected obfuscation
    TRAFFIC_BEACON,             // Periodic C2-like patterns
    TRAFFIC_DNS_OVER_HTTPS,     // DoH traffic

    // Data movement
    TRAFFIC_SENSITIVE_DATA,     // PII, credentials detected
    TRAFFIC_BULK_TRANSFER,      // Large data exfiltration risk

    // Unknown
    TRAFFIC_UNCLASSIFIED,

} traffic_class_t;
```

### Classification Engine

```c
typedef struct {
    // Pattern matchers (compiled regex or literal)
    pattern_matcher_t *url_patterns;
    pattern_matcher_t *header_patterns;
    pattern_matcher_t *body_patterns;

    // Heuristics
    flow_heuristics_t *heuristics;

    // External threat intel (loaded from platform)
    threat_intel_t *threat_intel;

    // Stats
    uint64_t classifications[TRAFFIC_UNCLASSIFIED + 1];

} classifier_t;

// Classify a complete HTTP transaction
traffic_class_t classify_http_transaction(classifier_t *cls,
                                           const http_request_t *req,
                                           const http_response_t *resp,
                                           const flow_metadata_t *flow) {
    traffic_class_t result = TRAFFIC_UNCLASSIFIED;
    float confidence = 0.0;

    // URL-based classification
    if (match_url_pattern(cls->url_patterns, req->url, &result, &confidence)) {
        if (confidence > 0.9) return result;
    }

    // Content-Type based
    const char *content_type = http_get_header(resp, "Content-Type");
    if (content_type) {
        if (strstr(content_type, "video/") || strstr(content_type, "audio/")) {
            return TRAFFIC_WEB_STREAMING;
        }
        if (strstr(content_type, "application/grpc")) {
            return TRAFFIC_GRPC;
        }
        if (strstr(content_type, "application/graphql")) {
            return TRAFFIC_GRAPHQL;
        }
    }

    // Size-based heuristics
    if (resp->body_len > 10 * 1024 * 1024) {  // > 10MB
        return (req->method == HTTP_GET) ? TRAFFIC_WEB_DOWNLOAD : TRAFFIC_WEB_UPLOAD;
    }

    // Auth detection
    if (strstr(req->url, "/login") || strstr(req->url, "/auth") ||
        strstr(req->url, "/oauth") || strstr(req->url, "/token")) {
        return (strstr(req->url, "/oauth") || strstr(req->url, "/token"))
            ? TRAFFIC_OAUTH : TRAFFIC_AUTH;
    }

    // WebSocket upgrade
    const char *upgrade = http_get_header(req, "Upgrade");
    if (upgrade && strcasecmp(upgrade, "websocket") == 0) {
        return TRAFFIC_WEB_WEBSOCKET;
    }

    // Beacon detection (flow timing patterns)
    if (flow && detect_beacon_pattern(cls->heuristics, flow)) {
        return TRAFFIC_BEACON;
    }

    // Sensitive data detection (lightweight, regex-based)
    if (detect_sensitive_data(cls->body_patterns, req->body, req->body_len)) {
        return TRAFFIC_SENSITIVE_DATA;
    }

    // Default: API vs browsing
    const char *accept = http_get_header(req, "Accept");
    if (accept) {
        if (strstr(accept, "application/json") || strstr(accept, "application/xml")) {
            return TRAFFIC_WEB_API;
        }
        if (strstr(accept, "text/html")) {
            return TRAFFIC_WEB_BROWSING;
        }
    }

    return TRAFFIC_UNCLASSIFIED;
}
```

### JA3/JA4 Fingerprinting

```c
// JA3 fingerprint from TLS ClientHello
typedef struct {
    char ja3_hash[33];        // MD5 hash (32 chars + null)
    char ja3_string[1024];    // Raw JA3 string

    // JA4 components (more robust)
    char ja4[64];             // Full JA4 fingerprint
    char ja4_t[32];           // JA4 TLS version component
    char ja4_c[32];           // JA4 cipher component
    char ja4_e[32];           // JA4 extension component

} tls_fingerprint_t;

// Known malware fingerprints (loaded from threat intel)
typedef struct {
    const char *ja3_hash;
    const char *malware_family;
    float confidence;
} ja3_threat_t;

// Check fingerprint against threat intel
bool check_ja3_threat(classifier_t *cls,
                      const tls_fingerprint_t *fp,
                      threat_match_t *match) {
    // Binary search in sorted threat intel
    ja3_threat_t *threat = bsearch(fp->ja3_hash,
                                   cls->threat_intel->ja3_threats,
                                   cls->threat_intel->ja3_count,
                                   sizeof(ja3_threat_t),
                                   ja3_compare);

    if (threat) {
        match->type = THREAT_KNOWN_MALWARE;
        match->confidence = threat->confidence;
        strncpy(match->family, threat->malware_family, sizeof(match->family));
        return true;
    }

    return false;
}
```

---

## 7. EDR Agent Ready (v1.0.0)

### Agent Mode Features

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         v1.0.0 EDR AGENT MODE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                          AGENT CAPABILITIES                            │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │                                                                       │ │
│  │  CAPTURE                   CLASSIFY                   STREAM          │ │
│  │  ───────                   ────────                   ──────          │ │
│  │  • HTTP/1.1, HTTP/2, H3    • Traffic categories       • NATS pub/sub  │ │
│  │  • TLS/QUIC decryption     • JA3/JA4 fingerprints     • JetStream     │ │
│  │  • Packet metadata         • Threat intel matching    • Buffering     │ │
│  │  • Flow tracking           • Anomaly detection        • Compression   │ │
│  │  • Connection mapping      • Data classification      • Encryption    │ │
│  │                                                                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                          AGENT PROPERTIES                              │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │                                                                       │ │
│  │  • Self-contained binary (static linking where possible)              │ │
│  │  • Minimal dependencies on host                                       │ │
│  │  • Auto-update capability                                             │ │
│  │  • Heartbeat and health reporting                                     │ │
│  │  • Configuration from platform (NATS request/reply)                   │ │
│  │  • Graceful degradation on errors                                     │ │
│  │  • Privilege separation (eBPF loader vs event processor)              │ │
│  │                                                                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                          AGENT MANAGEMENT                              │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │                                                                       │ │
│  │  Platform → Agent (NATS Request/Reply):                               │ │
│  │  • Update threat intel                                                │ │
│  │  • Change capture filters                                             │ │
│  │  • Adjust classification rules                                        │ │
│  │  • Request diagnostic info                                            │ │
│  │  • Trigger config reload                                              │ │
│  │                                                                       │ │
│  │  Agent → Platform (NATS Publish):                                     │ │
│  │  • Heartbeat (every 30s)                                              │ │
│  │  • Metrics (every 60s)                                                │ │
│  │  • Events (real-time)                                                 │ │
│  │  • Alerts (real-time)                                                 │ │
│  │                                                                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Configuration

```c
typedef struct {
    // Identity
    char agent_id[64];
    char agent_name[256];
    char agent_group[64];

    // Capture settings
    capture_mode_t capture_mode;     // kernel, xdp, af_xdp, dpdk
    char *interfaces[MAX_INTERFACES];
    int interface_count;

    // Filtering
    pid_filter_t pid_filter;
    container_filter_t container_filter;
    traffic_filter_t traffic_filter;

    // Classification
    bool classification_enabled;
    char *threat_intel_path;
    int classification_threads;

    // NATS
    nats_config_t nats;

    // Performance
    int worker_threads;
    size_t buffer_size;
    bool cpu_pinning;
    int *cpu_affinity;

    // Logging
    log_level_t log_level;
    char *log_file;

} agent_config_t;

// Load configuration from platform via NATS
int agent_load_config_from_platform(agent_config_t *config,
                                    natsConnection *conn) {
    natsMsg *reply = NULL;
    char subject[256];

    snprintf(subject, sizeof(subject),
             "sslsniff.config.request.%s", config->agent_id);

    // Request configuration
    natsStatus s = natsConnection_RequestString(&reply, conn,
        subject, "{\"type\":\"config_request\"}", 5000);

    if (s != NATS_OK) {
        log_warn("Config request failed, using defaults");
        return -1;
    }

    // Parse JSON configuration
    const char *data = natsMsg_GetData(reply);
    int rc = parse_agent_config_json(config, data, natsMsg_GetDataLength(reply));

    natsMsg_Destroy(reply);
    return rc;
}
```

### Agent Heartbeat

```c
typedef struct {
    // Identity
    char agent_id[64];
    uint64_t timestamp;
    uint32_t uptime_seconds;

    // Version
    char version[32];
    char commit[41];

    // Status
    agent_status_t status;  // RUNNING, DEGRADED, ERROR

    // Capture stats
    uint64_t events_captured;
    uint64_t events_published;
    uint64_t events_dropped;
    uint64_t bytes_captured;

    // Resource usage
    float cpu_percent;
    uint64_t memory_bytes;
    uint64_t memory_limit;

    // Connection stats
    uint64_t flows_active;
    uint64_t flows_total;

    // Errors
    uint32_t error_count;
    char last_error[256];

} agent_heartbeat_t;

void* heartbeat_thread(void *arg) {
    agent_ctx_t *ctx = arg;

    while (ctx->running) {
        agent_heartbeat_t hb = {0};

        // Populate heartbeat
        strncpy(hb.agent_id, ctx->config->agent_id, sizeof(hb.agent_id));
        hb.timestamp = time(NULL);
        hb.uptime_seconds = hb.timestamp - ctx->start_time;
        strncpy(hb.version, SSLSNIFF_VERSION, sizeof(hb.version));

        // Collect stats
        collect_capture_stats(ctx, &hb);
        collect_resource_usage(&hb);
        collect_flow_stats(ctx, &hb);

        // Serialize and publish
        uint8_t buf[1024];
        size_t len = serialize_heartbeat(&hb, buf, sizeof(buf));

        char subject[256];
        snprintf(subject, sizeof(subject),
                 "sslsniff.heartbeat.%s", ctx->config->agent_id);

        natsConnection_Publish(ctx->nats->conn, subject, buf, len);

        // Sleep 30 seconds
        sleep(30);
    }

    return NULL;
}
```

---

## 8. Platform Components

The platform receives events from agents and provides:

### 8.1 Event Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PLATFORM ARCHITECTURE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       NATS CLUSTER                                   │   │
│  │                                                                      │   │
│  │   Subjects:                                                          │   │
│  │   • sslsniff.events.>        (all agent events)                      │   │
│  │   • sslsniff.heartbeat.>     (agent heartbeats)                      │   │
│  │   • sslsniff.alerts.>        (agent-generated alerts)                │   │
│  │   • sslsniff.config.>        (config requests/responses)             │   │
│  │                                                                      │   │
│  └──────────────────────────────────┬──────────────────────────────────┘   │
│                                     │                                       │
│       ┌─────────────────────────────┼─────────────────────────────┐        │
│       │                             │                             │        │
│       ▼                             ▼                             ▼        │
│  ┌─────────────┐           ┌─────────────┐           ┌─────────────┐      │
│  │  ENRICHMENT │           │  DETECTION  │           │   STORAGE   │      │
│  │   SERVICE   │           │   ENGINE    │           │   SERVICE   │      │
│  │             │           │             │           │             │      │
│  │ • GeoIP     │           │ • YARA      │           │ • TimescaleDB│     │
│  │ • ASN       │           │ • Sigma     │           │ • ClickHouse│      │
│  │ • Threat    │           │ • Custom    │           │ • S3        │      │
│  │   intel     │           │   rules     │           │             │      │
│  │ • DNS       │           │ • ML models │           │             │      │
│  └──────┬──────┘           └──────┬──────┘           └──────┬──────┘      │
│         │                         │                         │              │
│         └─────────────────────────┴─────────────────────────┘              │
│                                   │                                         │
│                                   ▼                                         │
│                    ┌───────────────────────────┐                            │
│                    │      ALERT MANAGER        │                            │
│                    │                           │                            │
│                    │  • Deduplication          │                            │
│                    │  • Correlation            │                            │
│                    │  • Severity scoring       │                            │
│                    │  • Notification routing   │                            │
│                    │                           │                            │
│                    └─────────────┬─────────────┘                            │
│                                  │                                          │
│            ┌─────────────────────┼─────────────────────┐                   │
│            │                     │                     │                   │
│            ▼                     ▼                     ▼                   │
│     ┌────────────┐       ┌────────────┐       ┌────────────┐              │
│     │   Slack    │       │  PagerDuty │       │   SIEM     │              │
│     │            │       │            │       │ (Splunk,   │              │
│     │            │       │            │       │  Elastic)  │              │
│     └────────────┘       └────────────┘       └────────────┘              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Detection Rules

```yaml
# Example Sigma-style detection rules

title: Potential C2 Beacon Activity
id: c2-beacon-001
status: stable
description: Detects periodic outbound connections with consistent intervals
classification: TRAFFIC_BEACON

detection:
  selection:
    flow.direction: outbound
    flow.interval_stddev: < 5%
    flow.connection_count: > 10
  timeframe: 1h

condition: selection
falsepositives:
  - Legitimate heartbeat services
  - Health check endpoints

level: medium
tags:
  - attack.command_and_control
  - attack.t1071

---

title: Sensitive Data Exfiltration
id: data-exfil-001
status: stable
description: Detects large uploads containing potential sensitive data

detection:
  selection:
    http.method: POST
    http.request.body_size: > 1000000
    classification: TRAFFIC_SENSITIVE_DATA
  filter:
    destination.domain|endswith:
      - '.internal.company.com'
      - '.s3.amazonaws.com'

condition: selection and not filter
level: high
tags:
  - attack.exfiltration
  - attack.t1048

---

title: Known Malware JA3 Fingerprint
id: malware-ja3-001
status: stable
description: TLS fingerprint matches known malware family

detection:
  selection:
    tls.ja3_hash:
      - 'e7d705a3286e19ea42f587b344ee6865'  # Cobalt Strike
      - '72a589da586844d7f0818ce684948eea'  # Metasploit
      - 'b386946a5a44d1ddcc843bc75336dfce'  # Trickbot

condition: selection
level: critical
tags:
  - attack.command_and_control
```

### 8.3 Dashboard Metrics

```
Key Performance Indicators:
─────────────────────────────────────────────────────────────────────

AGENTS                          TRAFFIC                    THREATS
─────────────────────────       ─────────────────────      ─────────────
Active:      127                Events/sec:    45,230      Critical:   3
Degraded:      2                MB/sec:           892      High:      12
Offline:       5                HTTP Requests:  12.4M      Medium:    47
                                Connections:    8,923      Low:      156

CLASSIFICATION BREAKDOWN        TOP DESTINATIONS           TOP THREATS
─────────────────────────       ─────────────────────      ─────────────
Web Browsing:     45.2%         google.com                 C2 Beacon
Web API:          32.1%         amazonaws.com              Data Exfil
Streaming:        12.3%         cloudflare.com             Malware JA3
Downloads:         5.4%         github.com                 Tunnel
Other:             5.0%         microsoft.com              DoH
```

---

## 9. Event Schema Design

### Serialization Format

Using **MessagePack** for compact binary serialization (smaller than JSON, faster than Protobuf for small messages).

Alternative: **FlatBuffers** for zero-copy access.

### Base Event Structure

```c
// All events share this header
typedef struct {
    uint64_t timestamp_ns;      // Nanosecond precision
    char agent_id[32];          // Agent identifier
    uint32_t event_type;        // Event type enum
    uint32_t event_flags;       // Flags (compressed, encrypted, etc.)
    uint64_t sequence;          // Monotonic sequence number

} event_header_t;

// Flow identifier (used across events)
typedef struct {
    uint8_t protocol;           // IPPROTO_TCP, IPPROTO_UDP
    uint32_t src_ip;            // Source IP (v4, or last 32 bits of v6)
    uint32_t dst_ip;            // Destination IP
    uint16_t src_port;          // Source port
    uint16_t dst_port;          // Destination port
    uint32_t pid;               // Process ID
    char container_id[64];      // Container ID if applicable

} flow_key_t;
```

### HTTP Event

```c
typedef struct {
    event_header_t header;
    flow_key_t flow;

    // Request
    struct {
        uint8_t method;             // HTTP method enum
        uint16_t url_len;
        char url[2048];
        uint16_t host_len;
        char host[256];
        uint8_t version;            // HTTP/1.0, 1.1, 2, 3
        uint32_t header_count;
        // Headers follow as key-value pairs
    } request;

    // Response (may be separate event for streaming)
    struct {
        uint16_t status_code;
        uint32_t header_count;
        uint64_t body_length;
        uint32_t content_type_len;
        char content_type[128];
    } response;

    // Timing
    uint64_t request_start_ns;
    uint64_t first_byte_ns;
    uint64_t complete_ns;

    // Classification (if enabled)
    uint8_t traffic_class;
    float classification_confidence;

} http_event_t;
```

### TLS Event

```c
typedef struct {
    event_header_t header;
    flow_key_t flow;

    // Handshake info
    uint16_t tls_version;           // 0x0303 = TLS 1.2, 0x0304 = TLS 1.3
    uint16_t cipher_suite;
    char sni[256];
    char alpn[32];

    // Fingerprints
    char ja3_hash[33];
    char ja4[64];

    // Certificate info (optional)
    struct {
        char subject_cn[256];
        char issuer_cn[256];
        uint64_t not_before;
        uint64_t not_after;
        uint8_t sha256_fingerprint[32];
    } cert;

    // Session info
    bool session_resumed;
    bool cert_pinning_detected;

} tls_event_t;
```

### Flow Event

```c
typedef struct {
    event_header_t header;
    flow_key_t flow;

    enum {
        FLOW_START,
        FLOW_DATA,
        FLOW_END,
    } event_subtype;

    // Cumulative stats
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t packets_sent;
    uint32_t packets_received;

    // Timing
    uint64_t start_time_ns;
    uint64_t end_time_ns;           // For FLOW_END
    uint64_t duration_ns;

    // Derived metrics
    uint32_t rtt_us;                // Round-trip time
    float loss_rate;                // Packet loss estimate

    // Process info
    char process_name[256];
    char cmdline[1024];
    uint32_t uid;

} flow_event_t;
```

### Packet Metadata Event

```c
typedef struct {
    event_header_t header;
    flow_key_t flow;

    // Packet info
    uint16_t packet_len;
    uint16_t payload_len;
    uint8_t ip_ttl;
    uint8_t tcp_flags;              // For TCP
    uint32_t tcp_seq;
    uint32_t tcp_ack;

    // Timing
    uint64_t wire_time_ns;

    // XDP-specific
    uint32_t xdp_rx_queue;
    uint32_t xdp_action;

} packet_event_t;
```

---

## 10. Security Considerations

### Agent Security

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGENT SECURITY MODEL                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PRIVILEGE SEPARATION                                                       │
│  ────────────────────                                                       │
│                                                                             │
│  ┌───────────────────────┐       ┌───────────────────────┐                 │
│  │   LOADER PROCESS      │       │   WORKER PROCESS      │                 │
│  │   (root/CAP_*)        │       │   (unprivileged)      │                 │
│  ├───────────────────────┤       ├───────────────────────┤                 │
│  │ • Load eBPF programs  │       │ • Event processing    │                 │
│  │ • Attach uprobes      │       │ • Protocol parsing    │                 │
│  │ • Setup XDP           │       │ • NATS publishing     │                 │
│  │ • Map creation        │──────►│ • Classification      │                 │
│  │                       │ IPC   │                       │                 │
│  │ Capabilities:         │       │ Capabilities:         │                 │
│  │ • CAP_SYS_ADMIN       │       │ • None (dropped)      │                 │
│  │ • CAP_BPF             │       │                       │                 │
│  │ • CAP_PERFMON         │       │ Seccomp:              │                 │
│  │ • CAP_NET_ADMIN       │       │ • Restricted syscalls │                 │
│  └───────────────────────┘       └───────────────────────┘                 │
│                                                                             │
│  COMMUNICATION SECURITY                                                     │
│  ──────────────────────                                                     │
│                                                                             │
│  Agent ←→ NATS:                                                             │
│  • TLS 1.3 required                                                         │
│  • mTLS for agent authentication                                            │
│  • NKey or JWT/NKey for authorization                                       │
│  • Subject permissions (can only publish to own agent.* subjects)           │
│                                                                             │
│  DATA PROTECTION                                                            │
│  ───────────────                                                            │
│                                                                             │
│  • Captured data encrypted in transit (TLS to NATS)                         │
│  • Optional: Encrypt sensitive fields before publishing                     │
│  • Configurable: Mask/redact sensitive patterns (passwords, tokens)         │
│  • Memory: Secure zeroing of buffers after use                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Sensitivity

```c
// Sensitive data patterns to redact
typedef struct {
    const char *pattern;
    const char *replacement;
    bool enabled;
} redaction_rule_t;

static redaction_rule_t default_redactions[] = {
    // Authorization headers
    {"Authorization:\\s*Bearer\\s+[A-Za-z0-9\\-_]+",
     "Authorization: Bearer [REDACTED]", true},
    {"Authorization:\\s*Basic\\s+[A-Za-z0-9+/=]+",
     "Authorization: Basic [REDACTED]", true},

    // API keys
    {"[Aa]pi[_-]?[Kk]ey[\"']?\\s*[:=]\\s*[\"']?[A-Za-z0-9\\-_]+",
     "api_key=[REDACTED]", true},

    // Passwords
    {"[Pp]assword[\"']?\\s*[:=]\\s*[\"'][^\"']+[\"']",
     "password=[REDACTED]", true},

    // Tokens
    {"[Tt]oken[\"']?\\s*[:=]\\s*[\"']?[A-Za-z0-9\\-_]+",
     "token=[REDACTED]", true},

    // Credit cards (basic pattern)
    {"\\b[0-9]{4}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}\\b",
     "[CC-REDACTED]", true},
};
```

---

## 11. Performance Budgets

### Agent Resource Limits

| Metric | Idle | Moderate (1K evt/s) | High (10K evt/s) | Max (100K evt/s) |
|--------|------|---------------------|------------------|------------------|
| CPU | < 1% | < 5% | < 15% | < 50% (dedicated cores) |
| Memory | < 50 MB | < 100 MB | < 200 MB | < 500 MB |
| Network (to NATS) | < 1 Mbps | < 10 Mbps | < 50 Mbps | < 200 Mbps |
| Disk I/O | 0 | 0 | 0 | 0 (no disk writes) |

### Latency Budgets

| Operation | Target | Maximum |
|-----------|--------|---------|
| Event capture to NATS publish | < 1 ms | < 10 ms |
| HTTP parsing | < 100 μs | < 1 ms |
| Classification | < 50 μs | < 500 μs |
| JA3/JA4 computation | < 10 μs | < 100 μs |

### Throughput Targets

| Mode | Events/sec | Bandwidth |
|------|------------|-----------|
| Kernel | 10K | 1-5 Gbps |
| XDP | 100K | 10-25 Gbps |
| AF_XDP | 500K | 25-50 Gbps |
| DPDK | 1M+ | 100+ Gbps |

---

## 12. Dependencies

### Core (All Versions)

| Library | Version | Purpose |
|---------|---------|---------|
| libbpf | 1.0+ | eBPF program loading |
| llhttp | 9.0+ | HTTP/1.1 parsing |
| nghttp2 | 1.50+ | HTTP/2, HPACK |
| OpenSSL/BoringSSL | 3.0+ | Crypto utilities |

### v0.6.0 (HTTP/3)

| Library | Version | Purpose |
|---------|---------|---------|
| nghttp3 | 1.0+ | HTTP/3, QPACK |
| ngtcp2 | 0.8+ | QUIC (optional, for testing) |

### v0.7.0 (XDP)

| Library | Version | Purpose |
|---------|---------|---------|
| libxdp | 1.2+ | XDP program management |
| libbpf | 1.0+ | AF_XDP sockets |
| ck | 0.7+ | Lock-free data structures |
| liburcu | 0.14+ | Userspace RCU |
| jemalloc | 5.3+ | Memory allocator |

### v0.7.0 (DPDK - Optional)

| Library | Version | Purpose |
|---------|---------|---------|
| DPDK | 23.11+ | Kernel bypass packet I/O |

### v0.8.0 (NATS)

| Library | Version | Purpose |
|---------|---------|---------|
| nats.c | 3.6+ | NATS client |
| msgpack-c | 6.0+ | Event serialization |

### v0.9.0 (Classification)

| Library | Version | Purpose |
|---------|---------|---------|
| pcre2 | 10.40+ | Pattern matching |
| hyperscan | 5.4+ | High-performance regex (optional) |

---

## Appendix A: CLI Reference (v1.0.0)

```
sslsniff - eBPF-based SSL/TLS traffic inspector and EDR agent

USAGE:
    sslsniff [OPTIONS] [COMMAND]

COMMANDS:
    capture         Capture and output traffic (default)
    agent           Run in EDR agent mode with NATS streaming

COMMON OPTIONS:
    -p, --pid <PID>           Filter by process ID
    -n, --name <NAME>         Filter by process name
    -c, --container <ID>      Filter by container ID
    -i, --interface <IF>      Network interface (for XDP/DPDK)
    -v, --verbose             Increase verbosity
    -q, --quiet               Minimal output
    --version                 Show version
    --help                    Show help

CAPTURE OPTIONS:
    -o, --output <FILE>       Output file (default: stdout)
    -f, --format <FMT>        Output format: text, json, msgpack
    --mode <MODE>             Capture mode: kernel, xdp, af_xdp, dpdk
    --no-http1                Disable HTTP/1.1 parsing
    --no-http2                Disable HTTP/2 parsing
    --no-http3                Disable HTTP/3 parsing
    --raw                     Output raw captured data

AGENT OPTIONS:
    --nats-url <URL>          NATS server URL
    --nats-creds <FILE>       NATS credentials file
    --nats-tls                Enable TLS for NATS
    --agent-id <ID>           Agent identifier (auto-generated if not set)
    --agent-group <GROUP>     Agent group for configuration
    --config-from-platform    Fetch configuration from platform
    --classify                Enable traffic classification
    --threat-intel <FILE>     Local threat intelligence file
    --heartbeat-interval <S>  Heartbeat interval in seconds (default: 30)

XDP OPTIONS:
    --xdp-mode <MODE>         XDP mode: skb, native, offload
    --xdp-queue <N>           Number of XDP queues
    --workers <N>             Number of worker threads

DPDK OPTIONS:
    --dpdk-args <ARGS>        DPDK EAL arguments
    --dpdk-port <N>           DPDK port ID
    --dpdk-queues <N>         Number of RX queues

EXAMPLES:
    # Basic capture
    sslsniff -p 1234 -f json

    # XDP mode with classification
    sslsniff --mode xdp -i eth0 --classify

    # Agent mode
    sslsniff agent --nats-url nats://nats.example.com:4222 \
                   --nats-creds /etc/sslsniff/agent.creds \
                   --classify

    # High-performance DPDK mode
    sslsniff --mode dpdk --dpdk-args "-l 0-3 -n 4" \
             --dpdk-port 0 --dpdk-queues 4
```

---

## Appendix B: Future Considerations (Post v1.0)

### v1.1+: Extended Visibility

- Process tree correlation (parent/child relationships)
- Container/Kubernetes metadata enrichment
- User attribution (UID → username → identity)
- File access correlation (network + file operations)

### v1.2+: Response Capabilities

- Connection blocking via XDP
- Rate limiting suspicious traffic
- TCP RST injection for kill switch
- Integration with firewall APIs

### v1.3+: Advanced Detection

- Behavioral ML models (on-agent inference)
- Encrypted traffic analysis (timing, sizing patterns)
- Protocol tunneling detection (DNS, ICMP, HTTP)
- Data loss prevention (DLP) patterns

### v2.0: Full XDR

- Cross-agent correlation
- Attack chain visualization
- Automated response playbooks
- MITRE ATT&CK mapping

---

## Appendix C: Tamper Protection & System Monitoring (v2.0+)

This section details agent self-protection mechanisms and comprehensive system monitoring to prevent rogue insiders (sysadmins, compromised accounts) from disabling or removing the agent without detection.

### C.1 Threat Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INSIDER THREAT MODEL                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ADVERSARY: Rogue sysadmin with root access                                 │
│                                                                             │
│  ATTACK VECTORS:                                                            │
│  ───────────────                                                            │
│  1. Kill agent process (kill -9, systemctl stop)                            │
│  2. Unload eBPF programs (bpftool prog detach)                              │
│  3. Modify agent binary (replace with no-op)                                │
│  4. Block network to platform (iptables, routing)                           │
│  5. Modify agent config (disable features)                                  │
│  6. Remove agent entirely (rm, package uninstall)                           │
│  7. Load kernel module to interfere                                         │
│  8. Container escape to host                                                │
│  9. Manipulate logs to hide activity                                        │
│  10. Time-based attacks (disable during maintenance window)                 │
│                                                                             │
│  DETECTION GOALS:                                                           │
│  ────────────────                                                           │
│  • Detect tampering within seconds                                          │
│  • Alert platform even if agent is killed                                   │
│  • Forensic evidence of tampering attempts                                  │
│  • Resist sophisticated evasion techniques                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### C.2 Agent Self-Protection Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AGENT SELF-PROTECTION (v2.0+)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        PROTECTION LAYERS                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Layer 1: HEARTBEAT MONITORING (Platform-side)                              │
│  ─────────────────────────────────────────────                              │
│  • Agent sends heartbeat every 30 seconds                                   │
│  • Platform expects heartbeat within window (+ jitter tolerance)            │
│  • Missing heartbeat = CRITICAL ALERT                                       │
│  • "Silence is suspicious" - no heartbeat = assume compromise               │
│                                                                             │
│  Layer 2: WATCHDOG PROCESS                                                  │
│  ────────────────────────                                                   │
│  • Separate minimal process monitors main agent                             │
│  • Independent NATS connection                                              │
│  • Reports if main agent dies unexpectedly                                  │
│  • Mutual monitoring (each watches the other)                               │
│                                                                             │
│  Layer 3: eBPF SELF-MONITORING                                              │
│  ────────────────────────────                                               │
│  • eBPF program monitors its own attachment points                          │
│  • Detects bpf() syscalls attempting detach                                 │
│  • Alerts on program unload attempts                                        │
│  • Kernel-level - hard to bypass from userspace                             │
│                                                                             │
│  Layer 4: BINARY INTEGRITY                                                  │
│  ─────────────────────────                                                  │
│  • Agent binary hash verified at startup                                    │
│  • Periodic self-verification during runtime                                │
│  • Code signing verification (if available)                                 │
│  • Immutable deployment (read-only root, dm-verity)                         │
│                                                                             │
│  Layer 5: CONFIGURATION PROTECTION                                          │
│  ─────────────────────────────────                                          │
│  • Config file integrity monitoring (inotify + hash)                        │
│  • Configuration fetched from platform (not local file)                     │
│  • Encrypted config with platform-held key                                  │
│  • Change alerts sent before new config applied                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### C.3 Heartbeat & Dead Man's Switch

```c
// Platform-side heartbeat monitoring (pseudo-code)
typedef struct {
    char agent_id[64];
    uint64_t last_heartbeat;
    uint64_t expected_interval_ms;
    uint64_t grace_period_ms;
    alert_state_t alert_state;
} agent_monitor_t;

void heartbeat_monitor_loop(platform_ctx_t *ctx) {
    while (running) {
        uint64_t now = current_time_ms();

        for (int i = 0; i < ctx->agent_count; i++) {
            agent_monitor_t *mon = &ctx->agents[i];
            uint64_t silence = now - mon->last_heartbeat;

            if (silence > mon->expected_interval_ms + mon->grace_period_ms) {
                if (mon->alert_state != ALERT_ACTIVE) {
                    // CRITICAL: Agent may be compromised or killed
                    emit_critical_alert(&(alert_t){
                        .type = ALERT_AGENT_SILENT,
                        .agent_id = mon->agent_id,
                        .silence_duration_ms = silence,
                        .message = "Agent heartbeat missing - possible tampering",
                        .severity = SEVERITY_CRITICAL,
                        .mitre_tactic = "TA0005",  // Defense Evasion
                        .mitre_technique = "T1562.001",  // Disable Security Tools
                    });
                    mon->alert_state = ALERT_ACTIVE;

                    // Trigger automated response
                    trigger_response_playbook(ctx, mon->agent_id,
                        PLAYBOOK_AGENT_DOWN);
                }
            }
        }
        sleep_ms(1000);
    }
}

// Agent-side: Last-gasp notification on termination signals
void setup_termination_handlers(agent_ctx_t *ctx) {
    struct sigaction sa = {0};
    sa.sa_sigaction = termination_handler;
    sa.sa_flags = SA_SIGINFO;

    // Catch all termination signals
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    // Note: SIGKILL cannot be caught - rely on heartbeat monitoring

    // Also catch suspicious signals
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

void termination_handler(int sig, siginfo_t *info, void *context) {
    // Best-effort notification before death
    // This may not complete if SIGKILL follows quickly

    tamper_event_t event = {
        .type = TAMPER_SIGNAL_RECEIVED,
        .signal = sig,
        .sender_pid = info->si_pid,
        .sender_uid = info->si_uid,
        .timestamp = time(NULL),
    };

    // Get sender process info
    char cmdline[256];
    get_process_cmdline(info->si_pid, cmdline, sizeof(cmdline));
    strncpy(event.sender_cmdline, cmdline, sizeof(event.sender_cmdline));

    // Send via pre-established UDP socket (faster than TCP)
    // Uses separate "emergency" NATS connection
    nats_publish_emergency(g_agent->emergency_conn,
                           "sslsniff.tamper.signal",
                           &event, sizeof(event));

    // If SIGTERM, allow graceful shutdown
    if (sig == SIGTERM) {
        g_agent->shutdown_requested = true;
    } else {
        _exit(128 + sig);  // Immediate exit for other signals
    }
}
```

### C.4 eBPF Self-Monitoring

```c
// eBPF program that monitors for tampering attempts
// Attached to bpf() syscall and critical kernel functions

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_syscall(struct trace_event_raw_sys_enter *ctx) {
    int cmd = (int)ctx->args[0];
    union bpf_attr *attr = (union bpf_attr *)ctx->args[1];

    // Commands that could disable our monitoring
    bool suspicious = false;
    switch (cmd) {
        case BPF_PROG_DETACH:
        case BPF_LINK_DETACH:
        case BPF_PROG_UNLOAD:  // Conceptual - actual varies by kernel
            suspicious = true;
            break;
    }

    if (suspicious) {
        struct tamper_event evt = {0};
        evt.type = TAMPER_BPF_DETACH_ATTEMPT;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp = bpf_ktime_get_ns();
        evt.bpf_cmd = cmd;

        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        // Check if target is our program
        // (Would need to track our own prog_id in a map)
        __u32 *our_prog_ids = bpf_map_lookup_elem(&protected_progs, &zero);
        if (our_prog_ids) {
            // Attempt to read target prog_id from attr
            // If it matches ours, this is a tampering attempt
            evt.is_self_targeted = check_if_our_program(attr);
        }

        bpf_perf_event_output(ctx, &tamper_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

// Monitor attempts to kill our process
SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill_syscall(struct trace_event_raw_sys_enter *ctx) {
    pid_t target_pid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    // Check if target is our agent process
    __u32 *our_pids = bpf_map_lookup_elem(&protected_pids, &zero);
    if (!our_pids) return 0;

    bool targeting_us = false;
    for (int i = 0; i < MAX_PROTECTED_PIDS; i++) {
        if (our_pids[i] == target_pid) {
            targeting_us = true;
            break;
        }
    }

    if (targeting_us && sig != 0) {  // sig=0 is just existence check
        struct tamper_event evt = {0};
        evt.type = TAMPER_KILL_ATTEMPT;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp = bpf_ktime_get_ns();
        evt.target_pid = target_pid;
        evt.signal = sig;

        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        bpf_perf_event_output(ctx, &tamper_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

// Monitor writes to our binary or config files
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    int flags = (int)ctx->args[2];

    // Only care about write access
    if (!(flags & (O_WRONLY | O_RDWR | O_TRUNC))) {
        return 0;
    }

    char path[256];
    bpf_probe_read_user_str(path, sizeof(path), (void *)ctx->args[1]);

    // Check against protected paths
    if (is_protected_path(path)) {
        struct tamper_event evt = {0};
        evt.type = TAMPER_FILE_MODIFY_ATTEMPT;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp = bpf_ktime_get_ns();
        evt.open_flags = flags;

        __builtin_memcpy(evt.path, path, sizeof(evt.path));
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        bpf_perf_event_output(ctx, &tamper_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}
```

### C.5 Watchdog Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DUAL WATCHDOG DESIGN                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────┐           ┌───────────────────────┐             │
│  │    MAIN AGENT         │◄─────────►│    WATCHDOG           │             │
│  │                       │  mutual   │                       │             │
│  │  • Full functionality │  monitor  │  • Minimal footprint  │             │
│  │  • All eBPF programs  │           │  • Separate binary    │             │
│  │  • Event processing   │           │  • Own NATS conn      │             │
│  │  • Classification     │           │  • Reports agent death│             │
│  │                       │           │  • Can restart agent  │             │
│  └───────────┬───────────┘           └───────────┬───────────┘             │
│              │                                   │                          │
│              │ heartbeat                         │ watchdog                 │
│              │ events                            │ status                   │
│              │                                   │                          │
│              └───────────────┬───────────────────┘                          │
│                              │                                              │
│                              ▼                                              │
│              ┌───────────────────────────────────┐                          │
│              │         NATS CLUSTER              │                          │
│              │                                   │                          │
│              │  Subjects:                        │                          │
│              │  • sslsniff.heartbeat.{id}        │                          │
│              │  • sslsniff.watchdog.{id}         │                          │
│              │  • sslsniff.tamper.{id}           │                          │
│              └───────────────────────────────────┘                          │
│                                                                             │
│  WATCHDOG IMPLEMENTATION:                                                   │
│  ─────────────────────────                                                  │
│                                                                             │
│  • Statically linked, minimal dependencies                                  │
│  • Runs as separate systemd unit                                            │
│  • Checks main agent via:                                                   │
│    - Process existence (kill(pid, 0))                                       │
│    - Unix socket ping                                                       │
│    - Shared memory heartbeat counter                                        │
│  • On agent death:                                                          │
│    1. Emit tamper alert to platform                                         │
│    2. Collect forensic data (last logs, open fds)                           │
│    3. Attempt restart (configurable)                                        │
│    4. Continue monitoring                                                   │
│                                                                             │
│  MUTUAL MONITORING:                                                         │
│  ──────────────────                                                         │
│                                                                             │
│  • Agent also monitors watchdog                                             │
│  • If watchdog dies, agent reports it                                       │
│  • Platform expects BOTH heartbeats                                         │
│  • Attacker must kill both simultaneously                                   │
│    (harder to do without detection)                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### C.6 Binary Integrity Verification

```c
// Self-verification at runtime
typedef struct {
    char path[PATH_MAX];
    uint8_t expected_hash[32];  // SHA-256
    uint64_t expected_size;
    mode_t expected_mode;
    uid_t expected_uid;
    gid_t expected_gid;
} protected_file_t;

static protected_file_t protected_files[] = {
    {"/usr/bin/sslsniff", {/* hash */}, 0, 0755, 0, 0},
    {"/usr/bin/sslsniff-watchdog", {/* hash */}, 0, 0755, 0, 0},
    {"/etc/sslsniff/agent.conf", {/* hash */}, 0, 0600, 0, 0},
    // eBPF objects
    {"/usr/lib/sslsniff/sslsniff.bpf.o", {/* hash */}, 0, 0644, 0, 0},
};

int verify_binary_integrity(agent_ctx_t *ctx) {
    for (size_t i = 0; i < ARRAY_SIZE(protected_files); i++) {
        protected_file_t *pf = &protected_files[i];

        // Check file exists and permissions
        struct stat st;
        if (stat(pf->path, &st) != 0) {
            emit_tamper_alert(ctx, TAMPER_FILE_MISSING, pf->path);
            return -1;
        }

        if ((st.st_mode & 0777) != pf->expected_mode) {
            emit_tamper_alert(ctx, TAMPER_FILE_PERMISSIONS, pf->path);
            return -1;
        }

        if (st.st_uid != pf->expected_uid || st.st_gid != pf->expected_gid) {
            emit_tamper_alert(ctx, TAMPER_FILE_OWNERSHIP, pf->path);
            return -1;
        }

        // Compute and verify hash
        uint8_t actual_hash[32];
        if (compute_file_sha256(pf->path, actual_hash) != 0) {
            emit_tamper_alert(ctx, TAMPER_FILE_UNREADABLE, pf->path);
            return -1;
        }

        if (memcmp(actual_hash, pf->expected_hash, 32) != 0) {
            emit_tamper_alert(ctx, TAMPER_FILE_MODIFIED, pf->path);
            return -1;
        }
    }

    return 0;  // All files verified
}

// Periodic verification thread
void* integrity_monitor_thread(void *arg) {
    agent_ctx_t *ctx = arg;

    while (ctx->running) {
        if (verify_binary_integrity(ctx) != 0) {
            // Integrity violation detected
            // Alert already sent by verify_binary_integrity

            // Optionally: self-terminate to prevent running modified code
            if (ctx->config->self_terminate_on_tamper) {
                log_critical("Integrity violation - self-terminating");
                _exit(1);
            }
        }

        // Check every 60 seconds
        sleep(60);
    }

    return NULL;
}
```

---

## Appendix D: System-Wide Monitoring (v2.1+)

Beyond network traffic, full endpoint visibility requires monitoring processes, syscalls, file system, and more.

### D.1 Monitoring Scope

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SYSTEM-WIDE VISIBILITY (v2.1+)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      MONITORING LAYERS                               │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │  PROCESS EXECUTION           SYSCALL MONITORING                      │   │
│  │  ─────────────────           ─────────────────────                   │   │
│  │  • execve/execveat           • Security-relevant syscalls            │   │
│  │  • fork/clone/vfork          • File operations (open, unlink)        │   │
│  │  • Process exit              • Network operations (connect, bind)    │   │
│  │  • Process ancestry          • Privilege operations (setuid)         │   │
│  │  • Command line args         • Mount operations                      │   │
│  │  • Environment variables     • Namespace operations                  │   │
│  │                                                                      │   │
│  │  FILE SYSTEM                 KERNEL MODULES                          │   │
│  │  ────────────                ──────────────                          │   │
│  │  • File creation/deletion    • Module load/unload                    │   │
│  │  • Permission changes        • init_module syscall                   │   │
│  │  • Sensitive file access     • Hidden module detection               │   │
│  │  • SUID binary execution     • Kernel symbol tampering               │   │
│  │  • /etc modifications                                                │   │
│  │                                                                      │   │
│  │  CONTAINER/NAMESPACE         CGROUPS                                 │   │
│  │  ────────────────────        ───────                                 │   │
│  │  • Namespace creation        • Cgroup creation/modification          │   │
│  │  • Container escape attempts • Resource limit changes                │   │
│  │  • Privileged containers     • Cgroup escape attempts                │   │
│  │  • Docker socket access      • Device access                         │   │
│  │                                                                      │   │
│  │  AUTHENTICATION              SCHEDULED TASKS                         │   │
│  │  ──────────────              ────────────────                        │   │
│  │  • SSH login/logout          • Cron job creation                     │   │
│  │  • sudo usage                • Systemd timer creation                │   │
│  │  • PAM events                • At job scheduling                     │   │
│  │  • Password changes          • Startup script modification           │   │
│  │  • Key-based auth            • Init system changes                   │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### D.2 Process Execution Monitoring

```c
// eBPF program for comprehensive process monitoring
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    struct process_event evt = {0};
    evt.type = PROC_EXEC;
    evt.timestamp = bpf_ktime_get_ns();

    // Current process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.tid = pid_tgid & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;

    // Parent process
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid), &parent->tgid);

    // Executable path
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);

    // Command line arguments (first N args)
    const char **argv = (const char **)ctx->args[1];
    for (int i = 0; i < MAX_ARGS && i < 8; i++) {
        const char *arg;
        bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
        if (!arg) break;
        bpf_probe_read_user_str(evt.args[i], sizeof(evt.args[i]), arg);
        evt.argc++;
    }

    // Container/cgroup info
    get_cgroup_name(task, evt.cgroup, sizeof(evt.cgroup));
    get_container_id(task, evt.container_id, sizeof(evt.container_id));

    // Namespace info
    get_namespace_ids(task, &evt.ns);

    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return 0;
}

// Process tree tracking
typedef struct {
    u32 pid;
    u32 ppid;
    u32 pppid;  // Grandparent
    u64 start_time;
    char comm[16];
    char filename[256];
} process_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);  // PID
    __type(value, process_info_t);
} process_tree SEC(".maps");

// On process exit, cleanup and emit event
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    process_info_t *proc = bpf_map_lookup_elem(&process_tree, &pid);
    if (proc) {
        struct process_event evt = {0};
        evt.type = PROC_EXIT;
        evt.pid = pid;
        evt.timestamp = bpf_ktime_get_ns();
        evt.duration_ns = evt.timestamp - proc->start_time;

        // Get exit code from task_struct
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&evt.exit_code, sizeof(evt.exit_code),
                              &task->exit_code);

        bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));

        bpf_map_delete_elem(&process_tree, &pid);
    }

    return 0;
}
```

### D.3 Syscall Monitoring with Seccomp-BPF

```c
// Security-relevant syscall categories
typedef enum {
    SYSCALL_CAT_FILE,           // open, read, write, unlink, chmod
    SYSCALL_CAT_PROCESS,        // fork, execve, kill, ptrace
    SYSCALL_CAT_NETWORK,        // socket, connect, bind, accept
    SYSCALL_CAT_PRIVILEGE,      // setuid, setgid, capset
    SYSCALL_CAT_MOUNT,          // mount, umount, pivot_root
    SYSCALL_CAT_NAMESPACE,      // unshare, setns, clone(CLONE_NEW*)
    SYSCALL_CAT_MODULE,         // init_module, finit_module, delete_module
    SYSCALL_CAT_TIME,           // settimeofday, clock_settime
    SYSCALL_CAT_AUDIT,          // syslog, acct
} syscall_category_t;

// eBPF-based syscall monitoring (more flexible than seccomp)
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
    long syscall_nr = ctx->id;

    // Filter to security-relevant syscalls
    syscall_category_t cat;
    if (!is_monitored_syscall(syscall_nr, &cat)) {
        return 0;
    }

    struct syscall_event evt = {0};
    evt.syscall_nr = syscall_nr;
    evt.category = cat;
    evt.timestamp = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    // Capture syscall arguments based on category
    switch (cat) {
        case SYSCALL_CAT_FILE:
            // For open: capture path and flags
            if (syscall_nr == __NR_openat || syscall_nr == __NR_open) {
                bpf_probe_read_user_str(evt.args.file.path,
                    sizeof(evt.args.file.path),
                    (void *)ctx->args[syscall_nr == __NR_openat ? 1 : 0]);
                evt.args.file.flags = ctx->args[syscall_nr == __NR_openat ? 2 : 1];
            }
            break;

        case SYSCALL_CAT_NETWORK:
            // For connect: capture sockaddr
            if (syscall_nr == __NR_connect) {
                evt.args.net.fd = ctx->args[0];
                bpf_probe_read_user(&evt.args.net.addr,
                    sizeof(evt.args.net.addr),
                    (void *)ctx->args[1]);
            }
            break;

        case SYSCALL_CAT_PRIVILEGE:
            // For setuid: capture target UID
            if (syscall_nr == __NR_setuid) {
                evt.args.priv.target_uid = ctx->args[0];
            }
            break;

        // ... other categories
    }

    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return 0;
}
```

### D.4 File System Monitoring

```c
// Critical file paths to monitor
static const char *sensitive_paths[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
    "/root/.ssh/",
    "/etc/cron",
    "/etc/systemd/",
    "/usr/lib/systemd/",
    "/var/spool/cron/",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/lib/x86_64-linux-gnu/",  // Shared libraries
    "/usr/bin/",
    "/usr/sbin/",
    NULL
};

// eBPF LSM (Linux Security Module) hooks for file monitoring
// Requires CONFIG_BPF_LSM=y and bpf LSM enabled
SEC("lsm/file_open")
int BPF_PROG(file_open_audit, struct file *file) {
    // Get path from file struct
    char path[256];
    struct path *f_path = &file->f_path;
    // Use d_path helper or build path from dentry chain

    // Check if sensitive
    if (is_sensitive_path(path)) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

        struct file_event evt = {0};
        evt.type = FILE_OPEN;
        evt.pid = pid;
        evt.uid = uid;
        evt.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(evt.path, path, sizeof(evt.path));
        bpf_get_current_comm(evt.comm, sizeof(evt.comm));

        // Check access mode
        evt.flags = file->f_flags;
        evt.mode = file->f_mode;

        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;  // Allow (audit only, not enforcement)
}

SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink_audit, struct inode *dir, struct dentry *dentry) {
    // Monitor file deletions
    char name[64];
    bpf_probe_read_kernel_str(name, sizeof(name), dentry->d_name.name);

    // Check if critical file/directory
    if (is_critical_file(dir, name)) {
        struct file_event evt = {0};
        evt.type = FILE_DELETE;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(evt.filename, name, sizeof(evt.filename));

        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}
```

### D.5 Container and Namespace Monitoring

```c
// Monitor container-relevant operations
SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx) {
    unsigned long flags = ctx->args[0];

    // Monitor namespace creation
    if (flags & (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET |
                 CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWIPC)) {

        struct namespace_event evt = {0};
        evt.type = NS_CREATE;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp = bpf_ktime_get_ns();
        evt.ns_flags = flags;

        bpf_get_current_comm(evt.comm, sizeof(evt.comm));

        // Detect potential container escape indicators
        if (flags & CLONE_NEWUSER) {
            evt.risk_score += 20;  // User namespace can enable other ns
        }
        if ((flags & CLONE_NEWPID) && (flags & CLONE_NEWNS)) {
            evt.risk_score += 10;  // Common in container escape
        }

        bpf_perf_event_output(ctx, &namespace_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

// Monitor Docker socket access
SEC("kprobe/unix_stream_connect")
int trace_unix_connect(struct pt_regs *ctx) {
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sockaddr_un *addr = (struct sockaddr_un *)PT_REGS_PARM2(ctx);

    char sun_path[108];
    bpf_probe_read_kernel(sun_path, sizeof(sun_path), addr->sun_path);

    // Check for Docker/containerd socket access
    if (str_contains(sun_path, "docker.sock") ||
        str_contains(sun_path, "containerd.sock") ||
        str_contains(sun_path, "crio.sock")) {

        struct container_event evt = {0};
        evt.type = CONTAINER_SOCKET_ACCESS;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(evt.socket_path, sun_path, sizeof(evt.socket_path));

        bpf_get_current_comm(evt.comm, sizeof(evt.comm));

        // High risk if from within a container
        if (is_in_container()) {
            evt.risk_score = 90;  // Container escape attempt
        }

        bpf_perf_event_output(ctx, &container_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}
```

### D.6 Cgroup Monitoring

```c
// Monitor cgroup modifications
SEC("tracepoint/cgroup/cgroup_mkdir")
int trace_cgroup_mkdir(struct trace_event_raw_cgroup *ctx) {
    struct cgroup_event evt = {0};
    evt.type = CGROUP_CREATE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.timestamp = bpf_ktime_get_ns();

    bpf_probe_read_kernel_str(evt.path, sizeof(evt.path), ctx->path);
    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    bpf_perf_event_output(ctx, &cgroup_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return 0;
}

SEC("tracepoint/cgroup/cgroup_rmdir")
int trace_cgroup_rmdir(struct trace_event_raw_cgroup *ctx) {
    struct cgroup_event evt = {0};
    evt.type = CGROUP_REMOVE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.timestamp = bpf_ktime_get_ns();

    bpf_probe_read_kernel_str(evt.path, sizeof(evt.path), ctx->path);

    bpf_perf_event_output(ctx, &cgroup_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return 0;
}

// Monitor device cgroup modifications (container escape vector)
SEC("kprobe/devcgroup_check_permission")
int trace_device_access(struct pt_regs *ctx) {
    short type = (short)PT_REGS_PARM2(ctx);
    u32 major = (u32)PT_REGS_PARM3(ctx);
    u32 minor = (u32)PT_REGS_PARM4(ctx);
    short access = (short)PT_REGS_PARM5(ctx);

    // Monitor access to sensitive devices
    // /dev/mem (1,1), /dev/kmem (1,2), /dev/port (1,4)
    // Block devices that could be used for escape
    bool sensitive = false;
    if (major == 1 && (minor == 1 || minor == 2 || minor == 4)) {
        sensitive = true;  // Memory devices
    }
    if (type == 'b') {
        sensitive = true;  // Any block device
    }

    if (sensitive) {
        struct device_event evt = {0};
        evt.type = DEVICE_ACCESS;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.timestamp = bpf_ktime_get_ns();
        evt.dev_type = type;
        evt.major = major;
        evt.minor = minor;
        evt.access = access;

        bpf_perf_event_output(ctx, &device_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}
```

---

## Appendix E: Runtime Security Policies (v2.2+)

Inspired by Cilium Tetragon and Falco, runtime policies define what behavior to monitor and alert on.

### E.1 Policy Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      RUNTIME POLICY ENGINE (v2.2+)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        POLICY FLOW                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐            │
│    │   Platform   │      │    Agent     │      │   Kernel     │            │
│    │              │      │              │      │   (eBPF)     │            │
│    └──────┬───────┘      └──────┬───────┘      └──────┬───────┘            │
│           │                     │                     │                     │
│           │  1. Push policy     │                     │                     │
│           │  (YAML → compiled)  │                     │                     │
│           │────────────────────►│                     │                     │
│           │                     │                     │                     │
│           │                     │  2. Load eBPF       │                     │
│           │                     │  programs & maps    │                     │
│           │                     │────────────────────►│                     │
│           │                     │                     │                     │
│           │                     │      3. Events      │                     │
│           │                     │◄────────────────────│                     │
│           │                     │                     │                     │
│           │  4. Alerts          │                     │                     │
│           │◄────────────────────│                     │                     │
│           │                     │                     │                     │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     POLICY COMPONENTS                                │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │  SELECTORS          What to monitor                                  │   │
│  │  ──────────         ────────────────                                 │   │
│  │  • matchProcesses   Process name, path, args                         │   │
│  │  • matchPids        Specific PIDs                                    │   │
│  │  • matchNamespaces  Container/namespace IDs                          │   │
│  │  • matchLabels      Kubernetes labels                                │   │
│  │  • matchBinaries    Binary hash, signature                           │   │
│  │                                                                      │   │
│  │  HOOKS              Where to monitor                                 │   │
│  │  ─────              ────────────────                                 │   │
│  │  • tracepoints      Kernel tracepoints                               │   │
│  │  • kprobes          Kernel function entry/exit                       │   │
│  │  • uprobes          Userspace function hooks                         │   │
│  │  • lsm              LSM hook points                                  │   │
│  │                                                                      │   │
│  │  ACTIONS            What to do                                       │   │
│  │  ───────            ──────────                                       │   │
│  │  • Audit            Log event (default)                              │   │
│  │  • Alert            Generate alert with severity                     │   │
│  │  • Override         Modify return value (LSM)                        │   │
│  │  • Kill             Terminate process (SIGKILL)                      │   │
│  │  • Throttle         Rate limit the operation                         │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### E.2 Policy Definition (YAML)

```yaml
# Example: Detect reverse shell attempts
apiVersion: sslsniff.io/v1
kind: TracingPolicy
metadata:
  name: detect-reverse-shell
  description: Detect potential reverse shell connections
  mitre:
    tactic: TA0011  # Command and Control
    technique: T1059  # Command and Scripting Interpreter

spec:
  selectors:
    # Monitor shell interpreters
    matchBinaries:
      operator: In
      values:
        - /bin/bash
        - /bin/sh
        - /bin/zsh
        - /usr/bin/bash
        - /usr/bin/sh
        - /usr/bin/python*
        - /usr/bin/perl
        - /usr/bin/ruby

  hooks:
    # Monitor when shell connects to network
    - hook: kprobe
      function: tcp_connect
      args:
        - name: sock
          type: sock
      selectors:
        # Only remote connections
        matchArgs:
          - arg: sock
            operator: NotEqual
            values:
              - "127.0.0.1"

    # Monitor dup2 to redirect stdio to socket
    - hook: tracepoint
      tracepoint: syscalls/sys_enter_dup2
      args:
        - name: oldfd
          type: int
        - name: newfd
          type: int
      selectors:
        matchArgs:
          - arg: newfd
            operator: In
            values: [0, 1, 2]  # stdin, stdout, stderr

  actions:
    - action: Alert
      severity: Critical
      message: "Potential reverse shell detected"

---
# Example: Protect sensitive files
apiVersion: sslsniff.io/v1
kind: TracingPolicy
metadata:
  name: protect-sensitive-files
  description: Monitor access to sensitive system files

spec:
  hooks:
    - hook: lsm
      function: file_open
      args:
        - name: file
          type: file
      selectors:
        matchArgs:
          - arg: file
            operator: Prefix
            values:
              - /etc/shadow
              - /etc/sudoers
              - /root/.ssh/

  actions:
    - action: Alert
      severity: High
      message: "Sensitive file accessed"
      includeContext:
        - processTree
        - networkConnections
        - fileDescriptors

---
# Example: Container escape detection
apiVersion: sslsniff.io/v1
kind: TracingPolicy
metadata:
  name: container-escape-detection
  description: Detect container escape attempts
  mitre:
    tactic: TA0004  # Privilege Escalation
    technique: T1611  # Escape to Host

spec:
  selectors:
    matchNamespaces:
      operator: NotEqual
      values:
        - host  # Only monitor containers, not host processes

  hooks:
    # Mount namespace escape
    - hook: tracepoint
      tracepoint: syscalls/sys_enter_mount
      args:
        - name: source
          type: string
        - name: target
          type: string
        - name: flags
          type: uint64

    # Privileged device access
    - hook: lsm
      function: inode_permission
      args:
        - name: inode
          type: inode
      selectors:
        matchArgs:
          - arg: inode
            operator: DeviceType
            values:
              - block
              - char_mem  # /dev/mem, /dev/kmem

    # nsenter attempt
    - hook: tracepoint
      tracepoint: syscalls/sys_enter_setns
      args:
        - name: fd
          type: fd
        - name: nstype
          type: int

    # Docker socket access from container
    - hook: kprobe
      function: unix_stream_connect
      selectors:
        matchArgs:
          - arg: path
            operator: Contains
            values:
              - docker.sock
              - containerd.sock

  actions:
    - action: Alert
      severity: Critical
      message: "Container escape attempt detected"
    - action: Kill
      signal: SIGKILL
      when:
        matchArgs:
          - arg: path
            operator: Contains
            values: ["docker.sock"]
```

### E.3 Policy Compiler

```c
// Compile YAML policy to eBPF bytecode
typedef struct {
    char name[64];
    char description[256];

    // Selectors
    selector_t *selectors;
    int selector_count;

    // Hooks
    hook_spec_t *hooks;
    int hook_count;

    // Actions
    action_spec_t *actions;
    int action_count;

    // Compiled eBPF
    struct bpf_object *bpf_obj;
    struct bpf_program **progs;
    int prog_count;

} compiled_policy_t;

int compile_policy(const char *yaml_path, compiled_policy_t *out) {
    // Parse YAML
    policy_yaml_t *yaml = parse_policy_yaml(yaml_path);
    if (!yaml) return -1;

    // Generate eBPF source
    char *bpf_source = generate_bpf_source(yaml);

    // Compile with libbpf
    struct bpf_object *obj = bpf_object__open_mem(bpf_source,
                                                   strlen(bpf_source), NULL);
    if (!obj) {
        free(bpf_source);
        return -1;
    }

    // Load programs
    int err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        free(bpf_source);
        return -1;
    }

    // Attach hooks
    for (int i = 0; i < yaml->hook_count; i++) {
        hook_spec_t *hook = &yaml->hooks[i];
        struct bpf_program *prog = bpf_object__find_program_by_name(
            obj, hook->program_name);

        if (hook->type == HOOK_KPROBE) {
            bpf_program__attach_kprobe(prog, false, hook->function);
        } else if (hook->type == HOOK_TRACEPOINT) {
            bpf_program__attach_tracepoint(prog, hook->category,
                                           hook->tracepoint);
        } else if (hook->type == HOOK_LSM) {
            bpf_program__attach_lsm(prog);
        }
    }

    out->bpf_obj = obj;
    // ... populate other fields

    free(bpf_source);
    return 0;
}

// Hot-reload policies without agent restart
int reload_policy(agent_ctx_t *ctx, const char *policy_name,
                  compiled_policy_t *new_policy) {
    // Find existing policy
    compiled_policy_t *old = find_policy(ctx, policy_name);

    // Atomic swap using RCU
    rcu_assign_pointer(ctx->policies[policy_index], new_policy);
    synchronize_rcu();

    // Cleanup old policy
    if (old) {
        bpf_object__close(old->bpf_obj);
        free(old);
    }

    return 0;
}
```

---

## Appendix F: Full Endpoint Protection (v3.0+)

### F.1 Vision: Unified Endpoint Security

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SSLSNIFF v3.0: FULL ENDPOINT PROTECTION                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      UNIFIED VISIBILITY                              │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │   NETWORK              PROCESS              FILE SYSTEM              │   │
│  │   ───────              ───────              ───────────              │   │
│  │   • HTTP/1,2,3         • Execution          • Access                 │   │
│  │   • TLS/QUIC           • Syscalls           • Modification           │   │
│  │   • DNS                • Memory             • Permissions            │   │
│  │   • Flow metadata      • Signals            • Integrity              │   │
│  │                                                                      │   │
│  │   CONTAINER            KERNEL               USER                     │   │
│  │   ─────────            ──────               ────                     │   │
│  │   • Namespaces         • Modules            • Auth events            │   │
│  │   • Cgroups            • Syscalls           • Sessions               │   │
│  │   • Runtime            • eBPF               • Privilege use          │   │
│  │   • Orchestrator       • LSM                • Key usage              │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      PROTECTION CAPABILITIES                         │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │   DETECT              PREVENT              RESPOND                   │   │
│  │   ──────              ───────              ───────                   │   │
│  │   • Threat intel      • Policy enforce     • Process kill            │   │
│  │   • Anomaly           • Syscall block      • Network block           │   │
│  │   • Behavioral        • File quarantine    • Isolate host            │   │
│  │   • Signature         • Network filter     • Collect forensics       │   │
│  │   • ML inference      • Rate limit         • Alert & escalate        │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      INTEGRATION POINTS                              │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │   SIEM/SOAR           ORCHESTRATION        IDENTITY                  │   │
│  │   ─────────           ────────────         ────────                  │   │
│  │   • Splunk            • Kubernetes         • Active Directory        │   │
│  │   • Elastic           • Docker             • LDAP                    │   │
│  │   • Sentinel          • Nomad              • OIDC                    │   │
│  │   • Chronicle         • ECS                • SAML                    │   │
│  │                                                                      │   │
│  │   THREAT INTEL        TICKETING            COMPLIANCE                │   │
│  │   ────────────        ─────────            ──────────                │   │
│  │   • MISP              • ServiceNow         • PCI-DSS                 │   │
│  │   • OTX               • Jira               • HIPAA                   │   │
│  │   • VirusTotal        • PagerDuty          • SOC2                    │   │
│  │   • STIX/TAXII        • Opsgenie           • GDPR                    │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### F.2 Attack Chain Correlation

```c
// Correlate events into attack chains (MITRE ATT&CK mapping)
typedef struct {
    char chain_id[64];
    uint64_t start_time;
    uint64_t last_update;

    // Attack progression
    attack_stage_t current_stage;
    /*
     * INITIAL_ACCESS → EXECUTION → PERSISTENCE → PRIVILEGE_ESCALATION →
     * DEFENSE_EVASION → CREDENTIAL_ACCESS → DISCOVERY → LATERAL_MOVEMENT →
     * COLLECTION → COMMAND_AND_CONTROL → EXFILTRATION → IMPACT
     */

    // Evidence
    event_ref_t *events;
    int event_count;

    // Affected assets
    char *hosts[MAX_HOSTS];
    char *users[MAX_USERS];
    char *processes[MAX_PROCESSES];

    // Risk scoring
    float confidence;
    float severity;

    // MITRE mapping
    mitre_technique_t *techniques;
    int technique_count;

} attack_chain_t;

// Correlate incoming event with existing chains
void correlate_event(correlation_engine_t *engine, event_t *event) {
    // Check if event matches any existing chain
    attack_chain_t *chain = find_matching_chain(engine, event);

    if (chain) {
        // Add to existing chain
        add_event_to_chain(chain, event);
        update_chain_stage(chain);
        recalculate_risk(chain);
    } else if (is_initial_access_indicator(event)) {
        // Start new potential chain
        chain = create_chain(engine);
        add_event_to_chain(chain, event);
        chain->current_stage = INITIAL_ACCESS;
    }

    // Check for chain completion or high severity
    if (chain && should_alert(chain)) {
        emit_attack_chain_alert(engine, chain);
    }
}

// Generate MITRE ATT&CK navigator layer
void export_mitre_layer(attack_chain_t *chain, char *json_out, size_t len) {
    // Generate ATT&CK Navigator compatible JSON
    // Shows which techniques were observed in this attack chain
}
```

### F.3 Automated Response Playbooks

```yaml
# Example: Ransomware response playbook
apiVersion: sslsniff.io/v1
kind: ResponsePlaybook
metadata:
  name: ransomware-response
  description: Automated response to ransomware indicators
  severity: Critical

triggers:
  - type: AttackChain
    stage: IMPACT
    indicators:
      - massive_file_encryption
      - ransom_note_creation

  - type: Alert
    name: known-ransomware-behavior

actions:
  - name: isolate-host
    type: NetworkIsolate
    params:
      allow:
        - sslsniff-platform  # Maintain agent communication
      block:
        - all

  - name: kill-malicious-process
    type: ProcessKill
    params:
      signal: SIGKILL
      target: triggering_process
      descendants: true  # Also kill child processes

  - name: snapshot-memory
    type: ForensicCapture
    params:
      type: memory_dump
      target: triggering_process
      upload: true

  - name: preserve-evidence
    type: ForensicCapture
    params:
      type: file_system_snapshot
      paths:
        - /tmp
        - /var/tmp
        - triggering_process_cwd

  - name: notify-security-team
    type: Alert
    params:
      channel: security-critical
      include:
        - attack_chain_summary
        - affected_files
        - process_tree
        - network_connections

  - name: create-incident
    type: TicketCreate
    params:
      system: servicenow
      priority: P1
      assignee: security-oncall
```

---

*Document created: 2026-01-11*
*Last updated: 2026-01-11*
*Author: sslsniff development team*
