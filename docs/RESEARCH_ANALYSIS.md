# Research Analysis: Golden Thread Correlation Improvements

This document analyzes the research findings from `/tmp/research.txt` and maps them to spliff's current implementation status.

## Executive Summary

Of the 15 recommendations in the research document:
- **10 are fully implemented** (Handshake Race, Bitmask Retries, Atomics, Bidirectional Maps, LRU, Process Cleanup, Warm-up, Byte Order, Worker Sharding, Flow Janitor)
- **0 are partially implemented**
- **5 are not implemented** (TC-BPF, L3 Parsing, ALPN Hinting, Zero-Copy, XDP Retry Flag)

## Detailed Analysis

### 1. Handshake Race (Lines 96-160) ✅ IMPLEMENTED

**Research Recommendation:**
> "Instead of giving up when the map lookup fails, use the Retry Queue in your Golden Thread... packets missing a cookie are flagged for a 500μs sleep."

**Current Implementation:**
- `src/threading/worker.c`: Cookie retry queue with 64-slot bitmask
- `src/threading/dispatcher.c`: Sets `needs_cookie_retry` flag on cache miss
- Up to 3 retries with batch processing every 4 NAPI iterations

**Status:** ✅ Fully implemented in v0.9.2

---

### 2. Byte Order Handling (Lines 1-31, 243-251) ✅ IMPLEMENTED

**Research Recommendation:**
```c
key.sport = (__u16)skops->local_port;  // HBO
key.dport = (__u16)bpf_ntohl(skops->remote_port);  // NBO in __u32
```

**Current Implementation:**
- `src/bpf/spliff.bpf.c:3220-3250`: Proper HBO/NBO conversion
- Both local and remote ports correctly converted to NBO for map consistency

**Status:** ✅ Fully implemented

---

### 3. Mirror Image Problem - Bidirectional Storage (Lines 32-86) ✅ IMPLEMENTED

**Research Recommendation:**
> "Store two entries in the map: {Local_IP, Remote_IP, Local_Port, Remote_Port} → Cookie AND {Remote_IP, Local_IP, Remote_Port, Local_Port} → Cookie"

**Current Implementation:**
- `src/bpf/spliff.bpf.c:3253-3282`: Stores both `fkey` and `reverse_fkey`
- Handles both ingress and egress packet directions

**Status:** ✅ Fully implemented

---

### 4. CPU Efficiency - Bitmask Retries (Lines 262-264) ✅ IMPLEMENTED

**Research Recommendation:**
> "Use a uint64_t bitmask. Each bit represents a slot in your retry array. Use __builtin_ctzll to find and process all pending retries in a single batch."

**Current Implementation:**
- `src/threading/worker.c`: `deferred_busy_mask` (uint64_t)
- Uses `__builtin_ctzll()` for O(1) slot finding
- Batch retry processing via `process_deferred_batch()`

**Status:** ✅ Fully implemented in v0.9.2

---

### 5. Memory Ordering - Atomics (Lines 265-267) ✅ IMPLEMENTED

**Research Recommendation:**
> "Use memory_order_release when the Golden Thread writes metadata and memory_order_acquire when the worker reads it."

**Current Implementation:**
- `src/correlation/flow_cache.c`: `atomic_store_explicit(..., memory_order_release)`
- `src/correlation/flow_cache.c`: `atomic_load_explicit(..., memory_order_acquire)`
- `src/correlation/flow_cache.h`: `_Atomic bool active` field

**Status:** ✅ Fully implemented in v0.9.2

---

### 6. Worker Sharding (Lines 268-272, 334) ✅ IMPLEMENTED

**Research Recommendation:**
> "Shard your worker threads by (socket_cookie % worker_count). This guarantees that all packets and uprobe data for a specific connection land on the same CPU core."

**Resolution (v0.9.3):**
- Added `get_worker_id_ex()` function in `src/threading/threading.h:1178-1186`
- Uses `socket_cookie % num_workers` when cookie is available
- Falls back to `flow_hash(pid, ssl_ctx) % num_workers` when cookie is 0
- Updated `src/threading/dispatcher.c:91-93` to use socket_cookie-first strategy

**Status:** ✅ Fully implemented

---

### 7. Flow Janitor (Lines 358-360) ✅ IMPLEMENTED

**Research Recommendation:**
> "Implement a 'Janitor' in the Golden Thread. If a flow hasn't seen a packet in 60 seconds, explicitly delete it from your userspace session tracking."

**Resolution (v0.9.3):**
- Added `FLOW_JANITOR_INTERVAL_NS` constant (30 seconds) in `src/threading/dispatcher.c:56`
- Integrated periodic cleanup into dispatcher main loop at `src/threading/dispatcher.c:419-427`
- Calls `flow_cache_evict_stale()` every 30 seconds
- Debug output shows eviction count when flows are cleaned up

**Status:** ✅ Fully implemented

---

### 8. Process Exit Cleanup (Lines 274-278) ✅ IMPLEMENTED

**Research Recommendation:**
> "Use tracepoint/sched/sched_process_exit to trigger cleanup of all HTTP/2 session states."

**Current Implementation:**
- `src/bpf/spliff.bpf.c`: `handle_process_exit` tracepoint attached
- Cleans up SSL session tracking maps on process exit

**Status:** ✅ Fully implemented

---

### 9. Warm-up / SOCK_DIAG (Lines 286-292) ✅ IMPLEMENTED

**Research Recommendation:**
> "Use NETLINK_SOCK_DIAG to dump all existing TCP sockets. Pre-populate the BPF map."

**Current Implementation:**
- `src/bpf/bpf_loader.c`: Seeds existing connections at startup
- Reads /proc/net/tcp for warm-up

**Status:** ✅ Fully implemented

---

### 10. VPN/WireGuard - TC-BPF (Lines 162-226, 253-259) ❌ NOT IMPLEMENTED

**Research Recommendation:**
> "TC hooks fire for all packets including tunnel-injected ones... Use XDP_FLAGS_SKB_MODE for virtual drivers."

**Current Issue:**
XDP on tunnel interfaces doesn't see decapsulated packets because they're "injected" into the stack after decryption.

**Recommended Fix:**
1. Detect virtual/tunnel interfaces (already done via `is_physical` flag)
2. For virtual interfaces, attach TC-BPF instead of XDP
3. Create `SEC("tc")` program with same flow tracking logic

**Priority:** HIGH - Required for VPN support

---

### 11. L3 Parsing for Tunnels (Lines 207-218, 453-459) ❌ NOT IMPLEMENTED

**Research Recommendation:**
> "Tunnel interfaces often omit the Ethernet header. The XDP parser must detect the interface type and start parsing directly from the IP header."

**Current Implementation:**
- `src/bpf/spliff.bpf.c:2638-2649`: Always expects Ethernet header
- Will fail on tunnel interfaces that start with IP header

**Recommended Fix:**
```c
// In xdp_parse_packet_cached():
if (is_tunnel_interface) {
    // Start at IP header directly
    struct iphdr *ip = data;
    // ...
} else {
    // Normal Ethernet parsing
    struct ethhdr *eth = data;
    // ...
}
```

**Priority:** MEDIUM - Would help some tunnel cases

---

### 12. ALPN Protocol Hinting (Lines 349-351, 384-388) ❌ NOT IMPLEMENTED

**Research Recommendation:**
> "Have XDP parse the ALPN extension in Client Hello. Write HTTP/2 or HTTP/1.1 into flow_info. Initialize the correct parser before first encrypted byte."

**Current Implementation:**
- XDP detects TLS but doesn't parse ALPN extension
- Protocol detection happens after handshake via SSL_get0_alpn_selected uprobe

**Benefit:** Earlier protocol detection, potentially faster parser initialization

**Priority:** LOW - Current approach works, this is optimization

---

### 13. Zero-Copy Uprobe Buffers (Lines 352-354) ❌ NOT IMPLEMENTED

**Research Recommendation:**
> "Use Perf Buffer with custom-sized chunks for large responses, or shared memory map."

**Current Implementation:**
- Uses BPF ring buffer with fixed-size events
- Large payloads truncated to fit

**Benefit:** Handle large responses without truncation

**Priority:** LOW - Current approach adequate for most HTTP traffic

---

### 14. XDP RETRY_LOOKUP Flag (Lines 137-154, 304-306) ❌ NOT IMPLEMENTED

**Research Recommendation:**
> "In XDP, signal COOKIE_NOT_YET_AVAILABLE flag to Golden Thread for retry."

**Current Implementation:**
- XDP sends events with cookie=0 when lookup fails
- Retry logic is in SSL event path, not XDP event path

**Benefit:** Could improve XDP-side correlation for early packets

**Priority:** LOW - Cookie retry already works for SSL events

---

### 15. LRU Map (Line 94) ✅ IMPLEMENTED

**Research Recommendation:**
> "Ensure flow_cookie_map is an LRU_HASH so the 2x entries don't overflow."

**Current Implementation:**
- `src/bpf/spliff.bpf.c:482`: `BPF_MAP_TYPE_LRU_HASH`
- 65K max entries

**Status:** ✅ Fully implemented

---

## Recommended Implementation Order

### Phase 1: Quick Wins (Low Effort, High Impact)
1. **Flow Janitor** - Just call existing function periodically
2. **Worker Sharding** - Change hash function to use socket_cookie

### Phase 2: VPN Support (Medium Effort, High Impact)
3. **TC-BPF Fallback** - New BPF program for virtual interfaces
4. **L3 Parsing** - Handle missing Ethernet header on tunnels

### Phase 3: Optimization (Higher Effort, Lower Impact)
5. **ALPN Hinting** - Parse Client Hello in XDP
6. **Zero-Copy Buffers** - Perf buffer for large payloads
7. **XDP Retry Flag** - Signal retry need from XDP

---

## Quick Reference: Current File Locations

| Component | File | Key Functions |
|-----------|------|---------------|
| Cookie Retry Queue | `src/threading/worker.c` | `defer_event_for_retry()`, `process_deferred_batch()` |
| Flow Cache | `src/correlation/flow_cache.c` | `flow_cache_upsert()`, `flow_cache_lookup()`, `flow_cache_evict_stale()` |
| Sock_ops | `src/bpf/spliff.bpf.c` | `sockops_cache_cookie()` |
| XDP | `src/bpf/spliff.bpf.c` | `xdp_flow_tracker()`, `xdp_parse_packet_cached()` |
| Worker Sharding | `src/threading/threading.h` | `get_worker_id()`, `flow_hash()` |
| Interface Detection | `src/bpf/bpf_loader.c` | `is_virtual_interface()`, `bpf_loader_xdp_discover_interfaces()` |
