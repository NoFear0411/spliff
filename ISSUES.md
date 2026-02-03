# Known Issues

This document tracks known issues, bugs, limitations, and resolved issues in spliff. For feature requests and discussion, see [GitHub Issues](https://github.com/NoFear0411/spliff/issues).

## Open Issues

### 1. VPN (Wireguard) Correlation Failure (High Priority)

**Symptoms:**
- XDP correlation stops working when VPN is connected
- Traffic through wg0/tunnel interface shows `flow_info=NOT_FOUND` even with cookie retry
- SSL events have cookies, but flow_cache never gets populated for VPN traffic
- Cookie retry statistics show high failure rate (~76%) for VPN sessions
- Works perfectly when VPN disconnected

**Root Cause:**
**XDP doesn't see tunnel-decapsulated packets.** Even when XDP is attached to the WireGuard interface in SKB mode, packets that are "injected" into the network stack after decapsulation bypass the XDP hook.

Packet flow with WireGuard:
1. Encrypted UDP arrives on physical interface → XDP sees encrypted blob (ignored)
2. WireGuard decrypts packet
3. Decrypted TCP packet is "injected" into stack → **bypasses XDP hook on wg0**
4. sock_ops fires correctly → cookie stored in `flow_cookie_map`
5. SSL uprobes fire → cookie obtained from socket
6. But XDP never saw the packet → `flow_cache` never populated → correlation fails

This is a **fundamental limitation of XDP on virtual/tunnel interfaces**, not a bug in spliff.

**Evidence:**
- `Cookie misses: 0` - XDP finds cookies when it DOES see packets
- `Retry failures: 76%` - flow_cache never populated for VPN traffic
- XDP IS attached to wg interface (confirmed in debug output)

**Affected Components:**
- `src/bpf/spliff.bpf.c` - XDP program (cannot see injected packets)
- Linux kernel XDP architecture

**Potential Fixes:**
1. **TC-BPF fallback (recommended)**: Use Traffic Control BPF for virtual interfaces instead of XDP. TC hooks fire for all packets including tunnel-injected ones.
2. **Process-based correlation**: Fall back to PID+timing correlation when XDP fails
3. **Accept as limitation**: Document that VPN traffic correlation requires TC-BPF

**Workaround:** Disconnect VPN for full correlation. SSL interception still works with VPN, only the network metadata (IP:port) is missing.

---

### 2. Static NIC Attachment (Medium Priority)

**Symptoms:**
- Interfaces that appear after spliff starts are not monitored
- Interfaces that go down may cause errors
- Hot-plugged USB NICs not automatically attached

**Root Cause:**
XDP interface discovery and attachment happens once at startup. No monitoring for interface lifecycle events.

**Affected Components:**
- `src/bpf/bpf_loader.c` - `xdp_init()` function

**Potential Fixes:**
- Add netlink socket monitoring for RTMGRP_LINK events
- Handle RTM_NEWLINK: attach XDP to new interfaces
- Handle RTM_DELLINK: cleanup detached interfaces
- Similar pattern to dynamic process monitoring for SSL libraries

**Workaround:** Restart spliff after connecting new interfaces.

---

## Known Limitations

These are architectural or design constraints rather than bugs.

- **Chrome/Chromium Support (Experimental)**: Browsers using statically-linked BoringSSL are **experimental**:
  - Offsets vary between browser versions, builds, and distributions
  - Detection relies on heuristic binary scanning that may fail
  - Recommended: Use Firefox (NSS) for reliable browser traffic capture

- **Protocol Detection Timing**: ALPN-based protocol detection may miss if the ALPN event arrives after data events. Content-based fallback detection is planned for v0.10.0.
- **HTTP/2 Mid-Stream Capture**: Joining existing HTTP/2 connections may cause HPACK decode errors for first few responses. Recovery is automatic via `hpack_corrupted` flag per RFC 7540.
- **HTTP/2 Stream Limits**: 64 concurrent streams per flow. Ghost streams (inactive >10s) are automatically reaped.
- **XDP Native Mode**: Some network drivers don't support XDP native mode; spliff automatically falls back to SKB mode with a status message.
- **Plain HTTP Capture**: Currently only captures TLS-encrypted traffic. Plain HTTP capture planned for future release.
- **QUIC/HTTP/3**: Not yet supported (planned for v0.11.0).
- **Kernel Requirements**: Requires Linux 5.x+ with BTF support (`CONFIG_DEBUG_INFO_BTF=y`).

- **XDP Classification Timing** (v0.9.9): Some HTTP messages may show `[XDP:?]` with a single checkmark instead of `[XDP:TLS] ✓✓`. This occurs because XDP classification depends on seeing protocol data in packets - the first packet (SYN/ACK) has no payload. XDP needs a data packet with TLS record header or HTTP signature to classify. This is by design: single checkmark means App-layer confirmed, XDP pending/unavailable. Not a bug.

---

## Resolved Issues

### IPv6 XOR Hash Collisions (Fixed in v0.9.10)

**Symptoms:**
- IPv6 flow correlation fails or has high collision rate (~50% at 65K flows)
- Different IPv6 flows incorrectly correlated to same flow context

**Root Cause:**
XOR hashing of 128-bit IPv6 addresses to 32-bit values loses too much information. With 65K flows, birthday problem causes ~50% collision probability.

**Resolution:**
Implemented zero-collision IPv6 flow correlation:
- New `struct flow_key_v6` with full 16-byte source and destination addresses (40 bytes total)
- Separate `flow_cookie_map_v6` BPF map (LRU_HASH, 32768 entries)
- IPv6 extension header walking with bounded loop (MAX_IPV6_EXT_HEADERS=5)
- XDP parser updated to use appropriate flow key type based on IP version

**Fixed in:** `src/bpf/spliff.bpf.c`, `src/include/spliff.h`

---

### O(n) Cookie Lookup in Shadow Index (Fixed in v0.9.10)

**Symptoms:**
- `ck_shadow_find_by_cookie()` performs O(n) linear scan
- Performance degrades with many concurrent flows

**Root Cause:**
Shadow index only had composite key (pid, ssl_ctx) → flow lookup. Finding flow by socket_cookie required iterating all entries.

**Resolution:**
Added secondary `ck_hs` hash table keyed by socket_cookie:
- `by_cookie` hash set added to `ck_shadow_index_t` struct
- O(1) lookup via `ck_shadow_find_by_cookie()`
- Dual insert/remove to maintain both indexes
- ~8KB memory cost (256 entries × 32 bytes)

**Fixed in:** `src/correlation/ck_shadow_index.h`, `src/correlation/ck_shadow_index.c`

---

### Hardcoded cgroup2 Paths (Fixed in v0.9.10)

**Symptoms:**
- sock_ops attachment fails on systems with non-standard cgroup2 mount
- Manual path configuration required for some distributions

**Root Cause:**
Hardcoded fallback paths (`/sys/fs/cgroup`, `/sys/fs/cgroup/unified`) don't cover all configurations.

**Resolution:**
Implemented dynamic cgroup2 detection:
- `find_cgroup2_mount()` parses `/proc/mounts` for "cgroup2" filesystem type
- Falls back to standard paths if parsing fails
- Works across all distributions: Fedora 31+, Ubuntu 21.10+, RHEL 9+

**Fixed in:** `src/bpf/bpf_loader.c`

---

### Cache-Line Alignment Verification (Fixed in v0.9.10)

**Symptoms:**
- Potential performance issues on systems where `aligned_alloc(64, ...)` may not work
- No compile-time verification of alignment requirements

**Root Cause:**
jemalloc dependency implicit; glibc < 2.16 may not honor 64-byte alignment.

**Resolution:**
Added compile-time verification:
- `_Static_assert(alignof(max_align_t) >= 16, ...)` ensures system alignment is sufficient
- Documentation clarifies jemalloc requirement for cache-line alignment
- `aligned_alloc(64, ...)` used for HTTP/2 response buffer (65KB)

**Fixed in:** `src/correlation/flow_context.c`, `src/threading/state.c`

---

### SSL-sockops Timing Race (Fixed in v0.9.2)

**Symptoms:**
- First HTTP request from each process lacks XDP correlation
- Under high load, ~50% of request/response pairs miss correlation
- Statistics show "Cookie misses" incrementing

**Root Cause:**
Race condition between SSL uprobe events and sockops `flow_cookie_map` population. The SSL_read/SSL_write uprobe fires before sockops has cached the socket cookie in `flow_cookie_map`.

**Resolution:**
Implemented cookie retry queue with bitmask-based slot management:
- Events with valid `socket_cookie` but missing `flow_info` are deferred
- Up to 3 retry attempts with batch processing every 4 NAPI iterations
- Acquire/release memory ordering ensures cross-thread visibility
- Statistics tracked: `deferred_successes` and `deferred_failures`

**Fixed in:** `src/threading/worker.c` and `src/threading/dispatcher.c`

---

### High CPU Usage / 99% Active Polling (Fixed in v0.9.2)

**Symptoms:**
- CPU efficiency always shows "High load (99% active polling)"
- Workers consume CPU even when idle
- System load unnecessarily high during low traffic

**Root Cause:**
Worker threads use spin-wait polling loop instead of event-driven blocking. Workers continuously check queues and yield, burning CPU cycles.

**Resolution:**
Implemented NAPI-style adaptive polling:
- Workers use `epoll_wait()` when caught up with traffic (zero CPU when idle)
- Under heavy load, workers loop continuously without syscall overhead
- Budget-based processing: max 64 events per iteration before checking epoll
- Sleep cycles tracked for efficiency reporting

**Results:**
- CPU (idle): ~0% (vs 99% before)
- CPU (heavy load): 80-95% (actual work vs busy-wait)
- Statistics now show "Good (NAPI-style, N sleep cycles)" when efficient

**Fixed in:** `src/threading/worker.c` and `src/threading/threading.h`

---

## Reporting New Issues

When reporting issues, please include:

1. **spliff version**: `spliff --version`
2. **OS and kernel**: `uname -a`
3. **Steps to reproduce**: Minimal steps to trigger the issue
4. **Expected behavior**: What should happen
5. **Actual behavior**: What actually happens
6. **Debug output**: Run with `-d` flag and include relevant output
7. **Statistics**: Include shutdown statistics block

**Example report:**
```
Version: spliff 0.9.1
OS: Fedora 43, kernel 6.18.5
Steps: 1. Start spliff, 2. Connect to VPN, 3. curl https://example.com
Expected: XDP correlation info shown with HTTP output
Actual: No correlation info displayed
Debug: [paste -d output]
Stats: [paste shutdown statistics]
```

Submit issues at: https://github.com/NoFear0411/spliff/issues
