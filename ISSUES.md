# Known Issues

This document tracks known issues, bugs, and limitations in spliff. For feature requests and discussion, see [GitHub Issues](https://github.com/NoFear0411/spliff/issues).

## Open Issues

### 1. SSL-sockops Timing Race (High Priority)

**Symptoms:**
- First HTTP request from each process lacks XDP correlation
- Under high load, ~50% of request/response pairs miss correlation
- Statistics show "Cookie misses" incrementing

**Root Cause:**
Race condition between SSL uprobe events and sockops `flow_cookie_map` population. The SSL_read/SSL_write uprobe fires before sockops has cached the socket cookie in `flow_cookie_map`.

**Affected Components:**
- `src/bpf/spliff.bpf.c` - sockops handler timing
- `src/threading/dispatcher.c` - cookie lookup in SSL event handler

**Potential Fixes:**
- Implement retry with backoff for cookie lookup
- Queue SSL events and process after cookie is available
- Add synchronization barrier between sockops and uprobe

**Workaround:** None currently. Subsequent requests typically correlate correctly.

---

### 2. VPN (Wireguard) Correlation Failure (High Priority)

**Symptoms:**
- XDP correlation stops working when VPN is connected
- Traffic through wg0 interface not correlated
- Works again after VPN disconnect

**Root Cause:**
Two-part issue:
1. **Static attachment**: XDP programs attached only at startup. If wg0 interface appears after spliff starts, no XDP attached to it.
2. **Tunnel IP mismatch**: sockops sees tunnel IPs (10.x.x.x), but XDP on physical NIC sees encrypted wireguard UDP packets with different 5-tuple.

**Affected Components:**
- `src/bpf/bpf_loader.c` - static interface discovery
- `src/bpf/spliff.bpf.c` - XDP flow tracking

**Potential Fixes:**
- Implement dynamic NIC monitoring via netlink (RTM_NEWLINK/RTM_DELLINK)
- Attach XDP to tunnel interfaces (wg0) not just physical NICs
- Handle tunnel IP to socket cookie mapping

**Workaround:** Start spliff after VPN is connected so wg0 is discovered at startup.

---

### 3. High CPU Usage (99% Active Polling) (Medium Priority)

**Symptoms:**
- CPU efficiency always shows "High load (99% active polling)"
- Workers consume CPU even when idle
- System load unnecessarily high during low traffic

**Root Cause:**
Worker threads use spin-wait polling loop instead of event-driven blocking. Workers continuously check queues and yield, burning CPU cycles.

**Affected Components:**
- `src/threading/worker.c` - worker main loop
- `src/threading/dispatcher.c` - event dispatch loop

**Potential Fixes:**
- Replace spin-wait with `epoll_wait()` on eventfd
- Use ring buffer poll mechanism for BPF events
- Implement proper condition variable signaling

**Workaround:** None. Impact is higher power consumption and CPU contention.

---

### 4. Static NIC Attachment (Medium Priority)

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

## Resolved Issues

*No resolved issues yet in this tracking document.*

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
