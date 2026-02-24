# spliff Troubleshooting

> Back to [README](../README.md) | See also [ISSUES.md](../ISSUES.md) for known issues and limitations

Common issues and solutions for running spliff v0.10.0.

---

## Runtime Issues

### "Operation not permitted"
```bash
# spliff requires root for eBPF attachment (uprobes, XDP, sock_ops)
sudo ./spliff
```

### "Failed to load BPF program"
```bash
# Check BTF support (required for CO-RE)
ls /sys/kernel/btf/vmlinux

# If missing, your kernel doesn't support BTF
# Requires CONFIG_DEBUG_INFO_BTF=y (Linux 5.x+)
# Most distros since 2021 ship BTF-enabled kernels:
#   Fedora 31+, Ubuntu 21.10+, RHEL 9+, Debian 12+

# Check kernel version
uname -r
```

### No traffic captured
```bash
# 1. Check if SSL libraries are detected
sudo ./spliff --show-libs

# 2. Try debug mode to see raw BPF events
sudo ./spliff -d

# 3. Ensure target process uses a supported SSL library:
#    OpenSSL, GnuTLS, NSS/NSPR, WolfSSL, BoringSSL (experimental)
# Static-linked binaries won't be detected by uprobe discovery

# 4. Check if traffic is TLS-encrypted
#    spliff currently captures TLS traffic only (plain HTTP: Phase 4, v0.11.0)
#    Plaintext flow support (FLOW_FLAG_PLAINTEXT) is in place but not wired to capture yet
```

### No XDP correlation (missing IP addresses)
```bash
# Check XDP attachment status at startup
sudo ./spliff -d 2>&1 | grep -i xdp

# XDP requires CAP_NET_ADMIN — ensure running as root
# Some drivers don't support XDP native mode; spliff falls back to SKB mode
# If XDP fails completely, SSL traffic still works but without IP:port metadata
```

**VPN/WireGuard:** XDP correlation fails when traffic routes through VPN tunnels.
This is a fundamental XDP limitation — tunnel-decapsulated packets bypass the XDP hook.
See [ISSUES.md](../ISSUES.md) §1 for details. Workaround: disconnect VPN for full
correlation; SSL interception still works over VPN.

### Firefox shows no traffic
```bash
# Firefox uses multiple processes — use process name filter
sudo ./spliff --comm firefox

# If using Snap/Flatpak Firefox, the process may have a different name
# Check: ps aux | grep firefox
```

### Chrome/Chromium shows no traffic
Chrome uses statically-linked BoringSSL, which requires heuristic binary scanning
to find function offsets. This is **experimental** and may fail silently.

```bash
# Check if BoringSSL offsets were found
sudo ./spliff -d 2>&1 | grep -i boring

# Offsets vary between browser versions, builds, and distributions
# Recommended: Use Firefox (NSS) for reliable browser traffic capture
```

### HTTP/2 garbled output on existing connections
Joining an already-established HTTP/2 connection mid-stream can cause HPACK
dynamic table desync. The first few responses may show corrupted headers.

This is expected behavior — spliff sets the `hpack_corrupted` flag per RFC 7540
and automatically recovers. Subsequent requests on the same connection will
decode correctly.

### Single checkmark instead of double (`[XDP:?] ✓` vs `[XDP:TLS] ✓✓`)
XDP classification requires seeing a data packet with a TLS record header or
HTTP signature. The initial SYN/SYN-ACK has no payload, so the first event
may show `[XDP:?]` with a single checkmark. This is by design:
- `✓✓` = App-layer confirmed + XDP classified
- `✓` = App-layer confirmed, XDP classification pending

---

## Memory and Performance

### High memory usage
```bash
# Flow pool allocates ~37KB per active flow via jemalloc (cache-line aligned)
# Check pool stats at shutdown (printed automatically)
sudo ./spliff -d 2>&1 | grep -i pool

# Shutdown statistics show:
#   Active/peak flow counts
#   Allocation successes/failures
#   Index hit rates (cookie_index, shadow_index)
```

### High CPU usage
```bash
# Check shutdown statistics for CPU efficiency
# "Good (NAPI-style, N sleep cycles)" = healthy
# "High load (99% active polling)" = workers not sleeping (shouldn't happen in v0.9.2+)

# Per-worker stats show event counts and retry statistics
# If workers are unbalanced, connection affinity hash may be skewed
```

### Decompression bomb rejected
Streaming decompression (v0.10.0) includes bomb protection:
- Ratio limit: >1000:1 compression ratio triggers permanent reject
- Size limit: >100MB decompressed output triggers permanent reject
- Once rejected, the flow's decompressor is permanently disabled

This protects against malicious payloads. If legitimate traffic triggers this,
the limits are compile-time constants in `src/content/stream_decompressor.h`.

---

## Build Issues

### Dependencies not found
```bash
# Install all required dependencies (Fedora/RHEL)
sudo dnf install -y \
    clang llvm libbpf-devel libelf-devel bpftool \
    zlib-ng-compat-devel libzstd-devel brotli-devel \
    llhttp-devel libnghttp2-devel \
    ck-devel libxdp-devel liburcu-devel \
    jemalloc-devel pcre2-devel \
    cmake ninja-build

# For vectorscan (optional, USE_VECTORSCAN=ON)
sudo dnf install -y vectorscan-devel
# Or build from source if not packaged
```

### Build fails on AlmaLinux 9 / RHEL 9
GCC 11 (the default on these platforms) doesn't support some C23 features.
The build should work as of v0.10.0 — if you see `static_assert` errors,
ensure you're using the latest code.

```bash
# Verify GCC version
gcc --version

# GCC 11 works with v0.10.0+ (C23 single-arg static_assert was fixed)
# For best C23 support, GCC 13+ is recommended
```

### mimalloc build fails
```bash
# Prior to v0.10.0, test targets hardcoded jemalloc and broke mimalloc builds
# Fixed in v0.10.0 — ensure you're on the latest version
cmake -B build-debug -DUSE_MIMALLOC=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

### Build commands
```bash
# Always use the Makefile wrapper (auto-detects Ninja for faster builds)
make debug          # Debug with sanitizers
make release        # Optimized, stripped
make tests          # Build + run all 17 test suites

# Module-level test targets (build + run only that group)
make test-ring      # Ring transport (5 suites)
make test-protocol  # Protocol parsers (4 suites)
make test-flow      # Flow context (2 suites)
make test-content   # Decompression (2 suites)
make test-memory    # Memory infra (1 suite)
make test-util      # Utilities (3 suites)

# Do NOT use raw cmake commands — the Makefile handles build directories,
# Ninja detection, and parallel job configuration
```

---

## Debugging

### Enable debug output
```bash
# -d flag enables verbose debug logging
sudo ./spliff -d

# Key things to look for in debug output:
#   "Attached uprobe to ..." — SSL library discovery
#   "XDP attached to ..." — network interface attachment
#   "flow_get_or_create" — flow correlation activity
#   "cookie_retry" — deferred cookie lookup attempts
```

### Reading shutdown statistics
spliff prints comprehensive session statistics on shutdown (Ctrl+C). Key sections:

- **Event Counts:** Total SSL/XDP events processed per worker
- **Flow Pool:** Active/peak flows, allocation stats, index hit rates
- **XDP Classification:** Packets, flows, correlation success rate
- **SSL Probes:** Total SSL_read/SSL_write interceptions by library
- **CPU Efficiency:** NAPI sleep cycles, active polling percentage

### Running with sanitizers
```bash
# Debug builds include AddressSanitizer + UBSan by default
make debug
sudo ./build-debug/spliff -d

# If ASan reports errors, include the full output when filing issues
# ASan output starts with "ERROR: AddressSanitizer:"
```

---

## Reporting Issues

When reporting issues, include:

1. **spliff version:** `spliff --version`
2. **OS and kernel:** `uname -a`
3. **Steps to reproduce:** Minimal steps to trigger the issue
4. **Expected vs actual behavior**
5. **Debug output:** Run with `-d` flag and include relevant output
6. **Shutdown statistics:** Include the full statistics block

Submit issues at: https://github.com/NoFear0411/spliff/issues

---

*Last updated: v0.10.0 (February 2026)*
