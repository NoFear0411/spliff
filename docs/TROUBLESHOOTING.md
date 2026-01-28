# spliff Troubleshooting

> Back to [README](../README.md)

Common issues and solutions for running spliff.

## "Operation not permitted"
```bash
# spliff requires root for eBPF
sudo ./spliff
```

## "Failed to load BPF program"
```bash
# Check BTF support
ls /sys/kernel/btf/vmlinux

# If missing, your kernel may not support BTF
# Rebuild kernel with CONFIG_DEBUG_INFO_BTF=y
```

## No traffic captured
```bash
# Check if SSL libraries are found
sudo ./spliff --show-libs

# Try debug mode to see raw events
sudo ./spliff -d
```

## No XDP correlation (missing IP addresses in output)
```bash
# Check XDP attachment status at startup
sudo ./spliff -d 2>&1 | grep -i xdp

# XDP requires CAP_NET_ADMIN - ensure running as root
# Some drivers don't support XDP native mode, but SKB fallback should work
# If XDP fails completely, traffic still works but without IP:port correlation
```

## Firefox shows no traffic
```bash
# Firefox uses multiple processes - use process name filter
sudo ./spliff --comm firefox
```

## High memory usage
```bash
# Flow pool allocates dynamically via jemalloc (~37KB per active flow)
# Check pool stats at shutdown (shown automatically)
# Active/peak flow count and allocation failures reported in Session Statistics
sudo ./spliff -d 2>&1 | grep -i pool
```
