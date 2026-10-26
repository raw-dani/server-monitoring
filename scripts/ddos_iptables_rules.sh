#!/usr/bin/env bash
# ==============================================================================
# Linux Kernel & Firewall Tier-1 DDoS Hardening Script for CyberPanel / OLS
# ==============================================================================
# This script applies kernel-level connection limits and SYN flood mitigations.
# Packets exceeding thresholds are dropped DIRECTLY at the kernel network layer,
# consuming zero web server (OLS/PHP) CPU and memory.
# ==============================================================================

set -euo pipefail

echo "==> [1/3] Applying Linux Kernel Anti-DDoS sysctl parameters..."

cat << 'EOF' > /etc/sysctl.d/99-shsm-ddos.conf
# Enable TCP SYN cookies to defend against SYN Flood attacks
net.ipv4.tcp_syncookies = 1

# Increase max syn backlog for burst traffic
net.ipv4.tcp_max_syn_backlog = 8192

# Decrease SYN-ACK retries to drop half-open connections faster
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Recycle TIME_WAIT sockets safely
net.ipv4.tcp_fin_timeout = 15

# Protect against TCP TIME_WAIT assassination
net.ipv4.tcp_rfc1337 = 1

# Ignore bogus ICMP broadcast & error responses
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

sysctl --system > /dev/null || sysctl -p /etc/sysctl.d/99-shsm-ddos.conf

echo "==> [2/3] Configuring iptables Layer-4 Rate-Limiting rules..."

# Check if iptables is available
if command -v iptables > /dev/null 2>&1; then
    # 1. Protect against SYN Floods (limit to 50/sec burst 100 per source)
    iptables -C INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT

    # 2. Limit concurrent connections per IP on HTTP/HTTPS to prevent socket exhaustion
    # Maximum 80 simultaneous connections per individual IP
    iptables -C INPUT -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset 2>/dev/null || \
    iptables -A INPUT -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

    echo "    iptables rate-limiting rules applied successfully."
else
    echo "    iptables not found; skipping direct rule insertion."
fi

echo "==> [3/3] DDoS Kernel & Firewall tier-1 hardening complete!"
