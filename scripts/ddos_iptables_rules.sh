#!/usr/bin/env bash
# ==============================================================================
# Linux Kernel & Firewall Tier-1 DDoS Hardening Script for CyberPanel / OLS
# ==============================================================================
# Applies kernel-level per-IP SYN/connection limits, invalid packet drops,
# and O(1) ipset blacklist hooks. Exceeding packets are dropped DIRECTLY at
# the kernel network layer (0% OpenLiteSpeed / PHP / MariaDB CPU).
# ==============================================================================

set -euo pipefail

echo "==> [1/4] Applying Linux Kernel Anti-DDoS sysctl parameters..."

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

sysctl -p /etc/sysctl.d/99-shsm-ddos.conf > /dev/null 2>&1 || true

echo "==> [2/4] Initializing O(1) ipset blacklist (if ipset is available)..."

# Determine safe insertion index in INPUT chain: if CSF ALLOWIN exists, insert AFTER it
# so csf.allow whitelisted IPs are NEVER blocked by ipset/hashlimit/connlimit.
_insert_pos_after_allowin() {
    local tool="$1"
    local allow_line
    allow_line=$("$tool" -L INPUT --line-numbers -n 2>/dev/null | awk '$2 == "ALLOWIN" {print $1; exit}')
    if [ -n "$allow_line" ]; then
        echo $((allow_line + 1))
    else
        echo 1
    fi
}

if command -v ipset > /dev/null 2>&1; then
    ipset create shsm_blacklist hash:ip family inet timeout 3600 -exist
    ipset create shsm_blacklist_v6 hash:ip family inet6 timeout 3600 -exist
    if command -v iptables > /dev/null 2>&1; then
        POS=$(_insert_pos_after_allowin iptables)
        iptables -C INPUT -m set --match-set shsm_blacklist src -j DROP 2>/dev/null || \
        iptables -I INPUT "$POS" -m set --match-set shsm_blacklist src -j DROP
    fi
    if command -v ip6tables > /dev/null 2>&1; then
        POS6=$(_insert_pos_after_allowin ip6tables)
        ip6tables -C INPUT -m set --match-set shsm_blacklist_v6 src -j DROP 2>/dev/null || \
        ip6tables -I INPUT "$POS6" -m set --match-set shsm_blacklist_v6 src -j DROP
    fi
    echo "    ipset O(1) blacklist hooks active."
fi

echo "==> [3/4] Configuring iptables Layer-4 per-IP Rate-Limiting rules..."

if command -v iptables > /dev/null 2>&1; then
    POS=$(_insert_pos_after_allowin iptables)
    # Insert after CSF ALLOWIN (or at top of INPUT on UFW/Firewalld) so whitelisted admin IPs always pass
    # 1. Drop malformed/INVALID packets immediately
    iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
    iptables -I INPUT "$POS" -m conntrack --ctstate INVALID -j DROP

    # 2. Per-IP SYN Flood protection (only drops IPs exceeding 30 SYN/s burst 60, never global users)
    iptables -C INPUT -p tcp --syn -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name shsm_syn -j DROP 2>/dev/null || \
    iptables -I INPUT "$POS" -p tcp --syn -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name shsm_syn -j DROP

    # 3. Limit concurrent connections per IP on HTTP/HTTPS to prevent socket exhaustion
    iptables -C INPUT -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset 2>/dev/null || \
    iptables -I INPUT "$POS" -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

    echo "    iptables per-IP rate-limiting rules applied successfully."
    if command -v netfilter-persistent > /dev/null 2>&1; then
        netfilter-persistent save > /dev/null 2>&1 || true
    elif command -v iptables-save > /dev/null 2>&1 && [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
else
    echo "    iptables not found; skipping direct rule insertion."
fi

echo "==> [4/4] DDoS Kernel & Firewall tier-1 hardening complete!"
