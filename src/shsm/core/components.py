"""Mapping of check IDs to score components, expected checks, and staleness windows.

This is the single source of truth used by scoring, coverage, and reporting.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

HEALTH = "health"
SECURITY = "security"

# component -> (score kind, weight, label)
COMPONENTS: Dict[str, Tuple[str, int, str]] = {
    "cpu_load": (HEALTH, 20, "CPU / load"),
    "ram_swap": (HEALTH, 20, "RAM / swap"),
    "disk_inodes": (HEALTH, 15, "Disk / inodes"),
    "services": (HEALTH, 20, "Service availability"),
    "databases": (HEALTH, 10, "MariaDB / Redis"),
    "websites": (HEALTH, 15, "Website availability"),
    "ssh_auth": (SECURITY, 15, "SSH / authentication"),
    "firewall_network": (SECURITY, 15, "Firewall / network"),
    "malware_integrity": (SECURITY, 25, "Malware / file integrity"),
    "wordpress": (SECURITY, 25, "WordPress security"),
    "system_integrity": (SECURITY, 10, "System integrity"),
    "vulnerability": (SECURITY, 10, "Vulnerability / patch status"),
}

# longest matching prefix wins; ``None`` means informational only (not scored)
PREFIX_COMPONENT: List[Tuple[str, Optional[str]]] = [
    ("cpu.", "cpu_load"),
    ("load.", "cpu_load"),
    ("memory.", "ram_swap"),
    ("swap.", "ram_swap"),
    ("disk.", "disk_inodes"),
    ("inode.", "disk_inodes"),
    ("logs.", "disk_inodes"),
    ("service.", "services"),
    ("systemd.failed", "services"),
    ("mariadb.", "databases"),
    ("redis.", "databases"),
    ("website.", "websites"),
    ("ssl.", "websites"),
    ("openlitespeed.", "websites"),
    ("ssh.", "ssh_auth"),
    ("firewall.", "firewall_network"),
    ("fail2ban.", "firewall_network"),
    ("network.errors", None),
    ("network.", "firewall_network"),
    ("malware.", "malware_integrity"),
    ("clamav.", "malware_integrity"),
    ("rootkit.", "malware_integrity"),
    ("integrity.", "malware_integrity"),
    ("wordpress.", "wordpress"),
    ("lynis.", "system_integrity"),
    ("process.", "system_integrity"),
    ("systemd.", "system_integrity"),
    ("vulnerability.", "vulnerability"),
    ("patch.", "vulnerability"),
    ("shsm.", None),
]

# Checks that must exist for a component to be fully covered. Missing => unknown (reduces coverage).
EXPECTED_CHECKS: Dict[str, List[str]] = {
    "cpu_load": ["cpu.usage", "cpu.load", "cpu.steal", "cpu.iowait"],
    "ram_swap": ["memory.available", "swap.usage", "memory.oom"],
    "disk_inodes": ["disk.usage", "inode.usage"],
    "services": ["systemd.failed"],  # service.<role> for required roles are appended dynamically
    "databases": ["mariadb.status", "redis.status"],
    "websites": ["website.http", "ssl.certificate", "openlitespeed.logs"],
    "ssh_auth": ["ssh.config", "ssh.auth_events"],
    "firewall_network": ["firewall.status", "firewall.ports", "fail2ban.status", "network.outbound"],
    "malware_integrity": ["malware.heuristic", "clamav.scan", "clamav.signatures", "rootkit.scan", "integrity.files"],
    "wordpress": ["wordpress.discovery", "wordpress.core", "wordpress.checksums", "wordpress.plugins",
                  "wordpress.users"],
    "system_integrity": ["lynis.audit", "process.privileged"],
    "vulnerability": ["vulnerability.lookup", "patch.apt"],
}

# seconds after which a check result is considered stale (=> unknown for coverage)
STALE_SECONDS: List[Tuple[str, int]] = [
    ("ssl.", 24 * 3600),
    ("wordpress.", 3 * 86400),
    ("vulnerability.", 3 * 86400),
    ("malware.", 3 * 86400),
    ("clamav.scan", 10 * 86400),  # full scans are weekly; quick scan refreshes the same check daily
    ("clamav.", 3 * 86400),
    ("rootkit.", 10 * 86400),
    ("lynis.", 10 * 86400),
    ("integrity.", 86400),
    ("patch.", 2 * 86400),
    ("firewall.", 7200),
    ("fail2ban.", 7200),
    ("ssh.config", 7200),
    ("ssh.", 3600),
    ("process.", 7200),
    ("mariadb.", 1800),
    ("redis.", 1800),
    ("", 1800),
]


def component_for(check_id: str) -> Optional[str]:
    best: Optional[Tuple[int, Optional[str]]] = None
    for prefix, comp in PREFIX_COMPONENT:
        if check_id.startswith(prefix) and (best is None or len(prefix) > best[0]):
            best = (len(prefix), comp)
    return best[1] if best else None


def stale_after(check_id: str) -> int:
    best = (-1, 1800)
    for prefix, seconds in STALE_SECONDS:
        if check_id.startswith(prefix) and len(prefix) > best[0]:
            best = (len(prefix), seconds)
    return best[1]
