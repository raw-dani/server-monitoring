"""Firewall status and public listening ports audit."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import psutil

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "firewall_audit"
CATEGORY = "security"


def detect_active_firewall(ctx: Context) -> Tuple[str, bool, str]:
    """Check UFW, CSF, Firewalld, or iptables/nftables."""
    # 1. UFW
    if ctx.runner.which("ufw"):
        res = ctx.runner.run(["ufw", "status"], timeout=10)
        if res.ok:
            if "status: active" in res.stdout.lower():
                return "ufw", True, "UFW is active"
            elif "status: inactive" in res.stdout.lower():
                return "ufw", False, "UFW is installed but inactive"

    # 2. CSF
    if ctx.runner.which("csf"):
        res = ctx.runner.run(["csf", "-l"], timeout=10)
        if res.ok:
            return "csf", True, "CSF firewall is active"

    # 3. Firewalld
    if ctx.runner.which("firewall-cmd"):
        res = ctx.runner.run(["firewall-cmd", "--state"], timeout=10)
        if res.ok and "running" in res.stdout.lower():
            return "firewalld", True, "Firewalld is running"

    # 4. iptables / nftables fallback check
    if ctx.runner.which("nft"):
        res = ctx.runner.run(["nft", "list", "ruleset"], timeout=10)
        if res.ok and len(res.stdout.strip()) > 20:
            return "nftables", True, "nftables rules active"

    if ctx.runner.which("iptables"):
        res = ctx.runner.run(["iptables", "-L", "-n"], timeout=10)
        if res.ok and "Chain" in res.stdout:
            return "iptables", True, "iptables rules active"

    return "none", False, "No active firewall service detected"


def _is_public_ip(ip: str) -> bool:
    if ip in ("0.0.0.0", "::", "*"):
        return True
    if ip.startswith(("127.", "::1", "10.", "192.168.")):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    return True


def collect_listening_ports() -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return ports

    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr:
            ip = c.laddr.ip if hasattr(c.laddr, "ip") else str(c.laddr[0])
            port = c.laddr.port if hasattr(c.laddr, "port") else int(c.laddr[1])
            pid = c.pid
            pname = ""
            if pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = "unknown"

            ports.append({
                "ip": ip,
                "port": port,
                "is_public": _is_public_ip(ip),
                "pid": pid,
                "process": pname,
            })
    return ports


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()

    # 1. Active firewall detection
    fw_name, fw_active, fw_desc = detect_active_firewall(ctx)
    out.metric("firewall.active", 1.0 if fw_active else 0.0)

    if not fw_active:
        out.check(
            "firewall.status",
            CATEGORY,
            CheckStatus.WARNING,
            fw_desc,
            source=SOURCE,
        )
        out.finding(
            "firewall.status",
            CATEGORY,
            Severity.HIGH,
            Confidence.HIGH,
            "No host firewall is currently active",
            f"Firewall state check returned: {fw_desc}. Host ports may be exposed directly.",
            "Enable and configure a firewall such as UFW ('ufw enable') or CyberPanel CSF integration.",
            source=SOURCE,
            key="firewall_inactive",
        )
    else:
        out.check(
            "firewall.status",
            CATEGORY,
            CheckStatus.PASS,
            f"Active firewall: {fw_name} ({fw_desc})",
            source=SOURCE,
        )

    # 2. Public listening ports audit
    listening = collect_listening_ports()
    public_ports = [p for p in listening if p["is_public"]]

    exceptions = {
        item.get("port")
        for item in ctx.config.get("security.documented_exceptions", [])
        if item.get("check") == "firewall.public_db"
    }

    flagged_dbs = []
    for p in public_ports:
        port = p["port"]
        proc = p["process"].lower()
        if port in exceptions:
            continue
        # Check MariaDB (3306) and Redis (6379)
        if port == 3306 or "mysql" in proc or "mariadb" in proc:
            flagged_dbs.append((port, p["process"], "MariaDB"))
        elif port == 6379 or "redis" in proc:
            flagged_dbs.append((port, p["process"], "Redis"))

    if flagged_dbs:
        for port, proc, name in flagged_dbs:
            out.finding(
                "firewall.public_db",
                CATEGORY,
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"{name} database port {port} is publicly exposed",
                f"Process {proc} is listening on public interface on port {port}. This allows direct external brute force.",
                f"Bind {name} to 127.0.0.1 or block port {port} in firewall rules unless external access is strictly required.",
                asset=f"{name}:{port}",
                source=SOURCE,
                key=f"public_db:{port}",
            )
        out.check(
            "firewall.ports",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"Detected {len(flagged_dbs)} database service(s) exposed to public interfaces",
            source=SOURCE,
        )
    else:
        out.check(
            "firewall.ports",
            CATEGORY,
            CheckStatus.PASS,
            f"{len(public_ports)} public listening port(s) detected; database ports are protected",
            source=SOURCE,
        )

    return out
