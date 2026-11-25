"""Firewall status and public listening ports audit."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.core.subprocesses import Runner

SOURCE = "firewall_audit"
CATEGORY = "security"

_FW_DETECT_CACHE: Dict[str, Tuple[float, Tuple[str, bool, str]]] = {}
_FW_CACHE_TTL_SECONDS = 30.0


def find_firewall_binary(ctx: Context, name: str, extra_paths: Tuple[str, ...] = ()) -> Optional[str]:
    """Locate firewall binary, falling back to root-owned sbin paths when running via sudo."""
    found = ctx.runner.which(name)
    if found:
        return found
    for p in extra_paths:
        found_p = ctx.runner.which(p)
        if found_p:
            return found_p
    # Root-owned binaries (e.g. /usr/sbin/csf mode 0700) fail os.access(X_OK) for non-root user 'shsm'
    # even though 'sudo -n /usr/sbin/csf ...' is allowed via sudoers.
    if type(ctx.runner) is Runner:
        search_paths = extra_paths or (
            f"/usr/sbin/{name}",
            f"/sbin/{name}",
            f"/usr/local/sbin/{name}",
            f"/usr/bin/{name}",
        )
        for p in search_paths:
            if os.path.isfile(p):
                return p
    return None


def _exec_firewall_cmd(ctx: Context, cmd: List[str], timeout: float = 10) -> Any:
    """Execute command, with fallback to sudo if unprivileged."""
    res = ctx.runner.run(cmd, timeout=timeout)
    if res.ok:
        return res
    sudo_bin = ctx.runner.which("sudo")
    if sudo_bin:
        res_sudo = ctx.runner.run([sudo_bin, "-n"] + cmd, timeout=timeout)
        if res_sudo.ok:
            return res_sudo
    return res


def detect_active_firewall(ctx: Context) -> Tuple[str, bool, str]:
    """Check configured or auto-detected firewall: CSF, Firewalld, UFW, iptables, nftables, or custom."""
    backend = str(ctx.config.get("security.firewall_backend", "auto")).lower()
    use_cache = type(ctx.runner) is Runner and backend != "custom"
    if use_cache:
        cached = _FW_DETECT_CACHE.get(backend)
        if cached and (time.monotonic() - cached[0]) < _FW_CACHE_TTL_SECONDS:
            return cached[1]

    def _ret(res: Tuple[str, bool, str]) -> Tuple[str, bool, str]:
        if use_cache:
            _FW_DETECT_CACHE[backend] = (time.monotonic(), res)
        return res

    # 1. Custom command check if explicitly configured
    if backend == "custom":
        custom_cmd = ctx.config.get("security.firewall_custom_cmd", [])
        if isinstance(custom_cmd, list) and custom_cmd:
            res = _exec_firewall_cmd(ctx, custom_cmd, timeout=10)
            if res.ok:
                return "custom", True, f"Custom firewall command '{custom_cmd[0]}' succeeded"
            return "custom", False, f"Custom firewall command '{custom_cmd[0]}' failed: {res.stderr or res.message}"
        return "custom", False, "Custom firewall backend selected but no security.firewall_custom_cmd defined"

    # 2. CSF (ConfigServer Security & Firewall) - very popular on CyberPanel
    csf_bin = find_firewall_binary(ctx, "csf", ("/usr/sbin/csf", "/usr/local/sbin/csf", "/sbin/csf"))
    if backend in ("auto", "csf") and csf_bin:
        res = _exec_firewall_cmd(ctx, [csf_bin, "-l"], timeout=10)
        if res.ok and ("Chain" in res.stdout or "csf" in res.stdout.lower()):
            return _ret(("csf", True, "CSF (ConfigServer Security & Firewall) is active"))

    # 3. Firewalld (firewall-cmd)
    fwd_bin = find_firewall_binary(ctx, "firewall-cmd", ("/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd"))
    if backend in ("auto", "firewalld") and fwd_bin:
        res = _exec_firewall_cmd(ctx, [fwd_bin, "--state"], timeout=10)
        if res.ok and "running" in res.stdout.lower():
            return _ret(("firewalld", True, "Firewalld is running and active"))

    # 4. UFW (Uncomplicated Firewall)
    ufw_bin = find_firewall_binary(ctx, "ufw", ("/usr/sbin/ufw", "/usr/bin/ufw"))
    if backend in ("auto", "ufw") and ufw_bin:
        res = _exec_firewall_cmd(ctx, [ufw_bin, "status"], timeout=10)
        if res.ok:
            if "status: active" in res.stdout.lower():
                return _ret(("ufw", True, "UFW firewall is active"))
            elif "status: inactive" in res.stdout.lower() and backend == "ufw":
                return _ret(("ufw", False, "UFW is installed but inactive"))

    # 5. nftables
    nft_bin = find_firewall_binary(ctx, "nft", ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"))
    if backend in ("auto", "nftables") and nft_bin:
        res = _exec_firewall_cmd(ctx, [nft_bin, "list", "ruleset"], timeout=10)
        if res.ok and len(res.stdout.strip()) > 20:
            return _ret(("nftables", True, "nftables ruleset is active"))

    # 6. iptables / iptables-legacy
    ipt = find_firewall_binary(ctx, "iptables", ("/sbin/iptables", "/usr/sbin/iptables", "/usr/bin/iptables"))
    if backend in ("auto", "iptables") and ipt:
        res = _exec_firewall_cmd(ctx, [ipt, "-L", "-n"], timeout=10)
        if res.ok and "Chain" in res.stdout:
            lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip() and not ln.startswith("Chain") and not ln.startswith("target")]
            return _ret(("iptables", True, f"iptables is active ({len(lines)} rules configured)"))

    # 7. Fallback to active systemd units
    for unit_name, fw_label in [
        ("lfd.service", "csf"),
        ("csf.service", "csf"),
        ("firewalld.service", "firewalld"),
        ("ufw.service", "ufw"),
        ("nftables.service", "nftables"),
        ("netfilter-persistent.service", "iptables"),
        ("iptables.service", "iptables"),
    ]:
        if backend in ("auto", fw_label):
            res = ctx.runner.run(["systemctl", "is-active", unit_name], timeout=5)
            if res.ok and res.stdout.strip() == "active":
                return _ret((fw_label, True, f"{unit_name} is active in systemd"))

    if backend != "auto" and backend != "none":
        return _ret((backend, False, f"Configured firewall backend '{backend}' is not active or not installed"))

    return _ret(("none", False, "No active firewall service detected (checked CSF, Firewalld, UFW, iptables, nftables)"))


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
        # Exclude FTP daemons that link to mysql (e.g. pure-ftpd-mysql) and port 21
        if "pure-ftpd" in proc or "ftpd" in proc or port in (20, 21):
            continue

        # Check MariaDB (3306 or actual mysqld processes) and Redis (6379 or redis-server)
        is_mariadb = port == 3306 or any(m in proc for m in ("mysqld", "mariadbd"))
        is_redis = port == 6379 or "redis-server" in proc

        if is_mariadb:
            flagged_dbs.append((port, p["process"], "MariaDB"))
        elif is_redis:
            flagged_dbs.append((port, p["process"], "Redis"))

    out.scope("firewall.public_db")

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
