"""Fail2Ban status, enabled jails, and ban statistics."""

from __future__ import annotations

from typing import Any, Dict, List

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.utils.redact import mask_ip

SOURCE = "fail2ban"
CATEGORY = "security"


def _run_with_sudo_fallback(ctx: Context, cmd: List[str], timeout: float = 10) -> Any:
    res = ctx.runner.run(cmd, timeout=timeout)
    if res.ok:
        return res
    if ctx.runner.which("sudo"):
        res_sudo = ctx.runner.run(["sudo"] + cmd, timeout=timeout)
        if res_sudo.ok:
            return res_sudo
    return res


def query_jail_status(ctx: Context, client_bin: str, jail: str) -> Dict[str, Any]:
    res = _run_with_sudo_fallback(ctx, [client_bin, "status", jail], timeout=10)
    if not res.ok:
        return {"jail": jail, "ok": False, "currently_banned": 0, "total_banned": 0, "banned_ips": []}

    curr_banned = 0
    total_banned = 0
    banned_ips: List[str] = []

    for line in res.stdout.splitlines():
        if "Currently banned:" in line:
            parts = line.split(":")
            if len(parts) == 2 and parts[1].strip().isdigit():
                curr_banned = int(parts[1].strip())
        elif "Total banned:" in line:
            parts = line.split(":")
            if len(parts) == 2 and parts[1].strip().isdigit():
                total_banned = int(parts[1].strip())
        elif "Banned IP list:" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ips = parts[1].strip().split()
                banned_ips = [mask_ip(ip) for ip in ips]

    return {
        "jail": jail,
        "ok": True,
        "currently_banned": curr_banned,
        "total_banned": total_banned,
        "banned_ips": banned_ips,
    }


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()

    client_bin = ctx.runner.which("fail2ban-client")
    if not client_bin:
        out.check("fail2ban.status", CATEGORY, CheckStatus.NOT_APPLICABLE, "fail2ban-client not installed", source=SOURCE)
        return out

    out.scope("fail2ban.status")

    res = _run_with_sudo_fallback(ctx, [client_bin, "status"], timeout=10)
    if not res.ok:
        # Check if service is actually active via systemctl
        svc_res = ctx.runner.run(["systemctl", "is-active", "fail2ban"], timeout=5)
        is_svc_active = svc_res.ok and svc_res.stdout.strip() == "active"
        if is_svc_active:
            out.check(
                "fail2ban.status",
                CATEGORY,
                CheckStatus.WARNING,
                "Fail2Ban service is active but socket communication failed (check sudoers / socket permissions)",
                source=SOURCE,
            )
        else:
            out.check(
                "fail2ban.status",
                CATEGORY,
                CheckStatus.WARNING,
                f"Fail2Ban service not running or socket error: {res.stderr[:100]}",
                source=SOURCE,
            )
            out.finding(
                "fail2ban.status",
                CATEGORY,
                Severity.MEDIUM,
                Confidence.CONFIRMED,
                "Fail2Ban is installed but not currently active",
                f"fail2ban-client status failed: {res.describe()}.",
                "Check fail2ban service (systemctl status fail2ban) and verify configuration in /etc/fail2ban/.",
                source=SOURCE,
                key="fail2ban_inactive",
            )
        return out

    jails: List[str] = []
    for line in res.stdout.splitlines():
        if "Jail list:" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                jails = [j.strip() for j in parts[1].split(",") if j.strip()]

    out.metric("fail2ban.jail_count", len(jails))

    if not jails:
        out.check("fail2ban.status", CATEGORY, CheckStatus.WARNING, "Fail2Ban is running but has no active jails", source=SOURCE)
        out.finding(
            "fail2ban.jails",
            CATEGORY,
            Severity.LOW,
            Confidence.HIGH,
            "Fail2Ban has 0 active jails configured",
            "Fail2Ban daemon is running, but no active jail was found in the jail list.",
            "Enable relevant jails in /etc/fail2ban/jail.local (e.g. [sshd], [openlitespeed]).",
            source=SOURCE,
        )
        return out

    total_curr_banned = 0
    total_lifetime_banned = 0
    jail_summaries = []

    for j in jails:
        st = query_jail_status(ctx, client_bin, j)
        total_curr_banned += st["currently_banned"]
        total_lifetime_banned += st["total_banned"]
        jail_summaries.append(f"{j}: {st['currently_banned']} banned")

    out.metric("fail2ban.currently_banned", total_curr_banned)
    out.metric("fail2ban.total_banned", total_lifetime_banned)

    summary_str = f"Active jails ({len(jails)}): {', '.join(jail_summaries)}"
    out.check("fail2ban.status", CATEGORY, CheckStatus.PASS, summary_str, source=SOURCE)

    return out
