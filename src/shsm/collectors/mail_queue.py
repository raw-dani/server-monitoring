"""Mail queue monitoring and outbound direct-to-MX spam connection detector.

Designed for CyberPanel/Ubuntu with zero performance impact:
- Fast directory file count on Postfix queue spool (falls back to lightweight mailq command).
- Audits outbound direct SMTP connections (ports 25, 465, 587) from non-MTA processes (PHP, shells, etc.).
- Identifies top spam sender envelopes if queue is swollen.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

import psutil

from shsm.collectors.base import threshold_result
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "mail_queue"
CATEGORY = "health"

# Standard postfix spool queues
POSTFIX_SPOOL = "/var/spool/postfix"
QUEUE_DIRS = ["incoming", "active", "deferred", "hold"]

# Standard MTA and monitor process names allowed to establish outbound port 25/465/587 connections
ALLOWED_MTA_PROCESSES = {
    "master",
    "qmgr",
    "smtp",
    "pickup",
    "cleanup",
    "trivial-rewrite",
    "exim",
    "exim4",
    "sendmail",
    "dovecot",
    "shsm",
}


def _count_dir_files(path: str, max_count: int = 50000) -> int:
    """Fast directory file counter without deep stats."""
    if not os.path.isdir(path):
        return 0
    count = 0
    try:
        # Postfix deferred/active queues are 1-level or 2-level hashed (e.g., active/0/ABC)
        for root, dirs, files in os.walk(path):
            count += len(files)
            if count >= max_count:
                return max_count
    except (PermissionError, FileNotFoundError):
        pass
    return count


def get_postfix_queue_counts(ctx: Context) -> Tuple[int, Dict[str, int], str]:
    """Retrieve mail queue counts by spool directory inspect or mailq."""
    breakdown: Dict[str, int] = {}
    total = 0

    if os.path.isdir(POSTFIX_SPOOL) and os.access(POSTFIX_SPOOL, os.R_OK):
        # Ultra fast path: count directly from spool filesystem
        for q in QUEUE_DIRS:
            cnt = _count_dir_files(os.path.join(POSTFIX_SPOOL, q))
            breakdown[q] = cnt
            total += cnt
        return total, breakdown, "spool"

    # Fallback to mailq / postqueue -p
    mailq_bin = ctx.runner.which("postqueue") or ctx.runner.which("mailq")
    if mailq_bin:
        cmd = [mailq_bin, "-p"] if "postqueue" in mailq_bin else [mailq_bin]
        res = ctx.runner.run(cmd, timeout=5)
        if res.ok:
            # Mail queue is empty: 'Mail queue is empty'
            if "Mail queue is empty" in res.stdout:
                return 0, {}, "mailq"
            # Parse total requests, usually last line: '-- 12 Kbytes in 15 Requests.'
            lines = res.stdout.strip().splitlines()
            for line in reversed(lines):
                if "Requests" in line or "Request." in line:
                    parts = line.split()
                    for idx, p in enumerate(parts):
                        if "Request" in p and idx > 0 and parts[idx - 1].isdigit():
                            total = int(parts[idx - 1])
                            return total, {"total": total}, "mailq"
            # If line not matched, count lines starting with queue id (hexadecimal ~10-12 chars)
            queue_ids = [l for l in lines if l and l[0].isalnum() and not l.startswith("-")]
            return len(queue_ids), {"total": len(queue_ids)}, "mailq"

    return 0, {}, "none"


def get_top_queue_senders(ctx: Context, limit: int = 5) -> List[Tuple[str, int]]:
    """Inspect top sender envelopes from mailq when queue is backed up."""
    mailq_bin = ctx.runner.which("mailq") or ctx.runner.which("postqueue")
    if not mailq_bin:
        return []

    cmd = [mailq_bin] if "mailq" in mailq_bin else [mailq_bin, "-p"]
    res = ctx.runner.run(cmd, timeout=8)
    if not res.ok:
        return []

    senders: Dict[str, int] = {}
    for line in res.stdout.splitlines():
        line = line.strip()
        # Postfix mailq format: "5A8D410068  1248 Sun Oct 26 10:00:00  sender@example.com"
        if "@" in line and not line.startswith("-"):
            tokens = line.split()
            for t in tokens:
                if "@" in t and "<" not in t and ">" not in t:
                    senders[t] = senders.get(t, 0) + 1
                    break

    sorted_senders = sorted(senders.items(), key=lambda x: x[1], reverse=True)
    return sorted_senders[:limit]


def check_outbound_spam_connections(ctx: Context) -> List[Dict[str, Any]]:
    """Detect non-MTA processes (PHP, shells, unknown bots) opening connections to port 25/465/587."""
    flagged: List[Dict[str, Any]] = []
    smtp_ports = {25, 465, 587}

    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, Exception):
        return []

    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue

        r_port = c.raddr.port if hasattr(c.raddr, "port") else int(c.raddr[1])
        if r_port not in smtp_ports:
            continue

        pid = c.pid
        if not pid:
            continue

        try:
            proc = psutil.Process(pid)
            pname = proc.name().lower()
            u_name = proc.username()
            cmdline = " ".join(proc.cmdline()[:4])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pname = "unknown"
            u_name = "unknown"
            cmdline = ""

        # Check if process is an authorized MTA or SHSM itself
        if pname in ALLOWED_MTA_PROCESSES or u_name in ("postfix", "mail", "Debian-exim", "shsm") or "shsm" in cmdline:
            continue

        r_ip = c.raddr.ip if hasattr(c.raddr, "ip") else str(c.raddr[0])
        # Loopback is normal for local relay
        if r_ip in ("127.0.0.1", "::1", "localhost"):
            continue

        # Whitelist legitimate outbound SMTP host configured in config.yaml
        configured_smtp = ctx.config.get("email.smtp_host")
        if configured_smtp and (configured_smtp == r_ip or configured_smtp in cmdline):
            continue

        flagged.append({
            "pid": pid,
            "process": pname,
            "username": u_name,
            "cmdline": cmdline,
            "remote_ip": r_ip,
            "remote_port": r_port,
        })

    return flagged


def collect(ctx: Context) -> CollectorOutput:
    """Collect mail queue metrics and audit outbound spam sockets."""
    out = CollectorOutput()

    # 1. Mail queue inspection
    warn_thresh = float(ctx.config.get("thresholds.mail_queue_warning", 100))
    crit_thresh = float(ctx.config.get("thresholds.mail_queue_critical", 500))

    queue_total, breakdown, method = get_postfix_queue_counts(ctx)
    out.metric("mail.queue_size", float(queue_total))
    for qname, qcnt in breakdown.items():
        out.metric(f"mail.queue.{qname}", float(qcnt))

    evidence_extra = ""
    top_senders: List[Tuple[str, int]] = []
    if queue_total >= warn_thresh:
        top_senders = get_top_queue_senders(ctx)
        if top_senders:
            sender_str = ", ".join(f"{s[0]} ({s[1]} msgs)" for s in top_senders)
            evidence_extra = f"Top senders in queue: {sender_str}."

    rec = (
        "Inspect mail queue with 'postqueue -p' or 'qshape'. Check for compromised WordPress accounts or "
        "PHP mail() exploitation. Purge unauthorized queue items with 'postsuper -d ALL deferred'."
    )

    threshold_result(
        out,
        check_id="mail.queue",
        category="health",
        asset="postfix",
        value=float(queue_total),
        warning=warn_thresh,
        critical=crit_thresh,
        emergency=crit_thresh * 2,
        label="Mail Queue Size",
        unit=" messages",
        recommendation=rec,
        source=SOURCE,
        evidence_extra=evidence_extra,
        details={"breakdown": breakdown, "method": method, "top_senders": top_senders},
    )

    # 2. Outbound SMTP connection audit (Spam bot detection)
    out.scope("mail.outbound_smtp")
    flagged_conns = check_outbound_spam_connections(ctx)
    out.metric("mail.unauthorized_outbound_smtp", float(len(flagged_conns)))

    if flagged_conns:
        for c in flagged_conns:
            out.finding(
                "mail.outbound_smtp",
                "security",
                Severity.CRITICAL,
                Confidence.HIGH,
                f"Unauthorized outbound SMTP connection ({c['process']}:{c['pid']})",
                f"Process '{c['process']}' (PID {c['pid']}, user '{c['username']}') is actively connected "
                f"to remote mail server {c['remote_ip']}:{c['remote_port']}. Cmdline: {c['cmdline']}",
                "Terminate process immediately. This indicates a direct spam bot or PHP malware bypassing local MTA. "
                "Block non-MTA outbound port 25 with firewall rules.",
                asset=f"{c['process']}:{c['pid']}",
                source=SOURCE,
                key=f"{c['pid']}:{c['remote_ip']}:{c['remote_port']}",
            )
        out.check(
            "mail.outbound_smtp",
            "security",
            CheckStatus.CRITICAL,
            f"Detected {len(flagged_conns)} unauthorized outbound SMTP connection(s)",
            source=SOURCE,
        )
    else:
        out.check(
            "mail.outbound_smtp",
            "security",
            CheckStatus.PASS,
            "No unauthorized direct outbound SMTP connections detected",
            source=SOURCE,
        )

    return out
