"""SSH configuration audit and authentication log aggregation."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.utils.redact import mask_ip

SOURCE = "ssh_audit"
CATEGORY = "security"

# Regex for auth.log / secure
_FAILED_PASS = re.compile(r"(?i)Failed password for (?:invalid user )?(\S+) from (\S+) port \d+")
_ACCEPTED_PASS = re.compile(r"(?i)Accepted (?:password|publickey) for (\S+) from (\S+) port \d+")
_ROOT_LOGIN = re.compile(r"(?i)Accepted \S+ for root from (\S+)")


def inspect_sshd_config(config_path: str = "/etc/ssh/sshd_config") -> Dict[str, Any]:
    """Parse effective settings from sshd_config without executing shell."""
    settings: Dict[str, str] = {
        "port": "22",
        "permitrootlogin": "prohibit-password",
        "passwordauthentication": "yes",
        "pubkeyauthentication": "yes",
    }
    if not os.path.isfile(config_path) or not os.access(config_path, os.R_OK):
        return settings

    try:
        with open(config_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    key = parts[0].lower()
                    val = parts[1].strip().lower()
                    if key in settings:
                        settings[key] = val
    except OSError:
        pass
    return settings


def parse_auth_lines(lines: List[str]) -> Dict[str, Any]:
    failed_attempts = 0
    success_logins: List[Tuple[str, str]] = []
    root_logins: List[str] = []

    for line in lines:
        if "sshd" not in line.lower():
            continue
        m_fail = _FAILED_PASS.search(line)
        if m_fail:
            failed_attempts += 1
            continue

        m_ok = _ACCEPTED_PASS.search(line)
        if m_ok:
            user = m_ok.group(1)
            ip = m_ok.group(2)
            success_logins.append((user, ip))

        m_root = _ROOT_LOGIN.search(line)
        if m_root:
            root_logins.append(m_root.group(1))

    return {
        "failed_attempts": failed_attempts,
        "success_logins": success_logins,
        "root_logins": root_logins,
    }


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    # 1. SSH Configuration check
    cfg = inspect_sshd_config()
    port = cfg.get("port", "22")
    root_login = cfg.get("permitrootlogin", "prohibit-password")
    pass_auth = cfg.get("passwordauthentication", "yes")

    out.metric("ssh.port", float(port) if port.isdigit() else 22.0)

    if root_login in ("yes", "without-password"):
        out.check(
            "ssh.config",
            CATEGORY,
            CheckStatus.WARNING,
            f"SSH PermitRootLogin is set to '{root_login}'",
            source=SOURCE,
        )
        out.finding(
            "ssh.config",
            CATEGORY,
            Severity.MEDIUM,
            Confidence.CONFIRMED,
            "SSH root login is permitted via password or unrestricted",
            f"sshd_config has PermitRootLogin {root_login}. Best practice is prohibit-password or no.",
            "Set PermitRootLogin prohibit-password or no in /etc/ssh/sshd_config and reload sshd.",
            source=SOURCE,
            key="PermitRootLogin",
        )
    else:
        out.check(
            "ssh.config",
            CATEGORY,
            CheckStatus.PASS,
            f"SSH configuration secure (Port {port}, PermitRootLogin {root_login}, PasswordAuth {pass_auth})",
            source=SOURCE,
        )

    # 2. Authentication Log Analysis
    log_candidates = ctx.config.get("security.ssh_log_candidates", ["/var/log/auth.log", "/var/log/secure"])
    auth_log = None
    for cand in log_candidates:
        if os.path.isfile(cand):
            auth_log = cand
            break

    if not auth_log:
        out.check("ssh.auth_events", CATEGORY, CheckStatus.NOT_APPLICABLE, "No SSH auth log file found", source=SOURCE)
        return out

    max_bytes = int(ctx.config.get("security.ssh_max_bytes_per_run", 20 * 1024 * 1024))
    tail_res = ctx.tailer.read_new(auth_log, now, max_bytes=max_bytes)

    if tail_res.lines:
        auth_data = parse_auth_lines(tail_res.lines)
        fails = auth_data["failed_attempts"]
        successes = len(auth_data["success_logins"])
        roots = len(auth_data["root_logins"])

        out.metric("ssh.failed_logins", fails)
        out.metric("ssh.successful_logins", successes)
        out.metric("ssh.root_logins", roots)

        warn_fail = ctx.threshold("ssh_failed_warning")
        crit_fail = ctx.threshold("ssh_failed_critical")

        if fails >= warn_fail:
            status = CheckStatus.CRITICAL if fails >= crit_fail else CheckStatus.WARNING
            out.check(
                "ssh.auth_events",
                CATEGORY,
                status,
                f"Observed {fails} failed SSH login attempts",
                source=SOURCE,
            )
            out.finding(
                "ssh.failed_burst",
                CATEGORY,
                Severity.HIGH if status == CheckStatus.CRITICAL else Severity.MEDIUM,
                Confidence.HIGH,
                f"High rate of failed SSH logins ({fails} attempts)",
                f"Encountered {fails} failed authentication attempts in recent SSH logs.",
                "Ensure Fail2Ban is active and consider changing SSH port or restricting SSH access by IP.",
                source=SOURCE,
            )
        else:
            out.check(
                "ssh.auth_events",
                CATEGORY,
                CheckStatus.PASS,
                f"SSH logins normal ({fails} failed, {successes} successful)",
                source=SOURCE,
            )

        # Learning login baseline for anomaly detection
        if ctx.config.get("security.ssh_learning", True):
            for user, ip in auth_data["success_logins"]:
                masked_net = mask_ip(ip)
                row = ctx.db.query_one("SELECT * FROM login_baseline WHERE username=? AND network=?", (user, masked_net))
                from shsm.core.timeutils import to_iso

                ts = to_iso(now)
                if not row:
                    ctx.db.execute(
                        "INSERT INTO login_baseline (username, network, first_seen, last_seen, success_count) VALUES (?,?,?,?,1)",
                        (user, masked_net, ts, ts),
                    )
                else:
                    ctx.db.execute(
                        "UPDATE login_baseline SET last_seen=?, success_count=success_count+1 WHERE username=? AND network=?",
                        (ts, user, masked_net),
                    )

    return out
