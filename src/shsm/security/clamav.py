"""ClamAV antivirus integration and signature freshness checks."""

from __future__ import annotations

import datetime
import os
import re
from typing import List, Optional, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.core.timeutils import UTC

SOURCE = "clamav"
CATEGORY = "security"

_CLAM_INFECTED_LINE = re.compile(r"^([^:]+):\s+(.+)\s+FOUND$")
_CLAM_SUMMARY_INFECTED = re.compile(r"Infected files:\s+(\d+)")


def check_signature_freshness(ctx: Context) -> Tuple[CheckStatus, Optional[float], str]:
    """Check modification time of ClamAV database (daily.cvd / daily.cld)."""
    db_dirs = ["/var/lib/clamav", "/var/clamav"]
    found_mtime: Optional[float] = None

    for d in db_dirs:
        if os.path.isdir(d):
            for fname in ("daily.cvd", "daily.cld", "main.cvd", "main.cld"):
                fpath = os.path.join(d, fname)
                if os.path.isfile(fpath):
                    try:
                        mt = os.path.getmtime(fpath)
                        if found_mtime is None or mt > found_mtime:
                            found_mtime = mt
                    except OSError:
                        continue

    if found_mtime is None:
        return CheckStatus.UNKNOWN, None, "ClamAV virus database files not found"

    db_date = datetime.datetime.fromtimestamp(found_mtime, tz=UTC)
    now = datetime.datetime.now(tz=UTC)
    age_days = (now - db_date).total_seconds() / 86400.0

    t_warn = ctx.threshold("clamav_signature_warning_days")
    t_crit = ctx.threshold("clamav_signature_critical_days")

    if age_days >= t_crit:
        return CheckStatus.CRITICAL, age_days, f"ClamAV signatures are {age_days:.1f} days old (critical)"
    elif age_days >= t_warn:
        return CheckStatus.WARNING, age_days, f"ClamAV signatures are {age_days:.1f} days old (warning)"
    return CheckStatus.PASS, age_days, f"ClamAV signatures are fresh ({age_days:.1f} days old)"


def parse_clamscan_output(stdout: str) -> List[Tuple[str, str]]:
    """Return list of (file_path, virus_name) from scan output."""
    infections: List[Tuple[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        m = _CLAM_INFECTED_LINE.match(line)
        if m:
            infections.append((m.group(1).strip(), m.group(2).strip()))
    return infections


def scan(ctx: Context, profile: str = "quick") -> CollectorOutput:
    out = CollectorOutput()

    enabled = ctx.config.get("scanning.clamav.enabled", True)
    if not enabled:
        out.check("clamav.scan", CATEGORY, CheckStatus.NOT_APPLICABLE, "ClamAV scanning is disabled in configuration", source=SOURCE)
        return out

    # Check binaries
    bin_prog = None
    if ctx.config.get("scanning.clamav.prefer_daemon", True) and ctx.runner.which("clamdscan"):
        bin_prog = ctx.runner.which("clamdscan")
    elif ctx.runner.which("clamscan"):
        bin_prog = ctx.runner.which("clamscan")

    if not bin_prog:
        out.check("clamav.scan", CATEGORY, CheckStatus.NOT_APPLICABLE, "ClamAV is not installed (clamscan/clamdscan missing)", source=SOURCE)
        return out

    # Signature freshness check
    sig_status, sig_age, sig_desc = check_signature_freshness(ctx)
    if sig_age is not None:
        out.metric("clamav.signature_age_days", sig_age)
    out.check("clamav.signatures", CATEGORY, sig_status, sig_desc, source=SOURCE)
    if sig_status in (CheckStatus.WARNING, CheckStatus.CRITICAL):
        out.finding(
            "clamav.signatures",
            CATEGORY,
            Severity.HIGH if sig_status == CheckStatus.CRITICAL else Severity.MEDIUM,
            Confidence.HIGH,
            "Outdated ClamAV antivirus signatures",
            f"{sig_desc}. The scanner cannot reliably detect newer malware strains.",
            "Run 'freshclam' to update virus signatures and verify the freshclam-daemon service is active.",
            source=SOURCE,
            key="clamav_freshclam",
        )

    # Determine paths to scan
    scan_targets: List[str] = []
    if profile == "quick":
        # Scan uploaded directories and temp
        for site in ctx.inventory.active_websites():
            uploads = os.path.join(site.get("doc_root", ""), "wp-content", "uploads")
            if os.path.isdir(uploads):
                scan_targets.append(uploads)
        for tmp in ctx.config.get("scanning.tmp_dirs", ["/tmp", "/var/tmp", "/dev/shm"]):
            if os.path.isdir(tmp):
                scan_targets.append(tmp)
    else:
        # Full scan: all document roots
        for site in ctx.inventory.active_websites():
            doc_root = site.get("doc_root")
            if doc_root and os.path.isdir(doc_root):
                scan_targets.append(doc_root)

    if not scan_targets:
        out.check("clamav.scan", CATEGORY, CheckStatus.PASS, f"No targets to scan for profile '{profile}'", source=SOURCE)
        return out

    timeout = float(
        ctx.config.get(
            f"scanning.clamav.timeout_seconds_{profile}",
            1800 if profile == "quick" else 10800,
        )
    )

    cmd = [bin_prog, "--infected", "--no-summary"]
    # clamdscan vs clamscan flags
    if "clamscan" in os.path.basename(bin_prog) and "clamdscan" not in os.path.basename(bin_prog):
        cmd.extend(["--recursive", f"--max-filesize={ctx.config.get('scanning.clamav.max_filesize_mb', 50)}M"])
    cmd.extend(scan_targets)

    # Apply nice/ionice if available
    res = ctx.runner.run(cmd, timeout=timeout, ok_returncodes=(0, 1))

    if not res.ran:
        out.check("clamav.scan", CATEGORY, CheckStatus.ERROR, f"ClamAV scan execution failed: {res.describe()}", source=SOURCE)
        out.error(f"clamav.scan: {res.describe()}")
        return out

    # Exit code 0 = clean, 1 = virus found
    infections = parse_clamscan_output(res.stdout)
    out.metric("clamav.infections_count", len(infections))

    if infections or res.returncode == 1:
        for fpath, vname in infections:
            out.finding(
                "clamav.malware",
                CATEGORY,
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"Malware detected by ClamAV: {vname}",
                f"File {fpath} was identified as infected with '{vname}'.",
                f"Inspect and quarantine the infected file ({fpath}). Check web server logs for exploitation attempts.",
                asset=os.path.basename(fpath),
                source=SOURCE,
                key=fpath,
            )
        out.check(
            "clamav.scan",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"ClamAV scan ({profile}) identified {len(infections)} malware file(s)",
            source=SOURCE,
        )
    else:
        out.check(
            "clamav.scan",
            CATEGORY,
            CheckStatus.PASS,
            f"ClamAV ({profile}) scan clean across {len(scan_targets)} target directory path(s)",
            source=SOURCE,
        )

    return out
