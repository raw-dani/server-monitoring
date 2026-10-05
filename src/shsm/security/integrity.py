"""File and system integrity monitoring (FIM) and baseline management."""

from __future__ import annotations

import hashlib
import os
import stat
from typing import Any, Dict, Optional, Set

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.core.timeutils import to_iso

SOURCE = "file_integrity"
CATEGORY = "integrity"


def _hash_file(path: str, max_size_bytes: int = 50 * 1024 * 1024) -> Optional[str]:
    try:
        st = os.stat(path)
        if st.st_size > max_size_bytes or stat.S_ISDIR(st.st_mode):
            return None
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None


def inspect_path(path: str, max_size: int = 50 * 1024 * 1024) -> Optional[Dict[str, Any]]:
    """Capture metadata and sha256 for a single file/directory/symlink."""
    try:
        st = os.lstat(path)
    except OSError:
        return None

    if stat.S_ISLNK(st.st_mode):
        ftype = "symlink"
        sha = hashlib.sha256(os.readlink(path).encode("utf-8", "replace")).hexdigest()
    elif stat.S_ISDIR(st.st_mode):
        ftype = "directory"
        sha = None
    elif stat.S_ISREG(st.st_mode):
        ftype = "file"
        sha = _hash_file(path, max_size)
    else:
        ftype = "special"
        sha = None

    import datetime
    import json

    from shsm.core.timeutils import UTC
    from shsm.security import accounts

    mtime_dt = datetime.datetime.fromtimestamp(st.st_mtime, tz=UTC)

    meta_json: Optional[str] = None
    if ftype == "file":
        norm = path.replace("\\", "/")
        if norm.endswith("/etc/passwd"):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    meta_json = json.dumps(accounts.parse_passwd_content(fh.read()))
            except OSError:
                pass
        elif norm.endswith("/etc/group"):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    meta_json = json.dumps(accounts.parse_group_content(fh.read()))
            except OSError:
                pass

    return {
        "path": path,
        "file_type": ftype,
        "sha256": sha,
        "size": st.st_size,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.S_IMODE(st.st_mode),
        "mtime": to_iso(mtime_dt),
        "metadata_json": meta_json,
    }


def expand_monitored_paths(ctx: Context) -> Set[str]:
    """Expand configured paths and directories into full list of files to check."""
    configured_paths = list(ctx.config.get("integrity.paths", []))
    configured_paths.extend(ctx.config.get("integrity.extra_paths", []))
    max_files = int(ctx.config.get("integrity.max_files_per_dir", 5000))

    files: Set[str] = set()

    for p in configured_paths:
        if not os.path.exists(p):
            continue
        if os.path.isfile(p) or os.path.islink(p):
            files.add(os.path.abspath(p))
        elif os.path.isdir(p):
            count = 0
            for root, _, filenames in os.walk(p, followlinks=False):
                for f in filenames:
                    files.add(os.path.join(root, f))
                    count += 1
                    if count >= max_files:
                        break
                if count >= max_files:
                    break

    return files


def build_or_update_baseline(ctx: Context, paths: Optional[Set[str]] = None) -> int:
    """Explicit administrator action to build or refresh the baseline in the database."""
    now = ctx.now()
    targets = paths or expand_monitored_paths(ctx)
    max_size = int(ctx.config.get("integrity.max_file_size_mb", 50)) * 1024 * 1024

    count = 0
    with ctx.db.transaction():
        for p in targets:
            rec = inspect_path(p, max_size)
            if rec:
                ctx.integrity.upsert_baseline(rec, now)
                ctx.integrity.resolve_open_events_for_path(p, now)
                ctx.findings.resolve_by_asset(
                    p,
                    ["integrity.modified", "integrity.deleted", "integrity.permissions", "integrity.new_file", "integrity.accounts"],
                    now,
                )
                count += 1
    return count


def check(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    baseline = ctx.integrity.baseline()
    if not baseline:
        out.check(
            "integrity.files",
            CATEGORY,
            CheckStatus.WARNING,
            "Integrity baseline has not been initialized yet. Run 'shsm integrity baseline --review' to create it.",
            source=SOURCE,
        )
        return out

    out.scope("integrity.modified")
    out.scope("integrity.deleted")
    out.scope("integrity.permissions")
    out.scope("integrity.new_file")
    out.scope("integrity.accounts")
    out.scope("integrity.files")

    max_size = int(ctx.config.get("integrity.max_file_size_mb", 50)) * 1024 * 1024
    current_paths = expand_monitored_paths(ctx)
    critical_paths = set(ctx.config.get("integrity.critical_paths", []))

    critical_changes = 0
    warning_changes = 0
    info_changes = 0

    import json

    from shsm.security import accounts

    # 1. Check existing baseline items for modification or deletion
    for path, b in baseline.items():
        curr = inspect_path(path, max_size)
        is_critical = any(path == c or path.startswith(c.rstrip("/") + "/") for c in critical_paths)
        base_sev = Severity.CRITICAL if is_critical else Severity.HIGH

        if not curr:
            # File deleted
            critical_changes += 1 if is_critical else 0
            warning_changes += 0 if is_critical else 1
            ctx.integrity.add_event(path, "DELETED", base_sev.value, b, None, now)
            out.finding(
                "integrity.deleted",
                CATEGORY,
                base_sev,
                Confidence.CONFIRMED,
                f"Monitored file deleted: {path}",
                f"File {path} in baseline was deleted from disk.",
                "Verify whether file removal was intentional by an administrator.",
                asset=path,
                source=SOURCE,
                key=f"{path}:deleted",
            )
            continue

        # Check content changes
        if b["sha256"] and curr["sha256"] and b["sha256"] != curr["sha256"]:
            norm = path.replace("\\", "/")
            if norm.endswith("/etc/passwd") or norm.endswith("/etc/group"):
                # Structural account & group diffing
                old_meta_raw = b.get("metadata_json")
                curr_meta_raw = curr.get("metadata_json")

                if norm.endswith("/etc/passwd"):
                    old_users = json.loads(old_meta_raw) if old_meta_raw else {}
                    new_users = json.loads(curr_meta_raw) if curr_meta_raw else {}
                    acc_events = accounts.diff_passwd(old_users, new_users, ctx=ctx)
                else:
                    old_groups = json.loads(old_meta_raw) if old_meta_raw else {}
                    new_groups = json.loads(curr_meta_raw) if curr_meta_raw else {}
                    acc_events = accounts.diff_group(old_groups, new_groups, ctx=ctx)

                if not acc_events:
                    # Whitespace / comment change only
                    info_changes += 1
                    ctx.integrity.add_event(path, "CONTENT_MODIFIED", Severity.INFO.value, b, curr, now)
                    out.finding(
                        "integrity.accounts",
                        CATEGORY,
                        Severity.INFO,
                        Confidence.CONFIRMED,
                        f"Non-structural modification in {path}",
                        f"Hash changed on {path}, but account and group definitions remained identical.",
                        "Update baseline with 'sudo -u shsm shsm integrity baseline --update'.",
                        asset=path,
                        source=SOURCE,
                        key=f"{path}:structure_clean",
                    )
                else:
                    all_sys_only = all(e.get("is_system_only", False) for e in acc_events)
                    has_crit = any(e.get("severity") == Severity.CRITICAL for e in acc_events)

                    if has_crit:
                        critical_changes += 1
                    elif not all_sys_only:
                        warning_changes += 1
                    else:
                        info_changes += 1

                    for ev in acc_events:
                        ctx.integrity.add_event(path, ev["event_type"], ev["severity"].value, b, curr, now)
                        out.finding(
                            "integrity.accounts",
                            CATEGORY,
                            ev["severity"],
                            Confidence.CONFIRMED,
                            ev["title"],
                            ev["details"],
                            ev["recommendation"],
                            asset=path,
                            source=SOURCE,
                            key=f"{path}:{ev['name']}:{ev['event_type']}",
                        )
            else:
                # Regular system / binary file modification
                if is_critical:
                    critical_changes += 1
                else:
                    warning_changes += 1

                ctx.integrity.add_event(path, "CONTENT_MODIFIED", base_sev.value, b, curr, now)
                out.finding(
                    "integrity.modified",
                    CATEGORY,
                    base_sev,
                    Confidence.CONFIRMED,
                    f"Critical system file modified: {path}",
                    f"Hash changed on {path} (old: {b['sha256'][:8]}..., new: {curr['sha256'][:8]}...).",
                    "Review diff or package status ('dpkg -S' or 'debsums'). Verify unauthorized modifications.",
                    asset=path,
                    source=SOURCE,
                    key=f"{path}:content",
                )

        # Check permissions / owner changes
        elif b["mode"] != curr["mode"] or b["uid"] != curr["uid"] or b["gid"] != curr["gid"]:
            warning_changes += 1
            ctx.integrity.add_event(path, "PERMISSIONS_CHANGED", Severity.HIGH.value, b, curr, now)
            out.finding(
                "integrity.permissions",
                CATEGORY,
                Severity.HIGH,
                Confidence.CONFIRMED,
                f"File permissions or ownership modified: {path}",
                f"Mode changed from {oct(b['mode'])} (uid:{b['uid']}) to {oct(curr['mode'])} (uid:{curr['uid']}).",
                "Restore correct file permissions and verify if an intruder altered access controls.",
                asset=path,
                source=SOURCE,
                key=f"{path}:perms",
            )

    # 2. Check for added files inside monitored directories
    for path in current_paths:
        if path not in baseline:
            curr = inspect_path(path, max_size)
            if not curr:
                continue
            is_critical = any(path == c or path.startswith(c.rstrip("/") + "/") for c in critical_paths)
            if is_critical:
                critical_changes += 1
            else:
                warning_changes += 1

            sev = Severity.HIGH if is_critical else Severity.MEDIUM
            ctx.integrity.add_event(path, "NEW_FILE", sev.value, None, curr, now)
            out.finding(
                "integrity.new_file",
                CATEGORY,
                sev,
                Confidence.CONFIRMED,
                f"New file created in monitored directory: {path}",
                f"Found new file {path} not present in baseline.",
                "Review file contents and update baseline with 'shsm integrity baseline --review' if legitimate.",
                asset=path,
                source=SOURCE,
                key=f"{path}:new",
            )

    total_changes = critical_changes + warning_changes + info_changes
    out.metric("integrity.changes_detected", total_changes)
    out.metric("integrity.critical_changes", critical_changes)
    out.metric("integrity.info_changes", info_changes)

    if critical_changes > 0:
        out.check(
            "integrity.files",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"Detected {critical_changes} critical integrity violation(s) against baseline ({len(baseline)} files monitored)",
            source=SOURCE,
        )
    elif warning_changes > 0:
        out.check(
            "integrity.files",
            CATEGORY,
            CheckStatus.WARNING,
            f"Detected {warning_changes} unconfirmed file modification(s) against baseline ({len(baseline)} files monitored)",
            source=SOURCE,
        )
    elif info_changes > 0:
        out.check(
            "integrity.files",
            CATEGORY,
            CheckStatus.PASS,
            f"All {len(baseline)} baselined critical files verified ({info_changes} legitimate system service account change(s) noted)",
            source=SOURCE,
        )
    else:
        out.check(
            "integrity.files",
            CATEGORY,
            CheckStatus.PASS,
            f"All {len(baseline)} baselined critical files and directories verified without changes",
            source=SOURCE,
        )

    return out
