"""Service monitoring: systemctl/systemd checks, restart detection, failed units, and unit file integrity."""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any, Dict, Optional, Set

from shsm.collectors.base import join_limited
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.utils.paths import is_valid_unit_name

SOURCE = "systemd"
CATEGORY = "services"

_PROPERTIES = (
    "Id",
    "Description",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ExecMainStartTimestamp",
    "NRestarts",
    "Result",
)


def _show_unit(ctx: Context, unit: str) -> Optional[Dict[str, str]]:
    if not is_valid_unit_name(unit):
        return None
    res = ctx.runner.run(
        ["systemctl", "show", unit, "--no-page", "-p", ",".join(_PROPERTIES)],
        timeout=10,
    )
    if not res.ok:
        return None
    info: Dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    return info


def discover_unit_for_role(ctx: Context, role: str, spec: Dict[str, Any]) -> Optional[str]:
    """Find active or installed systemd unit matching configured units or pattern list."""
    configured_units = spec.get("units", [])
    for u in configured_units:
        info = _show_unit(ctx, u)
        if info and info.get("LoadState") not in ("not-found", ""):
            return u

    patterns = spec.get("patterns", [])
    if not patterns:
        return None

    # Query systemctl list-units to find matching active or loaded services
    res = ctx.runner.run(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
        timeout=15,
    )
    if not res.ok:
        return None

    for line in res.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        unit_name = parts[0]
        base_name = unit_name.removesuffix(".service").lower()
        for pat in patterns:
            pat_lower = pat.lower()
            if pat_lower == base_name or pat_lower in base_name:
                return unit_name

    return None


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    roles = ctx.config.get("services.roles", {})
    discovered_units: Dict[str, str] = {}

    # 1. Evaluate configured roles
    for role, spec in roles.items():
        unit = discover_unit_for_role(ctx, role, spec)
        check_id = f"service.{role}"

        if not unit:
            if spec.get("required", False):
                out.check(
                    check_id,
                    CATEGORY,
                    CheckStatus.CRITICAL,
                    f"Required service for '{role}' not found or not installed",
                    asset=role,
                    source=SOURCE,
                )
                out.finding(
                    check_id,
                    CATEGORY,
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    f"Required service '{role}' is not found",
                    f"Could not discover any systemd unit matching patterns: {spec.get('patterns', [])}.",
                    f"Verify that {role} is installed and its systemd unit is enabled.",
                    asset=role,
                    source=SOURCE,
                )
            else:
                out.check(
                    check_id,
                    CATEGORY,
                    CheckStatus.NOT_APPLICABLE,
                    f"Optional service '{role}' is not installed",
                    asset=role,
                    source=SOURCE,
                )
            continue

        discovered_units[role] = unit
        info = _show_unit(ctx, unit)
        if not info:
            out.check(
                check_id,
                CATEGORY,
                CheckStatus.UNKNOWN,
                f"Failed to query systemctl show for unit {unit}",
                asset=unit,
                source=SOURCE,
            )
            continue

        active_state = info.get("ActiveState", "unknown")
        sub_state = info.get("SubState", "unknown")
        load_state = info.get("LoadState", "unknown")
        pid_str = info.get("MainPID", "0")
        main_pid = int(pid_str) if pid_str.isdigit() else 0
        n_restarts_str = info.get("NRestarts", "0")
        n_restarts = int(n_restarts_str) if n_restarts_str.isdigit() else 0
        result = info.get("Result", "success")

        # Restart anomaly detection
        last_check = ctx.inventory.last_service_check(unit)
        restart_detected = False
        if last_check:
            last_pid = last_check.get("main_pid")
            last_active = last_check.get("active_state")
            if (
                last_active == "active"
                and active_state == "active"
                and main_pid > 0
                and last_pid
                and main_pid != last_pid
            ):
                restart_detected = True

        # Record into database
        check_record = {
            "unit": unit,
            "role": role,
            "load_state": load_state,
            "active_state": active_state,
            "sub_state": sub_state,
            "main_pid": main_pid,
            "started_at": info.get("ExecMainStartTimestamp"),
            "uptime_seconds": None,
            "n_restarts": n_restarts,
            "result": result,
            "restart_detected": restart_detected,
            "detail": f"{sub_state} (result: {result})",
        }
        ctx.inventory.add_service_check(now, check_record)

        # Check health status
        if active_state != "active":
            status = CheckStatus.CRITICAL if spec.get("required", False) else CheckStatus.WARNING
            out.check(
                check_id,
                CATEGORY,
                status,
                f"Unit {unit} is {active_state} ({sub_state})",
                asset=unit,
                source=SOURCE,
                details=info,
            )
            sev = Severity.CRITICAL if spec.get("required", False) else Severity.HIGH
            out.finding(
                check_id,
                CATEGORY,
                sev,
                Confidence.CONFIRMED,
                f"Service {unit} is down ({active_state})",
                f"Service unit {unit} (role: {role}) is {active_state}/{sub_state}. Result: {result}.",
                f"Inspect service logs using 'journalctl -u {unit} -e --no-pager' and resolve the failure.",
                asset=unit,
                source=SOURCE,
            )
        else:
            # Active service: check for restart flapping
            recent_restarts = ctx.inventory.restarts_since(unit, now - timedelta(hours=1))
            warn_restarts = int(ctx.threshold("restarts_per_hour_warning"))
            if recent_restarts >= warn_restarts:
                out.check(
                    check_id,
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"Unit {unit} restarted {recent_restarts} times in the last hour",
                    asset=unit,
                    source=SOURCE,
                )
                out.finding(
                    f"{check_id}.restarts",
                    CATEGORY,
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"Service {unit} is flapping/restarting repeatedly",
                    f"Unit {unit} experienced {recent_restarts} restarts in the past hour (threshold {warn_restarts}).",
                    f"Check {unit} error logs and memory limits to find what is triggering process restarts.",
                    asset=unit,
                    source=SOURCE,
                )
            else:
                out.check(
                    check_id,
                    CATEGORY,
                    CheckStatus.PASS,
                    f"Unit {unit} is active ({sub_state}, PID {main_pid})",
                    asset=unit,
                    source=SOURCE,
                )

    # 2. Check for overall failed systemd units across the host
    _check_failed_units(ctx, out)

    # 3. Check for new systemd unit files in sensitive unit dirs
    _check_sensitive_unit_files(ctx, out)

    return out


def _check_failed_units(ctx: Context, out: CollectorOutput) -> None:
    res = ctx.runner.run(
        ["systemctl", "list-units", "--state=failed", "--no-legend", "--no-pager"],
        timeout=15,
    )
    if not res.ok:
        out.check(
            "systemd.failed",
            CATEGORY,
            CheckStatus.UNKNOWN,
            f"Failed to query failed systemd units: {res.describe()}",
            source=SOURCE,
        )
        return

    failed_units = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if parts:
            failed_units.append(parts[0])

    out.metric("systemd.failed_units_count", len(failed_units))

    if failed_units:
        unit_str = join_limited(failed_units, 5)
        out.check(
            "systemd.failed",
            CATEGORY,
            CheckStatus.WARNING,
            f"{len(failed_units)} failed systemd unit(s): {unit_str}",
            source=SOURCE,
        )
        out.finding(
            "systemd.failed",
            CATEGORY,
            Severity.HIGH,
            Confidence.CONFIRMED,
            f"{len(failed_units)} failed systemd unit(s) detected",
            f"The following unit(s) are in failed state: {unit_str}.",
            "Run 'systemctl --failed' and 'journalctl -u <unit>' to inspect and reset failed units.",
            asset=unit_str,
            source=SOURCE,
        )
    else:
        out.check(
            "systemd.failed",
            CATEGORY,
            CheckStatus.PASS,
            "No failed systemd units on the host",
            source=SOURCE,
        )


def _check_sensitive_unit_files(ctx: Context, out: CollectorOutput) -> None:
    dirs = ctx.config.get("services.sensitive_unit_dirs", ["/etc/systemd/system"])
    found_files: Set[str] = set()

    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.scandir(d):
                if entry.is_file(follow_symlinks=False) and (
                    entry.name.endswith(".service") or entry.name.endswith(".timer")
                ):
                    found_files.add(entry.path)
        except OSError:
            continue

    # Compare with recorded known unit files in state_kv
    known_units = set(ctx.runs.kv_get_json("systemd.known_unit_files", default=[]))
    now = ctx.now()

    if not known_units:
        # Initial baseline recording
        ctx.runs.kv_set_json("systemd.known_unit_files", sorted(found_files), now)
        out.check(
            "systemd.unit_files",
            "security",
            CheckStatus.PASS,
            f"Baselined {len(found_files)} systemd unit file(s)",
            source=SOURCE,
        )
        return

    new_units = found_files - known_units
    if new_units:
        out.check(
            "systemd.unit_files",
            "security",
            CheckStatus.WARNING,
            f"Detected {len(new_units)} new unit file(s) in sensitive systemd dirs",
            source=SOURCE,
        )
        for u in sorted(new_units):
            out.finding(
                "systemd.new_unit",
                "security",
                Severity.MEDIUM,
                Confidence.HIGH,
                f"New systemd unit file installed: {os.path.basename(u)}",
                f"New unit file was created in {u}.",
                "Verify whether this unit file was installed legitimately by an administrator or package.",
                asset=u,
                source=SOURCE,
                key=u,
            )
        # Update state with new units so we alert once
        ctx.runs.kv_set_json("systemd.known_unit_files", sorted(found_files), now)
    else:
        out.check(
            "systemd.unit_files",
            "security",
            CheckStatus.PASS,
            f"No unexpected systemd unit files ({len(found_files)} tracked)",
            source=SOURCE,
        )
