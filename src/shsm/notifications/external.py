"""External monitoring heartbeat adapter (generic webhook & Uptime Kuma push)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests

from shsm import __version__
from shsm.core.context import Context
from shsm.core.timeutils import to_iso

SOURCE = "external_heartbeat"


def send_heartbeat(ctx: Context) -> Tuple[bool, int, Optional[str]]:
    """Send heartbeat payload to configured HTTPS endpoint."""
    cfg = ctx.config.section("external_monitoring")
    if not cfg.get("enabled", False):
        return False, 0, "External monitoring is disabled in configuration"

    url = str(cfg.get("heartbeat_url", "")).strip()
    if not url or not url.lower().startswith("https://"):
        return False, 0, "external_monitoring.heartbeat_url must use https://"

    provider = str(cfg.get("provider", "generic_webhook"))
    token = ctx.config.secret("external_token")
    timeout = float(cfg.get("timeout_seconds", 15))
    now = ctx.now()

    server_info = ctx.runs.server_info() or ctx.runs.ensure_server_info(now)
    server_id = server_info.get("server_id", "unknown")

    # Determine status
    has_crit = len(ctx.findings.list(statuses=["OPEN"], min_severity=None))
    status_str = "DOWN" if (has_crit > 0 and cfg.get("report_critical_as_down", False)) else "UP"

    payload: Dict[str, Any] = {
        "server_id": server_id,
        "timestamp": to_iso(now),
        "version": __version__,
        "status": status_str,
    }

    headers = {"Content-Type": "application/json", "User-Agent": f"SHSM-Heartbeat/{__version__}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    http_status: Optional[int] = None
    err_msg: Optional[str] = None
    success = False

    try:
        # If Uptime Kuma push, it's often a GET with ?status=up&msg=OK&ping=...
        if provider == "uptime_kuma_push":
            kuma_url = f"{url}?status={'up' if status_str == 'UP' else 'down'}&msg=OK"
            resp = requests.get(kuma_url, headers=headers, timeout=timeout)
        else:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)

        http_status = resp.status_code
        success = (200 <= resp.status_code < 300)
        if not success:
            err_msg = f"HTTP {resp.status_code}: {resp.text[:100]}"
    except Exception as exc:
        err_msg = str(exc)

    ctx.runs.add_heartbeat(
        now,
        provider,
        "SUCCESS" if success else "FAILED",
        http_status,
        1,
        err_msg,
        payload,
    )

    return success, 1, err_msg
