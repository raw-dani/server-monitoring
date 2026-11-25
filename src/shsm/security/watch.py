"""Ultra-lightweight real-time adaptive DDoS & Layer-7 flood watcher daemon.

Designed for near-zero idle overhead:
- Reads only /proc/net/tcp sockets (via psutil) and newly appended log bytes via in-memory seek offsets.
- Zero SQLite writes during quiet ticks; only logs/blocks when thresholds are breached.
- Skips dormant vhost logs in O(1) via mtime filtering.
- Uses an in-memory ban cooldown cache so already-blocked IPs never trigger duplicate subprocesses.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from shsm.collectors.ddos import analyze_tcp_connections
from shsm.collectors.openlitespeed import (
    _DEFAULT_BAD_BOTS,
    discover_active_access_logs,
    find_l7_offenders,
    merge_access_stats,
    parse_access_lines,
)
from shsm.core.context import Context
from shsm.security.blocked import ban_ip_cloudflare, ban_ip_unified, is_protected_ip
from shsm.security.fail2ban import _run_with_sudo_fallback

log = logging.getLogger(__name__)


@dataclass
class WatchState:
    """Bounded in-memory state for the real-time watcher loop."""

    log_cursors: Dict[str, Tuple[int, int]] = field(default_factory=dict)  # path -> (inode, offset)
    recent_bans: Dict[str, float] = field(default_factory=dict)  # ip -> monotonic expiry timestamp
    consecutive_emergency_ticks: int = 0
    last_breaker_ts: float = 0.0
    last_discovery_ts: float = 0.0
    cached_logs: List[str] = field(default_factory=list)

    def is_recently_banned(self, ip: str, now_mono: float) -> bool:
        exp = self.recent_bans.get(ip)
        if exp is None:
            return False
        if now_mono >= exp:
            self.recent_bans.pop(ip, None)
            return False
        return True

    def mark_banned(self, ip: str, ttl_seconds: int, now_mono: float) -> None:
        if len(self.recent_bans) > 4096:
            expired = [k for k, v in self.recent_bans.items() if now_mono >= v]
            for k in expired:
                self.recent_bans.pop(k, None)
        self.recent_bans[ip] = now_mono + max(60, ttl_seconds)


def _read_new_lines_memory(
    path: str,
    state: WatchState,
    max_bytes: int = 2 * 1024 * 1024,
) -> List[str]:
    """Read newly appended complete lines using only in-memory (inode, offset) cursors."""
    try:
        fh = open(path, "rb")
    except OSError:
        return []
    try:
        st = os.fstat(fh.fileno())
        prev = state.log_cursors.get(path)
        if prev is None:
            # First sight: start at end of file so historical logs are never replayed
            state.log_cursors[path] = (st.st_ino, st.st_size)
            return []

        prev_ino, prev_offset = prev
        if prev_ino != st.st_ino or st.st_size < prev_offset:
            offset = 0
        else:
            offset = prev_offset

        if st.st_size == offset:
            return []

        fh.seek(offset)
        data = fh.read(max_bytes)
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            consumed = len(data) if len(data) >= max_bytes else 0
            chunk = b"" if consumed == 0 else data
        else:
            consumed = last_nl + 1
            chunk = data[:consumed]

        state.log_cursors[path] = (st.st_ino, offset + consumed)
        if not chunk:
            return []
        return chunk.decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    finally:
        fh.close()


def _get_load_per_cpu() -> float:
    try:
        if hasattr(os, "getloadavg"):
            load1 = os.getloadavg()[0]
            cpus = os.cpu_count() or 1
            return load1 / float(cpus)
    except OSError:
        pass
    return 0.0


def run_watch_tick(
    ctx: Context,
    state: WatchState,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Execute one fast Layer-4 + Layer-7 check-and-ban cycle."""
    now_mono = time.monotonic()
    ttl = int(ctx.config.get("security.ddos_ban_ttl_seconds", 3600))
    load_per_cpu = _get_load_per_cpu()

    actions: List[str] = []
    banned_ips: List[str] = []

    def _ban(ip: str, reason: str) -> None:
        if state.is_recently_banned(ip, now_mono):
            return
        if is_protected_ip(ctx, ip)[0]:
            return
        if dry_run:
            actions.append(f"[DRY-RUN] Would ban {ip} ({reason})")
            state.mark_banned(ip, ttl, now_mono)
            banned_ips.append(ip)
            return
        ok, msg = ban_ip_unified(ctx, ip, use_iptables=True, ttl_seconds=ttl, reason=reason)
        if ok:
            state.mark_banned(ip, ttl, now_mono)
            banned_ips.append(ip)
            actions.append(f"Banned {ip}: {reason} -> {msg}")
            log.warning("SHSM Watch auto-banned %s (%s): %s", ip, reason, msg)
            if bool(ctx.config.get("security.cloudflare_enabled", False)):
                ban_ip_cloudflare(ctx, ip, reason=reason)

    # 1. Layer-4 TCP socket inspection (kernel memory only)
    if bool(ctx.config.get("security.ddos_auto_block", True)):
        _total, syn_cnt, _top, violators = analyze_tcp_connections(ctx)
        for v in violators:
            # Under normal load ban CRITICAL; under elevated load ban WARNING too
            if v["level"] == "CRITICAL" or load_per_cpu >= 2.0:
                _ban(v["ip"], f"L4 socket flood ({v['connections']} conns)")

    # 2. Layer-7 Multi-Vhost incremental log inspection
    if (now_mono - state.last_discovery_ts) >= 30.0 or not state.cached_logs:
        state.cached_logs = discover_active_access_logs(ctx, active_window_seconds=120)
        state.last_discovery_ts = now_mono

    bad_bots = ctx.config.get("security.bad_bot_user_agents", list(_DEFAULT_BAD_BOTS))
    batches: List[Dict[str, Any]] = []
    for log_p in state.cached_logs:
        lines = _read_new_lines_memory(log_p, state)
        if lines:
            batches.append(parse_access_lines(lines, bad_bot_agents=bad_bots))

    if batches:
        merged = merge_access_stats(batches)
        watch_burst = int(ctx.config.get("security.l7_watch_burst_threshold", 50))
        thresh_404 = int(ctx.config.get("security.scanner_404_threshold", 30))

        # Check exploit attempts immediately (single request is enough)
        if bool(ctx.config.get("security.fail2ban_auto_block", True)):
            for ex in merged.get("suspicious", []):
                ex_ip = ex.get("ip")
                if ex_ip:
                    _ban(ex_ip, f"Exploit probe ({ex.get('path', '')[:60]})")

        if bool(ctx.config.get("security.scanner_404_auto_block", True)):
            for ip, cnt in merged.get("ip_404_counts", {}).items():
                if cnt >= thresh_404:
                    _ban(ip, f"404 scanner burst ({cnt} hits)")

        if bool(ctx.config.get("security.l7_flood_auto_block", True)):
            l7_off = find_l7_offenders(ctx, merged, burst_threshold=watch_burst)
            for ip, info in l7_off.items():
                _ban(ip, ", ".join(info["reasons"]))

    # 3. Emergency Circuit Breaker for sustained extreme CPU thrashing
    breaker_triggered = False
    if bool(ctx.config.get("security.emergency_circuit_breaker", True)):
        emerg_thresh = float(ctx.config.get("security.emergency_load_per_cpu", 5.0))
        if load_per_cpu >= emerg_thresh:
            state.consecutive_emergency_ticks += 1
        else:
            state.consecutive_emergency_ticks = 0

        if state.consecutive_emergency_ticks >= 3 and (now_mono - state.last_breaker_ts) >= 120.0:
            state.last_breaker_ts = now_mono
            state.consecutive_emergency_ticks = 0
            breaker_triggered = True
            if dry_run:
                actions.append(f"[DRY-RUN] Emergency breaker would reset hung lsphp (load/cpu={load_per_cpu:.2f})")
            else:
                kill_bin = ctx.runner.which("killall") or ctx.runner.which("/usr/bin/killall") or "/usr/bin/killall"
                res = _run_with_sudo_fallback(ctx, [kill_bin, "-9", "lsphp"], timeout=5)
                if res.ok:
                    actions.append(f"Emergency breaker cleared hung lsphp workers (load/cpu={load_per_cpu:.2f})")
                    log.error("SHSM emergency circuit breaker killed hung lsphp (load/cpu=%.2f)", load_per_cpu)

    # Adaptive sleep: tighten to 5s during high load or active attack, relax to configured interval when idle
    base_interval = max(3, int(ctx.config.get("security.watch_interval_seconds", 10)))
    next_sleep = max(3, base_interval // 2) if (load_per_cpu >= 1.5 or banned_ips) else base_interval

    return {
        "load_per_cpu": load_per_cpu,
        "banned_ips": banned_ips,
        "actions": actions,
        "breaker_triggered": breaker_triggered,
        "next_sleep": next_sleep,
        "logs_watched": len(state.cached_logs),
    }


def run_watch_loop(
    ctx: Context,
    interval_override: Optional[int] = None,
    once: bool = False,
    dry_run: bool = False,
    on_tick: Optional[Any] = None,
) -> None:
    """Run continuous low-overhead watcher loop until SIGTERM/SIGINT or once=True."""
    state = WatchState()
    stop_requested = False

    def _handle_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    try:
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
    except (ValueError, RuntimeError):
        pass

    while not stop_requested:
        summary = run_watch_tick(ctx, state, dry_run=dry_run)
        if on_tick is not None:
            on_tick(summary)
        if once:
            break
        sleep_s = interval_override if interval_override is not None else int(summary["next_sleep"])
        # Interruptible short sleeps
        end_t = time.monotonic() + max(1, sleep_s)
        while not stop_requested and time.monotonic() < end_t:
            time.sleep(min(1.0, max(0.1, end_t - time.monotonic())))
