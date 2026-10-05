"""Redis lightweight monitoring via direct socket RESP or redis-cli."""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Dict, Optional, Tuple

from shsm.collectors.base import human_bytes, threshold_result
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "redis"
CATEGORY = "health"


def _send_redis_command(
    host: str,
    port: int,
    password: Optional[str],
    timeout: float,
    cmd: str,
    use_tls: bool = False,
) -> Tuple[bool, str, float]:
    """Send command using simple RESP over TCP socket and measure round-trip latency in ms."""
    start = time.monotonic()
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        sock: Any
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        with sock:
            sock.settimeout(timeout)
            if password:
                sock.sendall(f"AUTH {password}\r\n".encode())
                auth_resp = sock.recv(1024).decode("utf-8", errors="replace")
                if not auth_resp.startswith("+OK"):
                    return False, f"AUTH failed: {auth_resp.strip()}", 0.0

            sock.sendall(f"{cmd}\r\n".encode())

            # Read response
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if len(data) < 4096 and (b"\r\n" in data):
                    break

            latency_ms = (time.monotonic() - start) * 1000.0
            resp_str = b"".join(chunks).decode("utf-8", errors="replace")
            return True, resp_str, latency_ms

    except Exception as exc:
        return False, str(exc), 0.0


def parse_info_response(text: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()

    enabled = ctx.config.get("redis.enabled", "auto")
    if enabled is False:
        out.check("redis.status", CATEGORY, CheckStatus.NOT_APPLICABLE, "Redis monitoring is disabled", source=SOURCE)
        return out

    host = str(ctx.config.get("redis.host", "127.0.0.1"))
    port = int(ctx.config.get("redis.port", 6379))
    timeout = float(ctx.config.get("redis.timeout_seconds", 5))
    use_tls = bool(ctx.config.get("redis.tls", False))
    password = ctx.config.secret("redis_password")

    # 1. PING & Latency
    ok, resp, latency_ms = _send_redis_command(host, port, password, timeout, "PING", use_tls)
    if not ok:
        if enabled is True:
            out.check("redis.status", CATEGORY, CheckStatus.CRITICAL, f"Redis connection failed: {resp}", source=SOURCE)
            out.finding(
                "redis.status",
                CATEGORY,
                Severity.HIGH,
                Confidence.CONFIRMED,
                "Redis server is down or unreachable",
                f"Could not connect to Redis at {host}:{port}. Error: {resp}.",
                "Check if redis-server is running (systemctl status redis-server) and review port/bind configuration.",
                source=SOURCE,
            )
        else:
            out.check("redis.status", CATEGORY, CheckStatus.NOT_APPLICABLE, f"Redis not active ({resp})", source=SOURCE)
        return out

    out.metric("redis.latency_ms", latency_ms)
    warn_lat = ctx.threshold("redis_latency_warning_ms")
    if latency_ms >= warn_lat:
        out.check("redis.status", CATEGORY, CheckStatus.WARNING, f"Redis up with high latency ({latency_ms:.1f}ms)", source=SOURCE)
        out.finding(
            "redis.latency",
            CATEGORY,
            Severity.LOW,
            Confidence.HIGH,
            "Redis latency is elevated",
            f"Redis ping response time is {latency_ms:.1f}ms (warning threshold {warn_lat}ms).",
            "Investigate slow Redis commands (SLOWLOG GET), high CPU usage, or disk persistence (BGSAVE).",
            source=SOURCE,
        )
    else:
        out.check("redis.status", CATEGORY, CheckStatus.PASS, f"Redis up (latency {latency_ms:.1f}ms)", source=SOURCE)

    # 2. INFO
    ok, info_text, _ = _send_redis_command(host, port, password, timeout, "INFO", use_tls)
    if not ok:
        return out

    data = parse_info_response(info_text)

    uptime = float(data.get("uptime_in_seconds", 0))
    used_mem = float(data.get("used_memory", 0))
    max_mem = float(data.get("maxmemory", 0))
    connected_clients = float(data.get("connected_clients", 0))
    hits = float(data.get("keyspace_hits", 0))
    misses = float(data.get("keyspace_misses", 0))
    evicted = float(data.get("evicted_keys", 0))
    expired = float(data.get("expired_keys", 0))

    out.metric("redis.uptime_seconds", uptime)
    out.metric("redis.used_memory_bytes", used_mem)
    out.metric("redis.max_memory_bytes", max_mem)
    out.metric("redis.connected_clients", connected_clients)
    out.metric("redis.evicted_keys", evicted)
    out.metric("redis.expired_keys", expired)

    # Hit ratio
    if (hits + misses) > 0:
        hit_ratio = (hits / (hits + misses)) * 100.0
        out.metric("redis.hit_ratio", hit_ratio)

    # Memory utilization if maxmemory is set
    if max_mem > 0:
        mem_pct = (used_mem / max_mem) * 100.0
        out.metric("redis.memory_percent", mem_pct)
        t = ctx.threshold
        threshold_result(
            out,
            check_id="redis.memory",
            category=CATEGORY,
            asset="redis",
            value=mem_pct,
            warning=t("redis_memory_warning_percent"),
            critical=t("redis_memory_critical_percent"),
            emergency=None,
            label="Redis memory usage",
            unit="%",
            recommendation="Review Redis maxmemory policy (volatile-lru, allkeys-lru) or allocate more memory.",
            source=SOURCE,
            details={"used": human_bytes(used_mem), "max": human_bytes(max_mem)},
        )

    return out
