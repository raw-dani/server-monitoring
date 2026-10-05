"""MariaDB/MySQL lightweight monitoring: status, connections, slow queries, InnoDB metrics, and error logs."""

from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from shsm.collectors.base import threshold_result
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "mariadb"
CATEGORY = "health"


def _find_mysql_client(ctx: Context) -> Optional[str]:
    cfg_bin = ctx.config.get("mariadb.binary")
    if cfg_bin and cfg_bin != "auto":
        return ctx.runner.which(cfg_bin)
    for cand in ("mariadb", "mysql"):
        p = ctx.runner.which(cand)
        if p:
            return p
    return None


def _run_query(ctx: Context, query: str) -> Tuple[bool, str, str]:
    """Execute a read-only query using local socket / defaults file without exposing passwords on CLI."""
    client = _find_mysql_client(ctx)
    if not client:
        return False, "", "mysql/mariadb client binary not found"

    args = [client, "--batch", "--raw", "--silent", "-e", query]

    defaults_file = ctx.config.secret_path("mariadb_defaults")
    if defaults_file and os.path.isfile(defaults_file):
        args.insert(1, f"--defaults-file={defaults_file}")
    else:
        # Check standard defaults locations if readable
        for std in ("/etc/mysql/debian.cnf", "/root/.my.cnf"):
            if os.path.isfile(std) and os.access(std, os.R_OK):
                args.insert(1, f"--defaults-file={std}")
                break

    socket_path = ctx.config.get("mariadb.socket")
    if socket_path and os.path.exists(socket_path):
        args.extend(["--socket", socket_path])
    elif ctx.config.get("mariadb.host"):
        args.extend(["--host", str(ctx.config.get("mariadb.host"))])
        args.extend(["--port", str(ctx.config.get("mariadb.port", 3306))])

    timeout = float(ctx.config.get("mariadb.timeout_seconds", 15))
    res = ctx.runner.run(args, timeout=timeout)
    return res.ok, res.stdout, res.stderr


def parse_name_value_tsv(stdout: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for line in stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            res[parts[0].strip()] = parts[1].strip()
    return res


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()

    # Check if enabled
    enabled = ctx.config.get("mariadb.enabled", "auto")
    if enabled is False:
        out.check("mariadb.status", CATEGORY, CheckStatus.NOT_APPLICABLE, "MariaDB monitoring is disabled", source=SOURCE)
        return out

    client = _find_mysql_client(ctx)
    if not client:
        if enabled is True:
            out.check("mariadb.status", CATEGORY, CheckStatus.ERROR, "MariaDB client not found but monitoring is explicitly enabled", source=SOURCE)
        else:
            out.check("mariadb.status", CATEGORY, CheckStatus.NOT_APPLICABLE, "MariaDB client not found", source=SOURCE)
        return out

    # 1. Ping / basic status
    ok, stdout, stderr = _run_query(ctx, "SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Max_used_connections','Aborted_connects','Slow_queries','Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests'); SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections','slow_query_log');")
    if not ok:
        out.check("mariadb.status", CATEGORY, CheckStatus.CRITICAL, f"Cannot connect to MariaDB: {stderr[:150]}", source=SOURCE)
        out.finding(
            "mariadb.status",
            CATEGORY,
            Severity.CRITICAL,
            Confidence.CONFIRMED,
            "MariaDB database is down or inaccessible",
            f"Failed to execute query against local MariaDB. Error: {stderr[:250]}.",
            "Check if mariadb/mysql service is running (systemctl status mariadb) and verify local client credentials.",
            source=SOURCE,
        )
        return out

    data = parse_name_value_tsv(stdout)
    out.check("mariadb.status", CATEGORY, CheckStatus.PASS, f"MariaDB is up (uptime {data.get('Uptime', '?')}s)", source=SOURCE)

    uptime = float(data.get("Uptime", 0))
    threads_connected = float(data.get("Threads_connected", 0))
    max_connections = float(data.get("max_connections", 100))
    slow_queries = float(data.get("Slow_queries", 0))
    aborted_connects = float(data.get("Aborted_connects", 0))

    out.metric("mariadb.uptime_seconds", uptime)
    out.metric("mariadb.threads_connected", threads_connected)
    out.metric("mariadb.max_connections", max_connections)
    out.metric("mariadb.slow_queries", slow_queries)
    out.metric("mariadb.aborted_connects", aborted_connects)

    # Connection saturation check
    conn_pct = (threads_connected / max_connections * 100.0) if max_connections > 0 else 0.0
    out.metric("mariadb.connections_percent", conn_pct)

    t = ctx.threshold
    threshold_result(
        out,
        check_id="mariadb.connections",
        category=CATEGORY,
        asset="mariadb",
        value=conn_pct,
        warning=t("mariadb_connections_warning_percent"),
        critical=t("mariadb_connections_critical_percent"),
        emergency=t("mariadb_connections_emergency_percent"),
        label="MariaDB active connections",
        unit="%",
        recommendation="Check for hung MySQL connections, unclosed pool sessions, or adjust max_connections in my.cnf.",
        source=SOURCE,
        details={"connected": threads_connected, "max": max_connections},
    )

    # InnoDB buffer pool hit ratio
    reads = float(data.get("Innodb_buffer_pool_reads", 0))
    reqs = float(data.get("Innodb_buffer_pool_read_requests", 0))
    if reqs > 0:
        hit_ratio = ((reqs - reads) / reqs) * 100.0
        out.metric("mariadb.innodb_hit_ratio", hit_ratio)

    # 2. Database sizes (Daily or periodic)
    _collect_sizes(ctx, out)

    return out


def _collect_sizes(ctx: Context, out: CollectorOutput) -> None:
    now = ctx.now()
    last = ctx.runs.kv_get("mariadb.sizes.last")
    from shsm.core.timeutils import from_iso, to_iso

    interval = int(ctx.config.get("mariadb.size_interval_seconds", 86400))
    if last and (now - from_iso(last)).total_seconds() < interval:
        return

    query = "SELECT table_schema, ROUND(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys') GROUP BY table_schema;"
    ok, stdout, stderr = _run_query(ctx, query)
    if not ok:
        return

    total_size = 0.0
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].replace(".", "", 1).isdigit():
            db_name = parts[0]
            db_size = float(parts[1])
            total_size += db_size
            out.metric("mariadb.database_size_bytes", db_size, asset=db_name)

    out.metric("mariadb.total_size_bytes", total_size)
    ctx.runs.kv_set("mariadb.sizes.last", to_iso(now), now)
