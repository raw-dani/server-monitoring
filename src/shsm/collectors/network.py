"""Network metrics: interface counters, error rates, connection summaries, and suspicious outbound checks."""

from __future__ import annotations

from typing import Any, Dict, List

import psutil

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.core.timeutils import from_iso

SOURCE = "psutil/net"
CATEGORY = "health"


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    # --- 1. Interface I/O and errors
    try:
        net_io = psutil.net_io_counters(pernic=True)
    except Exception as exc:
        net_io = {}
        out.error(f"network.io: cannot get net_io_counters: {exc}")

    total_err_in = 0
    total_err_out = 0
    total_drop_in = 0
    total_drop_out = 0

    for iface, io in net_io.items():
        if iface.startswith(("lo", "docker", "veth", "br-")):
            continue

        out.metric("net.bytes_sent", io.bytes_sent, iface)
        out.metric("net.bytes_recv", io.bytes_recv, iface)
        out.metric("net.errin", io.errin, iface)
        out.metric("net.errout", io.errout, iface)
        out.metric("net.dropin", io.dropin, iface)
        out.metric("net.dropout", io.dropout, iface)

        total_err_in += io.errin
        total_err_out += io.errout
        total_drop_in += io.dropin
        total_drop_out += io.dropout

        # Calculate rate if previous sample exists
        prev = ctx.metrics.latest("net.bytes_recv", iface)
        if prev and io.bytes_recv >= prev[1]:
            dt = (now - from_iso(prev[0])).total_seconds()
            if dt > 0:
                out.metric("net.recv_bytes_per_s", (io.bytes_recv - prev[1]) / dt, iface)

        prev_sent = ctx.metrics.latest("net.bytes_sent", iface)
        if prev_sent and io.bytes_sent >= prev_sent[1]:
            dt = (now - from_iso(prev_sent[0])).total_seconds()
            if dt > 0:
                out.metric("net.sent_bytes_per_s", (io.bytes_sent - prev_sent[1]) / dt, iface)

    # Errors rate evaluation
    prev_err = ctx.metrics.latest("net.total_errors")
    out.metric("net.total_errors", total_err_in + total_err_out)
    out.metric("net.total_dropped", total_drop_in + total_drop_out)

    warn_rate = ctx.threshold("network_error_rate_warning_per_minute")
    error_rate = 0.0
    if prev_err and (total_err_in + total_err_out) >= prev_err[1]:
        dt = (now - from_iso(prev_err[0])).total_seconds()
        if dt > 10:
            error_rate = ((total_err_in + total_err_out) - prev_err[1]) / (dt / 60.0)

    if error_rate >= warn_rate:
        out.check(
            "network.errors",
            CATEGORY,
            CheckStatus.WARNING,
            f"Network error rate is high ({error_rate:.1f} errors/min)",
            source=SOURCE,
        )
        out.finding(
            "network.errors",
            CATEGORY,
            Severity.LOW,
            Confidence.HIGH,
            "Network interface packet errors detected",
            f"Observed {error_rate:.1f} errors/min (warning threshold {warn_rate:.1f}/min). "
            f"Total errors: {total_err_in + total_err_out}, dropped packets: {total_drop_in + total_drop_out}.",
            "Check VPS host connectivity, duplex/MTU settings, or provider network status.",
            source=SOURCE,
        )
    else:
        out.check(
            "network.errors",
            CATEGORY,
            CheckStatus.PASS,
            f"Network packet errors normal ({total_err_in + total_err_out} total errors, {total_drop_in + total_drop_out} dropped)",
            source=SOURCE,
        )

    # --- 2. TCP Connections summary
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        conns = []
        out.check(
            "network.connections",
            CATEGORY,
            CheckStatus.UNKNOWN,
            f"insufficient privileges to inspect all connections: {exc}",
            source=SOURCE,
        )
    except Exception as exc:
        conns = []
        out.check("network.connections", CATEGORY, CheckStatus.ERROR, f"error listing connections: {exc}", source=SOURCE)

    if conns:
        counts: Dict[str, int] = {}
        established = 0
        listening = 0
        for c in conns:
            st = c.status
            counts[st] = counts.get(st, 0) + 1
            if st == psutil.CONN_ESTABLISHED:
                established += 1
            elif st == psutil.CONN_LISTEN:
                listening += 1

        out.metric("net.tcp_established", established)
        out.metric("net.tcp_listening", listening)
        out.metric("net.tcp_total", len(conns))

        out.check(
            "network.connections",
            CATEGORY,
            CheckStatus.PASS,
            f"{established} established, {listening} listening, {len(conns)} total network sockets",
            source=SOURCE,
            details=counts,
        )

    # --- 3. Suspicious Outbound Connections (Attribution)
    _check_suspicious_outbound(ctx, conns, out)

    return out


def _check_suspicious_outbound(ctx: Context, conns: List[Any], out: CollectorOutput) -> None:
    suspicious_procs = set(ctx.config.get("security.suspicious_outbound_processes", []))
    if not suspicious_procs or not conns:
        return

    pid_to_name: Dict[int, str] = {}
    flagged: List[Dict[str, Any]] = []

    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        pid = c.pid
        if not pid:
            continue

        if pid not in pid_to_name:
            try:
                proc = psutil.Process(pid)
                pid_to_name[pid] = proc.name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pid_to_name[pid] = ""

        pname = pid_to_name[pid]
        if pname in suspicious_procs:
            r_ip = c.raddr.ip if hasattr(c.raddr, "ip") else str(c.raddr[0])
            r_port = c.raddr.port if hasattr(c.raddr, "port") else int(c.raddr[1])
            # Filter loopback/private destinations if not dangerous, but shells connecting out is suspicious
            flagged.append({
                "pid": pid,
                "process": pname,
                "remote_ip": r_ip,
                "remote_port": r_port,
            })

    if flagged:
        for item in flagged:
            out.finding(
                "network.outbound",
                "security",
                Severity.CRITICAL,
                Confidence.HIGH,
                f"Suspicious outbound interactive shell connection ({item['process']})",
                f"Process {item['process']} (PID {item['pid']}) has an established outbound connection to {item['remote_ip']}:{item['remote_port']}.",
                "Inspect the process immediately (pwdx <pid>, lsof -p <pid>). This may indicate an active reverse shell or remote code execution compromise.",
                asset=f"{item['process']}:{item['pid']}",
                source=SOURCE,
                key=f"{item['pid']}:{item['remote_ip']}:{item['remote_port']}",
            )
        out.check(
            "network.outbound",
            "security",
            CheckStatus.CRITICAL,
            f"Detected {len(flagged)} suspicious outbound process connection(s)",
            source=SOURCE,
        )
    else:
        out.check(
            "network.outbound",
            "security",
            CheckStatus.PASS,
            "No suspicious outbound connections from interactive shells detected",
            source=SOURCE,
        )
