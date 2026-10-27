"""Systemd service and timer unit file generator."""

from __future__ import annotations

import os
from typing import List

from shsm.deploy.schedule import JOBS, JobDef


def generate_service_unit(job: JobDef, bin_path: str = "/opt/shsm/venv/bin/shsm", cfg_path: str = "/etc/shsm/config.yaml") -> str:
    args_str = " ".join(job.argv)
    user_line = "User=root\nGroup=root" if job.root else "User=shsm\nGroup=shsm"
    
    # Resource control & strict throttling to prevent CPU contention
    resource_lines = []
    if job.heavy:
        resource_lines.extend([
            "Nice=19",
            "CPUSchedulingPolicy=idle",
            "IOSchedulingClass=idle",
            "CPUQuota=15%",
            "MemoryHigh=256M",
            "MemoryMax=384M",
            "IOWeight=50",
        ])
    else:
        resource_lines.extend([
            "Nice=19",
            "CPUSchedulingPolicy=idle",
            "IOSchedulingClass=best-effort",
            "IOSchedulingPriority=7",
            "CPUQuota=20%",
            "MemoryHigh=192M",
            "MemoryMax=256M",
            "IOWeight=100",
        ])

    lines = [
        "[Unit]",
        f"Description=SHSM {job.description}",
        "Documentation=https://github.com/gmteknologi/shsm",
        "After=network.target local-fs.target",
        "",
        "[Service]",
        "Type=oneshot",
        user_line,
        f"ExecStart={bin_path} --config {cfg_path} {args_str}",
        f"TimeoutStartSec={job.timeout_seconds}",
        "StandardOutput=journal",
        "StandardError=journal",
    ]
    lines.extend(resource_lines)
    return "\n".join(lines) + "\n"


def generate_timer_unit(job: JobDef) -> str:
    # Only infrequent jobs (daily/weekly/monthly) should be persistent across downtime.
    # Frequent checks (health, services, openlitespeed, ddos, websites) must NOT catch up
    # simultaneously on restart to prevent thundering herd spikes.
    persistent_val = "true" if job.calendar.startswith("0") or "00/" in job.calendar else "false"

    lines = [
        "[Unit]",
        f"Description=SHSM timer for {job.description}",
        "Documentation=https://github.com/gmteknologi/shsm",
        "",
        "[Timer]",
        f"OnCalendar={job.calendar}",
        f"Persistent={persistent_val}",
    ]
    # Add default randomized delay to spread execution load
    delay = job.random_delay if job.random_delay > 0 else 30
    lines.append(f"RandomizedDelaySec={delay}")

    lines.extend([
        f"Unit=shsm-{job.name}.service",
        "",
        "[Install]",
        "WantedBy=timers.target",
    ])
    return "\n".join(lines) + "\n"


def write_all_units(output_dir: str, bin_path: str = "/opt/shsm/venv/bin/shsm", cfg_path: str = "/etc/shsm/config.yaml") -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    generated_files = []
    for job in JOBS:
        svc_name = f"shsm-{job.name}.service"
        timer_name = f"shsm-{job.name}.timer"

        svc_path = os.path.join(output_dir, svc_name)
        with open(svc_path, "w", encoding="utf-8") as fh:
            fh.write(generate_service_unit(job, bin_path, cfg_path))
        generated_files.append(svc_path)

        timer_path = os.path.join(output_dir, timer_name)
        with open(timer_path, "w", encoding="utf-8") as fh:
            fh.write(generate_timer_unit(job))
        generated_files.append(timer_path)

    return generated_files
