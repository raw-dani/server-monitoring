"""Systemd service and timer unit file generator."""

from __future__ import annotations

import os
from typing import List

from shsm.deploy.schedule import JOBS, JobDef


def generate_service_unit(job: JobDef, bin_path: str = "/opt/shsm/venv/bin/shsm", cfg_path: str = "/etc/shsm/config.yaml") -> str:
    args_str = " ".join(job.argv)
    user_line = "User=root\nGroup=root" if job.root else "User=shsm\nGroup=shsm"
    nice_line = "Nice=19\nIOSchedulingClass=best-effort\nIOSchedulingPriority=7" if job.heavy else ""

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
    if nice_line:
        lines.append(nice_line)
    return "\n".join(lines) + "\n"


def generate_timer_unit(job: JobDef) -> str:
    lines = [
        "[Unit]",
        f"Description=SHSM timer for {job.description}",
        "Documentation=https://github.com/gmteknologi/shsm",
        "",
        "[Timer]",
        f"OnCalendar={job.calendar}",
        "Persistent=true",
    ]
    if job.random_delay > 0:
        lines.append(f"RandomizedDelaySec={job.random_delay}")
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
