"""Job execution runner: locking, lifecycle tracking, result persistence, and alert dispatching."""

from __future__ import annotations

import logging
import os
import time
from typing import Callable, Tuple

from shsm.core.context import Context
from shsm.core.findings import CollectorOutput
from shsm.core.locks import FileLock, LockBusy
from shsm.deploy.schedule import HEAVY_LOCK, JOBS_BY_NAME
from shsm.notifications.alerts import AlertManager

log = logging.getLogger(__name__)


class RunnerEngine:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.alert_mgr = AlertManager(ctx)

    def run_job(
        self,
        job_name: str,
        collector_fn: Callable[[], CollectorOutput],
        profile: str = "default",
    ) -> Tuple[int, CollectorOutput]:
        """Execute a job wrapped in file locks, DB run lifecycle tracking, and finding reconciliation."""
        now = self.ctx.now()
        lock_dir = str(self.ctx.config.get("paths.lock_dir", "/run/shsm"))
        os.makedirs(lock_dir, exist_ok=True)

        job_def = JOBS_BY_NAME.get(job_name)
        is_heavy = job_def.heavy if job_def else False

        job_lock = FileLock(os.path.join(lock_dir, f"{job_name}.lock"))
        heavy_lock = FileLock(os.path.join(lock_dir, f"{HEAVY_LOCK}.lock")) if is_heavy else None

        try:
            job_lock.acquire()
        except LockBusy:
            log.warning("Job %s is already running; skipping overlapping execution", job_name)
            return 0, CollectorOutput(errors=[f"Job {job_name} is locked by another process"])

        if heavy_lock:
            try:
                heavy_lock.acquire()
            except LockBusy:
                job_lock.release()
                log.warning("Heavy scan is already running; skipping %s", job_name)
                return 0, CollectorOutput(errors=["A heavy scan is already running"])

        run_id = self.ctx.runs.start(job_name, profile, now)
        start_time = time.monotonic()
        out = CollectorOutput()
        status_str = "SUCCESS"
        exit_code = 0

        try:
            out = collector_fn()
            now_finish = self.ctx.now()

            # 1. Persist metrics
            if out.metrics:
                self.ctx.metrics.insert(now_finish, out.metrics)

            # 2. Persist checks
            if out.checks:
                self.ctx.checks.upsert_many(out.checks, now_finish)

            # 3. Reconcile findings & auto-resolve
            conclusive_pairs = [
                (c.check_id, c.asset) for c in out.checks if c.status.conclusive
            ]
            recon_events = self.ctx.findings.record_run(
                out.findings,
                out.scopes,
                now_finish,
                pairs=conclusive_pairs,
            )

            # 4. Trigger alert manager
            resolved_ids = recon_events.get("RESOLVED", [])
            self.alert_mgr.process_findings(out.findings, resolved_ids)

            if not out.complete:
                status_str = "PARTIAL"
                exit_code = 1
            elif out.errors:
                status_str = "PARTIAL"
                exit_code = 0

        except Exception as exc:
            log.exception("Error executing job %s: %s", job_name, exc)
            status_str = "FAILED"
            exit_code = 2
            out.error(str(exc))
            out.complete = False

        finally:
            duration = time.monotonic() - start_time
            summary_dict = {
                "metrics_count": len(out.metrics),
                "checks_count": len(out.checks),
                "findings_count": len(out.findings),
            }
            summary_dict.update(out.meta)

            self.ctx.runs.finish(
                run_id,
                self.ctx.now(),
                status_str,
                out.complete,
                exit_code,
                summary_dict,
                out.errors,
                out.tool_versions,
                duration,
            )

            if heavy_lock:
                heavy_lock.release()
            job_lock.release()

        return exit_code, out
