"""Execution context shared by collectors, scanners, notifiers and reports."""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from shsm.config import Config
from shsm.core.subprocesses import Runner
from shsm.core.timeutils import utcnow
from shsm.database.connection import Database
from shsm.database.repositories.alerts import AlertsRepo, ReportsRepo
from shsm.database.repositories.findings import CheckRepo, FindingsRepo
from shsm.database.repositories.integrity import IntegrityRepo
from shsm.database.repositories.inventory import InventoryRepo
from shsm.database.repositories.metrics import MetricsRepo
from shsm.database.repositories.runs import RunsRepo
from shsm.utils.logtail import LogTailer


class Context:
    def __init__(self, config: Config, db: Database, runner: Optional[Runner] = None,
                 clock: Optional[Callable[[], datetime]] = None):
        self.config = config
        self.db = db
        self.runner = runner or Runner()
        self.clock = clock or utcnow
        self.metrics = MetricsRepo(db)
        self.findings = FindingsRepo(db)
        self.checks = CheckRepo(db)
        self.inventory = InventoryRepo(db)
        self.runs = RunsRepo(db)
        self.alerts = AlertsRepo(db)
        self.reports = ReportsRepo(db)
        self.integrity = IntegrityRepo(db)
        self.tailer = LogTailer(db)

    def now(self) -> datetime:
        return self.clock()

    @property
    def tz(self) -> str:
        return self.config.timezone

    def threshold(self, name: str) -> float:
        return self.config.threshold(name)
