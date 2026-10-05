"""Common test fixtures for SHSM test suite."""

from __future__ import annotations

import copy
import os
import tempfile
from typing import Generator

import pytest

from shsm.config import DEFAULTS, Config
from shsm.database.connection import Database


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Provide a temporary directory cleaned up after test."""
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def test_db(temp_dir: str) -> Generator[Database, None, None]:
    """Provide a fresh migrated SQLite database in a temporary directory."""
    db_path = os.path.join(temp_dir, "test_monitoring.db")
    db = Database(path=db_path)
    # Run initial migrations
    db.migrate()
    yield db
    db.close()


@pytest.fixture
def sample_config(temp_dir: str) -> Config:
    """Provide a valid test Config with test paths."""
    config_dict = copy.deepcopy(DEFAULTS)
    config_dict["general"]["server_name"] = "test-vps-cyberpanel"
    config_dict["general"]["timezone"] = "Asia/Jakarta"
    config_dict["paths"]["data_dir"] = temp_dir
    config_dict["paths"]["log_dir"] = temp_dir
    config_dict["paths"]["report_dir"] = os.path.join(temp_dir, "reports")
    config_dict["email"]["enabled"] = False
    config_dict["email"]["recipients"] = ["rohmataliwardani@gmail.com"]
    return Config(config_dict)
