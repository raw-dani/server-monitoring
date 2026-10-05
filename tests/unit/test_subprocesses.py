"""Unit tests for safe subprocess execution."""

import sys

from shsm.core.subprocesses import TIMEOUT, Runner


def test_runner_basic_command():
    runner = Runner()
    cmd = [sys.executable, "-c", "print('hello shsm')"]
    res = runner.run(cmd, timeout=5)
    assert res.ok is True
    assert res.returncode == 0
    assert "hello shsm" in res.stdout


def test_runner_timeout():
    runner = Runner()
    cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
    res = runner.run(cmd, timeout=0.5)
    assert res.error == TIMEOUT
    assert res.ok is False


def test_runner_redacts_secrets_in_output():
    runner = Runner()
    cmd = [sys.executable, "-c", "print('password=SuperSecretPass999')"]
    res = runner.run(cmd, timeout=5)
    assert "SuperSecretPass999" not in res.stdout
    assert "[REDACTED]" in res.stdout
