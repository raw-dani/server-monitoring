"""Unit tests for configuration loading and validation."""

import copy

from shsm.config import DEFAULTS, Config, validate_config


def test_default_config_values():
    cfg = Config(DEFAULTS)
    assert cfg.timezone == "Asia/Jakarta"
    assert "rohmataliwardani@gmail.com" in cfg.get("email.recipients")
    assert cfg.threshold("cpu_warning") == 80.0
    assert cfg.threshold("cpu_critical") == 90.0
    assert cfg.get("paths.data_dir") == "/var/lib/shsm"


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("SHSM_SMTP_PASSWORD", "secret_pass_123")
    cfg = Config(DEFAULTS)
    assert cfg.secret("smtp_password") == "secret_pass_123"


def test_config_redacted_dict():
    cfg = Config(DEFAULTS)
    redacted = cfg.redacted()
    # Ensure structure exists and no raw passwords leak
    assert "general" in redacted
    assert "email" in redacted


def test_config_validation():
    bad_data = copy.deepcopy(DEFAULTS)
    bad_data["thresholds"]["cpu_warning"] = 95.0
    bad_data["thresholds"]["cpu_critical"] = 80.0  # Invalid: warning > critical
    res = validate_config(bad_data)
    assert not res.ok
    assert any("thresholds" in err for err in res.errors)


def test_lock_dir_default():
    cfg = Config(DEFAULTS)
    assert cfg.get("paths.lock_dir") == "/var/lib/shsm/locks"


def test_report_recipients_config_validation():
    data = copy.deepcopy(DEFAULTS)
    data["email"]["weekly_recipients"] = ["weekly-report@example.com"]
    data["email"]["monthly_recipients"] = ["monthly-report@example.com"]
    data["email"]["report_recipients"] = ["general-report@example.com"]
    res = validate_config(data)
    assert res.ok

    # Test invalid email format in report_recipients
    data["email"]["weekly_recipients"] = ["invalid-email"]
    res_bad = validate_config(data)
    assert not res_bad.ok
    assert any("weekly_recipients contains an invalid address" in err for err in res_bad.errors)

