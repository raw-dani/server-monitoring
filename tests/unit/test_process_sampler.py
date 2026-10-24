import sys
from unittest.mock import MagicMock

# Mock psutil if not installed in environment
if "psutil" not in sys.modules:
    sys.modules["psutil"] = MagicMock()

from shsm.collectors.process import format_top, top_by, _USER_CACHE, _safe_user


def test_format_top_with_active_processes():
    rows = [
        {"pid": 101, "name": "lsphp", "cpu": 78.4, "rss": 200000000},
        {"pid": 102, "name": "mysqld", "cpu": 15.6, "rss": 500000000},
        {"pid": 103, "name": "shsm", "cpu": 0.2, "rss": 30000000},
    ]
    formatted = format_top(rows, "cpu")
    assert "lsphp[101] 78%" in formatted
    assert "mysqld[102] 16%" in formatted
    assert "shsm" not in formatted  # shsm with negligible CPU is excluded


def test_format_top_when_only_shsm_visible():
    rows = [
        {"pid": 3224660, "name": "shsm", "cpu": 0.0, "rss": 45000000},
    ]
    formatted = format_top(rows, "cpu")
    assert "insufficient privileges" in formatted
    assert "3224660" not in formatted  # never report itself as 0% culprit


def test_format_top_when_all_idle():
    rows = [{"pid": i, "name": f"worker_{i}", "cpu": 0.0, "rss": 10000000} for i in range(10)]
    formatted = format_top(rows, "cpu")
    assert "none active during 1s sample" in formatted


def test_format_top_memory():
    rows = [
        {"pid": 201, "name": "mariadbd", "rss": 524288000},  # 500 MiB
        {"pid": 202, "name": "lshttpd", "rss": 104857600},   # 100 MiB
    ]
    formatted = format_top(rows, "rss")
    assert "mariadbd[201] 500 MiB" in formatted
    assert "lshttpd[202] 100 MiB" in formatted


def test_safe_user_caching():
    _USER_CACHE.clear()
    proc_mock = MagicMock()
    uids_mock = MagicMock()
    uids_mock.real = 1001
    proc_mock.uids.return_value = uids_mock
    proc_mock.username.return_value = "webuser1"

    u1 = _safe_user(proc_mock)
    assert u1 == "webuser1"
    assert 1001 in _USER_CACHE

    # Calling again should use cache without invoking username()
    proc_mock.username.reset_mock()
    u2 = _safe_user(proc_mock)
    assert u2 == "webuser1"
    proc_mock.username.assert_not_called()
