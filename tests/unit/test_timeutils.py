"""Unit tests for time conversion and reporting window calculations."""

from datetime import datetime, timezone

from shsm.core.timeutils import (
    from_iso,
    monthly_period,
    to_iso,
    to_local,
    utcnow,
    weekly_period,
)


def test_utcnow_is_timezone_aware():
    now = utcnow()
    assert now.tzinfo == timezone.utc


def test_to_iso_formatting():
    dt = datetime(2026, 10, 5, 2, 30, 0, tzinfo=timezone.utc)
    iso = to_iso(dt)
    assert iso == "2026-10-05T02:30:00Z"


def test_from_iso_parsing():
    iso = "2026-10-05T02:30:00Z"
    dt = from_iso(iso)
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 5
    assert dt.tzinfo == timezone.utc


def test_to_local_jakarta_timezone():
    # 02:00 UTC should be 09:00 in Asia/Jakarta (UTC+7)
    utc_dt = datetime(2026, 10, 5, 2, 0, 0, tzinfo=timezone.utc)
    local_dt = to_local(utc_dt, "Asia/Jakarta")
    assert local_dt.hour == 9
    assert local_dt.day == 5


def test_weekly_period():
    now = utcnow()
    start, end = weekly_period(now, "Asia/Jakarta")
    assert start < end
    delta = end - start
    assert delta.days == 7


def test_monthly_period():
    now = utcnow()
    start, end = monthly_period(now, "Asia/Jakarta")
    assert start < end
    assert start.day == 1
    assert end.day == 1
