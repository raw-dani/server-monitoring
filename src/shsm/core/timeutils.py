"""Time helpers. All timestamps are stored as UTC ISO-8601 text and rendered in the configured timezone."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Tuple
from zoneinfo import ZoneInfo

UTC = timezone.utc
ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_TZ = "Asia/Jakarta"


def utcnow() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("naive datetime is not allowed")
    return dt.astimezone(UTC).strftime(ISO_FMT)


def from_iso(text: str) -> datetime:
    return datetime.strptime(text, ISO_FMT).replace(tzinfo=UTC)


def now_iso() -> str:
    return to_iso(utcnow())


def get_tz(name: str = DEFAULT_TZ) -> ZoneInfo:
    return ZoneInfo(name)


def to_local(dt: datetime, tz_name: str = DEFAULT_TZ) -> datetime:
    return dt.astimezone(get_tz(tz_name))


def format_local(iso_or_dt, tz_name: str = DEFAULT_TZ, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
    if iso_or_dt in (None, ""):
        return "-"
    dt = from_iso(iso_or_dt) if isinstance(iso_or_dt, str) else iso_or_dt
    return to_local(dt, tz_name).strftime(fmt)


def weekly_period(now: datetime, tz_name: str = DEFAULT_TZ) -> Tuple[datetime, datetime]:
    """Previous Monday 00:00 (inclusive) to this Monday 00:00 (exclusive), in local time, as aware datetimes."""
    tz = get_tz(tz_name)
    local = now.astimezone(tz)
    this_monday = datetime(local.year, local.month, local.day, tzinfo=tz) - timedelta(days=local.weekday())
    start = _local_midnight(this_monday - timedelta(days=7), tz)
    end = _local_midnight(this_monday, tz)
    return start, end


def monthly_period(now: datetime, tz_name: str = DEFAULT_TZ) -> Tuple[datetime, datetime]:
    """First day of the previous calendar month (inclusive) to first day of this month (exclusive)."""
    tz = get_tz(tz_name)
    local = now.astimezone(tz)
    this_first = datetime(local.year, local.month, 1, tzinfo=tz)
    if local.month == 1:
        prev_first = datetime(local.year - 1, 12, 1, tzinfo=tz)
    else:
        prev_first = datetime(local.year, local.month - 1, 1, tzinfo=tz)
    return prev_first, this_first


def _local_midnight(dt: datetime, tz: ZoneInfo) -> datetime:
    return datetime(dt.year, dt.month, dt.day, tzinfo=tz)


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
