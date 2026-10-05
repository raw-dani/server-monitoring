"""Bounded exponential backoff retry."""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional, Tuple, Type, TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)


class PermanentError(Exception):
    """Raise from the callable to stop retrying immediately."""


def backoff_delays(retries: int, base: float, maximum: float) -> list:
    return [min(maximum, base * (2 ** i)) for i in range(retries)]


def retry_call(
    fn: Callable[[], T],
    retries: int,
    base_delay: float = 2.0,
    max_delay: float = 60.0,
    retry_on: Tuple[Type[BaseException], ...] = (Exception,),
    sleep: Callable[[float], None] = time.sleep,
    on_attempt: Optional[Callable[[int, Optional[BaseException]], None]] = None,
) -> Tuple[T, int]:
    """Call ``fn`` up to ``retries + 1`` times. Returns ``(result, attempts)``; re-raises the last error."""
    delays = backoff_delays(retries, base_delay, max_delay)
    attempt = 0
    while True:
        attempt += 1
        try:
            result = fn()
            if on_attempt:
                on_attempt(attempt, None)
            return result, attempt
        except PermanentError:
            raise
        except retry_on as exc:
            if on_attempt:
                on_attempt(attempt, exc)
            if attempt > retries:
                raise
            delay = delays[attempt - 1]
            log.debug("attempt %d failed (%s); retrying in %.1fs", attempt, type(exc).__name__, delay)
            sleep(delay)
