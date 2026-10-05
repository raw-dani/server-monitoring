"""Standard-library logging with secret redaction."""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from typing import Iterable, List, Optional

from shsm.utils.redact import redact


class RedactingFilter(logging.Filter):
    def __init__(self, secrets: Optional[Iterable[str]] = None):
        super().__init__()
        self.secrets = [s for s in (secrets or []) if s]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = redact(message, self.secrets)
        record.args = None
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info), self.secrets)
            record.exc_info = None
        return True


def setup_logging(level: str = "INFO", log_dir: Optional[str] = None, secrets: Optional[Iterable[str]] = None,
                  console: bool = True, name: str = "shsm") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(logger.handlers):
        logger.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    flt = RedactingFilter(secrets)
    handlers: List[logging.Handler] = []
    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        handlers.append(sh)
    if log_dir:
        try:
            os.makedirs(log_dir, mode=0o750, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, "shsm.log"), maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            fh.setFormatter(fmt)
            handlers.append(fh)
        except OSError:
            pass  # logging to file is best-effort; the console handler still works
    for h in handlers:
        h.addFilter(flt)
        logger.addHandler(h)
    logger.propagate = False
    return logger
