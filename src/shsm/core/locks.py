"""Non-blocking inter-process locks to prevent overlapping jobs."""

from __future__ import annotations

import os
from typing import Optional

try:  # POSIX
    import fcntl

    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows development hosts
    _HAVE_FCNTL = False
    import msvcrt


class LockBusy(Exception):
    pass


class FileLock:
    """Advisory lock backed by ``flock`` (``msvcrt.locking`` on Windows development machines)."""

    def __init__(self, path: str):
        self.path = path
        self._fh: Optional[object] = None

    def acquire(self) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            fh = open(self.path, "a+b")  # noqa: SIM115 - held until release()
        except (PermissionError, OSError):
            # Fallback to /var/lib/shsm/locks or temp directory if /run/shsm is unwritable
            import tempfile
            fallback_dir = "/var/lib/shsm/locks"
            try:
                os.makedirs(fallback_dir, exist_ok=True)
                self.path = os.path.join(fallback_dir, os.path.basename(self.path))
                fh = open(self.path, "a+b")
            except (PermissionError, OSError):
                tmp_dir = tempfile.gettempdir()
                self.path = os.path.join(tmp_dir, f"shsm_{os.path.basename(self.path)}")
                fh = open(self.path, "a+b")
        try:
            if _HAVE_FCNTL:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # pragma: no cover
                fh.seek(0)
                getattr(msvcrt, "locking")(fh.fileno(), getattr(msvcrt, "LK_NBLCK"), 1)  # noqa: B009
        except OSError as exc:
            fh.close()
            raise LockBusy(self.path) from exc
        self._fh = fh
        try:
            fh.seek(0)
            fh.truncate()
            fh.write(str(os.getpid()).encode())
            fh.flush()
        except OSError:
            pass

    def release(self) -> None:
        fh = self._fh
        if fh is None:
            return
        try:
            if _HAVE_FCNTL:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
            else:  # pragma: no cover
                fh.seek(0)  # type: ignore[attr-defined]
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        except OSError:
            pass
        finally:
            fh.close()  # type: ignore[attr-defined]
            self._fh = None

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()
