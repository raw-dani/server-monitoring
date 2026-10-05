"""Safe subprocess execution.

Rules enforced here (see spec section 4.2):
* argument arrays only, ``shell=False``;
* mandatory timeout on every call;
* bounded, redacted output;
* explicit, structured handling of missing binaries, timeouts, permission errors and non-zero exits;
* optional privilege drop to a validated non-root Linux user (used for WP-CLI).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from shsm.utils.redact import redact

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_OUTPUT_BYTES = 2 * 1024 * 1024

OK = "ok"
NOT_FOUND = "not_found"
TIMEOUT = "timeout"
PERMISSION = "permission_denied"
NONZERO = "nonzero_exit"
ERROR = "error"
INVALID = "invalid_arguments"

_SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")


@dataclass
class CommandResult:
    args: List[str]
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: str = OK  # one of the constants above
    message: str = ""
    duration: float = 0.0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error == OK

    @property
    def ran(self) -> bool:
        """The process executed to completion (regardless of exit status)."""
        return self.returncode is not None and self.error in (OK, NONZERO)

    def describe(self) -> str:
        if self.error == OK:
            return "ok"
        return f"{self.error}: {self.message}" if self.message else self.error


class Runner:
    """Thin injectable wrapper; tests substitute :class:`FakeRunner`."""

    def which(self, name: str) -> Optional[str]:
        return find_executable(name)

    def run(
        self,
        args: Sequence[str],
        timeout: float = DEFAULT_TIMEOUT,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        input_text: Optional[str] = None,
        max_output: int = MAX_OUTPUT_BYTES,
        ok_returncodes: Sequence[int] = (0,),
    ) -> CommandResult:
        return run_command(
            args,
            timeout=timeout,
            cwd=cwd,
            env=env,
            user=user,
            input_text=input_text,
            max_output=max_output,
            ok_returncodes=ok_returncodes,
        )


_EXTRA_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin")


def find_executable(name: str) -> Optional[str]:
    if os.sep in name:
        return name if os.path.isfile(name) and os.access(name, os.X_OK) else None
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_PATH:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _validate_args(args: Sequence[str]) -> Optional[str]:
    if not args:
        return "empty command"
    for a in args:
        if not isinstance(a, str):
            return "all arguments must be strings"
        if "\x00" in a:
            return "NUL byte in argument"
    return None


def _truncate(data: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    return data.decode("utf-8", errors="replace"), truncated


def _clean_env(extra: Optional[Dict[str, str]]) -> Dict[str, str]:
    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env.setdefault("LANG", "C.UTF-8")
    if extra:
        env.update(extra)
    return env


def resolve_user(username: str):
    """Return (uid, gid, home, supplementary_gids) for ``username`` on Linux; raises KeyError/OSError."""
    import grp
    import pwd

    pw = pwd.getpwnam(username)
    groups = [g.gr_gid for g in grp.getgrall() if username in g.gr_mem and g.gr_gid != pw.pw_gid]
    return pw.pw_uid, pw.pw_gid, pw.pw_dir, groups


def run_command(
    args: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    user: Optional[str] = None,
    input_text: Optional[str] = None,
    max_output: int = MAX_OUTPUT_BYTES,
    ok_returncodes: Sequence[int] = (0,),
) -> CommandResult:
    argv = [str(a) for a in args]
    err = _validate_args(argv)
    if err:
        return CommandResult(argv, error=INVALID, message=err)
    if timeout is None or timeout <= 0:
        return CommandResult(argv, error=INVALID, message="a positive timeout is required")

    exe = find_executable(argv[0])
    if exe is None:
        return CommandResult(argv, error=NOT_FOUND, message=f"{argv[0]}: command not found")
    argv[0] = exe

    kwargs: Dict[str, object] = {}
    if user is not None:
        if not hasattr(os, "geteuid"):
            return CommandResult(argv, error=INVALID, message="privilege drop is only supported on Linux")
        try:
            uid, gid, home, groups = resolve_user(user)
        except (KeyError, ImportError, OSError) as exc:
            return CommandResult(argv, error=INVALID, message=f"cannot resolve user {user!r}: {exc}")
        if uid == 0:
            return CommandResult(argv, error=INVALID, message="refusing to run as root user")
        if os.geteuid() != 0 and os.geteuid() != uid:
            return CommandResult(
                argv, error=PERMISSION, message=f"cannot switch to user {user!r}: SHSM is not running as root"
            )
        if os.geteuid() == 0:
            kwargs.update(user=uid, group=gid, extra_groups=groups)
        env = dict(env or {})
        env.setdefault("HOME", home)
        env.setdefault("USER", user)
        env.setdefault("LOGNAME", user)

    start = time.monotonic()
    try:
        proc = subprocess.run(  # type: ignore[call-overload]
            argv,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            env=_clean_env(env),
            input=input_text.encode() if input_text is not None else None,
            shell=False,
            check=False,
            **kwargs,
        )
    except subprocess.TimeoutExpired as exc:
        out, _ = _truncate(exc.stdout or b"", max_output) if isinstance(exc.stdout, bytes) else ("", False)
        return CommandResult(
            argv, error=TIMEOUT, message=f"timed out after {timeout}s", stdout=redact(out),
            duration=time.monotonic() - start,
        )
    except FileNotFoundError as exc:
        return CommandResult(argv, error=NOT_FOUND, message=redact(str(exc)))
    except PermissionError as exc:
        return CommandResult(argv, error=PERMISSION, message=redact(str(exc)))
    except OSError as exc:
        return CommandResult(argv, error=ERROR, message=redact(str(exc)))

    out, t1 = _truncate(proc.stdout, max_output)
    errtxt, t2 = _truncate(proc.stderr, max_output)
    status = OK if proc.returncode in ok_returncodes else NONZERO
    res = CommandResult(
        argv,
        returncode=proc.returncode,
        stdout=redact(out),
        stderr=redact(errtxt),
        error=status,
        message="" if status == OK else f"exit status {proc.returncode}",
        duration=time.monotonic() - start,
        truncated=t1 or t2,
    )
    if proc.returncode is not None and "permission denied" in errtxt.lower() and status != OK:
        res.message = (res.message + "; permission denied").strip("; ")
    return res


@dataclass
class FakeRunner(Runner):
    """Deterministic runner for tests: map ``tuple(argv)`` prefixes or callables to results."""

    responses: Dict[str, CommandResult] = field(default_factory=dict)
    calls: List[List[str]] = field(default_factory=list)
    available: Optional[set] = None  # names reported by which(); None = all

    def which(self, name: str) -> Optional[str]:
        if self.available is None or name in self.available:
            return "/usr/bin/" + name
        return None

    def run(self, args, timeout=DEFAULT_TIMEOUT, cwd=None, env=None, user=None, input_text=None,
            max_output=MAX_OUTPUT_BYTES, ok_returncodes=(0,)) -> CommandResult:
        argv = [str(a) for a in args]
        self.calls.append(argv)
        key = " ".join(argv)
        best = None
        for prefix, res in self.responses.items():
            if key.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
                best = (prefix, res)
        if best is None:
            return CommandResult(argv, error=NOT_FOUND, message=f"{argv[0]}: not mocked")
        res = best[1]
        return CommandResult(argv, res.returncode, res.stdout, res.stderr, res.error, res.message)

    @staticmethod
    def ok(stdout: str = "", rc: int = 0, stderr: str = "") -> CommandResult:
        return CommandResult([], rc, stdout, stderr, OK if rc == 0 else NONZERO, "" if rc == 0 else f"exit status {rc}")
