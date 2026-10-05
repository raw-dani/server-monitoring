"""SQLite access: WAL, foreign keys, busy timeout, versioned migrations, safe backup/restore."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, List, Optional, Sequence

from shsm.core.timeutils import now_iso

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_MIGRATION_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class DatabaseError(Exception):
    pass


class Database:
    def __init__(self, path: Any, busy_timeout_ms: int = 30000, migrations_dir: Optional[Path] = None):
        self.path = str(path)
        self.busy_timeout_ms = busy_timeout_ms
        self.migrations_dir = migrations_dir or MIGRATIONS_DIR
        self._conn: Optional[sqlite3.Connection] = None

    # ---------------------------------------------------------------- connection
    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def _connect(self) -> sqlite3.Connection:
        created = self.path != ":memory:" and not os.path.exists(self.path)
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        try:
            conn = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000.0, isolation_level=None)
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot open database {self.path}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            try:
                mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                if str(mode).lower() != "wal":
                    log.warning("could not enable WAL mode (got %s)", mode)
            except sqlite3.DatabaseError as exc:
                conn.close()
                raise DatabaseError(f"database {self.path} is unreadable or corrupt: {exc}") from exc
        conn.execute("PRAGMA synchronous = NORMAL")
        if created:
            try:
                os.chmod(self.path, 0o660)
            except OSError:
                pass
        return conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ helpers
    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        self.conn.executemany(sql, rows)

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        row = self.conn.execute(sql, params).fetchone()
        return default if row is None or row[0] is None else row[0]

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Write transaction (BEGIN IMMEDIATE) that rolls back on any exception. Re-entrant."""
        conn = self.conn
        if conn.in_transaction:
            conn.execute("SAVEPOINT shsm_nested")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK TO shsm_nested")
                conn.execute("RELEASE shsm_nested")
                raise
            else:
                conn.execute("RELEASE shsm_nested")
            return
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    # --------------------------------------------------------------- migrations
    def available_migrations(self) -> List[Any]:
        found = []
        for p in sorted(self.migrations_dir.glob("*.sql")):
            m = _MIGRATION_RE.match(p.name)
            if not m:
                raise DatabaseError(f"invalid migration file name: {p.name}")
            found.append((int(m.group(1)), m.group(2), p))
        versions = [v for v, _, _ in found]
        if versions != sorted(set(versions)):
            raise DatabaseError("duplicate migration versions")
        return found

    def current_version(self) -> int:
        exists = self.scalar("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
        if not exists:
            return 0
        return int(self.scalar("SELECT MAX(version) FROM schema_migrations", default=0))

    def migrate(self) -> List[int]:
        """Apply pending migrations, each atomically. Returns the list of applied versions."""
        self.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL, checksum TEXT NOT NULL)"
        )
        applied = {r["version"]: r["checksum"] for r in self.query("SELECT version, checksum FROM schema_migrations")}
        done: List[int] = []
        for version, name, path in self.available_migrations():
            sql = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode()).hexdigest()
            if version in applied:
                if applied[version] != checksum:
                    raise DatabaseError(f"migration {version:04d}_{name} was modified after being applied")
                continue
            log.info("applying migration %04d_%s", version, name)
            try:
                self.conn.executescript("BEGIN IMMEDIATE;\n" + sql + "\n")
                self.conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at, checksum) VALUES (?,?,?,?)",
                    (version, name, now_iso(), checksum),
                )
                self.conn.execute("COMMIT")
            except sqlite3.Error as exc:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
                raise DatabaseError(f"migration {version:04d}_{name} failed: {exc}") from exc
            done.append(version)
        return done

    # --------------------------------------------------------- integrity/backup
    def quick_check(self) -> str:
        try:
            return str(self.scalar("PRAGMA quick_check", default="unknown"))
        except sqlite3.DatabaseError as exc:
            return f"error: {exc}"

    def backup_to(self, dest: str) -> str:
        """Consistent online backup using the SQLite backup API (never a raw file copy)."""
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        tmp = dest + ".partial"
        if os.path.exists(tmp):
            os.remove(tmp)
        target = sqlite3.connect(tmp)
        try:
            self.conn.backup(target)
        finally:
            target.close()
        check = sqlite3.connect(tmp)
        try:
            result = check.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            check.close()
        if result != "ok":
            os.remove(tmp)
            raise DatabaseError(f"backup failed integrity check: {result}")
        os.replace(tmp, dest)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest


def restore_database(backup_path: str, db_path: str, keep_safety_copy: bool = True) -> Optional[str]:
    """Replace ``db_path`` with a verified backup. Returns the path of the safety copy (if any)."""
    if not os.path.exists(backup_path):
        raise DatabaseError(f"backup not found: {backup_path}")
    src = sqlite3.connect(backup_path)
    try:
        result = src.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise DatabaseError(f"backup failed integrity check: {result}")
        tables = {r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "schema_migrations" not in tables:
            raise DatabaseError("file is not an SHSM database (schema_migrations missing)")
    finally:
        src.close()
    safety = None
    if os.path.exists(db_path):
        if keep_safety_copy:
            safety = f"{db_path}.pre-restore-{int(time.time())}"
            existing = Database(db_path)
            try:
                existing.backup_to(safety)
            except (DatabaseError, sqlite3.Error):
                shutil.copy2(db_path, safety)
            finally:
                existing.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_path + suffix)
            except FileNotFoundError:
                pass
    shutil.copy2(backup_path, db_path)
    try:
        os.chmod(db_path, 0o660)
    except OSError:
        pass
    return safety
