"""Durable, owner-bound approval and operation state for the optional runner."""

from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
import uuid
from typing import Any, Iterator, NoReturn

from .protocol import RunnerError, binding, canonical_json, decode_json, fingerprint


_DB_NAME = "state.sqlite3"
_MAX_ROWS_PER_TABLE = 1000
_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_PAGE_SIZE = 4096
_MAX_PAGE_COUNT = _MAX_DATABASE_BYTES // _PAGE_SIZE
_BUSY_TIMEOUT_SECONDS = 1.0
_BUSY_TIMEOUT_MS = int(_BUSY_TIMEOUT_SECONDS * 1000)
_JSON_LIMIT = 65536
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MUTATIONS = frozenset(("start", "submit", "answer", "cancel"))
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _error(code: str) -> NoReturn:
    raise RunnerError(code) from None


def _raise_sqlite(exc: sqlite3.Error) -> NoReturn:
    result = getattr(exc, "sqlite_errorcode", None)
    if result is not None and (result & 0xFF) == sqlite3.SQLITE_FULL:
        _error("resource_limit")
    if isinstance(exc, sqlite3.IntegrityError):
        _error("request_conflict")
    _error("state_unavailable")


def _open_private_directory(state_dir: Path) -> tuple[int, Path]:
    try:
        path = Path(state_dir)
        if not path.is_absolute() or ".." in path.parts:
            _error("state_unavailable")
        fd = os.open("/", _DIR_FLAGS)
        try:
            for component in path.parts[1:]:
                if component in ("", ".", ".."):
                    _error("state_unavailable")
                next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            info = os.fstat(fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                _error("state_unavailable")
            return fd, path
        except BaseException:
            os.close(fd)
            raise
    except RunnerError:
        raise
    except (OSError, TypeError, ValueError):
        _error("state_unavailable")


def _validate_database_file(directory_fd: int, *, limit_size: bool = True) -> os.stat_result:
    try:
        info = os.stat(_DB_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            _error("state_unavailable")
        fd = os.open(_DB_NAME, _READ_FLAGS, dir_fd=directory_fd)
        try:
            opened = os.fstat(fd)
            current = os.stat(_DB_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or (
                current.st_dev,
                current.st_ino,
            ) != (info.st_dev, info.st_ino):
                _error("state_unavailable")
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_nlink != 1
            ):
                _error("state_unavailable")
            if limit_size and opened.st_size > _MAX_DATABASE_BYTES:
                _error("resource_limit")
            return opened
        finally:
            os.close(fd)
    except RunnerError:
        raise
    except (OSError, TypeError, ValueError):
        _error("state_unavailable")


def _database_uri(path: Path) -> str:
    return path.as_uri() + "?mode=rw"


def _connect(path: Path, *, initialize: bool = False) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            _database_uri(path),
            timeout=_BUSY_TIMEOUT_SECONDS,
            isolation_level=None,
            uri=True,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            if initialize:
                connection.execute(f"PRAGMA page_size={_PAGE_SIZE}")
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            if page_size != _PAGE_SIZE:
                _error("state_unavailable")
            max_pages = connection.execute(f"PRAGMA max_page_count={_MAX_PAGE_COUNT}").fetchone()[0]
            if max_pages > _MAX_PAGE_COUNT:
                _error("state_unavailable")
            return connection
        except BaseException:
            connection.close()
            raise
    except RunnerError:
        raise
    except sqlite3.Error as exc:
        _raise_sqlite(exc)
    except (OSError, ValueError):
        _error("state_unavailable")


def _json_bytes(value: object, *, code: str = "invalid_request") -> bytes:
    try:
        encoded = canonical_json(value)
    except RunnerError as exc:
        _error("resource_limit" if exc.code == "resource_limit" else code)
    except (TypeError, ValueError, OverflowError):
        _error(code)
    if not isinstance(encoded, bytes):
        _error(code)
    if len(encoded) > _JSON_LIMIT:
        _error("resource_limit")
    return encoded


def _decode_object(value: bytes | str) -> dict[str, Any]:
    try:
        raw = value.encode("utf-8") if isinstance(value, str) else value
        decoded = decode_json(raw)
    except RunnerError:
        _error("state_unavailable")
    except (TypeError, ValueError, UnicodeError):
        _error("state_unavailable")
    if not isinstance(decoded, dict):
        _error("state_unavailable")
    return decoded


def _finite_time(value: object, *, maximum_from_now: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _error("invalid_request")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        _error("invalid_request")
    if not math.isfinite(number):
        _error("invalid_request")
    if maximum_from_now:
        now = time.time()
        if number <= now or number > now + 3600:
            _error("invalid_request")
    return number


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


class Store:
    """SQLite-backed single-dispatch grants, prepared operations, and owned jobs."""

    @classmethod
    def initialize(cls, state_dir: Path) -> dict[str, Any]:
        directory_fd, path = _open_private_directory(Path(state_dir))
        db_fd = -1
        created_info: os.stat_result | None = None
        connection: sqlite3.Connection | None = None
        try:
            db_fd = os.open(_DB_NAME, _CREATE_FLAGS, 0o600, dir_fd=directory_fd)
            created_info = os.fstat(db_fd)
            os.fchmod(db_fd, 0o600)
            created_info = os.fstat(db_fd)
            if (
                not stat.S_ISREG(created_info.st_mode)
                or created_info.st_uid != os.getuid()
                or stat.S_IMODE(created_info.st_mode) != 0o600
                or created_info.st_nlink != 1
            ):
                _error("state_unavailable")
            os.close(db_fd)
            db_fd = -1

            connection = _connect(path / _DB_NAME, initialize=True)
            owner = {"instance_id": str(uuid.uuid4()), "epoch": 1}
            owner_json = _json_bytes(owner).decode("utf-8")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), owner_json TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE grants ("
                "grant_id TEXT PRIMARY KEY, owner_instance TEXT NOT NULL, owner_epoch INTEGER NOT NULL, "
                "binding_json BLOB NOT NULL, action TEXT NOT NULL, operation_id TEXT NOT NULL, "
                "fingerprint TEXT NOT NULL, expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, "
                "consumed INTEGER NOT NULL DEFAULT 0, profile_fingerprint TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE operations ("
                "owner_instance TEXT NOT NULL, owner_epoch INTEGER NOT NULL, operation_id TEXT NOT NULL, "
                "fingerprint TEXT NOT NULL, binding_json BLOB NOT NULL, action TEXT NOT NULL, "
                "request_json BLOB NOT NULL, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL, "
                "status TEXT NOT NULL CHECK(status IN ('prepared','finished')), report_json BLOB, profile_fingerprint TEXT NOT NULL, "
                "PRIMARY KEY(owner_instance, owner_epoch, operation_id))"
            )
            connection.execute(
                "CREATE TABLE jobs ("
                "job_id TEXT NOT NULL, attempt_id TEXT NOT NULL, owner_instance TEXT NOT NULL, "
                "owner_epoch INTEGER NOT NULL, binding_json BLOB NOT NULL, request_json BLOB NOT NULL, "
                "operation_id TEXT NOT NULL, fingerprint TEXT NOT NULL, "
                "status TEXT NOT NULL CHECK(status IN ('prepared','finished')), report_json BLOB, profile_fingerprint TEXT NOT NULL, "
                "PRIMARY KEY(job_id, attempt_id))"
            )
            connection.execute("INSERT INTO metadata(singleton, owner_json) VALUES(1, ?)", (owner_json,))
            connection.execute("COMMIT")
            _validate_database_file(directory_fd)
            created_info = None
            return owner
        except RunnerError:
            if connection is not None and connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        except sqlite3.Error as exc:
            if connection is not None and connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            _raise_sqlite(exc)
        except (OSError, TypeError, ValueError):
            if connection is not None and connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            _error("state_unavailable")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            if db_fd >= 0:
                os.close(db_fd)
            if created_info is not None:
                try:
                    current = os.stat(_DB_NAME, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (created_info.st_dev, created_info.st_ino):
                        os.unlink(_DB_NAME, dir_fd=directory_fd)
                        try:
                            os.unlink(_DB_NAME + "-journal", dir_fd=directory_fd)
                        except FileNotFoundError:
                            pass
                except OSError:
                    pass
            os.close(directory_fd)

    def __init__(self, state_dir: Path):
        self._dir_fd, self._state_dir = _open_private_directory(Path(state_dir))
        self._path = self._state_dir / _DB_NAME
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        try:
            original = _validate_database_file(self._dir_fd)
            self._database_identity = (original.st_dev, original.st_ino)
            self._connection = _connect(self._path)
            self._check_database()
            row = self._connection.execute("SELECT owner_json FROM metadata WHERE singleton=1").fetchone()
            if row is None:
                _error("state_unavailable")
            owner = _decode_object(row[0])
            if set(owner) != {"instance_id", "epoch"}:
                _error("state_unavailable")
            try:
                parsed_uuid = uuid.UUID(owner["instance_id"])
            except (AttributeError, TypeError, ValueError):
                _error("state_unavailable")
            if str(parsed_uuid) != owner["instance_id"] or owner["epoch"] != 1 or isinstance(owner["epoch"], bool):
                _error("state_unavailable")
            self._owner = owner
        except RunnerError:
            self.close()
            raise
        except sqlite3.Error as exc:
            self.close()
            _raise_sqlite(exc)
        except (OSError, TypeError, ValueError):
            self.close()
            _error("state_unavailable")

    @property
    def owner(self) -> dict[str, Any]:
        self._ensure_open()
        self._check_database()
        return dict(self._owner)

    def _ensure_open(self) -> sqlite3.Connection:
        if self._connection is None:
            _error("state_unavailable")
        return self._connection

    def _check_database(self) -> None:
        try:
            info = os.fstat(self._dir_fd)
        except OSError:
            _error("state_unavailable")
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            _error("state_unavailable")
        current = _validate_database_file(self._dir_fd)
        if (current.st_dev, current.st_ino) != self._database_identity:
            _error("state_unavailable")

    def _validate_request(self, request: dict[str, Any], *, authorization: bool = False) -> tuple[dict[str, Any], bytes, bytes, str, str, str]:
        if not isinstance(request, dict):
            _error("invalid_request")
        owner = request.get("owner")
        operation = request.get("operation")
        action = request.get("action")
        if (
            not isinstance(owner, dict)
            or isinstance(owner.get("epoch"), bool)
            or not isinstance(owner.get("epoch"), int)
            or owner != self._owner
        ):
            _error("request_conflict")
        if not isinstance(operation, dict) or not _identifier(operation.get("id")):
            _error("invalid_request")
        operation_id = operation["id"]
        operation_fingerprint = operation.get("fingerprint")
        if not isinstance(operation_fingerprint, str) or _FINGERPRINT.fullmatch(operation_fingerprint) is None:
            _error("invalid_request")
        if not isinstance(action, str) or action not in _MUTATIONS:
            _error("invalid_request")
        try:
            actual_fingerprint = fingerprint(request)
            binding_value = binding(request)
        except RunnerError as exc:
            _error("resource_limit" if exc.code == "resource_limit" else "invalid_request")
        except (KeyError, TypeError, ValueError, AttributeError):
            _error("invalid_request")
        if actual_fingerprint != operation_fingerprint:
            _error("request_conflict")
        if not isinstance(binding_value, dict):
            _error("invalid_request")
        binding_json = _json_bytes(binding_value)
        request_json = _json_bytes(request)
        request_id = request.get("request_id")
        if not _identifier(request_id):
            _error("invalid_request")
        if authorization:
            auth = request.get("authorization")
            if not isinstance(auth, dict) or auth.get("action") != action or not _identifier(auth.get("grant_id")):
                _error("approval_required")
        return binding_value, binding_json, request_json, action, operation_id, operation_fingerprint

    def _scope(self, request: dict[str, Any]) -> tuple[str, int, str]:
        owner = request["owner"]
        return owner["instance_id"], owner["epoch"], request["operation"]["id"]

    def _operation_row(self, request: dict[str, Any]) -> tuple[Any, ...] | None:
        owner_instance, owner_epoch, operation_id = self._scope(request)
        return self._ensure_open().execute(
            "SELECT fingerprint, binding_json, action, request_json, job_id, attempt_id, status, report_json, profile_fingerprint "
            "FROM operations WHERE owner_instance=? AND owner_epoch=? AND operation_id=?",
            (owner_instance, owner_epoch, operation_id),
        ).fetchone()

    def _check_existing(
        self,
        row: tuple[Any, ...],
        *,
        binding_json: bytes,
        action: str,
        operation_fingerprint: str,
    ) -> None:
        if row[0] != operation_fingerprint or row[1] != binding_json or row[2] != action:
            _error("operation_conflict")

    def _unknown_report(self, request: dict[str, Any], row: tuple[Any, ...], binding_value: dict[str, Any]) -> dict[str, Any]:
        job = {"job_id": row[4], "attempt_id": row[5]}
        for key in ("owner", "project", "backend", "target"):
            if key in binding_value:
                job[key] = binding_value[key]
        return {
            "protocol": "dotunnel.adapter/1",
            "request_id": request["request_id"],
            "outcome": "unknown",
            "code": "outcome_unknown",
            "binding": binding_value,
            "profile_fingerprint": row[8],
            "job": job,
        }

    def _operation_result(
        self,
        request: dict[str, Any],
        row: tuple[Any, ...],
        binding_value: dict[str, Any],
    ) -> dict[str, Any]:
        if row[6] == "finished" and row[7] is not None:
            result = _decode_object(row[7])
            result["request_id"] = request["request_id"]
            return result
        return self._unknown_report(request, row, binding_value)

    def lookup_operation(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Return a prior report without consuming consent or performing effects."""
        with self._lock:
            try:
                self._check_database()
                binding_value, binding_json, _request_json, action, _operation_id, operation_fingerprint = self._validate_request(request)
                row = self._operation_row(request)
                if row is None:
                    return None
                self._check_existing(
                    row,
                    binding_json=binding_json,
                    action=action,
                    operation_fingerprint=operation_fingerprint,
                )
                return self._operation_result(request, row, binding_value)
            except RunnerError:
                raise
            except sqlite3.Error as exc:
                _raise_sqlite(exc)
            except (OSError, TypeError, ValueError):
                _error("state_unavailable")

    @contextmanager
    def _atomic(self) -> Iterator[sqlite3.Connection]:
        connection = self._ensure_open()
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise

    def _ensure_room(self, connection: sqlite3.Connection, table: str) -> None:
        count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if count >= _MAX_ROWS_PER_TABLE:
            _error("resource_limit")

    @staticmethod
    def _profile_hash(value: str) -> str:
        if not isinstance(value, str) or _FINGERPRINT.fullmatch(value) is None:
            _error("invalid_request")
        return value

    def issue_grant(self, request: dict[str, Any], expires_at: float, *, profile_fingerprint: str) -> str:
        profile_fingerprint = self._profile_hash(profile_fingerprint)
        with self._lock:
            try:
                self._check_database()
                _binding_value, binding_json, _request_json, action, operation_id, operation_fingerprint = self._validate_request(request)
                if action not in _MUTATIONS:
                    _error("invalid_request")
                expiry = _finite_time(expires_at, maximum_from_now=True)
                owner_instance, owner_epoch, _ = self._scope(request)
                grant_id = str(uuid.uuid4())
                with self._atomic() as transaction:
                    self._ensure_room(transaction, "grants")
                    self._check_database()
                    transaction.execute(
                        "INSERT INTO grants(grant_id, owner_instance, owner_epoch, binding_json, action, "
                        "operation_id, fingerprint, expires_at, revoked, consumed, profile_fingerprint) "
                        "VALUES(?,?,?,?,?,?,?,?,0,0,?)",
                        (grant_id, owner_instance, owner_epoch, binding_json, action, operation_id, operation_fingerprint, expiry, profile_fingerprint),
                    )
                self._check_database()
                return grant_id
            except RunnerError:
                raise
            except sqlite3.Error as exc:
                _raise_sqlite(exc)
            except (OSError, TypeError, ValueError):
                _error("state_unavailable")

    def revoke_grant(self, grant_id: str) -> bool:
        if not _identifier(grant_id):
            _error("invalid_request")
        with self._lock:
            try:
                self._check_database()
                with self._atomic() as transaction:
                    cursor = transaction.execute(
                        "UPDATE grants SET revoked=1 WHERE grant_id=? AND revoked=0",
                        (grant_id,),
                    )
                    changed = cursor.rowcount == 1
                self._check_database()
                return changed
            except RunnerError:
                raise
            except sqlite3.Error as exc:
                _raise_sqlite(exc)
            except (OSError, TypeError, ValueError):
                _error("state_unavailable")

    def begin_operation(self, request: dict[str, Any], job_id: str, attempt_id: str,
                        now: float, *, profile_fingerprint: str) -> dict[str, Any] | None:
        profile_fingerprint = self._profile_hash(profile_fingerprint)
        with self._lock:
            committed = False
            try:
                self._check_database()
                binding_value, binding_json, request_json, action, operation_id, operation_fingerprint = self._validate_request(request)
                if not _identifier(job_id) or not _identifier(attempt_id):
                    _error("invalid_request")
                timestamp = _finite_time(now)
                owner_instance, owner_epoch, _ = self._scope(request)
                result: dict[str, Any] | None = None
                with self._atomic() as transaction:
                    existing = self._operation_row(request)
                    if existing is not None:
                        self._check_existing(
                            existing,
                            binding_json=binding_json,
                            action=action,
                            operation_fingerprint=operation_fingerprint,
                        )
                        result = self._operation_result(request, existing, binding_value)
                    else:
                        # Admission occurs after SQLite's bounded lock wait.
                        timestamp = max(timestamp, time.time())
                        authorization = request.get("authorization")
                        if (
                            not isinstance(authorization, dict)
                            or authorization.get("action") != action
                            or not _identifier(authorization.get("grant_id"))
                        ):
                            _error("approval_required")
                        grant_id = authorization["grant_id"]
                        grant = transaction.execute(
                            "SELECT owner_instance, owner_epoch, binding_json, action, operation_id, fingerprint, "
                            "expires_at, revoked, consumed, profile_fingerprint FROM grants WHERE grant_id=?",
                            (grant_id,),
                        ).fetchone()
                        if (
                            grant is None
                            or grant[0] != owner_instance
                            or grant[1] != owner_epoch
                            or grant[2] != binding_json
                            or grant[3] != action
                            or grant[4] != operation_id
                            or grant[5] != operation_fingerprint
                            or not isinstance(grant[6], (int, float))
                            or grant[6] <= timestamp
                            or grant[7] != 0
                            or grant[8] != 0
                            or grant[9] != profile_fingerprint
                        ):
                            _error("approval_required")
                        self._ensure_room(transaction, "operations")
                        self._ensure_room(transaction, "jobs")
                        duplicate_job = transaction.execute(
                            "SELECT 1 FROM jobs WHERE job_id=? AND attempt_id=?",
                            (job_id, attempt_id),
                        ).fetchone()
                        if duplicate_job is not None:
                            _error("request_conflict")
                        self._check_database()
                        consumed = transaction.execute(
                            "UPDATE grants SET consumed=1 WHERE grant_id=? AND revoked=0 AND consumed=0 AND expires_at>?",
                            (grant_id, timestamp),
                        )
                        if consumed.rowcount != 1:
                            _error("approval_required")
                        transaction.execute(
                            "INSERT INTO operations(owner_instance, owner_epoch, operation_id, fingerprint, binding_json, "
                            "action, request_json, job_id, attempt_id, status, report_json, profile_fingerprint) "
                            "VALUES(?,?,?,?,?,?,?,?,?,'prepared',NULL,?)",
                            (owner_instance, owner_epoch, operation_id, operation_fingerprint, binding_json, action, request_json, job_id, attempt_id, profile_fingerprint),
                        )
                        transaction.execute(
                            "INSERT INTO jobs(job_id, attempt_id, owner_instance, owner_epoch, binding_json, request_json, "
                            "operation_id, fingerprint, status, report_json, profile_fingerprint) "
                            "VALUES(?,?,?,?,?,?,?,?,'prepared',NULL,?)",
                            (job_id, attempt_id, owner_instance, owner_epoch, binding_json, request_json, operation_id, operation_fingerprint, profile_fingerprint),
                        )
                committed = result is None
                self._check_database()
                return result
            except RunnerError:
                if committed:
                    _error("outcome_unknown")
                raise
            except sqlite3.Error as exc:
                _raise_sqlite(exc)
            except (OSError, TypeError, ValueError):
                _error("state_unavailable")

    def finish_operation(self, request: dict[str, Any], report: dict[str, Any]) -> None:
        with self._lock:
            try:
                self._check_database()
                binding_value, binding_json, _request_json, action, operation_id, operation_fingerprint = self._validate_request(request)
                if not isinstance(report, dict) or report.get("request_id") != request.get("request_id"):
                    _error("request_conflict")
                if report.get("binding") != binding_value:
                    _error("request_conflict")
                report_json = _json_bytes(report)
                owner_instance, owner_epoch, _ = self._scope(request)
                with self._atomic() as transaction:
                    row = transaction.execute(
                        "SELECT fingerprint, binding_json, action, job_id, attempt_id, status, report_json, profile_fingerprint "
                        "FROM operations WHERE owner_instance=? AND owner_epoch=? AND operation_id=?",
                        (owner_instance, owner_epoch, operation_id),
                    ).fetchone()
                    if row is None or row[0] != operation_fingerprint or row[1] != binding_json or row[2] != action:
                        _error("request_conflict")
                    if report.get("profile_fingerprint") != row[7]:
                        _error("request_conflict")
                    if row[5] == "finished":
                        if row[6] != report_json:
                            _error("request_conflict")
                        return
                    job_info = report.get("job")
                    if isinstance(job_info, dict):
                        if (
                            job_info.get("job_id", row[3]) != row[3]
                            or job_info.get("attempt_id", row[4]) != row[4]
                        ):
                            _error("request_conflict")
                    updated = transaction.execute(
                        "UPDATE operations SET status='finished', report_json=? "
                        "WHERE owner_instance=? AND owner_epoch=? AND operation_id=? AND status='prepared'",
                        (report_json, owner_instance, owner_epoch, operation_id),
                    )
                    if updated.rowcount != 1:
                        _error("request_conflict")
                    job_updated = transaction.execute(
                        "UPDATE jobs SET status='finished', report_json=? WHERE job_id=? AND attempt_id=? AND status='prepared'",
                        (report_json, row[3], row[4]),
                    )
                    if job_updated.rowcount != 1:
                        _error("request_conflict")
                self._check_database()
            except RunnerError:
                raise
            except sqlite3.Error as exc:
                _raise_sqlite(exc)
            except (OSError, TypeError, ValueError):
                _error("state_unavailable")

    def get_job(self, job_id: str, attempt_id: str) -> dict[str, Any] | None:
        if not _identifier(job_id) or not _identifier(attempt_id):
            _error("invalid_request")
        with self._lock:
            try:
                self._check_database()
                row = self._ensure_open().execute(
                    "SELECT binding_json, request_json, status, report_json, profile_fingerprint FROM jobs WHERE job_id=? AND attempt_id=?",
                    (job_id, attempt_id),
                ).fetchone()
                if row is None:
                    return None
                record: dict[str, Any] = {
                    "binding": _decode_object(row[0]),
                    "request": _decode_object(row[1]),
                    "job_id": job_id,
                    "attempt_id": attempt_id,
                    "report": _decode_object(row[3]) if row[3] is not None else None,
                    "status": row[2],
                    "profile_fingerprint": row[4],
                }
                return record
            except RunnerError:
                raise
            except sqlite3.Error as exc:
                _raise_sqlite(exc)
            except (OSError, TypeError, ValueError):
                _error("state_unavailable")


    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        self._connection = None
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                pass
        directory_fd = getattr(self, "_dir_fd", -1)
        self._dir_fd = -1
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError:
                pass
