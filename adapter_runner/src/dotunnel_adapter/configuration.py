"""Owner-pinned configuration for the isolated optional adapter runner."""

from __future__ import annotations

import hashlib
import json
import math
import os
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .protocol import RunnerError, canonical_json


_CONFIG_PROTOCOL = "dotunnel.adapter.config/1"
_CONFIG_LIMIT = 65536
_PATH_LIMIT = 4096
_ARG_LIMIT = 4096
_ARGV_LIMIT = 16384
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ACTIONS = frozenset(
    {
        "capabilities",
        "list_targets",
        "inspect",
        "read_output",
        "start",
        "submit",
        "answer",
        "cancel",
        "report",
    }
)
_PROTECTED_NAMES = frozenset(
    {
        "credential",
        "credentials",
        "secret",
        "secrets",
        "token",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_xmss",
        "identity",
        "private",
        "private_key",
        "private-key",
        "privatekey",
        "privkey",
        "authorized_keys",
        "known_hosts",
        "agent.db",
        "auth.json",
        "client.json",
        "config.local",
        "config.local.json",
        "profile.json",
    }
)
_PROTECTED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".p8", ".ppk", ".der", ".jks", ".keystore", ".gpg", ".pgp", ".asc")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY


@dataclass(frozen=True)
class RunnerConfig:
    config_path: Path
    workspace: Path
    request: str
    reports: str
    state_dir: Path
    project: dict
    backend: dict


def _invalid() -> None:
    raise RunnerError("invalid_config")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _check_json(value: Any, depth: int = 0) -> None:
    if depth > 64:
        _invalid()
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _invalid()
        return
    if isinstance(value, str):
        try:
            if len(value.encode("utf-8", "strict")) > _CONFIG_LIMIT:
                _invalid()
        except UnicodeError:
            _invalid()
        return
    if isinstance(value, list):
        for item in value:
            _check_json(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _invalid()
            _check_json(key, depth + 1)
            _check_json(item, depth + 1)
        return
    _invalid()


def _config_path(value: object) -> Path:
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            _invalid()
        path = Path(os.path.abspath(raw))
        if not path.is_absolute() or ".." in path.parts:
            _invalid()
        path.as_posix().encode("utf-8", "strict")
        return path
    except RunnerError:
        raise
    except (OSError, TypeError, ValueError, UnicodeError):
        _invalid()


def _absolute_directory(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        _invalid()
    try:
        value.encode("utf-8", "strict")
        path = Path(value)
    except (TypeError, ValueError, UnicodeError):
        _invalid()
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        _invalid()
    return path


def _open_absolute(path: Path, flags: int) -> int:
    if not path.is_absolute() or ".." in path.parts or "\x00" in os.fspath(path):
        _invalid()
    current = -1
    try:
        current = os.open("/", _DIR_FLAGS)
        for component in path.parts[1:-1]:
            child = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        result = os.open(path.name or ".", flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
        return result
    except RunnerError:
        raise
    except OSError:
        _invalid()
    finally:
        if current >= 0:
            os.close(current)


def _verify_config_parents(path: Path) -> None:
    uid = os.getuid()
    current = -1
    try:
        current = os.open("/", _DIR_FLAGS)
        root_info = os.fstat(current)
        if root_info.st_mode & 0o022:
            _invalid()
        parent_parts = path.parts[1:-1]
        if not parent_parts:
            _invalid()
        for index, component in enumerate(parent_parts):
            child = os.open(component, _DIR_FLAGS, dir_fd=current)
            info = os.fstat(child)
            os.close(current)
            current = child
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (uid, 0):
                _invalid()
            if index == len(parent_parts) - 1:
                if info.st_uid != uid or mode & 0o077:
                    _invalid()
            elif mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
                _invalid()
    except RunnerError:
        raise
    except OSError:
        _invalid()
    finally:
        if current >= 0:
            os.close(current)


def _private_config(path: Path) -> dict:
    _verify_config_parents(path)
    fd = _open_absolute(path, _FILE_FLAGS)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) not in (0o600, 0o400)
        ):
            _invalid()
        if before.st_size > _CONFIG_LIMIT:
            raise RunnerError("resource_limit")
        chunks = bytearray()
        while len(chunks) <= _CONFIG_LIMIT:
            data = os.read(fd, min(8192, _CONFIG_LIMIT + 1 - len(chunks)))
            if not data:
                break
            chunks.extend(data)
        after = os.fstat(fd)
        if (
            len(chunks) > _CONFIG_LIMIT
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or after.st_nlink != 1
            or len(chunks) != after.st_size
        ):
            _invalid()
        try:
            text = bytes(chunks).decode("utf-8", "strict")
            value = json.loads(
                text,
                object_pairs_hook=_pairs,
                parse_constant=lambda _constant: _invalid(),
            )
            _check_json(value)
        except RunnerError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
            _invalid()
        if not isinstance(value, dict):
            _invalid()
        return value
    except RunnerError:
        raise
    except OSError:
        _invalid()
    finally:
        os.close(fd)


def _exact(value: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        _invalid()
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _invalid()
    return value


def _bounded_string(value: object, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _invalid()
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        _invalid()
    if len(encoded) > maximum or (not allow_empty and not encoded):
        _invalid()
    return value


def _is_protected(component: str) -> bool:
    lowered = component.casefold()
    return component.startswith(".") or lowered in _PROTECTED_NAMES or lowered.split(".", 1)[0] in _PROTECTED_NAMES or lowered.endswith(_PROTECTED_SUFFIXES)


def _relative_components(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\x00" in value or value.startswith("/"):
        _invalid()
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        _invalid()
    if len(encoded) > _PATH_LIMIT:
        _invalid()
    components = tuple(value.split("/"))
    if any(component in ("", ".", "..") or _is_protected(component) for component in components):
        _invalid()
    return components


def _relative_path(value: object) -> str:
    return "/".join(_relative_components(value))


def _within(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def _open_directory(path: Path) -> tuple[int, os.stat_result]:
    fd = _open_absolute(path, _DIR_FLAGS)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            _invalid()
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _check_state_directory(path: Path) -> None:
    fd, info = _open_directory(path)
    try:
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _invalid()
    finally:
        os.close(fd)


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _check_executable(path: Path, workspace: Path, expected_digest: str) -> None:
    if not path.is_absolute() or ".." in path.parts or _within(path, workspace):
        _invalid()
    fd = _open_absolute(path, _FILE_FLAGS)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in (os.getuid(), 0)
            or before.st_mode & 0o111 == 0
            or before.st_mode & 0o022
        ):
            _invalid()
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
        after = os.fstat(fd)
        if not _same_file(before, after) or total != after.st_size or after.st_nlink != 1:
            _invalid()
        if "sha256:" + digest.hexdigest() != expected_digest:
            _invalid()
    except RunnerError:
        raise
    except OSError:
        _invalid()
    finally:
        os.close(fd)


def _parse_project(value: object) -> dict:
    project = _exact(value, {"id", "generation", "protected", "write_enabled", "operations"})
    _identifier(project["id"])
    _bounded_string(project["generation"], 128)
    if type(project["protected"]) is not bool or type(project["write_enabled"]) is not bool:
        _invalid()
    operations = project["operations"]
    if not isinstance(operations, list) or len(operations) > len(_ACTIONS):
        _invalid()
    parsed = []
    for action in operations:
        if not isinstance(action, str) or action not in _ACTIONS or action in parsed:
            _invalid()
        parsed.append(action)
    result = dict(project)
    result["operations"] = parsed
    return result


def _parse_backend(value: object, workspace: Path, state_dir: Path) -> dict:
    backend = _exact(value, {"id", "generation", "version", "digest", "argv", "timeout_seconds"})
    _identifier(backend["id"])
    _bounded_string(backend["generation"], 128)
    _bounded_string(backend["version"], 128)
    digest = backend["digest"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        _invalid()
    argv = backend["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 64:
        _invalid()
    parsed_argv = []
    total_bytes = 0
    for argument in argv:
        text = _bounded_string(argument, _ARG_LIMIT)
        if "\x00" in text:
            _invalid()
        path_arguments = [text]
        if "=" in text:
            path_arguments.append(text.split("=", 1)[1])
        if text.startswith("-") and "/" in text:
            path_arguments.append(text[text.index("/"):])
        for path_argument in path_arguments:
            candidate = Path(os.path.abspath(state_dir / path_argument))
            try:
                resolved = candidate.resolve(strict=False)
            except (OSError, RuntimeError):
                _invalid()
            if _within(candidate, workspace) or _within(resolved, workspace):
                _invalid()
        total_bytes += len(text.encode("utf-8", "strict"))
        parsed_argv.append(text)
    if total_bytes > _ARGV_LIMIT:
        _invalid()
    executable = Path(parsed_argv[0])
    _check_executable(executable, workspace, digest)
    timeout = backend["timeout_seconds"]
    if type(timeout) is int:
        if not 0 < timeout <= 200:
            _invalid()
    elif type(timeout) is float:
        if not math.isfinite(timeout) or not 0 < timeout <= 200:
            _invalid()
    else:
        _invalid()
    result = dict(backend)
    result["argv"] = tuple(parsed_argv)
    result["timeout_seconds"] = float(timeout)
    return result


def load_config(path: str | Path) -> RunnerConfig:
    config_path = _config_path(path)
    value = _private_config(config_path)
    config = _exact(
        value,
        {"protocol", "workspace", "request", "reports", "state_dir", "project", "backend"},
    )
    if config["protocol"] != _CONFIG_PROTOCOL:
        _invalid()
    workspace = _absolute_directory(config["workspace"])
    state_dir = _absolute_directory(config["state_dir"])
    try:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except KeyError:
        _invalid()
    if workspace == account_home or workspace == state_dir or _within(workspace, state_dir) or _within(state_dir, workspace):
        _invalid()
    if _within(config_path, workspace) or _within(config_path, state_dir):
        _invalid()
    workspace_fd, _workspace_info = _open_directory(workspace)
    os.close(workspace_fd)
    _check_state_directory(state_dir)
    request = _relative_path(config["request"])
    reports = _relative_path(config["reports"])
    request_parts = tuple(request.split("/"))
    report_parts = tuple(reports.split("/"))
    if request_parts[: len(report_parts)] == report_parts or report_parts[: len(request_parts)] == request_parts:
        _invalid()
    project = _parse_project(config["project"])
    backend = _parse_backend(config["backend"], workspace, state_dir)
    return RunnerConfig(
        config_path=config_path,
        workspace=workspace,
        request=request,
        reports=reports,
        state_dir=state_dir,
        project=project,
        backend=backend,
    )


def registry_profile(config: RunnerConfig) -> dict[str, Any]:
    """Canonical local consent profile; never supplied by the workspace caller."""
    backend = dict(config.backend)
    backend["argv"] = list(config.backend["argv"])
    # Configuration permits fractional seconds; the request protocol is integer-only.
    backend["timeout_seconds"] = repr(config.backend["timeout_seconds"])
    project = dict(config.project)
    project["operations"] = sorted(config.project["operations"])
    return {"workspace": str(config.workspace), "project": project, "backend": backend}


def profile_fingerprint(config: RunnerConfig) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(registry_profile(config))).hexdigest()
