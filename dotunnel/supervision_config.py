"""Strict, fixed configuration for optional agent supervision."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any


_CODES = frozenset({
    "invalid_request",
    "not_approved",
    "protected_target",
    "stale_target",
    "stale_observation",
    "unsupported_operation",
    "backend_unavailable",
    "busy",
    "operation_conflict",
    "state_unsafe",
    "state_full",
    "delivery_unknown",
})
_MESSAGES = {
    "invalid_request": "The supervision request is invalid.",
    "not_approved": "The configured supervision scope is not approved.",
    "protected_target": "The target is protected by operator configuration.",
    "stale_target": "The target is no longer verified.",
    "stale_observation": "The observation is no longer current.",
    "unsupported_operation": "The operation is not supported for this target.",
    "backend_unavailable": "The configured backend is unavailable.",
    "busy": "Supervision state is busy.",
    "operation_conflict": "The operation ID was used with a different request.",
    "state_unsafe": "Supervision state is missing, damaged, or unsafe.",
    "state_full": "Supervision state has reached a configured bound.",
    "delivery_unknown": "The backend effect may have occurred; delivery is unknown.",
}


class SupervisionError(ValueError):
    """A stable, safe supervision error suitable for tool/operator results."""

    def __init__(self, code: str, *, reason: str | None = None):
        if code not in _CODES:
            raise ValueError("Unknown supervision error code")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 128 or not re.fullmatch(r"[A-Za-z0-9_:-]+", reason)):
            reason = None
        self.code = code
        self.reason = reason
        self.message = _MESSAGES[code]
        super().__init__(self.message)

    def as_result(self) -> dict[str, dict[str, str]]:
        error = {"code": self.code, "message": self.message}
        if self.reason is not None:
            error["reason"] = self.reason
        return {"error": error}


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Connection:
    id: str
    backend: str
    executable: Path
    session: str | None = None
    socket: Path | None = None
    read_targets: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class Project:
    id: str
    path: Path
    connections: tuple[str, ...]
    profiles: tuple[str, ...]
    allowed_actions: frozenset[str] = frozenset()
    profile_actions: Mapping[str, frozenset[str]] = field(default_factory=dict)
    workspaces: tuple[str, ...] = ()
    protected: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_actions", frozenset(self.allowed_actions))
        object.__setattr__(
            self,
            "profile_actions",
            MappingProxyType({profile: frozenset(actions) for profile, actions in self.profile_actions.items()}),
        )

    def allows(self, action: str, profile_id: str | None = None) -> bool:
        if action == "read":
            return "read" in self.allowed_actions
        if (
            action not in _PROFILE_MUTATIONS
            or profile_id is None
            or profile_id not in self.profiles
            or action not in self.allowed_actions
            or (action in ("prompt", "answer") and "read" not in self.allowed_actions)
        ):
            return False
        return action in self.profile_actions.get(profile_id, ())

@dataclass(frozen=True)
class Profile:
    id: str
    kind: str
    executable: Path
    args: tuple[str, ...] = ()
    backends: tuple[str, ...] = ("herdr", "tmux")
    input_mode: str = "bracketed-paste"
    executable_policy: str = "compatible"

@dataclass(frozen=True)
class SupervisionSettings:
    state_dir: Path
    workspace_root: Path
    connections: Mapping[str, Connection]
    projects: Mapping[str, Project]
    profiles: Mapping[str, Profile]
    protected_paths: tuple[Path, ...]
    default_connection: str | None
    generation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "connections", MappingProxyType(dict(self.connections)))
        object.__setattr__(self, "projects", MappingProxyType(dict(self.projects)))
        object.__setattr__(self, "profiles", MappingProxyType(dict(self.profiles)))
        object.__setattr__(self, "protected_paths", tuple(self.protected_paths))


_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_WORKSPACE = re.compile(r"w[A-Za-z0-9]{1,16}\Z")
_SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_NATIVE_PANE = re.compile(r"%[0-9]{1,12}\Z")
_PID = re.compile(r"[0-9]{1,20}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_BACKENDS = frozenset(("herdr", "tmux"))
_KINDS = frozenset(("omp", "claude", "codex"))
_PROJECT_ACTIONS = frozenset(("read", "start", "prompt", "answer"))
_PROFILE_MUTATIONS = frozenset(("start", "prompt", "answer"))


def _invalid(reason: str) -> SupervisionError:
    return SupervisionError("invalid_request", reason=reason)


def _keys(value: object, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise _invalid("invalid_fields")
    return value


def _identifier(value: object, reason: str = "invalid_identifier") -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise _invalid(reason)
    return value


def _list(value: object, reason: str) -> list[Any]:
    if not isinstance(value, list):
        raise _invalid(reason)
    return value


def _unique_ids(value: object, reason: str) -> tuple[str, ...]:
    items = tuple(_identifier(item) for item in _list(value, reason))
    if len(items) != len(set(items)):
        raise _invalid(reason)
    return items

def _action_set(value: object, allowed: frozenset[str], reason: str) -> frozenset[str]:
    items = _list(value, reason)
    if any(not isinstance(item, str) or item not in allowed for item in items) or len(items) != len(set(items)):
        raise _invalid(reason)
    return frozenset(items)


def _path_value(value: object, reason: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _invalid(reason)
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise _invalid(reason)
    return path


def _open_trusted_directory(path: Path, *, allow_missing: bool = False, private_final: bool = False) -> int:
    """Open every directory component without following links and verify ownership."""
    if not path.is_absolute() or ".." in path.parts:
        raise _invalid("unsafe_directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    uid = os.getuid()
    try:
        _check_directory_owner(os.fstat(fd), uid, final=False)
        parts = path.parts[1:]
        for index, component in enumerate(parts):
            final = index == len(parts) - 1
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if allow_missing:
                    result = fd
                    fd = -1
                    return result
                raise _invalid("missing_directory") from None
            except OSError:
                raise _invalid("unsafe_directory") from None
            try:
                _check_directory_owner(os.fstat(child), uid, final=final and private_final)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        result = fd
        fd = -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _trusted_directory(path: Path, *, allow_missing: bool = False, private_final: bool = False) -> Path:
    fd = _open_trusted_directory(path, allow_missing=allow_missing, private_final=private_final)
    os.close(fd)
    return path

def _trusted_future_directory(path: Path, *, setup_directory: Path | None = None) -> Path:
    """Validate a future directory without creating it or following links."""
    if not path.is_absolute() or ".." in path.parts or path == Path("/") or not path.name:
        raise _invalid("unsafe_directory")
    if setup_directory is not None:
        setup_directory = Path(setup_directory)
        if not setup_directory.is_absolute() or ".." in setup_directory.parts or not setup_directory.name:
            raise _invalid("unsafe_directory")
    if setup_directory is not None and path.parent == setup_directory:
        parent_fd = _open_trusted_directory(setup_directory.parent)
        try:
            try:
                directory_fd = os.open(
                    setup_directory.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                return path
            except OSError:
                raise _invalid("unsafe_directory") from None
            try:
                _check_directory_owner(os.fstat(directory_fd), os.getuid(), final=True)
                try:
                    os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return path
                except OSError:
                    raise _invalid("unsafe_directory") from None
                raise _invalid("future_directory_exists")
            finally:
                os.close(directory_fd)
        finally:
            os.close(parent_fd)
    parent_fd = _open_trusted_directory(path.parent)
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return path
        except OSError:
            raise _invalid("unsafe_directory") from None
        raise _invalid("future_directory_exists")
    finally:
        os.close(parent_fd)


def _check_directory_owner(info: os.stat_result, uid: int, *, final: bool) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
        raise _invalid("unsafe_directory")
    if final:
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise _invalid("unsafe_private_directory")
    elif info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0):
        raise _invalid("untrusted_directory_ancestor")



def _trusted_executable(path: Path, root: Path, *, policy: str = "strict") -> Path:
    if not isinstance(policy, str) or policy not in ("compatible", "strict"):
        raise _invalid("invalid_executable_policy")
    if not path.is_absolute() or ".." in path.parts or _overlaps(path, root):
        raise _invalid("unsafe_executable_path")
    try:
        parent_fd = _open_trusted_directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    except OSError:
        raise _invalid("unsafe_executable") from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or not (info.st_mode & 0o111)
            or (policy == "strict" and (info.st_nlink != 1 or bool(info.st_mode & 0o022)))
        ):
            raise _invalid("unsafe_executable")
    finally:
        os.close(fd)
    return path

def _canonical(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        raise _invalid("unsafe_path") from None


def _overlaps(path: Path, other: Path) -> bool:
    try:
        left = _canonical(path)
        right = _canonical(other)
    except SupervisionError:
        raise
    return left.is_relative_to(right) or right.is_relative_to(left)


def _string_list(value: object, reason: str, *, maximum: int = 64, allow_empty_item: bool = False) -> tuple[str, ...]:
    items = _list(value, reason)
    if len(items) > maximum:
        raise _invalid(reason)
    result: list[str] = []
    for item in items:
        if not isinstance(item, str) or "\x00" in item or len(item) > 4096 or (not item and not allow_empty_item):
            raise _invalid(reason)
        result.append(item)
    return tuple(result)


def _parse_connection(item: object, root: Path) -> tuple[Connection, str]:
    if not isinstance(item, dict):
        raise _invalid("invalid_connection")
    backend = item.get("backend")
    if backend == "herdr":
        value = _keys(item, {"id", "backend", "executable"}, {"session", "read_targets"})
        session = value.get("session")
        if session is not None and (not isinstance(session, str) or not _SESSION.fullmatch(session)):
            raise _invalid("invalid_session_selector")
        if "read_targets" in value:
            raise _invalid("readonly_targets_require_tmux")
        socket = None
        selector = session or "local"
    elif backend == "tmux":
        value = _keys(item, {"id", "backend", "executable", "socket"}, {"read_targets"})
        session = None
        socket = _path_value(value["socket"], "invalid_socket_path")
        parent_fd = _open_trusted_directory(socket.parent)
        try:
            try:
                info = os.stat(socket.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                info = None
            except OSError:
                raise _invalid("unsafe_tmux_socket") from None
            if info is not None and (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()):
                raise _invalid("unsafe_tmux_socket")
        finally:
            os.close(parent_fd)
        selector = str(_canonical(socket))
    else:
        raise _invalid("invalid_backend")

    connection_id = _identifier(value["id"])
    executable = _trusted_executable(_path_value(value["executable"], "invalid_executable_path"), root)
    read_targets: tuple[dict[str, Any], ...] = ()
    if backend == "tmux":
        raw_targets = value.get("read_targets", [])
        if not isinstance(raw_targets, list):
            raise _invalid("invalid_read_targets")
        parsed: list[dict[str, Any]] = []
        native_ids: set[str] = set()
        identity_fields = {"boot_id", "server_pid", "server_start", "pane_pid", "pane_start"}
        for raw in raw_targets:
            target = _keys(raw, {"project", "native_id", "identity"})
            project_id = _identifier(target["project"], "invalid_read_target_project")
            native_id = target["native_id"]
            if not isinstance(native_id, str) or not _NATIVE_PANE.fullmatch(native_id) or native_id in native_ids:
                raise _invalid("invalid_read_target_identity")
            native_ids.add(native_id)
            identity = _keys(target["identity"], identity_fields)
            boot_id = identity["boot_id"]
            if not isinstance(boot_id, str) or not 1 <= len(boot_id) <= 128 or not re.fullmatch(r"[A-Za-z0-9-]+", boot_id):
                raise _invalid("invalid_read_target_identity")
            normalized_identity: dict[str, str | int] = {"boot_id": boot_id}
            for name in ("server_pid", "server_start", "pane_pid", "pane_start"):
                number = identity[name]
                pattern = _PID if name.endswith("pid") else _PID
                if not isinstance(number, str) or not pattern.fullmatch(number):
                    raise _invalid("invalid_read_target_identity")
                normalized_identity[name] = int(number)
            parsed.append({"project": project_id, "native_id": native_id, "identity": normalized_identity})
        read_targets = tuple(parsed)
    return Connection(connection_id, backend, executable, session, socket, read_targets), selector


def _parse_project(item: object) -> Project:
    value = _keys(
        item,
        {"id", "path", "connections", "profiles", "allowed_actions", "profile_actions"},
        {"workspaces", "protected"},
    )
    project_id = _identifier(value["id"])
    path = _path_value(value["path"], "invalid_project_path")
    _trusted_directory(path)
    connections = _unique_ids(value["connections"], "invalid_project_connections")
    profiles = _unique_ids(value["profiles"], "invalid_project_profiles")
    allowed_actions = _action_set(value["allowed_actions"], _PROJECT_ACTIONS, "invalid_project_actions")
    raw_profile_actions = value["profile_actions"]
    if not isinstance(raw_profile_actions, dict):
        raise _invalid("invalid_project_profile_actions")
    profile_actions: dict[str, frozenset[str]] = {}
    for profile_id, actions_value in raw_profile_actions.items():
        if not isinstance(profile_id, str) or profile_id not in profiles:
            raise _invalid("unknown_project_profile_action")
        actions = _action_set(actions_value, _PROFILE_MUTATIONS, "invalid_profile_actions")
        if not actions <= allowed_actions:
            raise _invalid("profile_action_outside_project_ceiling")
        profile_actions[profile_id] = actions
    if "read" not in allowed_actions and any(
        action in actions for actions in profile_actions.values() for action in ("prompt", "answer")
    ):
        raise _invalid("profile_input_requires_read")
    raw_workspaces = value.get("workspaces", [])
    workspaces = _string_list(raw_workspaces, "invalid_project_workspaces", maximum=256)
    if any(not _WORKSPACE.fullmatch(workspace) for workspace in workspaces):
        raise _invalid("invalid_project_workspaces")
    protected = value.get("protected", False)
    if not isinstance(protected, bool):
        raise _invalid("invalid_project_protection")
    return Project(project_id, _canonical(path), connections, profiles, allowed_actions, profile_actions, workspaces, protected)


def _parse_profile(item: object, root: Path) -> Profile:
    value = _keys(
        item, {"id", "kind", "executable"}, {"args", "backends", "input_mode", "executable_policy"}
    )
    profile_id = _identifier(value["id"])
    kind = value["kind"]
    if not isinstance(kind, str) or kind not in _KINDS:
        raise _invalid("invalid_profile_kind")
    executable_policy = value.get("executable_policy", "compatible")
    if not isinstance(executable_policy, str) or executable_policy not in ("compatible", "strict"):
        raise _invalid("invalid_executable_policy")
    executable = _trusted_executable(
        _path_value(value["executable"], "invalid_executable_path"), root, policy=executable_policy
    )
    args = _string_list(value.get("args", []), "invalid_profile_args", maximum=64)
    raw_backends = value.get("backends", ["herdr", "tmux"])
    backends = _unique_ids(raw_backends, "invalid_profile_backends")
    if not backends or any(backend not in _BACKENDS for backend in backends):
        raise _invalid("invalid_profile_backends")
    input_mode = value.get("input_mode", "bracketed-paste")
    if input_mode != "bracketed-paste":
        raise _invalid("unsupported_input_mode")
    return Profile(profile_id, kind, executable, args, backends, input_mode, executable_policy)


def _parse_supervision(
    value: object, root: Path, config_path: Path, *, future_root: bool
) -> SupervisionSettings:
    section = _keys(value, {"state_dir", "connections", "projects", "profiles"}, {"default_connection", "protected_paths"})
    root = Path(root)
    config_path = Path(config_path)
    if not root.is_absolute() or not config_path.is_absolute() or ".." in root.parts or ".." in config_path.parts:
        raise _invalid("invalid_parent_paths")
    if future_root:
        _trusted_future_directory(root, setup_directory=config_path.parent)
    else:
        _trusted_directory(root)
    state_dir = _path_value(section["state_dir"], "invalid_state_directory")
    _trusted_directory(state_dir, allow_missing=True, private_final=True)
    if _overlaps(state_dir, root) or _canonical(config_path).is_relative_to(_canonical(state_dir)):
        raise _invalid("state_directory_overlap")

    raw_connections = _list(section["connections"], "invalid_connections")
    if len(raw_connections) > 4:
        raise _invalid("too_many_connections")
    connections: dict[str, Connection] = {}
    selectors: set[tuple[str, str]] = set()
    parsed_connections: list[tuple[Connection, str]] = []
    for raw in raw_connections:
        connection, selector = _parse_connection(raw, root)
        if connection.id in connections:
            raise _invalid("duplicate_connection_id")
        selector_key = (connection.backend, selector)
        if selector_key in selectors:
            raise _invalid("duplicate_connection_selector")
        selectors.add(selector_key)
        connections[connection.id] = connection
        parsed_connections.append((connection, selector))

    raw_projects = _list(section["projects"], "invalid_projects")
    projects: dict[str, Project] = {}
    for raw in raw_projects:
        project = _parse_project(raw)
        if project.id in projects:
            raise _invalid("duplicate_project_id")
        if any(connection not in connections for connection in project.connections):
            raise _invalid("unknown_project_connection")
        projects[project.id] = project

    raw_profiles = _list(section["profiles"], "invalid_profiles")
    profiles: dict[str, Profile] = {}
    for raw in raw_profiles:
        profile = _parse_profile(raw, root)
        if profile.id in profiles:
            raise _invalid("duplicate_profile_id")
        profiles[profile.id] = profile

    for project in projects.values():
        if any(profile not in profiles for profile in project.profiles):
            raise _invalid("unknown_project_profile")
        for connection_id in project.connections:
            backend = connections[connection_id].backend
            if project.profiles and not any(backend in profiles[profile_id].backends for profile_id in project.profiles):
                raise _invalid("project_profile_backend_mismatch")

    for connection, _ in parsed_connections:
        for target in connection.read_targets:
            project = projects.get(target["project"])
            if project is None or connection.id not in project.connections:
                raise _invalid("unregistered_read_target_project")

    default_connection = section.get("default_connection")
    if default_connection is not None:
        default_connection = _identifier(default_connection, "invalid_default_connection")
        if default_connection not in connections:
            raise _invalid("unknown_default_connection")

    raw_protected = section.get("protected_paths", [])
    if not isinstance(raw_protected, list) or len(raw_protected) > 64:
        raise _invalid("invalid_protected_paths")
    protected_paths = tuple(_canonical(_path_value(item, "invalid_protected_path")) for item in raw_protected)

    generation_value = {
        "root": str(_canonical(root)),
        "state_dir": str(_canonical(state_dir)),
        "connections": [
            {
                "id": item.id,
                "backend": item.backend,
                "executable": str(item.executable),
                "session": item.session,
                "socket": str(item.socket) if item.socket is not None else None,
                "read_targets": [
                    {
                        "project": target["project"],
                        "native_id": target["native_id"],
                        "identity": dict(target["identity"]),
                    }
                    for target in item.read_targets
                ],
            }
            for item in connections.values()
        ],
        "projects": [
            {
                "id": item.id, "path": str(item.path), "connections": item.connections,
                "profiles": item.profiles, "allowed_actions": sorted(item.allowed_actions),
                "profile_actions": {
                    profile: sorted(item.profile_actions.get(profile, ())) for profile in sorted(item.profiles)
                },
                "workspaces": item.workspaces, "protected": item.protected,
            }
            for item in projects.values()
        ],
        "profiles": [
            {
                "id": item.id, "kind": item.kind, "executable": str(item.executable), "args": item.args,
                "backends": item.backends, "input_mode": item.input_mode,
                "executable_policy": item.executable_policy,
            }
            for item in profiles.values()
        ],
        "protected_paths": [str(path) for path in protected_paths],
        "default_connection": default_connection,
    }
    generation = canonical_sha256(generation_value)
    return SupervisionSettings(
        state_dir=_canonical(state_dir),
        connections=connections,
        projects=projects,
        profiles=profiles,
        protected_paths=protected_paths,
        default_connection=default_connection,
        generation=generation,
        workspace_root=_canonical(root),
    )

def parse_supervision(value: object, root: Path, config_path: Path) -> SupervisionSettings:
    return _parse_supervision(value, root, config_path, future_root=False)


def _parse_setup_draft_supervision(
    value: object, root: Path, config_path: Path
) -> SupervisionSettings:
    return _parse_supervision(value, root, config_path, future_root=True)


def protected(path: str | Path, settings: SupervisionSettings) -> bool:
    if not isinstance(path, (str, Path)) or not str(path) or "\x00" in str(path):
        raise _invalid("invalid_protected_target_path")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise _invalid("protected_target_path_not_absolute")
    canonical_candidate = _canonical(candidate)
    for protected_path in settings.protected_paths:
        canonical_protected = _canonical(protected_path)
        if canonical_candidate.is_relative_to(canonical_protected) or canonical_protected.is_relative_to(canonical_candidate):
            return True
    return False
