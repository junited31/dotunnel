"""Herdr CLI backend for the common supervision service."""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .supervision_config import SupervisionError
from .tasks import _ANSI_SEQUENCE, _C1_SEQUENCE

_PANE_ID = re.compile(r"w[A-Za-z0-9]{1,16}:p[0-9]{1,9}")
_WORKSPACE_ID = re.compile(r"w[A-Za-z0-9]{1,16}")
_AGENT_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_KINDS = frozenset({"omp", "claude", "codex"})
_STATUSES = frozenset({"idle", "working", "blocked", "done", "unknown"})
_KEYS = frozenset({"enter", "esc", "up", "down", "left", "right", "tab", "y", "n", *"123456789"})
_MAX_KEYS = 8
_MAX_PROMPT_BYTES = 8 * 1024
_MAX_READ_LINES = 200
_MAX_READ_BYTES = 16 * 1024
_PROMPT_START_MS = 15_000
_AGENT_START_MS = 60_000


def _clean_text(text: str) -> str:
    text = _ANSI_SEQUENCE.sub("", text)
    text = _C1_SEQUENCE.sub("", text)
    return "".join(c for c in text if c in "\n\t" or (ord(c) >= 0x20 and c != "\x7f"))


def _absolute_path(value: object) -> Path | None:
    if not isinstance(value, (str, Path)):
        return None
    try:
        path = Path(value)
        return path.resolve(strict=False) if path.is_absolute() else None
    except (OSError, RuntimeError, ValueError):
        return None


def _invalid(reason: str) -> SupervisionError:
    return SupervisionError("invalid_request", reason=reason)



def _resolved_executable(value: object) -> Path | None:
    if not isinstance(value, (str, Path)):
        return None
    try:
        path = Path(value)
        if not path.is_absolute():
            return None
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        return None
    return resolved


def _trusted_path_entries(runner: Any) -> tuple[Path, ...] | None:
    value = getattr(runner, "trusted_path", None)
    if not isinstance(value, str) or not value:
        return None
    entries = value.split(os.pathsep)
    if any(not entry or not Path(entry).is_absolute() for entry in entries):
        return None
    return tuple(Path(entry) for entry in entries)


def _which(name: str, paths: Sequence[Path]) -> Path | None:
    for directory in paths:
        executable = _resolved_executable(directory / name)
        if executable is not None:
            return executable
    return None


def _shebang_interpreter(script: Path, paths: Sequence[Path]) -> Path | None:
    try:
        with script.open("rb") as stream:
            line = stream.readline(4097)
    except OSError:
        return None
    if len(line) > 4096 or not line.startswith(b"#!"):
        return None
    try:
        words = line[2:].decode("ascii").strip().split()
    except UnicodeDecodeError:
        return None
    if not words:
        return None
    if words[0] == "/usr/bin/env":
        if (
            len(words) != 2
            or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*", words[1])
            or _resolved_executable(words[0]) is None
        ):
            return None
        return _which(words[1], paths)
    if len(words) == 1 and Path(words[0]).is_absolute():
        return _resolved_executable(words[0])
    return None


def _profile_executable_matches(profile: Any, runner: Any) -> bool:
    """Match Herdr's kind lookup to the configured executable or its interpreter.

    Herdr's native records expose no process image, PID, or argv; this is only
    a fixed-path configuration check, so native identity remains weak.
    """
    kind = getattr(profile, "kind", None)
    if not isinstance(kind, str) or kind not in _KINDS:
        return False
    paths = _trusted_path_entries(runner)
    if paths is None:
        return False
    native_executable = _which(kind, paths)
    registered_executable = _resolved_executable(getattr(profile, "executable", None))
    if native_executable is None or registered_executable is None:
        return False
    if registered_executable == native_executable:
        return True
    interpreter = _shebang_interpreter(native_executable, paths)
    return interpreter is not None and interpreter == registered_executable


class _HerdrCLIError(Exception):
    def __init__(self, code: str | None):
        self.code = code


class HerdrBackend:
    """Normalize the fixed Herdr CLI into common supervision records."""

    def __init__(self, connection: Any, runner: Any):
        self.connection = connection
        self.runner = runner

    def _argv(self, args: Sequence[str]) -> list[str]:
        argv = [str(self.connection.executable)]
        if self.connection.session is not None:
            argv.extend(["--session", self.connection.session])
        argv.extend(args)
        return argv

    async def _run(self, args: Sequence[str], *, deadline: float, cwd: Path) -> tuple[int, bytes, bytes]:
        return await self.runner(
            self._argv(args), cwd=cwd, deadline=deadline, input=None
        )

    @staticmethod
    def _error_code(data: bytes) -> str | None:
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        error = payload.get("error") if isinstance(payload, dict) else None
        code = error.get("code") if isinstance(error, dict) else None
        return code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else None

    @staticmethod
    def _cli_error(code: str | None) -> SupervisionError:
        if code in {"agent_not_found", "pane_not_found", "workspace_not_found"}:
            return SupervisionError("stale_target", reason="native_target_missing")
        if code in {"agent_blocked", "agent_not_blocked"}:
            return SupervisionError("invalid_request", reason="agent_not_ready")
        if code in {"agent_prompt_stalled", "timeout"}:
            return SupervisionError("backend_unavailable", reason=code)
        return SupervisionError("backend_unavailable", reason="herdr_command_failed")

    async def _json(
        self, args: Sequence[str], *, deadline: float, cwd: Path
    ) -> dict[str, Any]:
        code, stdout, stderr = await self._run(args, deadline=deadline, cwd=cwd)
        data = stderr if code != 0 else stdout
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SupervisionError("backend_unavailable", reason="invalid_response") from None
        if not isinstance(payload, dict):
            raise SupervisionError("backend_unavailable", reason="invalid_response")
        error = payload.get("error")
        if error is not None or code != 0:
            raise _HerdrCLIError(self._error_code(data))
        result = payload.get("result")
        if not isinstance(result, dict):
            raise SupervisionError("backend_unavailable", reason="invalid_response")
        return result

    async def _call_json(
        self, args: Sequence[str], *, deadline: float, cwd: Path
    ) -> dict[str, Any]:
        try:
            return await self._json(args, deadline=deadline, cwd=cwd)
        except _HerdrCLIError as error:
            raise self._cli_error(error.code) from None

    async def _call_text(
        self, args: Sequence[str], *, deadline: float, cwd: Path
    ) -> bytes:
        code, stdout, stderr = await self._run(args, deadline=deadline, cwd=cwd)
        if code != 0:
            raise self._cli_error(self._error_code(stderr))
        return stdout

    @staticmethod
    def _identity(
        agent: Mapping[str, Any],
        *,
        pane_id: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any] | None:
        actual_pane = agent.get("pane_id")
        if not isinstance(actual_pane, str):
            actual_pane = pane_id
        if not isinstance(actual_pane, str) or not _PANE_ID.fullmatch(actual_pane):
            return None

        encoded_workspace = actual_pane.split(":", 1)[0]
        actual_workspace = agent.get("workspace_id")
        if actual_workspace is None:
            actual_workspace = workspace_id or encoded_workspace
        if (
            not isinstance(actual_workspace, str)
            or not _WORKSPACE_ID.fullmatch(actual_workspace)
            or actual_workspace != encoded_workspace
            or workspace_id is not None and actual_workspace != workspace_id
        ):
            return None

        identity: dict[str, Any] = {
            "pane_id": actual_pane,
            "workspace_id": actual_workspace,
        }
        for field in ("name", "agent"):
            value = agent.get(field)
            if isinstance(value, str):
                identity[field] = value
        identity["strength"] = "weak"
        return identity

    @staticmethod
    def _state(agent: Mapping[str, Any], pane: Mapping[str, Any]) -> tuple[str, str]:
        for source in (agent, pane):
            if "agent_status" not in source:
                continue
            value = source.get("agent_status")
            if isinstance(value, str) and value in _STATUSES:
                return value, "backend"
            return "unknown", "unavailable"
        return "unknown", "unavailable"

    @staticmethod
    def _process_state(agent: Mapping[str, Any], pane: Mapping[str, Any]) -> str:
        for source in (agent, pane):
            value = source.get("process_state")
            if isinstance(value, str) and value in {"running", "exited", "unknown"}:
                return value
        # Herdr's live agent inventory is authoritative that its agent pane is
        # present; its logical `done` state does not imply process exit.
        return "running"

    @staticmethod
    def _record_info(records: Sequence[dict[str, Any]], pane_id: str) -> tuple[Any, Any]:
        for record in records:
            if not isinstance(record, Mapping):
                continue
            nested = record.get("native")
            target = record.get("target")
            containers = [record]
            if isinstance(nested, Mapping):
                containers.append(nested)
            if isinstance(target, Mapping):
                containers.append(target)
            native_id = None
            project = record.get("project")
            profile = record.get("profile")
            for container in containers:
                candidate = container.get("native_id", container.get("pane_id"))
                if candidate == pane_id:
                    native_id = candidate
                    project = container.get("project", project)
                    profile = container.get("profile", profile)
                    break
            if native_id == pane_id:
                return project, profile
        return None, None

    def _row(
        self,
        project: Any,
        workspace: Mapping[str, Any],
        pane: Mapping[str, Any],
        agent: Mapping[str, Any],
        records: Sequence[dict[str, Any]],
    ) -> dict[str, Any] | None:
        pane_id = agent.get("pane_id")
        workspace_id = pane.get("workspace_id")
        if (
            not isinstance(pane_id, str)
            or not _PANE_ID.fullmatch(pane_id)
            or not isinstance(workspace_id, str)
            or not _WORKSPACE_ID.fullmatch(workspace_id)
            or workspace.get("workspace_id") != workspace_id
        ):
            return None
        agent_workspace = agent.get("workspace_id")
        if agent_workspace is not None and agent_workspace != workspace_id:
            return None
        identity = self._identity(agent, pane_id=pane_id, workspace_id=workspace_id)
        if identity is None:
            return None

        project_path = _absolute_path(project.path)
        if project_path is None:
            return None
        worktree = workspace.get("worktree")
        if worktree is None:
            original_repo = project_path
            allowed_root = project_path
        elif isinstance(worktree, Mapping):
            original_repo = _absolute_path(worktree.get("repo_root"))
            checkout = _absolute_path(worktree.get("checkout_path"))
            if original_repo != project_path or checkout is None:
                return None
            allowed_root = checkout
        else:
            return None

        cwd_path = None
        for value in (
            agent.get("cwd"),
            pane.get("foreground_cwd"),
            pane.get("cwd"),
        ):
            cwd_path = _absolute_path(value)
            if cwd_path is not None:
                break
        cwd_is_safe = cwd_path is not None and cwd_path.is_relative_to(allowed_root)
        record_project, record_profile = self._record_info(records, pane_id)
        workspaces = project.workspaces or ()
        configured_workspace = workspace_id in workspaces
        if worktree is None and not (
            configured_workspace or record_project == project.id or cwd_is_safe
        ):
            return None

        name = agent.get("name")
        if not isinstance(name, str) or not name:
            name = pane_id
        agent_state, state_source = self._state(agent, pane)
        row: dict[str, Any] = {
            "native_id": pane_id,
            "project": project.id,
            "name": name,
            "identity": identity,
            "process_state": self._process_state(agent, pane),
            "agent_state": agent_state,
            "state_source": state_source,
            "readonly": bool(project.protected) or not cwd_is_safe,
            "cwd": str(cwd_path) if cwd_path is not None else "",
            "original_repo": str(original_repo),
        }
        if isinstance(record_profile, str):
            row["profile"] = record_profile
        return row

    async def _inventory(
        self,
        projects: Sequence[Any],
        records: Sequence[dict[str, Any]],
        *,
        deadline: float,
        cwd: Path,
    ) -> list[dict[str, Any]]:
        workspaces_result = await self._call_json(
            ["workspace", "list"], deadline=deadline, cwd=cwd
        )
        panes_result = await self._call_json(["pane", "list"], deadline=deadline, cwd=cwd)
        agents_result = await self._call_json(["agent", "list"], deadline=deadline, cwd=cwd)
        workspaces = workspaces_result.get("workspaces")
        panes = panes_result.get("panes")
        agents = agents_result.get("agents")
        if not all(isinstance(values, list) for values in (workspaces, panes, agents)):
            raise SupervisionError("backend_unavailable", reason="invalid_response")

        workspace_by_id: dict[str, Mapping[str, Any]] = {}
        duplicate_workspaces: set[str] = set()
        for workspace in workspaces:
            if not isinstance(workspace, Mapping):
                continue
            workspace_id = workspace.get("workspace_id")
            if not isinstance(workspace_id, str) or not _WORKSPACE_ID.fullmatch(workspace_id):
                continue
            if workspace_id in workspace_by_id:
                duplicate_workspaces.add(workspace_id)
            else:
                workspace_by_id[workspace_id] = workspace
        pane_by_id: dict[str, Mapping[str, Any]] = {}
        duplicate_panes: set[str] = set()
        for pane in panes:
            if not isinstance(pane, Mapping):
                continue
            pane_id = pane.get("pane_id")
            if not isinstance(pane_id, str) or not _PANE_ID.fullmatch(pane_id):
                continue
            if pane_id in pane_by_id:
                duplicate_panes.add(pane_id)
            else:
                pane_by_id[pane_id] = pane

        rows = []
        seen_agents: set[str] = set()
        for agent in agents:
            if not isinstance(agent, Mapping):
                continue
            pane_id = agent.get("pane_id")
            if (
                not isinstance(pane_id, str)
                or pane_id in seen_agents
                or pane_id in duplicate_panes
                or not _PANE_ID.fullmatch(pane_id)
            ):
                continue
            seen_agents.add(pane_id)
            pane = pane_by_id.get(pane_id)
            if pane is None:
                continue
            workspace_id = pane.get("workspace_id")
            if (
                not isinstance(workspace_id, str)
                or workspace_id in duplicate_workspaces
                or workspace_id not in workspace_by_id
            ):
                continue
            workspace = workspace_by_id[workspace_id]
            for project in projects:
                if self.connection.id not in project.connections:
                    continue
                row = self._row(
                    project,
                    workspace,
                    pane,
                    agent,
                    records,
                )
                if row is not None:
                    rows.append(row)
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["native_id"]] = counts.get(row["native_id"], 0) + 1
        return sorted(
            (row for row in rows if counts[row["native_id"]] == 1),
            key=lambda row: (row["project"], row["native_id"]),
        )

    async def inventory(
        self,
        projects: Sequence[Any],
        records: Sequence[dict[str, Any]],
        *,
        deadline: float,
    ) -> list[dict[str, Any]]:
        return await self._inventory(projects, records, deadline=deadline, cwd=Path("/"))

    @staticmethod
    def _target_identity(target: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
        native_id = target.get("native_id")
        identity = target.get("identity")
        if not isinstance(native_id, str) or not _PANE_ID.fullmatch(native_id):
            raise _invalid("invalid_target")
        if (
            not isinstance(identity, Mapping)
            or identity.get("pane_id") != native_id
            or identity.get("strength") != "weak"
        ):
            raise SupervisionError("stale_target")
        return native_id, identity

    async def _fresh_agent(
        self,
        target: Mapping[str, Any],
        *,
        deadline: float,
        cwd: Path = Path("/"),
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        native_id, expected_identity = self._target_identity(target)
        result = await self._call_json(
            ["agent", "get", native_id], deadline=deadline, cwd=cwd
        )
        agent = result.get("agent")
        if not isinstance(agent, dict):
            raise SupervisionError("backend_unavailable", reason="invalid_response")
        actual_identity = self._identity(agent)
        if actual_identity is None or actual_identity != dict(expected_identity):
            raise SupervisionError("stale_target")
        actual_cwd = _absolute_path(agent.get("cwd"))
        prior_cwd = _absolute_path(target.get("cwd"))
        if actual_cwd is not None and prior_cwd is not None and actual_cwd != prior_cwd:
            raise SupervisionError("stale_target")
        current = dict(target)
        current["identity"] = actual_identity
        current["agent_state"], current["state_source"] = self._state(agent, {})
        process_state = agent.get("process_state")
        if isinstance(process_state, str) and process_state in {"running", "exited", "unknown"}:
            current["process_state"] = process_state
        if actual_cwd is not None:
            current["cwd"] = str(actual_cwd)
        return current, agent

    async def read(
        self, target: dict[str, Any], lines: int, *, deadline: float
    ) -> dict[str, Any]:
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= _MAX_READ_LINES:
            raise _invalid("invalid_lines")
        current, _ = await self._fresh_agent(target, deadline=deadline)
        native_id, _ = self._target_identity(target)
        stdout = await self._call_text(
            [
                "agent", "read", native_id, "--source", "recent", "--lines",
                str(lines), "--format", "text",
            ],
            deadline=deadline,
            cwd=Path("/"),
        )
        text = _clean_text(stdout.decode("utf-8", errors="replace"))
        encoded = text.encode("utf-8")
        truncated = len(encoded) > _MAX_READ_BYTES
        if truncated:
            text = encoded[-_MAX_READ_BYTES:].decode("utf-8", errors="ignore")
        return dict(current, text=text, truncated=truncated)

    @staticmethod
    def _refused(code: str) -> dict[str, Any]:
        return {"delivery": "refused", "error": {"code": code}}

    @staticmethod
    def _unknown_delivery() -> dict[str, Any]:
        return {"delivery": "unknown", "error": {"code": "delivery_unknown"}}

    @staticmethod
    def _validate_text(text: object) -> str:
        if not isinstance(text, str) or not text or "\x00" in text:
            raise _invalid("invalid_prompt")
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError:
            raise _invalid("invalid_prompt") from None
        if len(encoded) > _MAX_PROMPT_BYTES:
            raise _invalid("invalid_prompt")
        if any(
            (ord(char) < 0x20 and char not in "\n\t")
            or 0x7F <= ord(char) <= 0x9F
            for char in text
        ):
            raise _invalid("invalid_prompt")
        return text

    @staticmethod
    def _validate_keys(keys: object) -> list[str]:
        if (
            not isinstance(keys, list)
            or not 1 <= len(keys) <= _MAX_KEYS
            or any(not isinstance(key, str) or key not in _KEYS for key in keys)
        ):
            raise _invalid("invalid_keys")
        return keys

    @staticmethod
    def _remaining_ms(deadline: float, maximum: int) -> int:
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining < 1:
            raise SupervisionError("backend_unavailable", reason="deadline")
        return min(maximum, remaining)

    async def prompt(
        self,
        target: dict[str, Any],
        text: str,
        profile: Any,
        *,
        deadline: float,
    ) -> dict[str, Any]:
        text = self._validate_text(text)
        if "herdr" not in profile.backends:
            raise SupervisionError("unsupported_operation", reason="profile_unavailable")
        if target.get("profile") is not None and target["profile"] != profile.id:
            return self._refused("unsupported_operation")
        if target.get("readonly"):
            raise SupervisionError("protected_target")
        if not _profile_executable_matches(profile, self.runner):
            return self._refused("unsupported_operation")
        try:
            current, _ = await self._fresh_agent(target, deadline=deadline)
        except SupervisionError as error:
            if error.code in {"stale_target", "protected_target", "invalid_request"}:
                return self._refused(error.code)
            raise
        if current.get("identity", {}).get("agent") != profile.kind:
            return self._refused("unsupported_operation")
        if current.get("process_state") != "running":
            return self._refused("unsupported_operation")
        if current.get("agent_state") not in {"idle", "done"}:
            return self._refused("invalid_request")

        native_id, _ = self._target_identity(target)
        args = [
            "agent", "prompt", native_id, text, "--wait", "--until", "working",
            "--until", "blocked", "--timeout",
            str(self._remaining_ms(deadline, _PROMPT_START_MS)),
        ]
        try:
            result = await self._json(args, deadline=deadline, cwd=Path("/"))
        except _HerdrCLIError as error:
            if error.code == "agent_prompt_stalled":
                return {
                    "delivery": "confirmed",
                    "started": False,
                    "herdr_code": "agent_prompt_stalled",
                }
            if error.code == "timeout":
                return self._unknown_delivery()
            if error.code in {"agent_blocked", "agent_not_blocked"}:
                return self._refused("invalid_request")
            if error.code in {"agent_not_found", "pane_not_found"}:
                return self._refused("stale_target")
            return self._unknown_delivery()
        except (SupervisionError, OSError, asyncio.TimeoutError):
            return self._unknown_delivery()

        response_agent = result.get("agent")
        if isinstance(response_agent, Mapping):
            response_identity = self._identity(response_agent)
            _, expected_identity = self._target_identity(target)
            if response_identity is not None and response_identity != dict(expected_identity):
                return self._unknown_delivery()
        return {"delivery": "confirmed", "started": True}

    async def answer(
        self,
        target: dict[str, Any],
        keys: list[str],
        *,
        deadline: float,
    ) -> dict[str, Any]:
        keys = self._validate_keys(keys)
        if target.get("readonly"):
            raise SupervisionError("protected_target")
        try:
            current, _ = await self._fresh_agent(target, deadline=deadline)
        except SupervisionError as error:
            if error.code in {"stale_target", "protected_target", "invalid_request"}:
                return self._refused(error.code)
            raise
        if current.get("process_state") != "running":
            return self._refused("unsupported_operation")
        if current.get("agent_state") != "blocked":
            return self._refused("invalid_request")
        native_id, _ = self._target_identity(target)
        try:
            await self._json(
                ["agent", "send-keys", native_id, *keys],
                deadline=deadline,
                cwd=Path("/"),
            )
        except _HerdrCLIError as error:
            if error.code in {"agent_blocked", "agent_not_blocked"}:
                return self._refused("invalid_request")
            if error.code in {"agent_not_found", "pane_not_found"}:
                return self._refused("stale_target")
            return self._unknown_delivery()
        except (SupervisionError, OSError, asyncio.TimeoutError):
            return self._unknown_delivery()
        return {"delivery": "confirmed"}

    async def start(
        self,
        project: Any,
        profile: Any,
        name: str,
        worktree_branch: str | None,
        attempt: dict[str, Any],
        *,
        deadline: float,
    ) -> dict[str, Any]:
        if not isinstance(name, str) or not _AGENT_NAME.fullmatch(name):
            raise _invalid("invalid_agent_name")
        if self.connection.id not in project.connections or profile.id not in project.profiles:
            raise SupervisionError("unsupported_operation", reason="profile_unavailable")
        if "herdr" not in profile.backends or profile.kind not in _KINDS:
            raise SupervisionError("unsupported_operation", reason="profile_unavailable")
        if project.protected:
            raise SupervisionError("protected_target")
        if worktree_branch is not None and (
            not isinstance(worktree_branch, str)
            or not _BRANCH.fullmatch(worktree_branch)
            or ".." in worktree_branch
            or "@{" in worktree_branch
        ):
            raise _invalid("invalid_branch")
        profile_args = profile.args
        if (
            not isinstance(profile_args, (tuple, list))
            or any(not isinstance(arg, str) or "\x00" in arg for arg in profile_args)
        ):
            raise _invalid("invalid_profile_arguments")
        project_path = _absolute_path(project.path)
        if project_path is None:
            raise _invalid("invalid_project_path")
        if not _profile_executable_matches(profile, self.runner):
            raise SupervisionError(
                "unsupported_operation", reason="profile_executable_unsupported"
            )

        try:
            if worktree_branch is None:
                created = await self._json(
                    [
                        "tab", "create", "--cwd", str(project_path), "--label",
                        "dot-" + name, "--no-focus",
                    ],
                    deadline=deadline,
                    cwd=project_path,
                )
            else:
                created = await self._json(
                    [
                        "worktree", "create", "--cwd", str(project_path), "--branch",
                        worktree_branch, "--no-focus",
                    ],
                    deadline=deadline,
                    cwd=project_path,
                )
            root = created.get("root_pane")
            if not isinstance(root, Mapping):
                return self._unknown_delivery()
            pane_id = root.get("pane_id")
            if not isinstance(pane_id, str) or not _PANE_ID.fullmatch(pane_id):
                return self._unknown_delivery()
            encoded_workspace = pane_id.split(":", 1)[0]
            workspace_id = root.get("workspace_id")
            if workspace_id is None:
                workspace_id = encoded_workspace
            if (
                not isinstance(workspace_id, str)
                or not _WORKSPACE_ID.fullmatch(workspace_id)
                or workspace_id != encoded_workspace
            ):
                return self._unknown_delivery()

            root_cwd = _absolute_path(root.get("cwd"))
            if worktree_branch is not None:
                workspace = created.get("workspace")
                worktree = workspace.get("worktree") if isinstance(workspace, Mapping) else None
                checkout = _absolute_path(worktree.get("checkout_path")) if isinstance(worktree, Mapping) else None
                original_repo = _absolute_path(worktree.get("repo_root")) if isinstance(worktree, Mapping) else None
                if (
                    not isinstance(workspace, Mapping)
                    or workspace.get("workspace_id") != workspace_id
                    or checkout is None
                    or original_repo != project_path
                    or root_cwd is None
                    or not root_cwd.is_relative_to(checkout)
                ):
                    return self._unknown_delivery()
            else:
                checkout = root_cwd or project_path
                if not checkout.is_relative_to(project_path):
                    return self._unknown_delivery()
                original_repo = project_path

            start_args = [
                "agent", "start", name, "--kind", profile.kind, "--pane", pane_id,
                "--timeout", str(self._remaining_ms(deadline, _AGENT_START_MS)),
            ]
            if profile_args:
                start_args.extend(["--", *profile_args])
            await self._json(start_args, deadline=deadline, cwd=project_path)

            rows = await self._inventory(
                [project], (), deadline=deadline, cwd=project_path
            )
            row = next((item for item in rows if item["native_id"] == pane_id), None)
            if (
                row is None
                or row.get("name") != name
                or row.get("identity", {}).get("agent") != profile.kind
                or row.get("original_repo") != str(project_path)
                or row.get("process_state") != "running"
                or _absolute_path(row.get("cwd")) is None
                or row.get("readonly")
            ):
                return self._unknown_delivery()
            row["profile"] = profile.id
            row["delivery"] = "confirmed"
            return row
        except asyncio.CancelledError:
            raise
        except (_HerdrCLIError, SupervisionError, OSError, asyncio.TimeoutError):
            return self._unknown_delivery()


