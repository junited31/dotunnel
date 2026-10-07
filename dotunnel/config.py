"""Local administrator-owned configuration; never writable through MCP tools."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .supervision_config import SupervisionSettings, parse_supervision
from .tasks import TaskSpec


@dataclass(frozen=True)
class Config:
    root: Path
    tasks: list[TaskSpec]
    supervision: SupervisionSettings | None = None


def _open_absolute(path: Path, flags: int) -> int:
    """Open each ancestor without following links (Linux only)."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("An absolute non-symlink path is required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        result = os.open(path.name or ".", flags | os.O_NOFOLLOW, dir_fd=fd)
        return result
    except OSError:
        raise ValueError("Configured path is inaccessible or unsafe") from None
    finally:
        os.close(fd)


def _within(path: Path, parent: Path) -> bool:
    return path.is_relative_to(parent)


def _object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate configuration key")
        value[key] = item
    return value


def _keys(value: object, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - (optional or set()):
        raise ValueError("Missing or unknown configuration field")
    return value


def load_config(path: Path | str) -> Config:
    path = Path(os.path.abspath(path))
    fd = _open_absolute(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("Config must be a private regular file owned by the runtime user")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError("Configuration exceeds 64 KiB")
        try:
            data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite configuration number")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Configuration must be valid UTF-8 JSON") from None
    finally:
        os.close(fd)
    data = _keys(data, {"root", "tasks"}, {"supervision"})
    if not isinstance(data["root"], str) or not data["root"] or "\x00" in data["root"]:
        raise ValueError("Invalid workspace root")
    root = Path(data["root"])
    if not root.is_absolute() or ".." in root.parts or root == Path("/") or root == Path.home():
        raise ValueError("Use an explicit project directory, not the filesystem root or home")
    root_fd = _open_absolute(root, os.O_RDONLY | os.O_DIRECTORY)
    os.close(root_fd)
    if _within(path, root) or _within(Path(__file__).absolute().parent, root):
        raise ValueError("Config and MCP runtime code must be outside the writable workspace")
    if not isinstance(data["tasks"], list) or len(data["tasks"]) > 50:
        raise ValueError("Tasks must be a list of at most 50 definitions")
    specs = []
    names = set()
    for value in data["tasks"]:
        task = _keys(value, {"name", "description", "argv"}, {"cwd", "timeout_seconds"})
        name, description, argv = task["name"], task["description"], task["argv"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or name in names:
            raise ValueError("Task names must be unique simple identifiers")
        if not isinstance(description, str) or not 1 <= len(description) <= 512:
            raise ValueError("Invalid task description")
        if not isinstance(argv, list) or not 1 <= len(argv) <= 64 or any(not isinstance(arg, str) or not arg or "\x00" in arg or len(arg) > 4096 for arg in argv):
            raise ValueError("Invalid fixed task argv")
        executable = Path(argv[0])
        if not executable.is_absolute() or ".." in executable.parts or _within(executable, root):
            raise ValueError("Task executable must be absolute and outside the writable workspace")
        cwd = task.get("cwd", ".")
        if not isinstance(cwd, str) or not cwd or "\x00" in cwd or Path(cwd).is_absolute() or ".." in Path(cwd).parts or any(part.startswith(".") for part in Path(cwd).parts if part != "."):
            raise ValueError("Task cwd must be an unhidden directory inside the workspace")
        directory = root / cwd
        directory_fd = _open_absolute(directory, os.O_RDONLY | os.O_DIRECTORY)
        os.close(directory_fd)
        timeout = task.get("timeout_seconds", 60)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
            raise ValueError("Task timeout must be finite and within (0, 300] seconds")
        names.add(name)
        specs.append(TaskSpec(name=name, description=description, argv=tuple(argv), cwd=directory, timeout_seconds=float(timeout)))
    supervision = parse_supervision(data["supervision"], root, path) if "supervision" in data else None
    return Config(root=root, tasks=specs, supervision=supervision)
