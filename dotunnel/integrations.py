"""Installed native CLI discovery and credential-content-free job validation."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import shlex
import subprocess
from typing import Any

from . import cli_backend, cli_jobs, config as config_helpers
from .files import WorkspaceFiles, _validate_components


SUPPORTED_CLIS = ("codex", "claude", "omp")
CLI_LABELS = {"codex": "Codex", "claude": "Claude Code", "omp": "OMP"}
TASK_NAMES = {backend: f"dotunnel-{backend}" for backend in SUPPORTED_CLIS}
BWRAP_PATH = Path("/usr/bin/bwrap")
_COMMANDS = {"codex": "codex", "claude": "claude", "omp": "omp"}
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY_FLAGS = _FILE_FLAGS | os.O_DIRECTORY


def is_managed_task(task: dict[str, Any], backend: str, job_config: Path) -> bool:
    """Classify a fixed setup task by its executable/arguments, not display wording."""
    required = {"name", "description", "argv"}
    allowed = required | {"cwd", "timeout_seconds"}
    argv = task.get("argv")
    return (
        required <= set(task) <= allowed
        and task.get("name") == TASK_NAMES.get(backend)
        and isinstance(task.get("description"), str)
        and isinstance(argv, (list, tuple))
        and len(argv) == 4
        and isinstance(argv[0], str)
        and Path(argv[0]).is_absolute()
        and Path(argv[0]).name == "dotunnel"
        and ".." not in Path(argv[0]).parts
        and tuple(argv[1:]) == ("cli-job", "--config", str(job_config))
        and task.get("cwd", ".") == "."
        and not isinstance(task.get("timeout_seconds"), bool)
        and task.get("timeout_seconds", 60) == 240
    )


def _trusted_parent(path: Path) -> int:
    from .setup import _trusted_parent as setup_trusted_parent

    return setup_trusted_parent(path)


def _inspect_launcher(candidate: str) -> Path | None:
    try:
        launcher = Path(candidate)
        if not launcher.is_absolute() or ".." in launcher.parts:
            return None
        launcher_parent = _trusted_parent(launcher.parent)
        try:
            original = os.stat(launcher.name, dir_fd=launcher_parent, follow_symlinks=False)
        finally:
            os.close(launcher_parent)
        if not (stat.S_ISREG(original.st_mode) or stat.S_ISLNK(original.st_mode)):
            return None
        if original.st_uid not in (0, os.getuid()):
            return None
        resolved = launcher.resolve(strict=True)
        if not resolved.is_absolute() or ".." in resolved.parts:
            return None
        parent_fd = _trusted_parent(resolved.parent)
        try:
            fd = os.open(resolved.name, _FILE_FLAGS, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022
                or not info.st_mode & 0o111
            ):
                return None
        finally:
            os.close(fd)
        return resolved
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def discover_clis() -> dict[str, Path]:
    """Find installed PATH launchers without executing any native CLI command."""
    found: dict[str, Path] = {}
    for backend in SUPPORTED_CLIS:
        candidate = shutil.which(_COMMANDS[backend])
        if candidate is None:
            continue
        resolved = _inspect_launcher(candidate)
        if resolved is not None:
            found[backend] = resolved
    return found


def _checked_path(path: Path, kind: str, *, private: bool = False) -> os.stat_result:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ValueError("Native runtime path is invalid")
    flags = _DIRECTORY_FLAGS if kind == "directory" else _FILE_FLAGS
    try:
        parent_fd = _trusted_parent(path.parent)
        try:
            fd = os.open(path.name, flags, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    except (OSError, TypeError, ValueError):
        raise ValueError("Native runtime path is unavailable or unsafe") from None
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise ValueError("Native runtime path metadata is unsafe")
    if kind == "directory":
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Native runtime directory is invalid")
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Native runtime file is invalid")
        if kind == "executable" and not info.st_mode & 0o111:
            raise ValueError("Native runtime executable is not executable")
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("Native authentication reference must be private to the operator")
    return info


def _check_private_file(path: Path, *, limit: int) -> os.stat_result:
    info = _checked_path(path, "file", private=True)
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit:
        raise ValueError("Operator-managed integration file is not private and bounded")
    return info


def _check_workspace(workspace: Path) -> None:
    if not workspace.is_absolute() or ".." in workspace.parts:
        raise ValueError("MCP workspace is invalid")
    try:
        from .setup import _trusted_parent as trusted_parent

        parent_fd = trusted_parent(workspace.parent)
        try:
            fd = os.open(workspace.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    except (OSError, TypeError, ValueError):
        raise ValueError("MCP workspace is unavailable or unsafe") from None
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("MCP workspace must be a private operator-owned directory")


def _check_runtime_metadata(backend: str, runtime: dict[str, str]) -> None:
    expected_kinds = {
        "codex": {"executable": "executable", "companion": "executable", "auth": "file"},
        "claude": {"executable": "executable", "oauth_token": "file"},
        "omp": {
            "executable": "executable",
            "cli": "file",
            "modules": "directory",
            "config": "file",
            "auth": "file",
        },
    }.get(backend)
    if expected_kinds is None:
        raise ValueError("Unsupported native backend")

    checked: dict[str, Path] = {}
    for key, kind in expected_kinds.items():
        path = Path(runtime[key])
        private = key in {"auth", "oauth_token", "config"}
        info = _checked_path(path, kind, private=private)
        if key == "oauth_token" and info.st_size > 4096:
            raise ValueError("Claude OAuth token reference exceeds the supported size")
        checked[key] = path

    if backend == "codex":
        executable = checked["executable"]
        companion = checked["companion"]
        if companion.parent != executable.parent or companion.name != "codex-code-mode-host":
            raise ValueError("Codex companion must be adjacent to the native executable")
    elif backend == "omp":
        if not checked["cli"].is_relative_to(checked["modules"]):
            raise ValueError("OMP CLI must be inside its installed module directory")
        for sidecar in cli_backend._optional_readonly_siblings(checked["auth"]):
            _checked_path(sidecar, "file", private=True)


def _check_target_files(target: cli_jobs._Target, workspace: Path) -> None:
    root = target.root
    if root == workspace or root.is_relative_to(workspace) or workspace.is_relative_to(root):
        raise ValueError("Source root and writable MCP workspace must be separate")
    source = WorkspaceFiles(root)
    try:
        for relative in target.files:
            components = _validate_components(relative, allow_root=False)
            parent_fd = source._open_directory(components[:-1])
            try:
                info = os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64 * 1024:
                    raise ValueError("Allowed source file is unavailable or unsafe")
                fd = os.open(
                    components[-1],
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(fd)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_nlink != 1
                        or opened.st_dev != info.st_dev
                        or opened.st_ino != info.st_ino
                        or opened.st_size > 64 * 1024
                    ):
                        raise ValueError("Allowed source file changed or is unsafe")
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)
    except (OSError, TypeError, UnicodeError):
        raise ValueError("Allowed source path is unavailable or unsafe") from None
    finally:
        source.close()


def _check_bwrap(path: Path) -> None:
    try:
        info = _checked_path(path, "executable")
    except (OSError, TypeError, ValueError):
        raise ValueError("Bubblewrap is required at /usr/bin/bwrap for native CLI integrations") from None
    if info.st_mode & 0o022:
        raise ValueError("Bubblewrap is required at /usr/bin/bwrap for native CLI integrations")


_PROBE_TARGET = next((path for path in ("/usr/bin/true", "/bin/true") if os.path.exists(path)), "/bin/true")


def bubblewrap_status(path: Path = BWRAP_PATH) -> str:
    """Return "ready", "missing" or "unusable" without trusting presence alone.

    The probe asks for the same namespace isolation as real CLI jobs, so a
    binary that exists but cannot create namespaces (kernel, AppArmor or
    container policy) is reported as unusable rather than ready.
    """
    try:
        _check_bwrap(path)
    except ValueError:
        return "missing"
    command = [
        str(path), "--die-with-parent", "--unshare-all", "--cap-drop", "ALL",
        "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", _PROBE_TARGET,
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unusable"
    return "ready" if result.returncode == 0 else "unusable"


_INSTALL_ARGV = (
    ({"debian", "ubuntu"}, ("sudo", "apt-get", "install", "-y", "bubblewrap")),
    ({"fedora", "rhel", "centos"}, ("sudo", "dnf", "install", "-y", "bubblewrap")),
    ({"arch"}, ("sudo", "pacman", "-S", "--noconfirm", "bubblewrap")),
    ({"opensuse", "suse", "sles"}, ("sudo", "zypper", "--non-interactive", "install", "bubblewrap")),
    ({"alpine"}, ("sudo", "apk", "add", "bubblewrap")),
)
_ADMIN_GROUPS = frozenset({"sudo", "wheel", "admin"})


def bubblewrap_install_argv(os_release: Path = Path("/etc/os-release")) -> list[str] | None:
    """The distribution's non-interactive install command; None for unknown distributions."""
    try:
        text = os_release.read_text(encoding="utf-8", errors="replace")[:65536]
    except OSError:
        return None
    families: list[str] = []
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() in ("ID", "ID_LIKE"):
            families += value.strip().strip("'\"").lower().split()
    for family in families:
        for names, argv in _INSTALL_ARGV:
            if family in names or any(family.startswith(name + "-") for name in names):
                return list(argv)
    return None


def _group_names() -> set[str]:
    import grp

    names: set[str] = set()
    for gid in os.getgroups():
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return names


def sudo_available(*, sudo: str | None | object = ..., group_names: set[str] | None = None) -> bool:
    """Best-effort check that this account may use sudo, without asking for a password.

    Passwordless sudo is detected with `sudo -n true`; password sudo is inferred from
    membership in a conventional administrator group. A wrong guess only means the
    install attempt fails and setup falls back to printed guidance.
    """
    path = shutil.which("sudo") if sudo is ... else sudo
    if not path:
        return False
    try:
        result = subprocess.run(
            [str(path), "-n", "true"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        if result.returncode == 0:
            return True
    except (OSError, subprocess.SubprocessError):
        return False
    groups = _group_names() if group_names is None else group_names
    return bool(groups & _ADMIN_GROUPS)


def install_bubblewrap(argv: list[str]) -> bool:
    """Run the approved install command on this terminal so sudo can ask for a password."""
    print(f"Running: {shlex.join(argv)}", flush=True)
    try:
        return subprocess.run(argv, timeout=900).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def print_bubblewrap_status(status: str) -> None:
    """Explain readiness for optional CLI integrations; the core MCP never needs it."""
    if status == "ready":
        print("Bubblewrap: ready (required only for optional Codex/Claude Code/OMP integrations).")
        return
    if status == "missing":
        print("Bubblewrap: not installed. It is required only for optional Codex/Claude Code/OMP integrations;")
        print("the Tunnel connection, file tools and fixed tasks work without it.")
    else:
        print("Bubblewrap: installed but cannot create isolated namespaces here (kernel, AppArmor or container policy).")
        print("Optional CLI integrations stay unavailable until an administrator allows unprivileged user namespaces for bwrap.")


def print_bubblewrap_guidance(argv: list[str] | None) -> None:
    if argv:
        print(f"Install it from an account with sudo rights: {shlex.join(argv)}")
    else:
        print("Install the 'bubblewrap' package (providing /usr/bin/bwrap) with your distribution's package manager, using sudo.")


def _validate_job_data(
    config_path: Path,
    backend: str,
    workspace: Path,
    value: dict[str, Any],
    request_text: str,
    *,
    bwrap_path: Path = BWRAP_PATH,
) -> cli_jobs._JobConfig:
    try:
        parsed = cli_jobs._parse_config_shape(value)
        if (
            parsed.backend != backend
            or parsed.workspace != workspace
            or parsed.request != f"dotunnel-requests/{backend}.json"
            or config_path.name != f"{backend}.json"
            or config_path.parent.name != "cli-jobs"
            or len(parsed.targets) != 1
        ):
            raise ValueError
        cli_jobs._validate_runtime_paths(parsed, config_path)
        cli_jobs._validate_target_roots(parsed.targets)
        _check_workspace(workspace)
        credentials = {
            Path(path) for key, path in parsed.runtime.items()
            if key in {"auth", "oauth_token", "config"}
        }
        credentials |= {
            Path(str(path) + suffix) for path in tuple(credentials)
            for suffix in ("-wal", "-shm")
        }
        private_state = config_path.parent.parent
        for target in parsed.targets.values():
            for relative in target.files:
                candidate = target.root / relative
                if candidate in credentials or candidate.is_relative_to(private_state):
                    raise ValueError
        for target in parsed.targets.values():
            _check_target_files(target, workspace)
        cli_jobs._parse_request(request_text, parsed.targets)
        _check_runtime_metadata(backend, parsed.runtime)
        _check_bwrap(bwrap_path)
        return parsed
    except (cli_jobs._InvalidConfig, cli_jobs._InvalidRequest, KeyError, OSError, TypeError, UnicodeError, ValueError):
        raise ValueError("Selected CLI runtime or source scope is invalid; verify prompted paths, editable files, and required Bubblewrap. Nothing was registered.") from None


def _read_request(workspace: Path, request: str) -> str:
    files = WorkspaceFiles(workspace)
    try:
        return files.read_file(request)["content"]
    finally:
        files.close()


def _load_managed_job(
    config_path: Path,
    backend: str,
    workspace: Path,
    *,
    bwrap_path: Path = BWRAP_PATH,
) -> tuple[cli_jobs._JobConfig, dict[str, Any]]:
    try:
        actual_path, value = cli_jobs._load_private_config(os.fspath(config_path))
        parsed = cli_jobs._parse_config_shape(value)
        if (
            parsed.backend != backend
            or parsed.workspace != workspace
            or parsed.request != f"dotunnel-requests/{backend}.json"
            or actual_path.name != f"{backend}.json"
            or actual_path.parent.name != "cli-jobs"
        ):
            raise cli_jobs._InvalidConfig
        _check_private_file(actual_path, limit=64 * 1024)
        _check_private_file(workspace / parsed.request, limit=64 * 1024)
        request_text = _read_request(workspace, parsed.request)
    except (cli_jobs._InvalidConfig, cli_jobs._InvalidRequest, OSError, TypeError, UnicodeError, ValueError):
        raise ValueError("Native CLI integration configuration is invalid or unsafe") from None
    checked = _validate_job_data(
        actual_path,
        backend,
        workspace,
        value,
        request_text,
        bwrap_path=bwrap_path,
    )
    return checked, value


def validate_managed_job(config_path: Path, backend: str, workspace: Path) -> bool:
    """Return safe metadata validity without opening auth/token contents or running a CLI."""
    if backend not in SUPPORTED_CLIS or not isinstance(config_path, Path) or not isinstance(workspace, Path):
        return False
    try:
        _load_managed_job(config_path, backend, workspace)
    except (cli_jobs._InvalidConfig, cli_jobs._InvalidRequest, OSError, TypeError, ValueError):
        return False
    return True
