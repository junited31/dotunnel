"""Explicit operator commands for a local Dotunnel setup."""

from __future__ import annotations

import argparse
import http.client
import importlib.metadata
import json
import os
import shutil
import stat
import sys
import urllib.parse
from pathlib import Path

from . import __version__
from .config import load_config


_HELP = """Usage: dotunnel <command> [options]

Commands:
  help       Show this usage and command reference.
  setup      Review workspace, file access, fixed CLI tasks and live-agent permissions.
  update     Check GitHub Releases and ask Y/n before upgrading this virtualenv.
  doctor     Validate an existing setup and inspect local Tunnel/CLI readiness.
  supervision  Initialize or explicitly reinitialize private supervision state.

Engine commands (normally started by the Tunnel client or a registered task):
  serve --config PATH [--check-config]
             Run the stdio MCP server for one trusted config; --check-config validates only.
  cli-job --config PATH
             Run one isolated native CLI job (registered task argv; see cli-job --help).
  claude-token --output PATH [--replace]
             Save a Claude long-lived token to a private file from an interactive terminal.

Setup options:
  --directory DIR       New private setup or explicit permission migration of an existing setup.
  --tunnel-client PATH  Path to the separately installed client executable.

Doctor options:
  --directory DIR       Existing setup directory (default: .dotunnel-setup in the current directory).
  --tunnel-client PATH  Trusted absolute executable (default: installed tunnel-client on PATH).

Supervision options (dotunnel supervision):
  init --config PATH    Initialize configured private state; never starts an agent.
  reinit --config PATH  Rotate the epoch after interactive reconciliation; retain prior state.

Setup and doctor require Linux and a non-root user; setup also requires an interactive terminal.
A new setup is created after prompts. An existing directory reconfigures only setup-owned CLI
integrations and preserves its existing key/profile. Credentials use the hidden prompt; never put
secrets in command arguments.
Update checks GitHub releases over HTTPS without gh or GitHub login. A newer version prompts [Y/n];
Enter approves, n cancels. Installation requires a non-root Linux, non-editable virtualenv.
Update never restarts services. Doctor is read-only: it does not start a Tunnel client or make a
model request, and reports readiness only when observed from the local health endpoint.

Exit status: 0 for success, 2 for invalid arguments, unsupported environment, or failed checks.
"""


class _DoctorParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        self.exit(2, "Invalid doctor arguments; use 'dotunnel help' for usage.\n")


def _argument_error() -> int:
    print("Invalid dotunnel command or arguments; use 'dotunnel help' for usage.", file=sys.stderr)
    return 2


def _supported_environment() -> bool:
    return sys.platform == "linux" and os.getuid() != 0


def _environment_error() -> int:
    print("Setup and doctor require Linux and a non-root user.", file=sys.stderr)
    return 2


def _installed_version() -> tuple[str, bool]:
    try:
        return importlib.metadata.version("dotunnel"), False
    except (importlib.metadata.PackageNotFoundError, OSError, ValueError):
        return __version__, True




def _safe_regular_file(path: Path, *, executable: bool = False, private: bool = False) -> bool:
    absolute = Path(os.path.abspath(path))
    parent_fd = file_fd = -1
    try:
        from .setup import _trusted_parent

        parent_fd = _trusted_parent(absolute.parent)
        file_fd = os.open(
            absolute.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return False
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            return False
        if executable and not info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            return False
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            return False
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _bubblewrap_status() -> str:
    from .integrations import BWRAP_PATH, bubblewrap_status

    return bubblewrap_status(BWRAP_PATH)


def _local_readiness(health_file: Path) -> tuple[bool, bool]:
    """Return (endpoint_observed, ready_with_a_successful_control-plane_poll)."""
    from .setup import _health_url

    try:
        url = _health_url(health_file)
        parsed = urllib.parse.urlsplit(url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=1)
        try:
            connection.request("GET", "/health?details=true")
            response = connection.getresponse()
            if response.status != 200:
                return True, False
            raw = response.read(65537)
        finally:
            connection.close()
        if len(raw) > 65536:
            return True, False
        health = json.loads(raw)
        components = health.get("components") if isinstance(health, dict) else None
        control = components.get("control-plane") if isinstance(components, dict) else None
        details = control.get("details") if isinstance(control, dict) else None
        if not isinstance(control, dict) or not isinstance(details, dict):
            return True, False
        observed = (
            health.get("live") is True
            and health.get("ready") is True
            and control.get("status") == "ok"
            and not details.get("consecutive_failures", 0)
            and isinstance(details.get("last_success"), str)
            and bool(details["last_success"])
        )
        return True, observed
    except FileNotFoundError:
        return False, False
    except (OSError, ValueError, UnicodeError, http.client.HTTPException, json.JSONDecodeError):
        return False, False


def _matches_managed_task(task: object, backend: str, job_config: Path, workspace: Path) -> bool:
    from .integrations import is_managed_task

    value = {
        "name": getattr(task, "name", None),
        "description": getattr(task, "description", None),
        "argv": getattr(task, "argv", ()),
        "cwd": "." if getattr(task, "cwd", None) == workspace else None,
        "timeout_seconds": getattr(task, "timeout_seconds", None),
    }
    return is_managed_task(value, backend, job_config) and _safe_regular_file(
        Path(value["argv"][0]), executable=True,
    )


def _managed_job_config_path(task: object, backend: str, directory: Path) -> Path | None:
    argv = getattr(task, "argv", ())
    if (
        not isinstance(argv, (list, tuple))
        or len(argv) != 4
        or tuple(argv[1:3]) != ("cli-job", "--config")
        or not isinstance(argv[3], str)
    ):
        return None
    job_config = Path(argv[3])
    if not job_config.is_absolute() or ".." in job_config.parts:
        return None
    try:
        relative = job_config.relative_to(directory)
    except ValueError:
        return None
    if relative == Path("cli-jobs") / f"{backend}.json":
        return job_config
    if (
        len(relative.parts) == 3
        and relative.parts[0] == "native-cli"
        and relative.parts[1]
        and all(character.isalnum() or character in "_-" for character in relative.parts[1])
        and relative.parts[2] == f"{backend}.json"
    ):
        return job_config
    return None



def _diagnose(argv: list[str]) -> int:
    parser = _DoctorParser(
        prog="dotunnel doctor",
        description="Read-only checks for an existing local setup.",
    )
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path.cwd() / ".dotunnel-setup",
        help="Existing setup directory",
    )
    parser.add_argument(
        "--tunnel-client",
        type=Path,
        default=Path(client) if (client := shutil.which("tunnel-client")) else None,
        help="Local tunnel-client executable",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code) if isinstance(error.code, int) else 2

    if not _supported_environment():
        return _environment_error()

    directory = Path(os.path.abspath(args.directory))
    try:
        config = load_config(directory / "config.json")
    except (OSError, ValueError):
        print("MCP configuration: missing, invalid, or unsafe.")
        return 2
    print(f"MCP configuration: valid ({len(config.tasks)} fixed task(s)).")

    tasks_by_name = {task.name: task for task in config.tasks}
    configured_names = {
        backend for backend in ("codex", "claude", "omp")
        if f"dotunnel-{backend}" in tasks_by_name
    }
    try:
        from .integrations import discover_clis, validate_managed_job

        installed = discover_clis()
        installed_names = {name for name in ("codex", "claude", "omp") if name in installed}
    except Exception:
        print("Native CLI discovery: failed.")
        return 2

    print("Configured CLI integrations: " + (", ".join(sorted(configured_names)) if configured_names else "none"))
    print("Installed native CLIs: " + (", ".join(sorted(installed_names)) if installed_names else "none"))
    checks_ok = True
    missing_clis = configured_names - installed_names
    if missing_clis:
        print("Configured CLI integrations missing an installed CLI: " + ", ".join(sorted(missing_clis)) + ".")
        checks_ok = False

    for backend in sorted(configured_names):
        task = tasks_by_name[f"dotunnel-{backend}"]
        job_config = _managed_job_config_path(task, backend, directory)
        if job_config is None or not _matches_managed_task(task, backend, job_config, config.root):
            valid_job = False
        else:
            try:
                valid_job = validate_managed_job(job_config, backend, config.root)
            except Exception:
                valid_job = False
        if valid_job:
            print(f"Configured {backend} CLI integration metadata: valid.")
        else:
            print(f"Configured {backend} CLI integration metadata: invalid or unsafe.")
            checks_ok = False

    try:
        sandbox_status = _bubblewrap_status()
    except Exception:
        sandbox_status = "unusable"
    from .integrations import bubblewrap_install_argv, print_bubblewrap_guidance, print_bubblewrap_status

    print_bubblewrap_status(sandbox_status)
    if sandbox_status == "missing":
        print_bubblewrap_guidance(bubblewrap_install_argv())
    if configured_names and sandbox_status != "ready":
        print("Configured CLI integrations require a working Bubblewrap.")
        checks_ok = False

    profile = directory / "profile.yaml"
    client = args.tunnel_client
    if not _safe_regular_file(profile, private=True):
        print("Tunnel profile: missing or unsafe.")
        checks_ok = False
    elif client is None or not client.is_absolute() or not _safe_regular_file(client, executable=True):
        print("Tunnel client doctor: executable missing or unsafe.")
        checks_ok = False
    else:
        try:
            from .setup import _doctor

            _doctor(client, profile)
        except Exception:
            print("Tunnel client doctor: failed.")
            checks_ok = False
        else:
            print("Tunnel client doctor: passed.")

    endpoint_observed, ready = _local_readiness(directory / "health-url")
    if ready:
        print("Local Tunnel readiness: live and ready; successful control-plane polling observed.")
    elif endpoint_observed:
        print("Local Tunnel readiness: endpoint responded, but ready state or successful polling was not observed.")
        checks_ok = False
    else:
        print("Local Tunnel readiness: not observed; no client was started.")
        checks_ok = False
    return 0 if checks_ok else 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("Run 'dotunnel help' for usage.", file=sys.stderr)
        return 2

    command, command_args = args[0], args[1:]
    if command == "help":
        if command_args:
            return _argument_error()
        print(_HELP, end="")
        return 0
    if command == "update":
        if command_args:
            return _argument_error()
        from .updates import run_update

        return run_update(*_installed_version())
    if command == "doctor":
        return _diagnose(command_args)
    if command == "supervision":
        from .supervision_cli import main as supervision_main

        return int(supervision_main(command_args))
    if command == "setup":
        if not _supported_environment():
            return _environment_error()
        try:
            from .onboarding import main as setup_main

            return int(setup_main(command_args))
        except SystemExit as error:
            return int(error.code) if isinstance(error.code, int) else 2
    if command == "serve":
        from .serve import main as serve_main

        return serve_main(command_args)
    if command == "cli-job":
        from .cli_jobs import main as cli_job_main

        return int(cli_job_main(command_args))
    if command == "claude-token":
        from .claude_token import main as claude_token_main

        return int(claude_token_main(command_args))
    return _argument_error()


if __name__ == "__main__":
    raise SystemExit(main())
