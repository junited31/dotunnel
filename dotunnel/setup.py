"""Operator-only interactive setup; never exposed as an MCP tool."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from pathlib import Path
from typing import Callable

from .config import _open_absolute, load_config

TUNNELS_URL = "https://platform.openai.com/settings/organization/tunnels"
KEYS_URL = "https://platform.openai.com/settings/organization/api-keys"
PLUGINS_URL = "https://chatgpt.com/plugins"
CLIENT_URL = "https://github.com/openai/tunnel-client/releases/latest"


def _trusted_parent(path: Path) -> int:
    """Return a no-follow fd only for ancestors protected from other UIDs."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (None, *path.parts[1:]):
            if component is not None:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise ValueError("Setup ancestors must be root/operator-owned and protected from other users' writes (shared sticky directories are allowed)")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _destination(directory: Path) -> Path:
    if ".." in directory.parts:
        raise ValueError("Use a directory without parent traversal")
    directory = Path(os.path.abspath(directory))
    if not directory.name:
        raise ValueError("Choose a new named private directory")
    parent_fd = _trusted_parent(directory.parent)
    try:
        try:
            os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return directory
        raise ValueError("Setup directory already exists; choose a new directory. Nothing overwritten")
    finally:
        os.close(parent_fd)


def _validate(tunnel_id: str, key: str) -> None:
    if not re.fullmatch(r"tunnel_[0-9a-f]{32}", tunnel_id):
        raise ValueError("Paste the tunnel_ ID from Platform Tunnel settings")
    if not key or len(key) > 16384 or any(char.isspace() or char == "\x00" for char in key):
        raise ValueError("Runtime key must be a single nonempty value")


def read_key() -> str:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Use an interactive terminal with hidden input; no credential was requested")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Runtime API key (hidden; never paste into ChatGPT): ").strip()
    except getpass.GetPassWarning:
        raise ValueError("Terminal cannot hide input; credential entry aborted") from None


def _write_private(directory_fd: int, name: str, text: str) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(text)


def create_artifacts(directory: Path, tunnel_id: str, key: str) -> Path:
    """Create a NEW private state directory. Never overwrite or reuse credentials."""
    _validate(tunnel_id, key)
    directory = _destination(directory)
    parent_fd = _trusted_parent(directory.parent)
    try:
        os.mkdir(directory.name, 0o700, dir_fd=parent_fd)
        os.chmod(directory.name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        state_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        os.mkdir("workspace", 0o700, dir_fd=state_fd)
        os.chmod("workspace", 0o700, dir_fd=state_fd, follow_symlinks=False)
        config = directory / "config.json"
        profile = directory / "profile.yaml"
        _write_private(state_fd, "runtime-api-key", key + "\n")
        _write_private(state_fd, "config.json", json.dumps({"root": str(directory / "workspace"), "tasks": []}, indent=2) + "\n")
        # JSON is also valid YAML; quoting paths/commands must not permit YAML injection.
        data = {
            "config_version": 1,
            "control_plane": {
                "base_url": "https://api.openai.com",
                "tunnel_id": tunnel_id,
                "api_key": "file:" + str(directory / "runtime-api-key"),
            },
            "health": {"listen_addr": "127.0.0.1:0", "url_file": str(directory / "health-url")},
            "admin_ui": {"open_browser": False},
            "log": {"level": "warn", "format": "json"},
            "mcp": {
                "stdio_send_initialized_notification": True,
                "commands": [{"channel": "main", "command": shlex.join([sys.executable, "-m", "dotunnel", "serve", "--config", str(config)])}],
            },
        }
        _write_private(state_fd, "profile.yaml", json.dumps(data, indent=2) + "\n")
    finally:
        os.close(state_fd)
    load_config(config)
    return profile


def _environment() -> dict[str, str]:
    return {"HOME": str(Path.home()), "PATH": os.defpath, "LANG": "C.UTF-8"}


def _doctor(client: Path, profile: Path) -> None:
    result = subprocess.run(
        [str(client), "doctor", "--profile-file", str(profile), "--json"],
        env=_environment(), capture_output=True, text=True, timeout=30,
    )
    # Do not relay arbitrary child output into the user's setup transcript.
    try:
        valid = result.returncode == 0 and json.loads(result.stdout).get("result") == "ok"
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("Official client doctor failed; inspect the private profile and client version. Key not displayed")
    print("Configuration doctor: OK. Optional network/stdio probes may be skipped; authentication is NOT proven yet.")


def _health_url(path: Path) -> str:
    parent_fd = _open_absolute(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        # Preserve missing-file semantics while the client publishes its listener.
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("Unsafe local health URL file")
        value = os.read(fd, 257)
    finally:
        os.close(fd)
    if len(value) > 256:
        raise ValueError("Invalid local health URL")
    url = value.decode("utf-8").strip()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Health endpoint must be loopback-only")
    return url.rstrip("/")


def _wait_connected(process: subprocess.Popen, profile: Path) -> str:
    deadline = time.monotonic() + 45
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError("Tunnel client exited before authenticated readiness")
        try:
            url = _health_url(profile.parent / "health-url")
            with opener.open(url + "/health?details=true", timeout=1) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("Invalid client health response")
            health = json.loads(raw)
            if not isinstance(health, dict) or not isinstance(health.get("components"), dict):
                raise ValueError("Invalid client health response")
            control = health["components"].get("control-plane")
            if not isinstance(control, dict) or not isinstance(control.get("details"), dict):
                raise ValueError("Invalid control-plane health response")
            details = control["details"]
            if details.get("consecutive_failures", 0):
                raise ValueError("Control-plane connection failed; check organization permissions, runtime key and Tunnel ID")
            if health.get("live") is True and health.get("ready") is True and control.get("status") == "ok" and details.get("last_success"):
                return url
        except (FileNotFoundError, urllib.error.URLError, TimeoutError):
            pass  # Only initial listener/file availability is transient.
        time.sleep(0.1)
    raise ValueError("Authenticated readiness not observed within 45 seconds; foreground client will stop")


def _stop(process: subprocess.Popen) -> None:
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # Clean same-group descendants even after an early parent exit.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    finally:
        signal.signal(signal.SIGINT, previous)


def _registration(tunnel_id: str) -> None:
    print(f"ChatGPT registration: {PLUGINS_URL}")
    print(f"Create a custom MCP app; Connection = Tunnel; select/paste {tunnel_id}.")
    print("This local stdio MCP has no separate OAuth; its Platform runtime key is NOT an app authentication field.")
    print("In ChatGPT, select your registered app (menu location varies by account/UI), then send a file-list request to verify tools.")


def _foreground(client: Path, profile: Path, tunnel_id: str) -> int:
    process = subprocess.Popen(
        [str(client), "run", "--profile-file", str(profile)],
        env=_environment(), start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        url = _wait_connected(process, profile)
        print(f"Authenticated polling and readiness: OK. Local health: {url}/health?details=true")
        _registration(tunnel_id)
        print("Client remains running ONLY while this foreground command is active. Ctrl-C stops it; it does not revoke app/key access.")
        code = process.wait()
        print(f"Foreground client exited (code {code}). ChatGPT calls can no longer be handled by this client.")
        return 0 if code == 0 else 2
    except KeyboardInterrupt:
        print("\nStopping the setup-owned foreground client; no other clients are touched.")
        return 0
    finally:
        _stop(process)
        print("Foreground client stopped. Private app/Tunnel/key remain; no automatic restart is configured.")


class _SetupParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Unknown/malformed argument diagnostics may include a mistakenly pasted key.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid setup arguments; use --help. Runtime keys belong only in the hidden terminal prompt, never argv.\n")


def main(
    argv: list[str] | None = None,
    *,
    configuration_callback: Callable[[Path], None] | None = None,
) -> int:
    parser = _SetupParser(prog="dotunnel setup", description="Interactive private MCP Tunnel setup (no automatic OS/account/service changes)")
    parser.add_argument("--directory", type=Path, default=Path.cwd() / ".dotunnel-setup", help="NEW private setup directory; existing directories are refused")
    parser.add_argument("--tunnel-client", type=Path, default=Path(shutil.which("tunnel-client") or Path.cwd() / ".tunnel-client" / "tunnel-client"), help="Trusted official client executable, installed separately")
    args = parser.parse_args(argv)
    print(f"1. Create/manage a Tunnel: {TUNNELS_URL}")
    print("Organization permissions: Read + Manage for creation; Read + Use for runtime/app selection.")
    print("Associate BOTH the owning Platform organization and target ChatGPT workspace. Developer-mode access is separate.")
    print(f"2. Create a Restricted runtime API key (Tunnels Read + Use): {KEYS_URL}")
    print("Do not use an Admin key. Key permissions cannot grant organization access you do not have.")
    print(f"Official client download/install and checksum: {CLIENT_URL}")
    print("No OS account, group, service, browser, public endpoint or repository changes are performed.")
    profile: Path | None = None
    try:
        if sys.platform != "linux" or os.getuid() == 0:
            raise ValueError("Run on Linux as a non-root user")
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValueError("Setup requires an interactive terminal; no credential was requested")
        directory = _destination(args.directory)
        client = args.tunnel_client.absolute()
        if not client.is_file() or not os.access(client, os.X_OK):
            raise ValueError("Install and verify the official client, then pass its executable via --tunnel-client")
        print(f"New private directory: {directory}; writable workspace: {directory / 'workspace'}; tasks disabled.")
        print("Use a least-privilege runtime account; this setup does not remove existing permissions (including Docker access).")
        print("Do not include secrets in workspace files. Keep this private setup directory out of version control.")
        tunnel_id = input("Tunnel ID from Platform settings: ").strip()
        if not re.fullmatch(r"tunnel_[0-9a-f]{32}", tunnel_id):
            raise ValueError("Invalid Tunnel ID; no credential was requested")
        key = read_key()
        profile = create_artifacts(directory, tunnel_id, key)
        del key
        print("Private key/config/profile saved; credential value not displayed. Existing files were not overwritten.")
        _doctor(client, profile)
        if configuration_callback is not None:
            configuration_callback(profile)
        command = shlex.join([str(client), "run", "--profile-file", str(profile)])
        print(f"Manual foreground command (no secret argument): env -i HOME={shlex.quote(str(Path.home()))} PATH={shlex.quote(os.defpath)} LANG=C.UTF-8 {command}")
        print("Stdio supports ONE active client per Tunnel. Do not start if another client already owns this Tunnel.")
        answer = input("Start manual foreground connection now? [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            return _foreground(client, profile, tunnel_id)
        _registration(tunnel_id)
        print("NOT CONNECTED: start the printed foreground command before registering/testing the app; it must remain running.")
        return 0
    except ValueError as error:
        if configuration_callback is not None and profile is not None:
            print(f"Setup failed: {error}. Private files are preserved; rerun dotunnel setup to reconfigure this setup without replacing its key or profile.", file=sys.stderr)
        else:
            print(f"Setup failed: {error}. Private files already created are preserved; use a new directory to retry.", file=sys.stderr)
        return 2
    except (OSError, EOFError, subprocess.TimeoutExpired) as error:
        if configuration_callback is not None and profile is not None:
            print("Setup input or local files failed; private files are preserved. Rerun dotunnel setup to reconfigure this setup without replacing its key or profile.", file=sys.stderr)
        else:
            print(f"Setup failed ({type(error).__name__}); check local files/client or interrupted input. No key value is displayed; private files already created are preserved.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nSetup cancelled; private files already created are preserved, never overwritten.", file=sys.stderr)
        return 130
