"""Private setup artifact and Tunnel-client helpers for operator onboarding."""

from __future__ import annotations

import getpass
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
import uuid
from pathlib import Path

from .config import _open_absolute, load_config

PLUGINS_URL = "https://chatgpt.com/plugins"


def _trusted_parent(path: Path, *, root_only: bool = False) -> int:
    """Return a no-follow fd only for ancestors protected from untrusted writes."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (None, *path.parts[1:]):
            if component is not None:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if (
                info.st_uid != 0 and (root_only or info.st_uid != os.getuid())
            ) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                if root_only:
                    raise ValueError("System executable ancestors must be root-owned and protected from other users' writes")
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


def _create_workspace(path: Path) -> tuple[int, int, int, int]:
    parent_fd = _trusted_parent(path.parent)
    fd = -1
    created = False
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        created = True
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("New workspace must be private and operator-owned")
        return parent_fd, fd, info.st_dev, info.st_ino
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if created:
            try:
                os.rmdir(path.name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
        raise


def prepare_private_artifacts(
    directory: Path,
    tunnel_id: str,
    key: str,
    *,
    workspace: Path,
    create_workspace: bool,
) -> tuple[Path, tuple[int, int, int, int] | None]:
    """Create key/profile references only after approval; publish no config."""
    _validate(tunnel_id, key)
    directory = _destination(directory)
    if not workspace.is_absolute() or ".." in workspace.parts or workspace in (Path("/"), Path.home()):
        raise ValueError("Choose an explicit safe workspace directory")
    if (directory / "config.json").is_relative_to(workspace):
        raise ValueError("Private setup configuration must remain outside the writable workspace")
    parent_fd = _trusted_parent(directory.parent)
    try:
        os.mkdir(directory.name, 0o700, dir_fd=parent_fd)
        state_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    owned_workspace = None
    try:
        if create_workspace:
            owned_workspace = _create_workspace(workspace)
        else:
            fd = _open_absolute(workspace, os.O_RDONLY | os.O_DIRECTORY)
            os.close(fd)
        _write_private(state_fd, "runtime-api-key", key + "\n")
        config = directory / "config.json"
        data = {
            "config_version": 1,
            "control_plane": {"base_url": "https://api.openai.com", "tunnel_id": tunnel_id,
                              "api_key": "file:" + str(directory / "runtime-api-key")},
            "health": {"listen_addr": "127.0.0.1:0", "url_file": str(directory / "health-url")},
            "admin_ui": {"open_browser": False},
            "log": {"level": "warn", "format": "json"},
            "mcp": {"stdio_send_initialized_notification": True,
                    "commands": [{"channel": "main", "command": shlex.join([
                        sys.executable, "-I", "-m", "dotunnel", "serve", "--config", str(config),
                    ])}]},
        }
        _write_private(state_fd, "profile.yaml", json.dumps(data, indent=2) + "\n")
        return directory / "profile.yaml", owned_workspace
    except BaseException:
        if owned_workspace is not None:
            workspace_parent, workspace_fd, device, inode = owned_workspace
            try:
                visible = os.stat(workspace.name, dir_fd=workspace_parent, follow_symlinks=False)
                if (visible.st_dev, visible.st_ino) == (device, inode) and not os.listdir(workspace_fd):
                    os.rmdir(workspace.name, dir_fd=workspace_parent)
            except OSError:
                pass
            os.close(workspace_fd)
            os.close(workspace_parent)
        try:
            if not os.listdir(state_fd):
                cleanup_parent = _trusted_parent(directory.parent)
                try:
                    os.rmdir(directory.name, dir_fd=cleanup_parent)
                finally:
                    os.close(cleanup_parent)
        except (OSError, ValueError):
            pass
        raise
    finally:
        os.close(state_fd)


def publish_initial_config(
    directory: Path,
    document: dict[str, object],
    *,
    expected_directory: tuple[int, int] | None = None,
) -> Path:
    """Atomically publish a validated private config after all references exist."""
    directory = Path(directory)
    parent_fd = _trusted_parent(directory.parent)
    try:
        directory_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    temporary = f".config.json.{uuid.uuid4().hex}.tmp"
    created = False
    try:
        opened = os.fstat(directory_fd)
        visible = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        identity = (opened.st_dev, opened.st_ino)
        if (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700
                or identity != (visible.st_dev, visible.st_ino)
                or (expected_directory is not None and identity != expected_directory)):
            raise ValueError("Private setup directory changed before configuration publication")
        try:
            os.stat("config.json", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("Setup config appeared before initial publication")
        raw = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        if len(raw) > 65536:
            raise ValueError("Configuration exceeds 64 KiB")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        created = True
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        load_config(directory / temporary)
        current = os.fstat(directory_fd)
        visible = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        if ((current.st_dev, current.st_ino) != (visible.st_dev, visible.st_ino)
                or (expected_directory is not None and (visible.st_dev, visible.st_ino) != expected_directory)):
            raise ValueError("Private setup directory changed before configuration publication")
        try:
            os.stat("config.json", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("Setup config appeared before initial publication")
        os.rename(temporary, "config.json", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        created = False
        os.fsync(directory_fd)
    except OSError:
        raise ValueError("The private setup configuration could not be published safely") from None
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)
        os.close(parent_fd)
    return directory / "config.json"


def create_artifacts(directory: Path, tunnel_id: str, key: str) -> Path:
    """Create a new setup with an explicit empty file-access policy."""
    directory = Path(directory)
    workspace = directory / "workspace"
    profile, owned_workspace = prepare_private_artifacts(
        directory, tunnel_id, key, workspace=workspace, create_workspace=True,
    )
    document = {"root": str(workspace), "file_access": {"read": [], "write": []}, "tasks": []}
    try:
        info = os.stat(directory, follow_symlinks=False)
        publish_initial_config(directory, document, expected_directory=(info.st_dev, info.st_ino))
    finally:
        if owned_workspace is not None:
            os.close(owned_workspace[1])
            os.close(owned_workspace[0])
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


