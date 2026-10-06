"""Operator-only Claude long-lived token setup; never exposed as an MCP tool.

`claude setup-token` prints a one-year subscription token but does not store
it. This command runs it in a wide pseudo-terminal (so the token is not
wrapped), mirrors the interaction to the operator's terminal, and saves the
single detected token to a new private file without echoing it again.
"""

from __future__ import annotations

import argparse
import fcntl
import getpass
import os
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import termios
import tty
import uuid
import warnings
from pathlib import Path

from .setup import _trusted_parent

_COLUMNS = 400
_CAPTURE_LIMIT = 1024 * 1024
_TOKEN_FILE_LIMIT = 4096
_TOKEN_MAX_CHARS = _TOKEN_FILE_LIMIT - 1  # save_token appends one newline
# Observed subscription OAuth token shape; anything else falls back to paste.
_DETECTED_TOKEN = re.compile(rb"sk-ant-oat\d\d-[A-Za-z0-9_-]{20,1000}")
_VALID_TOKEN = re.compile(rf"[A-Za-z0-9._~+/=-]{{20,{_TOKEN_MAX_CHARS}}}")
_TERMINAL_CONTROL = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]"
)


def extract_token(output: bytes) -> str | None:
    """Return the token only when exactly one distinct value was printed."""
    plain = _TERMINAL_CONTROL.sub(b"", output)
    found = {match.group(0).decode("ascii") for match in _DETECTED_TOKEN.finditer(plain)}
    return found.pop() if len(found) == 1 else None


def validate_token(token: str) -> str:
    if not isinstance(token, str) or not _VALID_TOKEN.fullmatch(token):
        raise ValueError(f"Token must be one value of 20-{_TOKEN_MAX_CHARS} URL-safe characters")
    return token


def save_token(path: Path, token: str, replace: bool) -> None:
    """Create (or, when asked, atomically replace) a 0600 single-token file."""
    validate_token(token)
    path = Path(os.path.abspath(path))
    if not path.name:
        raise ValueError("Choose a token file path")
    parent_fd = _trusted_parent(path.parent)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is not None:
            if not replace:
                raise ValueError("Token file already exists; nothing overwritten (use --replace to rotate)")
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Existing token path is not a private regular file; nothing overwritten")
        temporary = f".{path.name}.{uuid.uuid4().hex}.tmp" if info is not None else path.name
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(token + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if temporary != path.name:
                os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(parent_fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def run_in_pty(argv: list[str], stdin_fd: int, stdout_fd: int) -> tuple[int, bytes]:
    """Run argv on a wide pseudo-terminal, relaying input and mirroring output."""
    master, slave = os.openpty()
    try:
        rows = os.get_terminal_size(stdout_fd).lines
    except OSError:
        rows = 40
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, _COLUMNS, 0, 0))

    def own_terminal() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    try:
        process = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave, close_fds=True, preexec_fn=own_terminal
        )
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    saved = termios.tcgetattr(stdin_fd) if os.isatty(stdin_fd) else None
    captured = bytearray()
    try:
        if saved is not None:
            # TCSANOW: the default TCSAFLUSH would discard input already typed.
            tty.setraw(stdin_fd, termios.TCSANOW)
        sources = [master, stdin_fd]
        while True:
            ready, _, _ = select.select(sources, [], [])
            if master in ready:
                try:
                    data = os.read(master, 65536)
                except OSError:  # EIO once the child side is closed
                    data = b""
                if not data:
                    break
                _write_all(stdout_fd, data)
                captured.extend(data[: max(0, _CAPTURE_LIMIT - len(captured))])
            if stdin_fd in ready:
                data = os.read(stdin_fd, 4096)
                if data:
                    _write_all(master, data)
                else:
                    sources.remove(stdin_fd)
    finally:
        if saved is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved)
        if process.poll() is None:
            process.kill()
        exit_code = process.wait()
        os.close(master)
    return exit_code, bytes(captured)


def _paste_token() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Paste the token printed above (hidden): ").strip()
    except getpass.GetPassWarning:
        raise ValueError("Terminal cannot hide input; nothing saved") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "Invalid claude-token arguments; use --help. Never pass a token as an argument.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        prog="dotunnel claude-token",
        description="Run `claude setup-token` and save the issued long-lived token to a private file for Claude cli-jobs",
    )
    parser.add_argument("--output", type=Path, required=True, help="Absolute token file path outside the MCP workspace")
    parser.add_argument("--claude", type=Path, help="Claude CLI executable (default: claude on PATH)")
    parser.add_argument("--replace", action="store_true", help="Atomically replace an existing token file (rotation)")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.getuid() == 0:
        print("Run on Linux as the non-root operator account", file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Use an interactive terminal; nothing was run or saved", file=sys.stderr)
        return 2
    output = args.output
    if not output.is_absolute() or ".." in output.parts:
        print("--output must be an absolute path without '..'", file=sys.stderr)
        return 2
    claude = str(args.claude) if args.claude else shutil.which("claude")
    if not claude or not os.path.isabs(claude) or not os.access(claude, os.X_OK):
        print("Claude CLI not found; pass --claude /absolute/path", file=sys.stderr)
        return 2
    try:
        # Fail before the browser flow if the destination is unusable.
        parent_fd = _trusted_parent(output.parent)
        try:
            exists = os.path.lexists(output)
        finally:
            os.close(parent_fd)
        if exists and not args.replace:
            raise ValueError("Token file already exists; nothing run (use --replace to rotate)")
    except (OSError, ValueError) as error:
        print(f"Unusable --output: {error}", file=sys.stderr)
        return 2

    print("Starting `claude setup-token`. Complete the browser authorization it shows.", flush=True)
    try:
        exit_code, captured = run_in_pty([claude, "setup-token"], sys.stdin.fileno(), sys.stdout.fileno())
    except OSError:
        print("\nCould not start the Claude CLI; nothing saved", file=sys.stderr)
        return 1
    if exit_code != 0:
        print(f"\n`claude setup-token` exited with {exit_code}; nothing saved", file=sys.stderr)
        return 1
    token = extract_token(captured)
    if token is None:
        print("\nToken not detected automatically.", flush=True)
        try:
            token = _paste_token()
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 1
    try:
        save_token(output, token, replace=args.replace)
    except (OSError, ValueError) as error:
        print(f"Token not saved: {error}", file=sys.stderr)
        return 1
    print(f"\nSaved token to {output} (0600); value not displayed.")
    print('Use it in the Claude operator config runtime: {"executable": "...", "oauth_token": "' + str(output) + '"}')
    return 0
