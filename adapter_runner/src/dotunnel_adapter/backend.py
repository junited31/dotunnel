"""Fixed-argv JSON-stdio backend transport with bounded owned-process cleanup."""

from __future__ import annotations

import ctypes
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time
from typing import Any, NoReturn

from .protocol import RunnerError, canonical_json, decode_json


_MAX_INPUT_BYTES = 65536
_MAX_OUTPUT_BYTES = 65536
_MAX_TIMEOUT_SECONDS = 200.0
_ESCAPE_PIPE_CLEANUP_SECONDS = 1.0
_GROUP_CLEANUP_SECONDS = 1.0
_MAX_ARGV = 64
_MAX_ARG_BYTES = 4096
_PATH_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PRCTL = ctypes.CDLL(None, use_errno=True).prctl
_PRCTL.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                  ctypes.c_ulong, ctypes.c_ulong]
_PRCTL.restype = ctypes.c_int


def _error(code: str) -> NoReturn:
    raise RunnerError(code) from None


def _validate_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _error("invalid_config")
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError):
        _error("invalid_config")
    if not math.isfinite(timeout) or timeout <= 0 or timeout > _MAX_TIMEOUT_SECONDS:
        _error("invalid_config")
    return timeout


def _validate_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(argv, tuple) or not 1 <= len(argv) <= _MAX_ARGV:
        _error("invalid_config")
    if not isinstance(argv[0], str) or not os.path.isabs(argv[0]):
        _error("invalid_config")
    for item in argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            _error("invalid_config")
        try:
            if len(item.encode("utf-8")) > _MAX_ARG_BYTES:
                _error("invalid_config")
        except UnicodeEncodeError:
            _error("invalid_config")
    return argv


def _private_cwd(cwd: Path) -> str:
    try:
        path = Path(cwd)
        if not path.is_absolute() or ".." in path.parts:
            _error("invalid_config")
        fd = os.open("/", _PATH_FLAGS)
        try:
            for component in path.parts[1:]:
                if component in ("", ".", ".."):
                    _error("invalid_config")
                next_fd = os.open(component, _PATH_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                _error("invalid_config")
        finally:
            os.close(fd)
        return str(path)
    except RunnerError:
        raise
    except (OSError, TypeError, ValueError):
        _error("invalid_config")


def _encode_envelope(envelope: dict[str, Any]) -> bytes:
    if not isinstance(envelope, dict):
        _error("invalid_request")
    try:
        data = canonical_json(envelope)
    except RunnerError as exc:
        _error("resource_limit" if exc.code == "resource_limit" else "invalid_request")
    except (TypeError, ValueError, OverflowError):
        _error("invalid_request")
    if not isinstance(data, bytes):
        _error("invalid_request")
    if len(data) > _MAX_INPUT_BYTES:
        _error("resource_limit")
    return data


def _kill_owned_group(process_group: int) -> bool:
    try:
        os.killpg(process_group, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return True
    except OSError:
        return False


def _close_pipe(selector: selectors.BaseSelector, pipe: Any | None) -> None:
    if pipe is None:
        return
    try:
        selector.unregister(pipe.fileno())
    except (KeyError, ValueError, OSError):
        pass
    try:
        pipe.close()
    except OSError:
        pass


def _bind_parent_death(expected_parent: int) -> None:
    # The CLI is single-threaded; this fork hook uses pre-resolved syscalls only.
    # Close the race where the runner dies before PR_SET_PDEATHSIG is installed.
    if _PRCTL(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent:
        os._exit(126)


def invoke(argv: tuple[str, ...], envelope: dict[str, Any], *, cwd: Path, timeout_seconds: float) -> dict[str, Any]:
    """Run one configured backend process and return its strict JSON response."""
    fixed_argv = _validate_argv(argv)
    timeout = _validate_timeout(timeout_seconds)
    working_directory = _private_cwd(cwd)
    input_bytes = _encode_envelope(envelope)
    parent_pid = os.getpid()
    environment = {"HOME": working_directory, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    group_killed = False
    cleanup_failed = False
    primary_error: BaseException | None = None
    response: dict[str, Any] | None = None
    stdout_pipe: Any | None = None
    stderr_pipe: Any | None = None
    stdin_pipe: Any | None = None

    try:
        process = subprocess.Popen(
            fixed_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=environment,
            shell=False,
            close_fds=True,
            start_new_session=True,
            preexec_fn=lambda: _bind_parent_death(parent_pid),
            bufsize=0,
        )
        stdin_pipe = process.stdin
        stdout_pipe = process.stdout
        stderr_pipe = process.stderr
        if stdin_pipe is None or stdout_pipe is None or stderr_pipe is None:
            _error("backend_unavailable")

        selector = selectors.DefaultSelector()
        stdout_open = True
        stderr_open = True
        stdin_open = bool(input_bytes)
        stdin_failed = False
        bytes_sent = 0
        output_size = 0
        stdout_buffer = bytearray()
        deadline = time.monotonic() + timeout
        leader_exited = False
        escape_deadline = 0.0

        for pipe in (stdin_pipe, stdout_pipe, stderr_pipe):
            os.set_blocking(pipe.fileno(), False)
        if stdin_open:
            selector.register(stdin_pipe.fileno(), selectors.EVENT_WRITE, "stdin")
        else:
            _close_pipe(selector, stdin_pipe)
            stdin_pipe = None
        selector.register(stdout_pipe.fileno(), selectors.EVENT_READ, "stdout")
        selector.register(stderr_pipe.fileno(), selectors.EVENT_READ, "stderr")

        while True:
            now = time.monotonic()
            return_code = process.poll()
            if return_code is not None and not leader_exited:
                leader_exited = True
                escape_deadline = now + _ESCAPE_PIPE_CLEANUP_SECONDS
                if stdin_open:
                    _close_pipe(selector, stdin_pipe)
                    stdin_pipe = None
                    stdin_open = False
                    if bytes_sent != len(input_bytes):
                        stdin_failed = True
                group_killed = _kill_owned_group(process.pid)
                if not group_killed:
                    _error("backend_unavailable")
            if not leader_exited and now >= deadline:
                _error("backend_unavailable")
            if leader_exited:
                if not stdout_open and not stderr_open:
                    break
                if now >= escape_deadline:
                    _error("backend_unavailable")
                wait_seconds = min(0.05, max(0.0, escape_deadline - now))
            else:
                wait_seconds = min(0.05, max(0.0, deadline - now))

            for key, _events in selector.select(wait_seconds):
                stream = key.data
                if stream == "stdin":
                    try:
                        count = os.write(stdin_pipe.fileno(), input_bytes[bytes_sent : bytes_sent + 32768])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        stdin_failed = True
                        stdin_open = False
                        _close_pipe(selector, stdin_pipe)
                        stdin_pipe = None
                        continue
                    except OSError:
                        stdin_failed = True
                        stdin_open = False
                        _close_pipe(selector, stdin_pipe)
                        stdin_pipe = None
                        continue
                    if count <= 0:
                        stdin_failed = True
                        stdin_open = False
                        _close_pipe(selector, stdin_pipe)
                        stdin_pipe = None
                        continue
                    bytes_sent += count
                    if bytes_sent == len(input_bytes):
                        stdin_open = False
                        _close_pipe(selector, stdin_pipe)
                        stdin_pipe = None
                    continue

                pipe = stdout_pipe if stream == "stdout" else stderr_pipe
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    if stream == "stdout":
                        stdout_open = False
                        _close_pipe(selector, stdout_pipe)
                        stdout_pipe = None
                    else:
                        stderr_open = False
                        _close_pipe(selector, stderr_pipe)
                        stderr_pipe = None
                    continue
                output_size += len(chunk)
                if output_size > _MAX_OUTPUT_BYTES:
                    _error("resource_limit")
                if stream == "stdout":
                    stdout_buffer.extend(chunk)

        return_code = process.poll()
        if return_code is None or return_code != 0 or stdin_failed or bytes_sent != len(input_bytes):
            _error("backend_unavailable")
        try:
            decoded = decode_json(bytes(stdout_buffer))
        except RunnerError:
            _error("backend_unavailable")
        except (TypeError, ValueError, UnicodeError):
            _error("backend_unavailable")
        if not isinstance(decoded, dict):
            _error("backend_unavailable")
        response = decoded
    except RunnerError as exc:
        primary_error = exc
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        primary_error = RunnerError("backend_unavailable")
    except BaseException as exc:
        primary_error = exc
    finally:
        if process is not None:
            if not group_killed:
                group_killed = _kill_owned_group(process.pid)
                if not group_killed:
                    cleanup_failed = True
            if selector is None:
                selector = selectors.DefaultSelector()
            _close_pipe(selector, stdin_pipe)
            _close_pipe(selector, stdout_pipe)
            _close_pipe(selector, stderr_pipe)
            try:
                process.wait(timeout=_GROUP_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                cleanup_failed = True
                _kill_owned_group(process.pid)
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                cleanup_failed = True
        if selector is not None:
            try:
                selector.close()
            except OSError:
                cleanup_failed = True

    if cleanup_failed and primary_error is None:
        primary_error = RunnerError("backend_unavailable")
    if primary_error is not None:
        if isinstance(primary_error, RunnerError):
            raise primary_error from None
        raise primary_error
    if response is None:
        _error("backend_unavailable")
    return response
