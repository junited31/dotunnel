"""Run administrator-defined tasks with bounded output and process-group cleanup.

This is not an OS sandbox. A configured task runs with the runtime user's
permissions, and a descendant that deliberately creates a new session can
escape this runner's process-group cleanup.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import unicodedata
import uuid


_MAX_RESULTS = 20
_MAX_OUTPUT_BYTES = 16 * 1024
_READ_CHUNK_BYTES = 4096
_CLEANUP_TIMEOUT_SECONDS = 1
_MAX_ARGV_COUNT = 64
_MAX_ARGV_ITEM_CHARS = 4096
_MAX_ARGV_TOTAL_CHARS = 16 * 1024
_MAX_NAME_CHARS = 128
_MAX_DESCRIPTION_CHARS = 2048

_INVALID_SPEC = "Invalid task configuration."
_INVALID_CWD = "Task working directory is unavailable."

_ANSI_SEQUENCE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07]*?(?:\x07|\x1b\\|$)"
    r"|[PX^_].*?(?:\x1b\\|$)"
    r"|[@-_]"
    r")",
    re.DOTALL,
)
_C1_SEQUENCE = re.compile(
    r"(?:"
    r"\x9b[0-?]*[ -/]*[@-~]"
    r"|\x9d[^\x07\x9c]*(?:[\x07\x9c]|$)"
    r"|[\x90\x98\x9e\x9f].*?(?:\x9c|$)"
    r")",
    re.DOTALL,
)


def _require_text(value: object, limit: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= limit
        and "\x00" not in value
    )


def _validate_spec(spec: TaskSpec) -> None:
    if not _require_text(spec.name, _MAX_NAME_CHARS):
        raise ValueError(_INVALID_SPEC)
    if not _require_text(spec.description, _MAX_DESCRIPTION_CHARS):
        raise ValueError(_INVALID_SPEC)
    if not isinstance(spec.argv, tuple) or not 1 <= len(spec.argv) <= _MAX_ARGV_COUNT:
        raise ValueError(_INVALID_SPEC)
    if any(not _require_text(argument, _MAX_ARGV_ITEM_CHARS) for argument in spec.argv):
        raise ValueError(_INVALID_SPEC)
    if sum(len(argument) for argument in spec.argv) > _MAX_ARGV_TOTAL_CHARS:
        raise ValueError(_INVALID_SPEC)
    if not os.path.isabs(spec.argv[0]):
        raise ValueError(_INVALID_SPEC)
    if not isinstance(spec.cwd, Path):
        raise ValueError(_INVALID_SPEC)
    cwd_value = os.fspath(spec.cwd)
    if len(cwd_value) > 4096 or "\x00" in cwd_value:
        raise ValueError(_INVALID_SPEC)
    timeout = spec.timeout_seconds
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError(_INVALID_SPEC)
    try:
        valid_timeout = math.isfinite(timeout) and 0 < timeout <= 300
    except (OverflowError, TypeError):
        valid_timeout = False
    if not valid_timeout:
        raise ValueError(_INVALID_SPEC)


@dataclass(frozen=True, slots=True)
class TaskSpec:
    name: str
    description: str
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float = 60

    def __post_init__(self) -> None:
        _validate_spec(self)


class _OutputCapture:
    __slots__ = ("data", "truncated")

    def __init__(self) -> None:
        self.data = bytearray()
        self.truncated = False

    def append(self, chunk: bytes) -> None:
        remaining = _MAX_OUTPUT_BYTES - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.truncated = True

    def text(self) -> str:
        decoded = self.data.decode("utf-8", errors="replace")
        decoded = _ANSI_SEQUENCE.sub("", decoded)
        decoded = _C1_SEQUENCE.sub("", decoded)
        cleaned = "".join(
            character
            for character in decoded
            if character in "\n\t" or unicodedata.category(character) != "Cc"
        )
        encoded = cleaned.encode("utf-8")
        if len(encoded) > _MAX_OUTPUT_BYTES:
            self.truncated = True
            return encoded[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="ignore")
        return cleaned


class TaskRunner:
    """Start exact configured argv values and retain bounded status snapshots."""

    def __init__(self, specs: list[TaskSpec], root: Path):
        if (
            not isinstance(root, Path)
            or not root.is_absolute()
            or len(os.fspath(root)) > 4096
        ):
            raise ValueError(_INVALID_SPEC)
        if not isinstance(specs, list):
            raise ValueError(_INVALID_SPEC)

        validated: dict[str, TaskSpec] = {}
        for spec in specs:
            if not isinstance(spec, TaskSpec):
                raise ValueError(_INVALID_SPEC)
            _validate_spec(spec)
            if spec.name in validated:
                raise ValueError(_INVALID_SPEC)
            validated[spec.name] = spec

        self.root = root
        self._specs = validated
        self._results: OrderedDict[str, dict[str, object]] = OrderedDict()
        self._admission_task: asyncio.Task | None = None
        self._admission_done: asyncio.Future[None] | None = None
        self._job_task: asyncio.Task | None = None
        self._closing = False
        self._close_task: asyncio.Task | None = None

    def list_tasks(self) -> dict[str, list[dict[str, str]]]:
        return {
            "tasks": [
                {"name": spec.name, "description": spec.description}
                for spec in self._specs.values()
            ]
        }

    def get_task_result(self, result_id: str) -> dict[str, object]:
        if not isinstance(result_id, str):
            raise ValueError("Task result is unavailable.")
        result = self._results.get(result_id)
        if result is None:
            raise ValueError("Task result is unavailable.")
        return dict(result)

    async def run_task(self, name: str) -> dict[str, object]:
        """Spawn once and return its running status snapshot."""
        if not isinstance(name, str) or name not in self._specs:
            raise ValueError("Unknown task.")
        if self._closing:
            raise ValueError("Task runner is shutting down.")
        if self._admission_task is not None or self._job_task is not None:
            raise ValueError("A task is already running.")

        admission = asyncio.current_task()
        if admission is None:
            raise RuntimeError("Task admission requires an asyncio task.")
        self._admission_task = admission
        admission_done = asyncio.get_running_loop().create_future()
        self._admission_done = admission_done
        process: asyncio.subprocess.Process | None = None
        cwd_fd: int | None = None
        handed_off = False
        try:
            spec = self._specs[name]
            cwd_fd = self._open_working_directory(spec.cwd)
            try:
                process = await self._spawn(spec, cwd_fd)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise ValueError("Configured task could not be started.") from None

            if self._closing:
                raise asyncio.CancelledError

            launched_at = time.monotonic()
            result_id = uuid.uuid4().hex
            result: dict[str, object] = {
                "result_id": result_id,
                "task": spec.name,
                "status": "running",
                "exit_code": None,
                "output": "",
                "truncated": False,
            }
            running_snapshot = dict(result)
            self._results[result_id] = result
            while len(self._results) > _MAX_RESULTS:
                self._results.popitem(last=False)

            try:
                job = asyncio.create_task(
                    self._complete_task(result_id, spec, process, launched_at)
                )
            except Exception:
                self._results.pop(result_id, None)
                raise
            self._job_task = None if job.done() else job
            self._admission_task = None
            self._admission_done = None
            handed_off = True
            return running_snapshot
        except asyncio.CancelledError:
            if process is not None and not handed_off:
                try:
                    await self._stop_process_group(process)
                except asyncio.CancelledError:
                    pass
            raise
        except ValueError:
            raise
        except Exception:
            if process is not None and not handed_off:
                try:
                    await self._stop_process_group(process)
                except asyncio.CancelledError:
                    raise
            raise ValueError("Configured task could not be started.") from None
        finally:
            if cwd_fd is not None:
                try:
                    os.close(cwd_fd)
                except OSError:
                    pass
            if self._admission_task is admission:
                self._admission_task = None
                self._admission_done = None
            if not admission_done.done():
                admission_done.set_result(None)

    async def _complete_task(
        self,
        result_id: str,
        spec: TaskSpec,
        process: asyncio.subprocess.Process,
        launched_at: float,
    ) -> None:
        capture = _OutputCapture()
        status = "completed"
        exit_code: int | None = None
        remaining = spec.timeout_seconds - (time.monotonic() - launched_at)
        try:
            if remaining <= 0:
                status = "timed_out"
            else:
                try:
                    exit_code = await asyncio.wait_for(
                        self._collect_output(process, capture), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    status = "timed_out"
                except asyncio.CancelledError:
                    status = "cancelled"
                except Exception:
                    status = "failed"
        except asyncio.CancelledError:
            status = "cancelled"
        except Exception:
            status = "failed"

        try:
            # Reap ordinary same-session descendants even when they close
            # stdout and outlive the direct task process.
            await self._stop_process_group(process)
        except asyncio.CancelledError:
            status = "cancelled"
        except Exception:
            status = "failed"

        if exit_code is None:
            exit_code = process.returncode
        result = self._results.get(result_id)
        if result is not None:
            result.update(
                status=status,
                exit_code=exit_code,
                output=capture.text(),
                truncated=capture.truncated,
            )
        if self._job_task is asyncio.current_task():
            self._job_task = None

    async def aclose(self) -> None:
        """Close admission and wait for owned spawning and running jobs to stop."""
        if self._close_task is None:
            self._closing = True
            self._close_task = asyncio.create_task(self._close_owned_tasks())

        close_task = self._close_task
        cancelled = False
        while not close_task.done():
            try:
                await asyncio.shield(close_task)
            except asyncio.CancelledError:
                cancelled = True
            except Exception:
                break
        close_task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _close_owned_tasks(self) -> None:
        admission = self._admission_task
        admission_done = self._admission_done
        job = self._job_task
        current = asyncio.current_task()
        if admission is not None and admission is not current and not admission.done():
            admission.cancel()
        if job is not None and job is not current and not job.done():
            job.cancel()

        # Admission ownership ends at run_task's finally, not when its caller
        # finishes unrelated cancellation/error handling.
        for task in (admission_done, job):
            if task is None or task is current:
                continue
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not task.cancelled():
                try:
                    task.result()
                except Exception:
                    pass

    async def _spawn(
        self, spec: TaskSpec, cwd_fd: int
    ) -> asyncio.subprocess.Process:
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *spec.argv,
                cwd=f"/proc/self/fd/{cwd_fd}",
                env={"PATH": os.defpath, "HOME": str(self.root), "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                pass_fds=(cwd_fd,),
            )
        )
        try:
            return await asyncio.shield(spawn)
        except asyncio.CancelledError:
            # A further request cancellation must not abandon the still-running
            # spawn task; retain ownership until it yields a handle or fails.
            while not spawn.done():
                try:
                    await asyncio.shield(spawn)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            try:
                process = spawn.result()
            except (Exception, asyncio.CancelledError):
                process = None
            if process is not None:
                await self._stop_process_group(process)
            raise

    async def _collect_output(
        self, process: asyncio.subprocess.Process, capture: _OutputCapture
    ) -> int:
        assert process.stdout is not None
        while True:
            chunk = await process.stdout.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            capture.append(chunk)
        return await process.wait()

    @staticmethod
    async def _stop_process_group(process: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
        async def drain_and_reap():
            try:
                async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
                    # Drain paused transports, but an escaped descendant can
                    # keep the pipe open after the original group has exited.
                    if process.stdout is not None:
                        while await process.stdout.read(_READ_CHUNK_BYTES):
                            pass
                    await process.wait()
            except TimeoutError:
                # Process exposes no public pipe-close API. Closing its
                # subprocess transport releases pipes and kills/reaps the
                # direct child if group termination did not reach it.
                process._transport.close()
                await process.wait()

        cleanup = asyncio.create_task(drain_and_reap())
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError

    def _open_working_directory(self, cwd: Path) -> int:
        if cwd.is_absolute():
            try:
                components = cwd.relative_to(self.root).parts
            except ValueError:
                raise ValueError(_INVALID_CWD) from None
        else:
            components = cwd.parts
        if any(component in {"..", ""} for component in components):
            raise ValueError(_INVALID_CWD)

        root_components = self.root.parts[1:]
        if any(component in {"..", ""} for component in root_components):
            raise ValueError(_INVALID_CWD)

        directory_flag = getattr(os, "O_DIRECTORY", 0)
        nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
        flags = os.O_RDONLY | directory_flag | nofollow_flag
        fd: int | None = None
        try:
            fd = os.open("/", flags)
            for component in (*root_components, *components):
                next_fd = os.open(component, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            safe_fd = fd
            fd = None
            return safe_fd
        except (OSError, ValueError, TypeError):
            raise ValueError(_INVALID_CWD) from None
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
