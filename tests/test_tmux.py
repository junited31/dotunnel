from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from dotunnel.supervision_config import Connection, Profile, Project, SupervisionError
from dotunnel.tmux import TmuxBackend


_FAKE_TMUX = r'''#!@PYTHON@
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

state_path = Path(@STATE_PATH@)
state = json.loads(state_path.read_text())
args = sys.argv[1:]
stdin = sys.stdin.buffer.read()
state.setdefault("calls", []).append({"argv": [sys.argv[0], *args], "stdin": base64.b64encode(stdin).decode("ascii")})
commands = {"new-session", "display-message", "list-panes", "capture-pane", "load-buffer", "paste-buffer", "delete-buffer", "send-keys", "set-option", "show-option"}
command = next((item for item in args if item in commands), None)

def save():
    temporary = state_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False))
    os.replace(temporary, state_path)
save()

def option(name):
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError):
        return None

def pane_for(target):
    return next((pane for pane in state.get("panes", []) if pane.get("pane_id") == target), None)

def render(fmt, pane=None):
    values = {
        "pid": str(state.get("server_pid", "")),
        "pane_id": (pane or {}).get("pane_id", ""),
        "pane_pid": str((pane or {}).get("pane_pid", "")),
        "pane_dead": str((pane or {}).get("pane_dead", "")),
        "pane_current_path": (pane or {}).get("cwd", ""),
        "pane_start_path": (pane or {}).get("cwd", ""),
        "pane_current_command": (pane or {}).get("current_command", ""),
        "pane_start_command": (pane or {}).get("start_command", ""),
        "session_name": (pane or {}).get("session_name", ""),
        "session_id": (pane or {}).get("session_id", ""),
        "@dotunnel_nonce": (pane or {}).get("nonce", ""),
    }
    for key, value in values.items():
        fmt = fmt.replace("#{" + key + "}", value)
    return fmt

if command == "new-session":
    if state.get("fail_new_session"):
        save()
        print("new-session failed", file=sys.stderr)
        sys.exit(1)
    cwd = option("-c") or "/"
    command_tail = args[args.index("new-session") + 1:]
    direct_launch = "--" in command_tail
    if direct_launch:
        split = command_tail.index("--")
        launched = command_tail[split + 1:]
        option_args = command_tail[:split]
        shell_command = launched[0] if len(launched) == 1 else None
        direct_launch = len(launched) > 1
    else:
        shell_command = command_tail[-1] if command_tail else ""
        launched = shlex.split(shell_command)
        if launched and launched[0] == "exec":
            launched = launched[1:]
        option_args = command_tail[:-1]
    if not launched:
        print("missing command", file=sys.stderr)
        sys.exit(2)
    env = os.environ.copy()
    for index, argument in enumerate(option_args[:-1]):
        if argument == "-e":
            variable, separator, value = option_args[index + 1].partition("=")
            if separator:
                env[variable] = value
    child = subprocess.Popen(
        launched if direct_launch else ["/bin/sh", "-c", shell_command],
        cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    pane_id = state.get("new_pane_id", "%1")
    session_id = state.get("new_session_id", "$1")
    pane = {"pane_id": pane_id, "pane_pid": child.pid, "pane_dead": "0",
            "cwd": cwd, "current_command": Path(launched[0]).name,
            "start_command": shlex.join(launched), "session_name": option("-s") or "",
            "session_id": session_id, "nonce": env.get("DOTUNNEL_MCP_NONCE", "")}
    state.setdefault("panes", []).append(pane)
    state.setdefault("child_pids", []).append(child.pid)
    state["last_start_argv"] = launched
    state["last_start_direct"] = direct_launch
    save()
    if state.get("omit_new_session_identity"):
        print("", end="")
    else:
        fmt = option("-F") or ""
        print(session_id if "session_id" in fmt else pane_id)
elif command == "display-message":
    fmt = option("-F") or ""
    target = option("-t")
    if target is None and state.get("server_absent"):
        print("no server running on " + (option("-S") or ""), file=sys.stderr)
        sys.exit(1)
    if target is None:
        print(render(fmt))
    else:
        pane = pane_for(target)
        if pane is None:
            print("", end="")
            sys.exit(1)
        print(render(fmt, pane))
elif command == "list-panes":
    fmt = option("-F") or ""
    target = option("-t")
    panes = state.get("panes", [])
    if target is not None:
        panes = [pane for pane in panes if target in (pane.get("pane_id"), pane.get("session_id"), pane.get("session_name"))]
    for pane in panes:
        print(render(fmt, pane))
elif command == "capture-pane":
    target = option("-t")
    state.setdefault("captures", []).append(target)
    save()
    if pane_for(target) is None:
        print("pane missing", file=sys.stderr)
        sys.exit(1)
    screen = state.get("screens", {}).get(target, state.get("screen", "synthetic screen\n"))
    visible = screen.splitlines()
    history = state.get("history", {}).get(target, [])
    capture_args = args[args.index("capture-pane") + 1:]
    if "-S" not in capture_args and "-E" not in capture_args:
        sys.stdout.write(screen)
    else:
        history_size = len(history)
        all_lines = [*history, *visible]
        if "-S" in capture_args:
            start_value = capture_args[capture_args.index("-S") + 1]
            start = 0 if start_value == "-" else history_size + int(start_value)
            start = max(0, start)
        else:
            start = history_size
        if "-E" in capture_args:
            end_value = capture_args[capture_args.index("-E") + 1]
            end = history_size + len(visible) - 1 if end_value == "-" else history_size + int(end_value)
        else:
            end = history_size + len(visible) - 1
        captured = all_lines[start:end + 1] if end >= start else []
        output = "\n".join(captured)
        if captured and (end < history_size or screen.endswith("\n")):
            output += "\n"
        sys.stdout.write(output)
elif command == "load-buffer":
    name = option("-b")
    state.setdefault("buffers", {})[name] = base64.b64encode(stdin).decode("ascii")
    state.setdefault("loaded_buffers", []).append(name)
    save()
elif command == "paste-buffer":
    paste_args = args[args.index("paste-buffer") + 1:]
    if "-S" in paste_args:
        print("unknown option: -S", file=sys.stderr)
        sys.exit(2)
    name = option("-b")
    target = option("-t")
    state.setdefault("pastes", []).append({"buffer": name, "target": target,
                                            "bytes": state.get("buffers", {}).get(name)})
    save()
    if state.get("fail_paste_after_effect"):
        print("synthetic lost acknowledgement", file=sys.stderr)
        sys.exit(1)
elif command == "delete-buffer":
    name = option("-b")
    state.setdefault("deleted_buffers", []).append(name)
    state.setdefault("buffers", {}).pop(name, None)
    save()
elif command == "send-keys":
    target = option("-t")
    keys = args[args.index("-t") + 2:] if "-t" in args else []
    state.setdefault("key_sends", []).append({"target": target, "keys": keys})
    save()
elif command == "set-option":
    target = option("-t")
    name = next((item for item in args if item.startswith("@")), None)
    value = args[-1] if args else ""
    pane = pane_for(target)
    if pane is not None and name:
        pane[name] = value
    save()
elif command == "show-option":
    target = option("-t")
    name = next((item for item in args if item.startswith("@")), None)
    pane = pane_for(target)
    print((pane or {}).get(name, ""))
else:
    print("unsupported synthetic tmux command", file=sys.stderr)
    sys.exit(2)
'''

_AGENT = "import time\nwhile True:\n    time.sleep(1)\n"


def _proc_start_time(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    tail = raw[raw.rfind(")") + 2 :].split()
    return int(tail[19])


def _proc_cmdline(pid: int) -> list[str]:
    return [part.decode("utf-8", "surrogateescape") for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if part]


def _process_state(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    return raw[raw.rfind(")") + 2 :].split()[0]


def _load_state(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))



class FixtureRunner:
    trusted_path = "/fixture/trusted-bin:/usr/bin:/bin"

    def __init__(self, fixture):
        self.fixture = fixture

    async def __call__(self, argv, *, cwd=None, deadline=None, input=None):
        return await self.fixture.run(argv, cwd=cwd, deadline=deadline, input=input)


class SyntheticTmux:
    def __init__(self, root: Path, name: str):
        self.root = root / name
        self.root.mkdir()
        self.state_path = self.root / "state.json"
        self.socket = self.root / "tmux.sock"
        self.project_path = self.root / "project"
        self.project_path.mkdir()
        self.agent_script = self.root / "agent.py"
        self.agent_script.write_text(_AGENT, encoding="utf-8")
        self.executable = self.root / "tmux-fixture"
        fake = _FAKE_TMUX.replace("@PYTHON@", sys.executable).replace(
            "@STATE_PATH@", json.dumps(str(self.state_path))
        )
        self.executable.write_text(fake, encoding="utf-8")
        self.executable.chmod(0o700)
        self.state_path.write_text(
            json.dumps({"server_pid": os.getpid(), "panes": [{
                "pane_id": "%99", "pane_pid": 99999999, "pane_dead": "1",
                "cwd": "/unregistered", "current_command": "unrelated", "session_name": "elsewhere",
            }], "screen": "synthetic screen\n", "screens": {"%99": "must not be captured\n"}}),
            encoding="utf-8",
        )
        self.connection = Connection(
            id=name,
            backend="tmux",
            executable=self.executable,
            socket=self.socket,
        )
        self.project = Project(
            id="project",
            path=self.project_path,
            connections=(name,),
            profiles=("omp",),
        )
        self.profile = Profile(
            id="omp",
            kind="omp",
            executable=Path(sys.executable),
            args=(str(self.agent_script), "--profile", "registered", "--label", "雪"),
            backends=("tmux",),
            input_mode="bracketed-paste",
        )
        self.runner = FixtureRunner(self)
        self.backend = TmuxBackend(self.connection, self.runner)

    async def run(self, argv, *, cwd=None, deadline=None, input=None):
        process = await asyncio.create_subprocess_exec(
            *(str(part) for part in argv),
            cwd=str(cwd) if cwd is not None else "/",
            stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"HOME": str(self.root), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        remaining = None if deadline is None else max(0.001, deadline - time.monotonic())
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input), remaining)
        except TimeoutError:
            process.kill()
            await process.wait()
            return 124, b"", b"synthetic timeout"
        return process.returncode or 0, stdout, stderr

    def state(self) -> dict:
        return _load_state(self.state_path)

    def save_state(self, state: dict) -> None:
        self.state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")

    def stop_children(self) -> None:
        for pid in self.state().get("child_pids", []):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            for _ in range(50):
                try:
                    if _process_state(pid) == "Z":
                        break
                    os.kill(pid, 0)
                except (ProcessLookupError, FileNotFoundError):
                    break
                time.sleep(0.01)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class TmuxBackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dotunnel-tmux-test-")
        self.root = Path(self.temp.name)
        self.fixtures: list[SyntheticTmux] = []
        self.processes: list[subprocess.Popen] = []
        self.first = self.add_fixture("connection-one")

    async def asyncTearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            try:
                await asyncio.to_thread(process.wait, timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait)
        for fixture in self.fixtures:
            fixture.stop_children()
        self.temp.cleanup()

    def add_fixture(self, name: str) -> SyntheticTmux:
        fixture = SyntheticTmux(self.root, name)
        self.fixtures.append(fixture)
        return fixture

    async def start_managed(self, fixture: SyntheticTmux | None = None, *, name: str = "same-name", attempt_id: str = "attempt-1", nonce: str = "nonce-1") -> tuple[dict, dict]:
        fixture = fixture or self.first
        attempt = {"target_id": attempt_id, "nonce": nonce}
        started = await fixture.backend.start(
            fixture.project,
            fixture.profile,
            name,
            None,
            attempt,
            deadline=time.monotonic() + 10,
        )
        record = {
            "target_id": attempt_id,
            "operation_id": "operation-" + attempt_id,
            "nonce": nonce,
            "state": "active",
            "binding": {
                "connection": fixture.connection.id,
                "project": fixture.project.id,
                "profile": fixture.profile.id,
            },
            "native": started,
        }
        rows = await fixture.backend.inventory(
            [fixture.project], [record], deadline=time.monotonic() + 10
        )
        self.assertEqual(len(rows), 1)
        return started, rows[0]

    def calls(self, fixture: SyntheticTmux) -> list[dict]:
        return fixture.state().get("calls", [])

    def tmux_calls(self, fixture: SyntheticTmux, command: str) -> list[dict]:
        return [call for call in self.calls(fixture) if command in call["argv"]]

    def assert_fixed_socket(self, fixture: SyntheticTmux) -> None:
        for call in self.calls(fixture):
            argv = call["argv"]
            self.assertEqual(argv[0], str(fixture.executable))
            self.assertIn("-S", argv)
            self.assertEqual(argv[argv.index("-S") + 1], str(fixture.socket))

    async def test_start_uses_fixed_socket_and_records_direct_profile_identity(self):
        started, target = await self.start_managed()
        native = started["identity"]
        self.assertEqual(
            {"boot_id", "server_pid", "server_start", "pane_pid", "pane_start", "nonce", "native_id"}
            - set(native),
            set(),
        )
        self.assertEqual(native["nonce"], "nonce-1")
        self.assertEqual(native["native_id"], "%1")
        self.assertEqual(native["boot_id"], Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        self.assertEqual(_proc_start_time(native["server_pid"]), native["server_start"])
        self.assertEqual(_proc_start_time(native["pane_pid"]), native["pane_start"])
        self.assertEqual(
            _proc_cmdline(native["pane_pid"]),
            [str(self.first.profile.executable), *self.first.profile.args],
        )
        self.assertEqual(started["command_argv"], [str(self.first.profile.executable), *self.first.profile.args])
        environment = Path(f"/proc/{native['pane_pid']}/environ").read_bytes().split(b"\0")
        self.assertIn(b"DOTUNNEL_MCP_NONCE=nonce-1", environment)
        self.assertEqual(target["native_id"], native["native_id"])
        self.assertEqual(target["process_state"], "running")
        self.assertEqual(target["agent_state"], "unknown")
        self.assertEqual(target["state_source"], "unavailable")
        self.assertFalse(target["readonly"])
        self.assertNotIn("command_argv", target)
        self.assertNotIn("command_executable", target)
        state = self.first.state()
        self.assertTrue(state["last_start_direct"])
        self.assertEqual(
            state["last_start_argv"],
            [str(self.first.profile.executable), *self.first.profile.args],
        )
        start_call = self.tmux_calls(self.first, "new-session")[0]["argv"]
        self.assertEqual(start_call[1:3], ["-f", "/dev/null"])
        command_args = start_call[start_call.index("new-session") + 1:]
        separator = command_args.index("--")
        self.assertEqual(
            command_args[separator + 1:],
            [str(self.first.profile.executable), *self.first.profile.args],
        )
        environment = {}
        for index, argument in enumerate(command_args[:separator - 1]):
            if argument == "-e":
                key, _, value = command_args[index + 1].partition("=")
                environment[key] = value
        self.assertEqual(environment["PATH"], self.first.runner.trusted_path)
        self.assertEqual(environment["DOTUNNEL_MCP_NONCE"], "nonce-1")
        self.assert_fixed_socket(self.first)

    async def test_start_empty_binary_profile_preserves_metacharacter_executable_identity(self):
        executable_dir = self.root / "trusted binary; shell"
        executable_dir.mkdir()
        executable = executable_dir / "yes"
        shutil.copyfile("/usr/bin/yes", executable)
        executable.chmod(0o700)
        self.first.profile = Profile(
            id="omp",
            kind="omp",
            executable=executable,
            args=(),
            backends=("tmux",),
            input_mode="bracketed-paste",
        )

        started, target = await self.start_managed()
        native = started["identity"]
        pane_pid = native["pane_pid"]
        self.assertEqual(native["nonce"], "nonce-1")
        self.assertEqual(native["boot_id"], Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        self.assertEqual(_proc_start_time(pane_pid), native["pane_start"])
        self.assertEqual(_proc_cmdline(pane_pid), [str(executable)])
        self.assertEqual(os.readlink(f"/proc/{pane_pid}/exe"), str(executable))
        self.assertEqual(started["command_argv"], [str(executable)])
        environment = Path(f"/proc/{pane_pid}/environ").read_bytes().split(b"\0")
        self.assertIn(b"DOTUNNEL_MCP_NONCE=nonce-1", environment)
        self.assertEqual(target["native_id"], native["native_id"])
        self.assertEqual(target["process_state"], "running")

    async def test_env_s_shebang_preserves_quoted_arguments_in_running_process(self):
        executable = self.root / "agent with env shebang"
        executable.write_text(
            f"#!/usr/bin/env -S {sys.executable} -W 'ignore:hello world'\n{_AGENT}",
            encoding="utf-8",
        )
        executable.chmod(0o700)
        self.first.profile = Profile(
            id="omp",
            kind="omp",
            executable=executable,
            args=(),
            backends=("tmux",),
            input_mode="bracketed-paste",
        )

        started = await self.first.backend.start(
            self.first.project,
            self.first.profile,
            "quoted-env-arguments",
            None,
            {"target_id": "env-s", "nonce": "nonce-env-s"},
            deadline=time.monotonic() + 10,
        )

        process_argv = _proc_cmdline(started["identity"]["pane_pid"])
        self.assertEqual(
            process_argv,
            [sys.executable, "-W", "ignore:hello world", str(executable)],
        )
        self.assertEqual(started["command_argv"], process_argv)

    async def test_inventory_and_read_report_live_cwd_without_changing_record_binding(self):
        protected_path = self.root / "protected"
        protected_path.mkdir()
        agent_script = self.root / "agent_changes_cwd.py"
        agent_script.write_text(
            "import os, sys, time\n"
            "os.chdir(sys.argv[1])\n"
            "while True:\n"
            "    time.sleep(1)\n",
            encoding="utf-8",
        )
        self.first.profile = Profile(
            id="omp",
            kind="omp",
            executable=Path(sys.executable),
            args=(str(agent_script), str(protected_path)),
            backends=("tmux",),
            input_mode="bracketed-paste",
        )
        nonce = "nonce-chdir"
        started = await self.first.backend.start(
            self.first.project,
            self.first.profile,
            "changes-cwd",
            None,
            {"target_id": "chdir", "nonce": nonce},
            deadline=time.monotonic() + 10,
        )
        native = started["identity"]
        expected_cwd = str(protected_path.resolve())
        for _ in range(200):
            try:
                actual_cwd = Path(f"/proc/{native['pane_pid']}/cwd").resolve(strict=True)
            except OSError:
                actual_cwd = None
            if actual_cwd == Path(expected_cwd):
                break
            await asyncio.sleep(0.01)
        self.assertEqual(actual_cwd, Path(expected_cwd))

        record = {
            "target_id": "chdir",
            "nonce": nonce,
            "state": "active",
            "binding": {
                "connection": self.first.connection.id,
                "project": self.first.project.id,
                "profile": self.first.profile.id,
            },
            "native": dict(started, cwd=expected_cwd),
        }
        self.assertEqual(record["binding"]["project"], self.first.project.id)
        reopened = TmuxBackend(self.first.connection, self.first.runner)
        rows = await reopened.inventory(
            [self.first.project], [record], deadline=time.monotonic() + 10
        )
        self.assertEqual(len(rows), 1)
        managed = rows[0]
        self.assertTrue(managed["managed"])
        self.assertEqual(managed["cwd"], expected_cwd)
        read = await reopened.read(managed, 20, deadline=time.monotonic() + 10)
        self.assertEqual(read["cwd"], expected_cwd)
        self.assertEqual(record["native"]["cwd"], expected_cwd)

        readonly_identity = {
            key: native[key]
            for key in ("boot_id", "server_pid", "server_start", "pane_pid", "pane_start")
        }
        readonly_connection = Connection(
            id=self.first.connection.id,
            backend="tmux",
            executable=self.first.connection.executable,
            socket=self.first.connection.socket,
            read_targets=({
                "project": self.first.project.id,
                "native_id": native["native_id"],
                "identity": readonly_identity,
            },),
        )
        readonly_backend = TmuxBackend(readonly_connection, self.first.runner)
        readonly_rows = await readonly_backend.inventory(
            [self.first.project], [], deadline=time.monotonic() + 10
        )
        self.assertEqual(len(readonly_rows), 1)
        readonly = readonly_rows[0]
        self.assertTrue(readonly["readonly"])
        self.assertEqual(readonly["cwd"], expected_cwd)
        readonly_read = await readonly_backend.read(
            readonly, 20, deadline=time.monotonic() + 10
        )
        self.assertEqual(readonly_read["cwd"], expected_cwd)

    async def test_unavailable_process_cwd_hides_target_and_prevents_read_or_input(self):
        missing_cwd = self.root / "removed-process-cwd"
        missing_cwd.mkdir()
        agent_script = self.root / "agent_removed_cwd.py"
        agent_script.write_text(
            "import os, sys, time\n"
            "os.chdir(sys.argv[1])\n"
            "while True:\n"
            "    time.sleep(1)\n",
            encoding="utf-8",
        )
        self.first.profile = Profile(
            id="omp",
            kind="omp",
            executable=Path(sys.executable),
            args=(str(agent_script), str(missing_cwd)),
            backends=("tmux",),
            input_mode="bracketed-paste",
        )
        nonce = "nonce-missing-cwd"
        started = await self.first.backend.start(
            self.first.project,
            self.first.profile,
            "removed-cwd",
            None,
            {"target_id": "removed-cwd", "nonce": nonce},
            deadline=time.monotonic() + 10,
        )
        native = started["identity"]
        for _ in range(200):
            try:
                actual_cwd = Path(f"/proc/{native['pane_pid']}/cwd").resolve(strict=True)
            except OSError:
                actual_cwd = None
            if actual_cwd == missing_cwd.resolve():
                break
            await asyncio.sleep(0.01)
        self.assertEqual(actual_cwd, missing_cwd.resolve())

        record = {
            "target_id": "removed-cwd",
            "nonce": nonce,
            "state": "active",
            "binding": {
                "connection": self.first.connection.id,
                "project": self.first.project.id,
                "profile": self.first.profile.id,
            },
            "native": started,
        }
        rows = await self.first.backend.inventory(
            [self.first.project], [record], deadline=time.monotonic() + 10
        )
        self.assertEqual(len(rows), 1)
        target = rows[0]
        missing_cwd.rmdir()

        self.assertEqual(
            await self.first.backend.inventory(
                [self.first.project], [record], deadline=time.monotonic() + 10
            ),
            [],
        )
        before = len(self.calls(self.first))
        with self.assertRaises(SupervisionError):
            await self.first.backend.read(target, 20, deadline=time.monotonic() + 10)
        with self.assertRaises(SupervisionError):
            await self.first.backend.prompt(
                target,
                "must not send",
                self.first.profile,
                deadline=time.monotonic() + 10,
            )
        with self.assertRaises(SupervisionError):
            await self.first.backend.answer(
                target, ["y"], deadline=time.monotonic() + 10
            )
        new_calls = self.calls(self.first)[before:]
        self.assertFalse(any("capture-pane" in call["argv"] for call in new_calls))
        self.assertFalse(any("paste-buffer" in call["argv"] for call in new_calls))
        self.assertFalse(any("send-keys" in call["argv"] for call in new_calls))

    async def test_scheduler_state_change_preserves_live_identity_but_birth_or_exit_does_not(self):
        from unittest.mock import patch
        from dotunnel import tmux as tmux_module

        _, target = await self.start_managed()
        pid = target["identity"]["pane_pid"]
        start = target["identity"]["pane_start"]
        real_stat = tmux_module._proc_stat

        def sampling(after):
            samples = iter((("R", start), after))

            def stat(current_pid):
                actual = real_stat(current_pid)
                if current_pid != pid or actual is None:
                    return actual
                return next(samples)

            return stat

        with patch.object(tmux_module, "_proc_stat", side_effect=sampling(("S", start))):
            read = await self.first.backend.read(target, 20, deadline=time.monotonic() + 10)
        self.assertEqual(read["identity"], target["identity"])
        self.assertEqual(read["text"], "synthetic screen\n")
        captures = self.first.state()["captures"]

        for after in (("S", start + 1), ("Z", start)):
            with self.subTest(after=after):
                with patch.object(tmux_module, "_proc_stat", side_effect=sampling(after)):
                    with self.assertRaises(SupervisionError) as raised:
                        await self.first.backend.read(target, 20, deadline=time.monotonic() + 10)
                self.assertEqual(raised.exception.code, "stale_target")
                self.assertEqual(self.first.state()["captures"], captures)

    async def test_inventory_uses_managed_records_and_exact_readonly_registration_only(self):
        started, managed = await self.start_managed()
        native = started["identity"]
        read_target = {
            "project": self.first.project.id,
            "native_id": native["native_id"],
            "identity": {
                key: str(native[key])
                for key in ("boot_id", "server_pid", "server_start", "pane_pid", "pane_start")
            },
        }
        from dotunnel.config import load_config

        config_path = self.root / "readonly-config.json"
        config_path.write_text(json.dumps({
            "root": str(self.first.project_path),
            "tasks": [],
            "supervision": {
                "state_dir": str(self.root / "readonly-state"),
                "connections": [{
                    "id": self.first.connection.id,
                    "backend": "tmux",
                    "executable": str(self.first.executable),
                    "socket": str(self.first.socket),
                    "read_targets": [read_target],
                }],
                "projects": [{
                    "id": self.first.project.id,
                    "path": str(self.first.project_path),
                    "connections": [self.first.connection.id],
                    "profiles": [],
                }],
                "profiles": [],
            },
        }), encoding="utf-8")
        config_path.chmod(0o600)
        settings = load_config(config_path).supervision
        backend = TmuxBackend(settings.connections[self.first.connection.id], self.first.runner)
        rows = await backend.inventory(
            [self.first.project], [], deadline=time.monotonic() + 10
        )
        self.assertEqual([row["native_id"] for row in rows], [managed["native_id"]])
        readonly = rows[0]
        self.assertTrue(readonly["readonly"])
        self.assertEqual(readonly["agent_state"], "unknown")
        self.assertEqual(readonly["state_source"], "unavailable")
        await backend.read(readonly, 20, deadline=time.monotonic() + 10)
        captures = self.first.state().get("captures", [])
        self.assertEqual(captures, [started["identity"]["native_id"]])
        self.assertNotIn("%99", captures)
        with self.assertRaises(SupervisionError):
            await backend.prompt(readonly, "must not send", self.first.profile, deadline=time.monotonic() + 10)
        with self.assertRaises(SupervisionError):
            await backend.answer(readonly, ["y"], deadline=time.monotonic() + 10)
        self.assertEqual(self.first.state().get("pastes", []), [])
        self.assertEqual(self.first.state().get("key_sends", []), [])
        self.assert_fixed_socket(self.first)

    async def test_read_returns_requested_visible_screen_tail_after_scrollback(self):
        _, target = await self.start_managed()
        state = self.first.state()
        state.setdefault("history", {})[target["native_id"]] = ["OLD HISTORY MARKER"]
        state.setdefault("screens", {})[target["native_id"]] = "visible line\nCURRENT SCREEN MARKER\n"
        self.first.save_state(state)
        result = await self.first.backend.read(
            target, 1, deadline=time.monotonic() + 10
        )
        self.assertEqual(result["text"], "CURRENT SCREEN MARKER\n")
        self.assertNotIn("OLD HISTORY MARKER", result["text"])

    async def test_inventory_without_listening_socket_returns_empty_without_starting_server(self):
        started, _ = await self.start_managed()
        record = {
            "target_id": "attempt-1",
            "nonce": started["nonce"],
            "state": "active",
            "binding": {
                "connection": self.first.connection.id,
                "project": self.first.project.id,
                "profile": self.first.profile.id,
            },
            "native": started,
        }
        state = self.first.state()
        before = len(state["calls"])
        state["server_absent"] = True
        self.first.save_state(state)
        rows = await self.first.backend.inventory(
            [self.first.project], [record], deadline=time.monotonic() + 10
        )
        self.assertEqual(rows, [])
        calls = self.calls(self.first)[before:]
        self.assertFalse(any("new-session" in call["argv"] for call in calls))
        self.assertTrue(calls)
        self.assertTrue(all("-N" in call["argv"] for call in calls))

    async def test_unregistered_panes_are_never_captured_or_used_as_input_targets(self):
        _, managed = await self.start_managed()
        before = len(self.calls(self.first))
        rogue = {
            **managed,
            "native_id": "%99",
            "identity": {"native_id": "%99"},
            "native": {"native_id": "%99"},
            "readonly": False,
            "managed": False,
        }
        with self.assertRaises(SupervisionError):
            await self.first.backend.read(rogue, 20, deadline=time.monotonic() + 10)
        with self.assertRaises(SupervisionError):
            await self.first.backend.prompt(rogue, "not allowed", self.first.profile, deadline=time.monotonic() + 10)
        new_calls = self.calls(self.first)[before:]
        self.assertFalse(any("capture-pane" in call["argv"] for call in new_calls))
        self.assertFalse(any("paste-buffer" in call["argv"] or "send-keys" in call["argv"] for call in new_calls))
        self.assertNotIn("%99", self.first.state().get("captures", []))

    async def test_stale_native_generations_refuse_before_screen_capture_or_input(self):
        _, target = await self.start_managed()
        stale_values = (
            ("boot_id", "0" * 36),
            ("server_start", target["identity"]["server_start"] + 1),
            ("server_pid", 99999998),
            ("pane_start", target["identity"]["pane_start"] + 1),
            ("pane_pid", 99999997),
            ("nonce", "different-nonce"),
        )
        for field, value in stale_values:
            with self.subTest(field=field):
                stale = dict(target)
                stale_identity = dict(target["identity"])
                stale_identity[field] = value
                stale["identity"] = stale_identity
                stale["native_id"] = stale_identity["native_id"]
                before_captures = len(self.first.state().get("captures", []))
                before_pastes = len(self.first.state().get("pastes", []))
                with self.assertRaises(SupervisionError):
                    await self.first.backend.read(stale, 20, deadline=time.monotonic() + 10)
                with self.assertRaises(SupervisionError):
                    await self.first.backend.prompt(stale, "stale must not send", self.first.profile, deadline=time.monotonic() + 10)
                self.assertEqual(len(self.first.state().get("captures", [])), before_captures)
                self.assertEqual(len(self.first.state().get("pastes", [])), before_pastes)

    async def test_shell_or_herdr_client_replacement_is_not_the_recorded_agent(self):
        started, target = await self.start_managed()
        original_pid = started["identity"]["pane_pid"]
        os.kill(original_pid, signal.SIGTERM)
        for _ in range(100):
            try:
                if _process_state(original_pid) == "Z":
                    break
            except (FileNotFoundError, ProcessLookupError):
                break
            await asyncio.sleep(0.01)

        replacement = subprocess.Popen(
            ["/bin/sh", "-c", "exec sleep 60"],
            cwd=self.first.project.path,
            env={"PATH": "/usr/bin:/bin", "DOTUNNEL_MCP_NONCE": "nonce-1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.processes.append(replacement)
        state = self.first.state()
        pane = next(item for item in state["panes"] if item["pane_id"] == started["identity"]["native_id"])
        pane["pane_pid"] = replacement.pid
        state.setdefault("child_pids", []).append(replacement.pid)
        self.first.save_state(state)
        replacement_identity = dict(started["identity"])
        replacement_identity["pane_pid"] = replacement.pid
        replacement_identity["pane_start"] = _proc_start_time(replacement.pid)
        replacement_target = dict(target)
        replacement_target["identity"] = replacement_identity
        replacement_start = {**started, "identity": replacement_identity}
        rows = await self.first.backend.inventory(
            [self.first.project],
            [
                {
                    "target_id": "attempt-1",
                    "nonce": target["nonce"],
                    "state": "active",
                    "binding": {
                        "connection": self.first.connection.id,
                        "project": self.first.project.id,
                        "profile": self.first.profile.id,
                    },
                    "native": replacement_start,
                }
            ],
            deadline=time.monotonic() + 10,
        )
        self.assertEqual(rows, [])
        before_captures = len(self.first.state().get("captures", []))
        before_pastes = len(self.first.state().get("pastes", []))
        with self.assertRaises(SupervisionError):
            await self.first.backend.read(replacement_target, 20, deadline=time.monotonic() + 10)
        with self.assertRaises(SupervisionError):
            await self.first.backend.prompt(replacement_target, "not the agent", self.first.profile, deadline=time.monotonic() + 10)
        self.assertEqual(len(self.first.state().get("captures", [])), before_captures)
        self.assertEqual(len(self.first.state().get("pastes", [])), before_pastes)

    async def test_prompt_pastes_literal_unicode_multiline_once_and_deletes_only_its_buffer(self):
        _, target = await self.start_managed()
        protected_buffer = base64.b64encode(b"operator buffer").decode("ascii")
        state = self.first.state()
        state["buffers"] = {"operator-buffer": protected_buffer}
        self.first.save_state(state)
        text = "-looks-like-an-option --no-shell\nUnicode: 雪 ☃ café\nlast line"
        result = await self.first.backend.prompt(
            target, text, self.first.profile, deadline=time.monotonic() + 10
        )
        self.assertEqual(result["delivery"], "confirmed")
        state = self.first.state()
        self.assertEqual(len(state.get("pastes", [])), 1)
        paste = state["pastes"][0]
        self.assertEqual(paste["target"], target["native_id"])
        self.assertEqual(base64.b64decode(paste["bytes"]), text.encode("utf-8"))
        self.assertEqual(len(state.get("loaded_buffers", [])), 1)
        self.assertEqual(state.get("deleted_buffers"), state.get("loaded_buffers"))
        self.assertEqual(state.get("buffers"), {"operator-buffer": protected_buffer})
        buffer_name = state["loaded_buffers"][0]
        paste_call = next(call for call in self.tmux_calls(self.first, "paste-buffer") if buffer_name in call["argv"])
        self.assertIn("-p", paste_call["argv"])
        self.assertIn("-r", paste_call["argv"])
        self.assertNotIn(text, [item for call in self.calls(self.first) for item in call["argv"]])
        self.assertNotIn("send-keys", [item for call in self.calls(self.first) for item in call["argv"]])
        self.assert_fixed_socket(self.first)
    async def test_uncertain_paste_failure_is_unknown_and_never_retried(self):
        _, target = await self.start_managed()
        state = self.first.state()
        state["fail_paste_after_effect"] = True
        self.first.save_state(state)
        result = await self.first.backend.prompt(
            target, "one attempt only\n雪", self.first.profile, deadline=time.monotonic() + 10
        )
        state = self.first.state()
        self.assertEqual(result["delivery"], "unknown")
        self.assertEqual(len(state.get("pastes", [])), 1)
        self.assertEqual(len(self.tmux_calls(self.first, "paste-buffer")), 1)
        self.assertEqual(state.get("deleted_buffers"), state.get("loaded_buffers"))
        self.assertEqual(state.get("buffers"), {})

    async def test_each_prompt_uses_a_unique_owned_buffer(self):
        _, target = await self.start_managed()
        await self.first.backend.prompt(target, "first\n雪", self.first.profile, deadline=time.monotonic() + 10)
        await self.first.backend.prompt(target, "second\n☃", self.first.profile, deadline=time.monotonic() + 10)
        state = self.first.state()
        self.assertEqual(len(state.get("pastes", [])), 2)
        self.assertEqual(len(set(state.get("loaded_buffers", []))), 2)
        self.assertEqual(state.get("deleted_buffers"), state.get("loaded_buffers"))
        self.assertEqual(state.get("buffers"), {})
        self.assertEqual(
            [base64.b64decode(item["bytes"]) for item in state["pastes"]],
            ["first\n雪".encode(), "second\n☃".encode()],
        )

    async def test_answer_sends_only_constrained_keys_to_managed_pane(self):
        _, target = await self.start_managed()
        result = await self.first.backend.answer(
            target, ["y", "enter", "up"], deadline=time.monotonic() + 10
        )
        self.assertEqual(result["delivery"], "confirmed")
        self.assertEqual(
            self.first.state().get("key_sends"),
            [{"target": target["native_id"], "keys": ["y", "Enter", "Up"]}],
        )
        before = len(self.first.state().get("key_sends", []))
        with self.assertRaises(SupervisionError):
            await self.first.backend.answer(target, ["C-c"], deadline=time.monotonic() + 10)
        self.assertEqual(len(self.first.state().get("key_sends", [])), before)

    async def test_two_connections_with_the_same_display_name_remain_socket_scoped(self):
        _, target_one = await self.start_managed(self.first, name="same-name", attempt_id="one", nonce="nonce-one")
        second = self.add_fixture("connection-two")
        _, target_two = await self.start_managed(second, name="same-name", attempt_id="two", nonce="nonce-two")
        await self.first.backend.prompt(target_one, "only one", self.first.profile, deadline=time.monotonic() + 10)
        self.assertEqual(len(self.first.state().get("pastes", [])), 1)
        self.assertEqual(self.first.state()["pastes"][0]["target"], target_one["native_id"])
        self.assertEqual(second.state().get("pastes", []), [])
        self.assertEqual(target_one["name"], target_two["name"])
        self.assertNotEqual(self.first.connection.socket, second.connection.socket)
        self.assert_fixed_socket(self.first)
        self.assert_fixed_socket(second)

    async def test_missing_post_start_native_identity_is_unknown_not_actionable(self):
        state = self.first.state()
        state["omit_new_session_identity"] = True
        self.first.save_state(state)
        with self.assertRaises(SupervisionError) as caught:
            await self.first.backend.start(
                self.first.project,
                self.first.profile,
                "lost-identity",
                None,
                {"target_id": "attempt-lost", "nonce": "nonce-lost"},
                deadline=time.monotonic() + 10,
            )
        self.assertEqual(caught.exception.code, "delivery_unknown")
        calls = self.calls(self.first)
        self.assertTrue(any("new-session" in call["argv"] for call in calls))
        self.assertFalse(any("capture-pane" in call["argv"] or "paste-buffer" in call["argv"] for call in calls))
        self.assertEqual(self.first.state().get("pastes", []), [])


if __name__ == "__main__":
    unittest.main()
