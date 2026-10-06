import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mcp import Client, StdioServerParameters


class ProtocolBoundaryTests(unittest.IsolatedAsyncioTestCase):

    @staticmethod
    def make_stdio_server(base, root, tasks):
        config = base / "config.json"
        config.write_text(json.dumps({"root": str(root), "tasks": tasks}))
        config.chmod(0o600)
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "dotunnel", "serve", "--config", str(config)],
            cwd=Path(__file__).absolute().parent.parent,
        )

    @staticmethod
    def result_data(result):
        return json.loads(result.content[0].text)

    async def wait_for_file(self, path, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            await asyncio.sleep(0.01)
        self.fail("stdio task fixture did not start")

    @staticmethod
    def process_is_running(pid):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except FileNotFoundError:
            return False
        return stat.rsplit(") ", 1)[1].split()[0] not in {"Z", "X"}

    async def wait_for_process_exit(self, pid, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.process_is_running(pid):
                return
            await asyncio.sleep(0.02)
        self.fail(f"stdio task child {pid} did not stop at EOF")

    async def wait_for_terminal_result(self, client, result_id, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = await client.call_tool("get_task_result", {"result_id": result_id})
            self.assertFalse(response.is_error)
            result = self.result_data(response)
            if result["status"] != "running":
                return result
            await asyncio.sleep(0.01)
        self.fail("stdio task result did not reach a terminal state")

    async def test_stdio_task_returns_running_then_same_id_terminal_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "workspace"
            root.mkdir()
            started = base / "started.pid"
            release = base / "release"
            code = (
                "import os, pathlib, time\n"
                f"started = pathlib.Path({str(started)!r})\n"
                "temporary = started.with_suffix('.tmp')\n"
                "temporary.write_text(str(os.getpid()))\n"
                "temporary.replace(started)\n"
                f"release = pathlib.Path({str(release)!r})\n"
                "while not release.exists():\n"
                "    time.sleep(0.01)\n"
                "print('stdio output', flush=True)\n"
            )
            server = self.make_stdio_server(
                base,
                root,
                [{
                    "name": "held",
                    "description": "Held task fixture",
                    "argv": [sys.executable, "-I", "-c", code],
                    "cwd": ".",
                    "timeout_seconds": 10,
                }],
            )
            child_pid = None
            async with Client(server) as client:
                listed = await client.list_tools()
                self.assertEqual(
                    {tool.name for tool in listed.tools},
                    {"list_files", "read_file", "search_files", "write_file",
                     "list_tasks", "run_task", "get_task_result"},
                )
                try:
                    response = await client.call_tool("run_task", {"name": "held"})
                    self.assertFalse(response.is_error)
                    accepted = self.result_data(response)
                    await self.wait_for_file(started)
                    child_pid = int(started.read_text())
                    self.assertEqual(accepted["status"], "running")
                    self.assertIsNone(accepted["exit_code"])
                    self.assertEqual(accepted["output"], "")
                    self.assertFalse(accepted["truncated"])

                    snapshot_response = await client.call_tool(
                        "get_task_result", {"result_id": accepted["result_id"]}
                    )
                    self.assertFalse(snapshot_response.is_error)
                    self.assertEqual(self.result_data(snapshot_response), accepted)
                    release.touch()
                    terminal = await self.wait_for_terminal_result(
                        client, accepted["result_id"]
                    )
                    self.assertEqual(terminal["result_id"], accepted["result_id"])
                    self.assertEqual(terminal["status"], "completed")
                    self.assertEqual(terminal["exit_code"], 0)
                    self.assertEqual(terminal["output"], "stdio output\n")
                    self.assertFalse(terminal["truncated"])
                finally:
                    release.touch()
            if child_pid is not None:
                await self.wait_for_process_exit(child_pid)

    async def test_stdio_eof_cleans_up_an_owned_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "workspace"
            root.mkdir()
            started = base / "shutdown-started.pid"
            release = base / "shutdown-release"
            code = (
                "import os, pathlib, time\n"
                f"started = pathlib.Path({str(started)!r})\n"
                "temporary = started.with_suffix('.tmp')\n"
                "temporary.write_text(str(os.getpid()))\n"
                "temporary.replace(started)\n"
                f"release = pathlib.Path({str(release)!r})\n"
                "while not release.exists():\n"
                "    time.sleep(0.01)\n"
                "print('never released', flush=True)\n"
            )
            server = self.make_stdio_server(
                base,
                root,
                [{
                    "name": "held",
                    "description": "Held shutdown fixture",
                    "argv": [sys.executable, "-I", "-c", code],
                    "cwd": ".",
                    "timeout_seconds": 60,
                }],
            )
            child_pid = None
            try:
                async with Client(server) as client:
                    response = await client.call_tool("run_task", {"name": "held"})
                    self.assertFalse(response.is_error)
                    accepted = self.result_data(response)
                    self.assertEqual(accepted["status"], "running")
                    await self.wait_for_file(started)
                    child_pid = int(started.read_text())

                self.assertIsNotNone(child_pid)
                await self.wait_for_process_exit(child_pid)
            finally:
                release.touch()
                if child_pid is not None and self.process_is_running(child_pid):
                    await self.wait_for_process_exit(child_pid)

    async def test_extra_task_arguments_are_rejected_before_any_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "workspace"
            root.mkdir()
            marker = root / "executed"
            config = base / "config.json"
            config.write_text(json.dumps({
                "root": str(root),
                "tasks": [{
                    "name": "probe", "description": "Synthetic side-effect probe",
                    "argv": [sys.executable, "-I", "-c", "from pathlib import Path; Path('executed').touch()"],
                    "cwd": ".", "timeout_seconds": 3,
                }],
            }))
            config.chmod(0o600)
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "dotunnel", "serve", "--config", str(config)],
                cwd=Path(__file__).absolute().parent.parent,
            )
            async with Client(server) as client:
                result = await client.call_tool("run_task", {"name": "probe", "argv": ["/bin/sh"]})
                self.assertTrue(result.is_error)
                self.assertFalse(marker.exists(), "Rejected arguments must not execute even the fixed task")


if __name__ == "__main__":
    unittest.main()
