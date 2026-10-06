import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from dotunnel_adapter.backend import invoke
from dotunnel_adapter.protocol import RunnerError


class InvokeTests(unittest.TestCase):
    def envelope(self, *, payload_size=0):
        return {"protocol": "dotunnel.adapter.backend/1", "phase": "dispatch", "payload": "x" * payload_size}

    def python_argv(self, code, *args):
        return (sys.executable, "-I", "-c", code, *(str(arg) for arg in args))

    def assert_code(self, code, callback, *args, **kwargs):
        with self.assertRaises(RunnerError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_feeds_large_stdin_while_draining_stdout_and_stderr(self):
        script = (
            "import json,sys; "
            "sys.stderr.write('e'*40000); sys.stderr.flush(); "
            "data=sys.stdin.buffer.read(); "
            "sys.stdout.write(json.dumps({'received':len(data)}))"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = invoke(self.python_argv(script), self.envelope(payload_size=50000), cwd=Path(directory), timeout_seconds=5)
        expected = json.dumps(self.envelope(payload_size=50000), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertEqual(result["received"], len(expected))

    def test_rejects_combined_output_overflow(self):
        script = "import sys; sys.stderr.write('e'*40000); sys.stderr.flush(); sys.stdout.write('o'*27000); sys.stdout.flush()"
        with tempfile.TemporaryDirectory() as directory:
            self.assert_code("resource_limit", invoke, self.python_argv(script), self.envelope(), cwd=Path(directory), timeout_seconds=5)

    def test_rejects_oversized_input_before_starting_backend(self):
        script = "import pathlib,sys; pathlib.Path(sys.argv[1]).touch(); print('{}')"
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "started"
            self.assert_code("resource_limit", invoke, self.python_argv(script, marker), self.envelope(payload_size=65536), cwd=Path(directory), timeout_seconds=5)
            self.assertFalse(marker.exists())

    def test_timeout_kills_owned_process_group(self):
        child = "import pathlib,sys,time; time.sleep(0.5); pathlib.Path(sys.argv[1]).touch()"
        parent = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-I','-c'," + repr(child) + ",sys.argv[1]]); "
            "import time; time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "survived"
            self.assert_code("backend_unavailable", invoke, self.python_argv(parent, marker), self.envelope(), cwd=Path(directory), timeout_seconds=0.15)
            time.sleep(0.6)
            self.assertFalse(marker.exists())

    def test_kills_leftover_owned_group_even_after_success(self):
        child = "import pathlib,sys,time; time.sleep(0.4); pathlib.Path(sys.argv[1]).touch()"
        parent = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-I','-c'," + repr(child) + ",sys.argv[1]]); "
            "print('{}')"
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "survived"
            self.assertEqual(invoke(self.python_argv(parent, marker), self.envelope(), cwd=Path(directory), timeout_seconds=5), {})
            time.sleep(0.5)
            self.assertFalse(marker.exists())

    def test_escaped_pipe_cleanup_has_a_separate_one_second_bound(self):
        child = "import os,sys,time; os.setsid(); open(sys.argv[1],'w').write('ready'); time.sleep(10)"
        parent = (
            "import pathlib,subprocess,sys,time\n"
            "ready=sys.argv[1]\n"
            "child=subprocess.Popen([sys.executable,'-I','-c'," + repr(child) + ",ready])\n"
            "deadline=time.monotonic()+2\n"
            "while not pathlib.Path(ready).exists() and time.monotonic()<deadline:\n"
            "    time.sleep(0.005)\n"
            "if not pathlib.Path(ready).exists(): raise SystemExit(2)\n"
            "open(sys.argv[2],'w').write(str(child.pid))\n"
            "print('{}')\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "escaped-ready"
            pid_file = Path(directory) / "escaped-pid"
            started = time.monotonic()
            try:
                self.assert_code("backend_unavailable", invoke, self.python_argv(parent, ready, pid_file), self.envelope(), cwd=Path(directory), timeout_seconds=5)
                self.assertLess(time.monotonic() - started, 3.0)
                self.assertTrue(pid_file.exists())
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_direct_backend_dies_when_its_runner_is_force_killed(self):
        child = (
            "import os,pathlib,sys,time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
        )
        leader = (
            "import pathlib,sys; sys.path.insert(0,sys.argv[1]); "
            "from dotunnel_adapter.backend import invoke; "
            "invoke((sys.executable,'-I','-c',sys.argv[3],sys.argv[4]),"
            "{'request':1},cwd=pathlib.Path(sys.argv[2]),timeout_seconds=30)"
        )
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "direct-backend-pid"
            parent = subprocess.Popen(
                [sys.executable, "-I", "-c", leader, str(SOURCE),
                 directory, child, str(pid_file)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            child_pid = None
            try:
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_file.exists(), "backend did not reach its owned launch")
                child_pid = int(pid_file.read_text())
                parent.kill()
                parent.wait(timeout=5)
                stat_path = Path(f"/proc/{child_pid}/stat")
                deadline = time.monotonic() + 2
                running = True
                while time.monotonic() < deadline:
                    try:
                        running = stat_path.read_text().rsplit(") ", 1)[1].split()[0] != "Z"
                    except FileNotFoundError:
                        running = False
                    if not running:
                        break
                    time.sleep(0.01)
                self.assertFalse(running, "direct backend survived forced runner death")
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=5)
                if child_pid is not None:
                    try:
                        os.killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_uses_only_sanitized_backend_environment(self):
        script = "import json,os; print(json.dumps({k:os.environ.get(k) for k in ('HOME','PATH','LANG','ADAPTER_TEST_SECRET')}))"
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"ADAPTER_TEST_SECRET": "must-not-leak"}):
                result = invoke(self.python_argv(script), self.envelope(), cwd=Path(directory), timeout_seconds=5)
        self.assertEqual(result, {"HOME": directory, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "ADAPTER_TEST_SECRET": None})

    def test_never_interprets_argument_text_as_shell(self):
        script = "import json,sys; print(json.dumps({'argument':sys.argv[1]}))"
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "shell-ran"
            argument = f"; touch {marker}"
            self.assertEqual(invoke(self.python_argv(script, argument), self.envelope(), cwd=Path(directory), timeout_seconds=5), {"argument": argument})
            self.assertFalse(marker.exists())

    def test_nonzero_exit_hides_stderr_and_malformed_backend_json_is_rejected(self):
        secret = "private-backend-diagnostic-91a3"
        nonzero = "import sys; sys.stderr.write(" + repr(secret) + "); sys.exit(7)"
        with tempfile.TemporaryDirectory() as directory:
            error = self.assert_code("backend_unavailable", invoke, self.python_argv(nonzero), self.envelope(), cwd=Path(directory), timeout_seconds=5)
            self.assertNotIn(secret, str(error))
            for output in ('{"x":1,"x":2}', '{"x":NaN}', 'not-json'):
                script = "import sys; sys.stdout.write(" + repr(output) + ")"
                self.assert_code("backend_unavailable", invoke, self.python_argv(script), self.envelope(), cwd=Path(directory), timeout_seconds=5)

    def test_timeout_must_be_finite_and_at_most_two_hundred_seconds(self):
        argv = self.python_argv("print('{}')")
        with tempfile.TemporaryDirectory() as directory:
            for value in (0, -1, float("inf"), float("nan"), 200.01):
                self.assert_code("invalid_config", invoke, argv, self.envelope(), cwd=Path(directory), timeout_seconds=value)


if __name__ == "__main__":
    unittest.main()
