import asyncio
import math
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from dotunnel.tasks import TaskRunner, TaskSpec


MAX_OUTPUT = 16 * 1024


class TaskRunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name)

    def make_spec(self, name, code, *, cwd=None, timeout_seconds=60):
        return TaskSpec(
            name=name,
            description=f"Run {name}",
            argv=(sys.executable, "-c", code),
            cwd=self.root if cwd is None else cwd,
            timeout_seconds=timeout_seconds,
        )

    async def wait_for_file(self, path, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            await asyncio.sleep(0.01)
        self.fail("task fixture did not create its readiness file")

    async def wait_for_condition(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            await asyncio.sleep(0.01)
        self.fail("condition was not reached")

    async def wait_for_result(self, runner, result_id, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = runner.get_task_result(result_id)
            if result["status"] != "running":
                return result
            await asyncio.sleep(0.01)
        self.fail("task result did not reach a terminal state")

    async def run_to_completion(self, runner, name, timeout=4):
        admission = await runner.run_task(name)
        return await self.wait_for_result(runner, admission["result_id"], timeout)

    @staticmethod
    def process_is_running(pid):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return False
        state = stat.rsplit(") ", 1)[1].split()[0]
        return state not in {"Z", "X"}

    async def wait_for_process_exit(self, pid, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.process_is_running(pid):
                return
            await asyncio.sleep(0.02)
        self.fail(f"task child process {pid} was not terminated")

    async def test_shutdown_does_not_wait_for_unrelated_request_cleanup(self):
        runner = TaskRunner(
            [self.make_spec("held", "import time; time.sleep(30)")], self.root
        )
        spawned = asyncio.Event()
        release_spawn = asyncio.Event()
        request_cleanup = asyncio.Event()
        release_request = asyncio.Event()
        processes = []
        original_spawn = asyncio.create_subprocess_exec

        async def delayed_spawn(*args, **kwargs):
            process = await original_spawn(*args, **kwargs)
            processes.append(process)
            spawned.set()
            await release_spawn.wait()
            return process

        async def request():
            try:
                await runner.run_task("held")
            except asyncio.CancelledError:
                request_cleanup.set()
                await release_request.wait()

        closing = None
        with patch("dotunnel.tasks.asyncio.create_subprocess_exec", delayed_spawn):
            admission = asyncio.create_task(request())
            try:
                await asyncio.wait_for(spawned.wait(), 2)
                closing = asyncio.create_task(runner.aclose())
                release_spawn.set()
                await asyncio.wait_for(request_cleanup.wait(), 2)
                try:
                    await asyncio.wait_for(asyncio.shield(closing), 0.5)
                except asyncio.TimeoutError:
                    self.fail("shutdown waited for unrelated caller cleanup after its child was reaped")
                self.assertFalse(admission.done())
                self.assertFalse(self.process_is_running(processes[0].pid))
            finally:
                release_spawn.set()
                release_request.set()
                if closing is not None:
                    await asyncio.wait_for(asyncio.shield(closing), 3)
                await asyncio.wait_for(admission, 3)
                await runner.aclose()

    async def test_run_task_returns_before_child_finishes_and_result_can_be_polled(self):
        started = self.root / "held-started.pid"
        release = self.root / "held-release"
        child_code = (
            "import os, pathlib, time\n"
            f"started = pathlib.Path({str(started)!r})\n"
            "pending = started.with_suffix('.pending')\n"
            "pending.write_text(str(os.getpid()))\n"
            "pending.replace(started)\n"
            f"release = pathlib.Path({str(release)!r})\n"
            "while not release.exists():\n"
            "    time.sleep(0.01)\n"
            "print('released output', flush=True)\n"
        )
        runner = TaskRunner([self.make_spec("held", child_code)], self.root)
        active = asyncio.create_task(runner.run_task("held"))
        child_pid = None
        try:
            await self.wait_for_file(started)
            child_pid = int(started.read_text())
            try:
                accepted = await asyncio.wait_for(asyncio.shield(active), timeout=0.25)
            except asyncio.TimeoutError:
                self.fail("run_task did not return an admission before the child was released")

            self.assertEqual(
                accepted,
                {
                    "result_id": accepted["result_id"],
                    "task": "held",
                    "status": "running",
                    "exit_code": None,
                    "output": "",
                    "truncated": False,
                },
            )
            snapshot = runner.get_task_result(accepted["result_id"])
            self.assertEqual(snapshot, accepted)
            snapshot["status"] = "completed"
            self.assertEqual(runner.get_task_result(accepted["result_id"])["status"], "running")

            release.touch()
            terminal = await self.wait_for_result(runner, accepted["result_id"])
            self.assertEqual(terminal["result_id"], accepted["result_id"])
            self.assertEqual(terminal["status"], "completed")
            self.assertEqual(terminal["exit_code"], 0)
            self.assertEqual(terminal["output"], "released output\n")
            self.assertFalse(terminal["truncated"])
        finally:
            if not active.done():
                active.cancel()
            await asyncio.gather(active, return_exceptions=True)
            release.touch()
            if child_pid is not None:
                await self.wait_for_process_exit(child_pid)
            await runner.aclose()

    async def test_cancelling_request_after_handoff_does_not_cancel_owned_child(self):
        started = self.root / "handoff-started.pid"
        release = self.root / "handoff-release"
        handoff = asyncio.Event()
        accepted = {}
        child_code = (
            "import os, pathlib, time\n"
            f"pathlib.Path({str(started)!r}).write_text(str(os.getpid()))\n"
            f"release = pathlib.Path({str(release)!r})\n"
            "while not release.exists():\n"
            "    time.sleep(0.01)\n"
            "print('child finished', flush=True)\n"
        )
        runner = TaskRunner([self.make_spec("held", child_code)], self.root)

        async def request():
            accepted["result"] = await runner.run_task("held")
            handoff.set()
            await asyncio.Event().wait()

        request_task = asyncio.create_task(request())
        child_pid = None
        try:
            await self.wait_for_file(started)
            child_pid = int(started.read_text())
            await self.wait_for_condition(handoff.is_set)
            request_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request_task

            admission = accepted["result"]
            self.assertEqual(admission["status"], "running")
            self.assertTrue(self.process_is_running(child_pid))
            self.assertEqual(runner.get_task_result(admission["result_id"])["status"], "running")
            release.touch()
            terminal = await self.wait_for_result(runner, admission["result_id"])
            self.assertEqual(terminal["output"], "child finished\n")
            self.assertEqual(terminal["status"], "completed")
        finally:
            release.touch()
            if not request_task.done():
                request_task.cancel()
            await asyncio.gather(request_task, return_exceptions=True)
            if child_pid is not None:
                await self.wait_for_process_exit(child_pid)
            await runner.aclose()

    async def terminate_fixture_process(self, pid):
        if self.process_is_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await self.wait_for_process_exit(pid)

    async def test_captures_exact_output_and_exit_code_and_retrieves_result(self):
        runner = TaskRunner(
            [self.make_spec("report", "import sys; print('exact output'); sys.exit(7)")],
            self.root,
        )

        result = await self.run_to_completion(runner, "report")

        self.assertEqual(
            set(result),
            {"result_id", "task", "status", "exit_code", "output", "truncated"},
        )
        self.assertEqual(result["task"], "report")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["output"], "exact output\n")
        self.assertFalse(result["truncated"])
        self.assertEqual(runner.get_task_result(result["result_id"]), result)
        self.assertEqual(runner.list_tasks(), {"tasks": [{"name": "report", "description": "Run report"}]})

    async def test_unknown_task_is_rejected_without_disclosing_configured_command(self):
        private_argument = "fixture-private-command-text"
        runner = TaskRunner(
            [self.make_spec("known", f"print({private_argument!r})")], self.root
        )

        with self.assertRaises(ValueError) as raised:
            await runner.run_task("unknown")

        self.assertNotIn(private_argument, str(raised.exception))
        self.assertNotIn(sys.executable, str(raised.exception))

    async def test_spawn_failure_returns_no_id_and_releases_admission_slot(self):
        async def fail_spawn(*args, **kwargs):
            raise OSError("private startup detail")

        runner = TaskRunner([self.make_spec("probe", "print('started')")], self.root)
        with patch("dotunnel.tasks.asyncio.create_subprocess_exec", fail_spawn):
            with self.assertRaisesRegex(ValueError, "could not be started"):
                await runner.run_task("probe")

        self.assertEqual(runner._results, {})
        result = await self.run_to_completion(runner, "probe")
        self.assertEqual(result["output"], "started\n")

    async def test_post_start_collection_failure_is_retrievable(self):
        class FailedCollector(TaskRunner):
            process = None

            async def _spawn(self, spec, cwd_fd):
                self.process = await super()._spawn(spec, cwd_fd)
                return self.process

            async def _collect_output(self, process, capture):
                raise OSError("private collection detail")

        runner = FailedCollector([self.make_spec("fails", "import time; time.sleep(60)")], self.root)
        try:
            admission = await runner.run_task("fails")
            result = await self.wait_for_result(runner, admission["result_id"])
            self.assertEqual(result["result_id"], admission["result_id"])
            self.assertEqual(result["status"], "failed")
            self.assertIsNotNone(result["exit_code"])
            self.assertEqual(result["output"], "")
            self.assertIsNotNone(runner.process.returncode)
        finally:
            await runner.aclose()

    async def test_output_is_bounded_while_overflow_is_drained(self):
        runner = TaskRunner(
            [self.make_spec("noisy", f"import sys; sys.stdout.write('x' * {MAX_OUTPUT + 8192})")],
            self.root,
        )

        result = await self.run_to_completion(runner, "noisy")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["output"], "x" * MAX_OUTPUT)
        self.assertTrue(result["truncated"])


    async def test_timeout_deadline_runs_before_the_first_result_query(self):
        started = self.root / "timeout-deadline-started"
        code = (
            "import pathlib, time\n"
            f"pathlib.Path({str(started)!r}).touch()\n"
            "time.sleep(60)\n"
        )
        runner = TaskRunner(
            [self.make_spec("short", code, timeout_seconds=0.15)],
            self.root,
        )
        try:
            admission = await runner.run_task("short")
            await self.wait_for_file(started)
            query_delay_elapsed = asyncio.Event()
            asyncio.get_running_loop().call_later(0.3, query_delay_elapsed.set)
            await asyncio.wait_for(query_delay_elapsed.wait(), 1)
            result = await self.wait_for_result(runner, admission["result_id"])
            self.assertEqual(result["status"], "timed_out")
        finally:
            await runner.aclose()

    async def test_timeout_kills_child_even_after_leader_exits_with_pipe_open(self):
        child_pid_file = self.root / "timeout-child.pid"
        child_code = "import time; time.sleep(60)"
        parent_code = (
            "import pathlib, subprocess, sys; "
            f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
            "print(child.pid, flush=True)"
        )
        runner = TaskRunner(
            [self.make_spec("leaked-pipe", parent_code, timeout_seconds=0.5)],
            self.root,
        )
        child_pid = None
        try:
            result = await self.run_to_completion(runner, "leaked-pipe")
            self.assertEqual(result["status"], "timed_out")
            child_pid = int(result["output"].strip())
            await self.wait_for_process_exit(child_pid)
        finally:
            if child_pid is None and child_pid_file.exists():
                child_pid = int(child_pid_file.read_text())
            if child_pid is not None:
                await self.terminate_fixture_process(child_pid)

    async def test_detached_output_pipe_releases_runner_after_timeout(self):
        child_pid_file = self.root / "escaped-timeout.pid"
        parent_code = (
            "import pathlib, subprocess, sys; "
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
            "start_new_session=True); "
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
            "print('leader finished', flush=True)"
        )
        runner = TaskRunner(
            [
                self.make_spec("escaped", parent_code, timeout_seconds=0.2),
                self.make_spec("quick", "print('available')"),
            ],
            self.root,
        )
        child_pid = None
        try:
            admission = await asyncio.wait_for(runner.run_task("escaped"), 2)
            await self.wait_for_file(child_pid_file)
            child_pid = int(child_pid_file.read_text())
            result = await self.wait_for_result(runner, admission["result_id"])
            self.assertEqual(result["status"], "timed_out")
            self.assertTrue(self.process_is_running(child_pid))
            follow_up = await asyncio.wait_for(self.run_to_completion(runner, "quick"), 2)
            self.assertEqual(follow_up["output"], "available\n")
        finally:
            if child_pid is None and child_pid_file.exists():
                child_pid = int(child_pid_file.read_text())
            if child_pid is not None:
                await self.terminate_fixture_process(child_pid)
            await runner.aclose()


    async def test_normal_completion_kills_same_group_child_that_closed_output(self):
        child_pid_file = self.root / "detached-output-child.pid"
        child_code = "import time; time.sleep(60)"
        parent_code = (
            "import pathlib, subprocess, sys; "
            f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
            "print(child.pid, flush=True)"
        )
        runner = TaskRunner([self.make_spec("leader-exits", parent_code)], self.root)
        child_pid = None
        try:
            result = await self.run_to_completion(runner, "leader-exits")
            child_pid = int(result["output"].strip())
            self.assertEqual(result["status"], "completed")
            await self.wait_for_process_exit(child_pid)
        finally:
            if child_pid is None and child_pid_file.exists():
                child_pid = int(child_pid_file.read_text())
            if child_pid is not None:
                await self.terminate_fixture_process(child_pid)

    async def test_aclose_is_idempotent_and_cleans_a_held_output_pipe(self):
        child_pid_file = self.root / "escaped-shutdown.pid"
        parent_code = (
            "import pathlib, subprocess, sys; "
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
            "start_new_session=True); "
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
            "print('leader finished', flush=True)"
        )
        runner = TaskRunner(
            [self.make_spec("escaped", parent_code, timeout_seconds=60)],
            self.root,
        )
        child_pid = None
        closing = concurrent_close = None
        try:
            admission = await asyncio.wait_for(runner.run_task("escaped"), 2)
            await self.wait_for_file(child_pid_file)
            child_pid = int(child_pid_file.read_text())
            self.assertEqual(runner.get_task_result(admission["result_id"])["status"], "running")

            closing = asyncio.create_task(runner.aclose())
            await self.wait_for_condition(lambda: runner._close_task is not None)
            closing.cancel()
            closing.cancel()
            concurrent_close = asyncio.create_task(runner.aclose())
            await asyncio.wait_for(concurrent_close, 3)
            with self.assertRaises(asyncio.CancelledError):
                await closing

            terminal = runner.get_task_result(admission["result_id"])
            self.assertEqual(terminal["status"], "cancelled")
            self.assertTrue(self.process_is_running(child_pid))
            with self.assertRaises(ValueError):
                await runner.run_task("escaped")
        finally:
            if child_pid is None and child_pid_file.exists():
                child_pid = int(child_pid_file.read_text())
            if closing is not None and not closing.done():
                closing.cancel()
            if concurrent_close is not None:
                await asyncio.gather(concurrent_close, return_exceptions=True)
            if closing is not None:
                await asyncio.gather(closing, return_exceptions=True)
            if child_pid is not None:
                await self.terminate_fixture_process(child_pid)
            await runner.aclose()

    async def test_rejects_overlapping_task_before_spawn_side_effect(self):
        ready_file = self.root / "ready"
        release_file = self.root / "release"
        second_started = self.root / "second-started"
        long_code = (
            "import pathlib, time\n"
            f"ready = pathlib.Path({str(ready_file)!r})\n"
            f"release = pathlib.Path({str(release_file)!r})\n"
            "ready.touch()\n"
            "while not release.exists():\n"
            "    time.sleep(0.01)\n"
            "print('long complete')\n"
        )
        quick_code = f"import pathlib; pathlib.Path({str(second_started)!r}).touch(); print('ready')"
        runner = TaskRunner(
            [
                self.make_spec("long", long_code),
                self.make_spec("quick", quick_code),
            ],
            self.root,
        )
        admission = await runner.run_task("long")
        try:
            await self.wait_for_file(ready_file)
            with self.assertRaises(ValueError):
                await runner.run_task("quick")
            self.assertFalse(second_started.exists())
        finally:
            release_file.touch()
            try:
                terminal = await self.wait_for_result(runner, admission["result_id"])
                self.assertEqual(terminal["status"], "completed")
                follow_up = await self.run_to_completion(runner, "quick")
                self.assertEqual(follow_up["output"], "ready\n")
                self.assertTrue(second_started.exists())
            finally:
                await runner.aclose()

    async def test_child_does_not_inherit_parent_environment(self):
        variable = "DOTUNNEL_TASK_TEST_SECRET"
        runner = TaskRunner(
            [self.make_spec("environment", f"import os; print(os.getenv({variable!r}, 'missing'))")],
            self.root,
        )

        with patch.dict(os.environ, {variable: "parent-secret-value"}, clear=True):
            result = await self.run_to_completion(runner, "environment")

        self.assertEqual(result["output"], "missing\n")

    async def test_rejects_escaping_and_symlinked_working_directories(self):
        outside = Path(tempfile.mkdtemp(prefix=f"{self.root.name}-outside-", dir=self.root.parent))
        self.addCleanup(outside.rmdir)
        (self.root / "linked").symlink_to(outside, target_is_directory=True)
        unsafe_cwds = [Path("../" + outside.name), outside, Path("linked/child")]

        for cwd in unsafe_cwds:
            with self.subTest(cwd=str(cwd)):
                runner = TaskRunner([self.make_spec("unsafe", "print('ran')", cwd=cwd)], self.root)
                with self.assertRaises(ValueError) as raised:
                    await runner.run_task("unsafe")
                self.assertNotIn(str(outside), str(raised.exception))

    async def test_rejects_symlink_in_root_ancestor(self):
        linked_parent = self.root.parent / f"{self.root.name}-parent-link"
        linked_parent.symlink_to(self.root.parent, target_is_directory=True)
        self.addCleanup(linked_parent.unlink)
        linked_root = linked_parent / self.root.name
        runner = TaskRunner(
            [self.make_spec("symlinked-root", "print('ran')", cwd=linked_root)],
            linked_root,
        )

        with self.assertRaises(ValueError):
            await runner.run_task("symlinked-root")

    async def test_accepts_root_relative_and_absolute_working_directories(self):
        (self.root / "nested").mkdir()
        runner = TaskRunner(
            [
                self.make_spec("relative-cwd", "import os; print(os.getcwd())", cwd=Path("nested")),
                self.make_spec("absolute-cwd", "import os; print(os.getcwd())", cwd=self.root / "nested"),
            ],
            self.root,
        )

        relative_result = await self.run_to_completion(runner, "relative-cwd")
        absolute_result = await self.run_to_completion(runner, "absolute-cwd")

        expected = str(self.root / "nested") + "\n"
        self.assertEqual(relative_result["output"], expected)
        self.assertEqual(absolute_result["output"], expected)

    async def test_terminal_sequences_and_control_bytes_are_removed(self):
        runner = TaskRunner(
            [self.make_spec("terminal", "import sys; sys.stdout.buffer.write(b'\\x1b[31mred\\x1b[0m\\x00\\n')")],
            self.root,
        )

        result = await self.run_to_completion(runner, "terminal")

        self.assertEqual(result["output"], "red\n")

    async def test_osc_terminators_preserve_following_visible_output(self):
        cases = (
            ("title-st", b"\x1b]0;title\x1b\\hello\n", "hello\n"),
            ("title-bel", b"\x1b]0;title\x07hello\n", "hello\n"),
            (
                "hyperlink-st",
                b"before \x1b]8;;https://example.invalid/\x1b\\link\x1b]8;;\x1b\\ after\n",
                "before link after\n",
            ),
            ("unterminated-osc", b"before\x1b]0;private-title", "before"),
        )
        for name, payload, expected in cases:
            with self.subTest(name=name):
                runner = TaskRunner(
                    [self.make_spec(name, f"import os; os.write(1, {payload!r})")],
                    self.root,
                )
                result = await self.run_to_completion(runner, name)
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["output"], expected)
                self.assertFalse(result["truncated"])

    async def test_invalid_utf8_output_is_decoded_safely(self):
        runner = TaskRunner(
            [self.make_spec("invalid-utf8", "import sys; sys.stdout.buffer.write(b'\\xff')")],
            self.root,
        )

        result = await self.run_to_completion(runner, "invalid-utf8")

        self.assertEqual(result["output"], "\ufffd")
        self.assertFalse(result["truncated"])

    async def test_replacement_output_respects_final_utf8_byte_limit(self):
        runner = TaskRunner(
            [
                self.make_spec(
                    "invalid-utf8-cap",
                    f"import sys; sys.stdout.buffer.write(b'\\xff' * {MAX_OUTPUT})",
                )
            ],
            self.root,
        )

        result = await self.run_to_completion(runner, "invalid-utf8-cap")

        self.assertLessEqual(len(result["output"].encode("utf-8")), MAX_OUTPUT)
        self.assertTrue(result["truncated"])

    async def test_accepts_maximum_finite_timeout(self):
        runner = TaskRunner(
            [self.make_spec("limit", "pass", timeout_seconds=300.0)],
            self.root,
        )
        self.assertEqual(runner.list_tasks()["tasks"][0]["name"], "limit")

    async def test_rejects_nonfinite_or_out_of_range_timeouts(self):
        invalid_timeouts = [0, -1, 300.01, math.nan, math.inf, -math.inf, True, 10**1000]
        for timeout in invalid_timeouts:
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    TaskRunner([self.make_spec("invalid", "pass", timeout_seconds=timeout)], self.root)

    async def test_constructor_rejects_invalid_and_duplicate_task_definitions(self):
        invalid_definitions = [
            lambda: [self.make_spec("", "pass")],
            lambda: [TaskSpec("empty-description", "", (sys.executable, "-c", "pass"), self.root)],
            lambda: [TaskSpec("empty-arg", "desc", (sys.executable, ""), self.root)],
            lambda: [TaskSpec("relative-exe", "desc", ("python", "-c", "pass"), self.root)],
            lambda: [self.make_spec("same", "pass"), self.make_spec("same", "pass")],
            lambda: [self.make_spec("n" * 129, "pass")],
            lambda: [TaskSpec("long-description", "x" * 2049, (sys.executable, "-c", "pass"), self.root)],
            lambda: [TaskSpec("long-argument", "desc", (sys.executable, "x" * 4097), self.root)],
            lambda: [TaskSpec("long-cwd", "desc", (sys.executable, "-c", "pass"), Path("x" * 4097))],
        ]

        for make_specs in invalid_definitions:
            with self.subTest(definition=make_specs):
                with self.assertRaises(ValueError):
                    TaskRunner(make_specs(), self.root)

    async def test_result_cache_evicts_oldest_after_twenty_results(self):
        runner = TaskRunner([self.make_spec("repeat", "print('done')")], self.root)

        results = [await self.run_to_completion(runner, "repeat") for _ in range(21)]

        with self.assertRaises(ValueError):
            runner.get_task_result(results[0]["result_id"])
        self.assertEqual(runner.get_task_result(results[-1]["result_id"]), results[-1])

    async def test_running_id_counts_toward_cache_and_is_not_evicted(self):
        started = self.root / "cache-held-started"
        release = self.root / "cache-held-release"
        held_code = (
            "import pathlib, time\n"
            f"started = pathlib.Path({str(started)!r})\n"
            f"release = pathlib.Path({str(release)!r})\n"
            "started.touch()\n"
            "while not release.exists():\n"
            "    time.sleep(0.01)\n"
            "print('held done')\n"
        )
        runner = TaskRunner(
            [self.make_spec("repeat", "print('done')"), self.make_spec("held", held_code)],
            self.root,
        )
        completed = [await self.run_to_completion(runner, "repeat") for _ in range(20)]
        admission = await runner.run_task("held")
        try:
            await self.wait_for_file(started)
            self.assertLessEqual(len(runner._results), 20)
            with self.assertRaises(ValueError):
                runner.get_task_result(completed[0]["result_id"])
            self.assertEqual(runner.get_task_result(admission["result_id"])["status"], "running")
        finally:
            release.touch()
            try:
                await self.wait_for_result(runner, admission["result_id"])
            finally:
                await runner.aclose()

        terminal = runner.get_task_result(admission["result_id"])
        self.assertEqual(terminal["status"], "completed")
        self.assertEqual(terminal["output"], "held done\n")

    async def test_timeout_with_backpressured_pipe_reaps_and_releases_runner(self):
        class DelayedDrainRunner(TaskRunner):
            process = None

            async def _spawn(self, spec, cwd_fd):
                self.process = await super()._spawn(spec, cwd_fd)
                return self.process

            async def _collect_output(self, process, capture):
                # A real noisy child fills the pipe while its consumer is delayed.
                await asyncio.sleep(0.5)
                return await super()._collect_output(process, capture)

        runner = DelayedDrainRunner(
            [self.make_spec("noisy-timeout", "import os,time; os.write(1,b'x'*(1024*1024)); time.sleep(60)", timeout_seconds=0.15)],
            self.root,
        )
        try:
            result = await asyncio.wait_for(self.run_to_completion(runner, "noisy-timeout"), 2)
            self.assertEqual(result["status"], "timed_out")
            self.assertIsNotNone(runner.process.returncode)
            repeated = await asyncio.wait_for(self.run_to_completion(runner, "noisy-timeout"), 2)
            self.assertEqual(repeated["status"], "timed_out")
        finally:
            if runner.process is not None:
                try:
                    os.killpg(runner.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await asyncio.wait_for(runner.process.stdout.read(), 2)
                await runner.process.wait()

    async def test_repeated_startup_cancellation_cleans_real_child_before_release(self):
        original_spawn = asyncio.create_subprocess_exec
        ready = asyncio.Event()
        release = asyncio.Event()
        processes = []

        async def delayed_spawn(*args, **kwargs):
            process = await original_spawn(*args, **kwargs)
            processes.append(process)
            ready.set()
            await release.wait()
            return process

        runner = TaskRunner(
            [self.make_spec("long", "import time; time.sleep(60)"), self.make_spec("quick", "print('available')")],
            self.root,
        )
        active = None
        try:
            with patch("dotunnel.tasks.asyncio.create_subprocess_exec", delayed_spawn):
                active = asyncio.create_task(runner.run_task("long"))
                await asyncio.wait_for(ready.wait(), 2)
                active.cancel()
                active.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(active, 2)
                self.assertEqual(runner._results, {})
                self.assertFalse(self.process_is_running(processes[0].pid))
                follow_up = await asyncio.wait_for(self.run_to_completion(runner, "quick"), 2)
                self.assertEqual(follow_up["output"], "available\n")
        finally:
            release.set()
            if active is not None and not active.done():
                active.cancel()
                try:
                    await asyncio.wait_for(active, 2)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
            for process in processes:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await asyncio.wait_for(process.stdout.read(), 2)
                await process.wait()

    async def test_shutdown_waits_for_and_reaps_delayed_spawn_before_handoff(self):
        original_spawn = asyncio.create_subprocess_exec
        spawned = asyncio.Event()
        release = asyncio.Event()
        processes = []

        async def delayed_spawn(*args, **kwargs):
            process = await original_spawn(*args, **kwargs)
            processes.append(process)
            spawned.set()
            await release.wait()
            return process

        runner = TaskRunner(
            [self.make_spec("long", "import time; time.sleep(60)")],
            self.root,
        )
        admission = closing = None
        try:
            with patch("dotunnel.tasks.asyncio.create_subprocess_exec", delayed_spawn):
                admission = asyncio.create_task(runner.run_task("long"))
                await asyncio.wait_for(spawned.wait(), 2)
                closing = asyncio.create_task(runner.aclose())
                await self.wait_for_condition(lambda: admission.cancelling() > 0)
                self.assertFalse(admission.done())
                self.assertFalse(closing.done())
                release.set()
                await asyncio.wait_for(closing, 3)

            outcome = await asyncio.gather(admission, return_exceptions=True)
            self.assertIsInstance(outcome[0], asyncio.CancelledError)
            self.assertEqual(runner._results, {})
            self.assertFalse(self.process_is_running(processes[0].pid))
            with self.assertRaises(ValueError):
                await runner.run_task("long")
        finally:
            release.set()
            if admission is not None and not admission.done():
                admission.cancel()
            if closing is not None and not closing.done():
                closing.cancel()
            await asyncio.gather(
                *(task for task in (admission, closing) if task is not None),
                return_exceptions=True,
            )
            for process in processes:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.stdout is not None and not process.stdout.at_eof():
                    await asyncio.wait_for(process.stdout.read(), 2)
                await process.wait()
            await runner.aclose()


if __name__ == "__main__":
    unittest.main()
