import hashlib
import importlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch


_MODULE_NAME = "tools.release_verify.ci_supervisor"
_RUN_ID = "0123456789abcdef0123456789abcdef"
_OWNED_NAME = "dotunnel-verify-" + _RUN_ID
_CONTAINER_ID = "b" * 64


class ReleaseVerifyCIWatchdogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original = importlib.import_module(_MODULE_NAME)
        fixture = tempfile.TemporaryDirectory(prefix="dotunnel-watchdog-tests-", dir="/tmp")
        cls.addClassCleanup(fixture.cleanup)
        cls.fixture_root = Path(fixture.name)
        source = cls.fixture_root / "ci_supervisor.py"
        source.write_bytes(Path(original.__file__).read_bytes())
        source.chmod(0o600)
        name = "_dotunnel_watchdog_test_fixture"
        spec = importlib.util.spec_from_file_location(name, source)
        if spec is None or spec.loader is None:
            raise RuntimeError("watchdog fixture loader is unavailable")
        cls.api = importlib.util.module_from_spec(spec)
        sys.modules[name] = cls.api
        cls.addClassCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(cls.api)

    def _ledger(self, *, container_id=None):
        return {
            "schema": 1,
            "run_id": _RUN_ID,
            "name": _OWNED_NAME,
            "state": "create-starting",
            "container_id": container_id,
            "attempted": True,
            "cleanup_confirmed": False,
            "cleanup_reason": "create-pending",
            "docker_pid": 87654321,
            "docker_start_ticks": 1234,
            "status": "BLOCKED",
            "source_sha256": "e" * 64,
        }

    def _started_ledger(self):
        ledger = self._ledger(container_id=_CONTAINER_ID)
        ledger.update(state="started", cleanup_reason="started")
        return ledger


    def _owned_docker(self, directory, *, running=True):
        api = self.api
        directory = Path(directory)
        docker = directory / "synthetic-docker"
        state_path = directory / "docker-state.json"
        log_path = directory / "docker-operations.log"
        state_path.write_text(
            json.dumps({"exists": True, "running": running}), encoding="utf-8",
        )
        details = {
            "Id": _CONTAINER_ID,
            "Name": "/" + _OWNED_NAME,
            "Config": {"Labels": {
                "dotunnel.verify.run": _RUN_ID,
                "dotunnel.verify.kind": "release-pilot",
            }},
        }
        script = (
            f"#!{sys.executable}\n"
            "import json,sys\n"
            f"STATE_PATH={str(state_path)!r}\n"
            f"LOG_PATH={str(log_path)!r}\n"
            f"CONTAINER_ID={_CONTAINER_ID!r}\n"
            f"CONTAINER_NAME={_OWNED_NAME!r}\n"
            f"DETAILS=json.loads({json.dumps(json.dumps(details, separators=(',', ':')))})\n"
            "def load():\n"
            "    with open(STATE_PATH,encoding='utf-8') as stream: return json.load(stream)\n"
            "def save(value):\n"
            "    with open(STATE_PATH,'w',encoding='utf-8') as stream: json.dump(value,stream)\n"
            "def record(value):\n"
            "    with open(LOG_PATH,'a',encoding='utf-8') as stream: stream.write(value+'\\n')\n"
            "args=sys.argv[1:]\n"
            "if args[:2] != ['--host','unix:///var/run/docker.sock']: sys.exit(2)\n"
            "command=args[2:]\n"
            "state=load()\n"
            "if command[:2] == ['container','inspect']:\n"
            "    reference=command[2]\n"
            "    if not state['exists'] or reference not in (CONTAINER_ID,CONTAINER_NAME):\n"
            "        sys.stderr.write('Error: No such object: '+reference+'\\n'); sys.exit(1)\n"
            "    value=dict(DETAILS); value['State']={'Running':state['running']}\n"
            "    print(json.dumps([value],separators=(',',':')))\n"
            "elif command[:2] == ['container','stop']:\n"
            "    state['running']=False; save(state); record('stop')\n"
            "elif command[:2] == ['container','kill']:\n"
            "    state['running']=False; save(state); record('kill')\n"
            "elif command[:2] == ['container','rm']:\n"
            "    if state['running']: sys.exit(4)\n"
            "    state.update(exists=False,running=False); save(state); record('rm')\n"
            "else:\n"
            "    sys.stderr.write('unexpected synthetic Docker operation\\n'); sys.exit(3)\n"
        )
        docker.write_text(script, encoding="utf-8")
        docker.chmod(0o700)
        return docker, log_path

    def _run_watchdog(self, root, docker, ledger, *, fail_reconciliation=False,
                      client_kill=True, client_alive=False):
        api = self.api
        root = Path(root)
        root_info = os.lstat(root)
        control = {
            "docker_path": str(docker),
            "docker_root_path": str(Path("/tmp").resolve(strict=True)),
            "run_id": _RUN_ID,
            "name": _OWNED_NAME,
            "deadline_ns": time.monotonic_ns() - 1,
            "controller_pid": 98765432,
            "controller_start_ticks": 8765,
            "owner_uid": os.getuid(),
            "root_dev": root_info.st_dev,
            "root_ino": root_info.st_ino,
        }
        api._ledger_write(root, ledger)
        original_write = api._ledger_write

        def maybe_fail_reconciliation(write_root, value):
            if fail_reconciliation and value.get("state") == "create-reconciled":
                raise OSError("injected interrupted reconciliation write")
            original_write(write_root, value)

        def process_matches(pid, _ticks, _uid):
            return client_alive and pid == ledger["docker_pid"]

        with ExitStack() as stack:
            for name, value in (
                ("_control_read", control),
                ("_source_matches", True),
                ("_secure_executable", True),
                ("_current_process_matches", process_matches),
                ("_kill_verified_process", client_kill),
                ("_host_resources", {
                    "memory_available_bytes": 64 * 1024**3,
                    "disk_free_bytes": 64 * 1024**3,
                    "docker_root_disk_free_bytes": 64 * 1024**3,
                }),
                ("_ledger_write", maybe_fail_reconciliation if fail_reconciliation else original_write),
            ):
                if name in {"_current_process_matches", "_ledger_write"}:
                    stack.enter_context(patch.object(api, name, side_effect=value))
                else:
                    stack.enter_context(patch.object(api, name, return_value=value))
            stack.enter_context(redirect_stdout(io.StringIO()))
            exit_status = api._watchdog(root, "f" * 64)
        return exit_status

    def _new_root(self, name):
        root = self.fixture_root / name
        root.mkdir(mode=0o700)
        return root

    def test_orphaned_atomic_ledger_temp_does_not_block_owned_cid_recovery(self):
        root = self._new_root("orphan-recovery")
        docker, log_path = self._owned_docker(self.fixture_root)
        orphan = root / (".ledger.tmp.2468." + "a" * 32)
        orphan.write_bytes(b'{"partial":')
        orphan.chmod(0o600)

        exit_status = self._run_watchdog(root, docker, self._ledger())

        self.assertEqual(exit_status, 0)
        self.assertEqual(log_path.read_text(encoding="utf-8").splitlines(), ["stop", "rm"])
        self.assertFalse(root.exists(), "resolved owned state and safe orphan should be reclaimed")

    def test_unknown_atomic_temp_name_is_not_reclaimed(self):
        root = self._new_root("unknown-ledger-temp")
        unknown = root / ".ledger.tmp"
        unknown.write_bytes(b"unrecognized metadata")
        unknown.chmod(0o600)
        identity = os.lstat(root)

        removed = self.api._remove_private_root(root, identity.st_dev, identity.st_ino)

        self.assertFalse(removed)
        self.assertTrue(root.exists())
        self.assertTrue(unknown.exists(), "unknown metadata must not be deleted to force cleanup")

    def test_failed_intermediate_cid_ledger_write_does_not_skip_owned_teardown(self):
        root = self._new_root("intermediate-ledger-failure")
        docker, log_path = self._owned_docker(self.fixture_root)

        exit_status = self._run_watchdog(
            root, docker, self._ledger(), fail_reconciliation=True,
        )

        self.assertEqual(exit_status, 0)
        self.assertEqual(log_path.read_text(encoding="utf-8").splitlines(), ["stop", "rm"])
        self.assertFalse(root.exists(), "safe teardown must complete after a persistence hiccup")

    def _start_go_consumer(self, directory):
        marker = Path(directory) / "go-consumed"
        script = (
            "import pathlib,sys\n"
            "value=sys.stdin.readline()\n"
            f"if value == 'GO\\n': pathlib.Path({str(marker)!r}).write_bytes(value.encode())\n"
        )
        session = self.api._AttachedSession.start(
            [sys.executable, "-I", "-c", script], Path.home(),
        )
        return session, marker

    @staticmethod
    def _close_session(session):
        session.close()
        try:
            session.process.wait(timeout=2)
        except Exception:
            if session.process.poll() is None:
                session.process.kill()
                session.process.wait(timeout=2)

    def test_slow_final_proof_crossing_absolute_deadline_never_sends_go(self):
        root = self._new_root("go-deadline")
        self.api._ledger_write(root, self._started_ledger())
        session, marker = self._start_go_consumer(self.fixture_root)
        proof_calls = []

        def slow_final_proof():
            proof_calls.append(True)
            time.sleep(0.1)

        try:
            deadline_ns = time.monotonic_ns() + 20_000_000
            failure = self.api._admit_and_send_go(
                root, session, type("LiveWatchdog", (), {"poll": lambda self: None})(),
                deadline_ns, final_proof=slow_final_proof,
            )
            self.assertEqual(failure, "go-admission-deadline-exceeded")
            self.assertEqual(proof_calls, [True])
            self.assertFalse(marker.exists(), "GO must not be emitted after its absolute deadline")
        finally:
            self._close_session(session)

    def test_watchdog_client_kill_failure_still_tears_down_but_fences_go(self):
        root = self._new_root("client-kill-failure")
        docker, log_path = self._owned_docker(self.fixture_root)

        exit_status = self._run_watchdog(
            root, docker, self._ledger(container_id=_CONTAINER_ID),
            client_kill=False, client_alive=True,
        )

        self.assertEqual(exit_status, 74)
        self.assertEqual(log_path.read_text(encoding="utf-8").splitlines(), ["stop", "rm"])
        ledger = self.api._ledger_read(root)
        self.assertFalse(ledger["cleanup_confirmed"])
        self.assertEqual(ledger["state"], "watchdog-unresolved")
        self.assertIn("docker-client-quiescence-unconfirmed", ledger["cleanup_reason"])

        session, marker = self._start_go_consumer(self.fixture_root)
        try:
            failure = self.api._admit_and_send_go(
                root, session, type("LiveWatchdog", (), {"poll": lambda self: None})(),
                time.monotonic_ns() + 5_000_000_000,
            )
            self.assertEqual(failure, "watchdog-teardown-in-progress")
            self.assertFalse(marker.exists(), "watchdog teardown must permanently fence GO")
        finally:
            self._close_session(session)

    def test_live_docker_client_keeps_complete_ledger_unresolved(self):
        root = self._new_root("complete-client-alive")
        docker, _log_path = self._owned_docker(self.fixture_root)
        ledger = self._ledger(container_id=_CONTAINER_ID)
        ledger.update(
            state="complete", cleanup_confirmed=True,
            cleanup_reason="removed", status="PASS",
        )

        exit_status = self._run_watchdog(
            root, docker, ledger, client_kill=False, client_alive=True,
        )

        self.assertEqual(exit_status, 74)
        unresolved = self.api._ledger_read(root)
        self.assertFalse(unresolved["cleanup_confirmed"])
        self.assertEqual(unresolved["state"], "watchdog-unresolved")
        self.assertIn("removed;docker-client-quiescence-unconfirmed", unresolved["cleanup_reason"])

    def test_teardown_fence_serializes_with_inflight_go_admission(self):
        root = self._new_root("go-teardown-race")
        docker, log_path = self._owned_docker(self.fixture_root)
        session, marker = self._start_go_consumer(self.fixture_root)
        api = self.api
        fence_written = threading.Event()
        release_fence = threading.Event()
        watchdog_status = []
        watchdog_errors = []
        go_result = []

        original_marker_write = api._write_private_marker

        def hold_teardown_fence(write_root, name, contents):
            written = original_marker_write(write_root, name, contents)
            if name == "go.closed":
                fence_written.set()
                release_fence.wait(timeout=10)
            return written

        def run_watchdog():
            try:
                watchdog_status.append(self._run_watchdog(
                    root, docker, self._ledger(container_id=_CONTAINER_ID),
                    client_kill=False, client_alive=True,
                ))
            except Exception as exc:
                watchdog_errors.append(exc)

        def admit_go():
            try:
                go_result.append(api._admit_and_send_go(
                    root, session,
                    type("LiveWatchdog", (), {"poll": lambda self: None})(),
                    time.monotonic_ns() + 5_000_000_000,
                ))
            except Exception as exc:
                go_result.append(exc)

        watchdog_thread = threading.Thread(target=run_watchdog)
        go_thread = threading.Thread(target=admit_go)
        try:
            with patch.object(api, "_write_private_marker", side_effect=hold_teardown_fence):
                try:
                    watchdog_thread.start()
                    self.assertTrue(fence_written.wait(timeout=5))
                    go_thread.start()
                    time.sleep(0.05)
                    self.assertFalse(marker.exists())
                finally:
                    release_fence.set()
                    if go_thread.ident is not None:
                        go_thread.join(timeout=5)
                    watchdog_thread.join(timeout=10)
            self.assertFalse(go_thread.is_alive())
            self.assertFalse(watchdog_thread.is_alive())
            self.assertEqual(go_result, ["watchdog-teardown-in-progress"])
            self.assertEqual(watchdog_errors, [])
            self.assertEqual(watchdog_status, [74])
            self.assertFalse(marker.exists(), "teardown must fence GO before cleanup")
            self.assertEqual(log_path.read_text(encoding="utf-8").splitlines(), ["stop", "rm"])
        finally:
            release_fence.set()
            self._close_session(session)


    def test_control_reader_requires_canonical_docker_root_path(self):
        root = self._new_root("control-docker-root")
        root_info = os.lstat(root)
        control = {
            "schema": 1,
            "run_id": _RUN_ID,
            "name": _OWNED_NAME,
            "root": str(root),
            "root_dev": root_info.st_dev,
            "root_ino": root_info.st_ino,
            "owner_uid": os.getuid(),
            "source_path": str(Path(__file__).resolve()),
            "source_sha256": "e" * 64,
            "source_dev": 1,
            "source_ino": 2,
            "python_path": "/usr/bin/python3",
            "python_dev": 1,
            "python_ino": 2,
            "docker_path": "/usr/bin/docker",
            "docker_root_path": str(Path("/tmp").resolve(strict=True)),
            "controller_pid": 123,
            "controller_start_ticks": 456,
            "deadline_ns": 789,
        }
        control_path = root / "control.json"
        raw = self.api._canonical_bytes(control)
        self.api._write_exclusive(control_path, raw)
        self.assertEqual(
            self.api._control_read(root, hashlib.sha256(raw).hexdigest()), control,
        )

        for invalid_root in (None, "/tmp/../tmp"):
            with self.subTest(docker_root_path=invalid_root):
                invalid = dict(control)
                if invalid_root is None:
                    invalid.pop("docker_root_path")
                else:
                    invalid["docker_root_path"] = invalid_root
                invalid_raw = self.api._canonical_bytes(invalid)
                control_path.write_bytes(invalid_raw)
                self.assertIsNone(
                    self.api._control_read(root, hashlib.sha256(invalid_raw).hexdigest()),
                )


if __name__ == "__main__":
    unittest.main()
