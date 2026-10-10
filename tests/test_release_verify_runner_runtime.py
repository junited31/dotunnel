import hashlib
import json
import os
import socket
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tools.release_verify import runner_policy
from tools.release_verify import runner_prepare
from tools.release_verify import runner_runtime


class RunnerRuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.context = {
            "schema": 1,
            "repository": "junited31/dotunnel",
            "ref": "refs/heads/main",
            "event": "workflow_dispatch",
            "actor": "junited31",
            "triggering_actor": "junited31",
            "run": "92731",
            "attempt": "2",
        }

    def handoff(self, **changes):
        value = {
            "context": self.context,
            "dispatcher_pid": os.getpid(),
            "scenario": "normal",
            "outer_deadline_ns": str(time.monotonic_ns() + 590_000_000_000),
            "runtime": {
                "ACTIONS_RUNTIME_TOKEN": "synthetic-runtime-token",
                "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
                "ACTIONS_RUNTIME_URL": "https://pipelines.actions.githubusercontent.com/",
            },
        }
        value.update(changes)
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    def _manager_properties(self, names, role, private_network):
        unit = names.unit(role)
        slice_name = runner_runtime._slice_name(names, role)
        memory, cpu, tasks, runtime = runner_policy.BUDGETS[role]
        return {
            "Id": unit, "LoadState": "loaded", "ActiveState": "active",
            "SubState": "running", "Result": "success", "InvocationID": "a" * 32,
            "FragmentPath": runner_runtime._unit_file_name(unit), "DropInPaths": "",
            "ControlGroup": f"/{slice_name}/{unit}", "Slice": slice_name,
            "MainPID": "123", "ControlPID": "0", "User": "0", "Group": "0",
            "MemoryMax": str(memory), "MemorySwapMax": "0",
            "CPUQuotaPerSecUSec": f"{cpu * 10_000}us", "TasksMax": str(tasks),
            "RuntimeMaxUSec": f"{runtime * 1_000_000}us",
            "KillMode": "control-group", "TimeoutStopUSec": "2s",
            "Restart": "no", "OOMPolicy": "kill", "StandardOutput": "null",
            "StandardError": "null", "LogRateIntervalUSec": "1s",
            "LogRateLimitBurst": "1", "PrivateNetwork": private_network,
            "ExecMainStatus": "0", "ExecMainStartTimestampMonotonic": "1",
            "ExecMainExitTimestampMonotonic": "0",
            "ActiveEnterTimestampMonotonic": "1", "WorkingDirectory": "/",
            "Environment": "", "NoNewPrivileges": "yes",
        }

    def test_root_lifecycle_manager_requires_private_network_namespace(self):
        names = runner_policy.RunNames("81234", "1")
        for role in ("reaper", "recovery", "recovery-probe"):
            with self.subTest(role=role):
                properties = self._manager_properties(names, role, "yes")
                manager = runner_runtime._check_unit_budget(
                    properties, role, runner_runtime._slice_name(names, role), active=True,
                )
                self.assertEqual(manager["private_network"], "yes")
                properties["PrivateNetwork"] = "no"
                with self.assertRaises(ValueError):
                    runner_runtime._check_unit_budget(
                        properties, role, runner_runtime._slice_name(names, role), active=True,
                    )

        names = runner_policy.RunNames("81234", "1")
        idle = self._manager_properties(names, "recovery", "yes")
        idle.update({
            "ActiveState": "inactive", "SubState": "dead", "InvocationID": "",
            "MainPID": "0", "ControlPID": "0", "ControlGroup": "",
        })
        manager = runner_runtime._check_unit_budget(
            idle, "recovery", runner_runtime._slice_name(names, "recovery"), active=False,
        )
        self.assertEqual(manager["invocation_id"], "")
        self.assertEqual(manager["main_pid"], 0)
        self.assertEqual(manager["control_pid"], 0)
        self.assertEqual(manager["control_group"], "")


    def test_child_placement_uses_authenticated_service_cgroup_birth(self):
        names = runner_policy.RunNames("81234", "1")
        unit = names.unit("harmless")
        expected_cgroup = f"/{names.work_slice}/{unit}"
        process = runner_runtime.observe_process(os.getpid())
        service_cgroup = {
            "control_group": expected_cgroup, "present": True,
            "pids": [{"pid": process.pid, "birth": process.birth}],
        }
        ancestor_slice = {"pids": []}
        self.assertEqual(ancestor_slice["pids"], [])
        runner_runtime._require_process_in_unit_cgroup(
            process, expected_cgroup, service_cgroup, expected_cgroup,
        )
        wrong_birth = {**service_cgroup, "pids": [{"pid": process.pid, "birth": process.birth + 1}]}
        with self.assertRaises(ValueError):
            runner_runtime._require_process_in_unit_cgroup(
                process, expected_cgroup, wrong_birth, expected_cgroup,
            )
    def test_handoff_rejects_unknown_capabilities_and_non_owner_context(self):
        valid = json.loads(self.handoff())
        for value in (
            {**valid, "command": "/bin/sh"},
            {**valid, "context": {**self.context, "actor": "foreign"}},
            {**valid, "runtime": {**valid["runtime"], "GITHUB_TOKEN": "contents-token"}},
            {**valid, "scenario": "arbitrary"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    runner_runtime.parse_handoff(json.dumps(value).encode("utf-8"))

    def test_handoff_binds_actual_live_dispatcher_and_hides_runtime_token(self):
        handoff = runner_runtime.parse_handoff(self.handoff())
        self.assertEqual(handoff.context, self.context)
        self.assertEqual(handoff.dispatcher.pid, os.getpid())
        self.assertEqual(handoff.dispatcher.uid, os.getuid())
        self.assertGreater(handoff.dispatcher.birth, 0)
        self.assertTrue(handoff.dispatcher.exe_inode > 0)
        self.assertNotIn("synthetic-runtime-token", repr(handoff))
        self.assertNotIn("synthetic-runtime-token", str(handoff))

    def test_stale_birth_or_executable_identity_is_preserved_and_denied(self):
        observed = runner_runtime.observe_process(os.getpid())
        with self.assertRaises(ValueError):
            runner_runtime.require_same_process(replace(observed, birth=observed.birth + 1))
        with self.assertRaises(ValueError):
            runner_runtime.require_same_process(replace(observed, exe_inode=observed.exe_inode + 1))
        self.assertEqual(runner_runtime.observe_process(os.getpid()), observed)

    def test_dead_real_process_is_not_reconstructed_from_old_identity(self):
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.addCleanup(child.wait, timeout=3)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        identity = runner_runtime.observe_process(child.pid)
        self.assertEqual(identity.pid, child.pid)
        self.assertTrue(runner_runtime._process_identity_live(identity))
        child.terminate()
        self.assertEqual(child.wait(timeout=3), -15)
        self.assertFalse(runner_runtime._process_identity_live(identity))
        with self.assertRaises((ProcessLookupError, ValueError)):
            runner_runtime.require_same_process(identity)

    def test_recovery_retry_requires_old_actual_actor_birth_to_be_gone(self):
        names = runner_policy.RunNames("81234", "1")
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.addCleanup(child.wait, timeout=3)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        identity = runner_runtime.observe_process(child.pid)
        old_invocation = "a" * 32
        old_unit = {
            "unit": names.unit("recovery"),
            "invocation_id": old_invocation,
            "process": identity.to_record(),
            "cgroup": {"pids": [{"pid": identity.pid, "birth": identity.birth}]},
        }
        state = {"units": {"recovery": old_unit}}
        effect = {"unit": names.unit("recovery"), "invocation_id": old_invocation}

        with self.assertRaises(ValueError):
            runner_runtime._require_previous_recovery_actor_gone(
                state, effect, names.unit("recovery"), "b" * 32,
            )

        child.terminate()
        self.assertEqual(child.wait(timeout=3), -15)
        self.assertIsNone(runner_runtime._require_previous_recovery_actor_gone(
            state, effect, names.unit("recovery"), "b" * 32,
        ))


    def test_handoff_rejects_nonexistent_dispatcher_before_effects(self):
        payload = json.loads(self.handoff())
        payload["dispatcher_pid"] = 2_000_000_000
        with self.assertRaises(ValueError):
            runner_runtime.parse_handoff(json.dumps(payload).encode("utf-8"))

    def test_interrupted_journal_cleanup_closes_go_writer_without_fake_completion(self):
        context = {**self.context, "run": str(700_000_000 + os.getpid()), "attempt": "1"}
        handoff_value = json.loads(self.handoff())
        handoff_value["context"] = context
        handoff = runner_runtime.parse_handoff(
            json.dumps(handoff_value, separators=(",", ":")).encode("utf-8"),
        )
        names = runner_policy.validate_context(context)
        source = {
            "commit": "a" * 40, "closure_sha256": "b" * 64,
            "files": {"runner_runtime.py": "c" * 64},
            "upload_action_commit": "d" * 40, "source_path": names.source,
            "source_directory": {
                "device": 1, "inode": 2, "uid": 0, "gid": 0,
                "mode": 0o500, "nlink": 2,
            },
        }
        source_binding = {"commit": source["commit"], "closure_sha256": source["closure_sha256"]}

        # This test proves the real filesystem journal-fault and pre-GO EOF
        # fence only; fixture source identity and systemd/cgroup are NOT_VERIFIED.
        with patch.object(runner_prepare, "_ROOT_UID", os.geteuid()):
            with tempfile.TemporaryDirectory(prefix="dotunnel-runtime-journal-fault-") as directory:
                parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                store = pipe = child = None
                reader_fd = ready_reader = ready_writer = None
                try:
                    store = runner_prepare.AuthorityStore.create(parent_fd, context, source_binding)
                    state = runner_runtime._make_initial_state(names, handoff, source, store.nonce)
                    runner_runtime._validate_state(state, names)
                    store.save_runtime_state(state, initial=True)
                    original_journal = runner_prepare._read_at(
                        store.directory_fd, "journal.json",
                    )[0]
                    interrupted = json.loads(original_journal)
                    interrupted["phase"] = "RECOVERING"
                    interrupted["cleanup_owner"] = {
                        "pid": os.getpid(), "birth": runner_prepare._pid_birth(os.getpid()),
                    }
                    next_raw = runner_prepare._encode(interrupted)
                    next_fd = os.open(
                        "journal.next",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0o600, dir_fd=store.directory_fd,
                    )
                    try:
                        self.assertEqual(os.write(next_fd, next_raw), len(next_raw))
                        os.fsync(next_fd)
                    finally:
                        os.close(next_fd)

                    pipe = runner_prepare.AdmissionPipe(
                        deadline_ns=time.monotonic_ns() + 10_000_000_000,
                    )
                    reader_fd = pipe.take_reader()
                    ready_reader, ready_writer = os.pipe2(os.O_CLOEXEC)
                    child_code = (
                        "import os,sys;"
                        "reader=int(sys.argv[1]);ready=int(sys.argv[2]);"
                        "os.write(ready,(str(os.getuid())+'!').encode());os.close(ready);"
                        "data=os.read(reader,3);os.write(1,b'EOF' if not data else b'GO')"
                    )
                    credentials = {}
                    if os.geteuid() == 0:
                        credentials = {"user": 65534, "group": 65534, "extra_groups": ()}
                    try:
                        child = subprocess.Popen(
                            [sys.executable, "-I", "-S", "-c", child_code,
                             str(reader_fd), str(ready_writer)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, close_fds=True,
                            pass_fds=(reader_fd, ready_writer), **credentials,
                        )
                    except PermissionError:
                        if os.geteuid() == 0:
                            self.skipTest("cannot create the required non-root pipe consumer")
                        raise
                    os.close(ready_writer)
                    ready_writer = None
                    self.assertTrue(select.select([ready_reader], [], [], 3)[0])
                    ready = bytearray()
                    while b"!" not in ready and len(ready) < 16:
                        chunk = os.read(ready_reader, 16 - len(ready))
                        if not chunk:
                            break
                        ready.extend(chunk)
                    self.assertTrue(ready.endswith(b"!"))
                    child_uid = int(ready[:-1])
                    self.assertEqual(runner_runtime.observe_process(child.pid).uid, child_uid)
                    time.sleep(0.05)
                    self.assertIsNone(child.poll())
                    self.assertFalse(select.select([reader_fd], [], [], 0)[0])

                    # Manager/cgroup observations are intentionally NOT_VERIFIED
                    # by this filesystem-and-pipe fallback fixture.
                    with patch.object(
                        runner_runtime, "_work_slice_observation",
                        side_effect=RuntimeError("systemd/cgroup proof not in this test"),
                    ):
                        result = runner_runtime._cleanup_receipt(
                            names, store, "interrupted-journal", time.monotonic_ns() + 250_000_000,
                            pipe=pipe, reader_fd=reader_fd,
                        )
                    reader_fd = None  # production cleanup closed the held reader
                    self.assertEqual(result, 2)
                    stdout, _stderr = child.communicate(timeout=3)
                    self.assertEqual(child.returncode, 0)
                    self.assertEqual(stdout, b"EOF")
                    self.assertEqual(
                        runner_prepare._read_at(store.directory_fd, "journal.json")[0],
                        original_journal,
                    )
                    self.assertEqual(
                        runner_prepare._read_at(store.directory_fd, "journal.next")[0],
                        next_raw,
                    )
                    self.assertIsNone(store.terminal_receipt())
                    with self.assertRaises(FileNotFoundError):
                        os.stat("terminal.json", dir_fd=store.directory_fd, follow_symlinks=False)
                finally:
                    if child is not None and child.poll() is None:
                        child.kill()
                        child.wait(timeout=3)
                    if pipe is not None:
                        pipe.close()
                    if reader_fd is not None:
                        try:
                            os.close(reader_fd)
                        except OSError:
                            pass
                    for fd in (ready_reader, ready_writer):
                        if fd is not None:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
                    if store is not None:
                        store.close()
                    os.close(parent_fd)


class RunnerRuntimeControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dotunnel-runtime-control-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "status.sock"
        self.cancel_receipt_path = Path(self.temp.name) / "cancel.json"
        self.context = {
            "schema": 1,
            "repository": "junited31/dotunnel",
            "ref": "refs/heads/main",
            "event": "workflow_dispatch",
            "actor": "junited31",
            "triggering_actor": "junited31",
            "run": "81234",
            "attempt": "1",
        }
        self.child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.addCleanup(self._stop_child)
        self.child_identity = runner_runtime.observe_process(self.child.pid)
        self.identity = runner_runtime.observe_process(os.getpid())
        self.source = {"commit": "a" * 40, "closure_sha256": "b" * 64}
        self.state = runner_runtime.RuntimeControlState(
            context=self.context,
            boot_id=runner_runtime.boot_id(),
            nonce="4f" * 16,
            source=self.source,
            dispatcher=self.identity,
            scenario="workflow-cancel",
            live_probe=self._live_probe,
            status_probe=self._status_probe,
            cancel_handler=self._persist_cancel,
        )
        self.server = runner_runtime.ControlServer(self.path, self.state)
        self.server.start()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.close)
    def _stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
            self.child.wait(timeout=3)

    def _live_probe(self):
        current = runner_runtime.require_same_process(self.child_identity)
        return True, {"pid": current.pid, "birth": current.birth}

    def _status_probe(self):
        try:
            current = runner_runtime.require_same_process(self.child_identity)
            running = current.pid == self.child.pid
        except (ProcessLookupError, ValueError):
            running = False
        return {
            "running": running, "readiness_publication": "PENDING",
            "terminal_publication": "PENDING", "publisher_exit": None,
        }

    def _persist_cancel(self, record):
        fd = os.open(
            self.cancel_receipt_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as output:
            output.write(json.dumps(record, separators=(",", ":")).encode("ascii"))
            output.flush()
            os.fsync(output.fileno())

    def test_cancel_refuses_without_a_current_process_identity(self):
        stale = replace(self.child_identity, birth=self.child_identity.birth + 1)
        self.state.live_probe = lambda: (
            runner_runtime.require_same_process(stale), None,
        )
        response = self.request({
            "op": "CANCEL", "notice_ns": str(time.monotonic_ns()),
        })
        self.assertEqual(response, {"error": "control peer refused"})
        self.assertIsNone(self.state.cancel_notice)

    def test_failed_bind_does_not_unlink_an_existing_socket(self):
        collision_path = Path(self.temp.name) / "existing.sock"
        existing = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        existing.bind(str(collision_path))
        existing.listen(1)
        self.addCleanup(existing.close)
        server = runner_runtime.ControlServer(collision_path, self.state)
        with self.assertRaises(OSError):
            server.start()
        self.assertTrue(collision_path.exists())
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(str(collision_path))
        client.close()

    def request(self, request, *, path=None):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(str(path or self.path))
        with client:
            client.sendall(json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n")
            raw = bytearray()
            while b"\n" not in raw:
                chunk = client.recv(4096)
                if not chunk:
                    break
                raw.extend(chunk)
                self.assertLessEqual(len(raw), 64 * 1024)
        return json.loads(bytes(raw).split(b"\n", 1)[0])

    def test_authenticated_status_and_cancel_are_live_and_idempotent(self):
        status = self.request({"op": "STATUS"})
        self.assertEqual(status["state"], "WAITING")
        self.assertEqual(status["nonce"], "4f" * 16)
        self.assertEqual(status["source"], self.source)
        self.assertEqual(set(status), runner_runtime._CONTROL_STATUS_FIELDS)
        self.assertNotIn("runtime", status)

        notice = time.monotonic_ns()
        request = {"op": "CANCEL", "notice_ns": str(notice)}
        first = self.request(request)
        self.assertEqual(first["state"], "CANCEL_REQUESTED")
        self.assertEqual(first["cancel_notice_ns"], str(notice))
        self.assertGreaterEqual(int(first["cancel_received_ns"]), notice)
        recorded = self.state.cancel_notice
        self.assertEqual(json.loads(self.cancel_receipt_path.read_text(encoding="ascii")), recorded)
        second = self.request({**request, "notice_ns": str(notice + 1)})
        self.assertEqual(second["state"], "CANCEL_REQUESTED")
        self.assertEqual(second["cancel_notice_ns"], str(notice))
        self.assertEqual(second["cancel_received_ns"], first["cancel_received_ns"])
        self.assertEqual(self.state.cancel_notice, recorded)

    def test_foreign_live_peer_cannot_read_or_cancel_dispatcher_state(self):
        script = (
            "import json,socket,sys;"
            "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
            "s.settimeout(2);s.connect(sys.argv[1]);"
            "s.sendall(b'{\\\"op\\\":\\\"STATUS\\\"}\\n');"
            "print(s.recv(4096).decode('ascii'));s.close()"
        )
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-c", script, str(self.path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=True,
        )
        response = json.loads(child.stdout)
        self.assertEqual(response, {"error": "control peer refused"})
        self.assertIsNone(self.state.cancel_notice)

    def test_extra_routing_fields_are_denied_without_changing_state(self):
        response = self.request({"op": "STATUS", "run": "81235", "attempt": "1"})
        self.assertEqual(response, {"error": "control peer refused"})
        self.assertIsNone(self.state.cancel_notice)

    def test_cancel_after_cleanup_is_denied(self):
        self.state.phase = "CLEANUP"
        with self.assertRaises(ValueError):
            self.state.request_cancel(time.monotonic_ns() - 1)
        self.assertIsNone(self.state.cancel_notice)

    def test_terminal_projection_binds_generation_and_cancel_order(self):
        names = runner_policy.RunNames(self.context["run"], self.context["attempt"])
        boot = runner_runtime.boot_id()
        terminal_ns = time.monotonic_ns()
        notice_ns = terminal_ns - 100
        snapshot = {
            "run": names.run, "attempt": names.attempt, "boot_id": boot,
            "source": self.source, "terminal_ns": terminal_ns,
        }
        state = {
            "prepared_terminal": snapshot,
            "terminal_sha256": hashlib.sha256(runner_runtime._canonical(snapshot)).hexdigest(),
            "boot_id": boot, "source": self.source, "nonce": "4f" * 16,
            "readiness_sha256": "c" * 64,
            "cancel_notice": {
                "notice_ns": str(notice_ns), "received_ns": notice_ns + 1,
                "live_at_notice": True, "child": {"pid": self.child.pid},
            },
            "publication": {
                "readiness": {"state": "LOCAL_PUBLISHED"},
                "terminal": {"state": "FAILED", "exit_code": 17},
            },
        }
        status = runner_runtime._terminal_status_projection(names, state, snapshot)
        self.assertEqual(set(status), runner_runtime._CONTROL_STATUS_FIELDS)
        self.assertEqual(status["state"], "TERMINAL")
        self.assertTrue(status["terminal"])
        self.assertEqual(status["cancel_notice_ns"], str(notice_ns))
        self.assertEqual(status["cancel_received_ns"], str(notice_ns + 1))
        self.assertGreater(int(status["cancel_received_ns"]), int(status["cancel_notice_ns"]))
        self.assertEqual(status["source"], self.source)
        self.assertEqual(status["publisher_exit"], 17)

        state["cancel_notice"]["received_ns"] = notice_ns - 1
        with self.assertRaises(ValueError):
            runner_runtime._terminal_status_projection(names, state, snapshot)

    def test_terminal_status_rename_is_real_and_noreplace(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-terminal-rename-") as directory:
            directory_fd = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            try:
                temporary = Path(directory) / "terminal-status.next"
                final = Path(directory) / "terminal-status.json"
                temporary.write_bytes(b"first")
                runner_runtime._rename_terminal_noreplace(directory_fd)
                self.assertEqual(final.read_bytes(), b"first")
                self.assertFalse(temporary.exists())

                temporary.write_bytes(b"second")
                with self.assertRaises(FileExistsError):
                    runner_runtime._rename_terminal_noreplace(directory_fd)
                self.assertEqual(final.read_bytes(), b"first")
                self.assertEqual(temporary.read_bytes(), b"second")
            finally:
                os.close(directory_fd)


if __name__ == "__main__":
    unittest.main()
