import importlib
import json
import os
import tempfile
import fcntl
import signal
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


class RunnerAuthorityTests(unittest.TestCase):
    base: Path
    base_fd: int
    context: dict[str, object]
    names: Any
    source: dict[str, str]

    @classmethod
    def setUpClass(cls):
        cls.prepare = importlib.import_module("tools.release_verify.runner_prepare")
        cls.policy = importlib.import_module("tools.release_verify.runner_policy")

    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="dotunnel-runner-authority-", dir="/tmp")
        self.addCleanup(fixture.cleanup)
        self.base = Path(fixture.name)
        self.base.chmod(0o700)
        self.base_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.base_fd)
        # Synthetic owner fixture only: no root effects or kernel acceptance.
        owner = patch.object(self.prepare, "_ROOT_UID", os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        self.context = {
            "schema": 1, "repository": "junited31/dotunnel",
            "ref": "refs/heads/main", "event": "workflow_dispatch",
            "actor": "junited31", "triggering_actor": "junited31",
            "run": "123", "attempt": "1",
        }
        self.names = self.policy.validate_context(self.context)
        self.source = {"commit": "a" * 40, "closure_sha256": "b" * 64}

    def create(self):
        store = self.prepare.AuthorityStore.create(self.base_fd, self.context, self.source)
        self.addCleanup(store.close)
        return store

    def test_foreign_context_creates_no_authority_directory(self):
        context = {**self.context, "triggering_actor": "foreign"}
        with self.assertRaises(ValueError):
            self.prepare.AuthorityStore.create(self.base_fd, context, self.source)
        self.assertEqual(list(self.base.iterdir()), [])

    def test_collision_preserves_existing_owned_record(self):
        existing = self.base / self.names.prefix
        existing.mkdir(mode=0o700)
        marker = existing / "foreign-record"
        marker.write_bytes(b"preserve this generation")
        with self.assertRaises((OSError, ValueError)):
            self.prepare.AuthorityStore.create(self.base_fd, self.context, self.source)
        self.assertEqual(marker.read_bytes(), b"preserve this generation")

    def test_replaced_root_cannot_admit_effect_or_touch_replacement(self):
        store = self.create()
        path = self.base / self.names.prefix
        retired = self.base / "retired"
        path.rename(retired)
        path.mkdir(mode=0o700)
        marker = path / "foreign-record"
        marker.write_bytes(b"new generation")
        with self.assertRaises(ValueError):
            store.intent("harmless", {"unit": self.names.unit("harmless")})
        self.assertEqual(marker.read_bytes(), b"new generation")

    def test_changed_authority_is_preserved_and_denies_effect(self):
        store = self.create()
        authority = self.base / self.names.prefix / "authority.json"
        value = json.loads(authority.read_bytes())
        value["context"]["actor"] = "foreign"
        changed = json.dumps(value).encode("utf-8")
        authority.write_bytes(changed)
        with self.assertRaises(ValueError):
            store.intent("harmless", {"unit": self.names.unit("harmless")})
        self.assertEqual(authority.read_bytes(), changed)

    def test_uncommitted_intent_survives_reopen_without_replay(self):
        store = self.create()
        desired = {"unit": self.names.unit("harmless")}
        identifier = store.intent("harmless", desired)
        store.close()
        reopened = self.prepare.AuthorityStore.open(self.base_fd, self.context, self.source)
        self.addCleanup(reopened.close)
        pending = reopened.uncommitted_effects()
        self.assertEqual(tuple(row["id"] for row in pending), (identifier,))
        with self.assertRaises(ValueError):
            reopened.intent("harmless", desired)
        self.assertEqual(tuple(row["id"] for row in reopened.uncommitted_effects()), (identifier,))

    def test_interrupted_journal_preserves_uncertainty_and_never_replays_effect(self):
        store = self.create()
        identifier = store.intent("harmless", {"unit": self.names.unit("harmless")})
        root = self.base / self.names.prefix
        original = (root / "journal.json").read_bytes()
        interrupted = b'{"nonce":"' + store.nonce.encode("ascii")
        with (root / "journal.next").open("xb") as output:
            output.write(interrupted)
        (root / "journal.next").chmod(0o600)
        store.close()
        reopened = self.prepare.AuthorityStore.open(self.base_fd, self.context, self.source)
        self.addCleanup(reopened.close)
        self.assertEqual(tuple(row["id"] for row in reopened.uncommitted_effects()), (identifier,))
        with self.assertRaises((OSError, ValueError)):
            reopened.begin_cleanup()
        with self.assertRaises((OSError, ValueError)):
            reopened.intent("harmless", {"unit": self.names.unit("harmless")})
        self.assertIsNone(reopened.terminal_receipt())
        self.assertEqual((root / "journal.json").read_bytes(), original)
        self.assertEqual((root / "journal.next").read_bytes(), interrupted)

    def test_changed_commit_identity_keeps_pending_effect(self):
        store = self.create()
        unit = self.names.unit("harmless")
        identifier = store.intent("harmless", {"unit": unit})
        with self.assertRaises(ValueError):
            store.commit(identifier, {"unit": unit + "-foreign", "invocation_id": "c" * 32})
        self.assertEqual(tuple(row["id"] for row in store.uncommitted_effects()), (identifier,))

    def test_terminal_generation_makes_recovery_single_flight_noop(self):
        store = self.create()
        self.assertTrue(store.begin_cleanup())
        self.assertFalse(store.begin_cleanup())
        receipt = {
            "scenario_result": "PASS", "cleanup_state": "COMPLETE",
            "original_cause": None, "work_populated": False,
            "container_record_state": "NOT_CREATED",
        }
        store.finish_cleanup(receipt)
        store.close()
        reopened = self.prepare.AuthorityStore.open(self.base_fd, self.context, self.source)
        self.addCleanup(reopened.close)
        self.assertFalse(reopened.begin_cleanup())
        self.assertEqual(reopened.terminal_receipt(), receipt)

    def test_cleanup_owner_can_admit_only_frozen_terminal_publication(self):
        store = self.create()
        terminal = {"unit": self.names.unit("publisher-terminal")}
        with self.assertRaises(ValueError):
            store.intent("publisher-terminal", terminal)
        self.assertTrue(store.begin_cleanup())
        with self.assertRaises(ValueError):
            store.intent("publisher-terminal", terminal)
        store.write_snapshot("terminal", {"schema": 1, "cleanup_state": "COMPLETE"})
        with self.assertRaises(ValueError):
            store.intent("harmless", {"unit": self.names.unit("harmless")})
        identifier = store.intent("publisher-terminal", terminal)
        with self.assertRaises(ValueError):
            store.intent("publisher-terminal", terminal)
        store.commit(identifier, {**terminal, "invocation_id": "c" * 32})
        store.finish_cleanup({
            "scenario_result": "PASS", "cleanup_state": "COMPLETE",
            "original_cause": None, "work_populated": False,
            "container_record_state": "NOT_CREATED",
        })
        with self.assertRaises(ValueError):
            store.intent("publisher-readiness", {"unit": self.names.unit("publisher-readiness")})

    def test_pending_effect_cannot_be_projected_as_complete_cleanup(self):
        store = self.create()
        store.intent("harmless", {"unit": self.names.unit("harmless")})
        store.begin_cleanup()
        with self.assertRaises(ValueError):
            store.finish_cleanup({
                "scenario_result": "PASS", "cleanup_state": "COMPLETE",
                "original_cause": None, "work_populated": False,
                "container_record_state": "NOT_CREATED",
            })
        self.assertIsNone(store.terminal_receipt())

    def test_absence_requires_explicit_fresh_zero_pid_observation(self):
        store = self.create()
        unit = self.names.unit("harmless")
        identifier = store.intent("harmless", {"unit": unit})
        store.begin_cleanup()
        observation = {
            "unit": unit, "load_state": "not-found", "active_state": "inactive",
            "main_pid": 0, "control_pid": 0,
        }
        for mutation in (
            {"unit": unit + "-foreign"}, {"main_pid": 1},
            {"main_pid": False}, {"load_state": "loaded"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                store.commit_absence(identifier, {**observation, **mutation})
        self.assertEqual(len(store.uncommitted_effects()), 1)
        store.commit_absence(identifier, observation)
        self.assertEqual(store.uncommitted_effects(), ())
        store.finish_cleanup({
            "scenario_result": "FAIL", "cleanup_state": "COMPLETE",
            "original_cause": "interrupted-effect", "work_populated": False,
            "container_record_state": "NOT_CREATED",
        })
        self.assertEqual(store.terminal_receipt()["original_cause"], "interrupted-effect")

    def test_replaced_credential_record_is_neither_read_nor_removed(self):
        store = self.create()
        runtime = {
            "ACTIONS_RUNTIME_TOKEN": "synthetic-never-publish",
            "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com",
            "ACTIONS_RUNTIME_URL": "https://pipelines.actions.githubusercontent.com",
        }
        store.write_credentials(runtime)
        path = self.base / self.names.prefix / "runtime.json"
        path.rename(path.with_name("retired-credentials"))
        path.write_bytes(json.dumps(runtime).encode())
        path.chmod(0o600)
        replaced = path.read_bytes()
        with self.assertRaises(ValueError):
            store.read_credentials()
        with self.assertRaises(ValueError):
            store.remove_credentials()
        self.assertEqual(path.read_bytes(), replaced)

    def test_credentials_survive_reopen_then_owned_removal(self):
        store = self.create()
        runtime = {
            "ACTIONS_RUNTIME_TOKEN": "synthetic-never-publish",
            "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com",
            "ACTIONS_RUNTIME_URL": "https://pipelines.actions.githubusercontent.com",
        }
        store.write_credentials(runtime)
        store.close()
        reopened = self.prepare.AuthorityStore.open(self.base_fd, self.context, self.source)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.read_credentials(), runtime)
        reopened.remove_credentials()
        self.assertFalse((self.base / self.names.prefix / "runtime.json").exists())

    def test_terminal_snapshot_cannot_be_rewritten_or_follow_symlink(self):
        store = self.create()
        snapshot = {"schema": 1, "cleanup_state": "UNKNOWN", "scenario_result": "FAIL"}
        store.write_snapshot("terminal", snapshot)
        with self.assertRaises((OSError, ValueError)):
            store.write_snapshot("terminal", {"schema": 1, "cleanup_state": "COMPLETE"})
        self.assertEqual(store.read_snapshot("terminal"), snapshot)
        path = self.base / self.names.prefix / "terminal.json"
        path.rename(path.with_name("retired-terminal"))
        target = self.base / "foreign-terminal"
        target.write_bytes(b"preserve foreign snapshot")
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            store.read_snapshot("terminal")
        self.assertEqual(target.read_bytes(), b"preserve foreign snapshot")

    def test_concurrent_cancel_and_publication_preserve_both_durable_transitions(self):
        store = self.create()
        store.save_runtime_state({"cancel": False, "publication": "PENDING"}, initial=True)
        reopened = self.prepare.AuthorityStore.open(self.base_fd, self.context, self.source)
        self.addCleanup(reopened.close)
        holding = threading.Event()
        release = threading.Event()
        attempted = threading.Event()
        entered = threading.Event()

        def cancel(state):
            holding.set()
            if not release.wait(1):
                raise AssertionError("bounded cancellation transition stalled")
            return {**state, "cancel": True}

        def publish():
            attempted.set()
            def transition(state):
                entered.set()
                return {**state, "publication": "COMPLETE"}
            return reopened.update_runtime_state(transition)

        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(store.update_runtime_state, cancel)
            try:
                self.assertTrue(holding.wait(1))
                second = workers.submit(publish)
                self.assertTrue(attempted.wait(1))
                self.assertFalse(entered.wait(0.05))
            finally:
                release.set()
            first.result(timeout=1)
            second.result(timeout=1)
        self.assertEqual(
            reopened.read_runtime_state(),
            {"cancel": True, "publication": "COMPLETE"},
        )


    def test_loaded_never_started_recovery_can_close_without_claiming_an_invocation(self):
        store = self.create()
        unit = self.names.unit("recovery")
        effect = store.intent("recovery", {"unit": unit})
        definition = self.base / unit
        definition.write_bytes(b"synthetic sealed recovery definition")
        metadata = definition.stat()
        idle = {
            "load_state": "loaded", "active_state": "inactive", "sub_state": "dead",
            "main_pid": 0, "control_pid": 0,
            "fragment_path": "/run/systemd/system/" + unit,
            "definition_sha256": hashlib.sha256(definition.read_bytes()).hexdigest(),
            "device": metadata.st_dev, "inode": metadata.st_ino, "nonce": store.nonce,
            "control_group": "", "cgroup_absent": True,
        }
        self.assertTrue(store.begin_cleanup("normal-exit"))
        for altered in (
            {**idle, "main_pid": os.getpid()}, {**idle, "control_pid": True},
            {**idle, "nonce": ("0" if store.nonce[0] != "0" else "1") + store.nonce[1:]},
            {**idle, "cgroup_absent": False},
            {**idle, "control_group": "/foreign.slice"},
            {**idle, "fragment_path": "/tmp/" + unit},
        ):
            with self.subTest(altered=altered):
                with self.assertRaises(ValueError):
                    store.commit(effect, {"unit": unit, "invocation_id": None, "never_started": altered})
        store.commit(effect, {"unit": unit, "invocation_id": None, "never_started": idle})
        receipt = {
            "scenario_result": "NOT_VERIFIED", "cleanup_state": "COMPLETE",
            "original_cause": "normal-exit", "work_populated": False,
            "container_record_state": "NOT_CREATED",
        }
        store.finish_cleanup(receipt)
        with self.assertRaises(ValueError):
            store.commit(effect, {"unit": unit, "invocation_id": "a" * 32})
        with self.assertRaises(ValueError):
            store.intent("recovery-probe", {"unit": self.names.unit("recovery-probe")})


class RunnerAdmissionPipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepare = importlib.import_module("tools.release_verify.runner_prepare")

    def _pipe_and_reader(self):
        pipe = self.prepare.AdmissionPipe(deadline_ns=time.monotonic_ns() + 5_000_000_000)
        self.addCleanup(pipe.close)
        reader = pipe.take_reader()
        self.addCleanup(os.close, reader)
        self.assertEqual(fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
        with self.assertRaises(OSError):
            os.write(reader, b"forged GO")
        code = (
            "import os,signal; signal.alarm(3); "
            "data=os.read(0,3); os.write(1,data if data else b'EOF')"
        )
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", code], stdin=reader,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True,
        )
        def cleanup():
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)
            child.stdout.close()
            child.stderr.close()
        self.addCleanup(cleanup)
        return pipe, child, self.prepare._pid_birth(child.pid)

    def test_root_retained_writer_sends_exact_go_only_to_birth_bound_read_client(self):
        pipe, child, birth = self._pipe_and_reader()
        pipe.admit_go(child.pid, birth)
        stdout, stderr = child.communicate(timeout=2)
        self.assertEqual((child.returncode, stdout, stderr), (0, b"GO\n", b""))
        with self.assertRaises(ValueError):
            pipe.admit_go(child.pid, birth)

    def test_closed_admission_produces_eof_without_go(self):
        pipe, child, birth = self._pipe_and_reader()
        pipe.close()
        with self.assertRaises(ValueError):
            pipe.admit_go(child.pid, birth)
        stdout, stderr = child.communicate(timeout=2)
        self.assertEqual((child.returncode, stdout, stderr), (0, b"EOF", b""))

    def test_wrong_birth_denies_go_and_can_only_be_closed(self):
        pipe, child, birth = self._pipe_and_reader()
        with self.assertRaises(ValueError):
            pipe.admit_go(child.pid, birth + 1)
        pipe.close()
        stdout, stderr = child.communicate(timeout=2)
        self.assertEqual((child.returncode, stdout, stderr), (0, b"EOF", b""))


if __name__ == "__main__":
    unittest.main()
