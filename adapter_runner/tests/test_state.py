import copy
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from dotunnel_adapter.protocol import RunnerError, binding, fingerprint
from dotunnel_adapter.state import Store
PROFILE = "sha256:" + "a" * 64


class StoreTests(unittest.TestCase):
    def make_state_dir(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        private = root / "private"
        private.mkdir(mode=0o700)
        private.chmod(0o700)
        state_dir = private / "state"
        state_dir.mkdir(mode=0o700)
        state_dir.chmod(0o700)
        return state_dir

    def make_store(self):
        state_dir = self.make_state_dir()
        owner = Store.initialize(state_dir)
        store = Store(state_dir)
        self.addCleanup(store.close)
        return state_dir, owner, store

    def make_request(self, owner, *, request_id="request-1", operation_id="operation-1"):
        request = {
            "protocol": "dotunnel.adapter/1",
            "request_id": request_id,
            "action": "submit",
            "owner": copy.deepcopy(owner),
            "project": {"id": "project", "generation": "project-generation-1"},
            "backend": {"id": "backend", "generation": "backend-generation-1"},
            "target": {"kind": "agent", "id": "agent-1", "incarnation": "incarnation-1"},
            "instruction": "review this change",
            "operation": {"id": operation_id},
        }
        request["operation"]["fingerprint"] = fingerprint(request)
        return request

    def authorized(self, store, request, *, expires_in=120):
        grant_id = store.issue_grant(request, time.time() + expires_in, profile_fingerprint=PROFILE)
        dispatched = copy.deepcopy(request)
        dispatched["authorization"] = {"grant_id": grant_id, "action": dispatched["action"]}
        return grant_id, dispatched

    def report(self, request, job_id="job-1", attempt_id="attempt-1"):
        return {
            "protocol": "dotunnel.adapter/1",
            "request_id": request["request_id"],
            "outcome": "ok",
            "binding": binding(request),
            "profile_fingerprint": PROFILE,
            "job": {
                "job_id": job_id,
                "attempt_id": attempt_id,
                **binding(request),
            },
        }

    def assert_code(self, code, callback, *args, **kwargs):
        with self.assertRaises(RunnerError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_initialization_is_exclusive_private_and_does_not_recreate_lost_state(self):
        state_dir = self.make_state_dir()
        self.assert_code("state_unavailable", Store, state_dir)
        db = state_dir / "state.sqlite3"
        self.assertFalse(db.exists())

        owner = Store.initialize(state_dir)
        self.assertEqual(owner["epoch"], 1)
        self.assertEqual(str(uuid.UUID(owner["instance_id"])), owner["instance_id"])
        info = db.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(info.st_uid, os.getuid())

        store = Store(state_dir)
        self.addCleanup(store.close)
        self.assertEqual(store.owner, owner)
        original = db.read_bytes()
        self.assert_code("state_unavailable", Store.initialize, state_dir)
        self.assertEqual(db.read_bytes(), original)

        store.close()
        db.unlink()
        self.assert_code("state_unavailable", Store, state_dir)
        replacement = Store.initialize(state_dir)
        self.assertNotEqual(replacement["instance_id"], owner["instance_id"])
        self.assertEqual(replacement["epoch"], 1)

    def test_sqlite_uses_full_sync_and_finite_busy_timeout(self):
        state_dir, owner, store = self.make_store()
        self.assertEqual(store._connection.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(store._connection.execute("PRAGMA busy_timeout").fetchone()[0], 1000)
        request = self.make_request(owner)
        lock = sqlite3.connect(state_dir / "state.sqlite3", timeout=0, isolation_level=None)
        self.addCleanup(lock.close)
        lock.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        try:
            self.assert_code("state_unavailable", store.issue_grant, request, time.time() + 120, profile_fingerprint=PROFILE)
        finally:
            lock.execute("ROLLBACK")
        waited = time.monotonic() - started
        self.assertGreaterEqual(waited, 0.75)
        self.assertLess(waited, 2.5)

    def test_initialization_refuses_nonprivate_directory_and_constructor_refuses_unsafe_database(self):
        state_dir = self.make_state_dir()
        state_dir.chmod(0o755)
        self.assert_code("state_unavailable", Store.initialize, state_dir)
        state_dir.chmod(0o700)

        Store.initialize(state_dir)
        db = state_dir / "state.sqlite3"
        os.link(db, state_dir.parent / "database-hardlink")
        self.assert_code("state_unavailable", Store, state_dir)
        (state_dir.parent / "database-hardlink").unlink()

        db.chmod(0o640)
        self.assert_code("state_unavailable", Store, state_dir)

    def test_grant_consumption_prepares_owned_job_before_effect_and_replay_is_unknown(self):
        _state_dir, owner, store = self.make_store()
        request = self.make_request(owner)
        grant_id, dispatched = self.authorized(store, request)

        self.assertIsNone(store.begin_operation(dispatched, "job-1", "attempt-1", time.time(), profile_fingerprint=PROFILE))
        job = store.get_job("job-1", "attempt-1")
        self.assertEqual(job["request"], dispatched)
        self.assertEqual(job["binding"], binding(dispatched))
        self.assertEqual(job["job_id"], "job-1")
        self.assertEqual(job["attempt_id"], "attempt-1")
        self.assertIsNone(job["report"])
        self.assertEqual(job["status"], "prepared")

        replay = copy.deepcopy(dispatched)
        replay["request_id"] = "request-replay"
        self.assertEqual(store.lookup_operation(replay)["code"], "outcome_unknown")
        historical = store.begin_operation(replay, "job-replay", "attempt-replay", time.time(), profile_fingerprint=PROFILE)
        self.assertEqual(historical["outcome"], "unknown")
        self.assertEqual(historical["code"], "outcome_unknown")
        self.assertEqual(historical["request_id"], "request-replay")
        self.assertEqual(historical["job"]["job_id"], "job-1")
        self.assertEqual(historical["job"]["attempt_id"], "attempt-1")
        self.assertEqual(store.get_job("job-replay", "attempt-replay"), None)
        self.assertIsNotNone(grant_id)

    def test_terminal_replay_uses_new_request_id_without_replacing_persisted_report(self):
        _state_dir, owner, store = self.make_store()
        request = self.make_request(owner)
        _grant_id, dispatched = self.authorized(store, request)
        self.assertIsNone(store.begin_operation(dispatched, "job-1", "attempt-1", time.time(), profile_fingerprint=PROFILE))
        report = self.report(dispatched)
        store.finish_operation(dispatched, report)

        replay = copy.deepcopy(dispatched)
        replay["request_id"] = "request-replay"
        replay.pop("authorization")
        result = store.lookup_operation(replay)
        self.assertEqual(result["request_id"], "request-replay")
        self.assertEqual(result["job"], report["job"])
        self.assertEqual(store.begin_operation(replay, "unused-job", "unused-attempt", time.time(), profile_fingerprint=PROFILE), result)
        saved = store.get_job("job-1", "attempt-1")
        self.assertEqual(saved["status"], "finished")
        self.assertEqual(saved["report"], report)

    def test_changed_fingerprint_conflicts_even_before_authorization_checks(self):
        _state_dir, owner, store = self.make_store()
        request = self.make_request(owner)
        _grant_id, dispatched = self.authorized(store, request)
        self.assertIsNone(store.begin_operation(dispatched, "job-1", "attempt-1", time.time(), profile_fingerprint=PROFILE))

        changed = copy.deepcopy(dispatched)
        changed["request_id"] = "request-changed"
        changed["instruction"] = "different payload"
        changed["operation"]["fingerprint"] = fingerprint(changed)
        self.assert_code("operation_conflict", store.lookup_operation, changed)
        self.assert_code("operation_conflict", store.begin_operation, changed, "other-job", "other-attempt", time.time(), profile_fingerprint=PROFILE)

    def test_grants_bind_full_action_operation_and_payload_and_are_single_use(self):
        _state_dir, owner, store = self.make_store()
        cases = (
            ("target", lambda r: r["target"].update(id="other-agent")),
            ("payload", lambda r: r.update(instruction="changed instruction")),
            ("project", lambda r: r["project"].update(generation="project-generation-2")),
            ("backend", lambda r: r["backend"].update(generation="backend-generation-2")),
            ("operation", lambda r: r["operation"].update(id="different-operation")),
            ("action", lambda r: (r.update(action="start"), r["target"].update(kind="profile"))),
        )
        for index, (name, mutate) in enumerate(cases):
            request = self.make_request(owner, operation_id=f"operation-{index}")
            grant_id, _dispatched = self.authorized(store, request)
            changed = copy.deepcopy(request)
            mutate(changed)
            changed["request_id"] = f"request-{name}"
            changed["operation"]["fingerprint"] = fingerprint(changed)
            changed["authorization"] = {"grant_id": grant_id, "action": changed["action"]}
            self.assert_code("approval_required", store.begin_operation, changed, f"job-{index}", f"attempt-{index}", time.time(), profile_fingerprint=PROFILE)

        request = self.make_request(owner, operation_id="one-use")
        grant_id, dispatched = self.authorized(store, request)
        self.assertIsNone(store.begin_operation(dispatched, "job-one", "attempt-one", time.time(), profile_fingerprint=PROFILE))
        other = self.make_request(owner, operation_id="other-operation")
        other["authorization"] = {"grant_id": grant_id, "action": "submit"}
        self.assert_code("approval_required", store.begin_operation, other, "job-two", "attempt-two", time.time(), profile_fingerprint=PROFILE)

    def test_expiry_and_revocation_refuse_dispatch(self):
        _state_dir, owner, store = self.make_store()
        expired = self.make_request(owner, operation_id="expired")
        expiry = time.time() + 10
        grant_id = store.issue_grant(expired, expiry, profile_fingerprint=PROFILE)
        expired_request = copy.deepcopy(expired)
        expired_request["authorization"] = {"grant_id": grant_id, "action": "submit"}
        self.assert_code("approval_required", store.begin_operation, expired_request, "job-expired", "attempt-expired", expiry + 1, profile_fingerprint=PROFILE)

        revoked = self.make_request(owner, operation_id="revoked")
        grant_id, revoked_request = self.authorized(store, revoked)
        self.assertTrue(store.revoke_grant(grant_id))
        self.assertFalse(store.revoke_grant(grant_id))
        self.assert_code("approval_required", store.begin_operation, revoked_request, "job-revoked", "attempt-revoked", time.time(), profile_fingerprint=PROFILE)

    def test_terminal_replay_does_not_require_fresh_grant_but_grant_cannot_be_reused_for_new_work(self):
        _state_dir, owner, store = self.make_store()
        request = self.make_request(owner)
        grant_id, dispatched = self.authorized(store, request)
        self.assertIsNone(store.begin_operation(dispatched, "job-1", "attempt-1", time.time(), profile_fingerprint=PROFILE))
        report = self.report(dispatched)
        store.finish_operation(dispatched, report)
        self.assertTrue(store.revoke_grant(grant_id))

        replay = copy.deepcopy(dispatched)
        replay["request_id"] = "request-after-revocation"
        replay.pop("authorization")
        self.assertEqual(store.lookup_operation(replay)["outcome"], "ok")

    def test_owner_reinitialization_invalidates_old_requests(self):
        state_dir, owner, store = self.make_store()
        stale_request = self.make_request(owner)
        store.close()
        (state_dir / "state.sqlite3").unlink()
        replacement = Store.initialize(state_dir)
        self.assertNotEqual(replacement["instance_id"], owner["instance_id"])
        fresh_store = Store(state_dir)
        self.addCleanup(fresh_store.close)
        self.assert_code("request_conflict", fresh_store.lookup_operation, stale_request)

    def test_record_table_and_database_size_limits_refuse_without_eviction(self):
        import dotunnel_adapter.state as state_module

        _state_dir, owner, store = self.make_store()
        self.assertEqual(state_module._MAX_ROWS_PER_TABLE, 1000)
        stored = []
        with mock.patch.object(state_module, "_MAX_ROWS_PER_TABLE", 3):
            for index in range(2):
                request = self.make_request(owner, operation_id=f"operation-{index}")
                grant_id, dispatched = self.authorized(store, request)
                stored.append(dispatched)
                self.assertIsNone(store.begin_operation(dispatched, f"job-{index}", f"attempt-{index}", time.time(), profile_fingerprint=PROFILE))
            extra = self.make_request(owner, operation_id="operation-extra")
            extra_grant = store.issue_grant(extra, time.time() + 120, profile_fingerprint=PROFILE)

        with mock.patch.object(state_module, "_MAX_ROWS_PER_TABLE", 2):
            extra["authorization"] = {"grant_id": extra_grant, "action": "submit"}
            self.assert_code("resource_limit", store.begin_operation, extra, "job-extra", "attempt-extra", time.time(), profile_fingerprint=PROFILE)
            self.assert_code("resource_limit", store.issue_grant, self.make_request(owner, operation_id="grant-extra"), time.time() + 120, profile_fingerprint=PROFILE)
        self.assertEqual(store.lookup_operation(stored[0])["code"], "outcome_unknown")

    def test_grant_history_limit_is_one_thousand_and_never_evicts(self):
        _state_dir, owner, store = self.make_store()
        request = self.make_request(owner)
        grant_ids = [store.issue_grant(request, time.time() + 3500, profile_fingerprint=PROFILE) for _ in range(1000)]
        self.assertEqual(len(grant_ids), 1000)
        self.assert_code("resource_limit", store.issue_grant, request, time.time() + 3500, profile_fingerprint=PROFILE)
        request["authorization"] = {"grant_id": grant_ids[0], "action": "submit"}
        self.assertIsNone(store.begin_operation(request, "job-retained", "attempt-retained", time.time(), profile_fingerprint=PROFILE))

        db = _state_dir / "state.sqlite3"
        with db.open("r+b") as handle:
            handle.truncate(64 * 1024 * 1024 + 1)
        self.assert_code("resource_limit", store.issue_grant, self.make_request(owner, operation_id="too-large"), time.time() + 120, profile_fingerprint=PROFILE)

    def test_replaced_database_invalidates_an_open_owner(self):
        state_dir, owner, store = self.make_store()
        (state_dir / "state.sqlite3").unlink()
        replacement = Store.initialize(state_dir)
        self.assertNotEqual(replacement, owner)
        self.assert_code("state_unavailable", lambda: store.owner)

    def test_expiry_is_checked_at_admission_not_before_waiting_for_a_lock(self):
        _state_dir, owner, store = self.make_store()
        now = time.time()
        _, request = self.authorized(store, self.make_request(owner), expires_in=30)
        with mock.patch("dotunnel_adapter.state.time.time", return_value=now + 60):
            self.assert_code("approval_required", store.begin_operation, request, "job-late", "attempt-late", now, profile_fingerprint=PROFILE)
        self.assertIsNone(store.get_job("job-late", "attempt-late"))

    def test_invalid_grant_expiry_is_rejected(self):
        _state_dir, owner, store = self.make_store()
        request = self.make_request(owner)
        for expiry in (float("nan"), float("inf"), time.time() - 1, time.time() + 3601):
            self.assert_code("invalid_request", store.issue_grant, request, expiry, profile_fingerprint=PROFILE)


if __name__ == "__main__":
    unittest.main()
