import errno
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from dotunnel_adapter import filesystem as filesystem_module
from dotunnel_adapter.filesystem import Workspace
from dotunnel_adapter.protocol import RunnerError

class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        os.chmod(self.base, 0o700)
        self.root = self.base / "workspace"
        self.root.mkdir(mode=0o700)
        self.workspace = Workspace(self.root)

    def tearDown(self):
        self.workspace.close()
        self.temporary.cleanup()

    def put_request(self, path="pending.json", data=b'{"protocol":"dotunnel.adapter/1"}'):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(data)
        target.chmod(0o600)
        return target, hashlib.sha256(data).hexdigest()

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(RunnerError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_read_request_returns_exact_bytes_and_plain_sha256(self):
        data = b'{"request_id":"read_1"}'
        self.put_request(data=data)
        actual, digest = self.workspace.read_request("pending.json")
        self.assertEqual(actual, data)
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())

    def test_request_refuses_group_or_world_readable_workspace_files(self):
        self.put_request()
        (self.root / "pending.json").chmod(0o644)
        self.assert_code("request_conflict", self.workspace.read_request, "pending.json")

    def test_claim_requires_the_read_snapshot_and_consumes_it_only_once(self):
        data = b'{"request_id":"claim_1"}'
        self.put_request(data=data)
        snapshot, digest = self.workspace.read_request("pending.json")
        self.assertEqual(self.workspace.claim_request("pending.json", digest), snapshot)
        self.assertFalse((self.root / "pending.json").exists())
        self.assert_code("request_conflict", self.workspace.claim_request, "pending.json", digest)

    def test_claim_refuses_replaced_path_without_unlinking_the_replacement(self):
        data = b'{"request_id":"original"}'
        _, digest = self.put_request(data=data)
        self.workspace.read_request("pending.json")
        replacement = self.root / "replacement.json"
        replacement.write_bytes(data)
        replacement.chmod(0o600)
        os.replace(replacement, self.root / "pending.json")
        self.assert_code("request_conflict", self.workspace.claim_request, "pending.json", digest)
        self.assertEqual((self.root / "pending.json").read_bytes(), data)
    def test_claim_quarantines_and_restores_same_bytes_replaced_after_open(self):
        data = b'{"request_id":"same-bytes"}'
        _, digest = self.put_request(data=data)
        self.workspace.read_request("pending.json")
        replacement = self.root / "replacement.json"
        replacement.write_bytes(data)
        replacement.chmod(0o600)
        real_move = filesystem_module._rename_noreplace
        raced = False

        def replace_before_move(source_fd, source_name, destination_fd, destination_name):
            nonlocal raced
            if not raced and destination_name.startswith("claim-"):
                os.replace(replacement, self.root / "pending.json")
                raced = True
            return real_move(source_fd, source_name, destination_fd, destination_name)

        with patch.object(filesystem_module, "_rename_noreplace", side_effect=replace_before_move):
            self.assert_code("request_conflict", self.workspace.claim_request, "pending.json", digest)
        self.assertTrue(raced)
        self.assertEqual((self.root / "pending.json").read_bytes(), data)
        self.assertEqual(list((self.root / ".dotunnel-claims").iterdir()), [])

    def test_claim_preserves_quarantined_substitution_when_pending_path_is_reoccupied(self):
        data = b'{"request_id":"same-bytes"}'
        _, digest = self.put_request(data=data)
        self.workspace.read_request("pending.json")
        replacement = self.root / "replacement.json"
        replacement.write_bytes(data)
        replacement.chmod(0o600)
        real_move = filesystem_module._rename_noreplace
        moved = False

        def replace_and_reoccupy(source_fd, source_name, destination_fd, destination_name):
            nonlocal moved
            if not moved and destination_name.startswith("claim-"):
                os.replace(replacement, self.root / "pending.json")
                result = real_move(source_fd, source_name, destination_fd, destination_name)
                (self.root / "pending.json").write_bytes(b"new pending request")
                (self.root / "pending.json").chmod(0o600)
                moved = True
                return result
            return real_move(source_fd, source_name, destination_fd, destination_name)

        with patch.object(filesystem_module, "_rename_noreplace", side_effect=replace_and_reoccupy):
            self.assert_code("request_conflict", self.workspace.claim_request, "pending.json", digest)
        self.assertEqual((self.root / "pending.json").read_bytes(), b"new pending request")
        quarantined = list((self.root / ".dotunnel-claims").iterdir())
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].read_bytes(), data)


    def test_claim_serializes_concurrent_consumers_so_exactly_one_gets_the_snapshot(self):
        data = b'{"request_id":"one-shot"}'
        self.put_request(data=data)
        _, digest = self.workspace.read_request("pending.json")
        barrier = threading.Barrier(3)
        outcomes = []

        def claim():
            barrier.wait()
            try:
                outcomes.append(("claimed", self.workspace.claim_request("pending.json", digest)))
            except RunnerError as error:
                outcomes.append(("refused", error.code))

        workers = [threading.Thread(target=claim) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=3)
        self.assertEqual(sum(kind == "claimed" for kind, _ in outcomes), 1)
        self.assertEqual(sum(kind == "refused" for kind, _ in outcomes), 1)

    def test_request_path_refuses_traversal_hidden_private_symlink_hardlink_and_special_files(self):
        data = b"private request"
        target, _ = self.put_request("ordinary.json", data)
        os.link(target, self.root / "hardlink.json")
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (outside / "pending.json").write_bytes(data)
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        os.mkfifo(self.root / "pipe")
        for path in ("../outside.json", ".hidden", "private/key.json", "/etc/passwd", "bad\x00name"):
            self.assert_code("invalid_request", self.workspace.read_request, path)
        for path in ("escape/pending.json", "hardlink.json", "pipe", "ordinary.json"):
            self.assert_code("request_conflict", self.workspace.read_request, path)

    def test_request_size_limit_is_checked_before_unbounded_read(self):
        self.put_request(data=b"x" * 65537)
        self.assert_code("resource_limit", self.workspace.read_request, "pending.json")

    def test_report_is_descriptor_rooted_create_only_private_and_digest_verifiable(self):
        path, digest = self.workspace.write_report("reports/daily", "request_1", {"request_id": "request_1", "outcome": "ok"})
        report_path = self.root / path
        report_bytes = report_path.read_bytes()
        self.assertEqual(path, "reports/daily/request_1.json")
        self.assertEqual(hashlib.sha256(report_bytes).hexdigest(), digest)
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((report_path.parent.stat().st_mode & 0o777), 0o700)
        report_path.write_bytes(b"preserve me")
        self.assert_code("request_conflict", self.workspace.write_report, "reports/daily", "request_1", {"request_id": "request_1"})
        self.assertEqual(report_path.read_bytes(), b"preserve me")

    def test_failed_report_write_leaves_no_partial_final_name_and_can_publish_same_id(self):
        report = {'request_id': 'atomic-report', 'outcome': 'ok'}
        final = self.root / 'reports' / 'atomic-report.json'

        def fail_after_partial_write(fd, content):
            os.write(fd, content[:8])
            raise OSError(errno.ENOSPC, 'synthetic full device')

        with patch.object(filesystem_module, '_write_all', side_effect=fail_after_partial_write):
            self.assert_code('request_conflict', self.workspace.write_report,
                             'reports', 'atomic-report', report)
        self.assertFalse(final.exists())
        relative, digest = self.workspace.write_report('reports', 'atomic-report', report)
        self.assertEqual(hashlib.sha256((self.root / relative).read_bytes()).hexdigest(), digest)
        self.assertIn(b'"outcome":"ok"', final.read_bytes())

    def test_report_refuses_symlink_escape_and_request_id_path_injection(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (self.root / "reports").symlink_to(outside, target_is_directory=True)
        self.assert_code("request_conflict", self.workspace.write_report, "reports", "request_2", {"request_id": "request_2"})
        self.assertFalse((outside / "request_2.json").exists())
        self.assert_code("invalid_request", self.workspace.write_report, "safe-reports", "../escape", {})

    def test_report_rejects_oversized_serialized_data_and_closed_root(self):
        self.assert_code("resource_limit", self.workspace.write_report, "reports", "large", {"text": "x" * 65536})
        self.workspace.close()
        self.assert_code("request_conflict", self.workspace.read_request, "pending.json")

    def test_workspace_root_must_not_be_a_symlink_or_special_directory(self):
        link = self.base / "workspace-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(RunnerError) as caught:
            Workspace(link)
        self.assertEqual(caught.exception.code, "invalid_config")


if __name__ == "__main__":
    unittest.main()
