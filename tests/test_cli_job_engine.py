import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


class CliJobEngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.workspace = self.base / "workspace"
        self.source = self.base / "source"
        self.workspace.mkdir()
        self.source.mkdir()
        (self.source / "logic.py").write_bytes(b"value = 1")
        (self.source / "protected.txt").write_bytes(b"leave unchanged\n")
        self.request_path = self.workspace / "request.json"
        self.config_path = self.base / "job.json"

    def save_config(self, request, **changes):
        self.request_path.write_text(json.dumps(request), encoding="utf-8")
        config = {
            "backend": "codex",
            "workspace": str(self.workspace),
            "request": "request.json",
            "runtime": {
                "executable": "/missing/codex",
                "companion": "/missing/codex-code-mode-host",
                "auth": "/missing/auth.json",
            },
            "targets": {
                "fixture": {
                    "root": str(self.source),
                    "files": ["logic.py", "protected.txt"],
                    "editable": ["logic.py"],
                }
            },
        }
        config.update(changes)
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        self.config_path.chmod(0o600)

    def invoke(self, request, native, *, environment=None, **config_changes):
        self.save_config(request, **config_changes)
        backend = importlib.import_module("dotunnel.cli_backend")
        uid = os.getuid() or 65534
        if os.getuid() == 0:
            self.config_path.chown(uid)
        output = io.StringIO()
        # The operator entrypoint intentionally scrubs inherited environment.
        with patch.dict(os.environ, environment or {}, clear=True), \
                patch("dotunnel.cli_jobs.sys.platform", "linux"), \
                patch("dotunnel.cli_jobs.os.getuid", return_value=uid), \
                patch("dotunnel.cli_jobs.os.geteuid", return_value=uid), \
                patch.object(backend, "run_native", side_effect=native), \
                redirect_stdout(output):
            status = importlib.import_module("dotunnel.cli_jobs").main(
                ["--config", str(self.config_path)]
            )
        return status, json.loads(output.getvalue())

    @staticmethod
    def request(mode="edit"):
        return {"target": "fixture", "mode": mode, "instruction": "Change value to 2"}

    @staticmethod
    def completed(*, exit_code=0, summary="Changed one line."):
        return {
            "status": "completed",
            "cli_exit_code": exit_code,
            "elapsed_seconds": 0.25,
            "summary": summary,
        }

    def test_unknown_request_arguments_are_rejected_before_native_execution(self):
        request = self.request() | {"argv": ["/bin/sh"], "env": {"TOKEN": "not-a-secret"}}

        def native(*args):
            self.fail("invalid request reached native runtime")

        status, output = self.invoke(request, native)

        self.assertEqual(status, 2)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(output["error_code"], "INVALID_REQUEST")
        self.assertEqual(sorted(path.name for path in self.workspace.iterdir()), ["request.json"])
        self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")


    def test_invalid_instruction_text_is_rejected_before_native_execution(self):
        for instruction in ("\x00", "\ud800", "x" * 8193):
            with self.subTest(instruction_length=len(instruction)):
                def native(*args):
                    self.fail("invalid instruction reached native runtime")

                status, output = self.invoke(self.request() | {"instruction": instruction}, native)

                self.assertEqual(status, 2)
                self.assertEqual(output["status"], "rejected")
                self.assertEqual(output["error_code"], "INVALID_REQUEST")
                self.assertFalse((self.workspace / "cli-results").exists())

    def test_edit_candidate_is_reported_as_a_diff_without_writing_originals(self):
        before = (self.source / "logic.py").read_bytes()
        claude_config = {
            "backend": "claude",
            "runtime": {"executable": "/missing/claude", "oauth_token": "/missing/claude-oauth-token"},
        }

        for backend, config in (("codex", {}), ("claude", claude_config)):
            with self.subTest(backend=backend):
                def native(native_backend, runtime, snapshot, editable, mode, instruction):
                    self.assertEqual(native_backend, backend)
                    self.assertEqual(mode, "edit")
                    self.assertEqual((snapshot / "logic.py").read_bytes(), before)
                    (snapshot / "logic.py").write_bytes(b"value = 2")
                    return self.completed()

                status, output = self.invoke(self.request(), native, **config)

                self.assertEqual(status, 0)
                self.assertEqual(output["status"], "candidate_ready")
                self.assertEqual(output["backend"], backend)
                self.assertEqual(output["changed_file_count"], 1)
                self.assertEqual(output["verification"], "not_run")
                self.assertEqual((self.source / "logic.py").read_bytes(), before)
                report_path = self.workspace / output["report_path"]
                report_bytes = report_path.read_bytes()
                self.assertEqual(hashlib.sha256(report_bytes).hexdigest(), output["report_sha256"])
                self.assertLessEqual(len(report_bytes), 64 * 1024)
                report = json.loads(report_bytes)
                self.assertEqual(report["verification"], "not_run")
                protected = (self.source / "protected.txt").read_bytes()
                self.assertEqual(
                    report["protected_source_hashes"]["protected.txt"],
                    hashlib.sha256(protected).hexdigest(),
                )
                file_result = next(item for item in report["files"] if item["path"] == "logic.py")
                self.assertEqual(file_result["before_sha256"], hashlib.sha256(before).hexdigest())
                after = b"value = 2"
                self.assertEqual(file_result["after_sha256"], hashlib.sha256(after).hexdigest())
                diff_chunks = []
                for item in report["diff_chunks"]:
                    chunk = (self.workspace / item["path"]).read_bytes()
                    self.assertLessEqual(len(chunk), 48 * 1024)
                    self.assertEqual(len(chunk), item["size_bytes"])
                    self.assertEqual(hashlib.sha256(chunk).hexdigest(), item["sha256"])
                    diff_chunks.append(chunk)
                diff_bytes = b"".join(diff_chunks)
                self.assertEqual(hashlib.sha256(diff_bytes).hexdigest(), report["diff_sha256"])
                diff = diff_bytes.decode("utf-8")
                self.assertIn("-value = 1\n\\ No newline at end of file\n", diff)
                self.assertIn("+value = 2\n\\ No newline at end of file\n", diff)


    def test_claude_runtime_rejects_extra_execution_controls_before_native_execution(self):
        def native(*args):
            self.fail("unsupported Claude runtime controls reached native execution")

        for key, value in (
            ("model", "unapproved-model"),
            ("env", {"TOKEN": "not-a-secret"}),
            ("cwd", "/tmp"),
            ("auth", "/missing/.credentials.json"),
        ):
            with self.subTest(control=key):
                runtime = {
                    "executable": "/missing/claude",
                    "oauth_token": "/missing/claude-oauth-token",
                    key: value,
                }
                status, output = self.invoke(
                    self.request(),
                    native,
                    backend="claude",
                    runtime=runtime,
                )

                self.assertEqual(status, 2)
                self.assertEqual(output["status"], "rejected")
                self.assertEqual(output["error_code"], "INVALID_CONFIG")
                self.assertFalse((self.workspace / "cli-results").exists())


    def test_review_reports_readonly_baseline_without_changes(self):
        def native(backend, runtime, snapshot, editable, mode, instruction):
            self.assertEqual(mode, "review")
            return self.completed()

        status, output = self.invoke(self.request("review"), native)

        self.assertEqual(status, 0)
        self.assertEqual(output["status"], "reviewed")
        self.assertEqual(output["changed_file_count"], 0)
        self.assertEqual(output["verification"], "not_run")
        report = json.loads((self.workspace / output["report_path"]).read_text(encoding="utf-8"))
        self.assertEqual(report["diff_chunks"], [])
        self.assertEqual(report["changed_file_count"], 0)
        self.assertEqual(
            set(report["protected_source_hashes"]),
            {"logic.py", "protected.txt"},
        )
        self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")
        self.assertEqual((self.source / "protected.txt").read_bytes(), b"leave unchanged\n")

    def test_forbidden_candidate_mutations_never_publish_results(self):
        def mutate(snapshot, mutation):
            if mutation == "extra":
                (snapshot / "unexpected.txt").write_text("extra", encoding="utf-8")
            elif mutation == "deleted":
                (snapshot / "protected.txt").unlink()
            elif mutation == "renamed":
                (snapshot / "logic.py").rename(snapshot / "renamed.py")
            elif mutation == "symlink":
                (snapshot / "logic.py").unlink()
                (snapshot / "logic.py").symlink_to(self.source / "logic.py")
            elif mutation == "hardlink":
                (snapshot / "logic.py").unlink()
                os.link(snapshot / "protected.txt", snapshot / "logic.py")
            elif mutation == "oversized":
                (snapshot / "logic.py").write_bytes(b"x" * (64 * 1024 + 1))
            elif mutation == "non_utf8":
                (snapshot / "logic.py").write_bytes(b"\xff")
            elif mutation == "protected_change":
                (snapshot / "protected.txt").write_text("changed", encoding="utf-8")
            elif mutation == "review_change":
                (snapshot / "logic.py").write_bytes(b"value = 3")

        for mutation in (
            "extra", "deleted", "renamed", "symlink", "hardlink", "oversized",
            "non_utf8", "protected_change", "review_change",
        ):
            with self.subTest(mutation=mutation):
                mode = "review" if mutation == "review_change" else "edit"

                def native(backend, runtime, snapshot, editable, native_mode, instruction):
                    mutate(snapshot, mutation)
                    return self.completed()

                status, output = self.invoke(self.request(mode), native)

                self.assertEqual(status, 1)
                self.assertEqual(output["status"], "failed")
                self.assertEqual(output["error_code"], "CANDIDATE_INVALID")
                self.assertFalse((self.workspace / "cli-results").exists())
                self.assertEqual((self.source / "protected.txt").read_bytes(), b"leave unchanged\n")
                self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")

    def test_external_original_conflict_rejects_candidate_without_publication(self):
        def native(backend, runtime, snapshot, editable, mode, instruction):
            (snapshot / "logic.py").write_bytes(b"value = 2")
            (self.source / "logic.py").write_bytes(b"external change\n")
            return self.completed()

        status, output = self.invoke(self.request(), native)

        self.assertEqual(status, 1)
        self.assertEqual(output["status"], "failed")
        self.assertEqual(output["error_code"], "SOURCE_CONFLICT")
        self.assertFalse((self.workspace / "cli-results").exists())
        self.assertEqual((self.source / "logic.py").read_bytes(), b"external change\n")

    def test_replaced_source_root_rejects_stale_candidate(self):
        def native(backend, runtime, snapshot, editable, mode, instruction):
            (snapshot / "logic.py").write_bytes(b"value = 2")
            self.source.rename(self.base / "old-source")
            self.source.mkdir()
            (self.source / "logic.py").write_bytes(b"value = 1")
            (self.source / "protected.txt").write_bytes(b"leave unchanged\n")
            return self.completed()

        status, output = self.invoke(self.request(), native)

        self.assertEqual(status, 1)
        self.assertEqual(output["error_code"], "SOURCE_CONFLICT")
        self.assertFalse((self.workspace / "cli-results").exists())
        self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")

    def test_synthetic_task_home_does_not_disable_workspace_admission(self):
        def native(backend, runtime, snapshot, editable, mode, instruction):
            (snapshot / "logic.py").write_bytes(b"value = 2")
            return self.completed()

        status, output = self.invoke(
            self.request(), native, environment={"HOME": str(self.workspace)}
        )

        self.assertEqual(status, 0)
        self.assertEqual(output["status"], "candidate_ready")
        self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")


    def test_configuration_rejects_unknown_native_controls(self):
        def native(*args):
            self.fail("unknown configuration controls reached native runtime")

        status, output = self.invoke(self.request(), native, model="unapproved-model")

        self.assertEqual(status, 2)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(output["error_code"], "INVALID_CONFIG")
        self.assertFalse((self.workspace / "cli-results").exists())

    def test_symlink_source_root_is_rejected(self):
        linked_root = self.base / "linked-source"
        linked_root.symlink_to(self.source, target_is_directory=True)
        target = {
            "root": str(linked_root),
            "files": ["logic.py"],
            "editable": ["logic.py"],
        }

        def native(*args):
            self.fail("symlink source root reached native runtime")

        status, output = self.invoke(
            self.request(),
            native,
            targets={"fixture": target},
        )

        self.assertEqual(status, 2)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(output["error_code"], "INVALID_CONFIG")
        self.assertFalse((self.workspace / "cli-results").exists())

    def test_unsafe_source_paths_and_files_are_rejected_without_native_execution(self):
        cases = (
            ("protected_name", "credentials.json", None),
            ("live_config", "config.local.json", None),
            ("runtime_auth", "auth.json", None),
            ("client_state", "client.json", None),
            ("profile_state", "profile.json", None),
            ("symlink", "linked.py", "symlink"),
            ("hardlink", "linked.py", "hardlink"),
            ("oversized", "large.py", "oversized"),
            ("non_utf8", "invalid.py", b"\xff"),
        )
        for case, relative, content in cases:
            with self.subTest(case=case):
                path = self.source / relative
                if content == "symlink":
                    path.symlink_to(self.source / "logic.py")
                elif content == "hardlink":
                    os.link(self.source / "protected.txt", path)
                elif content == "oversized":
                    path.write_bytes(b"x" * (64 * 1024 + 1))
                elif content is not None:
                    path.write_bytes(content)
                target = {
                    "root": str(self.source),
                    "files": [relative],
                    "editable": [relative],
                }

                def native(*args):
                    self.fail("unsafe source reached native runtime")

                try:
                    status, output = self.invoke(
                        self.request(),
                        native,
                        targets={"fixture": target},
                    )
                finally:
                    if path.exists() or path.is_symlink():
                        path.unlink()

                self.assertEqual(status, 2)
                self.assertEqual(output["status"], "rejected")
                self.assertEqual(output["error_code"], "INVALID_CONFIG")
                self.assertFalse((self.workspace / "cli-results").exists())

    def test_mcp_runtime_inside_writable_workspace_is_rejected(self):
        def native(*args):
            self.fail("remotely writable MCP runtime reached native execution")

        with patch("dotunnel.cli_jobs.__file__", str(self.workspace / "runtime" / "cli_jobs.py")):
            status, output = self.invoke(self.request(), native)

        self.assertEqual(status, 2)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(output["error_code"], "INVALID_CONFIG")
        self.assertFalse((self.workspace / "cli-results").exists())
        self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")

    def test_native_failure_reports_allowlisted_diagnostics_without_native_text(self):
        def native(*args):
            return {
                "status": "failed",
                "cli_exit_code": 1,
                "elapsed_seconds": 1.5,
                "summary": "private-native-stream-must-not-escape",
                "error_code": "NATIVE_FAILURE",
                "detail": "AUTH_FAILED",
            }

        status, output = self.invoke(self.request(), native)

        self.assertEqual(status, 1)
        self.assertEqual(
            output,
            {
                "status": "failed",
                "error_code": "NATIVE_FAILED",
                "native_error_code": "NATIVE_FAILURE",
                "native_detail": "AUTH_FAILED",
                "native_exit_code": 1,
                "native_elapsed_seconds": 1.5,
            },
        )
        self.assertNotIn("private-native-stream-must-not-escape", json.dumps(output))
        self.assertFalse((self.workspace / "cli-results").exists())
        self.assertEqual((self.source / "logic.py").read_bytes(), b"value = 1")

    def test_native_failure_drops_unrecognized_or_malformed_diagnostics(self):
        def native(*args):
            return {
                "status": "failed",
                "cli_exit_code": True,
                "elapsed_seconds": float("nan"),
                "summary": "",
                "error_code": "secret-provider-detail",
                "detail": "OAuth token rejected: secret-provider-detail",
            }

        status, output = self.invoke(self.request(), native)

        self.assertEqual(status, 1)
        self.assertEqual(output, {"status": "failed", "error_code": "NATIVE_FAILED"})


if __name__ == "__main__":
    unittest.main()
