"""Consumer-visible regressions for retained setup integrations and authority."""

import hashlib
import importlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


TUNNEL = "tunnel_" + "4" * 32
SYNTHETIC_KEY = "synthetic-retained-setup-key-never-used-for-provider-auth"
GENERATION = "fixture-generation"


class Terminal(io.StringIO):
    def isatty(self):
        return True


class RetainedSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.setup = importlib.import_module("dotunnel.setup")
        self.onboarding = importlib.import_module("dotunnel.onboarding")
        self.integrations = importlib.import_module("dotunnel.integrations")

    def _file(self, path, *, executable=False, content=b"synthetic fixture\n"):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(content)
        path.chmod(0o700 if executable else 0o600)
        return path

    def _new_setup(self, name):
        base = self.base / name
        base.mkdir(mode=0o700)
        source = base / "source"
        source.mkdir(mode=0o700)
        source.chmod(0o700)
        (source / "sample.py").write_text("value = 1\n", encoding="utf-8")
        (source / "sample.py").chmod(0o600)
        directory = base / "private"
        self.setup.create_artifacts(directory, TUNNEL, SYNTHETIC_KEY)
        return {
            "base": base,
            "directory": directory,
            "config": directory / "config.json",
            "workspace": directory / "workspace",
            "source": source,
        }

    def _add_codex_task(self, fixture, *, missing_executable=True, unrelated=True):
        base = fixture["base"]
        directory = fixture["directory"]
        workspace = fixture["workspace"]
        source = fixture["source"]
        runtime = base / "runtime"
        runtime.mkdir(mode=0o700)
        runtime.chmod(0o700)
        executable = self._file(runtime / "codex", executable=True)
        companion = self._file(runtime / "codex-code-mode-host", executable=True)
        auth = self._file(runtime / "auth-reference", content=b"")
        job_path = directory / "native-cli" / GENERATION / "codex.json"
        job_path.parent.mkdir(mode=0o700, parents=True)
        (directory / "native-cli").chmod(0o700)
        job_path.parent.chmod(0o700)
        request_relative = f"dotunnel-requests/{GENERATION}/codex.json"
        request_path = workspace / request_relative
        request_path.parent.mkdir(mode=0o700, parents=True)
        (workspace / "dotunnel-requests").chmod(0o700)
        request_path.parent.chmod(0o700)
        job = {
            "backend": "codex",
            "workspace": str(workspace),
            "request": request_relative,
            "runtime": {
                "executable": str(executable),
                "companion": str(companion),
                "auth": str(auth),
            },
            "targets": {
                "project": {
                    "root": str(source),
                    "files": ["sample.py"],
                    "editable": [],
                },
            },
        }
        job_path.write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
        job_path.chmod(0o600)
        request_path.write_text(json.dumps({
            "target": "project",
            "mode": "review",
            "instruction": "Review the selected source file.",
        }, indent=2) + "\n", encoding="utf-8")
        request_path.chmod(0o600)

        wrapper = self._file(base / "bin" / "dotunnel", executable=True)
        registered = {
            "name": "dotunnel-codex",
            "description": "Run the setup-owned fixed Codex review task",
            "argv": [str(wrapper), "cli-job", "--config", str(job_path)],
            "cwd": ".",
            "timeout_seconds": 240,
        }
        tasks = [registered]
        unowned = None
        if unrelated:
            runner = self._file(base / "bin" / "operator-task", executable=True)
            unowned = {
                "name": "existing_review",
                "description": "Existing unrelated task",
                "argv": [str(runner)],
                "cwd": ".",
                "timeout_seconds": 90,
            }
            tasks.append(unowned)

        document = json.loads(fixture["config"].read_text(encoding="utf-8"))
        document["tasks"] = tasks
        exact_request = {"path": request_relative, "kind": "file"}
        document["file_access"] = {
            "read": [dict(exact_request)],
            "write": [dict(exact_request)],
        }
        fixture["config"].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        fixture["config"].chmod(0o600)
        if missing_executable:
            executable.unlink()
        fixture.update({
            "task": registered,
            "unowned_task": unowned,
            "job_path": job_path,
            "request_path": request_path,
            "source_file": source / "sample.py",
            "runtime_executable": executable,
        })
        return fixture

    def _add_supervision(self, fixture):
        from dotunnel.supervision_state import SupervisionState

        base = fixture["base"]
        state_path = base / "supervision-state"
        authority = SupervisionState.initialize(state_path)
        authority.close()
        opened = SupervisionState(state_path)
        opened.close()
        executable = self._file(base / "bin" / "herdr", executable=True)
        profile_executable = self._file(base / "bin" / "codex-profile", executable=True)
        document = json.loads(fixture["config"].read_text(encoding="utf-8"))
        document["supervision"] = {
            "state_dir": str(state_path),
            "connections": [{
                "id": "isolated",
                "backend": "herdr",
                "executable": str(executable),
                "session": "fixture",
            }],
            "projects": [{
                "id": "supervised",
                "path": str(fixture["source"]),
                "connections": ["isolated"],
                "profiles": ["codex"],
                "allowed_actions": [],
                "profile_actions": {"codex": []},
            }],
            "profiles": [{
                "id": "codex",
                "kind": "codex",
                "executable": str(profile_executable),
                "backends": ["herdr"],
                "executable_policy": "compatible",
            }],
        }
        fixture["config"].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        fixture["config"].chmod(0o600)
        fixture["state_path"] = state_path
        return fixture

    def _run_existing(
        self,
        fixture,
        answers=(),
        *,
        installed=None,
        selected=(),
        bwrap_status="ready",
        prompt_callback=None,
    ):
        responses = iter(answers)
        prompts = []
        stdout, stderr = Terminal(), Terminal()
        wrapper = self._file(fixture["base"] / "bin" / "dotunnel", executable=True)
        client = self._file(fixture["base"] / "tunnel-client", executable=True)

        def answer(prompt):
            prompts.append(prompt)
            if prompt_callback is not None:
                return prompt_callback(prompt, len(prompts))
            return next(responses)

        def inspect_launcher(candidate):
            return wrapper if Path(candidate).name == "dotunnel" else client

        def choose(_available, _initially_selected):
            return set(selected)

        with ExitStack() as stack:
            stack.enter_context(patch.object(self.onboarding.sys, "platform", "linux"))
            stack.enter_context(patch.object(self.onboarding.os, "getuid", return_value=os.getuid()))
            stack.enter_context(patch.object(self.onboarding.sys, "stdin", Terminal()))
            stack.enter_context(patch.object(self.onboarding.sys, "stdout", stdout))
            stack.enter_context(patch.object(self.onboarding.sys, "stderr", stderr))
            stack.enter_context(patch("builtins.input", side_effect=answer))
            stack.enter_context(patch.object(
                self.integrations, "_inspect_launcher", side_effect=inspect_launcher,
            ))
            stack.enter_context(patch.object(
                self.integrations, "discover_clis", return_value=dict(installed or {}),
            ))
            stack.enter_context(patch.object(
                self.integrations, "bubblewrap_status", return_value=bwrap_status,
            ))
            stack.enter_context(patch.object(self.integrations, "_check_bwrap"))
            stack.enter_context(patch.object(self.integrations, "sudo_available", return_value=False))
            stack.enter_context(patch.object(self.integrations, "bubblewrap_install_argv", return_value=None))
            stack.enter_context(patch.object(self.onboarding, "select_clis", side_effect=choose))
            stack.enter_context(patch.object(self.onboarding, "_require_stopped_client"))
            stack.enter_context(patch.object(
                self.onboarding, "_confirm_no_other_client", return_value=True,
            ))
            stack.enter_context(patch.object(self.setup, "_doctor"))
            stack.enter_context(patch("shutil.which", return_value=str(wrapper)))
            status = self.onboarding.main([
                "--directory", str(fixture["directory"]), "--tunnel-client", str(client),
            ])
        return status, stdout.getvalue(), stderr.getvalue(), prompts

    @staticmethod
    def _file_snapshot(path):
        info = path.stat(follow_symlinks=False)
        return (
            info.st_dev,
            info.st_ino,
            info.st_nlink,
            info.st_uid,
            stat.S_IMODE(info.st_mode),
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            path.read_bytes(),
        )

    @staticmethod
    def _state_snapshot(path):
        entries = [path, *sorted(path.rglob("*"))]
        snapshot = []
        for entry in entries:
            info = entry.lstat()
            relative = "." if entry == path else entry.relative_to(path).as_posix()
            kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
            content = entry.read_bytes() if kind == "file" else None
            snapshot.append((
                relative,
                kind,
                info.st_dev,
                info.st_ino,
                info.st_nlink,
                info.st_uid,
                stat.S_IMODE(info.st_mode),
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                content,
            ))
        return tuple(snapshot)


    def test_unavailable_task_removal_is_default_no_even_without_discovery_or_bubblewrap(self):
        fixture = self._add_codex_task(self._new_setup("default-no"))
        before = self._file_snapshot(fixture["config"])
        artifacts = {
            path: self._file_snapshot(path)
            for path in (fixture["job_path"], fixture["request_path"], fixture["source_file"])
        }

        status, stdout, _stderr, prompts = self._run_existing(
            fixture,
            ["", "", "", "s", ""],
            installed={},
            bwrap_status="missing",
        )

        self.assertEqual(status, 2)
        self.assertEqual(self._file_snapshot(fixture["config"]), before)
        self.assertEqual(
            json.loads(fixture["config"].read_text(encoding="utf-8"))["tasks"],
            [fixture["task"], fixture["unowned_task"]],
        )
        for path, snapshot in artifacts.items():
            self.assertEqual(self._file_snapshot(path), snapshot)

    def test_unavailable_task_removal_waits_for_final_approval(self):
        fixture = self._add_codex_task(self._new_setup("review-no"))
        before = self._file_snapshot(fixture["config"])
        artifacts = {
            path: self._file_snapshot(path)
            for path in (fixture["job_path"], fixture["request_path"], fixture["source_file"])
        }

        status, stdout, _stderr, _prompts = self._run_existing(
            fixture,
            ["", "", "", "y", "n"],
            installed={},
        )

        self.assertEqual(status, 130)
        self.assertEqual(self._file_snapshot(fixture["config"]), before)
        self.assertEqual(
            json.loads(fixture["config"].read_text(encoding="utf-8"))["tasks"],
            [fixture["task"], fixture["unowned_task"]],
        )
        for path, snapshot in artifacts.items():
            self.assertEqual(self._file_snapshot(path), snapshot)

    def test_approved_removal_only_unregisters_the_task_and_keeps_old_files(self):
        fixture = self._add_codex_task(self._new_setup("approved-removal"))
        old_document = json.loads(fixture["config"].read_text(encoding="utf-8"))
        artifacts = {
            path: self._file_snapshot(path)
            for path in (fixture["job_path"], fixture["request_path"], fixture["source_file"])
        }

        status, stdout, stderr, _prompts = self._run_existing(
            fixture,
            ["", "", "", "s", "y", "y", ""],
            installed={},
            bwrap_status="missing",
        )

        self.assertEqual(status, 0, stderr)
        final = json.loads(fixture["config"].read_text(encoding="utf-8"))
        self.assertEqual(final["tasks"], [fixture["unowned_task"]])
        for key, value in old_document.items():
            if key != "tasks":
                self.assertEqual(final[key], value)
        for path, snapshot in artifacts.items():
            self.assertTrue(path.is_file())
            self.assertEqual(self._file_snapshot(path), snapshot)

    def test_retained_task_with_missing_runtime_is_still_fully_validated(self):
        fixture = self._add_codex_task(self._new_setup("retained-invalid"))
        before = self._file_snapshot(fixture["config"])
        artifacts = {
            path: self._file_snapshot(path)
            for path in (fixture["job_path"], fixture["request_path"], fixture["source_file"])
        }

        status, _stdout, stderr, _prompts = self._run_existing(
            fixture,
            ["", "", ""],
            installed={"codex": self.base / "discovered-codex"},
            selected={"codex"},
        )

        self.assertEqual(status, 2, stderr)
        self.assertEqual(self._file_snapshot(fixture["config"]), before)
        for path, snapshot in artifacts.items():
            self.assertEqual(self._file_snapshot(path), snapshot)

    def test_invalid_persisted_supervision_state_fails_read_only_before_approval(self):
        from dotunnel.supervision_state import SupervisionState

        corruptions = (
            ("missing-key", lambda path: (path / "key").unlink()),
            ("malformed-key", lambda path: (path / "key").write_bytes(b"short")),
            ("malformed-epoch", lambda path: (path / "epoch.json").write_bytes(b"{bad json")),
            ("missing-category", lambda path: (path / "receipts").rmdir()),
        )
        for name, corrupt in corruptions:
            with self.subTest(state=name):
                fixture = self._add_supervision(self._new_setup(f"invalid-{name}"))
                corrupt(fixture["state_path"])
                config_before = self._file_snapshot(fixture["config"])
                state_before = self._state_snapshot(fixture["state_path"])
                with self.assertRaises(ValueError):
                    SupervisionState(fixture["state_path"])
                self.assertEqual(self._state_snapshot(fixture["state_path"]), state_before)

                def answer(_prompt, count):
                    return "y" if count == 4 else ""

                status, _stdout, stderr, prompts = self._run_existing(
                    fixture,
                    installed={},
                    prompt_callback=answer,
                )

                self.assertEqual(status, 2, stderr)
                self.assertEqual(self._file_snapshot(fixture["config"]), config_before)
                self.assertEqual(self._state_snapshot(fixture["state_path"]), state_before)

    @staticmethod
    def _replace_state_file(path, content):
        replacement = path.with_name(path.name + ".fixture-replacement")
        replacement.write_bytes(content)
        replacement.chmod(0o600)
        os.replace(replacement, path)

    def _change_to_a_different_valid_state(self, state_path):
        from dotunnel.supervision_state import SupervisionState

        replacement_key = bytes(range(32))
        metadata_path = state_path / "epoch.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["epoch"] = "f" * 32
        metadata["key_sha256"] = hashlib.sha256(replacement_key).hexdigest()
        self._replace_state_file(state_path / "key", replacement_key)
        self._replace_state_file(
            metadata_path,
            (json.dumps(metadata, indent=2) + "\n").encode("utf-8"),
        )
        authority = SupervisionState(state_path)
        authority.close()

    def test_valid_supervision_state_changed_after_review_blocks_publication(self):
        from dotunnel.supervision_state import SupervisionState

        fixture = self._add_supervision(self._new_setup("changed-authority"))
        config_before = self._file_snapshot(fixture["config"])
        changed_state = []

        def answer(_prompt, count):
            if count == 4:
                self._change_to_a_different_valid_state(fixture["state_path"])
                changed_state.append(self._state_snapshot(fixture["state_path"]))
                return "y"
            return ""

        status, _stdout, stderr, _seen = self._run_existing(
            fixture,
            installed={},
            prompt_callback=answer,
        )

        self.assertEqual(status, 2, stderr)
        self.assertEqual(self._file_snapshot(fixture["config"]), config_before)
        self.assertEqual(self._state_snapshot(fixture["state_path"]), changed_state[0])
        authority = SupervisionState(fixture["state_path"])
        authority.close()


if __name__ == "__main__":
    unittest.main()
