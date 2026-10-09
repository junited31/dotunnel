"""Initial-config publication fault regressions for operator onboarding."""

import io
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


TUNNEL = "tunnel_" + "7" * 32
SYNTHETIC_KEY = "synthetic-initial-publication-key"


class Terminal(io.StringIO):
    def isatty(self):
        return True


class InitialPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.directory = self.base / "private setup"
        self.workspace = self.directory / "workspace"
        self.source = self.base / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "sample.py").write_text("value = 1\n", encoding="utf-8")
        self.runtime = self.base / "runtime"
        self.codex = self._file(self.runtime / "codex", executable=True)
        self.code_mode_host = self._file(self.runtime / "codex-code-mode-host", executable=True)
        self.auth = self._file(self.runtime / "auth.json")
        self.client = self._file(self.base / "tunnel-client", executable=True)
        self.herdr = self._file(self.base / "herdr", executable=True)
        self.dotunnel = self._file(self.base / "bin" / "dotunnel", executable=True)
        self.start_marker = self.base / "client-started"
        from dotunnel import integrations, onboarding, setup

        self.integrations = integrations
        self.onboarding = onboarding
        self.setup = setup

    def _file(self, path, *, executable=False):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text("synthetic fixture\n", encoding="utf-8")
        path.chmod(0o700 if executable else 0o600)
        return path

    def _run_onboarding(self, fault):
        answers = iter([
            "",  # new dedicated workspace (default)
            "",  # default private workspace path
            "",  # no MCP read rules
            "",  # no MCP write rules
            "y",  # configure synthetic, observation-only live supervision
            "herdr",
            "",  # local Herdr session
            "codex",
            "",  # compatible live executable policy
            str(self.source),
            "",  # default project identifier
            "",  # no live actions
            "",  # no profile actions
            "y",  # mark the project protected
            str(self.codex),
            str(self.code_mode_host),
            str(self.auth),
            "project",
            str(self.source),
            "sample.py",
            "sample.py",
            "y",  # allow exact request-file access
            "y",  # approve setup publication
            "y",  # approve initialization of new supervision state
            TUNNEL,
            "y",  # if publication were treated as certain, expose an accidental start
        ])
        stdout, stderr = Terminal(), Terminal()
        state = {"config_rename_attempted": False, "config_renamed": False,
                 "directory_fsync_failed": False, "readback_failed": False}
        real_rename, real_fsync, real_open = os.rename, os.fsync, os.open

        def rename(source, destination, *args, **kwargs):
            is_initial_config = (
                destination == "config.json"
                and isinstance(source, str)
                and source.startswith(".config.json.")
            )
            if not is_initial_config:
                return real_rename(source, destination, *args, **kwargs)
            state["config_rename_attempted"] = True
            if fault == "before-rename":
                raise OSError("injected failure before initial config rename")
            from dotunnel.supervision_state import SupervisionState
            authority = SupervisionState(self.directory / "supervision")
            try:
                state["expected_epoch"] = authority.epoch
            finally:
                authority.close()
            result = real_rename(source, destination, *args, **kwargs)
            state["config_renamed"] = True
            return result

        def fsync(fd):
            if state["config_renamed"] and not state["directory_fsync_failed"]:
                state["directory_fsync_failed"] = True
                raise OSError("injected directory durability failure after config rename")
            return real_fsync(fd)

        def open_file(file, *args, **kwargs):
            if state["config_renamed"] and file == "config.json":
                state["readback_failed"] = True
                raise PermissionError("injected unsafe initial-config readback")
            return real_open(file, *args, **kwargs)

        def inspect_launcher(candidate):
            candidate = Path(candidate)
            if candidate == self.client:
                return self.client
            if candidate == self.dotunnel:
                return self.dotunnel
            if candidate == self.herdr:
                return self.herdr
            return None

        def which(name):
            return {"codex": self.codex, "herdr": self.herdr, "dotunnel": self.dotunnel}.get(name)

        def fake_foreground(*_args):
            self.start_marker.write_text("started\n", encoding="utf-8")
            return 0

        with ExitStack() as stack:
            stack.enter_context(patch.object(self.onboarding.sys, "platform", "linux"))
            uid = os.getuid()
            stack.enter_context(patch.object(self.onboarding.os, "getuid", return_value=uid))
            stack.enter_context(patch.object(self.onboarding.sys, "stdin", Terminal()))
            stack.enter_context(patch.object(self.onboarding.sys, "stdout", stdout))
            stack.enter_context(patch.object(self.onboarding.sys, "stderr", stderr))
            stack.enter_context(patch("builtins.input", side_effect=lambda _prompt: next(answers)))
            stack.enter_context(patch.object(self.integrations, "_inspect_launcher", side_effect=inspect_launcher))
            stack.enter_context(patch.object(
                self.integrations, "discover_clis", return_value={"codex": self.codex},
            ))
            stack.enter_context(patch.object(self.integrations, "bubblewrap_status", return_value="ready"))
            stack.enter_context(patch.object(self.integrations, "_check_bwrap"))
            stack.enter_context(patch.object(self.onboarding, "_choose_fixed_jobs", return_value={"codex"}))
            stack.enter_context(patch.object(self.onboarding, "_require_stopped_client"))
            stack.enter_context(patch.object(self.onboarding, "_confirm_no_other_client", return_value=True))
            stack.enter_context(patch.object(self.setup, "read_key", return_value=SYNTHETIC_KEY))
            stack.enter_context(patch.object(self.setup, "_doctor"))
            stack.enter_context(patch.object(self.setup, "_foreground", side_effect=fake_foreground))
            stack.enter_context(patch("shutil.which", side_effect=which))
            stack.enter_context(patch("os.rename", side_effect=rename))
            stack.enter_context(patch("os.fsync", side_effect=fsync))
            stack.enter_context(patch("os.open", side_effect=open_file))
            status = self.onboarding.main([
                "--directory", str(self.directory), "--tunnel-client", str(self.client),
            ])
        return status, stdout.getvalue(), stderr.getvalue(), state

    def _assert_published_references_are_usable(self, document, expected_epoch):
        from dotunnel import cli_jobs
        from dotunnel.config import load_config
        from dotunnel.supervision_state import SupervisionState

        config_path = self.directory / "config.json"
        self.assertTrue(self.workspace.is_dir(), "published workspace reference was removed")
        config = load_config(config_path)
        self.assertEqual(config.root, self.workspace)
        self.assertIsNotNone(config.supervision)
        self.assertEqual(self.workspace.stat(follow_symlinks=False).st_mode & 0o777, 0o700)
        self.assertTrue((self.directory / "profile.yaml").is_file())
        self.assertTrue((self.directory / "runtime-api-key").is_file())

        tasks = document["tasks"]
        self.assertEqual([task["name"] for task in tasks], ["dotunnel-codex"])
        job_path = Path(tasks[0]["argv"][3])
        self.assertTrue(job_path.is_file())
        _loaded_path, job = cli_jobs._load_private_config(str(job_path))
        parsed = cli_jobs._parse_config_shape(job)
        cli_jobs._validate_runtime_paths(parsed, job_path)
        cli_jobs._validate_target_roots(parsed.targets)
        request_path = self.workspace / parsed.request
        self.assertTrue(request_path.is_file())

        state_path = Path(document["supervision"]["state_dir"])
        self.assertTrue(state_path.is_dir())
        authority = SupervisionState(state_path)
        try:
            self.assertEqual(authority.epoch, expected_epoch)
        finally:
            authority.close()

    def test_post_rename_directory_fsync_and_unsafe_readback_preserve_published_references(self):
        status, _stdout, _stderr, fault = self._run_onboarding("after-rename")

        self.assertTrue(fault["config_rename_attempted"])
        self.assertTrue(fault["config_renamed"])
        self.assertTrue(fault["directory_fsync_failed"])
        self.assertEqual(status, 2)
        self.assertTrue((self.directory / "config.json").is_file())
        document = json.loads((self.directory / "config.json").read_text(encoding="utf-8"))
        self._assert_published_references_are_usable(document, fault["expected_epoch"])
        self.assertFalse(self.start_marker.exists())

    def test_failure_before_initial_rename_cleans_unpublished_artifacts(self):
        status, _stdout, _stderr, fault = self._run_onboarding("before-rename")

        self.assertTrue(fault["config_rename_attempted"])
        self.assertFalse(fault["config_renamed"])
        self.assertFalse(fault["directory_fsync_failed"])
        self.assertEqual(status, 2)
        self.assertFalse((self.directory / "config.json").exists())
        self.assertFalse(self.workspace.exists())
        self.assertFalse((self.directory / "native-cli").exists())
        self.assertFalse((self.directory / "supervision").exists())
        self.assertFalse(self.start_marker.exists())


if __name__ == "__main__":
    unittest.main()
