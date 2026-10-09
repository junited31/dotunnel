

import importlib
import io
import json
import os
import pty
import stat
import tempfile
import termios
import threading
import time
import unittest
from contextlib import ExitStack

from pathlib import Path
from unittest.mock import patch


TUNNEL = "tunnel_" + "2" * 32
SYNTHETIC_KEY = "synthetic-onboarding-key-never-used-for-provider-auth"


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.directory = self.base / "private setup"
        self.source = self.base / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "sample.py").write_text("value = 1\n", encoding="utf-8")
        self.setup_module = importlib.import_module("dotunnel.setup")
        self.onboarding = importlib.import_module("dotunnel.onboarding")
        self.integrations = importlib.import_module("dotunnel.integrations")

    def _create_setup(self):
        self.setup_module.create_artifacts(self.directory, TUNNEL, SYNTHETIC_KEY)
        return self.directory / "config.json"

    def _file(self, path, *, executable=False, mode=None):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"synthetic runtime fixture\n")
        path.chmod(mode if mode is not None else (0o700 if executable else 0o600))
        return path

    def _file_identity(self, path):
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
        )

    class _Terminal(io.StringIO):
        def isatty(self):
            return True

    def _run_main(
        self,
        directory,
        client,
        answers=(),
        *,
        installed=None,
        selected=None,
        prompt_callback=None,
    ):
        responses = iter(answers)
        stdout, stderr = self._Terminal(), self._Terminal()
        wrapper = self._file(self.base / "bin" / "dotunnel", executable=True)

        def answer(prompt):
            if prompt_callback is not None:
                return prompt_callback(prompt)
            return next(responses)

        def inspect_launcher(candidate):
            return wrapper if Path(candidate).name == "dotunnel" else client

        def choose(available, initially_selected):
            if callable(selected):
                return selected(available, initially_selected)
            return None if selected is None else set(selected)

        with ExitStack() as stack:
            stack.enter_context(patch.object(self.onboarding.sys, "platform", "linux"))
            stack.enter_context(patch.object(self.onboarding.os, "getuid", return_value=os.getuid()))
            stack.enter_context(patch.object(self.onboarding.sys, "stdin", self._Terminal()))
            stack.enter_context(patch.object(self.onboarding.sys, "stdout", stdout))
            stack.enter_context(patch.object(self.onboarding.sys, "stderr", stderr))
            stack.enter_context(patch("builtins.input", side_effect=answer))
            stack.enter_context(patch.object(self.integrations, "_inspect_launcher", side_effect=inspect_launcher))
            stack.enter_context(patch.object(
                self.integrations, "discover_clis", return_value=dict(installed or {}),
            ))
            stack.enter_context(patch.object(
                self.integrations, "bubblewrap_status", return_value="ready",
            ))
            stack.enter_context(patch.object(self.integrations, "_check_bwrap"))
            stack.enter_context(patch.object(self.onboarding, "select_clis", side_effect=choose))
            stack.enter_context(patch.object(self.onboarding, "_require_stopped_client"))
            stack.enter_context(patch.object(
                self.onboarding, "_confirm_no_other_client", return_value=True,
            ))
            stack.enter_context(patch.object(self.setup_module, "_doctor"))
            stack.enter_context(patch("shutil.which", return_value=str(wrapper)))
            result = self.onboarding.main([
                "--directory", str(directory), "--tunnel-client", str(client),
            ])
        return result, stdout.getvalue(), stderr.getvalue()


    def _codex_answers(self, runtime):
        return [
            str(runtime / "codex"),
            str(runtime / "codex-code-mode-host"),
            str(runtime / "auth.json"),
            "project",
            str(self.source),
            "sample.py",
            "sample.py",
            "y",
        ]

    def _add_unrelated_config(self, config_path):
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["tasks"].append({
            "name": "existing_review",
            "description": "Existing unrelated task",
            "argv": [str(self._file(self.base / "existing-task", executable=True))],
            "cwd": ".",
            "timeout_seconds": 90,
        })
        from dotunnel.config import load_config
        from dotunnel.supervision_state import SupervisionState
        state = self.base / "supervision-state"
        executable = str(self._file(self.base / "herdr", executable=True))
        config["supervision"] = {
            "state_dir": str(state),
            "connections": [{"id": "isolated", "backend": "herdr", "executable": executable, "session": "fixture"}],
            "projects": [{
                "id": "supervised",
                "path": str(self.source),
                "connections": ["isolated"],
                "profiles": ["codex"],
                "allowed_actions": [],
                "profile_actions": {"codex": []},
            }],
            "profiles": [{"id": "codex", "kind": "codex", "executable": executable, "backends": ["herdr"]}],
        }
        initialized = SupervisionState.initialize(state)
        self.supervision_epoch = initialized.epoch
        initialized.close()
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        config_path.chmod(0o600)
        loaded = load_config(config_path)
        authority = SupervisionState(state)
        try:
            authority.set_approval("isolated:supervised", loaded.supervision.generation, True)
        finally:
            authority.close()
        return config

    def _assert_supervision_authority_preserved(self, config_path):
        from dotunnel.config import load_config
        from dotunnel.supervision_state import SupervisionState
        settings = load_config(config_path).supervision
        self.assertIsNotNone(settings)
        authority = SupervisionState(settings.state_dir)
        try:
            self.assertEqual(authority.epoch, self.supervision_epoch)
            self.assertTrue(authority.approved("isolated:supervised", settings.generation))
        finally:
            authority.close()

    def test_discovery_finds_only_safe_installed_launchers_without_running_them(self):
        bin_dir = self.base / "bin"
        bin_dir.mkdir(mode=0o700)
        marker = self.base / "launcher-ran"
        for name in ("codex", "claude-real", "omp", "unrelated"):
            launcher = bin_dir / name
            launcher.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            launcher.chmod(0o700)
        (bin_dir / "claude").symlink_to(bin_dir / "claude-real")
        (bin_dir / "not-executable").write_text("not executable\n", encoding="utf-8")
        (bin_dir / "not-executable").chmod(0o600)

        with patch.dict(os.environ, {"PATH": str(bin_dir)}):
            found = self.integrations.discover_clis()

        self.assertEqual(set(found), {"codex", "claude", "omp"})
        self.assertEqual(found["claude"], (bin_dir / "claude-real").resolve())
        self.assertFalse(marker.exists())

    def test_selector_space_toggles_focused_item_and_enter_accepts_selection(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        original = termios.tcgetattr(slave)
        stdin = os.fdopen(os.dup(slave), "r", encoding="utf-8")
        self.addCleanup(stdin.close)

        def send_keys():
            time.sleep(0.05)
            os.write(master, b"\x1b[B \x1b[A \r")

        sender = threading.Thread(target=send_keys)
        sender.start()
        with patch.object(self.onboarding.sys, "stdin", stdin), patch.object(
            self.onboarding.sys, "stdout", io.StringIO()
        ):
            selected = self.onboarding.select_clis(
                {"codex": Path("/bin/codex"), "claude": Path("/bin/claude")},
                initially_selected={"claude"},
            )
        sender.join(timeout=2)

        self.assertEqual(selected, {"codex"})
        self.assertEqual(termios.tcgetattr(slave), original)

    def test_selector_escape_and_ctrl_c_cancel_and_restore_terminal(self):
        for key in (b"\x1b", b"\x03"):
            with self.subTest(key=key):
                master, slave = pty.openpty()
                original = termios.tcgetattr(slave)
                stdin = os.fdopen(os.dup(slave), "r", encoding="utf-8")
                sender = threading.Thread(target=lambda: (time.sleep(0.05), os.write(master, key)))
                sender.start()
                with patch.object(self.onboarding.sys, "stdin", stdin), patch.object(
                    self.onboarding.sys, "stdout", io.StringIO()
                ):
                    result = self.onboarding.select_clis({"codex": Path("/bin/codex")})
                sender.join(timeout=2)
                stdin.close()
                self.assertIsNone(result)
                self.assertEqual(termios.tcgetattr(slave), original)
                os.close(master)
                os.close(slave)

    def test_selector_refuses_non_tty_instead_of_accepting_defaults(self):
        with patch.object(self.onboarding.sys, "stdin", open(os.devnull, "r", encoding="utf-8")) as stdin:
            self.addCleanup(stdin.close)
            with self.assertRaises(ValueError):
                self.onboarding.select_clis({"codex": Path("/bin/codex")})

    def test_selector_terminal_hangup_fails_closed(self):
        master, slave = pty.openpty()
        stdin = os.fdopen(os.dup(slave), "r", encoding="utf-8")

        def close_master():
            time.sleep(0.05)
            os.close(master)

        sender = threading.Thread(target=close_master)
        sender.start()
        with patch.object(self.onboarding.sys, "stdin", stdin), patch.object(
            self.onboarding.sys, "stdout", io.StringIO()
        ):
            with self.assertRaises(ValueError):
                self.onboarding.select_clis({"codex": Path("/bin/codex")})
        sender.join(timeout=2)
        stdin.close()
        os.close(slave)

    def test_generated_job_config_and_request_use_immutable_generation_and_safe_files(self):
        config_path = self._create_setup()
        original = self._add_unrelated_config(config_path)
        profile_before = self._file_identity(self.directory / "profile.yaml")
        key_before = self._file_identity(self.directory / "runtime-api-key")
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        client = self._file(self.base / "tunnel-client", executable=True)
        answers = ["", "", ""] + self._codex_answers(runtime) + ["y", ""]

        status, _stdout, stderr = self._run_main(
            self.directory,
            client,
            answers,
            installed={"codex": Path("/unused/launcher")},
            selected={"codex"},
        )
        self.assertEqual(status, 0, stderr)

        from dotunnel import cli_jobs

        final = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(final["root"], original["root"])
        self.assertEqual([task["name"] for task in final["tasks"]], ["existing_review", "dotunnel-codex"])
        task = final["tasks"][-1]
        job_path = Path(task["argv"][3])
        self.assertEqual(job_path.relative_to(self.directory).parts[0], "native-cli")
        generation = job_path.parent.name
        self.assertTrue(generation)
        self.assertEqual(job_path.name, "codex.json")
        self.assertEqual(task["timeout_seconds"], 240)
        self.assertEqual(task["cwd"], ".")
        self.assertEqual(Path(task["argv"][0]).name, "dotunnel")
        self.assertEqual(task["argv"][1:3], ["cli-job", "--config"])
        self.assertEqual(final["file_access"], {
            "read": [{
                "path": f"dotunnel-requests/{generation}/codex.json",
                "kind": "file",
            }],
            "write": [{
                "path": f"dotunnel-requests/{generation}/codex.json",
                "kind": "file",
            }],
        })

        _loaded_path, job = cli_jobs._load_private_config(str(job_path))
        parsed = cli_jobs._parse_config_shape(job)
        self.assertEqual(parsed.backend, "codex")
        cli_jobs._validate_runtime_paths(parsed, job_path)
        cli_jobs._validate_target_roots(parsed.targets)
        request_path = self.directory / "workspace" / parsed.request
        self.assertEqual(parsed.request, f"dotunnel-requests/{generation}/codex.json")
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual(request["target"], "project")
        self.assertEqual(request["mode"], "review")
        self.assertTrue(request["instruction"])
        for path in (job_path, request_path):
            info = path.stat(follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(self._file_identity(self.directory / "profile.yaml"), profile_before)
        self.assertEqual(self._file_identity(self.directory / "runtime-api-key"), key_before)

    def test_declining_exact_request_file_grants_prevents_job_artifacts(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        client = self._file(self.base / "tunnel-client", executable=True)
        answers = ["", "", ""] + self._codex_answers(runtime)[:-1] + ["n"]

        status, _stdout, _stderr = self._run_main(
            self.directory,
            client,
            answers,
            installed={"codex": Path("/unused/launcher")},
            selected={"codex"},
        )
        self.assertEqual(status, 130)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "native-cli").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_invalid_selected_runtime_does_not_publish_any_selection(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "good-auth.json")
        self._file(runtime / "claude", executable=True)
        (runtime / "unsafe-auth").symlink_to(runtime / "good-auth.json")
        client = self._file(self.base / "tunnel-client", executable=True)
        answers = ["", "", ""] + self._codex_answers(runtime)[:-1] + [
            str(runtime / "claude"),
            str(runtime / "unsafe-auth"),
            "project",
            str(self.source),
            "sample.py",
            "",
        ]

        status, _stdout, stderr = self._run_main(
            self.directory,
            client,
            answers,
            installed={
                "codex": Path("/unused/codex"),
                "claude": Path("/unused/claude"),
            },
            selected={"codex", "claude"},
        )
        self.assertEqual(status, 2)
        self.assertIn("Setup failed", stderr)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "native-cli").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_invalid_editable_scope_is_rejected_before_registry_publication(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        client = self._file(self.base / "tunnel-client", executable=True)
        answers = ["", "", ""] + self._codex_answers(runtime)
        answers[3 + 6] = "../outside.py"

        status, _stdout, stderr = self._run_main(
            self.directory,
            client,
            answers,
            installed={"codex": Path("/unused/launcher")},
            selected={"codex"},
        )
        self.assertEqual(status, 2)
        self.assertIn("Setup failed", stderr)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "native-cli").exists())

    def test_unsafe_config_link_is_refused_without_mutation(self):
        config_path = self._create_setup()
        original = config_path.read_bytes()
        linked = self.base / "outside-config.json"
        linked.write_bytes(original)
        linked.chmod(0o600)
        config_path.unlink()
        config_path.symlink_to(linked)
        client = self._file(self.base / "tunnel-client", executable=True)

        status, _stdout, _stderr = self._run_main(self.directory, client)
        self.assertEqual(status, 2)
        self.assertTrue(config_path.is_symlink())
        self.assertEqual(linked.read_bytes(), original)

    def test_reconfiguration_preserves_unrelated_state_and_old_generation(self):
        config_path = self._create_setup()
        original = self._add_unrelated_config(config_path)
        profile_before = self._file_identity(self.directory / "profile.yaml")
        key_before = self._file_identity(self.directory / "runtime-api-key")
        runtime = self.base / "runtime"
        for path in ("codex", "codex-code-mode-host", "claude"):
            self._file(runtime / path, executable=True)
        self._file(runtime / "auth.json")
        self._file(runtime / "oauth_token")
        client = self._file(self.base / "tunnel-client", executable=True)
        installed = {"codex": Path("/unused/codex"), "claude": Path("/unused/claude")}
        initial_states = []
        selections = iter(({"codex"}, {"claude"}))

        def selector(_installed, initially_selected):
            initial_states.append(set(initially_selected))
            return next(selections)

        first_answers = ["", "", ""] + self._codex_answers(runtime) + ["y", ""]
        first_status, _stdout, first_stderr = self._run_main(
            self.directory,
            client,
            first_answers,
            installed=installed,
            selected=selector,
        )
        self.assertEqual(first_status, 0, first_stderr)
        first_config = json.loads(config_path.read_text(encoding="utf-8"))
        codex_task = next(task for task in first_config["tasks"] if task["name"] == "dotunnel-codex")
        old_job_path = Path(codex_task["argv"][3])
        old_request_path = self.directory / "workspace" / f"dotunnel-requests/{old_job_path.parent.name}/codex.json"
        old_job = old_job_path.read_bytes()
        old_request = old_request_path.read_bytes()

        claude_answers = [
            str(runtime / "claude"),
            str(runtime / "oauth_token"),
            "project",
            str(self.source),
            "sample.py",
            "",
            "y",
        ]
        second_answers = ["", "", ""] + claude_answers + ["y", ""]
        second_status, _stdout, second_stderr = self._run_main(
            self.directory,
            client,
            second_answers,
            installed=installed,
            selected=selector,
        )
        self.assertEqual(second_status, 0, second_stderr)

        final = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(final["root"], original["root"])
        self.assertEqual(final["supervision"], original["supervision"])
        self._assert_supervision_authority_preserved(config_path)
        self.assertEqual([task["name"] for task in final["tasks"]], ["existing_review", "dotunnel-claude"])
        claude_task = final["tasks"][-1]
        claude_path = Path(claude_task["argv"][3])
        self.assertEqual(claude_path.relative_to(self.directory).parts[0], "native-cli")
        request_rules = {rule["path"] for rule in final["file_access"]["read"]}
        self.assertIn(
            f"dotunnel-requests/{claude_path.parent.name}/claude.json",
            request_rules,
        )
        self.assertTrue(old_job_path.exists())
        self.assertEqual(old_job_path.read_bytes(), old_job)
        self.assertTrue(old_request_path.exists())
        self.assertEqual(old_request_path.read_bytes(), old_request)
        self.assertEqual(self._file_identity(self.directory / "profile.yaml"), profile_before)
        self.assertEqual(self._file_identity(self.directory / "runtime-api-key"), key_before)
        self.assertEqual(initial_states, [set(), {"codex"}])

    def test_failed_registry_replace_keeps_active_generation_untouched(self):
        config_path = self._create_setup()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        client = self._file(self.base / "tunnel-client", executable=True)
        first_status, _stdout, first_stderr = self._run_main(
            self.directory,
            client,
            ["", "", ""] + self._codex_answers(runtime) + ["y", ""],
            installed={"codex": Path("/unused/codex")},
            selected={"codex"},
        )
        self.assertEqual(first_status, 0, first_stderr)

        original_document = config_path.read_bytes()
        config = json.loads(original_document)
        task = next(task for task in config["tasks"] if task["name"] == "dotunnel-codex")
        old_job_path = Path(task["argv"][3])
        old_job = old_job_path.read_bytes()
        old_request_path = self.directory / "workspace" / f"dotunnel-requests/{old_job_path.parent.name}/codex.json"
        old_request = old_request_path.read_bytes()
        alternate_workspace = self.base / "alternate-workspace"
        alternate_workspace.mkdir(mode=0o700)
        answers = ["e", str(alternate_workspace), "", ""] + self._codex_answers(runtime) + ["y"]
        original_rename = os.rename

        def fail_config_replace(source, destination, *args, **kwargs):
            if destination == "config.json":
                raise OSError("injected registry publication failure")
            return original_rename(source, destination, *args, **kwargs)

        with patch("os.rename", side_effect=fail_config_replace):
            status, _stdout, stderr = self._run_main(
                self.directory,
                client,
                answers,
                installed={"codex": Path("/unused/codex")},
                selected={"codex"},
            )

        self.assertEqual(status, 2)
        self.assertIn("registry could not be updated", stderr)
        self.assertEqual(config_path.read_bytes(), original_document)
        self.assertEqual(old_job_path.read_bytes(), old_job)
        self.assertEqual(old_request_path.read_bytes(), old_request)
        self.assertEqual(
            {path.name for path in (self.directory / "native-cli").iterdir()},
            {old_job_path.parent.name},
        )
        self.assertFalse((alternate_workspace / "dotunnel-requests").exists())


    def test_cancelled_existing_selection_does_not_change_registry_or_create_files(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        client = self._file(self.base / "tunnel-client", executable=True)
        status, _stdout, _stderr = self._run_main(
            self.directory,
            client,
            ["", "", ""],
            installed={"codex": Path("/unused/codex")},
            selected=None,
        )
        self.assertEqual(status, 130)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "native-cli").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_no_installed_cli_skips_selection_and_preserves_registry(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        client = self._file(self.base / "tunnel-client", executable=True)
        status, stdout, _stderr = self._run_main(
            self.directory,
            client,
            ["", "", "", ""],
            installed={},
        )
        self.assertEqual(status, 130)
        self.assertIn("No installed Codex, Claude Code, or OMP CLI", stdout)
        self.assertEqual(config_path.read_bytes(), before)

    def test_stale_registry_change_during_prompts_is_not_overwritten(self):
        config_path = self._create_setup()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        client = self._file(self.base / "tunnel-client", executable=True)
        responses = iter(["", "", ""] + self._codex_answers(runtime) + ["y", "y"])
        changed = False

        def prompt(_label):
            nonlocal changed
            if not changed:
                config = json.loads(config_path.read_text(encoding="utf-8"))
                config["tasks"].append({
                    "name": "concurrent_task",
                    "description": "Concurrent unrelated task",
                    "argv": [str(self._file(self.base / "concurrent-task", executable=True))],
                    "cwd": ".",
                    "timeout_seconds": 60,
                })
                config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
                config_path.chmod(0o600)
                changed = True
            return next(responses)

        status, _stdout, stderr = self._run_main(
            self.directory,
            client,
            installed={"codex": Path("/unused/codex")},
            selected={"codex"},
            prompt_callback=prompt,
        )
        final = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(status, 2)
        self.assertIn("registry changed", stderr)
        self.assertEqual([task["name"] for task in final["tasks"]], ["concurrent_task"])
        self.assertFalse((self.directory / "native-cli").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_existing_setup_rejects_piped_default_yes_before_admin_checks(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        stdout = self._Terminal()
        stderr = self._Terminal()
        with patch.object(self.onboarding.sys, "platform", "linux"), patch.object(
            self.onboarding.os, "getuid", return_value=os.getuid()
        ), patch.object(self.onboarding.sys, "stdin", io.StringIO("\n")), patch.object(
            self.onboarding.sys, "stdout", stdout
        ), patch.object(self.onboarding.sys, "stderr", stderr), patch.object(
            self.integrations, "discover_clis"
        ) as discover, patch.object(
            self.integrations, "bubblewrap_status"
        ) as bubblewrap_status, patch.object(
            self.integrations, "sudo_available"
        ) as sudo_available, patch.object(
            self.integrations, "install_bubblewrap"
        ) as install_bubblewrap:
            result = self.onboarding.main(["--directory", str(self.directory)])

        self.assertEqual(result, 2)
        discover.assert_not_called()
        bubblewrap_status.assert_not_called()
        sudo_available.assert_not_called()
        install_bubblewrap.assert_not_called()
        self.assertEqual(config_path.read_bytes(), before)

    def test_new_setup_validation_failure_returns_without_registry_state(self):
        directory = self.base / "new setup"

        class Terminal(io.StringIO):
            def isatty(self):
                return True

        stdout = Terminal()
        stderr = Terminal()
        with patch.object(self.onboarding.sys, "platform", "linux"), patch.object(
            self.onboarding.os, "getuid", return_value=os.getuid()
        ), patch.object(self.onboarding.sys, "stdin", Terminal()), patch.object(
            self.onboarding.sys, "stdout", stdout
        ), patch.object(self.onboarding.sys, "stderr", stderr), patch.object(
            self.onboarding.integrations, "_inspect_launcher", return_value=None
        ):
            result = self.onboarding.main([
                "--directory", str(directory), "--tunnel-client", "/missing/client",
            ])

        self.assertEqual(result, 2)
        self.assertIn("Setup failed", stderr.getvalue())
        self.assertFalse(directory.exists())

    def test_replaced_private_parent_is_revalidated_before_approval(self):
        parent = self.base / "setup-parent"
        parent.mkdir(mode=0o700)
        replacement_parent = self.base / "replacement-parent"
        replacement_parent.mkdir(mode=0o700)
        moved_parent = self.base / "moved-parent"
        directory = parent / "private"
        client = self._file(self.base / "tunnel-client", executable=True)
        responses = iter(("", "", "", "", ""))

        def choose_without_jobs(_available, _initially_selected, _directory, *, on_skip=None):
            parent.rename(moved_parent)
            parent.symlink_to(replacement_parent, target_is_directory=True)
            return set()

        def prompt(label):
            if label.startswith("I approve this exact permission setup"):
                return "n"
            return next(responses)

        with patch.object(
            self.onboarding, "_choose_fixed_jobs", side_effect=choose_without_jobs,
        ):
            status, _stdout, stderr = self._run_main(
                directory,
                client,
                prompt_callback=prompt,
                installed={},
            )

        self.assertEqual(status, 2)
        self.assertTrue(parent.is_symlink())
        self.assertFalse((moved_parent / "private").exists())
        self.assertFalse((replacement_parent / "private").exists())

    def test_cancelled_setup_exits_without_changing_existing_registry(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        profile_before = self._file_identity(self.directory / "profile.yaml")
        key_before = self._file_identity(self.directory / "runtime-api-key")
        client = self._file(self.base / "tunnel-client", executable=True)

        result, _stdout, _stderr = self._run_main(
            self.directory,
            client,
            ["", "", "", ""],
            installed={},
        )
        self.assertEqual(result, 130)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertEqual(self._file_identity(self.directory / "profile.yaml"), profile_before)
        self.assertEqual(self._file_identity(self.directory / "runtime-api-key"), key_before)

    def test_reserved_task_name_collision_is_refused(self):
        config_path = self._create_setup()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["tasks"].append({
            "name": "dotunnel-codex",
            "description": "Not a setup-owned task",
            "argv": ["/usr/bin/true"],
        })
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_path.chmod(0o600)
        before = config_path.read_bytes()
        client = self._file(self.base / "tunnel-client", executable=True)

        result, _stdout, _stderr = self._run_main(self.directory, client)
        self.assertEqual(result, 2)
        self.assertEqual(config_path.read_bytes(), before)

    def test_runtime_reference_under_group_writable_parent_is_rejected(self):
        runtime = self.base / "shared-runtime"
        executable = self._file(runtime / "codex", executable=True)
        companion = self._file(runtime / "codex-code-mode-host", executable=True)
        auth = self._file(runtime / "auth.json")
        runtime.chmod(0o770)
        with self.assertRaises(ValueError):
            self.integrations._check_runtime_metadata("codex", {
                "executable": str(executable),
                "companion": str(companion),
                "auth": str(auth),
            })


    def test_allowed_source_cannot_include_runtime_credential_reference(self):
        self._create_setup()
        executable = self._file(self.base / "runtime" / "claude", executable=True)
        token = self._file(self.source / "notes.txt")
        bwrap = self._file(self.base / "bwrap", executable=True)
        value = {
            "backend": "claude",
            "workspace": str(self.directory / "workspace"),
            "request": "dotunnel-requests/fixture-generation/claude.json",
            "runtime": {"executable": str(executable), "oauth_token": str(token)},
            "targets": {"project": {
                "root": str(self.source), "files": ["notes.txt"], "editable": [],
            }},
        }
        request = json.dumps({"target": "project", "mode": "review", "instruction": "Review"})
        with patch.object(self.integrations.WorkspaceFiles, "read_file",
                          side_effect=AssertionError("Credential contents must not be opened")):
            with self.assertRaises(ValueError):
                self.integrations._validate_job_data(
                    self.directory / "native-cli" / "fixture-generation" / "claude.json",
                    "claude",
                    self.directory / "workspace",
                    value,
                    request,
                    bwrap_path=bwrap,
                )



if __name__ == "__main__":
    unittest.main()
