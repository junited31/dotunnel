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

    def _codex_answers(self, runtime):
        return [
            str(runtime / "codex"),
            str(runtime / "codex-code-mode-host"),
            str(runtime / "auth.json"),
            "project",
            str(self.source),
            "sample.py",
            "sample.py",
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
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        config_path.chmod(0o600)
        return config

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

    def test_generated_job_config_and_request_use_existing_schema_and_safe_files(self):
        config_path = self._create_setup()
        key_info = (self.directory / "runtime-api-key").stat(follow_symlinks=False)
        key_before = (key_info.st_dev, key_info.st_ino, key_info.st_size, key_info.st_mtime_ns, key_info.st_ctime_ns)
        original = self._add_unrelated_config(config_path)
        profile_before = self._file_identity(self.directory / "profile.yaml")
        runtime = self.base / "runtime"
        executable = self._file(runtime / "codex", executable=True)
        companion = self._file(runtime / "codex-code-mode-host", executable=True)
        auth = self._file(runtime / "auth.json")
        wrapper = self._file(self.base / "bin" / "dotunnel", executable=True)
        bwrap = self._file(self.base / "bwrap", executable=True)
        installed = {"codex": Path("/unused/launcher")}
        answers = iter(self._codex_answers(runtime))
        with patch("shutil.which", return_value=str(wrapper)), patch.object(
            self.onboarding, "_BWRAP", bwrap
        ):
            self.onboarding.configure_integrations(
                self.directory,
                installed,
                {"codex"},
                prompt_fn=lambda _prompt: next(answers),
            )

        from dotunnel import cli_jobs

        final = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(final["root"], original["root"])
        self.assertEqual([task["name"] for task in final["tasks"]], ["existing_review", "dotunnel-codex"])
        task = final["tasks"][-1]
        job_path = self.directory / "cli-jobs" / "codex.json"
        self.assertEqual(task["argv"], [str(wrapper), "cli-job", "--config", str(job_path)])
        self.assertEqual(task["timeout_seconds"], 240)
        self.assertEqual(task["cwd"], ".")

        _loaded_path, job = cli_jobs._load_private_config(str(job_path))
        parsed = cli_jobs._parse_config_shape(job)
        self.assertEqual(parsed.backend, "codex")
        cli_jobs._validate_runtime_paths(parsed, job_path)
        cli_jobs._validate_target_roots(parsed.targets)
        request_path = self.directory / "workspace" / parsed.request
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
        key_after = (self.directory / "runtime-api-key").stat(follow_symlinks=False)
        self.assertEqual(
            key_before,
            (key_after.st_dev, key_after.st_ino, key_after.st_size, key_after.st_mtime_ns, key_after.st_ctime_ns),
        )

    def test_invalid_selected_runtime_does_not_publish_any_selection(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "good-auth.json")
        self._file(runtime / "claude", executable=True)
        (runtime / "unsafe-auth").symlink_to(runtime / "good-auth.json")
        bwrap = self._file(self.base / "bwrap", executable=True)
        wrapper = self._file(self.base / "bin" / "dotunnel", executable=True)
        answers = iter(self._codex_answers(runtime) + [
            str(runtime / "claude"),
            str(runtime / "unsafe-auth"),
            "project",
            str(self.source),
            "sample.py",
            "",
        ])
        with patch("shutil.which", return_value=str(wrapper)), patch.object(
            self.onboarding, "_BWRAP", bwrap
        ):
            with self.assertRaises(ValueError):
                self.onboarding.configure_integrations(
                    self.directory,
                    {"codex": Path("/unused/codex"), "claude": Path("/unused/claude")},
                    {"codex", "claude"},
                    prompt_fn=lambda _prompt: next(answers),
                )

        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "cli-jobs").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_invalid_editable_scope_is_rejected_before_registry_publication(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        wrapper = self._file(self.base / "bin" / "dotunnel", executable=True)
        bwrap = self._file(self.base / "bwrap", executable=True)
        answers = self._codex_answers(runtime)
        answers[-1] = "../outside.py"
        values = iter(answers)
        with patch("shutil.which", return_value=str(wrapper)), patch.object(
            self.onboarding, "_BWRAP", bwrap
        ):
            with self.assertRaises(ValueError):
                self.onboarding.configure_integrations(
                    self.directory,
                    {"codex": Path("/unused/codex")},
                    {"codex"},
                    prompt_fn=lambda _prompt: next(values),
                )

        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "cli-jobs").exists())

    def test_unsafe_config_link_is_refused_without_mutation(self):
        config_path = self._create_setup()
        original = config_path.read_bytes()
        linked = self.base / "outside-config.json"
        linked.write_bytes(original)
        linked.chmod(0o600)
        config_path.unlink()
        config_path.symlink_to(linked)
        with self.assertRaises(ValueError):
            self.onboarding.configure_integrations(
                self.directory, {"codex": Path("/unused/codex")}, set()
            )
        self.assertTrue(config_path.is_symlink())
        self.assertEqual(linked.read_bytes(), original)

    def test_existing_reconfiguration_checks_installed_integrations_and_preserves_unrelated_state(self):
        config_path = self._create_setup()
        original = self._add_unrelated_config(config_path)
        profile_before = self._file_identity(self.directory / "profile.yaml")
        key_info = (self.directory / "runtime-api-key").stat(follow_symlinks=False)
        key_before = (key_info.st_dev, key_info.st_ino, key_info.st_size, key_info.st_mtime_ns, key_info.st_ctime_ns)
        runtime = self.base / "runtime"
        for path in ("codex", "codex-code-mode-host", "claude"):
            self._file(runtime / path, executable=True)
        self._file(runtime / "auth.json")
        self._file(runtime / "oauth_token")
        bwrap = self._file(self.base / "bwrap", executable=True)
        wrapper = self._file(self.base / "bin" / "dotunnel", executable=True)
        installed = {"codex": Path("/unused/codex"), "claude": Path("/unused/claude")}
        initial_states = []
        selected = {"codex"}

        def selector(_installed, initially_selected):
            initial_states.append(set(initially_selected))
            return set(selected)

        codex_answers = iter(self._codex_answers(runtime))
        with patch("shutil.which", return_value=str(wrapper)), patch.object(
            self.onboarding, "_BWRAP", bwrap
        ):
            self.onboarding.configure_directory(
                self.directory,
                installed,
                selector_fn=selector,
                prompt_fn=lambda _prompt: next(codex_answers),
            )
            selected = {"claude"}
            claude_answers = iter((
                str(runtime / "claude"),
                str(runtime / "oauth_token"),
                "project",
                str(self.source),
                "sample.py",
                "",
            ))
            self.onboarding.configure_directory(
                self.directory,
                installed,
                selector_fn=selector,
                prompt_fn=lambda _prompt: next(claude_answers),
            )

        self.assertEqual(initial_states, [set(), {"codex"}])
        final = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(final["root"], original["root"])
        self.assertEqual([task["name"] for task in final["tasks"]], ["existing_review", "dotunnel-claude"])
        self.assertEqual(self._file_identity(self.directory / "profile.yaml"), profile_before)
        key_after = (self.directory / "runtime-api-key").stat(follow_symlinks=False)
        self.assertEqual(
            key_before,
            (key_after.st_dev, key_after.st_ino, key_after.st_size, key_after.st_mtime_ns, key_after.st_ctime_ns),
        )

    def test_cancelled_existing_selection_does_not_change_registry_or_create_files(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        result = self.onboarding.configure_directory(
            self.directory,
            {"codex": Path("/unused/codex")},
            selector_fn=lambda _installed, _initially_selected: None,
        )
        self.assertFalse(result)
        self.assertEqual(config_path.read_bytes(), before)
        self.assertFalse((self.directory / "cli-jobs").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_no_installed_cli_skips_selection_and_preserves_registry(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        output = io.StringIO()
        with patch.object(self.onboarding.sys, "stdout", output):
            result = self.onboarding.configure_directory(
                self.directory,
                {},
                selector_fn=lambda *_args: self.fail("selector must be skipped"),
            )
        self.assertTrue(result)
        self.assertIn("No installed Codex, Claude Code, or OMP CLI", output.getvalue())
        self.assertEqual(config_path.read_bytes(), before)

    def test_stale_registry_change_during_prompts_is_not_overwritten(self):
        config_path = self._create_setup()
        runtime = self.base / "runtime"
        self._file(runtime / "codex", executable=True)
        self._file(runtime / "codex-code-mode-host", executable=True)
        self._file(runtime / "auth.json")
        wrapper = self._file(self.base / "bin" / "dotunnel", executable=True)
        bwrap = self._file(self.base / "bwrap", executable=True)
        answers = iter(self._codex_answers(runtime))
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
            return next(answers)

        with patch("shutil.which", return_value=str(wrapper)), patch.object(
            self.onboarding, "_BWRAP", bwrap
        ):
            with self.assertRaisesRegex(ValueError, "registry changed"):
                self.onboarding.configure_integrations(
                    self.directory,
                    {"codex": Path("/unused/codex")},
                    {"codex"},
                    prompt_fn=prompt,
                )

        final = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual([task["name"] for task in final["tasks"]], ["concurrent_task"])
        self.assertFalse((self.directory / "cli-jobs").exists())
        self.assertFalse((self.directory / "workspace" / "dotunnel-requests").exists())

    def test_cancelled_setup_exits_without_changing_existing_registry(self):
        config_path = self._create_setup()
        before = config_path.read_bytes()
        profile_before = self._file_identity(self.directory / "profile.yaml")
        key_before = self._file_identity(self.directory / "runtime-api-key")
        with patch.object(self.onboarding.integrations, "discover_clis", return_value={
            "codex": Path("/unused/codex"),
        }), patch.object(self.onboarding, "select_clis", return_value=None):
            result = self.onboarding.main(["--directory", str(self.directory)])

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
        with self.assertRaises(ValueError):
            self.onboarding.configure_integrations(
                self.directory, {"codex": Path("/unused/codex")}, set()
            )
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
            "request": "dotunnel-requests/claude.json",
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
                    self.directory / "cli-jobs" / "claude.json", "claude",
                    self.directory / "workspace", value, request, bwrap_path=bwrap,
                )



if __name__ == "__main__":
    unittest.main()
