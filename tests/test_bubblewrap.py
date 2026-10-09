"""Bubblewrap is required only for optional CLI integrations; setup checks it up front."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dotunnel import integrations


class BubblewrapStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)

    def executable(self, body):
        path = self.base / "bwrap"
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_missing_executable_is_missing(self):
        self.assertEqual(integrations.bubblewrap_status(self.base / "absent"), "missing")

    def test_present_but_namespace_probe_failure_is_unusable(self):
        bwrap = self.executable("echo 'setting up uid map: Permission denied' >&2; exit 1")
        self.assertEqual(integrations.bubblewrap_status(bwrap), "unusable")

    def test_successful_isolated_probe_is_ready(self):
        marker = self.base / "args"
        bwrap = self.executable(f'printf "%s\\n" "$@" > {marker}; exit 0')
        self.assertEqual(integrations.bubblewrap_status(bwrap), "ready")
        args = marker.read_text().split()
        # The probe must request the same namespace isolation as real jobs, not just run the binary.
        for flag in ("--unshare-all", "--die-with-parent", "--cap-drop"):
            self.assertIn(flag, args)

    def test_group_writable_executable_is_not_trusted(self):
        bwrap = self.executable("exit 0")
        bwrap.chmod(0o770)
        self.assertEqual(integrations.bubblewrap_status(bwrap), "missing")


class InstallArgvTests(unittest.TestCase):
    def argv(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "os-release"
            path.write_text(text, encoding="utf-8")
            return integrations.bubblewrap_install_argv(path)

    def test_distribution_families_get_their_package_manager(self):
        cases = {
            'ID=ubuntu\nID_LIKE=debian\n': ["/usr/bin/sudo", "/usr/bin/apt-get", "install", "-y", "bubblewrap"],
            'ID=debian\n': ["/usr/bin/sudo", "/usr/bin/apt-get", "install", "-y", "bubblewrap"],
            'ID="fedora"\n': ["/usr/bin/sudo", "/usr/bin/dnf", "install", "-y", "bubblewrap"],
            'ID="rocky"\nID_LIKE="rhel centos fedora"\n': ["/usr/bin/sudo", "/usr/bin/dnf", "install", "-y", "bubblewrap"],
            'ID=arch\n': ["/usr/bin/sudo", "/usr/bin/pacman", "-S", "--noconfirm", "bubblewrap"],
            'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n': ["/usr/bin/sudo", "/usr/bin/zypper", "--non-interactive", "install", "bubblewrap"],
            'ID=alpine\n': ["/usr/bin/sudo", "/sbin/apk", "add", "bubblewrap"],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.argv(text), expected)

    def test_unknown_or_unreadable_distribution_has_no_guessed_command(self):
        self.assertIsNone(self.argv('ID=plan9\n'))
        self.assertIsNone(integrations.bubblewrap_install_argv(Path("/nonexistent/os-release")))


class SudoAvailableTests(unittest.TestCase):
    def test_explicitly_missing_sudo_means_no_sudo(self):
        with patch.object(integrations.subprocess, "run") as run:
            self.assertFalse(integrations.sudo_available(sudo=None, group_names={"sudo"}))
        run.assert_not_called()

    def test_missing_trusted_sudo_does_not_assume_admin_group_means_installable(self):
        with patch.object(integrations, "_checked_path", side_effect=FileNotFoundError), patch.object(
            integrations.subprocess, "run"
        ) as run:
            self.assertFalse(integrations.sudo_available(group_names={"sudo"}))
        run.assert_not_called()


    def test_non_interactive_sudo_success_means_sudo(self):
        with patch.object(integrations, "_checked_path"), patch.object(
            integrations.subprocess, "run", return_value=Mock(returncode=0)
        ) as run:
            self.assertTrue(integrations.sudo_available(group_names=set()))
        self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-n", "-l"])
        self.assertEqual(run.call_args.kwargs["env"]["PATH"], os.defpath)

    def test_admin_group_membership_allows_a_prompted_install_attempt(self):
        for group in ("sudo", "wheel", "admin"):
            with self.subTest(group=group):
                with patch.object(integrations, "_checked_path"), patch.object(
                    integrations.subprocess, "run", return_value=Mock(returncode=1)
                ) as run:
                    self.assertTrue(integrations.sudo_available(group_names={"users", group}))
                self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-n", "-l"])
                self.assertEqual(run.call_args.kwargs["env"]["PATH"], os.defpath)

    def test_ordinary_account_without_sudo_rights(self):
        with patch.object(integrations, "_checked_path"), patch.object(
            integrations.subprocess, "run", return_value=Mock(returncode=1)
        ):
            self.assertFalse(integrations.sudo_available(group_names={"users", "docker"}))

    def test_malicious_path_sudo_is_never_selected_for_preapproval_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            bindir = Path(directory)
            marker = bindir / "ran"
            impostor = bindir / "sudo"
            impostor.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            impostor.chmod(0o700)
            with patch.dict(os.environ, {"PATH": str(bindir)}), patch.object(
                integrations, "_checked_path"
            ), patch.object(
                integrations.subprocess, "run", return_value=Mock(returncode=1)
            ) as run:
                self.assertFalse(integrations.sudo_available(group_names=set()))
            self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-n", "-l"])
            self.assertEqual(run.call_args.kwargs["env"]["PATH"], os.defpath)
            self.assertFalse(marker.exists())


class InstallExecutionTests(unittest.TestCase):
    def test_package_install_uses_fixed_system_argv_and_clean_path(self):
        argv = ["/usr/bin/sudo", "/usr/bin/apt-get", "install", "-y", "bubblewrap"]
        with tempfile.TemporaryDirectory() as directory:
            bindir = Path(directory)
            marker = bindir / "ran"
            for name in ("sudo", "apt-get"):
                impostor = bindir / name
                impostor.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
                impostor.chmod(0o700)
            with patch.dict(os.environ, {"PATH": str(bindir)}), patch.object(
                integrations, "_checked_path"
            ), patch.object(
                integrations.subprocess, "run", return_value=Mock(returncode=0)
            ) as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(integrations.install_bubblewrap(argv))
            self.assertEqual(run.call_args.args[0], argv)
            self.assertEqual(run.call_args.kwargs["env"]["PATH"], os.defpath)
            self.assertFalse(marker.exists())

    def test_package_install_refuses_untrusted_system_executable_metadata(self):
        with patch.object(
            integrations, "_checked_path", side_effect=ValueError
        ), patch.object(integrations.subprocess, "run") as run, contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertFalse(integrations.install_bubblewrap(ARGV))
        run.assert_not_called()

    def test_untrusted_or_rewritten_package_command_is_never_spawned(self):
        with tempfile.TemporaryDirectory() as directory:
            bindir = Path(directory)
            marker = bindir / "ran"
            impostor = bindir / "apt-get"
            impostor.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            impostor.chmod(0o700)
            argv = ["/usr/bin/sudo", str(impostor), "install", "-y", "bubblewrap"]
            with patch.dict(os.environ, {"PATH": str(bindir)}), patch.object(
                integrations.subprocess, "run"
            ) as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(integrations.install_bubblewrap(argv))
            run.assert_not_called()
            self.assertFalse(marker.exists())


ARGV = ["/usr/bin/sudo", "/usr/bin/apt-get", "install", "-y", "bubblewrap"]


class SetupGatingTests(unittest.TestCase):
    def setUp(self):
        from dotunnel import setup, onboarding

        self.onboarding = onboarding
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)
        self.directory = self.base / "setup"
        setup.create_artifacts(self.directory, "tunnel_" + "1" * 32, "synthetic-not-a-key")
        self.config = self.directory / "config.json"

    def configure(self, statuses, answers, *, sudo=False, install_ok=True, installed=None):
        statuses, answers, selections, installs = iter(statuses), iter(answers), [], []

        def selector(available, initial):
            selections.append(set(initial))
            return None

        def install(argv):
            installs.append(list(argv))
            return install_ok

        output = io.StringIO()
        available = {"codex": Path("/unused/codex")} if installed is None else installed
        with contextlib.redirect_stdout(output):
            selected = self.onboarding._choose_fixed_jobs(
                available,
                set(),
                self.directory,
                chooser=selector,
                prompt_fn=lambda _text: next(answers),
                check=lambda: next(statuses),
                sudo_fn=lambda: sudo,
                install_fn=install,
                install_argv_fn=lambda: ARGV,
            )
        return selected is not None, selections, installs, output.getvalue()

    def test_sudo_account_installs_on_default_yes_and_continues_to_selection(self):
        _result, selections, installs, _output = self.configure(["missing", "ready"], [""], sudo=True)
        self.assertEqual(installs, [ARGV])
        self.assertEqual(selections, [set()])

    def test_declined_install_runs_nothing_and_falls_back_to_guidance(self):
        before = self.config.read_bytes()
        _result, selections, installs, output = self.configure(["missing"], ["n", "s"], sudo=True)
        self.assertEqual(installs, [])
        self.assertEqual(selections, [])
        self.assertEqual(self.config.read_bytes(), before)

    def test_invalid_answer_is_asked_again(self):
        _result, _selections, installs, _output = self.configure(["missing", "ready"], ["maybe", "y"], sudo=True)
        self.assertEqual(installs, [ARGV])

    def test_account_without_sudo_is_never_offered_installation(self):
        _result, selections, installs, output = self.configure(["missing"], ["s"], sudo=False)
        self.assertEqual(installs, [])
        self.assertEqual(selections, [])

    def test_failed_install_keeps_setup_and_waits_for_manual_install(self):
        # A failed install is not re-probed; the next check is the operator's Enter in the wait loop.
        _result, selections, installs, output = self.configure(
            ["missing", "ready"], ["y", ""], sudo=True, install_ok=False,
        )
        self.assertIn("did not complete", output)
        self.assertEqual(installs, [ARGV])
        self.assertEqual(selections, [set()])

    def test_unusable_bubblewrap_is_not_reinstalled(self):
        _result, selections, installs, _output = self.configure(["unusable"], ["s"], sudo=True)
        self.assertEqual(installs, [])
        self.assertEqual(selections, [])

    def test_install_is_offered_even_before_any_cli_is_installed(self):
        result, selections, installs, _output = self.configure(["missing", "ready"], [""], sudo=True, installed={})
        self.assertTrue(result)
        self.assertEqual(installs, [ARGV])
        self.assertEqual(selections, [])
        self.assertEqual(json.loads(self.config.read_text())["tasks"], [])

    def test_manual_install_then_recheck_opens_selection_in_same_run(self):
        _result, selections, _installs, _output = self.configure(["missing", "unusable", "ready"], ["", ""])
        self.assertEqual(selections, [set()])

    def test_ready_bubblewrap_goes_straight_to_selection(self):
        _result, selections, installs, _output = self.configure(["ready"], [], sudo=True)
        self.assertEqual(installs, [])
        self.assertEqual(selections, [set()])

    def test_no_installed_cli_without_sudo_reports_status_without_waiting(self):
        result, selections, installs, output = self.configure(["missing"], [], installed={})
        self.assertTrue(result)
        self.assertEqual(installs, [])
        self.assertIn("Bubblewrap", output)
        self.assertEqual(json.loads(self.config.read_text())["tasks"], [])


if __name__ == "__main__":
    unittest.main()
