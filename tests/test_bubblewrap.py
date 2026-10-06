"""Bubblewrap is required only for optional CLI integrations; setup checks it up front."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

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
            'ID=ubuntu\nID_LIKE=debian\n': ["sudo", "apt-get", "install", "-y", "bubblewrap"],
            'ID=debian\n': ["sudo", "apt-get", "install", "-y", "bubblewrap"],
            'ID="fedora"\n': ["sudo", "dnf", "install", "-y", "bubblewrap"],
            'ID="rocky"\nID_LIKE="rhel centos fedora"\n': ["sudo", "dnf", "install", "-y", "bubblewrap"],
            'ID=arch\n': ["sudo", "pacman", "-S", "--noconfirm", "bubblewrap"],
            'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n': ["sudo", "zypper", "--non-interactive", "install", "bubblewrap"],
            'ID=alpine\n': ["sudo", "apk", "add", "bubblewrap"],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.argv(text), expected)

    def test_unknown_or_unreadable_distribution_has_no_guessed_command(self):
        self.assertIsNone(self.argv('ID=plan9\n'))
        self.assertIsNone(integrations.bubblewrap_install_argv(Path("/nonexistent/os-release")))


class SudoAvailableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def sudo(self, code):
        path = self.base / "sudo"
        path.write_text(f"#!/bin/sh\nexit {code}\n", encoding="utf-8")
        path.chmod(0o700)
        return str(path)

    def test_no_sudo_binary_means_no_sudo(self):
        self.assertFalse(integrations.sudo_available(sudo=None, group_names={"sudo"}))

    def test_non_interactive_sudo_success_means_sudo(self):
        self.assertTrue(integrations.sudo_available(sudo=self.sudo(0), group_names=set()))

    def test_password_sudo_is_recognized_by_admin_group(self):
        for group in ("sudo", "wheel", "admin"):
            with self.subTest(group=group):
                self.assertTrue(integrations.sudo_available(sudo=self.sudo(1), group_names={"users", group}))

    def test_ordinary_account_without_sudo_rights(self):
        self.assertFalse(integrations.sudo_available(sudo=self.sudo(1), group_names={"users", "docker"}))


ARGV = ["sudo", "apt-get", "install", "-y", "bubblewrap"]


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
        with contextlib.redirect_stdout(output):
            result = self.onboarding.configure_directory(
                self.directory,
                {"codex": Path("/unused/codex")} if installed is None else installed,
                selector_fn=selector,
                prompt_fn=lambda _text: next(answers),
                bubblewrap_fn=lambda: next(statuses),
                sudo_fn=lambda: sudo,
                install_fn=install,
                install_argv_fn=lambda: ARGV,
            )
        return result, selections, installs, output.getvalue()

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
        self.assertIn("sudo apt-get install -y bubblewrap", output)

    def test_invalid_answer_is_asked_again(self):
        _result, _selections, installs, _output = self.configure(["missing", "ready"], ["maybe", "y"], sudo=True)
        self.assertEqual(installs, [ARGV])

    def test_account_without_sudo_is_never_offered_installation(self):
        _result, selections, installs, output = self.configure(["missing"], ["s"], sudo=False)
        self.assertEqual(installs, [])
        self.assertEqual(selections, [])
        self.assertIn("sudo apt-get install -y bubblewrap", output)

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
