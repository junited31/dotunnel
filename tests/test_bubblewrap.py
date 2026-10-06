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


class InstallCommandTests(unittest.TestCase):
    def command(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "os-release"
            path.write_text(text, encoding="utf-8")
            return integrations.bubblewrap_install_command(path)

    def test_distribution_families_get_their_package_manager(self):
        cases = {
            'ID=ubuntu\nID_LIKE=debian\n': "sudo apt install bubblewrap",
            'ID=debian\n': "sudo apt install bubblewrap",
            'ID="fedora"\n': "sudo dnf install bubblewrap",
            'ID="rocky"\nID_LIKE="rhel centos fedora"\n': "sudo dnf install bubblewrap",
            'ID=arch\n': "sudo pacman -S bubblewrap",
            'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n': "sudo zypper install bubblewrap",
            'ID=alpine\n': "sudo apk add bubblewrap",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.command(text), expected)

    def test_unknown_or_unreadable_distribution_has_no_guessed_command(self):
        self.assertIsNone(self.command('ID=plan9\n'))
        self.assertIsNone(integrations.bubblewrap_install_command(Path("/nonexistent/os-release")))


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

    def configure(self, statuses, answers):
        statuses, answers, selections = iter(statuses), iter(answers), []

        def selector(available, initial):
            selections.append(set(initial))
            return None

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.onboarding.configure_directory(
                self.directory,
                {"codex": Path("/unused/codex")},
                selector_fn=selector,
                prompt_fn=lambda _text: next(answers),
                bubblewrap_fn=lambda: next(statuses),
            )
        return result, selections, output.getvalue()

    def test_unusable_bubblewrap_skips_selection_without_changing_registry(self):
        before = self.config.read_bytes()
        result, selections, output = self.configure(["missing"], ["s"])
        self.assertTrue(result)
        self.assertEqual(selections, [])
        self.assertEqual(self.config.read_bytes(), before)
        self.assertIn("dotunnel setup --directory", output)

    def test_installing_then_rechecking_opens_selection_in_same_run(self):
        result, selections, _output = self.configure(["missing", "unusable", "ready"], ["", ""])
        self.assertEqual(selections, [set()])

    def test_ready_bubblewrap_goes_straight_to_selection(self):
        _result, selections, _output = self.configure(["ready"], [])
        self.assertEqual(selections, [set()])

    def test_no_installed_cli_reports_status_without_waiting(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.onboarding.configure_directory(
                self.directory, {}, prompt_fn=lambda _text: self.fail("must not wait"),
                bubblewrap_fn=lambda: "missing",
            )
        self.assertTrue(result)
        self.assertIn("Bubblewrap", output.getvalue())
        self.assertEqual(json.loads(self.config.read_text())["tasks"], [])


if __name__ == "__main__":
    unittest.main()
