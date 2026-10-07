import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class _TTY(io.StringIO):
    def isatty(self):
        return True


class SupervisionCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state_dir = self.base / "private-state"
        self.config_path = self.base / "config.json"
        self.config_path.write_text("{}", encoding="utf-8")
        self.config_path.chmod(0o600)
        self.settings = SimpleNamespace(state_dir=self.state_dir)

    def run_cli(self, argv, *, loaded=None, stdin=None, stderr=None, supported=True):
        from dotunnel.supervision_cli import main

        with patch("dotunnel.operator._supported_environment", return_value=supported), \
                patch("dotunnel.config.load_config", return_value=SimpleNamespace(supervision=loaded or self.settings)) as load_config, \
                patch("sys.stdin", stdin or io.StringIO()), \
                patch("sys.stdout", io.StringIO()), \
                patch("sys.stderr", stderr or io.StringIO()):
            status = main(argv)
        return status, load_config

    def initialize(self):
        status, loader = self.run_cli(["init", "--config", str(self.config_path)])
        self.assertEqual(status, 0)
        loader.assert_called_once()
        self.assertEqual(loader.call_args.args[0], self.config_path)

    def test_init_creates_private_epoch_once_and_does_not_replace_it(self):
        from dotunnel.supervision_state import SupervisionState

        status, _ = self.run_cli(["init", "--config", str(self.config_path)])
        self.assertEqual(status, 0)
        state = SupervisionState(self.state_dir)
        epoch, key = state.epoch, state.key
        state.close()

        repeated, _ = self.run_cli(["init", "--config", str(self.config_path)])
        self.assertEqual(repeated, 2)
        reopened = SupervisionState(self.state_dir)
        try:
            self.assertEqual(reopened.epoch, epoch)
            self.assertEqual(reopened.key, key)
        finally:
            reopened.close()

    def test_reinit_requires_tty_acknowledgement_and_leaves_existing_epoch_untouched(self):
        from dotunnel.supervision_state import SupervisionState

        self.initialize()
        state = SupervisionState(self.state_dir)
        epoch, key = state.epoch, state.key
        state.close()

        refused, _ = self.run_cli(["reinit", "--config", str(self.config_path)], stdin=io.StringIO("reinit\n"))
        self.assertEqual(refused, 2)
        unchanged = SupervisionState(self.state_dir)
        try:
            self.assertEqual(unchanged.epoch, epoch)
            self.assertEqual(unchanged.key, key)
        finally:
            unchanged.close()

    def test_acknowledged_reinit_rotates_epoch_and_invalidates_old_approvals(self):
        import asyncio
        from dotunnel.supervision_state import SupervisionState

        self.initialize()
        state = SupervisionState(self.state_dir)
        old_epoch = state.epoch
        async def approve():
            async with state.lock():
                state.set_approval("connection:project", "generation", True)
        asyncio.run(approve())
        state.close()

        accepted, _ = self.run_cli(
            ["reinit", "--config", str(self.config_path)],
            stdin=_TTY("reinit\n"), stderr=_TTY(),
        )
        self.assertEqual(accepted, 0)
        fresh = SupervisionState(self.state_dir)
        try:
            self.assertNotEqual(fresh.epoch, old_epoch)
            self.assertFalse(fresh.approved("connection:project", "generation"))
        finally:
            fresh.close()

    def test_linux_nonroot_gate_precedes_config_loading_or_state_creation(self):
        from dotunnel.supervision_cli import main

        with patch("dotunnel.operator._supported_environment", return_value=False), \
                patch("dotunnel.config.load_config") as load_config, \
                patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
            status = main(["init", "--config", str(self.config_path)])
        self.assertEqual(status, 2)
        load_config.assert_not_called()
        self.assertFalse(self.state_dir.exists())

    def test_load_uses_the_existing_trusted_config_loader_and_propagates_its_refusal(self):
        from dotunnel.supervision_cli import main

        with patch("dotunnel.operator._supported_environment", return_value=True), \
                patch("dotunnel.config.load_config", side_effect=ValueError("unsafe config")) as load_config, \
                patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
            status = main(["init", "--config", str(self.config_path)])
        self.assertEqual(status, 2)
        load_config.assert_called_once()
        self.assertFalse(self.state_dir.exists())

    def test_invalid_commands_options_and_duplicate_config_flags_do_not_load_settings(self):
        from dotunnel.supervision_cli import main

        cases = [
            ["unknown", "--config", str(self.config_path)],
            ["init"],
            ["init", "--config", str(self.config_path), "--config", str(self.config_path)],
            ["reinit", "--config", str(self.config_path), "--force"],
        ]
        for argv in cases:
            with self.subTest(argv=argv), \
                    patch("dotunnel.operator._supported_environment", return_value=True), \
                    patch("dotunnel.config.load_config") as load_config, \
                    patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                status = main(argv)
                self.assertEqual(status, 2)
                load_config.assert_not_called()

    def test_init_and_reinit_never_import_or_dispatch_a_backend(self):
        from dotunnel.supervision_cli import main

        with patch("dotunnel.operator._supported_environment", return_value=True), \
                patch("dotunnel.config.load_config", return_value=SimpleNamespace(supervision=self.settings)), \
                patch.dict(sys.modules, {"dotunnel.supervision": None, "dotunnel.tmux": None}), \
                patch("sys.stdin", io.StringIO()), patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
            status = main(["init", "--config", str(self.config_path)])
        self.assertEqual(status, 0)

    def test_reinit_requires_explicit_confirmation_even_on_a_tty(self):
        from dotunnel.supervision_state import SupervisionState

        self.initialize()
        before = SupervisionState(self.state_dir)
        epoch = before.epoch
        before.close()

        declined, _ = self.run_cli(
            ["reinit", "--config", str(self.config_path)], stdin=_TTY("no\n"), stderr=_TTY()
        )
        self.assertEqual(declined, 2)
        after = SupervisionState(self.state_dir)
        try:
            self.assertEqual(after.epoch, epoch)
        finally:
            after.close()


if __name__ == "__main__":
    unittest.main()
