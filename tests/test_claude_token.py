import os
from pathlib import Path
import stat
import sys
import tempfile
import termios
import textwrap
import unittest

from dotunnel.claude_token import extract_token, run_in_pty, save_token, validate_token

TOKEN = "sk-ant-oat01-Synthetic_token-value_0123456789abcdef"


class ExtractTokenTests(unittest.TestCase):
    def test_token_is_found_through_terminal_styling_and_redraws(self):
        output = (
            b"\x1b[2J\x1b[?25lWelcome\r\n"
            b"Your OAuth token (valid for 1 year):\r\n\x1b[1m\x1b[32m" + TOKEN.encode() + b"\x1b[39m\x1b[22m\r\n"
            b"\x1b]0;title\x07Store this token securely.\r\n"
            b"\x1b[3A\x1b[1m" + TOKEN.encode() + b"\x1b[22m\r\n"
        )
        self.assertEqual(extract_token(output), TOKEN)

    def test_missing_or_ambiguous_tokens_are_not_guessed(self):
        other = TOKEN[:-1] + "X"
        for output in (b"", b"Login failed\r\n", (TOKEN + "\r\n" + other + "\r\n").encode()):
            with self.subTest(output=output[:20]):
                self.assertIsNone(extract_token(output))


class SaveTokenTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        os.chmod(self.root, 0o700)
        self.path = self.root / "claude-oauth-token"

    def tearDown(self):
        self.directory.cleanup()

    def test_maximum_token_fits_the_4096_byte_consumer_limit(self):
        maximum = "A" * 4095
        self.assertEqual(validate_token(maximum), maximum)
        save_token(self.path, maximum, replace=False)
        self.assertEqual(self.path.stat().st_size, 4096)

        too_long = maximum + "A"
        with self.assertRaises(ValueError):
            validate_token(too_long)
        with self.assertRaises(ValueError):
            save_token(self.path, too_long, replace=True)
        self.assertEqual(self.path.stat().st_size, 4096)

    def test_new_token_file_is_private_and_existing_file_is_not_overwritten(self):
        save_token(self.path, TOKEN, replace=False)
        self.assertEqual(self.path.read_text(), TOKEN + "\n")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

        with self.assertRaises(ValueError):
            save_token(self.path, TOKEN[:-1] + "Y", replace=False)
        self.assertEqual(self.path.read_text(), TOKEN + "\n")

    def test_replace_rotates_token_atomically_without_leftovers(self):
        save_token(self.path, TOKEN, replace=False)
        rotated = TOKEN[:-1] + "Z"
        save_token(self.path, rotated, replace=True)
        self.assertEqual(self.path.read_text(), rotated + "\n")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["claude-oauth-token"])

    def test_symlink_destination_and_invalid_values_are_refused(self):
        target = self.root / "elsewhere"
        target.write_text("keep\n")
        self.path.symlink_to(target)
        for replace in (False, True):
            with self.subTest(replace=replace), self.assertRaises(ValueError):
                save_token(self.path, TOKEN, replace=replace)
        self.assertEqual(target.read_text(), "keep\n")
        self.path.unlink()

        for value in ("", "two words", "a\nb", "x" * 5000, "short"):
            with self.subTest(value=value[:10]), self.assertRaises(ValueError) as raised:
                save_token(self.path, value, replace=False)
            self.assertNotIn(value or "\x00", str(raised.exception))
        self.assertFalse(self.path.exists())


class PseudoTerminalTests(unittest.TestCase):
    def fake_claude(self, directory):
        script = Path(directory) / "fake-claude"
        script.write_text(textwrap.dedent(f"""\
            import os, select, sys
            assert os.isatty(0) and os.isatty(1)
            print("cols=%d" % os.get_terminal_size(1).columns, flush=True)
            ready, _, _ = select.select([sys.stdin], [], [], 5)
            code = sys.stdin.readline().strip() if ready else ""
            print("\\x1b[1m{TOKEN}\\x1b[22m" if code == "auth-code" else "bad code", flush=True)
        """))
        return [sys.executable, str(script)]

    def test_child_gets_wide_terminal_receives_input_and_output_is_mirrored(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = self.fake_claude(directory)
            stdin_read, stdin_write = os.pipe()
            stdout_read, stdout_write = os.pipe()
            os.write(stdin_write, b"auth-code\n")
            os.close(stdin_write)
            try:
                exit_code, captured = run_in_pty(argv, stdin_read, stdout_write)
            finally:
                os.close(stdin_read)
                os.close(stdout_write)
            mirrored = b""
            while chunk := os.read(stdout_read, 65536):
                mirrored += chunk
            os.close(stdout_read)

        self.assertEqual(exit_code, 0)
        self.assertEqual(mirrored, captured)
        columns = int(captured.split(b"cols=")[1].split(b"\r")[0])
        self.assertGreaterEqual(columns, 300)
        self.assertEqual(extract_token(captured), TOKEN)

    def test_terminal_input_typed_before_raw_mode_is_kept_and_settings_restored(self):
        operator, terminal = os.openpty()
        before = termios.tcgetattr(terminal)
        stdout_read, stdout_write = os.pipe()
        try:
            with tempfile.TemporaryDirectory() as directory:
                argv = self.fake_claude(directory)
                # Operator typed the code before the command switched to raw mode.
                os.write(operator, b"auth-code\r")
                exit_code, captured = run_in_pty(argv, terminal, stdout_write)
            after = termios.tcgetattr(terminal)
        finally:
            os.close(stdout_write)
            os.close(stdout_read)
            os.close(terminal)
            os.close(operator)

        self.assertEqual(exit_code, 0)
        self.assertEqual(extract_token(captured), TOKEN)
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
