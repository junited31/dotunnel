import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from tools.release_verify import runner_runtime


class RunnerCommandTests(unittest.TestCase):
    def command(self, code, *, output_limit=65536, allow_nonzero=False, timeout=2):
        return runner_runtime._bounded_command(
            [sys.executable, "-I", "-S", "-B", "-c", code],
            time.monotonic_ns() + int(timeout * 1_000_000_000),
            allowed={sys.executable}, output_limit=output_limit,
            allow_nonzero=allow_nonzero,
        )

    def test_actual_command_captures_both_streams_and_nonzero_exit(self):
        result = self.command(
            "import os; os.write(1, b'running\\n'); "
            "os.write(2, b'diagnostic\\n'); raise SystemExit(7)",
            allow_nonzero=True,
        )
        self.assertEqual(result, (7, b"running\n", b"diagnostic\n"))

    def test_actual_command_drains_output_larger_than_pipe_capacity(self):
        result = self.command(
            "import os; os.write(1, b'o' * 49152); os.write(2, b'e' * 49152)"
        )
        self.assertEqual(result, (0, b"o" * 49152, b"e" * 49152))

    def test_output_limit_accepts_boundary_and_rejects_next_byte(self):
        self.assertEqual(
            self.command("import os; os.write(1, b'x' * 32)", output_limit=32),
            (0, b"x" * 32, b""),
        )
        with self.assertRaises(runner_runtime.RuntimeFailure) as refused:
            self.command("import os; os.write(2, b'x' * 33)", output_limit=32)
        self.assertEqual(refused.exception.code, "fixed-command-output-limit")

    def test_deadline_kills_and_reaps_actual_child(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-command-deadline-") as directory:
            marker = Path(directory) / "pid"
            with self.assertRaises(runner_runtime.RuntimeFailure) as refused:
                self.command(
                    "import os,pathlib,time; "
                    f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); "
                    "time.sleep(30)",
                    timeout=1,
                )
            self.assertEqual(refused.exception.code, "fixed-command-timeout")
            pid = int(marker.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_expired_deadline_refuses_child_before_effect(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-command-refusal-") as directory:
            marker = Path(directory) / "effect"
            with self.assertRaises(runner_runtime.RuntimeFailure) as refused:
                self.command(f"from pathlib import Path; Path({str(marker)!r}).write_bytes(b'changed')", timeout=0)
            self.assertEqual(refused.exception.code, "fixed-command-refused")
            self.assertFalse(marker.exists())


class RunnerManagerDurationTests(unittest.TestCase):
    def test_combined_and_single_manager_durations_are_exact(self):
        for text, expected in (
            ("8min 30s", 510_000_000),
            ("1min 30s", 90_000_000),
            ("1s 500ms 1us", 1_500_001),
            ("2h 30min", 9_000_000_000),
            ("0us", 0), ("100ms", 100_000), ("2s", 2_000_000),
            ("510000000us", 510_000_000),
            ("1.5s", 1_500_000),
        ):
            with self.subTest(text=text):
                self.assertEqual(runner_runtime._manager_duration(text, "invalid-duration"), expected)

    def test_manager_duration_rejects_invalid_or_nonfinite_values(self):
        for text in ("", "infinity", "-1s", "1s extra", "1ns", "1e3s", "0.0000001s", "18446744073709551615us", "99999999999999999999y"):
            with self.subTest(text=text):
                with self.assertRaises(runner_runtime.RuntimeFailure) as refused:
                    runner_runtime._manager_duration(text, "invalid-duration")
                self.assertEqual(refused.exception.code, "invalid-duration")


if __name__ == "__main__":
    unittest.main()
