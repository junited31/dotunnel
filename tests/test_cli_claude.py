import json
import unittest

from dotunnel.cli_backend import _NativeStreamError
from dotunnel.cli_claude import _parse_claude_stream


def _result_frame(**overrides):
    frame = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "terminal_reason": "completed",
        "api_error_status": None,
        "permission_denials": [],
        "queued_turn_count": 0,
        "result_index": 0,
        "result": "Edited the requested file.",
    }
    frame.update(overrides)
    return frame


def _stream(*frames):
    return b"".join(
        json.dumps(frame, ensure_ascii=True).encode("utf-8") + b"\n"
        for frame in frames
    )


class ClaudeStreamTests(unittest.TestCase):
    def test_claude_preserves_summary_text_after_osc_terminators(self):
        cases = (
            ("before \x1b]0;title\x1b\\ after", "before  after"),
            ("before \x1b]0;title\x07 after", "before  after"),
            (
                "before \x1b]8;;https://example.invalid\x1b\\label\x1b]8;;\x1b\\ after",
                "before label after",
            ),
            ("before\x1b]0;first\x1b\\middle\x1b]0;second\x07after", "beforemiddleafter"),
            ("before \x1b]0;unfinished", "before"),
        )
        for summary, expected in cases:
            with self.subTest(summary=summary):
                self.assertEqual(
                    _parse_claude_stream(_stream(_result_frame(result=summary)), 0),
                    expected,
                )

    def test_success_uses_authoritative_terminal_and_scrubs_summary(self):
        terminal = _result_frame(result="Updated café 🌍: \x1b[31mready\x1b[0m\x01")
        self.assertEqual(
            _parse_claude_stream(
                _stream(
                    {"type": "system", "subtype": "init"},
                    {"type": "assistant", "message": {"content": "working"}},
                    {"type": "rate_limit_event", "status": "allowed"},
                    {"type": "user", "message": {"content": "continue"}},
                    terminal,
                ),
                0,
            ),
            "Updated café 🌍: ready",
        )

    def test_api_401_is_not_success_when_error_flag_is_true(self):
        private_error = "OAuth token rejected: secret-provider-detail"
        frame = _result_frame(
            is_error=True,
            api_error_status=401,
            result=private_error,
        )
        with self.assertRaises(_NativeStreamError) as raised:
            _parse_claude_stream(_stream(frame), 0)
        self.assertNotIn(private_error, str(raised.exception))
        self.assertNotIn("secret-provider-detail", str(raised.exception))

    def test_quota_or_noncompleted_terminal_is_rejected(self):
        for frame in (
            _result_frame(terminal_reason="max_turns"),
            _result_frame(subtype="error_max_turns", is_error=True, api_error_status=429),
        ):
            with self.subTest(frame=frame), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(_stream(frame), 0)

    def test_failure_detail_classifies_terminal_even_when_cli_exits_nonzero(self):
        private_error = "OAuth token rejected: secret-provider-detail"
        cases = (
            (_result_frame(is_error=True, api_error_status=401, result=private_error), 1, "AUTH_FAILED"),
            (_result_frame(is_error=True, api_error_status=403, result=private_error), 1, "AUTH_FAILED"),
            (_result_frame(is_error=True, api_error_status=429, result=private_error), 1, "RATE_LIMITED"),
            (_result_frame(is_error=True, api_error_status=529, result=private_error), 1, "PROVIDER_ERROR"),
            (_result_frame(permission_denials=[{"tool_name": "Bash"}]), 0, "PERMISSION_DENIED"),
            (_result_frame(subtype="error_max_turns", terminal_reason="max_turns"), 0, "UNSUCCESSFUL_RESULT"),
            (_result_frame(is_error=True, result=private_error), 1, "UNSUCCESSFUL_RESULT"),
        )
        for frame, exit_code, detail in cases:
            with self.subTest(detail=detail, frame=frame), self.assertRaises(_NativeStreamError) as raised:
                _parse_claude_stream(_stream(frame), exit_code)
            self.assertEqual(raised.exception.detail, detail)
            self.assertNotIn("secret-provider-detail", str(raised.exception))

    def test_failure_detail_without_classifiable_terminal(self):
        cases = (
            (b"", 1, "NO_RESULT"),
            (_stream({"type": "system", "subtype": "init"}), 0, "NO_RESULT"),
            (b"not json\n", 1, "INVALID_STREAM"),
            (_stream(_result_frame()), 1, "EXIT_NONZERO"),
            (_stream(_result_frame(result="")), 0, "EMPTY_RESULT"),
            (_stream(_result_frame(result="\u00e9" * 1500)), 0, "SUMMARY_TOO_LARGE"),
        )
        for stdout, exit_code, detail in cases:
            with self.subTest(detail=detail), self.assertRaises(_NativeStreamError) as raised:
                _parse_claude_stream(stdout, exit_code)
            self.assertEqual(raised.exception.detail, detail)

    def test_stream_without_result_terminal_is_rejected(self):
        with self.assertRaises(_NativeStreamError):
            _parse_claude_stream(
                _stream(
                    {"type": "system", "subtype": "init"},
                    {"type": "assistant", "message": {"content": "partial answer"}},
                ),
                0,
            )

    def test_no_frames_may_follow_or_duplicate_the_terminal_result(self):
        terminal = _result_frame()
        for frames in (
            (terminal, {"type": "assistant", "message": {"content": "late frame"}}),
            (terminal, _result_frame(result="second result")),
        ):
            with self.subTest(frames=frames), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(_stream(*frames), 0)

    def test_permission_denial_prevents_success(self):
        frame = _result_frame(
            permission_denials=[{"tool_name": "Edit", "tool_use_id": "toolu_123"}]
        )
        with self.assertRaises(_NativeStreamError):
            _parse_claude_stream(_stream(frame), 0)

    def test_missing_or_malformed_authoritative_fields_fail_closed(self):
        required_fields = (
            "subtype",
            "is_error",
            "terminal_reason",
            "api_error_status",
            "permission_denials",
            "queued_turn_count",
            "result_index",
            "result",
        )
        for field in required_fields:
            frame = _result_frame()
            del frame[field]
            with self.subTest(missing=field), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(_stream(frame), 0)

        malformed_values = (
            {"subtype": None},
            {"is_error": 0},
            {"terminal_reason": False},
            {"api_error_status": 0},
            {"permission_denials": None},
            {"queued_turn_count": False},
            {"result_index": 0.0},
            {"result": ["not a summary"]},
        )
        for values in malformed_values:
            with self.subTest(malformed=values), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(_stream(_result_frame(**values)), 0)

    def test_malformed_duplicate_and_nonfinite_json_are_rejected(self):
        for stdout in (
            b"not-json\n",
            b'{"type":"system","type":"system"}\n',
            b'{"type":"assistant","usage":NaN}\n',
            b'{"type":"assistant","usage":Infinity}\n',
            b'{"subtype":"success"}\n',
        ):
            with self.subTest(stdout=stdout), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(stdout, 0)

    def test_invalid_utf8_and_invalid_frame_types_are_rejected(self):
        for stdout in (
            b"\xff\n",
            _stream({"type": None}),
            _stream({"subtype": "init"}),
            _stream(["not", "an", "object"]),
        ):
            with self.subTest(stdout=stdout), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(stdout, 0)

    def test_empty_oversized_and_invalid_surrogate_summaries_are_rejected(self):
        for summary in ("  \t\n ", "é" * 1500, "unpaired \ud800 surrogate"):
            with self.subTest(summary=summary[:20]), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(_stream(_result_frame(result=summary)), 0)

    def test_nonzero_or_unknown_exit_status_is_rejected(self):
        valid = _stream(_result_frame())
        for exit_code in (1, 137, None):
            with self.subTest(exit_code=exit_code), self.assertRaises(_NativeStreamError):
                _parse_claude_stream(valid, exit_code)


if __name__ == "__main__":
    unittest.main()
