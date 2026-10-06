"""Validate Claude's native stream-json completion result."""

from __future__ import annotations

import json

from .cli_backend import _NativeStreamError, _reject_constant, _scrub_summary, _unique_object


_REQUIRED_RESULT_FIELDS = frozenset(
    {
        "subtype",
        "is_error",
        "terminal_reason",
        "api_error_status",
        "permission_denials",
        "queued_turn_count",
        "result_index",
        "result",
    }
)


def _failure_detail(event: dict) -> str | None:
    """Map an unsuccessful result frame to a fixed code without its text."""
    status = event.get("api_error_status")
    if type(status) is int:
        if status in (401, 403):
            return "AUTH_FAILED"
        if status == 429:
            return "RATE_LIMITED"
        return "PROVIDER_ERROR"
    denials = event.get("permission_denials")
    if isinstance(denials, list) and denials:
        return "PERMISSION_DENIED"
    if (
        event.get("subtype") != "success"
        or event.get("is_error") is not False
        or event.get("terminal_reason") != "completed"
    ):
        return "UNSUCCESSFUL_RESULT"
    return None


def _parse_claude_stream(stdout: bytes, exit_code: int | None) -> str:
    terminal: dict | None = None
    start = 0
    while start < len(stdout):
        end = stdout.find(b"\n", start)
        if end < 0:
            end = len(stdout)
            next_start = end
        else:
            next_start = end + 1

        raw_line = stdout[start:end]
        start = next_start
        if not raw_line.strip():
            continue
        if terminal is not None:
            raise _NativeStreamError("Native CLI produced an invalid completion stream", "INVALID_STREAM")

        try:
            line = raw_line.decode("utf-8", "strict")
            event = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, RecursionError):
            raise _NativeStreamError("Native CLI produced invalid JSON output", "INVALID_STREAM") from None

        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise _NativeStreamError("Native CLI produced invalid JSON output", "INVALID_STREAM")
        if event["type"] == "result":
            terminal = event

    if terminal is None:
        raise _NativeStreamError("Native CLI produced no completion stream", "NO_RESULT")
    # Classify before the exit status: Claude exits nonzero on provider errors
    # but still reports the authoritative cause in its result frame.
    detail = _failure_detail(terminal)
    if detail is not None:
        raise _NativeStreamError("Native CLI did not report successful completion", detail)
    if type(exit_code) is not int or exit_code != 0:
        raise _NativeStreamError("Native CLI did not complete successfully", "EXIT_NONZERO")
    if (
        not _REQUIRED_RESULT_FIELDS.issubset(terminal)
        or terminal["api_error_status"] is not None
        or not isinstance(terminal["permission_denials"], list)
        or type(terminal["queued_turn_count"]) is not int
        or terminal["queued_turn_count"] != 0
        or type(terminal["result_index"]) is not int
        or terminal["result_index"] != 0
    ):
        raise _NativeStreamError("Native CLI did not report successful completion", "INVALID_RESULT")

    result = terminal["result"]
    if not isinstance(result, str) or not result:
        raise _NativeStreamError("Native CLI completed without final assistant text", "EMPTY_RESULT")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in result):
        raise _NativeStreamError("Native CLI produced an invalid final summary", "INVALID_RESULT")
    try:
        summary = _scrub_summary(result)
    except UnicodeError:
        raise _NativeStreamError("Native CLI produced an invalid final summary", "INVALID_RESULT") from None
    if not summary:
        raise _NativeStreamError("Native CLI completed without final assistant text", "EMPTY_RESULT")
    return summary
