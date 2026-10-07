"""Explicit operator initialization and epoch rotation for supervision state."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence


def _arguments(argv: Sequence[str]) -> tuple[str, Path] | None:
    if len(argv) != 3 or argv[0] not in ("init", "reinit") or argv[1] != "--config" or not argv[2]:
        return None
    if "\x00" in argv[2]:
        return None
    return argv[0], Path(argv[2])


def _failure(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["--help"], ["-h"]):
        print("Usage: dotunnel supervision {init|reinit} --config PATH")
        print("init creates private state; reinit requires terminal acknowledgement and retains the prior namespace.")
        return 0
    parsed = _arguments(args)
    if parsed is None:
        return _failure("Usage: dotunnel supervision {init|reinit} --config PATH")
    command, config_path = parsed

    from .operator import _supported_environment

    if not _supported_environment():
        return _failure("Supervision initialization requires Linux and a non-root user.")

    try:
        from .config import load_config

        config = load_config(config_path)
    except (OSError, ValueError) as error:
        return _failure(f"Configuration refused: {error}")
    settings = getattr(config, "supervision", None)
    if settings is None or not isinstance(getattr(settings, "state_dir", None), Path):
        return _failure("The trusted configuration has no valid supervision section.")

    if command == "reinit":
        previous_path = settings.state_dir.with_name(settings.state_dir.name + ".previous")
        if not getattr(sys.stdin, "isatty", lambda: False)() or not getattr(sys.stderr, "isatty", lambda: False)():
            return _failure("Reinitialization requires an interactive terminal; no state was changed.")
        print(
            f"Reinitialization starts a fresh epoch and retains the prior private namespace at {previous_path}. "
            "Review unresolved or possibly in-flight backend effects, and reconcile, export, or remove "
            "that archive before another reinitialization. Type 'reinit' to acknowledge.",
            file=sys.stderr,
        )
        sys.stderr.flush()
        if sys.stdin.readline().strip() != "reinit":
            return _failure("Reinitialization was not acknowledged; no state was changed.")

    from .supervision_state import SupervisionState

    try:
        if command == "init":
            state = SupervisionState.initialize(settings.state_dir)
        else:
            state = SupervisionState.reinitialize(settings.state_dir)
    except (OSError, ValueError) as error:
        reason = getattr(error, "reason", None)
        detail = f" ({reason})" if isinstance(reason, str) else ""
        return _failure(f"Supervision state operation failed: {error}{detail}")
    try:
        if command == "init":
            print("Private supervision state initialized; no agent was started.")
        else:
            print(f"Private supervision state reinitialized; the prior namespace remains at {previous_path}.")
    finally:
        state.close()
    return 0
