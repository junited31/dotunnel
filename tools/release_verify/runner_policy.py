"""Pure policy for the fixed, owner-only kernel pilot invocation.

These checks validate bounded routing metadata and fixed names. They do not
authenticate a workflow, verify a source closure, or prove systemd/kernel state.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


GIB: Final = 1024 ** 3
MIB: Final = 1024 ** 2
_NANOSECONDS: Final = 1_000_000_000
_MAX_CONTEXT_BYTES: Final = 4096
_RUN_ID_PATTERN: Final = re.compile(r"[1-9][0-9]{0,19}\Z")
_FIXED_CONTEXT: Final = MappingProxyType(
    {
        "schema": 1,
        "repository": "junited31/dotunnel",
        "ref": "refs/heads/main",
        "event": "workflow_dispatch",
        "actor": "junited31",
        "triggering_actor": "junited31",
    }
)
_CONTEXT_FIELDS: Final = frozenset((*_FIXED_CONTEXT, "run", "attempt"))


@dataclass(frozen=True)
class RunNames:
    """Validated Actions run identity and its fixed filesystem/unit names."""

    run: str
    attempt: str

    def __post_init__(self) -> None:
        for value in (self.run, self.attempt):
            if type(value) is not str or _RUN_ID_PATTERN.fullmatch(value) is None:
                raise ValueError("invalid-run-identity")

    @property
    def prefix(self) -> str:
        return f"dotunnelpilot{self.run}a{self.attempt}"

    @property
    def root(self) -> str:
        return f"/run/{self.prefix}"

    @property
    def control(self) -> str:
        return f"{self.root}-control"

    @property
    def backing(self) -> str:
        return f"/var/tmp/{self.prefix}"

    @property
    def source(self) -> str:
        return f"{self.root}-source"

    @property
    def work_slice(self) -> str:
        return f"{self.prefix}.slice"

    @property
    def engine_slice(self) -> str:
        return f"{self.prefix}-engine.slice"

    @property
    def worker_slice(self) -> str:
        return f"{self.prefix}-worker.slice"

    def unit(self, role: str) -> str:
        """Return a canonical unit for a fixed role; caller names are refused."""
        if type(role) is not str or role not in _UNIT_ROLES:
            raise ValueError("unknown-unit-role")
        if role in {"work", "aggregate"}:
            return self.work_slice
        if role == "engine":
            return self.engine_slice
        if role == "worker":
            return self.worker_slice
        if role == "reaper":
            return f"dotunnelreaper{self.run}a{self.attempt}.service"
        if role == "recovery":
            return f"dotunnelrecovery{self.run}a{self.attempt}.service"
        if role == "recovery-probe":
            return f"dotunnelrecoveryprobe{self.run}a{self.attempt}.service"
        if role == "bootstrap-recovery":
            return f"dotunnelbootstraprecovery{self.run}a{self.attempt}.service"
        if role in {"publisher", "publisher-readiness", "publisher-terminal"}:
            suffix = "" if role == "publisher" else "-" + role.removeprefix("publisher-")
            return f"dotunnelpublisher{self.run}a{self.attempt}{suffix}.service"
        return f"{self.prefix}-{role}.service"


BUDGETS: Final = MappingProxyType(
    {
        # (memory_bytes, cpu_percent, tasks, maximum_seconds); swap is always 0.
        "aggregate": (4 * GIB, 200, 384, 450),
        "preparation": (768 * MIB, 100, 128, 90),
        "pull": (128 * MIB, 50, 32, 120),
        "controller": (256 * MIB, 50, 96, 210),
        "engine": (2 * GIB, 100, 256, 450),
        "worker": (512 * MIB, 50, 64, 180),
        "reaper": (128 * MIB, 10, 32, 510),
        "recovery": (128 * MIB, 10, 32, 30),
        "recovery-probe": (128 * MIB, 10, 32, 30),
        "bootstrap-recovery": (128 * MIB, 10, 32, 30),
        "publisher": (256 * MIB, 50, 64, 30),
        "harmless": (256 * MIB, 50, 16, 30),
    }
)

_UNIT_ROLES: Final = frozenset(
    {
        "aggregate",
        "work",
        "preparation",
        "pull",
        "controller",
        "engine",
        "worker",
        "reaper",
        "recovery",
        "recovery-probe",
        "bootstrap-recovery",
        "publisher",
        "publisher-readiness",
        "publisher-terminal",
        "harmless",
    }
)


@dataclass(frozen=True)
class Deadlines:
    """Monotonic stage deadlines, each clipped to the absolute outer deadline."""

    work_ns: int
    cleanup_ns: int
    publish_ns: int
    outer_ns: int


def validate_context(context: object) -> RunNames:
    """Validate the exact owner-only dispatch routing fields.

    This is not authentication and does not validate source, capabilities,
    authority records, platform state, or kernel observations.
    """
    if type(context) is not dict or frozenset(context) != _CONTEXT_FIELDS:
        raise ValueError("untrusted-invocation-fields")
    for field, expected in _FIXED_CONTEXT.items():
        actual = context[field]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError("untrusted-invocation")
    return RunNames(context["run"], context["attempt"])


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-key")
        result[key] = value
    return result


def _reject_json_constant(_token: str) -> object:
    raise ValueError("nonfinite-json-number")


def _parse_finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("nonfinite-json-number")
    return value


def parse_context(raw: bytes) -> RunNames:
    """Parse at most 4096 strict UTF-8 JSON bytes, then validate routing fields."""
    if type(raw) is not bytes or len(raw) > _MAX_CONTEXT_BYTES:
        raise ValueError("invalid-context-bytes")
    try:
        text = raw.decode("utf-8")
        context = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, OverflowError) as exc:
        raise ValueError("invalid-context-json") from exc
    return validate_context(context)


def pilot_id(names: RunNames) -> str:
    """Derive the documented 32-hex pilot binding from validated run identity."""
    if type(names) is not RunNames:
        raise ValueError("invalid-run-names")
    identity = f"junited31/dotunnel:{names.run}:{names.attempt}".encode("ascii")
    return hashlib.sha256(identity).hexdigest()[:32]


def validate_unit_receipt(role: str, names: RunNames, receipt: object) -> None:
    """Check a minimal observed unit tuple against the fixed role hierarchy.

    Matching receipt metadata is not proof that systemd or the kernel supplied
    the observation; callers must independently establish observation authority.
    """
    if type(role) is not str or role not in _RECEIPT_ROLES:
        raise ValueError("unknown-unit-role")
    if type(names) is not RunNames:
        raise ValueError("invalid-run-names")
    if type(receipt) is not dict or frozenset(receipt) != _RECEIPT_FIELDS:
        raise ValueError("invalid-unit-receipt")
    if any(type(receipt[field]) is not str for field in _RECEIPT_FIELDS):
        raise ValueError("invalid-unit-receipt")

    if role == "work":
        expected = (names.work_slice, "-.slice", f"/{names.work_slice}")
    elif role == "engine":
        expected = (
            names.engine_slice,
            names.work_slice,
            f"/{names.work_slice}/{names.engine_slice}",
        )
    elif role == "worker":
        expected = (
            names.worker_slice,
            names.work_slice,
            f"/{names.work_slice}/{names.worker_slice}",
        )
    else:
        external_unit = f"dotunnel{role}{names.run}a{names.attempt}.slice"
        expected = (external_unit, "-.slice", f"/{external_unit}")

    observed = (receipt["unit"], receipt["slice"], receipt["control_group"])
    if observed != expected:
        raise ValueError("unit-receipt-mismatch")


_RECEIPT_FIELDS: Final = frozenset({"unit", "slice", "control_group"})
_RECEIPT_ROLES: Final = frozenset({"work", "engine", "worker", "reaper", "recovery", "publisher"})


def admit_job(remaining_seconds: int | float) -> None:
    """Require preparation, work, cleanup, publication, and safety headroom."""
    if type(remaining_seconds) not in {int, float}:
        raise ValueError("insufficient-job-window")
    if type(remaining_seconds) is float and not math.isfinite(remaining_seconds):
        raise ValueError("insufficient-job-window")
    if remaining_seconds < 540:
        raise ValueError("insufficient-job-window")


def _monotonic_ns(value: object) -> bool:
    return type(value) is int and value >= 0


def plan_deadlines(reaper_start_ns: int, outer_deadline_ns: int) -> Deadlines:
    """Plan fixed work/cleanup/publication caps without extending outer time."""
    if not _monotonic_ns(reaper_start_ns) or not _monotonic_ns(outer_deadline_ns):
        raise ValueError("invalid-monotonic-deadline")
    if outer_deadline_ns < reaper_start_ns:
        raise ValueError("invalid-monotonic-deadline")

    outer_ns = min(
        outer_deadline_ns,
        reaper_start_ns + BUDGETS["reaper"][3] * _NANOSECONDS,
    )
    return Deadlines(
        work_ns=min(reaper_start_ns + 360 * _NANOSECONDS, outer_ns),
        cleanup_ns=min(reaper_start_ns + 390 * _NANOSECONDS, outer_ns),
        publish_ns=min(reaper_start_ns + 420 * _NANOSECONDS, outer_ns),
        outer_ns=outer_ns,
    )


def require_controller_window(deadlines: Deadlines, now_ns: int) -> None:
    """Require the entire controller budget before its admission closes."""
    if type(deadlines) is not Deadlines or not _monotonic_ns(now_ns):
        raise ValueError("invalid-controller-deadline")
    if any(
        not _monotonic_ns(value)
        for value in (deadlines.work_ns, deadlines.cleanup_ns, deadlines.publish_ns, deadlines.outer_ns)
    ):
        raise ValueError("invalid-controller-deadline")
    if not (
        deadlines.work_ns <= deadlines.cleanup_ns <= deadlines.publish_ns <= deadlines.outer_ns
    ):
        raise ValueError("invalid-controller-deadline")
    required_ns = BUDGETS["controller"][3] * _NANOSECONDS
    if deadlines.work_ns - now_ns < required_ns:
        raise ValueError("insufficient-controller-window")
