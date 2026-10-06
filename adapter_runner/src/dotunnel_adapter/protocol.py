"""Strict protocol validation shared by the optional adapter runner."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime
from typing import Any


_PROTOCOL = "dotunnel.adapter/1"
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_REQUEST_BYTES = 65536
_MAX_OUTPUT_BYTES = 16384
_MAX_REPORT_BYTES = 65536
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[P^_].*?\x1b\\|[@-_])",
    re.DOTALL,
)
_ERROR_CODES = frozenset(
    {
        "invalid_request",
        "invalid_config",
        "unsupported",
        "approval_required",
        "protected_project",
        "stale_target",
        "target_identity_unverifiable",
        "operation_conflict",
        "outcome_unknown",
        "resource_limit",
        "backend_unavailable",
        "state_unavailable",
        "request_conflict",
    }
)
_ACTIONS = frozenset(
    {
        "capabilities",
        "list_targets",
        "inspect",
        "read_output",
        "start",
        "submit",
        "answer",
        "cancel",
        "report",
    }
)
_MUTATIONS = frozenset({"start", "submit", "answer", "cancel"})
_TARGET_KINDS = frozenset({"agent", "owned-job", "profile"})
_JOB_STATES = frozenset(
    {
        "accepted",
        "queued",
        "starting",
        "running",
        "waiting_input",
        "blocked_approval",
        "completed",
        "failed",
        "cancelled",
        "outcome_unknown",
        "detached",
        "stale",
    }
)
_TARGET_STATES = frozenset({"ready", "working", "blocked", "unknown", "stale"})
_PROCESS_STATES = frozenset({"not_started", "starting", "running", "exited", "signaled", "unknown"})
_COMPLETION_SOURCES = frozenset({"provider", "owned_wrapper", "owned_process", "heuristic"})


class RunnerError(Exception):
    """An operator-safe error whose text is only a stable public code."""

    def __init__(self, code: str):
        self.code = code if isinstance(code, str) and code in _ERROR_CODES else "invalid_request"
        super().__init__(self.code)


def _fail(code: str = "invalid_request") -> None:
    raise RunnerError(code)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _reject_number(_value: str) -> Any:
    _fail()


def _check_json_value(value: Any, depth: int = 0) -> None:
    if depth > 64:
        _fail()
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            _fail()
        return
    if isinstance(value, float):
        _fail()
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeError:
            _fail()
        if len(encoded) > _MAX_REQUEST_BYTES:
            _fail("resource_limit")
        return
    if isinstance(value, list):
        for item in value:
            _check_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail()
            _check_json_value(key, depth + 1)
            _check_json_value(item, depth + 1)
        return
    _fail()


def decode_json(data: bytes, limit: int = 65536) -> dict:
    if not isinstance(data, bytes) or type(limit) is not int or limit < 1:
        _fail()
    if len(data) > limit:
        _fail("resource_limit")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        _check_json_value(value)
    except RunnerError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        _fail()
    if not isinstance(value, dict):
        _fail()
    return value


def _canonical_string(value: str) -> str:
    try:
        value.encode("utf-8", "strict")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, UnicodeError, ValueError):
        _fail()


def _canonical_value(value: Any, depth: int = 0) -> str:
    if depth > 64:
        _fail()
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            _fail()
        return str(value)
    if isinstance(value, float):
        _fail()
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_value(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            _fail()
        try:
            keys = sorted(value, key=lambda key: key.encode("utf-16-be", "strict"))
        except UnicodeError:
            _fail()
        return "{" + ",".join(
            _canonical_string(key) + ":" + _canonical_value(value[key], depth + 1)
            for key in keys
        ) + "}"
    _fail()


def canonical_json(value: object) -> bytes:
    try:
        _check_json_value(value)
        return _canonical_value(value).encode("utf-8", "strict")
    except RunnerError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        _fail()


def _text(value: object, minimum: int, maximum: int, *, code: str = "invalid_request") -> str:
    if not isinstance(value, str):
        _fail(code)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        _fail(code)
    if not minimum <= len(encoded) <= maximum:
        _fail(code)
    return value


def _identifier(value: object, *, code: str = "invalid_request") -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail(code)
    return value


def _generation(value: object, *, code: str = "invalid_request") -> str:
    return _text(value, 1, 128, code=code)


def _exact_object(value: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        _fail()
    return value


def _integer(value: object, minimum: int, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _owner(value: object) -> dict:
    owner = _exact_object(value, {"instance_id", "epoch"})
    _identifier(owner["instance_id"])
    _integer(owner["epoch"], 1)
    return owner


def _project(value: object) -> dict:
    project = _exact_object(value, {"id", "generation"})
    _identifier(project["id"])
    _generation(project["generation"])
    return project


def _backend(value: object) -> dict:
    backend = _exact_object(value, {"id", "generation"})
    _identifier(backend["id"])
    _generation(backend["generation"])
    return backend


def _target(value: object) -> dict:
    target = _exact_object(value, {"kind", "id", "incarnation"})
    if not isinstance(target["kind"], str) or target["kind"] not in _TARGET_KINDS:
        _fail()
    _identifier(target["id"])
    _generation(target["incarnation"])
    return target


def _fingerprint_payload(request: dict) -> dict:
    action = request.get("action")
    if not isinstance(action, str) or action not in _ACTIONS:
        _fail()
    keys_by_action = {
        "capabilities": (),
        "list_targets": (),
        "inspect": (),
        "read_output": ("cursor", "limit"),
        "start": ("instruction",),
        "submit": ("instruction",),
        "answer": ("prompt",),
        "cancel": ("job_id", "attempt_id"),
        "report": ("job_id", "attempt_id", "revision", "cursor"),
    }
    payload = {"action": action, "project": request["project"], "backend": request["backend"]}
    if "target" in request:
        payload["target"] = request["target"]
    for key in keys_by_action[action]:
        if key in request:
            payload[key] = request[key]
    return payload


def fingerprint(request: dict) -> str:
    if not isinstance(request, dict):
        _fail()
    try:
        payload = _fingerprint_payload(request)
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    except KeyError:
        _fail()
    return "sha256:" + digest


def validate_request(value: dict, *, allow_unapproved: bool = False) -> dict:
    if not isinstance(value, dict) or type(allow_unapproved) is not bool:
        _fail()
    action = value.get("action")
    if not isinstance(action, str) or action not in _ACTIONS:
        _fail()
    schemas = {
        "capabilities": (set(), set()),
        "list_targets": (set(), set()),
        "inspect": ({"target"}, set()),
        "read_output": ({"target"}, {"cursor", "limit"}),
        "start": ({"target", "instruction", "operation"}, {"authorization"}),
        "submit": ({"target", "instruction", "operation"}, {"authorization"}),
        "answer": ({"target", "prompt", "operation"}, {"authorization"}),
        "cancel": ({"target", "job_id", "attempt_id", "operation"}, {"authorization"}),
        "report": ({"target", "job_id", "attempt_id"}, {"cursor", "revision"}),
    }
    required_action, optional_action = schemas[action]
    base = {"protocol", "request_id", "action", "owner", "project", "backend"}
    if (
        not base <= value.keys()
        or not required_action <= value.keys()
        or value.keys() - base - required_action - optional_action
    ):
        _fail()
    if value["protocol"] != _PROTOCOL:
        _fail()
    _identifier(value["request_id"])
    _owner(value["owner"])
    _project(value["project"])
    _backend(value["backend"])
    if "target" in required_action:
        target = _target(value["target"])
        target_kinds = {
            "start": {"profile"},
            "submit": {"agent", "owned-job"},
            "answer": {"agent", "owned-job"},
            "cancel": {"agent", "owned-job"},
        }
        if action in target_kinds and target["kind"] not in target_kinds[action]:
            _fail()
    if "instruction" in required_action:
        _text(value["instruction"], 1, 8192)
    if "cursor" in value:
        _identifier(value["cursor"])
    if "limit" in value:
        _integer(value["limit"], 1, 16384)
    if "job_id" in value:
        _identifier(value["job_id"])
    if "attempt_id" in value:
        _identifier(value["attempt_id"])
    if "revision" in value:
        _integer(value["revision"], 0)
    if "prompt" in value:
        prompt = _exact_object(value["prompt"], {"id", "revision", "choice"})
        _identifier(prompt["id"])
        _integer(prompt["revision"], 0)
        _text(prompt["choice"], 1, 1024)
    if action in _MUTATIONS:
        operation = _exact_object(value["operation"], {"id", "fingerprint"})
        _identifier(operation["id"])
        if not isinstance(operation["fingerprint"], str) or _SHA256.fullmatch(operation["fingerprint"]) is None:
            _fail()
        if operation["fingerprint"] != fingerprint(value):
            _fail()
        if "authorization" not in value:
            if not allow_unapproved:
                _fail("approval_required")
        else:
            authorization = _exact_object(value["authorization"], {"grant_id", "action"})
            _identifier(authorization["grant_id"])
            if authorization["action"] != action:
                _fail()
    _check_json_value(value)
    return value


def binding(request: dict) -> dict:
    if not isinstance(request, dict):
        _fail()
    result = {}
    for key in ("owner", "project", "backend", "target"):
        if key in request:
            result[key] = request[key]
    if not {"owner", "project", "backend"} <= result.keys():
        _fail()
    return result


def validate_capabilities(value: dict) -> dict:
    capabilities = _exact_object(
        value,
        {"adapter", "operations", "identity", "completion"},
        {"durable_idempotency", "limits"},
    )
    adapter = _exact_object(capabilities["adapter"], {"id", "version", "digest"})
    _identifier(adapter["id"])
    _text(adapter["version"], 1, 128)
    if not isinstance(adapter["digest"], str) or _SHA256.fullmatch(adapter["digest"]) is None:
        _fail()
    operations = _exact_object(capabilities["operations"], set(_ACTIONS))
    if any(type(enabled) is not bool for enabled in operations.values()):
        _fail()
    identity = _exact_object(
        capabilities["identity"],
        {
            "stable_target_id",
            "target_incarnation",
            "owned_process_identity",
            "atomic_target_compare",
            "prompt_compare_and_set",
        },
    )
    if any(type(enabled) is not bool for enabled in identity.values()):
        _fail()
    completion = _exact_object(capabilities["completion"], {"authoritative_logical_result"})
    if type(completion["authoritative_logical_result"]) is not bool:
        _fail()
    if "durable_idempotency" in capabilities and type(capabilities["durable_idempotency"]) is not bool:
        _fail()
    if "limits" in capabilities:
        limits = _exact_object(
            capabilities["limits"],
            set(),
            {"instruction_bytes", "report_file_bytes", "task_stdout_bytes", "output_tail_bytes"},
        )
        maximums = {
            "instruction_bytes": 8192,
            "report_file_bytes": 65536,
            "task_stdout_bytes": 16384,
            "output_tail_bytes": 16384,
        }
        for key, limit in limits.items():
            _integer(limit, 1, maximums[key])
    _check_json_value(capabilities)
    return capabilities


def validate_inspection(value: dict, request: dict) -> dict:
    inspection = _exact_object(value, {"target"}, {"prompt", "ownership"})
    raw_target = inspection["target"]
    if not isinstance(raw_target, dict) or not {"kind", "id", "incarnation"} <= raw_target.keys():
        _fail("target_identity_unverifiable")
    returned_target = _target(raw_target)
    request_target = _target(request.get("target"))
    if returned_target != request_target:
        _fail("stale_target")
    if "prompt" in inspection:
        prompt = _exact_object(inspection["prompt"], {"id", "revision", "choices"})
        _identifier(prompt["id"])
        _integer(prompt["revision"], 0)
        choices = prompt["choices"]
        if not isinstance(choices, list) or not 1 <= len(choices) <= 64:
            _fail()
        for choice in choices:
            _text(choice, 1, 1024)
    if "ownership" in inspection:
        ownership = _exact_object(inspection["ownership"], {"owner", "job_id", "attempt_id"})
        _owner(ownership["owner"])
        _identifier(ownership["job_id"])
        _identifier(ownership["attempt_id"])
    action = request.get("action")
    if action == "answer":
        prompt = inspection.get("prompt")
        if prompt is None:
            _fail("target_identity_unverifiable")
        expected = request.get("prompt")
        if prompt["id"] != expected["id"] or prompt["revision"] != expected["revision"]:
            _fail("stale_target")
        if expected["choice"] not in prompt["choices"]:
            _fail("stale_target")
    if action == "cancel":
        ownership = inspection.get("ownership")
        if ownership is None:
            _fail("target_identity_unverifiable")
        if (
            ownership["owner"] != request.get("owner")
            or ownership["job_id"] != request.get("job_id")
            or ownership["attempt_id"] != request.get("attempt_id")
        ):
            _fail("stale_target")
    _check_json_value(inspection)
    return inspection


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        _fail()
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail()
    return value


def _clean_output(value: str, limit: int) -> tuple[str, bool]:
    without_ansi = _ANSI_ESCAPE.sub("", value)
    filtered = "".join(
        character
        for character in without_ansi
        if character in "\n\t" or not unicodedata.category(character).startswith("C")
    )
    was_reduced = filtered != value
    encoded = filtered.encode("utf-8", "strict")
    truncated = len(encoded) > limit
    if truncated:
        encoded = encoded[-limit:]
        while encoded and encoded[0] & 0xC0 == 0x80:
            encoded = encoded[1:]
        filtered = encoded.decode("utf-8", "strict")
    return filtered, was_reduced or truncated


def normalize_result(value: dict, request: dict) -> dict:
    if not isinstance(request, dict):
        _fail()
    result = _exact_object(value, {"status", "output"}, {"report", "target"})
    raw_status = _exact_object(result["status"], {"job_state", "target_state", "process", "completion", "observed_at", "revision"}, {"source"})
    if not isinstance(raw_status["job_state"], str) or raw_status["job_state"] not in _JOB_STATES:
        _fail()
    if not isinstance(raw_status["target_state"], str) or raw_status["target_state"] not in _TARGET_STATES:
        _fail()
    process = _exact_object(raw_status["process"], {"state"}, {"exit_code", "signal", "identity"})
    if not isinstance(process["state"], str) or process["state"] not in _PROCESS_STATES:
        _fail()
    if "exit_code" in process:
        _integer(process["exit_code"], 0, 255)
    if "signal" in process:
        _integer(process["signal"], 1, 127)
    if "identity" in process:
        _text(process["identity"], 1, 128)
    if "exit_code" in process and process["state"] != "exited":
        _fail()
    if "signal" in process and process["state"] != "signaled":
        _fail()
    completion = _exact_object(raw_status["completion"], {"authoritative", "source"})
    if type(completion["authoritative"]) is not bool or not isinstance(completion["source"], str) or completion["source"] not in _COMPLETION_SOURCES:
        _fail()
    if "source" in raw_status and (not isinstance(raw_status["source"], str) or raw_status["source"] not in _COMPLETION_SOURCES):
        _fail()
    _timestamp(raw_status["observed_at"])
    _integer(raw_status["revision"], 0)
    status = {
        "job_state": raw_status["job_state"],
        "target_state": raw_status["target_state"],
        "process": dict(process),
        "completion": dict(completion),
        "observed_at": raw_status["observed_at"],
        "revision": raw_status["revision"],
    }
    if "source" in raw_status:
        status["source"] = raw_status["source"]
    if status["job_state"] in {"completed", "failed", "cancelled"} and not (
        completion["authoritative"]
        and completion["source"] in {"provider", "owned_wrapper"}
        and status.get("source", completion["source"]) in {"provider", "owned_wrapper"}
    ):
        status["job_state"] = "outcome_unknown"
    raw_output = _exact_object(result["output"], {"tail", "truncated"}, {"cursor", "bytes", "sha256"})
    tail = _text(raw_output["tail"], 0, _MAX_REQUEST_BYTES)
    if type(raw_output["truncated"]) is not bool:
        _fail()
    if "cursor" in raw_output:
        _identifier(raw_output["cursor"])
    if "bytes" in raw_output:
        _integer(raw_output["bytes"], 0)
    if "sha256" in raw_output:
        if not isinstance(raw_output["sha256"], str) or _SHA256.fullmatch(raw_output["sha256"]) is None:
            _fail()
    output_limit = _MAX_OUTPUT_BYTES
    if request.get("action") == "read_output" and "limit" in request:
        output_limit = min(output_limit, _integer(request["limit"], 1, 16384))
    clean_tail, reduced = _clean_output(tail, output_limit)
    tail_bytes = clean_tail.encode("utf-8", "strict")
    output = {
        "tail": clean_tail,
        "truncated": raw_output["truncated"] or reduced,
        "bytes": len(tail_bytes),
        "sha256": "sha256:" + hashlib.sha256(tail_bytes).hexdigest(),
    }
    if "cursor" in raw_output:
        output["cursor"] = raw_output["cursor"]
    normalized = {"status": status, "output": output}
    if "report" in result:
        _check_json_value(result["report"])
        normalized["report"] = result["report"]
    if "target" in result:
        if request.get("action") != "start":
            _fail()
        created_target = _target(result["target"])
        if created_target["kind"] not in {"agent", "owned-job"}:
            _fail()
        normalized["target"] = created_target
    serialized = canonical_json(normalized)
    if len(serialized) > _MAX_REPORT_BYTES:
        _fail("resource_limit")
    return normalized
