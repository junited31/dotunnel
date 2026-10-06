import hashlib
import json
import unittest

from dotunnel_adapter.protocol import (
    RunnerError,
    binding,
    canonical_json,
    decode_json,
    fingerprint,
    normalize_result,
    validate_capabilities,
    validate_inspection,
    validate_request,
)


ACTIONS = (
    "capabilities", "list_targets", "inspect", "read_output", "start",
    "submit", "answer", "cancel", "report",
)


def request(action="read_output"):
    value = {
        "protocol": "dotunnel.adapter/1",
        "request_id": "request_1",
        "action": action,
        "owner": {"instance_id": "operator_1", "epoch": 7},
        "project": {"id": "project_1", "generation": "project-generation-2"},
        "backend": {"id": "backend_1", "generation": "backend-generation-3"},
    }
    if action not in ("capabilities", "list_targets"):
        value["target"] = {
            "kind": "agent", "id": "agent_1", "incarnation": "incarnation_2",
        }
    if action == "read_output":
        value["limit"] = 100
    if action == "start":
        value["target"] = {"kind": "profile", "id": "profile_1", "incarnation": "profile-generation-1"}
        value["instruction"] = "Do the bounded task."
    if action == "submit":
        value["instruction"] = "Do the bounded task."
    if action == "answer":
        value["prompt"] = {"id": "prompt_1", "revision": 2, "choice": "approve"}
    if action == "cancel":
        value["target"] = {"kind": "owned-job", "id": "job_1", "incarnation": "attempt_1"}
        value["job_id"] = "job_1"
        value["attempt_id"] = "attempt_1"
    if action == "report":
        value["job_id"] = "job_1"
        value["attempt_id"] = "attempt_1"
    if action in ("start", "submit", "answer", "cancel"):
        value["operation"] = {"id": "operation_1", "fingerprint": "sha256:" + "0" * 64}
        value["operation"]["fingerprint"] = fingerprint(value)
        value["authorization"] = {"grant_id": "grant_1", "action": action}
    return value


def capabilities():
    return {
        "adapter": {"id": "backend_1", "version": "1.0.0", "digest": "sha256:" + "a" * 64},
        "operations": {action: action in {"capabilities", "inspect", "read_output"} for action in ACTIONS},
        "identity": {
            "stable_target_id": True,
            "target_incarnation": True,
            "owned_process_identity": False,
            "atomic_target_compare": True,
            "prompt_compare_and_set": True,
        },
        "completion": {"authoritative_logical_result": False},
    }


def result(job_state="completed", authoritative=False, source="owned_process", tail="read-only result\n"):
    return {
        "status": {
            "job_state": job_state,
            "target_state": "ready",
            "process": {"state": "exited", "exit_code": 0},
            "completion": {"authoritative": authoritative, "source": source},
            "observed_at": "2026-10-06T00:00:00Z",
            "revision": 1,
        },
        "output": {"tail": tail, "truncated": False},
    }


class ProtocolTests(unittest.TestCase):
    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(RunnerError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_runner_error_exposes_only_fixed_code(self):
        error = RunnerError("backend_unavailable")
        self.assertEqual(error.code, "backend_unavailable")
        self.assertEqual(str(error), "backend_unavailable")
        untrusted = RunnerError("raw backend stderr")
        self.assertEqual(untrusted.code, "invalid_request")
        self.assertEqual(str(untrusted), "invalid_request")

    def test_decode_json_rejects_duplicate_keys_nonfinite_float_invalid_utf8_and_non_objects(self):
        for raw in (
            b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.0}', b"\xff", b"[]",
        ):
            self.assert_code("invalid_request", decode_json, raw)

    def test_decode_json_enforces_size_and_scalar_depth_boundaries(self):
        self.assert_code("resource_limit", decode_json, b'{"x":"1234"}', limit=8)
        self.assert_code("invalid_request", decode_json, b'{"x":"\\ud800"}')
        self.assert_code("invalid_request", decode_json, b'{"x":' + b"[" * 70 + b"0" + b"]" * 70 + b"}")

    def test_canonical_json_sorts_utf16_code_units_without_normalizing_unicode(self):
        value = {"\ue000": "e\u0301", "\U0001f600": "é", "a": [2, 1]}
        encoded = canonical_json(value)
        expected = '{"a":[2,1],"😀":"é","":"é"}'.encode("utf-8")
        self.assertEqual(encoded, expected)
        self.assertNotEqual(canonical_json({"name": "é"}), canonical_json({"name": "e\u0301"}))

    def test_canonical_json_rejects_float_boolean_integer_alias_and_unsafe_integer(self):
        for value in (1.0, float("inf"), 2**53, -(2**53), {"x": True, "n": 1.5}, "\udfff"):
            self.assert_code("invalid_request", canonical_json, value)
        self.assertEqual(canonical_json(True), b"true")
        self.assertEqual(canonical_json(1), b"1")

    def test_fingerprint_excludes_request_owner_operation_and_authorization_but_binds_inputs(self):
        original = request("submit")
        first = fingerprint(original)
        changed_reference = dict(original)
        changed_reference["request_id"] = "other"
        changed_reference["owner"] = {"instance_id": "other", "epoch": 8}
        changed_reference["authorization"] = {"grant_id": "different", "action": "submit"}
        changed_reference["operation"] = {"id": "different", "fingerprint": "sha256:" + "f" * 64}
        self.assertEqual(fingerprint(changed_reference), first)
        changed_input = dict(original)
        changed_input["instruction"] = "A different instruction"
        self.assertNotEqual(fingerprint(changed_input), first)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")

    def test_every_action_has_strict_schema_and_only_operator_approval_may_be_omitted(self):
        for action in ACTIONS:
            valid = request(action)
            self.assertEqual(validate_request(valid), valid)
            unknown = dict(valid)
            unknown["command"] = "whoami"
            self.assert_code("invalid_request", validate_request, unknown, allow_unapproved=True)
        required_fields = {
            "inspect": ("target",),
            "read_output": ("target",),
            "start": ("target", "instruction", "operation"),
            "submit": ("target", "instruction", "operation"),
            "answer": ("target", "prompt", "operation"),
            "cancel": ("target", "job_id", "attempt_id", "operation"),
            "report": ("target", "job_id", "attempt_id"),
        }
        for action, fields in required_fields.items():
            for field in fields:
                missing = dict(request(action))
                missing.pop(field)
                self.assert_code("invalid_request", validate_request, missing, allow_unapproved=True)
        unapproved = request("submit")
        unapproved.pop("authorization")
        self.assert_code("approval_required", validate_request, unapproved)
        self.assertEqual(validate_request(unapproved, allow_unapproved=True), unapproved)
        unapproved["instruction"] = "x" * 8193
        self.assert_code("invalid_request", validate_request, unapproved, allow_unapproved=True)

    def test_request_rejects_bool_integer_invalid_generations_and_fingerprint_mismatch(self):
        invalid_epoch = request()
        invalid_epoch["owner"]["epoch"] = True
        self.assert_code("invalid_request", validate_request, invalid_epoch)
        invalid_revision = request("answer")
        invalid_revision["prompt"]["revision"] = False
        invalid_revision["operation"]["fingerprint"] = fingerprint(invalid_revision)
        self.assert_code("invalid_request", validate_request, invalid_revision)
        invalid_generation = request()
        invalid_generation["backend"]["generation"] = "\ud800"
        self.assert_code("invalid_request", validate_request, invalid_generation)
        bad_fingerprint = request("cancel")
        bad_fingerprint["operation"]["fingerprint"] = "sha256:" + "f" * 64
        self.assert_code("invalid_request", validate_request, bad_fingerprint)

    def test_binding_contains_only_the_validated_owner_project_backend_and_target(self):
        request_value = request("inspect")
        self.assertEqual(binding(request_value), {
            "owner": request_value["owner"],
            "project": request_value["project"],
            "backend": request_value["backend"],
            "target": request_value["target"],
        })

    def test_capabilities_require_all_nine_operations_and_five_identity_contracts(self):
        parsed = validate_capabilities(capabilities())
        self.assertEqual(parsed["operations"]["cancel"], False)
        bad = capabilities()
        bad["operations"].pop("answer")
        self.assert_code("invalid_request", validate_capabilities, bad)
        bad = capabilities()
        bad["identity"]["atomic_target_compare"] = 1
        self.assert_code("invalid_request", validate_capabilities, bad)

    def test_inspection_requires_exact_incarnation_and_prompt_choice_binding(self):
        request_value = request("answer")
        inspection = {
            "target": request_value["target"],
            "prompt": {"id": "prompt_1", "revision": 2, "choices": ["approve", "reject"]},
        }
        self.assertEqual(validate_inspection(inspection, request_value), inspection)
        missing_identity = dict(inspection)
        missing_identity["target"] = dict(inspection["target"])
        missing_identity["target"].pop("incarnation")
        self.assert_code("target_identity_unverifiable", validate_inspection, missing_identity, request_value)
        stale = dict(inspection)
        stale["target"] = dict(inspection["target"], incarnation="reused")
        self.assert_code("stale_target", validate_inspection, stale, request_value)
        wrong_choice = dict(request_value)
        wrong_choice["prompt"] = dict(request_value["prompt"], choice="later")
        wrong_choice["operation"]["fingerprint"] = fingerprint(wrong_choice)
        self.assert_code("stale_target", validate_inspection, inspection, wrong_choice)

    def test_normalization_sanitizes_output_recomputes_digest_and_rejects_process_success_claim(self):
        request_value = request()
        raw = result(tail="\x1b[31mOK\x1b[0m\x00\u202e\n")
        raw["output"]["sha256"] = "sha256:" + "0" * 64
        normalized = normalize_result(raw, request_value)
        self.assertEqual(normalized["status"]["job_state"], "outcome_unknown")
        self.assertEqual(normalized["output"]["tail"], "OK\n")
        expected = b"OK\n"
        self.assertEqual(normalized["output"]["bytes"], len(expected))
        self.assertEqual(normalized["output"]["sha256"], "sha256:" + hashlib.sha256(expected).hexdigest())

    def test_normalization_preserves_only_authoritative_provider_or_wrapper_completion(self):
        request_value = request()
        provider = normalize_result(result(authoritative=True, source="provider"), request_value)
        self.assertEqual(provider["status"]["job_state"], "completed")
        heuristic = normalize_result(result(authoritative=True, source="heuristic"), request_value)
        self.assertEqual(heuristic["status"]["job_state"], "outcome_unknown")
        self.assertEqual(normalize_result(result(job_state="failed", authoritative=False), request_value)["status"]["job_state"], "outcome_unknown")

    def test_read_output_limit_caps_utf8_tail_and_hashes_only_complete_suffix(self):
        request_value = request()
        request_value["limit"] = 4
        normalized = normalize_result(result(tail="a€z"), request_value)
        tail_bytes = "€z".encode("utf-8")
        self.assertEqual(normalized["output"]["tail"], "€z")
        self.assertEqual(normalized["output"]["bytes"], 4)
        self.assertTrue(normalized["output"]["truncated"])
        self.assertEqual(normalized["output"]["sha256"], "sha256:" + hashlib.sha256(tail_bytes).hexdigest())

    def test_normalization_bounds_utf8_tail_without_splitting_codepoints_and_validates_status(self):
        request_value = request()
        request_value["limit"] = 16384
        normalized = normalize_result(result(tail="x" * 16380 + "é" * 20), request_value)
        tail_bytes = normalized["output"]["tail"].encode("utf-8")
        self.assertLessEqual(len(tail_bytes), 16384)
        self.assertTrue(normalized["output"]["truncated"])
        self.assertEqual(normalized["output"]["sha256"], "sha256:" + hashlib.sha256(tail_bytes).hexdigest())
        bad = result()
        bad["status"]["observed_at"] = "2026-10-06T00:00:00+00:00"
        self.assert_code("invalid_request", normalize_result, bad, request())
        bad = result()
        bad["status"]["revision"] = True
        self.assert_code("invalid_request", normalize_result, bad, request())

    def test_process_exit_observations_must_match_process_state(self):
        bad = result()
        bad["status"]["process"] = {"state": "running", "exit_code": 0}
        self.assert_code("invalid_request", normalize_result, bad, request())


if __name__ == "__main__":
    unittest.main()
