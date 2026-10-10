import importlib
import json
import re
import unittest
from dataclasses import FrozenInstanceError


_MODULE_NAME = "tools.release_verify.runner_policy"
_MAX_CONTEXT_BYTES = 4096
_NANOSECONDS = 1_000_000_000


def _context(**overrides):
    value = {
        "schema": 1,
        "repository": "junited31/dotunnel",
        "ref": "refs/heads/main",
        "event": "workflow_dispatch",
        "actor": "junited31",
        "triggering_actor": "junited31",
        "run": "731942",
        "attempt": "2",
    }
    value.update(overrides)
    return value


def _raw_context(value):
    return json.dumps(
        value,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _unit_receipt(role, names):
    """Minimal proposed systemd observation: Id, Slice, and ControlGroup."""
    prefix = f"dotunnelpilot{names.run}a{names.attempt}"
    if role == "work":
        unit = f"{prefix}.slice"
        parent = "-.slice"
        control_group = f"/{unit}"
    elif role == "engine":
        unit = f"{prefix}-engine.slice"
        parent = f"{prefix}.slice"
        control_group = f"/{parent}/{unit}"
    elif role == "worker":
        unit = f"{prefix}-worker.slice"
        parent = f"{prefix}.slice"
        control_group = f"/{parent}/{unit}"
    elif role in {"reaper", "recovery", "publisher"}:
        external_prefix = f"dotunnel{role}{names.run}a{names.attempt}"
        unit = f"{external_prefix}.slice"
        parent = "-.slice"
        control_group = f"/{unit}"
    else:
        raise AssertionError(f"test fixture has no receipt for role {role!r}")
    return {"unit": unit, "slice": parent, "control_group": control_group}


class ReleaseVerifyRunnerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.policy = importlib.import_module(_MODULE_NAME)

    def _assert_rejected(self, callback, *args, **kwargs):
        try:
            callback(*args, **kwargs)
        except (TypeError, ValueError):
            return
        self.fail(f"{callback.__name__} accepted an unsafe policy input")

    def test_valid_owner_dispatch_is_a_control_for_context_denials(self):
        expected = _context()
        from_dict = self.policy.validate_context(expected)
        from_json = self.policy.parse_context(_raw_context(expected))
        self.assertEqual((from_dict.run, from_dict.attempt), (from_json.run, from_json.attempt))

    def test_context_rejects_foreign_dispatch_and_rerun_actors(self):
        for field, value in (
            ("actor", "outside-contributor"),
            ("triggering_actor", "outside-contributor"),
            ("repository", "other/project"),
            ("ref", "refs/heads/feature"),
            ("event", "pull_request"),
        ):
            with self.subTest(field=field):
                context = _context(**{field: value})
                self._assert_rejected(self.policy.validate_context, context)
                self._assert_rejected(self.policy.parse_context, _raw_context(context))

    def test_context_rejects_caller_supplied_capabilities_paths_and_limits(self):
        for field, value in (
            ("capabilities", ["CAP_SYS_ADMIN"]),
            ("path", "/tmp/attacker-controlled"),
            ("limits", {"memory_bytes": 1}),
        ):
            with self.subTest(field=field):
                self._assert_rejected(self.policy.validate_context, _context(**{field: value}))
                self._assert_rejected(self.policy.parse_context, _raw_context(_context(**{field: value})))

    def test_context_rejects_missing_required_fields(self):
        context = _context()
        del context["triggering_actor"]
        self._assert_rejected(self.policy.validate_context, context)
        self._assert_rejected(self.policy.parse_context, _raw_context(context))

    def test_context_rejects_wrong_types_boolean_integers_and_invalid_run_numbers(self):
        invalid_values = (
            ("schema", True),
            ("run", True),
            ("attempt", False),
            ("run", 731942),
            ("attempt", 2),
            ("run", 731942.0),
            ("attempt", None),
            ("repository", None),
            ("ref", []),
            ("event", 0),
            ("actor", {}),
            ("triggering_actor", ["junited31"]),
            ("run", "0"),
            ("attempt", "-1"),
            ("run", "1" + "0" * 20),
            ("attempt", "1" + "0" * 20),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                raw = _raw_context(_context(**{field: value}))
                self._assert_rejected(self.policy.validate_context, _context(**{field: value}))
                self._assert_rejected(self.policy.parse_context, raw)

    def test_context_rejects_non_decimal_run_traversal_values(self):
        for field, value in (
            ("run", "../other"),
            ("run", "/tmp/pilot"),
            ("run", "%2e%2e%2fother"),
            ("attempt", "1/../../other"),
        ):
            with self.subTest(field=field, value=value):
                raw = _raw_context(_context(**{field: value}))
                self._assert_rejected(self.policy.validate_context, _context(**{field: value}))
                self._assert_rejected(self.policy.parse_context, raw)

    def test_context_accepts_twenty_digit_positive_run_and_attempt(self):
        value = _context(run="99999999999999999999", attempt="99999999999999999999")
        names = self.policy.validate_context(value)
        self.assertEqual(names.run, value["run"])
        self.assertEqual(names.attempt, value["attempt"])

    def test_raw_context_rejects_duplicate_keys(self):
        raw = (
            b'{"schema":1,"repository":"junited31/dotunnel","ref":"refs/heads/main",'
            b'"event":"workflow_dispatch","actor":"junited31",'
            b'"triggering_actor":"outside-contributor","triggering_actor":"junited31",'
            b'"run":"731942","attempt":"2"}'
        )
        self._assert_rejected(self.policy.parse_context, raw)

    def test_raw_context_rejects_nonfinite_json_numbers(self):
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            raw = _raw_context(_context()).replace(b'"run":"731942"', b'"run":' + token)
            with self.subTest(token=token):
                self._assert_rejected(self.policy.parse_context, raw)

    def test_raw_context_enforces_total_byte_limit_at_boundary(self):
        valid = _raw_context(_context())
        self.assertLess(len(valid), _MAX_CONTEXT_BYTES)
        at_limit = valid + b" " * (_MAX_CONTEXT_BYTES - len(valid))
        names = self.policy.parse_context(at_limit)
        self.assertEqual((names.run, names.attempt), ("731942", "2"))
        self._assert_rejected(self.policy.parse_context, at_limit + b" ")

    def test_raw_context_rejects_non_object_malformed_utf8_and_unknown_fields(self):
        for raw in (
            b"[]",
            b"{",
            b"\xff",
            _raw_context(_context(untrusted_path="/tmp/elsewhere")),
        ):
            with self.subTest(raw=raw):
                self._assert_rejected(self.policy.parse_context, raw)

    def test_run_names_and_pilot_binding_are_frozen_and_run_derived(self):
        names = self.policy.validate_context(_context())
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            names.run = 12

        pilot_id = self.policy.pilot_id(names)
        self.assertRegex(pilot_id, re.compile(r"\A[0-9a-fA-F]{32}\Z"))
        self.assertEqual(pilot_id, self.policy.pilot_id(self.policy.validate_context(_context())))
        self.assertNotEqual(pilot_id, self.policy.pilot_id(self.policy.validate_context(_context(run="731943"))))
        self.assertNotEqual(pilot_id, self.policy.pilot_id(self.policy.validate_context(_context(attempt="3"))))

    def test_observed_unit_receipt_binds_worker_names_to_its_run(self):
        names = self.policy.validate_context(_context())
        receipt = _unit_receipt("worker", names)
        self.assertIsNone(self.policy.validate_unit_receipt("worker", names, receipt))

        other_run = self.policy.validate_context(_context(run="731943"))
        self._assert_rejected(self.policy.validate_unit_receipt, "worker", other_run, receipt)

    def test_observed_engine_and_worker_receipts_must_follow_work_descendants(self):
        names = self.policy.validate_context(_context())
        for role in ("work", "engine", "worker"):
            with self.subTest(role=role):
                self.assertIsNone(self.policy.validate_unit_receipt(role, names, _unit_receipt(role, names)))

        work_prefix = f"dotunnelpilot{names.run}a{names.attempt}"
        engine = _unit_receipt("engine", names)
        self._assert_rejected(
            self.policy.validate_unit_receipt,
            "engine",
            names,
            {**engine, "slice": "-.slice", "control_group": f"/{engine['unit']}"},
        )
        worker = _unit_receipt("worker", names)
        self._assert_rejected(
            self.policy.validate_unit_receipt,
            "worker",
            names,
            {
                **worker,
                "slice": f"{work_prefix}-engine.slice",
                "control_group": f"/{work_prefix}.slice/{work_prefix}-engine.slice/{worker['unit']}",
            },
        )

    def test_observed_external_units_are_siblings_not_work_descendants(self):
        names = self.policy.validate_context(_context())
        work_prefix = f"dotunnelpilot{names.run}a{names.attempt}"
        for role in ("reaper", "recovery", "publisher"):
            receipt = _unit_receipt(role, names)
            with self.subTest(role=role):
                self.assertIsNone(self.policy.validate_unit_receipt(role, names, receipt))
                nested = {
                    **receipt,
                    "slice": f"{work_prefix}.slice",
                    "control_group": f"/{work_prefix}.slice/{receipt['unit']}",
                }
                self._assert_rejected(self.policy.validate_unit_receipt, role, names, nested)

    def test_observed_unit_receipts_reject_extra_effect_authority_fields(self):
        names = self.policy.validate_context(_context())
        receipt = _unit_receipt("worker", names)
        for field, value in (
            ("capabilities", ["CAP_SYS_ADMIN"]),
            ("path", "/tmp/attacker-controlled"),
            ("limits", {"memory_bytes": 1}),
        ):
            with self.subTest(field=field):
                self._assert_rejected(
                    self.policy.validate_unit_receipt,
                    "worker",
                    names,
                    {**receipt, field: value},
                )

    def test_budget_policy_cannot_be_mutated_by_a_consumer(self):
        before = self.policy.BUDGETS["engine"]
        with self.assertRaises(TypeError):
            self.policy.BUDGETS["engine"] = (1, 1, 1, 1)
        self.assertEqual(self.policy.BUDGETS["engine"], before)

    def test_privileged_effect_admission_requires_full_job_window(self):
        self.assertIsNone(self.policy.admit_job(540))
        self.assertIsNone(self.policy.admit_job(600))
        for remaining in (539.999, 0, -1, True, float("inf"), float("nan")):
            with self.subTest(remaining=remaining):
                self._assert_rejected(self.policy.admit_job, remaining)

    def test_deadlines_are_monotonic_and_cannot_outlive_outer_job_or_stage_caps(self):
        start_ns = 10 * _NANOSECONDS
        outer_ns = start_ns + 600 * _NANOSECONDS
        deadlines = self.policy.plan_deadlines(start_ns, outer_ns)

        self.assertEqual(deadlines.work_ns, start_ns + 360 * _NANOSECONDS)
        self.assertEqual(deadlines.cleanup_ns, start_ns + 390 * _NANOSECONDS)
        self.assertEqual(deadlines.publish_ns, start_ns + 420 * _NANOSECONDS)
        engine_limit_ns = start_ns + self.policy.BUDGETS["engine"][3] * _NANOSECONDS
        self.assertLessEqual(deadlines.work_ns, deadlines.cleanup_ns)
        self.assertLessEqual(deadlines.cleanup_ns, deadlines.publish_ns)
        self.assertLessEqual(deadlines.publish_ns, engine_limit_ns)
        self.assertLessEqual(engine_limit_ns, deadlines.outer_ns)
        self.assertLessEqual(deadlines.outer_ns, min(outer_ns, start_ns + 510 * _NANOSECONDS))
        self.assertLessEqual(deadlines.work_ns, deadlines.cleanup_ns)
        self.assertLessEqual(deadlines.cleanup_ns, deadlines.publish_ns)
        self.assertLessEqual(deadlines.publish_ns, deadlines.outer_ns)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            deadlines.work_ns = outer_ns

    def test_short_outer_deadline_only_shortens_stage_deadlines(self):
        start_ns = 20 * _NANOSECONDS
        long = self.policy.plan_deadlines(start_ns, start_ns + 600 * _NANOSECONDS)
        short_outer_ns = start_ns + 300 * _NANOSECONDS
        short = self.policy.plan_deadlines(start_ns, short_outer_ns)

        self.assertLessEqual(short.work_ns, short_outer_ns)
        self.assertLessEqual(short.cleanup_ns, short_outer_ns)
        self.assertLessEqual(short.publish_ns, short_outer_ns)
        self.assertLessEqual(short.outer_ns, short_outer_ns)
        self.assertLessEqual(short.work_ns, long.work_ns)
        self.assertLessEqual(short.cleanup_ns, long.cleanup_ns)
        self.assertLessEqual(short.publish_ns, long.publish_ns)
        self.assertLessEqual(short.outer_ns, long.outer_ns)

    def test_controller_admission_requires_full_work_window_and_rejects_one_ns_late(self):
        start_ns = 30 * _NANOSECONDS
        deadlines = self.policy.plan_deadlines(start_ns, start_ns + 600 * _NANOSECONDS)
        controller_ns = 210 * _NANOSECONDS
        exact_boundary = deadlines.work_ns - controller_ns

        self.assertIsNone(self.policy.require_controller_window(deadlines, exact_boundary))
        self._assert_rejected(self.policy.require_controller_window, deadlines, exact_boundary + 1)
