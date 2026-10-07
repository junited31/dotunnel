import asyncio
import json
import os
from functools import partial
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

from dotunnel.herdr import HerdrBackend


def _pane(pane_id, cwd, agent=None, status="unknown"):
    return {
        "pane_id": pane_id,
        "workspace_id": pane_id.split(":")[0],
        "tab_id": pane_id.split(":")[0] + ":t1",
        "cwd": cwd,
        "foreground_cwd": cwd,
        "agent": agent,
        "agent_status": status,
        "terminal_title_stripped": "title " + pane_id,
    }


FAKE_BACKEND_HERDR = r'''
import json, os, pathlib, sys

here = pathlib.Path(__file__).parent
scenario = json.loads((here / "scenario.json").read_text())
state_path = here / "native-state.json"
if state_path.exists():
    state = json.loads(state_path.read_text())
else:
    state = {key: scenario.get(key, []) for key in ("workspaces", "panes", "agents")}

raw_args = sys.argv[1:]
args = list(raw_args)
session = None
if args[:1] == ["--session"]:
    session = args[1]
    args = args[2:]
with open(here / "calls.jsonl", "a") as stream:
    stream.write(json.dumps({"argv": raw_args, "args": args, "session": session,
                             "cwd": os.getcwd()}) + "\n")

def save():
    state_path.write_text(json.dumps(state))

def ok(result):
    print(json.dumps({"id": "cli:fixture", "result": result}))
    sys.exit(0)

def fail(code):
    print(json.dumps({"id": "cli:fixture",
                      "error": {"code": code, "message": "fixture error"}}), file=sys.stderr)
    sys.exit(1)

def option(name):
    return args[args.index(name) + 1]

group, command = args[:2]
if (group, command) == ("workspace", "list"):
    ok({"workspaces": state["workspaces"]})
if (group, command) == ("pane", "list"):
    ok({"panes": state["panes"]})
if (group, command) == ("agent", "list"):
    ok({"agents": state["agents"]})
if (group, command) == ("agent", "get"):
    target = args[2]
    if scenario.get("agent_get_error"):
        fail(scenario["agent_get_error"])
    for agent in state["agents"]:
        if target in (agent.get("pane_id"), agent.get("name")):
            ok({"agent": agent})
    fail("agent_not_found")
if (group, command) == ("agent", "read"):
    sys.stdout.write(scenario.get("screen", ""))
    sys.exit(0)
if (group, command) == ("agent", "prompt"):
    target, text = args[2], args[3]
    if text.startswith("-") and "--" in args[4:]:
        sys.stderr.write("prompt options were confused with positional text\n")
        sys.exit(2)
    if scenario.get("prompt") == "agent_prompt_stalled":
        fail("agent_prompt_stalled")
    if scenario.get("prompt") == "timeout":
        fail("timeout")
    for agent in state["agents"]:
        if agent.get("pane_id") == target:
            agent["agent_status"] = "working"
            save()
            ok({"agent": agent})
    fail("agent_not_found")
if (group, command) == ("agent", "send-keys"):
    if scenario.get("answer_error"):
        fail(scenario["answer_error"])
    ok({"type": "ok"})
if (group, command) == ("worktree", "create"):
    cwd, branch = option("--cwd"), option("--branch")
    workspace_id = scenario.get("new_workspace_id", "wNEW")
    checkout = scenario.get(
        "worktree_checkout_path",
        str(here.parent / "worktrees" / branch.replace("/", "_")),
    )
    repo_root = scenario.get("worktree_repo_root", cwd)
    pane_id = workspace_id + ":p1"
    workspace = {
        "workspace_id": workspace_id,
        "label": "worktree",
        "worktree": {"checkout_path": checkout, "repo_root": repo_root},
    }
    pane = {
        "pane_id": pane_id, "workspace_id": workspace_id,
        "cwd": checkout, "foreground_cwd": checkout,
        "agent": None, "agent_status": "unknown",
    }
    state["workspaces"].append(workspace)
    state["panes"].append(pane)
    save()
    if scenario.get("worktree_response_loss"):
        sys.exit(1)
    ok({"workspace": workspace, "root_pane": pane})
if (group, command) == ("tab", "create"):
    cwd = option("--cwd")
    workspace_id = scenario.get("tab_workspace_id", "wTAB")
    pane_id = workspace_id + ":p1"
    workspace = {"workspace_id": workspace_id, "label": "tab"}
    pane = {
        "pane_id": pane_id, "workspace_id": workspace_id,
        "cwd": cwd, "foreground_cwd": cwd,
        "agent": None, "agent_status": "unknown",
    }
    state["workspaces"].append(workspace)
    state["panes"].append(pane)
    save()
    ok({"workspace": workspace, "root_pane": pane})
if (group, command) == ("agent", "start"):
    name = args[2]
    pane_id = option("--pane")
    kind = option("--kind")
    pane = next((item for item in state["panes"] if item.get("pane_id") == pane_id), None)
    if pane is None:
        fail("pane_not_found")
    agent = {
        "pane_id": pane_id, "workspace_id": pane["workspace_id"],
        "name": name, "agent": kind, "agent_status": "idle",
        "cwd": pane["cwd"],
    }
    state["agents"].append(agent)
    save()
    if scenario.get("agent_start_error"):
        fail(scenario["agent_start_error"])
    ok({"agent": agent})
fail("unknown_command")
'''


class HerdrBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.runtime_bin = self.base / "runtime"
        self.runtime_bin.mkdir()
        self.bun = self.runtime_bin / "bun"
        self.bun.write_text("#!/bin/sh\nexit 0\n")
        self.bun.chmod(0o700)
        for kind in ("omp", "claude", "codex"):
            real_executable = self.runtime_bin / f"real-{kind}"
            if kind == "omp":
                real_executable.write_text("#!/usr/bin/env bun\n")
            else:
                real_executable.write_text("#!/bin/sh\nexit 0\n")
            real_executable.chmod(0o700)
            (self.runtime_bin / kind).symlink_to(real_executable.name)
        self.backend_runner = partial(self.runner)
        self.backend_runner.trusted_path = os.pathsep.join(
            str(path) for path in (self.runtime_bin, Path("/usr/bin"), Path("/bin"))
        )
        self.project_path = self.base / "projects" / "dacon"
        self.project_path.mkdir(parents=True)
        self.other_path = self.base / "projects" / "other"
        self.other_path.mkdir(parents=True)
        self.fake = self.bin / "herdr"
        self.fake.write_text(f"#!{sys.executable}\n" + FAKE_BACKEND_HERDR)
        self.fake.chmod(0o700)
        self.scenario = {
            "workspaces": [{"workspace_id": "wA", "label": "dacon"}],
            "panes": [_pane("wA:p1", str(self.project_path), "codex", "idle")],
            "agents": [
                dict(_pane("wA:p1", str(self.project_path), "codex", "idle"), name="worker")
            ],
            "screen": "line1\n\x1b[31mred\x1b[0m\x07line3\n",
        }
        self.calls_seen = []
        self.write_scenario()
        self.connection = self._connection()
        self.project = self._project()
        self.backend = HerdrBackend(self.connection, self.backend_runner)

    def tearDown(self):
        self.temporary.cleanup()

    def _connection(self):
        return SimpleNamespace(
            id="herdr-main",
            backend="herdr",
            executable=self.fake,
            session="fixture-session",
            socket=None,
            read_targets=(),
        )

    def _project(self, *, protected=False, workspaces=("wA",)):
        return SimpleNamespace(
            id="dacon",
            path=self.project_path,
            connections=("herdr-main",),
            profiles=("codex-profile", "claude-profile", "omp-profile"),
            workspaces=workspaces,
            protected=protected,
        )

    def _profile(self, *, args=(), kind="codex"):
        return SimpleNamespace(
            id=f"{kind}-profile",
            kind=kind,
            executable=(
                self.bun if kind == "omp" else self.runtime_bin / f"real-{kind}"
            ),
            args=tuple(args),
            backends=("herdr",),
            input_mode="bracketed-paste",
        )

    def write_scenario(self):
        (self.bin / "scenario.json").write_text(json.dumps(self.scenario))
        state = {key: self.scenario.get(key, []) for key in ("workspaces", "panes", "agents")}
        (self.bin / "native-state.json").write_text(json.dumps(state))

    def deadline(self):
        return time.monotonic() + 60

    async def runner(self, argv, *, cwd=None, deadline=None, input=None):
        command = tuple(str(part) for part in argv)
        self.calls_seen.append({"argv": command, "cwd": cwd, "deadline": deadline, "input": input})
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else "/",
            env={"HOME": str(self.base), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        stdout, stderr = await process.communicate(input)
        return process.returncode or 0, stdout, stderr

    def native_calls(self):
        path = self.bin / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def commands(self):
        return [call["args"][:2] for call in self.native_calls()]

    async def discovered(self, *, project=None, records=()):
        return await self.backend.inventory(
            [project or self.project], records, deadline=self.deadline()
        )

    def assert_error_code(self, raised, expected):
        self.assertIsInstance(raised.exception, ValueError)
        self.assertEqual(getattr(raised.exception, "code", None), expected)

    async def test_inventory_normalizes_configured_projects_and_real_weak_identity(self):
        checkout = self.base / "worktrees" / "feature"
        self.scenario["workspaces"].extend([
            {"workspace_id": "wWT", "label": "renamed",
             "worktree": {"checkout_path": str(checkout), "repo_root": str(self.project_path)}},
            {"workspace_id": "wElse", "label": "unrelated"},
        ])
        self.scenario["panes"].extend([
            _pane("wWT:p2", str(checkout), "claude", "blocked"),
            _pane("wElse:p1", str(self.other_path), "codex", "idle"),
        ])
        self.scenario["agents"].extend([
            dict(_pane("wWT:p2", str(checkout), "claude", "blocked"), name="brancher"),
            dict(_pane("wElse:p1", str(self.other_path), "codex", "idle"), name="unrelated"),
        ])
        self.write_scenario()
        project = self._project(workspaces=("wA", "wWT"))

        rows = await self.discovered(
            project=project,
            records=[{"native_id": "wWT:p2", "profile": "claude-profile"}],
        )

        self.assertEqual([row["native_id"] for row in rows], ["wA:p1", "wWT:p2"])
        base_row, worktree_row = rows
        self.assertEqual(base_row["project"], "dacon")
        self.assertEqual(base_row["name"], "worker")
        self.assertEqual(base_row["identity"]["pane_id"], "wA:p1")
        self.assertEqual(base_row["process_state"], "running")
        self.assertEqual(base_row["agent_state"], "idle")
        self.assertEqual(base_row["state_source"], "backend")
        self.assertFalse(base_row["readonly"])
        self.assertEqual(base_row["cwd"], str(self.project_path))
        self.assertEqual(base_row["original_repo"], str(self.project_path))
        self.assertEqual(worktree_row["name"], "brancher")
        self.assertEqual(worktree_row["cwd"], str(checkout))
        self.assertEqual(worktree_row["original_repo"], str(self.project_path))
        self.assertEqual(worktree_row["agent_state"], "blocked")
        self.assertEqual(worktree_row["profile"], "claude-profile")
        self.assertEqual(worktree_row["identity"]["strength"], "weak")
        self.assertNotIn("incarnation", worktree_row["identity"])
        self.assertNotIn("nonce", worktree_row["identity"])
        self.assertEqual({call["session"] for call in self.native_calls()}, {"fixture-session"})
        self.assertTrue(all(call["deadline"] == self.calls_seen[0]["deadline"]
                            for call in self.calls_seen))

    async def test_inventory_marks_absent_agent_state_unavailable(self):
        del self.scenario["agents"][0]["agent_status"]
        del self.scenario["panes"][0]["agent_status"]
        self.write_scenario()

        [row] = await self.discovered()

        self.assertEqual(row["process_state"], "running")
        self.assertEqual(row["agent_state"], "unknown")
        self.assertEqual(row["state_source"], "unavailable")

    async def test_inventory_marks_protected_project_readonly(self):
        [row] = await self.discovered(project=self._project(protected=True))

        self.assertTrue(row["readonly"])

    async def test_protected_project_refuses_input_and_start_before_effect(self):
        protected = self._project(protected=True)
        [target] = await self.discovered(project=protected)

        with self.assertRaises(ValueError) as raised:
            await self.backend.prompt(target, "do work", self._profile(), deadline=self.deadline())
        self.assert_error_code(raised, "protected_target")

        with self.assertRaises(ValueError) as raised:
            await self.backend.start(
                protected, self._profile(), "fixer", "feature/safe", {},
                deadline=self.deadline(),
            )
        self.assert_error_code(raised, "protected_target")
        self.assertNotIn(["agent", "prompt"], self.commands())
        self.assertNotIn(["worktree", "create"], self.commands())

    async def test_read_cleans_and_caps_text_after_exact_native_identity_check(self):
        [target] = await self.discovered()

        result = await self.backend.read(target, 20, deadline=self.deadline())

        self.assertEqual(result["text"], "line1\nredline3\n")
        self.assertFalse(result["truncated"])
        self.assertEqual(result["native_id"], "wA:p1")
        self.scenario["screen"] = "x" * 20000
        self.write_scenario()
        large = await self.backend.read(target, 20, deadline=self.deadline())
        self.assertTrue(large["truncated"])
        self.assertEqual(len(large["text"].encode()), 16 * 1024)

    async def test_read_refuses_changed_native_fields_without_name_rebinding(self):
        [target] = await self.discovered()
        before = len(self.native_calls())
        self.scenario["agents"][0]["name"] = "replacement"
        self.write_scenario()

        with self.assertRaises(ValueError) as raised:
            await self.backend.read(target, 20, deadline=self.deadline())

        self.assert_error_code(raised, "stale_target")
        later = self.native_calls()[before:]
        self.assertIn(["agent", "get"], [call["args"][:2] for call in later])
        self.assertNotIn(["agent", "read"], [call["args"][:2] for call in later])

    async def test_prompt_keeps_option_like_text_positional_and_reports_stalled_start(self):
        [target] = await self.discovered()
        before = len(self.calls_seen)
        text = "--help is literal\nUnicode Ω"
        self.scenario["prompt"] = "agent_prompt_stalled"
        self.write_scenario()
        deadline = self.deadline()

        result = await self.backend.prompt(target, text, self._profile(), deadline=deadline)

        self.assertEqual(result["delivery"], "confirmed")
        self.assertFalse(result["started"])
        self.assertEqual(result["herdr_code"], "agent_prompt_stalled")
        prompt_call = next(call for call in self.native_calls() if call["args"][:2] == ["agent", "prompt"])
        self.assertEqual(prompt_call["args"][2:4], ["wA:p1", text])
        self.assertIn("--wait", prompt_call["args"][4:])
        self.assertIn("--until", prompt_call["args"][4:])
        self.assertNotIn("--", prompt_call["args"])
        self.assertTrue(all(call["deadline"] == deadline for call in self.calls_seen[before:]))

    async def test_prompt_timeout_reports_unknown_delivery(self):
        [target] = await self.discovered()
        self.scenario["prompt"] = "timeout"
        self.write_scenario()

        result = await self.backend.prompt(
            target, "continue", self._profile(), deadline=self.deadline()
        )

        self.assertEqual(result["delivery"], "unknown")

    async def test_prompt_success_starts_from_done_and_confirms_delivery(self):
        self.scenario["agents"][0]["agent_status"] = "done"
        self.scenario["panes"][0]["agent_status"] = "done"
        self.write_scenario()
        [target] = await self.discovered()

        result = await self.backend.prompt(
            target, "continue", self._profile(), deadline=self.deadline()
        )

        self.assertEqual(result["delivery"], "confirmed")
        self.assertTrue(result["started"])

    async def test_prompt_refuses_nonready_agent_before_effect(self):
        self.scenario["agents"][0]["agent_status"] = "blocked"
        self.scenario["panes"][0]["agent_status"] = "blocked"
        self.write_scenario()
        [target] = await self.discovered()

        result = await self.backend.prompt(
            target, "continue", self._profile(), deadline=self.deadline()
        )
        self.assertEqual(result["delivery"], "refused")
        self.assertEqual(result["error"]["code"], "invalid_request")
        self.assertNotIn(["agent", "prompt"], self.commands())


    async def test_prompt_refuses_profile_for_different_native_agent_kind(self):
        [target] = await self.discovered()
        target["profile"] = "claude-profile"

        result = await self.backend.prompt(
            target, "continue", self._profile(kind="claude"), deadline=self.deadline()
        )

        self.assertEqual(result["delivery"], "refused")
        self.assertEqual(result["error"]["code"], "unsupported_operation")
        self.assertNotIn(["agent", "prompt"], self.commands())

    async def test_answer_requires_blocked_agent_and_sends_only_allowed_keys(self):
        [target] = await self.discovered()
        result = await self.backend.answer(target, ["y"], deadline=self.deadline())
        self.assertEqual(result["delivery"], "refused")
        self.assertEqual(result["error"]["code"], "invalid_request")

        self.scenario["agents"][0]["agent_status"] = "blocked"
        self.scenario["panes"][0]["agent_status"] = "blocked"
        self.write_scenario()
        [blocked] = await self.discovered()

        with self.assertRaises(ValueError) as raised:
            await self.backend.answer(blocked, ["ctrl+c"], deadline=self.deadline())
        self.assert_error_code(raised, "invalid_request")
        self.assertNotIn(["agent", "send-keys"], self.commands())
        result = await self.backend.answer(blocked, ["down", "enter"], deadline=self.deadline())

        self.assertEqual(result["delivery"], "confirmed")
        send = next(call for call in self.native_calls() if call["args"][:2] == ["agent", "send-keys"])
        self.assertEqual(send["args"], ["agent", "send-keys", "wA:p1", "down", "enter"])

    async def test_stderr_json_agent_error_maps_to_stale_target(self):
        [target] = await self.discovered()
        self.scenario["agent_get_error"] = "agent_not_found"
        self.write_scenario()

        with self.assertRaises(ValueError) as raised:
            await self.backend.read(target, 10, deadline=self.deadline())

        self.assert_error_code(raised, "stale_target")

    async def test_start_uses_fixed_repo_and_positional_argument_separator(self):
        profile = self._profile(args=("--help", "--literal=value"))
        deadline = self.deadline()

        row = await self.backend.start(
            self.project,
            profile,
            "fixer",
            "feature/safe",
            {"target_id": "local-attempt", "nonce": "must-not-be-native"},
            deadline=deadline,
        )

        self.assertEqual(
            {key: row[key] for key in (
                "native_id", "project", "name", "process_state", "agent_state",
                "state_source", "readonly", "cwd", "original_repo", "profile", "delivery",
            )},
            {
                "native_id": "wNEW:p1", "project": "dacon", "name": "fixer",
                "process_state": "running", "agent_state": "idle", "state_source": "backend",
                "readonly": False, "cwd": str(self.base / "worktrees" / "feature_safe"),
                "original_repo": str(self.project_path), "profile": "codex-profile",
                "delivery": "confirmed",
            },
        )
        self.assertEqual(row["identity"]["pane_id"], "wNEW:p1")
        self.assertEqual(row["identity"]["strength"], "weak")
        self.assertNotIn("nonce", row["identity"])
        worktree = next(call for call in self.native_calls()
                        if call["args"][:2] == ["worktree", "create"])
        self.assertEqual(worktree["args"][worktree["args"].index("--cwd") + 1],
                         str(self.project_path))
        self.assertEqual(worktree["args"][worktree["args"].index("--branch") + 1], "feature/safe")
        start = next(call for call in self.native_calls() if call["args"][:2] == ["agent", "start"])
        separator = start["args"].index("--")
        self.assertEqual(start["args"][separator + 1:], ["--help", "--literal=value"])
        self.assertTrue(all(call["deadline"] == deadline for call in self.calls_seen))


    async def test_start_supports_only_the_legacy_herdr_kinds(self):
        for kind in ("omp", "claude", "codex"):
            with self.subTest(kind=kind):
                self.write_scenario()
                row = await self.backend.start(
                    self.project, self._profile(kind=kind), "fixer", None, {},
                    deadline=self.deadline(),
                )
                self.assertEqual(row["identity"]["agent"], kind)
                start = [call for call in self.native_calls()
                         if call["args"][:2] == ["agent", "start"]][-1]
                self.assertEqual(start["args"][start["args"].index("--kind") + 1], kind)

        self.write_scenario()
        with self.assertRaises(ValueError) as raised:
            await self.backend.start(
                self.project, self._profile(kind="gemini"), "fixer", None, {},
                deadline=self.deadline(),
            )
        self.assert_error_code(raised, "unsupported_operation")

    async def test_start_rejects_custom_executable_before_native_effects(self):
        custom_executable = self.bin / "custom-codex"
        custom_executable.write_text("#!/bin/sh\nexit 0\n")
        custom_executable.chmod(0o700)
        profile = self._profile()
        profile.executable = custom_executable

        with self.assertRaises(ValueError) as raised:
            await self.backend.start(
                self.project, profile, "fixer", "feature/safe", {},
                deadline=self.deadline(),
            )

        self.assert_error_code(raised, "unsupported_operation")
        self.assertEqual(self.native_calls(), [])

    async def test_start_accepts_canonical_omp_interpreter_profile(self):
        row = await self.backend.start(
            self.project, self._profile(kind="omp"), "fixer", None, {},
            deadline=self.deadline(),
        )

        self.assertEqual(row["delivery"], "confirmed")
        self.assertEqual(row["profile"], "omp-profile")
        self.assertEqual(row["identity"]["agent"], "omp")

    async def test_start_rejects_wrong_omp_interpreter_without_native_effects(self):
        wrong_interpreter = self.bin / "wrong-bun"
        wrong_interpreter.write_text("#!/bin/sh\nexit 0\n")
        wrong_interpreter.chmod(0o700)
        profile = self._profile(kind="omp")
        profile.executable = wrong_interpreter

        with self.assertRaises(ValueError) as raised:
            await self.backend.start(
                self.project, profile, "fixer", None, {},
                deadline=self.deadline(),
            )

        self.assert_error_code(raised, "unsupported_operation")
        self.assertEqual(self.native_calls(), [])

    async def test_unrelated_original_repo_never_gets_an_agent_and_returns_unknown(self):
        self.scenario["worktree_repo_root"] = str(self.other_path)
        self.write_scenario()

        result = await self.backend.start(
            self.project, self._profile(), "fixer", "feature/safe",
            {"target_id": "attempt-only"}, deadline=self.deadline(),
        )

        self.assertEqual(result["delivery"], "unknown")
        self.assertNotIn("native_id", result)
        self.assertNotIn("identity", result)
        self.assertNotIn(["agent", "start"], self.commands())

    async def test_worktree_response_loss_has_no_synthetic_handle(self):
        self.scenario["worktree_response_loss"] = True
        self.write_scenario()

        result = await self.backend.start(
            self.project, self._profile(), "fixer", "feature/safe",
            {"target_id": "attempt-only", "nonce": "diagnostic-only"},
            deadline=self.deadline(),
        )

        self.assertEqual(result["delivery"], "unknown")
        self.assertNotIn("native_id", result)
        self.assertNotIn("identity", result)
        self.assertNotIn(["agent", "start"], self.commands())

    async def test_start_without_worktree_uses_only_configured_project_path(self):
        row = await self.backend.start(
            self.project, self._profile(), "fixer", None,
            {"target_id": "attempt-only"}, deadline=self.deadline(),
        )

        self.assertEqual(row["delivery"], "confirmed")
        self.assertEqual(row["original_repo"], str(self.project_path))
        tab = next(call for call in self.native_calls() if call["args"][:2] == ["tab", "create"])
        self.assertEqual(tab["args"][tab["args"].index("--cwd") + 1], str(self.project_path))
if __name__ == "__main__":
    unittest.main()
