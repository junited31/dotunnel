"""Project and profile action permission regressions at the Supervisor boundary."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from dotunnel.supervision import Supervisor
from dotunnel.supervision_config import Connection, Profile, Project, SupervisionError
from dotunnel.supervision_state import SupervisionState
from test_supervision import ProcessBackend


class SupervisionPermissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.state = SupervisionState.initialize(self.base / "state")
        self.addCleanup(self.state.close)
        self.backend = ProcessBackend(self.base)
        self.backend.rows[0]["profile"] = "codex"
        self.executable = Path(sys.executable).resolve()
        self.profile_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.profile_temporary.cleanup)
        self.profile_executable = Path(self.profile_temporary.name) / "agent-cli"
        self.profile_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.profile_executable.chmod(0o755)
        self.connection = Connection("c", "tmux", self.executable, socket=self.base / "socket")
        self.profiles = {"codex": Profile("codex", "codex", self.profile_executable)}

    def project(self, allowed_actions=("read", "start", "prompt", "answer"), profile_actions=None):
        if profile_actions is None:
            profile_actions = {"codex": ("start", "prompt", "answer")}
        return Project(
            "p", self.base, ("c",), ("codex",),
            allowed_actions=frozenset(allowed_actions),
            profile_actions={key: frozenset(value) for key, value in profile_actions.items()},
        )

    def supervisor(self, project):
        settings = SimpleNamespace(
            workspace_root=self.base, state_dir=self.base / "state",
            connections={"c": self.connection}, projects={"p": project},
            profiles=self.profiles, protected_paths=(), default_connection="c",
            generation="fixture-generation",
        )
        return Supervisor(settings, self.state, {"c": self.backend})

    async def observed(self, supervisor):
        status = await supervisor.status()
        target = status["targets"][0]["target"]
        read = await supervisor.read(target)
        return target, read["observation"]

    async def test_project_ceiling_disables_profile_grant_and_blocks_mutation(self):
        supervisor = self.supervisor(self.project(
            allowed_actions=("read",), profile_actions={"codex": ("prompt", "answer", "start")}
        ))
        await supervisor.approve("c:p")
        status = await supervisor.status()
        self.assertFalse(status["targets"][0]["capabilities"]["prompt"])
        target, observation = await self.observed(supervisor)
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.prompt(target, observation, "not permitted", "ceiling-prompt")
        self.assertEqual(denied.exception.code, "unsupported_operation")
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.start("p", "codex", "blocked", "ceiling-start")
        self.assertEqual(denied.exception.code, "unsupported_operation")
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_per_profile_grants_are_independent_for_prompt_and_answer(self):
        supervisor = self.supervisor(self.project(profile_actions={"codex": ("prompt",)}))
        await supervisor.approve("c:p")
        target, observation = await self.observed(supervisor)
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.answer(target, observation, ["enter"], "profile-answer")
        self.assertEqual(denied.exception.code, "unsupported_operation")
        self.assertEqual(self.backend.effect_count(), 0)
        result = await supervisor.prompt(target, observation, "allowed", "profile-prompt")
        self.assertEqual(result["delivery"], "confirmed")
        self.assertEqual(self.backend.effect_count(), 1)

    async def test_missing_profile_grant_denies_by_default(self):
        supervisor = self.supervisor(self.project(profile_actions={}))
        await supervisor.approve("c:p")
        target, observation = await self.observed(supervisor)
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.prompt(target, observation, "denied", "no-grant")
        self.assertEqual(denied.exception.code, "unsupported_operation")
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_start_requires_start_grant_before_allocating_or_effect(self):
        supervisor = self.supervisor(self.project(profile_actions={"codex": ("prompt",)}))
        await supervisor.approve("c:p")
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.start("p", "codex", "blocked", "no-start-grant")
        self.assertEqual(denied.exception.code, "unsupported_operation")
        self.assertEqual(self.backend.effect_count(), 0)
        self.assertEqual(self.state.list_targets(), [])

    async def test_project_without_read_denies_screen_access_and_prompt_answer(self):
        supervisor = self.supervisor(self.project(
            allowed_actions=("start",), profile_actions={"codex": ("start",)}
        ))
        status = await supervisor.status()
        target = status["targets"][0]["target"]
        self.assertFalse(status["targets"][0]["capabilities"]["read"])
        with self.assertRaises(SupervisionError):
            await supervisor.read(target)
        self.assertEqual(self.backend.screen.read_text(), "approval ready\n")
        self.assertEqual(self.backend.effect_count(), 0)


    async def test_compatible_runtime_policy_accepts_writable_hardlinked_profile(self):
        self.profile_executable.chmod(0o777)
        os.link(self.profile_executable, self.profile_executable.with_name("compatible-link"))
        supervisor = self.supervisor(self.project())
        await supervisor.approve("c:p")
        target, observation = await self.observed(supervisor)
        result = await supervisor.prompt(target, observation, "allowed", "compatible-policy")
        self.assertEqual(result["delivery"], "confirmed")
        self.assertEqual(self.backend.effect_count(), 1)

    async def test_strict_runtime_policy_rejects_changed_executable_before_start(self):
        self.profiles["codex"] = Profile(
            "codex", "codex", self.profile_executable, executable_policy="strict"
        )
        self.profile_executable.chmod(0o777)
        os.link(self.profile_executable, self.profile_executable.with_name("strict-start-link"))
        supervisor = self.supervisor(self.project())
        await supervisor.approve("c:p")
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.start("p", "codex", "blocked", "strict-start")
        self.assertEqual(denied.exception.reason, "unsafe_executable")
        self.assertEqual(self.backend.effect_count(), 0)
        self.assertEqual(self.state.list_targets(), [])

    async def test_strict_runtime_policy_rejects_changed_executable_before_prompt(self):
        self.profiles["codex"] = Profile(
            "codex", "codex", self.profile_executable, executable_policy="strict"
        )
        supervisor = self.supervisor(self.project())
        await supervisor.approve("c:p")
        target, observation = await self.observed(supervisor)
        self.profile_executable.chmod(0o777)
        os.link(self.profile_executable, self.profile_executable.with_name("strict-prompt-link"))
        with self.assertRaises(SupervisionError) as denied:
            await supervisor.prompt(target, observation, "blocked", "strict-prompt")
        self.assertEqual(denied.exception.reason, "unsafe_executable")
        self.assertEqual(self.backend.effect_count(), 0)


if __name__ == "__main__":
    unittest.main()
