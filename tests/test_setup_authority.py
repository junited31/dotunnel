"""Fail-closed local-client authority checks for setup."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class SetupAuthorityTests(unittest.TestCase):

    def test_legacy_permission_schema_converts_authority_explicitly(self):
        from dotunnel import onboarding

        legacy = {
            "root": "/synthetic/workspace",
            "tasks": [],
            "supervision": {
                "state_dir": "/synthetic/private/supervision",
                "connections": [
                    {"id": "herdr", "backend": "herdr", "executable": "/usr/bin/herdr"},
                    {
                        "id": "tmux",
                        "backend": "tmux",
                        "executable": "/usr/bin/tmux",
                        "socket": "/tmp/tmux/default",
                        "read_targets": [{"project": "tmux-readonly"}],
                    },
                ],
                "projects": [
                    {
                        "id": "live",
                        "path": "/synthetic/live",
                        "connections": ["herdr"],
                        "profiles": ["codex"],
                    },
                    {
                        "id": "tmux-readonly",
                        "path": "/synthetic/readonly",
                        "connections": ["tmux"],
                        "profiles": ["codex"],
                    },
                    {
                        "id": "protected",
                        "path": "/synthetic/protected",
                        "connections": ["herdr"],
                        "profiles": ["codex"],
                        "protected": True,
                    },
                ],
                "profiles": [
                    {
                        "id": "codex",
                        "kind": "codex",
                        "executable": "/usr/bin/codex",
                        "backends": ["herdr", "tmux"],
                    }
                ],
            },
        }

        converted = onboarding._migrate_legacy_document(legacy)
        self.assertEqual(
            converted["file_access"],
            {
                "read": [{"path": ".", "kind": "tree"}],
                "write": [{"path": ".", "kind": "tree"}],
            },
        )
        projects = {project["id"]: project for project in converted["supervision"]["projects"]}
        self.assertEqual(projects["live"]["allowed_actions"], ["answer", "prompt", "read", "start"])
        self.assertEqual(
            projects["live"]["profile_actions"],
            {"codex": ["answer", "prompt", "start"]},
        )
        for project_id in ("tmux-readonly", "protected"):
            self.assertEqual(projects[project_id]["allowed_actions"], ["read"])
            self.assertEqual(projects[project_id]["profile_actions"], {"codex": []})
        self.assertNotIn("file_access", legacy)
        self.assertNotIn("allowed_actions", legacy["supervision"]["projects"][0])

    def test_unreadable_or_missing_client_identity_is_unknown(self):
        from dotunnel import onboarding

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir(mode=0o700)
            client = Path(temporary) / "tunnel-client"
            profile = Path(temporary) / "profile.yaml"
            self.assertEqual(onboarding._local_client_state(client, profile, proc_root=root), "unknown")
    def test_matching_client_process_is_active_without_reading_environment(self):
        from dotunnel import onboarding

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            client = base / "tunnel-client"
            profile = base / "profile.yaml"
            client.write_text("synthetic executable")
            profile.write_text("synthetic profile")
            proc_root = base / "proc"
            proc_root.mkdir(mode=0o700)
            process = proc_root / "4321"
            process.mkdir(mode=0o700)
            uid = os.getuid()
            (process / "status").write_text(
                f"Name:{chr(9)}tunnel-client{chr(10)}Uid:{chr(9)}{uid}{chr(9)}{uid}{chr(9)}{uid}{chr(9)}{uid}{chr(10)}"
            )
            (process / "stat").write_text(
                "4321 (tunnel-client) S " + " ".join(["1"] * 18 + ["123"]) + chr(10)
            )
            (process / "exe").symlink_to(client.resolve())
            (process / "cmdline").write_bytes(
                bytes([0]).join(
                    os.fsencode(value)
                    for value in (str(client.resolve()), "run", "--profile-file", str(profile.resolve()))
                ) + bytes([0])
            )
            read_proc_file = onboarding._read_proc_file
            observed = []

            def guarded(path, limit):
                observed.append(Path(path).name)
                self.assertNotEqual(Path(path).name, "environ")
                return read_proc_file(path, limit)

            with patch.object(onboarding, "_read_proc_file", side_effect=guarded):
                state = onboarding._local_client_state(client, profile, proc_root=proc_root)

            self.assertEqual(state, "active")
            self.assertNotIn("environ", observed)

    def test_single_thread_stable_zombie_is_excluded_as_provably_vanished(self):
        from dotunnel import onboarding

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir(mode=0o700)
            process = root / "4322"
            process.mkdir(mode=0o700)
            uid = os.getuid()
            (process / "status").write_text(
                f"Name:{chr(9)}tunnel-client{chr(10)}Uid:{chr(9)}{uid}{chr(9)}{uid}{chr(9)}{uid}{chr(9)}{uid}{chr(10)}"
            )
            stat_text = "4322 (tunnel-client) Z " + " ".join(["1"] * 18 + ["124"]) + chr(10)
            (process / "stat").write_text(stat_text)
            task = process / "task"
            task.mkdir(mode=0o700)
            (task / "4322").mkdir(mode=0o700)
            client = Path(temporary) / "tunnel-client"
            profile = Path(temporary) / "profile.yaml"
            client.write_text("synthetic executable")
            profile.write_text("synthetic profile")
            self.assertEqual(onboarding._local_client_state(client, profile, proc_root=root), "stopped")

    def test_unreadable_live_executable_is_unknown(self):
        from dotunnel import onboarding

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            client = base / "tunnel-client"
            profile = base / "profile.yaml"
            client.write_text("synthetic executable")
            profile.write_text("synthetic profile")
            root = base / "proc"
            root.mkdir(mode=0o700)
            process = root / "4323"
            process.mkdir(mode=0o700)
            uid = os.getuid()
            (process / "status").write_text(
                f"Name:{chr(9)}tunnel-client{chr(10)}Uid:{chr(9)}{uid}{chr(9)}{uid}{chr(9)}{uid}{chr(9)}{uid}{chr(10)}"
            )
            (process / "stat").write_text(
                "4323 (tunnel-client) S " + " ".join(["1"] * 18 + ["125"]) + chr(10)
            )
            (process / "exe").symlink_to(client.resolve())
            real_readlink = os.readlink

            def deny_executable(path, *args, **kwargs):
                if Path(path) == process / "exe":
                    raise PermissionError("synthetic permission denial")
                return real_readlink(path, *args, **kwargs)

            with patch("os.readlink", side_effect=deny_executable):
                self.assertEqual(onboarding._local_client_state(client, profile, proc_root=root), "unknown")

    def test_setup_refuses_unknown_local_client_state(self):
        from dotunnel import onboarding

        with self.assertRaises(ValueError):
            onboarding._require_stopped_client(Path("/missing/client"), Path("/missing/profile"), state="unknown")


if __name__ == "__main__":
    unittest.main()
