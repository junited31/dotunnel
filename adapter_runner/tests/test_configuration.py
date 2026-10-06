import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from dotunnel_adapter.configuration import RunnerConfig, load_config
from dotunnel_adapter.protocol import RunnerError


READ_ACTIONS = ["capabilities", "list_targets", "inspect", "read_output", "report"]


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        os.chmod(self.base, 0o700)
        self.private = self.base / "private"
        self.workspace = self.base / "workspace"
        self.state = self.private / "state"
        self.private.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        self.backend_script = self.private / "backend.py"
        self.backend_script.write_bytes(b"")
        self.backend_script.chmod(0o600)
        self.executable = Path("/usr/bin/python3").resolve(strict=True)
        self.digest = "sha256:" + hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.config_path = self.private / "config.json"
        self.write_config()

    def tearDown(self):
        self.temporary.cleanup()

    def configuration(self, **overrides):
        value = {
            "protocol": "dotunnel.adapter.config/1",
            "workspace": str(self.workspace),
            "request": "pending.json",
            "reports": "reports",
            "state_dir": str(self.state),
            "project": {
                "id": "demo", "generation": "project-1", "protected": False,
                "write_enabled": False, "operations": list(READ_ACTIONS),
            },
            "backend": {
                "id": "fixture-backend", "generation": "backend-1",
                "version": "1.0.0", "digest": self.digest,
                "argv": [str(self.executable), "-I", str(self.backend_script), self.digest],
                "timeout_seconds": 5,
            },
        }
        value.update(overrides)
        return value

    def write_config(self, value=None, path=None, mode=0o600):
        target = path or self.config_path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(json.dumps(value if value is not None else self.configuration()), encoding="utf-8")
        target.chmod(mode)
        return target

    def assert_invalid(self, path=None):
        with self.assertRaises(RunnerError) as caught:
            load_config(path or self.config_path)
        self.assertEqual(caught.exception.code, "invalid_config")
        self.assertEqual(str(caught.exception), "invalid_config")

    def test_loads_exact_owner_profile_with_private_backend_script_outside_workspace(self):
        config = load_config(self.config_path)
        self.assertIsInstance(config, RunnerConfig)
        self.assertEqual(config.config_path, self.config_path)
        self.assertEqual(config.workspace, self.workspace)
        self.assertEqual(config.request, "pending.json")
        self.assertEqual(config.reports, "reports")
        self.assertEqual(config.state_dir, self.state)
        self.assertEqual(config.project["id"], "demo")
        self.assertEqual(config.backend["argv"], (str(self.executable), "-I", str(self.backend_script), self.digest))
        self.assertFalse(config.workspace in config.backend["argv"])
        self.assertFalse(self.backend_script.is_relative_to(config.workspace))

    def test_rejects_workspace_script_and_option_value_despite_pinned_interpreter(self):
        script = self.workspace / 'adapter.py'
        script.write_text('raise SystemExit(0)')
        script.chmod(0o600)
        for argument in (str(script), '--script=' + str(script),
                         str(self.workspace / '..' / 'workspace' / 'adapter.py'),
                         os.path.relpath(script, self.state),
                         '--script=' + os.path.relpath(script, self.state),
                         str(self.workspace / 'a=b.py'), '-f' + str(script)):
            with self.subTest(argument=argument):
                value = self.configuration()
                value['backend']['argv'] = [str(self.executable), argument]
                self.write_config(value)
                self.assert_invalid()

    def test_accepts_read_only_four_hundred_config_but_rejects_public_modes_and_linked_config(self):
        self.config_path.chmod(0o400)
        load_config(self.config_path)
        self.config_path.chmod(0o644)
        self.assert_invalid()
        self.config_path.chmod(0o600)
        linked = self.private / "config-link.json"
        os.link(self.config_path, linked)
        self.assert_invalid(linked)

    def test_rejects_config_symlink_and_untrusted_private_parent(self):
        link = self.private / "config-link.json"
        link.symlink_to(self.config_path)
        self.assert_invalid(link)
        loose_parent = self.base / "loose"
        loose_parent.mkdir(mode=0o700)
        os.chmod(loose_parent, 0o700)
        leaf_parent = loose_parent / "private"
        leaf_parent.mkdir(mode=0o700)
        loose_config = self.write_config(path=leaf_parent / "config.json")
        os.chmod(loose_parent, 0o777)
        self.assert_invalid(loose_config)

    def test_rejects_duplicate_unknown_and_wrong_protocol_configuration_fields(self):
        self.config_path.write_text('{"protocol":"dotunnel.adapter.config/1","protocol":"other"}', encoding="utf-8")
        self.config_path.chmod(0o600)
        self.assert_invalid()
        self.write_config({**self.configuration(), "extra": "field"})
        self.assert_invalid()
        self.write_config({**self.configuration(), "protocol": "other"})
        self.assert_invalid()

    def test_rejects_workspace_config_state_or_backend_executable_overlap(self):
        in_workspace_config = self.write_config(path=self.workspace / "config.json")
        self.assert_invalid(in_workspace_config)
        value = self.configuration()
        value["state_dir"] = str(self.workspace / "state")
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        workspace_executable = self.workspace / "program"
        workspace_executable.write_bytes(b"")
        workspace_executable.chmod(0o700)
        value["backend"]["argv"][0] = str(workspace_executable)
        value["backend"]["digest"] = "sha256:" + hashlib.sha256(b"").hexdigest()
        self.write_config(value)
        self.assert_invalid()

    def test_rejects_workspace_state_and_executable_symlinks(self):
        workspace_link = self.base / "workspace-link"
        workspace_link.symlink_to(self.workspace, target_is_directory=True)
        value = self.configuration()
        value["workspace"] = str(workspace_link)
        self.write_config(value)
        self.assert_invalid()
        self.write_config()
        self.state.chmod(0o700)
        state_link = self.private / "state-link"
        state_link.symlink_to(self.state, target_is_directory=True)
        value = self.configuration()
        value["state_dir"] = str(state_link)
        self.write_config(value)
        self.assert_invalid()
        executable_link = self.private / "python-link"
        executable_link.symlink_to(self.executable)
        value = self.configuration()
        value["backend"]["argv"][0] = str(executable_link)
        self.write_config(value)
        self.assert_invalid()

    def test_requires_private_seventy_hundred_state_and_regular_single_link_executable(self):
        self.state.chmod(0o755)
        self.assert_invalid()
        self.state.chmod(0o700)
        linked_executable = self.private / "python-hardlink"
        os.link(self.executable, linked_executable)
        value = self.configuration()
        value["backend"]["argv"][0] = str(linked_executable)
        self.write_config(value)
        self.assert_invalid()

    def test_digest_mismatch_and_nonexecutable_or_special_backend_are_refused(self):
        value = self.configuration()
        value["backend"]["digest"] = "sha256:" + "0" * 64
        self.write_config(value)
        self.assert_invalid()
        not_executable = self.private / "not-executable"
        not_executable.write_bytes(b"not executable")
        not_executable.chmod(0o600)
        value = self.configuration()
        value["backend"]["argv"][0] = str(not_executable)
        value["backend"]["digest"] = "sha256:" + hashlib.sha256(not_executable.read_bytes()).hexdigest()
        self.write_config(value)
        self.assert_invalid()

        fifo = self.private / "backend-fifo"
        os.mkfifo(fifo)
        value = self.configuration()
        value["backend"]["argv"][0] = str(fifo)
        self.write_config(value)
        self.assert_invalid()

    def test_rejects_path_injection_unknown_fields_and_out_of_range_limits(self):
        value = self.configuration()
        value["request"] = "../pending.json"
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        value["reports"] = ".private"
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        value["backend"]["env"] = {"PATH": "/tmp"}
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        value["backend"]["timeout_seconds"] = 201
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        value["backend"]["timeout_seconds"] = True
        self.write_config(value)
        self.assert_invalid()

    def test_project_policy_requires_exact_types_known_operations_and_unique_ids(self):
        value = self.configuration()
        value["project"]["protected"] = 1
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        value["project"]["operations"] = ["submit", "submit"]
        self.write_config(value)
        self.assert_invalid()
        value = self.configuration()
        value["project"]["operations"] = ["shell"]
        self.write_config(value)
        self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
