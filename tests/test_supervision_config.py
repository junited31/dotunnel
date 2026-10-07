import dataclasses
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


class SupervisionConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "workspace"
        self.root.mkdir(mode=0o700)
        self.state = self.base / "state"
        self.state.mkdir(mode=0o700)
        self.bin = self.base / "bin"
        self.bin.mkdir(mode=0o700)
        self.executable = self.bin / "agent-cli"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o755)
        self.config_path = self.base / "config.json"

    def connection(self, connection_id="local", backend="herdr", **changes):
        result = {"id": connection_id, "backend": backend, "executable": str(self.executable)}
        if backend == "herdr":
            result["session"] = "session-" + connection_id
        elif backend == "tmux":
            result["socket"] = str(self.base / ("tmux-" + connection_id + ".sock"))
        result.update(changes)
        return result

    def base_value(self, connections=None):
        return {
            "state_dir": str(self.state),
            "connections": [self.connection()] if connections is None else connections,
            "projects": [{
                "id": "project",
                "path": str(self.root),
                "connections": ["local"],
                "profiles": ["codex"],
                "workspaces": ["w123"],
                "protected": False,
            }],
            "profiles": [{
                "id": "codex",
                "kind": "codex",
                "executable": str(self.executable),
                "args": ["--full-auto"],
                "backends": ["herdr", "tmux"],
                "input_mode": "bracketed-paste",
            }],
        }

    def parse(self, value=None):
        from dotunnel.supervision_config import parse_supervision

        return parse_supervision(value or self.base_value(), self.root, self.config_path)

    def test_one_project_can_select_backend_specific_profiles(self):
        value = self.base_value([self.connection("h", "herdr"), self.connection("t", "tmux")])
        value["projects"][0]["connections"] = ["h", "t"]
        value["projects"][0]["profiles"] = ["codex-herdr", "codex-tmux"]
        value["profiles"] = [
            {**value["profiles"][0], "id": "codex-herdr", "backends": ["herdr"]},
            {**value["profiles"][0], "id": "codex-tmux", "backends": ["tmux"]},
        ]
        parsed = self.parse(value)
        for connection_id in parsed.projects["project"].connections:
            backend = parsed.connections[connection_id].backend
            eligible = [key for key in parsed.projects["project"].profiles if backend in parsed.profiles[key].backends]
            self.assertEqual(eligible, ["codex-" + backend])
        value["profiles"] = value["profiles"][:1]
        value["projects"][0]["profiles"] = ["codex-herdr"]
        with self.assertRaises(ValueError):
            self.parse(value)

    def test_accepts_zero_one_and_four_explicit_connections_and_freezes_maps(self):
        empty_value = self.base_value(connections=[])
        empty_value["projects"][0]["connections"] = []
        empty = self.parse(empty_value)
        self.assertEqual(dict(empty.connections), {})

        one = self.parse()
        self.assertEqual(tuple(one.connections), ("local",))
        self.assertIsInstance(one.connections["local"].executable, Path)
        with self.assertRaises((AttributeError, TypeError)):
            one.connections["other"] = one.connections["local"]
        with self.assertRaises((AttributeError, TypeError)):
            one.projects["other"] = one.projects["project"]
        with self.assertRaises((AttributeError, TypeError)):
            one.profiles["other"] = one.profiles["codex"]

        four_connections = [
            self.connection("herdr-1", "herdr"),
            self.connection("herdr-2", "herdr"),
            self.connection("tmux-1", "tmux"),
            self.connection("tmux-2", "tmux"),
        ]
        value = self.base_value(four_connections)
        value["projects"][0]["connections"] = [item["id"] for item in four_connections]
        four = self.parse(value)
        self.assertEqual(len(four.connections), 4)
        self.assertTrue(dataclasses.is_dataclass(four))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            four.generation = "changed"
        self.assertEqual(one.projects["project"].workspaces, ("w123",))
        self.assertEqual(one.profiles["codex"].args, ("--full-auto",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            one.connections["local"].session = "changed"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            one.projects["project"].protected = True
        with self.assertRaises(dataclasses.FrozenInstanceError):
            one.profiles["codex"].kind = "omp"

    def test_rejects_more_than_four_connections_and_unknown_or_invalid_default(self):
        connections = [self.connection(f"herdr-{index}") for index in range(5)]
        value = self.base_value(connections)
        value["projects"][0]["connections"] = [item["id"] for item in connections]
        with self.assertRaises(ValueError):
            self.parse(value)
        valid_default = self.base_value()
        valid_default["default_connection"] = "local"
        self.assertEqual(self.parse(valid_default).default_connection, "local")

        for default in ("missing", 1, True, ""):
            invalid = self.base_value()
            invalid["default_connection"] = default
            with self.subTest(default=default), self.assertRaises(ValueError):
                self.parse(invalid)

    def test_rejects_duplicate_actual_herdr_and_tmux_selectors(self):
        pairs = [
            [self.connection("one", session="same"), self.connection("two", session="same")],
            [
                self.connection("one", "tmux", socket=str(self.base / "shared.sock")),
                self.connection("two", "tmux", socket=str(self.base / "shared.sock")),
            ],
        ]
        for connections in pairs:
            value = self.base_value(connections)
            value["projects"][0]["connections"] = [item["id"] for item in connections]
            with self.subTest(connections=connections), self.assertRaises(ValueError):
                self.parse(value)

    def test_rejects_state_directory_inside_workspace_or_containing_config(self):
        value = self.base_value()
        value["state_dir"] = str(self.root / "state")
        with self.assertRaises(ValueError):
            self.parse(value)

        value = self.base_value()
        value["state_dir"] = str(self.base)
        with self.assertRaises(ValueError):
            self.parse(value)

    def test_rejects_symlink_hardlink_nonexecutable_and_untrusted_executable_ancestors(self):
        alias = self.base / "agent-alias"
        alias.symlink_to(self.executable)
        value = self.base_value()
        value["connections"][0]["executable"] = str(alias)
        with self.assertRaises(ValueError):
            self.parse(value)

        linked = self.base / "agent-hardlink"
        os.link(self.executable, linked)
        value = self.base_value()
        value["connections"][0]["executable"] = str(linked)
        with self.assertRaises(ValueError):
            self.parse(value)

        no_exec = self.bin / "not-executable"
        no_exec.write_text("data", encoding="utf-8")
        no_exec.chmod(0o600)
        value = self.base_value()
        value["connections"][0]["executable"] = str(no_exec)
        with self.assertRaises(ValueError):
            self.parse(value)

        writable_bin = self.base / "writable-bin"
        writable_bin.mkdir(mode=0o700)
        unsafe = writable_bin / "agent"
        unsafe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        unsafe.chmod(0o755)
        writable_bin.chmod(0o777)
        value = self.base_value()
        value["profiles"][0]["executable"] = str(unsafe)
        with self.assertRaises(ValueError):
            self.parse(value)

    def test_rejects_project_profile_connection_mismatches(self):
        for field, value_to_set in (("connections", ["missing"]), ("profiles", ["missing"])):
            value = self.base_value()
            value["projects"][0][field] = value_to_set
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.parse(value)

        value = self.base_value([self.connection("tmux-only", "tmux")])
        value["projects"][0]["connections"] = ["tmux-only"]
        value["profiles"][0]["backends"] = ["herdr"]
        with self.assertRaises(ValueError):
            self.parse(value)

    def test_readonly_target_schema_rejects_unknown_generation_and_unregistered_project(self):
        valid = self.base_value([self.connection("tmux", "tmux")])
        valid["projects"][0]["connections"] = ["tmux"]
        valid["connections"][0]["read_targets"] = [{
            "project": "project",
            "native_id": "%3",
            "identity": {
                "boot_id": "boot-a",
                "server_pid": "100",
                "server_start": "200",
                "pane_pid": "300",
                "pane_start": "400",
            },
        }]
        accepted = self.parse(valid)
        self.assertEqual(accepted.connections["tmux"].read_targets[0]["native_id"], "%3")
        value = self.base_value([self.connection("tmux", "tmux")])
        value["projects"][0]["connections"] = ["tmux"]
        value["connections"][0]["read_targets"] = [{
            "project": "project",
            "native_id": "%3",
            "identity": {
                "boot_id": "boot-a",
                "server_pid": "100",
                "server_start": "200",
                "pane_pid": "300",
                "pane_start": "400",
            },
            "generation": "old-generation",
        }]
        with self.assertRaises(ValueError):
            self.parse(value)

        value = self.base_value([self.connection("tmux", "tmux")])
        value["projects"][0]["connections"] = ["tmux"]
        value["connections"][0]["read_targets"] = [{
            "project": "unregistered-project",
            "native_id": "%3",
            "identity": {
                "boot_id": "boot-a",
                "server_pid": "100",
                "server_start": "200",
                "pane_pid": "300",
                "pane_start": "400",
            },
        }]
        with self.assertRaises(ValueError):
            self.parse(value)

    def test_protected_checks_canonical_ancestor_and_descendant_overlap(self):
        from dotunnel.supervision_config import protected

        protected_root = self.base / "protected"
        child = protected_root / "child"
        protected_root.mkdir()
        value = self.base_value()
        value["protected_paths"] = [str(protected_root)]
        settings = self.parse(value)
        self.assertTrue(protected(protected_root, settings))
        self.assertTrue(protected(child, settings))
        self.assertTrue(protected(self.base, settings))

        alias = self.base / "protected-alias"
        alias.symlink_to(protected_root, target_is_directory=True)
        self.assertTrue(protected(alias / "child", settings))

    def test_canonical_fingerprint_is_stable_for_json_values_and_rejects_nonfinite_numbers(self):
        from dotunnel.supervision_config import canonical_sha256

        left = {"z": [1, "안녕"], "a": {"b": True}}
        right = {"a": {"b": True}, "z": [1, "안녕"]}
        self.assertEqual(canonical_sha256(left), canonical_sha256(right))
        self.assertEqual(len(canonical_sha256(left)), 64)
        with self.assertRaises((ValueError, TypeError)):
            canonical_sha256({"not_json": float("nan")})

    def test_omitting_supervision_does_not_inspect_optional_backend_executables(self):
        from dotunnel.config import load_config

        self.config_path.write_text(json.dumps({"root": str(self.root), "tasks": []}), encoding="utf-8")
        self.config_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        loaded = load_config(self.config_path)
        self.assertIsNone(loaded.supervision)


    def test_rejects_unknown_fields_and_duplicate_ids(self):
        invalid = self.base_value()
        invalid["unrecognized"] = True
        with self.assertRaises(ValueError):
            self.parse(invalid)

        invalid = self.base_value([
            self.connection("same"),
            self.connection("same", session="different"),
        ])
        invalid["projects"][0]["connections"] = ["same"]
        with self.assertRaises(ValueError):
            self.parse(invalid)

        invalid = self.base_value()
        invalid["profiles"].append(dict(invalid["profiles"][0]))
        with self.assertRaises(ValueError):
            self.parse(invalid)

    def test_rejects_symlink_state_ancestor(self):
        alias = self.base / "state-parent-alias"
        alias.symlink_to(self.base, target_is_directory=True)
        value = self.base_value()
        value["state_dir"] = str(alias / "new-state")
        with self.assertRaises(ValueError):
            self.parse(value)
    def test_schema_errors_expose_stable_safe_supervision_results(self):
        from dotunnel.supervision_config import SupervisionError

        value = self.base_value()
        value["default_connection"] = "not-configured"
        with self.assertRaises(SupervisionError) as raised:
            self.parse(value)
        self.assertEqual(raised.exception.code, "invalid_request")
        result = raised.exception.as_result()
        self.assertEqual(set(result), {"error"})
        self.assertEqual(result["error"]["code"], "invalid_request")
        self.assertIsInstance(result["error"]["message"], str)
        if raised.exception.reason is not None:
            self.assertEqual(result["error"]["reason"], raised.exception.reason)

if __name__ == "__main__":
    unittest.main()

