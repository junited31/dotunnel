import json
import os
import tempfile
import unittest
from pathlib import Path


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.config = self.base / "config.json"

    def save(self, **changes):
        data = {"root": str(self.root), "tasks": [], "file_access": {"read": [], "write": []}}
        data.update(changes)
        self.config.write_text(json.dumps(data))
        self.config.chmod(0o600)
        return self.config

    def load(self, path=None):
        from dotunnel.config import load_config
        return load_config(path or self.config)

    def test_valid_root_and_empty_tasks(self):
        self.save()
        result = self.load()
        self.assertEqual(result.root, self.root)
        self.assertEqual(result.file_access.read, ())
        self.assertEqual(result.file_access.write, ())

    def test_missing_file_access_is_rejected(self):
        self.config.write_text(json.dumps({"root": str(self.root), "tasks": []}))
        self.config.chmod(0o600)
        with self.assertRaises(ValueError):
            self.load()

    def test_parses_explicit_file_access_policy(self):
        self.save(
            file_access={
                "read": [{"path": "src/public.txt", "kind": "file"}],
                "write": [],
            }
        )
        result = self.load()
        self.assertTrue(result.file_access.allows("read", ("src", "public.txt")))
        self.assertFalse(result.file_access.allows("read", ("src", "private.txt")))

    def test_rejects_invalid_file_access_policy(self):
        self.save(file_access={"read": [], "write": [{"path": "outside.txt", "kind": "file"}]})
        with self.assertRaises(ValueError):
            self.load()

    def test_rejects_config_inside_writable_root(self):
        path = self.root / "settings.json"
        self.save()
        path.write_bytes(self.config.read_bytes())
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.load(path)

    def test_rejects_symlink_and_group_writable_config(self):
        self.save()
        link = self.base / "alias.json"
        link.symlink_to(self.config)
        with self.assertRaises(ValueError):
            self.load(link)
        self.config.chmod(0o620)
        with self.assertRaises(ValueError):
            self.load()

    def test_rejects_unknown_fields_and_duplicate_keys(self):
        self.save(shell=True)
        with self.assertRaises(ValueError):
            self.load()
        self.config.write_text('{"root":"' + str(self.root) + '","tasks":[],"tasks":[]}')
        with self.assertRaises(ValueError):
            self.load()

    def test_rejects_unsafe_root(self):
        for root in ["/", str(Path.home()), "relative", str(self.base / "absent")]:
            with self.subTest(root=root):
                self.save(root=root)
                with self.assertRaises(ValueError):
                    self.load()
        link = self.base / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        self.save(root=str(link))
        with self.assertRaises(ValueError):
            self.load()

    def test_rejects_task_escape_relative_executable_and_nonfinite_timeout(self):
        task = {"name": "check", "description": "local check", "argv": ["/usr/bin/true"], "cwd": ".", "timeout_seconds": 2}
        for changes in [{"cwd": ".."}, {"cwd": "/"}, {"argv": ["sh"]}, {"timeout_seconds": float("nan")}, {"timeout_seconds": 301}, {"env": {"TOKEN": "not-a-secret"}}]:
            with self.subTest(changes=changes):
                self.save(tasks=[task | changes])
                with self.assertRaises(ValueError):
                    self.load()

    def test_accepts_only_exact_task_arguments(self):
        task = {"name": "check", "description": "fixed check", "argv": ["/usr/bin/true"], "cwd": ".", "timeout_seconds": 2}
        self.save(tasks=[task])
        result = self.load()
        self.assertEqual(result.tasks[0].argv, ("/usr/bin/true",))
        self.assertEqual(result.tasks[0].cwd, self.root)

    def test_rejects_duplicate_names_and_symlink_task_directory(self):
        task = {"name": "check", "description": "fixed check", "argv": ["/usr/bin/true"], "cwd": ".", "timeout_seconds": 2}
        self.save(tasks=[task, task])
        with self.assertRaises(ValueError):
            self.load()
        (self.root / "linked").symlink_to(self.base, target_is_directory=True)
        self.save(tasks=[task | {"cwd": "linked"}])
        with self.assertRaises(ValueError):
            self.load()

    def test_rejects_oversized_integer_timeout_without_overflow(self):
        self.save(tasks=[{"name": "check", "description": "check", "argv": ["/usr/bin/true"], "timeout_seconds": 10 ** 1000}])
        with self.assertRaises(ValueError):
            self.load()

    def test_rejects_non_utf8_json(self):
        self.save()
        self.config.write_bytes(json.dumps({"root": str(self.root), "tasks": []}).encode("utf-16"))
        with self.assertRaises(ValueError):
            self.load()


if __name__ == "__main__":
    unittest.main()
