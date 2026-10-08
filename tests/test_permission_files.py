import hashlib
import tempfile
import unittest
from pathlib import Path

from dotunnel.file_access import FileAccess
from dotunnel.files import WorkspaceFiles


class WorkspaceFilePermissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspace"
        (self.root / "src").mkdir(parents=True)
        (self.root / "src" / "allowed.txt").write_text("allowed\n", encoding="utf-8")
        (self.root / "src" / "denied.txt").write_text("denied\n", encoding="utf-8")
        self.files = WorkspaceFiles(
            self.root,
            FileAccess.parse(
                {
                    "read": [{"path": "src/allowed.txt", "kind": "file"}, {"path": "src/new.txt", "kind": "file"}],
                    "write": [{"path": "src/new.txt", "kind": "file"}],
                }
            ),
        )
        self.addCleanup(self.files.close)

    def test_browse_prunes_denied_files_and_search_does_not_read_them(self):
        self.assertEqual(
            self.files.list_files("."),
            {"entries": [{"path": "src", "type": "directory"}], "truncated": False},
        )
        self.assertEqual(
            self.files.list_files("src")["entries"],
            [{"path": "src/allowed.txt", "type": "file"}],
        )
        result = self.files.search_files("denied")
        self.assertEqual(result["matches"], [])

    def test_explicit_read_and_write_grants_are_enforced(self):
        self.assertEqual(self.files.read_file("src/allowed.txt")["content"], "allowed\n")
        with self.assertRaisesRegex(ValueError, "Workspace access denied"):
            self.files.read_file("src/denied.txt")
        with self.assertRaisesRegex(ValueError, "Workspace access denied"):
            self.files.write_file("src/allowed.txt", "changed\n", hashlib.sha256(b"allowed\n").hexdigest())
        result = self.files.write_file("src/new.txt", "created\n")
        self.assertTrue(result["created"])
        self.assertEqual((self.root / "src" / "new.txt").read_text(encoding="utf-8"), "created\n")
        with self.assertRaisesRegex(ValueError, "Workspace access denied"):
            self.files.write_file("src/other.txt", "no\n")


if __name__ == "__main__":
    unittest.main()
