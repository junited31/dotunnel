import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from dotunnel.cli_file_tools import CandidateFileTools


class CandidateFileToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "snapshot"
        self.root.mkdir()
        self.candidates = (
            "main.py",
            "docs/guide.txt",
            "absent.py",
            "hardlink.py",
            "symlink.py",
        )
        self.editable = ("main.py", "absent.py", "hardlink.py", "symlink.py")
        (self.root / "docs").mkdir()
        (self.root / "main.py").write_text("old source\n", encoding="utf-8")
        (self.root / "docs" / "guide.txt").write_text(
            "read only\n", encoding="utf-8"
        )
        self.tools = CandidateFileTools(
            self.root, self.candidates, self.editable, "edit"
        )
        self.addCleanup(self.tools.close)

    @staticmethod
    def digest(text):
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def call_text(response):
        return response["contentItems"][0]["text"]

    def assert_native_response(self, response, success):
        self.assertIs(type(response["success"]), bool)
        self.assertEqual(response["success"], success)
        self.assertIs(type(response["contentItems"]), list)
        self.assertEqual(len(response["contentItems"]), 1)
        self.assertEqual(response["contentItems"][0]["type"], "inputText")
        text = self.call_text(response)
        encoded = text.encode("utf-8", "strict")
        self.assertLessEqual(len(encoded), 512 * 1024)
        return text

    def test_edit_definitions_expose_only_exact_candidate_and_editable_paths(self):
        definitions = self.tools.definitions()
        self.assertEqual(
            [item["name"] for item in definitions],
            ["candidate_read_file", "candidate_write_file"],
        )
        self.assertTrue(all(item["type"] == "function" for item in definitions))

        read_schema = definitions[0]["inputSchema"]
        self.assertEqual(read_schema["additionalProperties"], False)
        self.assertEqual(read_schema["required"], ["path"])
        self.assertEqual(
            read_schema["properties"]["path"]["enum"], list(self.candidates)
        )

        write_schema = definitions[1]["inputSchema"]
        self.assertEqual(write_schema["additionalProperties"], False)
        self.assertEqual(
            write_schema["required"], ["path", "content", "expected_sha256"]
        )
        self.assertEqual(
            write_schema["properties"]["path"]["enum"], list(self.editable)
        )
        self.assertEqual(write_schema["properties"]["content"]["type"], "string")
        self.assertEqual(
            write_schema["properties"]["expected_sha256"]["type"], "string"
        )

    def test_read_returns_existing_candidate_content_and_sha256(self):
        response = self.tools.call("candidate_read_file", {"path": "main.py"})
        result = json.loads(self.assert_native_response(response, True))
        self.assertEqual(
            result,
            {
                "path": "main.py",
                "content": "old source\n",
                "sha256": self.digest("old source\n"),
            },
        )

    def test_write_replaces_only_existing_editable_candidate_with_current_hash(self):
        response = self.tools.call(
            "candidate_write_file",
            {
                "path": "main.py",
                "content": "new source\n",
                "expected_sha256": self.digest("old source\n"),
            },
        )
        result = json.loads(self.assert_native_response(response, True))
        self.assertEqual(
            result,
            {
                "path": "main.py",
                "sha256": self.digest("new source\n"),
                "created": False,
            },
        )
        self.assertEqual(
            (self.root / "main.py").read_text(encoding="utf-8"), "new source\n"
        )

    def test_invalid_arguments_tools_and_paths_never_mutate_candidates(self):
        before = (self.root / "main.py").read_text(encoding="utf-8")
        outside = Path(self.temp.name) / "outside.py"
        outside.write_text("outside\n", encoding="utf-8")
        calls = (
            ("candidate_read_file", None),
            ("candidate_read_file", {"path": "main.py", "extra": True}),
            ("candidate_read_file", {"path": "../outside.py"}),
            ("candidate_read_file", {"path": str(outside)}),
            (
                "candidate_write_file",
                {"path": "main.py", "content": "changed"},
            ),
            (
                "candidate_write_file",
                {"path": "main.py", "content": "changed", "expected_sha256": None},
            ),
            (
                "candidate_write_file",
                {
                    "path": "main.py",
                    "content": "changed",
                    "expected_sha256": self.digest(before),
                    "extra": True,
                },
            ),
            (
                "candidate_write_file",
                {
                    "path": "../outside.py",
                    "content": "changed",
                    "expected_sha256": self.digest("outside\n"),
                },
            ),
            (
                "candidate_write_file",
                {
                    "path": "docs/guide.txt",
                    "content": "changed",
                    "expected_sha256": self.digest("read only\n"),
                },
            ),
            (
                "candidate_write_file",
                {
                    "path": ".env",
                    "content": "changed",
                    "expected_sha256": self.digest("secret"),
                },
            ),
            ("unknown_tool", {"path": "main.py"}),
        )
        for tool, arguments in calls:
            with self.subTest(tool=tool, arguments=arguments):
                text = self.assert_native_response(
                    self.tools.call(tool, arguments), False
                )
                self.assertNotIn(str(self.root), text)

        self.assertEqual((self.root / "main.py").read_text(encoding="utf-8"), before)
        self.assertEqual(
            (self.root / "docs" / "guide.txt").read_text(encoding="utf-8"),
            "read only\n",
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
        self.assertFalse((self.root / "absent.py").exists())
        self.assertFalse((self.root / ".env").exists())

    def test_stale_hash_cannot_replace_candidate(self):
        response = self.tools.call(
            "candidate_write_file",
            {
                "path": "main.py",
                "content": "stale replacement",
                "expected_sha256": self.digest("not current"),
            },
        )
        self.assert_native_response(response, False)
        self.assertEqual(
            (self.root / "main.py").read_text(encoding="utf-8"), "old source\n"
        )

    def test_candidate_write_enforces_utf8_byte_limit_before_mutation(self):
        original = "old source\n"
        for content in ("a" * (64 * 1024 + 1), "é" * (32 * 1024 + 1)):
            with self.subTest(utf8_bytes=len(content.encode("utf-8"))):
                response = self.tools.call(
                    "candidate_write_file",
                    {
                        "path": "main.py",
                        "content": content,
                        "expected_sha256": self.digest(original),
                    },
                )
                self.assert_native_response(response, False)
                self.assertEqual((self.root / "main.py").read_text(), original)
        boundary = "é" * (32 * 1024)
        response = self.tools.call(
            "candidate_write_file",
            {
                "path": "main.py",
                "content": boundary,
                "expected_sha256": self.digest(original),
            },
        )
        self.assert_native_response(response, True)
        self.assertEqual((self.root / "main.py").read_bytes(), boundary.encode("utf-8"))

    def test_hardlinks_and_symlinks_cannot_be_read_or_replaced(self):
        original = self.root / "main.py"
        os.link(original, self.root / "hardlink.py")
        target = Path(self.temp.name) / "outside-target.py"
        target.write_text("outside target\n", encoding="utf-8")
        (self.root / "symlink.py").symlink_to(target)

        for path in ("hardlink.py", "symlink.py"):
            with self.subTest(path=path):
                self.assert_native_response(
                    self.tools.call("candidate_read_file", {"path": path}), False
                )
                self.assert_native_response(
                    self.tools.call(
                        "candidate_write_file",
                        {
                            "path": path,
                            "content": "tampered",
                            "expected_sha256": self.digest("old source\n"),
                        },
                    ),
                    False,
                )

        self.assertEqual(original.read_text(encoding="utf-8"), "old source\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "outside target\n")

    def test_review_mode_has_read_only_capability(self):
        with CandidateFileTools(
            self.root, self.candidates, self.editable, "review"
        ) as tools:
            self.assertEqual(
                [item["name"] for item in tools.definitions()],
                ["candidate_read_file"],
            )
            self.assert_native_response(
                tools.call(
                    "candidate_write_file",
                    {
                        "path": "main.py",
                        "content": "tampered",
                        "expected_sha256": self.digest("old source\n"),
                    },
                ),
                False,
            )
        self.assertEqual(
            (self.root / "main.py").read_text(encoding="utf-8"), "old source\n"
        )

    def test_invalid_hash_and_missing_existing_file_do_not_create_or_change_files(self):
        for expected in (None, "not-a-sha256", self.digest("anything")):
            with self.subTest(expected=expected):
                response = self.tools.call(
                    "candidate_write_file",
                    {
                        "path": "absent.py",
                        "content": "must not be created",
                        "expected_sha256": expected,
                    },
                )
                self.assert_native_response(response, False)
        self.assertFalse((self.root / "absent.py").exists())
        self.assertEqual(
            (self.root / "main.py").read_text(encoding="utf-8"), "old source\n"
        )

    def test_maximum_control_text_read_stays_within_utf8_response_bound(self):
        content = "\x00" * (64 * 1024)
        (self.root / "main.py").write_text(content, encoding="utf-8")

        response = self.tools.call("candidate_read_file", {"path": "main.py"})
        text = self.assert_native_response(response, True)
        self.assertEqual(json.loads(text)["content"], content)

    def test_constructor_rejects_escaping_candidates_and_unapproved_editable_paths(
        self,
    ):
        invalid_files = (
            ("/outside.py",),
            ("../outside.py",),
            ("nested/../outside.py",),
        )
        for files in invalid_files:
            with self.subTest(files=files):
                with self.assertRaises(ValueError):
                    CandidateFileTools(self.root, files, (), "edit")

        with self.assertRaises(ValueError):
            CandidateFileTools(self.root, ("main.py",), ("other.py",), "edit")

    def test_close_is_idempotent_and_disables_file_operations(self):
        self.tools.close()
        self.tools.close()

        self.assert_native_response(
            self.tools.call("candidate_read_file", {"path": "main.py"}), False
        )


if __name__ == "__main__":
    unittest.main()
