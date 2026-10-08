import hashlib
import os
import queue
import stat
import tempfile
import threading
import unittest
from pathlib import Path

import dotunnel.files as files_module
from dotunnel.file_access import FileAccess
from dotunnel.files import WorkspaceFiles


MAX_FILE_BYTES = 64 * 1024


class WorkspaceFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)
        self.root = self.temp_path / "workspace"
        self.root.mkdir()
        self.access = FileAccess.parse(
            {"read": [{"path": ".", "kind": "tree"}], "write": [{"path": ".", "kind": "tree"}]}
        )
        self.files = WorkspaceFiles(self.root, self.access)
        self.addCleanup(self.files.close)

    def assertClientError(self, operation):
        with self.assertRaises(ValueError) as caught:
            operation()
        message = str(caught.exception)
        self.assertNotIn(str(self.root), message)
        self.assertNotIn(str(self.temp_path), message)

    @staticmethod
    def digest(content):
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def test_create_read_and_hash_guarded_replace(self):
        (self.root / "notes").mkdir()
        created = self.files.write_file("notes/today.txt", "first\n")
        self.assertEqual(
            created,
            {
                "path": "notes/today.txt",
                "sha256": self.digest("first\n"),
                "created": True,
            },
        )
        self.assertEqual(
            self.files.read_file("notes/today.txt"),
            {
                "path": "notes/today.txt",
                "content": "first\n",
                "sha256": self.digest("first\n"),
            },
        )

        replaced = self.files.write_file(
            "notes/today.txt", "second\n", expected_sha256=created["sha256"]
        )
        self.assertEqual(
            replaced,
            {
                "path": "notes/today.txt",
                "sha256": self.digest("second\n"),
                "created": False,
            },
        )
        self.assertEqual(self.files.read_file("notes/today.txt")["content"], "second\n")

    def test_create_only_conflict_and_wrong_hash_preserve_existing_contents(self):
        path = self.root / "existing.txt"
        path.write_text("unchanged", encoding="utf-8")

        self.assertClientError(lambda: self.files.write_file("existing.txt", "replace"))
        self.assertClientError(
            lambda: self.files.write_file("existing.txt", "replace", "0" * 64)
        )
        self.assertEqual(path.read_text(encoding="utf-8"), "unchanged")

    def test_invalid_hash_and_oversized_content_do_not_mutate_files(self):
        path = self.root / "existing.txt"
        path.write_text("stable", encoding="utf-8")
        matching_hash = self.digest("stable")

        self.assertClientError(
            lambda: self.files.write_file("existing.txt", "new", "not-a-sha256")
        )
        self.assertClientError(
            lambda: self.files.write_file(
                "existing.txt", "x" * (MAX_FILE_BYTES + 1), matching_hash
            )
        )
        self.assertClientError(
            lambda: self.files.write_file("new.txt", "x" * (MAX_FILE_BYTES + 1))
        )
        self.assertEqual(path.read_text(encoding="utf-8"), "stable")
        self.assertFalse((self.root / "new.txt").exists())

    def test_file_size_boundary_and_utf8_byte_count(self):
        content = "x" * MAX_FILE_BYTES
        result = self.files.write_file("limit.txt", content)
        self.assertEqual(result["sha256"], self.digest(content))
        self.assertEqual(self.files.read_file("limit.txt")["content"], content)

        large_path = self.root / "too-large.txt"
        large_path.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        self.assertClientError(lambda: self.files.read_file("too-large.txt"))

        multibyte = "€" * (MAX_FILE_BYTES // len("€".encode("utf-8")) + 1)
        self.assertGreater(len(multibyte.encode("utf-8")), MAX_FILE_BYTES)
        self.assertClientError(lambda: self.files.write_file("utf8-large.txt", multibyte))
        self.assertFalse((self.root / "utf8-large.txt").exists())

    def test_new_files_are_private_and_replacement_preserves_existing_mode(self):
        created = self.files.write_file("created.txt", "initial")
        self.assertTrue(created["created"])
        self.assertEqual(stat.S_IMODE((self.root / "created.txt").stat().st_mode), 0o600)

        existing = self.root / "group-readable.txt"
        existing.write_text("old", encoding="utf-8")
        existing.chmod(0o640)
        self.files.write_file("group-readable.txt", "new", self.digest("old"))
        self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o640)

    def test_paths_reject_absolute_parent_nul_and_non_root_dot_components(self):
        outside = self.temp_path / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        bad_paths = ["../outside.txt", str(outside), "nested/../../outside.txt", "bad\x00name"]
        for path in bad_paths:
            with self.subTest(path=path):
                self.assertClientError(lambda: self.files.read_file(path))
                self.assertClientError(lambda: self.files.write_file(path, "no"))
                self.assertClientError(lambda: self.files.list_files(path))
                self.assertClientError(lambda: self.files.search_files("x", path))

        self.assertClientError(lambda: self.files.read_file("."))
        self.assertClientError(lambda: self.files.write_file(".", "no"))
        self.assertClientError(lambda: self.files.list_files("./"))
        self.assertClientError(lambda: self.files.search_files("x", "./nested"))
        self.assertEqual(self.files.list_files("."), {"entries": [], "truncated": False})

    def test_root_cannot_be_filesystem_root_home_or_a_symlink(self):
        self.assertClientError(lambda: WorkspaceFiles(Path("/"), self.access))
        self.assertClientError(lambda: WorkspaceFiles(Path.home(), self.access))

        target = self.temp_path / "real-root"
        target.mkdir()
        root_link = self.temp_path / "root-link"
        root_link.symlink_to(target, target_is_directory=True)
        self.assertClientError(lambda: WorkspaceFiles(root_link, self.access))

    def test_symlinked_root_ancestor_is_rejected(self):
        parent = self.temp_path / "parent"
        parent.mkdir()
        root = parent / "workspace"
        root.mkdir()
        parent_link = self.temp_path / "parent-link"
        parent_link.symlink_to(parent, target_is_directory=True)

        self.assertClientError(lambda: WorkspaceFiles(parent_link / "workspace", self.access))

    def test_nested_symlinks_are_not_read_or_exposed(self):
        outside = self.temp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (self.root / "linked.txt").symlink_to(outside)
        (self.root / "linked-dir").symlink_to(self.temp_path, target_is_directory=True)
        (self.root / "visible.txt").write_text("public", encoding="utf-8")

        self.assertClientError(lambda: self.files.read_file("linked.txt"))
        self.assertClientError(lambda: self.files.list_files("linked-dir"))
        self.assertClientError(lambda: self.files.search_files("secret", "linked-dir"))
        self.assertEqual(
            self.files.list_files("."),
            {"entries": [{"path": "visible.txt", "type": "file"}], "truncated": False},
        )

    def test_hidden_and_credential_or_private_key_names_are_inaccessible(self):
        protected = [".env", ".ssh", ".git", ".hidden", "id_rsa", "private.pem", "server.key"]
        for name in protected:
            path = self.root / name
            if name in {".ssh", ".git"}:
                path.mkdir()
            else:
                path.write_text("sensitive", encoding="utf-8")

        (self.root / "public.txt").write_text("safe", encoding="utf-8")
        self.assertEqual(
            self.files.list_files("."),
            {"entries": [{"path": "public.txt", "type": "file"}], "truncated": False},
        )
        for name in protected:
            with self.subTest(name=name):
                self.assertClientError(lambda: self.files.read_file(name))

    def test_credential_stems_with_document_extensions_are_protected(self):
        content = "synthetic credential fixture"
        for name in ("credentials.json", "credentials.txt", "secrets.json", "token.txt"):
            path = self.root / name
            path.write_text(content)
            with self.subTest(name=name):
                self.assertClientError(lambda: self.files.read_file(name))
                self.assertClientError(lambda: self.files.write_file(name, "changed", self.digest(content)))
                self.assertEqual(path.read_text(), content)
        self.assertEqual(self.files.list_files(".")["entries"], [])
        self.assertEqual(self.files.search_files("synthetic credential fixture")["matches"], [])

    def test_hardlinked_files_are_rejected_for_read_and_replace(self):
        original = self.root / "original.txt"
        original.write_text("shared", encoding="utf-8")
        alias = self.root / "alias.txt"
        os.link(original, alias)

        self.assertClientError(lambda: self.files.read_file("alias.txt"))
        self.assertClientError(
            lambda: self.files.write_file("alias.txt", "changed", self.digest("shared"))
        )
        self.assertEqual(original.read_text(encoding="utf-8"), "shared")
        self.assertEqual(alias.read_text(encoding="utf-8"), "shared")

    def test_fifo_is_not_read_or_listed_as_a_regular_file(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)

        self.assertClientError(lambda: self.files.read_file("pipe"))
        listing = self.files.list_files(".")
        self.assertEqual(listing, {"entries": [], "truncated": False})

    def test_list_is_bounded_and_deterministically_ordered(self):
        for index in range(205):
            (self.root / f"entry-{index:03}.txt").write_text("x", encoding="utf-8")

        result = self.files.list_files(".")
        self.assertEqual(len(result["entries"]), 200)
        self.assertTrue(result["truncated"])
        paths = [entry["path"] for entry in result["entries"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), len(set(paths)))
        self.assertTrue(all(entry["type"] == "file" for entry in result["entries"]))

    def test_search_is_literal_and_reports_relative_path_line_and_text(self):
        source = self.root / "src"
        source.mkdir()
        (source / "match.txt").write_text("first\na.b exact\naxb is different\n", encoding="utf-8")
        (self.root / "other.txt").write_text("a.b elsewhere\n", encoding="utf-8")

        result = self.files.search_files("a.b", "src")
        self.assertEqual(
            result,
            {
                "matches": [
                    {"path": "src/match.txt", "line": 2, "text": "a.b exact"}
                ],
                "truncated": False,
            },
        )

    def test_search_caps_matches_and_returns_stable_order(self):
        for index in range(101):
            (self.root / f"match-{index:03}.txt").write_text("needle\n", encoding="utf-8")

        result = self.files.search_files("needle")
        self.assertEqual(len(result["matches"]), 100)
        self.assertTrue(result["truncated"])
        paths = [match["path"] for match in result["matches"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(paths, [f"match-{index:03}.txt" for index in range(100)])
        self.assertTrue(all(match["line"] == 1 and match["text"] == "needle" for match in result["matches"]))

    def test_search_caps_visited_entries_and_scanned_bytes(self):
        for index in range(1001):
            (self.root / f"entry-{index:04}.txt").write_text("x", encoding="utf-8")
        visited_limited = self.files.search_files("absent")
        self.assertTrue(visited_limited["truncated"])
        self.assertEqual(visited_limited["matches"], [])

        for path in self.root.iterdir():
            path.unlink()
        for index in range(65):
            (self.root / f"large-{index:03}.txt").write_bytes(b"x" * MAX_FILE_BYTES)
        byte_limited = self.files.search_files("absent")
        self.assertTrue(byte_limited["truncated"])
        self.assertEqual(byte_limited["matches"], [])

    def test_search_bounds_long_line_text_and_marks_truncation(self):
        (self.root / "long-line.txt").write_text("needle" + ("x" * 20_000) + "\n", encoding="utf-8")

        result = self.files.search_files("needle")
        self.assertEqual(len(result["matches"]), 1)
        self.assertLessEqual(len(result["matches"][0]["text"]), 4096)
        self.assertTrue(result["truncated"])

    def test_concurrent_hash_guard_allows_only_one_replacement(self):
        path = self.root / "shared.txt"
        path.write_text("original", encoding="utf-8")
        expected_sha256 = self.digest("original")
        read_barrier = threading.Barrier(2, timeout=2)
        start_barrier = threading.Barrier(3, timeout=3)
        outcomes = queue.Queue()
        original_read = files_module._read_up_to

        def synchronized_read(fd, limit):
            data = original_read(fd, limit)
            try:
                read_barrier.wait()
            except threading.BrokenBarrierError:
                pass
            return data

        def replace(content):
            try:
                start_barrier.wait()
                result = self.files.write_file(
                    "shared.txt", content, expected_sha256=expected_sha256
                )
            except ValueError as error:
                outcomes.put(("conflict", error))
            except BaseException as error:
                outcomes.put(("unexpected", error))
            else:
                outcomes.put(("success", content, result))

        files_module._read_up_to = synchronized_read
        workers = [
            threading.Thread(target=replace, args=(content,), daemon=True)
            for content in ("first replacement", "second replacement")
        ]
        try:
            for worker in workers:
                worker.start()
            start_barrier.wait()
            for worker in workers:
                worker.join(timeout=4)
        finally:
            files_module._read_up_to = original_read

        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(outcomes.qsize(), 2)
        results = [outcomes.get_nowait() for _ in range(2)]
        self.assertCountEqual([result[0] for result in results], ["success", "conflict"])
        self.assertIn(
            path.read_text(encoding="utf-8"),
            ("first replacement", "second replacement"),
        )

    def test_close_is_safe_and_prevents_later_access(self):
        self.files.close()
        self.files.close()
        self.assertClientError(lambda: self.files.list_files("."))


if __name__ == "__main__":
    unittest.main()
