import unittest

from dotunnel.file_access import FileAccess


class FileAccessTests(unittest.TestCase):
    def rule(self, path, kind="file"):
        return {"path": path, "kind": kind}

    def test_empty_policy_denies_access_and_browsing(self):
        access = FileAccess.parse({"read": [], "write": []})
        self.assertFalse(access.allows("read", ()))
        self.assertFalse(access.allows("write", ("new.txt",)))
        self.assertFalse(access.browsable(()))
        with self.assertRaisesRegex(ValueError, "Workspace access denied"):
            access.require("read", ("public.txt",))

    def test_exact_file_allows_navigation_not_sibling_access(self):
        access = FileAccess.parse({"read": [self.rule("src/a.txt")], "write": []})
        self.assertTrue(access.browsable(()))
        self.assertTrue(access.browsable(("src",)))
        self.assertFalse(access.browsable(("src", "a.txt")))
        self.assertTrue(access.allows("read", ("src", "a.txt")))
        self.assertFalse(access.allows("read", ("src", "b.txt")))

    def test_tree_rule_and_write_subset(self):
        access = FileAccess.parse(
            {"read": [self.rule("src", "tree")], "write": [self.rule("src/new.txt")]}
        )
        self.assertTrue(access.allows("read", ("src", "nested", "a")))
        self.assertTrue(access.allows("write", ("src", "new.txt")))
        self.assertFalse(access.allows("write", ("src", "nested", "a")))
        with self.assertRaises(ValueError):
            FileAccess.parse({"read": [self.rule("src/a.txt")], "write": [self.rule("src", "tree")]})

    def test_malformed_duplicate_and_unknown_fields_are_rejected(self):
        cases = (
            {"read": [], "write": [], "other": []},
            {"read": [self.rule("a"), self.rule("a")], "write": []},
            {"read": [self.rule("../a")], "write": []},
            {"read": [self.rule("a", "directory")], "write": []},
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                FileAccess.parse(value)

    def test_root_tree_and_rule_limit(self):
        access = FileAccess.parse({"read": [self.rule(".", "tree")], "write": []})
        self.assertTrue(access.browsable(()))
        too_many = [self.rule(f"f-{index}") for index in range(129)]
        with self.assertRaises(ValueError):
            FileAccess.parse({"read": too_many, "write": []})


if __name__ == "__main__":
    unittest.main()
