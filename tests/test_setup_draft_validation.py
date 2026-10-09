"""Complete setup drafts are validated before approval and side effects."""

import tempfile
import unittest
from pathlib import Path


class SetupDraftValidationTests(unittest.TestCase):
    def test_invalid_complete_draft_is_rejected_without_creating_future_paths(self):
        from dotunnel.permission_setup import Draft, validate_draft_document

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "future-workspace"
            private = base / "private"
            access = {"read": [{"path": "../secret", "kind": "file"}], "write": []}
            draft = Draft(private, root, True, "generation", access, None, frozenset(), (), False)
            document = {"root": str(root), "file_access": access, "tasks": []}
            with self.assertRaises(ValueError):
                validate_draft_document(draft, document, private / "config.json")
            self.assertFalse(root.exists())
            self.assertFalse(private.exists())

    def test_legacy_conversion_requires_explicit_complete_policy(self):
        from dotunnel.permission_setup import Draft, validate_draft_document

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "workspace"
            root.mkdir(mode=0o700)
            draft = Draft(base / "private", root, False, "generation", {"read": [], "write": []}, None, frozenset(), (), True)
            document = {"root": str(root), "tasks": []}
            with self.assertRaises(ValueError):
                validate_draft_document(draft, document, base / "private" / "config.json")


if __name__ == "__main__":
    unittest.main()
