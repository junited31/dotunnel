"""Permission draft and review behavior for the public setup flow."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path


class PermissionSetupTests(unittest.TestCase):
    def test_confirmation_defaults_no_and_rejects_ambiguous_input(self):
        from dotunnel.permission_setup import confirm

        self.assertFalse(confirm(lambda _prompt: "", "approve?", default=False))
        self.assertTrue(confirm(lambda _prompt: "", "keep?", default=True))
        with self.assertRaisesRegex(ValueError, "Answer yes or no"):
            confirm(lambda _prompt: "perhaps", "approve?", default=False)

    def test_file_access_draft_is_explicit_and_summarized_without_side_effects(self):
        from dotunnel.permission_setup import collect_draft, print_summary

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory = base / "private-setup"
            root = base / "project"
            root.mkdir(mode=0o700)
            answers = iter(("e", str(root), "", "", "n"))
            draft = collect_draft(
                lambda _prompt: next(answers), directory=directory,
                current_root=None, current_file_access=None,
                current_supervision=None, existing_setup=False,
                legacy=False, selected_jobs=set(), generation="generation",
            )
            self.assertEqual(draft.workspace, root)
            self.assertFalse(draft.create_workspace)
            self.assertEqual(draft.file_access, {"read": [], "write": []})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                print_summary(draft, tasks=[], job_details=[], removed_jobs=[], key_reference=directory / "runtime-api-key")
            self.assertIn("nothing has been created, saved, or connected", output.getvalue())
            self.assertFalse(directory.exists())

    def test_request_grants_are_exact_file_rules(self):
        from dotunnel.permission_setup import add_request_grants

        access = add_request_grants({"read": [], "write": []}, ("dotunnel-requests/fixture-generation/codex.json",))
        self.assertEqual(access["read"], [{"path": "dotunnel-requests/fixture-generation/codex.json", "kind": "file"}])
        self.assertEqual(access["write"], access["read"])


if __name__ == "__main__":
    unittest.main()
