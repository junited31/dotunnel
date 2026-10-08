"""Setup approval and artifact publication lifecycle regressions."""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


TUNNEL = "tunnel_" + "7" * 32


class Terminal(io.StringIO):
    def isatty(self):
        return True


class SetupLifecycleTests(unittest.TestCase):
    def test_new_config_has_explicit_empty_file_access_and_public_server_route(self):
        from dotunnel import setup
        from dotunnel.config import load_config

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            profile = setup.create_artifacts(directory, TUNNEL, "synthetic-key")
            document = json.loads((directory / "config.json").read_text())
            self.assertEqual(document["file_access"], {"read": [], "write": []})
            self.assertEqual(load_config(directory / "config.json").file_access.read, ())
            self.assertIn("-m dotunnel serve", profile.read_text())

    def test_initial_publication_requires_private_references_to_exist(self):
        from dotunnel.setup import publish_initial_config

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            with self.assertRaises((OSError, ValueError)):
                publish_initial_config(directory, {"root": str(directory / "workspace"), "file_access": {"read": [], "write": []}, "tasks": []})
            self.assertFalse((directory / "config.json").exists())

    def test_default_no_review_precedes_hidden_credential_input_and_writes(self):
        from dotunnel import onboarding, setup
        from unittest.mock import Mock

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            client = Path(temporary) / "tunnel-client"
            client.write_text("synthetic executable")
            client.chmod(0o700)
            read_key = Mock(side_effect=AssertionError("credential requested before approval"))
            discovery = []

            def discover():
                discovery.append(True)
                return {}

            with patch.object(onboarding.sys, "platform", "linux"), patch.object(
                onboarding.os, "getuid", return_value=os.getuid()
            ), patch.object(onboarding.sys, "stdin", Terminal()), patch.object(
                onboarding.sys, "stderr", Terminal()
            ), patch.object(onboarding.integrations, "_inspect_launcher", return_value=client), patch.object(
                onboarding.integrations, "discover_clis", side_effect=discover
            ), patch.object(
                onboarding.integrations, "bubblewrap_status", return_value="ready"
            ), patch(
                "builtins.input", return_value=""
            ), patch.object(setup, "read_key", new=read_key):
                status = onboarding.main([
                    "--directory", str(directory), "--tunnel-client", str(client),
                ])
            self.assertEqual(status, 130)
            self.assertEqual(discovery, [True])
            read_key.assert_not_called()
            self.assertFalse(directory.exists())
if __name__ == "__main__":
    unittest.main()
