import importlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TUNNEL = "tunnel_" + "1" * 32
SYNTHETIC_KEY = "synthetic-setup-secret-not-a-runtime-key"


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.destination = self.base / "private setup"

    def module(self):
        return importlib.import_module("dotunnel.setup")

    def test_private_artifacts_keep_credentials_outside_mcp_root(self):
        setup = self.module()
        profile = setup.create_artifacts(self.destination, TUNNEL, SYNTHETIC_KEY)
        from dotunnel.config import load_config
        config = load_config(self.destination / "config.json")
        self.assertEqual(config.file_access.read, ())
        self.assertEqual(config.file_access.write, ())
        self.assertFalse((self.destination / "runtime-api-key").is_relative_to(config.root))
        self.assertFalse(profile.is_relative_to(config.root))
        self.assertEqual(list(config.root.iterdir()), [])
        for path in (self.destination, config.root):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (profile, self.destination / "config.json", self.destination / "runtime-api-key"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual((self.destination / "runtime-api-key").read_text(), SYNTHETIC_KEY + "\n")
        self.assertNotIn(SYNTHETIC_KEY, profile.read_text())
        self.assertNotIn(SYNTHETIC_KEY, (self.destination / "config.json").read_text())


    def test_existing_destination_and_credentials_are_never_overwritten(self):
        setup = self.module()
        self.destination.mkdir()
        key = self.destination / "runtime-api-key"
        key.write_text("existing fixture credential")
        with self.assertRaises((ValueError, OSError)):
            setup.create_artifacts(self.destination, TUNNEL, SYNTHETIC_KEY)
        self.assertEqual(key.read_text(), "existing fixture credential")
        self.assertEqual(list(self.destination.iterdir()), [key])

    def test_symlink_ancestor_cannot_redirect_private_artifacts(self):
        setup = self.module()
        real = self.base / "real"
        real.mkdir()
        alias = self.base / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            setup.create_artifacts(alias / "state", TUNNEL, SYNTHETIC_KEY)
        self.assertEqual(list(real.iterdir()), [])

    def test_nonsticky_writable_ancestor_cannot_host_credentials_or_profile(self):
        setup = self.module()
        shared = self.base / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        with self.assertRaises(ValueError):
            setup.create_artifacts(shared / "private", TUNNEL, SYNTHETIC_KEY)
        self.assertEqual(list(shared.iterdir()), [])

    def test_invalid_tunnel_or_key_does_not_create_any_state(self):
        setup = self.module()
        for tunnel, key in (("../tunnel", SYNTHETIC_KEY), (TUNNEL, ""), (TUNNEL, "first\nsecond")):
            with self.subTest(tunnel=tunnel, key_length=len(key)):
                with self.assertRaises(ValueError):
                    setup.create_artifacts(self.destination, tunnel, key)
                self.assertFalse(self.destination.exists())

    def test_noninteractive_cli_refuses_before_consuming_or_echoing_key(self):
        self.module()
        result = subprocess.run(
            [sys.executable, "-m", "dotunnel", "setup", "--directory", str(self.destination)],
            input=SYNTHETIC_KEY + "\n", text=True, capture_output=True, timeout=5,
            cwd=Path(__file__).absolute().parent.parent,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(SYNTHETIC_KEY, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())

    def test_rejected_secret_cli_argument_is_not_relayed_to_error_output(self):
        result = subprocess.run(
            [sys.executable, "-m", "dotunnel", "setup", "--directory", str(self.destination), "--api-key", SYNTHETIC_KEY],
            text=True, capture_output=True, timeout=5,
            cwd=Path(__file__).absolute().parent.parent,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(SYNTHETIC_KEY, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())

    def test_secret_input_warning_aborts_without_returning_key(self):
        setup = self.module()
        import getpass
        import warnings
        from unittest.mock import patch

        def insecure_input(*args, **kwargs):
            warnings.warn("fixture cannot hide input", getpass.GetPassWarning)
            return SYNTHETIC_KEY

        with patch.object(setup.sys.stdin, "isatty", return_value=True), patch.object(setup.sys.stderr, "isatty", return_value=True), patch.object(setup.getpass, "getpass", side_effect=insecure_input):
            with self.assertRaises(ValueError):
                setup.read_key()

    def test_foreground_waits_for_health_file_and_authenticated_poll_not_just_ready(self):
        setup = self.module()
        import json
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer

        observed = []

        class Health(BaseHTTPRequestHandler):
            def do_GET(self):
                status = "unknown" if not observed else "ok"
                observed.append(status)
                details = {"consecutive_failures": 0}
                if status == "ok":
                    details["last_success"] = "fixture-successful-poll"
                body = json.dumps({"live": True, "ready": True, "components": {"control-plane": {"status": status, "details": details}}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Health)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f"http://127.0.0.1:{server.server_port}"
        health_file = self.base / "health-url"

        def publish():
            time.sleep(0.05)
            health_file.write_text(url)

        publisher = threading.Thread(target=publish)
        publisher.start()
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"], start_new_session=True)
        try:
            result = setup._wait_connected(process, self.base / "profile.yaml")
            self.assertEqual(result, url)
            self.assertEqual(observed, ["unknown", "ok"])
        finally:
            process.terminate()
            process.wait(timeout=2)
            publisher.join(timeout=2)
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
