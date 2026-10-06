import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


INSTALLER = Path(__file__).resolve().parent.parent / "install.sh"
WHEEL_PINS = dict(
    line.split("=", 1) for line in INSTALLER.read_text(encoding="utf-8").splitlines()
    if line.startswith(("WHEEL_URL=", "WHEEL_BYTES="))
)
PRODUCTION_WHEEL_URL = shlex.split(WHEEL_PINS["WHEEL_URL"])[0]
WHEEL_BYTES = int(WHEEL_PINS["WHEEL_BYTES"])
WHEEL_PATH = "/fixture.whl"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.fixture_dir = self.base / "fixtures"
        self.fixture_dir.mkdir()
        self.bin_dir = self.base / "bin"
        self.bin_dir.mkdir()
        self.marker = self.base / "venv-or-pip-started"
        python3 = shutil.which("python3")
        if not python3:
            self.skipTest("python3 is unavailable for installer subprocesses")
        wrapper = self.bin_dir / "python3"
        wrapper.write_text(
            "#!/bin/sh\n"
            "previous=\n"
            "for argument do\n"
            "  case \"$previous:$argument\" in\n"
            "    -m:venv|-m:pip) : > \"$DOTUNNEL_TEST_MARKER\" ;;\n"
            "  esac\n"
            "  previous=$argument\n"
            "done\n"
            f"exec {shlex.quote(python3)} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        self.environment = os.environ.copy()
        self.environment["HOME"] = str(self.home)
        self.environment["PATH"] = str(self.bin_dir) + os.pathsep + self.environment.get("PATH", os.defpath)
        self.environment["DOTUNNEL_TEST_MARKER"] = str(self.marker)
        self.environment["NO_PROXY"] = "127.0.0.1,localhost"
        self.environment["no_proxy"] = "127.0.0.1,localhost"

    def serve(self, payload):
        class WheelHandler(BaseHTTPRequestHandler):
            def do_GET(handler):
                if handler.path != WHEEL_PATH:
                    handler.send_error(404)
                    return
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(payload)))
                handler.end_headers()
                handler.wfile.write(payload)

            def log_message(handler, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), WheelHandler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}{WHEEL_PATH}"

    def script_copy(self, wheel_url):
        source = INSTALLER.read_text(encoding="utf-8")
        rewritten = source.replace(PRODUCTION_WHEEL_URL, wheel_url, 1)
        if rewritten == source:
            raise AssertionError("Could not point disposable installer copy at the local wheel fixture")
        path = self.fixture_dir / "install.sh"
        path.write_text(rewritten, encoding="utf-8")
        path.chmod(0o755)
        return path

    def run_installer(self, *, wheel_url=None, home=None, arguments=()):
        if wheel_url is None:
            wheel_url = self.serve(b"invalid fixture wheel")
        script = self.script_copy(wheel_url)
        environment = self.environment.copy()
        if home is not None:
            environment["HOME"] = str(home)
        return subprocess.run(
            [str(script), *arguments],
            cwd=self.workspace,
            env=environment,
            text=True,
            capture_output=True,
            timeout=20,
        )


    @unittest.skipIf(os.geteuid() == 0, "installer security scenarios require a non-root user")
    def test_tampered_wheel_is_rejected_before_venv_or_pip(self):
        result = self.run_installer(wheel_url=self.serve(b"x" * WHEEL_BYTES))

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.home / ".local").exists())
        self.assertFalse((self.workspace / Path(PRODUCTION_WHEEL_URL).name).exists())

    @unittest.skipIf(os.geteuid() == 0, "installer security scenarios require a non-root user")
    def test_existing_install_directory_and_state_are_preserved(self):
        existing = self.home / ".local/share/dotunnel/venv"
        existing.mkdir(parents=True)
        marker = existing / "user-state"
        marker.write_text("preserve this installation\n", encoding="utf-8")

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve this installation\n")
        self.assertFalse((self.home / ".local/bin/dotunnel").exists())
        self.assertFalse(self.marker.exists())

    @unittest.skipIf(os.geteuid() == 0, "installer security scenarios require a non-root user")
    def test_existing_launcher_is_not_overwritten(self):
        launcher = self.home / ".local/bin/dotunnel"
        launcher.parent.mkdir(parents=True)
        launcher.write_text("unrelated command\n", encoding="utf-8")

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(launcher.read_text(encoding="utf-8"), "unrelated command\n")
        self.assertFalse((self.home / ".local/share/dotunnel/venv").exists())
        self.assertFalse(self.marker.exists())

    @unittest.skipIf(os.geteuid() == 0, "installer security scenarios require a non-root user")
    def test_symlinked_install_parent_cannot_escape_home(self):
        outside = self.base / "outside"
        outside.mkdir()
        local = self.home / ".local"
        local.symlink_to(outside, target_is_directory=True)

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse(self.marker.exists())

    @unittest.skipIf(os.geteuid() == 0, "installer security scenarios require a non-root user")
    def test_shared_writable_install_parent_is_rejected(self):
        local = self.home / ".local"
        local.mkdir(mode=0o777)
        local.chmod(0o777)

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(local.iterdir()), [])
        self.assertFalse(self.marker.exists())

    @unittest.skipUnless(os.geteuid() == 0, "root refusal is exercised when the suite runs as root")
    def test_root_installation_is_refused_without_creating_state(self):
        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / ".local").exists())
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
