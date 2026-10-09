import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


_MODULE_NAME = "tools.release_verify.ci_supervisor"
_RUN_ID = "c0ffee1234567890c0ffee1234567890"
_CONTAINER_ID = "b" * 64


class ReleaseVerifyCIMonitoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original = importlib.import_module(_MODULE_NAME)
        fixture = tempfile.TemporaryDirectory(prefix="dotunnel-monitoring-tests-", dir="/tmp")
        cls.addClassCleanup(fixture.cleanup)
        cls.fixture_root = Path(fixture.name)
        source = cls.fixture_root / "ci_supervisor.py"
        source.write_bytes(Path(original.__file__).read_bytes())
        source.chmod(0o600)
        spec = importlib.util.spec_from_file_location("_dotunnel_monitoring_fixture", source)
        if spec is None or spec.loader is None:
            raise RuntimeError("supervisor fixture loader is unavailable")
        cls.api = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.api
        cls.addClassCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(cls.api)
        cls.python = Path("/usr/bin/python3").resolve(strict=True)
        if not cls.api._secure_executable(str(cls.python)):
            raise RuntimeError("trusted system watchdog Python is unavailable")
        info = cls.python.stat()
        cls.python_identity = (cls.python, info.st_dev, info.st_ino)

    def _pilot(self, stage="capabilities"):
        policy = self.api.Policy(image=self.api._DEFAULT_IMAGE)
        spec = self.api._spec_from_cli(stage, _RUN_ID, policy)
        return spec, policy

    def _docker_fixture(self, home, *, stop_delay=0.35):
        api = self.api
        state_path = home / "container-state.json"
        log_path = home / "docker.log"
        image_started = home / "image-inspect-started"
        docker = home / "synthetic-docker"
        details = {
            "Id": _CONTAINER_ID,
            "Name": "/dotunnel-verify-" + _RUN_ID,
            "Config": {
                "Labels": {
                    "dotunnel.verify.run": _RUN_ID,
                    "dotunnel.verify.kind": "release-pilot",
                },
                "Image": api._DEFAULT_IMAGE,
                "Entrypoint": ["python"],
                "Cmd": ["-I", "-c", api._CONTAINER_DRIVER, "capabilities", _RUN_ID],
                "Volumes": None,
                "User": "65532:65532",
                "OpenStdin": True,
                "Tty": False,
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "NetworkMode": "none",
                "Privileged": False,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 512 * 1024**2,
                "MemorySwap": 512 * 1024**2,
                "NanoCpus": 500000000,
                "CpuQuota": 0,
                "CpuPeriod": 0,
                "PidsLimit": 64,
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=268435456,uid=65532,gid=65532,mode=1777"},
                "Binds": [],
                "Devices": [],
                "DeviceRequests": [],
                "VolumesFrom": [],
            },
            "Mounts": [{"Type": "tmpfs", "Destination": "/tmp", "RW": True}],
            "State": {"Running": False},
        }
        state_path.write_text(json.dumps({"exists": False, "running": False}), encoding="utf-8")
        script = (
            "import json,sys,time\n"
            f"STATE={str(state_path)!r}\nLOG={str(log_path)!r}\n"
            f"IMAGE_STARTED={str(image_started)!r}\n"
            f"CID={_CONTAINER_ID!r}\nNAME={('dotunnel-verify-' + _RUN_ID)!r}\n"
            f"IMAGE={api._DEFAULT_IMAGE!r}\nSTOP_DELAY={stop_delay!r}\n"
            f"DETAILS=json.loads({json.dumps(json.dumps(details, separators=(',', ':')))})\n"
            "def load():\n    with open(STATE,encoding='utf-8') as f: return json.load(f)\n"
            "def save(s):\n    with open(STATE,'w',encoding='utf-8') as f: json.dump(s,f)\n"
            "def log(s):\n    with open(LOG,'a',encoding='utf-8') as f: f.write(s+'\\n')\n"
            "args=sys.argv[1:]\n"
            "if args[:2] != ['--host','unix:///var/run/docker.sock']: sys.exit(2)\n"
            "cmd=args[2:]\nstate=load()\n"
            "if cmd[:2] == ['image','inspect']:\n"
            "    open(IMAGE_STARTED,'wb').close(); log('image-inspect'); time.sleep(0.35)\n"
            "    print(json.dumps([{'Os':'linux','Architecture':'amd64','RepoDigests':[IMAGE]}]))\n"
            "elif cmd and cmd[0] == 'create':\n"
            "    state.update(exists=True,running=False); save(state); log('create'); print(CID)\n"
            "elif cmd[:2] == ['container','inspect']:\n"
            "    ref=cmd[2]\n"
            "    if not state['exists'] or ref not in (CID,NAME):\n"
            "        sys.stderr.write('Error: No such object: '+ref+'\\n'); sys.exit(1)\n"
            "    value=json.loads(json.dumps(DETAILS)); value['State']={'Running':state['running']}\n"
            "    print(json.dumps([value],separators=(',',':')))\n"
            "elif cmd[:2] == ['container','stop']:\n"
            "    log('stop-start'); time.sleep(STOP_DELAY); state['running']=False; save(state); log('stop')\n"
            "elif cmd[:2] == ['container','kill']:\n"
            "    state['running']=False; save(state); log('kill')\n"
            "elif cmd[:2] == ['container','rm']:\n"
            "    state.update(exists=False,running=False); save(state); log('rm')\n"
            "else:\n    sys.stderr.write('unexpected synthetic Docker command\\n'); sys.exit(2)\n"
        )
        docker.write_text("#!" + str(self.python) + "\n" + script, encoding="utf-8")
        docker.chmod(0o700)
        return docker, state_path, log_path, image_started

    def _patch_preflight(self, stack, home, docker):
        api = self.api
        stack.enter_context(patch.object(api, "_private_home", return_value=home))
        stack.enter_context(patch.object(api, "_docker_binary", return_value=(str(docker), None)))
        stack.enter_context(patch.object(
            api, "probe",
            return_value={"status": "AVAILABLE", "docker": {"dockerrootdir": str(home)}},
        ))

    @staticmethod
    def _healthy():
        return {
            "memory_available_bytes": 64 * 1024**3,
            "disk_free_bytes": 64 * 1024**3,
            "docker_root_disk_free_bytes": 64 * 1024**3,
        }

    def test_image_preflight_latches_loss_after_wait_and_never_submits_create(self):
        api = self.api
        spec, policy = self._pilot()
        with tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
            home = Path(temporary)
            docker, _state, log_path, image_started = self._docker_fixture(home)
            healthy = self._healthy()
            missing = dict(healthy, disk_free_bytes=None)
            samples = [0]

            def host_resources(*_args):
                if image_started.exists():
                    samples[0] += 1
                    if samples[0] == 2:
                        return missing
                return healthy

            with ExitStack() as stack:
                self._patch_preflight(stack, home, docker)
                stack.enter_context(patch.object(api, "_host_resources", side_effect=host_resources))
                result = api._run_pilot(spec, policy)

            commands = log_path.read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(samples[0], 2, "telemetry loss followed a bounded image-inspect wait")
            self.assertIn("image-inspect", commands)
            self.assertNotIn("create", commands)
            self.assertEqual(result["status"], "BLOCKED", result)
            self.assertEqual(result["reason"], "host-resource-telemetry-unavailable")
            self.assertEqual(result["original_cause"], "host-resource-telemetry-unavailable")
            self.assertEqual(result["host_telemetry"]["after"], healthy)
            self.assertTrue(result["cleanup_confirmed"], result)

    def test_watchdog_readiness_loss_is_latched_through_recovery_and_exit_wait(self):
        api = self.api
        spec, policy = self._pilot()
        with tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
            home = Path(temporary)
            docker, _state, log_path, _image_started = self._docker_fixture(home)
            healthy = self._healthy()
            missing = dict(healthy, docker_root_disk_free_bytes=None)
            watchdog_started = [False]
            readiness_samples = [0]

            def host_resources(*_args):
                if watchdog_started[0]:
                    readiness_samples[0] += 1
                    if readiness_samples[0] == 2:
                        return missing
                return healthy

            def start_delayed_watchdog(*_args):
                watchdog_started[0] = True
                code = (
                    "import sys,time\n"
                    "time.sleep(.25)\n"
                    "try:\n"
                    " sys.stdout.write('READY\\n')\n"
                    " sys.stdout.flush()\n"
                    "except BrokenPipeError:\n"
                    " pass\n"
                    "time.sleep(.2)\n"
                )
                return subprocess.Popen(
                    [str(self.python), "-c", code],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    cwd="/",
                    env=api._safe_env(home),
                )

            with ExitStack() as stack:
                self._patch_preflight(stack, home, docker)
                stack.enter_context(patch.object(api, "_host_resources", side_effect=host_resources))
                stack.enter_context(patch.object(api, "_python_identity", return_value=self.python_identity))
                stack.enter_context(patch.object(api, "_watchdog_start", side_effect=start_delayed_watchdog))
                result = api._run_pilot(spec, policy)

            commands = log_path.read_text(encoding="utf-8").splitlines()
            root = home / ".cache" / "dotunnel-release-verifier" / _RUN_ID
            self.assertGreaterEqual(readiness_samples[0], 2)
            self.assertNotIn("create", commands)
            self.assertEqual(result["status"], "BLOCKED", result)
            self.assertEqual(result["reason"], "host-resource-telemetry-unavailable")
            self.assertEqual(result["original_cause"], "host-resource-telemetry-unavailable")
            self.assertEqual(result["host_telemetry"]["after"], healthy)
            self.assertEqual(result["watchdog_exit"], 0, result)
            self.assertTrue(result["cleanup_confirmed"], result)
            self.assertFalse(root.exists())

    def test_transient_loss_during_delayed_owned_cleanup_fails_but_removal_finishes(self):
        api = self.api
        spec, policy = self._pilot()
        with tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
            home = Path(temporary)
            docker, state_path, log_path, _image_started = self._docker_fixture(home, stop_delay=0.45)
            healthy = self._healthy()
            missing = dict(healthy, memory_available_bytes=None)
            cleanup_started = [False]
            cleanup_samples = [0]
            watchdog_wait_samples = [0]

            class ReadyWatchdog:
                def __init__(self):
                    read_fd, write_fd = os.pipe()
                    self.stdout = os.fdopen(read_fd, "rb", buffering=0)
                    os.write(write_fd, b"READY\n")
                    os.close(write_fd)
                    self.wait_started = None
                    self.exit_code = None

                def poll(self):
                    if (self.wait_started is not None
                            and time.monotonic() - self.wait_started >= 0.18):
                        self.exit_code = 0
                    return self.exit_code

                def wait(self, timeout):
                    if self.wait_started is None:
                        self.wait_started = time.monotonic()
                    remaining = 0.18 - (time.monotonic() - self.wait_started)
                    if remaining <= 0:
                        self.exit_code = 0
                        return 0
                    time.sleep(min(timeout, remaining))
                    if remaining > timeout:
                        raise subprocess.TimeoutExpired("synthetic-watchdog", timeout)
                    self.exit_code = 0
                    return 0

            watchdog = ReadyWatchdog()

            class AttachProcess:
                def __init__(self):
                    self.go_sent = False
                    self.polls_after_go = 0

                def poll(self):
                    if not self.go_sent:
                        return None
                    self.polls_after_go += 1
                    return 0 if self.polls_after_go >= 2 else None

                def wait(self, timeout):
                    return 0

            class EmptySelector:
                @staticmethod
                def get_map():
                    return {}

            class SyntheticSession:
                def __init__(self):
                    self.process = AttachProcess()
                    self.selector = EmptySelector()
                    self.outputs = {"stdout": bytearray(), "stderr": bytearray()}
                    self.truncated = {"stdout": False, "stderr": False}
                    self.events = {
                        "ready": {
                            "phase": "ready", "run_id": _RUN_ID, "ok": True,
                            "root_read_only": True, "tmpfs": True,
                            "tmpfs_bytes": 268435456, "effective_uid": 65532,
                            "cgroup": {
                                "version": 2, "memory_max": 512 * 1024**2,
                                "pids_max": 64, "cpu_quota": 50000,
                                "cpu_period": 100000, "swap_max": 0,
                            },
                        },
                        "done": {"phase": "done", "status": "PASS"},
                    }

                def pop_event(self, phase):
                    return self.events.pop(phase, None)

                def send_go(self):
                    self.process.go_sent = True

                @staticmethod
                def pump(_timeout, *, resource_check):
                    resource_check()
                    return False

                @staticmethod
                def close():
                    return None

            session = SyntheticSession()

            def host_resources(*_args):
                if watchdog.wait_started is not None:
                    watchdog_wait_samples[0] += 1
                if cleanup_started[0]:
                    cleanup_samples[0] += 1
                    if cleanup_samples[0] == 2:
                        return missing
                return healthy

            real_docker_command = api._docker_command

            def observed_docker_command(docker_path, arguments, **kwargs):
                if arguments[:2] == ["container", "stop"]:
                    cleanup_started[0] = True
                return real_docker_command(docker_path, arguments, **kwargs)

            def start_attach(*_args, **_kwargs):
                state = json.loads(state_path.read_text(encoding="utf-8"))
                state["running"] = True
                state_path.write_text(json.dumps(state), encoding="utf-8")
                return session

            with ExitStack() as stack:
                self._patch_preflight(stack, home, docker)
                stack.enter_context(patch.object(api, "_host_resources", side_effect=host_resources))
                stack.enter_context(patch.object(api, "_python_identity", return_value=self.python_identity))
                stack.enter_context(patch.object(api, "_watchdog_start", return_value=watchdog))
                stack.enter_context(patch.object(api, "_docker_command", side_effect=observed_docker_command))
                stack.enter_context(patch.object(api._AttachedSession, "start", side_effect=start_attach))
                result = api._run_pilot(spec, policy)

            commands = log_path.read_text(encoding="utf-8").splitlines()
            root = home / ".cache" / "dotunnel-release-verifier" / _RUN_ID
            self.assertIn("stop", commands)
            self.assertIn("rm", commands)
            self.assertGreaterEqual(cleanup_samples[0], 3, "telemetry recovered while cleanup continued")
            self.assertGreaterEqual(watchdog_wait_samples[0], 1, "watchdog exit wait sampled host resources")
            self.assertEqual(result["status"], "FAIL", result)
            self.assertEqual(result["reason"], "host-resource-telemetry-unavailable")
            self.assertEqual(result["original_cause"], "host-resource-telemetry-unavailable")
            self.assertIn("host-resource-telemetry-unavailable", result["cleanup_failures"])
            self.assertEqual(result["host_telemetry"]["after"], healthy)
            self.assertTrue(result["cleanup_confirmed"], result)
            self.assertIsInstance(result["cleanup_failures"], list)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
