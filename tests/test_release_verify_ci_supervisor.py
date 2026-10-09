import importlib
import importlib.util
import io
import os
import json
import re
import sys
import time
import tempfile
import unittest
from pathlib import Path
from contextlib import ExitStack, redirect_stdout
from unittest.mock import patch


_MODULE_NAME = "tools.release_verify.ci_supervisor"
_PINNED_IMAGE = "docker.io/library/python@sha256:" + ("a" * 64)
_RUN_ID = "0123456789abcdef0123456789abcdef"
_OWNED_NAME = "dotunnel-verify-" + _RUN_ID


class ReleaseVerifyCISupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        original = importlib.import_module(_MODULE_NAME)
        fixture = tempfile.TemporaryDirectory(prefix="dotunnel-supervisor-tests-", dir="/tmp")
        cls.addClassCleanup(fixture.cleanup)
        cls.fixture_root = Path(fixture.name)
        source = cls.fixture_root / "ci_supervisor.py"
        source.write_bytes(Path(original.__file__).read_bytes())
        source.chmod(0o600)
        name = "_dotunnel_supervisor_test_fixture"
        spec = importlib.util.spec_from_file_location(name, source)
        if spec is None or spec.loader is None:
            raise RuntimeError("supervisor fixture loader is unavailable")
        cls.supervisor = importlib.util.module_from_spec(spec)
        sys.modules[name] = cls.supervisor
        cls.addClassCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(cls.supervisor)

    def test_supervisor_source_rejects_writable_ancestor(self):
        unsafe = self.fixture_root / "untrusted"
        unsafe.mkdir(mode=0o700)
        source = unsafe / "ci_supervisor.py"
        source.write_bytes(Path(self.supervisor.__file__).read_bytes())
        source.chmod(0o600)
        unsafe.chmod(0o777)
        with patch.object(self.supervisor, "__file__", str(source)):
            with self.assertRaises(ValueError):
                self.supervisor._source_identity()


    @staticmethod
    def _spec_value(stage="capabilities", **extra):
        value = {"schema": 1, "stage": stage, "run_id": _RUN_ID}
        value.update(extra)
        return value

    @classmethod
    def _raw_spec(cls, stage="capabilities", **extra):
        return json.dumps(
            cls._spec_value(stage, **extra),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")

    def _policy(self, *, image=_PINNED_IMAGE, input_root=None):
        return self.supervisor.Policy(image=image, input_root=input_root)

    def _assert_spec_rejected(self, raw):
        with self.assertRaises(ValueError):
            self.supervisor.parse_spec(raw, self._policy())

    def _assert_policy_rejected(self, **policy_options):
        try:
            policy = self._policy(**policy_options)
            spec = self.supervisor.parse_spec(self._raw_spec(), policy)
            self.supervisor.docker_arguments(spec, policy, _OWNED_NAME)
        except (OSError, ValueError):
            return
        self.fail("unsafe trusted Policy was accepted for Docker arguments")

    @staticmethod
    def _option_values(arguments, option):
        values = []
        for index, argument in enumerate(arguments):
            if argument == option and index + 1 < len(arguments):
                values.append(arguments[index + 1])
            elif argument.startswith(option + "="):
                values.append(argument[len(option) + 1 :])
        return values

    def _one_option(self, arguments, option):
        values = self._option_values(arguments, option)
        self.assertEqual(len(values), 1, f"expected one {option}, got {values!r}")
        return values[0]

    @staticmethod
    def _docker_bytes(value):
        match = re.fullmatch(r"([0-9]+)([a-zA-Z]*)", value.strip())
        if match is None:
            raise AssertionError(f"unrecognized Docker byte limit: {value!r}")
        amount = int(match.group(1))
        suffix = match.group(2).lower()
        multipliers = {
            "": 1,
            "b": 1,
            "k": 1024,
            "kb": 1024,
            "kib": 1024,
            "m": 1024**2,
            "mb": 1024**2,
            "mib": 1024**2,
            "g": 1024**3,
            "gb": 1024**3,
            "gib": 1024**3,
        }
        if suffix not in multipliers:
            raise AssertionError(f"unrecognized Docker byte suffix: {suffix!r}")
        return amount * multipliers[suffix]

    def _run_synthetic_pilot(
        self, *, stage, input_root=None, mutate_input=False, monitor_loss=False,
    ):
        api = self.supervisor
        policy = self._policy(input_root=input_root)
        spec = api.parse_spec(self._raw_spec(stage), policy)
        with tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
            home = Path(temporary)
            docker = home / "synthetic-docker"
            state_path = home / "container-state.json"
            log_path = home / "docker-commands.log"
            effect_path = home / "go-observed"
            top_started = home / "top-started"
            container_id = "b" * 64
            details = {
                "Id": container_id,
                "Name": "/" + _OWNED_NAME,
                "Config": {
                    "Labels": {
                        "dotunnel.verify.run": _RUN_ID,
                        "dotunnel.verify.kind": "release-pilot",
                    },
                    "Image": _PINNED_IMAGE,
                    "Entrypoint": ["python"],
                    "Cmd": ["-I", "-c", api._CONTAINER_DRIVER, stage, _RUN_ID],
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
                    "Tmpfs": {
                        "/tmp": (
                            "rw,noexec,nosuid,nodev,size=268435456,"
                            "uid=65532,gid=65532,mode=1777"
                        ),
                    },
                    "Binds": [],
                    "Devices": [],
                    "DeviceRequests": [],
                    "VolumesFrom": [],
                },
                "Mounts": (
                    ([{
                        "Type": "bind",
                        "Source": str(input_root),
                        "Destination": "/candidate-input",
                        "RW": False,
                    }] if input_root is not None else [])
                    + [{"Type": "tmpfs", "Destination": "/tmp", "RW": True}]
                ),
                "State": {"Running": False},
            }
            state_path.write_text(
                json.dumps({"exists": False, "running": False}),
                encoding="utf-8",
            )
            input_file = str(input_root / "fixture.bin") if input_root else ""
            script = (
                "import json,os,sys,time\n"
                f"STATE_PATH={str(state_path)!r}\n"
                f"LOG_PATH={str(log_path)!r}\n"
                f"EFFECT_PATH={str(effect_path)!r}\n"
                f"TOP_STARTED={str(top_started)!r}\n"
                f"INPUT_FILE={input_file!r}\n"
                f"CONTAINER_ID={container_id!r}\n"
                f"CONTAINER_NAME={_OWNED_NAME!r}\n"
                f"STAGE={stage!r}\n"
                f"MUTATE_INPUT={mutate_input!r}\n"
                f"DETAILS=json.loads({json.dumps(json.dumps(details, separators=(',', ':')))})\n"
                "def load_state():\n"
                "    with open(STATE_PATH, encoding='utf-8') as stream: return json.load(stream)\n"
                "def save_state(value):\n"
                "    with open(STATE_PATH, 'w', encoding='utf-8') as stream: json.dump(value, stream)\n"
                "def log(value):\n"
                "    with open(LOG_PATH, 'a', encoding='utf-8') as stream: stream.write(value+'\\n')\n"
                "args=sys.argv[1:]\n"
                "if args[:2] != ['--host','unix:///var/run/docker.sock']: sys.exit(2)\n"
                "command=args[2:]\n"
                "state=load_state()\n"
                "if command and command[0]=='create':\n"
                "    state.update(exists=True,running=False); save_state(state); log('create')\n"
                "    print(CONTAINER_ID)\n"
                "elif command[:2] == ['container','inspect']:\n"
                "    reference=command[2]\n"
                "    if not state['exists'] or reference not in (CONTAINER_ID,CONTAINER_NAME):\n"
                "        sys.stderr.write('Error: No such object: '+reference+'\\n'); sys.exit(1)\n"
                "    value=dict(DETAILS); value['State']=dict(DETAILS['State'],Running=state['running'])\n"
                "    print(json.dumps([value],separators=(',',':')))\n"
                "elif command[:2] == ['container','start']:\n"
                "    if MUTATE_INPUT:\n"
                "        with open(INPUT_FILE,'r+b') as stream:\n"
                "            stream.seek(0); stream.write(b'changed!'); stream.flush(); os.fsync(stream.fileno())\n"
                "    state['running']=True; state['attach_pid']=os.getpid(); save_state(state); log('start')\n"
                "    ready={'phase':'ready','run_id':"
                + repr(_RUN_ID)
                + ",'ok':True,'root_read_only':True,'tmpfs':True,'tmpfs_bytes':268435456,"
                " 'effective_uid':65532,'cgroup':{'version':2,'memory_max':536870912,"
                " 'pids_max':64,'cpu_quota':50000,'cpu_period':100000,'swap_max':0}}\n"
                "    print(json.dumps(ready,separators=(',',':')),flush=True)\n"
                "    if sys.stdin.readline() != 'GO\\n': sys.exit(3)\n"
                "    open(EFFECT_PATH,'wb').write(b'GO')\n"
                "    log('go')\n"
                "    if STAGE == 'capabilities':\n"
                "        print(json.dumps({'phase':'done','status':'PASS'}),flush=True); sys.exit(0)\n"
                "    for value in ({'phase':'pids','limit_enforced':True},"
                "                  {'phase':'scratch','exhausted':True},"
                "                  {'phase':'tree-ready'}):\n"
                "        print(json.dumps(value,separators=(',',':')),flush=True)\n"
                "    for descriptor, value in ((1,b'x'),(2,b'y')):\n"
                "        for _ in range(16): os.write(descriptor,value*8192)\n"
                "    while True: time.sleep(1)\n"
                "elif command[:2] == ['container','top']:\n"
                "    open(TOP_STARTED,'wb').close(); log('top-start'); time.sleep(0.5)\n"
                "    print('PID PPID')\n"
                "    for _ in range(4): print(str(state.get('attach_pid',0))+' 0')\n"
                "elif command[:2] == ['container','stop']:\n"
                "    state['running']=False; save_state(state); log('stop')\n"
                "elif command[:2] == ['container','rm']:\n"
                "    state.update(exists=False,running=False); save_state(state); log('rm')\n"
                "else:\n"
                "    sys.stderr.write('unexpected synthetic Docker command\\n'); sys.exit(2)\n"
            )
            docker.write_text("#!" + sys.executable + "\n" + script, encoding="utf-8")
            docker.chmod(0o700)
            healthy = {
                "memory_available_bytes": 64 * 1024**3,
                "disk_free_bytes": 64 * 1024**3,
                "docker_root_disk_free_bytes": 64 * 1024**3,
            }
            telemetry_lost = [False]
            top_resource_checks = [0]

            class ReadyWatchdog:
                def poll(self):
                    return None

                def wait(self, timeout):
                    return 0

            def host_resources(*_args):
                if monitor_loss and top_started.exists():
                    top_resource_checks[0] += 1
                    if top_resource_checks[0] >= 2 and not telemetry_lost[0]:
                        telemetry_lost[0] = True
                        return {
                            "memory_available_bytes": 64 * 1024**3,
                            "disk_free_bytes": None,
                            "docker_root_disk_free_bytes": 64 * 1024**3,
                        }
                return healthy

            with ExitStack() as stack:
                for name, value in (
                    ("_private_home", home),
                    ("_docker_binary", (str(docker), None)),
                    ("probe", {
                        "status": "AVAILABLE",
                        "docker": {"dockerrootdir": str(home)},
                    }),
                    ("_image_preflight", (True, None, {})),
                    ("_watchdog_start", ReadyWatchdog()),
                    ("_wait_watchdog_ready", None),
                ):
                    stack.enter_context(
                        patch.object(api, name, return_value=value),
                    )
                stack.enter_context(
                    patch.object(api, "_host_resources", side_effect=host_resources),
                )
                result = api._run_pilot(spec, policy)
            commands = log_path.read_text(encoding="utf-8").splitlines()
            return (
                result, commands, effect_path.exists(), telemetry_lost[0],
                top_resource_checks[0], healthy,
            )


    def test_manifest_revalidates_earlier_file_after_in_place_mutation(self):
        api = self.supervisor
        with tempfile.TemporaryDirectory() as temporary:
            input_root = Path(temporary) / "reviewed-input"
            input_root.mkdir(mode=0o700)
            first = input_root / "a-first.bin"
            later = input_root / "z-later.bin"
            first.write_bytes(b"original")
            later.write_bytes(b"later")
            original_identity = (first.stat().st_dev, first.stat().st_ino)
            real_sha256 = api.hashlib.sha256
            hash_calls = 0

            def mutate_after_first_hash(*args, **kwargs):
                nonlocal hash_calls
                hash_calls += 1
                if hash_calls == 2:
                    with first.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(b"tampered")
                return real_sha256(*args, **kwargs)

            with patch.object(api.hashlib, "sha256", side_effect=mutate_after_first_hash):
                with self.assertRaisesRegex(
                    ValueError,
                    "reviewed input entry changed during manifest validation",
                ):
                    api._input_tree_proof(input_root)

            current = first.stat()
            self.assertEqual((current.st_dev, current.st_ino), original_identity)
            self.assertEqual(first.read_bytes(), b"tampered")

    def test_manifest_enforces_global_entry_bound_after_nested_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            input_root = Path(temporary) / "reviewed-input"
            input_root.mkdir(mode=0o700)
            nested = input_root / "00-nested"
            nested.mkdir(mode=0o700)
            (nested / "child.bin").touch()
            for index in range(self.supervisor._INPUT_MAX_ENTRIES - 1):
                (input_root / f"sibling-{index:04d}.bin").touch()

            with self.assertRaisesRegex(ValueError, "entry bound"):
                self.supervisor._input_tree_proof(input_root)

    def test_in_place_input_mutation_before_go_prevents_effects_and_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as temporary:
            input_root = Path(temporary) / "reviewed-input"
            input_root.mkdir(mode=0o700)
            fixture = input_root / "fixture.bin"
            fixture.write_bytes(b"original")
            info = fixture.stat()
            identity = (info.st_dev, info.st_ino)
            result, commands, effect, _lost, _wait_checks, _healthy = self._run_synthetic_pilot(
                stage="capabilities",
                input_root=input_root,
                mutate_input=True,
            )
            mutated = fixture.stat()
            self.assertEqual((mutated.st_dev, mutated.st_ino), identity)

        self.assertEqual(result["status"], "FAIL", result)
        self.assertEqual(
            result["original_cause"],
            "reviewed-input-content-changed-before-go",
        )
        self.assertFalse(effect, "the synthetic Docker client observed no GO")
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertIn("stop", commands)
        self.assertIn("rm", commands)

    def test_telemetry_loss_during_bounded_docker_child_fails_after_recovery_and_cleans_up(self):
        result, commands, _effect, loss_observed, wait_checks, healthy = self._run_synthetic_pilot(
            stage="hostile-pilot",
            monitor_loss=True,
        )

        self.assertTrue(loss_observed, "telemetry disappeared during synthetic Docker top")
        self.assertGreaterEqual(wait_checks, 2, "loss followed an actual bounded child wait")
        self.assertIn("top-start", commands)
        self.assertEqual(result["status"], "FAIL", result)
        self.assertEqual(result["reason"], "host-resource-telemetry-unavailable")
        self.assertEqual(result["original_cause"], "host-resource-telemetry-unavailable")
        self.assertEqual(result["host_telemetry"]["after"], healthy)
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertIn("stop", commands)
        self.assertIn("rm", commands)


    def test_synthetic_hostile_pilot_completes_tree_probe_and_cleanup(self):
        result, commands, effect, telemetry_lost, _wait_checks, healthy = self._run_synthetic_pilot(
            stage="hostile-pilot",
        )

        self.assertFalse(telemetry_lost)
        self.assertEqual(result["status"], "PASS", result)
        self.assertTrue(effect, "the synthetic Docker client observed GO")
        self.assertEqual(result["host_telemetry"]["after"], healthy)
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertIn("top-start", commands)
        self.assertIn("stop", commands)
        self.assertIn("rm", commands)

    def test_canonical_stages_use_the_fixed_bounded_core_policy(self):
        policy = self._policy()
        spec = self.supervisor.parse_spec(self._raw_spec(), policy)
        arguments = self.supervisor.docker_arguments(spec, policy, _OWNED_NAME)

        self.assertIn("--read-only", arguments)
        self.assertEqual(self._one_option(arguments, "--network").lower(), "none")
        self.assertEqual(self._one_option(arguments, "--cap-drop").upper(), "ALL")
        self.assertTrue(
            any(
                option.lower().startswith("no-new-privileges")
                for option in self._option_values(arguments, "--security-opt")
            )
        )
        user = self._one_option(arguments, "--user").lower()
        self.assertNotIn(user, {"0", "0:0", "root"})

        memory = self._docker_bytes(self._one_option(arguments, "--memory"))
        memory_swap = self._docker_bytes(self._one_option(arguments, "--memory-swap"))
        self.assertEqual(memory, 512 * 1024**2)
        # Docker's memory-swap value is memory plus swap; equality means zero
        # additional swap, the contract's fixed swap limit.
        self.assertEqual(memory_swap, memory)
        self.assertEqual(float(self._one_option(arguments, "--cpus")), 0.5)
        self.assertEqual(int(self._one_option(arguments, "--pids-limit")), 64)
        self.assertEqual(int(self._one_option(arguments, "--stop-timeout")), 2)

        rendered = " ".join(arguments).lower()
        self.assertIn("tmpfs", rendered)
        self.assertRegex(
            rendered,
            r"(?:tmpfs-)?size=(?:268435456|256m(?:i?b)?)",
        )
        self.assertNotIn("--privileged", arguments)
        self.assertFalse(any(arg == "--device" or arg.startswith("--device=") for arg in arguments))
        self.assertFalse(any(arg.lower() == "host" for arg in self._option_values(arguments, "--network")))
        self.assertNotIn("docker.sock", rendered)
        self.assertFalse(self._option_values(arguments, "--volume"))
        self.assertFalse(self._option_values(arguments, "-v"))
        self.assertFalse(
            any("type=bind" in value.lower() for value in self._option_values(arguments, "--mount")),
            "Policy.input_root=None must not create a host bind mount",
        )

    def test_trusted_input_root_is_the_only_read_only_host_bind(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            input_root = base / "reviewed-input"
            input_root.mkdir()
            policy = self._policy(input_root=input_root)
            spec = self.supervisor.parse_spec(self._raw_spec(), policy)
            arguments = self.supervisor.docker_arguments(spec, policy, _OWNED_NAME)

            mounts = []
            for option in ("--mount", "--volume", "-v"):
                mounts.extend(self._option_values(arguments, option))
            normalized = [value.lower() for value in mounts]
            host_mounts = [
                value
                for value in normalized
                if "type=bind" in value
                or "source=" in value
                or "src=" in value
                or value.startswith("/")
            ]
            self.assertEqual(len(host_mounts), 1, "only the reviewed input root may be host-bound")
            mount = host_mounts[0]
            fields = {
                key: value
                for part in mount.split(",")
                if "=" in part
                for key, value in (part.split("=", 1),)
            }
            source = fields.get("source", fields.get("src"))
            if source is None:
                source = mount.split(":", 1)[0]
            self.assertEqual(source, str(input_root).lower())
            self.assertTrue(
                any(part in {"readonly", "readonly=true"} for part in mount.split(","))
                or any(part == "ro" for part in mount.split(":")),
                "the reviewed input root must be read-only",
            )
            self.assertFalse(any("docker.sock" in value for value in normalized))

    def test_unknown_and_privileged_spec_fields_are_rejected(self):
        attempts = {
            "surprise": True,
            "command": ["sh", "-c", "id"],
            "image": "docker.io/library/python:latest",
            "mount": "/:/host",
            "mounts": [{"source": "/", "target": "/host"}],
            "socket": "/var/run/docker.sock",
            "device": "/dev/kvm",
            "network": "host",
            "privileged": True,
            "resources": {"memory_bytes": 512 * 1024**2 + 1},
            "limits": {"cpu_percent": 0.5001},
            "memory_bytes": True,
            "wall_seconds": 181,
        }
        for field, value in attempts.items():
            with self.subTest(field=field):
                self._assert_spec_rejected(
                    self._raw_spec(**{field: value}),
                )

    def test_duplicate_json_fields_are_rejected_even_when_values_match(self):
        raw = (
            b'{"schema":1,"schema":1,"stage":"capabilities",'
            b'"run_id":"0123456789abcdef0123456789abcdef"}'
        )
        self._assert_spec_rejected(raw)

    def test_boolean_schema_and_noncanonical_run_ids_are_rejected(self):
        self._assert_spec_rejected(self._raw_spec(schema=True))
        self._assert_spec_rejected(self._raw_spec(run_id="01234567-89ab-cdef-0123-456789abcdef"))
        self._assert_spec_rejected(self._raw_spec(run_id="not-a-uuid-hex"))

    def test_only_exact_official_immutable_image_policy_is_accepted(self):
        spec = self.supervisor.parse_spec(self._raw_spec(), self._policy())
        denied_images = (
            "docker.io/library/python:3.12",
            "python:latest",
            "registry.example/python@sha256:" + ("a" * 64),
            "docker.io/library/python@sha256:" + ("A" * 64),
            "docker.io/library/python@sha256:" + ("a" * 63),
        )
        for image in denied_images:
            with self.subTest(image=image):
                self._assert_policy_rejected(image=image)
                with self.assertRaises(ValueError):
                    bad_policy = self._policy(image=image)
                    self.supervisor.docker_arguments(spec, bad_policy, _OWNED_NAME)

    def test_input_root_parent_traversal_symlink_and_file_collision_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            safe_root = base / "safe-root"
            safe_root.mkdir()
            nested = safe_root / "nested"
            nested.mkdir()
            traversal_root = nested / ".."

            outside = base / "outside"
            outside.mkdir()
            symlink_root = base / "input-link"
            symlink_root.symlink_to(outside, target_is_directory=True)

            file_collision = base / "input-root-collision"
            file_collision.write_text("not a directory", encoding="utf-8")

            for label, root in (
                ("parent traversal", traversal_root),
                ("symlink", symlink_root),
                ("file/directory collision", file_collision),
            ):
                with self.subTest(input_root=label):
                    self._assert_policy_rejected(input_root=root)

    def test_foreign_container_identity_cannot_be_cleaned_up(self):
        expected_id = "b" * 64
        owned = {
            "Id": expected_id,
            "Name": "/" + _OWNED_NAME,
            "Config": {"Labels": {
                "dotunnel.verify.run": _RUN_ID,
                "dotunnel.verify.kind": "release-pilot",
            }},
        }
        self.assertTrue(self.supervisor.container_is_owned(
            owned, _RUN_ID, _OWNED_NAME, expected_id,
        ))
        for field, value in (
            ("Id", "c" * 64),
            ("Name", "/another-project"),
            ("Config", {"Labels": {"dotunnel.verify.run": "d" * 32}}),
        ):
            foreign = {**owned, field: value}
            with self.subTest(field=field):
                self.assertFalse(self.supervisor.container_is_owned(
                    foreign, _RUN_ID, _OWNED_NAME, expected_id,
                ))

    def test_effective_inspect_accepts_cpus_nano_field_not_quota_defaults(self):
        api = self.supervisor
        policy = self._policy()
        spec = api.parse_spec(self._raw_spec(), policy)
        details = {
            "Id": "b" * 64, "Name": "/" + _OWNED_NAME,
            "Config": {
                "Labels": {"dotunnel.verify.run": _RUN_ID, "dotunnel.verify.kind": "release-pilot"},
                "Image": _PINNED_IMAGE, "Entrypoint": ["python"],
                "Cmd": ["-I", "-c", api._CONTAINER_DRIVER, "capabilities", _RUN_ID],
                "User": "65532:65532", "OpenStdin": True, "Tty": False,
            },
            "HostConfig": {
                "ReadonlyRootfs": True, "NetworkMode": "none", "Privileged": False,
                "CapDrop": ["ALL"], "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 536870912, "MemorySwap": 536870912,
                "NanoCpus": 500000000, "CpuQuota": 0, "CpuPeriod": 0,
                "PidsLimit": 64,
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=268435456,uid=65532,gid=65532,mode=1777"},
            },
            "Mounts": [],
        }
        accepted, reasons = api._inspect_limits(details, spec, policy, _OWNED_NAME)
        self.assertTrue(accepted, reasons)
        details["HostConfig"]["NanoCpus"] = 1000000000
        accepted, reasons = api._inspect_limits(details, spec, policy, _OWNED_NAME)
        self.assertFalse(accepted)
        self.assertIn("docker-cpu-limit-mismatch", reasons)

    def test_exited_leader_cannot_extend_pipe_drain_deadline(self):
        script = (
            "import os,time\n"
            "if os.fork(): os._exit(0)\n"
            "os.setsid()\n"
            "time.sleep(3)\n"
            "os._exit(0)\n"
        )
        result = self.supervisor._bounded_command(
            [sys.executable, "-I", "-c", script], timeout=0.1,
        )
        self.assertTrue(result.timed_out)
        self.assertLess(result.elapsed_seconds, 2.0,
                        "an inherited pipe outlived the fixed drain deadline")

    def test_completion_proof_is_drained_after_actual_client_exit(self):
        session = self.supervisor._AttachedSession.start(
            [sys.executable, "-I", "-c", 'print("{\\\"phase\\\":\\\"complete\\\",\\\"ok\\\":true}", flush=True)'],
            Path.home(),
        )
        try:
            session.process.wait(timeout=3)
            def observe_host():
                self.supervisor._host_resources(Path.home(), Path.home())

            event = self.supervisor._wait_event(
                session, "complete", time.monotonic() + 2,
                resource_check=observe_host,
            )
            self.assertEqual(event, {"phase": "complete", "ok": True})
        finally:
            if session.process.poll() is None:
                session.process.kill()
                session.process.wait(timeout=2)
            session.close()

    def test_unknown_create_retains_real_intent_despite_absent_inspections(self):
        api = self.supervisor
        with tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
            root = Path(temporary) / "owned-control"
            root.mkdir(mode=0o700)
            ledger = {
                "schema": 1, "run_id": _RUN_ID, "name": _OWNED_NAME,
                "state": "create-starting", "container_id": None, "attempted": True,
                "cleanup_confirmed": False, "cleanup_reason": "create-pending",
                "docker_pid": 123, "docker_start_ticks": 456,
                "status": "BLOCKED", "source_sha256": "e" * 64,
            }
            api._ledger_write(root, ledger)
            control = {
                "docker_path": "/synthetic/docker", "run_id": _RUN_ID,
                "name": _OWNED_NAME, "deadline_ns": time.monotonic_ns() - 1,
                "controller_pid": 789, "controller_start_ticks": 123,
                "owner_uid": os.getuid(),
            }
            # Synthetic daemon boundary: a dead client and current NotFound do
            # not cancel the daemon's potentially still-pending create request.
            with ExitStack() as stack:
                for name, value in (
                    ("_control_read", control), ("_source_matches", True),
                    ("_secure_executable", True), ("_current_process_matches", False),
                    ("_kill_verified_process", True), ("_inspect_expected", None),
                    ("_docker_reference_absent", True),
                ):
                    stack.enter_context(patch.object(api, name, return_value=value))
                stack.enter_context(redirect_stdout(io.StringIO()))
                exit_status = api._watchdog(root, "e" * 64)
            self.assertEqual(exit_status, 74)
            self.assertTrue(root.is_dir(), "ambiguous create intent was erased")
            remaining = api._ledger_read(root)
            self.assertTrue(remaining["attempted"])
            self.assertFalse(remaining["cleanup_confirmed"])
            self.assertEqual(remaining["state"], "watchdog-unresolved")

    def test_controller_reports_unknown_create_as_failure_and_retains_intent(self):
        api = self.supervisor
        policy = self._policy()
        spec = api.parse_spec(self._raw_spec(), policy)
        class ExitedWatchdog:
            def poll(self):
                return None

            def wait(self, timeout):
                return 74

        with tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
            home = Path(temporary)
            with ExitStack() as stack:
                for name, value in (
                    ("_private_home", home),
                    ("_docker_binary", ("/synthetic/docker", None)),
                    ("probe", {"status": "AVAILABLE", "docker": {"dockerrootdir": str(home)}}),
                    ("_image_preflight", (True, None, {})),
                    ("_host_resources", {
                        "memory_available_bytes": 64 * 1024**3,
                        "disk_free_bytes": 64 * 1024**3,
                        "docker_root_disk_free_bytes": 64 * 1024**3,
                    }),
                    ("_watchdog_start", ExitedWatchdog()),
                    ("_wait_watchdog_ready", None),
                    ("_docker_reference_absent", True),
                    ("_inspect_expected", None),
                    ("_docker_command", api._CommandResult(1, b"", b"deadline", True, False, False, 0.01)),
                ):
                    stack.enter_context(patch.object(api, name, return_value=value))
                result = api._run_pilot(spec, policy)
            root = home / ".cache" / "dotunnel-release-verifier" / _RUN_ID
            self.assertEqual(result["status"], "FAIL", result)
            self.assertEqual(api._exit_for_status(result["status"]), 1)
            self.assertFalse(result["cleanup_confirmed"])
            self.assertEqual(result.get("original_cause"), "docker-create-outcome-ambiguous")
            self.assertIn("owned-container-cleanup-unconfirmed", result.get("cleanup_failures", []))
            self.assertIn("independent-watchdog-failed", result.get("cleanup_failures", []))
            self.assertTrue(root.is_dir(), "unresolved daemon intent must survive")
            ledger = api._ledger_read(root)
            self.assertTrue(ledger["attempted"])
            self.assertFalse(ledger["cleanup_confirmed"])

    def test_missing_host_accounting_refuses_actual_create_submission(self):
        api = self.supervisor
        policy = self._policy()
        spec = api.parse_spec(self._raw_spec(), policy)

        class ReadyWatchdog:
            def poll(self):
                return None

            def wait(self, timeout):
                return 0

        # Synthetic daemon boundary, not kernel proof. The executable's marker
        # independently witnesses whether the controller submitted creation.
        for missing in ("memory_available_bytes", "disk_free_bytes",
                        "docker_root_disk_free_bytes"):
            with self.subTest(counter=missing), tempfile.TemporaryDirectory(dir=self.fixture_root) as temporary:
                home = Path(temporary)
                marker = home / "create-submitted"
                docker = home / "synthetic-docker"
                docker.write_text(
                    "#!" + sys.executable + "\n"
                    "import pathlib,sys\n"
                    "if sys.argv[1:4] == ['--host','unix:///var/run/docker.sock','create']:\n"
                    "    pathlib.Path(" + repr(str(marker)) + ").write_bytes(b'submitted')\n"
                    "sys.exit(1)\n",
                    encoding="utf-8",
                )
                docker.chmod(0o700)
                counters = {
                    "memory_available_bytes": 64 * 1024**3,
                    "disk_free_bytes": 64 * 1024**3,
                    "docker_root_disk_free_bytes": 64 * 1024**3,
                }
                counters[missing] = None
                with ExitStack() as stack:
                    for name, value in (
                        ("_private_home", home),
                        ("_docker_binary", (str(docker), None)),
                        ("probe", {"status": "AVAILABLE", "docker": {"dockerrootdir": str(home)}}),
                        ("_image_preflight", (True, None, {})),
                        ("_watchdog_start", ReadyWatchdog()),
                        ("_wait_watchdog_ready", None),
                        ("_docker_reference_absent", True),
                        ("_inspect_expected", None),
                        ("_host_resources", counters),
                    ):
                        stack.enter_context(patch.object(api, name, return_value=value))
                    result = api._run_pilot(spec, policy)
                self.assertFalse(
                    marker.exists(),
                    "Missing host accounting must prevent a real create submission",
                )
                self.assertEqual(result["status"], "BLOCKED", result)
                self.assertEqual(result["reason"], "host-resource-telemetry-unavailable")
                self.assertTrue(result["cleanup_confirmed"], result)

if __name__ == "__main__":
    unittest.main()
