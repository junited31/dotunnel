"""Behavioral regressions for publisher identity and output boundaries.

Authority fixtures use real Linux process/fd observations but synthetic root
credentials/capabilities; they do not claim to exercise a privileged publisher.
"""
from __future__ import annotations

import base64
import json
import os
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from tools.release_verify import runner_artifact
from tools.release_verify import runner_runtime


_RUN_BACKEND_ID = "ce7f54c7-61c7-4aae-887f-30da475f5f1a"
_JOB_BACKEND_ID = "ca395085-040a-526b-2ce8-bdc85f692774"
_RUNTIME_TOKEN = "synthetic-runtime-token-for-publisher-regressions"
_ARTIFACT_DIGEST = "a" * 64
_ARTIFACT_URL = (
    "https://github.com/junited31/dotunnel/actions/runs/987654321/artifacts/67890"
)


def _jwt(claims: object) -> str:
    header = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode("ascii")
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    return f"{header}.{payload}.synthetic-signature"


def _output_record(name: str, value: str, delimiter: str) -> bytes:
    return f"{name}<<{delimiter}\n{value}\n{delimiter}\n".encode("ascii")


_PUBLISHER_OUTPUT = b"".join((
    _output_record(
        "artifact-id", "67890",
        "ghadelimiter_01234567-89ab-cdef-0123-456789abcdef",
    ),
    _output_record(
        "artifact-digest", _ARTIFACT_DIGEST,
        "ghadelimiter_11234567-89ab-cdef-0123-456789abcdef",
    ),
    _output_record(
        "artifact-url", _ARTIFACT_URL,
        "ghadelimiter_21234567-89ab-cdef-0123-456789abcdef",
    ),
))


def _synthetic_root_authority(identity: runner_runtime.ProcessIdentity):
    """Keep real PID/birth/executable/cgroup/fds; synthesize privileged fields only."""
    return replace(
        identity,
        uid=0,
        gid=0,
        cap_eff="0000000000000000",
        cap_prm="0000000000000000",
        cap_bnd="0000000000000000",
        cap_amb="0000000000000000",
        no_new_privs=1,
    )


def _stop_child(child: subprocess.Popen[bytes]) -> None:
    if child.poll() is None:
        try:
            if child.stdin is not None:
                child.stdin.write(b"x")
                child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
    if child.stdin is not None:
        child.stdin.close()
    if child.stdout is not None:
        child.stdout.close()

def _read_ready_line(test_case: unittest.TestCase, child: subprocess.Popen[bytes]) -> None:
    if child.stdout is None:
        test_case.fail("child stdout pipe is unavailable")
    ready = bytearray()
    deadline = time.monotonic() + 3
    while b"\n" not in ready:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            test_case.fail("child readiness timed out")
        readable, _writable, _exceptional = select.select(
            [child.stdout.fileno()], [], [], remaining,
        )
        if not readable:
            test_case.fail("child readiness timed out")
        chunk = os.read(child.stdout.fileno(), 64 - len(ready))
        if not chunk:
            test_case.fail("child closed before readiness")
        ready.extend(chunk)
        if len(ready) > 64:
            test_case.fail("child readiness record is too large")

    test_case.assertEqual(bytes(ready), b"ready\n")


@unittest.skipUnless(sys.platform.startswith("linux"), "publisher identity requires Linux procfs")
class RuntimeClaimsTests(unittest.TestCase):
    def test_extracts_ids_from_the_official_results_scope(self):
        token = _jwt({
            "scp": f"Actions.ExampleScope Actions.Results:{_RUN_BACKEND_ID}:{_JOB_BACKEND_ID}",
        })

        self.assertEqual(
            runner_runtime._runtime_claims(token),
            (_RUN_BACKEND_ID, _JOB_BACKEND_ID),
        )

    def test_requires_exactly_one_well_formed_results_scope(self):
        cases = (
            {},
            {"scp": ""},
            {"scp": "Actions.ExampleScope"},
            {"scp": "Actions.Results"},
            {"scp": "Actions.Results::job"},
            {"scp": "Actions.Results:run:"},
            {"scp": "Actions.Results:run:job:extra"},
            {"scp": "Actions.Results:unsafe/value:job"},
            {"scp": f"Actions.Results:{'a' * 65}:job"},
            {"scp": f"Actions.Results:{_RUN_BACKEND_ID}:{_JOB_BACKEND_ID} "
                    f"Actions.Results:{_RUN_BACKEND_ID}:{_JOB_BACKEND_ID}"},
            {"scp": f"Actions.Results:{_RUN_BACKEND_ID}:{_JOB_BACKEND_ID} "
                    "Actions.Results:malformed"},
            {"scp": [f"Actions.Results:{_RUN_BACKEND_ID}:{_JOB_BACKEND_ID}"]},
        )
        for claims in cases:
            with self.subTest(claims=claims):
                with self.assertRaises(runner_runtime.RuntimeFailure):
                    runner_runtime._runtime_claims(_jwt(claims))

    def test_legacy_top_level_ids_are_not_a_fallback(self):
        token = _jwt({
            "workflow_run_backend_id": _RUN_BACKEND_ID,
            "workflow_job_run_backend_id": _JOB_BACKEND_ID,
        })

        with self.assertRaises(runner_runtime.RuntimeFailure):
            runner_runtime._runtime_claims(token)


@unittest.skipUnless(sys.platform.startswith("linux"), "publisher identity requires Linux procfs")
class PublisherChildIdentityTests(unittest.TestCase):
    def _start_child(self, command: list[str], *, env: dict[str, str]):
        child = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            close_fds=True,
        )
        self.addCleanup(_stop_child, child)
        _read_ready_line(self, child)
        return child

    def test_closed_github_output_writer_fd_does_not_block_a_live_publisher(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-publisher-output-") as directory:
            output_path = Path(directory) / "github-output"
            output_fd = os.open(
                output_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            os.fchmod(output_fd, 0o600)
            output_info = os.fstat(output_fd)
            self.addCleanup(os.close, output_fd)

            # Node's appendFileSync uses a transient open/write/close descriptor,
            # matching @actions/core's GITHUB_OUTPUT file-command behavior.
            script = (
                "const fs = require('node:fs');"
                "fs.appendFileSync(process.env.GITHUB_OUTPUT, "
                "Buffer.from(process.env.PUBLISHER_OUTPUT_B64, 'base64'));"
                "process.stdout.write('ready\\n');"
                "process.stdin.once('data', () => process.exit(0));"
            )
            child = self._start_child(
                [
                    "node", "--jitless", "--disable-wasm-trap-handler",
                    "--max-old-space-size=64", "--v8-pool-size=1", "-e", script,
                ],
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": directory,
                    "GITHUB_OUTPUT": str(output_path),
                    "PUBLISHER_OUTPUT_B64": base64.b64encode(_PUBLISHER_OUTPUT).decode("ascii"),
                },
            )
            observed = runner_runtime.observe_process(child.pid)
            self.assertFalse(any(
                (row[1], row[2]) == (output_info.st_dev, output_info.st_ino)
                for row in observed.held_fds
            ))

            # This fixture is not privileged: only its authority fields are
            # synthetic; process birth, executable, cgroup and descriptor rows
            # come from /proc for the actual Node child.
            runner_runtime._verify_publisher_child(
                _synthetic_root_authority(observed), _RUNTIME_TOKEN,
            )
            child.stdin.write(b"exit\n")
            child.stdin.flush()
            self.assertEqual(child.wait(timeout=3), 0)

            raw = runner_runtime._read_verified_publisher_output(
                output_fd, str(output_path), output_info,
            )
            self.assertEqual(raw, _PUBLISHER_OUTPUT)
            parsed = runner_artifact.parse_publisher_output(raw)
            self.assertEqual(parsed["digest"], _ARTIFACT_DIGEST)
            self.assertEqual(parsed["url"], _ARTIFACT_URL)
            final_info = os.fstat(output_fd)
            named_info = os.stat(output_path, follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(final_info.st_mode))
            self.assertEqual(
                (final_info.st_dev, final_info.st_ino),
                (output_info.st_dev, output_info.st_ino),
            )
            self.assertEqual((final_info.st_uid, final_info.st_gid),
                             (output_info.st_uid, output_info.st_gid))
            self.assertEqual(stat.S_IMODE(final_info.st_mode), 0o600)
            self.assertEqual(final_info.st_nlink, 1)
            self.assertEqual((named_info.st_dev, named_info.st_ino),
                             (output_info.st_dev, output_info.st_ino))

    def test_child_still_refuses_a_fd_target_that_contains_the_runtime_secret(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-publisher-fd-") as directory:
            secret_path = Path(directory) / _RUNTIME_TOKEN
            secret_path.write_bytes(b"synthetic-only")
            script = (
                "import os,sys;"
                "fd=os.open(sys.argv[1], os.O_RDONLY|os.O_CLOEXEC);"
                "sys.stdout.write('ready\\n');sys.stdout.flush();"
                "sys.stdin.buffer.read(1);os.close(fd)"
            )
            child = self._start_child(
                [sys.executable, "-I", "-S", "-c", script, str(secret_path)],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": directory},
            )
            observed = runner_runtime.observe_process(child.pid)
            self.assertTrue(any(_RUNTIME_TOKEN in row[-1] for row in observed.held_fds))

            with self.assertRaises(runner_runtime.RuntimeFailure):
                runner_runtime._verify_publisher_child(
                    _synthetic_root_authority(observed), _RUNTIME_TOKEN,
                )

    def test_child_still_refuses_enabled_capabilities(self):
        script = (
            "import sys;sys.stdout.write('ready\\n');sys.stdout.flush();"
            "sys.stdin.buffer.read(1)"
        )
        child = self._start_child(
            [sys.executable, "-I", "-S", "-c", script],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"},
        )
        observed = _synthetic_root_authority(runner_runtime.observe_process(child.pid))

        with self.assertRaises(runner_runtime.RuntimeFailure):
            runner_runtime._verify_publisher_child(
                replace(observed, cap_eff="0000000000000001"), _RUNTIME_TOKEN,
            )


@unittest.skipUnless(sys.platform.startswith("linux"), "publisher output uses Linux descriptors")
class PublisherOutputIdentityTests(unittest.TestCase):
    """Use real user-owned files; production enforces root ownership at creation."""

    def _open_output(self, path: Path):
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        return descriptor, os.fstat(descriptor)

    def test_replaced_output_path_is_refused_even_while_original_fd_is_held(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-publisher-replace-") as directory:
            path = Path(directory) / "github-output"
            output_fd, output_info = self._open_output(path)
            self.addCleanup(os.close, output_fd)
            replacement = Path(directory) / "replacement"
            replacement.write_bytes(_PUBLISHER_OUTPUT)
            os.chmod(replacement, 0o600)
            os.replace(replacement, path)

            with self.assertRaises(runner_runtime.RuntimeFailure):
                runner_runtime._read_verified_publisher_output(
                    output_fd, str(path), output_info,
                )

    def test_unsafe_output_mode_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-publisher-mode-") as directory:
            path = Path(directory) / "github-output"
            output_fd, output_info = self._open_output(path)
            self.addCleanup(os.close, output_fd)
            os.fchmod(output_fd, 0o644)

            with self.assertRaises(runner_runtime.RuntimeFailure):
                runner_runtime._read_verified_publisher_output(
                    output_fd, str(path), output_info,
                )

    def test_output_hard_link_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-publisher-link-") as directory:
            path = Path(directory) / "github-output"
            output_fd, output_info = self._open_output(path)
            self.addCleanup(os.close, output_fd)
            os.link(path, Path(directory) / "second-link")
            self.assertEqual(os.fstat(output_fd).st_nlink, 2)

            with self.assertRaises(runner_runtime.RuntimeFailure):
                runner_runtime._read_verified_publisher_output(
                    output_fd, str(path), output_info,
                )

    def test_oversized_output_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="dotunnel-publisher-size-") as directory:
            path = Path(directory) / "github-output"
            output_fd, output_info = self._open_output(path)
            self.addCleanup(os.close, output_fd)
            os.write(output_fd, b"x" * (4 * 1024 + 1))

            with self.assertRaises(runner_runtime.RuntimeFailure):
                runner_runtime._read_verified_publisher_output(
                    output_fd, str(path), output_info,
                )
