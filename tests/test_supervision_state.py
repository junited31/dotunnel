import asyncio
import os
import stat
import tempfile
import unittest
from pathlib import Path


class SupervisionStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state_dir = self.base / "private-state"

    def open_initialized(self):
        from dotunnel.supervision_state import SupervisionState

        state = SupervisionState.initialize(self.state_dir)
        self.addCleanup(state.close)
        return state

    def assert_code(self, error, code):
        self.assertEqual(getattr(error, "code", None), code)

    def fingerprint(self, label):
        from dotunnel.supervision_config import canonical_sha256

        return canonical_sha256({"test_operation": label})

    def test_constructor_requires_existing_initialized_state_and_does_not_create_it(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        with self.assertRaises(SupervisionError) as raised:
            SupervisionState(self.state_dir)
        self.assert_code(raised.exception, "state_unsafe")
        self.assertFalse(self.state_dir.exists())

    def test_epoch_and_signing_key_survive_restart_and_state_is_private(self):
        state = self.open_initialized()
        epoch, key = state.epoch, state.key
        self.assertTrue(epoch)
        self.assertIsInstance(key, bytes)
        self.assertGreaterEqual(len(key), 32)

        from dotunnel.supervision_state import SupervisionState

        state.close()
        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.epoch, epoch)
        self.assertEqual(reopened.key, key)

        directory_info = self.state_dir.stat()
        self.assertEqual(directory_info.st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(directory_info.st_mode), 0o700)
        for path in self.state_dir.rglob("*"):
            info = path.lstat()
            self.assertFalse(stat.S_ISLNK(info.st_mode))
            if stat.S_ISDIR(info.st_mode):
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            elif stat.S_ISREG(info.st_mode):
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(info.st_nlink, 1)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)

    def test_initialization_refuses_existing_state_without_rotating_it(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        epoch, key = state.epoch, state.key
        with self.assertRaises(SupervisionError):
            SupervisionState.initialize(self.state_dir)
        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.epoch, epoch)
        self.assertEqual(reopened.key, key)

    def test_initialization_accepts_precreated_state_in_readonly_parent(self):
        from dotunnel.supervision_state import SupervisionState

        if os.getuid() == 0:
            self.skipTest("root bypasses the directory write permission boundary")
        parent = self.base / "readonly-parent"
        parent.mkdir(mode=0o700)
        existing = parent / "state"
        existing.mkdir(mode=0o700)
        original_inode = existing.stat().st_ino
        parent.chmod(0o500)
        initialized = None
        reopened = None
        try:
            initialized = SupervisionState.initialize(existing)

            async def write_approval(state):
                async with state.lock():
                    state.set_approval("connection:project", "generation", True)

            asyncio.run(write_approval(initialized))
            initialized.close()
            initialized = None
            reopened = SupervisionState(existing)

            async def read_approval():
                async with reopened.lock():
                    self.assertTrue(reopened.approved("connection:project", "generation"))

            asyncio.run(read_approval())
            self.assertEqual(existing.stat().st_ino, original_inode)
        finally:
            if initialized is not None:
                initialized.close()
            if reopened is not None:
                reopened.close()
            parent.chmod(0o700)

    def test_readonly_parent_does_not_bypass_unsafe_owner_file(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState, _owner_lock_name

        if os.getuid() == 0:
            self.skipTest("root bypasses the directory write permission boundary")
        for label, contents, mode in (("contents", b"not-empty", 0o600), ("inaccessible", b"", 0o000)):
            with self.subTest(label=label):
                parent = self.base / label
                parent.mkdir(mode=0o700)
                existing = parent / "state"
                existing.mkdir(mode=0o700)
                guard = parent / _owner_lock_name(existing.name)
                guard.write_bytes(contents)
                guard.chmod(mode)
                parent.chmod(0o500)
                try:
                    with self.assertRaises(SupervisionError) as refused:
                        unexpected = SupervisionState.initialize(existing)
                        unexpected.close()
                    self.assert_code(refused.exception, "state_unsafe")
                    self.assertEqual(list(existing.iterdir()), [])
                finally:
                    parent.chmod(0o700)
                    guard.chmod(0o600)

    def test_readonly_parent_transition_never_creates_root_without_guard(self):
        from unittest.mock import patch
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        if os.getuid() == 0:
            self.skipTest("root bypasses the directory write permission boundary")
        parent = self.base / "readonly-transition"
        parent.mkdir(mode=0o700)
        existing = parent / "missing-state"
        parent.chmod(0o500)
        real_open = os.open
        changed = []

        def make_parent_writable_after_creation_denial(path, flags, *args, **kwargs):
            try:
                return real_open(path, flags, *args, **kwargs)
            except PermissionError:
                if flags & os.O_CREAT:
                    parent.chmod(0o700)
                    changed.append(True)
                raise

        try:
            with patch("os.open", make_parent_writable_after_creation_denial):
                with self.assertRaises(SupervisionError) as refused:
                    unexpected = SupervisionState.initialize(existing)
                    unexpected.close()
            self.assert_code(refused.exception, "state_unsafe")
            self.assertEqual(changed, [True])
            self.assertFalse(existing.exists())
        finally:
            parent.chmod(0o700)

    def test_concurrent_initializers_serialize_directory_creation(self):
        import json
        import subprocess
        import sys
        import textwrap
        import time

        from dotunnel.supervision_state import SupervisionState

        self.state_dir.mkdir(mode=0o700)
        self.state_dir.chmod(0o700)
        barrier = self.base / "initializer-barrier"
        barrier.mkdir(mode=0o700)
        source_root = str(Path(__file__).resolve().parents[1])
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (source_root, environment.get("PYTHONPATH", "")) if part
        )
        worker = textwrap.dedent(
            """
            import fcntl
            import json
            import os
            import sys
            import time
            from pathlib import Path

            from dotunnel.supervision_config import SupervisionError
            from dotunnel.supervision_state import SupervisionState

            state_path = Path(sys.argv[1])
            barrier = Path(sys.argv[2])
            worker_id = sys.argv[3]
            other_id = "b" if worker_id == "a" else "a"
            expected = state_path.stat()
            real_listdir = os.listdir
            real_flock = fcntl.flock
            used = [False]

            def wait_for_release(phase):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    both_checked = all(
                        (barrier / f"{phase}-{index}").exists() for index in ("a", "b")
                    )
                    other_contended = (
                        (barrier / f"{phase}-{worker_id}").exists()
                        and (barrier / f"flocked-{other_id}").exists()
                    )
                    if both_checked or other_contended:
                        return
                    time.sleep(0.005)
                raise RuntimeError(f"initializer synchronization timed out at {phase}")

            def coordinated_flock(directory, operation):
                try:
                    os.fstat(directory)
                except OSError:
                    pass
                else:
                    (barrier / f"flocked-{worker_id}").touch()
                return real_flock(directory, operation)

            def coordinated_listdir(directory=None):
                if isinstance(directory, int) and not used[0]:
                    try:
                        current = os.fstat(directory)
                    except OSError:
                        current = None
                    if current is not None and (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
                        used[0] = True
                        (barrier / f"checked-{worker_id}").touch()
                        wait_for_release("checked")
                        entries = real_listdir(directory)
                        (barrier / f"observed-{worker_id}").write_text(json.dumps(entries))
                        wait_for_release("observed")
                        return entries
                return real_listdir(directory)

            fcntl.flock = coordinated_flock
            os.listdir = coordinated_listdir
            (barrier / f"ready-{worker_id}").touch()
            deadline = time.monotonic() + 10
            while not (barrier / "go").exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            if not (barrier / "go").exists():
                raise RuntimeError("parent did not release initializer barrier")

            try:
                state = SupervisionState.initialize(state_path)
            except SupervisionError as error:
                if error.code not in ("busy", "state_unsafe"):
                    raise
                print("ERR " + json.dumps({"code": error.code}), flush=True)
            else:
                print("OK " + json.dumps({"epoch": state.epoch, "key": state.key.hex()}), flush=True)
                state.close()

            """
        )
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", worker, str(self.state_dir), str(barrier), worker_id],
                cwd=source_root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for worker_id in ("a", "b")
        ]
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not all(
                (barrier / f"ready-{worker_id}").exists() for worker_id in ("a", "b")
            ):
                if any(process.poll() is not None for process in processes):
                    break
                time.sleep(0.005)
            self.assertTrue(
                all((barrier / f"ready-{worker_id}").exists() for worker_id in ("a", "b")),
                "both initializer processes must reach the start barrier",
            )
            (barrier / "go").touch()
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, stderr)
                outputs.extend(stdout.splitlines())
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()

        successes = [json.loads(line[3:]) for line in outputs if line.startswith("OK ")]
        failures = [json.loads(line[4:]) for line in outputs if line.startswith("ERR ")]
        self.assertEqual(len(successes), 1, outputs)
        self.assertEqual(len(failures), 1, outputs)
        self.assertIn(failures[0]["code"], ("busy", "state_unsafe"))

        authority = SupervisionState(self.state_dir)
        self.addCleanup(authority.close)
        self.assertEqual(authority.epoch, successes[0]["epoch"])
        self.assertEqual(authority.key.hex(), successes[0]["key"])

    def test_initialize_refuses_during_rotation_gap_and_preserves_archive(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from unittest.mock import patch

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        old = self.open_initialized()

        async def seed_old_authority():
            async with old.lock():
                old.set_approval("connection:project", "generation-old", True)

        asyncio.run(seed_old_authority())
        old.close()
        owner_files = [path for path in self.base.iterdir() if path.is_file()]
        self.assertEqual(len(owner_files), 1)
        owner_path = owner_files[0]
        owner_stat = owner_path.stat()
        owner_identity = (owner_stat.st_dev, owner_stat.st_ino)
        published = {
            path.relative_to(self.state_dir): path.read_bytes()
            for path in self.state_dir.rglob("*")
            if path.is_file()
        }

        moved_old = threading.Event()
        release_rotation = threading.Event()
        real_rename = os.rename

        def pause_after_old_to_previous(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            result = real_rename(
                src,
                dst,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )
            if src == self.state_dir.name and dst == f"{self.state_dir.name}.previous":
                moved_old.set()
                if not release_rotation.wait(5):
                    raise TimeoutError("rotation gap barrier was not released")
            return result

        with ThreadPoolExecutor(max_workers=1) as executor:
            with patch("os.rename", pause_after_old_to_previous):
                pending = executor.submit(SupervisionState.reinitialize, self.state_dir)
                try:
                    self.assertTrue(moved_old.wait(5), "rotation must reach the old-to-previous rename")
                    sibling_path = self.base / "sibling-state"
                    sibling = SupervisionState.initialize(sibling_path)
                    sibling.close()
                    sibling_owner_files = [
                        path for path in self.base.iterdir() if path.is_file() and path != owner_path
                    ]
                    self.assertEqual(len(sibling_owner_files), 1)
                    sibling_owner_path = sibling_owner_files[0]
                    with self.assertRaises(SupervisionError) as refused:
                        unexpected = SupervisionState.initialize(self.state_dir)
                        unexpected.close()
                    self.assert_code(refused.exception, "busy")
                finally:
                    release_rotation.set()
                replacement = pending.result(timeout=5)
                replacement.close()

        previous = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertEqual(
            {
                path.relative_to(previous): path.read_bytes()
                for path in previous.rglob("*")
                if path.is_file()
            },
            published,
        )
        self.assertEqual(list(self.base.glob(".dotunnel-state-*.new")), [])
        owner_stat = owner_path.stat()
        self.assertEqual((owner_stat.st_dev, owner_stat.st_ino), owner_identity)
        with self.assertRaises(SupervisionError) as still_archived:
            SupervisionState.reinitialize(self.state_dir)
        self.assert_code(still_archived.exception, "state_full")
        self.assertEqual(
            {path for path in self.base.iterdir() if path.is_file()},
            {owner_path, sibling_owner_path},
        )

    def test_initialize_refuses_during_rollback_and_restores_old_authority(self):
        from concurrent.futures import ThreadPoolExecutor
        import hashlib
        import threading
        from unittest.mock import patch

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        old = self.open_initialized()

        async def seed_old_authority():
            async with old.lock():
                old.set_approval("connection:project", "generation-old", True)

        asyncio.run(seed_old_authority())
        old.close()
        published = {
            path.relative_to(self.state_dir): path.read_bytes()
            for path in self.state_dir.rglob("*")
            if path.is_file()
        }

        stage_name = (
            ".dotunnel-state-"
            + hashlib.sha256(os.fsencode(str(self.state_dir))).hexdigest()[:16]
            + ".new"
        )
        moved_old = threading.Event()
        release_rollback = threading.Event()
        real_rename = os.rename

        def fail_stage_promotion(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            if src == self.state_dir.name and dst == f"{self.state_dir.name}.previous":
                result = real_rename(
                    src,
                    dst,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )
                moved_old.set()
                if not release_rollback.wait(5):
                    raise TimeoutError("rollback barrier was not released")
                return result
            if src == stage_name and dst == self.state_dir.name:
                raise OSError("injected stage promotion failure")
            return real_rename(
                src,
                dst,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        with ThreadPoolExecutor(max_workers=1) as executor:
            with patch("os.rename", fail_stage_promotion):
                pending = executor.submit(SupervisionState.reinitialize, self.state_dir)
                try:
                    self.assertTrue(moved_old.wait(5), "rotation must reach the old-to-previous rename")
                    with self.assertRaises(SupervisionError) as refused:
                        unexpected = SupervisionState.initialize(self.state_dir)
                        unexpected.close()
                    self.assert_code(refused.exception, "busy")
                finally:
                    release_rollback.set()

                with self.assertRaises(SupervisionError) as failed:
                    pending.result(timeout=5)
                self.assert_code(failed.exception, "state_unsafe")

        self.assertEqual(
            {
                path.relative_to(self.state_dir): path.read_bytes()
                for path in self.state_dir.rglob("*")
                if path.is_file()
            },
            published,
        )
        previous = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertFalse(previous.exists())
        self.assertEqual(list(self.base.glob(".dotunnel-state-*.new")), [])

        retry = SupervisionState.reinitialize(self.state_dir)
        retry.close()
        self.assertEqual(
            {
                path.relative_to(previous): path.read_bytes()
                for path in previous.rglob("*")
                if path.is_file()
            },
            published,
        )

    def test_reinitialization_rejects_unsafe_parent_owner_metadata(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        mutations = {
            "mode": lambda owner_path, state_path: owner_path.chmod(0o640),
            "hardlink": lambda owner_path, state_path: os.link(
                owner_path,
                self.base / f"{state_path.name}-owner-link",
            ),
            "size": lambda owner_path, state_path: (
                owner_path.write_bytes(b"unexpected owner data"),
                owner_path.chmod(0o600),
            ),
            "symlink": lambda owner_path, state_path: (
                owner_path.unlink(),
                owner_path.symlink_to(state_path / "key"),
            ),
        }
        for label, corrupt_owner in mutations.items():
            with self.subTest(owner_metadata=label):
                state_path = self.base / f"state-{label}"
                before = set(self.base.iterdir())
                state = SupervisionState.initialize(state_path)
                state.close()
                created = set(self.base.iterdir()) - before
                owner_files = [path for path in created if path.is_file()]
                self.assertEqual(len(owner_files), 1)
                owner_path = owner_files[0]
                published = {
                    path.relative_to(state_path): path.read_bytes()
                    for path in state_path.rglob("*")
                    if path.is_file()
                }

                corrupt_owner(owner_path, state_path)
                with self.assertRaises(SupervisionError) as refused:
                    SupervisionState.reinitialize(state_path)
                self.assert_code(refused.exception, "state_unsafe")
                self.assertEqual(
                    {
                        path.relative_to(state_path): path.read_bytes()
                        for path in state_path.rglob("*")
                        if path.is_file()
                    },
                    published,
                )
                self.assertFalse(state_path.with_name(state_path.name + ".previous").exists())

    def test_reinitialization_refuses_an_initialization_owner_and_preserves_archive(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from unittest.mock import patch
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        entered = threading.Event()
        release = threading.Event()
        real_fsync = os.fsync
        def pause_after_lock_publication(fd):
            real_fsync(fd)
            if os.readlink(f"/proc/self/fd/{fd}") == str(self.state_dir / "lock"):
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("initialization barrier was not released")
        with ThreadPoolExecutor(max_workers=1) as executor:
            with patch("os.fsync", pause_after_lock_publication):
                pending = executor.submit(SupervisionState.initialize, self.state_dir)
                try:
                    self.assertTrue(entered.wait(5))
                    with self.assertRaises(SupervisionError) as refused:
                        accidental = SupervisionState.reinitialize(self.state_dir)
                        accidental.close()
                    self.assert_code(refused.exception, "busy")
                finally:
                    release.set()
                    winner = pending.result(timeout=5)
                    winner.close()
        old = SupervisionState(self.state_dir)
        old_epoch = old.epoch
        old.close()
        published = {
            path.relative_to(self.state_dir): path.read_bytes()
            for path in self.state_dir.rglob("*") if path.is_file()
        }
        fresh = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(fresh.close)
        self.assertNotEqual(fresh.epoch, old_epoch)
        previous = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertEqual(
            {path.relative_to(previous): path.read_bytes() for path in previous.rglob("*") if path.is_file()},
            published,
        )

    def test_sigkill_before_atomic_rename_is_archived_without_startup_recovery(self):
        import signal
        import subprocess
        import sys
        import textwrap
        import time

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        old = self.open_initialized()

        async def seed():
            async with old.lock():
                old.set_approval("connection:project", "generation-a", True)

        asyncio.run(seed())
        old_epoch, old_key = old.epoch, old.key
        published = {
            path.relative_to(self.state_dir): path.read_bytes()
            for path in (self.state_dir / "approvals").glob("*.json")
        }
        old.close()

        marker = self.base / "atomic-write-ready"
        source_root = str(Path(__file__).resolve().parents[1])
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (source_root, environment.get("PYTHONPATH", "")) if part
        )
        worker = textwrap.dedent(
            """
            import asyncio
            import os
            import sys
            import time
            from pathlib import Path

            from dotunnel.supervision_state import SupervisionState

            state = SupervisionState(Path(sys.argv[1]))
            marker = Path(sys.argv[2])

            def stop_before_rename(source, destination, *args, **kwargs):
                marker.write_text(os.fspath(source) + "\\n" + os.fspath(destination))
                while True:
                    time.sleep(1)

            os.replace = stop_before_rename

            async def update():
                async with state.lock():
                    state.set_approval("connection:project", "generation-a", False)

            asyncio.run(update())
            """
        )
        process = subprocess.Popen(
            [sys.executable, "-c", worker, str(self.state_dir), str(marker)],
            cwd=source_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                time.sleep(0.005)
            self.assertTrue(marker.exists(), "writer must stop after fsync and before os.replace")
            source_name, destination_name = marker.read_text().splitlines()
            self.assertRegex(source_name, r"\.write-[0-9a-f]{32}\Z")
            self.assertTrue(destination_name.endswith(".json"))
            staged_path = self.state_dir / "approvals" / source_name
            staged_bytes = staged_path.read_bytes()
            process.send_signal(signal.SIGKILL)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        with self.assertRaises(SupervisionError) as startup_error:
            SupervisionState(self.state_dir)
        self.assert_code(startup_error.exception, "state_unsafe")
        self.assertEqual(staged_path.read_bytes(), staged_bytes)
        self.assertEqual(
            {
                path.relative_to(self.state_dir): path.read_bytes()
                for path in (self.state_dir / "approvals").glob("*.json")
            },
            published,
        )

        fresh = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(fresh.close)
        previous_path = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertEqual((previous_path / "approvals" / source_name).read_bytes(), staged_bytes)
        self.assertEqual(
            {
                path.relative_to(previous_path): path.read_bytes()
                for path in (previous_path / "approvals").glob("*.json")
            },
            published,
        )
        self.assertNotEqual(fresh.epoch, old_epoch)
        self.assertNotEqual(fresh.key, old_key)
        self.assertFalse(fresh.approved("connection:project", "generation-a"))

    def test_reinitialization_archives_valid_root_staging_file_verbatim(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        old_epoch, old_key = state.epoch, state.key
        state.close()
        staged_name = ".write-" + ("a" * 32)
        staged_bytes = b'{"incomplete":"root metadata write"'
        staged_path = self.state_dir / staged_name
        staged_path.write_bytes(staged_bytes)
        staged_path.chmod(0o600)

        with self.assertRaises(SupervisionError) as startup_error:
            SupervisionState(self.state_dir)
        self.assert_code(startup_error.exception, "state_unsafe")
        self.assertEqual(staged_path.read_bytes(), staged_bytes)

        fresh = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(fresh.close)
        previous_path = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertEqual((previous_path / staged_name).read_bytes(), staged_bytes)
        self.assertNotEqual(fresh.epoch, old_epoch)
        self.assertNotEqual(fresh.key, old_key)

    def test_reinitialization_rejects_malformed_staging_entries_at_root_and_categories(self):
        import hashlib

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        corruptions = ("unknown", "malformed_name", "symlink", "hardlink", "oversized", "wrong_mode")
        for location in ("root", "category"):
            for corruption in corruptions:
                with self.subTest(location=location, corruption=corruption):
                    self.state_dir = self.base / f"malformed-{location}-{corruption}"
                    state = self.open_initialized()

                    async def seed():
                        async with state.lock():
                            state.set_approval("connection:project", "generation-a", True)

                    asyncio.run(seed())
                    published_path = next((self.state_dir / "approvals").glob("*.json"))
                    published_bytes = published_path.read_bytes()
                    old_metadata = (self.state_dir / "epoch.json").read_bytes()
                    old_key = (self.state_dir / "key").read_bytes()
                    state.close()

                    directory = self.state_dir if location == "root" else self.state_dir / "approvals"
                    if corruption == "unknown":
                        staged_path = directory / "unexpected"
                    elif corruption == "malformed_name":
                        staged_path = directory / (".write-" + "b" * 31)
                    else:
                        staged_path = directory / (
                            ".write-" + hashlib.sha256(f"{location}-{corruption}".encode()).hexdigest()[:32]
                        )
                    if corruption in ("unknown", "malformed_name", "oversized", "wrong_mode"):
                        staged_path.write_bytes(b"x" * (65_537 if corruption == "oversized" else 1))
                        staged_path.chmod(0o640 if corruption == "wrong_mode" else 0o600)
                    elif corruption == "symlink":
                        target = self.base / f"symlink-target-{location}"
                        target.write_bytes(b"target")
                        staged_path.symlink_to(target)
                    elif corruption == "hardlink":
                        target = self.base / f"hardlink-target-{location}"
                        target.write_bytes(b"target")
                        target.chmod(0o600)
                        os.link(target, staged_path)

                    with self.assertRaises(SupervisionError) as startup_error:
                        SupervisionState(self.state_dir)
                    self.assert_code(startup_error.exception, "state_unsafe")
                    with self.assertRaises(SupervisionError) as reinit_error:
                        SupervisionState.reinitialize(self.state_dir)
                    self.assert_code(reinit_error.exception, "state_unsafe")
                    self.assertEqual((self.state_dir / "epoch.json").read_bytes(), old_metadata)
                    self.assertEqual((self.state_dir / "key").read_bytes(), old_key)
                    self.assertEqual(published_path.read_bytes(), published_bytes)
                    self.assertTrue(staged_path.exists() or staged_path.is_symlink())

    def test_reinitialization_refuses_staging_files_owned_by_another_user(self):
        import hashlib

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        for location in ("root", "category"):
            with self.subTest(location=location):
                self.state_dir = self.base / f"foreign-staging-{location}"
                state = self.open_initialized()
                old_metadata = (self.state_dir / "epoch.json").read_bytes()
                old_key = (self.state_dir / "key").read_bytes()
                state.close()
                directory = self.state_dir if location == "root" else self.state_dir / "approvals"
                staged_path = directory / (
                    ".write-" + hashlib.sha256(location.encode()).hexdigest()[:32]
                )
                staged_path.write_bytes(b"foreign owner")
                staged_path.chmod(0o600)
                try:
                    os.chown(staged_path, os.getuid() + 1, -1)
                except PermissionError:
                    self.skipTest("changing a test file owner requires elevated privileges")

                with self.assertRaises(SupervisionError) as startup_error:
                    SupervisionState(self.state_dir)
                self.assert_code(startup_error.exception, "state_unsafe")
                with self.assertRaises(SupervisionError) as reinit_error:
                    SupervisionState.reinitialize(self.state_dir)
                self.assert_code(reinit_error.exception, "state_unsafe")
                self.assertEqual((self.state_dir / "epoch.json").read_bytes(), old_metadata)
                self.assertEqual((self.state_dir / "key").read_bytes(), old_key)
                self.assertTrue(staged_path.exists())

    def test_reinitialization_allows_one_staged_file_beyond_category_capacity(self):
        import hashlib

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        state.close()
        category = self.state_dir / "approvals"
        for index in range(1_000):
            name = hashlib.sha256(f"archive-capacity-{index}".encode()).hexdigest() + ".json"
            record = category / name
            record.write_bytes(b"{}")
            record.chmod(0o600)
        staged_name = ".write-" + ("c" * 32)
        staged_bytes = b"interrupted write"
        staged_path = category / staged_name
        staged_path.write_bytes(staged_bytes)
        staged_path.chmod(0o600)

        fresh = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(fresh.close)
        previous = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertEqual(len(list((previous / "approvals").glob("*.json"))), 1_000)
        self.assertEqual((previous / "approvals" / staged_name).read_bytes(), staged_bytes)

        self.state_dir = self.base / "too-many-staged-files"
        another = self.open_initialized()
        another.close()
        category = self.state_dir / "approvals"
        root_stage = self.state_dir / (".write-" + "d" * 32)
        category_stage = category / (".write-" + "e" * 32)
        for staged_path in (root_stage, category_stage):
            staged_path.write_bytes(b"interrupted write")
            staged_path.chmod(0o600)
        with self.assertRaises(SupervisionError) as reinit_error:
            SupervisionState.reinitialize(self.state_dir)
        self.assert_code(reinit_error.exception, "state_unsafe")
        self.assertTrue(root_stage.exists())
        self.assertTrue(category_stage.exists())

    def test_reinitialization_rotates_epoch_and_starts_empty_namespace(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        old_epoch, old_key = state.epoch, state.key
        async def seed():
            async with state.lock():
                state.set_approval("connection:project", "generation-a", True)
                state.prepare("operation-old", self.fingerprint("operation-old"), {"connection": "connection"})
                state.allocate_target("operation-old", {"connection": "connection", "project": "project"})
        asyncio.run(seed())

        state.close()
        replacement = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(replacement.close)
        self.assertNotEqual(replacement.epoch, old_epoch)
        self.assertNotEqual(replacement.key, old_key)
        self.assertFalse(replacement.approved("connection:project", "generation-a"))
        self.assertIsNone(replacement.lookup_receipt("operation-old", self.fingerprint("operation-old")))
        self.assertEqual(replacement.list_targets(), [])

    def test_reinitialization_retains_one_previous_namespace_until_reconciliation(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        fingerprint = self.fingerprint("operation-history")

        async def seed_history():
            async with state.lock():
                state.set_approval("connection:project", "generation-a", True)
                state.prepare("operation-history", fingerprint, {"connection": "connection", "project": "project"})
                attempt = state.allocate_target(
                    "operation-history", {"connection": "connection", "project": "project"}
                )
                state.activate_target(attempt["target_id"], {
                    "native_id": "%7",
                    "project": "project",
                    "identity": {"boot_id": "boot-a", "pane_pid": "123"},
                })
                state.finish("operation-history", {"delivery": "unknown", "evidence": "retained"})
            return attempt

        attempt = asyncio.run(seed_history())
        previous_path = self.state_dir.with_name(self.state_dir.name + ".previous")
        replacement = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(replacement.close)
        retained = SupervisionState(previous_path)
        self.addCleanup(retained.close)

        historical = retained.lookup_receipt("operation-history", fingerprint)
        self.assertTrue(historical["historical"])
        self.assertEqual(historical["evidence"], "retained")
        target = next(record for record in retained.list_targets() if record["target_id"] == attempt["target_id"])
        self.assertEqual(target["state"], "active")
        self.assertEqual(target["native"]["native_id"], "%7")
        self.assertTrue(retained.approved("connection:project", "generation-a"))
        self.assertIsNone(replacement.lookup_receipt("operation-history", fingerprint))
        self.assertEqual(replacement.list_targets(), [])
        self.assertFalse(replacement.approved("connection:project", "generation-a"))

        with self.assertRaises(SupervisionError) as raised:
            SupervisionState.reinitialize(self.state_dir)
        self.assert_code(raised.exception, "state_full")
        self.assertEqual(
            retained.lookup_receipt("operation-history", fingerprint),
            historical,
        )
        self.assertEqual(
            next(record for record in retained.list_targets() if record["target_id"] == attempt["target_id"])["native"]["native_id"],
            "%7",
        )

    def test_explicit_reinitialization_archives_private_damaged_authority(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        for case in ("malformed-epoch", "missing-key", "invalid-key"):
            with self.subTest(case=case):
                self.state_dir = self.base / f"private-state-{case}"
                old = self.open_initialized()
                old_epoch = old.epoch
                operation_id = f"operation-{case}"
                fingerprint = self.fingerprint(case)

                async def seed():
                    async with old.lock():
                        old.set_approval("connection:project", "generation-a", True)
                        old.prepare(operation_id, fingerprint, {"connection": "connection", "project": "project"})
                        attempt = old.allocate_target(operation_id, {"connection": "connection", "project": "project"})
                        old.activate_target(attempt["target_id"], {
                            "native_id": "%9",
                            "project": "project",
                            "identity": {"boot_id": "boot-a", "pane_pid": "321"},
                        })
                        old.finish(operation_id, {"delivery": "confirmed", "evidence": case})
                asyncio.run(seed())

                epoch_path = self.state_dir / "epoch.json"
                key_path = self.state_dir / "key"
                if case == "malformed-epoch":
                    epoch_path.write_bytes(b'{"broken":')
                    epoch_path.chmod(0o600)
                elif case == "missing-key":
                    key_path.unlink()
                else:
                    key_path.write_bytes(b"invalid-signing-key")
                    key_path.chmod(0o600)
                evidence = {
                    path.relative_to(self.state_dir): path.read_bytes()
                    for path in self.state_dir.rglob("*")
                    if path.is_file()
                }

                fresh = SupervisionState.reinitialize(self.state_dir)
                self.addCleanup(fresh.close)
                previous_path = self.state_dir.with_name(self.state_dir.name + ".previous")
                archived = {
                    path.relative_to(previous_path): path.read_bytes()
                    for path in previous_path.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(archived, evidence)
                self.assertEqual(stat.S_IMODE(previous_path.stat().st_mode), 0o700)
                self.assertNotEqual(fresh.epoch, old_epoch)
                self.assertIsNone(fresh.lookup_receipt(operation_id, fingerprint))
                self.assertEqual(fresh.list_targets(), [])
                self.assertFalse(fresh.approved("connection:project", "generation-a"))
                with self.assertRaises(SupervisionError) as prepare_error:
                    old.prepare(f"new-{case}", self.fingerprint(f"new-{case}"), {"project": "p"})
                self.assert_code(prepare_error.exception, "state_unsafe")
                with self.assertRaises(SupervisionError) as approval_error:
                    old.set_approval("connection:project", "generation-a", True)
                self.assert_code(approval_error.exception, "state_unsafe")

    def test_open_state_cannot_prepare_or_approve_after_reinitialization(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        old = self.open_initialized()
        old_epoch, old_key = old.epoch, old.key
        replacement = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(replacement.close)
        self.assertNotEqual(replacement.epoch, old_epoch)
        self.assertNotEqual(replacement.key, old_key)

        with self.assertRaises(SupervisionError) as prepare_error:
            old.prepare("old-operation", self.fingerprint("old-operation"), {"project": "p"})
        self.assert_code(prepare_error.exception, "state_unsafe")
        with self.assertRaises(SupervisionError) as approval_error:
            old.set_approval("connection:project", "generation", True)
        self.assert_code(approval_error.exception, "state_unsafe")
        self.assertIsNone(replacement.lookup_receipt("old-operation", self.fingerprint("old-operation")))
        self.assertFalse(replacement.approved("connection:project", "generation"))

    def test_rejects_symlink_state_directory_and_hardlinked_state_records(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        self.open_initialized().close()
        alias = self.base / "state-alias"
        alias.symlink_to(self.state_dir, target_is_directory=True)
        with self.assertRaises(SupervisionError):
            SupervisionState(alias)

        regular = next(path for path in self.state_dir.rglob("*") if path.is_file())
        os.link(regular, self.base / "state-hardlink")
        with self.assertRaises(SupervisionError) as raised:
            SupervisionState(self.state_dir)
        self.assert_code(raised.exception, "state_unsafe")

    def test_detects_state_directory_inode_replacement_after_open(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        moved = self.base / "original-state"
        os.rename(self.state_dir, moved)
        self.state_dir.mkdir(mode=0o700)
        try:
            with self.assertRaises(SupervisionError) as raised:
                async def acquire():
                    async with state.lock(timeout=0.05):
                        pass
                asyncio.run(acquire())
            self.assert_code(raised.exception, "state_unsafe")
            self.assertEqual(list(self.state_dir.iterdir()), [])
        finally:
            self.state_dir.rmdir()
            os.rename(moved, self.state_dir)

    def test_historical_receipt_replay_survives_restart_and_payload_conflicts(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def save():
            async with state.lock():
                state.prepare("operation-1", self.fingerprint("operation-1"), {"connection": "c", "project": "p"})
                state.finish("operation-1", {"delivery": "confirmed", "value": "saved-result"})
        asyncio.run(save())
        state.close()

        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        historical = reopened.lookup_receipt("operation-1", self.fingerprint("operation-1"))
        self.assertTrue(historical["historical"])
        self.assertEqual(historical["delivery"], "confirmed")
        self.assertEqual(historical["value"], "saved-result")
        with self.assertRaises(SupervisionError) as raised:
            reopened.lookup_receipt("operation-1", self.fingerprint("different-payload"))
        self.assert_code(raised.exception, "operation_conflict")

    def test_pre_rename_state_write_failure_preserves_data_and_recovers_namespace(self):
        import errno
        from unittest import mock

        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        for failure_site in ("approval", "prepare"):
            with self.subTest(failure_site=failure_site):
                self.state_dir = self.base / f"private-state-{failure_site}"
                state = self.open_initialized()
                epoch = state.epoch
                operation_id = "operation-durable"
                fingerprint = self.fingerprint(operation_id)

                async def seed():
                    async with state.lock():
                        state.set_approval("connection:project", "generation-a", True)
                        state.prepare(
                            operation_id,
                            fingerprint,
                            {"connection": "connection", "project": "project"},
                        )
                        state.finish(
                            operation_id,
                            {"delivery": "confirmed", "value": "preserved"},
                        )

                asyncio.run(seed())

                async def fail_durable_write():
                    async with state.lock():
                        if failure_site == "approval":
                            state.set_approval("connection:project", "generation-a", False)
                        else:
                            state.prepare(
                                "operation-interrupted",
                                self.fingerprint("operation-interrupted"),
                                {"connection": "connection", "project": "project"},
                            )

                def fail_first_file_fsync(_fd):
                    raise OSError(errno.ENOSPC, "injected pre-rename fsync failure")

                with mock.patch(
                    "dotunnel.supervision_state.os.fsync",
                    side_effect=fail_first_file_fsync,
                ):
                    with self.assertRaises(SupervisionError) as raised:
                        asyncio.run(fail_durable_write())
                self.assert_code(raised.exception, "state_unsafe")
                state.close()

                reopened = SupervisionState(self.state_dir)
                self.addCleanup(reopened.close)
                self.assertEqual(reopened.epoch, epoch)
                self.assertTrue(reopened.approved("connection:project", "generation-a"))
                saved = reopened.lookup_receipt(operation_id, fingerprint)
                self.assertTrue(saved["historical"])
                self.assertEqual(saved["delivery"], "confirmed")
                self.assertEqual(saved["value"], "preserved")

                recovered_id = "operation-after-recovery"
                recovered_fingerprint = self.fingerprint(recovered_id)

                async def perform_recovered_operation():
                    async with reopened.lock():
                        reopened.prepare(
                            recovered_id,
                            recovered_fingerprint,
                            {"connection": "connection", "project": "project"},
                        )
                        reopened.finish(
                            recovered_id,
                            {"delivery": "confirmed", "value": "recovered"},
                        )

                asyncio.run(perform_recovered_operation())
                recovered = reopened.lookup_receipt(recovered_id, recovered_fingerprint)
                self.assertEqual(recovered["delivery"], "confirmed")
                self.assertEqual(recovered["value"], "recovered")
                reopened.close()

                replacement = SupervisionState.reinitialize(self.state_dir)
                self.addCleanup(replacement.close)
                self.assertNotEqual(replacement.epoch, epoch)
                previous_path = self.state_dir.with_name(self.state_dir.name + ".previous")
                retained = SupervisionState(previous_path)
                self.addCleanup(retained.close)
                retained_receipt = retained.lookup_receipt(operation_id, fingerprint)
                self.assertEqual(retained_receipt["delivery"], "confirmed")
                self.assertEqual(retained_receipt["value"], "preserved")
                self.assertTrue(retained.approved("connection:project", "generation-a"))

    def test_prepared_receipt_projects_to_unknown_after_restart_without_retry(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def prepare_only():
            async with state.lock():
                state.prepare("operation-crashed", self.fingerprint("operation-crashed"), {"project": "p"})
        asyncio.run(prepare_only())
        self.assertFalse(any("operation-crashed" in path.name for path in self.state_dir.rglob("*")))
        state.close()

        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        first = reopened.lookup_receipt("operation-crashed", self.fingerprint("operation-crashed"))
        second = reopened.lookup_receipt("operation-crashed", self.fingerprint("operation-crashed"))
        self.assertTrue(first["historical"])
        self.assertEqual(first["delivery"], "unknown")
        self.assertEqual(first["error"]["code"], "delivery_unknown")
        self.assertEqual(second, first)
        async def admit_new_operation():
            async with reopened.lock():
                reopened.prepare("operation-new", self.fingerprint("operation-new"), {"project": "p"})
        asyncio.run(admit_new_operation())
        diagnostics = reopened.unresolved_predecessors()
        self.assertEqual(diagnostics["unresolved_predecessor_ids"], ["operation-crashed", "operation-new"])

    def test_target_allocation_activation_and_unverified_recovery_are_durable(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def allocate():
            async with state.lock():
                state.prepare("operation-start", self.fingerprint("operation-start"), {"connection": "c", "project": "p"})
                record = state.allocate_target(
                    "operation-start", {"connection": "c", "project": "p", "profile": "f", "generation": "g"}
                )
            return record
        allocating = asyncio.run(allocate())
        self.assertEqual(allocating["state"], "allocating")
        self.assertTrue(allocating["target_id"])
        self.assertTrue(allocating["nonce"])
        self.assertEqual(len(state.list_targets()), 1)

        state.close()
        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        recovery = reopened.list_targets()[0]
        self.assertEqual(recovery["state"], "unknown")
        self.assertEqual(recovery["target_id"], allocating["target_id"])
        self.assertEqual(recovery["nonce"], allocating["nonce"])
        self.assertNotIn("native", recovery)
        self.assertEqual(recovery["binding"]["generation"], "g")

        async def activate():
            async with reopened.lock():
                reopened.prepare("operation-active", self.fingerprint("operation-active"), {"connection": "c", "project": "p"})
                attempt = reopened.allocate_target(
                    "operation-active", {"connection": "c", "project": "p", "profile": "f", "generation": "g"}
                )
                active = reopened.activate_target(attempt["target_id"], {
                    "native_id": "pane-1",
                    "project": "p",
                    "identity": {"pid": 12},
                    "process_state": "running",
                })
                reopened.finish("operation-active", {"delivery": "confirmed", "target_id": attempt["target_id"]})
            return active
        active = asyncio.run(activate())
        self.assertEqual(active["state"], "active")
        self.assertEqual(active["native"]["native_id"], "pane-1")
        active_record = next(record for record in reopened.list_targets() if record["target_id"] == active["target_id"])
        self.assertEqual(active_record["state"], "active")

        reopened.close()
        final_state = SupervisionState(self.state_dir)
        self.addCleanup(final_state.close)
        records = {record["target_id"]: record for record in final_state.list_targets()}
        self.assertEqual(records[allocating["target_id"]]["state"], "unknown")
        self.assertNotIn("native", records[allocating["target_id"]])
        self.assertEqual(records[active["target_id"]]["state"], "active")
        self.assertEqual(records[active["target_id"]]["native"]["native_id"], "pane-1")
        historical = final_state.lookup_receipt("operation-active", self.fingerprint("operation-active"))
        self.assertTrue(historical["historical"])

    def test_target_state_can_be_finalized_as_unknown_without_native_identity(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def allocate_and_mark():
            async with state.lock():
                state.prepare("operation-unknown", self.fingerprint("operation-unknown"), {"connection": "c", "project": "p"})
                target = state.allocate_target("operation-unknown", {"connection": "c", "project": "p"})
                updated = state.update_target(target["target_id"], "unknown")
                state.prepare("operation-refused", self.fingerprint("operation-refused"), {"connection": "c", "project": "p"})
                refused_target = state.allocate_target("operation-refused", {"connection": "c", "project": "p"})
                refused = state.update_target(refused_target["target_id"], "refused")
            return updated, refused
        record, refused = asyncio.run(allocate_and_mark())
        self.assertEqual(record["state"], "unknown")
        self.assertNotIn("native", record)
        self.assertEqual(refused["state"], "refused")
        self.assertNotIn("native", refused)

    def test_approval_is_scoped_to_connection_project_and_generation(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def approve():
            async with state.lock():
                state.set_approval("connection:project", "generation-a", True)
        asyncio.run(approve())
        state.close()

        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        self.assertTrue(reopened.approved("connection:project", "generation-a"))
        self.assertFalse(reopened.approved("connection:project", "generation-b"))

        async def revoke():
            async with reopened.lock():
                reopened.set_approval("connection:project", "generation-a", False)
        asyncio.run(revoke())
        self.assertFalse(reopened.approved("connection:project", "generation-a"))

    def test_approval_records_are_bounded(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def fill_approvals():
            async with state.lock():
                for index in range(1000):
                    state.set_approval(f"connection:project-{index:04d}", "generation", True)
                with self.assertRaises(SupervisionError) as raised:
                    state.set_approval("connection:project-overflow", "generation", True)
                self.assert_code(raised.exception, "state_full")
        asyncio.run(fill_approvals())


    def test_unresolved_diagnostics_are_admission_ordered_and_capped(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        operation_ids = [f"operation-{index:03d}" for index in range(35)]
        fingerprint = self.fingerprint("diagnostics")
        async def prepare_all():
            async with state.lock():
                for operation_id in operation_ids:
                    state.prepare(operation_id, fingerprint, {"project": "p"})
        asyncio.run(prepare_all())
        diagnostics = state.unresolved_predecessors()
        self.assertEqual(diagnostics["unresolved_predecessor_count"], 35)
        self.assertEqual(diagnostics["unresolved_predecessor_ids"], operation_ids[:32])
        self.assertTrue(diagnostics["unresolved_predecessors_truncated"])

    def test_receipt_and_target_count_limits_fail_closed(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        receipt_state = self.open_initialized()
        fingerprint = self.fingerprint("receipt-count")
        async def fill_receipts():
            async with receipt_state.lock():
                for index in range(1000):
                    receipt_state.prepare(f"receipt-{index:04d}", fingerprint, {"scope": "s"})
                with self.assertRaises(SupervisionError) as raised:
                    receipt_state.prepare("receipt-overflow", fingerprint, {"scope": "s"})
                self.assert_code(raised.exception, "state_full")
        asyncio.run(fill_receipts())

        receipt_state.close()
        self.state_dir = self.base / "target-state"
        target_state = self.open_initialized()
        async def fill_targets():
            async with target_state.lock():
                for index in range(1000):
                    target_state.allocate_target(f"target-op-{index:04d}", {"project": "p"})
                with self.assertRaises(SupervisionError) as preflight_error:
                    target_state.check_target_capacity()
                self.assert_code(preflight_error.exception, "state_full")
                with self.assertRaises(SupervisionError) as raised:
                    target_state.allocate_target("target-overflow", {"project": "p"})
                self.assert_code(raised.exception, "state_full")
        asyncio.run(fill_targets())
        self.assertEqual(len(target_state.list_targets()), 1000)

    def test_target_capacity_preflight_is_pure(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def preflight():
            async with state.lock():
                state.check_target_capacity()
                self.assertEqual(state.list_targets(), [])
                state.allocate_target("capacity-one", {"project": "p"})
                state.check_target_capacity()
                self.assertEqual(len(state.list_targets()), 1)
        asyncio.run(preflight())

    def test_oversized_receipt_and_target_records_are_refused_before_publication(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def try_oversized():
            async with state.lock():
                with self.assertRaises(SupervisionError) as receipt_error:
                    state.prepare("large-receipt", self.fingerprint("large-receipt"), {"metadata": "x" * 70_000})
                self.assert_code(receipt_error.exception, "state_full")
                with self.assertRaises(SupervisionError) as target_error:
                    state.allocate_target("large-target", {"metadata": "x" * 70_000})
                self.assert_code(target_error.exception, "state_full")
        asyncio.run(try_oversized())
        self.assertIsNone(state.lookup_receipt("large-receipt", self.fingerprint("large-receipt")))
        self.assertEqual(state.list_targets(), [])

    def test_oversized_damaged_record_on_disk_is_state_unsafe(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def create():
            async with state.lock():
                state.prepare("damaged-record", self.fingerprint("damaged-record"), {"marker": "locate-this-record"})
        asyncio.run(create())
        state.close()
        record = next(path for path in self.state_dir.rglob("*") if path.is_file() and b"locate-this-record" in path.read_bytes())
        record.write_bytes(b"x" * 65_537)
        record.chmod(0o600)

        with self.assertRaises(SupervisionError) as raised:
            try:
                reopened = SupervisionState(self.state_dir)
            except SupervisionError:
                raise
            self.addCleanup(reopened.close)
            reopened.lookup_receipt("damaged-record", self.fingerprint("damaged-record"))
        self.assert_code(raised.exception, "state_unsafe")

    def test_audit_rotates_to_only_two_bounded_files_and_does_not_persist_secrets_or_screens(self):
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        async def append_audit():
            async with state.lock():
                try:
                    state.audit({"event": "input", "credential": "credential-marker", "screen": "screen-marker"})
                except ValueError:
                    pass
                for index in range(55):
                    state.audit({"event": f"AUDIT-{index:03d}", "detail": "x" * 59_000})
        asyncio.run(append_audit())

        audit_payloads = [
            path.read_bytes()
            for path in self.state_dir.rglob("*")
            if path.is_file() and b"AUDIT-" in path.read_bytes()
        ]
        self.assertEqual(len(audit_payloads), 2)
        self.assertTrue(all(len(payload) <= 1_048_576 for payload in audit_payloads))
        joined = b"\n".join(audit_payloads)
        self.assertNotIn(b"AUDIT-000", joined)
        self.assertIn(b"AUDIT-054", joined)
        for path in self.state_dir.rglob("*"):
            if path.is_file():
                contents = path.read_bytes()
                self.assertNotIn(b"credential-marker", contents)
                self.assertNotIn(b"screen-marker", contents)


    def test_torn_audit_tail_is_unknown_safe_and_retained_across_rotation(self):
        import json
        from dotunnel.supervision_state import SupervisionState

        state = self.open_initialized()
        fingerprint = self.fingerprint("audit-tail-operation")
        async def prepare_and_audit():
            async with state.lock():
                state.prepare("audit-tail-operation", fingerprint, {"project": "p"})
                state.audit({"event": "operation_prepared", "operation_id": "audit-tail-operation"})
        asyncio.run(prepare_and_audit())
        state.close()

        audit_current = self.state_dir / "audit.current"
        complete_prefix = audit_current.read_bytes()
        torn_tail = b'{"event":"partial-audit-record"'
        audit_current.write_bytes(complete_prefix + torn_tail)
        audit_current.chmod(0o600)

        reopened = SupervisionState(self.state_dir)
        self.addCleanup(reopened.close)
        unknown = reopened.lookup_receipt("audit-tail-operation", fingerprint)
        self.assertTrue(unknown["historical"])
        self.assertEqual(unknown["delivery"], "unknown")
        self.assertEqual(unknown["error"]["code"], "delivery_unknown")
        reopened.audit({"event": "audit_recovered", "outcome": "bounded"})

        torn_file = self.state_dir / "audit.previous"
        current_file = self.state_dir / "audit.current"
        self.assertEqual(torn_file.read_bytes(), complete_prefix + torn_tail)
        current_payload = current_file.read_bytes()
        self.assertTrue(current_payload.endswith(b"\n"))
        self.assertEqual(json.loads(current_payload)["event"], "audit_recovered")

        fresh = SupervisionState.reinitialize(self.state_dir)
        self.addCleanup(fresh.close)
        previous_path = self.state_dir.with_name(self.state_dir.name + ".previous")
        self.assertEqual((previous_path / "audit.previous").read_bytes(), complete_prefix + torn_tail)
        self.assertEqual((previous_path / "audit.current").read_bytes(), current_payload)
    def test_async_lock_has_a_bounded_busy_failure(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        owner = self.open_initialized()
        contender = SupervisionState(self.state_dir)
        self.addCleanup(contender.close)
        async def contend():
            async with owner.lock(timeout=0.05):
                with self.assertRaises(SupervisionError) as raised:
                    async with contender.lock(timeout=0.02):
                        pass
                self.assert_code(raised.exception, "busy")
        asyncio.run(contend())


    def test_rejects_symlink_ancestor_and_nonprivate_existing_state_directory(self):
        from dotunnel.supervision_config import SupervisionError
        from dotunnel.supervision_state import SupervisionState

        alias = self.base / "parent-alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(SupervisionError) as raised:
            SupervisionState.initialize(alias / "state")
        self.assert_code(raised.exception, "state_unsafe")

        state = self.open_initialized()
        state.close()
        self.state_dir.chmod(0o755)
        with self.assertRaises(SupervisionError) as raised:
            SupervisionState(self.state_dir)
        self.assert_code(raised.exception, "state_unsafe")

if __name__ == "__main__":
    unittest.main()
