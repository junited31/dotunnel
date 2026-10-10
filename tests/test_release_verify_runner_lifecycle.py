import copy
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_release_verify_runner_runtime as fixtures
from tools.release_verify import runner_policy as policy
from tools.release_verify import runner_prepare as prepare
from tools.release_verify import runner_runtime as runtime


class OwnedPublisherLifecycleTests(unittest.TestCase):
    """Real ordinary-file cgroup fixtures; manager/root ownership is synthetic.

    These regressions do not constitute privileged systemd/cgroup acceptance.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="runner-lifecycle-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cgroup_root = self.root / "cgroups"
        self.unit_root = self.root / "units"
        self.cgroup_root.mkdir()
        self.unit_root.mkdir()
        self.context = {
            "schema": 1, "repository": "junited31/dotunnel",
            "ref": "refs/heads/main", "event": "workflow_dispatch",
            "actor": "junited31", "triggering_actor": "junited31",
            "run": "88123", "attempt": "1",
        }
        self.names = policy.validate_context(self.context)
        self.state = {"nonce": "a" * 32, "definitions": {}, "units": {}}
        self.properties = {}
        for attribute, value in (("_CGROUP_DIR", str(self.cgroup_root)),
                                 ("_SYSTEMD_DIR", str(self.unit_root))):
            patched = patch.object(runtime, attribute, value)
            patched.start()
            self.addCleanup(patched.stop)
        manager = patch.object(runtime, "_show_unit", side_effect=self.show_unit)
        manager.start()
        self.addCleanup(manager.stop)
        # Root ownership/content verification itself remains a kernel gate.
        definition = patch.object(runtime, "_read_unit_definition")
        definition.start()
        self.addCleanup(definition.stop)
        state = patch.object(runtime, "_load_state_from_names", side_effect=lambda _names: copy.deepcopy(self.state))
        state.start()
        self.addCleanup(state.stop)
        self.add_role("publisher-readiness")

    def show_unit(self, unit, _deadline):
        return dict(self.properties[unit])

    def write_cgroup(self, role, *, pid=None):
        unit = self.names.unit(role)
        path = f"/{runtime._slice_name(self.names, role)}/{unit}"
        directory = self.cgroup_root / path.lstrip("/")
        directory.mkdir(parents=True)
        memory, cpu, tasks, _duration = policy.BUDGETS["publisher"]
        values = {
            "memory.max": str(memory), "memory.swap.max": "0",
            "cpu.max": f"{cpu * 1000} 100000", "pids.max": str(tasks),
            "memory.current": "0", "memory.swap.current": "0",
            "pids.current": "0" if pid is None else "1", "memory.oom.group": "1",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
            "cgroup.events": "populated 0\n" if pid is None else "populated 1\n",
            "cgroup.procs": "" if pid is None else str(pid) + "\n",
        }
        for name, content in values.items():
            (directory / name).write_text(content, encoding="ascii")
        return path, directory

    def add_role(self, role, *, child=None):
        unit = self.names.unit(role)
        cgroup, directory = self.write_cgroup(role, pid=None if child is None else child.pid)
        fragment = self.unit_root / unit
        fragment.write_bytes(b"synthetic owned unit definition\n")
        info = fragment.stat()
        definition = {"unit": unit, "sha256": hashlib.sha256(fragment.read_bytes()).hexdigest(),
                      "device": info.st_dev, "inode": info.st_ino}
        props = fixtures.RunnerRuntimeIdentityTests._manager_properties(None, self.names, "reaper", "yes")
        memory, cpu, tasks, duration = policy.BUDGETS["publisher"]
        props.update({
            "Id": unit, "Slice": runtime._slice_name(self.names, role),
            "FragmentPath": str(fragment), "ControlGroup": cgroup,
            "MemoryMax": str(memory), "CPUQuotaPerSecUSec": f"{cpu * 10000}us",
            "TasksMax": str(tasks), "RuntimeMaxUSec": f"{duration}s",
            "MainPID": "0" if child is None else str(child.pid),
            "ActiveState": "inactive" if child is None else "active",
            "SubState": "dead" if child is None else "running",
            "Environment": f"DOTUNNEL_GENERATION={self.state['nonce']} DOTUNNEL_RUN={self.names.run} "
                           f"DOTUNNEL_ATTEMPT={self.names.attempt} LANG=C.UTF-8 LC_ALL=C.UTF-8",
        })
        snapshot = runtime._cgroup_snapshot(cgroup, policy.BUDGETS["publisher"])
        observation = {
            "unit": unit, "role": role, "invocation_id": props["InvocationID"],
            "fragment_path": str(fragment), "definition_sha256": definition["sha256"],
            "control_group": cgroup, "slice": props["Slice"],
            "main_pid": int(props["MainPID"]), "control_pid": 0,
            "manager": runtime._manager_values(props), "cgroup": snapshot,
            "process": None if child is None else runtime.observe_process(child.pid).to_record(),
        }
        self.state["definitions"][role] = definition
        self.state["units"][role] = observation
        self.properties[unit] = props
        return directory

    def stopped(self, role="publisher-readiness"):
        props = self.properties[self.names.unit(role)]
        props.update({"ActiveState": "inactive", "SubState": "dead",
                      "MainPID": "0", "ControlPID": "0", "ControlGroup": ""})

    def deadline(self):
        return time.monotonic_ns() + 3 * runtime._NS

    def test_inactive_empty_manager_cgroup_retains_and_proves_the_recorded_generation(self):
        self.stopped()
        result = runtime._observe_unit(self.names, "publisher-readiness", self.deadline(), active=False)
        recorded = self.state["units"]["publisher-readiness"]
        self.assertEqual(result["invocation_id"], recorded["invocation_id"])
        self.assertEqual(result["manager"]["control_group"], "")
        self.assertEqual(result["control_group"], recorded["control_group"])
        self.assertEqual((result["cgroup"]["device"], result["cgroup"]["inode"]),
                         (recorded["cgroup"]["device"], recorded["cgroup"]["inode"]))
        self.assertFalse(result["cgroup"]["populated"])

    def test_removed_recorded_cgroup_is_positively_observed_after_owned_unit_stops(self):
        self.stopped()
        recorded = self.state["units"]["publisher-readiness"]
        directory = self.cgroup_root / recorded["control_group"].lstrip("/")
        directory.rename(directory.with_name(directory.name + ".old"))
        result = runtime._stop_owned_unit(self.names, "publisher-readiness", self.state, self.deadline())
        self.assertTrue(result["cgroup"]["observed_absent"])
        self.assertTrue(result["pids_gone"])
        self.assertEqual(result["invocation_id"], recorded["invocation_id"])

    def test_replacement_cgroup_generation_is_not_adopted(self):
        self.stopped()
        recorded = self.state["units"]["publisher-readiness"]
        directory = self.cgroup_root / recorded["control_group"].lstrip("/")
        directory.rename(directory.with_name(directory.name + ".old"))
        self.write_cgroup("publisher-readiness")
        with self.assertRaises(runtime.RuntimeFailure):
            runtime._observe_unit(self.names, "publisher-readiness", self.deadline(), active=False)

    def test_replacement_invocation_is_not_adopted(self):
        self.stopped()
        self.properties[self.names.unit("publisher-readiness")]["InvocationID"] = "b" * 32
        with self.assertRaises(runtime.RuntimeFailure):
            runtime._stop_owned_unit(self.names, "publisher-readiness", self.state, self.deadline())

    def test_live_recorded_process_birth_prevents_stopped_cgroup_acceptance(self):
        child = self.start_child()
        recorded = self.state["units"]["publisher-readiness"]
        recorded["cgroup"]["pids"] = [{"pid": child.pid, "birth": runtime.observe_process(child.pid).birth}]
        self.stopped()
        with self.assertRaises(runtime.RuntimeFailure):
            runtime._observe_unit(self.names, "publisher-readiness", self.deadline(), active=False)

    def test_empty_manager_path_without_a_recorded_actual_generation_is_refused(self):
        self.stopped()
        self.state["units"].clear()
        with self.assertRaises(runtime.RuntimeFailure):
            runtime._observe_unit(self.names, "publisher-readiness", self.deadline(), active=False)

    def test_both_owned_publishers_can_be_quiescent_with_empty_manager_paths(self):
        self.add_role("publisher-terminal")
        self.stopped("publisher-readiness")
        self.stopped("publisher-terminal")
        self.assertTrue(runtime._publishers_quiescent(self.names, self.state, self.deadline()))
        self.properties[self.names.unit("publisher-terminal")]["InvocationID"] = "b" * 32
        self.assertFalse(runtime._publishers_quiescent(self.names, self.state, self.deadline()))

    def test_missing_cgroup_observation_does_not_leave_owned_directory_descriptors(self):
        identity = self.cgroup_root.stat()
        def owned_descriptors():
            result = []
            for value in os.listdir("/proc/self/fd"):
                try:
                    info = os.fstat(int(value))
                except OSError:
                    continue
                if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                    result.append(int(value))
            return result
        before = set(owned_descriptors())
        try:
            for _ in range(4):
                with self.assertRaises(runtime.RuntimeFailure) as error:
                    runtime._open_cgroup("/missing-owned-generation")
                self.assertEqual(error.exception.code, "cgroup-removed")
            self.assertEqual(set(owned_descriptors()), before)
        finally:
            for fd in set(owned_descriptors()) - before:
                # Recheck exact owned directory identity before closing a leak.
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                    os.close(fd)

    def start_child(self):
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(30)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        self.addCleanup(child.wait, timeout=3)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        return child

    def prepare_timeout_store(self):
        child = self.start_child()
        role = "publisher-readiness"
        directory = self.cgroup_root / self.state["units"][role]["control_group"].lstrip("/")
        directory.rename(directory.with_name(directory.name + ".old"))
        self.add_role(role, child=child)
        parent_path = self.root / "authority"
        parent_path.mkdir(mode=0o700)
        parent_fd = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, parent_fd)
        owner = patch.object(prepare, "_ROOT_UID", os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        binding = {"commit": "a" * 40, "closure_sha256": "b" * 64}
        store = prepare.AuthorityStore.create(parent_fd, self.context, binding)
        self.addCleanup(store.close)
        source = {
            **binding, "files": {}, "upload_action_commit": runtime._UPLOAD_ACTION_COMMIT,
            "source_path": self.names.source,
            # Synthetic Root source metadata; no Root source directory created.
            "source_directory": {"device": 1, "inode": 2, "uid": 0, "gid": 0, "mode": 0o500, "nlink": 2},
        }
        handoff = runtime.Handoff(self.context, runtime.observe_process(os.getpid()), "normal",
                                  time.monotonic_ns() + 60 * runtime._NS, {})
        state = runtime._make_initial_state(self.names, handoff, source, store.nonce)
        state["definitions"] = copy.deepcopy(self.state["definitions"])
        state["units"] = copy.deepcopy(self.state["units"])
        state["original_cause"] = "original-consumer-failure"
        store.save_runtime_state(state, initial=True)
        self.state = state
        return child, store, parent_fd, binding

    def test_publisher_deadline_stops_before_the_same_deadline_and_persists_unknown(self):
        child, store, parent_fd, binding = self.prepare_timeout_store()
        deadline = time.monotonic_ns() + runtime._NS
        def systemctl(_args, stop_deadline, **_kwargs):
            return runtime._bounded_command(
                [sys.executable, "-I", "-S", "-B", "-c",
                 f"import os, signal; os.kill({child.pid}, signal.SIGTERM)"],
                stop_deadline, allowed={sys.executable})[1]
        with patch.object(runtime, "_systemctl", side_effect=systemctl):
            try:
                runtime._wait_publisher_quiescent(self.names, store, "readiness", deadline)
            except runtime.RuntimeFailure:
                pass
        reopened = prepare.AuthorityStore.open(parent_fd, self.context, binding)
        self.addCleanup(reopened.close)
        state = reopened.read_runtime_state()
        self.assertEqual(state["publication"]["readiness"]["state"], "UNKNOWN")
        self.assertEqual(state["original_cause"], "original-consumer-failure")
        self.assertEqual(child.wait(timeout=3), -signal.SIGTERM)
        self.assertLess(time.monotonic_ns(), deadline)

    def test_stop_failure_still_persists_unknown_without_replacing_the_original_cause(self):
        _child, store, parent_fd, binding = self.prepare_timeout_store()
        deadline = time.monotonic_ns() + runtime._NS
        def systemctl(_args, stop_deadline, **_kwargs):
            return runtime._bounded_command([sys.executable, "-I", "-S", "-B", "-c", "raise SystemExit(7)"],
                                            stop_deadline, allowed={sys.executable})[1]
        with patch.object(runtime, "_systemctl", side_effect=systemctl):
            with self.assertRaises(runtime.RuntimeFailure):
                runtime._wait_publisher_quiescent(self.names, store, "readiness", deadline)
        reopened = prepare.AuthorityStore.open(parent_fd, self.context, binding)
        self.addCleanup(reopened.close)
        state = reopened.read_runtime_state()
        self.assertEqual(state["publication"]["readiness"]["state"], "UNKNOWN")
        self.assertEqual(state["original_cause"], "original-consumer-failure")


if __name__ == "__main__":
    unittest.main()
