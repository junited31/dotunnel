import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

import test_release_verify_runner_runtime as runtime_fixtures


class RunnerControlConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = runtime_fixtures.RunnerRuntimeControlTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def _send(self, request, *, timeout=0.5, path=None):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        with client:
            client.connect(str(path or self.fixture.path))
            client.sendall(json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n")
            raw = bytearray()
            while b"\n" not in raw:
                piece = client.recv(4096)
                if not piece:
                    break
                raw.extend(piece)
                self.assertLessEqual(len(raw), 64 * 1024)
        self.assertTrue(raw.endswith(b"\n"), "control peer closed before a complete reply")
        return json.loads(bytes(raw[:-1]))

    def _blocked_status(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []
        original = self.fixture._status_probe

        def probe():
            calls.append(time.monotonic_ns())
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release delayed STATUS probe")
            return original()

        self.fixture.state.status_probe = probe
        return entered, release, calls

    def _status_request_thread(self, result, done, *, timeout=3):
        def request_status():
            try:
                result["status"] = self._send({"op": "STATUS"}, timeout=timeout)
            except BaseException as error:
                result["error"] = error
            finally:
                done.set()

        thread = threading.Thread(target=request_status, name="test-control-status-client")
        thread.start()
        return thread

    def test_first_cancel_is_acknowledged_within_delivery_budget_while_status_probe_waits(self):
        entered, release, probe_calls = self._blocked_status()
        status_result = {}
        status_done = threading.Event()
        status_client_thread = self._status_request_thread(status_result, status_done)
        self.addCleanup(lambda: (release.set(), status_client_thread.join(2)))

        self.assertTrue(entered.wait(1), "STATUS did not enter its deliberately delayed live probe")
        notice_ns = time.monotonic_ns()
        deadline_ns = notice_ns + 1_000_000_000
        try:
            ack = self._send(
                {"op": "CANCEL", "notice_ns": str(notice_ns)},
                timeout=max(0.01, (deadline_ns - time.monotonic_ns()) / 1_000_000_000),
            )
            self.assertLessEqual(time.monotonic_ns(), deadline_ns, "CANCEL exceeded the dispatcher's fixed 1s budget")
            self.assertEqual(set(ack), {
                "schema", "tag", "run", "attempt", "cancel_ack", "cancel_notice_ns",
                "cancel_received_ns", "boot_id", "nonce", "source",
            })
            self.assertEqual(ack["schema"], 1)
            self.assertEqual(ack["tag"], "CANCEL_ACK")
            self.assertEqual(ack["run"], self.fixture.context["run"])
            self.assertEqual(ack["attempt"], self.fixture.context["attempt"])
            self.assertEqual(ack["cancel_ack"], True)
            self.assertEqual(ack["cancel_notice_ns"], str(notice_ns))
            self.assertGreaterEqual(int(ack["cancel_received_ns"]), notice_ns)
            self.assertEqual(ack["boot_id"], self.fixture.state.boot_id)
            self.assertEqual(ack["nonce"], self.fixture.state.nonce)
            self.assertEqual(ack["source"], self.fixture.source)
            self.assertNotIn("running", ack, "a CANCEL acknowledgement must not imply cached child liveness")
            self.assertEqual(json.loads(self.fixture.cancel_receipt_path.read_text(encoding="ascii")), self.fixture.state.cancel_notice)
            self.assertEqual(len(probe_calls), 1, "CANCEL must not call the blocked STATUS probe")
            self.assertFalse(status_done.is_set(), "the STATUS reply should still be waiting for the released probe")
        finally:
            release.set()

        self.assertTrue(status_done.wait(1), "the accepted STATUS request was not reaped after its probe returned")
        self.assertNotIn("error", status_result)
        self.assertTrue(status_result["status"]["cancel_ack"])
        self.assertEqual(len(probe_calls), 1)
        self.assertEqual(self.fixture.cancel_receipt_path.read_text(encoding="ascii"),
                         json.dumps(self.fixture.state.cancel_notice, separators=(",", ":")))


    def test_slow_status_has_one_handler_and_additional_status_requests_are_not_queued(self):
        entered, release, probe_calls = self._blocked_status()
        first_result = {}
        first_done = threading.Event()
        first_client_thread = self._status_request_thread(first_result, first_done)
        self.addCleanup(lambda: (release.set(), first_client_thread.join(2)))

        self.assertTrue(entered.wait(1), "first STATUS did not start")
        workers_before = {
            thread.ident for thread in threading.enumerate()
            if thread.name == "runner-control-status"
        }
        self.assertEqual(len(workers_before), 1, "server must admit only one slow STATUS handler")
        for _ in range(4):
            denied = self._send({"op": "STATUS"})
            self.assertEqual(denied, {"error": "control peer refused"})
        workers_after = {
            thread.ident for thread in threading.enumerate()
            if thread.name == "runner-control-status"
        }
        self.assertEqual(workers_after, workers_before, "busy STATUS requests must not create queued handlers")
        self.assertEqual(len(probe_calls), 1)
        with self.fixture.server._lifecycle_lock:
            self.assertLessEqual(len(self.fixture.server._connections), 2, "accepted sockets exceed the fixed handler lanes")

        release.set()
        self.assertTrue(first_done.wait(1))
        self.assertNotIn("error", first_result)
        status_worker = self.fixture.server._status_thread
        self.assertIsNotNone(status_worker)
        status_worker.join(1)
        self.assertFalse(status_worker.is_alive(), "completed STATUS handler thread was not reaped")
        self.assertFalse(any(
            thread.name == "runner-control-status" for thread in threading.enumerate()
        ), "an extra STATUS handler thread remains")

    def test_peer_authentication_and_cancel_replay_rules_are_preserved(self):
        notice_ns = time.monotonic_ns()
        script = (
            "import json,socket,sys;"
            "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
            "s.settimeout(2);s.connect(sys.argv[1]);"
            "s.sendall((json.dumps({'op':'CANCEL','notice_ns':sys.argv[2]},separators=(',',':'))+'\\n').encode());"
            "print(s.recv(4096).decode('ascii'));s.close()"
        )
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-c", script, str(self.fixture.path), str(notice_ns)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=True,
        )
        self.assertEqual(json.loads(child.stdout), {"error": "control peer refused"})
        self.assertIsNone(self.fixture.state.cancel_notice)
        self.assertFalse(self.fixture.cancel_receipt_path.exists())

        malformed = self._send({"op": "CANCEL", "notice_ns": "01"})
        self.assertEqual(malformed, {"error": "control peer refused"})
        self.assertIsNone(self.fixture.state.cancel_notice)
        self.assertFalse(self.fixture.cancel_receipt_path.exists())

        accepted_notice = time.monotonic_ns()
        original = self._send({"op": "CANCEL", "notice_ns": str(accepted_notice)})
        self.assertTrue(original["cancel_ack"])
        persisted_before = self.fixture.cancel_receipt_path.read_bytes()
        live_probe = self.fixture.state.live_probe
        live_calls = []

        def counted_live_probe():
            live_calls.append(None)
            return live_probe()

        self.fixture.state.live_probe = counted_live_probe
        exact_retry = self._send({"op": "CANCEL", "notice_ns": str(accepted_notice)})
        self.assertEqual(exact_retry, original, "exact immutable-notice transport retries stay idempotent")
        distinct_notice = max(accepted_notice + 1, time.monotonic_ns())
        distinct_replay = self._send({"op": "CANCEL", "notice_ns": str(distinct_notice)})
        self.assertEqual(distinct_replay, {"error": "control peer refused"})
        malformed_replay = self._send({"op": "CANCEL", "notice_ns": "0"})
        self.assertEqual(malformed_replay, {"error": "control peer refused"})
        self.assertEqual(len(live_calls), 0, "replays must not produce a new live-at-notice proof")
        self.assertEqual(self.fixture.cancel_receipt_path.read_bytes(), persisted_before)
        self.assertEqual(json.loads(persisted_before), self.fixture.state.cancel_notice)

    def test_close_reaps_owned_connections_and_threads_before_endpoint_disposal(self):
        entered, release, _probe_calls = self._blocked_status()
        client_box = {}
        client_done = threading.Event()

        def hold_status_client():
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client_box["socket"] = client
            client.settimeout(3)
            try:
                client.connect(str(self.fixture.path))
                client.sendall(b'{"op":"STATUS"}\n')
                while client.recv(4096):
                    pass
            except OSError:
                pass
            finally:
                client.close()
                client_done.set()

        client_thread = threading.Thread(target=hold_status_client, name="test-control-held-client")
        client_thread.start()
        self.addCleanup(lambda: (release.set(), client_thread.join(2)))
        self.assertTrue(entered.wait(1), "STATUS handler did not begin")

        close_done = threading.Event()
        close_error = []

        def close_server():
            try:
                self.fixture.server.close()
            except BaseException as error:
                close_error.append(error)
            finally:
                close_done.set()

        closer = threading.Thread(target=close_server, name="test-control-close")
        closer.start()
        self.addCleanup(lambda: (release.set(), closer.join(2)))
        deadline = time.monotonic() + 1
        while not self.fixture.server.closed and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertTrue(self.fixture.server.closed, "close did not begin")
        self.assertFalse(close_done.is_set(), "endpoint close must wait for the owned STATUS handler")
        self.assertTrue(self.fixture.path.exists(), "endpoint was disposed before owned handlers were reaped")

        release.set()
        self.assertTrue(close_done.wait(2), "server close did not finish after STATUS probe returned")
        self.assertFalse(close_error)
        closer.join(1)
        self.fixture.thread.join(1)
        client_thread.join(1)
        self.assertFalse(closer.is_alive())
        self.assertFalse(self.fixture.thread.is_alive(), "accept thread was not reaped")
        self.assertFalse(client_thread.is_alive(), "client socket thread was not reaped")
        self.assertTrue(client_done.is_set())
        with self.fixture.server._lifecycle_lock:
            self.assertEqual(self.fixture.server._connections, set(), "accepted server sockets were not released")
        self.assertFalse(self.fixture.path.exists(), "owned endpoint remains after server close")
        self.assertFalse(any(
            thread.name == "runner-control-status" for thread in threading.enumerate()
        ), "accepted STATUS handler remains after endpoint disposal")

    def test_close_preserves_a_replacement_socket(self):
        os.unlink(self.fixture.path)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(self.fixture.path))
        replacement.listen(1)
        replacement.settimeout(1)
        self.addCleanup(replacement.close)

        self.fixture.server.close()
        self.fixture.thread.join(1)
        self.assertFalse(self.fixture.thread.is_alive())
        self.assertTrue(self.fixture.path.exists(), "server close removed a replacement endpoint")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(1)
        with client:
            client.connect(str(self.fixture.path))
            accepted, _address = replacement.accept()
            accepted.close()
