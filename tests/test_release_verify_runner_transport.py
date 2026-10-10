"""Real local TLS/HTTP scheduling; not namespace or GitHub authority proof."""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit

fixtures = importlib.import_module("test_release_verify_runner_artifact")


class RunnerTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = importlib.import_module("tools.release_verify.runner_artifact")
        cls.directory = tempfile.TemporaryDirectory(prefix="dotunnel-transport-tls-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        cls.certificate = root / "certificate.pem"
        key = root / "key.pem"
        # Generated test-only key, never committed or published. No root/network.
        subprocess.run(
            ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cls.certificate), "-days", "1",
             "-subj", "/CN=local-transport-fixture"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=3, check=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(str(cls.certificate), str(key))
        cls.client_context = ssl.create_default_context(cafile=str(cls.certificate))
        cls.client_context.check_hostname = False

    def setUp(self):
        self.policy = self.artifact.ArtifactGuardPolicy(
            results_url=fixtures._RESULTS_ORIGIN,
            runtime_token=fixtures._RUNTIME_TOKEN,
            run_backend_id=fixtures._RUN_BACKEND_ID,
            job_backend_id=fixtures._JOB_BACKEND_ID,
            artifact_name=fixtures._ARTIFACT_NAME,
        )
        artifact = self.artifact
        context = self.server_context
        owner = self

        class LocalTransportGuard(artifact.BoundedTLSGuard):
            """Only substitute upstream network authority with a local fixture.

            Actual request parser, TLS interceptor, exchange lock, response
            parser and publication state machine remain production code.
            Namespace/DNS/public upstream TLS are intentionally not exercised.
            """
            def __init__(self):
                self.policy = owner.policy
                self.deadline_ns = time.monotonic_ns() + 4_000_000_000
                self.context_for_host = lambda _host: context
                self._stop = threading.Event()
                self.sockets = set()
                self.socket_lock = threading.Lock()
                self.threads = []
                self.failures = []

            def track(self, connection):
                with self.socket_lock:
                    self.sockets.add(connection)
                return connection

            def _replace_socket(self, old, new):
                with self.socket_lock:
                    self.sockets.discard(old)
                    self.sockets.add(new)

            def _close_socket(self, connection):
                with self.socket_lock:
                    self.sockets.discard(connection)
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()

            def start_thread(self, operation):
                def run():
                    try:
                        operation()
                    except Exception as error:
                        self.failures.append(type(error).__name__)
                thread = threading.Thread(target=run)
                self.threads.append(thread)
                thread.start()

            def _open_upstream(self, _host):
                client, server = socket.socketpair()
                self.track(client)
                self.track(server)
                def respond():
                    try:
                        channel = artifact._Wire(server, self.deadline_ns)
                        _method, target, _version, _headers, _body = artifact._read_request(channel)
                        if target.endswith("/CreateArtifact"):
                            status, body = 200, fixtures._signed_response()
                        elif target.endswith("/FinalizeArtifact"):
                            status = 200
                            body = json.dumps({"ok": True, "artifactId": str(fixtures._ARTIFACT_ID)}).encode()
                        else:
                            status, body = 201, b""
                        channel.sendall(
                            f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                            + body
                        )
                    finally:
                        self._close_socket(server)
                self.start_thread(respond)
                return client

        self.guard = LocalTransportGuard()
        self.addCleanup(self.close_transport)

    def close_transport(self):
        self.guard._stop.set()
        with self.guard.socket_lock:
            connections = tuple(self.guard.sockets)
        for connection in connections:
            self.guard._close_socket(connection)
        for thread in self.guard.threads:
            thread.join(timeout=1)
        self.assertFalse(any(thread.is_alive() for thread in self.guard.threads))

    def tunnel(self, host):
        client, server = socket.socketpair()
        self.guard.track(client)
        self.guard.track(server)
        self.guard.start_thread(lambda: self.guard._handle_client(server))
        channel = self.artifact._Wire(client, self.guard.deadline_ns)
        channel.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        self.assertEqual(channel.read_until(b"\r\n\r\n", 4096), b"HTTP/1.1 200 Connection Established\r\n\r\n")
        client.settimeout(1)
        secure = self.client_context.wrap_socket(client, server_hostname=host)
        self.guard._replace_socket(client, secure)
        # The independent test deadline rejects starvation before the guard's
        # four-second manager-equivalent deadline can expire.
        return self.artifact._Wire(secure, time.monotonic_ns() + 1_000_000_000)

    def request(self, channel, method, url, body, headers=()):
        parts = urlsplit(url)
        target = parts.path + ("?" + parts.query if parts.query else "")
        fields = [("Host", parts.hostname), ("Content-Length", str(len(body))), *headers]
        raw = f"{method} {target} HTTP/1.1\r\n".encode()
        raw += b"".join(f"{key}: {value}\r\n".encode() for key, value in fields)
        channel.sendall(raw + b"\r\n" + body)
        return self.artifact._read_response(channel)

    def test_idle_authorized_tls_tunnel_does_not_starve_create(self):
        host = urlsplit(fixtures._RESULTS_ORIGIN).hostname
        idle = self.tunnel(host)
        active = self.tunnel(host)
        status, _headers, response = self.request(
            active, "POST", fixtures._RESULTS_RPC, fixtures._create_body(),
            (("Authorization", "Bearer " + fixtures._RUNTIME_TOKEN), ("Content-Type", "application/json")),
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(response), json.loads(fixtures._signed_response()))
        self.assertFalse(self.policy.finalized)

    def test_idle_successful_stage_tunnel_does_not_starve_commit_and_finalize(self):
        # Establish previously authenticated Create state; this test isolates
        # Azure's stage-on-one-connection, commit-on-another scheduling boundary.
        self.policy.validate_request(
            "POST", fixtures._RESULTS_RPC,
            {"Authorization": "Bearer " + fixtures._RUNTIME_TOKEN, "Content-Type": "application/json"},
            fixtures._create_body(),
        )
        self.policy.validate_response_status(200)
        self.policy.accept_create_response(fixtures._signed_response())
        blob_host = urlsplit(fixtures._SIGNED_BLOB_URL).hostname
        stage = self.tunnel(blob_host)
        chunk = b"synthetic-local-artifact-zip-bytes"
        status, _headers, _body = self.request(
            stage, "PUT", fixtures._azure_block_url(component="block", block_id=fixtures._BLOCK_ID), chunk,
        )
        self.assertEqual(status, 201)
        commit = self.tunnel(blob_host)
        blocklist = f'<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>{fixtures._BLOCK_ID}</Latest></BlockList>'.encode()
        status, _headers, _body = self.request(
            commit, "PUT", fixtures._azure_block_url(component="blocklist"), blocklist,
            (("x-ms-blob-content-type", "zip"),),
        )
        self.assertEqual(status, 201)
        result = self.tunnel(urlsplit(fixtures._RESULTS_ORIGIN).hostname)
        digest = hashlib.sha256(chunk).hexdigest()
        finalize = json.dumps({
            "workflow_run_backend_id": fixtures._RUN_BACKEND_ID,
            "workflow_job_run_backend_id": fixtures._JOB_BACKEND_ID,
            "name": fixtures._ARTIFACT_NAME, "size": str(len(chunk)), "hash": "sha256:" + digest,
        }, separators=(",", ":")).encode()
        status, _headers, _body = self.request(
            result, "POST", fixtures._RESULTS_RPC.replace("/CreateArtifact", "/FinalizeArtifact"), finalize,
            (("Authorization", "Bearer " + fixtures._RUNTIME_TOKEN), ("Content-Type", "application/json")),
        )
        self.assertEqual(status, 200)
        self.assertEqual((self.policy.finalized, self.policy.uploaded_size, self.policy.uploaded_digest), (True, len(chunk), digest))


if __name__ == "__main__":
    unittest.main()
