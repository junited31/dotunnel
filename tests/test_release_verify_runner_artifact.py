"""Pure security-consumer regressions for the pinned artifact publisher."""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_MODULE_NAME = "tools.release_verify.runner_artifact"
_FEATURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "release_verify"
    / "runner_artifact.py"
)

_RESULTS_ORIGIN = "https://results.actions.githubusercontent.com"
_RESULTS_RPC = (
    _RESULTS_ORIGIN
    + "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact"
)
_RUNTIME_TOKEN = "synthetic-runtime-token-never-forward"
_RUN_BACKEND_ID = "1234567890123456789"
_ACTIONS_RUN_ID = "987654321"
_JOB_BACKEND_ID = "2345678901234567890"
_ARTIFACT_NAME = "dotunnelpilot1234567890123456789a1"
_ARTIFACT_ID = 67890
_ARTIFACT_SHA256 = "a" * 64

_SAS_SECRET = "synthetic-sas-signature-never-log"
_SAS_QUERY = (
    ("sv", "2023-11-03"),
    ("se", "2099-01-01T00:00:00Z"),
    ("sp", "cw"),
    ("sr", "b"),
    ("sig", _SAS_SECRET),
)
_SIGNED_BLOB_URL = (
    "https://runner-artifacts.blob.core.windows.net/container/runner.zip?"
    + urlencode(_SAS_QUERY)
)
_BLOCK_ID_PREFIX = "01234567-89ab-cdef-0123-456789abcdef"
_BLOCK_ID = base64.b64encode(
    (_BLOCK_ID_PREFIX + "0" * (48 - len(_BLOCK_ID_PREFIX))).encode("ascii")
).decode("ascii")


def _create_body(**updates: object) -> bytes:
    request: dict[str, object] = {
        "workflow_run_backend_id": _RUN_BACKEND_ID,
        "workflow_job_run_backend_id": _JOB_BACKEND_ID,
        "name": _ARTIFACT_NAME,
        "version": 4,
    }
    request.update(updates)
    return json.dumps(request, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _signed_response(url: str = _SIGNED_BLOB_URL) -> bytes:
    return json.dumps(
        {"ok": True, "signedUploadUrl": url},
        separators=(",", ":"),
    ).encode("utf-8")


def _azure_block_url(*, component: str, block_id: str | None = None) -> str:
    parts = urlsplit(_SIGNED_BLOB_URL)
    query = list(parse_qsl(parts.query, keep_blank_values=True))
    query.append(("comp", component))
    if block_id is not None:
        query.append(("blockid", block_id))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

def _mutate_query(url: str, key: str, value: str | None = None) -> str:
    parts = urlsplit(url)
    query = list(parse_qsl(parts.query, keep_blank_values=True))
    result = []
    replaced = False
    for name, item in query:
        if name == key and not replaced:
            replaced = True
            if value is not None:
                result.append((name, value))
        else:
            result.append((name, item))
    if not replaced and value is not None:
        result.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(result), ""))



def _gha_output_record(key: str, value: str, delimiter: str) -> bytes:
    return f"{key}<<{delimiter}\n{value}\n{delimiter}\n".encode("utf-8")


def _gha_output(
    *,
    artifact_id: str = str(_ARTIFACT_ID),
    digest: str = _ARTIFACT_SHA256,
    url: str | None = None,
) -> bytes:
    if url is None:
        url = (
            "https://github.com/junited31/dotunnel/actions/runs/"
            f"{_ACTIONS_RUN_ID}/artifacts/{artifact_id}"
        )
    return b"".join(
        (
            _gha_output_record(
                "artifact-id", artifact_id,
                "ghadelimiter_01234567-89ab-cdef-0123-456789abcdef",
            ),
            _gha_output_record(
                "artifact-digest", digest,
                "ghadelimiter_11234567-89ab-cdef-0123-456789abcdef",
            ),
            _gha_output_record(
                "artifact-url", url,
                "ghadelimiter_21234567-89ab-cdef-0123-456789abcdef",
            ),
        )
    )


class _RunnerArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.artifact = importlib.import_module(_MODULE_NAME)
        except ModuleNotFoundError as error:
            if error.name == _MODULE_NAME and not _FEATURE_PATH.is_file():
                cls.artifact = None
            else:
                raise

    def setUp(self):
        if self.artifact is None:
            self.fail(
                "release verifier feature missing: expected "
                "tools/release_verify/runner_artifact.py"
            )

    def _policy(self, *, results_url: str = _RESULTS_ORIGIN):
        return self.artifact.ArtifactGuardPolicy(
            results_url=results_url,
            runtime_token=_RUNTIME_TOKEN,
            run_backend_id=_RUN_BACKEND_ID,
            job_backend_id=_JOB_BACKEND_ID,
            artifact_name=_ARTIFACT_NAME,
        )

    def _create(self, policy, body: bytes | None = None, *, headers=None):
        if headers is None:
            headers = {
                "Authorization": f"Bearer {_RUNTIME_TOKEN}",
                "Content-Type": "application/json",
            }
        result = policy.validate_request(
            "POST", _RESULTS_RPC, headers,
            _create_body() if body is None else body,
        )
        self.assertIsNone(policy.validate_response_status(200))
        return result

    def _armed_policy(self):
        policy = self._policy()
        self.assertIsNone(self._create(policy))
        self.assertIsNone(policy.accept_create_response(_signed_response()))
        return policy

    def _assert_rejected(self, operation, *, secrets=()):
        try:
            operation()
        except Exception as error:
            message = str(error)
        else:
            self.fail("unsafe artifact protocol input was accepted")
        for secret in secrets:
            self.assertNotIn(secret, message)

    def _validate_blob(self, policy, url: str, *, body: bytes = b"artifact-block", headers=None):
        result = policy.validate_request(
            "PUT", url, {} if headers is None else headers, body,
        )
        self.assertIsNone(policy.validate_response_status(201))
        return result


class ResultsServicePolicyTests(_RunnerArtifactTests):
    def test_create_artifact_accepts_the_exact_pinned_rpc_and_bound_request(self):
        policy = self._policy()

        self.assertIsNone(self._create(policy))

    def test_runtime_selected_results_origin_is_bound_not_replaced_by_fixture_host(self):
        origin = "https://results-receiver.actions.githubusercontent.com"
        policy = self._policy(results_url=origin)
        headers = {
            "Authorization": f"Bearer {_RUNTIME_TOKEN}",
            "Content-Type": "application/json",
        }
        rpc = origin + "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact"
        self.assertIsNone(policy.validate_request("POST", rpc, headers, _create_body()))
        self._assert_rejected(
            lambda: self._policy(results_url=origin).validate_request("POST", _RESULTS_RPC, headers, _create_body()),
            secrets=(_RUNTIME_TOKEN,),
        )

    def test_create_artifact_binds_run_job_name_and_v4_request_schema(self):
        mutations = (
            {"workflow_run_backend_id": "different-run"},
            {"workflow_job_run_backend_id": "different-job"},
            {"name": "other-artifact"},
            {"version": 3},
            {"version": True},
            {"unexpected": "field"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self._assert_rejected(
                    lambda mutation=mutation: self._create(
                        self._policy(), _create_body(**mutation),
                    )
                )

    def test_create_artifact_rejects_missing_duplicate_and_ambiguous_json_fields(self):
        valid = _create_body().decode("utf-8")
        malformed = (
            valid.replace('"name":"' + _ARTIFACT_NAME + '",', "", 1).encode(),
            valid.replace('"version":4', '"version":4,"version":4').encode(),
            valid.replace('"version":4', '"version":NaN').encode(),
            valid.encode() + b"{}",
            b"\xff",
        )
        for body in malformed:
            with self.subTest(body=body[:80]):
                self._assert_rejected(lambda body=body: self._create(self._policy(), body))

    def test_create_artifact_requires_runtime_bearer_and_json_content_type(self):
        invalid_headers = (
            {"Content-Type": "application/json"},
            {
                "Authorization": "Bearer wrong-runtime-token",
                "Content-Type": "application/json",
            },
            {
                "Authorization": f"Bearer {_RUNTIME_TOKEN}",
                "Content-Type": "text/plain",
            },
        )
        for headers in invalid_headers:
            with self.subTest(headers=headers):
                self._assert_rejected(
                    lambda headers=headers: self._create(
                        self._policy(), headers=headers,
                    ),
                    secrets=(_RUNTIME_TOKEN, "wrong-runtime-token"),
                )

    def test_create_artifact_rejects_wrong_origin_url_shape_and_proxy_credentials(self):
        policy = self._policy()
        headers = {
            "Authorization": f"Bearer {_RUNTIME_TOKEN}",
            "Content-Type": "application/json",
        }
        bad_urls = (
            "not-an-absolute-url",
            _RESULTS_RPC.replace("https://", "http://", 1),
            _RESULTS_RPC.replace(
                "https://results.actions.githubusercontent.com",
                "https://user:pass@results.actions.githubusercontent.com",
                1,
            ),
            _RESULTS_RPC.replace(
                "results.actions.githubusercontent.com",
                "results.actions.githubusercontent.com.attacker.invalid",
                1,
            ),
            _RESULTS_RPC.replace(
                "results.actions.githubusercontent.com", "127.0.0.1", 1,
            ),
            _RESULTS_RPC.replace(
                "results.actions.githubusercontent.com", "[::1]", 1,
            ),
            _RESULTS_RPC + "?redirect=https://attacker.invalid/",
            _RESULTS_RPC + "#fragment",
            _RESULTS_RPC.replace("/CreateArtifact", "/GetSignedArtifactURL"),
        )
        for url in bad_urls:
            with self.subTest(url=url):
                self._assert_rejected(
                    lambda url=url: policy.validate_request(
                        "POST", url, headers, _create_body(),
                    ),
                    secrets=(_RUNTIME_TOKEN,),
                )

        self._assert_rejected(
            lambda: policy.validate_request(
                "POST", _RESULTS_RPC,
                {**headers, "Proxy-Authorization": "Basic synthetic-proxy-secret"},
                _create_body(),
            ),
            secrets=(_RUNTIME_TOKEN, "synthetic-proxy-secret"),
        )

    def test_results_service_origin_rejects_http_and_private_configured_hosts(self):
        path = "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact"
        headers = {
            "Authorization": f"Bearer {_RUNTIME_TOKEN}",
            "Content-Type": "application/json",
        }
        for origin in (
            "http://results.actions.githubusercontent.com",
            "https://127.0.0.1",
            "https://10.0.0.7",
            "https://[::1]",
            "https://user:pass@results.actions.githubusercontent.com",
        ):
            with self.subTest(origin=origin):
                self._assert_rejected(
                    lambda origin=origin: self._policy(results_url=origin).validate_request(
                        "POST", origin.rstrip("/") + path, headers, _create_body(),
                    ),
                    secrets=(_RUNTIME_TOKEN,),
                )

    def test_unpinned_results_rpc_names_and_methods_are_rejected(self):
        policy = self._policy()
        headers = {
            "Authorization": f"Bearer {_RUNTIME_TOKEN}",
            "Content-Type": "application/json",
        }
        for method, rpc in (
            ("GET", _RESULTS_RPC),
            ("POST", _RESULTS_RPC.replace("/CreateArtifact", "/ListArtifacts")),
            ("POST", _RESULTS_RPC.replace("/CreateArtifact", "/DeleteArtifact")),
            ("POST", _RESULTS_RPC.replace("/CreateArtifact", "/MigrateArtifact")),
        ):
            with self.subTest(method=method, rpc=rpc):
                self._assert_rejected(
                    lambda method=method, rpc=rpc: policy.validate_request(
                        method, rpc, headers, _create_body(),
                    ),
                    secrets=(_RUNTIME_TOKEN,),
                )

    def test_finalize_artifact_uses_pinned_wire_fields_after_blob_upload(self):
        zip_chunk = b"synthetic-zip-payload"
        digest = hashlib.sha256(zip_chunk).hexdigest()
        finalize_url = _RESULTS_RPC.replace("/CreateArtifact", "/FinalizeArtifact")
        headers = {
            "Authorization": f"Bearer {_RUNTIME_TOKEN}",
            "Content-Type": "application/json",
        }
        body = {
            "workflow_run_backend_id": _RUN_BACKEND_ID,
            "workflow_job_run_backend_id": _JOB_BACKEND_ID,
            "name": _ARTIFACT_NAME,
            "size": str(len(zip_chunk)),
            "hash": f"sha256:{digest}",
        }

        policy = self._armed_policy()
        self._assert_rejected(
            lambda: policy.validate_request(
                "POST", finalize_url, headers,
                json.dumps(body, separators=(",", ":")).encode(),
            ),
            secrets=(_RUNTIME_TOKEN,),
        )
        self.assertIsNone(self._validate_blob(
            policy,
            _azure_block_url(component="block", block_id=_BLOCK_ID),
            body=zip_chunk,
        ))
        self.assertIsNone(self._validate_blob(
            policy,
            _azure_block_url(component="blocklist"),
            body=f"<BlockList><Latest>{_BLOCK_ID}</Latest></BlockList>".encode(),
            headers={"x-ms-blob-content-type": "zip"},
        ))
        self.assertIsNone(policy.validate_request(
            "POST", finalize_url, headers,
            json.dumps(body, separators=(",", ":")).encode(),
        ))
        self.assertIsNone(policy.validate_response_status(200))

        for key, value in (
            ("workflow_run_backend_id", "different-run"),
            ("workflow_job_run_backend_id", "different-job"),
            ("name", "other-artifact"),
            ("size", "-1"),
            ("hash", "sha256:not-a-digest"),
        ):
            with self.subTest(field=key):
                fresh = self._armed_policy()
                self.assertIsNone(self._validate_blob(
                    fresh,
                    _azure_block_url(component="block", block_id=_BLOCK_ID),
                    body=zip_chunk,
                ))
                self.assertIsNone(self._validate_blob(
                    fresh,
                    _azure_block_url(component="blocklist"),
                    body=f"<BlockList><Latest>{_BLOCK_ID}</Latest></BlockList>".encode(),
                    headers={"x-ms-blob-content-type": "zip"},
                ))
                invalid = {**body, key: value}
                self._assert_rejected(
                    lambda invalid=invalid, fresh=fresh: fresh.validate_request(
                        "POST", finalize_url, headers,
                        json.dumps(invalid, separators=(",", ":")).encode(),
                    ),
                    secrets=(_RUNTIME_TOKEN,),
                )

    def test_all_redirect_statuses_are_denied(self):
        policy = self._policy()
        for status in (300, 301, 302, 303, 307, 308, 399):
            with self.subTest(status=status):
                self._assert_rejected(lambda status=status: policy.validate_response_status(status))
        for status in (200, 201, 204):
            with self.subTest(status=status):
                self.assertIsNone(policy.validate_response_status(status))

    def test_create_response_is_required_before_blob_upload_and_is_single_use(self):
        policy = self._policy()
        stage_url = _azure_block_url(component="block", block_id=_BLOCK_ID)
        self._assert_rejected(
            lambda: self._validate_blob(policy, stage_url),
            secrets=(_RUNTIME_TOKEN, _SAS_SECRET),
        )

        self.assertIsNone(self._create(policy))
        self._assert_rejected(
            lambda: self._validate_blob(policy, stage_url),
            secrets=(_RUNTIME_TOKEN, _SAS_SECRET),
        )
        self.assertIsNone(policy.accept_create_response(_signed_response()))
        self._assert_rejected(
            lambda: policy.accept_create_response(_signed_response()),
            secrets=(_SAS_SECRET,),
        )


class BlobDestinationPolicyTests(_RunnerArtifactTests):
    def test_pinned_azure_stage_and_commit_queries_use_registered_destination(self):
        policy = self._armed_policy()
        zip_chunk = b"synthetic-zip-payload"
        stage_url = _azure_block_url(component="block", block_id=_BLOCK_ID)
        commit_url = _azure_block_url(component="blocklist")

        self.assertIsNone(self._validate_blob(policy, stage_url, body=zip_chunk))
        self.assertIsNone(self._validate_blob(
            policy,
            commit_url,
            body=f"<BlockList><Latest>{_BLOCK_ID}</Latest></BlockList>".encode(),
            headers={"x-ms-blob-content-type": "zip"},
        ))

    def test_blob_destination_rejects_changed_origin_path_sas_and_query_boundaries(self):
        valid_stage = _azure_block_url(component="block", block_id=_BLOCK_ID)
        original = urlsplit(valid_stage)
        bad_urls = (
            urlunsplit(("http", original.netloc, original.path, original.query, "")),
            urlunsplit((original.scheme, "attacker.blob.core.windows.net", original.path,
                        original.query, "")),
            urlunsplit((original.scheme, "attacker.blob.core.windows.net.invalid",
                        original.path, original.query, "")),
            urlunsplit((original.scheme, "user:pass@" + original.netloc,
                        original.path, original.query, "")),
            urlunsplit((original.scheme, original.netloc, "/container/other.zip",
                        original.query, "")),
            urlunsplit((original.scheme, original.netloc, original.path,
                        original.query.replace(_SAS_SECRET, "changed-signature"), "")),
            urlunsplit((original.scheme, original.netloc, original.path,
                        original.query.replace("sv=2023-11-03", "sv=2020-01-01"), "")),
            _mutate_query(valid_stage, "sig", "changed-signature"),
            _mutate_query(valid_stage, "sv", "2020-01-01"),
            _mutate_query(valid_stage, "sig", None),
            _mutate_query(valid_stage, "blockid", "not-a-block-id"),
            _mutate_query(valid_stage, "blockid", None),
            valid_stage + "&sig=duplicate-signature",
            valid_stage + "&comp=block",
            _azure_block_url(component="blocklist", block_id=_BLOCK_ID),
            valid_stage + "&unexpected=parameter",
            valid_stage.replace("comp=block", "comp=delete"),
            valid_stage + "&timeout=5",
        )
        for url in bad_urls:
            with self.subTest(url=url):
                policy = self._armed_policy()
                self._assert_rejected(
                    lambda url=url, policy=policy: self._validate_blob(policy, url),
                    secrets=(_RUNTIME_TOKEN, _SAS_SECRET, "changed-signature"),
                )

    def test_blob_transfer_never_receives_runtime_or_proxy_authority(self):
        stage_url = _azure_block_url(component="block", block_id=_BLOCK_ID)
        for header_name, header_value in (
            ("Authorization", f"Bearer {_RUNTIME_TOKEN}"),
            ("Proxy-Authorization", "Basic synthetic-proxy-secret"),
        ):
            with self.subTest(header=header_name):
                policy = self._armed_policy()
                self._assert_rejected(
                    lambda: self._validate_blob(
                        policy, stage_url,
                        headers={header_name: header_value},
                    ),
                    secrets=(_RUNTIME_TOKEN, _SAS_SECRET, "synthetic-proxy-secret"),
                )

    def test_signed_response_rejects_non_azure_userinfo_private_and_non_https_destinations(self):
        bad_urls = (
            "http://runner-artifacts.blob.core.windows.net/container/runner.zip?" + urlencode(_SAS_QUERY),
            "https://user:pass@runner-artifacts.blob.core.windows.net/container/runner.zip?" + urlencode(_SAS_QUERY),
            "https://127.0.0.1/container/runner.zip?" + urlencode(_SAS_QUERY),
            "https://[::1]/container/runner.zip?" + urlencode(_SAS_QUERY),
            "https://runner-artifacts.blob.core.windows.net.attacker.invalid/container/runner.zip?" + urlencode(_SAS_QUERY),
            "https://runner-artifacts.blob.core.windows.net/container/runner.zip?sv=2023-11-03",
        )
        for url in bad_urls:
            with self.subTest(url=url):
                policy = self._policy()
                self.assertIsNone(self._create(policy))
                self._assert_rejected(
                    lambda url=url, policy=policy: policy.accept_create_response(
                        _signed_response(url),
                    ),
                    secrets=(_RUNTIME_TOKEN, _SAS_SECRET),
                )

    def test_create_response_json_is_strict_bounded_and_does_not_leak_sas(self):
        policy = self._policy()
        self.assertIsNone(self._create(policy))
        valid = _signed_response()
        self.assertIsNone(policy.accept_create_response(valid))
        self.assertNotIn(_RUNTIME_TOKEN, repr(policy))
        self.assertNotIn(_SAS_SECRET, repr(policy))

        invalid_responses = (
            b'{"ok":true,"ok":true,"signedUploadUrl":"' + _SIGNED_BLOB_URL.encode() + b'"}',
            b'{"ok":true,"signedUploadUrl":"' + _SIGNED_BLOB_URL.encode() + b'"} trailing',
            b'{"ok":Infinity,"signedUploadUrl":"' + _SIGNED_BLOB_URL.encode() + b'"}',
            b'{"ok":1,"signedUploadUrl":"' + _SIGNED_BLOB_URL.encode() + b'"}',
            b'{"ok":false,"signedUploadUrl":"' + _SIGNED_BLOB_URL.encode() + b'"}',
            b'{"ok":true,"signedUploadUrl":null}',
            b'{"ok":true,"signedUploadUrl":"' + _SIGNED_BLOB_URL.encode()
            + b'","signedUploadUrl":"' + _SIGNED_BLOB_URL.encode() + b'"}',
            b"\xff",
            b" " * (16 * 1024 + 1) + valid,
        )
        for body in invalid_responses:
            with self.subTest(size=len(body), prefix=body[:36]):
                fresh = self._policy()
                self.assertIsNone(self._create(fresh))
                self._assert_rejected(
                    lambda body=body, fresh=fresh: fresh.accept_create_response(body),
                    secrets=(_RUNTIME_TOKEN, _SAS_SECRET),
                )


class PublisherOutputTests(_RunnerArtifactTests):
    def test_pinned_github_output_delimited_records_parse_to_bound_receipt(self):
        parsed = self.artifact.parse_publisher_output(_gha_output())

        self.assertEqual(parsed["artifact_id"], _ARTIFACT_ID)
        self.assertEqual(parsed["digest"], _ARTIFACT_SHA256)
        self.assertEqual(
            parsed["url"],
            "https://github.com/junited31/dotunnel/actions/runs/"
            f"{_ACTIONS_RUN_ID}/artifacts/{_ARTIFACT_ID}",
        )

    def test_publisher_output_rejects_duplicate_missing_unknown_and_malformed_records(self):
        one = _gha_output_record(
            "artifact-id", str(_ARTIFACT_ID),
            "ghadelimiter_01234567-89ab-cdef-0123-456789abcdef",
        )
        good = _gha_output()
        unknown = _gha_output_record(
            "unexpected", "value",
            "ghadelimiter_31234567-89ab-cdef-0123-456789abcdef",
        )
        bad_outputs = (
            good + one,
            good + unknown,
            _gha_output().replace(b"artifact-id<<", b"other-id<<", 1),
            _gha_output().replace(b"artifact-digest<<", b"extra<<", 1),
            good.replace(b"ghadelimiter_01234567-89ab-cdef-0123-456789abcdef\n",
                         b"ghadelimiter_different\n", 1),
            b"artifact-id=67890\nartifact-digest=" + _ARTIFACT_SHA256.encode()
            + b"\nartifact-url=https://github.com/junited31/dotunnel/actions/runs/"
            + _ACTIONS_RUN_ID.encode() + b"/artifacts/67890\n",
            good + b"x" * (4097 - len(good)),
        )
        for raw in bad_outputs:
            with self.subTest(size=len(raw), prefix=raw[:48]):
                self._assert_rejected(lambda raw=raw: self.artifact.parse_publisher_output(raw))

    def test_publisher_output_rejects_unsafe_id_digest_and_url_identity(self):
        invalid = (
            {"artifact_id": "0"},
            {"artifact_id": "-1"},
            {"artifact_id": "+1"},
            {"artifact_id": "9007199254740992"},
            {"artifact_id": "100000000000000000000"},
            {"digest": "A" * 64},
            {"digest": "sha256:" + _ARTIFACT_SHA256},
            {"digest": "a" * 63},
            {"url": "http://github.com/junited31/dotunnel/actions/runs/1/artifacts/67890"},
            {"url": "https://github.com.attacker.invalid/junited31/dotunnel/actions/runs/1/artifacts/67890"},
            {"url": "https://user@github.com/junited31/dotunnel/actions/runs/1/artifacts/67890"},
            {"url": "https://github.com/junited31/other/actions/runs/1/artifacts/67890"},
            {"url": "https://github.com/junited31/dotunnel/actions/runs/1/artifacts/67891"},
            {"url": "https://github.com/junited31/dotunnel/actions/runs/1/artifacts/67890?redirect=evil"},
            {"url": "https://github.com/junited31/dotunnel/actions/runs/0/artifacts/67890"},
            {"url": "https://github.com/junited31/dotunnel/actions/runs/-1/artifacts/67890"},
            {"url": "https://github.com/junited31/dotunnel/actions/runs/run/artifacts/67890"},
            {"url": "https://github.com/junited31/dotunnel/actions/runs/123456789012345678901/artifacts/67890"},
        )
        for mutation in invalid:
            with self.subTest(mutation=mutation):
                self._assert_rejected(
                    lambda mutation=mutation: self.artifact.parse_publisher_output(
                        _gha_output(**mutation),
                    )
                )

    def test_publisher_output_rejects_control_and_multiline_values(self):
        for field, value in (
            ("artifact-id", "67890\nartifact-digest=attacker"),
            ("artifact-digest", _ARTIFACT_SHA256 + "\r"),
            ("artifact-url", "https://github.com/junited31/dotunnel/\nartifacts/67890"),
        ):
            with self.subTest(field=field):
                raw = _gha_output()
                delimiter = {
                    "artifact-id": b"ghadelimiter_01234567-89ab-cdef-0123-456789abcdef",
                    "artifact-digest": b"ghadelimiter_11234567-89ab-cdef-0123-456789abcdef",
                    "artifact-url": b"ghadelimiter_21234567-89ab-cdef-0123-456789abcdef",
                }[field]
                start = raw.index(field.encode() + b"<<" + delimiter + b"\n")
                value_start = start + len(field.encode() + b"<<" + delimiter + b"\n")
                end = raw.index(b"\n" + delimiter + b"\n", value_start)
                replacement = _gha_output_record(field, value, delimiter.decode())
                raw = raw[:start] + replacement + raw[end + len(b"\n" + delimiter + b"\n"):]
                self._assert_rejected(
                    lambda raw=raw: self.artifact.parse_publisher_output(raw),
                )



if __name__ == "__main__":
    unittest.main()
