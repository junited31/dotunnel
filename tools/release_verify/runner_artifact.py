"""Strict policy and bounded transport for the pinned Actions artifact publisher.

The policy is deliberately independent of sockets so the trust decisions can be
used by the real publisher guard without coupling them to a particular HTTP
implementation.  The transport accepts only a local CONNECT proxy, verifies
upstream TLS, and opens external sockets from the held host network namespace
only while resolving and connecting to an already-authorized destination.
"""
from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import struct
import threading
import time
import xml.etree.ElementTree as ElementTree
import zlib
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any
from urllib.parse import quote, unquote_plus, urlsplit


_RESULTS_HOST_SUFFIX = ".actions.githubusercontent.com"
_CREATE_PATH = "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact"
_FINALIZE_PATH = "/twirp/github.actions.results.api.v1.ArtifactService/FinalizeArtifact"
_MAX_CONTROL = 16 * 1024
_MAX_ZIP = 128 * 1024
_MAX_OUTPUT = 4 * 1024
_MAX_SESSIONS = 5
_MAX_LIFETIME_NS = 30_000_000_000
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_UUID_TEXT = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PERCENT_BAD = re.compile(r"%(?![0-9A-Fa-f]{2})")
_BLOCK_ID_TEXT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[0-9]{12}$"
)
_CRITICAL_HEADERS = frozenset(
    {
        "host",
        "authorization",
        "proxy-authorization",
        "content-length",
        "transfer-encoding",
        "content-type",
        "content-encoding",
        "connection",
        "expect",
        "location",
        "x-ms-blob-content-type",
        "x-ms-version",
    }
)
_SAS_KEYS = frozenset(
    {
        "sv", "ss", "srt", "sp", "se", "st", "spr", "sip", "si", "sr", "sig",
        "rscc", "rscd", "rsce", "rscl", "rsct", "skoid", "sktid", "skt", "ske",
        "sks", "skv", "saoid", "suoid", "scid", "sdd", "ses",
    }
)
_REQUIRED_SAS_KEYS = frozenset({"sv", "se", "sp", "sr", "sig"})
_HOP_HEADERS = frozenset(
    {
        "connection", "proxy-connection", "keep-alive", "te", "trailer",
        "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization",
    }
)


class ArtifactGuardError(ValueError):
    """A sanitized policy or transport rejection with no request data attached."""

    def __repr__(self) -> str:
        return "ArtifactGuardError('artifact publication rejected')"


class _HeaderSet:
    __slots__ = ("pairs", "values")

    def __init__(self, pairs: tuple[tuple[str, str], ...], values: dict[str, tuple[str, ...]]):
        self.pairs = pairs
        self.values = values

    def one(self, name: str, *, required: bool = False) -> str | None:
        values = self.values.get(name.lower(), ())
        if len(values) > 1:
            _deny()
        if not values:
            if required:
                _deny()
            return None
        return values[0]


class _PendingAction:
    __slots__ = ("kind", "payload")

    def __init__(self, kind: str, payload: Any = None):
        self.kind = kind
        self.payload = payload


def _deny() -> None:
    raise ArtifactGuardError("artifact publication rejected")


def _valid_text(value: object, *, maximum: int, allow_empty: bool = False) -> bool:
    if type(value) is not str or len(value) > maximum or (not allow_empty and not value):
        return False
    for character in value:
        codepoint = ord(character)
        if codepoint < 0x20 or codepoint == 0x7F:
            return False
    return True


def _strict_json_object(raw: bytes, *, maximum: int = _MAX_CONTROL) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > maximum:
        _deny()

    def object_from_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _deny()
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        _deny()

    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except ArtifactGuardError:
        raise
    except Exception:
        raise ArtifactGuardError("invalid artifact JSON") from None
    if type(value) is not dict:
        _deny()
    return value


def _collect_headers(headers: object) -> _HeaderSet:
    if isinstance(headers, Mapping):
        source = headers.items()
    elif isinstance(headers, Iterable) and not isinstance(headers, (str, bytes, bytearray)):
        source = headers
    else:
        _deny()

    pairs: list[tuple[str, str]] = []
    values: dict[str, list[str]] = {}
    try:
        for pair in source:
            if not isinstance(pair, tuple) and not isinstance(pair, list):
                _deny()
            if len(pair) != 2:
                _deny()
            name, value = pair
            if type(name) is not str or not _HEADER_NAME.fullmatch(name):
                _deny()
            if type(value) is not str or len(value) > _MAX_CONTROL:
                _deny()
            if any(
                character in "\r\n"
                or (ord(character) < 0x20 and character != "\t")
                or ord(character) == 0x7F
                or ord(character) > 0xFF
                for character in value
            ):
                _deny()
            lower_name = name.lower()
            pairs.append((name, value.strip(" \t")))
            values.setdefault(lower_name, []).append(value.strip(" \t"))
    except ArtifactGuardError:
        raise
    except Exception:
        raise ArtifactGuardError("invalid HTTP headers") from None

    for name in _CRITICAL_HEADERS:
        if len(values.get(name, ())) > 1:
            _deny()
    if "proxy-authorization" in values:
        _deny()
    return _HeaderSet(tuple(pairs), {name: tuple(items) for name, items in values.items()})


def _validate_content_length(headers: _HeaderSet, body: bytes) -> None:
    value = headers.one("content-length")
    if value is None:
        return
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value):
        _deny()
    if int(value) != len(body):
        _deny()
    if headers.one("transfer-encoding") is not None:
        _deny()


def _validate_percent_escapes(value: str) -> None:
    if _PERCENT_BAD.search(value):
        _deny()
    try:
        decoded = unquote_plus(value, encoding="utf-8", errors="strict")
    except Exception:
        raise ArtifactGuardError("invalid URL encoding") from None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded):
        _deny()


def _valid_dns_name(host: str) -> bool:
    if not host or len(host) > 253 or not host.isascii() or host.endswith("."):
        return False
    labels = host.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def _parse_https_url(url: object) -> tuple[Any, str]:
    if not _valid_text(url, maximum=16 * 1024) or not url.isascii() or "\\" in url or "#" in url:
        _deny()
    try:
        parts = urlsplit(url)
        port = parts.port
    except Exception:
        raise ArtifactGuardError("invalid artifact URL") from None
    if (
        parts.scheme.lower() != "https"
        or not parts.netloc
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or port not in (None, 443)
        or not parts.hostname
    ):
        _deny()
    host = parts.hostname.lower()
    if not _valid_dns_name(host):
        _deny()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        _deny()
    _validate_percent_escapes(parts.path)
    _validate_percent_escapes(parts.query)
    if not parts.path.startswith("/"):
        _deny()
    return parts, host


def _parse_origin(value: object) -> tuple[str, str]:
    if not _valid_text(value, maximum=2048) or not value.isascii() or "\\" in value or "#" in value:
        _deny()
    try:
        parts = urlsplit(value)
        port = parts.port
    except Exception:
        raise ArtifactGuardError("invalid Results origin") from None
    if (
        parts.scheme.lower() != "https"
        or parts.username is not None
        or parts.password is not None
        or "?" in value
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
        or port not in (None, 443)
        or not parts.hostname
        or not parts.hostname.lower().endswith(_RESULTS_HOST_SUFFIX)
        or not _valid_dns_name(parts.hostname)
    ):
        _deny()
    host = parts.hostname.lower()
    return "https://" + host, host


def _parse_sas_query(raw_query: str) -> dict[str, str]:
    if not raw_query or len(raw_query) > 8192 or ";" in raw_query:
        _deny()
    result: dict[str, str] = {}
    for field in raw_query.split("&"):
        key, separator, value = field.partition("=")
        if not separator or not key or not value or not re.fullmatch(r"[a-z]+", key):
            _deny()
        if key not in _SAS_KEYS or key in result:
            _deny()
        _validate_percent_escapes(value)
        try:
            decoded = unquote_plus(value, encoding="utf-8", errors="strict")
        except Exception:
            raise ArtifactGuardError("invalid signed destination") from None
        if not decoded or any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded):
            _deny()
        result[key] = decoded
    if not _REQUIRED_SAS_KEYS.issubset(result):
        _deny()
    return result


def _blob_destination(url: object) -> tuple[str, str, str]:
    parts, host = _parse_https_url(url)
    if not host.endswith(".blob.core.windows.net") or host == "blob.core.windows.net":
        _deny()
    if not parts.path or parts.path == "/" or "//" in parts.path:
        _deny()
    try:
        decoded_path = unquote_plus(parts.path, encoding="utf-8", errors="strict")
    except Exception:
        raise ArtifactGuardError("invalid blob path") from None
    if any(segment in {".", ".."} for segment in decoded_path.split("/")) or "\\" in decoded_path:
        _deny()
    sas = _parse_sas_query(parts.query)
    if "comp" in sas or "blockid" in sas or "timeout" in sas:
        _deny()
    return host, parts.path, parts.query


def _block_id_value(value: str) -> str:
    if not value or len(value) > 128:
        _deny()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ArtifactGuardError("invalid Azure block identifier") from None
    if len(decoded) != 48 or base64.b64encode(decoded).decode("ascii") != value:
        _deny()
    try:
        text = decoded.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise ArtifactGuardError("invalid Azure block identifier") from None
    if not _BLOCK_ID_TEXT.fullmatch(text):
        _deny()
    return value


def _blocklist_ids(body: bytes) -> tuple[str, ...]:
    if type(body) is not bytes or not body or len(body) > _MAX_CONTROL:
        _deny()
    try:
        text = body.decode("utf-8", "strict")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
            _deny()
        root = ElementTree.fromstring(text)
    except ArtifactGuardError:
        raise
    except Exception:
        raise ArtifactGuardError("invalid Azure block list") from None
    if root.tag != "BlockList" or root.attrib or (root.text or "").strip():
        _deny()
    ids: list[str] = []
    for child in root:
        if child.tag != "Latest" or child.attrib or list(child) or child.tail and child.tail.strip():
            _deny()
        value = child.text
        if type(value) is not str:
            _deny()
        ids.append(_block_id_value(value))
    if not ids or len(set(ids)) != len(ids):
        _deny()
    return tuple(ids)


def _valid_backend_id(value: object) -> bool:
    if type(value) is not str or len(value) > 64:
        return False
    return bool(
        re.fullmatch(r"[1-9][0-9]{0,19}", value)
        or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value)
    )


class ArtifactGuardPolicy:
    """Pure, stateful policy for the pinned Create/upload/Finalize wire sequence."""

    def __init__(
        self,
        results_url: str,
        runtime_token: str,
        run_backend_id: str,
        job_backend_id: str,
        artifact_name: str,
    ) -> None:
        self._results_origin, self._results_host = _parse_origin(results_url)
        if not _valid_text(runtime_token, maximum=8192):
            _deny()
        if not _valid_backend_id(run_backend_id) or not _valid_backend_id(job_backend_id):
            _deny()
        if not _valid_text(artifact_name, maximum=128) or not re.fullmatch(r"[A-Za-z0-9._-]+", artifact_name):
            _deny()
        self._runtime_token = runtime_token
        self._run_backend_id = run_backend_id
        self._job_backend_id = job_backend_id
        self._artifact_name = artifact_name
        self._blob_host: str | None = None
        self._blob_path: str | None = None
        self._sas_query: str | None = None
        self._staged: dict[str, bytes] = {}
        self._blob_committed = False
        self._committed_ids: tuple[str, ...] | None = None
        self._committed_size = 0
        self._committed_digest: str | None = None
        self._create_response_ready = False
        self._create_response_consumed = False
        self._finalize_response_ready = False
        self._finalized = False
        self._pending: _PendingAction | None = None
        self._lock = threading.RLock()
        # The real transport serializes a complete request/response exchange.  The
        # lock makes that ordering explicit while allowing independent pure callers.
        self._exchange_lock = threading.Lock()

    def __repr__(self) -> str:
        return "ArtifactGuardPolicy()"

    def __str__(self) -> str:
        return "ArtifactGuardPolicy()"

    @property
    def uploaded_size(self) -> int:
        return self._committed_size

    @property
    def uploaded_digest(self) -> str | None:
        return self._committed_digest

    @property
    def finalized(self) -> bool:
        return self._finalized

    def _parse_rpc_request(self, path: str, body: bytes) -> tuple[str, dict[str, Any]]:
        request = _strict_json_object(body)
        if path == _CREATE_PATH:
            if self._blob_host is not None or self._create_response_consumed:
                _deny()
            if set(request) not in (
                {"workflow_run_backend_id", "workflow_job_run_backend_id", "name", "version"},
                {"workflow_run_backend_id", "workflow_job_run_backend_id", "name", "version", "expires_at"},
            ):
                _deny()
            if (
                request.get("workflow_run_backend_id") != self._run_backend_id
                or request.get("workflow_job_run_backend_id") != self._job_backend_id
                or request.get("name") != self._artifact_name
                or type(request.get("version")) is not int
                or request["version"] != 4
            ):
                _deny()
            if "expires_at" in request:
                expires_at = request["expires_at"]
                if type(expires_at) is not str or not _valid_text(expires_at, maximum=64):
                    _deny()
                if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", expires_at):
                    _deny()
                try:
                    datetime.fromisoformat(expires_at[:-1] + "+00:00")
                except ValueError:
                    _deny()
            return "create", request
        if path == _FINALIZE_PATH:
            if not self._blob_committed or self._finalized or self._finalize_response_ready:
                _deny()
            if set(request) != {
                "workflow_run_backend_id", "workflow_job_run_backend_id", "name", "size", "hash",
            }:
                _deny()
            size = request.get("size")
            digest = request.get("hash")
            if (
                request.get("workflow_run_backend_id") != self._run_backend_id
                or request.get("workflow_job_run_backend_id") != self._job_backend_id
                or request.get("name") != self._artifact_name
                or type(size) is not str
                or not re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", size)
                or int(size) != self._committed_size
                or type(digest) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                or digest[7:] != self._committed_digest
            ):
                _deny()
            return "finalize", request
        _deny()

    def _check_results_headers(self, headers: _HeaderSet) -> None:
        authorization = headers.one("authorization", required=True)
        if not hmac.compare_digest(authorization or "", "Bearer " + self._runtime_token):
            _deny()
        content_type = headers.one("content-type", required=True)
        if content_type is None or content_type.split(";", 1)[0].strip().lower() != "application/json":
            _deny()

    def _check_blob_query(self, url_parts: Any, block: bool) -> str | None:
        if self._blob_host is None or self._blob_path is None or self._sas_query is None:
            _deny()
        if url_parts.path != self._blob_path or not url_parts.query.startswith(self._sas_query + "&"):
            _deny()
        suffix = url_parts.query[len(self._sas_query) + 1 :]
        if block:
            match = re.fullmatch(r"comp=block&blockid=([^&]+)", suffix)
            if not match:
                _deny()
            encoded = match.group(1)
            block_id = unquote_plus(encoded, encoding="utf-8", errors="strict")
            _block_id_value(block_id)
            if quote(block_id, safe="") != encoded:
                _deny()
            return block_id
        if suffix != "comp=blocklist":
            _deny()
        return None

    def validate_request(self, method: str, url: str, headers: object, body: bytes) -> None:
        with self._lock:
            if self._pending is not None or type(method) is not str or type(body) is not bytes:
                _deny()
            if len(body) > _MAX_ZIP:
                _deny()
            header_set = _collect_headers(headers)
            _validate_content_length(header_set, body)
            if header_set.one("transfer-encoding") is not None:
                _deny()
            connection = header_set.one("connection")
            if connection is not None and any(token.strip().lower() not in {"close", "keep-alive"} for token in connection.split(",")):
                _deny()

            parts, host = _parse_https_url(url)
            host_header = header_set.one("host")
            if host_header is not None and host_header.lower() not in {host, host + ":443"}:
                _deny()

            if host == self._results_host and parts.scheme.lower() == "https":
                if parts.netloc.lower() not in {self._results_host, self._results_host + ":443"}:
                    _deny()
                if "?" in url or parts.query or parts.fragment or method != "POST" or len(body) > _MAX_CONTROL:
                    _deny()
                self._check_results_headers(header_set)
                kind, payload = self._parse_rpc_request(parts.path, body)
                self._pending = _PendingAction(kind, payload)
                return None

            if (
                self._blob_host is None
                or host != self._blob_host
                or parts.netloc.lower() not in {host, host + ":443"}
                or method != "PUT"
                or parts.fragment
                or header_set.one("authorization") is not None
                or len(body) > _MAX_ZIP
                or self._finalized
            ):
                _deny()
            runtime_token = self._runtime_token.encode("utf-8")
            if runtime_token in body or any(
                runtime_token in value.encode("utf-8") for _name, value in header_set.pairs
            ):
                _deny()
            if parts.query.startswith(self._sas_query + "&comp=block&"):
                if self._blob_committed:
                    _deny()
                block_id = self._check_blob_query(parts, True)
                if block_id is None:
                    _deny()
                previous = self._staged.get(block_id)
                if previous is not None and previous != body:
                    _deny()
                if previous is None and sum(map(len, self._staged.values())) + len(body) > _MAX_ZIP:
                    _deny()
                if not body:
                    _deny()
                self._pending = _PendingAction("stage", (block_id, body))
                return None
            if parts.query == self._sas_query + "&comp=blocklist":
                self._check_blob_query(parts, False)
                if header_set.one("x-ms-blob-content-type") != "zip":
                    _deny()
                ids = _blocklist_ids(body)
                if set(ids) != set(self._staged) or len(ids) != len(self._staged):
                    _deny()
                size = sum(len(self._staged[block_id]) for block_id in ids)
                if size <= 0 or size > _MAX_ZIP:
                    _deny()
                digest = hashlib.sha256()
                for block_id in ids:
                    digest.update(self._staged[block_id])
                self._pending = _PendingAction("blocklist", (ids, size, digest.hexdigest()))
                return None
            _deny()

    def validate_response_status(self, status: int) -> None:
        if type(status) is not int or not 100 <= status <= 599:
            _deny()
        with self._lock:
            if 300 <= status < 400:
                self._pending = None
                self._create_response_ready = False
                self._finalize_response_ready = False
                _deny()
            pending = self._pending
            if pending is None or status < 200:
                return None
            self._pending = None
            if not 200 <= status < 300:
                return None
            if pending.kind == "stage":
                if status != 201:
                    _deny()
                block_id, body = pending.payload
                prior = self._staged.get(block_id)
                if prior is not None and prior != body:
                    _deny()
                self._staged[block_id] = body
            elif pending.kind == "blocklist":
                if status != 201:
                    _deny()
                ids, size, digest = pending.payload
                self._blob_committed = True
                self._committed_ids = ids
                self._committed_size = size
                self._committed_digest = digest
            elif pending.kind == "create":
                self._create_response_ready = True
            elif pending.kind == "finalize":
                self._finalize_response_ready = True
        return None

    def accept_create_response(self, body: bytes) -> None:
        with self._lock:
            if not self._create_response_ready or self._create_response_consumed:
                _deny()
            self._create_response_ready = False
            self._create_response_consumed = True
            response = _strict_json_object(body)
            if set(response) != {"ok", "signedUploadUrl"} or response.get("ok") is not True:
                _deny()
            destination = response.get("signedUploadUrl")
            host, path, query = _blob_destination(destination)
            self._blob_host = host
            self._blob_path = path
            self._sas_query = query
        return None

    def accept_finalize_response(self, body: bytes) -> None:
        """Record finalization only after a bounded 2xx response with ``ok`` true."""
        with self._lock:
            if not self._finalize_response_ready or self._finalized:
                _deny()
            self._finalize_response_ready = False
            response = _strict_json_object(body)
            if set(response) != {"ok", "artifactId"} or response.get("ok") is not True:
                _deny()
            artifact_id = response.get("artifactId")
            if type(artifact_id) is not str or not re.fullmatch(r"[1-9][0-9]{0,15}", artifact_id):
                _deny()
            if int(artifact_id) > _MAX_SAFE_INTEGER:
                _deny()
            self._finalized = True
        return None

    def _discard_pending_response(self) -> None:
        with self._lock:
            self._pending = None
            self._create_response_ready = False
            self._finalize_response_ready = False

    def _connect_host_allowed(self, host: str) -> bool:
        with self._lock:
            return host == self._results_host or (self._blob_host is not None and host == self._blob_host)


def parse_publisher_output(raw: bytes) -> dict[str, object]:
    """Parse the pinned @actions/core heredoc records and bind their identities."""
    if type(raw) is not bytes or not raw or len(raw) > _MAX_OUTPUT:
        _deny()
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise ArtifactGuardError("invalid publisher output") from None
    if "\r" in text or any(ord(character) < 0x20 and character != "\n" for character in text):
        _deny()
    values: dict[str, str] = {}
    delimiters: set[str] = set()
    offset = 0
    while offset < len(text):
        match = re.match(
            r"(artifact-id|artifact-digest|artifact-url)<<ghadelimiter_(" + _UUID_TEXT + r")\n",
            text[offset:],
        )
        if match is None:
            _deny()
        key = match.group(1)
        delimiter = "ghadelimiter_" + match.group(2)
        if key in values or delimiter in delimiters:
            _deny()
        value_start = offset + match.end()
        end_marker = "\n" + delimiter + "\n"
        value_end = text.find(end_marker, value_start)
        if value_end < 0:
            _deny()
        value = text[value_start:value_end]
        if not value or "\n" in value or "\r" in value or delimiter in value:
            _deny()
        values[key] = value
        delimiters.add(delimiter)
        offset = value_end + len(end_marker)
    if set(values) != {"artifact-id", "artifact-digest", "artifact-url"}:
        _deny()

    artifact_id_text = values["artifact-id"]
    if not re.fullmatch(r"[1-9][0-9]{0,15}", artifact_id_text):
        _deny()
    artifact_id = int(artifact_id_text)
    if artifact_id > _MAX_SAFE_INTEGER:
        _deny()
    digest = values["artifact-digest"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        _deny()
    url = values["artifact-url"]
    match = re.fullmatch(
        r"https://github\.com/junited31/dotunnel/actions/runs/([1-9][0-9]{0,19})/artifacts/([1-9][0-9]{0,15})",
        url,
    )
    if match is None or int(match.group(2)) != artifact_id:
        _deny()
    return {"artifact_id": artifact_id, "digest": digest, "url": url}


class _Wire:
    """Small deadline-aware buffered channel for one HTTP/1.x socket."""

    __slots__ = ("sock", "deadline_ns", "buffer")

    def __init__(self, sock: socket.socket, deadline_ns: int):
        self.sock = sock
        self.deadline_ns = deadline_ns
        self.buffer = bytearray()

    def _remaining(self) -> float:
        remaining_ns = self.deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            _deny()
        return remaining_ns / 1_000_000_000

    def _recv(self, maximum: int) -> bytes:
        if maximum <= 0:
            _deny()
        try:
            self.sock.settimeout(self._remaining())
            value = self.sock.recv(maximum)
        except ArtifactGuardError:
            raise
        except Exception:
            raise ArtifactGuardError("bounded transport failed") from None
        if not value:
            raise ArtifactGuardError("bounded transport closed")
        return value

    def read_until(self, marker: bytes, maximum: int) -> bytes:
        while True:
            index = self.buffer.find(marker)
            if index >= 0:
                end = index + len(marker)
                if end > maximum:
                    _deny()
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            if len(self.buffer) >= maximum:
                _deny()
            self.buffer.extend(self._recv(min(4096, maximum - len(self.buffer))))

    def read_exact(self, count: int, maximum: int) -> bytes:
        if count < 0 or count > maximum:
            _deny()
        while len(self.buffer) < count:
            self.buffer.extend(self._recv(min(4096, count - len(self.buffer))))
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def read_to_eof(self, maximum: int) -> bytes:
        result = bytearray(self.buffer)
        self.buffer.clear()
        while True:
            if len(result) > maximum:
                _deny()
            try:
                self.sock.settimeout(self._remaining())
                chunk = self.sock.recv(min(4096, maximum + 1 - len(result)))
            except ArtifactGuardError:
                raise
            except Exception:
                raise ArtifactGuardError("bounded transport failed") from None
            if not chunk:
                return bytes(result)
            result.extend(chunk)

    def sendall(self, value: bytes) -> None:
        try:
            self.sock.settimeout(self._remaining())
            self.sock.sendall(value)
        except ArtifactGuardError:
            raise
        except Exception:
            raise ArtifactGuardError("bounded transport failed") from None


def _parse_http_headers(block: bytes, *, request: bool) -> tuple[str, _HeaderSet]:
    if not block.endswith(b"\r\n\r\n") or len(block) > _MAX_CONTROL:
        _deny()
    try:
        lines = block[:-4].split(b"\r\n")
        start = lines[0].decode("ascii", "strict")
        pairs: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line or line[:1] in (b" ", b"\t") or b":" not in line:
                _deny()
            raw_name, raw_value = line.split(b":", 1)
            name = raw_name.decode("ascii", "strict")
            value = raw_value.decode("latin-1", "strict")
            if not _HEADER_NAME.fullmatch(name):
                _deny()
            pairs.append((name, value.strip(" \t")))
    except ArtifactGuardError:
        raise
    except Exception:
        raise ArtifactGuardError("invalid HTTP message") from None
    headers = _collect_headers(pairs)
    return start, headers


def _read_request(channel: _Wire) -> tuple[str, str, str, _HeaderSet, bytes]:
    start, headers = _parse_http_headers(channel.read_until(b"\r\n\r\n", _MAX_CONTROL), request=True)
    try:
        pieces = start.split(" ")
        if len(pieces) != 3:
            _deny()
        method, target, version = pieces
        if version not in {"HTTP/1.0", "HTTP/1.1"} or not re.fullmatch(r"[A-Z]+", method):
            _deny()
        if not target.startswith("/") or "#" in target or "\\" in target:
            _deny()
        target.encode("ascii", "strict")
    except ArtifactGuardError:
        raise
    except Exception:
        raise ArtifactGuardError("invalid HTTP request") from None
    if method not in {"POST", "PUT"}:
        _deny()
    headers.one("host", required=True)
    if headers.one("transfer-encoding") is not None or headers.one("expect") is not None:
        _deny()
    content_length = headers.one("content-length")
    if content_length is None:
        length = 0
    elif re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", content_length):
        length = int(content_length)
    else:
        _deny()
    body_limit = _MAX_CONTROL if method == "POST" or "comp=blocklist" in target else _MAX_ZIP
    if length > body_limit:
        _deny()
    body = channel.read_exact(length, body_limit) if length else b""
    return method, target, version, headers, body


def _read_chunked(channel: _Wire, maximum: int) -> bytes:
    result = bytearray()
    while True:
        line = channel.read_until(b"\r\n", 1024)
        size_text = line[:-2]
        if b";" in size_text:
            size_text = size_text.split(b";", 1)[0]
        if not size_text or not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_text):
            _deny()
        size = int(size_text, 16)
        if size == 0:
            trailer_bytes = 0
            while True:
                trailer = channel.read_until(b"\r\n", _MAX_CONTROL)
                trailer_bytes += len(trailer)
                if trailer_bytes > _MAX_CONTROL:
                    _deny()
                if trailer == b"\r\n":
                    return bytes(result)
                if trailer[:1] in (b" ", b"\t") or b":" not in trailer:
                    _deny()
                name = trailer[:-2].split(b":", 1)[0].decode("ascii", "strict").lower()
                if name in _CRITICAL_HEADERS or name == "proxy-authorization":
                    _deny()
        if size > maximum - len(result):
            _deny()
        result.extend(channel.read_exact(size, maximum))
        if channel.read_exact(2, 2) != b"\r\n":
            _deny()


def _read_response(channel: _Wire) -> tuple[int, _HeaderSet, bytes]:
    for _ in range(6):
        start, headers = _parse_http_headers(channel.read_until(b"\r\n\r\n", _MAX_CONTROL), request=False)
        match = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", start)
        if match is None:
            _deny()
        status = int(match.group(1))
        if 100 <= status < 200:
            if status == 101:
                _deny()
            continue
        break
    else:
        _deny()

    content_length = headers.one("content-length")
    transfer_encoding = headers.one("transfer-encoding")
    if content_length is not None and transfer_encoding is not None:
        _deny()
    if status in {204, 304}:
        body = b""
    elif content_length is not None:
        if not re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", content_length):
            _deny()
        length = int(content_length)
        if length > _MAX_CONTROL:
            _deny()
        body = channel.read_exact(length, _MAX_CONTROL) if length else b""
    elif transfer_encoding is not None:
        if transfer_encoding.lower() != "chunked":
            _deny()
        body = _read_chunked(channel, _MAX_CONTROL)
    else:
        body = channel.read_to_eof(_MAX_CONTROL)
    return status, headers, body


def _rpc_response_body(headers: _HeaderSet, body: bytes) -> bytes:
    encoding = headers.one("content-encoding")
    if encoding is None or encoding.lower() == "identity":
        return body
    if encoding.lower() not in {"gzip", "deflate"}:
        _deny()
    try:
        window = zlib.MAX_WBITS | 16 if encoding.lower() == "gzip" else zlib.MAX_WBITS
        decompressor = zlib.decompressobj(window)
        decoded = decompressor.decompress(body, _MAX_CONTROL + 1)
        if len(decoded) > _MAX_CONTROL or decompressor.unconsumed_tail:
            _deny()
        decoded += decompressor.flush(_MAX_CONTROL + 1 - len(decoded))
        if len(decoded) > _MAX_CONTROL or not decompressor.eof or decompressor.unused_data:
            _deny()
        return decoded
    except ArtifactGuardError:
        raise
    except Exception:
        raise ArtifactGuardError("invalid compressed RPC response") from None


def _authority_host(authority: str) -> str:
    if not _valid_text(authority, maximum=512) or not authority.isascii() or "@" in authority or not authority.endswith(":443"):
        _deny()
    host = authority[:-4]
    if ":" in host or not _valid_dns_name(host):
        _deny()
    return host.lower()


def _status_reason(status: int) -> str:
    reasons = {
        200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
        400: "Bad Request", 403: "Forbidden", 404: "Not Found", 408: "Request Timeout",
        413: "Payload Too Large", 429: "Too Many Requests", 500: "Internal Server Error",
        502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
    }
    return reasons.get(status, "Upstream Response")


def _serialize_response(status: int, headers: _HeaderSet, body: bytes) -> bytes:
    blocked = set(_HOP_HEADERS)
    connection = headers.one("connection")
    if connection:
        blocked.update(token.strip().lower() for token in connection.split(","))
    blocked.update({"content-length", "transfer-encoding"})
    lines = [f"HTTP/1.1 {status} {_status_reason(status)}\r\n".encode("ascii")]
    for name, value in headers.pairs:
        if name.lower() in blocked:
            continue
        try:
            lines.append((name + ": " + value + "\r\n").encode("latin-1", "strict"))
        except UnicodeEncodeError:
            _deny()
    if status not in {204, 304}:
        lines.append(f"Content-Length: {len(body)}\r\n".encode("ascii"))
    lines.append(b"Connection: keep-alive\r\n\r\n")
    lines.append(body)
    return b"".join(lines)


def _dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    seen: set[int] = set()
    while True:
        if cursor >= len(packet) or len(seen) > 128:
            _deny()
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                _deny()
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in seen:
                _deny()
            seen.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            _deny()
        cursor += 1
        if length == 0:
            return ".".join(labels).lower(), next_offset if next_offset is not None else cursor
        if length > 63 or cursor + length > len(packet):
            _deny()
        try:
            labels.append(packet[cursor : cursor + length].decode("ascii", "strict"))
        except UnicodeDecodeError:
            _deny()
        cursor += length


def _dns_question(host: str, record_type: int, transaction_id: int) -> bytes:
    try:
        labels = host.encode("ascii").split(b".")
    except UnicodeEncodeError:
        _deny()
    if any(not label or len(label) > 63 for label in labels):
        _deny()
    name = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
    return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", record_type, 1)


def _dns_answers(packet: bytes, transaction_id: int, host: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if len(packet) < 12:
        _deny()
    received_id, flags, questions, answers, authorities, additional = struct.unpack("!HHHHHH", packet[:12])
    if received_id != transaction_id or not flags & 0x8000 or flags & 0x0200 or flags & 0x000F != 0 or questions != 1:
        _deny()
    name, offset = _dns_name(packet, 12)
    if name != host.lower() or offset + 4 > len(packet):
        _deny()
    offset += 4
    results: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _ in range(answers):
        _owner, offset = _dns_name(packet, offset)
        if offset + 10 > len(packet):
            _deny()
        record_type, record_class, _ttl, length = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        if offset + length > len(packet):
            _deny()
        value = packet[offset : offset + length]
        offset += length
        if record_class != 1:
            continue
        if (record_type == 1 and length != 4) or (record_type == 28 and length != 16):
            _deny()
        if record_type not in (1, 28):
            continue
        try:
            answer = ipaddress.ip_address(value)
        except ValueError:
            _deny()
        # Preserve invalid addresses for the caller's fail-closed decision.
        results.append(answer)
    # Consume the remainder defensively so malformed/truncated additional sections
    # cannot be mistaken for a complete valid response.
    for count in (authorities, additional):
        for _ in range(count):
            _owner, offset = _dns_name(packet, offset)
            if offset + 10 > len(packet):
                _deny()
            _rtype, _rclass, _ttl, length = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10 + length
            if offset > len(packet):
                _deny()
    if offset != len(packet):
        _deny()
    return tuple(results)


class BoundedTLSGuard:
    """A loopback-only CONNECT/TLS interceptor for one bounded publication."""

    def __init__(
        self,
        policy: ArtifactGuardPolicy,
        *,
        deadline_ns: int,
        host_network_fd: int,
        context_for_host: Callable[[str], ssl.SSLContext],
    ) -> None:
        if not isinstance(policy, ArtifactGuardPolicy) or type(deadline_ns) is not int:
            _deny()
        now = time.monotonic_ns()
        if deadline_ns <= now or deadline_ns - now > _MAX_LIFETIME_NS:
            _deny()
        if type(host_network_fd) is not int or host_network_fd < 0 or not callable(context_for_host):
            _deny()
        isolated_fd = -1
        try:
            if not hasattr(os, "O_CLOEXEC"):
                _deny()
            isolated_fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            own_name = os.readlink("/proc/self/ns/net")
            host_name = os.readlink(f"/proc/self/fd/{host_network_fd}")
            os.fstat(host_network_fd)
            os.fstat(isolated_fd)
            if (
                not own_name.startswith("net:[")
                or not host_name.startswith("net:[")
                or host_name == own_name
                or os.get_inheritable(host_network_fd)
                or os.get_inheritable(isolated_fd)
            ):
                _deny()
        except ArtifactGuardError:
            if isolated_fd >= 0:
                os.close(isolated_fd)
            raise
        except Exception:
            if isolated_fd >= 0:
                try:
                    os.close(isolated_fd)
                except OSError:
                    pass
            raise ArtifactGuardError("invalid network namespace authority") from None

        self.policy = policy
        self.deadline_ns = deadline_ns
        self.host_network_fd = host_network_fd
        self.context_for_host = context_for_host
        self._isolated_fd = isolated_fd
        self._isolated_name = own_name
        self._host_name = host_name
        self._upstream_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        self._upstream_context.check_hostname = True
        self._upstream_context.verify_mode = ssl.CERT_REQUIRED
        self._listener: socket.socket | None = None
        self._address: tuple[str, int] | None = None
        self._accept_thread: threading.Thread | None = None
        self._workers: list[threading.Thread] = []
        self._queue: queue.Queue[socket.socket | None] = queue.Queue(maxsize=_MAX_SESSIONS)
        self._slots = threading.BoundedSemaphore(_MAX_SESSIONS)
        self._stop = threading.Event()
        self._state_lock = threading.RLock()
        self._sockets: set[socket.socket] = set()
        self._started = False
        self._running_workers = 0
        self._closed = False
        self._dns_cache: dict[str, tuple[tuple[int, tuple[Any, ...]], ...]] = {}

    def __repr__(self) -> str:
        return "BoundedTLSGuard()"

    def __str__(self) -> str:
        return "BoundedTLSGuard()"

    @property
    def address(self) -> tuple[str, int]:
        with self._state_lock:
            if self._address is None:
                _deny()
            return self._address

    def start(self) -> "BoundedTLSGuard":
        with self._state_lock:
            if self._started or self._closed or time.monotonic_ns() >= self.deadline_ns:
                _deny()
            listener: socket.socket | None = None
            try:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(_MAX_SESSIONS)
                listener.set_inheritable(False)
                self._listener = listener
                host, port = listener.getsockname()
                self._address = (str(host), int(port))
                self._started = True
                self._workers = [
                    threading.Thread(target=self._worker_loop, name=f"artifact-guard-{index}", daemon=True)
                    for index in range(_MAX_SESSIONS)
                ]
                for worker in self._workers:
                    self._running_workers += 1
                    try:
                        worker.start()
                    except Exception:
                        self._running_workers -= 1
                        raise
                self._accept_thread = threading.Thread(
                    target=self._accept_loop,
                    name="artifact-guard-accept",
                    daemon=True,
                )
                self._accept_thread.start()
            except Exception:
                self._closed = True
                self._stop.set()
                self._listener = None
                if listener is not None:
                    try:
                        listener.close()
                    except OSError:
                        pass
                join_deadline = time.monotonic_ns() + 500_000_000
                for thread in self._workers:
                    if thread.ident is not None and thread is not threading.current_thread():
                        thread.join(timeout=max(0.0, (join_deadline - time.monotonic_ns()) / 1_000_000_000))
                self._release_isolated_if_idle()
                raise ArtifactGuardError("unable to start bounded transport") from None
        return self

    def close(self) -> None:
        with self._state_lock:
            self._closed = True
            self._stop.set()
            listener = self._listener
            self._listener = None
            sockets = tuple(self._sockets)
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        for sock in sockets:
            self._close_socket(sock)

        # Close queued clients without creating additional worker threads.
        while True:
            try:
                pending = self._queue.get_nowait()
            except queue.Empty:
                break
            if pending is not None:
                self._close_socket(pending)
                try:
                    self._slots.release()
                except ValueError:
                    pass

        join_deadline = max(self.deadline_ns, time.monotonic_ns() + 1_500_000_000)
        threads = ([self._accept_thread] if self._accept_thread is not None else []) + self._workers
        joining = [thread for thread in threads if thread is not None and thread is not threading.current_thread()]
        for thread in joining:
            thread.join(timeout=max(0.0, (join_deadline - time.monotonic_ns()) / 1_000_000_000))
        self._release_isolated_if_idle()
        return None

    def _release_isolated_if_idle(self) -> None:
        with self._state_lock:
            if not self._closed or self._running_workers or self._isolated_fd < 0:
                return
            try:
                os.close(self._isolated_fd)
            except OSError:
                pass
            self._isolated_fd = -1


    def _remaining(self) -> float:
        remaining_ns = self.deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0 or self._stop.is_set():
            _deny()
        return remaining_ns / 1_000_000_000

    def _track_socket(self, sock: socket.socket) -> None:
        with self._state_lock:
            if self._closed:
                try:
                    sock.close()
                except OSError:
                    pass
                _deny()
            self._sockets.add(sock)

    def _replace_socket(self, old: socket.socket, new: socket.socket) -> None:
        with self._state_lock:
            self._sockets.discard(old)
            if self._closed:
                try:
                    new.close()
                except OSError:
                    pass
                _deny()
            self._sockets.add(new)

    def _close_socket(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._sockets.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def _accept_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    remaining = self._remaining()
                    listener = self._listener
                    if listener is None:
                        return
                    listener.settimeout(min(0.25, remaining))
                    client, _peer = listener.accept()
                except socket.timeout:
                    continue
                except Exception:
                    if not self._stop.is_set():
                        self._stop.set()
                    return
                if not self._slots.acquire(blocking=False):
                    self._reject_plain(client, 503)
                    continue
                try:
                    client.set_inheritable(False)
                    with self._state_lock:
                        self._track_socket(client)
                        self._queue.put_nowait(client)
                except Exception:
                    self._close_socket(client)
                    try:
                        self._slots.release()
                    except ValueError:
                        pass
        finally:
            self.close()

    def _reject_plain(self, sock: socket.socket, status: int) -> None:
        try:
            sock.settimeout(min(0.1, max(0.001, self._remaining())))
            sock.sendall(
                f"HTTP/1.1 {status} {_status_reason(status)}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii")
            )
        except Exception:
            pass
        self._close_socket(sock)

    def _worker_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    client = self._queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                if client is None:
                    return
                try:
                    self._handle_client(client)
                except Exception:
                    # A proxy error is intentionally not surfaced: exception strings
                    # can contain signed URLs, headers, response bodies, or credentials.
                    pass
                finally:
                    self._close_socket(client)
                    try:
                        self._slots.release()
                    except ValueError:
                        pass
        finally:
            with self._state_lock:
                if self._running_workers > 0:
                    self._running_workers -= 1
                self._release_isolated_if_idle()

    def _handle_client(self, raw_client: socket.socket) -> None:
        current_client: socket.socket = raw_client
        client_channel = _Wire(current_client, self.deadline_ns)
        upstream: socket.socket | None = None
        try:
            start, connect_headers = _parse_http_headers(
                client_channel.read_until(b"\r\n\r\n", _MAX_CONTROL), request=True
            )
            pieces = start.split(" ")
            if len(pieces) != 3 or pieces[0] != "CONNECT" or pieces[2] not in {"HTTP/1.0", "HTTP/1.1"}:
                self._reject_plain(raw_client, 403)
                return
            host = _authority_host(pieces[1])
            host_header = connect_headers.one("host", required=True)
            if host_header is None or _authority_host(host_header) != host:
                self._reject_plain(raw_client, 403)
                return
            if connect_headers.one("content-length") not in (None, "0") or connect_headers.one("transfer-encoding") is not None:
                self._reject_plain(raw_client, 403)
                return
            if client_channel.buffer or not self.policy._connect_host_allowed(host):
                self._reject_plain(raw_client, 403)
                return
            try:
                server_context = self.context_for_host(host)
            except Exception:
                raise ArtifactGuardError("unable to establish local TLS") from None
            if not isinstance(server_context, ssl.SSLContext):
                _deny()
            client_channel.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            try:
                current_client.settimeout(self._remaining())
                client_tls = server_context.wrap_socket(current_client, server_side=True)
            except Exception:
                raise ArtifactGuardError("local TLS negotiation failed") from None
            self._replace_socket(current_client, client_tls)
            current_client = client_tls
            client_channel = _Wire(current_client, self.deadline_ns)

            while not self._stop.is_set():
                remaining = self._remaining()
                acquired = self.policy._exchange_lock.acquire(timeout=remaining)
                if not acquired:
                    _deny()
                try:
                    method, target, _version, headers, body = _read_request(client_channel)
                    request_url = "https://" + host + target
                    self.policy.validate_request(method, request_url, headers.pairs, body)
                    pending = self.policy._pending
                    if pending is None:
                        _deny()
                    kind = pending.kind
                    upstream = self._open_upstream(host)
                    upstream_channel = _Wire(upstream, self.deadline_ns)
                    upstream_channel.sendall(self._serialize_request(host, method, target, headers, body))
                    status, response_headers, response_body = _read_response(upstream_channel)
                    if kind in {"stage", "blocklist"} and status == 201 and response_body:
                        _deny()
                    self.policy.validate_response_status(status)
                    if 200 <= status < 300:
                        if kind == "create":
                            self.policy.accept_create_response(
                                _rpc_response_body(response_headers, response_body)
                            )
                        elif kind == "finalize":
                            self.policy.accept_finalize_response(
                                _rpc_response_body(response_headers, response_body)
                            )
                    client_channel.sendall(_serialize_response(status, response_headers, response_body))
                except Exception:
                    self.policy._discard_pending_response()
                    self._send_tls_rejection(client_channel)
                    return
                finally:
                    if upstream is not None:
                        self._close_socket(upstream)
                        upstream = None
                    self.policy._exchange_lock.release()
                connection = headers.one("connection")
                if connection is not None and "close" in {token.strip().lower() for token in connection.split(",")}:
                    return
        finally:
            if upstream is not None:
                self._close_socket(upstream)
            if current_client is not raw_client:
                self._close_socket(current_client)

    def _send_tls_rejection(self, channel: _Wire) -> None:
        try:
            channel.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except Exception:
            pass

    def _serialize_request(
        self,
        host: str,
        method: str,
        target: str,
        headers: _HeaderSet,
        body: bytes,
    ) -> bytes:
        blocked = set(_HOP_HEADERS)
        connection = headers.one("connection")
        if connection:
            blocked.update(token.strip().lower() for token in connection.split(","))
        blocked.update({"host", "content-length", "transfer-encoding", "proxy-connection"})
        try:
            lines = [f"{method} {target} HTTP/1.1\r\n".encode("ascii")]
            for name, value in headers.pairs:
                if name.lower() in blocked:
                    continue
                lines.append((name + ": " + value + "\r\n").encode("latin-1", "strict"))
        except Exception:
            raise ArtifactGuardError("invalid HTTP request") from None
        lines.append(f"Host: {host}\r\n".encode("ascii"))
        lines.append(f"Content-Length: {len(body)}\r\n".encode("ascii"))
        lines.append(b"Connection: close\r\n\r\n")
        lines.append(body)
        return b"".join(lines)

    def _resolver_addresses(self) -> tuple[tuple[int, tuple[Any, ...]], ...]:
        nameservers: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        try:
            with open("/etc/resolv.conf", "rb") as resolver_file:
                resolver_bytes = resolver_file.read(4096)
            for line in resolver_bytes.decode("ascii", "strict").splitlines():
                fields = line.split()
                if len(fields) == 2 and fields[0] == "nameserver":
                    try:
                        candidate = ipaddress.ip_address(fields[1])
                    except ValueError:
                        continue
                    if candidate not in nameservers:
                        nameservers.append(candidate)
        except Exception:
            raise ArtifactGuardError("DNS resolution unavailable") from None
        if not nameservers:
            _deny()
        result: list[tuple[int, tuple[Any, ...]]] = []
        for nameserver in nameservers[:4]:
            if nameserver.version == 4:
                result.append((socket.AF_INET, (str(nameserver), 53)))
            else:
                result.append((socket.AF_INET6, (str(nameserver), 53, 0, 0)))
        return tuple(result)

    def _resolve_public(self, host: str) -> tuple[tuple[int, tuple[Any, ...]], ...]:
        cached = self._dns_cache.get(host)
        if cached is not None:
            return cached
        nameservers = self._resolver_addresses()
        answers: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for family, resolver in nameservers:
            for record_type in (1, 28):
                transaction_id = int.from_bytes(os.urandom(2), "big")
                question = _dns_question(host, record_type, transaction_id)
                dns_socket = socket.socket(family, socket.SOCK_DGRAM)
                self._track_socket(dns_socket)
                try:
                    dns_socket.settimeout(min(1.0, self._remaining()))
                    dns_socket.connect(resolver)
                    dns_socket.send(question)
                    packet = dns_socket.recv(4096)
                    answers.extend(_dns_answers(packet, transaction_id, host))
                except ArtifactGuardError:
                    raise
                except Exception:
                    # A resolver timeout is bounded and another configured resolver
                    # may answer; no system resolver/direct-route fallback is used.
                    continue
                finally:
                    self._close_socket(dns_socket)
        if not answers or any(not address.is_global for address in answers):
            _deny()
        endpoints: list[tuple[int, tuple[Any, ...]]] = []
        seen: set[str] = set()
        for address in answers:
            text = str(address)
            if text in seen:
                continue
            seen.add(text)
            if address.version == 4:
                endpoints.append((socket.AF_INET, (text, 443)))
            else:
                endpoints.append((socket.AF_INET6, (text, 443, 0, 0)))
        if not endpoints:
            _deny()
        result = tuple(endpoints)
        self._dns_cache[host] = result
        return result

    def _libc_setns(self, fd: int) -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            setns = libc.setns
            setns.argtypes = (ctypes.c_int, ctypes.c_int)
            setns.restype = ctypes.c_int
            result = setns(fd, 0x40000000)  # CLONE_NEWNET
        except Exception:
            raise ArtifactGuardError("network namespace transition failed") from None
        if result != 0:
            _deny()

    def _check_network_fds(self) -> None:
        try:
            if (
                os.readlink("/proc/self/ns/net") != self._isolated_name
                or os.readlink(f"/proc/self/fd/{self.host_network_fd}") != self._host_name
                or os.get_inheritable(self.host_network_fd)
                or os.fstat(self.host_network_fd).st_ino == 0
            ):
                _deny()
        except ArtifactGuardError:
            raise
        except Exception:
            raise ArtifactGuardError("network namespace authority changed") from None

    def _open_upstream(self, host: str) -> ssl.SSLSocket:
        self._check_network_fds()
        self._libc_setns(self.host_network_fd)
        raw: socket.socket | None = None
        restore_error = False
        try:
            endpoints = self._resolve_public(host)
            for family, sockaddr in endpoints:
                candidate = socket.socket(family, socket.SOCK_STREAM)
                self._track_socket(candidate)
                try:
                    candidate.settimeout(self._remaining())
                    candidate.connect(sockaddr)
                    raw = candidate
                    break
                except Exception:
                    self._close_socket(candidate)
                    if time.monotonic_ns() >= self.deadline_ns:
                        raise ArtifactGuardError("bounded transport deadline reached") from None
            if raw is None:
                _deny()
        finally:
            try:
                self._libc_setns(self._isolated_fd)
            except Exception:
                restore_error = True
                if raw is not None:
                    self._close_socket(raw)
                self._stop.set()
        if restore_error or raw is None:
            _deny()
        try:
            raw.settimeout(self._remaining())
            tls = self._upstream_context.wrap_socket(raw, server_hostname=host)
            self._replace_socket(raw, tls)
            return tls
        except Exception:
            self._close_socket(raw)
            raise ArtifactGuardError("upstream TLS verification failed") from None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
