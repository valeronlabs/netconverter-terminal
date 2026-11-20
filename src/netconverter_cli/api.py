"""Direct NetConverter data channel. No model SDK imports belong here."""

from __future__ import annotations

import re
from contextlib import contextmanager
import uuid
from urllib.parse import urlsplit

import httpx

DEFAULT_BASE = "https://api.netconverter.ai/external/v1"
MAX_DOCUMENT_EXPORT_BYTES = 100 * 1024 * 1024
MAX_WORKBOOK_EXPORT_BYTES = 50 * 1024 * 1024
WORKBOOK_FAILURE_CODES = frozenset({"export_failed", "export_stale", "export_size_limit",
    "export_deadline", "export_queue_expired", "export_renderer_mismatch",
    "evidence_unavailable", "evidence_integrity_failed", "export_render_failed"})
WORKBOOK_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_WORKBOOK_EXPORT_ID = re.compile(r"exp_[a-f0-9]{32}\Z")


def document_export_query(kind, revision=None, expected_document_sha256=None):
    """Fixed file export parameters; no arbitrary URL, path, or document body."""
    if kind not in {"decision-yaml", "source-ncir"}:
        raise ValueError("Unsupported document export")
    if kind == "source-ncir" and (revision is not None or expected_document_sha256 is not None):
        raise ValueError("NCIR exports do not accept decision revision parameters")
    params = {}
    if revision is not None:
        if type(revision) is not int or not 0 <= revision <= 10000:
            raise ValueError("Invalid decision revision")
        params["revision"] = revision
    if expected_document_sha256 is not None:
        if not isinstance(expected_document_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_document_sha256):
            raise ValueError("Invalid decision hash")
        params["expected_document_sha256"] = expected_document_sha256
    return params


def _printable(value, limit: int = 300) -> str:
    """Server-supplied text shown to a person: printable characters only, capped."""
    return "".join(ch for ch in str(value or "") if ch.isprintable() or ch == " ")[:limit].strip()


class APIError(RuntimeError):
    def __init__(self, status: int, code: str, request_id: str = "", detail=None, message=None):
        self.message = _printable(message) if isinstance(message, str) else ""
        text = f"NetConverter {code} (HTTP {status}, request {request_id or 'unavailable'})"
        if self.message:  # the server's reason, e.g. "unknown source_vendor 'auto'; valid: [...]"
            text += f": {self.message}"
        super().__init__(text)
        self.status, self.code, self.request_id, self.detail = (
            status,
            code,
            request_id,
            detail,
        )


def check_url(base: str) -> str:
    """HTTPS only (HTTP for explicit loopback testing); no userinfo/query/fragment."""
    parts = urlsplit(base)
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Invalid server URL")
    if parts.scheme != "https" and not (
        parts.scheme == "http" and parts.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError(
            "Server connections require HTTPS (HTTP only for explicit loopback testing)"
        )
    return base


class StaticCredential:
    """An API key (``nck_*`` or terminal_quick). It cannot be refreshed."""

    kind = "key"

    def __init__(self, key: str):
        self._key = key

    def token(self) -> str:
        return self._key

    def refresh(self) -> bool:
        return False


class BearerAuth(httpx.Auth):
    """Bearer from a credential; one refresh-and-retry on HTTP 401.

    Works for static keys (no retry) and for Clerk OAuth sessions, whose
    ``token()`` refreshes an expiring access token and whose ``refresh()``
    forces a refresh after the server rejected the current one.
    """

    requires_request_body = True

    def __init__(self, credential):
        self.credential = credential

    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self.credential.token()}"
        response = yield request
        if response.status_code == 401 and self.credential.refresh():
            request.headers["Authorization"] = f"Bearer {self.credential.token()}"
            yield request


def as_credential(key):
    return StaticCredential(key) if isinstance(key, str) else key


class Client:
    # Path allowlist for this client's restricted surface.
    _ALLOWED = re.compile(r"quick/[A-Za-z0-9_/-]{1,200}\Z")

    def __init__(self, key, base: str = DEFAULT_BASE, *, transport=None):
        check_url(base)
        self.credential = as_credential(key)
        self.http = httpx.Client(
            base_url=base.rstrip("/") + "/",
            timeout=60,
            auth=BearerAuth(self.credential),
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self):
        self.http.close()

    @staticmethod
    def identifier(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
            raise ValueError("Invalid resource identifier")
        return value

    def _send(self, method, path, idempotency_key=None, **kwargs):
        if not self._ALLOWED.fullmatch(path) or ".." in path:
            raise ValueError("Only the restricted NetConverter API may be called")
        headers = {"X-Request-ID": "req_" + uuid.uuid4().hex}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            response = self.http.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError:
            raise APIError(0, "connection_failed", headers["X-Request-ID"]) from None
        return response, headers["X-Request-ID"]

    @staticmethod
    def _error(response, request_id):
        try:
            body = response.json()
        except ValueError:
            return APIError(response.status_code, "invalid_response", request_id)
        error = body.get("error", {}) if isinstance(body, dict) else {}
        if not isinstance(error, dict):
            error = {}
        detail = body.get("detail", error.get("detail")) if isinstance(body, dict) else None
        # The External API envelope carries the reason in error.message; an older
        # server may send a plain-string detail instead.
        message = error.get("message")
        if not isinstance(message, str) and isinstance(detail, str):
            message, detail = detail, None
        return APIError(
            response.status_code,
            str(error.get("code", "request_failed")),
            body.get("request_id", request_id) if isinstance(body, dict) else request_id,
            detail,
            message,
        )

    def request(
        self, method: str, path: str, *, idempotency_key: str | None = None, **kwargs
    ):
        response, request_id = self._send(method, path, idempotency_key, **kwargs)
        try:
            body = response.json()
        except ValueError:
            raise APIError(response.status_code, "invalid_response", request_id) from None
        if response.is_error or not isinstance(body, dict) or body.get("success") is not True:
            raise self._error(response, request_id)
        return body["data"]

    def capabilities(self):
        return self.request("GET", "quick/capabilities")

    def upload(self, content: bytes, vendor: str):
        return self.request(
            "POST", "quick/configurations", content=content, params={"vendor": vendor}
        )

    def submit(
        self, configuration_id: str, operation: str, options: dict, idempotency_key: str
    ):
        return self.request(
            "POST",
            "quick/jobs",
            idempotency_key=idempotency_key,
            json={
                "configuration_id": configuration_id,
                "operation": operation,
                "options": options,
            },
        )

    def jobs(self):
        return self.request("GET", "quick/jobs")

    def status(self, job_id: str):
        return self.request("GET", f"quick/jobs/{self.identifier(job_id)}")

    def query(
        self,
        job_id: str,
        operation: str,
        arguments: dict,
        idempotency_key: str,
        offset: int = 0,
    ):
        return self.request(
            "POST",
            "quick/queries",
            idempotency_key=idempotency_key,
            json={
                "job_id": job_id,
                "operation": operation,
                "arguments": arguments,
                "offset": offset,
            },
        )

    def target(self, job_id: str):
        return self.request("POST", f"quick/jobs/{self.identifier(job_id)}/target")

    def artifacts(self, job_id: str):
        return self.request("GET", f"quick/jobs/{self.identifier(job_id)}/artifacts")

    def download(self, job_id: str, artifact_id: str):
        return self.request(
            "GET",
            f"quick/jobs/{self.identifier(job_id)}/artifacts/{self.identifier(artifact_id)}",
        )


class ExternalClient(Client):
    """Full External API v1 (``/jobs``, ``/me``, ``/capabilities``), same Bearer handling.

    Accepts ``nck_*`` keys and Clerk OAuth access tokens.
    """

    _ALLOWED = re.compile(
        r"(?:me|capabilities|files/upload|jobs|jobs/[A-Za-z0-9_-]{1,80}(?:/translated|/report|/evidence\.xlsx|/findings\.sarif|/diagrams/render|/validation/(?:ncir|receipt|txt|pdf|xlsx)|/exports/(?:decision-yaml|source-ncir|evidence\.xlsx(?:/exp_[a-f0-9]{32}(?:/content)?)?))?)\Z"
    )

    def me(self):
        return self.request("GET", "me")

    def capabilities(self):
        """Vendors, source→target paths, job types and limits POST /jobs accepts."""
        return self.request("GET", "capabilities")

    def upload_file(self, content: bytes, filename: str = "configuration.cfg"):
        """Authenticated multipart transport; no configuration bytes enter a model tool."""
        return self.request("POST", "files/upload", data={"folder": "uploads", "purpose": "file"},
                            files={"file": (filename, content, "application/octet-stream")})

    def jobs(self, limit: int = 25):
        data = self.request("GET", "jobs", params={"comparable": "false", "limit": limit})
        return data.get("jobs", []) if isinstance(data, dict) else []

    def evidence_workbook(self, job_id: str) -> bytes | None:
        """The customer evidence workbook; None when this job has none."""
        response, request_id = self._send(
            "GET", f"jobs/{self.identifier(job_id)}/evidence.xlsx"
        )
        if response.status_code in (404, 409, 422):
            return None
        if response.is_error:
            raise self._error(response, request_id)
        return response.content

    @staticmethod
    def _workbook_metadata(data, job_id, export_id=None):
        """Allowlisted, job-bound metadata; never return server URLs or prose."""
        if (not isinstance(data, dict) or data.get("job_id") != job_id
                or not isinstance(data.get("export_id"), str)
                or not _WORKBOOK_EXPORT_ID.fullmatch(data["export_id"])
                or (export_id is not None and data["export_id"] != export_id)
                or data.get("state") not in {"queued", "processing", "ready", "failed", "stale"}
                or type(data.get("retry_after_seconds")) is not int
                or not 0 <= data["retry_after_seconds"] <= 3600):
            raise APIError(502, "invalid_export_metadata")
        result = {key: data[key] for key in ("export_id", "job_id", "state", "retry_after_seconds")}
        if data["state"] == "ready":
            size, digest = data.get("bytes"), data.get("content_sha256")
            if (type(size) is not int or not 0 < size <= MAX_WORKBOOK_EXPORT_BYTES
                    or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
                raise APIError(502, "invalid_export_metadata")
            result.update(bytes=size, content_sha256=digest)
        # Failure prose is intentionally not passed through this metadata surface.
        if data["state"] in {"failed", "stale"}:
            code = data.get("failure_code")
            result["failure_code"] = code if code in WORKBOOK_FAILURE_CODES else "export_" + data["state"]
        return result

    @contextmanager
    def _workbook_stream(self, method, path, request_id):
        # Disable HTTPX's automatic auth retry: it drains a rejected response
        # before retrying, outside our body limits. Close a 401 unread instead.
        for attempt in range(2):
            headers = {"X-Request-ID": request_id, "Accept-Encoding": "identity",
                       "Authorization": f"Bearer {self.credential.token()}"}
            with self.http.stream(method, path, auth=None, headers=headers) as response:
                if response.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
                    raise APIError(502, "invalid_export_encoding", request_id)
                if response.status_code == 401 and attempt == 0 and self.credential.refresh():
                    continue
                yield response
                return

    def workbook_export(self, job_id: str, export_id: str | None = None) -> dict:
        """Prepare once or inspect an exact export; never poll or fall back implicitly."""
        job_id = self.identifier(job_id)
        path = f"jobs/{job_id}/exports/evidence.xlsx"
        if export_id is not None:
            if not isinstance(export_id, str) or not _WORKBOOK_EXPORT_ID.fullmatch(export_id):
                raise ValueError("Invalid workbook export identifier")
            path += "/" + export_id
        import json
        request_id = "req_" + uuid.uuid4().hex
        try:
            with self._workbook_stream("GET" if export_id is not None else "POST", path, request_id) as response:
                if response.status_code == 404:
                    raise APIError(404, "export_unavailable", request_id)
                if response.status_code not in (200, 202):
                    raise APIError(response.status_code, "export_request_failed", request_id)
                if (response.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json"
                        or response.headers.get("Content-Encoding", "identity") != "identity"):
                    raise APIError(502, "invalid_export_metadata", request_id)
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=8192):
                    if len(body) + len(chunk) > 16384:
                        raise APIError(502, "invalid_export_metadata", request_id)
                    body.extend(chunk)
                try:
                    data = json.loads(body)
                    if not isinstance(data, dict) or data.get("success") is not True:
                        raise ValueError
                    return self._workbook_metadata(data["data"], job_id, export_id)
                except (ValueError, KeyError, TypeError, RecursionError):
                    raise APIError(502, "invalid_export_metadata", request_id) from None
        except httpx.HTTPError:
            raise APIError(0, "connection_failed", request_id) from None

    def workbook_export_content(self, job_id: str, metadata: dict) -> tuple[bytes, str]:
        """Bounded authenticated transfer; status and content identities must agree."""
        import hashlib
        import json
        job_id = self.identifier(job_id)
        meta = self._workbook_metadata(metadata, job_id)
        if meta["state"] != "ready":
            raise APIError(409, "export_not_ready")
        path = f"jobs/{job_id}/exports/evidence.xlsx/{meta['export_id']}/content"
        request_id = "req_" + uuid.uuid4().hex
        try:
            with self._workbook_stream("GET", path, request_id) as response:
                if response.status_code != 200:
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=8192):
                        if len(body) + len(chunk) > 8192:
                            break
                        body.extend(chunk)
                    code = "export_unavailable" if response.status_code == 404 else "request_failed"
                    try:
                        data = json.loads(body)
                        detail = data.get("detail", data.get("error", {}))
                        if isinstance(detail, dict) and isinstance(detail.get("code"), str) and detail["code"] in {
                                "export_not_ready", "export_failed", "export_stale"}:
                            code = detail["code"]
                    except (ValueError, AttributeError, RecursionError):
                        pass
                    raise APIError(response.status_code, code, request_id)
                size = response.headers.get("Content-Length", "")
                if (response.headers.get("Content-Type", "").split(";", 1)[0].strip() != WORKBOOK_MIME
                        or response.headers.get("Content-Encoding", "identity") != "identity"
                        or response.headers.get("X-Content-SHA256") != meta["content_sha256"]
                        or not size.isdecimal() or len(size) > 12 or int(size) != meta["bytes"]):
                    raise APIError(502, "invalid_export_content", request_id)
                content = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    if len(content) + len(chunk) > meta["bytes"]:
                        raise APIError(502, "artifact_size_mismatch", request_id)
                    content.extend(chunk)
                if len(content) != meta["bytes"] or hashlib.sha256(content).hexdigest() != meta["content_sha256"]:
                    raise APIError(502, "artifact_checksum_mismatch", request_id)
                return bytes(content), meta["content_sha256"]
        except httpx.HTTPError:
            raise APIError(0, "connection_failed", request_id) from None

    def validation_artifact(self, job_id: str, format: str) -> tuple[bytes, str] | None:
        """Recorded source artifacts; the server hash is verified before any write.

        A 404 means an old server/job has no artifact. Integrity failures (409)
        and authorization refusals propagate, rather than silently disappearing.
        """
        import hashlib
        if format not in {"ncir", "receipt", "txt", "pdf", "xlsx"}:
            raise ValueError("Unsupported validation artifact format")
        response, request_id = self._send(
            "GET", f"jobs/{self.identifier(job_id)}/validation/{format}"
        )
        if response.status_code == 404:
            return None
        if response.is_error:
            raise self._error(response, request_id)
        expected = response.headers.get("X-Content-SHA256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(response.content).hexdigest() != expected:
            raise APIError(502, "artifact_checksum_mismatch", request_id)
        return response.content, expected

    def document_export(self, job_id, kind, *, revision=None, expected_document_sha256=None,
                        max_bytes=MAX_DOCUMENT_EXPORT_BYTES):
        """Stream one explicit document directly to the file-transport caller.

        Error bodies are bounded and only their safe code is retained. Hash,
        provenance and revision checks precede every filesystem write.
        """
        import hashlib
        params = document_export_query(kind, revision, expected_document_sha256)
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_DOCUMENT_EXPORT_BYTES:
            raise ValueError("Invalid export byte limit")
        path = f"jobs/{self.identifier(job_id)}/exports/{kind}"
        request_id = "req_" + uuid.uuid4().hex
        try:
            for attempt in range(2):
                # HTTPX drains a 401 body before automatic auth retries, outside
                # our limits. Refresh here only after a bounded response read.
                headers = {"X-Request-ID": request_id, "Accept-Encoding": "identity",
                           "Authorization": f"Bearer {self.credential.token()}"}
                with self.http.stream("GET", path, params=params, auth=None, headers=headers) as response:
                    if 300 <= response.status_code < 400:
                        raise APIError(response.status_code, "artifact_redirect_refused", request_id)
                    if response.headers.get("Content-Encoding", "").strip().lower() not in {"", "identity"}:
                        raise APIError(502 if response.status_code == 200 else response.status_code,
                                       "unsupported_export_encoding", request_id)
                    content = bytearray()
                    limit = max_bytes if response.status_code == 200 else 8192
                    length = response.headers.get("Content-Length")
                    if length and (not length.isdecimal() or len(length) > 12 or int(length) > limit):
                        raise APIError(413 if response.status_code == 200 else response.status_code,
                                       "artifact_too_large" if response.status_code == 200 else "request_failed", request_id)
                    for chunk in response.iter_bytes(chunk_size=min(64 * 1024, limit + 1)):
                        if len(content) + len(chunk) > limit:
                            raise APIError(413 if response.status_code == 200 else response.status_code,
                                           "artifact_too_large" if response.status_code == 200 else "request_failed", request_id)
                        content.extend(chunk)
                    if response.status_code == 401 and attempt == 0 and self.credential.refresh():
                        continue
                    if response.status_code != 200:
                        import json
                        code = "request_failed"
                        try:
                            body = json.loads(content)
                            detail = body.get("detail", body.get("error", {})) if isinstance(body, dict) else {}
                            value = detail.get("code") if isinstance(detail, dict) else None
                            if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{1,79}", value):
                                code = value
                        except (ValueError, TypeError, RecursionError):
                            pass
                        raise APIError(response.status_code, code, request_id)
                    expected = response.headers.get("X-Content-SHA256", "")
                    if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(content).hexdigest() != expected:
                        raise APIError(502, "artifact_checksum_mismatch", request_id)
                    provenance = response.headers.get("X-Export-Provenance")
                    media = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
                    meta = {"sha256": expected, "provenance": provenance}
                    if kind == "source-ncir":
                        original = response.headers.get("X-Artifact-SHA256", "")
                        if (provenance != "source-stage-2.5" or media != "application/json"
                                or not re.fullmatch(r"[a-f0-9]{64}", original)):
                            raise APIError(502, "invalid_export_provenance", request_id)
                        meta["artifact_sha256"] = original
                    else:
                        doc_hash = response.headers.get("X-Document-SHA256", "")
                        number = response.headers.get("X-Document-Revision")
                        if (provenance not in {"prescan-revision", "conversion-effective"}
                                or media != "application/yaml" or not re.fullmatch(r"[a-f0-9]{64}", doc_hash)
                                or (expected_document_sha256 is not None and doc_hash != expected_document_sha256)):
                            raise APIError(502, "invalid_export_provenance", request_id)
                        if provenance == "prescan-revision":
                            if (number is None or not re.fullmatch(r"[0-9]{1,5}", number)
                                    or int(number) > 10000 or (revision is not None and int(number) != revision)):
                                raise APIError(502, "export_revision_mismatch", request_id)
                            meta["revision"] = int(number)
                        elif revision is not None or number is not None:
                            raise APIError(502, "export_revision_mismatch", request_id)
                        meta["document_sha256"] = doc_hash
                    return bytes(content), meta
        except httpx.HTTPError:
            raise APIError(0, "connection_failed", request_id) from None

    def findings(self, job_id: str):
        """Every finding of a completed validate/optimize job (SARIF 2.1.0 JSON)."""
        response, request_id = self._send("GET", f"jobs/{self.identifier(job_id)}/findings.sarif")
        if response.is_error:
            raise self._error(response, request_id)
        try:
            return response.json()
        except ValueError:
            raise APIError(response.status_code, "invalid_response", request_id) from None

    def submit_job(self, body: dict, idempotency_key: str):
        return self.request("POST", "jobs", idempotency_key=idempotency_key, json=body)

    def job(self, job_id: str):
        return self.request("GET", f"jobs/{self.identifier(job_id)}")

    def report(self, job_id: str):
        return self.request("GET", f"jobs/{self.identifier(job_id)}/report")

    def translated(self, job_id: str) -> bytes | None:
        """Translated configuration bytes; None while absent (queued/blocked)."""
        response, request_id = self._send(
            "GET", f"jobs/{self.identifier(job_id)}/translated"
        )
        if response.status_code == 404:
            return None
        if response.is_error:
            raise self._error(response, request_id)
        return response.content

    def diagram(self, job_id: str, recipe: dict, *, max_bytes=32 * 1024 * 1024) -> bytes:
        """Fixed authenticated endpoint; the expected hash binds revision and view."""
        path = f"jobs/{self.identifier(job_id)}/diagrams/render"
        request_id = "req_" + uuid.uuid4().hex
        try:
            with self.http.stream("POST", path, json=recipe,
                                  headers={"X-Request-ID": request_id}) as response:
                content = bytearray()
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    if len(content) + len(chunk) > max_bytes:
                        raise APIError(413, "diagram_too_large", request_id)
                    content.extend(chunk)
                if response.status_code != 200:
                    raise self._error(httpx.Response(response.status_code, content=bytes(content)), request_id)
                return bytes(content)
        except httpx.HTTPError:
            raise APIError(0, "connection_failed", request_id) from None
