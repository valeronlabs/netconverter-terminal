"""Synthetic HTTP contract proof; not a live export acceptance claim."""
import hashlib
import json

import httpx
import jsonschema
import pytest

from netconverter_cli.mcp_server import Bridge
from netconverter_cli.mcp_client_features import OUTPUT_SCHEMAS
from netconverter_cli.api import StaticCredential

JOB = "tra_workbook2292"
EXPORT = "exp_22920000000040008000000000000001"
BASE = "https://api.example/external/v1"
MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
XLSX = b"PK\x03\x04synthetic-workbook-2292"
SHA = hashlib.sha256(XLSX).hexdigest()


class Server:
    def __init__(self, state="queued"):
        self.state = state
        self.calls = []
        self.corrupt = False
        self.interrupted = False
        self.unsupported = False

    def __call__(self, request):
        path = request.url.path.removeprefix("/external/v1/")
        self.calls.append((request.method, path))
        def envelope(data, status=200):
            return httpx.Response(status, json={"success": True, "data": data})
        if path == "me":
            return envelope({"job_types": ["convert"]})
        if path == f"jobs/{JOB}":
            return envelope({"job_id": JOB, "status": "completed", "job_type": "convert"})
        if path.endswith("/translated"):
            return httpx.Response(200, content=b"synthetic emitted configuration")
        if path.endswith("/report"):
            return envelope({"job_id": JOB, "review_required": True})
        prefix = f"jobs/{JOB}/exports/evidence.xlsx"
        if path in (prefix, prefix + "/" + EXPORT):
            if self.interrupted:
                raise httpx.ReadTimeout("synthetic timeout")
            if self.unsupported:
                return httpx.Response(404, json={"success": False, "error": {"code": "not_found"}})
            data = {"export_id": EXPORT, "job_id": JOB, "state": self.state, "retry_after_seconds": 3}
            if self.state == "ready":
                data.update(content_sha256=SHA, bytes=len(XLSX))
            return envelope(data, 202 if request.method == "POST" else 200)
        if path == prefix + "/" + EXPORT + "/content":
            return httpx.Response(200, content=XLSX + b"bad" if self.corrupt else XLSX,
                                  headers={"Content-Type": MIME, "X-Content-SHA256": SHA})
        if path.endswith("/evidence.xlsx"):
            raise httpx.ReadTimeout("old synchronous XLSX request exceeded timeout")
        raise AssertionError((request.method, path))


def bridge(tmp_path, server):
    return Bridge(tmp_path, BASE, StaticCredential("nck_synthetic"), transport=httpx.MockTransport(server))


def call(b, **args):
    response = b.call("download", {"job_id": JOB, **args})
    data = json.loads(response["content"][0]["text"])
    if not response.get("isError"):
        jsonschema.validate(data, OUTPUT_SCHEMAS["download"])
    return response, data


def test_pending_download_keeps_verified_primary_receipts(tmp_path):
    server = Server()
    result, data = call(bridge(tmp_path, server))
    assert not result.get("isError"), data
    assert data["complete"] is False
    assert data["pending_export"]["export_id"] == EXPORT
    assert len(data["files"]) == 2
    for item in data["files"]:
        assert hashlib.sha256((tmp_path / item["name"]).read_bytes()).hexdigest() == item["sha256"]
    assert ("GET", f"jobs/{JOB}/evidence.xlsx") not in server.calls


def test_resume_downloads_only_ready_workbook(tmp_path):
    server = Server("ready")
    result, data = call(bridge(tmp_path, server), artifact_kind="evidence-workbook", export_id=EXPORT)
    assert not result.get("isError"), data
    assert data["complete"] is True and len(data["files"]) == 1
    assert data["files"][0]["sha256"] == SHA
    assert server.calls == [("GET", "me"), ("GET", f"jobs/{JOB}/exports/evidence.xlsx/{EXPORT}"),
                            ("GET", f"jobs/{JOB}/exports/evidence.xlsx/{EXPORT}/content")]


def test_unknown_prepare_retains_files_and_never_falls_back(tmp_path):
    server = Server(); server.interrupted = True
    result, data = call(bridge(tmp_path, server))
    assert not result.get("isError"), data
    assert data["complete"] is False and len(data["files"]) == 2
    assert data["failure"]["code"] == "connection_failed"
    assert "outcome is unknown" in data["failure"]["message"]
    assert sum(method == "POST" for method, _ in server.calls) == 1
    assert ("GET", f"jobs/{JOB}/evidence.xlsx") not in server.calls


@pytest.mark.parametrize("state", ["processing", "failed", "stale"])
def test_resume_keeps_export_identity_and_never_regenerates(tmp_path, state):
    server = Server(state)
    result, data = call(bridge(tmp_path, server), artifact_kind="evidence-workbook", export_id=EXPORT)
    assert not result.get("isError"), data
    assert data["complete"] is False and data["files"] == []
    assert data["pending_export"]["export_id"] == EXPORT
    assert not any(method == "POST" or path.endswith("/content") for method, path in server.calls)
    if state != "processing":
        assert data["failure"]["code"] == "export_" + state


def test_old_server_unavailable_is_partial_without_sync_fallback(tmp_path):
    server = Server(); server.unsupported = True
    result, data = call(bridge(tmp_path, server))
    assert not result.get("isError"), data
    assert data["complete"] is False and len(data["files"]) == 2
    assert data["failure"]["code"] == "export_unavailable"
    assert not any(path == f"jobs/{JOB}/evidence.xlsx" for _, path in server.calls)


def test_corrupt_workbook_is_not_published_and_does_not_discard_primary_receipts(tmp_path):
    server = Server("ready"); server.corrupt = True
    result, data = call(bridge(tmp_path, server))
    assert not result.get("isError"), data
    assert data["complete"] is False and len(data["files"]) == 2
    assert data["pending_export"]["export_id"] == EXPORT
    assert data["failure"]["code"] in {"artifact_checksum_mismatch", "invalid_export_content"}
    assert not (tmp_path / (JOB + ".evidence.xlsx")).exists()


@pytest.mark.parametrize("fault", ["wrong_job", "wrong_export", "json_content", "content_pending", "wrong_hash"])
def test_identity_and_content_contract_fail_closed(tmp_path, fault):
    server = Server("ready")
    def handle(request):
        response = server(request)
        if request.url.path.endswith("/content"):
            if fault == "json_content":
                return httpx.Response(200, json={"state": "ready"}, headers={"X-Content-SHA256": SHA})
            if fault == "content_pending":
                return httpx.Response(202, json={"state": "processing"})
            if fault == "wrong_hash":
                return httpx.Response(200, content=XLSX, headers={"Content-Type": MIME, "X-Content-SHA256": "0" * 64})
        elif "/exports/" in request.url.path:
            body = response.json()
            if fault == "wrong_job": body["data"]["job_id"] = "tra_foreign"
            if fault == "wrong_export": body["data"]["export_id"] = "exp_" + "f" * 32
            return httpx.Response(response.status_code, json=body)
        return response
    result, data = call(bridge(tmp_path, handle), artifact_kind="evidence-workbook", export_id=EXPORT)
    assert not result.get("isError"), data
    assert data["complete"] is False and data["files"] == [] and data["failure"]
    assert not list(tmp_path.glob("*.xlsx"))


def test_conflicting_requests_refused_before_network(tmp_path):
    server = Server("ready")
    result, data = call(bridge(tmp_path, server), artifact_kind="evidence-workbook", export_kind="decision-yaml")
    assert result["isError"] and data["error"] == "invalid_arguments"
    assert server.calls == []


def test_resume_timeout_preserves_exact_reference(tmp_path):
    server = Server(); server.interrupted = True
    result, data = call(bridge(tmp_path, server), artifact_kind="evidence-workbook", export_id=EXPORT)
    assert not result.get("isError") and not data["complete"]
    assert data["export_reference"] == {"job_id": JOB, "artifact_kind": "evidence-workbook", "export_id": EXPORT}
    assert data["files"] == [] and "outcome is unknown" in data["failure"]["message"]
    assert not any(method == "POST" for method, _ in server.calls)


@pytest.mark.parametrize("fault", ["oversized_metadata", "oversized_workbook", "size_failure"])
def test_export_limits_and_typed_failures(tmp_path, fault):
    server = Server("ready")
    def handle(request):
        response = server(request)
        if "/exports/" in request.url.path and not request.url.path.endswith("/content"):
            body = response.json()
            if fault == "oversized_metadata": body["ignored"] = "x" * 20000
            if fault == "oversized_workbook": body["data"]["bytes"] = 50 * 1024 * 1024 + 1
            if fault == "size_failure": body["data"].update(state="failed", failure_code="export_size_limit")
            return httpx.Response(200, json=body)
        return response
    result, data = call(bridge(tmp_path, handle), artifact_kind="evidence-workbook", export_id=EXPORT)
    assert not result.get("isError") and not data["complete"] and not data["files"]
    assert data["failure"]["code"] == ("export_size_limit" if fault == "size_failure" else "invalid_export_metadata")
    assert not any(path.endswith("/content") for _, path in server.calls)


def test_local_workbook_write_refusal_preserves_primary_receipts(tmp_path, monkeypatch):
    from netconverter_cli.workspace import Workspace, WorkspaceError
    original = Workspace.save_artifact
    def save(self, job, name, content, digest=None):
        if name == "evidence.xlsx": raise WorkspaceError("synthetic unsafe destination")
        return original(self, job, name, content, digest)
    monkeypatch.setattr(Workspace, "save_artifact", save)
    result, data = call(bridge(tmp_path, Server("ready")))
    assert not result.get("isError") and not data["complete"] and len(data["files"]) == 2
    assert data["failure"]["code"] == "download_refused"
    assert data["export_reference"]["export_id"] == EXPORT


@pytest.mark.parametrize("fault", ["timeout", "stale", "malformed_error"])
def test_content_failure_retains_receipts_and_reference(tmp_path, fault):
    server = Server("ready")
    def handle(request):
        if request.url.path.endswith("/content"):
            if fault == "timeout": raise httpx.ReadTimeout("synthetic content timeout")
            return httpx.Response(409, json={"success": False, "error": {
                "code": "export_stale" if fault == "stale" else ["untrusted"]}})
        return server(request)
    result, data = call(bridge(tmp_path, handle))
    assert not result.get("isError") and not data["complete"] and len(data["files"]) == 2
    assert data["export_reference"]["export_id"] == EXPORT
    assert data["failure"]["code"] == {"timeout": "connection_failed", "stale": "export_stale", "malformed_error": "download_failed"}[fault]
    assert not list(tmp_path.glob("*.xlsx"))


def test_report_failure_does_not_claim_workbook_preparation_started(tmp_path):
    server = Server()
    def handle(request):
        if request.url.path.endswith("/report"): raise httpx.ReadTimeout("synthetic report timeout")
        return server(request)
    result, data = call(bridge(tmp_path, handle))
    assert not result.get("isError") and not data["complete"] and len(data["files"]) == 1
    assert "workbook preparation has not started" in data["failure"]["message"]
    assert not any("/exports/" in path for _, path in server.calls)


def test_encoded_error_body_is_never_consumed(tmp_path):
    class Unreadable(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("encoded error body must not be decoded")
            yield b""
    server = Server("ready")
    def handle(request):
        if request.url.path.endswith("/content"):
            return httpx.Response(409, headers={"Content-Encoding": "gzip"}, stream=Unreadable())
        return server(request)
    result, data = call(bridge(tmp_path, handle))
    assert not result.get("isError") and not data["complete"] and len(data["files"]) == 2
    assert data["failure"]["code"] == "invalid_export_encoding"


def test_workbook_auth_refresh_does_not_drain_401_body(tmp_path):
    from netconverter_cli.api import ExternalClient
    class Unreadable(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("401 body must not be drained by auth handling")
            yield b""
    class Credential(StaticCredential):
        def refresh(self): return True
    server = Server()
    calls = []
    def handle(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(401, stream=Unreadable())
        return server(request)
    client = ExternalClient(Credential("nck_synthetic"), BASE, transport=httpx.MockTransport(handle))
    try:
        assert client.workbook_export(JOB)["export_id"] == EXPORT
    finally:
        client.close()
    assert len(calls) == 2 and calls[0].headers["X-Request-ID"] == calls[1].headers["X-Request-ID"]
