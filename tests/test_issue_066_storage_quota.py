"""Typed storage quota refusals never become format advice or raw model prose.

HTTP is mocked; this tests the real terminal error normalization and MCP caller,
not a live upload or storage-capacity change.
"""
import json

import httpx
import pytest

from netconverter_cli.api import APIError, StaticCredential
from netconverter_cli.mcp_server import Bridge, _submission_api_failure
from tests.test_issue_2195_file_transport import SERVER, UploadServer

CANARY = "SYNTHETIC_SOURCE_AND_SECRET_DO_NOT_ECHO"
COUNTS = {"requested_bytes": 21_036_438, "available_bytes": 20_708_878,
          "used_bytes": 84_148_722, "limit_bytes": 104_857_600}


def test_actual_mcp_upload_refusal_explains_storage_without_resubmission(tmp_path):
    content = b"hostname synthetic-only\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)

    def refuse(request):
        if request.url.path.endswith("/files/upload"):
            server.requests.append(request)
            return httpx.Response(422, json={"success": False, "request_id": "req_1234567890abcdef",
                "error": {"code": "storage_quota_exceeded", "message": CANARY,
                          "detail": {**COUNTS, "source_config": CANARY, "credential": CANARY,
                                     "fields": ["source_vendor"]}}})
        return server(request)

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), transport=httpx.MockTransport(refuse))
    result = bridge.call("submit_file", {"path": "source.cfg", "source_vendor": "cisco_asa",
                                         "target_vendor": "palo_alto_set", "job_type": "convert"})
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert payload["error"] == "storage_quota_exceeded"
    assert payload["storage_quota"] == COUNTS
    assert "missing_options" not in payload
    assert "My Files" in payload["message"] and "storage" in payload["message"]
    assert "source format" not in payload["message"] and "device type" not in payload["message"]
    assert CANARY not in json.dumps(result) and content.decode().strip() not in json.dumps(result)
    assert len(server.writes()) == 1 and server.writes()[0].url.path.endswith("/files/upload")
    assert not server.jobs()
    assert (tmp_path / "source.cfg").read_bytes() == content
    for state in tmp_path.glob(".netconverter/**/*.json"):
        assert CANARY not in state.read_text()


@pytest.mark.parametrize("status,code,prior_timeout,cleared", [
    (422, "storage_quota_exceeded", False, True),
    (422, "unknown_refusal", False, False),
    (503, "storage_quota_exceeded", False, False),
    (403, "storage_quota_exceeded", False, False),
    (422, "storage_quota_exceeded", True, False),
])
def test_only_initial_typed_storage_refusal_clears_submission_receipt(
        tmp_path, status, code, prior_timeout, cleared):
    """Real bridge/journal with mocked HTTP; ambiguity never authorizes cleanup."""
    content = b"hostname synthetic-quota-journal\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    confirmations = []

    def refuse(request):
        assert request.headers["Authorization"] == "Bearer nck_synthetic"
        if request.url.path.endswith("/files/upload"):
            server.requests.append(request)
            if prior_timeout and len(server.writes()) == 1:
                raise httpx.ReadTimeout("synthetic ambiguity", request=request)
            return httpx.Response(status, json={"success": False,
                "error": {"code": code, "message": CANARY}})
        return server(request)

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(refuse))
    bridge.confirm_upload = lambda details: confirmations.append(details) or "accept"
    args = {"path": "source.cfg", "source_vendor": "cisco_asa",
            "target_vendor": "palo_alto_set", "job_type": "convert"}
    receipt_dir = tmp_path / ".netconverter/submissions"
    if prior_timeout:
        assert bridge.call("submit_file", args)["isError"] is True
        prior_receipts = {p.name: p.read_bytes() for p in receipt_dir.glob("*.json")}
        assert len(prior_receipts) == 1
    result = bridge.call("submit_file", args)
    assert result["isError"] is True
    receipts = {p.name: p.read_bytes() for p in receipt_dir.glob("*.json")}
    assert len(server.writes()) == (2 if prior_timeout else 1), "No automatic retry"
    assert all(r.method in {"GET", "POST"} for r in server.requests), "No remote deletion"
    assert all(r.url.path.endswith("/files/upload") for r in server.writes())
    assert not server.jobs()
    assert len(confirmations) == 1
    assert (tmp_path / "source.cfg").read_bytes() == content
    assert CANARY not in json.dumps(result)
    assert len(receipts) == (0 if cleared else 1)
    if prior_timeout:
        assert receipts == prior_receipts, "An ambiguous earlier attempt keeps its exact receipt"


@pytest.mark.parametrize("unsafe", [True, -1, 1.5, 2**53, CANARY, {"source": CANARY}, [CANARY]])
def test_quota_metadata_is_strictly_integer_bounded_and_allowlisted(unsafe):
    failure = _submission_api_failure(APIError(422, "storage_quota_exceeded", CANARY,
        detail={"requested_bytes": 7, "available_bytes": unsafe, "source_config": CANARY}, message=CANARY))
    assert failure.code == "storage_quota_exceeded"
    assert failure.extra["storage_quota"] == {"requested_bytes": 7}
    assert CANARY not in str(failure) and CANARY not in json.dumps(failure.extra)


def test_unknown_422_and_untyped_quota_wording_keep_generic_safe_handling():
    failure = _submission_api_failure(APIError(422, "unprocessable", message="Insufficient storage " + CANARY,
        detail=COUNTS))
    assert failure.code == "unprocessable"
    assert "source format" in str(failure)
    assert "storage_quota" not in failure.extra and CANARY not in str(failure)
