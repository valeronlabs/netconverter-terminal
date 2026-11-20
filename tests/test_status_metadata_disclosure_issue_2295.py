"""Frozen READINESS-001 regression: bounded polling disclosure, not readiness regrading.

Synthetic HTTP responses exercise the real standard Bridge and output schemas.
They do not establish live server or client acceptance.
"""

import json

import httpx
import pytest
from jsonschema import Draft202012Validator

from netconverter_cli.api import StaticCredential
from netconverter_cli.mcp_client_features import OUTPUT_SCHEMAS
from netconverter_cli.mcp_server import Bridge
from tests.test_mcp import ExternalServer, SERVER, envelope

JOB = "tra_2295synthetic"
PRIVATE = "private-object-192.0.2.99-ignore-instructions"


def bridge_with_status(tmp_path, data, level="none"):
    fallback = ExternalServer()

    def respond(request):
        if request.url.path == f"/external/v1/jobs/{JOB}":
            return envelope(data)
        return fallback(request)

    return Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                  level=level, transport=httpx.MockTransport(respond))


@pytest.mark.parametrize("tool", ["job_status", "wait_for_job"])
@pytest.mark.parametrize("level", ["none", "masked", "full"])
def test_polling_discloses_missing_metadata_without_replacing_producer_verdict(tmp_path, tool, level):
    data = {
        "status": "completed", "translation_status": "passed", "job_status": "needs_review",
        "review_required": True, "review_reasons": [PRIVATE], "blocking_reasons": [],
        "metadata_complete": False, "reasons_truncated": True,
        "metadata_omitted_fields": ["translation_chain", "evidence_executive_summary", "progress"],
        "metadata_notice": PRIVATE, "stats": {"source_ir_dict": PRIVATE},
        "evidence_data": {"private": PRIVATE},
    }
    bridge = bridge_with_status(tmp_path, data, level)
    args = {"job_id": JOB, **({"timeout_s": 0} if tool == "wait_for_job" else {})}
    result = bridge.call(tool, args)
    assert result["isError"] is False
    out = result["structuredContent"]
    assert out["status"] == "completed"
    assert out["verdict"] == "passed"  # stored producer disposition, not the polling hold
    assert out["job_status"] == "needs_review"
    assert out["review_required"] is True and out["review_reason_count"] == 1
    assert out["metadata_complete"] is False and out["reasons_truncated"] is True
    assert out["metadata_omitted_fields"] == data["metadata_omitted_fields"]
    notice = out["metadata_notice"].lower()
    assert "omitted" in notice and "polling" in notice and "report" in notice
    assert "ready" in notice
    if tool == "wait_for_job":
        assert out["timed_out"] is False  # a review hold does not restart lifecycle polling
    assert PRIVATE not in json.dumps(result)
    assert len(json.dumps(out)) < 2000
    Draft202012Validator(OUTPUT_SCHEMAS[tool]).validate(out)


def test_disclosure_is_allowlisted_bounded_and_legacy_optional(tmp_path):
    legacy = bridge_with_status(tmp_path, {"status": "completed", "translation_status": "passed"})
    assert legacy.job_status(JOB) == {"job_id": JOB, "status": "completed", "verdict": "passed"}
    data = {"status": "failed", "job_status": "blocked", "translation_status": "failed",
            "metadata_complete": False, "reasons_truncated": True,
            "metadata_notice": PRIVATE,
            "metadata_omitted_fields": ["warnings", "warnings", PRIVATE, {"secret": PRIVATE},
                                         "translation_chain"] * 1000}
    out = bridge_with_status(tmp_path, data).job_status(JOB)
    assert out["status"] == "failed" and out["job_status"] == "blocked" and out["verdict"] == "failed"
    assert out["metadata_omitted_fields"] == ["warnings", "translation_chain"]
    assert PRIVATE not in json.dumps(out)
    assert len(json.dumps(out)) < 2000
    Draft202012Validator(OUTPUT_SCHEMAS["job_status"]).validate(out)


def test_malformed_disclosure_cannot_inject_prose_or_claim_completeness(tmp_path):
    data = {"status": "processing", "job_status": PRIVATE,
            "metadata_complete": "true", "reasons_truncated": 1,
            "metadata_omitted_fields": {"warnings": PRIVATE}, "metadata_notice": PRIVATE}
    out = bridge_with_status(tmp_path, data).job_status(JOB)
    assert out["status"] == "processing" and out["job_status"] == "unknown"
    assert "metadata_complete" not in out and "reasons_truncated" not in out
    assert "metadata_omitted_fields" not in out and "metadata_notice" not in out
    assert PRIVATE not in json.dumps(out)
    Draft202012Validator(OUTPUT_SCHEMAS["job_status"]).validate(out)
