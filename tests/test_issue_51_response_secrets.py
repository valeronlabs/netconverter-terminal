"""Synthetic credential values must never cross the model response boundary."""
import copy
import json

import pytest

from netconverter_cli import exposure
from tests import test_exposure_levels_013 as harness

MARKER = "SYNTHETIC_CREDENTIAL_MUST_NOT_REACH_MODEL_51"


@pytest.mark.parametrize("level", exposure.LEVELS)
@pytest.mark.parametrize("key", ["api_key", "api-key", "apiKey", "API_KEY", "access_token", "refreshToken"])
def test_structured_credentials_are_removed_at_every_exposure(tmp_path, monkeypatch, level, key):
    payload = copy.deepcopy(harness.RESULT)
    payload["data"]["provider"] = {key: MARKER}
    monkeypatch.setattr(harness, "RESULT", payload)
    result, _ = harness.report(tmp_path, level)
    assert MARKER not in json.dumps(result)
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


@pytest.mark.parametrize("level", exposure.LEVELS)
@pytest.mark.parametrize("key", ["apiKey", "PASSWORD", "private-key", "access_token"])
@pytest.mark.parametrize("credential", [928317406291, 0, 928317406291.25])
def test_numeric_credential_fields_are_not_treated_as_summary_counts(
        tmp_path, monkeypatch, level, key, credential):
    payload = copy.deepcopy(harness.RESULT)
    payload["data"]["provider"] = {key: credential, "api_key_count": 2,
                                     "password_length": 12, "api_key_present": True}
    monkeypatch.setattr(harness, "RESULT", payload)
    result, _ = harness.report(tmp_path, level)
    provider = result["structuredContent"]["data"]["provider"]
    assert key not in provider or provider[key] == exposure.SECRET
    assert provider["api_key_count"] == 2
    assert provider["password_length"] == 12
    assert provider["api_key_present"] is True
    assert payload["data"]["provider"][key] == credential
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


@pytest.mark.parametrize("secret", [{"value": MARKER}, [{"value": MARKER}], [MARKER, {"nested": MARKER}]])
def test_structured_credential_container_does_not_lose_its_secret_parent(secret):
    source = {"password": secret, "psk_configured": True, "counts": {"rules": 20}}
    projected = exposure.strip_secrets(source)
    assert MARKER not in json.dumps(projected)
    assert projected["psk_configured"] is True
    assert projected["counts"]["rules"] == 20
    assert MARKER in json.dumps(source), "projection must not rewrite the original evidence"


def test_depth_limit_does_not_return_unfiltered_subtree(tmp_path, monkeypatch):
    nested = {"password": MARKER}
    for _ in range(45):
        nested = {"details": nested}
    payload = copy.deepcopy(harness.RESULT)
    payload["data"]["nested"] = nested
    monkeypatch.setattr(harness, "RESULT", payload)
    result, _ = harness.report(tmp_path, "full")
    assert MARKER not in json.dumps(result)
    assert "depth limit" in json.dumps(result)


def test_opaque_review_and_paging_handles_stay_usable():
    controls = {"draft_id": "draft_" + "a" * 32, "approval_ref": "approval_" + "b" * 32,
                "idempotency_key": "synthetic-stable-request", "cursor": "opaque-page-cursor",
                "confirm_token": "opaque-local-confirmation", "document_sha256": "c" * 64,
                "api_key_present": True, "api_key_count": 2}
    assert exposure.strip_secrets(controls) == controls


@pytest.mark.parametrize("level", exposure.LEVELS)
@pytest.mark.parametrize("key", [f"pre-shared-key {MARKER}",
    f"snmp-server community {MARKER} RO", f"$6$salt${MARKER}"])
def test_recognized_secret_syntax_in_mapping_keys_is_redacted(tmp_path, monkeypatch, level, key):
    payload = copy.deepcopy(harness.RESULT)
    payload["data"]["observed_lines"] = {key: 1}
    monkeypatch.setattr(harness, "RESULT", payload)
    result, _ = harness.report(tmp_path, level)
    assert MARKER not in json.dumps(result)
    assert list(result["structuredContent"]["data"]["observed_lines"].values()) == [1]
    assert payload["data"]["observed_lines"] == {key: 1}


def test_mapping_key_redaction_keeps_distinct_entries_and_safe_handles():
    source = {"pre-shared-key first_synthetic_credential": 1,
              "pre-shared-key second_synthetic_credential": 2,
              "pre-shared-key <secret>": 3,
              "pre-shared-key <secret> [redacted key 1]": 4,
              "approval_ref": "approval_synthetic", "cursor": "cursor_synthetic"}
    projected = exposure.strip_secrets(source)
    assert "first_synthetic_credential" not in json.dumps(projected)
    assert "second_synthetic_credential" not in json.dumps(projected)
    assert len(projected) == len(source)
    assert sorted(value for value in projected.values() if isinstance(value, int)) == [1, 2, 3, 4]
    assert projected["approval_ref"] == source["approval_ref"]
    assert projected["cursor"] == source["cursor"]
    assert exposure.strip_secrets(projected) == projected


def test_redacted_hash_key_does_not_turn_ordinary_metadata_into_credentials():
    metadata = {"status": "configured", "count": 2}
    source = {f"$6$salt${MARKER}": metadata}
    projected = exposure.strip_secrets(source)
    assert MARKER not in json.dumps(projected)
    assert list(projected.values()) == [metadata]
    assert exposure.strip_secrets(projected) == projected
