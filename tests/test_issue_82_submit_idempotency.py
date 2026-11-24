"""#82: ordinary retry keys are not portal approval receipts."""
import copy
import json

import pytest

from tests.test_issue_2194_prescan_receipts import REQUEST, error, make_bridge


ORDINARY = {key: REQUEST[key] for key in ("job_id", "revision", "idempotency_key")}


@pytest.mark.parametrize("offered", [False, True])
def test_key_only_submission_uses_local_confirmation_and_preserves_retry_key(tmp_path, offered):
    bridge, remote = make_bridge(tmp_path, offered=offered)
    asked = []
    bridge.confirm_apply = lambda details: asked.append(details) or "accept"

    result = bridge.call("submit_conversion", dict(ORDINARY))

    assert result["isError"] is False, result
    assert len(asked) == 1 and asked[0]["revision"] == ORDINARY["revision"]
    assert remote.calls == [("submit_conversion", ORDINARY)]


def test_key_only_submission_keeps_confirmation_token_bound_to_exact_arguments(tmp_path):
    bridge, remote = make_bridge(tmp_path, offered=False)
    bridge.confirm_apply = lambda _: "client_declined"
    pending = bridge.call("submit_conversion", dict(ORDINARY))
    assert error(pending) == "confirmation_required"
    token = json.loads(pending["content"][0]["text"])["confirm_token"]
    assert not remote.calls

    result = bridge.call("submit_conversion", {**ORDINARY, "confirm_token": token})
    assert result["isError"] is False
    assert remote.calls == [("submit_conversion", ORDINARY)]
    assert error(bridge.call("submit_conversion", {**ORDINARY, "confirm_token": token})) == "invalid_confirm_token"


def test_key_only_submission_cannot_override_server_approval_requirement(tmp_path):
    bridge, remote = make_bridge(tmp_path, accepted=False)
    bridge.confirm_apply = lambda _: "accept"
    assert error(bridge.call("submit_conversion", dict(ORDINARY))) == "approval_required"
    assert remote.calls == [("submit_conversion", ORDINARY)]


def test_declined_key_only_submission_never_reaches_server(tmp_path):
    bridge, remote = make_bridge(tmp_path, offered=False)
    bridge.confirm_apply = lambda _: "decline"
    assert error(bridge.call("submit_conversion", dict(ORDINARY))) == "apply_declined"
    assert not remote.calls


@pytest.mark.parametrize("marker", ["draft_id", "approval_ref"])
@pytest.mark.parametrize("offered", [False, True])
def test_partial_receipt_still_refuses_local_confirmation_fallback(tmp_path, marker, offered):
    bridge, remote = make_bridge(tmp_path, offered=offered)
    result = bridge.call("submit_conversion", {**ORDINARY, marker: REQUEST[marker]})
    assert error(result) == ("invalid_arguments" if offered else "server_upgrade_required")
    assert not remote.calls


def test_ordinary_retry_preserves_arguments_and_server_noop_receipt(tmp_path):
    bridge, remote = make_bridge(tmp_path, offered=False)
    bridge.confirm_apply = lambda _: "accept"
    replies = [{"job_id": "tra_synthetic", "status": "queued", "already_submitted": value}
               for value in (False, True)]

    def call_tool(name, arguments):
        remote.calls.append((name, copy.deepcopy(arguments)))
        return {"isError": False, "content": [{"type": "text", "text": json.dumps(replies[len(remote.calls) - 1])}]}

    remote.call_tool = call_tool
    # Server responses are fixtures: deduplication is owned and verified by the backend.
    for expected in replies:
        result = bridge.call("submit_conversion", dict(ORDINARY))
        assert result["isError"] is False
        assert json.loads(result["content"][0]["text"]) == expected
    assert remote.calls == [("submit_conversion", ORDINARY)] * 2
