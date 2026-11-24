"""#86/#80: hosted tools need bridge discovery and the existing queue confirmation.

Frozen public tool schemas from the authorized hosted tools/list on 2026-11-24;
all calls/results below are synthetic. This proves transport, not server admission.
"""
import copy
import json
from pathlib import Path

import pytest

from netconverter_cli import exposure
from netconverter_cli.mcp_server import Bridge, LOCAL_NAMES
from tests.test_guided_prescan_037 import instant_decline, payload, reply, run


TOOLS = json.loads((Path(__file__).parent / "fixtures/issue_86_hosted_tools.json").read_text())
STRICT_READS = {"get_mop", "list_artifacts", "diff_runs"}
FULL_READS = {"prove_flows", "explain_rule", "list_source_files"}
FILE = "00000000-0000-4000-8000-000000000086"
START = {"file_id": FILE, "source_vendor": "cisco_asa", "target_vendor": "palo_alto_set",
         "device_type": "firewall", "idempotency_key": "synthetic-job-86"}
WRITES = {"start_prescan": START, "start_job": {**START, "job_type": "convert"},
          "rerun_job": {"job_id": "tra_synthetic86", "idempotency_key": "synthetic-rerun-86"}}


class Remote:
    view_mode = "full"

    def __init__(self):
        self.tools = copy.deepcopy(TOOLS)
        self.calls = []
        self.refusal = None

    def list_tools(self):
        return self.tools

    def account_view(self):
        return "default" if self.view_mode == "full" else "strict"

    def call_tool(self, name, arguments):
        self.calls.append((name, copy.deepcopy(arguments)))
        data = {"error": self.refusal} if self.refusal else {"job_id": "tra_new86", "status": "queued"}
        return {"isError": bool(self.refusal), "content": [{"type": "text", "text": json.dumps(data)}]}


def make_bridge(tmp_path, level="full", **kwargs):
    remote = Remote()
    bridge = Bridge(tmp_path, "https://api.example/external/v1", remote=remote,
                    level=level, sections=list(exposure.SECTIONS), **kwargs)
    return bridge, remote


def test_full_discovery_preserves_hosted_schema_and_adds_only_local_confirmation(tmp_path):
    bridge, remote = make_bridge(tmp_path)
    original = copy.deepcopy(remote.tools)
    listed = {t["name"]: t for t in bridge.list_tools() if t["name"] not in LOCAL_NAMES}
    assert set(listed) == STRICT_READS | FULL_READS | set(WRITES)
    for tool in original:
        actual = copy.deepcopy(listed[tool["name"]])
        if tool["name"] in WRITES:
            assert actual["inputSchema"]["properties"].pop("confirm_token")["type"] == "string"
        if tool["name"] == "rerun_job":
            assert actual["inputSchema"]["required"][-2:] == ["job_id", "idempotency_key"]
            del actual["inputSchema"]["required"][-2:]
        assert actual == tool
    assert remote.tools == original


@pytest.mark.parametrize("level", ["none", "masked", "selected"])
def test_restricted_levels_only_offer_safe_reads_and_refuse_direct_write_calls(tmp_path, level):
    bridge, remote = make_bridge(tmp_path, level)
    assert {t["name"] for t in bridge.list_tools()} - LOCAL_NAMES == STRICT_READS
    bridge.confirm_apply = lambda _: pytest.fail("Hidden tools must not ask for approval")
    for name in FULL_READS | set(WRITES):
        assert bridge.call(name, dict(WRITES.get(name, {})))["isError"]
    assert not remote.calls
    for name in STRICT_READS:
        assert not bridge.call(name, {})["isError"]
    assert remote.view_mode == level


def test_new_reads_pass_through_without_confirmation(tmp_path):
    bridge, remote = make_bridge(tmp_path)
    bridge.confirm_apply = lambda _: pytest.fail("Read asked for queue approval")
    for name in STRICT_READS | FULL_READS:
        assert not bridge.call(name, {})["isError"]
    assert {name for name, _ in remote.calls} == STRICT_READS | FULL_READS


@pytest.mark.parametrize("name", WRITES)
@pytest.mark.parametrize("decision", ["decline", "cancel"])
def test_declined_or_cancelled_job_never_reaches_server(tmp_path, name, decision):
    bridge, remote = make_bridge(tmp_path)
    seen = []
    bridge.confirm_apply = lambda details: seen.append(details) or decision
    result = payload(bridge.call(name, dict(WRITES[name])))
    assert result["error"] == "apply_declined"
    assert result["reason"] == ("user_declined" if decision == "decline" else "form_dismissed")
    assert seen[0]["tool"] == name
    assert not remote.calls


@pytest.mark.parametrize("name", WRITES)
def test_exact_arguments_single_use_token_and_idempotency_are_preserved(tmp_path, name):
    bridge, remote = make_bridge(tmp_path)
    bridge.confirm_apply = lambda _: "client_declined"
    args = copy.deepcopy(WRITES[name])
    pending = payload(bridge.call(name, args))
    assert pending["error"] == "confirmation_required" and not remote.calls
    token = pending["confirm_token"]
    assert not bridge.call(name, {**args, "confirm_token": token})["isError"]
    assert remote.calls == [(name, args)]
    assert payload(bridge.call(name, {**args, "confirm_token": token}))["error"] == "invalid_confirm_token"
    token = payload(bridge.call(name, args))["confirm_token"]
    changed = {**args, "idempotency_key": "different-intended-job", "confirm_token": token}
    assert payload(bridge.call(name, changed))["error"] == "invalid_confirm_token"
    assert remote.calls == [(name, args)]


@pytest.mark.parametrize("name", WRITES)
def test_expired_token_or_lowered_exposure_cannot_queue(tmp_path, name):
    bridge, remote = make_bridge(tmp_path, workspace_level=True)
    exposure.set_level(tmp_path, "full", interactive=True, ask=lambda _: "raise to full")
    now = [1000.0]
    bridge._clock = lambda: now[0]
    bridge.confirm_apply = lambda _: "client_declined"
    args = WRITES[name]
    token = payload(bridge.call(name, dict(args)))["confirm_token"]
    now[0] += 601
    assert payload(bridge.call(name, {**args, "confirm_token": token}))["error"] == "invalid_confirm_token"
    token = payload(bridge.call(name, dict(args)))["confirm_token"]
    exposure.set_level(tmp_path, "masked", interactive=False)
    assert bridge.call(name, {**args, "confirm_token": token})["isError"]
    assert not remote.calls


@pytest.mark.parametrize("name", WRITES)
def test_only_advertised_tools_can_queue_and_server_refusals_remain_errors(tmp_path, name):
    bridge, remote = make_bridge(tmp_path)
    remote.tools = [t for t in remote.tools if t["name"] != name]
    bridge.confirm_apply = lambda _: pytest.fail("Unavailable tool asked for approval")
    assert bridge.call(name, WRITES[name])["isError"] and not remote.calls
    remote.tools = copy.deepcopy(TOOLS)
    bridge.list_tools()
    bridge.confirm_apply = lambda _: "accept"
    remote.refusal = "approval_required"
    assert payload(bridge.call(name, WRITES[name]))["error"] == "approval_required"
    assert remote.calls == [(name, WRITES[name])]


@pytest.mark.parametrize("name", WRITES)
def test_no_form_client_keeps_existing_approval_mode_and_retry_key(tmp_path, name):
    bridge, remote = make_bridge(tmp_path)
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": WRITES[name]}}
    sent = run(bridge, call, capabilities={})
    assert not any(m.get("method") == "elicitation/create" for m in sent)
    assert reply(sent, 2)["status"] == "queued"
    assert remote.calls == [(name, WRITES[name])]
    # Server admission owns deduplication; the bridge never generates a new retry key.
    assert not bridge.call(name, dict(WRITES[name]))["isError"]
    assert remote.calls == [(name, WRITES[name])] * 2


@pytest.mark.parametrize("job_type", ["validate", "optimize"])
def test_start_job_analysis_form_has_no_conversion_target(tmp_path, job_type):
    bridge, remote = make_bridge(tmp_path)
    args = {key: value for key, value in START.items() if key != "target_vendor"}
    args["job_type"] = job_type
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "start_job", "arguments": args}}
    sent = run(bridge, call, instant_decline())
    assert reply(sent, 2)["error"] == "confirmation_required"
    message = next(m["params"]["message"] for m in sent if m.get("method") == "elicitation/create")
    assert job_type in message and "firewall" in message and "cisco_asa" in message
    assert "palo_alto" not in message and "None" not in message
    assert not remote.calls


@pytest.mark.parametrize("job_id", [None, "", "../other", 86])
def test_rerun_requires_an_explicit_job_before_confirmation(tmp_path, job_id):
    bridge, remote = make_bridge(tmp_path)
    bridge.confirm_apply = lambda _: pytest.fail("A mutable selected job cannot be approved")
    args = {"idempotency_key": "synthetic-rerun-86"}
    if job_id is not None:
        args["job_id"] = job_id
    assert payload(bridge.call("rerun_job", args))["error"] == "invalid_arguments"
    assert not remote.calls


@pytest.mark.parametrize("name", WRITES)
@pytest.mark.parametrize("key", [None, "", "has spaces", "x" * 81, 86])
def test_queue_requires_a_stable_retry_key_before_confirmation(tmp_path, name, key):
    bridge, remote = make_bridge(tmp_path)
    bridge.confirm_apply = lambda _: pytest.fail("A non-idempotent job cannot be approved")
    args = {k: v for k, v in WRITES[name].items() if k != "idempotency_key"}
    if key is not None:
        args["idempotency_key"] = key
    assert payload(bridge.call(name, args))["error"] == "invalid_arguments"
    assert not remote.calls


@pytest.mark.parametrize("name", WRITES)
def test_lowering_exposure_during_confirmation_cancels_the_approved_call(tmp_path, name):
    bridge, remote = make_bridge(tmp_path, workspace_level=True)
    exposure.set_level(tmp_path, "full", interactive=True, ask=lambda _: "raise to full")

    def lower_and_accept(_):
        exposure.set_level(tmp_path, "masked", interactive=False)
        return "accept"

    bridge.confirm_apply = lower_and_accept
    assert payload(bridge.call(name, WRITES[name]))["error"] == "approval_context_changed"
    assert not remote.calls


@pytest.mark.parametrize("name", WRITES)
def test_stdio_form_describes_the_actual_job_and_fast_decline_requires_conversation(tmp_path, name):
    bridge, remote = make_bridge(tmp_path)
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": WRITES[name]}}
    sent = run(bridge, call, instant_decline())
    assert reply(sent, 2)["error"] == "confirmation_required"
    form = next(m["params"] for m in sent if m.get("method") == "elicitation/create")
    assert form["mode"] == "form"
    assert form["requestedSchema"]["properties"]["apply"]["default"] is False
    message = form["message"]
    if name == "rerun_job":
        assert "Re-run" in message and WRITES[name]["job_id"] in message and "current engine" in message
    else:
        assert FILE in message and START["source_vendor"] in message and START["target_vendor"] in message
        assert "firewall" in message and ("prescan" if name == "start_prescan" else "convert") in message
    assert "mapping answer" not in message
    assert not remote.calls
