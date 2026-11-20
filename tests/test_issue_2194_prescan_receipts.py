"""The bridge transports server approval receipts; it cannot issue approval."""
import copy
import json

import pytest

from netconverter_cli.mcp_server import Bridge


TOOLS = ("request_submission_review", "get_submission_approval", "submit_conversion")
REQUEST = {"job_id": "psc_synthetic", "revision": 0,
           "draft_id": "draft_" + "a" * 32,
           "approval_ref": "approval_" + "b" * 32,
           "idempotency_key": "synthetic-review-retry"}


class ApprovalRemote:
    view_mode = "full"

    def __init__(self, *, offered=True, schema=True, accepted=True):
        self.offered, self.schema, self.accepted = offered, schema, accepted
        self.calls = []

    def list_tools(self):
        names = TOOLS if self.offered else ("submit_conversion",)
        return [{"name": name, "inputSchema": {"type": "object", "properties":
                 {key: {"type": "string"} for key in ("draft_id", "approval_ref", "idempotency_key")}
                 if name == "submit_conversion" and self.schema else {}}} for name in names]

    def call_tool(self, name, arguments):
        self.calls.append((name, copy.deepcopy(arguments)))
        value = ({"job_id": "tra_synthetic", "status": "queued"} if self.accepted
                 else {"error": "approval_required"})
        return {"isError": not self.accepted,
                "content": [{"type": "text", "text": json.dumps(value)}]}

    def account_view(self):
        return "strict" if self.view_mode != "full" else "default"


def make_bridge(tmp_path, **kwargs):
    level = kwargs.pop("level", "full")
    remote = ApprovalRemote(**kwargs)
    bridge = Bridge(tmp_path, "https://api.example/external/v1", remote=remote, level=level)
    bridge.confirm_apply = lambda _: pytest.fail("Repeated approval form")
    return bridge, remote


def error(result):
    assert result["isError"]
    return json.loads(result["content"][0]["text"])["error"]


def test_review_and_receipt_tools_are_discovered_without_another_form(tmp_path):
    bridge, remote = make_bridge(tmp_path)
    assert set(TOOLS) <= {item["name"] for item in bridge.list_tools()}
    for tool in TOOLS[:2]:
        assert not bridge.call(tool, {"job_id": REQUEST["job_id"]})["isError"]
    assert [name for name, _ in remote.calls] == list(TOOLS[:2])


def test_server_receipt_submission_does_not_repeat_confirmation(tmp_path):
    bridge, remote = make_bridge(tmp_path)
    assert not bridge.call("submit_conversion", REQUEST)["isError"]
    assert remote.calls == [("submit_conversion", REQUEST)]
    # Retry uses the exact server key and receipt; the server owns idempotency.
    bridge.call("submit_conversion", REQUEST)
    assert remote.calls[-1] == remote.calls[0]


def test_invalid_or_pending_receipt_is_refused_by_server_without_local_fallback(tmp_path):
    bridge, remote = make_bridge(tmp_path, accepted=False)
    assert error(bridge.call("submit_conversion", REQUEST)) == "approval_required"
    assert len(remote.calls) == 1


@pytest.mark.parametrize("kwargs", [{"offered": False}, {"schema": False}])
def test_receipt_never_reaches_an_old_server_that_might_ignore_it(tmp_path, kwargs):
    bridge, remote = make_bridge(tmp_path, **kwargs)
    assert error(bridge.call("submit_conversion", REQUEST)) == "server_upgrade_required"
    assert not remote.calls


@pytest.mark.parametrize("change", [{"draft_id": None}, {"approval_ref": "agent-says-yes"},
                                    {"idempotency_key": "short"}, {"revision": True},
                                    {"revision": None}, {"confirm_token": "old-local-token"}])
def test_incomplete_receipt_arguments_do_not_fall_back_to_local_confirmation(tmp_path, change):
    bridge, remote = make_bridge(tmp_path)
    assert error(bridge.call("submit_conversion", {**REQUEST, **change})) == "invalid_arguments"
    assert not remote.calls


def test_receipt_tools_are_unavailable_below_full_exposure(tmp_path):
    bridge, remote = make_bridge(tmp_path, level="masked")
    assert not set(TOOLS) & {item["name"] for item in bridge.list_tools()}
    assert error(bridge.call("submit_conversion", REQUEST)) == "unknown_tool"
    assert not remote.calls


@pytest.mark.parametrize('schema', [None, [], 'legacy-invalid-schema'])
def test_malformed_submit_schema_cannot_break_discovery_or_enable_receipts(tmp_path, schema):
    bridge, remote = make_bridge(tmp_path)
    advertised = remote.list_tools()
    next(tool for tool in advertised if tool['name'] == 'submit_conversion')['inputSchema'] = schema
    remote.list_tools = lambda: advertised
    assert 'request_submission_review' in {tool['name'] for tool in bridge.list_tools()}
    assert error(bridge.call('submit_conversion', REQUEST)) == 'server_upgrade_required'
    assert not remote.calls


def test_no_receipt_local_acceptance_cannot_override_server_approval_required(tmp_path):
    bridge, remote = make_bridge(tmp_path, accepted=False)
    asked = []
    bridge.confirm_apply = lambda details: asked.append(details) or 'accept'
    legacy = {'job_id': REQUEST['job_id'], 'revision': 0}
    assert error(bridge.call('submit_conversion', legacy)) == 'approval_required'
    assert len(asked) == 1 and remote.calls == [('submit_conversion', legacy)]
    assert not bridge._confirm_tokens


def test_receipt_contract_is_rechecked_after_tool_list_refresh(tmp_path):
    bridge, remote = make_bridge(tmp_path)
    bridge.list_tools()
    assert bridge._prescan_receipts
    remote.schema = False
    bridge.list_tools()
    assert error(bridge.call('submit_conversion', REQUEST)) == 'server_upgrade_required'
    assert not remote.calls


def test_receipt_stdio_does_not_emit_elicitation_or_change_arguments(tmp_path):
    import io
    from netconverter_cli.mcp_server import StdioServer
    bridge, remote = make_bridge(tmp_path)
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'capabilities': {'elicitation': {'form': {}}}}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {
            'name': 'submit_conversion', 'arguments': REQUEST}},
    ]
    output = io.StringIO()
    StdioServer(bridge).serve(io.StringIO(''.join(json.dumps(m) + '\n' for m in messages)), output)
    replies = [json.loads(line) for line in output.getvalue().splitlines()]
    assert not any(item.get('method') == 'elicitation/create' for item in replies)
    assert not next(item['result'] for item in replies if item.get('id') == 2)['isError']
    assert remote.calls == [('submit_conversion', REQUEST)]


def test_approval_handles_survive_existing_secret_filter_without_exposing_credentials(tmp_path):
    bridge, remote = make_bridge(tmp_path)
    body = {'draft_id': REQUEST['draft_id'], 'approval_ref': REQUEST['approval_ref'],
            'status': 'approved', 'password': 'synthetic-private-credential'}
    remote.call_tool = lambda name, arguments: {
        'isError': False, 'structuredContent': copy.deepcopy(body),
        'content': [{'type': 'text', 'text': json.dumps(body)}]}
    response = bridge.call('get_submission_approval', {'job_id': REQUEST['job_id'], 'draft_id': REQUEST['draft_id']})
    assert 'synthetic-private-credential' not in json.dumps(response)
    for value in (response['structuredContent'], json.loads(response['content'][0]['text'])):
        assert value['draft_id'] == REQUEST['draft_id']
        assert value['approval_ref'] == REQUEST['approval_ref']


@pytest.mark.parametrize('missing', TOOLS)
def test_each_missing_contract_tool_refuses_receipt_submission(tmp_path, missing):
    bridge, remote = make_bridge(tmp_path)
    advertised = [tool for tool in remote.list_tools() if tool['name'] != missing]
    remote.list_tools = lambda: advertised
    assert error(bridge.call('submit_conversion', REQUEST)) in {'unknown_tool', 'server_upgrade_required'}
    assert not remote.calls
