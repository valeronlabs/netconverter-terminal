"""aws#1494: the bridge proxies the hosted ``why_needs_review`` tool (hosted/bridge parity).

It is a scrubbed summary like ``get_evidence``'s digest, so it is in the strict set and
listed at every exposure level when the server offers it. An older server that does not
offer it gets a clear "needs a newer NetConverter server" error, not unknown_tool.
Mocked transport only; this does not prove a live server.
"""

import json

import httpx
import pytest

from netconverter_cli import mcp_client_features
from netconverter_cli.api import StaticCredential
from netconverter_cli.mcp_server import (REMOTE_TOOLS_DEFAULT, REMOTE_TOOLS_STRICT, SERVER_ADDED_TOOLS, Bridge,
                                         remote_allowed)
from netconverter_cli.remote_mcp import RemoteMCP
from tests.test_mcp import LOCAL, QuickServer
from tests.test_strict_view_015 import LEAK, ViewServer

ANSWER = {
    "translation_status": "needs_review", "held": True, "blocking_reasons": [],
    "holds": [{"rank": 1, "gate": "nat_review", "title": "NAT needs review", "severity": "review",
               "count": 2, "first_to_hold": True, "items": [LEAK], "items_truncated": False,
               "remediation": "Check the NAT rules.", "evidence_section": "warnings"}],
    "converter_flagged": {"count": 0, "items": []}, "other_notes_count": 0, "basis": "ledger",
    "answer": "One check holds this job.",
}


class WhyServer(ViewServer):
    def __init__(self, tools, view_mode="default"):
        super().__init__(view_mode)
        self.tools = tools

    def __call__(self, request):
        message = json.loads(request.content)
        if message.get("method") == "tools/list":
            self.requests.append(request)
            schema = {"type": "object", "properties": {"job_id": {"type": "string"}}, "additionalProperties": False}
            result = {"tools": [{"name": n, "description": "d", "inputSchema": schema} for n in self.tools]}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})
        if message.get("method") == "tools/call" and message["params"]["name"] == "why_needs_review":
            self.requests.append(request)
            payload = {"tool": "why_needs_review", "success": True, "data": ANSWER, "error": None}
            result = {"content": [{"type": "text", "text": json.dumps(payload)}],
                      "structuredContent": payload, "isError": False}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})
        return super().__call__(request)


def bridge_with(tmp_path, tools, strict=True):
    server = WhyServer(tools)
    remote = RemoteMCP("https://api.example/mcp/v1/", StaticCredential("REMOTE_TOKEN"),
                       transport=httpx.MockTransport(server), view_mode="strict" if strict else None)
    bridge = Bridge(tmp_path, "https://api.example/external/v1", StaticCredential("nck_synthetic"), remote,
                    transport=httpx.MockTransport(QuickServer()), strict=strict)
    return bridge, server


def text_of(result):
    return json.loads(result["content"][0]["text"])


def test_why_needs_review_is_allowlisted_in_the_strict_set():
    assert "why_needs_review" in REMOTE_TOOLS_STRICT <= REMOTE_TOOLS_DEFAULT
    assert remote_allowed("why_needs_review") and remote_allowed("why_needs_review", REMOTE_TOOLS_STRICT)
    assert SERVER_ADDED_TOOLS <= REMOTE_TOOLS_DEFAULT


@pytest.mark.parametrize("strict", [True, False])
def test_listed_with_the_servers_job_id_schema_and_forwarded(tmp_path, strict):
    bridge, server = bridge_with(tmp_path, ("get_account", "get_evidence", "why_needs_review"), strict=strict)
    tools = {t["name"]: t for t in bridge.list_tools()}
    assert [n for n in tools if n not in LOCAL] == ["get_account", "get_evidence", "why_needs_review"]
    assert tools["why_needs_review"]["inputSchema"]["properties"] == {"job_id": {"type": "string"}}
    result = bridge.call("why_needs_review", {"job_id": "tra_1"})
    assert result["isError"] is False
    data = result["structuredContent"]["data"]
    assert data["basis"] == "ledger" and data["holds"][0]["gate"] == "nat_review"
    call = [json.loads(r.content) for r in server.requests if json.loads(r.content).get("method") == "tools/call"
            and json.loads(r.content)["params"]["name"] == "why_needs_review"]
    assert call[0]["params"]["arguments"] == {"job_id": "tra_1"}
    if strict:  # addresses masked in the result, like every remote result under strict
        assert "10.10.0.53" not in json.dumps(result) and "<ip>" in data["holds"][0]["items"][0]


def test_strict_never_refuses_it_locally(tmp_path):
    bridge, server = bridge_with(tmp_path, ("get_account", "why_needs_review"))
    assert bridge.call("why_needs_review", {})["isError"] is False  # no args: the selected job
    assert "why_needs_review" in server.calls()


@pytest.mark.parametrize("strict", [True, False])
def test_older_server_says_it_needs_a_newer_server(tmp_path, strict):
    bridge, server = bridge_with(tmp_path, ("get_account", "get_evidence"), strict=strict)
    assert "why_needs_review" not in [t["name"] for t in bridge.list_tools()]
    result = bridge.call("why_needs_review", {"job_id": "tra_1"})
    payload = text_of(result)
    assert result["isError"] is True and payload["error"] == "server_upgrade_required"
    assert "needs a newer NetConverter server" in payload["message"]
    assert "why_needs_review" not in server.calls()  # never forwarded
    assert text_of(bridge.call("not_a_tool", {}))["error"] == "unknown_tool"


def test_prompts_point_at_it():
    for name in ("guided-migration", "mapping-review"):
        assert "why_needs_review" in mcp_client_features._TEXT[name]
