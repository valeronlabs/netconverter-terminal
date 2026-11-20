"""#61: real CLI credential selection reaches the Bridge submission journal.

Synthetic credentials/configuration and MockTransport only; these are not live
server acceptance tests. The stdio runner is replaced, not credential selection
or the Bridge, so initial and lazy raw-string API keys exercise the real boundary.
"""
import hashlib
import json

import httpx
import pytest

from netconverter_cli import cli, mcp_server
from netconverter_cli.api import StaticCredential
from netconverter_cli.submission_journal import credential_scope
from tests.test_issue_2195_file_transport import SERVER, UploadServer


@pytest.mark.parametrize("auth,lazy", [("key", False), ("auto", False), ("key", True)])
@pytest.mark.parametrize("accept", [True, False], ids=["confirmed", "declined"])
def test_cli_key_submission_confirmation_and_durable_replay(
        tmp_path, monkeypatch, capsys, auth, lazy, accept):
    key = "nck_issue61_synthetic_private_marker"
    content = b"! issue61 synthetic configuration private marker\nASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    available = {"key": "" if lazy else key}
    monkeypatch.setattr(cli, "get_secret", lambda *_args, **_kwargs: available["key"])
    monkeypatch.setattr(cli, "keyring_problem", lambda: None)
    monkeypatch.setattr(cli, "_clerk_session", lambda: None)
    monkeypatch.delenv("NETCONVERTER_API_KEY", raising=False)
    server = UploadServer(content)
    confirmations, outputs, state_dirs = [], [], []
    revoked = False

    def handler(request):
        assert request.headers["Authorization"] == f"Bearer {key}"
        if revoked and "/jobs/" in request.url.path:
            return httpx.Response(403, json={"detail": "synthetic access revoked"})
        return server(request)

    def run_stdio(bridge):
        assert isinstance(bridge, mcp_server.Bridge)
        if not available["key"]:
            assert bridge.rest_credential is None and bridge._credential_loader is not None
            available["key"] = key
        bridge._transport = httpx.MockTransport(handler)
        bridge.confirm_upload = lambda details: confirmations.append(details) or (
            "accept" if accept else "decline")
        outputs.append(bridge.call("submit_file", {
            "path": "source.cfg", "source_vendor": "cisco_asa",
            "target_vendor": "palo_alto_set", "job_type": "prescan",
        }))
        state_dirs.append(bridge.workspace.state_dir)

    monkeypatch.setattr(mcp_server, "run_stdio", run_stdio)
    args = cli.parser().parse_args([
        "--server", SERVER, "mcp", "--workspace", str(tmp_path),
        "--auth", auth, "--no-remote", "--level", "masked",
    ])
    cli.run_mcp(args)
    assert len(confirmations) == 1
    assert confirmations[0] == {
        "path": "source.cfg", "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(), "job_type": "prescan",
        "source_vendor": "cisco_asa", "target_vendor": "palo_alto_set",
    }
    if accept:
        first = outputs[0]
        assert first["isError"] is False, first
        receipt = first["structuredContent"]
        assert receipt["job_id"] == "psc_0123456789ab"
        assert receipt["bytes"] == len(content)
        assert receipt["sha256"] == hashlib.sha256(content).hexdigest()
        # A fresh process uses its durable receipt and verifies current access.
        cli.run_mcp(args)
        assert outputs[1]["isError"] is False, outputs[1]
        assert outputs[1]["structuredContent"] == {**receipt, "replayed": True}
        assert len(confirmations) == 1
        assert len(server.writes()) == 2  # exactly one upload and one queue
        assert len(server.jobs()) == 1
        assert server.jobs()[0]["file_id"] == "file_synthetic"
        assert "source_config" not in server.jobs()[0]
        assert sum("/jobs/" in r.url.path for r in server.requests) == 1
        revoked = True
        cli.run_mcp(args)
        assert outputs[2]["isError"] is True
        assert len(server.writes()) == 2 and len(confirmations) == 1
        assert len(list((state_dirs[0] / "submissions").glob("*.json"))) == 1
    else:
        assert outputs[0]["isError"] is True
        assert "upload_declined" in json.dumps(outputs[0])
        assert not server.writes()
        assert not list((state_dirs[0] / "submissions").glob("*.json"))

    # Receipts, persisted metadata, confirmations and CLI logs reveal neither
    # the credential nor configuration content. Only the HTTP upload gets bytes.
    logs = capsys.readouterr()
    visible = json.dumps([outputs, confirmations]) + logs.out + logs.err
    for state_dir in set(state_dirs):
        for path in state_dir.rglob("*"):
            if path.is_file():
                visible += path.read_text()
    assert key not in visible
    assert content.decode() not in visible
    assert "issue61 synthetic configuration private marker" not in visible


def test_raw_key_and_credential_object_share_only_the_same_key_partition():
    key = "nck_issue61_synthetic_partition"
    assert credential_scope(key) == credential_scope(StaticCredential(key))
    assert credential_scope(key) != credential_scope("nck_issue61_different_partition")
