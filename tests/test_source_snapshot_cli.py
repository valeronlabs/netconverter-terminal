"""One-shot CLI boundary for opaque ZIP transport; synthetic HTTP only."""
import json

import httpx
import pytest

from netconverter_cli import cli, errors
from netconverter_cli.api import Client, StaticCredential
from tests.test_issue_2195_file_transport import SERVER, UploadServer, client
from tests.test_mcp import QuickServer
from tests.test_source_snapshot_transport import bundle


def run_cli(tmp_path, monkeypatch, server, command="convert", *, quick=False):
    (tmp_path / "handoff.zip").write_bytes(bundle())
    credential = StaticCredential("nck_synthetic")
    connection = (Client(credential, SERVER, transport=httpx.MockTransport(server))
                  if quick else client(server))
    monkeypatch.setattr(cli, "rest_credential", lambda *a, **k: credential)
    monkeypatch.setattr(cli, "open_client", lambda *a, **k: (connection, "quick" if quick else "external"))
    argv = ["--workspace", str(tmp_path), "--server", SERVER, command,
            "handoff.zip", "--vendor", "cisco_asa"]
    if command == "convert":
        argv += ["--to", "palo_alto_set"]
    try:
        cli.main(argv)
    except SystemExit as outcome:
        return outcome.code
    return 0


class CliUploadServer(UploadServer):
    def __init__(self, *, file_transport=True):
        super().__init__(bundle())
        self.file_transport = file_transport

    def __call__(self, request):
        response = super().__call__(request)
        if request.url.path.endswith("/capabilities"):
            body = response.json()
            body["data"]["vendors"] = [{"code": "cisco_asa", "roles": ["source"]}]
            body["data"]["limits"]["file_id_submission"] = self.file_transport
            return httpx.Response(200, json=body)
        return response


def test_cli_convert_transports_archive_as_verified_file_id(tmp_path, monkeypatch, capsys):
    server = CliUploadServer()
    assert run_cli(tmp_path, monkeypatch, server) == 0
    assert server.jobs()[0]["file_id"] == "file_synthetic"
    assert "source_config" not in server.jobs()[0]
    upload = next(r for r in server.writes() if r.url.path.endswith("files/upload"))
    assert b'filename="configuration.zip"' in upload.content
    captured = capsys.readouterr()
    assert "SYNTHETIC_PRIVATE_BUNDLE_MEMBER" not in captured.out + captured.err


@pytest.mark.parametrize("command", ["validate", "analyze", "optimize"])
def test_cli_analysis_archives_refuse_before_authentication(tmp_path, monkeypatch, command):
    (tmp_path / "handoff.zip").write_bytes(bundle())
    monkeypatch.setattr(cli, "rest_credential", lambda *a, **k: pytest.fail("authentication reached"))
    with pytest.raises(SystemExit) as outcome:
        cli.main(["--workspace", str(tmp_path), command, "handoff.zip", "--vendor", "cisco_asa"])
    assert outcome.value.code == errors.EXIT_INPUT


@pytest.mark.parametrize("profile", ["quick", "legacy_inline"])
def test_cli_convert_archive_requires_full_api_file_transport(tmp_path, monkeypatch, profile):
    quick = profile == "quick"
    server = QuickServer() if quick else CliUploadServer(file_transport=False)
    assert run_cli(tmp_path, monkeypatch, server, quick=quick) == errors.EXIT_INPUT
    assert not [r for r in server.requests if r.method == "POST"]
    state_file = tmp_path / ".netconverter/session.json"
    assert not state_file.exists() or "pending" not in json.loads(state_file.read_text())
