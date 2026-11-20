"""Frozen #63/#64 boundaries: actual CLI/Bridge, synthetic opaque bytes and HTTP.

These fixtures prove terminal transport and identity, not a valid manager bundle
or live server admission. Bundle interpretation remains exclusively server-side.
"""
import hashlib
import json
from contextlib import closing

import httpx
import pytest

from netconverter_cli import cli, mcp_server
from netconverter_cli.api import APIError
from netconverter_cli.backend import submit_external
from netconverter_cli.catalog import device_type_of
from tests.test_issue_2195_file_transport import SERVER, UploadServer, client
from tests.test_source_snapshot_transport import bundle
from tests.test_mcp import QuickServer


def launch(tmp_path, monkeypatch, server, arguments, *, accept=True):
    confirmations, outputs = [], []
    monkeypatch.setattr(cli, "get_secret", lambda *_a, **_kw: "nck_synthetic_63_64")
    monkeypatch.setattr(cli, "_clerk_session", lambda: None)

    def stdio(bridge):
        assert isinstance(bridge, mcp_server.Bridge)
        bridge._transport = httpx.MockTransport(server)
        bridge.confirm_upload = lambda details: confirmations.append(details) or (
            "accept" if accept else "decline")
        outputs.append(bridge.call("submit_file", arguments))

    monkeypatch.setattr(mcp_server, "run_stdio", stdio)
    cli.run_mcp(cli.parser().parse_args([
        "--server", SERVER, "mcp", "--workspace", str(tmp_path),
        "--auth", "key", "--no-remote", "--level", "masked",
    ]))
    return outputs[0], confirmations


def assert_private(tmp_path, outputs, confirmations, capsys):
    logs = capsys.readouterr()
    visible = json.dumps([outputs, confirmations]) + logs.out + logs.err
    for path in (tmp_path / ".netconverter").rglob("*"):
        if path.is_file():
            visible += path.read_text()
    for marker in ("SYNTHETIC_PRIVATE_BUNDLE_MEMBER", "nck_synthetic_63_64"):
        assert marker not in visible


@pytest.mark.parametrize("source", ["check_point", "cisco_fmc"])
@pytest.mark.parametrize("accept", [True, False], ids=["confirmed", "declined"])
def test_manager_prescan_opaque_transport_replay_and_confirmation(
        tmp_path, monkeypatch, capsys, source, accept):
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)
    args = {"path": "handoff.zip", "source_vendor": source,
            "target_vendor": "palo_alto_set", "job_type": "prescan"}
    first, confirmations = launch(tmp_path, monkeypatch, server, args, accept=accept)
    assert len(confirmations) == 1
    assert confirmations[0]["sha256"] == hashlib.sha256(content).hexdigest()
    assert confirmations[0]["bytes"] == len(content)
    outputs = [first]
    if accept:
        assert not first["isError"], first
        assert first["structuredContent"]["sha256"] == hashlib.sha256(content).hexdigest()
        assert first["structuredContent"]["bytes"] == len(content)
        replay, repeated = launch(tmp_path, monkeypatch, server, args)
        outputs.append(replay)
        assert not replay["isError"], replay
        assert replay["structuredContent"] == {**first["structuredContent"], "replayed": True}
        assert not repeated
        assert len(server.writes()) == 2 and len(server.jobs()) == 1
        assert server.jobs()[0] == {"source_vendor": source, "target_vendor": "palo_alto_set",
                                    "technology": "firewall", "file_id": "file_synthetic",
                                    "job_type": "prescan"}
        upload = next(r for r in server.writes() if r.url.path.endswith("files/upload"))
        assert content in upload.content and b'filename="configuration.zip"' in upload.content
        assert all(r.headers["Authorization"] == "Bearer nck_synthetic_63_64" for r in server.requests)
        assert sum("/jobs/" in r.url.path for r in server.requests) == 1
    else:
        assert first["isError"] and "upload_declined" in json.dumps(first)
        assert not server.writes()
        assert not list((tmp_path / ".netconverter/submissions").glob("*.json"))
    assert_private(tmp_path, outputs, confirmations, capsys)


@pytest.mark.parametrize("source", ["check_point", "cisco_fmc"])
def test_backend_manager_prescan_uses_same_file_transport(source):
    server = UploadServer(bundle())
    with closing(client(server)) as connection:
        result = submit_external(connection, server.content, source, "palo_alto_set", "prescan", {}, "synthetic-key")
    assert result["job_id"] == "psc_0123456789ab"
    assert len(server.writes()) == 2 and server.jobs()[0]["file_id"] == "file_synthetic"


def test_manager_prescan_still_refuses_quick_pilot(tmp_path, monkeypatch):
    (tmp_path / "handoff.zip").write_bytes(bundle())
    server = QuickServer()
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "handoff.zip", "source_vendor": "check_point",
        "target_vendor": "palo_alto_set", "job_type": "prescan"})
    assert result["isError"] and "not_available" in json.dumps(result)
    assert not confirmations and not [r for r in server.requests if r.method == "POST"]


@pytest.mark.parametrize("source,operation,legacy", [
    ("check_point", "validate", False), ("cisco_fmc", "optimize", False),
    ("cisco_asa", "prescan", False), ("palo_alto_panorama", "prescan", False),
    ("check_point", "prescan", True), ("cisco_fmc", "prescan", True),
])
def test_unsupported_archives_refuse_before_confirmation_or_upload(
        tmp_path, monkeypatch, source, operation, legacy):
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content, capabilities=not legacy)
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "handoff.zip", "source_vendor": source,
        "target_vendor": "palo_alto_set", "job_type": operation,
    })
    assert result["isError"] and not confirmations and not server.writes()


def test_old_server_manager_rejection_is_private_and_never_falls_back(tmp_path, monkeypatch, capsys):
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)

    def reject(request):
        if request.url.path.endswith("/jobs"):
            server.requests.append(request)
            return httpx.Response(422, json={"success": False, "error": {
                "code": "unprocessable", "message": "SYNTHETIC_PRIVATE_BUNDLE_MEMBER"}})
        return server(request)

    result, confirmations = launch(tmp_path, monkeypatch, reject, {
        "path": "handoff.zip", "source_vendor": "check_point",
        "target_vendor": "palo_alto_set", "job_type": "prescan",
    })
    assert result["isError"] and "unprocessable" in json.dumps(result)
    assert len(confirmations) == 1 and len(server.writes()) == 2 and len(server.jobs()) == 1
    assert "source_config" not in server.jobs()[0]
    assert server.jobs()[0]["job_type"] == "prescan"
    assert_private(tmp_path, [result], confirmations, capsys)


@pytest.mark.parametrize("source,target,canonical_source,canonical_target,kind", [
    ("aruba_cx", "cisco_ios_xe_switch", "aruba_cx_switch", "cisco_ios_xe_switch", "switch"),
    ("cisco_ios_xe_switch", "aruba_cx", "cisco_ios_xe_switch", "aruba_cx_switch", "switch"),
    ("fortinet_fortigate", "palo_alto_set", "fortinet", "palo_alto_set", "firewall"),
    ("checkpoint", "palo_alto_set", "check_point", "palo_alto_set", "firewall"),
    ("check-point", "palo_alto_set", "check_point", "palo_alto_set", "firewall"),
    ("cisco_ios_xe_router", "juniper_junos_router", "cisco_ios_xe_router", "juniper_junos_router", "router"),
    ("juniper_set_router", "cisco_ios_xe_router", "juniper_set_router", "cisco_ios_xe_router", "router"),
    ("juniper_junos_switch", "cisco_ios_xe_switch", "juniper_junos_switch", "cisco_ios_xe_switch", "switch"),
])
def test_canonical_identity_precedes_upload_confirmation_and_replay_binding(
        tmp_path, monkeypatch, source, target, canonical_source, canonical_target, kind):
    content = b"hostname synthetic-identity\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    args = {"path": "source.cfg", "source_vendor": source, "target_vendor": target, "job_type": "prescan"}
    first, confirmations = launch(tmp_path, monkeypatch, server, args)
    assert not first["isError"], first
    assert device_type_of(source) == kind
    assert confirmations[0]["source_vendor"] == canonical_source
    assert confirmations[0]["target_vendor"] == canonical_target
    assert server.jobs()[0]["source_vendor"] == canonical_source
    assert server.jobs()[0]["target_vendor"] == canonical_target
    assert server.jobs()[0]["technology"] == kind
    second, repeated = launch(tmp_path, monkeypatch, server, {
        **args, "source_vendor": canonical_source, "target_vendor": canonical_target})
    assert not second["isError"] and second["structuredContent"]["replayed"] is True
    assert not repeated and len(server.jobs()) == 1 and len(server.writes()) == 2


@pytest.mark.parametrize("source,target", [
    ("cisco_ios_xe", "juniper_junos_router"), ("juniper_junos", "cisco_ios_xe_router"),
    ("invented_switch", "aruba_cx_switch"), ("aruba_cx", "invented_switch"),
    ("cisco_ios_xe_router", "aruba_cx_switch"), ("cisco_asa", "juniper_set_switch"),
    ("palo_alto_scm", "palo_alto_set"), ("aruba_os", "aruba_cx_switch"),
])
def test_unknown_ambiguous_or_cross_device_identity_refuses_before_side_effects(
        tmp_path, monkeypatch, source, target):
    (tmp_path / "source.cfg").write_bytes(b"hostname synthetic-refusal\n")
    server = UploadServer(b"hostname synthetic-refusal\n")
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": source, "target_vendor": target, "job_type": "prescan"})
    assert result["isError"] and not confirmations and not server.requests
    assert not (tmp_path / ".netconverter/submissions").exists()
    with closing(client(server)) as connection, pytest.raises((APIError, ValueError)):
        submit_external(connection, server.content, source, target, "prescan", {}, "synthetic-key")
    assert not server.writes()
