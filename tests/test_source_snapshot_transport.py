"""Selected source bytes remain confined; handoff ZIPs use only direct file transport."""
import hashlib
import io
import json
import os
import sys
import zipfile

import httpx
import pytest

from netconverter_cli.api import APIError, StaticCredential
from netconverter_cli.backend import submit_external
from netconverter_cli.mcp_server import Bridge
from netconverter_cli.workspace import Workspace, WorkspaceError
from tests.test_issue_2195_file_transport import SERVER, UploadServer, client


def bundle():
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("handoff.json", '{"schema":"synthetic-transport-only"}')
        archive.writestr("source.cfg", "hostname SYNTHETIC_PRIVATE_BUNDLE_MEMBER\n")
    return target.getvalue()


@pytest.mark.skipif(sys.platform == "win32", reason="Native junction case runs in Windows acceptance")
def test_source_parent_swap_never_reads_outside_workspace(tmp_path, monkeypatch):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir(); outside.mkdir()
    (root / "source.cfg").write_bytes(b"hostname selected\n")
    marker = b"hostname outside-synthetic-marker\n"
    (outside / "source.cfg").write_bytes(marker)
    work = Workspace(root)
    locate = work.locate

    def swap_after_locate(filename):
        path = locate(filename)
        root.rename(tmp_path / "original-workspace")
        root.symlink_to(outside, target_is_directory=True)
        return path

    monkeypatch.setattr(work, "locate", swap_after_locate)
    with pytest.raises(WorkspaceError):
        work.snapshot("source.cfg")


def test_hardlinked_source_is_refused(tmp_path):
    outside = tmp_path / "outside.cfg"
    outside.write_bytes(b"hostname unrelated\n")
    root = tmp_path / "workspace"
    root.mkdir()
    os.link(outside, root / "source.cfg")
    with pytest.raises(WorkspaceError):
        Workspace(root).snapshot("source.cfg")


@pytest.mark.parametrize("reader", ["workspace", "draft"])
def test_case_alias_of_private_state_is_never_a_source(tmp_path, reader):
    """Native macOS/Windows names may alias the reserved directory's casing."""
    from netconverter_cli.draft_io import secure_snapshot
    work = Workspace(tmp_path)
    work.store({"version": 1, "jobs": {}, "configurations": {},
                "private_marker": "SYNTHETIC_STATE_NOT_A_CONFIGURATION"})
    if not (tmp_path / ".NETCONVERTER/session.json").exists():
        pytest.skip("Native case-insensitive filesystem required")
    with pytest.raises(WorkspaceError):
        if reader == "workspace":
            work.snapshot(".NETCONVERTER/session.json")
        else:
            secure_snapshot(work, ".NETCONVERTER/session.json")


def test_zip_conversion_uses_opaque_bytes_and_file_receipt_only(tmp_path):
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(server))
    result = bridge.call("submit_file", {"path": "handoff.zip", "source_vendor": "check_point",
                                         "target_vendor": "palo_alto_set", "job_type": "convert"})
    assert not result["isError"], result
    receipt = result["structuredContent"]
    assert receipt["sha256"] == hashlib.sha256(content).hexdigest()
    assert receipt["bytes"] == len(content)
    assert "SYNTHETIC_PRIVATE_BUNDLE_MEMBER" not in json.dumps(result)
    assert server.jobs()[0]["file_id"] == "file_synthetic"
    assert "source_config" not in server.jobs()[0]
    upload = next(r for r in server.writes() if r.url.path.endswith("files/upload"))
    assert b'filename="configuration.zip"' in upload.content


@pytest.mark.parametrize("job_type", ["validate", "optimize"])
def test_archive_analysis_remains_unsupported_after_manager_prescan_extension(tmp_path, job_type):
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(server))
    result = bridge.call("submit_file", {"path": "handoff.zip", "source_vendor": "check_point",
                                         "target_vendor": "palo_alto_set", "job_type": job_type})
    assert result["isError"]
    assert not server.writes()


def test_archive_refuses_legacy_inline_without_uploading():
    server = UploadServer(bundle(), capabilities=False)
    c = client(server)
    try:
        with pytest.raises(APIError) as exc:
            submit_external(c, server.content, "check_point", "palo_alto_set", "convert", {}, "synthetic-key")
        assert exc.value.code == "archive_requires_file_conversion"
        assert not server.writes()
    finally:
        c.close()


def test_server_bundle_refusal_is_not_reported_as_conversion_success(tmp_path):
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)

    def reject(request):
        if request.url.path.endswith("/jobs"):
            server.requests.append(request)
            return httpx.Response(422, json={"success": False,
                "error": {"code": "unprocessable", "message": "Synthetic bundle manifest rejected"}})
        return server(request)

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), transport=httpx.MockTransport(reject))
    result = bridge.call("submit_file", {"path": "handoff.zip", "source_vendor": "check_point",
                                         "target_vendor": "palo_alto_set"})
    assert result["isError"]
    assert "unprocessable" in json.dumps(result)
    assert len(server.jobs()) == 1


@pytest.mark.parametrize("status, code, expected", [(422, "unprocessable", "unprocessable"),
    (403, "forbidden", "forbidden"), (429, "rate_limited", "rate_limited"),
    (422, "SYNTHETIC_PRIVATE_CONFIG", "request_failed")])
def test_source_refusal_contains_no_server_free_text_or_private_fields(tmp_path, status, code, expected):
    marker = "SYNTHETIC_PRIVATE_CONFIG"
    content = ("hostname " + marker + "\n").encode()
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)

    def reject(request):
        if request.url.path.endswith("/jobs"):
            server.requests.append(request)
            return httpx.Response(status, json={"success": False, "request_id": marker,
                "error": {"code": code, "message": marker,
                    "detail": {"feature": marker, "fields": ["source_vendor", marker.lower()],
                               "source_config": content.decode()}}})
        return server(request)

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), transport=httpx.MockTransport(reject))
    result = bridge.call("submit_file", {"path": "source.cfg", "source_vendor": "cisco_asa",
                                         "target_vendor": "palo_alto_set"})
    assert result["isError"]
    payload = json.loads(result["content"][0]["text"])
    assert payload["error"] == expected
    assert marker.lower() not in json.dumps(result).lower()
    assert payload["http_status"] == status and payload["missing_options"] == ["source_vendor"]
    for path in tmp_path.glob(".netconverter/**/*.json"):
        assert marker.lower() not in path.read_text().lower()


@pytest.mark.parametrize("phase", ["profile", "capabilities", "upload", "replay"])
def test_entire_source_workflow_uses_private_error_projection(tmp_path, phase):
    marker = "SYNTHETIC_PRIVATE_REFUSAL_BODY"
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)
    reject_path = {"profile": "/me", "capabilities": "/capabilities", "upload": "/files/upload",
                   "replay": "/jobs/psc_0123456789ab"}[phase]

    def reject(request):
        if request.url.path.endswith(reject_path):
            server.requests.append(request)
            return httpx.Response(422, json={"success": False, "request_id": marker,
                "error": {"code": "unprocessable", "message": marker}})
        return server(request)

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), transport=httpx.MockTransport(reject))
    args = {"path": "handoff.zip", "source_vendor": "check_point", "target_vendor": "palo_alto_set"}
    if phase == "replay":
        assert not bridge.call("submit_file", args)["isError"]
    result = bridge.call("submit_file", args)
    assert result["isError"] and marker not in json.dumps(result)


def test_unknown_upload_limit_code_keeps_locally_authored_limit_guidance():
    from netconverter_cli.mcp_server import _submission_api_failure
    refusal = _submission_api_failure(APIError(413, "unexpected_code", message="PRIVATE_RESPONSE"))
    assert refusal.code == "request_failed"
    assert "upload limit" in str(refusal) and "PRIVATE_RESPONSE" not in str(refusal)


@pytest.mark.parametrize("operation", ["validate", "optimize"])
def test_cli_unsupported_bundle_does_not_leave_new_pending_submission(tmp_path, operation):
    from netconverter_cli.controller import Controller
    content = bundle()
    (tmp_path / "handoff.zip").write_bytes(content)
    server = UploadServer(content)
    controller = Controller(tmp_path, client(server))
    controller.select("handoff.zip", "check_point")
    with pytest.raises(APIError, match="archive_requires_file_conversion"):
        controller.submit(operation, {"target_vendor": "palo_alto_set"})
    assert "pending" not in controller.state
    assert "pending" not in controller.workspace.load()
    assert not server.writes()


@pytest.mark.parametrize("existing_pending", [False, True])
def test_cli_source_read_refusal_does_not_invent_or_discard_pending_job(tmp_path, existing_pending):
    from netconverter_cli.controller import Controller
    source = tmp_path / "source.cfg"
    source.write_bytes(b"hostname selected\n")
    server = UploadServer(source.read_bytes())

    def ambiguous(request):
        if request.url.path.endswith("/jobs"):
            raise httpx.ReadTimeout("synthetic ambiguous submission", request=request)
        return server(request)

    from netconverter_cli.api import ExternalClient
    c = ExternalClient(StaticCredential("nck_synthetic"), SERVER, transport=httpx.MockTransport(ambiguous))
    controller = Controller(tmp_path, c)
    controller.select("source.cfg", "cisco_asa")
    if existing_pending:
        with pytest.raises(APIError):
            controller.submit("convert", {"target_vendor": "palo_alto_set"})
    original = json.dumps(controller.workspace.load(), sort_keys=True)
    source.write_bytes(b"hostname changed\n")
    with pytest.raises(WorkspaceError, match="changed after you chose"):
        controller.submit("convert", {"target_vendor": "palo_alto_set"})
    assert json.dumps(controller.workspace.load(), sort_keys=True) == original
    assert ("pending" in controller.state) is existing_pending
