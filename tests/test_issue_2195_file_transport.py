"""Synthetic large uploads use the advertised, bounded file transport, never MCP bodies."""
import hashlib
import json
import time

import httpx
import pytest

from netconverter_cli.api import APIError, ExternalClient, StaticCredential
from netconverter_cli.backend import submit_external
from netconverter_cli.catalog import Catalog
from netconverter_cli.mcp_server import Bridge

SERVER = "https://api.example/external/v1"
MIB = 1024 * 1024


class UploadServer:
    def __init__(self, content, *, maximum=32 * MIB, checksum=True, capabilities=True):
        self.content, self.maximum, self.checksum = content, maximum, checksum
        self.has_capabilities = capabilities
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        path = request.url.path.removeprefix("/external/v1/")
        data = {}
        if path == "me":
            data = {"job_types": ["convert", "prescan", "validate", "optimize"]}
        elif path == "capabilities":
            if not self.has_capabilities:
                return httpx.Response(404, json={})
            data = {"limits": {"max_config_bytes": 5 * MIB, "max_inline_config_bytes": 5 * MIB,
                               "max_upload_bytes": self.maximum, "file_id_submission": True}}
        elif path == "files/upload":
            assert request.headers["content-type"].startswith("multipart/form-data;")
            assert self.content in request.content
            data = {"file": {"id": "file_synthetic", "file_size": len(self.content),
                             "checksum": hashlib.sha256(self.content).hexdigest() if self.checksum else "0" * 64}}
        elif path == "jobs":
            data = {"job_id": "psc_0123456789ab", "status": "queued"}
        elif path.startswith("jobs/"):
            data = {"job_id": path.split("/")[1], "status": "queued"}
        else:
            return httpx.Response(404, json={})
        return httpx.Response(200, json={"success": True, "data": data})

    def jobs(self):
        return [json.loads(r.content) for r in self.requests if r.url.path.endswith("/jobs")]

    def writes(self):
        return [r for r in self.requests if r.method == "POST"]


def client(server):
    return ExternalClient(StaticCredential("nck_synthetic"), SERVER, transport=httpx.MockTransport(server))


def test_large_file_by_path_returns_only_receipt(tmp_path):
    content = b"! synthetic-marker-never-in-model\n" + b"! bounded synthetic padding\n" * 400_000
    assert len(content) > 10 * MIB
    (tmp_path / "large.cfg").write_bytes(content)
    server = UploadServer(content)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(server))
    result = bridge.call("submit_file", {"path": "large.cfg", "source_vendor": "cisco_ios_xe_router",
                                          "target_vendor": "juniper_junos_router", "job_type": "prescan"})
    assert result["isError"] is False, result
    assert result["structuredContent"]["bytes"] == len(content)
    assert "synthetic-marker-never-in-model" not in json.dumps(result)
    body = server.jobs()[0]
    assert body["file_id"] == "file_synthetic" and "source_config" not in body
    assert body["technology"] == "router"


def test_advertised_limit_refuses_before_upload(tmp_path):
    content = b"x" * 65
    (tmp_path / "large.cfg").write_bytes(content)
    server = UploadServer(content, maximum=64)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(server))
    result = bridge.call("submit_file", {"path": "large.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"})
    assert result["isError"] is True
    assert not server.writes()


@pytest.mark.parametrize("content,checksum,code", [(b"abc", False, "upload_checksum_mismatch"),
                                                  (b"\xff", True, "unicode")])
def test_invalid_upload_does_not_queue(content, checksum, code):
    server = UploadServer(content, checksum=checksum)
    with pytest.raises((APIError, UnicodeDecodeError)) as error:
        submit_external(client(server), content, "cisco_asa", "palo_alto_set", "convert", {}, "test-key")
    if code != "unicode":
        assert error.value.code == code
    else:
        assert not server.writes()
    assert not server.jobs()


def test_old_server_keeps_bounded_inline_compatibility():
    content = b"ASA Version 9.16\n"
    server = UploadServer(content, capabilities=False)
    submit_external(client(server), content, "cisco_asa", "palo_alto_set", "convert", {}, "test-key")
    assert server.jobs()[0]["source_config"] == content.decode()
    large = b"!" * (5 * MIB + 1)
    with pytest.raises(APIError):
        submit_external(client(server), large, "cisco_asa", "palo_alto_set", "convert", {}, "different-key")
    assert len(server.jobs()) == 1


def test_catalog_displays_negotiated_upload_limit():
    caps = {"limits": {"max_config_bytes": 5 * MIB, "max_inline_config_bytes": 5 * MIB,
                       "max_upload_bytes": 32 * MIB, "file_id_submission": True}}
    assert Catalog.from_external(caps).max_bytes == 32 * MIB


def test_bridge_restart_after_ambiguous_queue_reuses_file_and_key(tmp_path):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    lost = True

    def handler(request):
        nonlocal lost
        response = server(request)
        if request.url.path.endswith("/jobs") and lost:
            lost = False
            raise httpx.ReadTimeout("synthetic lost response", request=request)
        return response

    def bridge():
        return Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                      transport=httpx.MockTransport(handler))

    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert bridge().call("submit_file", args)["isError"] is True
    retry = bridge().call("submit_file", args)
    assert retry["isError"] is False, retry
    writes = server.writes()
    assert sum(r.url.path.endswith("/files/upload") for r in writes) == 1
    jobs = [r for r in writes if r.url.path.endswith("/jobs")]
    assert len(jobs) == 2
    assert jobs[0].headers["Idempotency-Key"] == jobs[1].headers["Idempotency-Key"]
    assert jobs[0].content == jobs[1].content
    # A client that lost the successful response also recovers the original job.
    again = bridge().call("submit_file", args)
    assert again["structuredContent"]["job_id"] == retry["structuredContent"]["job_id"]
    assert len(server.jobs()) == 2


@pytest.mark.parametrize("value", [True, -1, 0, "33554432", 101 * MIB])
def test_invalid_advertised_upload_limits_fail_closed(value):
    server = UploadServer(b"abc", maximum=value)
    with pytest.raises(APIError):
        submit_external(client(server), b"abc", "cisco_asa", "palo_alto_set", "convert", {}, "test-key")
    assert not server.writes()


def test_pending_submission_keeps_confirmation_scope_and_declines_changes(tmp_path):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    confirmations = []

    def unavailable(request):
        if request.url.path.endswith("/jobs"):
            raise httpx.ReadTimeout("synthetic interruption", request=request)
        return server(request)

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(unavailable))
    bridge.confirm_upload = lambda details: confirmations.append(details) or "accept"
    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert bridge.call("submit_file", args)["isError"] is True
    assert bridge.call("submit_file", args)["isError"] is True
    assert len(confirmations) == 1
    for change in ({"target_vendor": "fortinet"}, {"options": {"file_name": "changed.cfg"}}):
        result = bridge.call("submit_file", {**args, **change})
        assert "submission_pending" in result["content"][0]["text"]
    (tmp_path / "source.cfg").write_bytes(b"ASA Version 9.18\n")
    result = bridge.call("submit_file", args)
    assert "submission_pending" in result["content"][0]["text"]
    assert len(confirmations) == 1
    assert sum(r.url.path.endswith("/files/upload") for r in server.writes()) == 1


def test_first_definitive_rejection_allows_corrected_submission(tmp_path):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    rejected = True
    def handler(request):
        nonlocal rejected
        response = server(request)
        if request.url.path.endswith("/jobs") and rejected:
            rejected = False
            return httpx.Response(422, json={"detail": "synthetic invalid options"})
        return response
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(handler))
    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert bridge.call("submit_file", args)["isError"] is True
    result = bridge.call("submit_file", {**args, "options": {"file_name": "corrected.cfg"}})
    assert result["isError"] is False, result
    assert len(server.jobs()) == 2


@pytest.mark.parametrize("started", [None, "bad", 0, float("nan"), "future", "expired"])
def test_ambiguous_replay_refuses_unknown_or_expired_deadline(tmp_path, started):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    def handler(request):
        response = server(request)
        if request.url.path.endswith("/jobs"):
            raise httpx.ReadTimeout("synthetic ambiguity", request=request)
        return response
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(handler))
    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert bridge.call("submit_file", args)["isError"] is True
    path = next((tmp_path / ".netconverter/submissions").glob("*.json"))
    record = json.loads(path.read_text())
    if started is None:
        record.pop("started_at", None)
    else:
        record["started_at"] = (time.time() + 3600 if started == "future" else
                                time.time() - 23 * 3600 - 1 if started == "expired" else started)
    path.write_text(json.dumps(record))
    result = bridge.call("submit_file", args)
    assert result["isError"] is True
    assert "submission_pending" in result["content"][0]["text"]
    assert len(server.jobs()) == 1
    assert path.exists()


@pytest.mark.parametrize("path_kind", ["receipt", "lock"])
def test_journal_refuses_nonregular_files_without_reading(tmp_path, monkeypatch, path_kind):
    import os
    from pathlib import Path
    from netconverter_cli.submission_journal import SubmissionJournal
    from netconverter_cli.workspace import Workspace, WorkspaceError
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO fixture requires POSIX")
    journal = SubmissionJournal(Workspace(tmp_path), "source.cfg", {"synthetic": True})
    path = journal.path if path_kind == "receipt" else journal.lock_path
    os.mkfifo(path)
    original_open = Path.open
    def refuse_fifo_read(self, *args, **kwargs):
        if self == path:
            pytest.fail("Nonregular receipt must be rejected before a blocking read")
        return original_open(self, *args, **kwargs)
    monkeypatch.setattr(Path, "open", refuse_fifo_read)
    with pytest.raises(WorkspaceError):
        with journal.locked():
            pass


def test_completed_receipt_replay_returns_only_reconstructed_fields(tmp_path):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(server))
    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert not bridge.call("submit_file", args)["isError"]
    path = next((tmp_path / ".netconverter/submissions").glob("*.json"))
    record = json.loads(path.read_text())
    record["result"]["extra_notes"] = "SYNTHETIC_UNTRUSTED_LOCAL_CONTENT"
    path.write_text(json.dumps(record))
    result = bridge.call("submit_file", args)
    assert not result["isError"]
    assert "SYNTHETIC_UNTRUSTED_LOCAL_CONTENT" not in json.dumps(result)


@pytest.mark.parametrize("first_ambiguous", [False, True])
def test_rejection_never_discards_prior_ambiguity_or_parse_failure(tmp_path, first_ambiguous):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    calls = 0
    def handler(request):
        nonlocal calls
        response = server(request)
        if request.url.path.endswith("/jobs"):
            calls += 1
            if first_ambiguous and calls == 1:
                raise httpx.ReadTimeout("synthetic ambiguity", request=request)
            return (httpx.Response(422, json={"detail": "synthetic rejection"}) if first_ambiguous
                    else httpx.Response(422, content=b"not-json"))
        return response
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(handler))
    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert bridge.call("submit_file", args)["isError"]
    if first_ambiguous:
        assert bridge.call("submit_file", args)["isError"]
    path = next((tmp_path / ".netconverter/submissions").glob("*.json"))
    key = json.loads(path.read_text())["key"]
    result = bridge.call("submit_file", {**args, "options": {"file_name": "changed.cfg"}})
    assert "submission_pending" in result["content"][0]["text"]
    assert json.loads(path.read_text())["key"] == key


@pytest.mark.parametrize("failure_call", [1, 2])
def test_journal_persistence_failure_never_queues(tmp_path, monkeypatch, failure_call):
    from netconverter_cli import _journal_directory as journal_io
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    replace = journal_io.os.replace
    calls = 0
    def broken(source, destination, **kwargs):
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise OSError("synthetic storage failure")
        return replace(source, destination, **kwargs)
    # Inject failure at the actual atomic filesystem publication, after the
    # secure directory handle was opened; no pathname-only helper remains.
    monkeypatch.setattr(journal_io.os, "replace", broken)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(server))
    result = bridge.call("submit_file", {"path": "source.cfg", "source_vendor": "cisco_asa",
                                          "job_type": "prescan"})
    assert result["isError"] and "submission_pending" in result["content"][0]["text"]
    assert not server.jobs()
    assert len(server.writes()) == failure_call - 1


def test_same_path_journal_lock_excludes_second_submitter(tmp_path):
    from netconverter_cli.submission_journal import SubmissionJournal
    from netconverter_cli.workspace import Workspace, WorkspaceError
    first = SubmissionJournal(Workspace(tmp_path), "source.cfg", {"synthetic": True})
    second = SubmissionJournal(Workspace(tmp_path), "source.cfg", {"synthetic": True})
    with first.locked():
        with pytest.raises(WorkspaceError, match="already in progress"):
            with second.locked():
                pytest.fail("Second submitter acquired a held lock")
    with second.locked():
        second.start()


def test_oauth_partition_survives_refresh_but_not_account_or_org_change():
    import base64
    from netconverter_cli.submission_journal import credential_scope
    class OAuth:
        kind = "clerk"
        def __init__(self, **changes):
            self.claims = {"iss": "https://synthetic.invalid", "sub": "synthetic-user", "org_id": "org-a",
                           "exp": 1, **changes}
        def token(self):
            part = base64.urlsafe_b64encode(json.dumps(self.claims).encode()).decode().rstrip("=")
            return "synthetic." + part + ".signature"
    original = credential_scope(OAuth())
    assert credential_scope(OAuth(exp=2)) == original
    assert credential_scope(OAuth(sub="other-user")) != original
    assert credential_scope(OAuth(org_id="other-org")) != original
    assert credential_scope(StaticCredential("other-key")) != original


def test_malformed_completed_receipt_returns_structured_refusal(tmp_path):
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"), None,
                    transport=httpx.MockTransport(server))
    args = {"path": "source.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"}
    assert not bridge.call("submit_file", args)["isError"]
    path = next((tmp_path / ".netconverter/submissions").glob("*.json"))
    record = json.loads(path.read_text())
    record["result"].pop("job_id")
    path.write_text(json.dumps(record))
    assert bridge.call("submit_file", args)["isError"]
    assert len(server.jobs()) == 1 and path.exists()


@pytest.mark.parametrize("change", ["credential", "server"])
def test_controller_resume_refuses_transport_scope_change(tmp_path, change):
    from netconverter_cli.controller import Controller
    from netconverter_cli.workspace import WorkspaceError
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    lost = True
    def handler(request):
        nonlocal lost
        response = server(request)
        if request.url.path.endswith("/jobs") and lost:
            lost = False
            raise httpx.ReadTimeout("synthetic ambiguity", request=request)
        return response
    def controller(key="nck_synthetic", url=SERVER):
        return Controller(tmp_path, ExternalClient(StaticCredential(key), url,
                          transport=httpx.MockTransport(handler)))
    original = controller()
    original.select("source.cfg", "cisco_asa")
    with pytest.raises(APIError):
        original.submit("prescan")
    path = tmp_path / ".netconverter/session.json"
    pending = path.read_bytes()
    switched = controller(key="nck_other") if change == "credential" else controller(url="https://other.example/external/v1")
    with pytest.raises(WorkspaceError):
        switched.resume()
    assert len(server.jobs()) == 1
    assert path.read_bytes() == pending
    assert controller().resume()["job_id"] == "psc_0123456789ab"
    assert len(server.jobs()) == 2
    assert sum(r.url.path.endswith("/files/upload") for r in server.writes()) == 1


def test_controller_preserves_ambiguity_after_rejection_and_expiry(tmp_path):
    from netconverter_cli.controller import Controller
    from netconverter_cli.workspace import WorkspaceError
    content = b"ASA Version 9.16\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    calls = 0
    def handler(request):
        nonlocal calls
        response = server(request)
        if request.url.path.endswith("/jobs"):
            calls += 1
            if calls == 1:
                raise httpx.ReadTimeout("synthetic ambiguity", request=request)
            return httpx.Response(422, json={"detail": "synthetic rejection"})
        return response
    controller = Controller(tmp_path, ExternalClient(StaticCredential("nck_synthetic"), SERVER,
                            transport=httpx.MockTransport(handler)))
    controller.select("source.cfg", "cisco_asa")
    with pytest.raises(APIError):
        controller.submit("prescan")
    key = controller.state["pending"]["key"]
    with pytest.raises(APIError):
        controller.resume()
    assert controller.state["pending"]["key"] == key
    controller.state["pending"]["started"] = time.time() - 23 * 3600 - 1
    with pytest.raises(WorkspaceError):
        controller.resume()
    assert len(server.jobs()) == 2 and controller.state["pending"]["key"] == key
