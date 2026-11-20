"""Synthetic journal confinement regressions, independent of a live service."""
import hashlib
import json
import os
import stat

import httpx
import pytest

from netconverter_cli.api import APIError, StaticCredential
from netconverter_cli.mcp_server import Bridge
from netconverter_cli.submission_journal import SubmissionJournal
from netconverter_cli.workspace import Workspace, WorkspaceError


@pytest.mark.parametrize("swap_at", ["before_lock", "after_lock"])
def test_journal_directory_swap_never_writes_outside_workspace(tmp_path, swap_at):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    journal = SubmissionJournal(Workspace(root), "source.cfg", {"synthetic": True})

    def swap_directory():
        journal.directory.rename(journal.directory.with_name("original-submissions"))
        journal.directory.symlink_to(outside, target_is_directory=True)

    if swap_at == "before_lock":
        swap_directory()
    try:
        with journal.locked():
            if swap_at == "after_lock":
                swap_directory()
            journal.start()
    except WorkspaceError:
        pass  # Refusing the changed boundary is also safe.

    assert list(outside.iterdir()) == [], "Journal followed a replaced parent outside its workspace"


def test_journal_refusal_never_deletes_outside_receipt_after_directory_swap(tmp_path):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    journal = SubmissionJournal(Workspace(root), "source.cfg", {"synthetic": True})
    outside_receipt = outside / journal.path.name
    outside_receipt.write_bytes(b"synthetic unrelated receipt")

    with journal.locked():
        journal.start()
        journal.directory.rename(journal.directory.with_name("original-submissions"))
        journal.directory.symlink_to(outside, target_is_directory=True)
        try:
            journal.forget_initial_refusal(APIError(422, "unprocessable"))
        except WorkspaceError:
            pass

    assert outside_receipt.exists(), "Refusal cleanup deleted a receipt outside the workspace"
    assert outside_receipt.read_bytes() == b"synthetic unrelated receipt"


def test_transport_receipts_exclude_source_and_credentials(tmp_path):
    content = b"! synthetic-private-configuration-marker\n"
    secret = "nck_synthetic-private-credential-marker"
    seen_jobs = []

    def handler(request):
        path = request.url.path
        if path.endswith("/me"):
            data = {"job_types": ["prescan"]}
        elif path.endswith("/capabilities"):
            data = {"limits": {"max_upload_bytes": 1000, "file_id_submission": True}}
        elif path.endswith("/files/upload"):
            assert request.headers["Authorization"] == "Bearer " + secret
            assert content in request.content
            data = {"file": {"id": "file_synthetic", "checksum": hashlib.sha256(content).hexdigest(),
                             "file_size": len(content), "source_content": content.decode(), "credential": secret}}
        elif path.endswith("/jobs"):
            seen_jobs.append(json.loads(request.content))
            data = {"job_id": "psc_0123456789ab", "status": "queued",
                    "source_content": content.decode(), "credential": secret}
        else:
            raise AssertionError(path)
        return httpx.Response(200, json={"success": True, "data": data})

    (tmp_path / "synthetic.cfg").write_bytes(content)
    result = Bridge(tmp_path, "https://synthetic.invalid/external/v1", StaticCredential(secret), None,
                    transport=httpx.MockTransport(handler)).call("submit_file", {
                        "path": "synthetic.cfg", "source_vendor": "cisco_asa", "job_type": "prescan"})
    assert result["isError"] is False, result
    journal = next((tmp_path / ".netconverter/submissions").glob("*.json"))
    raw = journal.read_text()
    for value in (content.decode(), secret):
        assert value not in raw and value not in json.dumps(result)
    assert "source_config" not in seen_jobs[0] and seen_jobs[0]["file_id"] == "file_synthetic"
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600
    assert set(json.loads(raw)["uploaded"]) == {"id", "checksum", "file_size"}


@pytest.mark.parametrize("component", [".netconverter", "submissions"])
def test_existing_parent_symlink_refuses_before_journal_creation(tmp_path, component):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    if component == ".netconverter":
        (root / component).symlink_to(outside, target_is_directory=True)
    else:
        (root / ".netconverter").mkdir()
        (root / ".netconverter" / component).symlink_to(outside, target_is_directory=True)
    with pytest.raises(WorkspaceError):
        SubmissionJournal(Workspace(root), "source.cfg", {"synthetic": True})
    assert list(outside.iterdir()) == []


def test_swapped_state_parent_is_refused_before_lock(tmp_path):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "submissions").mkdir()
    journal = SubmissionJournal(Workspace(root), "source.cfg", {"synthetic": True})
    state = root / ".netconverter"
    state.rename(root / "original-state")
    state.symlink_to(outside, target_is_directory=True)
    with pytest.raises(WorkspaceError):
        with journal.locked():
            journal.start()
    assert list((outside / "submissions").iterdir()) == []


@pytest.mark.parametrize("kind", ["receipt", "lock"])
def test_journal_rejects_metadata_hardlinks(tmp_path, kind):
    journal = SubmissionJournal(Workspace(tmp_path), "source.cfg", {"synthetic": True})
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"unrelated contents")
    os.link(unrelated, journal.path if kind == "receipt" else journal.lock_path)
    with pytest.raises(WorkspaceError):
        with journal.locked():
            journal.start()
    assert unrelated.read_bytes() == b"unrelated contents"


def test_unavailable_secure_platform_fails_before_upload_or_journal_creation(tmp_path, monkeypatch):
    from netconverter_cli import _journal_directory as journal_io
    monkeypatch.setattr(journal_io, "supported", lambda: False)
    with pytest.raises(WorkspaceError, match="unavailable on this platform"):
        SubmissionJournal(Workspace(tmp_path), "source.cfg", {"synthetic": True})
    assert list(tmp_path.iterdir()) == []
    (tmp_path / "source.cfg").write_bytes(b"hostname synthetic\n")
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET", "Unsupported journal must refuse before any upload or job write"
        data = ({"job_types": ["prescan"]} if request.url.path.endswith("/me") else
                {"limits": {"max_upload_bytes": 1000, "file_id_submission": True}})
        return httpx.Response(200, json={"success": True, "data": data})

    bridge = Bridge(tmp_path, "https://synthetic.invalid/external/v1", StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(handler))
    result = bridge.call("submit_file", {"path": "source.cfg", "source_vendor": "cisco_asa",
                                          "job_type": "prescan"})
    assert result["isError"] and "unavailable on this platform" in json.dumps(result)
    assert requests and not (tmp_path / ".netconverter").exists()


def test_journal_cannot_write_after_lock_closes(tmp_path):
    journal = SubmissionJournal(Workspace(tmp_path), "source.cfg", {"synthetic": True})
    with journal.locked():
        journal.start()
    initial = journal.path.read_bytes()
    with pytest.raises(WorkspaceError, match="require the journal lock"):
        journal.completed({"job_id": "psc_synthetic"})
    assert journal.path.read_bytes() == initial


def test_metadata_stat_failure_closes_open_descriptor(tmp_path, monkeypatch):
    from netconverter_cli import _journal_directory as journal_io
    descriptors = []
    fstat = os.fstat
    with journal_io.open_directory(tmp_path, create=True) as directory:
        def fail_stat(descriptor):
            descriptors.append(descriptor)
            raise OSError("synthetic metadata storage failure")

        with monkeypatch.context() as patch:
            patch.setattr(journal_io.os, "fstat", fail_stat)
            with pytest.raises(OSError):
                journal_io.open_regular(directory, "synthetic.lock", os.O_RDWR | os.O_CREAT)
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            fstat(descriptors[0])
