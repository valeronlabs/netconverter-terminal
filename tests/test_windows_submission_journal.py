"""Real Windows/NTFS submission-journal acceptance, never a mocked OS pass."""
import hashlib
import json
import os
import subprocess
import sys

import httpx
import pytest

from netconverter_cli.api import APIError, StaticCredential
from netconverter_cli.mcp_server import Bridge
from netconverter_cli.submission_journal import SubmissionJournal
from netconverter_cli.workspace import Workspace, WorkspaceError

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-native handles required")


def journal(root):
    return SubmissionJournal(Workspace(root), "source.cfg", {"synthetic": True})


def junction(path, target):
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(target)],
                            capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_journal_reopens_exact_receipt_and_cleans_refused_first_attempt(tmp_path):
    first = journal(tmp_path)
    with first.locked():
        first.start()
        key = first.record["key"]
        first.uploaded({"id": "file_synthetic", "file_size": 19, "checksum": "a" * 64})
    with journal(tmp_path).locked() as resumed:
        assert resumed.record["key"] == key
        assert resumed.record["uploaded"]["id"] == "file_synthetic"
        resumed.forget_initial_refusal(APIError(422, "unprocessable"))
    assert not first.path.exists()
    assert not list(first.directory.glob(".nc-*"))


def test_lock_is_exclusive_and_ancestors_cannot_be_replaced(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    first, second = journal(root), journal(root)
    with first.locked():
        first.start()
        with pytest.raises(WorkspaceError, match="already in progress"):
            with second.locked():
                pytest.fail("Second writer acquired the journal lock")
        for directory in (root, root / ".netconverter", first.directory):
            with pytest.raises(PermissionError):
                directory.rename(directory.with_name(directory.name + "-moved"))
        with pytest.raises(PermissionError):
            first.lock_path.unlink()
        child = subprocess.run([sys.executable, "-c",
            "import sys; from netconverter_cli.submission_journal import SubmissionJournal; "
            "from netconverter_cli.workspace import Workspace; "
            "j=SubmissionJournal(Workspace(sys.argv[1]), 'source.cfg', {'synthetic': True}); "
            "j.locked().__enter__()", str(root)], capture_output=True, timeout=15)
        assert child.returncode != 0
        assert b"already in progress" in child.stderr
    with second.locked():
        assert second.record["key"] == first.record["key"]


@pytest.mark.parametrize("component", [".netconverter", "submissions"])
def test_junction_parent_refuses_without_outside_writes(tmp_path, component):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    if component == ".netconverter":
        path = root / component
    else:
        (root / ".netconverter").mkdir()
        path = root / ".netconverter" / component
    junction(path, outside)
    with pytest.raises(WorkspaceError):
        journal(root)
    assert list(outside.iterdir()) == []


def test_directory_swapped_before_lock_refuses(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    first = journal(tmp_path)
    first.directory.rename(first.directory.with_name("original"))
    junction(first.directory, outside)
    with pytest.raises(WorkspaceError):
        with first.locked():
            first.start()
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("kind", ["receipt", "lock"])
def test_metadata_hardlinks_are_refused(tmp_path, kind):
    first = journal(tmp_path)
    with first.locked():
        first.start()
    metadata = first.path if kind == "receipt" else first.lock_path
    original = metadata.read_bytes()
    outside = tmp_path / "unrelated"
    # Start from an otherwise valid protected journal file so an inherited-ACL
    # refusal cannot accidentally stand in for the hardlink check.
    os.link(metadata, outside)
    with pytest.raises(WorkspaceError):
        with first.locked():
            first.start()
    assert outside.read_bytes() == original


def test_receipt_acl_is_owner_only_and_bounded_read_refuses_oversize(tmp_path):
    from netconverter_cli import windows_draft_io as native
    first = journal(tmp_path)
    with first.locked():
        first.start()
    handle = native._open(first.path, native._READ, native._OPEN_EXISTING, False)
    try:
        assert native._protected_owner_acl(handle)
    finally:
        native._k.CloseHandle(handle)
    first.path.write_bytes(b"x" * 32769)
    with pytest.raises(WorkspaceError):
        with journal(tmp_path).locked():
            pytest.fail("Oversized receipt admitted")


def test_bridge_ambiguous_retry_keeps_key_and_file_without_private_body(tmp_path):
    source = b"hostname synthetic-windows-private\n"
    secret = "nck_synthetic-private-windows"
    (tmp_path / "source.cfg").write_bytes(source)
    calls = []
    job_keys = []

    def server(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/me"):
            data = {"job_types": ["prescan"]}
        elif request.url.path.endswith("/capabilities"):
            data = {"limits": {"max_upload_bytes": 1000, "file_id_submission": True}}
        elif request.url.path.endswith("/files/upload"):
            assert source in request.content
            data = {"file": {"id": "file_synthetic", "file_size": len(source),
                             "checksum": hashlib.sha256(source).hexdigest()}}
        elif request.url.path.endswith("/jobs"):
            body = json.loads(request.content)
            assert body["file_id"] == "file_synthetic" and "source_config" not in body
            job_keys.append(request.headers["Idempotency-Key"])
            if len(job_keys) == 1:
                raise httpx.ReadTimeout("synthetic ambiguity", request=request)
            data = {"job_id": "psc_0123456789ab", "status": "queued"}
        else:
            raise AssertionError(request.url.path)
        return httpx.Response(200, json={"success": True, "data": data})

    def submit():
        bridge = Bridge(tmp_path, "https://synthetic.invalid/external/v1", StaticCredential(secret),
                        transport=httpx.MockTransport(server))
        return bridge.call("submit_file", {"path": "source.cfg", "source_vendor": "cisco_asa",
                                              "job_type": "prescan"})

    assert submit()["isError"]
    result = submit()
    assert not result["isError"], result
    assert len(job_keys) == 2 and job_keys[0] == job_keys[1]
    assert sum(path.endswith("/files/upload") for path in calls) == 1
    raw = next((tmp_path / ".netconverter/submissions").glob("*.json")).read_text()
    for private in (source.decode(), secret):
        assert private not in raw and private not in json.dumps(result)


@pytest.mark.parametrize("failure", ["write", "rename", "flush"])
def test_failed_publication_preserves_previous_receipt_and_no_temporary_files(tmp_path, monkeypatch, failure):
    from netconverter_cli import windows_submission_io as windows
    first = journal(tmp_path)
    with first.locked():
        first.start()
        key = first.record["key"]
        initial = first.path.read_bytes()

        def fail(*args, **kwargs):
            raise OSError(5, "synthetic storage failure")

        with monkeypatch.context() as patch:
            if failure == "rename":
                patch.setattr(windows.native, "_rename", fail)
            else:
                patch.setattr(windows, "_" + failure, fail)
            with pytest.raises(WorkspaceError):
                first.uploaded({"id": "file_synthetic"})
    assert not list(first.directory.glob(".nc-*"))
    with journal(tmp_path).locked() as retry:
        assert retry.record["key"] == key
        if failure != "flush":
            assert first.path.read_bytes() == initial
        else:
            # A failed flush after publication is ambiguous, not permission to
            # discard the original key or manufacture a new submission.
            assert retry.record["uploaded"]["id"] == "file_synthetic"


def test_existing_inherited_receipt_acl_is_refused(tmp_path):
    first = journal(tmp_path)
    with first.locked():
        first.start()
    original = first.path.read_bytes()
    first.path.unlink()
    first.path.write_bytes(original)
    with pytest.raises(WorkspaceError):
        with journal(tmp_path).locked():
            pytest.fail("Unprotected receipt was admitted")
