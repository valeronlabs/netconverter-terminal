"""Actual NTFS acceptance for generic downloads sharing secure publication."""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from netconverter_cli.workspace import Workspace, WorkspaceError
from netconverter_cli.draft_io import MAX_ARTIFACT_BYTES, secure_publish_file

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-native handles required")
DATA = b"synthetic generic download\n"


def save(workspace, data=DATA):
    return workspace.save_artifact("tra_synthetic", "output.set", data, hashlib.sha256(data).hexdigest())


def test_replaced_destination_junction_never_receives_download(tmp_path):
    root, moved, outside = tmp_path / "selected", tmp_path / "moved", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    workspace = Workspace(root)
    root.rename(moved)
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(root), str(outside)], capture_output=True)
    assert result.returncode == 0, "Native junction fixture could not be created"
    try:
        save(workspace)
    except WorkspaceError:
        pass
    assert list(outside.iterdir()) == []
    assert list(moved.iterdir()) == []


@pytest.mark.parametrize("data", [b"", DATA])
def test_empty_and_matching_legacy_downloads_remain_idempotent(tmp_path, data):
    path = tmp_path / "tra_synthetic.output.set"
    path.write_bytes(data)
    workspace = Workspace(tmp_path)
    assert save(workspace, data) == path
    assert workspace.artifact_receipt(path) == {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    if data:
        with pytest.raises(WorkspaceError):
            secure_publish_file(workspace, path.name, data, hashlib.sha256(data).hexdigest(), max_bytes=MAX_ARTIFACT_BYTES)
    path.unlink()
    assert save(workspace, data).read_bytes() == data
    assert save(workspace, data) == path


def test_output_directory_stays_pinned_during_native_publication(tmp_path, monkeypatch):
    from netconverter_cli import windows_draft_io as native
    root = tmp_path / "selected"
    root.mkdir()
    workspace = Workspace(root)
    rename, attempts = native._rename, []

    def racing(handle, directory, filename):
        attempts.append(filename)
        with pytest.raises(PermissionError):
            root.rename(tmp_path / "moved")
        return rename(handle, directory, filename)

    monkeypatch.setattr(native, "_rename", racing)
    assert save(workspace).read_bytes() == DATA
    assert attempts and not (tmp_path / "moved").exists()
    assert not list(root.glob(".nc-*"))


def test_concurrent_customer_file_is_never_overwritten(tmp_path, monkeypatch):
    from netconverter_cli import windows_draft_io as native
    destination = tmp_path / "tra_synthetic.output.set"
    rename = native._rename

    def racing(handle, directory, filename):
        destination.write_bytes(b"concurrent engineer content")
        return rename(handle, directory, filename)

    monkeypatch.setattr(native, "_rename", racing)
    with pytest.raises(WorkspaceError):
        save(Workspace(tmp_path))
    assert destination.read_bytes() == b"concurrent engineer content"
    assert sorted(p.name for p in tmp_path.iterdir()) == [destination.name]


def test_linked_existing_artifact_is_refused_even_with_correct_contents(tmp_path):
    workspace = Workspace(tmp_path)
    artifact = save(workspace)
    source = tmp_path / "source.cfg"
    os.link(artifact, source)
    with pytest.raises(WorkspaceError):
        save(workspace)
    assert source.read_bytes() == DATA


def test_download_above_guided_limit_keeps_distinct_size_policy(tmp_path):
    data = b"x" * (MAX_ARTIFACT_BYTES + 1)
    workspace = Workspace(tmp_path)
    path = save(workspace, data)
    assert path.stat().st_size == len(data)
    assert save(workspace, data) == path
    with pytest.raises(WorkspaceError):
        secure_publish_file(workspace, "guided.set", data, hashlib.sha256(data).hexdigest(), max_bytes=len(data))


def test_download_receipt_uses_verified_bytes_without_reopening_path(tmp_path, monkeypatch):
    from netconverter_cli.api import StaticCredential
    from netconverter_cli.mcp_server import Bridge
    outside = tmp_path / "outside.cfg"
    outside.write_bytes(b"SYNTHETIC_PRIVATE_OUTSIDE_FILE")
    bridge = Bridge(tmp_path, "https://synthetic.invalid/external/v1", StaticCredential("nck_synthetic"))
    bridge._profile = ("external", frozenset({"convert"}))
    reads = []

    def downloaded(job_id, output, **kwargs):
        artifact = save(output)
        artifact.unlink()
        os.symlink(outside, artifact)
        from netconverter_cli.backend import DownloadOutcome
        return DownloadOutcome(paths=[artifact], complete=True)

    def refuse_reopen(path):
        reads.append(path)
        raise AssertionError("Receipt reopened a substituted path")

    monkeypatch.setattr(bridge, "_download_external", downloaded)
    monkeypatch.setattr(Path, "read_bytes", refuse_reopen)
    result = bridge.call("download", {"job_id": "tra_synthetic"})
    assert not reads
    assert not result["isError"], result
    assert result["structuredContent"]["files"][0]["sha256"] == hashlib.sha256(DATA).hexdigest()
