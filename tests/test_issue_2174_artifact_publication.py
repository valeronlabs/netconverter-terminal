"""Generic downloaded artifacts must retain their selected filesystem boundary."""
import hashlib
import os
from pathlib import Path

import pytest

from netconverter_cli.workspace import Workspace, WorkspaceError
from netconverter_cli.draft_io import MAX_ARTIFACT_BYTES, secure_publish_file

DATA = b"synthetic private download\n"


def save(workspace, data=DATA):
    return workspace.save_artifact("tra_synthetic", "output.set", data, hashlib.sha256(data).hexdigest())


def test_download_directory_swapped_before_save_cannot_redirect_output(tmp_path):
    root, moved, outside = tmp_path / "selected", tmp_path / "moved", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    workspace = Workspace(root)
    root.rename(moved)
    root.symlink_to(outside, target_is_directory=True)
    try:
        save(workspace)
    except WorkspaceError:
        pass
    assert list(outside.iterdir()) == [], "Downloaded contents escaped the selected workspace"
    assert list(moved.iterdir()) == []


def test_directory_swap_during_publication_refuses_and_cleans_owned_temp(tmp_path, monkeypatch):
    root, moved, outside = tmp_path / "selected", tmp_path / "moved", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    workspace = Workspace(root)
    link = os.link

    def swap(*args, **kwargs):
        root.rename(moved)
        root.symlink_to(outside, target_is_directory=True)
        return link(*args, **kwargs)

    monkeypatch.setattr(os, "link", swap)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {swap})
    with pytest.raises(WorkspaceError):
        save(workspace)
    assert list(outside.iterdir()) == []
    # A final name may remain after publication fails. Removing it by pathname
    # could delete a concurrent customer replacement, so only the temp is cleaned.
    assert [path.name for path in moved.iterdir()] == ["tra_synthetic.output.set"]
    assert (moved / "tra_synthetic.output.set").read_bytes() == DATA
    with pytest.raises(WorkspaceError):
        workspace.artifact_receipt(root / "tra_synthetic.output.set")


def test_same_contents_hardlink_is_not_an_artifact_receipt(tmp_path):
    original = tmp_path / "source.cfg"
    original.write_bytes(DATA)
    os.link(original, tmp_path / "tra_synthetic.output.set")
    with pytest.raises(WorkspaceError):
        save(Workspace(tmp_path))
    assert original.read_bytes() == DATA


@pytest.mark.parametrize("data", [b"", DATA])
def test_empty_and_identical_legacy_artifacts_remain_idempotent(tmp_path, data):
    path = tmp_path / "tra_synthetic.output.set"
    path.write_bytes(data)
    workspace = Workspace(tmp_path)
    assert save(workspace, data) == path
    path.unlink()
    assert save(workspace, data).read_bytes() == data
    assert save(workspace, data) == path


def test_generic_download_over_32_mib_does_not_expand_guided_limit(tmp_path):
    data = b"x" * (MAX_ARTIFACT_BYTES + 1)
    digest = hashlib.sha256(data).hexdigest()
    workspace = Workspace(tmp_path)
    assert save(workspace, data).stat().st_size == len(data)
    with pytest.raises(WorkspaceError):
        secure_publish_file(workspace, "guided.set", data, digest, max_bytes=len(data))
    assert not (tmp_path / "guided.set").exists()


def test_concurrent_different_destination_is_preserved(tmp_path, monkeypatch):
    link = os.link
    destination = tmp_path / "tra_synthetic.output.set"

    def race(*args, **kwargs):
        destination.write_bytes(b"concurrent engineer edit")
        return link(*args, **kwargs)

    monkeypatch.setattr(os, "link", race)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {race})
    with pytest.raises(WorkspaceError):
        save(Workspace(tmp_path))
    assert destination.read_bytes() == b"concurrent engineer edit"
    assert sorted(path.name for path in tmp_path.iterdir()) == [destination.name]


def test_existing_fifo_is_refused_without_a_blocking_read(tmp_path, monkeypatch):
    destination = tmp_path / "tra_synthetic.output.set"
    os.mkfifo(destination)
    original_open = Path.open

    def refuse_blocking_open(path, *args, **kwargs):
        if path == destination:
            pytest.fail("FIFO must be refused before any blocking pathname read")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse_blocking_open)
    with pytest.raises(WorkspaceError):
        save(Workspace(tmp_path))


def test_existing_large_file_is_not_read_to_compare_small_download(tmp_path, monkeypatch):
    path = tmp_path / "tra_synthetic.output.set"
    with path.open("wb") as stream:
        stream.truncate(100 * 1024 * 1024)
    read = os.read

    def refuse_read(*args):
        pytest.fail("Length mismatch must refuse before reading existing artifact bytes")

    monkeypatch.setattr(os, "read", refuse_read)
    with pytest.raises(WorkspaceError):
        save(Workspace(tmp_path))
    monkeypatch.setattr(os, "read", read)
    assert path.stat().st_size == 100 * 1024 * 1024


def test_bridge_receipt_does_not_reopen_a_replaced_artifact(tmp_path, monkeypatch):
    from netconverter_cli.api import StaticCredential
    from netconverter_cli.mcp_server import Bridge
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.write_bytes(b"SYNTHETIC_PRIVATE_OUTSIDE_FILE")
    bridge = Bridge(tmp_path, "https://synthetic.invalid/external/v1", StaticCredential("nck_synthetic"))
    bridge._profile = ("external", frozenset({"convert"}))
    reads = []

    def downloaded(job_id, output, **kwargs):
        path = save(output)
        path.unlink()
        path.symlink_to(outside)
        from netconverter_cli.backend import DownloadOutcome
        return DownloadOutcome(paths=[path], complete=True)

    def refuse_reopen(path):
        reads.append(path)
        raise AssertionError("Artifact receipt must not reopen a pathname after verified publication")

    monkeypatch.setattr(bridge, "_download_external", downloaded)
    monkeypatch.setattr(Path, "read_bytes", refuse_reopen)
    result = bridge.call("download", {"job_id": "tra_synthetic"})
    assert not reads, "Receipt generation reopened a substituted outside path"
    assert not result["isError"], result
    assert result["structuredContent"]["files"] == [{
        "name": "tra_synthetic.output.set", "sha256": hashlib.sha256(DATA).hexdigest(), "bytes": len(DATA)}]


def test_failure_cleanup_never_unlinks_a_concurrent_customer_replacement(tmp_path, monkeypatch):
    import stat

    destination = tmp_path / "tra_synthetic.output.set"
    replacement = tmp_path / "engineer-new-file"
    replacement.write_bytes(b"concurrent customer edit")
    original_sync, original_stat = os.fsync, os.stat
    failed_sync = False

    def fail_directory_sync(descriptor):
        nonlocal failed_sync
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed_sync = True
            raise OSError(5, "synthetic directory sync failure")
        return original_sync(descriptor)

    def save_after_cleanup_identity_check(name, *args, **kwargs):
        info = original_stat(name, *args, **kwargs)
        if failed_sync and name == destination.name and replacement.exists():
            # A customer save wins after the cleanup identity check's stat,
            # before any subsequent pathname unlink can take place.
            os.replace(replacement, destination)
        return info

    monkeypatch.setattr(os, "fsync", fail_directory_sync)
    monkeypatch.setattr(os, "stat", save_after_cleanup_identity_check)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {save_after_cleanup_identity_check})
    workspace = Workspace(tmp_path)
    with pytest.raises(WorkspaceError):
        save(workspace)
    assert failed_sync
    assert destination.exists(), "Failure cleanup deleted a concurrently saved customer file"
    assert destination.read_bytes() in (DATA, b"concurrent customer edit")
    with pytest.raises(WorkspaceError):
        workspace.artifact_receipt(destination)
