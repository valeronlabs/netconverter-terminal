"""Real NTFS source-path and opaque bundle transport checks."""
import hashlib
import os
import sys

import pytest

from netconverter_cli.workspace import Workspace, WorkspaceError
from tests.test_source_snapshot_transport import bundle, test_zip_conversion_uses_opaque_bytes_and_file_receipt_only
from tests.test_windows_submission_journal import junction

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-native handles required")


def test_source_parent_replaced_by_junction_refuses_before_read(tmp_path, monkeypatch):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "source.cfg").write_bytes(b"hostname selected\n")
    (outside / "source.cfg").write_bytes(b"hostname outside-synthetic-marker\n")
    work = Workspace(root)
    locate = work.locate

    def replaced(filename):
        path = locate(filename)
        root.rename(tmp_path / "original")
        junction(root, outside)
        return path

    monkeypatch.setattr(work, "locate", replaced)
    with pytest.raises(WorkspaceError):
        work.snapshot("source.cfg")


def test_ordinary_source_hardlink_is_refused(tmp_path):
    outside = tmp_path / "outside.cfg"
    outside.write_bytes(b"hostname outside\n")
    root = tmp_path / "workspace"
    root.mkdir()
    os.link(outside, root / "source.cfg")
    with pytest.raises(WorkspaceError):
        Workspace(root).snapshot("source.cfg")


def test_bundle_bytes_need_explicit_native_snapshot_policy(tmp_path):
    content = bundle()
    path = tmp_path / "handoff.zip"
    path.write_bytes(content)
    work = Workspace(tmp_path)
    with pytest.raises(WorkspaceError):
        work.snapshot("handoff.zip")
    selected, data, digest = work.snapshot("handoff.zip", allow_archives=True)
    assert selected == path and data == content
    assert digest == hashlib.sha256(content).hexdigest()


def test_native_source_handle_prevents_inflight_replacement(tmp_path, monkeypatch):
    from netconverter_cli import windows_draft_io as native
    source = tmp_path / "source.cfg"
    source.write_bytes(b"hostname selected\n")
    original_read = native._read

    def held_read(*args, **kwargs):
        with pytest.raises(PermissionError):
            source.rename(tmp_path / "replaced.cfg")
        return original_read(*args, **kwargs)

    monkeypatch.setattr(native, "_read", held_read)
    assert Workspace(tmp_path).snapshot("source.cfg")[1] == b"hostname selected\n"
