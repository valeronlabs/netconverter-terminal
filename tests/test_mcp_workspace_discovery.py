"""Synthetic local metadata proof; no live server/client compatibility claim."""
import json
import os
from pathlib import Path

import pytest

from netconverter_cli.mcp_server import Bridge


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor listing")


def invoke(bridge, **args):
    result = bridge.call("list_workspace_files", args)
    return result, json.loads(result["content"][0]["text"])


def test_metadata_pages_exclude_unsafe_files_and_never_read_contents(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "HQ-ASA-01.txt").write_text("SYNTHETIC_PRIVATE_BODY")
    (root / "router.cfg").write_text("another private body")
    (root / "subfolder").mkdir()
    (root / "subfolder" / "nested.cfg").write_text("nested body")
    (root / ".netconverter").mkdir()
    (root / ".hidden.cfg").write_text("hidden")
    (root / "linked.cfg").symlink_to(root / "HQ-ASA-01.txt")
    outside = tmp_path / "outside.cfg"
    outside.write_text("outside")
    os.link(outside, root / "hardlinked.cfg")
    os.mkfifo(root / "pipe.cfg")
    bridge = Bridge(root, "https://unused.invalid")
    def forbidden(*args, **kwargs):
        raise AssertionError("Listing must not open file bodies")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(os, "read", forbidden)
    first, page = invoke(bridge, limit=2)
    assert first["isError"] is False
    assert page["entries"] == [
        {"path": "HQ-ASA-01.txt", "type": "file", "size_bytes": 22},
        {"path": "router.cfg", "type": "file", "size_bytes": 20},
    ]
    assert page["has_more"] and page["next_cursor"]
    second, last = invoke(bridge, limit=2, cursor=page["next_cursor"])
    assert not second["isError"]
    assert last["entries"] == [{"path": "subfolder", "type": "directory", "size_bytes": None}]
    assert last["has_more"] is False and last["next_cursor"] is None
    assert str(root) not in json.dumps([first, second])
    assert "SYNTHETIC_PRIVATE_BODY" not in json.dumps([first, second])
    _, nested = invoke(bridge, folder="subfolder")
    assert nested["entries"] == [{"path": "subfolder/nested.cfg", "type": "file", "size_bytes": 11}]


def test_traversal_links_invalid_limits_and_unknown_arguments_refused(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "sub", target_is_directory=True)
    bridge = Bridge(tmp_path, "https://unused.invalid")
    for args in ({"folder": "../"}, {"folder": str(tmp_path)}, {"folder": "link"},
                 {"folder": ".netconverter"}, {"folder": "sub/../"},
                 {"folder": "sub\\other"}, {"limit": True}, {"limit": 0},
                 {"limit": 101}, {"cursor": "forged"}, {"recursive": True}):
        response, _ = invoke(bridge, **args)
        assert response["isError"] is True, args


def test_stale_cursor_and_other_folder_or_process_cursor_refused(tmp_path):
    (tmp_path / "a.cfg").write_text("a")
    (tmp_path / "b.cfg").write_text("b")
    (tmp_path / "sub").mkdir()
    bridge = Bridge(tmp_path, "https://unused.invalid")
    result, page = invoke(bridge, limit=1)
    assert not result["isError"]
    token = page["next_cursor"]
    assert invoke(bridge, folder="sub", cursor=token)[0]["isError"]
    assert invoke(Bridge(tmp_path, "https://unused.invalid"), cursor=token)[0]["isError"]
    (tmp_path / "c.cfg").write_text("c")
    assert invoke(bridge, cursor=token)[0]["isError"]


def test_source_replacement_during_listing_returns_no_partial_page(tmp_path, monkeypatch):
    from netconverter_cli import workspace_listing
    (tmp_path / "a.cfg").write_text("a")
    bridge = Bridge(tmp_path, "https://unused.invalid")
    original = workspace_listing._metadata
    changed = False
    def replace_after_stat(fd, name):
        nonlocal changed
        value = original(fd, name)
        if name == "a.cfg" and not changed:
            changed = True
            (tmp_path / "a.cfg").unlink()
            (tmp_path / "a.cfg").symlink_to("/etc/passwd")
        return value
    monkeypatch.setattr(workspace_listing, "_metadata", replace_after_stat)
    response, data = invoke(bridge)
    assert response["isError"] is True and "entries" not in data


def test_directory_replacement_and_scan_bound_fail_closed(tmp_path, monkeypatch):
    from netconverter_cli import workspace_listing
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "a.cfg").write_text("a")
    bridge = Bridge(root, "https://unused.invalid")
    original = workspace_listing._metadata
    changed = False
    def replace_directory(fd, name):
        nonlocal changed
        value = original(fd, name)
        if not changed:
            changed = True
            root.rename(tmp_path / "old-workspace")
            root.mkdir()
        return value
    monkeypatch.setattr(workspace_listing, "_metadata", replace_directory)
    assert invoke(bridge)[0]["isError"]
    monkeypatch.setattr(workspace_listing, "_metadata", original)
    (root / "a").write_text("a")
    (root / "b").write_text("b")
    monkeypatch.setattr(workspace_listing, "MAX_SCANNED_ENTRIES", 1)
    result, data = invoke(bridge)
    assert result["isError"] and "entries" not in data


def test_catalog_describes_local_metadata_and_guided_prescan(tmp_path):
    tools = {t["name"]: t for t in Bridge(tmp_path, "https://unused.invalid").list_tools()}
    listing = tools["list_workspace_files"]
    assert listing["annotations"] == {"readOnlyHint": True, "destructiveHint": False,
                                      "idempotentHint": True, "openWorldHint": False}
    assert "prescan" in tools["submit_file"]["inputSchema"]["properties"]["job_type"]["enum"]
    assert "prescan" in listing["description"]


def test_lower_exposure_refuses_before_filesystem_enumeration(tmp_path, monkeypatch):
    for level in ("none", "masked", "selected"):
        bridge = Bridge(tmp_path, "https://unused.invalid", level=level)
        def forbidden(**kwargs):
            raise AssertionError("Lower exposure must not enumerate filenames")
        monkeypatch.setattr(bridge._workspace_listing, "list", forbidden)
        result, data = invoke(bridge)
        assert result["isError"] and data["error"] == "full_exposure_required"


def test_metadata_output_matches_schema_and_unsupported_platform_refuses(tmp_path, monkeypatch):
    import jsonschema
    from netconverter_cli import workspace_listing
    bridge = Bridge(tmp_path, "https://unused.invalid")
    tool = next(t for t in bridge.list_tools() if t["name"] == "list_workspace_files")
    result, data = invoke(bridge)
    assert not result["isError"]
    jsonschema.validate(data, tool["outputSchema"])
    # Simulate unavailable descriptor API, not Windows acceptance.
    monkeypatch.setattr(workspace_listing.os, "supports_fd", set())
    result, data = invoke(bridge)
    assert result["isError"] and "unavailable on this platform" in data["message"]


def test_page_byte_budget_and_expired_cursor(tmp_path, monkeypatch):
    from netconverter_cli import workspace_listing
    for number in range(100):
        (tmp_path / (f"{number:03}-" + "x" * 200 + ".cfg")).write_text("synthetic")
    bridge = Bridge(tmp_path, "https://unused.invalid")
    result, page = invoke(bridge, limit=100)
    assert not result["isError"] and page["has_more"]
    assert 0 < len(page["entries"]) < 100
    assert len(json.dumps(page).encode()) < 16_384
    now = workspace_listing.time.time()
    monkeypatch.setattr(workspace_listing.time, "time", lambda: now + 301)
    assert invoke(bridge, cursor=page["next_cursor"])[0]["isError"]


def test_first_entry_over_budget_refuses_instead_of_zero_progress(tmp_path, monkeypatch):
    from netconverter_cli import workspace_listing
    (tmp_path / "config.cfg").write_text("synthetic")
    bridge = Bridge(tmp_path, "https://unused.invalid")
    monkeypatch.setattr(workspace_listing, "MAX_ENTRY_PAGE_BYTES", 10)
    result, data = invoke(bridge)
    assert result["isError"] is True and "next_cursor" not in data


def test_secret_shaped_names_never_become_another_actionable_path(tmp_path):
    (tmp_path / "community public.cfg").write_text("synthetic")
    (tmp_path / "community <secret>").write_text("other synthetic")
    bridge = Bridge(tmp_path, "https://unused.invalid")
    result, data = invoke(bridge)
    assert not result["isError"]
    assert data["entries"] == [{"path": "community <secret>", "type": "file", "size_bytes": 15}]
    assert data["excluded_entries"] == 1
    assert invoke(bridge, folder="community public.cfg")[0]["isError"]


def test_unicode_folder_and_entire_response_budget_are_bounded(tmp_path, monkeypatch):
    from netconverter_cli import workspace_listing
    bridge = Bridge(tmp_path, "https://unused.invalid")
    # Reviewer-provided shape: character count fits the schema but UTF-8 and
    # escaped JSON are much larger. No filesystem creation is needed to refuse it.
    folder = "/".join(["😀" * 59] * 17)
    assert len(folder) == 1019
    result, data = invoke(bridge, folder=folder)
    assert result["isError"] and "too long" in data["message"]
    monkeypatch.setattr(workspace_listing, "MAX_RESPONSE_BYTES", 20)
    result, data = invoke(bridge)
    assert result["isError"] and "response budget" in data["message"]
