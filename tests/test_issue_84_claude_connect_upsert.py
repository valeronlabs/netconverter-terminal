"""Frozen reconnect regression: synthetic Claude user config, never real home files."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from netconverter_cli import cli, connect


@pytest.fixture
def claude_config(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(connect, "executable", lambda: "/opt/bin/netconverter")
    monkeypatch.setattr(connect.shutil, "which", lambda name: "/opt/bin/claude")
    calls = []

    def duplicate_add(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stdout="", stderr=
                               "MCP server netconverter already exists in user config")

    monkeypatch.setattr(connect.subprocess, "run", duplicate_add)
    path = tmp_path / ".claude.json"
    data = {
        "theme": "dark", "projects": {"/old": {"hasTrustDialogAccepted": True}},
        "mcpServers": {
            "netconverter": {"type": "stdio", "command": "/old/netconverter",
                             "args": ["mcp", "--workspace", "/old"],
                             "env": {"NETCONVERTER_AUTH": "keyring"}},
            "other": {"type": "http", "url": "https://example.test/mcp",
                      "headers": {"Authorization": "synthetic-private-marker"}},
        },
    }
    path.write_text(json.dumps(data))
    work = tmp_path / "migration"
    work.mkdir()
    return path, data, work, calls


@pytest.mark.parametrize("custom_directory", [False, True])
def test_reconnect_upserts_preserving_other_servers_and_settings(
        claude_config, monkeypatch, capsys, custom_directory):
    path, before, work, calls = claude_config
    if custom_directory:
        config_dir = path.parent / "custom-claude"
        config_dir.mkdir()
        alternate = config_dir / ".claude.json"
        alternate.write_bytes(path.read_bytes())
        path.write_text('{"theme": "untouched default"}')
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))
        path = alternate
    args = SimpleNamespace(workspace=str(work), client="claude-code", yes=True, print_only=False)
    cli.run_connect(args, ask=lambda prompt: pytest.fail("unexpected prompt"))
    after = json.loads(path.read_text())
    expected = json.loads(json.dumps(before))
    expected["mcpServers"]["netconverter"].update(
        command="/opt/bin/netconverter", args=["mcp", "--workspace", str(work.resolve())])
    assert after == expected
    assert json.loads(path.with_name(path.name + ".bak").read_text()) == before
    assert connect._claude_configured()
    cli.run_connect(args, ask=lambda prompt: pytest.fail("unexpected prompt"))
    assert json.loads(path.read_text()) == expected
    assert calls == []  # no destructive remove/add sequence
    assert "synthetic-private-marker" not in capsys.readouterr().out
    if custom_directory:
        assert json.loads((path.parent.parent / ".claude.json").read_text()) == {"theme": "untouched default"}
        assert (path.parent / "settings.json").exists()
        assert not (path.parent.parent / ".claude" / "settings.json").exists()


def test_reconnect_rereads_changes_after_preview(claude_config):
    path, before, work, calls = claude_config
    change = connect.plan("claude-code", work)
    before["mcpServers"]["later"] = {"command": "unrelated"}
    before["theme"] = "light"
    path.write_text(json.dumps(before))
    change.apply()
    after = json.loads(path.read_text())
    assert after["theme"] == "light"
    assert after["mcpServers"]["later"] == {"command": "unrelated"}
    assert calls == []


def test_failed_atomic_update_keeps_original_entry(claude_config, monkeypatch):
    path, before, work, calls = claude_config
    original = path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(connect.os, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic replace failure"):
        connect.plan("claude-code", work).apply()
    assert path.read_bytes() == original
    assert json.loads(path.with_name(path.name + ".bak").read_text()) == before
    assert not list(path.parent.glob(".nc-*"))
    assert calls == []


@pytest.mark.parametrize("contents", ['{not json', '{"mcpServers": []}'])
def test_reconnect_refuses_invalid_config_at_apply(claude_config, contents):
    path, _, work, calls = claude_config
    change = connect.plan("claude-code", work)
    path.write_text(contents)
    with pytest.raises(RuntimeError, match="nothing was changed"):
        change.apply()
    assert path.read_text() == contents
    assert calls == []


def test_reconnect_print_only_leaves_config_unchanged(claude_config, capsys):
    path, _, work, calls = claude_config
    original = path.read_bytes()
    args = SimpleNamespace(workspace=str(work), client="claude-code", yes=True, print_only=True)
    cli.run_connect(args, ask=lambda prompt: pytest.fail("unexpected prompt"))
    assert path.read_bytes() == original
    assert calls == []
    assert "synthetic-private-marker" not in capsys.readouterr().out
