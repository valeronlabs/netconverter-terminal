"""Frozen c690 -> PR65 upgrade cases, synthetic HTTP and version-1 receipt schema.

The real CLI/Bridge runs against independently specified old bindings/wire bodies.
The exact two-commit reproduction is recorded separately; no historical Git
checkout, credential store or network access is needed to run these in CI.
"""
import hashlib
import json
import time

import httpx
import pytest

from netconverter_cli import submission_journal
from netconverter_cli.submission_journal import SubmissionJournal
from netconverter_cli.workspace import Workspace, WorkspaceError
from tests.test_issue_2195_file_transport import SERVER, UploadServer
from tests.test_issue_63_64_submission_boundary import launch

CONTENT = b"hostname synthetic-upgrade\n"
KEY = "a" * 32
JOB = "psc_000000000001"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def seed_legacy(root, source="fortinet_fortigate", target="palo_alto_set", *, completed=True, **changes):
    (root / "source.cfg").write_bytes(CONTENT)
    sha = hashlib.sha256(CONTENT).hexdigest()
    # These are the exact c690 request-binding fields, before alias normalization.
    binding = {"path": "source.cfg", "bytes": len(CONTENT), "sha256": sha,
               "job_type": "prescan", "source_vendor": source, "target_vendor": target,
               "options": {}, "server": SERVER,
               "credential": digest(["key", "nck_synthetic_63_64"]),
               "exposure": "masked", "exposure_sections": [], **changes}
    record = {"version": 1, "binding": digest(binding), "key": KEY,
              "started_at": time.time() - 60,
              "uploaded": {"id": "file_synthetic", "checksum": sha, "file_size": len(CONTENT)}}
    if completed:
        record["result"] = {"job_id": JOB, "status": "queued", "sha256": sha, "bytes": len(CONTENT)}
    journal = SubmissionJournal(Workspace(root), "source.cfg", binding)
    with journal.locked():
        journal.record = record
        journal.save()
    return journal.path, record, binding


class OldServer(UploadServer):
    def __init__(self, source="fortinet_fortigate", target="palo_alto_set", *, revoked=False):
        super().__init__(CONTENT)
        self.revoked = revoked
        # One job was already accepted before its response was lost. A retry
        # may retrieve it only with the identical key and legacy wire values.
        self.old_body = {"source_vendor": source, "technology": "firewall",
                         "file_id": "file_synthetic", "target_vendor": target, "job_type": "prescan"}

    def __call__(self, request):
        if request.url.path.endswith("/jobs") and request.method == "POST":
            self.requests.append(request)
            if request.headers.get("Idempotency-Key") != KEY or json.loads(request.content) != self.old_body:
                return httpx.Response(409, json={"success": False, "error": {"code": "conflict"}})
            return httpx.Response(200, json={"success": True, "data": {"job_id": JOB, "status": "queued"}})
        if "/jobs/" in request.url.path:
            self.requests.append(request)
            assert request.headers["Authorization"] == "Bearer nck_synthetic_63_64"
            if self.revoked:
                return httpx.Response(403, json={"detail": "synthetic access revoked"})
            return httpx.Response(200, json={"success": True, "data": {"job_id": JOB, "status": "queued"}})
        return super().__call__(request)


@pytest.mark.parametrize("completed", [True, False], ids=["completed", "ambiguous"])
@pytest.mark.parametrize("source,target,canonical_source,canonical_target", [
    ("fortinet_fortigate", "palo_alto_set", "fortinet", "palo_alto_set"),
    ("cisco_asa", "fortinet_fortigate", "cisco_asa", "fortinet"),
    ("checkpoint", "palo_alto_set", "check_point", "palo_alto_set"),
])
def test_upgrade_preserves_old_job_key_wire_body_and_confirmation(
        tmp_path, monkeypatch, completed, source, target, canonical_source, canonical_target):
    path, old, _ = seed_legacy(tmp_path, source, target, completed=completed)
    before = path.read_bytes()
    server = OldServer(source, target)
    args = {"path": "source.cfg", "source_vendor": source, "target_vendor": target, "job_type": "prescan"}
    result, confirmations = launch(tmp_path, monkeypatch, server, args, accept=False)
    assert not result["isError"], result
    assert result["structuredContent"]["job_id"] == JOB
    assert not confirmations
    assert len(server.writes()) == (0 if completed else 1)
    assert not any(r.url.path.endswith("files/upload") for r in server.requests)
    stored = json.loads(path.read_bytes())
    for name in ("binding", "key", "started_at", "uploaded"):
        assert stored[name] == old[name]
    if completed:
        assert path.read_bytes() == before
    repeated, confirmations = launch(tmp_path, monkeypatch, server, {
        **args, "source_vendor": canonical_source, "target_vendor": canonical_target})
    assert not repeated["isError"] and repeated["structuredContent"]["replayed"] is True
    assert not confirmations and len(server.writes()) == (0 if completed else 1)


@pytest.mark.parametrize("completed", [True, False])
@pytest.mark.parametrize("change", [
    {"options": {"file_name": "changed.cfg"}}, {"credential": "b" * 64},
    {"exposure": "full"}, {"exposure_sections": ["policy"]},
    {"sha256": "b" * 64}, {"path": "different.cfg"}, {"target_vendor": "cisco_fmc"},
])
def test_changed_legacy_scope_refuses_without_replacing_receipt(tmp_path, monkeypatch, completed, change):
    path, _, _ = seed_legacy(tmp_path, completed=completed, **change)
    before = path.read_bytes()
    server = OldServer()
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": "fortinet", "target_vendor": "palo_alto_set", "job_type": "prescan"})
    assert result["isError"] and not confirmations and not server.writes()
    assert path.read_bytes() == before


def test_legacy_replay_still_checks_current_access(tmp_path, monkeypatch):
    path, _, _ = seed_legacy(tmp_path)
    before = path.read_bytes()
    server = OldServer(revoked=True)
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": "fortinet", "target_vendor": "palo_alto_set", "job_type": "prescan"})
    assert result["isError"] and not confirmations and not server.writes()
    assert any("/jobs/" in r.url.path for r in server.requests)
    assert path.read_bytes() == before


def test_old_aruba_firewall_identity_requires_reconciliation(tmp_path, monkeypatch):
    path, _, _ = seed_legacy(tmp_path, "aruba_cx", "cisco_ios_xe_switch")
    before = path.read_bytes()
    server = OldServer("aruba_cx", "cisco_ios_xe_switch")
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": "aruba_cx", "target_vendor": "cisco_ios_xe_switch", "job_type": "prescan"})
    assert result["isError"] and not confirmations and not server.writes()
    assert path.read_bytes() == before


@pytest.mark.parametrize("corruption", [{"version": 99}, {"version": True}, {"binding": "bad"}, {"key": "bad"}])
def test_corrupt_old_receipt_never_falls_back_to_new_job(tmp_path, monkeypatch, corruption):
    path, record, _ = seed_legacy(tmp_path)
    path.write_text(json.dumps({**record, **corruption}))
    before = path.read_bytes()
    server = OldServer()
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": "fortinet", "target_vendor": "palo_alto_set", "job_type": "prescan"})
    assert result["isError"] and not confirmations and not server.writes()
    assert path.read_bytes() == before


def test_legacy_pending_completion_save_failure_retains_replay_identity(tmp_path, monkeypatch):
    path, old, _ = seed_legacy(tmp_path, completed=False)
    before = path.read_bytes()
    server = OldServer()
    replace = submission_journal.journal_io.replace
    def fail_completion(directory, name, raw):
        if "result" in json.loads(raw):
            raise OSError("synthetic completion persistence failure")
        return replace(directory, name, raw)
    monkeypatch.setattr(submission_journal.journal_io, "replace", fail_completion)
    args = {"path": "source.cfg", "source_vendor": "fortinet", "target_vendor": "palo_alto_set", "job_type": "prescan"}
    result, confirmations = launch(tmp_path, monkeypatch, server, args)
    assert result["isError"] and not confirmations and path.read_bytes() == before
    assert len(server.jobs()) == 1
    monkeypatch.setattr(submission_journal.journal_io, "replace", replace)
    result, confirmations = launch(tmp_path, monkeypatch, server, args)
    assert not result["isError"] and not confirmations
    assert result["structuredContent"]["job_id"] == JOB
    assert len(server.jobs()) == 2  # identical idempotent retries, one existing server job
    assert json.loads(path.read_bytes())["key"] == old["key"]


def test_legacy_upgrade_retains_exclusive_receipt_lock(tmp_path, monkeypatch):
    path, _, binding = seed_legacy(tmp_path)
    before = path.read_bytes()
    server = OldServer()
    with SubmissionJournal(Workspace(tmp_path), "source.cfg", binding).locked():
        result, confirmations = launch(tmp_path, monkeypatch, server, {
            "path": "source.cfg", "source_vendor": "fortinet", "target_vendor": "palo_alto_set", "job_type": "prescan"})
        assert result["isError"] and not confirmations and not server.writes()
    assert path.read_bytes() == before


def test_fresh_version_two_retains_declined_then_confirmed_new_intent(tmp_path, monkeypatch):
    (tmp_path / "source.cfg").write_bytes(CONTENT)
    server = UploadServer(CONTENT)
    args = {"path": "source.cfg", "source_vendor": "fortinet_fortigate", "target_vendor": "palo_alto_set", "job_type": "prescan"}
    result, _ = launch(tmp_path, monkeypatch, server, args)
    assert not result["isError"]
    path, = (tmp_path / ".netconverter/submissions").glob("*.json")
    before = path.read_bytes()
    assert json.loads(before)["version"] == 2
    changed = {**args, "options": {"file_name": "different-intent.cfg"}}
    refused, confirmations = launch(tmp_path, monkeypatch, server, changed, accept=False)
    assert refused["isError"] and len(confirmations) == 1 and len(server.writes()) == 2
    assert path.read_bytes() == before
    accepted, confirmations = launch(tmp_path, monkeypatch, server, changed)
    assert not accepted["isError"] and len(confirmations) == 1 and len(server.writes()) == 4


def test_nonunique_legacy_match_is_refused_without_replacing_receipt(tmp_path):
    path, _, binding = seed_legacy(tmp_path)
    before = path.read_bytes()
    journal = SubmissionJournal(Workspace(tmp_path), "source.cfg", {**binding, "source_vendor": "fortinet"},
                                legacy_bindings=[binding, binding])
    with pytest.raises(WorkspaceError, match="uniquely"):
        with journal.locked():
            pytest.fail("Ambiguous legacy binding was accepted")
    assert path.read_bytes() == before
