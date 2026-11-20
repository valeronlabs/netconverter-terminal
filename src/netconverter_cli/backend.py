"""Which NetConverter API a credential reaches, and the full-API job path.

Shared by the full-screen app and the local MCP bridge so the two can never
disagree about what a credential may do. ``external``: an ``nck_*`` key or a
Clerk sign-in on the full External API (``/jobs``, any supported vendor).
``quick``: a 0.1.x Terminal Quick pilot key, whose scopes never reach
``/jobs`` (the server answers 403), limited to ASA → Palo Alto.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .api import APIError, Client, ExternalClient
from .catalog import JOB_TYPES, device_type_of, legacy_submission_vendors, submission_vendors
from .job_options import external_body
from .upload_policy import LEGACY_INLINE_BYTES, UploadPolicy
from .workspace import WorkspaceError

# Full External API inline-submit ceiling (server: 5 MB).
EXTERNAL_MAX_BYTES = LEGACY_INLINE_BYTES
QUICK_JOB_TYPES = frozenset({"convert", "optimize"})


def detect_profile(credential, server, *, transport=None) -> tuple[str, frozenset]:
    """('external', job types /me advertises) or ('quick', pilot job types).

    Raises APIError when neither surface accepts the credential.
    """
    client = ExternalClient(credential, server, transport=transport)
    try:
        try:
            me = client.me()
        except APIError as exc:
            if exc.status != 403 or getattr(credential, "kind", "key") != "key":
                raise
            quick = Client(credential, server, transport=transport)
            try:
                quick.capabilities()
            finally:
                quick.close()
            return "quick", QUICK_JOB_TYPES
        advertised = me.get("job_types") if isinstance(me, dict) else None
        types = frozenset(t for t in advertised or ["convert"] if t in JOB_TYPES)
        return "external", types or frozenset({"convert"})
    finally:
        client.close()


def open_client(credential, server, *, transport=None):
    """(client, profile) for the full-screen app and the plain CLI."""
    kind, _ = detect_profile(credential, server, transport=transport)
    cls = ExternalClient if kind == "external" else Client
    return cls(credential, server, transport=transport), kind


def archive_submission_allowed(policy: UploadPolicy, source_vendor: str, job_type: str) -> bool:
    """Opaque transport only; the server admits manager manifest and selected scope."""
    return policy.file_id_submission and (job_type == "convert" or (
        job_type == "prescan" and source_vendor in {"check_point", "cisco_fmc"}))


def submit_external(client, content: bytes, source_vendor: str, target_vendor, job_type: str,
                    options: dict, idempotency_key: str, *, allow_document: bool = True,
                    policy: UploadPolicy | None = None, uploaded: dict | None = None,
                    save_upload=None, legacy_vendors=None):
    """Use negotiated multipart/file-id transport, or bounded legacy inline UTF-8.

    Options go through ``job_options``: an option the server would ignore is
    refused (OptionsError) and guided settings travel as ``yaml_v2`` (#11, #19).
    """
    try:
        source_vendor, target_vendor = submission_vendors(source_vendor, target_vendor)
    except ValueError as exc:
        raise APIError(422, "unprocessable", message=str(exc)) from None
    if legacy_vendors is not None and legacy_vendors not in legacy_submission_vendors(source_vendor, target_vendor):
        raise APIError(409, "conflict")
    settings = external_body(options, job_type, target_vendor, allow_document=allow_document)
    policy = policy or UploadPolicy.fetch(client)
    if not content or len(content) > policy.max_bytes:
        raise APIError(413, "configuration_too_large", detail={"max_bytes": policy.max_bytes})
    from .upload_policy import is_handoff_archive
    archive = is_handoff_archive(content)
    if archive and not archive_submission_allowed(policy, source_vendor, job_type):
        raise APIError(422, "archive_requires_file_conversion")
    if not archive:
        from .draft_io import validate_source_bytes
        try:
            validate_source_bytes(content)
        except ValueError:
            raise APIError(422, "invalid_configuration_encoding") from None
    body = {**settings, "source_vendor": source_vendor,
            "technology": device_type_of(source_vendor)}
    if policy.file_id_submission:
        receipt = uploaded
        if receipt is None:
            response = client.upload_file(content, filename="configuration.zip" if archive else "configuration.cfg")
            receipt = response.get("file") if isinstance(response, dict) else None
        expected = hashlib.sha256(content).hexdigest()
        if (not isinstance(receipt, dict) or receipt.get("checksum") != expected
                or type(receipt.get("file_size")) is not int or receipt["file_size"] != len(content)):
            raise APIError(502, "upload_checksum_mismatch")
        try:
            body["file_id"] = client.identifier(receipt.get("id", ""))
        except (TypeError, ValueError):
            raise APIError(502, "invalid_upload_receipt") from None
        if save_upload is not None:
            save_upload({k: receipt[k] for k in ("id", "checksum", "file_size")})
    else:
        if uploaded is not None:
            raise APIError(409, "upload_capability_changed")
        body["source_config"] = content.decode("utf-8")
    if target_vendor:
        body["target_vendor"] = target_vendor
    if legacy_vendors is not None:
        body["source_vendor"] = legacy_vendors[0]
        if legacy_vendors[1] is not None:
            body["target_vendor"] = legacy_vendors[1]
    if job_type != "convert":
        body["job_type"] = job_type
    return client.submit_job(body, idempotency_key)


ANALYSIS_RESULTS = {"validate": "validation", "optimize": "optimization"}


def _save_json(output, job_id: str, filename: str, value):
    # Canonical bytes keep a repeat download identical (JSONB key order).
    content = json.dumps(value, indent=2, sort_keys=True, default=str).encode()
    return output.save_artifact(job_id, filename, content, hashlib.sha256(content).hexdigest())


def download_external(client, job_id: str, output, *, job=None) -> list:
    """Translated config, the structured report and the evidence workbook, hash-verified.

    A validate or optimize job emits no translation: GET /jobs/{id} carries its
    result, saved as ``<job>.validation.json`` / ``<job>.optimization.json``.
    Validation also downloads available NCIR, receipt, TXT, PDF and XLSX exports.
    """
    saved = []
    job = client.job(job_id) if job is None else job
    key = ANALYSIS_RESULTS.get(job.get("job_type")) if isinstance(job, dict) else None
    if key:
        result = job.get(key)
        if result is None:
            raise APIError(409, "job_not_completed", detail={"job_id": job_id, "status": job.get("status")})
        saved.append(_save_json(output, job_id, f"{key}.json", {
            "job_id": job_id, "job_type": job["job_type"], "status": job.get("status"),
            "source_vendor": job.get("source_vendor"), key: result}))
        workbook_saved = False
        if key == "validation":
            for fmt, filename in (("ncir", "source.ncir"), ("receipt", "receipt.json"),
                                  ("txt", "validation.txt"), ("pdf", "validation.pdf"),
                                  ("xlsx", "validation.xlsx")):
                artifact = client.validation_artifact(job_id, fmt)
                if artifact is not None:
                    content, expected = artifact
                    saved.append(output.save_artifact(job_id, filename, content, expected))
                    workbook_saved |= fmt == "xlsx"
        workbook = None if workbook_saved else client.evidence_workbook(job_id)
        if workbook:
            saved.append(output.save_artifact(job_id, "evidence.xlsx", workbook,
                                              hashlib.sha256(workbook).hexdigest()))
        return saved
    translated = client.translated(job_id)
    if translated:
        saved.append(output.save_artifact(job_id, "translated.txt", translated,
                                          hashlib.sha256(translated).hexdigest()))
    saved.append(_save_json(output, job_id, "report.json", client.report(job_id)))
    workbook = client.evidence_workbook(job_id)
    if workbook:
        saved.append(output.save_artifact(job_id, "evidence.xlsx", workbook,
                                          hashlib.sha256(workbook).hexdigest()))
    return saved


@dataclass
class DownloadOutcome:
    paths: list = field(default_factory=list)
    complete: bool = False
    pending_export: dict | None = None
    export_reference: dict | None = None
    failure: dict | None = None


def download_external_resumable(client, job_id: str, output, *, export_id=None,
                                workbook_only=False) -> DownloadOutcome:
    """One bounded export step; already-published primary files retain receipts.

    Legacy analysis exports keep their existing path. Normal conversion downloads
    never silently retry the old synchronous workbook endpoint. An explicit
    workbook-only resume inspects the exact returned export without re-preparing
    or re-downloading primary artifacts.
    """
    result = DownloadOutcome()
    workbook_started = workbook_only
    analysis_job = False
    if export_id is not None:
        result.export_reference = {"job_id": job_id, "artifact_kind": "evidence-workbook", "export_id": export_id}
    try:
        if not workbook_only:
            job = client.job(job_id)
            if isinstance(job, dict) and job.get("job_type") in ANALYSIS_RESULTS:
                analysis_job = True
                result.paths = download_external(client, job_id, output, job=job)
                result.complete = True
                return result
            translated = client.translated(job_id)
            if translated:
                result.paths.append(output.save_artifact(job_id, "translated.txt", translated,
                                                        hashlib.sha256(translated).hexdigest()))
            result.paths.append(_save_json(output, job_id, "report.json", client.report(job_id)))
        workbook_started = True
        meta = client.workbook_export(job_id, export_id)
        result.export_reference = {"job_id": job_id, "artifact_kind": "evidence-workbook", "export_id": meta["export_id"]}
        result.pending_export = meta
        if meta["state"] in {"queued", "processing"}:
            return result
        if meta["state"] in {"failed", "stale"}:
            result.failure = {"code": meta["failure_code"],
                              "message": "This export cannot be downloaded. Review its state before explicitly preparing a replacement."}
            return result
        content, digest = client.workbook_export_content(job_id, meta)
        result.paths.append(output.save_artifact(job_id, "evidence.xlsx", content, digest))
        result.complete = True
        result.pending_export = None
        result.export_reference = None
    except APIError as exc:
        if analysis_job:
            raise
        # Fixed guidance only: server exception prose and artifact bodies are not
        # model-facing. A timeout does not establish that preparation failed.
        known = {"connection_failed", "export_unavailable", "export_not_ready", "export_failed",
                 "export_stale", "invalid_export_metadata", "invalid_export_content", "invalid_export_encoding",
                 "artifact_size_mismatch", "artifact_checksum_mismatch"}
        code = exc.code if exc.code in known else "download_failed"
        outcome_note = "The network response outcome is unknown. " if exc.status == 0 else ""
        guidance = (
            "Saved file receipts remain valid. The remaining export was not downloaded; "
            "do not treat this as a complete bundle. Use the known export_id to inspect it; "
            "if no ID was returned, reconcile preparation before retrying. "
            "An unavailable export may require a server upgrade or restored access.")
        if not workbook_started:
            guidance = ("The primary artifact download did not finish; workbook preparation has not started. "
                        "Saved file receipts remain valid. Review those receipts before retrying.")
        result.failure = {"code": code, "message": outcome_note + guidance}
    except WorkspaceError:
        if analysis_job:
            raise
        result.failure = {"code": "download_refused", "message": (
            "A local artifact could not be safely published. Already verified file receipts remain valid. "
            "Check the output location without replacing existing files. "
            + ("Resume the known workbook export." if result.export_reference else
               "Workbook preparation has not returned a reference; review saved receipts before retrying."))}
    return result
