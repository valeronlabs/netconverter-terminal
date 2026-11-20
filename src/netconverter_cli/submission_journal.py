"""Durable, bounded transport receipts; never a source file or an approval authority.

An ambiguous POST is retried with its original file ID and idempotency key. The
workspace record only remembers the client confirmation already obtained; it
cannot authorize a different source, options, account, destination or exposure.
"""
import base64
import hashlib
import json
import math
import re
import time
import uuid
from contextlib import contextmanager

from .api import as_credential
from .workspace import WorkspaceError
from . import _journal_directory as journal_io

# The server retains POST /jobs idempotency for 24 hours. Reserve an hour for
# request/clock uncertainty; an expired ambiguity must be reconciled, not retried.
MAX_RETRY_SECONDS = 23 * 60 * 60
_INITIAL_REFUSALS = {
    400: {"bad_request", "request_failed"},
    403: {"forbidden", "request_failed"},
    404: {"not_found", "request_failed"},
    413: {"error", "request_failed"},
    422: {"unprocessable", "request_failed", "archive_requires_file_conversion", "invalid_configuration_encoding",
          "storage_quota_exceeded"},
    429: {"rate_limited", "request_failed"},
}


def definitive_refusal(error):
    """Recognized pre-queue rejections; malformed responses remain ambiguous."""
    return error.code in _INITIAL_REFUSALS.get(error.status, set())


def ensure_retry_timestamp(started):
    if (type(started) not in (int, float) or not math.isfinite(started)
            or not 0 <= time.time() - started < MAX_RETRY_SECONDS):
        raise WorkspaceError("The interrupted submission is outside its safe retry window or has an "
                             "invalid timestamp; reconcile the original job before changing its receipt")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def credential_scope(credential):
    """Local replay partition, not authentication; the server still verifies every write.

    OAuth subject/issuer keep a token refresh in the same partition. Opaque
    credentials use a digest. Neither credential bytes nor identity claims are
    written to disk or exposed to the assistant.
    """
    # Match REST client credential handling for initial and lazily loaded CLI
    # API keys, while preserving OAuth objects and their refresh/identity scope.
    credential = as_credential(credential)
    token = credential.token()
    if getattr(credential, "kind", "key") == "clerk" and len(token) <= 32768:
        try:
            part = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            if isinstance(claims, dict) and all(isinstance(claims.get(k), str) and claims[k] for k in ("iss", "sub")):
                return _digest(["clerk", claims["iss"], claims["sub"], claims.get("org_id")])
        except (ValueError, IndexError, UnicodeError):
            pass
    return _digest([getattr(credential, "kind", "key"), token])


class SubmissionJournal:
    def __init__(self, workspace, relative_path, binding, *, legacy_bindings=()):
        self.workspace = workspace
        self.directory = workspace.state_dir / "submissions"
        with journal_io.open_directory(workspace.root, create=True):
            pass
        name = _digest(relative_path)
        self.path = self.directory / (name + ".json")
        self.lock_path = self.directory / (name + ".lock")
        self.binding = _digest(binding)
        self._legacy_bindings = [(_digest(candidate), (candidate["source_vendor"], candidate["target_vendor"]))
                                 for candidate in legacy_bindings]
        self.legacy_vendors = None
        self.record = {}
        self._directory_fd = None

    @contextmanager
    def locked(self):
        if self._directory_fd is not None:
            raise WorkspaceError("This submission journal is already locked")
        with journal_io.open_directory(self.workspace.root) as directory:
            self._directory_fd = directory
            try:
                with self._locked_receipt():
                    yield self
            finally:
                self._directory_fd = None

    @contextmanager
    def _locked_receipt(self):
        with journal_io.lock(self._directory_fd, self.lock_path.name):
            self.record = {}
            self.legacy_vendors = None
            raw = journal_io.read(self._directory_fd, self.path.name)
            if raw is not None:
                try:
                    self.record = json.loads(raw)
                    if (not isinstance(self.record, dict) or type(self.record.get("version")) is not int
                            or self.record["version"] not in (1, 2)
                            or not isinstance(self.record.get("binding"), str)
                            or not re.fullmatch(r"[a-f0-9]{64}", self.record["binding"])
                            or not isinstance(self.record.get("key"), str)
                            or not re.fullmatch(r"[a-f0-9]{32}", self.record["key"])
                            or (self.record.get("result") is not None
                                and not isinstance(self.record["result"], dict))):
                        raise ValueError()
                except (OSError, ValueError, UnicodeError, RecursionError):
                    raise WorkspaceError("Invalid submission receipt; resolve it before starting another job") from None
                if self.record["version"] == 1:
                    matches = [vendors for binding, vendors in self._legacy_bindings
                               if binding == self.record["binding"]]
                    if len(matches) > 1 or (not matches and self.record["binding"] != self.binding):
                        raise WorkspaceError("The legacy submission receipt does not uniquely match this work; "
                                             "reconcile its original source, target, options, account and exposure")
                    self.legacy_vendors = matches[0] if matches else None
                    if not self.record.get("result"):
                        self.ensure_retryable()
                elif self.record.get("binding") != self.binding:
                    if not self.record.get("result"):
                        raise WorkspaceError("An interrupted submission for this file is pending; retry its original "
                                             "source, target, options, account and exposure before changing work")
                    self.record = {}
                elif not self.record.get("result"):
                    self.ensure_retryable()
            yield self

    def _require_locked(self):
        if self._directory_fd is None:
            raise WorkspaceError("Submission metadata changes require the journal lock")
        return self._directory_fd

    def start(self):
        if not self.record:
            self.record = {"version": 2, "binding": self.binding, "key": uuid.uuid4().hex,
                           "started_at": time.time()}
            self.save()

    def ensure_retryable(self):
        ensure_retry_timestamp(self.record.get("started_at"))

    def forget_initial_refusal(self, error):
        """Only called for a first attempt, never after an ambiguous earlier POST."""
        if definitive_refusal(error):
            try:
                journal_io.remove(self._require_locked(), self.path.name)
            except OSError:
                raise WorkspaceError("Cannot clear the rejected submission receipt") from None
            self.record = {}

    def save(self):
        raw = json.dumps(self.record, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > 32768:
            raise WorkspaceError("Submission receipt exceeds its metadata limit")
        try:
            journal_io.replace(self._require_locked(), self.path.name, raw)
        except OSError:
            raise WorkspaceError("Cannot persist submission receipt; reconcile it before retrying") from None

    def uploaded(self, receipt):
        self.ensure_retryable()
        self.record["uploaded"] = receipt
        self.save()

    def completed(self, result):
        self.record["result"] = result
        self.save()
