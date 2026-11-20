"""Negotiated file intake bounds; independent of the model and editable job decisions."""
from dataclasses import dataclass

from .api import APIError

LEGACY_INLINE_BYTES = 5 * 1024 * 1024
CLIENT_MAX_FILE_BYTES = 100 * 1024 * 1024


def is_handoff_archive(content: bytes) -> bool:
    """Recognize a transport container only; the server validates its manifest/scope."""
    return content.startswith((b"PK\x03\x04", b"PK\x05\x06"))


@dataclass(frozen=True)
class UploadPolicy:
    inline_bytes: int = LEGACY_INLINE_BYTES
    upload_bytes: int = LEGACY_INLINE_BYTES
    file_id_submission: bool = False

    @property
    def max_bytes(self):
        return self.upload_bytes if self.file_id_submission else self.inline_bytes

    @classmethod
    def from_capabilities(cls, caps):
        limits = caps.get("limits", {}) if isinstance(caps, dict) else None
        if not isinstance(limits, dict):
            raise APIError(502, "invalid_upload_policy")
        enabled = limits.get("file_id_submission", False)
        if type(enabled) is not bool:
            raise APIError(502, "invalid_upload_policy")
        inline = limits.get("max_inline_config_bytes", limits.get("max_config_bytes", LEGACY_INLINE_BYTES))
        upload = limits.get("max_upload_bytes", inline)
        if any(type(n) is not int or not 1 <= n <= CLIENT_MAX_FILE_BYTES for n in (inline, upload)):
            raise APIError(502, "invalid_upload_policy")
        # No new inline allowance: large files require the advertised upload path.
        return cls(min(inline, LEGACY_INLINE_BYTES), upload, enabled)

    @classmethod
    def fetch(cls, client):
        try:
            return cls.from_capabilities(client.capabilities())
        except APIError as exc:
            if exc.status != 404:
                raise
            return cls()  # Older servers without discovery retain the bounded inline path.
