"""Metadata-only, descriptor-confined workspace discovery for the local bridge.

No source file is opened. Listing is advisory: submit_file independently snapshots
and validates the selected source. Windows enumeration needs a native handle
implementation; refuse there rather than fall back to raceable pathname walks.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import PurePosixPath
import secrets
import stat
import time

from .workspace import WorkspaceError
from .exposure import strip_secrets

MAX_SCANNED_ENTRIES = 10_000
MAX_PAGE_SIZE = 100
MAX_ENTRY_PAGE_BYTES = 12_000
MAX_RESPONSE_BYTES = 16_384
MAX_PATH_BYTES = 1024
CURSOR_TTL_SECONDS = 300


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _metadata(fd, name):
    return os.stat(name, dir_fd=fd, follow_symlinks=False)


class WorkspaceListing:
    def __init__(self, workspace):
        self.workspace = workspace
        self._cursor_key = secrets.token_bytes(32)

    def _cursor(self, digest, offset):
        payload = json.dumps([1, int(time.time()) + CURSOR_TTL_SECONDS, digest, offset],
                             separators=(",", ":")).encode()
        signature = hmac.digest(self._cursor_key, payload, "sha256")
        return base64.urlsafe_b64encode(signature + payload).decode()

    def _offset(self, token, digest):
        if token is None:
            return 0
        try:
            if not isinstance(token, str) or not 1 <= len(token) <= 1024:
                raise ValueError()
            decoded = base64.b64decode(token, altchars=b"-_", validate=True)
            signature, payload = decoded[:32], decoded[32:]
            if not hmac.compare_digest(signature, hmac.digest(self._cursor_key, payload, "sha256")):
                raise ValueError()
            version, expires, previous, offset = json.loads(payload)
            if (version != 1 or expires < time.time() or previous != digest
                    or type(offset) is not int or offset < 0):
                raise ValueError()
            return offset
        except (ValueError, TypeError, UnicodeError):
            raise WorkspaceError("Invalid or stale listing cursor; list this folder again without a cursor") from None

    def list(self, folder=".", limit=50, cursor=None):
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise WorkspaceError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if (not isinstance(folder, str) or not 1 <= len(folder) <= 1024
                or "\\" in folder or not folder.isprintable()):
            raise WorkspaceError("Select a relative workspace folder")
        if len(folder.encode("utf-8")) > MAX_PATH_BYTES or strip_secrets(folder) != folder:
            raise WorkspaceError("Folder path is too long or cannot be disclosed safely; use a shorter neutral name")
        raw = PurePosixPath(folder)
        if raw.is_absolute() or any(p.startswith(".") or ":" in p for p in raw.parts):
            raise WorkspaceError("Hidden folders, parent traversal and absolute paths are not accepted")
        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
                or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
                or os.scandir not in os.supports_fd):
            raise WorkspaceError("Secure workspace listing is unavailable on this platform; submit a known relative file path")
        descriptors, links = [], []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

        def verify_links():
            for parent, name, child in links:
                current, opened = _metadata(parent, name), os.fstat(child)
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise WorkspaceError("Workspace folder changed during listing; try again")

        try:
            fd = os.open(self.workspace.root.anchor, flags)
            descriptors.append(fd)
            for component in (*self.workspace.root.parts[1:], *raw.parts):
                child = os.open(component, flags, dir_fd=fd)
                descriptors.append(child)
                links.append((fd, component, child))
                fd = child
            verify_links()
            before = _identity(os.fstat(fd))
            rows, excluded = [], 0
            with os.scandir(fd) as entries:
                for scanned, entry in enumerate(entries, 1):
                    if scanned > MAX_SCANNED_ENTRIES:
                        raise WorkspaceError("Folder exceeds the listing scan limit; select a smaller subfolder or a known file path")
                    name = entry.name
                    if name.startswith(".") or not name.isprintable() or "\\" in name or ":" in name:
                        excluded += 1
                        continue
                    try:
                        name.encode("utf-8")
                    except UnicodeError:
                        excluded += 1
                        continue
                    info = _metadata(fd, name)
                    is_file = stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    if not is_file and not stat.S_ISDIR(info.st_mode):
                        excluded += 1
                        continue  # no symlinks, hardlinked files, devices, sockets or pipes
                    path = str(raw / name)
                    if len(path.encode("utf-8")) > MAX_PATH_BYTES or strip_secrets(path) != path:
                        excluded += 1
                        continue
                    rows.append((path, "file" if is_file else "directory",
                                 info.st_size if is_file else None, name, _identity(info)))
            rows.sort(key=lambda row: row[0])
            for _, _, _, name, expected in rows:
                if _identity(_metadata(fd, name)) != expected:
                    raise WorkspaceError("Workspace entry changed during listing; try again")
            verify_links()
            if _identity(os.fstat(fd)) != before:
                raise WorkspaceError("Workspace folder changed during listing; try again")
            # Hash metadata only, never configuration bytes. Binds pagination to
            # this folder and the same names/identities/sizes/modification times.
            digest = hashlib.sha256(json.dumps([str(raw), before, rows], ensure_ascii=True,
                                               separators=(",", ":")).encode()).hexdigest()
            offset = self._offset(cursor, digest)
            if offset > len(rows):
                raise WorkspaceError("Invalid listing cursor; restart the listing")
            page, page_bytes = [], 0
            for row in rows[offset:offset + limit]:
                path, kind, size, _, _ = row
                cost = len(json.dumps({"path": path, "type": kind, "size_bytes": size},
                                      ensure_ascii=True).encode()) + 2
                if page_bytes + cost > MAX_ENTRY_PAGE_BYTES:
                    if not page:
                        raise WorkspaceError("A workspace entry exceeds the listing response budget; use a shorter path")
                    break
                page.append(row)
                page_bytes += cost
            more = offset + len(page) < len(rows)
            response = {
                "folder": str(raw),
                "entries": [{"path": path, "type": kind, "size_bytes": size}
                            for path, kind, size, _, _ in page],
                "has_more": more,
                "next_cursor": self._cursor(digest, offset + len(page)) if more else None,
                "excluded_entries": excluded,
                "scope": "nonrecursive metadata; hidden state, unsafe links, special files, unsupported or oversized paths and secret-shaped names excluded",
                "next_steps": "Select a file and explicit source/target/device identity, then call submit_file with job_type='prescan'. File bytes and eligibility are verified again at submission.",
            }
            if len(json.dumps(response, ensure_ascii=True).encode()) > MAX_RESPONSE_BYTES:
                raise WorkspaceError("Workspace listing exceeds its response budget; select a shorter folder path")
            return response
        except OSError:
            raise WorkspaceError("Workspace folder could not be listed securely; use an accessible folder inside the workspace") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
