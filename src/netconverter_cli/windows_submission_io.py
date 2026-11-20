"""Windows journal IO on local NTFS, with ancestors pinned against replacement."""
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from dataclasses import dataclass
import os
import re
import uuid

from . import windows_draft_io as native
from .workspace import WorkspaceError

native._k.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, wintypes.LPVOID]
native._k.CreateDirectoryW.restype = wintypes.BOOL
native._k.FlushFileBuffers.argtypes = [wintypes.HANDLE]
native._k.FlushFileBuffers.restype = wintypes.BOOL


@dataclass
class Directory:
    path: object
    handles: list


def _path(directory, name):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name) or ".." in name:
        raise WorkspaceError("Invalid submission metadata name")
    return directory.path / name


def _mkdir(path):
    descriptor = wintypes.LPVOID()
    try:
        if not native._adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "O:" + native._current_user_sid_text() + "D:P(A;;FA;;;OW)",
                1, ctypes.byref(descriptor), None):
            native._fail()
        attrs = native._SecurityAttributes(ctypes.sizeof(native._SecurityAttributes), descriptor, False)
        if not native._k.CreateDirectoryW(str(path), ctypes.byref(attrs)):
            error = ctypes.get_last_error()
            if error != 183:
                raise OSError(error, "secure journal directory creation failed")
    finally:
        if descriptor.value:
            native._k.LocalFree(descriptor)


@contextmanager
def open_directory(root, *, create=False):
    handles = []
    try:
        handles = native._directories(root)
        current = root
        for name in (".netconverter", "submissions"):
            current /= name
            if create:
                _mkdir(current)
            handles.append(native._open(current, native._READ, native._OPEN_EXISTING, True))
        if not native._protected_owner_acl(handles[-1]):
            raise WorkspaceError("Submission directory must have a protected owner-only ACL")
        yield Directory(current, handles)
    except OSError:
        raise WorkspaceError("Cannot securely access the submission journal") from None
    finally:
        for handle in reversed(handles):
            native._k.CloseHandle(handle)


def _owned_file(directory, name, access, disposition=native._OPEN_EXISTING):
    handle = native._open(_path(directory, name), access, disposition, False,
                          write_through=bool(access & native._WRITE))
    if not native._protected_owner_acl(handle):
        native._k.CloseHandle(handle)
        raise WorkspaceError("Submission metadata must have a protected owner-only ACL")
    return handle


def _flush(handle):
    if not native._k.FlushFileBuffers(handle):
        raise OSError(ctypes.get_last_error(), "submission metadata flush failed")


def _delete(handle):
    disposition = wintypes.BOOL(True)
    if not native._k.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
        raise OSError(ctypes.get_last_error(), "submission metadata removal failed")


@contextmanager
def lock(directory, name):
    handle = None
    try:
        try:
            handle = _owned_file(directory, name, native._READ | native._WRITE, native._CREATE_NEW)
            _flush(handle)
        except OSError as exc:
            if exc.errno not in (80, 183):
                raise
            handle = _owned_file(directory, name, native._READ | native._WRITE)
        # _open permits read sharing only: another write/delete handle cannot
        # open this lock until we close it, even from another process.
        yield
    except OSError as exc:
        if exc.errno in (32, 33):
            raise WorkspaceError("A submission for this file is already in progress") from None
        raise WorkspaceError("Cannot securely lock the submission journal") from None
    finally:
        if handle is not None:
            native._k.CloseHandle(handle)


def read(directory, name):
    try:
        handle = _owned_file(directory, name, native._READ)
    except OSError as exc:
        if exc.errno in (2, 3):
            return None
        raise
    try:
        raw = native._read(handle, 32768)
        native._require_single_link(handle)
        return raw
    finally:
        native._k.CloseHandle(handle)


def _write(handle, raw):
    duplicate = wintypes.HANDLE()
    process = native._k.GetCurrentProcess()
    if not native._k.DuplicateHandle(process, handle, process, ctypes.byref(duplicate), 0, False, 2):
        native._fail()
    fd = native._fd_from_owned_handle(duplicate.value, os.O_WRONLY | os.O_BINARY)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(fd, remaining)
            if not written:
                raise OSError("submission metadata write failed")
            remaining = remaining[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def replace(directory, name, raw):
    # Validate an existing receipt without following reparse points or accepting
    # hard links. Replacement changes a directory entry, never the old contents.
    try:
        existing = _owned_file(directory, name, native._READ)
    except OSError as exc:
        if exc.errno not in (2, 3):
            raise
    else:
        native._k.CloseHandle(existing)
    temporary = ".nc-" + uuid.uuid4().hex
    handle = _owned_file(directory, temporary, native._READ | native._WRITE | native._DELETE,
                         native._CREATE_NEW)
    published = False
    try:
        _write(handle, raw)
        native._require_single_link(handle)
        native._rename(handle, directory.handles[-1], str(_path(directory, name)), replace_existing=True)
        published = True
        _flush(handle)
    finally:
        try:
            if not published:
                _delete(handle)
        finally:
            native._k.CloseHandle(handle)


def remove(directory, name):
    try:
        handle = _owned_file(directory, name, native._READ | native._WRITE | native._DELETE)
    except OSError as exc:
        if exc.errno in (2, 3):
            return
        raise
    try:
        _delete(handle)
        _flush(handle)
    finally:
        native._k.CloseHandle(handle)
