"""Descriptor-anchored journal IO; never re-resolve a path after taking a lock."""
import os
import stat
import uuid
from contextlib import contextmanager

from .workspace import WorkspaceError


def supported():
    return os.name == "nt" or (os.name == "posix" and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
            and {os.open, os.mkdir, os.rename, os.unlink}.issubset(os.supports_dir_fd))


@contextmanager
def open_directory(root, *, create=False):
    if not supported():
        raise WorkspaceError("Secure submission journaling is unavailable on this platform; "
                             "no upload or job was submitted")
    if os.name == "nt":
        from .windows_submission_io import open_directory as windows_directory
        with windows_directory(root, create=create) as directory:
            yield directory
        return
    if not root.is_absolute() or ".." in root.parts:
        raise WorkspaceError("Invalid submission workspace")
    descriptors = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        current = os.open(root.anchor, flags)
        descriptors.append(current)
        for component in root.parts[1:]:
            current = os.open(component, flags, dir_fd=current)
            descriptors.append(current)
        for component in (".netconverter", "submissions"):
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
            current = os.open(component, flags, dir_fd=current)
            descriptors.append(current)
        yield current
    except OSError:
        raise WorkspaceError("Cannot securely access the submission journal") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def open_regular(directory, name, flags, mode=0o600):
    descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                         mode, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise WorkspaceError("Submission metadata must be a regular file without hard links")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def read(directory, name):
    if os.name == "nt":
        from .windows_submission_io import read as windows_read
        return windows_read(directory, name)
    try:
        descriptor = open_regular(directory, name, os.O_RDONLY)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise WorkspaceError("Submission receipt exceeds its metadata limit")
    return raw


def replace(directory, name, raw):
    if os.name == "nt":
        from .windows_submission_io import replace as windows_replace
        return windows_replace(directory, name, raw)
    temporary = ".nc-" + uuid.uuid4().hex
    descriptor = open_regular(directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def remove(directory, name):
    if os.name == "nt":
        from .windows_submission_io import remove as windows_remove
        return windows_remove(directory, name)
    try:
        os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass
    os.fsync(directory)


@contextmanager
def lock(directory, name):
    if os.name == "nt":
        from .windows_submission_io import lock as windows_lock
        with windows_lock(directory, name):
            yield
        return
    try:
        descriptor = open_regular(directory, name, os.O_RDWR | os.O_CREAT)
    except OSError:
        raise WorkspaceError("Cannot open submission lock") from None
    try:
        import fcntl
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise WorkspaceError("A submission for this file is already in progress") from None
        yield
    finally:
        os.close(descriptor)
