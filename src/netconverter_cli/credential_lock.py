"""Owner-scoped cross-process credential locks; no credential bytes on disk."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import time


class CredentialLockError(RuntimeError):
    pass


def lock_root() -> Path:
    # OS credentials are shared even when two clients choose different config
    # directories. Do not scope their lock to NETCONVERTER_CONFIG_HOME.
    return Path.home() / ".netconverter-credential-locks"


@contextmanager
def locked(path: Path, timeout: float = 5.0):
    """Never unlink lock files: waiters must keep naming the same inode."""
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "nt":
            with _windows_locked(path, timeout):
                yield
            return
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise CredentialLockError("Secure credential locking is unavailable on this platform")
        import fcntl
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise CredentialLockError("Credential lock directory must not be writable by other users")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or info.st_mode & 0o077):
                raise CredentialLockError("Credential lock must be an owner-only regular file")
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise CredentialLockError("Credential store is busy; retry after the active operation finishes")
                    time.sleep(0.01)
            current = path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise CredentialLockError("Credential lock changed while waiting")
            yield
        finally:
            # Closing releases flock only after the operation really finished.
            os.close(fd)
    except OSError:
        raise CredentialLockError("Credential lock could not be acquired securely") from None


@contextmanager
def _windows_locked(path: Path, timeout: float):
    # Reuse the existing local-NTFS, no-reparse, owner-ACL handle primitives.
    from . import windows_draft_io as native
    handles, held = [], None
    try:
        handles = native._directories(path.parent)
        deadline = time.monotonic() + timeout
        while held is None:
            try:
                try:
                    held = native._open(path, native._READ | native._WRITE, native._OPEN_EXISTING, False)
                except OSError as exc:
                    if exc.errno not in (2, 3):
                        raise
                    held = native._open(path, native._READ | native._WRITE, native._CREATE_NEW, False)
            except OSError as exc:
                if exc.errno not in (32, 33, 80, 183) or time.monotonic() >= deadline:
                    raise CredentialLockError("Credential store is busy or its native lock is unavailable") from None
                time.sleep(0.01)
        if not native._protected_owner_acl(held):
            raise CredentialLockError("Credential lock must have an owner-only protected ACL")
        yield
    finally:
        if held is not None:
            native._k.CloseHandle(held)
        for handle in reversed(handles):
            native._k.CloseHandle(handle)
