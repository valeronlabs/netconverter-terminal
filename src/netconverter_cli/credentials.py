"""Credentials never enter workspace files or model messages.

They live in the OS credential store, or, where there is none (an SSH host, a
container), in the encrypted credential file (``credential_file.py``, #10):
``NETCONVERTER_CREDENTIAL_STORE`` = ``auto`` (default: the OS keyring when it is
available, else the encrypted file; reads check both), ``keyring`` or ``file``.
"""

import getpass
import hashlib
import os
import sys
import threading
import time
from contextlib import ExitStack

import keyring

from .errors import KEYRING_LOCKED

SERVICE = "NetConverter Terminal"
# A locked Secret Service collection (or a keychain waiting on a dialog) can block
# a keyring call indefinitely; whoami hung for over 30 s after a reboot (#10).
KEYRING_TIMEOUT_S = 5.0
_RETRY_LOCKED_AFTER_S = 30.0
_locked_at: float | None = None
_transaction = threading.local()


class KeyringLocked(RuntimeError):
    """The OS credential store did not answer in time."""

    def __init__(self):
        super().__init__(KEYRING_LOCKED)


def _timeout() -> float:
    """KEYRING_TIMEOUT_S, or NETCONVERTER_KEYRING_TIMEOUT_S for a keychain that asks slowly."""
    try:
        return max(0.1, float(os.environ["NETCONVERTER_KEYRING_TIMEOUT_S"]))
    except (KeyError, ValueError):
        return KEYRING_TIMEOUT_S


def _bounded(call, *args, _cooldown=True):
    """Run one keyring call with a deadline; a call that never returns means locked.

    After one timeout, calls fail fast for a while instead of each waiting again.
    """
    global _locked_at
    if getattr(_transaction, "active", False):
        # The transaction's worker owns the OS lock. Never spawn a second
        # worker that could outlive that lock after an inner timeout.
        return call(*args)
    if _cooldown and _locked_at is not None and time.monotonic() - _locked_at < _RETRY_LOCKED_AFTER_S:
        raise KeyringLocked()
    box = {}

    def target():
        try:
            box["value"] = call(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=target, name="netconverter-keyring", daemon=True)
    worker.start()
    worker.join(_timeout())
    if worker.is_alive():
        if _cooldown:
            _locked_at = time.monotonic()
        raise KeyringLocked()
    if _cooldown:
        _locked_at = None
    if "error" in box:
        raise box["error"]
    return box.get("value")
# Only operating-system credential stores are trusted. Third-party keyring
# backends (plaintext files, encrypted-file backends with a master password on
# disk) are refused. The one file store is our own encrypted file (#10), used
# when chosen or when no OS store is reachable; it never holds plaintext.
_OS_BACKENDS = frozenset(
    {
        "keyring.backends.macOS",
        "keyring.backends.Windows",
        "keyring.backends.SecretService",
    }
)


def session_bus_fallback(environ=None, *, platform=None, uid=None, exists=os.path.exists):
    """Linux: point DBUS_SESSION_BUS_ADDRESS at the user's bus socket when it is unset (#17).

    Codex, Cursor CLI and OpenClaw start stdio MCP servers with a near-empty
    environment, and jeepney (keyring → Secret Service) reads only that
    variable, so the sign-in in the OS keyring was invisible. Tries
    ``$XDG_RUNTIME_DIR/bus``, then ``/run/user/<uid>/bus``; returns the socket
    path it chose, else None. Must run before keyring picks its backend.
    """
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    if not platform.startswith("linux") or environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return None
    candidates = []
    runtime = environ.get("XDG_RUNTIME_DIR")
    if runtime:
        candidates.append(f"{runtime.rstrip('/')}/bus")
    if uid is None:
        uid = getattr(os, "getuid", lambda: None)()
    if uid is not None:
        candidates.append(f"/run/user/{uid}/bus")
    for path in dict.fromkeys(candidates):  # in order, without a duplicate
        if exists(path):
            environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={path}"
            return path
    return None


STORE_ENV = "NETCONVERTER_CREDENTIAL_STORE"
STORES = ("auto", "keyring", "file")
OS_STORE_LABEL = "OS credential store"
_warned: set[str] = set()


def store_choice() -> str:
    """auto | keyring | file, from the user's environment (``login --store`` sets it per run)."""
    value = os.environ.get(STORE_ENV, "auto").strip().lower()
    return value if value in STORES else "auto"


def _file_store():
    from .credential_file import EncryptedFileStore

    return EncryptedFileStore()


def _warn(message: str) -> None:
    """One stderr line per message per process (never a secret; stdout stays clean for JSON/MCP)."""
    if message not in _warned:
        _warned.add(message)
        print(f"netconverter: {message}", file=sys.stderr)


class _Keyring:
    label = OS_STORE_LABEL

    def __init__(self, backend):
        self.backend = backend

    def get(self, name):
        return _bounded(self.backend.get_password, SERVICE, name)

    def set(self, name, value):
        _bounded(self.backend.set_password, SERVICE, name, value)

    def delete(self, name):
        if _bounded(self.backend.get_password, SERVICE, name) is not None:
            _bounded(self.backend.delete_password, SERVICE, name)


def _keyring_store():
    """The OS store wrapped as a store, or None. KeyringLocked propagates."""
    try:
        backend = _os_backend()
    except KeyringLocked:
        raise
    except Exception:
        return None
    return _Keyring(backend) if backend is not None else None


def _read_stores() -> list:
    choice = store_choice()
    stores = []
    if choice in ("auto", "keyring"):
        found = _keyring_store()
        if found is not None:
            stores.append(found)
    if choice == "file" or (choice == "auto" and _file_store().exists()):
        stores.append(_file_store())
    return stores


def _write_store():
    choice = store_choice()
    if choice == "file":
        return _file_store()
    found = _keyring_store()
    if found is not None or choice == "keyring":
        return found
    return _file_store()  # auto, and no OS store reachable


def store_in_use() -> str | None:
    """Where a new credential would be saved: "keyring", "file" or None (nowhere)."""
    store = _write_store()
    if store is None:
        return None
    return "keyring" if isinstance(store, _Keyring) else "file"


def store_label() -> str:
    """The store a new credential goes to, for messages: never a secret."""
    store = _write_store()
    return store.label if store is not None else "none"


def prepare_store() -> str:
    """Check the store a sign-in will be saved to before the sign-in starts.

    Returns its label; raises CredentialStoreError (message safe to show) when
    nothing can be saved, e.g. the encrypted file has no passphrase. A
    passphrase prompt (on a terminal) happens here, not after the browser.
    """
    from .credential_file import FileStoreError

    store = _write_store()
    if store is None:
        raise CredentialStoreError(
            "No OS credential store is available and NETCONVERTER_CREDENTIAL_STORE=keyring "
            "rules out the encrypted credential file")
    if isinstance(store, _Keyring):
        return store.label
    try:
        store.prepare()
    except FileStoreError as exc:
        raise CredentialStoreError(
            ("No OS credential store is available, so the sign-in goes to the encrypted credential "
             "file. " if store_choice() == "auto" else "") + str(exc)) from None
    return store.label


class CredentialStoreError(RuntimeError):
    """Nothing can store the credential; the message says why (never a secret)."""


def token_transaction(account, operation, *, writing=False):
    """Run an issuer/client account operation on pinned stores under OS locks.

    The deadline applies to the caller, not the worker: a late keyring call
    retains every lock until it completes. OAuth HTTP never runs here.
    """
    from .credential_lock import lock_root, locked
    from .credential_file import can_prompt, FileStoreError

    # An interactive passphrase belongs to the caller, before taking account
    # locks or starting a deadline worker. Never leave a timed-out worker
    # waiting for terminal input while it owns the credential transaction.
    try:
        if can_prompt() and store_choice() != "keyring":
            fallback = _file_store()
            if writing or fallback.exists():
                os_store = _keyring_store() if store_choice() == "auto" else None
                if os_store is None or (not writing and not os_store.get(account + ":access")):
                    fallback.prepare()
    except KeyringLocked:
        raise
    except FileStoreError as exc:
        raise CredentialStoreError(str(exc)) from None
    except Exception:
        raise CredentialStoreError("Could not prepare the credential store; unlock the store and retry") from None

    def run():
        _transaction.active = True
        try:
            stores = _read_stores()
            writer = _write_store()

            def identity(store):
                if isinstance(store, _Keyring):
                    return "keyring:" + store.backend.__class__.__module__
                path = str(store.path)
                return "file:" + (path.casefold() if os.name == "nt" or sys.platform == "darwin" else path)

            candidates = {identity(s): s for s in [*stores, *([writer] if writer is not None else [])]}
            with ExitStack() as stack:
                for scope, store in sorted(candidates.items()):
                    digest = hashlib.sha256(f"{scope}\0{account}".encode()).hexdigest()
                    path = (lock_root() / (digest + ".lock") if isinstance(store, _Keyring)
                            else store.path.with_name(store.path.name + ".oauth-" + digest + ".lock"))
                    stack.enter_context(locked(path))
                return operation([(identity(s), s) for s in stores],
                                 (identity(writer), writer) if writer is not None else None)
        except (KeyringLocked, CredentialStoreError):
            raise
        except Exception:
            raise CredentialStoreError("Could not complete the atomic credential-store operation; unlock the store and retry") from None
        finally:
            _transaction.active = False

    return _bounded(run, _cooldown=store_choice() != "file")


def _file_problem() -> str | None:
    """None when the file store is not involved; "" when it answers; else why it doesn't."""
    if store_choice() == "keyring":
        return None
    store = _file_store()
    if not store.exists():
        return None if store_choice() == "auto" else ""
    if store.unlockable():
        return ""
    from .credential_file import passphrase_hint

    return (f"the NetConverter credentials are in the encrypted file {store.path}, which this process "
            f"cannot open: {passphrase_hint()} (the same passphrase used at sign-in)")


def keyring_problem() -> str:
    """Why no credential store is reachable; "" when one is (#17, #10).

    Written for the person reading an AI client's tool error: it names the
    missing D-Bus bus and the keyring backend in use, or the encrypted
    credential file and the passphrase variable it needs; never a secret.
    """
    file_problem = _file_problem()
    if file_problem is not None:
        return file_problem
    session_bus_fallback()
    try:
        backend = _bounded(keyring.get_keyring)
    except KeyringLocked:
        return KEYRING_LOCKED
    except Exception as exc:  # noqa: BLE001 - any keyring failure is the answer
        return f"the keyring library failed ({type(exc).__name__})"
    if backend.__class__.__module__ in _OS_BACKENDS:
        return ""
    name = f"{backend.__class__.__module__}.{backend.__class__.__name__}"
    if sys.platform.startswith("linux"):
        if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
            return ("no D-Bus session bus: DBUS_SESSION_BUS_ADDRESS is not set and no "
                    "/run/user/<uid>/bus socket was found, so the Secret Service keyring is "
                    f"unreachable (keyring backend: {name})")
        return f"the Secret Service keyring did not answer on the D-Bus session bus (keyring backend: {name})"
    return f"no OS credential store is available (keyring backend: {name})"


def credential_access_hint() -> str:
    """Platform-specific recovery guidance; no credential reads or policy changes."""
    if sys.platform.startswith("linux"):
        return ("Start this MCP server with DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus "
                "in its environment, or configure NETCONVERTER_API_KEY through the client's protected "
                "credential settings; then restart it. Never paste credentials into chat.")
    if sys.platform == "darwin":
        return ("Run the bridge as the same macOS user who signed in. Check that the login Keychain "
                "is unlocked and permit the selected Terminal/Python executable in the macOS prompt "
                "if requested; then reconnect the assistant. Run `netconverter whoami` from that "
                "same installation. Do not paste credentials into chat or disable Keychain protection.")
    return ("Run the bridge as the same signed-in operating-system user and check access to the "
            "credential store from that installation with `netconverter whoami`; then reconnect "
            "the assistant. Never paste credentials into chat.")


def _os_backend():
    session_bus_fallback()
    backend = _bounded(keyring.get_keyring)
    if backend.__class__.__module__ not in _OS_BACKENDS:
        return None
    return backend


def keyring_available() -> bool:
    try:
        return _os_backend() is not None
    except KeyringLocked:
        raise
    except Exception:
        return False


def _prompt_text(name: str, label: str | None) -> str:
    """The hidden-input prompt: names the host, never the internal credential-store id (#9)."""
    if name == "server" or name.startswith("server:"):
        what = f"NetConverter API key for {label}" if label else "NetConverter API key"
    else:
        what = f"{name} API key"
    return f"{what} (hidden; kept in memory for this run only): "


def _stored(name: str) -> str:
    """The first stored value for ``name``; a file that cannot be opened is reported, not fatal."""
    from .credential_file import FileStoreError

    for store in _read_stores():
        try:
            value = store.get(name)
        except KeyringLocked:
            raise
        except FileStoreError as exc:
            _warn(str(exc))
            continue
        except Exception:
            continue
        if value:
            return value
    return ""


def get_secret(name: str, *, prompt: bool = True, label: str | None = None) -> str:
    value = os.environ.get(
        "NETCONVERTER_API_KEY"
        if name == "server" or name.startswith("server:")
        else f"NETCONVERTER_{name.upper()}_API_KEY"
    )
    if value:
        return value
    value = _stored(name)
    if value:
        return value
    if not prompt:
        return ""
    return getpass.getpass(_prompt_text(name, label)).strip()


def save_secret(name: str, value: str) -> bool:
    from .credential_file import FileStoreError

    store = _write_store()
    if store is None:
        return False
    try:
        store.set(name, value)
        return True
    except KeyringLocked:
        raise
    except FileStoreError as exc:
        _warn(str(exc))
        return False
    except Exception:
        return False


def load_secret(name: str) -> str:
    """Read a stored secret without prompting and without environment overrides."""
    return _stored(name)


def delete_secret(name: str) -> bool:
    """Remove a stored secret from every store; True when nothing remains stored under ``name``."""
    from .credential_file import FileStoreError

    stores = _read_stores()
    if not stores:
        return False
    ok = True
    for store in stores:
        try:
            store.delete(name)
        except KeyringLocked:
            raise
        except FileStoreError as exc:
            _warn(str(exc))
            ok = False
        except Exception:
            ok = False
    return ok
