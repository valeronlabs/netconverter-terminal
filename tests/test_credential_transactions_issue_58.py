"""Synthetic real-store transactions: no OS credentials or real OAuth traffic."""
import json
import multiprocessing
import threading
import time

import httpx
import pytest

from netconverter_cli import clerk, credential_lock, credentials
from netconverter_cli.clerk import ClerkSession, TokenStore
from netconverter_cli.credentials import CredentialStoreError, KeyringLocked
from tests.test_clerk import oauth_server, vault  # noqa: F401
from tests.test_clerk_recovery_issue_11 import tokens


@pytest.fixture(autouse=True)
def reset_timeout(monkeypatch):
    monkeypatch.setattr(credentials, "_locked_at", None)


@pytest.mark.parametrize("operation", ["failed_refresh", "successful_refresh", "logout"])
def test_real_store_new_login_wins_over_old_network_result(vault, monkeypatch, operation):
    store = TokenStore()
    store.save(tokens("old", expired=operation != "logout"))
    replacement = tokens("new-login")

    def during_oauth(request):
        # A second instance writes while OAuth is in flight. Holding the
        # credential-store lock across HTTP would deadlock this actual save.
        monkeypatch.setattr(clerk, "browser_login", lambda *args, **kw: replacement)
        login_transport, _ = oauth_server()
        clerk.login(store=TokenStore(), transport=login_transport)
        if operation == "failed_refresh":
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "synthetic-stale-success",
                                      "refresh_token": "synthetic-stale-refresh", "expires_in": 3600})

    transport, _ = oauth_server(during_oauth)
    original = transport.handler
    if operation == "logout":
        transport = httpx.MockTransport(lambda req: during_oauth(req) if req.url.path.endswith("/revoke") else original(req))
    session = ClerkSession(store, transport=transport)
    generation = session.session_generation()
    if operation == "logout":
        assert session.revoke_and_clear()
    else:
        assert session.token() == replacement.access_token
    assert store.load().access_token == replacement.access_token
    assert session.token() == replacement.access_token
    assert session.session_generation() > generation


def test_unexpired_sessions_observe_relogin_and_same_token_generation(vault):
    first = TokenStore()
    value = tokens("same-value")
    first.save(value)
    one, two = ClerkSession(first), ClerkSession(TokenStore())
    before = one.session_generation(), two.session_generation()
    TokenStore().save(value)  # deliberate login is a new generation, even with identical token bytes
    assert one.token() == two.token() == value.access_token
    assert one.session_generation() > before[0] and two.session_generation() > before[1]
    assert two.revoke_and_clear()
    with pytest.raises(clerk.ClerkError):
        one.token()


@pytest.mark.parametrize("operation", ["compare_save", "compare_delete"])
def test_comparison_window_blocks_other_login_until_mutation_finishes(vault, monkeypatch, operation):
    store = TokenStore()
    store.save(tokens("old"))
    captured = store.load()
    entered, proceed, login_done = threading.Event(), threading.Event(), threading.Event()
    read = vault.get_password
    armed = True

    def hold_read(service, name):
        nonlocal armed
        value = read(service, name)
        if armed and name.endswith(":access"):
            armed = False
            entered.set()
            assert proceed.wait(3)
        return value

    monkeypatch.setattr(vault, "get_password", hold_read)
    outputs = []
    def mutate():
        call = getattr(store, operation)
        outputs.append(call(captured, tokens("old-refresh")) if operation == "compare_save" else call(captured))
    actor = threading.Thread(target=mutate)
    actor.start()
    assert entered.wait(2)
    writer = threading.Thread(target=lambda: (TokenStore().save(tokens("new-login")), login_done.set()))
    writer.start()
    assert not login_done.wait(0.05)
    proceed.set()
    actor.join(3); writer.join(3)
    assert not actor.is_alive() and not writer.is_alive() and outputs
    assert store.load().access_token == "synthetic-access-new-login"


@pytest.mark.parametrize("operation", ["save", "delete"])
def test_late_keyring_mutation_retains_lock_after_caller_timeout(vault, monkeypatch, operation):
    store = TokenStore()
    store.save(tokens("old"))
    previous = store.load()
    entered, release, writer_done = threading.Event(), threading.Event(), threading.Event()
    setter, deleter = vault.set_password, vault.delete_password

    def slow_set(service, name, value):
        if operation == "save" and name.endswith(":refresh") and value == "synthetic-refresh-slow":
            entered.set()
            assert release.wait(4)
        setter(service, name, value)

    def slow_delete(service, name):
        if operation == "delete" and name.endswith(":access") and not entered.is_set():
            entered.set()
            assert release.wait(4)
        deleter(service, name)

    monkeypatch.setattr(vault, "set_password", slow_set)
    monkeypatch.setattr(vault, "delete_password", slow_delete)
    monkeypatch.setattr(credentials, "KEYRING_TIMEOUT_S", 0.1)
    with pytest.raises(KeyringLocked):
        store.save(tokens("slow")) if operation == "save" else store.compare_delete(previous)
    assert entered.is_set()
    # A separate client would not share this process's timeout cooldown. Clear
    # that optimization to prove the OS lock itself protects the late mutation.
    monkeypatch.setattr(credentials, "_locked_at", None)
    monkeypatch.setattr(credentials, "KEYRING_TIMEOUT_S", 3.0)
    writer = threading.Thread(target=lambda: (TokenStore().save(tokens("new-login")), writer_done.set()))
    writer.start()
    try:
        assert not writer_done.wait(0.1)
    finally:
        release.set()
        writer.join(4)
    assert writer_done.is_set()
    assert store.load().access_token == "synthetic-access-new-login"


def test_scope_and_incomplete_record_fail_closed_without_token_messages(vault):
    first = TokenStore(issuer="https://issuer-one.test", client_id="one")
    second = TokenStore(issuer="https://issuer-one.test", client_id="two")
    third = TokenStore(issuer="https://issuer-two.test", client_id="one")
    for store in (first, second, third):
        store.save(tokens(store.account))
    assert first.compare_delete(second.load())[0] is False
    assert first.load() and second.load() and third.load()
    vault.items[(credentials.SERVICE, first.account + ":meta")] = json.dumps({"state": "updating"})
    with pytest.raises(CredentialStoreError) as error:
        first.load()
    assert "synthetic-access" not in str(error.value)


def test_legacy_identical_token_bytes_do_not_cross_client_scope(vault):
    first, second = TokenStore(client_id="one"), TokenStore(client_id="two")
    for store in (first, second):
        store.save(tokens("same-legacy-value"))
        vault.items[(credentials.SERVICE, store.account + ":meta")] = "{}"
    assert first.compare_delete(second.load())[0] is False
    assert first.load() and second.load()


def test_store_failure_does_not_return_cached_credentials(vault, monkeypatch):
    store = TokenStore()
    store.save(tokens("cached"))
    session = ClerkSession(store)
    def unavailable(*args):
        raise RuntimeError("SYNTHETIC_PRIVATE_BACKEND_ERROR")
    monkeypatch.setattr(vault, "get_password", unavailable)
    with pytest.raises(clerk.ClerkError) as error:
        session.token()
    assert "PRIVATE_BACKEND" not in str(error.value)


@pytest.mark.parametrize("rollback_works", [True, False])
def test_partial_keyring_write_restores_old_record_or_refuses_incomplete_pair(vault, monkeypatch, rollback_works, capsys):
    store = TokenStore()
    store.save(tokens("old"))
    original = vault.set_password
    def failed(service, name, value):
        if name.endswith(":access") and (value == "synthetic-access-new" or not rollback_works):
            raise RuntimeError("SYNTHETIC_PRIVATE_BACKEND_ERROR")
        original(service, name, value)
    monkeypatch.setattr(vault, "set_password", failed)
    if rollback_works:
        assert store.save(tokens("new")) is False
        assert store.load().access_token == "synthetic-access-old"
        assert store.load().refresh_token == "synthetic-refresh-old"
    else:
        with pytest.raises(CredentialStoreError):
            store.save(tokens("new"))
        with pytest.raises(CredentialStoreError):
            store.load()
    captured = capsys.readouterr()
    assert "SYNTHETIC_PRIVATE" not in captured.out + captured.err


def _process_compare(path, operation, ready, proceed, result):
    """Spawn-safe actual encrypted store; never an inherited Python mutex."""
    import os
    from netconverter_cli import credential_file
    os.environ["NETCONVERTER_CREDENTIAL_STORE"] = "file"
    os.environ["NETCONVERTER_CREDENTIAL_FILE"] = path
    os.environ["NETCONVERTER_CREDENTIAL_PASSPHRASE"] = "synthetic-only-passphrase-issue58"
    credential_file.SCRYPT_N = 4096
    store = TokenStore()
    old = store.load()
    ready.set()
    if not proceed.wait(5):
        result.put("timeout")
        return
    changed, current = (store.compare_delete(old) if operation == "delete"
                        else store.compare_save(old, tokens("stale-refresh")))
    result.put((changed, current.access_token == "synthetic-access-new-login"))


@pytest.mark.parametrize("operation", ["save", "delete"])
def test_spawned_process_cannot_overwrite_or_delete_new_file_login(tmp_path, monkeypatch, operation):
    from netconverter_cli import credential_file
    path = tmp_path / "credentials.enc"
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "file")
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(path))
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_PASSPHRASE", "synthetic-only-passphrase-issue58")
    monkeypatch.setattr(credential_file, "SCRYPT_N", 4096)
    store = TokenStore()
    store.save(tokens("old"))
    context = multiprocessing.get_context("spawn")
    ready, proceed, result = context.Event(), context.Event(), context.Queue()
    process = context.Process(target=_process_compare, args=(str(path), operation, ready, proceed, result))
    process.start()
    try:
        assert ready.wait(5)
        assert TokenStore().save(tokens("new-login"))
        proceed.set()
        assert result.get(timeout=5) == (False, True)
        process.join(5)
        assert process.exitcode == 0
        assert store.load().access_token == "synthetic-access-new-login"
        assert b"synthetic-access" not in path.read_bytes()
    finally:
        if process.is_alive():
            process.terminate(); process.join(2)


def _process_lock(path, ready, proceed):
    from pathlib import Path
    with credential_lock.locked(Path(path)):
        ready.set()
        proceed.wait(5)


def test_actual_os_lock_blocks_a_distinct_process_and_fails_closed(tmp_path):
    path = tmp_path / "credential.lock"
    context = multiprocessing.get_context("spawn")
    ready, proceed = context.Event(), context.Event()
    process = context.Process(target=_process_lock, args=(str(path), ready, proceed))
    process.start()
    try:
        assert ready.wait(5)
        with pytest.raises(credential_lock.CredentialLockError):
            with credential_lock.locked(path, timeout=0.05):
                pytest.fail("credential lock was not exclusive")
        proceed.set()
        process.join(5)
        assert process.exitcode == 0
        with credential_lock.locked(path):
            assert path.stat().st_size == 0
    finally:
        if process.is_alive():
            process.terminate(); process.join(2)


def test_posix_lock_rejects_replaceable_metadata_but_accepts_readable_parent(tmp_path):
    import os
    if os.name != "posix":
        pytest.skip("POSIX permissions; native Windows ACL/sharing tested above")
    parent = tmp_path / "config"
    parent.mkdir(mode=0o755)
    lock = parent / "credential.lock"
    with credential_lock.locked(lock):
        assert lock.stat().st_mode & 0o777 == 0o600
    parent.chmod(0o777)
    try:
        with pytest.raises(credential_lock.CredentialLockError):
            with credential_lock.locked(lock):
                pytest.fail("a different user could replace this lock inode")
    finally:
        parent.chmod(0o700)


def _process_file_writer(path, client_id, held, proceed, result):
    import os
    from netconverter_cli import credential_file
    os.environ["NETCONVERTER_CREDENTIAL_STORE"] = "file"
    os.environ["NETCONVERTER_CREDENTIAL_FILE"] = path
    os.environ["NETCONVERTER_CREDENTIAL_PASSPHRASE"] = "synthetic-only-passphrase-issue58"
    credential_file.SCRYPT_N = 4096
    original = credential_file.EncryptedFileStore._write
    pause = client_id == "first"
    def write(store, document, entries):
        nonlocal pause
        if pause:
            pause = False
            held.set()
            if not proceed.wait(5):
                raise AssertionError("parent did not release synthetic file write")
        return original(store, document, entries)
    credential_file.EncryptedFileStore._write = write
    result.put((client_id, TokenStore(client_id=client_id).save(tokens(client_id))))


def test_encrypted_file_serializes_different_accounts_on_actual_os(tmp_path, monkeypatch):
    import queue
    from netconverter_cli import credential_file
    path = tmp_path / "credentials.enc"
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "file")
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(path))
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_PASSPHRASE", "synthetic-only-passphrase-issue58")
    monkeypatch.setattr(credential_file, "SCRYPT_N", 4096)
    # Explicit encrypted stores must not inherit an unrelated OS-keyring cooldown.
    monkeypatch.setattr(credentials, "_locked_at", time.monotonic())
    assert TokenStore(client_id="seed").save(tokens("seed"))
    context = multiprocessing.get_context("spawn")
    held, proceed, result = context.Event(), context.Event(), context.Queue()
    first = context.Process(target=_process_file_writer, args=(str(path), "first", held, proceed, result))
    second = context.Process(target=_process_file_writer, args=(str(path), "second", held, proceed, result))
    first.start()
    try:
        assert held.wait(5)
        second.start()
        with pytest.raises(queue.Empty):
            result.get(timeout=0.2)
        proceed.set()
        assert {result.get(timeout=5), result.get(timeout=5)} == {("first", True), ("second", True)}
        first.join(5); second.join(5)
        assert first.exitcode == second.exitcode == 0
        for name in ("seed", "first", "second"):
            assert TokenStore(client_id=name).load().access_token == "synthetic-access-" + name
    finally:
        for process in (first, second):
            if process.pid and process.is_alive():
                process.terminate(); process.join(2)


def test_interactive_file_unlock_occurs_before_transaction_worker(tmp_path, monkeypatch):
    from netconverter_cli import credential_file
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "file")
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(tmp_path / "interactive.enc"))
    monkeypatch.delenv("NETCONVERTER_CREDENTIAL_PASSPHRASE", raising=False)
    monkeypatch.setattr(credential_file, "SCRYPT_N", 4096)
    monkeypatch.setattr(credential_file, "can_prompt", lambda: True)
    owner = threading.current_thread()
    prompts = []
    def password(prompt):
        assert threading.current_thread() is owner
        assert not getattr(credentials._transaction, "active", False)
        prompts.append(prompt)
        return "synthetic-only-passphrase-issue58"
    monkeypatch.setattr(credential_file.getpass, "getpass", password)
    assert TokenStore().save(tokens("interactive"))
    assert len(prompts) == 2
    credential_file.forget_keys()
    assert TokenStore().load().access_token == "synthetic-access-interactive"
    assert len(prompts) == 3


def test_logout_never_adopts_or_erases_an_unrelated_fallback_store(vault, tmp_path, monkeypatch):
    from netconverter_cli import credential_file
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "file")
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(tmp_path / "fallback.enc"))
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_PASSPHRASE", "synthetic-only-passphrase-issue58")
    monkeypatch.setattr(credential_file, "SCRYPT_N", 4096)
    assert TokenStore().save(tokens("unrelated-file-login"))
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "keyring")
    assert TokenStore().save(tokens("active-keyring-login"))
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "auto")
    transport, _ = oauth_server()
    session = ClerkSession(TokenStore(), transport=transport)
    assert session.token() == "synthetic-access-active-keyring-login"
    assert session.revoke_and_clear()
    with pytest.raises(clerk.ClerkError):
        session.token()
    assert TokenStore().load().access_token == "synthetic-access-unrelated-file-login"
    # The bound session still recovers a new login in its original physical store.
    assert TokenStore().save(tokens("replacement-keyring-login"))
    assert session.token() == "synthetic-access-replacement-keyring-login"


def test_interactive_preflight_refuses_private_backend_error(vault, tmp_path, monkeypatch):
    from netconverter_cli import credential_file
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "auto")
    path = tmp_path / "present.enc"
    path.touch()
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(path))
    monkeypatch.setattr(credential_file, "can_prompt", lambda: True)
    def fail(*args):
        raise RuntimeError("synthetic-private-keyring-detail")
    monkeypatch.setattr(vault, "get_password", fail)
    with pytest.raises(CredentialStoreError) as error:
        TokenStore().load()
    assert "synthetic-private" not in str(error.value)


@pytest.mark.skipif(__import__("os").name != "posix", reason="existing POSIX nofollow contract")
def test_encrypted_store_final_symlink_remains_refused(tmp_path, monkeypatch):
    from netconverter_cli import credential_file
    target, alias = tmp_path / "real.enc", tmp_path / "alias.enc"
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_STORE", "file")
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(target))
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_PASSPHRASE", "synthetic-only-passphrase-issue58")
    monkeypatch.setattr(credential_file, "SCRYPT_N", 4096)
    assert TokenStore().save(tokens("original"))
    original = target.read_bytes()
    alias.symlink_to(target)
    monkeypatch.setenv("NETCONVERTER_CREDENTIAL_FILE", str(alias))
    with pytest.raises(CredentialStoreError):
        TokenStore().save(tokens("replacement"))
    assert target.read_bytes() == original and alias.is_symlink()


def test_cli_failed_login_save_reports_auth_error_without_traceback(vault, tmp_path, monkeypatch, capsys):
    from netconverter_cli import cli
    assert TokenStore().save(tokens("old"))
    setter = vault.set_password

    def fail_access(service, name, value):
        if name.endswith(":access"):
            raise RuntimeError("SYNTHETIC_PRIVATE_BACKEND_ERROR")
        return setter(service, name, value)

    monkeypatch.setattr(vault, "set_password", fail_access)
    monkeypatch.setattr(clerk, "browser_login", lambda *args, **kwargs: tokens("new"))
    transport, _ = oauth_server()
    login = clerk.login
    monkeypatch.setattr(clerk, "login", lambda **kwargs: login(transport=transport, **kwargs))
    with pytest.raises(SystemExit) as error:
        cli.main(["--workspace", str(tmp_path), "login", "--clerk"])
    assert error.value.code != 0
    output = capsys.readouterr()
    assert not output.out
    assert "credential store" in output.err
    assert "SYNTHETIC_PRIVATE" not in output.err


@pytest.mark.parametrize("command", ["whoami", "logout"])
def test_cli_incomplete_initial_signin_reports_auth_error(vault, tmp_path, capsys, command):
    from netconverter_cli import cli
    from netconverter_cli.errors import EXIT_AUTH
    store = TokenStore()
    assert store.save(tokens("incomplete"))
    vault.items[(credentials.SERVICE, store.account + ":meta")] = '{"state":"updating"}'
    with pytest.raises(SystemExit) as error:
        cli.main(["--workspace", str(tmp_path), command])
    assert error.value.code == EXIT_AUTH
    output = capsys.readouterr()
    assert not output.out
    assert "credential store" in output.err
    assert "synthetic-access" not in output.err


@pytest.mark.parametrize("auth", ["auto", "clerk"])
def test_mcp_incomplete_initial_signin_never_falls_back_to_api_key(vault, monkeypatch, auth):
    from netconverter_cli import cli
    store = TokenStore()
    assert store.save(tokens("incomplete"))
    vault.items[(credentials.SERVICE, store.account + ":meta")] = '{"state":"updating"}'
    monkeypatch.setenv("NETCONVERTER_API_KEY", "SYNTHETIC_OTHER_PRINCIPAL")
    rest, remote, source, notes = cli.choose_mcp_credential(
        auth, "https://api.netconverter.ai/external/v1", "https://api.netconverter.ai/mcp/v1/")
    assert rest is remote is None and source == "none"
    assert "credential store" in " ".join(notes)
    assert "SYNTHETIC_OTHER_PRINCIPAL" not in " ".join(notes)
