"""Explicit YAML/NCIR downloads stay off the model channel and fail closed."""
import hashlib
import json

import httpx
import pytest

from netconverter_cli.api import APIError, ExternalClient, StaticCredential
from netconverter_cli.mcp_server import Bridge
from tests.test_mcp import SERVER

CONTENT = b"interfaces:\n  SYNTHETIC_PRIVATE_INTERFACE: {description: private-example}\n"
HASH = hashlib.sha256(CONTENT).hexdigest()
DOC_HASH = "d" * 64


class ExportServer:
    def __init__(self, *, content=CONTENT, headers=None, status=200):
        self.content, self.status = content, status
        self.headers = {"X-Content-SHA256": HASH, "X-Document-SHA256": DOC_HASH,
                        "X-Document-Revision": "2", "X-Export-Provenance": "prescan-revision",
                        "Content-Type": "application/yaml"} if headers is None else headers
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        assert request.headers["Authorization"] == "Bearer nck_synthetic"
        return httpx.Response(self.status, content=self.content, headers=self.headers)


def client(server):
    return ExternalClient("nck_synthetic", SERVER, transport=httpx.MockTransport(server))


def test_exact_revision_download_returns_only_file_receipt_to_model(tmp_path):
    server = ExportServer()
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(server), level="masked")
    bridge._profile = ("external", frozenset({"prescan"}))
    result = bridge.call("download", {"job_id": "psc_synthetic", "export_kind": "decision-yaml",
                        "revision": 2, "expected_document_sha256": DOC_HASH})
    assert not result["isError"], result
    file = result["structuredContent"]["files"][0]
    assert (tmp_path / file["name"]).read_bytes() == CONTENT
    assert file["sha256"] == HASH
    assert "SYNTHETIC_PRIVATE_INTERFACE" not in json.dumps(result)
    request = server.requests[0]
    assert request.url.path.endswith("/jobs/psc_synthetic/exports/decision-yaml")
    assert dict(request.url.params) == {"revision": "2", "expected_document_sha256": DOC_HASH}


def test_ncir_source_provenance_and_original_hash_are_required():
    headers = {"X-Content-SHA256": HASH, "X-Artifact-SHA256": "a" * 64,
               "X-Export-Provenance": "source-stage-2.5", "Content-Type": "application/json"}
    with_client = client(ExportServer(headers=headers))
    try:
        content, metadata = with_client.document_export("tra_synthetic", "source-ncir")
        assert content == CONTENT
        assert metadata["artifact_sha256"] == "a" * 64
    finally:
        with_client.close()


@pytest.mark.parametrize("headers,code", [
    ({}, "artifact_checksum_mismatch"),
    ({"X-Content-SHA256": "0" * 64}, "artifact_checksum_mismatch"),
    ({"X-Content-SHA256": HASH, "X-Document-SHA256": DOC_HASH,
      "X-Document-Revision": "3", "X-Export-Provenance": "prescan-revision",
      "Content-Type": "application/yaml"}, "export_revision_mismatch"),
    ({"X-Content-SHA256": HASH, "X-Document-SHA256": "a" * 64,
      "X-Document-Revision": "2", "X-Export-Provenance": "prescan-revision",
      "Content-Type": "application/yaml"}, "invalid_export_provenance"),
])
def test_missing_hash_tampering_or_substituted_revision_is_refused(headers, code):
    c = client(ExportServer(headers=headers))
    try:
        with pytest.raises(APIError) as exc:
            c.document_export("psc_synthetic", "decision-yaml", revision=2,
                              expected_document_sha256=DOC_HASH)
        assert exc.value.code == code
    finally:
        c.close()


@pytest.mark.parametrize("status", [302, 403, 404, 409, 500])
def test_no_redirect_or_historical_fallback_on_export_failure(status):
    server = ExportServer(status=status, content=b'{"detail":{"code":"artifact_unavailable"}}',
                          headers={"Location": "https://untrusted.example/private"})
    c = client(server)
    try:
        with pytest.raises(APIError) as exc:
            c.document_export("psc_synthetic", "decision-yaml")
        assert exc.value.status == status
        assert len(server.requests) == 1
    finally:
        c.close()


def test_oversized_stream_stops_before_write(tmp_path):
    server = ExportServer()
    c = client(server)
    try:
        with pytest.raises(APIError) as exc:
            c.document_export("psc_synthetic", "decision-yaml", max_bytes=8)
        assert exc.value.code == "artifact_too_large"
        assert not list(tmp_path.iterdir())
    finally:
        c.close()


class InterruptedExport(httpx.SyncByteStream):
    def __iter__(self):
        yield CONTENT[:16]
        raise httpx.ReadError("SYNTHETIC_PRIVATE_UPSTREAM_ERROR")


def test_interrupted_stream_preserves_existing_files_and_returns_no_content(tmp_path):
    original = tmp_path / "existing.yaml"
    original.write_bytes(b"existing customer artifact")

    def upstream(request):
        return httpx.Response(200, headers=ExportServer().headers, stream=InterruptedExport())

    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(upstream))
    bridge._profile = ("external", frozenset({"prescan"}))
    result = bridge.call("download", {"job_id": "psc_synthetic", "export_kind": "decision-yaml"})
    assert result["isError"]
    assert "connection_failed" in json.dumps(result)
    assert "SYNTHETIC_PRIVATE" not in json.dumps(result)
    assert original.read_bytes() == b"existing customer artifact"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["existing.yaml"]


def test_stream_without_content_length_is_bounded_and_closed():
    class Chunks(httpx.SyncByteStream):
        read_count = 0
        closed = False

        def __iter__(self):
            for _ in range(20):
                self.read_count += 1
                yield b"x" * 65536

        def close(self):
            self.closed = True

    stream = Chunks()
    c = client(lambda request: httpx.Response(200, headers=ExportServer().headers, stream=stream))
    try:
        with pytest.raises(APIError) as exc:
            c.document_export("psc_synthetic", "decision-yaml", max_bytes=65536)
        assert exc.value.code == "artifact_too_large"
        assert stream.read_count == 2
        assert stream.closed
    finally:
        c.close()


@pytest.mark.parametrize("args", [{"export_kind": "../../source"},
    {"export_kind": "source-ncir", "revision": 0},
    {"export_kind": "decision-yaml", "revision": True},
    {"export_kind": "decision-yaml", "expected_document_sha256": "bad"},
    {"export_kind": "decision-yaml", "diagram": {}}])
def test_invalid_or_mixed_export_requests_make_no_network_call(tmp_path, args):
    server = ExportServer()
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(server))
    result = bridge.call("download", {"job_id": "psc_synthetic", **args})
    assert result["isError"]
    assert not server.requests






def test_deep_error_json_returns_structured_refusal_without_content(tmp_path):
    content = b'{"detail":' + b'[' * 1500 + b'"SYNTHETIC_PRIVATE_ERROR"' + b']' * 1500 + b'}'
    assert len(content) < 8192
    server = ExportServer(status=500, content=content, headers={})
    bridge = Bridge(tmp_path, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(server))
    bridge._profile = ("external", frozenset({"prescan"}))
    result = bridge.call("download", {"job_id": "psc_synthetic", "export_kind": "decision-yaml"})
    assert result["isError"]
    assert "SYNTHETIC_PRIVATE_ERROR" not in json.dumps(result)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("status", [200, 401, 500])
def test_compressed_response_refuses_before_unbounded_decompression(monkeypatch, status):
    import gzip
    from httpx._decoders import GZipDecoder
    decoded = []
    original = GZipDecoder.decode

    def track(self, data):
        result = original(self, data)
        decoded.append(len(result))
        return result

    monkeypatch.setattr(GZipDecoder, "decode", track)
    compressed = gzip.compress(b"x" * 1_000_000)

    class Compressed(httpx.SyncByteStream):
        def __iter__(self):
            yield compressed

    def handler(request):
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(status, headers={**ExportServer().headers,
            "Content-Encoding": "gzip", "Content-Length": str(len(compressed))}, stream=Compressed())

    c = client(handler)
    try:
        with pytest.raises(APIError):
            c.document_export("psc_synthetic", "decision-yaml", max_bytes=1024)
        assert decoded == [], "Encoded response expanded before the export byte limit could apply"
    finally:
        c.close()


@pytest.mark.parametrize("final_status", [200, 401])
def test_bounded_auth_refresh_retries_exact_request_at_most_once(final_status):
    class Credential:
        refresh_count = 0

        def token(self):
            return "nck_synthetic_" + str(self.refresh_count)

        def refresh(self):
            self.refresh_count += 1
            return True

    credential = Credential()
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer nck_synthetic_" + str(len(requests) - 1)
        assert request.headers["Accept-Encoding"] == "identity"
        if len(requests) == 1 or final_status == 401:
            return httpx.Response(401, json={"detail": {"code": "unauthorized"}})
        return httpx.Response(200, content=CONTENT, headers=ExportServer().headers)

    c = ExternalClient(credential, SERVER, transport=httpx.MockTransport(handler))
    try:
        if final_status == 200:
            content, _ = c.document_export("psc_synthetic", "decision-yaml", revision=2,
                                            expected_document_sha256=DOC_HASH)
            assert content == CONTENT
        else:
            with pytest.raises(APIError) as error:
                c.document_export("psc_synthetic", "decision-yaml", revision=2,
                                  expected_document_sha256=DOC_HASH)
            assert error.value.status == 401
        assert len(requests) == 2 and credential.refresh_count == 1
        assert requests[0].url == requests[1].url
        assert requests[0].headers["X-Request-ID"] == requests[1].headers["X-Request-ID"]
    finally:
        c.close()


def test_auth_refresh_does_not_drain_unbounded_error_body():
    class Credential:
        def token(self):
            return "nck_synthetic"

        def refresh(self):
            return True

    class ErrorBody(httpx.SyncByteStream):
        chunks_read = 0

        def __iter__(self):
            for _ in range(100):
                self.chunks_read += 1
                yield b"x" * 8192

    stream = ErrorBody()
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(401, stream=stream)
        return ExportServer()(request)

    c = ExternalClient(Credential(), SERVER, transport=httpx.MockTransport(handler))
    try:
        try:
            c.document_export("psc_synthetic", "decision-yaml")
        except APIError:
            pass
        assert stream.chunks_read <= 2, "Automatic auth refresh drained the unbounded 401 body"
    finally:
        c.close()


def test_export_destination_swap_during_request_never_writes_outside_workspace(tmp_path):
    root, outside = tmp_path / "workspace", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    destination = root / "exports"
    destination.mkdir()
    server = ExportServer()

    def handler(request):
        destination.rename(root / "original-exports")
        destination.symlink_to(outside, target_is_directory=True)
        return server(request)

    bridge = Bridge(root, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(handler))
    bridge._profile = ("external", frozenset({"prescan"}))
    bridge.call("download", {"job_id": "psc_synthetic", "dest_dir": "exports",
                             "export_kind": "decision-yaml"})
    assert list(outside.iterdir()) == [], "Export followed a replaced destination outside the workspace"

def test_export_receipt_does_not_follow_replaced_published_file(tmp_path, monkeypatch):
    from netconverter_cli.workspace import Workspace
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside-private-file"
    outside.write_bytes(b"SYNTHETIC_UNRELATED_PRIVATE_FILE" * 1000)
    original_save = Workspace.save_artifact

    def replace_after_save(self, *args, **kwargs):
        path = original_save(self, *args, **kwargs)
        path.unlink()
        path.symlink_to(outside)
        return path

    monkeypatch.setattr(Workspace, "save_artifact", replace_after_save)
    bridge = Bridge(root, SERVER, StaticCredential("nck_synthetic"),
                    transport=httpx.MockTransport(ExportServer()))
    bridge._profile = ("external", frozenset({"prescan"}))
    result = bridge.call("download", {"job_id": "psc_synthetic", "export_kind": "decision-yaml"})
    if not result["isError"]:
        receipt = result["structuredContent"]["files"][0]
        assert receipt["sha256"] == HASH and receipt["bytes"] == len(CONTENT), (
            "Export receipt read an unrelated replacement through an unbounded pathname read")
