"""Frozen #78: the NX-OS switch target reaches the server; a target-only code is never a source.

Synthetic bytes and a mock server: this proves the client boundary, not live admission.
"""
from contextlib import closing

import pytest

from netconverter_cli import cli
from netconverter_cli.api import APIError
from netconverter_cli.backend import submit_external
from netconverter_cli.catalog import (Catalog, device_type_of, normalize_vendor,
                                      submission_vendors)
from tests.test_issue_2195_file_transport import UploadServer, client
from tests.test_issue_63_64_submission_boundary import launch

NXOS = "cisco_nxos_switch"
CAPABILITIES = {
    "vendors": [
        {"code": "juniper_set_switch", "name": "Juniper (Set)", "device_type": "switch",
         "roles": ["source", "target"]},
        {"code": NXOS, "name": "Cisco NX-OS", "device_type": "switch", "roles": ["target"],
         "maturity": "preview"},
    ],
    "paths": [{"source": "juniper_set_switch", "target": NXOS}],
}


def test_nxos_is_an_explicit_switch_identity():
    assert normalize_vendor(NXOS) == NXOS
    assert device_type_of(NXOS) == "switch"
    assert submission_vendors("juniper_set_switch", NXOS) == ("juniper_set_switch", NXOS)
    assert submission_vendors("juniper_junos_switch", NXOS) == ("juniper_junos_switch", NXOS)


@pytest.mark.parametrize("source", ["juniper_set_switch", "juniper_junos_switch"])
def test_bridge_submits_the_nxos_pair(tmp_path, monkeypatch, source):
    content = b"set system host-name synthetic-78\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": source, "target_vendor": NXOS, "job_type": "prescan"})
    assert not result["isError"], result
    assert confirmations[0]["target_vendor"] == NXOS
    assert server.jobs()[0]["source_vendor"] == source
    assert server.jobs()[0]["target_vendor"] == NXOS
    assert server.jobs()[0]["technology"] == "switch"


@pytest.mark.parametrize("target", [None, "cisco_ios_xe_switch", NXOS])
def test_target_only_code_is_refused_as_a_source_before_side_effects(tmp_path, monkeypatch, target):
    content = b"hostname synthetic-78-refusal\n"
    (tmp_path / "source.cfg").write_bytes(content)
    server = UploadServer(content)
    result, confirmations = launch(tmp_path, monkeypatch, server, {
        "path": "source.cfg", "source_vendor": NXOS, "target_vendor": target,
        "job_type": "prescan" if target else "validate"})
    assert result["isError"] and "target only" in str(result)
    assert not confirmations and not server.requests
    assert not (tmp_path / ".netconverter/submissions").exists()
    with closing(client(server)) as connection, pytest.raises(APIError):
        submit_external(connection, content, NXOS, target, "prescan", {}, "synthetic-key")
    assert not server.writes()


@pytest.mark.parametrize("source,target", [
    ("cisco_nxos", "cisco_ios_xe_switch"), ("juniper_set_switch", "cisco_nxos"),
    ("juniper_set", NXOS), ("juniper_junos", NXOS), ("cisco_asa", NXOS),
    ("juniper_set_router", NXOS),
])
def test_bare_ambiguous_and_cross_device_codes_stay_refused(source, target):
    with pytest.raises(ValueError):
        submission_vendors(source, target)


def test_catalog_and_cli_never_offer_the_target_only_code_as_a_source():
    catalog = Catalog.from_external(CAPABILITIES)
    assert catalog.targets("juniper_set_switch") == [NXOS]
    for job_type in ("convert", "validate", "optimize", "prescan"):
        assert NXOS not in catalog.sources(job_type)
    cli.check_source_vendor("juniper_set_switch", catalog)
    with pytest.raises(cli.CommandError) as refused:
        cli.check_source_vendor(NXOS, catalog)
    assert "juniper_set_switch" in str(refused.value)
