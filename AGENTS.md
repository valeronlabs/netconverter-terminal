# NetConverter Terminals — canonical agent rules

This private repository owns the independently packaged Python terminal client. Its public
copy is `valeronlabs/netconverter-terminal` (Mac checkout `~/gitsync/netconverter_terminals-public`),
published one way from here; never edit the public copy directly or sync it back.
The server, conversion engine, tenant enrollment and quotas remain in
`devnexthop/aws-netconverter.ai`. Do not copy appliance or server code here.

Read shared `~/gitsync/netconverter-project-merger/AGENTS.md`, `PROJECT.md`,
`STATUS.md`, and published `docs/ai-coordination/NOW.md`. Use session-start
once and claim the exact checkout/branch before writes. Use the shared
verification operating policy for releases. Shared runtime deployments serialize.

Canonical checkout: `~/gitsync/netconverter_terminals`; isolated worktrees belong
under `~/DevWork-Local/worktrees`. Never put Git trees in cloud-synced folders.
`AGENTS.md` is canonical; other tool entry files point here.

## Development and verification

Python 3.12+. `uv sync --group dev`, `uv run pytest tests -q`, and
`uv run python -m build --wheel`. The package exposes `netconverter`.
Exercise Textual interactions with its test harness; use synthetic fixtures for
privacy and server integration proof. Do not claim mocked tests prove live servers.

## Product boundaries

The full API profile serves the firewall, router and switch migration, validation
and optimization paths advertised by the authenticated server capabilities.
Preserve explicit device identities, formats and unsupported-path refusals.
The legacy restricted Quick pilot remains ASA to Palo Alto SET/XML/Panorama
for migration, with its own ASA/Palo Alto analysis and smaller limits.
Raw configurations travel directly between client and NetConverter; MCP receives
bounded evidence and decision views. Full YAML/NCIR exports are explicit file
transfers whose model responses contain verified receipts, not document bodies.
No shell/model filesystem tools, arbitrary URLs, automatic hosted fallback, or
model-weight downloads. Credentials belong in the OS credential store, memory, or (headless,
owner decision 2026-10-22) the passphrase-encrypted file store; never plaintext on disk.
Preserve source/output files and verify artifact hashes before atomic writes.

Production endpoint: `https://api.netconverter.ai/external/v1`. A dedicated
terminal_quick key is required for the Quick pilot; the full profile uses its
supported Clerk sign-in or full-API credential. Never reuse a staging key for production.
Record actual production job IDs and artifact hashes before claiming acceptance.
Public distribution and Windows acceptance remain separate release steps.
