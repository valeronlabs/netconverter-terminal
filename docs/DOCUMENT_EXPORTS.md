# Explicit YAML and NCIR downloads

Use the standard bridge's `download` tool with an explicit `export_kind`:

- `decision-yaml`: a prescan decision revision, or the frozen effective YAML
  recorded by a completed conversion. For a prescan, pass `revision` and,
  when available, `expected_document_sha256` from the decision overview.
- `source-ncir`: the verified source Stage-2.5 NCIR. This is not a mapped target
  inventory or a claim that source extraction was complete.

The terminal downloads through the authenticated External API directly into
the workspace. Only file names, byte counts and SHA-256 receipts return to the
assistant. Downloading a file does not authorize displaying its body in chat.
Ordinary job downloads do not automatically fetch these documents.

The server checks tenant and owner scope and the stored artifact identity.
The terminal rejects redirects, missing or mismatched hashes, substituted
decision revisions, unknown provenance, and streams over 100 MiB. Verified
files use revision/hash names and atomic writes; different existing files
are preserved. A projected customer NCIR can differ from the internal stored
artifact; the server identifies both the original artifact hash and the hash
of the actual exported bytes.

Export requests require identity HTTP encoding; compressed responses are
refused before decoding. Error bodies are limited to 8 KiB. Credential refresh
retries at most once, after that bounded read, so an initial 401 response cannot
bypass the download limits. Error messages retain only a bounded error code.

A conversion export never substitutes the prescan's latest edits. Missing
historical documents, pending jobs, integrity failures and unsupported servers
remain errors; the terminal does not reconstruct the document or silently use
another download route. The restricted Quick API and `--guided` pilot retain
their existing artifact contracts.

These are candidate capabilities. Live server/client and final package
acceptance must be recorded separately from mocked transport tests.
