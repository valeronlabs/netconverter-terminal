# Negotiated configuration file transport

This development change addresses engine issue
[2195](https://github.com/devnexthop/aws-netconverter.ai/issues/2195).
Public terminal release and platform acceptance are separate gates.

Full API clients read the authenticated `/capabilities` limits before submission.
`max_inline_config_bytes` limits legacy JSON submission. `max_upload_bytes` is the
effective file allowance, governed by the administrator's upload policy and the
account's limits. `file_id_submission: true` enables multipart upload followed by
a `/jobs` request containing only the returned file ID and migration settings.
The terminal applies a 100 MiB local safety ceiling. An unavailable policy fails
closed; only an older server returning 404 uses the legacy 5 MiB inline path.
The dedicated Quick pilot retains its own smaller limits.

The bridge receives a path, reads at most the advertised allowance plus one byte,
checks the source format, and transfers the selected snapshot directly over authenticated
HTTPS. It verifies the upload receipt's SHA-256 and byte count before queueing.
The model receives the job ID, status, source hash and size, never the file body.
Summaries and decision values returned by MCP are still visible to the model.

All source reads use held descriptors on POSIX or native handles on local NTFS,
refuse special files and hard links, and verify the file and parent identity.
A parent replacement cannot redirect the read outside the workspace. Files
changed after CLI selection must be selected again; a failed local read creates
no new pending job and preserves any existing ambiguous submission.

Native configurations must be nonempty UTF-8 text without NUL bytes. Full-API
conversion can also submit an opaque ZIP when the server advertises file-ID
transport. Prescan additionally supports Check Point and Cisco FMC handoff ZIPs
over that transport. The client neither extracts nor interprets archive members;
the server remains responsible for validating the handoff manifest, scope,
vendor, size and contents. The ZIP transport tests use synthetic non-production
manifests and do not establish any vendor bundle's conversion correctness.
ZIPs cannot use legacy inline submission, the Quick pilot, validation or
optimization. Prescans of other ZIP source types also refuse before upload.
The server must support the handoff's manifest and selected-device scope; an
older server may reject it after upload. That refusal is returned honestly,
without retrying inline or substituting conversion. A successful transport
receipt alone is not manager-bundle or guided-workflow acceptance.

Accepted vendor aliases (`aruba_cx`, `fortinet_fortigate`, `checkpoint` and
`check-point`) resolve to their canonical identity before MCP source reading,
confirmation and replay binding. Router/switch and Junos SET/hierarchical codes
remain distinct. Unknown or ambiguous codes and cross-device requests refuse;
the server remains authoritative for supported directed paths and source-only
targets. New vendor identities require terminal contract updates before use.

The bridge saves private transport receipts under `.netconverter/submissions/`.
These contain hashes, request keys, file IDs and bounded job receipts, not source
content or credentials. An OS lock serializes submissions for the same path.
After an ambiguous job response, retry the same arguments: the original uploaded
file and idempotency key are reused, including after restarting the bridge.
A completed identical request returns its original job with `replayed: true`
after checking current access. Use the supported job rerun workflow for a new run.
Changes to a pending source, options, account, server or exposure are refused;
resolve the original request before replacing its receipt.

API keys selected explicitly, by automatic fallback, or after bridge startup use
the same credential normalization as REST requests when binding a receipt. OAuth
token refresh preserves its issuer/subject/organization partition; changing a key
or OAuth identity does not reuse the prior partition.

New receipts use journal version 2 with canonical vendor identities. Version-1
receipts are retained losslessly: equivalent old aliases can replay the same
completed job after an access check, or retry an ambiguous request with its
original file ID, idempotency key and vendor values. No new confirmation or
upload is introduced. A changed or nonunique legacy scope requires explicit
reconciliation; it never silently becomes a new job. An old bare `aruba_cx`
source receipt also requires reconciliation because the old client sent the
wrong device type. Unknown journal versions and malformed records refuse.
Fresh version-2 work retains the existing confirmation for genuinely changed
intent. Legacy records are not rewritten just to upgrade their format.

An ambiguous job submission is retryable for at most **23 hours from its first
attempt**, conservatively inside the server's 24-hour idempotency retention.
This relies on the local clock: missing, malformed, future or expired timestamps
refuse another POST and preserve the receipt for reconciliation. Keep the clock
accurate; no new key is generated automatically after the window. Completed
receipts remain replayable after checking current server access.

A first-attempt, well-formed rejection with a recognized 400, 403, 404, 413, 422
or 429 code clears that rejected request so corrected work can be confirmed.
Transport/response-parse failures and any later rejection after an ambiguous
attempt preserve the original receipt. The journal only reads bounded regular
files; POSIX receipt writes synchronize the file and its parent directory.
On POSIX, directory creation and every lock, read, replacement, deletion and
directory sync use securely opened directory descriptors. Each path component
is opened without following symlinks. On Windows, only local NTFS is supported:
held native handles pin every ancestor against deletion or renaming, reparse
points are refused, and an exclusive write handle locks the journal. Metadata
files and the submission directory require protected owner-only ACLs. Both
implementations refuse metadata hard links and special files.

Windows writes use write-through handles, checked file flushes and native
handle-based replacement/deletion. An error preserves the request's retry
identity; a failure after replacement is treated as ambiguous. This is not a
claim of tested abrupt power-loss durability or a POSIX-style directory flush.
The Windows contract follows Microsoft's [sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[native rename contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
and [file flush requirements](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

The full-API CLI/TUI pending session also binds the uploaded receipt to its
original credential and server, preserves prior ambiguous attempts on later
rejections, and applies the same 23-hour retry window. Changing accounts or
servers refuses resume without altering the original pending session. Older
pending sessions without a transport binding require reconciliation.

If the upload response itself is lost, no job has been queued by this client yet.
A retry may leave a quota-bound orphan upload; server-side upload idempotency is
not claimed. No client automatically deletes those files.

Transport receipt reuse avoids repeating an already obtained confirmation for an
identical interrupted submission. It does not authorize a different migration or
replace the independent guided-conversion approval workflow tracked in
[2194](https://github.com/devnexthop/aws-netconverter.ai/issues/2194).

Local mocked transport tests establish boundary and retry behavior. The private
Windows CI lane exercises actual NTFS handles, junction refusal, exclusive locks,
ACLs, replacement, cleanup and bridge retry against synthetic HTTP responses.
Live server, admin policy, large-config conversion, installed Windows client and
hosted-client compatibility must be recorded separately before claiming them tested.
