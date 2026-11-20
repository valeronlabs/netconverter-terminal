# Verified artifact publication

Ordinary job downloads, Quick API artifacts, diagrams and explicit document
exports share `Workspace.save_artifact`. It checks the supplied SHA-256 before
publishing through the same filesystem boundary used by guided artifacts.

POSIX operations traverse directories without following symlinks, retain
directory descriptors and verify directory identities during publication.
Windows uses held native handles on local NTFS, pinning ancestors against
renaming and refusing reparse points. Neither path overwrites a conflicting
customer file. Special files and hard links are refused, and existing files
are compared with a bounded read before an identical download is reused.

Generic downloads permit verified empty files and files up to 100 MiB.
Guided artifact publication retains its separate 32 MiB ceiling and nonempty
requirement. Existing identical generic downloads remain reusable, including
legacy Windows files whose ACLs were inherited; new Windows files receive a
protected owner-only ACL. Guided artifact reuse retains its stricter ACL rule.

After publication, the workspace retains only the verified hash and byte count
in memory. MCP builds its file receipt from that metadata without reopening
the pathname. A receipt identifies the bytes checked at publication; it does
not attest to later edits made by a user or another process. Raw file contents
are never retained in the receipt or returned to the model by this mechanism.

If verification or directory synchronization fails after a final filename was
published, the operation returns an error and no publication receipt. The final
file may remain: cleanup never unlinks that pathname, because a concurrent
customer save could have replaced it. Temporary-file cleanup still uses the
held directory and checks the temporary file's identity. A retained file does
not establish a successful flush or abrupt power-loss durability; inspect it
or retry the same download before treating it as a completed transfer.

Synthetic race tests cover directory replacement before and during publication,
conflicting concurrent files, hard links, FIFOs, oversized existing files and
post-publication pathname substitution. The private Windows CI lane runs real
native filesystem tests. Live service, installed-client and abrupt power-loss
acceptance remain separate from those tests.
