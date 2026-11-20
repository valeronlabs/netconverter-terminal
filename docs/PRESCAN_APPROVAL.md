# Exact-revision prescan approval

The standard bridge can proxy `request_submission_review` and
`get_submission_approval` when the authenticated server exposes them. These
tools require full exposure and the server's account-specific grant. The
restricted `--guided` pilot retains its separate contract.

After proposing and validating choices, request review for the exact prescan
revision, target, and acknowledged warnings. The review URL opens the server's
human approval ceremony. A URL, pending response, assistant statement, or local
`confirm_token` is not a server approval receipt.

Once the user approves, retrieve the receipt and call `submit_conversion` with
the prescan ID and revision, `draft_id`, `approval_ref`, and a stable
`idempotency_key`. The bridge forwards these handles without another queue
confirmation. The server checks ownership, current revision, expiry, revocation,
and the approved source/NCIR/decision binding before atomically consuming the
receipt and queuing the job. An ambiguous retry must keep the same handles and
key; no local acknowledgement creates approval authority.

The bridge refuses receipt-shaped requests if the advertised server contract
lacks the required tools or receipt fields. It does not fall back to an older
submission that could ignore approval fields. Ordinary legacy submissions keep
their existing confirmation behavior. Initial file upload consent remains
separate from approval of the migration design.

This source change is a candidate. Mocked bridge tests do not establish a live
portal ceremony, final worker behavior, or customer package acceptance.
