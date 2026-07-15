---
id: T06
title: "AuthN: tokens, AppRole, audiences, keyed verifiers, credential epochs"
label: wayfinder:grilling
status: open
assignee:
blocked-by: [T03, T05]
---

## Question

Walk and verdict the authentication design:

- Supported surface: token auth + AppRole login + lookup-self, non-renewable
  tokens (R31) — is that the right minimum?
- KTD5 credential format: `<kind>.<audience>.<accessor>.<secret>`, keyed-MAC
  verifiers, no password KDF, dummy-verifier timing defense — keep or
  simplify?
- Listener audiences (`control` vs `data`, R24) and the local-socket-only
  management split (R34) — the two-router consequence.
- Credential epochs (R41 incident command; restore interaction R32) — v0.1 or
  defer?
- First-credential bootstrap: R17's disclosure-before-commit ordering.

Resolution: verdicts plus explain-back on the token lifecycle — issue,
verify, revoke, epoch-invalidate — another named learning target.
