---
id: T11
title: "Transport & deployment: TLS, key delivery, proxy mode, runtime matrix"
label: wayfinder:grilling
status: open
assignee:
blocked-by: [T01]
---

## Question

Walk and verdict the transport and deployment posture:

- rustls TLS with live reload, plaintext-remote refusal, loopback allowance
  (R20, KTD6, U9); KTD1's axum-server adapter dependency note.
- Reverse-proxy as an explicit listener type, not a relaxation.
- Boot key delivery: attended stdin/FD/TTY + systemd
  `LoadCredential`/`LoadCredentialEncrypted` as the two R21 termini; tested
  example units. Enough, or does the attended-restart availability cost bite?
- R37 secret-input rules (never argv; env dev-only).
- Supported runtime matrix: Linux x86_64/aarch64, ext4/XFS, host service not
  container — right claim for who will actually run this?

Resolution: verdicts plus explain-back on why the server refuses rather than
warns (R18 fail-closed startup).
