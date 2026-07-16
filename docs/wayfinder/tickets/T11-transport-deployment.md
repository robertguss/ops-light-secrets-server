---
id: T11
title: "Transport & deployment: TLS, key delivery, proxy mode, runtime matrix"
label: wayfinder:grilling
status: closed
assignee: robertguss
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

## Resolution (2026-07-16)

Ask-only mode: four pieces analysis-determined (agent-recommended,
unopposed); one genuine question put to Robert — his deploy reality — and
answered: **systemd VM.** All five KEPT as written.

1. **rustls TLS + live reload + plaintext-remote refusal + loopback
   allowance — KEEP.** KTD6 was session-settled and T03-inherited; reload
   exists because restarts are expensive precisely when key supply is
   attended (R36 coherence); refusal-not-warning is R18 (rationale below).
   Loopback plaintext is the bounded dev allowance (`::1` counts). KTD1's
   `axum-server` adapter stays flagged as community-maintained in
   dependency review and is adopted only after U9 proves reload +
   graceful shutdown — the gate already exists.
2. **Reverse-proxy as explicit listener type — KEEP.** The alternative (a
   trust-forwarded-headers boolean on the normal listener) is the classic
   spoofed-XFF identity/rate-bucket hole. Explicit mode = binds only
   loopback/Unix socket, honors forwarded source only from the exact
   configured peer in one allowlisted syntax, proxy-derived rate buckets
   only in this mode. Middleware ordering stays integration-tested
   (guard → bounds → sensitive-header marking → tracing → limits → auth).
3. **Boot key delivery: two R21 termini — KEEP, no additions.** Attended
   stdin/FD/TTY + systemd `LoadCredential`/`LoadCredentialEncrypted` with
   tested example units. Robert's target is a systemd VM, so unattended
   restarts are covered by the credentials path and the attended-restart
   availability cost does not bite in practice; it remains the documented
   accepted cost for non-systemd hosts. Network KMS / custom unseal stay
   out of v0.1 (new dependency + network trust for no closed failure mode).
4. **R37 secret-input rules — KEEP, floor.** argv is world-readable in
   /proc and shell history; env leaks through crash dumps and child
   inheritance (dev-only behind the explicit unsafe flag). Zero-cost
   discipline. No plaintext bulk export in v0.1.
5. **Runtime matrix — KEEP as written, now confirmed against reality.**
   Certified: Linux x86_64/aarch64, ext4/XFS, host service under systemd,
   not a container. Robert deploys exactly that (systemd VM), so the
   reference claim, the durability contract, and the actual deployment
   coincide — no container config enters the tested matrix, nothing
   consciously accepted as out-of-claim.

### Why the server refuses rather than warns (rationale record)

**Agent-drafted, not Robert's words** (explain-back retired — map Notes).

A warning is a bet that a human is watching the boot log of a daemon that
exists to be forgotten — the ops-light server is specifically the one
nobody stares at. Every unsafe configuration R18 names (plaintext
non-loopback listener, world-readable data directory, missing lock, clock
behind the persisted mark, non-ready lifecycle) is a condition under which
the server's core guarantees are already broken *before the first request
arrives*: serving anyway converts a loud, immediate, fixable startup
failure into a silent, compounding one discovered during an incident. The
asymmetry is decisive — refusal costs minutes at deploy time, when the
operator is present and context is fresh; a warning costs discovery at
3am, months later, after the unsafe state has been load-bearing. Fail-
closed startup is also what makes the rest of the design honest: R20's
"never plaintext" and R21's custody story are only true claims because the
server won't run in configurations that falsify them. Readiness-vs-
liveness (R36) is the same posture while running: the process may live,
but it admits traffic only while the keyring, schema, audit path, capacity,
and clock can uphold the guarantees.

**Downstream:** nothing invalidated, no fog graduates, no new tickets.
Deploy-reality fact (systemd VM) recorded for T14's operating-docs
emphasis. Frontier: T12, T13; then T14.
