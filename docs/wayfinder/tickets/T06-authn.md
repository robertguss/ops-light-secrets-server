---
id: T06
title: "AuthN: tokens, AppRole, audiences, keyed verifiers, credential epochs"
label: wayfinder:grilling
status: closed
assignee: robertguss
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

## Resolution (2026-07-16)

Grilling session, all five walked. **Every verdict: KEEP as written** — the
first zero-amendment ticket since T01. Each keep argued against its cheapest
cut before verdict; none was close under the complexity budget.

1. **Surface (R31) — KEEP.** Token + AppRole login + lookup-self,
   non-renewable, and no remote `revoke-self`: cutting AppRole kills
   rotation-first (every TTL expiry would need an operator); short
   non-renewable TTLs already solve what revoke-self solves; incident path is
   R41 or control-socket revoke.
2. **KTD5 — KEEP whole** (structured string, keyed blake3 verifiers, no
   password KDF, dummy-verifier timing defense, secret_id use counts).
   Notable: the timing defense is negative-cost — uniform MAC path against a
   dummy record is fewer branches than early-exit. Keyed (vs plain) hashing
   is load-bearing in T05's settled boundary: DB alone can't verify guesses.
3. **Audiences + management split (R24/R34) — KEEP both.** Socket separation
   controls where endpoints live; audience controls where *credentials* work
   — a leaked control credential is cryptographically useless remotely, which
   R17's bootstrap story leans on. Accepted cost: two routers, and no
   differential oracle for the control plane (U0 covers data plane only).
4. **Credential epochs (R41) — KEEP in v0.1.** Decisive: R32 restore forces
   the epoch primitive regardless (else a restored snapshot resurrects
   revoked credentials), and `issue_epoch` is already in KTD5's MAC domain.
   R41 is one thin local command over machinery that ships anyway; it also
   doubles as lockout recovery if the bootstrap TTL lapses.
5. **Bootstrap ordering (R17) — KEEP.** Sink-validate → disclose+flush →
   commit is a free sequencing choice that deletes the one bad failure mode:
   a committed store whose only credential nobody saw, recoverable only by
   documenting `rm -rf` against a secrets directory.

### Token lifecycle (rationale record)

**Agent-drafted, not Robert's words** — explain-back retired mid-session by
Robert (map Notes updated, applies to future sessions); verdicts above are
Robert's.

- **Issue.** Workload hits AppRole login on the data listener with role_id +
  secret_id. The secret_id string parses as `<kind>.<audience>.<accessor>.
  <secret>`; accessor selects one record O(1); keyed blake3 MAC over (store
  id, kind, audience, accessor, issue_epoch, secret) compares constant-time
  against the stored verifier; epoch must equal `current_credential_epoch`;
  TTL checked; use count decremented atomically with token mint and audit.
  The minted token is a fresh 256-bit secret with kind `token`, audience
  `data`, current epoch — stored only as a verifier, disclosed once,
  non-renewable, inheriting `consumer_instance_id`. The first credential ever
  is R17's: sink validated, credential disclosed and flushed, verifier
  committed last; control audience, short TTL.
- **Verify (every request).** Parse `X-Vault-Token` (noncanonical encoding
  rejected); unknown accessor runs the same MAC path against a fixed dummy
  record so timing hides existence; MAC recompute binds store, kind,
  audience, accessor, epoch — wrong-listener or wrong-store tokens die here,
  before grant evaluation. Then: not revoked, TTL alive, epoch current.
  Tokens are capability-thin (identity, expiry, revocation state — never a
  grant snapshot), so the request reloads current grants inside the storage
  transaction (R28). Every rejection is uniform and audited by accessor,
  never by secret.
- **Revoke.** Control socket or offline CLI only (R34). Linearized at the
  transaction boundary (R28): any request whose authorization transaction
  begins after the revoke commits sees it, independent of TTL. No remote
  revoke-self; the normal death is TTL expiry followed by AppRole re-login.
- **Epoch-invalidate.** Two triggers: R32 restore auto-bumps the epoch so a
  restored snapshot cannot resurrect credentials revoked after the backup;
  R41 bumps it deliberately, cuts a new verifier key, and mints a
  replacement control credential via R17's ordering. Records keep their
  `issue_epoch`; validation demands equality with current — one bump ends
  every outstanding bearer credential while identities, grants, and secrets
  survive.

**Downstream:** nothing invalidated, nothing new surfaced — no fog
graduates, no vocabulary changes. T09/T10 still wait on T08; T14 inherits
these keeps. Process change recorded on the map: explain-back retired,
rationale sections are agent-drafted and labeled from here on.
