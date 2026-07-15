---
title: Ops-Light Secrets Server - Plan Revisions (Capture)
type: plan-revision
date: 2026-07-15
status: captured, not incorporated
relates-to: docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md
also-relates-to:
  - docs/ideas/2026-07-15-001-feature-ideas-top-10.md
  - docs/ideas/2026-07-15-002-rotation-first-feature-ideas-top-10.md
---

# Plan Revisions Capture — Ops-Light Secrets Server

**Status:** Capture only. Nothing in this document has been incorporated into
the canonical plan. Use this file to select, reject, or defer items before
editing `docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md`.

**Source plan:** `docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md`

**Purpose of this review:** Propose better architecture, reliability,
performance, and product leverage — with analysis, rationale, and git-diff
style patches relative to the original plan — without mutating the plan yet.

---

## Executive summary

The source plan is strong. The product thesis is sharp, the fail-closed
postures are real, and the settled decisions mostly hang together. These
revisions do **not** rewrite the thesis. They are targeted changes that make
v0.1 correct under load, honest about its consistency model, more
rotation-useful on day one, and cheaper to deepen later without reopening
sealed product choices.

| Tier | Theme | Verdict |
|------|--------|---------|
| **P0** | Correctness under the plan’s own invariants | Fix before coding |
| **P1** | Reliability / ops completeness | Fold into v0.1 units |
| **P2** | Product leverage at near-zero cost | Promote thin seams + one query |
| **P3** | Performance & capacity honesty | Document + small design choices |
| **P4** | Keep deferred, but reserve seams | Do not expand scope |

### Three highest-leverage fixes

1. **Do not argon2-hash every request token** (KTD5 is wrong for tokens).
2. **Put audit and secrets in one transactional durability model** (R26 is underspecified).
3. **Record secret version on every successful read audit event** (makes F4 real; unlocks post-v0.1 cutover tracking).

### Net shape of the revised product (v0.1)

**Unchanged thesis:**

- Single binary, single node, age-at-rest, Vault KV v2 + AppRole, ops-light non-goals.

**Hardened:**

- Correct R26 (one DB), correct R28 (thin tokens), correct token crypto (fast verify), real R14 export path, real recovery (identity + store), offline re-encrypt, format version.

**More useful for the stated pain:**

- Versioned read audit → rotation status → F4 is operational, not aspirational.
- CAS / max_versions / custom_metadata → safe rotations and bounded disk.
- lookup/renew-self, health, systemd-creds path → less “toy server” friction.

**Still not Vault:**

- No HA, no policy DSL, no dynamic secrets, no unseal ceremony, no campaign engine, no OIDC, no drift scanner — yet.

### Recommended adoption order (when incorporating)

1. **Must:** #1 KTD5 token hashing, #2 KTD8 single durability domain, #3 thin tokens, #4 concrete checkpoints
2. **Should:** #5 CAS/max_versions/custom_metadata, #7 format/lifecycle, #8 identity recovery, #11 version in audit, #12 thin rotation status
3. **Should (cheap):** #6 lookup/renew-self + health, #9 offline re-encrypt, #10 clock model, #13–14 seams, #15 systemd-creds, #16–18 performance/backup honesty
4. **Hygiene:** KTD12–14 license, pins, default mount

### What not to change

- **Write-is-cutover (R11)** — correct for SaaS keys; staging stays upstream.
- **age single recipient** — right for ops-light; U8 owns the cost.
- **No pre-migration inventory in v0.1** — consistent with deferred real Canvas/Populi rotation; just don’t pretend R10 is complete before migration.
- **fnox shells out to vault CLI** — ugly but correctly treated as a constraint; embedded shim stays post-v0.1 after the harness teaches the exact subset.
- **Learning goal as primary success criterion** — keep it; the architecture revisions above are still good pedagogy (they are the real hard parts of sealed systems).

---

## P0 — Critical architecture fixes

### 1. Split credential hashing: Argon2 for secret_ids, fast keyed hash for tokens

**Problem.** KTD5 says bootstrap credentials, secret_ids, **and tokens** are
stored as Argon2 verifiers. Argon2 is right for low-entropy or rarely
presented secrets (login). It is wrong for tokens presented on every KV
request:

- Every `vault kv get` becomes a deliberate CPU burn.
- Unauthenticated/authenticated DoS becomes trivial (flood valid-format tokens).
- Latency floor is measured in tens of ms per request by design.

Vault-class systems index a public token id and verify a high-entropy secret
portion with a **fast** constant-time hash (HMAC/BLAKE3/SHA-256), not a
password KDF.

**Rationale.** Preserves R24 (disclose once, non-recoverable verifier,
revocable) while making the request path usable and rate-limitable. Argon2
stays for AppRole `secret_id` and bootstrap credential.

```diff
--- a/docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md
+++ b/docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md
@@ -575,8 +575,16 @@ Technical Decisions
   re-chained log.
 
-- KTD5. **Credential verifiers: `argon2`; tokens are server-generated 128-bit
-  random.** Raw bootstrap credentials, secret_ids, and tokens are shown once and
-  stored only as `argon2` verifiers (R24). Satisfies the entropy floor implied
-  by R9 on a network-reachable auth surface.
+- KTD5. **Credential verifiers: split by presentation frequency.** Raw
+  bootstrap credentials, AppRole `secret_id`s, and tokens are disclosed once
+  and never recoverable (R24). Presentation-frequency rules:
+  - **Login secrets** (bootstrap credential, `secret_id`): stored as
+    `argon2id` verifiers — slow KDF is appropriate because presentation is
+    rare and the secret may have lower effective entropy than a pure token.
+  - **Request tokens:** server-generated ≥128-bit random, stored as a
+    public `token_id` index plus a **fast keyed hash** of the secret portion
+    (`blake3` keyed or HMAC-SHA-256) verified with constant-time compare.
+    Argon2 on the per-request path is rejected: it turns every KV read into a
+    deliberate CPU burn and a DoS amplifier on a network-reachable surface.
+  Satisfies R9's entropy floor without making authn the throughput ceiling.
```

Also update U3/U4 language that says “argon2 verifiers” for tokens:

```diff
@@ -749,8 +757,10 @@
-  Vault wire shape. secret_ids and tokens are stored only as `argon2` verifiers
-  and disclosed once (R24). **Bootstrap exchange (R30, F1):** on an
+  Vault wire shape. secret_ids are stored as `argon2id` verifiers; tokens are
+  stored as `token_id` + fast keyed hash (KTD5). Both classes are disclosed
+  once (R24). **Bootstrap exchange (R30, F1):** on an
```

---

### 2. Make R26 real: one durability domain for store + audit

**Problem.** The plan requires “audit append before HTTP response; if audit
fails, operation fails” but never specifies whether secrets and audit share a
transaction, two files, or two systems. Without that:

| Ordering | Failure mode |
|----------|----------------|
| Write secret, then audit fails | Secret exists, no audit → **R26 violated** |
| Audit success, then secret write fails | Audit lies about a write that never landed |
| Separate fsync domains | Crash between domains → same inconsistency |

Backup (U10) and restore integrity also get harder if the two logs can diverge.

**Rationale.** At single-node scale the clean design is:

- **One redb database** (or one redb + one append-only audit table **in the same DB file**) holding secrets, identities, tokens, **and** audit entries.
- Mutating operations: **one multi-table write transaction** that commits secret change + audit entry together, then responds.
- Pure reads: decrypt under a read txn → prepare audit entry → **write-txn append audit** → only then serialize the response. If the audit write fails, return error and do not send plaintext (R26 intent for reads).

Document the performance consequence honestly (see P3): every audited read is a
write to redb. That is acceptable at nonprofit ops-light scale; it must be
named so nobody “optimizes” R26 away later.

```diff
@@ -594,6 +602,28 @@
   inside serde/hyper/rustls are acknowledged out of scope by R5's wording.
 
+- KTD8. **Single durability domain for secrets and audit.** Secrets,
+  identities, tokens, and the audit hash-chain live in one redb database
+  (separate tables, one file). R26 is implemented as transactional commit,
+  not best-effort dual-write across two stores:
+  - **Mutations** (KV write/delete/destroy, identity/scope/credential
+    lifecycle): one multi-table write transaction commits the state change
+    and its audit entry together; the HTTP response is sent only after
+    that commit succeeds.
+  - **Reads and auth attempts:** outcome is known first; the audit entry is
+    committed in a write transaction before any success response that would
+    disclose a secret or issue a token. If the audit commit fails, the
+    client receives an error and no secret material is returned.
+  A separate audit file or external log is rejected for v0.1: it reintroduces
+  cross-store crash windows that R26 forbids. Off-host **checkpoints**
+  (KTD4) remain external; they pin chain heads, they are not the primary log.
+  **Accepted cost:** every audited read takes a redb write lock for the
+  audit append. Documented as the single-node throughput ceiling (see
+  System-Wide Impact / performance assumptions), not something to "fix"
+  by making audit asynchronous.
+
 ### High-Level Technical Design
 ...
@@ -614,7 +644,9 @@
 Audit write ordering: a read/write/auth outcome is committed to the audit log
-before the HTTP response is sent. If the audit append fails, the operation fails
-(R26) — the response the client sees is an error, not a silent success.
+before the HTTP response is sent, in the same redb durability domain as the
+store (KTD8). If the audit commit fails, the operation fails (R26) — the
+response the client sees is an error, not a silent success, and no secret
+material is returned on a failed-audit read.
```

U6/U2/U10 approach lines should reference KTD8 (same DB, multi-table; backup is
one snapshot of one file).

---

### 3. Tokens carry identity id only — never baked-in grants

**Problem.** R28 requires scope reduction / identity disable to take effect
**before the next authorized request**, independent of TTL. That only works if
authorization always reloads current grants from the identity store. If the
token snapshot embeds policies/scopes at issue time (Vault-ish mental model),
R28 is false unless you add a secondary invalidation channel.

**Rationale.** Make the model explicit: token → identity_id + expiry +
revocation flag; authz always joins current grants. Management grant checks the
same way. This is simpler **and** the only design that satisfies R28 without
distributed cache invalidation.

```diff
@@ -719,9 +751,14 @@
-  the logical path before matching (R8). Tokens carry a TTL and revocation
-  state; scope reductions and identity disable take effect on the next request
-  regardless of TTL (R28). Management capabilities (R22) require an explicit
-  grant, including audit-read and consumer-enumeration.
+  the logical path before matching (R8). Tokens are **capability-thin**: they
+  carry `identity_id`, TTL, and revocation state only — never a snapshot of
+  grants or scopes. Every authorized request reloads the identity's current
+  grants from the store before the scope check. That is the only design that
+  makes R28 true without a secondary invalidation bus: reducing a scope or
+  disabling an identity cannot be bypassed by a still-unexpired token that
+  cached broader rights at issue time. Management capabilities (R22) are
+  checked the same way (current grants), including audit-read and consumer
+  enumeration.
```

Add a test scenario under U3:

```diff
+  - Token issued while identity had broad scope; scope then reduced → request
+    using the still-unexpired token is denied on the removed path (R28;
+    proves grants are not baked into the token).
```

---

### 4. Concrete off-host checkpoint mechanism (KTD4 is incomplete)

**Problem.** R14’s trust anchor is “signed checkpoints mirrored off-host,” but
the plan never says **how** they leave the host. Without a mechanism,
implementers invent one (webhook, NFS, hope) and AE7’s “verifies against last
off-host checkpoint” is untestable in CI.

**Rationale.** Ops-light answer for v0.1:

1. Server writes signed checkpoint files to a configured local directory (or stdout via CLI).
2. Operator (or cron/systemd path unit) copies them off-host — rsync, object storage, another disk.
3. `audit verify --checkpoint <file>` uses the last imported checkpoint.

Webhooks (ideas list) can replace the copy step later; v0.1 needs a file-shaped
primitive.

```diff
@@ -562,15 +562,24 @@
-- KTD4. **Audit chain: per-entry hash chain (`blake3`) with periodic
-  `ed25519-dalek`-signed checkpoints mirrored off-host.** Resolves OQ4
+- KTD4. **Audit chain: per-entry hash chain (`blake3`) with periodic
+  `ed25519-dalek`-signed checkpoints exported for off-host mirror.** Resolves OQ4
   (per-entry, not per-batch) and answers R14's trust-anchor gap: a re-chaining
   attacker with write access is caught because the off-host checkpoint pins a
   chain head the attacker cannot retroactively rewrite. (Research: this is the
   Certificate-Transparency / Trillian signed-tree-head pattern reduced to
   single-node scale; full Merkle inclusion-proof infrastructure would be
-  over-building for v0.1.) The checkpoint signing key is supplied at boot via
-  the same secret-delivery mechanism as the `age` identity, held only in a
-  `secrecy::SecretBox` and never persisted on the host; signed checkpoints are
-  mirrored off-host per R14, so a host-write attacker cannot re-sign a
-  re-chained log.
+  over-building for v0.1.) **v0.1 delivery mechanism (concrete):** the server
+  periodically writes a signed checkpoint blob (sequence, chain-head hash,
+  timestamp, ed25519 signature) to a configured export directory on the host;
+  a CLI `audit checkpoint` forces an immediate export. Off-host mirror is an
+  operator-owned copy step (rsync/cron/systemd path unit) documented in
+  `docs/operating.md` — the server does not itself speak S3/webhooks in v0.1.
+  `audit verify` accepts `--checkpoint <path>` for the last known good export.
+  The checkpoint signing key is supplied at boot via the same secret-delivery
+  mechanism as the `age` identity, held only in a `secrecy::SecretBox` and
+  never persisted on the host; because verification uses an off-host copy of
+  a signature the host-write attacker cannot re-create without the key, a
+  re-chained log fails verification (R14).
```

U6 tests should include: export checkpoint → tamper chain → verify with exported
file fails.

---

## P1 — Reliability & completeness

### 5. CAS, `max_versions`, and `custom_metadata` on the KV surface

**Problem.** R1 lists read/write/list/delete/versioned-read but omits three KV
v2 features that matter for **this** product:

| Feature | Why it matters here |
|---------|---------------------|
| **CAS (`cas`)** | Two operators (or script + human) writing a rotation can clobber each other; write-is-cutover without CAS is a lost-update hazard. |
| **`max_versions`** | Unbounded history + R11 retaining old versions until “rotation complete” = unbounded disk; Vault’s default escape hatch is missing. |
| **`custom_metadata`** | R12 needs somewhere to store rotation interval; runbook URLs later; this is the compat-native bag, not a side table. |

**Rationale.** These are not feature-creep; they are the minimum KV v2 surface
for safe versioned mutation and for R12 without inventing a non-compat metadata
channel.

```diff
@@ -190,8 +190,12 @@
-- R1. The server serves the Vault KV v2 read, write, list, delete, and
-  versioned-read endpoints, plus the mount-discovery preflight
-  (`sys/internal/ui/mounts/<path>`, reporting KV version 2) and
-  `sys/seal-status` (always reporting unsealed), so an unmodified Vault client
-  can use it as a backend.
+- R1. The server serves the Vault KV v2 read, write, list, delete,
+  versioned-read, metadata read/write, and soft-delete/undelete/destroy
+  endpoints, including write `cas` (check-and-set), per-secret and mount-default
+  `max_versions`, and `custom_metadata`, plus the mount-discovery preflight
+  (`sys/internal/ui/mounts/<path>`, reporting KV version 2), `sys/seal-status`
+  (always reporting unsealed), and `sys/health`, so an unmodified Vault client
+  can use it as a backend.
```

```diff
@@ -252,6 +256,10 @@
-- R12. The server surfaces a secret's age — time since its last completed
-  rotation, or since creation when never rotated — against a per-secret rotation
-  interval, and reports "no interval set" when none is configured.
+- R12. The server surfaces a secret's age — time since its last completed
+  rotation, or since creation when never rotated — against a per-secret rotation
+  interval stored in KV v2 `custom_metadata` (key documented, e.g.
+  `rotation_interval`), and reports "no interval set" when none is configured.
+  Mount-default and per-secret `max_versions` bound retained history; retired
+  versions beyond the bound are destroyed per documented retention (R29).
```

U5 approach:

```diff
+  Support `options.cas` on write (reject on version mismatch), metadata
+  endpoints for `custom_metadata` / `max_versions` / `cas_required`, and
+  `GET /v1/sys/health` (initialized, standby=false, sealed=false).
```

---

### 6. Minimal token self-service: `lookup-self` (and optional `renew-self`)

**Problem.** Many Vault clients and operator habits call
`auth/token/lookup-self`. Returning R3 “unsupported” may be OK for some, but
breaks others and makes TTL debugging miserable (“when does my token die?”).

**Rationale.** Implement **lookup-self** in v0.1 (identity id, ttl remaining,
renewable flag, creation time — no secret material). **renew-self** can be v0.1
if cheap (extend TTL up to a configured max) or explicitly unsupported with a
stable error. Prefer implementing renew with a hard max TTL cap so R9 stays
meaningful.

```diff
@@ -199,7 +199,10 @@
-- R31. The server implements Vault token authentication (`X-Vault-Token`) plus
-  the AppRole login endpoint: a workload presents its role_id and secret_id and
-  receives a TTL-bound token (R9). Token auth and AppRole are the entire
-  supported auth surface.
+- R31. The server implements Vault token authentication (`X-Vault-Token`),
+  AppRole login (`POST /v1/auth/approle/login`), and token self-service
+  `GET /v1/auth/token/lookup-self` plus `POST /v1/auth/token/renew-self`
+  (renewal capped by a server-configured max TTL so R9 remains meaningful).
+  Token auth, AppRole, and these two self-service endpoints are the entire
+  supported auth surface for v0.1.
```

---

### 7. Store format version + exclusive re-encrypt / restore

**Problem.** Upgrade-with-rollback is deferred, but shipping **no** on-disk
format version forces a flag day later. U8 re-encrypt and U10 restore can leave
partial state; the plan tests resume but not “refuse to serve if mid-migration.”

**Rationale.** Tiny header table: `format_version`, `reencrypt_state`,
`restore_state`. Startup (U1) refuses to serve if state ≠ `ready` (R18
extension). Future upgrades read `format_version` and migrate or fail closed.

```diff
@@ -658,6 +670,8 @@
-  directory supports file locking, and no non-loopback listener without TLS. Any
-  failure exits non-zero naming the missing or unsafe setting.
+  directory supports file locking, no non-loopback listener without TLS, and
+  store lifecycle state is `ready` (not mid-reencrypt, not mid-restore; see
+  KTD9). Any failure exits non-zero naming the missing or unsafe setting.
```

```diff
+- KTD9. **On-disk format version and exclusive lifecycle states.** The redb
+  file carries a `meta` table with `format_version` (integer, starting at 1)
+  and `lifecycle` ∈ {`ready`, `reencrypting`, `restoring`}. Serving mode
+  requires `lifecycle=ready`. U8 and U10 set the lifecycle flag for the
+  duration of the job and clear it on success; crash recovery resumes or
+  rolls forward to a safe terminal state before serving. Unknown
+  `format_version` → fail-closed startup (R18), never silent interpret.
```

---

### 8. Age identity recovery is part of the backup story

**Problem.** R32 backs up the **encrypted store**. Without the age identity,
restore is a paperweight. R21 forbids casual plaintext identity on disk but does
not define a **recovery** story (paper backup, second offline medium, dual
recipient for disaster only).

**Rationale.** v0.1 does not need automatic dual-recipient crypto complexity,
but it **does** need:

1. Documented identity backup procedure (operator prints/stores identity offline at bootstrap).
2. AE/test: restore store + identity from offline backup → secrets readable.
3. Explicit warning: store backup alone is insufficient.

Optional hardening later: encrypt identity to a second offline age recipient at
bootstrap. Not required for v0.1 if documentation + test exist.

```diff
@@ -295,6 +307,9 @@
-- R32. A single operator can take an encrypted backup of the store and audit log
-  while the server runs, and restore it onto a fresh host by a documented,
-  tested sequence.
+- R32. A single operator can take an encrypted backup of the store and audit log
+  while the server runs, and restore it onto a fresh host by a documented,
+  tested sequence. The documented sequence includes offline recovery of the
+  server `age` identity (and checkpoint signing key): a store backup without
+  those keys is not a complete recovery package. v0.1 documents and tests the
+  dual recovery; it does not require an automatic dual-recipient scheme.
```

U10 + U12 approach text should list identity + checkpoint key in the recovery
package checklist.

---

### 9. U8 re-encrypt is offline-only (make exclusive)

**Problem.** “CLI subcommand” could mean against a running server. Concurrent
serve + full-store re-encrypt is a consistency nightmare (new writes under old
key mid-pass).

**Rationale.** Explicit: stop server → re-encrypt → start with new identity.
Matches ops-light and KTD9 lifecycle.

```diff
@@ -879,8 +899,10 @@
-- **Approach:** A CLI subcommand decrypts every blob under the old identity and
-  re-encrypts under the new recipient in a crash-recoverable pass
-  (write-new-then-swap, resumable if interrupted), preserving readable secrets
-  and audit history. `age` has no rotation primitive, so this is an explicit
-  application-level job (mirrors fnox's `fnox reencrypt`).
+- **Approach:** Offline-only. The server must not be serving (U1 refuses to
+  start while `lifecycle=reencrypting`). The CLI sets lifecycle, decrypts every
+  blob under the old identity, re-encrypts under the new recipient in a
+  crash-recoverable pass (write-new-then-swap, resumable if interrupted),
+  preserves audit history, then sets lifecycle=`ready`. `age` has no rotation
+  primitive, so this is an explicit application-level job (mirrors fnox's
+  `fnox reencrypt`). Online re-encrypt is out of scope for v0.1.
```

---

### 10. Clock model for TTLs and audit

**Problem.** Token TTL, rate limits, rotation age, and audit timestamps all
assume a well-behaved wall clock. Clock steps can extend TTLs or disorder the
chain’s human timestamps (hash chain order is still write order).

**Rationale.** Document the model; don’t overbuild NTP:

- Authorization TTL: `expires_at = issued_wall + ttl`, evaluated with current wall clock.
- Audit: wall timestamp for humans; chain sequence number is authoritative for order.
- Startup warning (or doctor later) if clock appears to step backward vs last audit timestamp.
- No monotonic-only TTL in v0.1 (doesn’t survive restart usefully without more design).

```diff
@@ -619,6 +641,12 @@
-- The data directory sits on a filesystem supporting POSIX file locks (KTD2
-  caveat). Startup verifies this.
+- The data directory sits on a filesystem supporting POSIX file locks (KTD2
+  caveat). Startup verifies this.
+- **Clock model:** wall clock is trusted for token expiry (R9), rotation age
+  (R12), and audit display timestamps. Hash-chain order is commit sequence,
+  not wall time. A large backward step vs the last audit timestamp is logged
+  at startup; v0.1 does not attempt to "fix" operator clocks. Operators
+  running without NTP accept that TTL enforcement tracks their wall clock.
```

---

## P2 — Make rotation the product on day one (without scope explosion)

### 11. Audit successful reads with non-secret version metadata

**Problem.** F4 says the operator “verifies consumers are reading the new
version.” R13’s audit fields are identity, path, operation, timestamp, outcome —
**no version**. Without version, verification is guesswork; the cutover-tracker
idea becomes a schema migration later.

**Rationale.** This is the single best **seam** in the ideas docs. It is
non-secret, tiny, and turns R10/F4 from “list who *could* read” into “prove who
*fetched which version*.”

```diff
@@ -263,7 +263,9 @@
-- R13. Every read, write, delete, and authentication attempt, and every
-  identity, scope, and credential lifecycle change, is written to an append-only
-  log whose entries record identity, path, operation, timestamp, and outcome —
-  never secret values or credential material.
+- R13. Every read, write, delete, and authentication attempt, and every
+  identity, scope, and credential lifecycle change, is written to an append-only
+  log whose entries record identity, path, operation, timestamp, outcome, and
+  **non-secret version metadata when applicable** (for successful secret reads
+  and writes: the version number involved) — never secret values or credential
+  material.
```

U6 approach: include `version` on read/write audit entries.

---

### 12. Thin `rotation status` query in U7 (promote from ideas)

**Problem.** U7 enumerates consumers by **scope** with recency annotation, and
marks rotation complete. It does not answer the scary question after
write-is-cutover: **who has fetched the new version vs who is still silent?**

**Rationale.** With change #11, this is a pure audit query under the management
grant — no new subsystem, no webhooks, no campaigns. It is the minimum product
that makes “rotation is the pain” visible in v0.1, and it differentiates from
“small Vault clone.”

Keep full **rotation campaigns** (prepare → observe → revoke upstream → receipt)
post-v0.1.

```diff
@@ -849,14 +871,22 @@
 ### U7. Rotation surfaces
 
-- **Goal:** Enumerate a secret's consumers, surface its age against a rotation
-  interval, and mark rotations complete.
+- **Goal:** Enumerate a secret's consumers, surface its age against a rotation
+  interval, show post-write version adoption, and mark rotations complete.
 - **Requirements:** R10, R12, R23, R29; Key Flow F4.
 ...
-- **Approach:** Consumer enumeration is every identity whose scope grants read
-  on the path, annotated with last-read recency from the audit log over R23's
-  window — recency annotates, never filters (R10). Secret age is time since last
-  completed rotation, else creation; "no interval set" when none configured
-  (R12). Marking a rotation complete retires the prior version. Enumeration and
-  audit read require the management grant (R22).
+- **Approach:** Consumer enumeration is every identity whose scope grants read
+  on the path, annotated with last-read recency from the audit log over R23's
+  window — recency annotates, never filters (R10). After a replacement write,
+  `rotation status <path>` (management API or CLI) shows each consumer as
+  `on-current` / `on-prior` / `silent-since-write` using R13's versioned read
+  audit events — observation only; no automatic revoke, no campaign state
+  machine in v0.1. Secret age is time since last completed rotation, else
+  creation; interval from `custom_metadata` (R12). Marking a rotation complete
+  retires the prior version (subject to `max_versions`). Enumeration, status,
+  and audit read require the management grant (R22).
+
+- **Test scenarios:** (add)
+  - After write of v2, identity A reads v2, identity B has not → status shows
+    A on-current, B silent-since-write (or on-prior if B read v1 after write
+    via versioned read).
```

Optional product requirement:

```diff
+- R33. After a secret write, a management-gated rotation status view reports,
+  for each R10 consumer, whether their latest read in the lookback window
+  fetched the current version, a prior version, or no version since the write.
```

---

### 13. Structured internal authz decisions (discard on hot path)

**Problem.** Future `access explain` / least-privilege advisor needs more than
bool allow/deny. Retrofitting the matcher later is painful.

**Rationale.** Authorization returns a small struct: logical path, operation,
matched grant id (or denial reason enum). Hot path logs only allow/deny to
audit; management tools can call an explain entry point later. **No** policy
DSL.

```diff
+- KTD10. **Authorization returns a structured decision internally.** The
+  scope matcher yields `{allow, logical_path, operation, grant_id | deny_reason}`
+  rather than a bare boolean. Request handlers use `allow` only; the full
+  decision is available to management-only explain tooling later and is never
+  echoed to unauthorized clients (R25). This is an internal seam, not a v0.1
+  user-facing policy debugger.
```

U3: implement decision struct; tests assert deny_reason discriminates
prefix-boundary vs missing grant.

---

### 14. Schema-versioned per-secret metadata record (unencrypted envelope)

**Problem.** Rotation interval, custom_metadata, future consumer declarations
and contracts need a place that is **not** inside the age ciphertext of the
secret value (so you can list/age/status without decrypting every blob if
desired — or at least evolve metadata independently).

**Rationale.** Store layout:

- `secrets` table: path → encrypted version chain (values only)
- `secret_meta` table: path → plaintext-or-integrity-protected JSON metadata (custom_metadata, max_versions, last_rotated_at, format of meta)

Integrity: metadata is not secret but should be covered by backup + optional
HMAC with server key to detect tampering. For v0.1, living inside redb + audit
of metadata changes may be enough.

```diff
+- KTD11. **Per-secret metadata is a first-class, schema-versioned record**
+  separate from version ciphertext. Holds KV `custom_metadata`,
+  `max_versions`, `cas_required`, and server fields (`last_completed_rotation_at`,
+  meta schema version). Value blobs remain age-encrypted; metadata changes are
+  audited. Reserved so post-v0.1 consumer declarations / structural contracts
+  do not force a ciphertext format break.
```

---

### 15. Documented optional systemd-creds terminus for age identity

**Problem.** Operator-attended restart is the biggest ops wart. Ideas doc #10
is almost free and R21 already allows OS secret storage.

**Rationale.** Not a new unseal ceremony: read identity from
`$CREDENTIALS_DIRECTORY` when configured. Fallback: interactive/env as today.
Puts the path in U1/U12 so the next host isn’t forced into attended mode.

```diff
@@ -454,8 +454,12 @@
-- **Server restart requires the operator to supply the `age` identity
-  interactively.** Unattended restart is out of scope for v0.1, and this
-  availability cost is accepted as part of the no-unseal-ceremony position — R21
-  rules out every unattended terminus short of an OS secret-storage facility,
-  which v0.1 does not assume.
+- **Server restart key delivery:** v0.1 supports two R21-compliant termini for
+  the `age` identity and checkpoint signing key: (1) operator-attended supply
+  at start, and (2) an OS secret-storage facility path — specifically reading
+  from a configured credentials directory (systemd `LoadCredential` /
+  `LoadCredentialEncrypted` layout). v0.1 does not implement a custom unseal
+  ceremony or network KMS client. Hosts without OS secret storage keep the
+  attended path; the availability cost of attended mode is accepted, not
+  required for every deployment.
```

---

## P3 — Performance & capacity honesty

### 16. Explicit throughput and concurrency model

**Problem.** The plan never states what “single-node nonprofit” means for
concurrency. Combined with KTD8 (every read audits = every read writes), surprise
contention is likely.

**Rationale.** Write the contract so implementers don’t add secret caches or
async audit “to go faster.”

```diff
+### Performance and capacity assumptions (v0.1)
+
+- **Target load:** tens of concurrent clients, hundreds of requests/sec peak
+  is more than enough; optimize for correctness and fail-closed behavior, not
+  multi-tenant SaaS throughput.
+- **redb:** concurrent readers for pure data inspection; audited operations
+  serialize on the write path for the audit (and mutation) commit (KTD8).
+- **No plaintext secret cache** across requests. Metadata (version numbers,
+  ages, custom_metadata) may be read without decrypting value blobs.
+- **Token verify** is O(1) keyed-hash verify (KTD5), not Argon2.
+- **AppRole login** remains Argon2-bound; rely on R27 rate limits.
+- **Age decrypt** is per successful authorized read of a value; acceptable at
+  target load. Do not batch-decrypt the store into memory at boot.
```

---

### 17. Authenticated path limits (extend R27)

**Problem.** R27 only rate-limits **unauthenticated** surfaces. A stolen token
(or buggy client loop) can still hammer decrypt + audit writes.

**Rationale.** Global max concurrent requests + per-identity rate limit on
authenticated routes. Still ops-light (tower middleware).

```diff
-- R27. Unauthenticated surfaces enforce request-size and attempt-rate limits,
-  and audit-log capacity is monitored with a documented fail-closed response
-  before storage exhaustion.
+- R27. Unauthenticated surfaces enforce request-size and attempt-rate limits.
+  Authenticated surfaces enforce request-size limits, a global concurrency
+  cap, and per-identity attempt-rate limits sufficient to bound decrypt+audit
+  write amplification. Audit-log / disk capacity is monitored with a
+  documented fail-closed response before storage exhaustion.
```

---

### 18. Backup = redb consistent snapshot API

**Problem.** “Crash-consistent snapshot while the server runs” needs a concrete
redb mechanism (database snapshot/copy under read lock), not hand-wavy file copy
of a live B-tree.

**Rationale.** U10 approach should name the API strategy: use redb’s
snapshot/consistent read view (or brief write barrier + file copy of a single
COW-friendly state), never `cp` a dirty file. Test concurrent writes during
backup remains.

```diff
-- **Approach:** `backup` produces an encrypted, crash-consistent snapshot of the
-  redb store and audit log while the server runs; `restore` reconstructs onto a
-  fresh host. The audit chain verifies against the last off-host checkpoint
-  after restore.
+- **Approach:** `backup` opens a redb consistent snapshot (single DB file per
+  KTD8 — secrets + audit), streams it into an age-encrypted archive under the
+  server recipient (or a backup-specific recipient documented in operating.md),
+  and records the latest audit sequence in the archive manifest. No raw `cp`
+  of a live data file. `restore` writes a new data dir, sets lifecycle
+  appropriately (KTD9), and verifies the audit chain against the last off-host
+  checkpoint after restore. Identity keys are out-of-band (R32).
```

---

## P4 — What not to pull into v0.1 (and why)

These remain good **post-v0.1** work. Pulling them now would fight the ops-light
wedge:

| Idea | Why wait |
|------|----------|
| Full rotation campaigns + signed closeout | Needs status query (#12) first; state machine can wait |
| Drift detector (hash of secret values) | High product value; new threat model (hash oracle / low-entropy brute force) needs design |
| Canaries + webhooks | Detection layer; needs outbound networking story |
| Exec-hook rotators | Crosses “server records but does not perform” line deliberately |
| OIDC/JWT auth | Expands R31; do after AppRole is solid |
| Embedded `vault` CLI shim | Best BUSL escape; large compat surface — after U11 pins real CLI behavior |
| Watch-and-run process supervisor | Great cutover closer; separate client concern |
| Declarative plan/apply | Excellent ops; needs stable management API first |
| TUI cockpit | After queries exist |
| Consumer truth graph / importers | User already deferred pre-migration inventory; keep that call unless they reopen it |

**Exception:** the three “low-cost accommodations” from the rotation-first ideas
doc **should** enter v0.1 as KTD10/KTD11 + R13 version field (changes #11, #13,
#14). That is planning discipline, not feature greed.

Sources for deferred ideas (not re-litigated here):

- `docs/ideas/2026-07-15-001-feature-ideas-top-10.md`
- `docs/ideas/2026-07-15-002-rotation-first-feature-ideas-top-10.md`

---

## Sequencing adjustments

```diff
 ### Sequencing
 
-U1 → U2 form the foundation. U3 → U4 → U5 build the request path; U6 (audit)
-lands alongside U5 because R26 requires audit wiring before any handler can be
-considered done. U7–U10 layer on the working core. U11 (compat harness) runs
-continuously once U5 exists but is only complete when every acceptance example
-passes. See the Unit Index for the dependency graph.
+U1 → U2 form the foundation (store format + lifecycle meta: KTD9, KTD11).
+U6 (audit tables + chain in the same DB, KTD8) lands **before** U5 handlers are
+considered done — R26/KTD8 make audit a storage concern, not a late addon.
+Recommended order: U1 → U2 → U6 → U3 → U4 → U5, with U9 parallel to U4/U5 after
+U1. U7 builds on versioned audit events (R13). U8 offline-only after U2.
+U10 after U2+U6. U11 continuous once U5 exists. U12 last.
```

Unit index dependency tweak:

```diff
-| U5   | Vault KV v2 API surface                    | ... | U2, U4     |
-| U6   | Tamper-evident audit log                   | ... | U1         |
+| U5   | Vault KV v2 API surface                    | ... | U2, U4, U6 |
+| U6   | Tamper-evident audit log                   | ... | U1, U2     |
```

---

## New / adjusted acceptance examples

```diff
+### AE9. Token verify is not Argon2-bound
+  - **Covers KTD5, R9.**
+  - **Given:** A valid token and N sequential authenticated reads.
+  - **When:** Each read is authorized.
+  - **Then:** Authorization does not invoke Argon2; secret_id login still does.
+    (Implementation test: injectable verifier counters / trait marks.)
+
+### AE10. Audit-commit failure returns no secret
+  - **Covers R26, KTD8.**
+  - **Given:** A readable secret and a fault-injected audit commit failure.
+  - **When:** A client reads the secret.
+  - **Then:** The response is an error and the body contains no secret bytes.
+
+### AE11. Rotation status observes version adoption
+  - **Covers R10, R13, R33, F4.**
+  - **Given:** Two identities with read scope; operator writes a new version.
+  - **When:** Only one identity reads after the write.
+  - **Then:** Rotation status shows one on-current and one silent-since-write.
```

---

## Implementation readiness hygiene

Small plan fixes that reduce thrash:

1. **Pick a license** (MPL-2.0 aligns with OpenBao research note; Apache-2.0 is fine too) — stop saying “e.g.”
2. **Name pinned CLI versions** in U11 (e.g. `vault` 1.15.x + 1.17.x, `bao` 2.x) — “pinned” without pins is not a gate.
3. **Name default mount** (`secret/` or `kv/`) and document it for fnox/`VAULT_ADDR` examples.
4. **IPv6 loopback** (`::1`) counts as loopback for plaintext allowance in U9.
5. **Error shape fixture corpus** in `tests/fixtures/vault-cli/` captured once from real CLI — U5 already implies this; make it a first-class artifact.
6. **`deny.toml` + MSRV** stated in U1 (e.g. stable - 2).

```diff
+- KTD12. **Default KV mount path is `secret/`** (Vault historical default).
+  Mount discovery reports it as KV v2. Documented in README; configurable later
+  if needed, not required for v0.1.
+- KTD13. **License: MPL-2.0** (entire tree, no `ee/`). Matches the OpenBao
+  research note's "rotation in core" ethos and R19.
+- KTD14. **Compat matrix (initial):** HashiCorp `vault` CLI 1.15.x and 1.17.x;
+  OpenBao `bao` CLI 2.x. Exact patch pins live in CI and `docs/operating.md`.
```

---

## Cross-cutting theme notes (for future incorporation)

### R26 + redb write path coupling

Every secret read that is audited becomes a redb write under KTD8. Options
considered and rejected for v0.1:

- Separate audit file + fsync — reintroduces crash windows between domains.
- Async audit queue — violates R26.
- Group commit batching — possible later optimization; must still fail-closed
  before response if the batch cannot commit.

v0.1 accepts serialization on the audited write path as the single-node
throughput ceiling.

### Token verification performance

Argon2 for bootstrap/`secret_id` is correct. Per-request token verification must
be fast keyed hash with constant-time compare. This is both a correctness-of-ops
issue (DoS) and a product usability issue (latency).

### Thin tokens and R28

R28 is only true if grants are reloaded every request. Tokens must not snapshot
scopes at issue time. This should be an explicit invariant in U3 tests.

### Checkpoint delivery

R14 without a concrete export path is incomplete. File export + operator copy
is the ops-light v0.1 mechanism; webhooks can supersede later without changing
the signed blob format.

### Rotation product differentiation

The plan’s wedge is “ops-light + rotation pain,” but U7 as written mostly
exposes enumeration + mark-complete. Version-on-audit + thin status query is
the minimum that makes write-is-cutover *observable* without campaign machinery.

### Seams for post-v0.1 (promote into plan as design, not features)

From `docs/ideas/2026-07-15-002-rotation-first-feature-ideas-top-10.md`:

1. Include returned secret version in every successful read audit event.
2. Authorization engine produces structured internal decision explanation.
3. Reserve schema-versioned metadata record per secret.

These are captured above as changes #11, #13, and #14.

---

## Index of proposed changes

| # | Title | Tier | Touches |
|---|--------|------|---------|
| 1 | Split credential hashing (Argon2 vs fast token hash) | P0 | KTD5, U3, U4 |
| 2 | Single durability domain for store + audit | P0 | KTD8, High-level design, U2, U6, U10 |
| 3 | Thin tokens (identity id only) | P0 | U3, R28 tests |
| 4 | Concrete off-host checkpoint export | P0 | KTD4, U6, U12 |
| 5 | CAS, max_versions, custom_metadata, health | P1 | R1, R12, U5 |
| 6 | lookup-self + renew-self | P1 | R31, U4 |
| 7 | Store format version + lifecycle states | P1 | KTD9, U1, U8, U10 |
| 8 | Age identity recovery in backup story | P1 | R32, U10, U12 |
| 9 | Offline-only re-encrypt | P1 | U8 |
| 10 | Clock model documentation | P1 | Assumptions |
| 11 | Version metadata on audit events | P2 | R13, U6 |
| 12 | Thin rotation status query | P2 | U7, optional R33, AE11 |
| 13 | Structured internal authz decisions | P2 | KTD10, U3 |
| 14 | Per-secret metadata record | P2 | KTD11, U2 |
| 15 | systemd-creds key delivery path | P2 | Dependencies, U1, U12 |
| 16 | Performance / capacity assumptions | P3 | Planning Contract |
| 17 | Authenticated path rate/concurrency limits | P3 | R27 |
| 18 | Backup via redb consistent snapshot | P3 | U10 |
| — | Sequencing / unit dependency reorder | — | Sequencing, Unit Index |
| — | AE9–AE11 | — | Acceptance Examples |
| — | KTD12–14 hygiene (mount, license, CLI pins) | — | KTDs, U11, U12 |

---

## Incorporation checklist (empty until decided)

Use this section when selecting what to merge into the canonical plan.

- [ ] #1 KTD5 token hashing split
- [ ] #2 KTD8 single durability domain
- [ ] #3 Thin tokens
- [ ] #4 Concrete checkpoints
- [ ] #5 CAS / max_versions / custom_metadata / health
- [ ] #6 lookup-self / renew-self
- [ ] #7 Format version + lifecycle
- [ ] #8 Identity recovery in R32
- [ ] #9 Offline re-encrypt
- [ ] #10 Clock model
- [ ] #11 Version on audit
- [ ] #12 Rotation status (+ optional R33)
- [ ] #13 KTD10 authz decision struct
- [ ] #14 KTD11 secret metadata record
- [ ] #15 systemd-creds terminus
- [ ] #16 Performance assumptions section
- [ ] #17 R27 authenticated limits
- [ ] #18 Backup snapshot approach
- [ ] Sequencing + unit dependency updates
- [ ] AE9–AE11
- [ ] KTD12–14 hygiene
- [ ] Explicitly defer / reject notes for P4 items

**Incorporation rule of thumb:** edit the plan only after this checklist has
explicit accept/reject marks; do not silently partial-apply diffs from this
file.

---

## Document history

| Date | Note |
|------|------|
| 2026-07-15 | Initial capture of full plan review; not incorporated into source plan. |
