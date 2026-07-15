# Overall assessment

This is already an unusually strong plan. The single-node product thesis is
coherent, the local-only management plane is an excellent architectural
constraint, the authorization model is deliberately small, and the
state-plus-audit atomicity requirement is exactly the sort of invariant that
prevents a security system from gradually becoming “best effort.” The threat
model, restore rehearsal, real-client compatibility harness, and explicit
rejection of daemon-side plugins, egress, and schedulers are also very good
decisions.

After reviewing the complete Product Contract, Planning Contract, R1–R38,
KTD1–KTD14, U0–U12, acceptance examples, and revision history, however, I would
not yet label the plan implementation-ready. Several statements currently
promise guarantees that the specified mechanisms do not fully provide, and a few
workflow descriptions contradict one another.

The most important revisions are:

1. Cryptographically authenticate the clear-text authorization and metadata
   records.
2. put the encrypted keyring inside the transactional store;
3. define a safe, queryable audit index;
4. validate raw request targets before Axum decodes them;
5. put synchronous redb work behind a bounded storage executor;
6. split rotation preparation from cutover;
7. make credential epochs and listener audiences concrete;
8. make clock handling safe against both backward and forward jumps;
9. use a logical backup format and explicit post-rollback audit epochs;
10. narrow the compatibility claim to the tested matrix.

I would preserve the project’s central product positioning and most of its
feature boundaries.

---

# Proposed revisions

## 1. Change the plan from “implementation-ready” to “gated implementation-ready”

**Priority: blocking**

The front matter says `implementation-ready`, and the Goal Capsule says there
are no open blockers. That conflicts with the plan’s own load-bearing proof
gates:

- U0 can change the required API surface.
- U2 can change the storage engine.
- The audit-query representation is not yet defined.
- The backup “snapshot mechanism” is not yet defined.
- The clear-metadata integrity mechanism is missing.
- The keyring’s transactional location is ambiguous.

These are not ordinary implementation details. They affect persistent formats
and security boundaries. Allowing code to proceed broadly before they are frozen
risks building handlers and schemas around assumptions that will later be
invalidated.

U1’s CLI/configuration scaffolding and parts of U9 can still proceed in
parallel. What should be blocked is storage-format freeze and the final
data-plane router.

```diff
 ---
 title: Ops-Light Secrets Server - Plan
 type: feat
 date: 2026-07-15
 topic: ops-light-secrets-server
 artifact_contract: ce-unified-plan/v1
-artifact_readiness: implementation-ready
+artifact_readiness: gated-implementation-ready
 product_contract_source: ce-brainstorm
 execution: code
 ---

@@
-- **Open blockers:** None. Rotation semantics, auth surface, storage, transport,
-  and audit-chain design are settled in the Planning Contract; the two remaining
-  open questions (fnox-native protocol, project name) gate phase 2 and
-  cosmetics, not v0.1. Two internal gates order the work without blocking it: U0
-  (client characterization) freezes fnox and Vault/OpenBao wire evidence before
-  the API router is finalized, and U2's storage spike proves redb can carry the
-  atomic state-plus-audit transaction (KTD8) before higher units build on it.
+- **Blocking design gates:** Four gates must close before the persistent format
+  and final data-plane router are frozen:
+  - G0 — U0 freezes the versioned client contract and client prerequisites.
+  - G1 — U2 proves the storage executor, atomic multi-table commit, crash
+    recovery, logical snapshot, and measured durability envelope.
+  - G2 — U2/U6 freeze the authenticated clear-record format, canonical crypto
+    encoding, audit event schema, and audit query-index format.
+  - G3 — U10 freezes the logical backup format and restore/audit-epoch rules.
+  U1 configuration, CLI scaffolding, and transport work may proceed before these
+  gates; storage-format fixtures, the final API router, and public compatibility
+  claims may not.
```

Also narrow the headline compatibility promise now rather than later:

```diff
-A self-hosted secrets server in Rust — single binary, no platform team — that
-serves the Vault KV v2 API so fnox, and any unmodified Vault client staying
-within the declared KV v2-plus-auth surface (R3), works against it on day one.
+A self-hosted secrets server in Rust — single binary, no platform team — that
+implements a published subset of the Vault KV v2-plus-auth wire protocol so
+the exact fnox, Vault CLI, OpenBao CLI, and library versions in the versioned
+compatibility matrix work without modification. Compatibility outside that
+matrix is best-effort until captured and promoted by contract tests.
```

That wording is still compelling, but it is falsifiable and maintainable.

---

## 2. Add cryptographic integrity for every clear-text structural record

**Priority: blocking security invariant**

R4 says logical paths, identity names, grants, version metadata, and timestamps
are “integrity-covered but stored in the clear.” The plan never defines the
mechanism that provides that integrity.

redb’s transactional and file-integrity properties do not cryptographically
authenticate a grant or identity record against a malicious offline editor.
Without a keyed integrity mechanism, someone who can edit the database but
cannot decrypt secrets could potentially broaden a grant, re-enable an identity,
alter `cas_required`, or roll back rotation metadata. The server would later
open the modified store using the legitimate keyring and might treat the altered
record as valid.

I recommend two layers:

1. Every clear structural record carries a keyed MAC binding it to:
   - store ID;
   - table/record domain;
   - primary key;
   - schema version;
   - record generation;
   - canonical serialized value.

2. Signed checkpoints anchor a deterministic `state_digest` over those
   authenticated records. This detects deletion and rollback through the last
   checkpoint, while per-record MACs detect arbitrary edits and cross-record
   transplantation immediately.

Per-record MACs alone do not detect deletion or replacement with an older,
formerly valid record. The checkpoint state digest and audit-tail reconciliation
close that part of the guarantee.

```diff
@@ R4
-- R4. Secret values and confidential audit payloads are encrypted at rest under
+- R4. Secret values and confidential audit payloads are encrypted at rest under
   purpose-separated record keys that cannot be derived from the storage medium
   alone. Every ciphertext is authenticated against its immutable logical context
   (store, record type, path, version, key id), so valid ciphertext copied to
   another path, version, or store fails authentication rather than decrypting.
   Confidentiality at rest covers exactly that set — secret values, credential
   verifier keys, audit payloads; structural metadata (logical paths, identity
-  names, grants, version numbers and timestamps) is integrity-covered but stored
-  in the clear, a documented offline-theft boundary...
+  names, grants, version numbers and timestamps) is stored in the clear but
+  authenticated with a purpose-separated metadata-integrity key. Every clear
+  record binds its canonical bytes to the store id, table/domain, primary key,
+  schema version, and monotonically increasing record generation. Invalid MACs
+  are fatal to readiness; records are never accepted on a warning-only path.
+  Signed audit checkpoints additionally anchor a deterministic state digest over
+  the authenticated structural records, so removal or rollback is detectable
+  through the anchored sequence. The unanchored tail retains R14's documented
+  live-compromise limitation.

@@ Requirements / Storage and crypto
+- R39. Every security-relevant clear record — identities, grants, credential
+  metadata, secret metadata, rotation state, consumer declarations, schema
+  metadata, and keyring metadata — is encoded canonically and protected by a
+  keyed MAC. Reads verify the MAC before using the record. A MAC failure takes
+  readiness false and prevents data-plane admission. Each signed checkpoint
+  contains a state digest over a consistent snapshot of these authenticated
+  records; `audit verify --state` verifies the anchored state and reconciles
+  post-checkpoint mutations from the audit tail.

@@ KTD3
   `init` generates a compact keyring of independent random symmetric keys —
   record-encryption key (with decrypt-only predecessors after rotation),
-  credential-verifier MAC key, audit-payload key — each with a key id.
+  credential-verifier MAC key, metadata-integrity MAC key, audit-payload key,
+  and audit-index key — each with a key id.

@@ Key Technical Decisions
+- KTD15. **Authenticated clear-state records and checkpointed state roots.**
+  Clear structural records use a fixed binary encoding and a keyed MAC under
+  the metadata-integrity key. The MAC domain includes store id, table id,
+  primary key, schema version, generation, and value bytes. Checkpoint creation
+  computes a deterministic digest over sorted `(table, key, generation, mac)`
+  tuples from one consistent read snapshot and signs that digest together with
+  the audit head. Per-record verification is mandatory on use; full-state
+  verification is performed by `doctor --full`, backup verification, restore,
+  migration, and checkpoint preparation.

@@ U2 test scenarios
+  - Modify an identity, grant, credential record, or secret metadata record
+    directly in the database → the record MAC fails and readiness becomes
+    false.
+  - Copy a valid clear record and MAC to another primary key or store → MAC
+    verification fails.
+  - Roll a record back to an older valid generation → `audit verify --state`
+    fails against the signed checkpoint or reconstructed audit tail.
```

This change is more important than switching AEAD algorithms. Authorization
metadata is part of the trusted computing base.

---

## 3. Store the `age`-encrypted keyring envelope inside redb

**Priority: blocking atomicity correction**

KTD8 says every state mutation and its audit record commit in one storage
transaction. U8’s recipient rewrap appears to update an external keyring file.
An external file replacement cannot be atomically committed with a redb audit
entry.

That creates two crash windows:

- the new keyring envelope is installed but the audit record is absent;
- the audit record commits but the old envelope remains.

It also makes backups, restore activation, and store/keyring mismatch handling
more complicated.

The simplest resolution is to store the opaque `age` ciphertext as a value in a
dedicated redb system table. redb does not need the decrypted keyring to open
the database and retrieve that blob. The decrypted keyring itself should contain
the store ID and keyring generation so the server can reject an envelope
transplanted from another store.

```diff
@@ KTD3
-  The keyring is `age` v0.12-encrypted to the boot-supplied server recipient
-  (and optionally to one documented offline recovery recipient), opened once at
-  boot into `secrecy` types.
+  The keyring plaintext contains the store id, keyring format version, keyring
+  generation, purpose-key records, and recipient metadata. Its `age` ciphertext
+  is stored as one opaque value in the redb `system_keyring` table, not in a
+  sidecar file. At boot the database is opened, the envelope is read, decrypted
+  once into `secrecy` types, and its embedded store id is compared with the
+  clear store id before any other record is accepted.

@@ KTD8
   Mutations ... commit the state change and its audit entry in one multi-table
   write transaction...
+  Keyring-envelope changes are included in this rule. Recipient rewrap,
+  keyring-generation changes, and verification-key changes update the
+  `system_keyring` record and append their audit event in the same redb
+  transaction.

@@ U8 Approach
-  **Recipient rotation** — the routine case — decrypts the keyring under the old
-  identity and atomically rewraps it to the new recipient...
+  **Recipient rotation** — the routine case — decrypts the current
+  `system_keyring` envelope, constructs and verifies the replacement envelope,
+  and commits the new envelope, incremented keyring generation, and audit event
+  in one redb transaction. A crash exposes either the old generation and its
+  old audit head or the new generation and its matching audit event — never a
+  cross-file partial state.

@@ U8 test scenarios
+  - Kill at every point around recipient rewrap commit → after restart, either
+    the old envelope and old audit head or the new envelope and new audit event
+    are present.
+  - Copy a valid keyring envelope into another store → embedded store-id
+    validation rejects it before readiness.
```

I would also add a fixed key-lifecycle table rather than describe “key rotation”
as one generic operation:

```diff
@@ U8 Approach
+  Purpose keys have deliberately different rotation semantics:
+  - secret-record key: offline whole-store re-encryption;
+  - metadata-integrity key: offline rewrite and MAC regeneration;
+  - audit-payload key: forward rotation only, retaining decrypt-only historical
+    keys because rewriting ciphertext would invalidate anchored audit hashes;
+  - audit-index key: rebuild the non-authoritative index from primary events;
+  - credential-verifier key: rotate only together with a credential-epoch
+    increment, invalidating all existing tokens and secret_ids.
```

This prevents a future “rotate all keys” command from making impossible
promises.

---

## 4. Define a query-safe, non-authoritative audit index

**Priority: blocking architecture gap**

The audit payload contains path, identity, accessor, operation, and version, but
KTD4 encrypts that payload and leaves only sequence, time, prior hash, and
ciphertext digest visible. R10 and R33 nevertheless require efficient queries
such as:

- all reads for a path during the lookback window;
- latest read by identity or credential instance;
- version fetched after a particular cutover;
- accessors that disagree.

Without an index, every rotation-status request must scan and decrypt the entire
audit history. At even moderate request volume, that makes rotation status
increasingly expensive and holds the single writer for too long.

A safe index should be an optimization, not a second source of truth:

- Use keyed, domain-separated tags for path, identity, credential instance, and
  event kind.
- Store index rows in the same transaction as the primary audit event.
- Have each row point to the immutable primary event sequence.
- Decrypt and verify the primary event before accepting a candidate.
- Treat missing or corrupt index rows as a fail-closed condition for rotation
  completion.
- Make the index fully rebuildable.

An attacker deleting an index row could cause a false `silent-since-write`,
which blocks completion. They must not be able to add a forged `on-current`
result.

```diff
@@ R13
 - R13. Every read, write, delete, authorization decision...
+  One externally visible operation produces one canonical, schema-versioned
+  audit event containing nested authentication and authorization results rather
+  than an unbounded number of rows for internal matcher steps. Each event has a
+  server-generated event id and request id, audit schema version, identity,
+  credential accessor, optional stable consumer-instance id, auth method,
+  canonical resource, requested capability, operation, outcome, reason code,
+  effective time, wall-clock observation, and served/written version where
+  applicable.

@@ Key Technical Decisions
+- KTD16. **The encrypted audit log has a rebuildable blind query index.**
+  Primary audit events remain the authority and retain KTD4's encrypted
+  payload. In the same transaction, the coordinator writes index rows under
+  keyed, domain-separated tags derived from canonical path, identity id,
+  consumer-instance id, accessor, event type, and time bucket. Index values
+  contain only an encrypted event locator and the minimum bounded query
+  projection.
+
+  Every query candidate is checked against the primary event: decrypt the
+  event, authenticate it, confirm its path/version/actor, and recompute the
+  expected index tags. An index row can therefore never prove adoption by
+  itself. Missing or corrupt index data may under-report observation but may
+  not produce a positive adoption result; `rotation complete` fails closed
+  while the index is unhealthy. `audit index rebuild` recreates the index into
+  a temporary table and atomically swaps it after full verification.

@@ R33
-  ... computed from R13's versioned read events ...
+  ... computed through KTD16's blind index and verified against the underlying
+  authenticated R13 events. Index health is part of the closeout guard; an
+  incomplete or unverifiable index can block completion but can never satisfy
+  it.

@@ U6 Files
-  `src/audit/checkpoint.rs`, ...
+  `src/audit/checkpoint.rs`, `src/audit/index.rs`, ...

@@ U6 test scenarios
+  - Delete an on-current index row → status becomes incomplete or
+    silent-since-write and completion is blocked.
+  - Insert or transplant an index row pointing to an event for another path,
+    identity, or version → primary-event verification rejects it.
+  - Rebuild the index from primary audit events → the same verified query
+    results are produced.
+  - Corrupt the index while leaving the primary chain intact → secret reads
+    remain available, but rotation closeout and audit queries fail closed until
+    rebuild.
```

The index necessarily reveals equality and bucket cardinality among opaque tags
to an offline database holder. That leakage should be added to the metadata
boundary.

---

## 5. Remove the checkpoint private key from the long-running daemon

**Priority: strong security and architectural consistency**

KTD4 currently keeps the checkpoint signing key in the daemon and says the
server “periodically writes” checkpoints. This has two problems:

1. It increases the value of compromising the running process.
2. It conflicts with the product decision that the daemon has no internal
   scheduler.

The daemon only needs the checkpoint public verification keys. The private key
should be loaded by the CLI for the duration of an explicit checkpoint or backup
operation. A systemd timer can invoke that command externally.

Use a three-step operation:

1. `audit checkpoint prepare` asks the daemon to commit a checkpoint-prepared
   event and return a canonical descriptor.
2. The CLI signs the descriptor using a key supplied through an approved
   credential channel and durably writes the checkpoint file.
3. `audit checkpoint register` verifies the signature with the stored public key
   and records the checkpoint digest.

A crash between steps leaves either an unsigned prepared descriptor or a signed
but unregistered file; both are recoverable and visible to `doctor`.

```diff
@@ KTD4
-  **Concrete delivery mechanism:** the server periodically writes a signed
-  checkpoint blob ... The checkpoint signing key is supplied at boot via the
-  same credential channel as the `age` identity, held only in a
-  `secrecy::SecretBox`, never persisted on the host...
+  **Concrete delivery mechanism:** the daemon stores only checkpoint public
+  keys and key-lineage metadata. `audit checkpoint prepare` commits an audited,
+  canonical descriptor containing store id, audit epoch, sequence range, chain
+  head, state digest, timestamp, signing-key id, and previous-checkpoint digest.
+  The local CLI loads the private signing key from an approved credential
+  channel, signs the descriptor, fsyncs the checkpoint file, zeroizes the key,
+  and calls `audit checkpoint register`. Registration verifies the signature
+  and records the checkpoint digest. A systemd timer or operator invokes this
+  command; the daemon has no checkpoint scheduler and never retains the private
+  signing key.

@@ KTD4
+  Checkpoints form their own signed chain through
+  `previous_checkpoint_digest`. Signing-key rotation retains the old public key
+  and records a trust transition; old checkpoints never become unverifiable.
+  Backup manifests use the same external signing flow with a distinct
+  domain-separation label.

@@ R36
-  ... flush, write a final checkpoint, zeroize key material.
+  ... flush, commit a final unsigned chain-head/shutdown event, and zeroize key
+  material. Because the daemon does not possess the checkpoint private key,
+  shutdown does not claim to create an independently anchored checkpoint;
+  `doctor` reports the resulting unanchored tail until the next external
+  checkpoint command.

@@ Assumptions
-  ... approved boot credential channel for the server's `age` identity and the
-  checkpoint signing key ...
+  ... approved boot credential channel for the server's `age` identity. The
+  checkpoint private key is supplied only to explicit CLI checkpoint and
+  backup-signing invocations; it is not a `serve` input.

@@ U12
-  ... tested example units covering `LoadCredential` delivery of the `age`
-  identity and checkpoint signing key...
+  ... a tested service unit covering `LoadCredential` delivery of the active
+  `age` identity, plus a separate timer/service pair that supplies the
+  checkpoint signing key only to the short-lived checkpoint CLI process.
```

This does not protect against a compromised daemon lying about its current head
to the signing process; the threat model already excludes live-process forgery.
It materially reduces private-key exposure and makes the no-scheduler decision
internally consistent.

---

## 6. Validate the raw request target before Axum path extraction

**Priority: blocking authorization boundary**

The plan says every API form is converted to one canonical resource and
ambiguous encodings are rejected. That is correct, but the implementation
approach must account for framework behavior.

Axum’s `Path` extractor automatically percent-decodes path parameters before
handing them to the handler. If authorization begins after that point, the code
may no longer know whether a slash, percent sign, dot segment, or character
arrived literally or through an encoded alias. ([Docs.rs][1])

Add an outer request-target guard that examines the raw URI before route
extraction. It should also reject duplicate security-sensitive JSON keys and
duplicate query parameters, both of which otherwise risk “parser differential”
behavior.

```diff
@@ R8
   The parser rejects rather than normalizes ambiguous forms: encoded
   separators, dot segments, empty middle segments, repeated separators,
   control characters, invalid UTF-8, and double-decoding.
+  This validation runs on the raw HTTP request target before router path
+  extraction or percent-decoding. The raw validator and canonical decoder are
+  one module with one test corpus; handlers never reconstruct a resource from
+  an Axum `Path<String>` value.

@@ KTD9
-  One parser converts every endpoint form to
+  An outer `RawTargetGuard` first validates `Request::uri()` before Axum route
+  extraction. It rejects malformed escapes, percent-encoded separators or
+  backslashes, encoded percent signs that could enable a second decode,
+  encoded or literal dot segments, empty/repeated segments, controls, NUL,
+  overlong targets, duplicate security-sensitive query parameters, and
+  noncanonical alternate encodings. It then performs exactly one decode and
+  constructs an `EndpointRequest` containing the endpoint kind and canonical
+  `Resource`.
+
+  One parser converts every endpoint form to
   `{mount, canonical_segments}` exactly once...
+  The typed request is placed in request extensions and is the only resource
+  representation available to authorization and handlers. The project does not
+  use path-normalization middleware.

@@ KTD9
+  Logical path segments compare byte-for-byte after one validated UTF-8 decode;
+  no Unicode normalization is performed. The supported segment character
+  contract is published and frozen by U0/U11.

@@ U3 Approach
+  JSON request bodies use a duplicate-key-rejecting deserializer. Duplicate
+  `cas`, `data`, `versions`, `role_id`, or `secret_id` keys are errors rather
+  than last-key-wins. Duplicate `version` query parameters and multiple
+  `X-Vault-Token` headers are rejected before authentication.

@@ U3 test scenarios
+  - Send raw HTTP requests containing `%2f`, `%2F`, `%5c`, `%25`, `%2e`,
+    malformed percent sequences, repeated separators, and double-encoded
+    forms → all are rejected before route dispatch.
+  - Send the same logical path using a noncanonical percent encoding → it is
+    rejected rather than authorized as an alias.
+  - Duplicate JSON keys or duplicate `version` parameters → rejected before
+    any state lookup or mutation.
```

The token header should be marked sensitive before the trace layer is installed;
`tower-http` has a dedicated sensitive-header layer for this purpose.
([Docs.rs][2])

```diff
@@ U9 Approach
+  Middleware ordering is security-significant and covered by an integration
+  test: raw-target guard → header-count/size bounds → sensitive-header marking
+  → tracing/request-id → rate/concurrency limits → authentication → handler.
+  `X-Vault-Token` and any future credential-bearing header are marked sensitive
+  before tracing is invoked.
```

---

## 7. Put redb behind a bounded, synchronous storage executor

**Priority: blocking performance and reliability architecture**

redb permits concurrent reads but only one write transaction at a time, and
`begin_write` blocks while another writer is active. ([Docs.rs][3]) Because R26
intentionally turns successful reads into durable writes, nearly every useful
request enters that single-writer path.

Calling redb directly from asynchronous Axum handlers would therefore:

- block Tokio worker threads on synchronous I/O or writer acquisition;
- make overload implicit rather than bounded;
- complicate cancellation and graceful shutdown;
- allow long management queries to starve reads;
- spread database ownership despite the intended transaction coordinator.

Use a dedicated storage executor—preferably one named OS thread initially—that
owns the database and receives typed commands over bounded queues. This makes
the single-writer ceiling explicit and gives the system a natural backpressure
boundary.

redb remains a reasonable candidate: its current project describes the format as
stable and maintained and supports ACID transactions and MVCC. The point of this
revision is to use its concurrency model deliberately, not to replace it
reflexively. ([GitHub][4])

```diff
@@ KTD8
-- KTD8. **One durability domain and one transaction coordinator.**
+- KTD8. **One durability domain, one transaction coordinator, and one bounded
+  storage executor.**
   Secrets, metadata, identities, grants, credentials, rotation records, and the
   audit chain live in one redb database...
+  The redb `Database` is owned by a dedicated blocking storage executor rather
+  than by Tokio request tasks. Routers submit typed coordinator commands over a
+  bounded channel and await typed results. The executor serializes write
+  transactions in an explicit order, performs synchronous database and fsync
+  work, and responds only after commit. No handler, middleware, background task,
+  or application service owns a raw database handle.

@@ KTD8
+  The executor has separate bounded admission lanes: a data-plane lane and a
+  small reserved control/recovery lane. Queue saturation rejects new data-plane
+  work before decryption with a stable overload error and bounded aggregate
+  accounting; checkpoint export, backup, diagnostics, and orderly shutdown
+  retain admission through the reserved lane.

@@ KTD8
+  Cancellation semantics are explicit: cancellation before a command begins
+  prevents execution; after a transaction begins, the coordinator completes or
+  aborts according to the transaction result even if the client disconnects.
+  The audit outcome records committed state, never inferred response delivery.
+  CAS remains the protection against ambiguous client retries.

@@ Performance and Capacity Assumptions
- **Target load:** tens of concurrent clients, low hundreds of requests per
-  second at peak.
+- **Measured envelope:** no throughput number is a release promise until U2's
+  storage spike measures durable operations on the named reference host. The
+  release target is expressed as headroom over the documented expected peak,
+  together with p50/p95/p99 queue and commit latency, rather than an unevidenced
+  request-per-second claim.
+
+- **Batch-ready, not batch-dependent:** the executor protocol may later commit a
+  bounded micro-batch of independently ordered commands in one write
+  transaction, but v0.1 starts with batching disabled. Any batching
+  implementation must preserve per-command linearization, audit ordering,
+  response-after-commit, bounded secret retention, and revocation ordering.

@@ U2 proof gate
-  demonstrate ... multi-table atomic commit, kill-point crash recovery, live
-  consistent snapshot, and the rotation/audit query shapes...
+  demonstrate multi-table atomic commit, kill-point crash recovery, bounded
+  executor backpressure, queue saturation behavior, a logical consistent
+  snapshot, rotation/audit index query latency, file growth and compaction
+  behavior, and durable commit latency on the named low-cost reference host.
+  The gate records quantitative pass/fail thresholds before higher units begin.
```

This is the main performance improvement I would make. It preserves the security
model rather than weakening read auditing to gain throughput.

---

## 8. Split rotation into `begin` and `cutover`, and use stable consumer-instance IDs

**Priority: blocking workflow correction**

The current plan has a direct contradiction:

- F4 says the operator starts a rotation, then mints the new value upstream,
  then writes it.
- R11 and U7 say starting the rotation atomically writes the target version.

The new credential cannot be written before it exists.

The minimal robust state machine is:

1. `prepared`: snapshot consumers, prior version, and expected CAS; do not write
   a secret.
2. `cutover`: accept the new value via stdin/FD and atomically CAS-write it with
   the rotation transition.
3. `completed`: close after verified adoption and upstream-revocation
   attestation.
4. `cancelled-before-cutover`: safe cancellation with no value change.
5. `superseded`: another write made the target non-current.

After cutover, “abort” is misleading. Recovery should be an explicit
copy-forward rollback creating another higher version.

The current accessor-level guard also needs a stable unit. Short-lived AppRole
tokens create changing accessors; requiring every historical accessor to read
the new version can block completion forever. Add a stable
`consumer_instance_id` to credential issuance. AppRole tokens inherit it from
the secret_id. Accessors remain useful diagnostics, but the completion guard
operates on declared consumers and stable instances.

Finally, rotation interval is server policy and should not live in
client-writable KV `custom_metadata`.

```diff
@@ F4
-  - **Steps:** The operator enumerates the secret's consumers ... starts a
-    rotation, which snapshots that consumer set; mints the new value ...
-    writes it to the server with check-and-set...
+  - **Steps:** The operator enumerates the secret's consumers and runs
+    `rotation begin`, which snapshots the declared, authorized, and active
+    consumer-instance sets together with the current version and expected CAS
+    but does not modify the secret. The operator mints the new value upstream
+    and runs `rotation cutover`, supplying the value through stdin or an
+    inherited descriptor; the server atomically validates the saved CAS,
+    writes the new version, records the target version and cutover time, and
+    appends the audit event. Status and closeout operate only after cutover.

@@ R11
-  Starting a rotation snapshots the consumer set and writes the target version
-  atomically...
+  `rotation begin` snapshots the consumer set and expected current version
+  without writing a secret. `rotation cutover` writes the target version and
+  transitions `prepared → cutover` atomically under the saved CAS. A CAS
+  conflict leaves the rotation prepared and requires an explicit refresh,
+  cancellation, or restart; it never silently changes the snapshot.
+
+  Cancellation is permitted only before cutover. After cutover, recovery uses
+  an explicit copy-forward rollback into a new version. A superseding write
+  marks the rotation `superseded` and prevents completion.

@@ R29
   `max_versions` bound retained history; retention never destroys the prior
   version of a rotation that has not been marked complete...
+  A protected prior version may temporarily cause the path to exceed
+  `max_versions`. Metadata and `doctor` report
+  `retention_deferred_by_rotation`; closeout, cancellation, or supersession
+  immediately re-evaluates pruning.

@@ R33
-  ... at identity granularity and, where R13 recorded distinct credential
-  accessors, at accessor granularity as well...
+  ... at declared-consumer, identity, and stable consumer-instance granularity.
+  Credential accessors remain a diagnostic drill-down, not the durable identity
+  of a replica. Tokens issued through AppRole inherit the
+  `consumer_instance_id` of the secret_id that created them. Workload
+  secret_ids require an instance id unless the operator explicitly accepts
+  identity-only tracking.
+
+  The closeout guard is evaluated over the rotation snapshot's declared
+  consumers and active consumer instances. Expired or revoked instances are
+  labeled `retired-without-proof`; they do not silently disappear and require a
+  recorded retirement reason or the existing unverified-consumer override.

@@ R12
-  ... per-secret rotation interval stored in KV v2 `custom_metadata` under a
-  documented key...
+  ... per-secret rotation interval stored in server-owned rotation metadata and
+  writable only through the local control plane. Vault `custom_metadata`
+  remains client-owned compatibility data and cannot alter rotation policy.
+  The control-plane view may project the interval alongside custom metadata,
+  but the remote metadata endpoint cannot overwrite or delete it.

@@ KTD5
+  Credentials may carry an optional stable `consumer_instance_id`; workload
+  secret_ids normally require one, and tokens minted from a secret_id inherit
+  it. It is non-secret metadata, MAC-authenticated under R39, and recorded in
+  audit events.

@@ U7
-  `rotation start` snapshots the consumer set, prior version, actor, and time,
-  and writes the target version atomically...
+  `rotation begin` creates a prepared record with snapshot and expected CAS.
+  `rotation cutover` accepts the bounded secret object through an approved
+  input channel and atomically performs the CAS write plus state transition.
+  States are `prepared | cutover | completed | cancelled-before-cutover |
+  superseded`; there is no post-cutover `aborted` state.
```

This remains much smaller than a campaign engine while making the actual
operator workflow internally consistent.

---

## 9. Pull a minimal declared-consumer registry into v0.1

**Priority: strongest product improvement**

I recommend reversing the earlier decision to defer the entire consumer
registry.

The project’s primary problem is that operators do not know every consumer of a
shared key. R10 can show only:

- who is currently authorized;
- who has already read through this server.

Before migration is complete, neither list identifies consumers still using
`.env`, 1Password, or another vault. The plan explicitly acknowledges that the
rotation view becomes trustworthy only after all known consumers are migrated.
That leaves the first migration—and therefore the first safe rotation—without a
system of record.

The answer does not need to be importers, scanning, a graph database, or a
discovery engine. Add only a small, manually managed, local-control-plane
registry:

- consumer ID;
- secret path;
- owner;
- environment;
- source/system;
- optional identity;
- optional stable consumer-instance ID;
- status;
- last verified time;
- non-secret note.

The consumer view then exposes three explicitly distinct sets:

- **declared** — what the team says should consume it;
- **authorized** — what grants permit;
- **observed** — what audit proves fetched it.

That triad makes the product useful before migration instead of only afterward.

```diff
@@ Requirements / Rotation
+- R40. The local control plane maintains a minimal declared-consumer registry.
+  A record contains a stable consumer id, canonical secret resource, owner,
+  environment, source, optional identity id, optional consumer-instance id,
+  lifecycle status, and last-verified time. It never contains a secret value,
+  command, script, webhook, or executable configuration.
+
+  Consumer views always report three separately labeled sets:
+  - declared — registry records;
+  - authorized — identities whose current grants allow read;
+  - observed — verified audit reads inside the lookback window.
+
+  Reconciliation reports declared-but-unauthorized, authorized-but-undeclared,
+  declared-but-unobserved, and observed-but-undeclared states. Rotation
+  snapshots use the union of declared and authorized consumers, with observed
+  data as evidence. An unresolved declared consumer blocks closeout unless
+  covered by the audited override.

@@ Scope Boundaries / first post-v0.1 package
-- The first post-v0.1 package (v0.2): the consumer truth graph plus migration
-  tooling. Small declared-consumer records ...
+- The first post-v0.1 package (v0.2): automated discovery, import, and richer
+  reconciliation tooling. The fixed-schema manual declared-consumer registry
+  ships in v0.1 under R40; `.env`, fnox, Vault/OpenBao discovery, import
+  manifests, and reuse of fnox scanning machinery remain v0.2.

@@ Unit Index
-| U7 | Rotation surfaces | `src/rotation.rs`, `src/api/kv.rs` | U5, U6 |
+| U7 | Consumers and rotation surfaces | `src/consumer.rs`, `src/rotation.rs`, `src/api/kv.rs` | U5, U6 |

@@ Acceptance Examples
+- AE13. Pre-migration consumer reconciliation
+  - **Covers R10, R40.**
+  - **Given:** A declared Canvas integration that has not yet received a server
+    identity, one authorized workload that has never read, and one observed but
+    undeclared developer identity.
+  - **When:** The operator opens the consumer view and begins a rotation.
+  - **Then:** All three facts remain separately visible; none is collapsed into
+    “the consumer list,” and the unmigrated declared integration is included in
+    the rotation snapshot and blocks unqualified completion.
```

This is a modest amount of CRUD and reconciliation logic, but it closes the
biggest gap between the product story and the v0.1 feature set.

---

## 10. Make credential epoch, credential audience, and local peer identity explicit

**Priority: blocking authentication detail**

R32 says restore opens a new credential epoch, but KTD5 does not say how the
epoch participates in verification. R17 also says the first management
credential is never accepted remotely, yet the token model does not define a
listener audience.

Add both directly to the verifier domain:

```text
MAC(
  credential-domain-v1,
  store_id,
  credential_kind,
  audience,
  accessor,
  issue_epoch,
  secret_bytes
)
```

Credential records should carry `issue_epoch`, and the store should carry
`current_credential_epoch`. Validation rejects a noncurrent epoch before
authorization.

Define listener audiences:

- `control`: local management socket only;
- `data`: remote Vault-compatible listener only.

The first administrator credential is control-only. AppRole tokens are
data-only. An operator may issue separate credentials to the same identity when
both uses are required.

Because the project already depends on a Linux Unix socket, add kernel
peer-credential verification. Linux’s `SO_PEERCRED` returns the credentials of
the process connected to a Unix-domain socket. Socket permissions, peer UID, and
a control credential then become three independent checks. ([man7.org][5])

```diff
@@ R24
   Each credential carries a public accessor that selects exactly one record...
+  Every credential also carries a fixed credential kind, listener audience
+  (`control` or `data`), and issue epoch. The keyed verifier domain includes
+  store id, kind, audience, accessor, issue epoch, and secret bytes so a token
+  cannot be reinterpreted as a secret_id, used on the wrong listener, replayed
+  into another store, or survive an epoch change.

@@ R17
-  The first management credential ... never accepted by the remote listener.
+  The first management credential has audience `control`, a short bootstrap
+  TTL, and is cryptographically rejected by the data-plane authenticator before
+  grant evaluation. It cannot be converted into a data-plane token.

@@ R31
+  AppRole secret_ids and the tokens they mint have audience `data`. The
+  Vault-compatible listener accepts only data-audience tokens. The control
+  socket accepts only control-audience credentials.

@@ R32
-  ... opens a new credential epoch that invalidates all pre-restore tokens and
-  secret_ids by default.
+  ... atomically increments `current_credential_epoch`. Every restored
+  credential record retains its original `issue_epoch`, so all pre-restore
+  tokens and secret_ids fail epoch validation even when their verifier and TTL
+  would otherwise be valid.

@@ R34
   ... owner-restricted local control socket (still authenticated and audited)...
+  On Linux, each accepted control connection must also have a kernel-reported
+  peer uid equal to the configured service owner or an explicitly allowed
+  administrative uid. Socket mode bits, `SO_PEERCRED`, and the control
+  credential are all required; none substitutes for another.

@@ KTD5
-  Tokens and AppRole secret_ids are `<kind>.<accessor>.<secret>`...
+  Credentials use a canonical fixed-length base64url-no-padding encoding:
+  `<kind>.<audience>.<accessor>.<secret>`. Noncanonical encodings are rejected.
+  The verifier MAC includes the store id and current credential epoch as
+  described in R24. Unknown accessors execute the same MAC path against a
+  fixed dummy record with the parsed kind, audience, and epoch.

@@ Operations
+- `credential epoch rotate --reason <...>` ships in v0.1 as a local incident
+  command. It increments the epoch, generates a new credential-verifier key,
+  invalidates all tokens and secret_ids, and creates a replacement emergency
+  control credential using R17's disclosure-before-commit ordering.

@@ U4 tests
+  - A valid control token presented to the data listener → rejected before
+    authorization.
+  - A valid data token presented to the control socket → rejected.
+  - A credential copied into another store → verifier failure.
+  - Epoch increment under concurrent requests → requests linearized afterward
+    reject every old token and secret_id.
+  - Control request from a disallowed Unix peer uid → rejected and audited.
```

Moving the global epoch command from v0.3 into v0.1 is low incremental
complexity because restore already requires the primitive. It dramatically
improves incident response.

---

## 11. Protect the clock high-water mark from forward-jump poisoning

**Priority: blocking availability edge case**

The plan correctly handles clock rollback but says a fast-forward clock merely
expires tokens early. Because the future time becomes the persisted high-water
mark, a large accidental forward jump can also make every later restart fail
until real time catches up. That is a durable availability failure.

Track runtime wall time against a monotonic anchor. A forward step beyond
tolerance must not be silently accepted or persisted. It should stop new
admission and require a local decision.

For an already-poisoned store, provide an offline repair operation. Since
resetting the high-water mark weakens confidence in all absolute expirations,
repair should increment the credential epoch and invalidate bearer credentials.

```diff
@@ R18
   Unsafe configurations include ... a wall clock behind the store's persisted
   time high-water mark beyond the documented tolerance...
+  Startup also refuses a persisted high-water mark implausibly ahead of the
+  current clock unless `clock repair` is performed. During service, a forward
+  or backward wall-clock step beyond tolerance takes readiness false before the
+  anomalous value is persisted.

@@ Assumptions / Clock model
-  effective time never moves backward while the server runs...
-  A fast-forward clock expires tokens early — inconvenient but fail-safe...
+  At startup the server records a `(wall_clock, monotonic_clock)` anchor.
+  Effective time advances from the monotonic clock while periodically checking
+  wall-clock agreement. Small drift is reconciled within the documented
+  tolerance. A backward or forward discontinuity beyond tolerance stops
+  data-plane admission and requires an audited local override; the anomalous
+  observation is not written as the new high-water mark automatically.
+
+  `clock repair` is an offline recovery operation for a persisted mark that is
+  known to be wrong. It requires an exact old mark, a replacement time, and an
+  audited reason; it increments the credential epoch before the store returns
+  to `ready`, because prior TTL conclusions can no longer be trusted.

@@ U1 test scenarios
+  - Advance the runtime wall clock far into the future while monotonic time
+    advances normally → readiness becomes false and the future observation is
+    not persisted as the new high-water mark.
+  - Restart after an intentionally injected poisoned future mark → startup
+    refuses; `clock repair` resets the mark, increments the credential epoch,
+    and old credentials remain invalid.
```

This keeps the useful fail-closed property without turning an NTP or
virtualization error into a long-lived lockout.

---

## 12. Prefer XChaCha20-Poly1305 and freeze a canonical crypto encoding

**Priority: strong recommendation**

The current AES-GCM design is defensible if nonce discipline is implemented
perfectly, but it introduces a security-critical operation counter, warning
threshold, and full-key rotation remedy solely to manage a 96-bit random-nonce
budget.

For this project, I would use XChaCha20-Poly1305:

- 192-bit random nonces make accidental random collision negligible at this
  scale;
- it avoids a security-critical persisted nonce allocator or budget counter;
- the current RustCrypto crate documents the extended 192-bit nonce variant and
  reports an NCC Group audit with no significant findings. ([Docs.rs][6])

AES-GCM-SIV is attractive for misuse resistance, but the current RustCrypto
crate explicitly states that the crate itself has not been security-audited.
([Docs.rs][7])

The more important companion change is to freeze an unambiguous binary record
header and AAD format. Concatenated strings are not an acceptable crypto format
because boundaries can become ambiguous across future schema changes.

```diff
@@ KTD3
-  Stored records are AEAD-encrypted (`aes-gcm`, already in the fnox stack)...
+  Stored records use `XChaCha20Poly1305` with a randomly generated 192-bit
+  nonce for every encryption. Cipher choice is identified by a fixed
+  `cipher_suite_id` in the record header but is not operator-configurable.
+  Adding another suite requires a storage-format migration, not a configuration
+  toggle.

@@ KTD3
-  **Nonce lifecycle** ... every AEAD encryption draws a fresh 96-bit CSPRNG
-  nonce ... per-key encryption bound ... persisted per-key-id operation counter
-  surfaced by `doctor`...
+  **Nonce lifecycle:** every encryption draws a fresh 192-bit CSPRNG nonce and
+  stores it in the record header. Rewrites and re-encryption always request a
+  new nonce. The keyring may retain an informational per-key operation count,
+  but correctness and readiness do not depend on a collision-budget counter.
+  Deterministic nonce derivation remains prohibited.

@@ KTD3
+  **Canonical cryptographic encoding:** record headers and AEAD associated data
+  use a fixed binary format with magic bytes, format version, cipher-suite id,
+  store UUID, record-domain id, key id, length-prefixed mount and canonical path
+  segments, logical record id, and secret version where applicable. No JSON,
+  debug formatting, string concatenation, platform endianness, or map iteration
+  order enters an authenticated encoding. Checked-in test vectors freeze the
+  encoding across releases.

@@ U2 Approach
-  ... persisted per-key-id operation counter tracking KTD3's documented bound.
-  ... one-time misuse-resistant-AEAD evaluation...
+  ... checked-in cross-version crypto fixtures and canonical AAD test vectors.
+  The storage spike records XChaCha software performance on the supported
+  targets; no configurable cipher negotiation is added.

@@ U2 tests
-  - Property test: nonces are unique across writes...
-  - The per-key-id encryption counter increments...
+  - Inject a deterministic test RNG and prove every encryption path requests a
+    fresh nonce rather than reusing a stored or derived value.
+  - Fixed record-header and AAD vectors decode identically across supported
+    architectures and reject altered lengths, domains, paths, versions, and key
+    ids.
```

This recommendation assumes the product does not need a FIPS-approved at-rest
primitive. If that requirement appears later, it should trigger an explicit
crypto-format decision rather than an informal cipher swap.

---

## 13. Define backups as a logical archive, and start a new audit epoch after rollback recovery

**Priority: blocking recovery architecture**

U10 says backup uses a “consistent snapshot of the single redb file,” but does
not specify whether that means a redb-supported backup primitive, a
copy-on-write filesystem snapshot, or serialization from a read transaction.

Use a logical, application-owned archive produced from one consistent redb read
transaction. redb permits read transactions concurrently with a writer, which
supports this design without copying a live database file. ([Docs.rs][3])

A logical archive offers several advantages:

- independent verification of every record;
- stable format across redb file-format changes;
- restore into a fresh database rather than trusting copied pages;
- easier schema migrations;
- explicit table counts and coverage;
- no dependence on filesystem-specific snapshot behavior.

The plan also needs explicit audit semantics when restoring a backup older than
the latest off-host checkpoint. The resulting history is a fork, not a
continuation. Starting a new `audit_epoch` makes that fact permanent and
verifiable.

```diff
@@ R32
-  The backup archive carries a manifest ... and never contains the private
-  `age` identity...
+  The backup is an application-level logical archive generated from one
+  consistent read transaction. It contains versioned canonical frames for each
+  table, encrypted record bytes unchanged, authenticated clear-record bytes,
+  the current keyring envelope, audit events or archived-segment manifests,
+  per-table counts and digests, and a signed manifest. It never copies the live
+  redb file as its normative format and never contains a private identity.

@@ R32
+  Backup creation rewraps a recovery copy of the keyring to the configured
+  backup recipients and records their non-secret recipient fingerprints in the
+  manifest. A fresh-host restore therefore needs the archive recipient identity
+  and can rewrap the recovered keyring to a new live server recipient before
+  activation; it does not require possession of the failed host's active
+  identity.

@@ R32
-  Restore targets an empty directory, verifies archive integrity...
+  Restore constructs a new redb database in a temporary sibling directory,
+  verifies every frame, record MAC, ciphertext, audit relationship, schema, and
+  count, fsyncs the database and directory, and atomically installs it into the
+  empty target only after all verification succeeds.

@@ R32
-  Restore whose chain head predates the supplied checkpoint ... explicit
-  disaster-recovery flag records the rollback and proceeds...
+  A restore whose audit head predates a supplied independently retained
+  checkpoint is a rollback recovery. It requires an explicit local
+  `--start-recovery-epoch` flag and reason, increments both the credential epoch
+  and audit epoch, and creates a first event containing the restored head,
+  missing anchored range, supplied checkpoint digest, archive digest, actor,
+  and reason. Future checkpoints identify the new epoch. Verification reports
+  the historical anchored epoch and recovery fork separately; it never presents
+  the chain as continuous.

@@ Key Technical Decisions
+- KTD17. **Logical backup format and explicit recovery epochs.** The backup
+  format is owned by the application and versioned independently from redb.
+  Restore always builds a new database. Normal restore continues the existing
+  audit epoch only when its head is consistent with the supplied checkpoint
+  set; rollback recovery creates a new audit epoch and credential epoch.

@@ U10 tests
+  - Upgrade redb while keeping the logical archive version supported → restore
+    succeeds into the new redb version without opening an old database file.
+  - Restore an archive behind the newest checkpoint without
+    `--start-recovery-epoch` → refused.
+  - Perform the explicit recovery → verifier reports the old anchored history,
+    missing range, and new audit epoch rather than a continuous chain.
```

This also makes the release requirement to restore older fixtures much more
sustainable.

---

## 14. Refresh the compatibility matrix and resolve the `vault`-binary dependency as a release gate

**Priority: blocking product-contract accuracy**

As of July 15, 2026:

- HashiCorp’s current Vault line is 2.0.x, with 2.0.3 released June 17, 2026.
  ([HashiCorp Developer][8])
- OpenBao 2.6.0 was released July 14, 2026. ([GitHub][9])
- fnox 1.30.0 was released July 9, 2026. ([GitHub][10])

The plan’s explicit Vault 1.15.x and 1.17.x lanes should therefore not be the
default modern matrix unless an actual deployed consumer requires them.

The current fnox source still launches `vault`, supplies `VAULT_ADDR` and
`VAULT_TOKEN`, runs `vault kv get -field=...`, and uses `vault status` for
connection testing. ([GitHub][11]) That validates the importance of U0 and means
the clean-host story still has a BUSL-licensed client dependency unless fnox
changes or the project supplies a narrow shim.

I would make that an explicit release gate rather than a conditional footnote.

The exact KV surface must also resolve the remote full-delete conflict.
OpenBao’s KV v2 API includes `DELETE /:mount/metadata/:path`, which permanently
removes all versions and metadata. ([OpenBao][12]) The plan simultaneously
requires an audited reason and explicit confirmation, neither of which an
unmodified Vault client necessarily supplies. For v0.1, I recommend keeping full
purge local-only and declaring the remote endpoint unsupported.

```diff
@@ KTD14
-- KTD14. **Compatibility matrix (initial):** HashiCorp `vault` CLI 1.15.x and
-  1.17.x, OpenBao `bao` 2.x, and the two most recent fnox releases captured by
-  U0.
+- KTD14. **Compatibility matrix:** U0 regenerates the initial matrix from the
+  latest stable Vault CLI, latest stable OpenBao CLI, and the latest two fnox
+  releases at characterization time. One legacy Vault line is retained only
+  when it represents a documented deployed consumer or captures a materially
+  different request contract. Exact versions, artifact checksums, download
+  provenance, and client prerequisites are committed to CI.

@@ U0 Approach
-  Run each pinned client — the two most recent fnox releases,
-  `vault` 1.15.x/1.17.x, `bao` 2.x...
+  Resolve and pin the current matrix at U0 execution time. Run each client with
+  synthetic canary credentials only, verify the downloaded artifact checksum,
+  and capture both process behavior and normalized wire behavior. The captured
+  contract records the exact `vault` subcommands invoked by fnox as well as the
+  HTTP requests emitted by those CLI versions.

@@ U0 exit gate
+  Clean-host onboarding has an additional release gate:
+  - preferred: an upstream fnox release speaks direct HTTP or accepts an
+    OpenBao-compatible CLI command;
+  - fallback: this project ships a tiny separate `vault` shim implementing only
+    the U0-captured `status` and `kv get -field` behavior.
+  The project may still document installation of HashiCorp Vault CLI, but may
+  not describe the client stack as fully OSI-licensed while that is the only
+  supported path.

@@ R1
+  The normative compatibility artifact is a generated method/path/status/body
+  matrix. Prose summaries never add an endpoint that is absent from the
+  contract tests.

@@ R29
-  full metadata-plus-all-versions deletion additionally requires explicit
-  confirmation and an audited reason.
+  full metadata-plus-all-versions deletion is available only as the local
+  control-plane `secret purge` operation, requiring the dedicated
+  `destroy-all` capability, exact resource, confirmation, and audited reason.
+  `DELETE /v1/:mount/metadata/:path` is explicitly unsupported on the remote
+  listener in v0.1 unless U0 proves it is required by a supported client and a
+  separate safety decision revises this contract.

@@ U5 Approach
-  Errors use `{"errors":[...]}` with Vault status conventions...
+  Status codes, error envelopes, and field-presence rules are generated from
+  the captured/differential compatibility contract. No exact 404 or empty-list
+  behavior is hard-coded in prose before U0/U11 evidence freezes it.
```

This makes the compatibility story stronger because it says exactly what is
guaranteed and gives the project an open client path.

---

## 15. Add a sustainable audit-retention and disk-recovery mechanism

**Priority: strong operational requirement**

The plan has warning and stop-admitting thresholds, but no path that prevents
the audit database from growing forever. Because every read is audited, “fail
closed before disk exhaustion” eventually becomes “the server permanently stops”
unless the operator can archive and reclaim space.

I recommend a segmented logical audit history:

- Active and recent events remain in redb.
- Events are grouped into immutable sequence segments.
- An explicit CLI command exports and verifies a closed encrypted segment.
- A signed checkpoint anchors the segment.
- Only then may a separate prune command replace the hot rows with an
  authenticated segment manifest.
- The retained hot window must always exceed R23’s rotation lookback.
- Full verification uses the archived segment; local verification without it
  reports an anchored archive reference rather than claiming full event
  inspection.
- redb compaction is an offline operation after pruning.

Also implement the “reserved recovery allowance” concretely as a preallocated
reserve file created at init.

```diff
@@ R13
-  ... written to an append-only log...
+  ... written to a logically append-only audit history. Recent events live in
+  the active database; older closed segments may be replaced only by an
+  authenticated archive manifest after the encrypted segment has been exported,
+  verified, independently checkpointed, and passed the retention guard. No
+  event is silently discarded.

@@ R14
+  A closed-segment manifest contains its audit epoch, sequence range,
+  predecessor hash, final hash, event count, encrypted archive digest, state
+  digest where applicable, checkpoint digest, and archive format version.
+  Verification distinguishes:
+  - fully inspected active or supplied archive events;
+  - segments whose integrity is anchored but whose archive was not supplied;
+  - the unanchored active tail.

@@ R23
   R13's audit retention is at least as long as that window.
+  Events and query-index rows inside the consumer-observation window are never
+  eligible for archival pruning. Increasing the lookback first verifies that
+  sufficient active or queryable history exists.

@@ R27
   ... plus a reserved recovery allowance...
+  `init` preallocates a same-filesystem `recovery.reserve` file sized above the
+  documented worst-case checkpoint, archive-registration, diagnostic, and
+  orderly-shutdown transaction. The data plane stops before consuming that
+  allowance. Releasing or recreating the reserve is a local, audited recovery
+  operation; ordinary request handling cannot spend it.

@@ R35
-  lifecycle state (`ready` | `reencrypting` | `restoring`).
+  lifecycle state (`ready` | `reencrypting` | `restoring` | `migrating` |
+  `compacting`).

@@ KTD4
+  Audit storage is segmented by bounded event count or encoded byte size while
+  preserving one global hash sequence per audit epoch. `audit archive` exports
+  a closed segment; `audit archive register` records its verified digest;
+  `audit prune` may replace event and index rows with the segment manifest only
+  after the signed-checkpoint and retention predicates hold.

@@ U6 test scenarios
+  - Fill the active audit area to the stop-admitting threshold → data-plane
+    admission stops while archive, checkpoint registration, diagnostics, and
+    orderly shutdown still succeed using the reserved lane and reserve file.
+  - Attempt to prune an uncheckpointed, unverified, or in-lookback segment →
+    refused.
+  - Archive, register, prune, and compact a closed segment → active disk usage
+    falls, full verification succeeds when the archive is supplied, and local
+    verification accurately reports the archive dependency when it is absent.
```

This is added machinery, but it closes a named disk-exhaustion failure mode and
therefore satisfies the plan’s own complexity budget.

---

## 16. Narrow v0.1 platform support and correct the transport decomposition

**Priority: strong scope reduction**

The plan uses:

- Unix-domain sockets;
- Linux/systemd credential delivery;
- Unix ownership and permission semantics;
- filesystem locks;
- systemd service examples;
- the proposed peer-credential check.

It should say plainly that the v0.1 server is Linux-first rather than imply
general portability.

Also correct KTD1’s crate attribution. Current Axum itself implements its
listener abstraction for `tokio::net::UnixListener`, so the control plane can
use `axum::serve` directly. `axum-server` can remain limited to the TLS data
listener. ([Docs.rs][13]) `axum-server` is a community-maintained project
independent of Axum, so it should not be described as a Tokio-team component.
([GitHub][14])

```diff
@@ Scope Boundaries
+**Supported v0.1 runtime**
+
+- The certified server runtime is Linux on x86_64 and aarch64.
+- The reference deployment is a host service, not a container, using a local
+  ext4 or XFS data directory with working advisory locks and documented
+  fsync/rename behavior.
+- Network filesystems, userspace filesystems, overlay-backed writable data
+  directories, Windows services, and macOS production serving are outside the
+  v0.1 durability contract.
+- The code may compile or run elsewhere, but release claims apply only to the
+  tested platform/filesystem matrix.

@@ KTD1
-- KTD1. **HTTP surface: two `axum` routers in one process.** A remote
-  Vault-compatible data-plane router over rustls (via `axum-server`), and an
-  owner-restricted Unix-socket control-plane router...
+- KTD1. **HTTP surface: two `axum` routers in one process.** The remote
+  Vault-compatible data plane uses the pinned `axum-server`/rustls adapter after
+  U9 proves reload and graceful shutdown. The local control plane binds a
+  `tokio::net::UnixListener` and is served directly with `axum::serve`, which
+  natively supports Unix listeners. Both routers call the same typed services.
+
+  `axum` is Tokio-team maintained; `axum-server` is an independent
+  community-maintained TLS server adapter and is treated as such in dependency
+  review. The plan does not attribute Unix-listener support to `axum-server`.

@@ R38
+  Release artifacts and claims name the supported OS, architecture, filesystem,
+  and deployment mode. Cross-compilation alone does not promote another target
+  into the supported matrix.
```

A narrow, heavily tested Linux support contract is much more professional than
nominal cross-platform support around Unix- and systemd-specific architecture.

---

## 17. Rework sequencing into security, recovery, and rotation milestones

**Priority: execution-plan improvement**

The current “first product milestone” occurs at the first fnox read, before
backup/restore and key operations are complete. That is an excellent vertical
slice, but it must not be confused with a release candidate.

I recommend four explicit milestones:

- **M0 — Contract freeze:** client traces, storage/executor spike, crypto and
  audit formats.
- **M1 — Security kernel:** authenticated read/write/CAS over TLS with
  current-state auth and atomic audit.
- **M2 — Recovery-ready alpha:** backup, full verification, restore, credential
  epoch, key rewrap, fault suite.
- **M3 — Rotation-ready v0.1:** declared consumers, rotation workflow, full
  declared API surface, release integrity and docs.

U1 need not depend on U0. U0 gates the data-plane router, not CLI/configuration
scaffolding.

```diff
@@ Sequencing
-U0 freezes client evidence before the API surface is finalized. U1 → U2 form the
-foundation...
+U0 and U1 begin in parallel. U0 gates the final data-plane router and
+compatibility claims; it does not gate CLI/configuration scaffolding, local
+initialization design, or the control socket. U1 → U2 form the storage
+foundation, with U2 closing G1/G2 before persistent-format fixtures freeze.
+
+Milestones:
+
+- **M0 — Contract freeze:** U0 complete; U2 storage/executor spike passes;
+  authenticated clear-record, crypto-header, audit-event/index, and logical
+  backup formats are reviewed and frozen.
+- **M1 — Security kernel vertical slice:** `init → serve → fnox read/write`
+  over TLS through audience-bound credentials, canonical authorization,
+  authenticated state, atomic audit, and bounded storage admission. This is a
+  development milestone, not a release.
+- **M2 — Recovery-ready alpha:** recipient rewrap, credential-epoch incident
+  operation, logical backup, `backup verify --full`, restore, recovery audit
+  epochs, crash tests, and disk-reserve behavior pass.
+- **M3 — Rotation-ready v0.1:** declared-consumer reconciliation, begin/cutover/
+  closeout rotation, full declared KV surface, current compatibility matrix,
+  published-binary smoke test, documentation, and release attestations pass.

@@ Unit Index
-| U1 ... | ... | U0 |
+| U1 ... | ... | —  |
@@
-| U5 ... | ... | U2, U4, U6 |
+| U5 ... | ... | U0, U2, U4, U6 |

@@ Success Criteria
+  No public v0.1 artifact is described as recovery-ready or suitable for real
+  non-production credentials until M2 passes using the published binary.
+  Production adoption remains separately gated on an independent review of the
+  threat model, cryptographic format, authorization boundary, and recovery
+  evidence.

@@ Definition of Done
-- Every requirement R1–R38...
+- Every requirement R1–R40 and every subsequently adopted requirement...
```

This preserves vertical-slice momentum while preventing an early demo from
becoming an accidentally deployed release.

---

## 18. Move revision history out of the canonical implementation plan

**Priority: maintainability**

The file currently contains the canonical contract, three rounds of revision
narrative, duplicate disposition sections, and historical explanations. That
history is valuable, but keeping it inline makes it harder for an implementer to
distinguish current requirements from superseded reasoning.

Use the current file as the canonical, present-tense contract and move the
history to:

- `docs/plan-history.md`;
- `docs/adr/0001-*.md` through the relevant technical decisions;
- the existing idea-consolidation document.

The KTDs can remain summarized in the plan, with each linking to its ADR.

```diff
@@ Planning Contract
-**Product Contract preservation:** Product Contract changed during planning...
-
-A second 2026-07-15 revision round incorporated...
-
-A third 2026-07-15 revision round integrated...
+**Plan history:** The decision and revision history is retained in
+`docs/plan-history.md`. The contract below is present-tense and canonical.
+Where a historical rationale remains load-bearing, the corresponding KTD links
+to a short ADR under `docs/adr/`.

@@ Deferred / Open Questions
-### From 2026-07-15 review — dispositions
-...
-### From 2026-07-15 idea-consolidation review — dispositions
-...
+Historical review dispositions live in `docs/plan-history.md`. This section
+contains only genuinely deferred work and currently open decisions.
```

This does not change scope, but it materially reduces the chance that
implementation follows superseded prose.

---

# Important smaller corrections

These do not each require a major architectural section, but I would include
them in the patch:

```diff
@@ U0
+  Client recordings use synthetic, high-entropy canary values only. Fixture
+  normalization removes tokens, credential-command output, TLS private
+  material, host paths, usernames, and nondeterministic identifiers before any
+  artifact is committed. The secret-output canary scan covers U0 fixtures.

@@ R26
+  A client disconnect after a transaction has begun does not roll the
+  transaction back merely because the response channel disappeared. The
+  coordinator reaches a deterministic commit/abort result and audits it;
+  clients must use CAS when ambiguous retry behavior matters.

@@ U2 tests
-  - Value buffer is zeroized after use (assert via a wrapper that observes
-    drop).
+  - Secret-owning types implement and invoke zeroization-on-drop; tests verify
+    the wrapper contract and prohibit accidental `Clone`/debug formatting.
+    Tests do not claim to inspect allocator or kernel copies outside R5.

@@ U5
+  A secret version stores one bounded encrypted JSON object, not independently
+  encrypted fields. Limits cover total encoded bytes, field count, field-name
+  length, nesting depth, and list-result cardinality.

@@ U9
+  Reverse-proxy mode is an explicit listener type, not a boolean relaxation.
+  It binds only to a configured Unix socket or loopback address. Forwarded
+  source headers are accepted only from the exact configured proxy peer and
+  from one allowlisted header syntax; otherwise they are ignored. Rate-limit
+  source buckets use the verified proxy-derived source only in this mode.

@@ R36
+  Checkpoint staleness is a warning and closeout limitation, not by itself a
+  data-plane readiness failure. Invalid state MACs, broken audit writes, or
+  exhausted capacity remain readiness failures. This distinction prevents an
+  off-host mirror outage from unnecessarily taking secret reads down.

@@ Verification Contract
+| Clear-state integrity     | record-MAC tamper/transplant/rollback suite; checkpoint state reconciliation                                  | U2, U6; gates R39       |
+| Raw-target parser         | raw HTTP corpus, duplicate-key/query/header tests, parser model                                               | U3; gates R8            |
+| Storage backpressure      | bounded queue saturation, reserved control lane, cancellation semantics                                      | U2, U6                  |
+| Recovery epoch            | rollback restore creates an explicit audit fork and invalidates credentials                                  | U10                     |
+| Consumer reconciliation   | declared/authorized/observed state matrix and rotation snapshot                                               | U7; gates R40           |
```

---

# Decisions I would keep unchanged

I would preserve these parts of the original plan:

- **Single-node as a product boundary.** Adding consensus or HA would
  fundamentally change the product and learning target.
- **Local-only management plane.** This is one of the plan’s best security
  decisions.
- **Fixed capabilities and segment-prefix grants.** No policy language is
  needed.
- **Current-grant reload on every request.** It gives revocation and grant
  reduction clean linearization.
- **Atomic state-plus-audit commit.** Do not trade this away for an asynchronous
  audit queue.
- **No plaintext secret cache across requests.**
- **No daemon-side scripts, webhooks, plugins, outbound adapters, or durable
  scheduler.**
- **AppRole before OIDC.**
- **Logical rather than cryptographic destruction claims.**
- **Restore rehearsal as a standing operational requirement.**
- **Real fnox/Vault/OpenBao binaries plus differential testing.**
- **Release checksums, SBOM, provenance, locked dependencies, and old-format
  restore fixtures.**
- **The honest memory and client-side leakage boundaries.**

# Resulting architecture

With the revisions, the core becomes:

```text
Remote TLS / local Unix socket
            │
            ▼
raw target + bounded parser
            │
            ▼
typed endpoint/resource + audience-bound credential
            │
            ▼
bounded storage executor
            │
            ▼
one redb transaction:
  current authn
  current authz
  authenticated structural records
  secret operation
  canonical encrypted audit event
  blind query-index rows
  commit
            │
            ▼
response released after commit
```

Around that core:

- `age` protects one keyring envelope stored transactionally in redb.
- XChaCha20-Poly1305 protects value and audit payload records.
- MACs protect clear authorization and metadata records.
- Signed checkpoints anchor both audit head and structural-state digest.
- Private signing keys live only in short-lived CLI operations.
- Logical backups are independent of the redb file format.
- Restore rollback creates an explicit audit epoch rather than pretending
  history remained continuous.
- Declared, authorized, and observed consumers make rotation useful before,
  during, and after migration.

That version is more internally consistent, more defensible against offline
tampering, easier to operate under disk and recovery pressure, and more
compelling as a rotation product rather than merely a small Vault-compatible
storage service.

[1]:
  https://docs.rs/axum/latest/axum/extract/struct.Path.html
  "Path in axum::extract - Rust"
[2]:
  https://docs.rs/tower-http/latest/tower_http/sensitive_headers/index.html
  "https://docs.rs/tower-http/latest/tower_http/sensitive_headers/index.html"
[3]:
  https://docs.rs/redb/latest/redb/struct.Database.html
  "Database in redb - Rust"
[4]: https://github.com/cberner/redb "https://github.com/cberner/redb"
[5]:
  https://man7.org/linux/man-pages/man7/unix.7.html
  "https://man7.org/linux/man-pages/man7/unix.7.html"
[6]: https://docs.rs/chacha20poly1305 "chacha20poly1305 - Rust"
[7]: https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/ "aes_gcm_siv - Rust"
[8]:
  https://developer.hashicorp.com/vault/docs/updates/release-notes
  "Release notes - 2.x | Vault | HashiCorp Developer"
[9]:
  https://github.com/openbao/openbao/releases
  "Releases · openbao/openbao · GitHub"
[10]: https://github.com/jdx/fnox/releases "Releases · jdx/fnox · GitHub"
[11]:
  https://github.com/jdx/fnox/blob/main/crates/fnox-core/src/providers/vault.rs
  "fnox/crates/fnox-core/src/providers/vault.rs at main · jdx/fnox · GitHub"
[12]:
  https://openbao.org/api-docs/secret/kv/kv-v2/
  "KV secrets engine - version 2 (API) | OpenBao"
[13]:
  https://docs.rs/axum/latest/axum/serve/trait.Listener.html
  "https://docs.rs/axum/latest/axum/serve/trait.Listener.html"
[14]:
  https://github.com/programatik29/axum-server
  "https://github.com/programatik29/axum-server"
