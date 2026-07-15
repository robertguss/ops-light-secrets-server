# Executive judgment

The plan is already much closer to a **security-conscious v1 design** than a
typical v0.1. It contains a sophisticated authorization model, atomic
state-plus-audit transactions, version-aware rotation tracking, encrypted
backups, restore credential epochs, fault injection, fuzzing, and a local-only
management plane. Adding most of the proposed features now would make the
implementation **less likely to be rock solid**, not more.

Several proposals described as new are already incorporated:

- The rotation cutover tracker is R33/U7.
- `authz explain` is KTD10/U12.
- The extensible per-secret metadata seam is KTD11.
- systemd credential loading is already an approved boot-key mechanism.
- `doctor` is already in U12.
- All three “low-cost architectural accommodations” from the second idea
  document—versioned read audit events, structured authorization decisions, and
  schema-versioned metadata—are already present.

That overlap is a good sign: the core design is pointed in the right direction.
It also means the roadmap should avoid counting those items twice.

My overall recommendation is:

1. **Do not materially expand the v0.1 runtime feature surface.**
2. Fix several security-contract ambiguities in the existing plan before
   implementation.
3. Add one major assurance capability now: **full backup/restore rehearsal**.
4. Make the first post-v0.1 product work **consumer truth and migration**, not
   more Vault-like features.
5. Keep arbitrary code execution, generic outbound networking, process
   supervision, and UI frameworks out of the server.

---

# Scoring method

The scores below are **net priority scores**, not a claim that an idea is
intrinsically good or bad.

| Dimension                                    | Weight |
| -------------------------------------------- | -----: |
| Direct alignment with rotation and migration |     25 |
| Security and reliability value               |     25 |
| Operational or adoption value                |     20 |
| Simplicity and long-term maintenance fit     |     20 |
| Confidence that the need is real             |     10 |

Interpretation:

|    Score | Meaning                                                  |
| -------: | -------------------------------------------------------- |
|   90–100 | Incorporate now, or preserve because it is foundational  |
|    75–89 | Strong candidate after the secure core is proven         |
|    55–74 | Conditional; implement only after real-use evidence      |
| Below 55 | Reject from the core product or move to an external tool |

A feature can have a high importance score but still belong after v0.1 because
of sequencing. The consumer truth graph is an example: strategically important,
but it should build on a proven core rather than delaying it.

---

# Consolidated evaluation of every proposed idea

## Incorporate, preserve, or promote

| Idea                                     |  Score | Decision                                  | Recommended scope                                                                                                                                                                                                                                    |
| ---------------------------------------- | -----: | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rotation adoption tracker                | **98** | **Already incorporated**                  | Preserve R33/U7 exactly: `on-current`, `on-prior`, and `silent-since-write`. Do not add a larger campaign engine yet.                                                                                                                                |
| Full disaster-recovery rehearsal         | **97** | **Add to v0.1**                           | Add `backup verify --full`: restore into an isolated temporary directory, validate schema and tables, authenticate/decrypt every encrypted record without outputting values, verify the audit chain and checkpoint, then remove the temporary store. |
| `doctor` operational checks              | **96** | **Already incorporated**                  | Keep U12. Include stable JSON, stable exit codes, and last successful full recovery-rehearsal age.                                                                                                                                                   |
| Consumer truth graph                     | **94** | **First post-v0.1 feature**               | Reconcile **declared**, **authorized**, and **observed** consumers. This is the best proposed product-level improvement.                                                                                                                             |
| systemd credential support               | **93** | **Already incorporated; make concrete**   | Treat this as documentation, fixtures, and deployment testing—not a new server subsystem.                                                                                                                                                            |
| Migration importers and discovery        | **90** | **First post-v0.1 feature**               | Build alongside the consumer graph. Prefer client-side import/discovery and reuse fnox rather than duplicating parsers.                                                                                                                              |
| Minimal rotation closeout guard          | **89** | **Small addition or first patch release** | Completion should require either all snapshotted consumers to be on-current or an explicit audited override with a reason. No extra campaign states.                                                                                                 |
| Narrow OIDC workload authentication      | **82** | **Post-v0.1**                             | Implement one tightly constrained issuer profile first, probably GitHub Actions. No claim-expression language or generic federation framework.                                                                                                       |
| Emergency global credential invalidation | **80** | **Post-v0.1**                             | Reuse the credential-epoch primitive: one local command invalidates all remote tokens and secret IDs and temporarily disables AppRole login.                                                                                                         |
| Contract-safe secret versions            | **78** | **Post-v0.1, narrowly scoped**            | Fixed structural checks only: required fields and primitive JSON types. No regex language, arbitrary scripts, JSON Schema engine, or value policies.                                                                                                 |
| Embedded Vault CLI replacement           | **76** | **Conditional on U0 evidence**            | Prefer an upstream fnox direct-HTTP/OpenBao provider or a tiny separate shim, rather than mixing CLI emulation into the server daemon.                                                                                                               |
| Aggregate operational metrics            | **75** | **Post-v0.1**                             | Local control socket or loopback-only aggregate metrics. No path, identity, accessor, or secret names as labels.                                                                                                                                     |
| Least-privilege dry-run/advisor          | **74** | **Post-v0.1, advisory only**              | Keep `authz explain`; later add a deterministic `scope dry-run`. Never remove grants automatically based on non-use.                                                                                                                                 |

### Why these rise to the top

The strongest product direction is:

> discover dependencies → reconcile declared/authorized/observed reality →
> safely cut over → observe version adoption → close with explicit evidence

That differentiates the project from “a smaller Vault.” It focuses on the actual
unresolved work around static SaaS credentials.

The consumer truth graph deserves its high score because the current plan
correctly acknowledges a circularity: observed consumers become trustworthy only
after migration, but operators need an inventory to conduct migration.
Declarations and local reference discovery fill that gap without adding HA, a
policy DSL, or dynamic-secret machinery.

The DR rehearsal also deserves promotion because it is not really a new feature.
It is executable proof that U10 works. A successful backup write is weak
evidence; a recent isolated restore, decryption pass, schema check, and audit
verification is much stronger evidence. It reuses functionality already being
built and adds very little conceptual surface.

systemd already supports decrypting encrypted service credentials during
activation and delivering them through the service’s runtime credentials
directory. With TPM-backed protection and the host credential key, encrypted
credentials can be tied to the local hardware and OS installation. The server
merely needs a well-tested credential-directory reader and clear operating
documentation. ([GitHub][1])

---

## Keep only in a reduced or redesigned form

| Idea                                                 | Proposed-form score | Decision                | Better minimal form                                                                                                                                                                                   |
| ---------------------------------------------------- | ------------------: | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full rotation campaigns and signed closeout receipts |              **66** | Defer                   | Keep the existing three-state rotation record. Add only a completion guard and a generated closeout report referencing the audit sequence/checkpoint.                                                 |
| Least-privilege “autopilot”                          |              **63** | Reduce                  | `authz explain` is already present. Add read-only dry-run analysis later, with the lookback window and limitations displayed prominently.                                                             |
| Drift detector using exposed salted hashes           |              **32** | Reject proposed design  | A reusable fingerprint is a secret-guessing and equality oracle. A later client-side scan can explicitly fetch authorized historical versions and compare locally in memory. No fingerprint endpoint. |
| Canary secrets                                       |              **60** | Conditional             | A management-only canary flag and high-severity local event can be useful, but only after there is a reliable way to monitor those events.                                                            |
| Declarative management `plan/apply`                  |              **64** | Reduce                  | Start with non-secret `export`, `validate`, `diff`, and idempotent `ensure` commands. Do not interpret omission as deletion.                                                                          |
| Attenuated delegated credentials                     |              **55** | Defer                   | Use CLI sugar that atomically creates an ephemeral identity, exact-path grant, short-TTL token, and optional use count. Avoid delegation ancestry and a second authorization model.                   |
| One-time-read handoff secrets                        |              **55** | Defer                   | Same treatment as attenuated credentials. It should not become a separate secret type with unusual destruction semantics.                                                                             |
| Per-secret runbook metadata                          |              **56** | Rework                  | Put operational instructions and upstream URLs in local-only encrypted operator metadata, not ordinary KV `custom_metadata` exposed through the remote compatibility API.                             |
| Local event outbox                                   |              **76** | Prefer over webhooks    | Write signed, redacted event files to an owner-only spool directory. Let systemd, cron, or another operator-owned process deliver them.                                                               |
| Operator-side rotation adapters                      |              **68** | Prefer over server exec | An explicitly invoked CLI may run an adapter, receive the new value through a pipe, and call the normal write path. The server process must never execute it.                                         |
| Client-side live reload                              |              **58** | Put outside server      | A companion process or fnox integration can poll metadata and restart/reload a child. The server should expose ordinary metadata, not become a supervisor.                                            |
| Simplified control-state reconciliation              |              **72** | Later                   | Concrete objects only—identities, grants, intervals, declarations. No conditions, inheritance, expressions, or delete-by-absence.                                                                     |

### Drift detection needs particular caution

The proposed server endpoint would expose a stable or semi-stable fingerprint of
each secret. Salting prevents simple precomputed rainbow tables, but it does not
prevent an authorized caller from testing guesses or comparing reused values. It
also creates a new long-lived representation of secret equality.

The safer minimalist version is entirely client-side:

1. A deliberately authorized operator requests selected current or historical
   versions.
2. The client holds them only in protected process memory.
3. It scans explicitly selected local files.
4. It reports file locations and matching versions.
5. It never uploads file contents or exposes a server-side fingerprint.

That still has risk—the client receives the old value—but it uses the existing
`read-history` authority rather than creating a new comparison oracle. I would
implement reference-based discovery first and only build value comparison after
concrete evidence that reference discovery is insufficient.

### Contract checks should remain deliberately small

A compact contract can prevent a common class of rotation mistakes:

- a required field disappears;
- an expected string becomes an object;
- a structured secret is malformed;
- a consumer-required field is removed.

The design should stop there. The moment it supports arbitrary predicates,
regex-based content policies, embedded scripts, or a full schema language, it
becomes another policy subsystem. Initially, I would make it:

- opt-in per secret;
- configurable only through the local management plane;
- limited to required field names and primitive types;
- enforced immediately before the existing transactional write;
- overridable only with a management capability and audited reason.

---

## Do not put these in the core server

| Idea                                        |  Score | Decision                     | Reason                                                                                                                                                           |
| ------------------------------------------- | -----: | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Generic outbound webhooks                   | **38** | **Reject from core**         | Introduces outbound-network trust, SSRF controls, DNS behavior, retry queues, replay handling, delivery secrets, redaction rules, and metadata leakage.          |
| Server-side `rotate_exec` hooks             | **20** | **Reject**                   | Arbitrary code execution inside the most privileged, secret-bearing process is fundamentally at odds with the design.                                            |
| Watch-and-run process supervisor            | **45** | **Move to client ecosystem** | Signal semantics, child lifecycle, restart policy, caching, platform differences, and application acknowledgements are a separate product.                       |
| Metadata-first TUI cockpit                  | **30** | **Ignore for now**           | UI work should not precede stable query semantics. Stable CLI JSON provides all necessary future seams.                                                          |
| In-process scheduler for reminders/rotation | **42** | **Reject initially**         | Adds time-based background behavior, persistent scheduling state, catch-up semantics, and failure modes. Use external timers.                                    |
| Demo mode in the production binary          | **15** | **Reject**                   | Unsafe modes have a habit of being used accidentally. Provide a containerized example, test fixture, or documented disposable setup instead.                     |
| Automatic grant pruning                     | **18** | **Reject**                   | Non-observation is not proof of non-need. Emergency jobs and infrequent workflows make automatic removal unsafe.                                                 |
| Automatic upstream revocation assertions    | **10** | **Reject as impossible**     | The server cannot prove that a third-party SaaS credential was revoked unless it owns a trusted integration with that upstream. Keep it an operator attestation. |

### Why generic webhooks are the wrong abstraction

A generic webhook sounds like one small primitive, but it quietly creates an
egress subsystem:

- URL validation and SSRF protection;
- DNS rebinding considerations;
- TLS trust and client authentication;
- retries, backoff, dead-letter handling, and queue persistence;
- duplicate delivery and idempotency semantics;
- signing-key rotation;
- rules governing whether identity names, paths, or rotation metadata may leave
  the host.

That is precisely the kind of hidden operational complexity this project is
trying to avoid. A local signed event spool gives most of the composability
without putting the secret server on the network as an outbound client.

### Why server-side exec is a hard no

Running operator scripts from the daemon would require decisions about:

- operating-system user and sandboxing;
- inherited environment and file descriptors;
- stdout/stderr leakage;
- process timeouts and cancellation;
- concurrent rotations;
- partial success after the upstream changes but before the local commit;
- crashes and retries that might mint multiple credentials;
- script integrity and upgrade behavior;
- scheduler semantics;
- incident response if the adapter itself is compromised.

The safer architecture is an operator-side orchestration command:

```text
operator CLI -> upstream adapter -> new value over pipe -> normal CAS write
```

The adapter runs with the operator’s authority, not the daemon’s. The server
remains a deterministic state and audit service.

---

# The highest-value idea from each proposal

From the first idea list, the best genuinely new direction is **migration/import
tooling**, not the proposed server-side rotation executor. The cutover tracker
is already present, and the hash-based drift design should not be adopted as
written.

From the second idea list, the best idea is clearly the **consumer truth
graph**. It directly improves the central product promise and resolves an
acknowledged weakness in the current migration story.

The most valuable operational idea across both documents is **automatic full
recovery rehearsal**.

The strongest combined package is therefore:

1. Full recovery rehearsal.
2. Declared/authorized/observed consumer truth.
3. Reference discovery and safe import.
4. Minimal rotation closeout evidence.
5. Narrow OIDC after AppRole is proven.

---

# Important existing-plan issues to fix before adding features

These are more important than nearly every proposed feature.

## 1. Resolve the metadata-confidentiality contradiction — **100/100**

The threat model says that theft of the data directory yields “ciphertext plus
verifiers only.” But KTD11 says secret metadata is merely integrity-covered, and
the storage design does not clearly say whether logical paths, identity names,
grants, version timestamps, and table keys are encrypted. KTD4 separately
recognizes that paths and identity names disclose topology and therefore
encrypts audit payloads. Those statements do not currently form one consistent
confidentiality contract.

There are two honest choices:

**Simpler recommendation:** explicitly state that offline database theft may
disclose structural metadata—record counts, logical paths or opaque path
identifiers, version times, identity names, and grants—while values, credential
material, and confidential audit payloads remain protected.

**Stronger but more complex alternative:** use opaque record identifiers and
encrypt paths, identities, grants, and metadata. Prefix listing and subtree
authorization make this significantly more complicated than simply encrypting
table values.

Given the product’s simplicity goal, I recommend the first choice unless path
and identity topology is itself considered regulated data. Operator runbooks,
upstream URLs, account identifiers, and similar sensitive metadata should remain
encrypted and local-only.

## 2. Correct the “irreversible destroy” promise — **99/100**

R29 says destruction irreversibly removes a version. That is too strong for the
selected architecture:

- redb is copy-on-write;
- filesystem free pages may retain prior ciphertext;
- backups can contain the version;
- one shared record-encryption key means deleting one record does not
  cryptographically erase only that version.

The product should promise:

> Destroy makes the version logically unavailable through the active store and
> supported APIs. Historical backups or residual filesystem blocks may retain
> encrypted copies until backup expiry, compaction, or media replacement.

Strict per-version cryptographic deletion would require a separate DEK per
version, individually wrapped so deleting the wrapped DEK destroys access to
that version. That is a real key-hierarchy expansion and conflicts with the
current simplicity choice. Use honest logical-destruction semantics for v0.1.

## 3. Specify the AEAD nonce lifecycle — **98/100**

KTD3 selects AES-GCM but does not define how nonces are generated, persisted,
bounded, and prevented from repeating across writes, migrations, restores, and
re-encryption. This cannot remain an implementation detail.

NIST treats same-key IV uniqueness as crucial to GCM security and warns that
even one repeated IV can permit forgery attacks. ([NIST Publications][2])

The plan should explicitly require:

- a fresh 96-bit CSPRNG-generated nonce for every AEAD encryption;
- the nonce stored alongside the ciphertext;
- a new nonce for every rewrite or re-encryption, even when plaintext is
  unchanged;
- a documented per-key encryption bound;
- key ID included in the authenticated context;
- fault/property tests looking for accidental reuse;
- no deterministic nonce construction unless uniqueness is formally demonstrated
  across every record type and lifecycle operation.

A misuse-resistant AEAD could also be evaluated during U2, but the critical
point is to settle the strategy before storage-format fixtures become permanent.

## 4. Make bootstrap credential delivery failure-safe — **96/100**

The current sequence initializes the store and then shows the first management
credential exactly once. That creates a dangerous edge case: the transaction
commits, but the output pipe breaks or the terminal write fails. The operator
now has an initialized store and no recoverable administrator credential.

Safer protocol:

1. Open and validate the caller-selected secret output sink first.
2. Generate the credential.
3. Successfully write and flush it to that sink.
4. Commit the initialization transaction containing its verifier.
5. Report ordinary command success separately.

If the process dies before commit, the disclosed credential is harmless and
initialization can be retried. If it dies after commit, the operator already
possesses the credential. Add broken-pipe and injected-crash tests around this
sequence.

## 5. Adopt an explicit complexity budget — **96/100**

Add a short architecture rule to the Product Contract:

> A feature must close a named failure mode or materially improve rotation,
> migration, or recovery. Reusing existing metadata and queries is preferred.
> Features that add a new privileged execution context, remote management
> surface, outbound network dependency, durable background queue, scheduler,
> authorization model, or policy language require exceptional evidence.

For at least the first two releases, I would make the following hard rules:

- no server-side arbitrary process execution;
- no generic server-initiated network calls;
- no remotely reachable management routes;
- no second authorization model;
- no policy or validation expression language;
- no durable job queue or internal scheduler;
- no client-process supervision in the server;
- no new compatibility endpoints that were not demonstrated by U0 evidence.

This single discipline will protect the product identity better than a long
deferred-features list.

## 6. Improve rotation evidence granularity — **93/100**

R33 currently reports adoption by identity. That can overstate confidence when
several processes or replicas share an identity:

- replica A fetches the new version;
- replica B still holds the old version;
- the identity is reported as `on-current`.

Record the public credential accessor or authenticated session identifier in
successful-read audit events, in addition to the identity. Then provide both:

- identity-level adoption;
- session/accessor-level adoption where available.

Vault accessors are intentionally non-secret references to tokens and are used
for lookup, revocation, and audit-oriented workflows, although their ability to
facilitate bulk revocation means they still require protection. ([HashiCorp
Developer][3])

The UI and documentation must still say **“fetched version N”**, never
“successfully used version N.” Only an application-level acknowledgement could
prove use, and that is outside v0.1.

## 7. Fail safely on clock rollback — **91/100**

The current plan trusts wall time and merely warns when startup time is behind
the final audit timestamp. A large clock rollback can unintentionally extend
token validity.

A simple stronger rule is:

- persist the highest accepted wall-clock time;
- during runtime, effective time never moves backward;
- at startup, refuse service when the clock is behind persisted time beyond a
  documented tolerance;
- provide a local recovery override requiring an audited reason.

A bad forward clock may expire tokens early, which is inconvenient but
fail-safe. A backward clock silently prolonging bearer credentials is worse.

## 8. Add differential compatibility testing — **89/100**

Captured client fixtures are necessary, but they can accidentally encode the
project’s own interpretation.

For every supported endpoint, run a normalized request corpus against:

1. a pinned OpenBao reference server;
2. this implementation.

Compare:

- status class;
- JSON envelope;
- missing-path behavior;
- CAS errors;
- delete/undelete/destroy behavior;
- metadata field presence;
- list behavior;
- auth response shape.

Normalize fields such as request IDs and timestamps rather than requiring byte
equality. This should complement—not replace—the real `fnox`, `vault`, and `bao`
client tests.

## 9. Add release-integrity requirements — **87/100**

A professional secrets server needs release assurances even though they add no
runtime features:

- signed release checksums;
- an SBOM;
- provenance for release artifacts;
- pinned Rust MSRV;
- `Cargo.lock` committed and enforced;
- dependency advisory and license checks;
- documented security-reporting process;
- upgrade notes for every storage-format change;
- release smoke test against the actual downloadable binary;
- restoration of at least one older released fixture in current CI.

This is much higher value than a TUI, demo mode, or webhooks.

---

# Detailed recommendations for the strongest retained ideas

## Consumer truth graph — **94/100**

Implement this as the first coherent post-v0.1 capability.

A declaration should remain small:

```text
consumer_id
secret_path
identity_id
owner
environment
source
last_verified_at
optional required_fields
```

Do not build a generic graph database. These are ordinary records and
reconciliation queries.

For each secret, show:

| State                              | Meaning                          |
| ---------------------------------- | -------------------------------- |
| Declared + authorized + observed   | Healthy evidence                 |
| Declared + unauthorized            | Expected future failure          |
| Declared + authorized + unobserved | Not migrated, dormant, or broken |
| Undeclared + authorized            | Excess privilege                 |
| Undeclared + observed              | Shadow dependency                |
| Declared reference outside server  | Migration incomplete             |

Important limitations should be displayed directly:

- observation is limited to the audit lookback window;
- declarations may be stale;
- one identity may represent multiple process instances;
- local discovery finds references, not proof of runtime use;
- the server cannot see copies that have not been scanned or migrated.

That makes the graph honest rather than falsely authoritative.

## Migration importers and discovery — **90/100**

Keep discovery on the client side so the server never scans filesystems, CI
configurations, or repositories.

The current fnox project already has a `scan` command for finding plaintext
secrets, a per-user daemon, and `.env` import/export behavior. Reusing or
extending those mechanisms is preferable to building another `.env` parser and
scanner inside this project. ([GitHub][4])

A minimal migration workflow would be:

```text
discover references
    -> produce a non-secret manifest
    -> review declared consumers
    -> import values through stdin/FD
    -> use cas=0 by default
    -> verify reads from migrated identities
    -> mark external references resolved
```

For live Vault/OpenBao migration:

- enumerate and read through an explicit source token;
- stream each secret directly into the normal write API;
- default to create-only CAS;
- produce a redacted resumable result manifest;
- never write an intermediate plaintext export;
- avoid one enormous transaction—the import should be restartable and report
  per-item results.

For fnox `age` values, compose fnox’s own decryption/export path where possible
instead of maintaining a second interpretation of its format.

## Minimal closeout evidence — **89/100**

Do not build a full campaign engine yet. Enhance the current rotation record
with one guard:

```text
rotation complete
```

succeeds when:

- the target remains current;
- upstream revocation is explicitly attested;
- every snapshotted consumer is `on-current`;

or requires:

```text
--acknowledge-unverified
--reason "legacy nightly job will be retired Friday"
```

when some consumers remain `on-prior` or `silent-since-write`.

Generate a redacted closeout report containing:

- secret opaque identifier or management-visible path;
- previous and target versions;
- snapshot consumer set;
- adoption state;
- write and completion audit sequence numbers;
- upstream-revocation attestation;
- override reason, if any;
- audit checkpoint reference.

The checkpoint already authenticates the underlying history. A separate campaign
signature hierarchy is unnecessary.

## Narrow OIDC — **82/100**

OIDC should follow—not precede—a stable AppRole implementation.

The minimalist version should have:

- one explicitly configured issuer;
- one configured JWKS location;
- an algorithm allowlist;
- exact audience validation;
- exact or tightly templated subject mappings;
- short maximum assertion age;
- bounded clock skew;
- cached keys with a fail-closed expiry policy;
- no arbitrary expressions over claims;
- no authorization capabilities embedded in the JWT;
- mappings to existing server identities and grants.

JWT best practices require validating issuer, subject, audience, and allowed
algorithms. They also warn that blindly following attacker-controlled key URLs
such as `jku` or `x5u` can create SSRF vulnerabilities. The server should never
discover key URLs from the presented token. ([RFC Editor][5])

Start with a specific profile such as GitHub Actions. Do not attempt “generic
OIDC for every platform” in the first implementation.

## Conditional Vault CLI shim — **76/100**

The motivation is real. The current fnox Vault provider still invokes
`Command::new("vault")`, supplies `VAULT_ADDR` and `VAULT_TOKEN`, and runs the
external Vault CLI. ([GitHub][6])

The Vault repository’s current license for version 1.15 and later is Business
Source License 1.1 with a future MPL-2.0 change date, so removing a required
external Vault binary can still matter to the project’s all-open operational
story. ([GitHub][7])

But the server daemon should not become a Vault CLI emulator. Preferred order:

1. U0 proves exactly what current fnox versions execute.
2. Explore contributing a direct HTTP or OpenBao-compatible provider upstream to
   fnox.
3. If pinned existing fnox versions must remain supported, create a very small
   separate `vault` shim binary or installation mode.
4. Implement only the captured command subset.
5. Keep the shim’s tests distinct from server API compatibility tests.

This prevents client-emulation behavior from contaminating the trusted server
process.

---

# Recommended roadmap

## Before implementation or during U0–U2

Make no new product features. Amend the plan to settle:

1. Metadata-confidentiality boundary.
2. Logical versus cryptographic destruction.
3. AEAD nonce requirements.
4. First-admin credential delivery ordering.
5. Clock rollback behavior.
6. Identity-versus-session rotation evidence.
7. Complexity-budget rules.
8. Release integrity and differential compatibility tests.

## v0.1

Ship the current secure vertical slice and existing planned functionality, plus:

- `backup verify --full`;
- concrete systemd-credential deployment fixtures and tests;
- rotation completion guard with audited override;
- credential/session accessor in read audit events;
- release signing, SBOM, and migration fixtures.

Do **not** add OIDC, declarations, schema contracts, webhooks, adapters, a TUI,
a scheduler, or process supervision before the core is running.

## v0.2: migration and consumer truth

Build one coherent feature package:

1. Declared consumer records.
2. Declared/authorized/observed reconciliation.
3. Local reference discovery.
4. `.env`, fnox, and Vault/OpenBao import workflows.
5. Rotation status incorporating declarations and session-level observations.
6. Stable redacted JSON reports.

This should be validated against one real non-production migration and rotation.

## v0.3: safer automation at the edges

Based on real demand:

- narrow GitHub Actions OIDC;
- fixed structural secret contracts;
- `scope dry-run`;
- global credential-epoch incident command;
- aggregate local metrics;
- operator-side rotation adapters.

## Explicitly outside the core roadmap

- generic webhooks;
- daemon-side script execution;
- general scheduler;
- full process supervisor;
- policy or validation DSL;
- token delegation trees;
- TUI until the CLI queries are proven;
- unsafe demo mode in the production binary.

---

# Final prioritized list

Taking the proposed ideas and my additional findings together, this is the order
I would use:

| Rank | Work                                            |   Score | Timing                        |
| ---: | ----------------------------------------------- | ------: | ----------------------------- |
|    1 | Resolve metadata-confidentiality contract       | **100** | Before storage implementation |
|    2 | Correct destruction guarantees                  |  **99** | Before storage implementation |
|    3 | Preserve existing rotation adoption tracker     |  **98** | v0.1                          |
|    4 | Specify and test AEAD nonce lifecycle           |  **98** | Before storage implementation |
|    5 | Add full recovery rehearsal                     |  **97** | v0.1                          |
|    6 | Make first-admin delivery failure-safe          |  **96** | v0.1                          |
|    7 | Adopt explicit complexity budget                |  **96** | Immediately                   |
|    8 | Build consumer truth graph                      |  **94** | First post-v0.1 package       |
|    9 | Add credential/session-level rotation evidence  |  **93** | v0.1                          |
|   10 | Finish systemd credential integration and tests |  **93** | v0.1                          |
|   11 | Harden clock rollback behavior                  |  **91** | v0.1                          |
|   12 | Add migration discovery and import workflows    |  **90** | First post-v0.1 package       |
|   13 | Add minimal rotation closeout guard/report      |  **89** | v0.1 or first patch           |
|   14 | Add differential compatibility testing          |  **89** | v0.1                          |
|   15 | Add release-integrity controls                  |  **87** | v0.1                          |
|   16 | Add narrow OIDC authentication                  |  **82** | After AppRole is proven       |
|   17 | Add global credential epoch invalidation        |  **80** | Post-v0.1                     |
|   18 | Add fixed structural contracts                  |  **78** | Post-v0.1                     |
|   19 | Evaluate separate Vault CLI shim                |  **76** | Conditional on U0             |
|   20 | Add aggregate local metrics                     |  **75** | Post-v0.1                     |

The central design principle should remain:

> **Make rotation, migration, recovery, and evidence excellent. Do not turn the
> product into a general automation platform.**

That preserves the sweet spot: a small, understandable server with unusually
strong security and rotation behavior, rather than a gradually reconstructed
Vault.

[1]:
  https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md
  "https://github.com/systemd/systemd/blob/main/docs/CREDENTIALS.md"
[2]:
  https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
  "https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf"
[3]:
  https://developer.hashicorp.com/vault/docs/concepts/tokens
  "https://developer.hashicorp.com/vault/docs/concepts/tokens"
[4]: https://github.com/jdx/fnox/releases "https://github.com/jdx/fnox/releases"
[5]:
  https://www.rfc-editor.org/info/rfc8725/
  "https://www.rfc-editor.org/info/rfc8725/"
[6]:
  https://github.com/jdx/fnox/blob/main/crates/fnox-core/src/providers/vault.rs
  "https://github.com/jdx/fnox/blob/main/crates/fnox-core/src/providers/vault.rs"
[7]:
  https://github.com/hashicorp/vault/blob/main/LICENSE
  "https://github.com/hashicorp/vault/blob/main/LICENSE"
