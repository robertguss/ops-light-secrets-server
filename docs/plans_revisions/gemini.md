This is an exceptionally well-scoped, Staff-level product contract. The
constraints you’ve chosen—specifically the single-node ceiling, the
single-binary distribution, and routing around Vault’s unseal/HA operational
bloat—are precisely where they need to be to deliver on the "ops-light" thesis
without compromising professional-grade security.

Reviewing the architecture, the crate selection (`axum`, `redb`, `age`,
`blake3`) is highly pragmatic. However, there are a few architectural seams
where the implementation details introduce unnecessary operational risk or
complexity.

Here is my analysis and recommended revisions to make the server more robust,
easier to operate, and future-proofed for the workloads it will inevitably face.

---

## 1. Storage: Atomic File Swap over Resumable Re-encryption

**Target:** U8 (Server-identity rotation)

**Rationale:** The plan currently calls for a "crash-recoverable pass
(write-new-then-swap, resumable if interrupted)" for re-encrypting the store
when the `age` identity rotates. Implementing a resumable in-place migration
inside a single `redb` database introduces severe state-management complexity
(tracking rotation cursors, handling reads during a mixed-encryption state).

**The Fix:** Rely on POSIX filesystem atomics instead. Read from `store.redb`,
write entirely to `store.redb.new` encrypted with the new key. When complete,
`fsync` the new file and perform an atomic `rename` over the old file. It
eliminates the "half-rotated" state entirely. If it crashes mid-rotation, you
simply delete the `.new` file and start over.

```diff
--- Original
+++ Revised
@@ -438,8 +438,8 @@
 - **Approach:** A CLI subcommand decrypts every blob under the old identity and
-  re-encrypts under the new recipient in a crash-recoverable pass
-  (write-new-then-swap, resumable if interrupted), preserving readable secrets
-  and audit history. `age` has no rotation primitive, so this is an explicit
-  application-level job (mirrors fnox's `fnox reencrypt`).
- - **Execution note:** Test the interrupt-and-resume path explicitly — a
-  half-rotated store must not lose secrets.
+  re-encrypts under the new recipient in a secondary file (`store.redb.new`).
+  Upon success, it atomically swaps the files via OS rename, preserving readable
+  secrets and audit history. `age` has no rotation primitive, so this is an explicit
+  application-level job.
+ - **Execution note:** Test the interruption path explicitly — an interrupted
+  process should leave the original `redb` untouched and functional.
 - **Test scenarios:**
   - Rotate identity → every secret readable under the new identity, none
     readable under the old.
-  - Interrupt mid-rotation, then resume → no secret lost, no blob left under the
-    old identity.
+  - Interrupt mid-rotation → original database remains intact, no mixed-encryption
+    state exists.

```

## 2. Infrastructure: Isolate the Audit Log from the KV Store

**Target:** KTD4 and U6 (Audit Log)

**Rationale:** If the audit log is stored in the same `redb` instance as the
secret data, you have a shared blast radius. If a power failure or filesystem
glitch corrupts `redb`, you lose your tamper-evident audit chain. Furthermore,
B-trees are suboptimal for pure append-only workloads.

**The Fix:** Isolate the audit log to a dedicated, append-only Write-Ahead Log
(WAL) file (e.g., `audit.log`). Appending to a flat file and calling `fsync` is
significantly faster than a B-tree insertion, satisfies R26 (fail-closed) with
lower latency, and guarantees that a corrupted KV store does not compromise the
security audit trail.

```diff
--- Original
+++ Revised
@@ -298,8 +298,10 @@
 - KTD4. **Audit chain: per-entry hash chain (`blake3`) with periodic
-  `ed25519-dalek`-signed checkpoints mirrored off-host.** Resolves OQ4...
+  `ed25519-dalek`-signed checkpoints mirrored off-host, stored in a dedicated
+  append-only flat file.** Resolves OQ4. Separating the audit log from the
+  `redb` KV store isolates the blast radius of database corruption and optimizes
+  for pure append-only disk I/O. (Research: this is the Certificate-Transparency...

@@ -402,8 +404,9 @@
 - **Approach:** Each entry records identity, path, operation, timestamp, outcome
   — never values or credential material (R25 extends this ban to all server
   output: logs, traces, errors, panics). Each entry's `blake3` hash chains to
-  its predecessor; periodic `ed25519-dalek`-signed checkpoints publish the chain
-  head off-host, signed with a boot-supplied key held only in a
-  `secrecy::SecretBox` (KTD4).
+  its predecessor, appended to an isolated flat file (not the `redb` store)
+  and immediately `fsync`ed to disk. Periodic `ed25519-dalek`-signed checkpoints
+  publish the chain head off-host...

```

## 3. Reliability: Explicit OS-Level File Locking

**Target:** KTD2 and U1 (Fail-closed startup)

**Rationale:** The `redb` single-writer lock caveat is a critical footgun. If an
operator accidentally points a second container or process at the data directory
mounted over NFS or a hypervisor share that drops POSIX locks, `redb` will
silently corrupt the KV store.

**The Fix:** Don't rely solely on `redb`'s internal lock detection. Implement an
explicit, fail-closed `.lock` file alongside the DB using a crate like `fd-lock`
or `fs3`. If the server cannot acquire an exclusive OS lock on startup, it
crashes.

```diff
--- Original
+++ Revised
@@ -288,10 +288,11 @@
   the single-binary thesis; SQLite remains the fallback if 20 years of hardening
   outweighs API fit.) Resolves OQ2's storage question. **Load-bearing caveat:**
-  redb's single-writer lock is silently skipped on filesystems without file-lock
-  support, permitting multi-process corruption — U1's startup MUST verify the
-  data directory supports locking and refuse to start otherwise (folds into
-  R18).
+  redb's internal single-writer lock can silently fail on complex filesystem mounts
+  (NFS, Docker volumes). U1's startup MUST enforce an explicit, OS-level exclusive
+  lock file (`store.lock`) in the data directory and refuse to start if it cannot
+  be acquired or if the filesystem rejects locking (folds into R18).

@@ -338,8 +339,9 @@
   - Boot on an uninitialized store with no bootstrap credential → exits
     non-zero.
-  - Boot with a data directory on a lock-unsupported filesystem → exits non-zero
-    (KTD2 caveat).
+  - Boot a second server instance pointing to the same data directory → second
+    instance exits non-zero due to explicit OS lock failure (KTD2 caveat).

```

## 4. Identity Taxonomy: The AI Agent Primitive

**Target:** A4, R7, and U3 (Identity Model)

**Rationale:** You've classified AI agents as an "anticipated, out of v0.1"
workload. Given the rapid acceleration of autonomous coding tools, agent
workloads are likely to arrive sooner than later. Vault's AppRole (which
requires managing a long-lived `role_id` and injecting a `secret_id`) is too
heavy for an ephemeral LLM agent spinning up in a Docker container for 5 minutes
to run integration tests.

**The Fix:** You don't need to build the native Model Context Protocol (MCP)
transport in v0.1, but you _should_ define the "Ephemeral Agent" at the
data-model layer now. Add a flag/type to identities in U3 that strictly enforces
read-only access and hard-caps the token TTL. This costs almost nothing to add
to the schema now, but prevents a painful migration later.

```diff
--- Original
+++ Revised
@@ -87,8 +87,9 @@
 - A3. Operator — runs the server and performs rotations. The same person as A1
   at this team size.
 - A4. AI agent — a non-human workload with a short-lived, narrow need.
-  Anticipated, out of v0.1.
+  Anticipated transport in phase 3, but the identity primitive (ephemeral,
+  read-only, strict TTL cap) is modeled in v0.1 to prepare the schema.

@@ -142,7 +143,8 @@
 **Identity and access**

 - R7. Every human, application, and integration authenticates as a distinct
-  identity.
+  identity. Identities are typed (`human`, `application`, `ephemeral_agent`),
+  allowing the server to enforce hard TTL caps and read-only bounds by type.

```

## 5. Security: Split the Management Grant

**Target:** R22 (Management capabilities)

**Rationale:** A boolean "Management" grant violates the principle of least
privilege. In a scenario where an external integration (e.g., a SIEM or a log
aggregator) needs to pull the audit log, giving it full power to create
identities and issue credentials is too broad.

**The Fix:** Split the management grant into two distinct flags: `audit_read`
and `admin`.

```diff
--- Original
+++ Revised
@@ -150,9 +150,11 @@
 - R9. A credential issued to an identity carries a TTL and can be revoked before
   that TTL expires.
-- R22. Management capabilities — creating identities, changing scopes, issuing
-  and revoking credentials, completing rotations, reading the audit log, and
-  enumerating a secret's consumers (R10) — require an explicit grant distinct
-  from any secret-path read or write grant. Audit records are confidential at
-  rest and accessible for query, export, and verification only under that grant.
+- R22. Management capabilities require explicit grants distinct from secret-path
+  read/write. These are split into two discrete flags: `audit_read` (access to
+  query/export the log, enumerate consumers via R10) and `admin` (creating
+  identities, changing scopes, issuing/revoking credentials, completing rotations).
+  Audit records are confidential at rest and accessible only to the `audit_read` grant.

```
