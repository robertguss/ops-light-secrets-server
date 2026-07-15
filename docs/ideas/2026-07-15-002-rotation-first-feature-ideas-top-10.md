---
title: Ops-Light Secrets Server - Rotation-First Feature Ideas (Top 10)
type: ideas
date: 2026-07-15
topic: ops-light-secrets-server
status: captured, not scoped
relates-to: docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md
---

# Rotation-First Feature Ideas — Top 10

This document captures a second, independent feature-ideation pass performed
after reading the complete v0.1 plan. One hundred candidates were considered
across rotation, migration, access, authentication, operations, resilience,
user experience, compatibility, and incident response. They were ranked by:

1. Direct value against the product's rotation and migration problems.
2. Differentiation from a smaller or simpler Vault clone.
3. Leverage of subsystems already required by v0.1.
4. Security, reliability, and operational value.
5. Implementation and ongoing complexity.
6. Compatibility with the product's ops-light identity and explicit non-goals.

The winning direction is not to add more of Vault. It is to make this system
exceptionally good at discovering what depends on a static secret and rotating
that secret safely.

None of these ideas is part of the current v0.1 scope. They are post-v0.1
candidates unless separately promoted through planning.

## 1. Rotation campaigns with provable completion

Turn rotation from "write a version and mark it complete" into a durable,
resumable workflow:

```text
prepare -> preflight -> cut over -> observe adoption -> revoke upstream
        -> retire the old version -> close
```

A campaign would:

- Snapshot every declared, authorized, and recently observed consumer before
  cutover.
- Record the replacement write and its version as the cutover event, preserving
  R11's write-is-cutover semantics.
- Show which identities have fetched the replacement version and which remain
  silent or have only fetched the prior version.
- Allow an operator to waive a consumer explicitly, with the reason audited.
- Roll back by appending the prior value as a new version rather than mutating
  version history.
- Record the operator's confirmation that the old credential was revoked in
  the upstream system.
- Produce a signed closeout receipt tied to an audit checkpoint.

The receipt must distinguish server evidence from operator attestation. The
server can prove writes, reads, version retirement, and audit-chain inclusion;
it cannot prove that a credential was revoked in an external SaaS product.

This idea turns the system's central promise from "rotation is supported" into
"a rotation is understandable, observable, resumable, and defensible."

**Relative implementation cost:** Medium. It primarily composes version
history, consumer enumeration, management metadata, audit entries, and signed
checkpoints already required by v0.1.

## 2. A consumer truth graph

For every secret, reconcile three different sources of truth:

- **Declared:** applications and integrations that say they require the secret
  or particular fields within it.
- **Authorized:** identities whose effective scopes permit access.
- **Observed:** identities that have actually read it during the audit
  lookback window.

The graph would expose discrepancies with direct operational meaning:

- Declared but unauthorized: the workload will fail when it tries to read.
- Authorized but undeclared: excess or unexplained privilege.
- Declared but never observed: an inactive, broken, or not-yet-migrated
  consumer.
- Observed but undeclared: a shadow dependency.
- Known pre-migration references that still point outside the server.

A local `discover` command could inspect `fnox.toml`, environment templates, CI
configuration, and systemd units while extracting references only, never
values. An initial migration path could decrypt existing fnox `age` values
locally and transmit them directly to the server over TLS without a plaintext
intermediate file.

This directly resolves the plan's acknowledged circularity: R10's observed
consumer list is trustworthy only after migration, while operators need a
consumer inventory in order to migrate safely. Declared dependencies supply the
missing pre-migration evidence.

**Relative implementation cost:** Medium. The server needs a small consumer
manifest model and reconciliation queries; source-specific discovery remains a
local client concern and can grow one adapter at a time.

## 3. Contract-safe secret versions

Allow each secret to carry a small, fixed structural contract containing such
information as:

- Required and optional fields.
- Basic field types.
- Which declared consumers require which fields.
- A small set of value-safe constraints, such as non-empty or valid structured
  encoding.

Before committing a replacement, the server would return a redacted
compatibility report such as:

```text
required field removed: api_key
field type changed: endpoint
new optional field added: region
affected declared consumers: ingest-worker, reporting-job
```

The report must never echo a supplied value. Ordinary Vault-compatible writes
would fail when they violate an active contract unless a management-authorized
breaking-change workflow is used. That workflow would enumerate affected
consumers and audit the override.

The intentionally small design is important. This should not become arbitrary
server-side scripts, a general schema language, or another policy DSL. Fixed
structural checks capture most accidental rotation failures without importing a
new subsystem.

**Relative implementation cost:** Small to medium. It extends encrypted secret
metadata and adds a validation step immediately before the existing transactional
write.

## 4. Attenuated, one-use handoff credentials

Allow an identity with an explicit delegation grant to mint a child credential
that can never exceed the parent's current authority. A handoff credential
could be restricted by:

- Exact secret path.
- Read-only or write-only operation.
- Short TTL.
- Maximum use count.
- Optional field projection for reads.

Parent revocation, identity disable, or scope reduction would invalidate every
derived credential before its next server request. Each credential would be
disclosed once, stored only as a verifier, and carry an audited issuer and
revocation lineage.

Two particularly useful workflows follow:

- A write-only **secret drop box** lets a teammate or vendor deposit a new
  credential without seeing the previous value.
- A read-once handoff lets a teammate, CI job, or other ephemeral consumer
  obtain one narrowly scoped secret without receiving a permanent identity or
  broad token.

Because the handoff is still presented through `X-Vault-Token`, its eventual
KV operation can remain compatible with the existing data API. Raw credentials
must never be embedded in URLs; delivery should use masked input, standard
input, or a deliberate pairing flow.

**Relative implementation cost:** Medium. It extends the existing token model
with attenuation, use counters, and revocation ancestry rather than introducing
a second authorization model.

## 5. A watch-and-run mode for live cutovers

Add a metadata-only version-change stream and a client mode such as:

```text
secrets-server run \
  --secret POPULI_KEY=apps/populi#api_key \
  -- my-service
```

The wrapper would:

- Resolve configured secrets directly into server-controlled memory.
- Inject them into a child process without rendering a file.
- Watch only non-secret version metadata.
- Fetch replacements when relevant versions change.
- Send a configured reload signal or restart the child process.
- Report that the new version was fetched, without claiming the application
  successfully used it unless the application explicitly acknowledges that.

If the server becomes unavailable, an already running process continues with
the values it already holds. The wrapper does not create an unaudited offline
cache or authorize new reads while disconnected; it reconnects and resumes
watching later.

This closes an important operational gap. A successful server-side write does
not cause a long-running process to reload its environment, so write-is-cutover
otherwise remains passive until the consumer happens to read again.

**Relative implementation cost:** Medium. A minimal implementation needs one
metadata watch endpoint and a Linux-oriented process supervisor, not a general
templating engine or permanent sidecar framework.

## 6. Automatic disaster-recovery rehearsals

Make backups prove themselves. A command such as `backup verify --full` would:

1. Restore the latest backup into an isolated temporary data directory.
2. Validate every database table and store-format invariant.
3. Verify that every encrypted record can be decrypted without printing its
   value.
4. Verify the complete audit chain against its last off-host checkpoint.
5. Detect incomplete backup, restore, or server-identity rotation state.
6. Destroy the temporary restored copy after the rehearsal.

A broader `doctor` command could also check:

- Backup and checkpoint freshness.
- TLS certificate expiry.
- Disk and audit-log capacity.
- Filesystem locking behavior.
- Clock skew relevant to token TTLs and audit ordering.
- Store-format compatibility with the running binary.
- Incomplete re-encryption or recovery work.

Both commands should provide stable exit codes and a redacted JSON mode suitable
for cron or monitoring. A compact signed recovery report could contain only
counts, timestamps, versions, and verification outcomes.

The operational distinction is substantial: "a backup command succeeded" is
weak evidence; "the most recent snapshot was restored and cryptographically
verified yesterday" is meaningful evidence.

**Relative implementation cost:** Small to medium. U10 already requires a
restore path, and U6 already requires audit verification; this idea composes
them in an isolated rehearsal.

## 7. Federated workload authentication

Add an OIDC token-exchange authentication method for workloads that already
receive short-lived identity assertions from CI or deployment platforms. An
exact binding would map an allow-listed issuer, audience, and subject to an
existing server identity, then issue the same short-lived server token used by
other authentication methods.

The safe, ops-light version would have deliberately narrow behavior:

- Explicitly allow-listed issuers and signing algorithms.
- Pinned audiences.
- Exact or tightly bounded subject bindings.
- Bounded clock skew and token lifetime.
- Cached, fail-closed key discovery.
- No arbitrary claim expressions or claim-based policy language.

This removes the AppRole `secret_id` terminus for suitable environments. A CI
job can exchange an ambient, short-lived assertion instead of storing another
static credential in repository or organization settings.

This is intentionally post-v0.1 because R31 settles token auth and AppRole as
the complete initial authentication surface. It should be evaluated as an
explicit extension, not slipped into the current implementation.

**Relative implementation cost:** Medium. JWT validation and issuer-key
handling are standard building blocks, while safe claim binding and operational
documentation are the main design work.

## 8. Declarative management with transactional plan/apply

Let operators define non-secret control-plane state in reviewable TOML or YAML:

- Identities.
- Existing path grants.
- Rotation intervals.
- Federated authentication bindings.
- Consumer declarations.

Secret values, bootstrap credentials, raw tokens, and AppRole secret IDs would
never be accepted in the document. Credential issuance remains an imperative,
disclose-once operation.

`plan` would calculate and explain:

- Privilege expansions and reductions.
- Active and declared consumers affected by the change.
- Live credentials whose next requests would lose access.
- Attempts to remove or disable the final management identity.
- Drift between declared and stored control-plane state.

`apply` would commit the complete management change in one redb transaction and
one auditable management operation. It would refuse unsafe transitions rather
than partially applying them.

This remains distinct from a policy DSL. The document serializes concrete
objects already understood by the server; it has no conditions, inheritance,
embedded code, or general-purpose expressions.

**Relative implementation cost:** Medium. The most important requirements are
a deterministic diff, atomic application, safety invariants, and stable object
identifiers.

## 9. A continuous least-privilege advisor

Use existing scopes, consumer declarations, and audit history to produce
deterministic recommendations and explanations:

- Access is granted but neither declared nor observed.
- An identity or credential has been dormant beyond a configured window.
- A scope pattern reaches paths the operator may not expect.
- A consumer still fetches a superseded version.
- A previously inactive identity begins reading a new path.
- A narrower concrete scope would cover all declared dependencies and recent
  activity.

Recommendations must never make authorization changes automatically. Rarely
run jobs, emergency procedures, and activity outside the audit window make
usage-only pruning unsafe. Each recommendation should state its evidence,
lookback period, confidence limitations, and affected declared consumers.

An accompanying command such as `access explain <identity> <operation> <path>`
would show the canonical logical path, the normalized API operation, and the
exact grant responsible for an allow or denial. External error responses remain
appropriately non-revealing; the detailed explanation is management-gated.

**Relative implementation cost:** Small to medium. It primarily reuses the
authorization matcher and audit data as read-only analysis, with no new policy
engine.

## 10. A metadata-first operator cockpit

Embed a terminal user interface in the existing binary instead of deploying a
separate web application. A single management-gated cockpit could show:

- Overdue rotations.
- Active rotation campaigns and consumer version adoption.
- The declared, authorized, and observed consumer graph.
- Scope discrepancies and least-privilege recommendations.
- Audit-chain and off-host checkpoint health.
- Backup rehearsal status.
- TLS and storage-capacity warnings.

Secret values should not be rendered by default. Deliberate writes can use
masked input and the same management APIs as the CLI. The TUI must not become a
second privileged implementation path: authentication, authorization,
validation, and auditing remain in the shared application services.

A TUI preserves the single-binary deployment model, introduces no browser,
JavaScript, CSRF, or additional listener surface, and makes the system's most
differentiating information immediately visible.

**Relative implementation cost:** Medium. It should be API-first and built only
after the underlying rotation, graph, and health queries are stable.

## Strongest combined product workflow

The highest-leverage package is ideas 1 through 3 together:

```text
declare dependencies
    -> reconcile declared, authorized, and observed reality
    -> preflight the replacement against its contract
    -> cut over
    -> observe each consumer fetch the new version
    -> revoke the old credential upstream
    -> retire the prior version
    -> produce signed evidence
```

That workflow is a genuine product moat. It focuses on the unsolved operational
work around static credentials rather than expanding toward Vault's platform
surface.

## Low-cost architectural accommodations for v0.1

These feature candidates should not expand the current v0.1 scope. Three small
internal seams would, however, make the strongest ideas much cheaper later:

1. Include the returned secret version in every successful read audit event.
   This remains non-secret metadata and enables precise cutover tracking.
2. Have the authorization engine produce a structured internal decision
   explanation rather than only a boolean. Normal request handling can discard
   it; future management tooling can render it safely.
3. Reserve a schema-versioned, encrypted metadata record per secret so consumer
   declarations, structural contracts, and rotation-campaign references can be
   added without changing stored secret ciphertext records.

The recommended roadmap discipline is to ship and validate v0.1 first, then
plan the consumer truth graph, rotation campaigns, and contract-safe versions
as one coherent follow-up rather than adding all ten features opportunistically.
