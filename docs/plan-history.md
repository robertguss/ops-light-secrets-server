# Plan History — Ops-Light Secrets Server

Decision and revision history moved out of
`docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md` so the plan
stays a present-tense, canonical contract. Where anything here disagrees with
the plan, the plan wins.

## Revision rounds (2026-07-15)

**Product Contract preservation:** Product Contract changed during planning. R11
recast to write-is-cutover (staging lives upstream); R12 gained a secret-age
anchor and no-interval display; R18 bootstrap-order reworded; R3 gained R31
(auth surface); R30/R32 and AE6–AE8 added; OQ2/OQ4–OQ7 resolved into Key
Technical Decisions below. Each change resolves a 2026-07-15 review finding the
user signed off on; none alters the product's problem frame, actors, or
positioning.

A second 2026-07-15 revision round incorporated a three-way competitive plan
review. Substantive outcomes: remote bootstrap replaced by local `init` plus a
local control plane (R17/R30/R34); the `age` decision evolved to a keyring wrap
with record AEAD (KTD3); state and audit unified into one transactional
durability domain (R26/KTD8); credentials recast as accessor-plus-keyed-MAC with
no hot-path password KDF (KTD5); CAS, capability separation, canonical paths,
version-on-audit, and the rotation status view added (R8/R11/R13/R22/ R33);
backup gained a manifest and credential epoch (R32); schema versioning,
operational lifecycle, and CLI hygiene added (R35–R37); U0 client
characterization added; threat model added below. The problem frame, actors,
positioning, single-node ceiling, and the deferrals the user already ruled on
(pre-migration inventory, production adoption) are unchanged.

A third 2026-07-15 revision round integrated the idea-consolidation review
(`docs/plans_revisions/gpt-ideas-consolidation.md`), which scored every
externally proposed feature and found several already present (the rotation
tracker, `authz explain`, the metadata seam, systemd credentials, `doctor`).
Substantive outcomes: the offline metadata-confidentiality boundary made
explicit (R4, KTD11, Threat Model); destroy recast as logical rather than
cryptographic erasure (R29); the AEAD nonce lifecycle specified (KTD3, U2, U8);
first-admin credential delivery made failure-safe by disclosure-before-commit
(R17, U1, F1); a complexity budget adopted as a Key Decision; clock rollback
made fail-closed (R18, Assumptions); audit events gained the credential
accessor, and the rotation status view gained accessor-level adoption plus a
completion guard with audited override and a redacted closeout report (R13, R11,
R33, F4, AE11, U6, U7); a full disaster-recovery rehearsal added as
`backup verify --full` (R32, U10, U12); differential compatibility testing
against a pinned OpenBao reference added (U11); release integrity added as a
requirement (R38, U12); and systemd-credential delivery made concrete with
tested fixtures (U1, U12). The consumer truth graph plus migration
import/discovery are named the first post-v0.1 package, and the review's
rejections — server-side execution, generic webhooks, schedulers, process
supervision, a TUI, demo mode, automatic grant pruning, fingerprint drift
endpoints — are recorded in Scope Boundaries and the dispositions table. The
problem frame, actors, positioning, and single-node ceiling are again unchanged.

A fourth 2026-07-15 revision round integrated the implementation review in
`docs/plans/revisions/gpt.md`. Substantive outcomes: readiness recast as gated
(G0–G3, front matter); clear structural records MAC-authenticated with
checkpointed state digests (R4, R39, KTD15); the `age`-encrypted keyring moved
into the redb `system_keyring` table so keyring changes commit atomically with
their audit events (KTD3, KTD8, U8); a rebuildable blind audit query index
(KTD16); the checkpoint private key moved out of the daemon into an explicit
prepare/sign/register CLI flow (KTD4, R14, R36); raw-request-target validation
before router decoding plus duplicate-key/header rejection (R8, KTD9, U3, U9);
a bounded storage executor owning redb (KTD8, U2); rotation split into
begin/cutover with stable consumer-instance ids and a server-owned rotation
interval (F4, R11, R12, R33, KTD5, U7); the declared-consumer registry pulled
into v0.1 (R40, AE13 — reversing the earlier deferral recorded below;
discovery/import stay v0.2); credential kind/audience/epoch in the verifier
domain, `SO_PEERCRED` on the control socket, and the credential-epoch incident
command pulled into v0.1 (R17, R24, R31, R32, R34, R41); clock forward-jump
protection and `clock repair` (R18, R36, Assumptions); XChaCha20-Poly1305 with
a canonical binary crypto encoding (KTD3, U2); a logical backup format with
explicit recovery audit epochs (R32, KTD17, U10); the compatibility matrix
regenerated at U0 time, a BUSL-client release gate, and remote metadata-delete
declared unsupported (KTD14, U0, R1, R29); segmented audit retention with
archive/prune and a preallocated recovery reserve (R13, R14, R23, R27, KTD4,
U6); a Linux-first supported-runtime contract and corrected axum/axum-server
attribution (Scope Boundaries, KTD1, R38); and milestones M0–M3 with U0 ∥ U1
sequencing (Sequencing, Unit Index). The problem frame, actors, positioning,
and single-node ceiling are again unchanged.

## Review dispositions

Dispositions below are historical records of earlier rounds; the fourth round
superseded two of them (declared-consumer registry and the credential-epoch
incident command now ship in v0.1 as R40 and R41).

### From 2026-07-15 review — dispositions

The document review's findings were resolved during planning enrichment; each
landed in the Product Contract or Planning Contract above.

| Finding                                                   | Disposition                                                                                                                   |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| KV v2 versions lack a cutover contract                    | Resolved — R11 recast to write-is-cutover; staging lives upstream. AE3, U7.                                                   |
| R14 tamper-evidence names no threat actor or trust anchor | Resolved — KTD4: per-entry `blake3` chain + off-host `ed25519` signed checkpoints. AE5, U6.                                   |
| Vault-compatible authentication surface undefined         | Resolved — R31: token auth + AppRole login. U4.                                                                               |
| Workload bootstrap has no secret-zero mechanism           | Resolved as accepted posture — secret_id delivered by the deployment mechanism (Assumptions, Dependencies). U12.              |
| Bootstrap sequence conflicts with startup validation      | Resolved — superseded by local `init` (2026-07-15 second revision): R17/R30/R34 recast, no remote bootstrap route exists. U1. |
| Developer credential storage an unchosen posture          | Resolved — accept-and-mitigate (scope + TTL + revocation), optional keychain helper (Dependencies). U12.                      |
| Ops-light stops before backup/restore                     | Resolved (backup/restore) — R32, AE7, U10. Upgrade-with-rollback deferred below.                                              |
| `age` identity rotation has no acceptance invariant       | Resolved — U8 crash-recoverable re-encrypt; KTD3.                                                                             |
| Secret age has no lifecycle anchor                        | Resolved — R12 anchors age to last completed rotation.                                                                        |
| Clean-host client onboarding unvalidated                  | Resolved — AE8, U11, U12.                                                                                                     |

### From 2026-07-15 planning

### From 2026-07-15 idea-consolidation review — dispositions

The idea-consolidation review
(`docs/plans_revisions/gpt-ideas-consolidation.md`) scored every externally
proposed feature. Several were already present — the rotation adoption tracker
(R33/U7), `authz explain` (KTD10/U12), the KTD11 metadata seam, systemd
credential loading, `doctor` (U12), versioned read audit events, structured
authorization decisions, schema-versioned metadata — and are preserved, not
double-counted. The rest:

| Idea                                     | Disposition                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Metadata-confidentiality contract        | Adopted — explicit offline boundary (R4, KTD11, Threat Model).                                          |
| Honest destroy semantics                 | Adopted — logical destruction, not cryptographic erasure (R29).                                         |
| AEAD nonce lifecycle                     | Adopted — KTD3 nonce discipline, per-key counter, reuse tests (U2, U8, U11).                            |
| Failure-safe first-admin delivery        | Adopted — disclosure-before-commit with kill-point tests (R17, U1).                                     |
| Complexity budget                        | Adopted — Product Contract Key Decision; hard rules for the first two releases.                         |
| Clock-rollback fail-safe                 | Adopted — persisted high-water mark, startup refusal, audited override (R18, Assumptions).              |
| Accessor-level rotation evidence         | Adopted — accessor on audit events (R13); accessor-granularity status, "fetched" not "using" (R33, U7). |
| Full recovery rehearsal                  | Adopted — `backup verify --full` (R32, U10); `doctor` reports rehearsal age (U12).                      |
| Rotation closeout guard + report         | Adopted into v0.1 — guard with audited override; redacted report rides the audit chain (R11, R33, U7).  |
| Differential compatibility testing       | Adopted — normalized corpus vs pinned OpenBao reference (U11).                                          |
| Release integrity                        | Adopted — R38, U12 (signing, SBOM, provenance, MSRV, `SECURITY.md`, published-binary smoke).            |
| systemd credential concreteness          | Adopted — tested example units and credentials-directory test (U1, U12).                                |
| Consumer truth graph                     | Deferred — named first post-v0.1 package (Scope Boundaries).                                            |
| Migration importers and discovery        | Deferred — same package; client-side, reuse fnox machinery (Scope Boundaries).                          |
| Narrow OIDC (single issuer profile)      | Deferred to v0.3, after AppRole is proven (Scope Boundaries).                                           |
| Credential-epoch incident command        | Deferred to v0.3; reuses R32's epoch primitive.                                                         |
| Fixed structural secret contracts        | Deferred to v0.3, narrowly scoped; never a schema language.                                             |
| `scope dry-run` advisor                  | Deferred to v0.3, advisory only; nothing is ever auto-revoked.                                          |
| Aggregate local metrics                  | Deferred to v0.3; control-socket/loopback only, no identifying labels (R25).                            |
| Operator-side rotation adapters          | Deferred to v0.3; operator authority, piped into the normal CAS write.                                  |
| Local signed event outbox                | Deferred; the accepted alternative to webhooks.                                                         |
| Declarative `plan/apply`                 | Deferred, reduced to `export`/`validate`/`diff`/`ensure`; omission never means deletion.                |
| Delegated / one-time-read credentials    | Deferred as CLI sugar over existing primitives; never a second authz model or special secret type.      |
| Per-secret runbook metadata              | Deferred; local-only encrypted operator record, not remote-visible `custom_metadata`.                   |
| Client-side live reload                  | Deferred to the client ecosystem; the server exposes metadata, never supervises.                        |
| Vault CLI shim                           | Conditional on U0/U11 evidence; upstream fnox provider preferred, else a tiny separate shim binary.     |
| Generic outbound webhooks                | Rejected — an egress subsystem inside the secret-bearing process (Scope Boundaries).                    |
| Server-side `rotate_exec` hooks          | Rejected — arbitrary code in the most privileged process.                                               |
| In-process scheduler / durable job queue | Rejected — external timers own time-based behavior.                                                     |
| Watch-and-run process supervision        | Rejected from the server — a client-ecosystem product.                                                  |
| Metadata TUI cockpit                     | Rejected for now — CLI JSON must stabilize first.                                                       |
| Demo mode in the production binary       | Rejected — unsafe modes get used accidentally; use disposable fixtures.                                 |
| Automatic grant pruning                  | Rejected — non-observation is not non-need.                                                             |
| Server-attested upstream revocation      | Rejected as impossible — remains an operator attestation (R33, U7).                                     |
| Salted-hash drift/fingerprint endpoint   | Rejected — a secret-equality oracle; any later drift scan is client-side over `read-history`.           |
