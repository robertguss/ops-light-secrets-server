---
id: T07
title: "AuthZ: canonical resource, raw-target guard, grants, capability set"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T03]
---

## Question

Walk and verdict the authorization boundary:

- KTD9's RawTargetGuard + single canonical `Resource` parse — reject-not-
  normalize posture, one module one corpus. Understand why validation must
  run before framework decoding.
- Grant model: exact-path or segment-prefix subtree, no globs/deny/DSL (R8).
- R22's closed capability set — 7 secret + 9 management capabilities.
  Ruthless-budget question: does v0.1 need this many distinct capabilities,
  or does a smaller set survive the same threat model?
- Capability-thin tokens + per-request grant reload as the R28 linearization
  story.
- R29's delete/destroy/purge ladder and destroy-all being local-only.

Resolution: verdicts plus explain-back on how a request becomes an
authorization decision.

## Resolution (2026-07-16)

Grilling session (same session as T06, Robert's call to continue). **All
five: KEEP as written, zero amendments.** Each argued against its cheapest
cut; the only one that was ever close was the capability count.

1. **KTD9 RawTargetGuard + canonical `Resource` — KEEP, not close.**
   Validation must precede framework decoding because Axum percent-decodes
   before handlers: after that, `/` and `%2F` are the same byte and the
   grant check can't see the smuggled separator — the classic path-confusion
   bypass class. Reject-not-normalize because a normalizer is a second
   interpretation layer and every normalizer disagreement is a bypass;
   rejection can't disagree. One module/one corpus feeds U0's differential
   oracle. Fail-closed floor — never cut per map preferences.
2. **R8 grant model — KEEP.** Allow-only (absence = deny, fail-closed, no
   precedence semantics); no globs (metacharacters reintroduce the ambiguity
   KTD9 killed); no DSL ("no policy language to author" is the plan's
   falsifiability line for ops-light). Exact-only was rejected as too
   simple: subtree-prefix is the minimum grouping that avoids per-secret
   grant churn.
3. **R22 closed capability set (7+9) — KEEP.** The steelmanned cut (two
   roles: admin/auditor) fails because: read-current/read-history *is* the
   rotation threat model (history = still-valid or never-yours-to-retain
   credentials); the delete/destroy/destroy-all splits are R29's safety
   line; audit-pull-without-mint and backup-only-cron are real narrow-grant
   actors; and the endpoint surface forces the distinct code paths anyway —
   the enum names distinctions the router already has, so collapsing saves
   ~zero code. Versioned closed set: growing later is a schema migration.
   Bundles (`admin`, `auditor`) already give the two-role UX. Only viable
   merge (soft-delete into write) saves one variant and breaks Vault-
   semantic symmetry the oracle compares.
4. **R28 capability-thin + per-request grant reload — KEEP.** The alternative
   (grant snapshots or caches) needs an invalidation bus or accepts staleness;
   reloading inside the already-open transaction is less machinery and a
   stronger guarantee (admin changes land at the transaction boundary,
   rejections audited). Cost: one b-tree lookup per request at small-team
   scale, under KTD8's single executor.
5. **R29 ladder + destroy-all local-only — KEEP whole.** Ladder rungs were
   already settled by T03's surface keep; this ticket's own pieces all hold:
   remote metadata-DELETE fenced (closes remote mass-destruction; U0 escape
   hatch priced in), purge ceremony (capability + exact resource +
   confirmation + audited reason), logical-not-cryptographic erasure
   documented honestly (per-version DEK hierarchy explicitly out of v0.1),
   and rotation-protected retention (`retention_deferred_by_rotation`)
   so pruning can never destroy the still-live prior version mid-cutover.

### Request → authorization decision (rationale record)

**Agent-drafted, not Robert's words** (explain-back retired — map Notes).

Raw `Request::uri()` hits the RawTargetGuard before any route extraction:
malformed escapes, encoded separators/backslashes, double-decode vectors,
dot segments, empty/repeated segments, control chars, NUL, overlong targets,
duplicate sensitive query params — all rejected. Exactly one decode runs,
producing an `EndpointRequest { endpoint_kind, Resource { mount,
canonical_segments } }` placed in request extensions — the only resource
representation handlers or authz ever see; nothing downstream touches a
framework-decoded path. Authentication then verifies the token (T06's
verify path). The handler's storage transaction opens; current grants for
the identity are reloaded inside it (R28). The matcher takes (Resource,
capability implied by endpoint kind) against grant records `{ mount,
exact_or_subtree, prefix_segments, capabilities }` — byte-for-byte segment
comparison, no normalization — and returns KTD10's structured decision
`{ allow, resource, operation, matched_grant | deny_reason }`. Allow: the
handler proceeds with the typed resource. Deny: uniform error to the client
(R25 — no oracle), full decision into the audit event, inspectable later via
control-plane `authz explain`.

**Downstream:** nothing invalidated, no fog graduates, no new tickets.
T14 inherits five more keeps. With T06+T07 both closed, the whole
authn/authz boundary is walked and owned — the plan's security spine is
holding up under first-principles re-derivation.
