---
label: wayfinder:map
title: Own and right-size the ops-light secrets server plan
created: 2026-07-15
---

# Map: Own and right-size the ops-light secrets server plan

Tracker convention (no external tracker configured — this directory is the
tracker): tickets live in `docs/wayfinder/tickets/`, one file each, frontmatter
carries `id`, `label` (`wayfinder:<type>`), `status` (`open`/`closed`),
`assignee` (claim = set it; empty = unclaimed), `blocked-by` (ticket ids).
**Frontier** = open + unassigned + every blocker closed. Resolve a ticket by
appending a `## Resolution` section, setting `status: closed`, and adding one
line to Decisions-so-far below.

## Destination

A revised plan (successor to
`docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md`) in which
every load-bearing decision has been walked and carries Robert's own verdict —
keep / simplify / defer — and which Robert can explain from understanding and
start building. The map is done when T14's rewrite lands and nothing is left
to decide before implementation starts.

## Notes

- Domain: self-hosted secrets server (Rust, Vault KV v2-compatible) for a
  small nonprofit dev team; solo operator; learning is the stated primary
  success criterion. Canonical current plan:
  `docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md`. Decision
  history: `docs/plan-history.md`.
- Skills: grilling tickets run `/grilling` + `/domain-modeling`; spawn
  `/research` only when a fact gap blocks a verdict; `/prototype` if a surface
  question (e.g. CLI UX) needs an artifact to react to.
- Standing preferences (settled at charting, 2026-07-15):
  - **Everything on the table.** No decision is frozen — session-settled
    product choices (Rust, Vault-compat, age, redb, license) included.
  - **Ruthless complexity budget.** Close call → simplify or defer unless it
    closes a named failure mode in the threat model. The fail-closed security
    floor is never cut.
  - **Explain-back required.** Every resolution ends with a short paragraph in
    Robert's own words stating the decision and why — feeds the plan's primary
    success criterion.
  - **One ticket per session.** The plan document itself is edited only by
    T14; earlier verdicts accumulate on their tickets and this map.

## Decisions so far

<!-- one line per closed ticket: [title](link) — gist -->

- [Product frame: is ops-light, rotation-first still the product?](tickets/T01-product-frame.md)
  — re-affirmed in full, zero amendments: rotation-first frame, ops-light
  ceiling (hard), actors + agent-later + `kind` field, explain-back as primary
  gate, no assumptions drift. Nothing downstream invalidated.
- [Task: post to fnox Discussions asking jdx about native/server interest (OQ1)](tickets/T02-fnox-discussions-post.md)
  — posted as [fnox discussion #615](https://github.com/jdx/fnox/discussions/615);
  jdx replied 2026-07-15: direct-HTTP rewrite of the existing `vault` provider
  welcome (in-place, keep config/auth/TLS, compat tests vs Vault + OpenBao);
  native protocol = interest, no commitment, use-case-first design discussion.
  Strengthens T03's ladder; nothing invalidated.
- [Wire protocol: Vault-compat vs fnox-native, surface size, BUSL shim](tickets/T03-wire-protocol.md)
  — keep Vault-compat first (differential oracle vs OpenBao is decisive); keep
  R1/R3/R31/KTD12 surface (sized by rotation workflow, not fnox traffic);
  simplify BUSL gate (shim demoted to post-v0.1 evidence-gated; ladder:
  bao-swap → upstream provider → documented vault install); keep full U0/G0
  with done-when-questions-answered guard. All four explain-backed.
- [Runtime stack: Rust, crate composition, redb vs SQLite, spike gate](tickets/T04-runtime-stack.md)
  — keep Rust (learning is the criterion; harness catches beginner mistakes);
  keep compose-thesis unamended; keep redb but shrink the KTD2 spike to
  store-facts only (backpressure + index latency move to U2/U6 executor
  tests — T14 applies); keep KTD8 exactly as designed, ceiling defended.
  All four explain-backed.

- [Crypto at rest: age keyring, AEAD binding, clear-metadata boundary](tickets/T05-crypto-at-rest.md)
  — keep all four pieces unamended: KTD3 keyring (five purpose keys, age
  envelope, boot-supplied identity as the whole seal), XChaCha AEAD with
  binary AAD + random nonces, clear-metadata boundary (MAC + state digest —
  digest **conditional on T08** keeping external checkpoints), zeroization
  with honest limits. Explain-back agent-supplied at Robert's request;
  own-words version pending — redo at T14 or before U2.

## Not yet specified

- Post-v0.1 package re-sort: the v0.2 (discovery/import) and v0.3 (automation
  edges) lists need re-cutting once v0.1 verdicts land — what got deferred
  joins them, what got cut leaves them.
- Whether the plan's unit structure (U0–U12), freeze gates (G0–G3), and
  milestones (M0–M3) survive the re-scope or get redrawn — sharpens at T14.

## Out of scope

- Implementing any unit — building follows the revised plan as a fresh
  effort; this map only decides.
- Production adoption and the real Canvas/Populi rotation — the plan already
  defers both on FERPA grounds; nothing here re-opens that.
- Choice of interim production tooling (OpenBao presumed) — the plan records
  that it does not change v0.1 goals.
