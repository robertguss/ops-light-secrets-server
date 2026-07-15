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
