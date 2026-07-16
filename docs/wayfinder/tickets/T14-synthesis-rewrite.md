---
id: T14
title: "Synthesis: rewrite the plan as the right-sized, owned v0.1"
label: wayfinder:grilling
status: closed
assignee: Robert Guss
blocked-by: [T01, T03, T04, T05, T06, T07, T08, T09, T10, T11, T12, T13]
---

## Question

Fold every ticket's verdict into a successor plan document:

- Revised requirement list, KTDs, units, gates, and milestones — everything
  cut or deferred moves to explicit post-v0.1 lists; nothing silently
  vanishes.
- Reconcile cascades (e.g. if T08 deferred checkpoints or the blind index,
  T09's rotation surface and the threat model's claims must match).
- T02's answer (jdx reply) folds into phase-2 framing if it has arrived;
  otherwise the plan keeps OQ1 open.
- Closes with the explain-back rehearsal: Robert states the full design —
  seal boundary, token lifecycle, audit chain, rotation evidence — without
  consulting the document, per the plan's primary success criterion.

Resolution: the revised plan committed under `docs/plans/`, superseding
`2026-07-15-001`, plus the map's Decisions-so-far complete. Reaching this is
the map's destination.

## Resolution (2026-07-16)

**The successor plan is
[`docs/plans/2026-07-16-002-feat-ops-light-secrets-server-plan.md`](../../plans/2026-07-16-002-feat-ops-light-secrets-server-plan.md)**
— produced by copying `2026-07-15-001` and surgically editing every site a
T01–T13 verdict touched, so everything kept stays byte-identical. The old
plan carries a superseded banner; `docs/plan-history.md` gains the
fifth-round entry with the full change list.

What changed (nothing vanished silently — every cut/defer lands in an
explicit list):

1. **T08's two defers folded through the whole document.** KTD16 blind index:
   R33/R23/U6/U7 recast to primary-event scans inside R23's window; the
   index-health closeout clause and the tag-cardinality threat-model line
   removed; `src/audit/index.rs` dropped from U6; doctor checks audit-table
   size against the upgrade trigger instead of index health; the index
   format left G2 and M0; DoD's fail-closed list dropped the KTD16 clause.
   Segmented retention: R13/R14 recast (all events active, two verification
   tiers in practice, manifest design recorded for later); KTD4's
   archive/prune commands marked deferred; R27's reserve sizing drops
   archive-registration; R32's backup frame list says "all audit events."
   Both defers + full designs recorded in Scope Boundaries and Deferred /
   Open Questions.
2. **T03's ladder replaces the shim gate.** Scope Boundaries and U0's exit
   gate now carry bao-CLI → upstream provider → documented-install; shim
   post-v0.1 evidence-gated; U0 gains the done-when-questions-answered
   guard.
3. **T04's spike shrink.** KTD2/U2/G1 narrowed to store-facts; backpressure
   moved to U2/U6 executor test scenarios (added both places).
4. **T10's dormant key.** KTD3 notes the audit-index key minted-but-dormant;
   U8 records four live rotation semantics with the fifth deferred.
5. **T13's meta.** KTD13 → MIT (rationale + accepted consequence recorded);
   U12 license text + deny.toml note + positioning paragraph added; OQ3
   parked with the before-any-public-artifact deadline.
6. **T02 folded.** OQ1 marked answered with jdx's constraints; phase-2
   framing (Goal Capsule, Scope Boundaries) now gates on the use-case-first
   design discussion; the provider rung marked confirmed-welcome.
7. **Structure survived.** U0–U12, G0–G3, M0–M3 all stand (G1/G2/M0
   rewordings only) — every ticket kept the machinery its unit builds, so
   there was nothing to redraw.

**Explain-back rehearsal: DEFERRED to build start — Robert's explicit call
this session,** consistent with the explain-back retirement (map Notes) that
moved the learn-by-explaining check "to T14 review and to building itself."
The rehearsal (seal boundary, token lifecycle, audit chain, rotation
evidence — stated without consulting the document) should run before or
during U1/U2, where the plan's own success criterion will enforce it anyway.
T05's own-words redo rides the same deferral.

**Map state:** destination reached. Decisions-so-far complete (this entry
closes it); both Not-yet-specified items resolved by this rewrite (post-v0.1
lists re-cut in the plan's Deferred section; unit/gate/milestone structure
confirmed standing). No new tickets — the way is clear: build follows the
revised plan as a fresh effort.
