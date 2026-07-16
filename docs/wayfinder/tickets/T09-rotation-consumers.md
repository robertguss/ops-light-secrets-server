---
id: T09
title: "Rotation & consumers: registry, three views, status granularity, closeout"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T08]
---

## Question

Rotation is the product's wedge — how much ceremony ships in v0.1?

- R40 declared-consumer registry (the fourth-round reversal put it back in
  v0.1) — keep, or trust migration order without it?
- R10's three separately labeled views (declared/authorized/observed) and
  reconciliation states.
- R33 status view: on-current/on-prior/silent-since-write at declared,
  identity, AND consumer-instance granularity, plus the guarded
  `rotation complete` with audited override. Ruthless-budget question: does
  v0.1 need instance granularity and the closeout guard, or is observation
  plus operator judgment enough for a solo operator?
- R11's begin/cutover/complete state machine with CAS protection; R12
  age/interval display.
- Dependency check: which of these survive if T08 deferred the blind index?

**Note (from T08, 2026-07-16):** blind index DEFERRED — v0.1 rotation-status
queries scan primary events over R23's lookback window; R33's index-health/
closeout fail-closed coupling is gone from v0.1 (primary is always
authoritative). Walk R33's granularity question against scan cost, not
index cost. Checkpoints and segmentation verdicts: checkpoints kept,
archive/prune deferred.

Resolution: a chosen v0.1 rotation surface (what's kept, what joins the
post-v0.1 campaign list) plus explain-back on why observed reads — not
grants — are the rotation evidence.

## Resolution (2026-07-16)

Grilling session (fourth ticket this session, Robert's call). **v0.1
rotation surface: kept in full.** The fourth-round reversal (R40 back in)
re-affirmed from first principles. Nothing new joins the post-v0.1 campaign
list beyond T08's index/segmentation defers; the campaign state machine was
already out (R33's last line).

1. **R40 declared-consumer registry — KEEP.** Declared is the only view
   that sees off-system consumers (secret pasted into a SaaS dashboard, a
   partner system — no identity, never observed). Declared-but-unobserved
   is the pre-closeout check that matters (the quarterly cron that hasn't
   fetched since cutover); authorized-but-undeclared is free grant-sprawl
   detection. Already the minimal cut: static records, no discovery, no
   import, no execution.
2. **R10 three labeled views, never collapsed — KEEP.** Intent (declared),
   capability (authorized), evidence (observed) — a collapsed list is one
   of two lies (grants overstate knowledge; observed understates it).
   Mostly a prohibition, not machinery: queries over tables already kept
   at T07/T08/Q1.
3. **R33 instance granularity + guarded closeout — KEEP whole** (index-
   health clause already removed by T08's defer; guard evaluates primary
   events). Instance granularity: identity rollup structurally overstates
   adoption (one replica re-fetches, two still hold the old value → revoke
   upstream → outage); the plumbing (consumer_instance_id in KTD5, in every
   audit event) was already paid for at T06/T08 — here it's a GROUP BY key
   plus retired-without-proof labeling. Closeout guard: one predicate over
   the status view; `--acknowledge-unverified` + audited reason IS
   "operator judgment," made recordable. Completion triggers upstream
   revocation — the guard is the last thing before the outage. "Fetched,
   never using" stays — server proves delivery, not adoption.
4. **R11 state machine + R12 age/interval — KEEP both.** begin freezes the
   goalposts (snapshot without write); cutover is CAS-atomic (T03's wire
   semantics reused; conflict leaves prepared, never a mutated snapshot);
   cancel pre-cutover only; post-cutover recovery is copy-forward (version
   pointer never moves backward); supersession blocks stale completion.
   Without the machine the closeout guard has no snapshot to evaluate.
   R12: interval is control-plane-owned (remote writers can never alter
   rotation policy), `changed_since_last_completed_rotation` keeps the age
   display honest, no in-daemon timers — the operator heartbeat, minimal.

### Why observed reads — not grants — are the rotation evidence
(rationale record)

**Agent-drafted, not Robert's words** (explain-back retired — map Notes).

A grant is a statement about the future: this identity *may* read. Rotation
closes on a statement about the past: who *has* the old value, and who has
picked up the new one. Only audited fetches answer that — version served,
instance, timestamp. Grants can't testify (an authorized identity may never
have fetched, or fetched last year); declarations can't either (intent, not
state). This is why the whole edifice stands on T08's kept floor: R26 makes
every read durably audited before the response leaves, so the observed view
is evidence-grade rather than best-effort telemetry — and why the guard
language stops at "fetched version N": delivery is provable from the
server's seat; *use* would need an application-level acknowledgement, which
is honestly out of v0.1. Rotation status is therefore a fold over audit
events against the rotation snapshot: last verified fetch per declared
consumer, identity, and instance, bucketed on-current / on-prior /
silent-since-write — computed in v0.1 by scanning primary events inside
R23's window (T08 defer), with completion gated on that evidence or an
audited human override.

**Downstream:** nothing invalidated, no new tickets, no fog graduates
(post-v0.1 re-sort note already carries the campaign/automation material).
T14 inherits the full-keep rotation surface; T10's recovery walk can rely
on rotation state surviving restore semantics unchanged.
