---
id: T04
title: "Runtime stack: Rust, crate composition, redb vs SQLite, spike gate"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T01]
---

## Question

Walk and verdict the stack foundations:

- Rust over Go (session-settled; on the table per charting preference).
- Compose-the-ecosystem thesis — proven crates wired together, learning lands
  in the assembly (Key Decisions).
- Storage: redb vs SQLite/rusqlite vs simpler; whether KTD2's proof-spike gate
  (multi-table atomic commit, crash recovery, backpressure, snapshot, latency
  thresholds — U2 opening) survives as designed, shrinks, or the fallback
  triggers pre-emptively.
- KTD8's single bounded storage executor and one-durability-domain shape —
  understand it well enough to defend the accepted throughput ceiling.

Resolution: verdicts plus explain-back on why this store and this executor
shape. A fact gap here (e.g. redb maturity signals) may spawn a research
ticket rather than stall the session.

## Resolution

Resolved 2026-07-15 (grilling session). Four verdicts:

1. **Rust over Go — keep.** Learning is the stated primary success criterion;
   Go would optimize for shipping speed, which is explicitly not the point.
   The fail-closed floor is enforced by tests and design (spike gate, crash
   suites), not language fluency, so beginner mistakes get caught by the
   harness rather than shipped. Phase-2 fnox provider is Rust either way.

2. **Compose-the-ecosystem — keep, no amendment.** Hand-building was rightly
   rejected; supply-chain slippery-slope risk is already fenced by the
   complexity budget and dependency review at addition time. A formal
   crate-count ceiling was considered and declined as process weight closing
   no named failure mode.

3. **Storage: keep redb, keep the spike gate, shrink the spike to
   store-facts.** The gate is what makes single-maintainer risk acceptable —
   it converts "trust a young crate" into "verified the behaviors we depend
   on." Spike now proves, on redb, on the reference host: multi-table atomic
   commit, kill-point crash recovery, logical consistent snapshot,
   durable-commit latency, file growth/compaction — quantitative pass/fail
   thresholds recorded, SQLite fallback triggers here or never.
   **Moved out of the gate** (they are executor properties, identical over
   any store, and belong in U2/U6 executor tests): bounded-executor
   backpressure and queue-saturation behavior; rotation/audit index query
   latency (KTD16 indexes are app-level tables). T14 applies this shrink to
   KTD2 and U2's approach text. Pre-emptive SQLite switch considered and
   declined: trades verified fit for unverified comfort.

4. **KTD8 — keep exactly as designed.** One thread, one file, one commit
   path; reads audited durably before response. Every alternative (async
   audit queue, separate audit file, best-effort read audit) reintroduces the
   crash window between state and record that R26 exists to close, buying
   throughput that has no customer. Reserved control lane stays — it closes a
   named failure mode (R27: saturation locking out backup/shutdown) for the
   cost of one bounded channel.

### Explain-back (Robert, verbatim / confirmed)

- "Rust has a steeper learning curve but it is something I want to learn; it
  is also used by fnox."
- "I would prefer to use well-known crates instead of rolling my own
  cryptography algos, for example. I prefer to stand on the shoulders of
  giants."
- "redb over SQLite because it fits a versioned-blob KV without an SQL layer,
  pure Rust, one small crate — and the spike proves atomic multi-table
  commit, crash recovery, snapshot, commit latency, and compaction on the
  real host before anything is built on it." (crib confirmed)
- "Every read and write goes through one thread and one fsync'd commit, so
  the server tops out around hundreds of ops/sec on cheap-VPS fsync, which is
  fine because consumers are a handful of devs' fnox pulls plus CI — peak
  load is tens of ops/sec." (crib confirmed)
- Framing, his words: "All of the other questions are an effort to keep
  things simple without overblowing in complexity."
