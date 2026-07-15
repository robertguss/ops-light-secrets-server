---
id: T04
title: "Runtime stack: Rust, crate composition, redb vs SQLite, spike gate"
label: wayfinder:grilling
status: open
assignee:
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
