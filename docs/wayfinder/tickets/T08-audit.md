---
id: T08
title: "Audit: atomic commit, hash chain, external checkpoints, blind index"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T04, T05]
---

## Question

The heaviest LLM-added machinery lives here — prime ruthless-budget
territory. Walk each layer, decide which assurance level v0.1 actually needs:

- R26 atomicity: state+audit in one transaction, response-after-commit, every
  read a durable write (KTD8's accepted ceiling). Floor or negotiable?
- blake3 per-entry hash chain over encrypted payloads (KTD4) — local
  tamper-evidence.
- Externally signed checkpoints: the prepare/sign/register ceremony, off-host
  mirror, signing key never in the daemon, checkpoint chains, KTD15 state
  digest anchoring. Keep for v0.1, or defer to the chain-only assurance tier?
  **Note (from T05):** T05's keep-verdict on the KTD15 state digest is
  conditional on checkpoints surviving here — cutting/deferring them re-opens
  that piece of T05.
- KTD16's blind query index (keyed tags, verify-against-primary, rebuild) —
  exists to make rotation status cheap. Defer with rotation, keep, or
  simplify to full-scan-at-small-scale?
- Segmented retention / archive / prune (R13, R23) — v0.1 or later?
- R25 no-secret-output ban and R27 capacity fail-closed + recovery reserve.

Resolution: a chosen assurance tier per layer with named failure modes that
justify it, plus explain-back on audit chaining — a named learning target.

## Resolution (2026-07-16)

Grilling session (third ticket this session, Robert's call). The ruthless-
budget pass finally cut something: **four layers kept as floor/keep, two
deferred to post-v0.1.** Assurance tier per layer, with the failure mode
that earned it:

1. **R26 atomicity — FLOOR, keep.** The audit log is the data rotation
   computes from (R10 observed view, closeout evidence). Async buffers or
   respond-before-commit reintroduce lie-by-omission exactly where the
   product's evidence lives. Ceiling (every read a durable write) was
   already bought at T04/KTD8.
2. **Per-entry blake3 chain (KTD4) — KEEP.** Closes silent edit/removal/
   reorder by a write-capable attacker; per-record MACs can't see absence.
   Envelope verifies without decrypting. Cost: one hash + one field +
   a verify walk. Honest limit: lazy tampering only — tier 2 is the
   checkpoints' job.
3. **External signed checkpoints — KEEP for v0.1.** Three settled decisions
   structurally hang on it: T05's state digest (conditional now resolved —
   digest stands), R32's stale/rollback-restore detection (the solo-operator
   accident case, not just an adversary), and signed backup manifests (same
   flow, distinct domain label). Recurring cost honestly small: daemon holds
   only public keys + descriptor records; ceremony = CLI pair + systemd
   timer + rsync line. CT pattern already reduced to single-node scale.
4. **KTD16 blind query index — DEFER (first real cut).** Performance
   machinery, zero threat-model failure modes closed; all its hard parts
   (verify-against-primary, fail-closed health, rebuild) exist to make the
   optimization safe — cut the optimization, the scaffolding goes too.
   v0.1: rotation-status queries scan primary events over R23's bounded
   lookback window (redb reads run beside the writer; µs-scale decrypts;
   operator-latency tolerance). Bonus simplifications: R33's index-health/
   closeout coupling vanishes (primary is always authoritative) and the
   tag-cardinality leak leaves the threat model. Ceiling + upgrade path:
   KTD16's design stays in the plan; add via `audit index rebuild` when a
   measured status scan actually hurts — append-only data, so never a
   migration crisis.
5. **Segmented retention/archive/prune — DEFER.** ~365MB/year at generous
   small-team rates; the problem arrives years out. R13 already says "may"
   — no pruning means no-silent-discard holds trivially, R23's guard is
   moot, R14 collapses to two verification tiers in practice, backups just
   carry all events. Upgrade path: audit table is schema-versioned; R35
   forward-only migration adds segmentation when `doctor` shows real
   pressure.
6. **R25 no-secret-output + R27 bounds/capacity/reserve — FLOOR, keep.**
   R25 is the product promise (type-system enforced per T05, corpus-tested).
   R27's recovery reserve earns its place *more* after cut #5: capacity
   fail-closed is doing retention's job for years, and the reserve is what
   keeps "fail closed" from meaning "bricked at 100% disk" — backup,
   checkpoint, and orderly shutdown stay possible. A preallocated file, one
   threshold, one audited release command.

### Audit chaining (rationale record)

**Agent-drafted, not Robert's words** (explain-back retired — map Notes).

Every admitted operation commits its state change and exactly one audit
event in the same redb transaction (R26); the event's payload is encrypted
under the keyring's audit key, and its clear envelope carries sequence,
timestamp, previous-entry hash, and ciphertext digest. Each envelope hashes
over its predecessor — that's the chain. `audit verify` walks it without
decrypting anything: any edited, missing, inserted, or reordered entry
breaks the walk (tier 1, catches lazy tampering). On a systemd timer,
`audit checkpoint prepare` commits a canonical descriptor — store id, audit
epoch, sequence range, chain head, KTD15's state digest over sorted
(table, key, generation, mac) tuples, timestamp, signing-key id, previous-
checkpoint digest — then the CLI loads the ed25519 key from an approved
channel (the daemon never holds it, and has no scheduler), signs, fsyncs
the checkpoint file, zeroizes the key, and `register` verifies against the
stored public key and records the digest. Off-host copy is operator-owned
rsync. The signed head pins all history before it: a re-chaining attacker
now has to forge an off-host signature (tier 2). Restore compares its head
to the newest retained checkpoint — behind it means rollback recovery,
which forks the audit and credential epochs permanently (R32). v0.1's
assurance stops there deliberately: no segments, no archives, no blind
index — status queries scan the active table inside R23's window, and
growth is a measured, migration-shaped problem for later.

**Downstream:** T05's conditional resolved (digest stands — addendum added
there). T09 unblocked and directly affected by the index defer: its status-
granularity and closeout questions now assume primary-scan, and R33's
index-health guard is gone from v0.1 (note added to T09). T10 unblocked
(checkpoints + reserve survive, which its recovery story assumes). Both
defers join the post-v0.1 re-sort (map fog updated). T14 rewrites R13/R14/
R23/R33/KTD16 wording to match the deferred tier.
