---
id: T08
title: "Audit: atomic commit, hash chain, external checkpoints, blind index"
label: wayfinder:grilling
status: open
assignee:
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
- KTD16's blind query index (keyed tags, verify-against-primary, rebuild) —
  exists to make rotation status cheap. Defer with rotation, keep, or
  simplify to full-scan-at-small-scale?
- Segmented retention / archive / prune (R13, R23) — v0.1 or later?
- R25 no-secret-output ban and R27 capacity fail-closed + recovery reserve.

Resolution: a chosen assurance tier per layer with named failure modes that
justify it, plus explain-back on audit chaining — a named learning target.
