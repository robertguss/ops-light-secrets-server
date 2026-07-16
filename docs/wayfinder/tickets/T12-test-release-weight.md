---
id: T12
title: "Test & release weight: harness, differential suite, fuzz, attestations"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T03]
---

## Question

Is the verification apparatus solo-project-sized? Walk U11/U12/R38 and the
18-row Verification Contract:

- Real-binary compat harness (pinned fnox/vault/bao) — the plan's strongest
  idea or its most expensive? Which clients gate v0.1?
- Differential suite against a pinned OpenBao reference — keep, defer, or
  fold into fixtures?
- Fault/kill-point suites, property tests, fuzz targets, secret-canary scan —
  which are floor (they guard fail-closed invariants) and which are ceremony?
- R38 release attestations: signed checksums, SBOM, provenance, MSRV,
  prior-release restore smoke — v0.1 or v1.0 posture?
- Benchmark baseline obligation.

Resolution: a kept/trimmed verification contract with each dropped row named,
plus explain-back on which failure each kept gate catches.

## Resolution (2026-07-16)

Ask-only mode: one genuine question (R38 posture — Robert: **keep the whole
set**); the rest analysis-determined. **Verification contract kept whole —
zero rows dropped.** The apparatus is solo-sized because nearly every gate
is the test-shaped shadow of a floor already kept on T06–T11; cutting a
gate here would mean un-deciding a ticket there.

1. **Real-binary compat harness — KEEP; it's the strongest idea, and the
   expense is the point.** T03's oracle verdict *is* this harness. Gating
   clients: exactly the three the product story names — pinned `fnox`
   (primary, first-class gate), `vault` CLI (operator workflow), `bao`
   (the non-BUSL rung-1 path). Pinning means a client upgrade can't
   silently break R2.
2. **Differential suite vs pinned OpenBao — KEEP, not foldable.** Fixtures
   prove what clients *send*; the differential corpus proves this server's
   *interpretation* matches the reference rather than its own assumptions.
   Folding it into fixtures deletes the mechanical-adversarial-reviewer
   property that T03 called decisive. Divergences stay allowlisted with
   stated reasons (R3's fence).
3. **Standing suites — all four are floor, none ceremony:** fault/kill-
   point/disk-full gates R26+KTD8 (the design's central claims are crash-
   atomicity claims; untested, they're vibes); property/model gates KTD9's
   parser (the security boundary — model equivalence is how a solo dev
   gets adversarial parser coverage); fuzz gates the trust-boundary
   decoders (network inputs AND on-disk record/checkpoint decoders — an
   offline attacker writes the database; scheduled-CI, corpus checked in —
   already the light cadence); canary scan gates R25 (trivially cheap,
   catches the catastrophic class).
4. **R38 — KEEP whole set in v0.1 (Robert's call).** Floor tier:
   `--locked` CI, MSRV pin, `cargo-deny`, SECURITY.md, upgrade notes,
   signed checksums, and the release smoke including the prior-release
   restore fixture — the "upgrade won't eat the store" gate, non-
   negotiable for a secrets server. Appetite tier (SBOM + provenance):
   ~10 lines of set-and-forget CI each; kept because deferring saves
   almost nothing and a secrets server without provenance is an awkward
   claim mismatch even pre-1.0.
5. **Benchmark baseline — KEEP as written**, already the light version:
   recorded once on a named reference host, regressions review-gated
   rather than CI-gated. It's the empirical anchor for KTD8's
   "audit-per-read stays usable" position.

### Which failure each kept gate catches (rationale record)

**Agent-drafted, not Robert's words** (explain-back retired — map Notes).

Compat harness: the pinned real client stops resolving secrets after a
change — the product's one non-negotiable behavior, caught before release
instead of by fnox users. Differential: my server's error shape or field
presence silently drifts from the reference my clients were written
against. Fault suite: a crash between state write and audit write leaves
them disagreeing — the R26 invariant — or a half-written store serves.
Property/model: two path spellings authorize differently — the KTD9
bypass class. Fuzz: a crafted token, path, JSON body, or on-disk record
crashes or confuses a decoder at a trust boundary. Canary: a seeded
secret value surfaces anywhere — log, trace, panic, artifact — the R25
catastrophe. Clear-state integrity: an offline editor's record edit,
transplant, or rollback goes unnoticed — R39/KTD15. Raw-target corpus:
an encoded alias sneaks past the guard — KTD9 again, from the wire side.
Backpressure: the bounded executor wedges or starves the control lane —
KTD8. Recovery epoch: a rollback restore fails to fork or to invalidate
bearers — R32. Consumer reconciliation: the three views collapse or a
snapshot lies — R40/R33. Release integrity + smoke: the published binary
(not the CI build) fails init→serve→read→rotate→backup→verify→restore —
the whole operator promise, end to end, on the artifact users download.
Lint/format/deny: drift that compounds.

**Downstream:** nothing invalidated, no fog graduates. T14 wording ripple
only: U6/U11 text references KTD16 index rows in the same-transaction
write path and rebuild — leaves v0.1 with T08's defer. Frontier: T13,
then T14.
