---
id: T12
title: "Test & release weight: harness, differential suite, fuzz, attestations"
label: wayfinder:grilling
status: open
assignee:
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
