---
id: T03
title: "Wire protocol: Vault-compat vs fnox-native, surface size, BUSL shim"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T01]
---

## Question

Walk and verdict the compatibility strategy:

- Vault-API-compatible first vs fnox-native first vs both (Key Decisions;
  session-settled but on the table).
- Size of the declared surface — R1's endpoint matrix, R3's explicit
  unsupported posture, R31's auth surface, KTD12's single `secret/` mount. Is
  the declared subset the minimum a pinned fnox actually needs?
- The BUSL problem: every consumer host currently needs HashiCorp's `vault`
  binary (fnox shells out to it — Dependencies/Assumptions). Verdict on the
  exit-gate options: upstream a direct-HTTP/OpenBao provider to fnox vs ship a
  tiny separate `vault` shim (Scope Boundaries; U0 exit gate).
- U0's weight: does full client characterization with recorded fixtures stay
  as the gate (G0), or shrink?

Resolution: keep/simplify/defer verdicts on each, plus explain-back on why
the compatibility boundary sits where it does. T02's answer feeds in if
available.

## Resolution (2026-07-15)

Checked [fnox discussion #615](https://github.com/jdx/fnox/discussions/615)
first: no reply from jdx yet. Decided without it — v0.1 needs no upstream
buy-in by design; the answer affects phase-2 priority only.

Verdicts (each rebuilt from first principles after the explain-back gate
caught three rubber-stamps; all four now owned):

1. **Compatibility strategy — KEEP.** Vault-KV-v2-compatible first;
   fnox-native stays phase-2-pending-OQ1. Decisive argument: the differential
   oracle — speaking Vault's protocol means every request can be replayed
   against real OpenBao and diffed, giving a solo developer a mechanical
   adversarial reviewer. fnox-native forfeits the oracle, requires upstream
   buy-in that doesn't exist, and doubles the work (client + server halves).
   Compat is wire-only: storage/crypto/authz stay internal; a native listener
   remains additive later.

2. **Declared surface — KEEP.** R1 + R3 + R31 + KTD12 as declared. Key
   insight: the surface has two customers — fnox (read + preflight only) and
   the human operator running rotations via stock `vault`/`bao` CLI. Every
   endpoint maps to a move in the rotation workflow (CAS write = no clobber,
   versioned read = cutover window, destroy = purge after closeout,
   soft-delete/undelete = CLI's own delete semantics + fat-finger recovery,
   metadata write = `cas_required` interlock). Sizing by fnox traffic alone
   would gut the product. `seal-status`/`health`/preflight are constant
   "handshake tax." R3's explicit-unsupported fence stays.

3. **BUSL exit gate — SIMPLIFY.** Shim demoted from v0.1 release-gate
   fallback to post-v0.1, evidence-gated. v0.1 ladder, cheapest first:
   (1) point fnox at `bao` (OpenBao CLI is a vault-CLI fork; zero code; U0
   proves or kills it), (2) upstream direct-HTTP provider (#615, jdx's
   timeline), (3) document `vault` CLI install with the honest licensing
   note — never claim fully-OSI while it's the only path. Shim built only if
   1–3 all fail AND someone is actually blocked: it's a second product
   (arg parsing, output emulation, releases, tests), permanent once setup
   docs depend on it, and closes zero threat-model failure modes — optics
   don't outrank the complexity budget. T14: reword U0's exit gate
   accordingly.

4. **U0 weight — KEEP,** with one guard added. Full characterization stays;
   G0 stays. Docs lie by omission (error-body shapes, preflight frequency,
   LIST encoding, subprocess-vs-HTTP per fnox version) — capture converts
   each would-be production bug into evidence before the router exists. U0's
   fixtures are burned twice: contract tests (my bytes match what clients
   expect) and the differential oracle (my bytes match bao's). Three of this
   ticket's four verdicts cash out through U0's evidence (oracle fuel, Q2's
   empirical floor, Q3's rung-1 answer). Guard for T14: U0 is done when its
   named questions are answered with committed evidence — not when the
   harness is beautiful.

**Explain-back (Robert's words, lightly stitched):** The oracle argument is
huge — it gives me an uncanny ability to test and verify against a solid
existing product, OpenBao. We implement endpoints like undelete for the human
operator, not fnox — e.g. recovering when someone runs a delete on the wrong
path. We don't write the vault shim now because it's an entirely different
product we'd have to maintain, more headache and maintenance burden than
value. And we record real clients before building because there are gaps in
the docs — the docs don't paint the entire picture; this way we build against
real examples.

Downstream: no tickets invalidated. Shim deferral joins the post-v0.1
re-sort (map fog note already covers it). T06 inherits R31 as-kept; T12
inherits the differential suite as affirmed; T11/T06 get U0's
token/TLS-supply evidence when it lands. No domain vocabulary changed.
