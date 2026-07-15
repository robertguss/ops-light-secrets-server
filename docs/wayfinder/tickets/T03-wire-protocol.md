---
id: T03
title: "Wire protocol: Vault-compat vs fnox-native, surface size, BUSL shim"
label: wayfinder:grilling
status: open
assignee:
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
