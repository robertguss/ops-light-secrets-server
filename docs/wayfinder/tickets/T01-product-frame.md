---
id: T01
title: "Product frame: is ops-light, rotation-first still the product?"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: []
---

## Question

Re-affirm or amend the product identity before any design walk: is "ops-light
self-hosted secrets server, rotation as the wedge, learning as the primary
goal" still what this project is? Specifically:

- Problem frame — rotation-not-storage as the pain; the shared-key/`.env`
  status quo (Plan: Problem Frame).
- The ops-light single-node ceiling as a positioning decision, not a shortcut
  (Key Decisions).
- Actors A1–A4 and the agent-later stance.
- Success criteria — learning/explain-back as primary; production explicitly
  not a v0.1 gate.
- Anything in Dependencies/Assumptions that changed since writing (team
  situation, interim tooling drift).

Resolution: re-affirmed or amended product frame. Amendments cascade — note
which downstream tickets they invalidate.

## Resolution

**Re-affirmed in full, zero amendments.** Walked 2026-07-15 (grilling, five
questions):

1. **Problem frame — re-affirmed as written.** Rotation-not-storage is the
   pain; the frame's honesty about its own limits holds (server can't end
   key-sharing — that's upstream in each SaaS; R10's consumer list is only
   trustworthy once consumers migrate, so migration is the precondition for
   safe rotation, and the v0.1 value is visibility plus one place to rotate
   from).
2. **Ops-light ceiling — re-affirmed, hard.** What the server refuses (HA,
   clustering, unseal ceremony, policy DSL) is the product. Accepted
   consequences, eyes open: downtime-until-restore on machine failure (systemd
   `LoadCredential` covers unattended reboot), and the README says "outgrow it
   → OpenBao" out loud. Walked after a full teach-down of HA/clustering/
   unseal/policy-DSL — decision made from understanding, not deference.
3. **Actors — all four re-affirmed; agent-later stands; `kind` field stays.**
   One enum column, zero behavior — passes the ruthless budget as cheap
   migration insurance.
4. **Success criteria — re-affirmed as written.** Explain-back stays the
   primary gate (understanding beats shipping-speed when they conflict);
   second-person read-back kept; production explicitly not a v0.1 gate.
5. **Assumptions drift — none.** Team situation, OpenBao-presumed interim
   tooling (uncommitted), fnox as the client, static-SaaS-key FERPA workload:
   all match reality as of today.

No downstream tickets invalidated. No fog graduated — frame unchanged means
the charted map stands as-is.

**Robert's explain-back (verbatim):**

> This product is a secrets manager that integrates with fnox. The product is
> meant for our small team at our non-profit to securely manage and handle our
> secrets, api keys etc. The primary reasons I am building this is
> costs/savings, and also other products currently available are overly
> complex for our needs. I also want to learn more about this space and
> domain.
