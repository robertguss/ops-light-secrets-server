---
id: T13
title: "Project meta: name, repo home, license"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T01]
---

## Question

The cosmetics, settled deliberately once:

- Project name and repository home (OQ3) — the working directory name serves
  until decided; deciding unblocks README/positioning language in T14's
  rewrite.
- MPL-2.0 (KTD13, R19) — on the table per charting preference; re-affirm or
  change before public artifacts exist.
- Positioning one-liner: how the README states what this is and is not (the
  ops-light refusals as the pitch).

Resolution: name chosen or explicitly parked with a deadline, license
re-affirmed, one-paragraph positioning drafted.

## Resolution (2026-07-16)

All three pieces Robert's taste; asked directly (ask-only mode — this
ticket is entirely judgment).

1. **Name — PARKED with deadline (Robert's choice).** The descriptive
   working name `ops-light-secrets-server` serves through T14's rewrite
   and the build. Deadline: a real name must be chosen **before any public
   artifact** — announcement, crates.io publish, or README positioning
   aimed at outside readers. Renames are cheap while there are no users.
2. **License — MIT (Robert's choice; first plan-decision override of the
   map).** The repo's LICENSE file (MIT, © 2026 Robert Guss) stands; the
   plan's KTD13 (MPL-2.0, rotation-in-core ethos note) is overridden.
   R19 is unaffected — MIT is OSI, whole tree, no `ee/` carve-out, nothing
   held back. **T14 must rewrite KTD13** to record MIT and drop the MPL
   rationale. Consequence accepted knowingly: closed forks are permitted;
   the anti-BUSL posture is expressed by the product's own openness, not
   by copyleft.
3. **Positioning paragraph — drafted** (agent-drafted; for T14's README
   section, name slot left generic):

   > **[name]** is a single-binary, Vault-KV-v2-compatible secrets server
   > for teams too small to run Vault. It exists for one workflow:
   > rotating a credential without an outage. Every read is audited
   > atomically, so before you revoke anything upstream the server can
   > show you exactly who fetched the old value and who has picked up the
   > new one — declared, authorized, and observed consumers, never
   > collapsed into one comfortable list. The ops-light claim is a list of
   > refusals: no cluster, no external database, no policy language, no
   > plugin system, no remotely reachable management surface, no unseal
   > ceremony. Management lives on a local socket; one operator can run
   > backup, restore, key rotation, and incident response alone. Works
   > with unmodified `vault`/`bao` CLIs and fnox. MIT, whole tree,
   > nothing held back.

**Downstream:** T14 edits: KTD13 → MIT; README/positioning language
unblocked (uses working name); `deny.toml` license config follows MIT.
Nothing else invalidated. T14 is now the sole open ticket — the frontier
is the synthesis itself.
