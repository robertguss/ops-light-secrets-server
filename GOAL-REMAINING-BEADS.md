# Goal: implement all remaining beads

Paste into Grok Build as:

```text
/goal @GOAL-REMAINING-BEADS.md
```

Or paste the body below into `/goal …` directly.

---

Implement and close every remaining open bead in ops-light-secrets-server until none remain open.

## Success criteria (goal done only when all true)

1. `br list --status=open` returns zero issues (no open tasks/features/epics, including root `olss-charter-qul` if its children are done).
2. Every closed leaf bead has a corresponding local git commit (one commit per leaf bead).
3. Parent epics (and root) are closed when all children are closed — do not leave empty epics open.
4. Final full local verification has been run (see Verification); remaining failures are either fixed or closed with an explicit documented substitute in the bead close reason / notes + commit body.
5. No push, no PR, no force-push, no amending published history. Work only on branch `main` with local commits.
6. Beads DB/JSONL kept in sync: after every beads mutation, `br sync --flush-only`.

## Hard constraints

- Follow `AGENTS.md` and project conventions. Surgical changes only; no speculative features beyond bead acceptance.
- Issue tracking is only via `br` / `bv`. Never hand-edit `.beads/*.jsonl` as the primary write path. Do not invent parallel todo systems.
- **No push. No PR.** Local commits only on `main`.
- Do not reopen waived work unless a new bead is created for a real regression. `olss-charter-qul.13.8` (U12.7 human learning explainer + second-reader gate) was already force-closed by the operator as out of scope — leave it closed; do not re-implement it.
- Secrets discipline (R25): no secret values in logs, commits, bead notes, or test output. Respect canary/scan gates already in tree.

## Beads workflow (mandatory every loop)

1. Triage: `bv --robot-triage` (optionally `--format toon`) and/or `bv --robot-next`.
2. Confirm claimable work: `br ready --json` and `br show <id> --json` before starting. Only claim unblocked, open work.
3. Claim: `br update <id> --status=in_progress --json` or `br update <id> --claim --json`.
4. Implement that bead’s acceptance criteria (read full description; treat acceptance/plan-review sections as binding).
5. Verify at the bead-local level (see Verification).
6. Close: `br close <id> --reason="..." --json` (use `-f` only if blocked for bookkeeping reasons the operator already waived, and document why).
7. If closing the last children of an epic, close the parent epic(s) up the chain when eligible (including milestones M2/M3 and root).
8. `br sync --flush-only`.
9. One local git commit for that leaf bead (see Commits). Include beads JSONL changes in the same commit when they belong to that close.
10. Repeat until open count is 0.

Work order: **strict triage** — always take the top claimable pick from `bv`/`br ready`. Do not invent a custom unit-by-unit schedule that overrides triage.

## When stuck (do not wait for the human)

Policy: **best judgment, document, continue.**

- If acceptance is ambiguous, pick the simplest interpretation consistent with existing code, frozen design/format docs, and sibling beads. Record the choice in the commit body and/or bead close reason/notes.
- If an external dependency is missing (e.g. OpenBao pin, named host for perf), implement the maximum in-repo substitute (fixture, harness, skip-gated integration with clear `OLSS_*`/feature flags already used in project, documented baseline file) and close with explicit gap notes — do not park the goal.
- If a flake persists after real diagnosis, quarantine with a reasoned allowlist/gate consistent with project patterns, open a follow-up bead only if needed, and continue.
- Never use destructive git shortcuts (`reset --hard`, force-push) to “make it green.”

## Human / external evidence gates

For beads that demand second-reader, named-host, or operator-only evidence:

- Still implement the real product docs, tests, harnesses, CI wiring, and automatable checks.
- If a literal human second-reader or external host run cannot be performed in-session, close with a **documented substitute** (what was automated, what evidence was simulated/local, residual risk) in close reason + commit body.
- Prefer real automated twins over empty claims of manual runs.

## Discoveries mid-work

- Small fixes that block current acceptance: fix in place under the current bead.
- Otherwise: `br create` a new bead, set type/priority/labels, add deps with `br dep` as appropriate, `br sync --flush-only`, and treat new beads as **in scope** — goal is not done until they are also implemented and closed (open set must return to zero).

## Verification

- **Per leaf bead:** run targeted tests/checks that prove that bead’s acceptance (e.g. specific `cargo test --test …`, new suite paths, unit tests it owns). Fix regressions you introduced, caught by those targeted runs.
- **Do not** require the full Verification Contract on every leaf close.
- **At epic/milestone close** (U7, U8, U11, U12, M2, M3, root) and **once at end of goal:** run the fullest practical local verify (`./scripts/verify.sh` and/or the standing local subset of the Verification Contract that exists). Fix failures you can; if something is blocked by unfinished work outside the epic being closed, either keep required children open or document substitute and continue per stuck policy.
- Prefer project scripts (`./scripts/verify.sh <check>`) over ad-hoc one-off commands when they exist.

## Commits (local only, on main)

- **One commit per closed leaf bead.**
- Epic-only closes (no code) may be `chore(beads): complete <epic> <id> [skip ci]` matching repo history.
- Message style (match recent history): conventional commits, mention bead id, often `[skip ci]` for beads-only or when appropriate.
  - Examples: `feat(rotation): … olss-charter-qul.9.4 [skip ci]`, `test(recovery): … olss-charter-qul.12.14 [skip ci]`, `chore(beads): complete U7 olss-charter-qul.9 [skip ci]`
- Commit body: what/why, acceptance notes, any judgment calls or evidence substitutes.
- Stage only files for that bead. No secrets. No unrelated cleanup.
- First action if `.beads/issues.jsonl` is already dirty from the pre-goal U12.7 waiver close: include that beads sync in the first related chore commit (or a dedicated `chore(beads): waive U12.7 …` commit) before or as part of normal loop — do not leave indefinite dirty tree.

## Out of scope / do not do

- Pushing to origin, opening PRs, force-pushing, rewriting published history.
- Re-opening or implementing waived U12.7 learning-explainer content as a release gate.
- Broad refactors unrelated to the claimed bead.
- Closing beads without implementing acceptance (except documented substitutes for human/external evidence only — code beads must ship real behavior/tests).

## Progress reporting

Use the goal progress mechanism (`update_goal`) as you complete meaningful chunks (each closed bead or epic). On true completion (0 open + final verify attempted), mark the goal completed with a short summary: closed counts, key milestones, residual documented substitutes, and that everything is local-only on `main`.

## Start now

1. `bv --robot-triage` + `br ready --json`
2. Handle any pre-existing dirty `.beads/issues.jsonl` cleanly in git
3. Claim top pick, implement, verify locally, close, sync, commit
4. Loop until open issues = 0 and final verification step is done

## Operator decisions (locked)

| Topic | Choice |
| --- | --- |
| Git remotes | Local commits only; no push, no PR |
| Branch | `main` |
| Epics | Close parents when children done |
| U12.7 | Force-closed / waived entirely |
| Stuck policy | Best judgment; document; continue |
| Issue tools | Hard-require `br` / `bv` |
| Commits | One commit per closed leaf bead |
| Human/evidence gates | Real artifacts + documented substitute if needed |
| Verification | Bead-local always; full at epic/milestone + goal end |
| New discoveries | `br create` and work new beads until open set empty |
| Work order | Strict `bv` triage / `br ready` top pick |
