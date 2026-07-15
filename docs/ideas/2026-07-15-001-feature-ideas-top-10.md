---
title: Ops-Light Secrets Server - Feature Ideas (Top 10)
type: ideas
date: 2026-07-15
topic: ops-light-secrets-server
status: captured, not scoped
relates-to: docs/plans/2026-07-15-001-feat-ops-light-secrets-server-plan.md
---

# Feature Ideas — Top 10 + Honorable Mentions

Candidate features for the ops-light secrets server, generated after the v0.1 plan was finalized. **None of these are v0.1 scope.** They are post-v0.1 candidates, captured here so they survive until roadmap time.

## How this list was made

Roughly 100 candidate ideas were generated across categories (rotation, developer experience, security hardening, operations, integrations, secret lifecycle, audit/compliance), then culled by two filters:

1. **Leverage on the real pain** — rotation, migration, and ops-light operation, per the Product Contract's problem frame.
2. **Cost sanity** — nothing that breaks the product's identity: no HA/clustering, no policy DSL, no unseal ceremony, no dynamic-secrets machinery, no hosted tier. Every idea composes the subsystems v0.1 already builds.

**Key realization from the cull:** the audit log and grant model being built for R10/R22 are a goldmine — half of the best ideas are just queries over data the server already collects. The marginal cost of several "enterprise-grade" features is a query, not a subsystem.

---

## The Top 10

### 1. Rotation cutover tracker — watch consumers flip, live

**Problem:** R11's write-is-cutover model leaves the scariest rotation question unanswered: "has every consumer actually picked up the new version yet?" Today the operator infers this by eyeballing audit entries.

**Idea:** The audit log already records identity and version per read. Add `rotation status <path>`: shows each consumer as on-new / on-old / silent-since-write. Rotation becomes a checklist — write the replacement, watch the list turn green, mark complete. Extend with:

- **Rotation journal states:** written → verified → upstream-revoked → complete, each transition audited. Gives the rotation lifecycle an auditable record instead of an implicit one.
- **Per-secret runbook metadata:** upstream console URL, minting steps — stored via KV v2 `custom_metadata`, which is compat-native (real Vault clients read/write it).

**Cost:** pure query over existing audit data plus a metadata field. Turns the core product promise from "list consumers" into "watch cutover happen."

### 2. Drift detector — hunt stale copies in the wild

**Problem:** The research stat that motivates the whole project — 64% of leaked secrets still active — is about copies living outside any vault. Rotation in the server does nothing about a stale value sitting in a laptop `.env`.

**Idea:** Server exposes a salted `blake3` hash of each secret's current version (never the value; salt per secret to resist brute-forcing low-entropy values). A client subcommand `drift scan` walks local `.env` files / process environment, hashes values, compares: "`POPULI_API_KEY` in `~/proj/.env` matches v3 (retired) — stale copy."

Two payoffs:

- Finds laptop stragglers **after** a rotation.
- Proves migration is complete **before** a rotation — the exact precondition the plan says R10's consumer list needs to be trustworthy.

**Cost:** hash-exposure endpoint plus a small client-side walker. No tool in this space has this.

### 3. Canary secrets — honeytokens for free

**Problem:** The plan itself names the worry: an authorization bug (or stolen token) is a full-store disclosure. v0.1 has prevention (scoping, TTLs) but no detection layer.

**Idea:** Flag any path as a canary. Operator plants decoys (`apps/prod-db/root-password`) that no legitimate consumer ever reads. Any read of a canary path → critical audit event + alarm (via the webhook primitive, idea 6). Instant tripwire for compromised tokens, authz regressions, and nosy scanning.

**Cost:** one flag on the secret record plus one branch in the read path. Best security-per-line-of-code on this list.

### 4. Access intelligence — least-privilege on autopilot

**Problem:** Scopes are written once and never revisited; grants accrete. Entitlement review is the thing enterprises pay for, and small teams never do.

**Idea:** Three queries over grants × audit window — machinery R10 builds anyway:

- `scope suggest` — grants with no matching read in 90 days, with a proposed tighter scope.
- `scope dry-run` — replay a proposed scope reduction against recent audit traffic: "this change would have denied 14 reads by `ingest-worker` last week." Makes tightening safe instead of scary.
- `explain <identity> <path>` — which grant matched, or why the request was denied. A policy debugger, which real Vault notably lacks.

**Cost:** matcher replays over data already collected. Recommendations, not policy language — no DSL smuggled in through the back door.

### 5. Embedded vault-CLI shim — kill the BUSL dependency on consumer hosts

**Problem:** The plan's ugliest accepted wart: fnox does not speak HTTP to Vault — it shells out to the `vault` binary. So every consumer host needs HashiCorp's BUSL-1.1-licensed CLI installed, undercutting the single-binary, fully-open story.

**Idea:** The server binary already speaks the wire protocol. Add a client mode implementing the exact CLI subset fnox invokes — `kv get -field=<f> <path>`, `kv put`, `kv list`, login, token-helper behavior (`VAULT_ADDR`, `VAULT_TOKEN`, `~/.vault-token`). Symlink it as `vault` on consumer hosts → fnox works unmodified, zero HashiCorp bits anywhere, one binary on both ends.

**Cost:** bounded and known — the U11 compat harness already captures the exact CLI behavior to mimic. This also de-risks R2 against future `vault` CLI drift.

### 6. Event webhooks — one primitive, five features

**Problem:** Several wants (rotation reminders, cutover push, alarms, off-host checkpoint delivery) each look like a feature; they are all "server tells something outside itself that an event happened."

**Idea:** One outbound-webhook primitive: registered URL + event filter, HMAC-signed payloads, never containing secret values. Event types:

- `secret.written` — consumers hot-reload instead of waiting for next read; fixes the "cutover happens on next read… whenever that is" gap.
- `rotation.due` — secret age exceeded its interval (R12 made proactive).
- `canary.tripped` — idea 3's alarm channel.
- `anomaly.detected` — cheap heuristics: identity reads a never-before-read path, burst reads, off-hours access.
- `audit.checkpoint` — KTD4 needs an off-host checkpoint channel anyway; same primitive.

**Cost:** one delivery loop with a retry queue in redb. Slack, CI, or anything else consumes it.

### 7. Exec-hook rotators — rotation tracker becomes rotation engine

**Problem:** For upstreams with management APIs (Postgres, Cloudflare, GitHub PATs), the mint-new-value step of F4 is scriptable — but the server currently only records rotations, never performs them.

**Idea:** Per-secret, opt-in `rotate_exec`: an operator-supplied script the server runs on demand or on schedule. Server captures stdout as the new value, writes the new version, journals the whole act into the audit chain. Upstreams with APIs rotate with one command — or automatically on interval. The server stays generic: no per-SaaS plugins, no dynamic-secrets scope creep; the script is the operator's.

**Honest caveat:** this nudges the Product Contract line "an action the server records but cannot perform." As an opt-in extension point it strengthens the rotation thesis rather than diluting it, but it is a deliberate scope decision, not a free add. Implementation needs care: value via stdout only, zeroize buffers, no secrets in argv, document the trust placed in the script.

**Cost:** process exec + capture + existing write path; scheduling via a simple internal timer. The single most *powerful* idea on this list.

### 8. OIDC auth for CI — secret-zero solved where leaks actually happen

**Problem:** The accepted v0.1 posture parks each workload's AppRole `secret_id` in deployment configuration. For CI specifically — the highest-leak-risk consumer — that is a static credential sitting in repo/org settings.

**Idea:** A GitHub Actions job presents its ambient OIDC JWT; the server validates the signature against pinned JWKS, maps claims (`repository`, `ref`, `environment`) to an identity and scope, and issues a short-TTL token. No stored credential in CI at all.

**Cost:** one additional auth method — JWT validation crate, JWKS fetch with caching, a claim-map in config. Well-trodden pattern (it is Vault's `jwt` auth method reduced to one documented target). GitHub Actions first; GitLab and friends come nearly free later.

### 9. Importers — migration on-ramp and Vault escape hatch

**Problem:** Migration is the stated precondition for trustworthy consumer lists ("migration, not R10, is the precondition for a safe rotation") — and today it is manual ceremony.

**Idea:** One `import` command with three sources:

- `.env` files — the actual current state on laptops and VPSes.
- `fnox.toml` — `age`-encrypted values; the `age` crate is already in the tree.
- Live Vault/OpenBao — walk list+read with their token, write locally. Doubles as positioning: an escape hatch off Vault.

**Cost:** parsers plus the existing write path. Makes the on-ramp one command instead of a project.

### 10. Unattended restart via systemd-creds/TPM — biggest ops wart, posture intact

**Problem:** v0.1 accepts operator-attended restart: the `age` identity must be supplied interactively because R21 forbids any plaintext-on-disk terminus. Every reboot or crash needs a human.

**Idea:** R21 explicitly allows an "OS secret-storage facility" as a terminus. systemd `LoadCredentialEncrypted` seals the `age` identity and checkpoint signing key to the host TPM; the server reads them from `$CREDENTIALS_DIRECTORY` at boot. Reboots and crashes self-heal. No unseal ceremony added; the threat model holds — credentials are bound to that specific host's TPM, so a copied disk image reveals nothing.

**Cost:** read a file at a well-known path, plus documentation of the `systemd-creds encrypt` setup. Fallback for hosts without TPM: keep attended mode. Highest ops-relief-per-effort on the list.

---

## Honorable mentions

Considered and cut from the top 10, worth keeping visible:

- **`lockdown` panic command** — one management action: freeze writes + revoke all non-management tokens. Incident-response one-liner; tiny code.
- **One-time-read handoff secrets** — write a secret flagged read-once; first authorized read atomically destroys it. Safe credential handoff to a teammate without a Slack paste.
- **`doctor` self-check command** — one command validating config, TLS cert expiry, disk space, audit-chain integrity, checkpoint-mirror freshness, clock sanity.
- **Prometheus `/metrics` endpoint** — request counts, audit lag, and notably secret-age gauges, so existing monitoring can alert on stale secrets. (Care with R25: no secret values in labels.)
- **30-second demo mode** — `demo` subcommand: in-memory store, seeded data, loopback-only, loudly marked unsafe. Onboarding and adoption accelerant.

---

## If forced to pick three

**Ideas 1, 2, and 7** — cutover tracker, drift detector, exec-hook rotators. Together they make "rotation is the product" not just true but visibly, mechanically true: watch a rotation propagate, find the copies that didn't, and automate the rotations that can be.
