# Security Policy

## Supported versions

Only the latest commit on `main` and published release tags (when cut) are
supported for security fixes. Pre-1.0 builds may change without notice; report
issues against current `main` whenever possible.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email the maintainer at the address in `LICENSE` / git history
(`robertguss@gmail.com`) with:

1. A short description of the issue and impact
2. Steps to reproduce (PoC welcome; no need for a full weaponized exploit)
3. Affected commit SHA or release tag if known
4. Whether you want public credit

You should receive an acknowledgment within **7 days**. We aim to provide a
fix timeline within **14 days** for confirmed issues that affect secret
confidentiality, integrity of the audit chain, or authentication/authorization
bypass.

Please avoid posting canary secret values, real production tokens, or customer
data in reports. Use synthetic fixtures only.

## Scope

In scope: authentication bypass, authorization bypass, audit-chain forgery or
loss, secret value leakage through logs/artifacts/CLI, crypto misuse in the
record/keyring path, and privilege escalation via the control socket.

Out of scope: denial-of-service against a single local process without a
security boundary violation; issues that require physical access to an
already-unlocked operator workstation holding the active age identity.

## Disclosure

We prefer coordinated disclosure. Once a fix is available on `main` (and a
release tag when applicable), we will credit reporters who want credit in the
release notes unless you request anonymity.
