# OQ3: authoritative project name

Status: accepted on 2026-07-16

Decision: retain the working name `ops-light-secrets-server` as the final public
name. Renaming after public release is not permitted without a new superseding
decision and coordinated migration.

The authoritative tuple is:

| Surface | Exact value |
| --- | --- |
| Display name | `ops-light-secrets-server` |
| Cargo package | `ops-light-secrets-server` |
| Binary | `ops-light-secrets-server` |
| Repository slug | `ops-light-secrets-server` |
| Artifact prefix | `ops-light-secrets-server` |
| systemd unit | `ops-light-secrets-server.service` |

[`project-name.toml`](../../project-name.toml) is the machine-readable source of
truth. Cargo metadata, CLI help, release artifacts, documentation, and service
units must consume this tuple. Because the name is retained, release validation
checks tuple consistency; it does not attempt a global zero-occurrence scan.

Historical planning documents, Beads metadata, source history, and this decision
record are provenance rather than public naming inputs.
