# Operating ops-light-secrets-server

## Local control socket

The management plane is a Unix socket owned by the service UID. Its parent
directory must be owned by that UID with no group or other permission bits; the
socket itself is mode `0600`. The server also checks Linux `SO_PEERCRED` on
every accepted connection and drops plus audits peers whose UID is unavailable
or differs from the configured service owner. Mode bits, peer credentials, and
the control-audience credential are independent required checks.

Run control CLI commands as the service account, normally through a narrowly
scoped sudo rule:

```text
sudo -u ops-light-secrets-server ops-light-secrets-server <control-command>
```

The v0.1 design has no supplementary UID, group, or ACL allowlist. Root's
ability to bypass filesystem mode bits is not application authorization. U4
owns the control-audience credential middleware; no management command may be
enabled without it. The U1 socket skeleton exposes only a non-mutating local
status route, while the remote data router has no control routes at all.

At startup, an existing socket is probed before removal. An active listener,
symlink, non-socket, wrong owner, unsafe mode, or inode race fails closed. A
confirmed stale owner-only socket may be replaced. Shutdown removes the socket
only when its device and inode still match the one created by this process.

## Compatibility client pins

Compatibility evidence applies only to the exact client archives in
`research/compat/client-matrix.json`: Vault OSS 2.0.3, OpenBao 2.6.0, and fnox
1.30.0 plus 1.29.0 on Linux amd64. Fetch and verify them before a capture run:

```text
./scripts/fetch-compat-clients.sh /private/output/directory
```

The fetcher checks every SHA-256 digest before the archive can be extracted or
executed. A client upgrade requires updating the pin, provenance, checksum, and
captured compatibility evidence together. No legacy Vault line is claimed
without a documented deployed consumer or a proven distinct request contract.
