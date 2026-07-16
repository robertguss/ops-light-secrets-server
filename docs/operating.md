# Operating ops-light-secrets-server

## One-time initialization and credential custody

`init` takes an exclusive owner-only data-directory lock. It refuses foreign
entries and an already initialized store. A retry may reconcile only the
validated lockfile, an uncommitted store, and reserve-provisioning artifacts
owned by the initialization protocol.

Choose a bootstrap lifetime from 5 minutes through 7 days; the default is 24
hours. Pass a pre-opened credential sink with `--credential-output-fd`. The sink
must be a TTY, pipe, Unix socket, or anonymous memory-backed FD. Persistent
regular files and block devices are refused. This supports piping the one-time
value directly into encryption or password-manager tooling without placing it
in argv, environment variables, ordinary stdout metadata, logs, or persistent
plaintext.

Initialization validates the sink, creates and self-tests the keyring envelope,
writes and flushes the credential, and only then commits its verifier with the
store. Failure before commit leaves a retryable uninitialized store. After
commit, use the bootstrap over the local control socket to issue a labeled,
bounded, non-renewable control token; verify the new token on an authenticated
control command; then revoke the bootstrap accessor. Repeat that
issue/verify/revoke-predecessor sequence before each normal control credential
expires.

If the bootstrap expires or is lost, use the offline emergency control-
credential operation owned by U8.3. It accepts the store-unwrapping identity,
bumps the credential epoch, and uses the same disclosure-before-commit sink
protocol. There is no network bootstrap route.

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

## TLS files and live reload

Configure the certificate and private key as a pair with `[tls].certificate`
and `[tls].private_key`, or `OLSS_TLS_CERTIFICATE` and
`OLSS_TLS_PRIVATE_KEY`. The service opens both with no-follow semantics, bounds
their size, parses the complete captured bytes, verifies the key/certificate
pair, and closes the descriptors before activation. The private-key file must
be owned by the service user with no group or other permission bits. Symlinks,
hard links, multiple keys, malformed or half-written files, and metadata
changes during a read are refused without exposing paths or parser text.

SIGHUP invokes the same serialized reload primitive reserved for the later
authenticated `tls reload` control command. A candidate is fully validated and
its public certificate fingerprint is committed through the audit/storage hook
before an infallible Arc swap. Failure leaves the old configuration serving.
On restart, the configured pair must match the committed expected fingerprint;
a mismatch fails closed and instructs the operator to restore the files or
perform an audited live reload.

`axum-server` 0.8.0 with its provider-neutral rustls feature is provisionally
adopted: HTTPS, plaintext refusal, SIGHUP, repeated/concurrent reload, and an
in-flight request across a certificate swap are locally proven on the MSRV.
U9.4 owns the final adopt-or-fallback verdict after the complete executor drain
and shutdown-barrier suite; this provisional result does not pre-judge it.

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
