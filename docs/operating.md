# Operating ops-light-secrets-server

## Clock safety

The server anchors effective time to wall and monotonic clocks at boot. Effective
time never moves backward in-process. The fixed v0.1 clock tolerance is 2
seconds. A runtime disagreement beyond that tolerance makes readiness false;
readiness returns only after 10 continuous seconds of agreement. An anomalous
wall observation is never written to the store.

The coordinator persists the accepted high-water mark on durable transactions,
clean shutdown, and every 30 seconds while idle. An idle checkpoint has a 100 ms
commit deadline and is coalesced to at most one pending command. A missed
deadline makes readiness false. From the measured durable-commit gate, the
published maximum restart rollback/TTL-extension window is therefore 32.1
seconds: 30 second checkpoint interval + 2 second tolerance + 100 ms commit
deadline. This is not a claim of zero extension across arbitrary host crashes;
that would require an external trusted time source.

Boot refuses when wall time is more than 2 seconds behind the persisted mark.
The one-invocation behind-mark override preserves that mark, clamps effective
time to it, and must commit its audit event before readiness. A mark more than
24 hours ahead is treated as implausible and cannot be overridden; use offline
`clock repair` with the exact old mark, replacement time, audited reason, and an
approved replacement-credential sink. The production repair adapter remains
fail-closed until U8.3 supplies the full credential-epoch/replacement-credential
primitive; the command never performs a mark-only repair that could lock out the
operator.

## Storage executor

All synchronous writes run on the single named `olss-storage-writer` OS thread.
The default pre-decrypt data lane holds 64 commands. The reserved recovery lane
holds 16 commands and is split into bounded urgent and ordinary sublanes;
watermarks, reserve status/release/recreate, shutdown, identity disable, grant
reduction, and credential revocation are urgent. Recovery receives at most three
consecutive dispatches while data is waiting, so neither side can starve the
other. Reserve work runs synchronously on the sole writer: once release begins,
its two-transaction backend budget cannot be consumed by unrelated commands.

Saturation returns `storage_overloaded` before payload decryption. Rejections
enter at most 64 in-memory aggregate buckets; further distinct buckets collapse
into one catch-all count. The next successful transaction on either lane commits
the snapshot of those counters. A failed transaction requeues them. Counts still
pending when the process crashes are lost; this bounded, explicitly accepted R13
loss window lasts only until the next successful command. v0.1 batching is
disabled.

Cancellation while accepted prevents execution. Once started, a command commits
or aborts according to the transaction even if its receiver disappears; an
undeliverable successful response is zeroized. Worker panic and a missed
clock-watermark deadline make readiness fail closed.

Audit query and backup use the internal snapshot service rather than exporting
raw database handles. It defaults to two named workers, eight queued requests, a
30-second cursor lifetime, and a 1 MiB buffered-result ceiling. Cursors receive a
deadline and remaining-byte budget on every chunk; expiration, cancellation, or
overflow drops the cursor promptly, releasing pinned pages. Snapshot buffers
have redacted debug output and zeroize on drop.

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

## Age identity and keyring custody

Generate each custody role separately. The command is stateless and does not
need a configuration file or an initialized store:

```text
ops-light-secrets-server key age-identity generate \
  --purpose active \
  --private-output-fd 3 \
  --output json 3>PRIVATE-SINK
```

Use `active`, `recovery`, and `audit-export` in separate invocations. The
private identity is written only to the pre-opened TTY, pipe, socket, or
anonymous-memory descriptor. Standard output contains only purpose, algorithm,
public recipient, fingerprint, and an opaque sink outcome ID. Persistent
plaintext files, argv, environment variables, application-managed sidecars,
and logs are forbidden custody locations. A systemd credentials directory is
accepted only as its runtime/tmpfs delivery endpoint; persistent provisioning
must use `LoadCredentialEncrypted=` or an equivalent encrypted-at-rest path.
Success metadata is the final local acknowledgment and is emitted only after
the private sink flushes. A short write, flush failure, cancellation, or lost
final reply never creates store state. A retry generates a fresh identity; the
custody process must discard or replace any partial or complete orphan.

The store contains one opaque age v0.12 envelope addressed to the active
recipient and, optionally, one distinct recovery recipient. Boot reads the
typed identity source, decrypts the envelope once, compares its embedded store
ID with the clear store ID before accepting other records, verifies the clear
keyring-metadata record, then drops the identity input. Wrong, absent, duplicate,
or transplanted material fails readiness without logging private bytes.

Audit-payload key generations are retained because v0.1 retains every audit
event. Capacity is 32 generations and operator warning begins at 24. At the
warning, plan an authenticated archive/prune operation plus a forward storage
migration in a post-v0.1 release. v0.1 does not silently retire an audit key,
expand the bound, or claim unbounded rotation.

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

## Reverse-proxy listener

Reverse proxying is a distinct listener type, never a switch that makes the
direct listener trust forwarding headers. Its backend is either the owner-only
Unix data socket or a loopback-only TCP address. A TCP proxy peer must be the
exact configured loopback address. The Unix form uses the same no-follow,
owner/mode, stale-inode, umask, `SO_PEERCRED`, and cleanup checks as the control
socket. Any local process can spoof the source of a loopback TCP connection, so
use the Unix form when the proxy can run as a dedicated service UID boundary.

The trusted proxy must replace, not append, `X-Forwarded-For` with exactly one
canonical IPv4 or IPv6 address. Comma lists, ports, brackets, whitespace,
non-canonical spellings, duplicate fields, and missing fields are rejected
before the handler. `Forwarded`, `X-Real-IP`, PROXY protocol, and other address
grammars are never interpreted. Direct mode and TCP connections from any peer
other than the configured proxy ignore all forwarding headers. Only the source
derived under these rules becomes the request's rate-limit bucket; it is
request-local and is not retained on a pooled connection.

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
