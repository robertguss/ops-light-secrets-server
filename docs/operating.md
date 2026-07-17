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

The transaction coordinator is the handler-facing commit boundary layered on
that writer. Its type-state protocol fixes the order as: begin one transaction,
reauthorize against current durable state, apply a mutation or prepare a bounded
read response, append the operation audit plus pending overload aggregates,
commit, then release the reply. A denial appends and commits its denial audit
before returning. Audit/commit failure releases no prepared secret. Prepared
responses must implement zeroize and zeroize-on-drop, covering commit failure,
serialization failure, panic unwind, caller disconnect, and receiver loss.
Handlers receive only typed submissions; neither the coordinator backend nor a
raw database transaction is exposed. The coordinator owns the reserved 100 ms
clock-watermark submission path as well as ordinary data and recovery lanes.

Audit payloads use schema version 1 and are encrypted under the keyring's
current audit-payload key with the U2.4 XChaCha20-Poly1305 frame in the distinct
`audit-event` record domain. The AAD-bound logical id contains the audit epoch,
epoch sequence, event id, effective timestamp, and previous hash. Only the
versioned audit epoch, epoch-scoped sequence, monotone effective timestamp,
previous hash, and digest of the complete encrypted frame remain clear. The
domain-separated chain hash and frame digest can therefore be checked without
decrypting identity, resource, operation, authorization, or wall-clock fields.
Decoders reject unknown versions, truncation, trailing bytes, noncanonical
ordering, missing mutation commitments, and wrong delta/whole-state forms.
Each epoch starts at sequence one with an encrypted genesis event binding the
prior epoch terminal hash; a fresh store binds the all-zero predecessor.

The canonical event type has no request-body, header, credential-secret, or
secret-value field and intentionally has no debug renderer. Successful secret
reads/writes record only the served/written version. Rejected raw targets record
only a typed reason, bounded digest, and offset. Admission overloads and
pre-verifier flood counts are bounded aggregates. The real redb transaction
factory stages authenticated clock state, exact tuple commitments, the
encrypted event, audit head, and overload snapshot in one writer transaction;
init-refusal and final-shutdown events use the same audit-only transaction path.
Golden version-1 event and envelope vectors live under `tests/fixtures/`.

Identity and grant records are schema-versioned, MAC-authenticated clear
records. Identity and grant ids are immutable opaque 128-bit values; operator
names are unique forever and cannot be reused after retirement. Identity kind
(`human` or `workload`) is descriptive in v0.1. Grant removal retains the grant
id as a tombstone and advances its generation, so stale or wrong-owner updates
fail closed. Fresh initialization stages one `bootstrap-management` human
identity and an explicit `admin@v1` capability snapshot in the same redb commit
as keyring metadata and audit genesis.

Capabilities are the closed version-1 registry frozen in
`tests/fixtures/capability-registry-v1.json`; bundles expand to concrete members
when a grant is created and never acquire later capabilities. KV grants contain
only secret capabilities. Management grants contain only management
capabilities and have the sole shape `sys`, exact, empty prefix; configuration
cannot create a KV `sys` mount. Subtree matching is by complete path segment and
includes equality; an empty subtree prefix covers the mount root. Any explicit
version query requires `secret-read-history`, even when it names the current
version. Full-version purge can only be constructed by the local-control request
API. Authorization returns a structured decision with resource, operation,
matched immutable grant id, or a distinct no-mount, prefix-boundary, or
missing-capability reason; unauthorized remote replies consume only `allow`.

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

## Clear metadata integrity

Secret values and audit payloads are encrypted. Security-relevant structural
records remain readable in the database but carry a 32-byte keyed BLAKE3 MAC
under a closed record-class registry. The authenticated frame binds MAC format,
table and class IDs, class domain, record schema version, store ID, canonical
primary key, monotonically changing record generation, and canonical value
bytes. A valid record copied to another table, key, generation, class, schema,
or store is invalid. This deliberately does not hide paths, identity names,
grant topology, versions, or timestamps from someone who steals the database.
If that topology is regulated data, v0.1 is unsuitable until an opaque-
identifier storage migration exists.

Store ID, schema/lifecycle, and the clock high-water mark are provisional boot
inputs only. Immediately after the age keyring opens, the server verifies their
sealed mirror and exact value agreement before readiness. Every other clear
record is verified before use. A failure is sticky for the process: ordinary
data traffic, management mutation, and bulk mutation stop. Only bounded
diagnostics, read-only recovery verification, orderly shutdown, and offline
restore/repair remain admitted. Diagnostics contain a stable reason, table,
and keyed 16-hex-character key identifier; attacker-controlled keys, paths,
labels, and values are never rendered. Investigate the storage boundary or
restore from authenticated evidence; there is no warning-only bypass.

Per-record MACs cannot alone expose deletion or replay of an older valid row.
Checkpoint, backup, restore, migration, and full-doctor owners therefore use
the deterministic state digest: sorted clear `(class, key, generation, MAC)`
tuples plus encrypted `(table, key, digest(authenticated record bytes))`
tuples. Ordinary audit events carry bounded sorted before/after tuple deltas so
an authenticated tail can be reverse-applied to reconstruct a checkpoint
state. Bulk rewrites instead bind explicit before/after whole-state digests.
The unanchored audit tail retains the documented live-compromise limitation.
A metadata-key rotation changes these tuples and is incomplete until its new
state digest is externally checkpointed.

## External audit checkpoints

Daemon stores checkpoint public keys and lineage only. Private Ed25519 keys
must remain in separate custody and enter only short-lived offline commands;
daemon has no checkpoint timer or private-key input. `audit checkpoint prepare`
atomically appends prepare event as last anchored sequence, computes state
digest inside same redb write transaction, and stores canonical descriptor.
`audit checkpoint sign --descriptor PATH --public-key-descriptor PATH
--private-key-source SOURCE --output PATH` reads exactly 32 raw private-key
bytes from approved typed source, checks descriptor key ID and retained public
key validity window, signs under checkpoint domain, zeroizes bytes, and creates
detached file with mode 0600 using no-follow, fsync, and atomic rename.
Registration verifies retained public key and chains to last registered
checkpoint. Abandoned prepares remain visible but never become previous link.

Signing trust begins with stateless `audit signing-key generate`; 32 raw
Ed25519 private bytes go only to a validated pre-opened FD, while stdout
contains public candidate/fingerprint/custody metadata. The daemon never reads
or stores a signing private key. First enrollment is one-time, requires exact
fingerprint, non-secret reason, digest-bound confirmation, owner peer plus a
control credential with `audit-checkpoint-manage`, and an attestation that an
independently protected off-host private-key copy exists.

Rollover is `audit signing-key rotate prepare|sign|register`. Prepare commits a
public-only, expiring intent and then binds its resulting audit head into the
canonical transition statement. Offline sign uses the old private key from a
typed source. Register rechecks authorization, incarnation/epoch ancestry,
current generation/key, expiry, signature, and the exact outstanding
descriptor inventory in the activation transaction. The activation event
retires A and makes B current; the first checkpoint covering that event must
use B and binds lineage generation plus transition digest. Until it registers,
status is `transition_registered_checkpoint_pending`.

All historical public keys remain verification-only and are never silently
pruned. The lineage holds at most 16 keys and warns at 12; authenticated
archival/pruning would require a future forward migration. Loss of the current
private key stops new checkpoints, signed backup/export manifests, receipts,
and rollover. There is no implicit re-enrollment or trust reset. A retired
private key must be removed from signing custody: Ed25519 provides no trusted
signing time, so public-only verification cannot eliminate later compromise
risk.

Offline detached verification proves signature validity and the descriptor's
authenticated key interval, not whether the server registered or abandoned
the artifact. Offline tools report `registration_status=unknown_offline`
unless supplied authenticated disposition evidence plus its covering
checkpoint. Unresolved old-key checkpoint, backup, or export descriptors block
activation; their owning command family must resume, register, supersede, or
audit-abandon them. Rollover output reports only bounded domain counts and
digests, never paths or payloads.

Checkpoint freshness is warning, never data-plane readiness failure. Defaults:
`checkpoint.max_age_seconds = 86400` and
`checkpoint.max_unanchored_events = 10000`. Environment names are
`OLSS_CHECKPOINT_MAX_AGE_SECONDS` and
`OLSS_CHECKPOINT_MAX_UNANCHORED_EVENTS`. Stale becomes true only when registered
checkpoint age is greater than max age or unanchored tail count is greater than
max events; equality remains fresh. Mirror detached checkpoints off-host with
operator-owned rsync, cron, or systemd path units. Server sends no webhook or
object-store traffic.

## Capability-thin tokens

Bearer value is opaque credential material only. Identity, effective-time
expiry, revocation status, issue epoch, and public display metadata live in
server records; grants never live in bearer or token record. Authorization
loads token record, current identity status, and current grants within one
storage transaction snapshot. Therefore grant removal, identity retirement,
credential revocation, and credential-epoch replacement affect every request
whose transaction begins after admin commit; an already-linearized request may
finish. Expiry denies at `effective_time >= expires_at`, using clock model's
non-regressing effective time rather than raw wall time. All denial decisions
are marked audit-required. If client disconnects after issuance commit, durable
record remains discoverable and revocable; server does not pretend commit
rolled back.

Credential wire form is exactly
`<kind>.<audience>.<22-char-accessor>.<43-char-secret>`. Closed kind labels are
`token` and `secret-id`; audiences are `control` and `data`; binary fields use
base64url without padding. Alternate case, padding, extra fields, truncation,
and noncanonical encodings fail. Control bootstrap tokens are cryptographically
invalid on data listener before grant checks. Accessor selects one MAC'd server
record; unknown accessors still perform one keyed BLAKE3 computation, one
32-byte constant-time comparison, one epoch read, and one accessor lookup using
dummy record inputs. Verifier domain binds store ID, kind, audience, accessor,
issue epoch, and 256-bit random secret. Raw secret is disclosed before commit,
zeroized, and never stored or recoverable; retry after lost disclosure returns
metadata only, then operator must revoke and replace.

Frozen bounds: direct tokens 300/86400/2592000 seconds min/default/max; role
tokens 60/3600/86400; secret IDs 300/86400/2592000. Secret-ID uses range is
1..=1000; zero is invalid, not unlimited. Inputs outside bounds are rejected,
never clamped. Credential epoch is a MAC'd state record and remains a separate
mandatory equality check even when verifier-key rotation also invalidates MAC.
No password KDF exists because all credential secrets are CSPRNG-generated
256-bit values.

## Encrypted record format

Encrypted records use the fixed, NCC-audited RustCrypto XChaCha20-Poly1305
suite (suite ID 1; `chacha20poly1305` 0.10.1). It is not configurable. The
authenticated header starts with `OLSSREC\0`, a big-endian format version and
suite ID, then binds the store ID, closed record-domain ID, key ID, 192-bit
nonce, bounded mount,
length-prefixed canonical path segments, opaque logical record ID, optional
secret version, and creation time in Unix milliseconds. Decoders reject unknown
versions, suites, and domains; invalid UTF-8, noncanonical paths, truncation,
limits, and trailing bytes also fail closed.

Every encryption and rewrite asks the configured CSPRNG for a new 24-byte
nonce, including identical-plaintext rewrites. There is no deterministic or
counter nonce mode and no collision-budget readiness counter. The header is the
AEAD associated data and is stored with the nonce and ciphertext; changing any
bound field or transplanting a record makes decryption fail. State-digest
callers hash the canonical header bytes followed by the ciphertext (whose
authentication tag is appended by the suite). Diagnostics may report a bounded
case ID, length, redacted key ID, or digest, but never plaintext, a full path,
or nonce and key material together.

Decrypted values are owned by a non-`Clone`, non-`Debug` zeroizing wrapper and
are decrypted anew for each value read; the server keeps no cross-request
plaintext cache. Metadata-only queries verify the clear-record MAC and never
invoke record decryption. This guarantee covers server-owned age-identity,
keyring, and decrypted-value buffers. It does not claim erasure of copies made
inside the allocator, kernel, HTTP/TLS stack, or client. Process-dump hardening
is best effort and does not expand that boundary.

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

Identity and grant administration uses `identity create|list|show|disable`,
`grant add|remove|list`, and `authz explain`. Each CLI group requires
`--control-socket` and a typed `--control-credential-source`; bearer bytes must
never appear in argv. Machine output uses schema version 1, immutable 128-bit
public IDs, stable ID ordering, cursor pagination, and a hard page limit of 100.

Identity names are unique forever, including after terminal disable. Mutation
targets use IDs, not names. Disable and grant removal require the exact current
generation, a non-secret reason, and a request ID. Replaying the same request ID
for the same target is idempotent; reuse for another command or target is a
conflict. Disable is terminal in v0.1. Bounded affected-object counts never
include names.

The exhaustive control-command registry is authoritative for capability
checks. Identity/grant operations map to `identity-grant-manage`; `authz
explain` maps only to `diagnostics`; reserve operations map only to
`store-maintenance`; and backup/audit-export discovery and resume retain their
narrow capabilities. Checkpoint signing is local and has no server mapping.
Control audience, owner UID, active credential, active identity, current grants,
operation, and audit outcome are evaluated at the final coordinator barrier.
The remote data router contains none of these routes.

### Token and AppRole authentication

The remote authentication surface is deliberately limited to
`PUT|POST /v1/auth/approle/login`, `GET /v1/auth/token/lookup-self`, and
`PUT|POST /v1/auth/token/renew-self`. Login accepts only the exact `role_id`
and `secret_id` JSON fields through the duplicate-key-rejecting input boundary.
Invalid secret IDs, wrong but existing roles, missing roles, exhausted uses,
expired secret IDs, and deleted roles share one 400-class Vault error envelope.

Role token TTL uses the frozen 60-second minimum, 1-hour default, and 24-hour
maximum. Secret-ID use count is finite; zero is invalid. Login verifies the
secret-ID audience and role binding, decrements a use, issues the data token,
and records the audit intent under one linearization lock. A one-use secret ID
therefore succeeds once under concurrency. Role deletion rejects later logins
without changing independently issued token TTL/revocation/identity/epoch
semantics.

`lookup-self` reports immutable accessor metadata, creation/expiry, and TTL
remaining but intentionally omits Vault's raw `data.id`. Tokens are
non-renewable and login advertises `renewable:false`; `renew-self` returns the
explicit Vault error `token renewal is not supported`. `X-Vault-Token` is
extracted once by the hygiene layer, and data/control listener middleware uses
cryptographically separate audience checks. No network bootstrap route exists.

## KV v2 data contract

The only data mount is `secret/`. Data reads and writes use
`/v1/secret/data/<path>`; listing uses the literal `LIST` method on
`/v1/secret/metadata/<prefix>` or the narrow `GET ...?list=true` equivalent.
Nonempty Vault namespaces and other mounts are refused explicitly.

Writes accept `data` plus optional `options.cas`. CAS `0` is create-only and
metadata existence remains authoritative after deletion. Positive CAS must
equal the current monotonically increasing version, including when that
version is deleted or destroyed. When effective `cas_required` is true, an
unconditional write is refused. A per-path setting overrides the live mount
default; otherwise changes to the mount default apply at the next transaction.

An unversioned read requires `secret-read-current`. Every explicit
`?version=N`, even when N is current, requires `secret-read-history`. LIST has
its own `secret-list` capability. Ordinary history is pruned to `max_versions`;
an active rotation may protect its snapshot temporarily, and clearing that
protection immediately reapplies ordinary retention.

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

## Request limiting

AppRole login and unauthenticated health/seal probes have separate fixed-shard
budgets beneath one global attempt cap. Source churn cannot allocate memory or
refresh a full allowance: colliding and overflow sources share existing bucket
state. Rate, malformed, and oversized drops are coalesced into a bounded
aggregate buffer containing only bucket IDs, counts, reasons, and window
durations. The next storage commit drains those aggregates into the encrypted
audit chain.

Authenticated requests have a separate body bound, fixed-shard per-identity
rate budget, and global concurrency cap. Direct listeners derive the source
only from the transport peer and ignore forwarding headers. Explicit proxy
listeners use only the address accepted by the verified proxy boundary. If a
proxy deployment does not provide a verified forwarded address, every client
uses one shared bucket: one login flood can therefore rate-limit legitimate
workload re-logins until the window resets. Operators should treat that mode
as degraded and configure the verified forwarded-address path.

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
