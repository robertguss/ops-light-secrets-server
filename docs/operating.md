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

## Capacity and recovery reserve

The frozen maximum transaction/storage commitment is 9 MiB: the 8 MiB record
ceiling plus 1 MiB for canonical headers, clear records, state commitment, and
the audit frame. Every data request owner must reject a request that cannot fit
this budget before RNG, allocation, decryption, or mutation. With the 64-entry
data lane, admission permanently protects 576 MiB of worst-case in-flight
headroom. The fixed idle clock event is bounded at 512 bytes every 30 seconds,
or 538,214,400 bytes per 365-day year; that entire annual amount separates the
warning band from data-stop.

The recovery sequence has 64 worst-case transaction slots (576 MiB): checkpoint
prepare/register; backup publication/outcome, signature, two receipts, and
status; emergency credential and shutdown/release work; output retry/abandon;
and eight incident investigations, each budgeted for query plus export
publication/outcome/signature/recipient/status. The exact data-stop floor is
1,207,959,552 bytes: 576 MiB queued data headroom, 558 MiB minimal recovery,
and an 18 MiB shutdown+reserve-release floor. At or below that floor, data is
refused before decryption. At or below 18 MiB, only shutdown and reserve release
may enter. A publication reservation holds up to two 9 MiB completion/abandon
transactions against its opaque output ID until terminal disposition.

`recovery.reserve` is a same-filesystem 576 MiB mode-0600 regular file with real
allocated blocks; sparse length is not capacity. Provisioning uses a no-follow,
create-exclusive temporary file, `posix_fallocate`, allocation/mode/owner/link
verification, file fsync, atomic rename, and parent-directory fsync. Release is
the authenticated, generation-checked sequence `release_requested` → verified
rename → parent fsync → unlink → parent fsync → `released`. Recreate records
`recreate_requested`, allocates and verifies the full file while ordinary
headroom still fits, then commits `healthy`. Startup never enables data while
the record/file/temp combination disagrees; it finishes only a uniquely
determined transition and rejects symlinks, foreign files, sparse files, quota,
ENOSPC, wrong ownership/mode/link count, or ambiguous artifacts.

Exact controls are `store reserve status`, `store reserve release
--expected-generation G --reason TEXT --confirm DIGEST`, and the corresponding
`recreate`. All require owner locality, an active control-audience credential,
and `store-maintenance`; broad diagnostics, a filesystem lock, and keyring
possession are not substitutes. Release is refused while capacity is healthy or
warning. Stable status exposes only generation/state, expected/allocated bytes,
band, held counts, and next action—never a raw path. The assembled online and
offline coordinator adapters remain fail-closed until the recovery E2E owner
wires these frozen primitives.

The G3-frozen logical archive, single-container publication, detached-signature,
recipient, restore-epoch, trust-import, and source/RPO rules are normative in
`docs/backup-format-v1.md`. A redb file copy is never a supported backup format.
The cross-release format/domain registry and shared publication, signer,
maintenance-preflight, and recovery evidence codecs are frozen in
`docs/format-freeze-v1.md`.

`backup create` captures all logical table frames, the exact non-audit state
digest, audit cutoff/head, latest checkpoint, keyring generation, recovery-set
generation, and signer lineage from one redb transaction. It publishes one
mode-0600 container through a private same-directory temp, durable `publishing`
reservation, rename/parent fsync, then a separate durable `published` outcome.
Never treat those two filesystem/database durability domains as one atomic
commit. `backup list`, `backup show <manifest-digest>`, and `backup resume
<manifest-digest>` discover and reconcile the immutable reservation without
revealing target paths or member data. Missing, corrupt, or substituted bytes
require explicit owner abandonment; resume never takes a new snapshot.

The configured recovery set is 1–7 distinct off-host public age recipients,
managed with generation CAS, reason, and exact confirmation. Backup derives the
effective set from that configuration plus the current active recipient; a
caller with only `backup` cannot override it. The archive contains both the
unchanged live envelope and a backup-only recovery envelope of the same purpose
keys, allowing a recovery identity to unwrap and immediately rewrap to a new
active recipient. No private identity or signing key is archived.

`backup manifest sign` reads the private Ed25519 key only through an approved
typed source, verifies it against the frozen public candidate/key id, zeroizes
it on every result, and atomically creates a detached mode-0600 signature. The
container is never rewritten. Operational maintenance accepts an artifact only
after authenticated signature registration and a matching cryptographically
valid, audited recovery-recipient rehearsal receipt. A detached file or local
receipt alone remains useful offline evidence but is not an operational
prerequisite.

## Backup verification and disaster-recovery rehearsal

Run `backup verify` for the cheap detached-signature, encrypted-container,
manifest, and frame checks. Run `backup verify --full` in an offline process to
reconstruct an isolated temporary store, authenticate every MAC and encrypted
record, decrypt every record without printing its plaintext, and verify the
state, audit, and checkpoint relationships. The temporary directory is removed
on success or failure. Select a work directory on a filesystem other than the
live store where possible; a same-filesystem rehearsal can pressure live
capacity and the verifier refuses when projected use exceeds half the available
space.

Supply either the active identity or, for the meaningful fresh-host test, only
one of the distinct recovery identities through an approved typed source. The
former records `integrity-verified (active-recipient path)`. Only the latter
records `DR-rehearsed (recovery path)`. A backup never successfully rehearsed is
unproven. A backup never rehearsed through a recovery recipient is unproven for
disaster recovery.

Full verification writes a detached receipt signed under the rehearsal domain.
Its `performed_at` is signer-claimed context, not trusted time, and offline
output always reports registration state as unknown. Operational freshness
starts at authenticated server registration, uses the effective registration
time, and is valid only for the exact latest archive digest and recipient-set
generation. Recipient changes invalidate prior freshness. Retired public keys
remain usable only through authenticated trust lineage; loss or compromise of a
retired private key remains an operator custody risk.

## Offline active-recipient rewrap

`key recipient rewrap` is the cheap routine key operation: it changes only the
age envelope, MAC-authenticated keyring metadata generation, and matching audit
event. Purpose keys and protected record bytes do not change. Stop the daemon
first; the command takes the independent exclusive data-directory lock and
refuses unsafe/symlinked/foreign-owned store paths.

Supply `--current-identity-source`, `--new-active-identity-source`, and
`--control-credential-source` as typed descriptors (`tty`, `fd:N`, or
`credential:NAME`; guarded development environments require the global unsafe
flag). `--recovery-recipient` is an optional distinct public age recipient.
Private identities and bearer credentials never belong in argv or output.

## Whole-store record-key rotation

`key record rotate` is the rare offline response to record-key compromise or a
deliberate cryptographic-hygiene event. Stop the daemon and keep the independent
data-directory lock for the whole operation. The final offline plan requires a
registered signature and a registered recovery-recipient rehearsal receipt for
the exact current backup; detached evidence whose registration is unknown does
not qualify. The exceptional no-current-backup path requires both key-rotation
and store-maintenance authority and an incident-specific confirmation.

Supply an approved active or recovery identity through a typed source and the
current active and optional recovery public recipients. Age envelopes retain
recipient fingerprints, not enough public-key material to rebuild a changed
envelope, so the command fingerprint-checks the supplied public recipients and
never guesses them. The read-only plan binds those recipients indirectly through
the current keyring, the generation, current state/head, exact recovery evidence,
owner, operation, and reason.

After confirmation, the original is atomically marked `reencrypting` with an
audit event. The pass creates a private same-filesystem `.new` sibling, decrypts
and re-encrypts every secret version with the same canonical AAD and a new nonce,
writes a ready target with a whole-state completion event and
`pending_anchor=record-key`, fsyncs it, and renames it over the original. There is
no post-rename lifecycle edit. A pre-rename interruption leaves the original
data authoritative; rerun the pass or use the owner-bound `key record abort` to
remove the partial sibling and atomically audit restoration to `ready`. Abort is
forbidden after installation.

Installation reports `installed_pending_anchor`. Register the matching new
checkpoint to reach `anchored_rewrite_complete_recovery_pending`, then create,
sign and register a backup of the new-key state and register its recovery-path
rehearsal receipt to reach `complete_recovery_current`. Until then doctor remains
non-green, another bulk rewrite is refused, and old-copy retirement is unsafe.
Rotation changes ciphertext but is not erasure.

First omit `--confirm`. After authenticating the control credential and its
current `key-rotation` grant, the command prints only old/new public
fingerprints, generation, lockout/backup-receipt blast radius, and the exact
digest confirmation; it mutates nothing. Repeat with the same inputs, audited
`--reason`, and `--confirm DIGEST`. The command self-tests the new private
identity, reloads credential/identity/grants at the final barrier, then commits
envelope, metadata, and audit together. A recovery identity may be the current
unwrap source. Retry after a lost final reply with the installed recipient set
returns a stable `already_installed` no-op. Any other stale generation refuses.

## Emergency credential-epoch rotation

`credential epoch rotate --mode offline` is the daemon-stopped incident route.
It requires the service owner, exclusive data-directory lock, an approved typed
age identity source that unwraps the current keyring (active or enrolled
recovery), an audited reason, expected epoch, and exact confirmation. First omit
`--confirm`: the command reports bounded active token/secret-id counts, the next
epoch, one-hour replacement TTL, and that the caller credential dies, with no
mutation. Repeat with the exact digest and an approved
`--credential-output-fd`; regular files and block devices are refused.

The shared R41 primitive creates a fresh system recovery identity, versioned
admin grant, and finite control-only credential. It writes and flushes the raw
replacement only to the approved sink, then one redb transaction installs the
identity, grant, credential, incremented epoch, and encrypted audit event. A
sink failure or pre-commit crash leaves the old epoch authoritative and any
orphan disclosure unusable. The epoch check invalidates every previous token
and secret ID even though this operation deliberately leaves the existing
credential-verifier key unchanged; verifier-key replacement is a separate
keyring-envelope concern and is never implied.

Online mode is distinct: owner peer credentials plus `key-rotation`,
identity/grant management, and credential issuance are all required. The daemon
sends the replacement only over the authenticated owner socket and commits only
after the CLI flushes its approved sink and ACKs the request nonce plus a
domain-separated credential digest. A narrow key operator cannot acquire the
recovery admin bundle. Interrupted authenticated original rewrite/migration/
compaction states may mint only an abort/cleanup credential and become
`auth_recovery_stale`; foreign, ambiguous, or post-rename states refuse.

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

The release-frozen record/AAD, encrypted-record, secret-metadata clear-MAC, and
age 0.12 envelope artifacts live under `tests/fixtures/`; their schema, domain
IDs, hashes, negative-case IDs, generator, and regeneration command are in
`crypto-fixtures-manifest-v1.json`. Run `./scripts/check-crypto-vectors.sh` on
native x86_64 and aarch64 runners. It regenerates to a private temporary file,
requires byte equality, verifies fixture hashes, and exercises strict decode
and tamper rejection. `--regenerate` is deliberately explicit and leaves hash
drift failing until reviewed. After Gate G2, accepted drift requires an R35
forward-only migration plus upgrade notes; never update golden bytes merely to
make a test pass.

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

Credential administration uses `token issue|list|revoke`, `approle role
create|list|delete`, and `approle secret-id issue|list|revoke`. Issuance needs
`credential-issue`; discovery and revocation need `credential-revoke`. A
cross-identity token or role binding additionally needs
`identity-grant-manage`, and ordinary authority can never mint an emergency or
more-privileged control credential. Token and secret-ID issue commands require
a unique public label, a request ID, bounded TTL, and an approved
`--credential-output-fd`; stable stdout contains metadata only. Retrying a
committed request returns metadata without the bearer. Find an issuance whose
reply was lost by label/accessor, revoke it with a non-secret reason, then issue
a fresh credential. There is no re-disclosure command.

Secret IDs use a bounded use count and normally require a stable
`consumer_instance_id`; accepting identity-only tracking is an explicit
operator choice. Role deletion requires the current generation, the exact
bounded count of active secret IDs it invalidates, a reason, and the canonical
digest confirmation. It revokes those secret IDs but does not revoke tokens
already minted by earlier logins. Lists are stable, cursor-paginated, capped at
100 rows, and contain accessors and lifecycle metadata only.

For finite control-token rollover, issue a labeled successor to the same human
identity, authenticate it on a read-only owner-socket command, then revoke the
predecessor by accessor and prove rejection. Never revoke the last tested
admin-capable credential first. The production owner-socket/redb adapter is
fail-closed until the U5.7 assembled-server slice wires the frozen lifecycle
kernel to the coordinator; no remote route substitutes for that adapter.

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

KV deletion has three distinct meanings. Soft-delete is reversible; destroy
removes one version's ciphertext from the active store while retaining its
metadata marker; full purge is a separately authorized local control-plane
operation and is never exposed by remote metadata DELETE. Destroy is logical
unavailability, not cryptographic erasure: encrypted copies can remain in
backups, filesystem remnants, and storage snapshots. Compaction may remove
obsolete active-file pages but is not an erasure claim. Disposal of whole
copies follows external backup, media, and key-custody policy.

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

KV values are one encrypted JSON object, bounded before encryption/storage to
512 KiB encoded bytes, 256 total object fields, 256 Unicode scalar values per
field name, and nesting depth 32. The shared strict parser additionally bounds
the whole body to 1 MiB, 1,024 JSON keys and 4,096 JSON values. Version mutation
arrays contain at most 64 unique nonzero versions. LIST returns at most 1,024
immediate children and fails with `list_results` at N+1; it never truncates.
`custom_metadata` permits 64 keys, 128 Unicode scalar values per key and 512 per
value. These are character limits, not UTF-8 byte limits. Request
`Content-Encoding` is unsupported and rejected before body processing. KV
responses carry `Cache-Control: no-store` and no `Content-Encoding`.

## Declared consumer registry

Before rotation, register every known consumer with `consumer create`, then add
each deployment/process row with `consumer instance create`. Parent and instance
IDs, labels, parent ownership and canonical secret resource are immutable;
updates use the opaque ID plus expected generation. `consumer list|show` and
their instance forms require `consumer-enumeration`; create, update and retire
require `rotation-management` over the owner-only control socket. No consumer
route exists on the remote listener.

Lifecycle is exactly `declared`, `migrated`, or `retired`. Only forward
transitions are accepted. Retirement is the sole delete-like operation, always
requires an audited non-secret reason, and retains the MAC-authenticated row.
Retire active child instances before their parent. A retired row no longer
blocks rotation closeout. The registry stores bounded facts and notes only—never
secret values, commands, scripts, webhooks, or executable configuration.

`consumer reconcile <resource>` reads declarations, current identities/grants,
and authenticated primary audit read events at one returned cutoff. It reports
registry lifecycle, current authorization, and current-window observation as
separate dimensions. Authorized identities are never hidden merely because they
were not recently observed. Flags are a closed ordered set:
`declared_unmigrated`, `declared_unauthorized`, `authorized_undeclared`,
`migrated_unobserved`, `observed_undeclared`, `reconciled_observed`, and
`retired_historical`. Observation includes reads exactly on either lookback
boundary and reports the served version. A missing/corrupt source or unauthentic
in-window event fails the whole view; no plausible partial list is returned.

## Fresh-host restore

Restore only into an absent path inside an existing service-owned mode-0700
directory. Keep daemon stopped. Generate a new active identity into approved
custody first; never reuse source-active or backup-recovery identity as routine
active identity. Supply private identities through typed `stdin`, `fd:N`,
`credential:NAME`, or `tty` descriptors and supply emergency credential custody
as a pre-opened TTY, pipe, socket, or anonymous-memory FD.

Use `ops-light-secrets-server restore --help` for exact arguments. Normal signed
operation requires archive, detached signature, authenticated public-key
candidate, backup recovery identity source, new active identity source, target,
source-decommissioned assertion, actor, reason, digest-bound confirmation, and
credential output FD. An absent signature additionally requires
`--allow-unsigned-manifest` and exact `--unsigned-confirm`; a present invalid
signature is never downgraded to unsigned mode.

Restore verifies outer container/signature before age unwrap, reconstructs a
new redb database from logical frames, checks archived state digest and complete
audit chain, validates authenticated identity/grant/credential records, installs
exactly new active plus confirmed recovery recipient, and invokes shared
credential-epoch recovery preparation. Recipient replacement, epoch bump,
finite emergency principal, `restore_activation` whole-state audit entry,
fresh incarnation, and `pending_anchor=normal-restore` commit in one redb
transaction. Emergency credential bytes flush before that transaction; any
earlier failure removes temporary sibling and leaves target absent. Final file
uses mode 0600 and is installed by sibling rename followed by parent fsync.

Successful restore remains explicitly unanchored. Use disclosed emergency
credential to issue finite normal admin token, authenticate it on named command,
revoke emergency accessor, then complete external checkpoint prepare/sign/register
and passing state verification. Until pending marker clears, ordinary service
warns and bulk rewrite, migration, compaction, another restore, and key jobs
remain refused. Preserve archive, signature, authenticated signing lineage,
off-host checkpoint, and restore receipt as recovery evidence.

## Offline store migration

Startup never migrates a store. A supported older format reports
`migration_required {from,to}`; a newer version, downgrade, skipped version, or
unregistered hop reports `unsupported_store_version` without writing the file.

Use this order: run `store migrate plan` for an advisory capacity/version check;
create the logical backup; register its detached manifest signature; complete
and register a recovery-recipient full-rehearsal receipt; stop the daemon; take
the no-follow exclusive store/parent lock; then run `store migrate plan
--offline-final` with that archive and receipt. Only this audited final plan's
digest-bound confirmation is accepted by `store migrate apply`. Apply rechecks
control `store-maintenance` authority, credential lifetime, generations, the
authenticated maintenance-only tail, free space after `recovery.reserve`, and
the lock immediately before mutation and replacement.

The engine writes and fsyncs an authenticated owned marker before entering
`migrating`, builds a mode-0600 same-directory sibling from the authoritative
table/codec registry, verifies it, preserves anchored history byte-for-byte,
then atomically renames and fsyncs the parent. Before rename the original is
authoritative and `store migrate abort` can restore `ready` before removing the
owned marker and sibling. After rename rollback is restore-from-backup, never an
automatic guess. The installed store is `ready` with
`pending_anchor=migration`; complete checkpoint prepare/sign/register and a
passing state verification to clear it. Until then doctor is non-green and all
other bulk rewrite, restore, migration, compaction, and key jobs are refused.

v0.1 has no real prior release. Its release evidence therefore uses the retained
synthetic v0-to-v1 adjacent fixture exactly once. Starting with the next release,
the committed fixture and actual prior released binary are mandatory migration
and prior-binary-refusal evidence.

## Offline store compaction

Compaction is an explicit physical rewrite, never a startup, migration, backup,
destroy, or purge side effect. Run `store compact plan` to measure the current
file, complete the same signed and recovery-rehearsed fresh-backup sequence used
for migration, stop cleanly and lock the parent/store without following links,
then run `store compact plan --offline-final`. Only that audited final token is
accepted by `store compact apply`; `store compact abort` is available only while
the original file remains authoritative before replacement.

The compacted sibling contains every logical record in the authoritative codec
registry byte-for-byte, including encrypted nonces/ciphertexts, MAC'd metadata,
soft-deleted versions and tombstones, audit history, checkpoints, signing trust,
and backup/recovery evidence. Only redb free and superseded physical pages are
left behind. A dense-store plan warns when predicted benefit is below 10%; it
does not invent reclamation. Capacity is rechecked after `recovery.reserve` at
the exact final barrier. After atomic install, complete a new external checkpoint
and passing state verification to clear `pending_anchor=compaction`.

Compaction is not secure deletion. Filesystem journals/snapshots, SSD remapping,
backups, old copies, and retained authenticated history can preserve ciphertext.
v0.1 makes no per-secret cryptographic-erasure claim; disposal remains an
external media, backup, and key-custody procedure.

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
