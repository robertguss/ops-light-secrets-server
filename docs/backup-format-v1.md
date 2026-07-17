# Logical backup format v1 (Gate G3 freeze)

Status: frozen for v0.1. Any authenticated byte change after Gate G3 is an R35
forward-only migration with release upgrade notes and prior-release restore
fixtures. Redb files are never normative backup artifacts.

## Publication unit and verification order

`backup create` publishes exactly one mode-0600 container. It has a bounded
clear canonical signing header and one age-encrypted payload. The payload holds
the recovery manifest followed by canonical table frames from one MVCC snapshot.
There is no manifest sidecar or bundle directory. Build and encrypt the payload,
hash it, then encode the header; this avoids a cyclic digest.

The clear header freezes format version, archive and source-incarnation IDs,
current backup-domain signing key ID and lineage generation, recovery-set
generation and effective-recipient digest, encrypted length/digest, and recovery
manifest digest. Header and payload close immutably together in the
unsigned-signature state. The detached signature is a separate artifact over
`ops-light-secrets-server.backup-manifest-signature.v1`, key ID, and the digest
of the complete immutable container. Signing and registration never rewrite the
container or change its archive/rehearsal identity.

Restore order is strict: frame/length/trailing limits → ciphertext hash →
detached signature and operator-supplied authenticated public lineage → age
decrypt → recovery-manifest digest → registry/table counts and digests → logical
state/audit/checkpoint relations. A signer or lineage carried only inside the
archive is never a trust root.

## Canonical archive registry

`ARCHIVE_REGISTRY` in `src/backup_format.rs` is authoritative. Stable IDs 1–24
cover current redb tables plus frozen owners for signing trust, AppRole usage,
reserve state, consumers, rotations, maintenance/rewrite jobs, publication
registries, backup/export registries, and receipts. Each row fixes table/domain,
codec version, required/optional cardinality, and owner. Backup enumerates this
registry. Tests compare every current `DURABLE_TABLE_NAMES` row to a required
codec; adding durable state without a registry row fails the gate.

Frames are ordered by ascending table ID and occur at most once. Entries are
strictly ordered by canonical key, with no empty/duplicate/reordered keys. A
frame fixes table ID, codec version, count, and bounded key/value bytes. Required
omission, unknown table/version, duplicate/reordered frame or entry, zero/over
limit count, noncanonical length, truncation, and trailing bytes refuse. Values
are authenticated clear-record bytes, unchanged encrypted-record bytes, or the
current age keyring envelope according to the registry codec. The archive is a
logical application format, never a redb page/file copy.

Frozen bounds: 32 table frames, 1,000,000 entries per table, 4 KiB key, 8 MiB
value, 1 GiB encrypted payload, and no paths, symlinks, device nodes, or archive
member filenames.

## Recovery manifest

Manifest v1 binds archive/store/source-incarnation IDs, keyring generation,
recovery-recipient-set generation, sorted effective recipient fingerprints,
full non-audit `state_digest` from the same snapshot, audit cutoff epoch,
sequence and head, latest checkpoint digest, creator audit position, current
backup-domain key, signing-lineage generation and transition digest, and sorted
per-table codec/count/digest summaries. Audit/checkpoint/descriptor state stays
excluded from `state_digest` exactly as frozen by U2.5/U6.4 and is committed by
its separate fields.

The active recipient is the daemon keyring recipient. The configured recovery
set contains 1–7 distinct sorted off-host fingerprints. The effective set is
derived as active plus recovery, has 2–8 members, rejects equality/duplicates,
and gets a domain-separated digest. Callers cannot override it per backup.
`backup recipient list|set` manages only the recovery set under
`backup-recipient-manage`, generation/CAS, reason, blast-radius summary, and
digest confirmation. Active rewrap changes the next effective digest and
invalidates active-path receipts; recovery-set changes invalidate affected DR
receipts.

## Signing lifecycle and disposition

The manifest closes under the U6.8 key current at creator audit position.
Offline `backup manifest sign` and authenticated registration must finish while
that key is current. Rollover inventories publishing or unsigned/unregistered
manifests. An old-key manifest left unsigned across rollover must be recreated
or retained explicitly unsigned. Historical registered signatures verify
through retained lineage; Ed25519 proves no trusted production time.

`backup manifest abandon <digest>` requires `backup`, registry generation,
reason and exact confirmation. It records an idempotent disposition but never
deletes or rewrites bytes and never cryptographically revokes a detached
signature. Offline output is `registration_status=unknown_offline` unless the
recovery package supplies the authenticated audit segment through disposition
and a covering checkpoint.

An absent signature refuses by default. It may proceed only with all of
`--allow-unsigned-manifest`, a non-secret reason, and the exact
archive-digest/reason confirmation. That emits a high-severity audited event and
doctor finding. A present invalid, mismatched, wrong-domain, wrong-store, or
wrong-lineage signature can never be overridden.

## Restore epochs, trust, and RPO truth

Every activation increments `current_credential_epoch` and must disclose a new
emergency control credential through R41/R17 before install; otherwise all
restored control credentials are dead and no bootstrap route exists.

A normal restore continues the archived audit epoch only when every supplied
authenticated checkpoint and effective lineage transition is no newer than the
archive. It installs exactly the archive's trust registry; newer out-of-band
lineage is evidence, not a silent registry update. A newer supplied checkpoint
or transition forces `--start-recovery-epoch`, reason and confirmation. Fork
activation increments credential and audit epochs and writes recovery genesis
binding restored head, missing anchored range, checkpoint-set digest, imported
complete lineage digest/current signer, archive digest, source/RPO assertion,
actor and reason. Historical anchored epoch and fork remain separate forever.

Source assertions freeze `claimed_decommissioned`, cutoff tuple and one of
`barrier_confirmed|last_known|unavailable`. Barrier-confirmed requires the exact
post-stop executor/store-lock head and makes later append stale. Last-known binds
optional tuple/time/provenance but is explicitly non-final. Unavailable has no
tuple. Tail status is complete/partial/unavailable with an optional digest;
complete must descend from cutoff. RPO is known-range or unknown with a
non-secret acknowledgment. Operator assertions never masquerade as external
proof.

The recovery package is the container, offline age identities, signing-key
custody where needed, and authenticated public trust-lineage/checkpoint evidence.
The archive contains no private age identity or signing key. A container without
the rest is a backup artifact, not demonstrated recovery.

## Frozen recovery event handoff

Stable recovery event IDs are: backup publishing, published, manifest signature
registered, manifest abandoned, receipt registered, restore activated, unsigned
override, recovery fork genesis, and backup recipient set changed. Gate G2 owns
their canonical audit payload realization without changing these meanings or
IDs.

Golden hashes are in `tests/fixtures/backup-format-v1.json`; positive and
negative coverage is in `tests/backup_format.rs`. The vectors cover signed and
unsigned states, detached signature domain confusion, immutable-container
signing, duplicate/reordered/omitted/unknown/truncated/trailing frames, recipient
confusion, payload edits/swaps, invalid-signature non-override, and normal/fork
epoch decisions.
