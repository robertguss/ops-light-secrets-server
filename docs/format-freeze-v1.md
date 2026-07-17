# G2 persistent-format freeze v1

Gate G2 freezes the cross-release-verifiable formats below. The authoritative
machine registry is `FORMAT_REGISTRY` in `src/format_registry.rs`; the reviewed
manifest and canonical bytes are in `tests/fixtures/format-freeze-v1.json`.
Every later incompatible change requires a new version, a forward-only R35
migration, and R38 upgrade notes. Audit query indexes are rebuildable and are
deliberately outside this freeze.

## Canonical primitives

Unless a format says otherwise, canonical values begin with a one-byte codec
version. Integers are unsigned network byte order. Fixed arrays have no length
prefix. Variable bytes and UTF-8 strings use a four-byte length followed by the
exact bytes. Optionals use tag `0` for absent or `1` followed by the value.
Booleans are exactly `0` or `1`. Decoders reject unknown versions/enums,
over-limit lengths, invalid UTF-8, truncation, and trailing bytes. Collections
have explicit counts and their owning codec defines canonical ordering and
duplicate rejection. No authenticated encoding uses JSON, debug output, string
concatenation, native endianness, or map iteration order.

## Registry

Format IDs 1 through 21, names, versions, domains, owners, and vector files are
binding in `FORMAT_REGISTRY`. The linter rejects zero/duplicate IDs, names, or
domains; missing owners/vectors; duplicate clear-record class IDs/domains;
duplicate archive IDs/tables; and any current durable redb table missing from
the backup registry. Future durable value codecs must register a unique
ID/version and positive plus edit/transplant/unknown/trailing vectors before
their first write.

The clear-record registry has stable class IDs 1..15. Its envelope is codec
version `u8`, MAC format `u16`, class/table/schema IDs, generation, canonical
value, then a 32-byte keyed BLAKE3 tag. The tag domain is
`ops-light-secrets-server.clear-record-mac.v1\0` and length-prefixes MAC format,
table ID, class ID, class domain, schema version, store ID, primary key,
generation, and value. This binds store/table/key/schema/generation/value and
rejects edits and transplants.

The encrypted-record header is magic `OLSSREC\0`, format `u16`, cipher-suite
`u16`, store ID `[16]`, record-domain `u16`, key ID `[16]`, XChaCha nonce `[24]`,
mount `u32+bytes`, path-segment count `u16` and each `u32+bytes`, logical ID
`u32+bytes`, optional secret version, and created Unix milliseconds `u64`.
Header bytes are AEAD associated data. Domains are secret value 1, audit
payload 2, and credential material 3. Bounds are 128-byte mount, 1,024-byte
path, 256 segments, 256-byte logical ID, 4,096-byte header, and 8 MiB
ciphertext.

## Audit, state, checkpoint, and trust

Audit event v1 fixes the field order implemented by `AuditEvent`: schema `u16`,
event/request IDs, authentication method/identity/accessor/result, authorization
capability/result/reason, consumer-instance ID, canonical or rejected resource,
operation/outcome/reason, effective and observed Unix milliseconds, served or
written version, state commitment, previous-epoch terminal, flood aggregate,
and sorted overload counts. Secret values and credential material have no
field. Envelope v1 is audit epoch `[16]`, epoch sequence `u64`, effective Unix
milliseconds `u64`, previous hash `[32]`, and ciphertext digest `[32]`; the
chain hash uses `ops-light-secrets-server.audit-chain.v1\0`. Event payloads use
the record AEAD audit domain. State tuples, sorted state digest, mutation-delta,
and whole-state-transition codecs are version 1 and bind protected-state
before/after digests.

Recovery event IDs are: backup publishing 1, published 2, manifest signature
registered 3, manifest abandoned 4, recovery receipt registered 5, restore
activated 6, unsigned override 7, recovery fork genesis 8, recipient-set change
9, and emergency CONTROL credential issued 10. Their canonical codec is version
`u8` plus event ID `u16`; unknown IDs fail closed. The issuance event contains
only non-secret disclosure metadata.

Checkpoint descriptor v2, checkpoint file v1, state-digest v1, signing-key
candidate v1, lineage v1, transition v1, and the realizable prepare/H1/old-sign/
activate-E/first-B-checkpoint ordering are frozen by their named fixtures.
Activation rechecks a same-incarnation/epoch descendant of H1 and zero
outstanding old-key descriptors. No format claims Ed25519 gives trusted time.

## Shared management codecs

`signer-eligibility.v1` is: artifact domain `u16`, creator epoch `[16]`, creator
sequence `u64`, creator head `[32]`, lineage generation `u64`, optional
transition digest `[32]`, and expected signer ID `[16]`. Domains are checkpoint
1, backup manifest 2, audit export 3, and recovery receipt 4. Generation 1 has
no transition; later generations require one. Registration must still see that
key current. Rollover requires every outstanding descriptor registered or
audited abandoned; retired keys cannot complete new or formerly unsigned
artifacts.

`maintenance-preflight.v1` binds store incarnation `[16]`, audit epoch `[16]`,
checkpoint S `u64`, head H `u64`, head/tail/state-at-S digests, delta count, and
one operation ID per S+1..H. The closed allowed set is backup output,
signature, receipt, checkpoint bookkeeping, audit-only verification,
clock-watermark, and clean shutdown. Unknown/substantive operations,
forced/unclean shutdown, count mismatch, or failed reverse reconstruction
refuse maintenance.

`output-publication.v1` is shared by backup and encrypted audit export. It
binds domain, opaque output ID, bounded owner, header/content/target identity,
artifact and inner-manifest digests, signer ID/lineage generation, creation
sequence, and state. `publishing` has no file outcome; `published` adds file
identity and parent-fsync sequence; `abandoned` adds exact reason/confirmation
digest. Transitions never go backward or publish after abandonment. The
canonical artifact identity is BLAKE3 over the fixed domain, artifact-domain
ID, length-prefixed signing header, and length-prefixed encrypted-payload
digest. `<manifest-digest>` and `<bundle-digest>` are aliases for this field.
The record describes the two serialized redb transactions around rename; it
does not claim filesystem/redb atomicity.

`recovery-activation.v1` binds source/target incarnations, archive cutoff,
decommission claim, source-observation and optional tail evidence, RPO
acknowledgment, checkpoint and trust evidence, recipient/assertion bindings,
and evidence completeness. Normal activation forbids trust import. A recovery
fork requires the complete imported lineage digest/generation/current signer
triple; partial imports refuse. The source-observation status and exact
barrier-confirmed/last-known/unavailable fields are frozen inside recovery
manifest v1.

## Verification and sign-off

Run `./scripts/check-crypto-vectors.sh` to hash every named fixture, regenerate
both deterministic generators, compare canonical output, and run crypto
negative tests. Run `cargo test --locked --test format_registry` for registry,
strict framing, domain confusion, maintenance, publication, and recovery-fork
vectors. Run `./scripts/verify.sh` for formatting, strict clippy, all targets,
MSRV, harness, and canary checks.

Reviewed and frozen on 2026-07-17 by the implementation agent against U2.7,
U6.3, U6.4, U6.8, and U10.1. x86_64 vectors were reproduced locally. The user
reported that native/emulated aarch64 execution is currently unavailable; the
same architecture-independent bytes remain pinned for later aarch64 evidence,
and this limitation is recorded on Gate G2 as `needs-user-review`.
