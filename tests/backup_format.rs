use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use ops_light_secrets_server::backup_format::{
    ARCHIVE_REGISTRY, ArchiveEntry, ArchiveFrame, BACKUP_FORMAT_VERSION, BACKUP_MANIFEST_VERSION,
    BACKUP_SIGNATURE_VERSION, BACKUP_SIGNING_DOMAIN_ID, BackupContainer, BackupSigningHeader,
    DetachedBackupSignature, RecoveryEventType, RecoveryEvidence, RecoveryManifest,
    RecoveryRecipientSet, RestoreMode, SignatureStatus, SourceObservation, SourceObservationStatus,
    TableSummary, TailStatus, UnsignedOverride, allow_restore_signature, classify_restore,
    restore_epoch_plan, signature_message, unsigned_confirmation,
};
use ops_light_secrets_server::store::{Canonical, CodecError, DURABLE_TABLE_NAMES, StoreId};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    schema: u16,
    manifest_blake3: String,
    header_blake3: String,
    container_blake3: String,
    signature_message_blake3: String,
}

fn summaries() -> Vec<TableSummary> {
    ARCHIVE_REGISTRY
        .iter()
        .filter(|codec| codec.required)
        .map(|codec| TableSummary {
            table_id: codec.id,
            codec_version: codec.codec_version,
            entry_count: codec.id as u64,
            digest: [codec.id as u8; 32],
        })
        .collect()
}

fn source() -> SourceObservation {
    SourceObservation {
        status: SourceObservationStatus::BarrierConfirmed,
        claimed_decommissioned: true,
        observed_epoch: Some(4),
        observed_sequence: Some(91),
        observed_head: Some([0x91; 32]),
        observation_unix_milliseconds: Some(1_800_000_000_123),
        provenance_digest: Some([0x92; 32]),
        tail_status: TailStatus::Complete,
        tail_digest: Some([0x93; 32]),
        rpo_known: true,
        acknowledgment_digest: [0x94; 32],
    }
}

fn manifest() -> RecoveryManifest {
    RecoveryManifest {
        archive_id: [1; 16],
        store_id: StoreId([2; 16]),
        store_incarnation_id: [3; 16],
        keyring_generation: 7,
        recovery_set_generation: 8,
        effective_recipient_fingerprints: vec![[0x10; 32], [0x20; 32]],
        state_digest: [0x30; 32],
        audit_epoch: 4,
        audit_sequence: 90,
        audit_head: [0x40; 32],
        latest_checkpoint_digest: Some([0x41; 32]),
        signing_key_id: [0x50; 16],
        signing_lineage_generation: 6,
        signing_transition_digest: [0x51; 32],
        creator_audit_epoch: 4,
        creator_audit_sequence: 90,
        creator_audit_head: [0x40; 32],
        tables: summaries(),
        source: source(),
    }
}

fn container() -> BackupContainer {
    let manifest = manifest();
    BackupContainer::new(
        BackupSigningHeader {
            archive_id: manifest.archive_id,
            store_incarnation_id: manifest.store_incarnation_id,
            signing_key_id: manifest.signing_key_id,
            signing_domain: BACKUP_SIGNING_DOMAIN_ID,
            signing_lineage_generation: manifest.signing_lineage_generation,
            recovery_set_generation: manifest.recovery_set_generation,
            effective_recipient_digest: [0x61; 32],
            encrypted_payload_length: 1,
            encrypted_payload_digest: [1; 32],
            recovery_manifest_digest: manifest.digest().unwrap(),
        },
        b"age-encrypted-canonical-manifest-and-frames".to_vec(),
    )
    .unwrap()
}

#[test]
fn registry_is_closed_unique_ordered_and_covers_every_durable_table() {
    assert_eq!(BACKUP_FORMAT_VERSION, 1);
    assert_eq!(BACKUP_MANIFEST_VERSION, 1);
    assert_eq!(BACKUP_SIGNATURE_VERSION, 1);
    assert!(
        ARCHIVE_REGISTRY
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    );
    assert_eq!(
        ARCHIVE_REGISTRY
            .iter()
            .map(|codec| codec.table)
            .collect::<BTreeSet<_>>()
            .len(),
        ARCHIVE_REGISTRY.len()
    );
    for table in DURABLE_TABLE_NAMES {
        assert!(
            ARCHIVE_REGISTRY
                .iter()
                .any(|codec| codec.table == table && codec.required),
            "missing durable table {table}"
        );
    }
    assert!(ARCHIVE_REGISTRY.iter().all(|codec| !codec.owner.is_empty()));
    assert_eq!(
        RecoveryEventType::ALL
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        RecoveryEventType::ALL.len()
    );
    let recovery = RecoveryRecipientSet {
        generation: 3,
        recovery_fingerprints: vec![[0x20; 32], [0x30; 32]],
    };
    assert_eq!(
        RecoveryRecipientSet::decode(&recovery.encode().unwrap()).unwrap(),
        recovery
    );
    let effective = recovery.effective([0x10; 32]).unwrap();
    assert_eq!(
        effective.fingerprints,
        vec![[0x10; 32], [0x20; 32], [0x30; 32]]
    );
    assert_ne!(effective.digest, [0; 32]);
    assert!(recovery.effective([0x20; 32]).is_err());
}

#[test]
fn frame_manifest_and_single_container_are_canonical_strict_and_immutable() {
    let frame = ArchiveFrame {
        table_id: 3,
        codec_version: 1,
        entries: vec![
            ArchiveEntry {
                key: b"a".to_vec(),
                value: b"authenticated-clear-record".to_vec(),
            },
            ArchiveEntry {
                key: b"b".to_vec(),
                value: b"unchanged-encrypted-record".to_vec(),
            },
        ],
    };
    let frame_bytes = frame.encode().unwrap();
    assert_eq!(ArchiveFrame::decode(&frame_bytes).unwrap(), frame);
    for end in 0..frame_bytes.len() {
        assert!(ArchiveFrame::decode(&frame_bytes[..end]).is_err());
    }
    let mut trailing = frame_bytes.clone();
    trailing.push(0);
    assert_eq!(ArchiveFrame::decode(&trailing), Err(CodecError::Trailing));
    let duplicate = ArchiveFrame {
        entries: vec![
            ArchiveEntry {
                key: b"a".to_vec(),
                value: vec![],
            },
            ArchiveEntry {
                key: b"a".to_vec(),
                value: vec![],
            },
        ],
        ..frame.clone()
    };
    assert!(duplicate.encode().is_err());
    let reordered = ArchiveFrame {
        entries: frame.entries.iter().cloned().rev().collect(),
        ..frame
    };
    assert!(reordered.encode().is_err());

    let manifest = manifest();
    let manifest_bytes = manifest.encode().unwrap();
    assert_eq!(RecoveryManifest::decode(&manifest_bytes).unwrap(), manifest);
    let mut recipients_duplicate = manifest.clone();
    recipients_duplicate.effective_recipient_fingerprints[1] = [0x10; 32];
    assert!(recipients_duplicate.encode().is_err());
    let mut missing = manifest.clone();
    missing.tables.remove(0);
    assert!(missing.encode().is_err());
    let mut reordered_tables = manifest.clone();
    reordered_tables.tables.swap(0, 1);
    assert!(reordered_tables.encode().is_err());

    let container = container();
    let bytes = container.encode().unwrap();
    assert_eq!(BackupContainer::decode(&bytes).unwrap(), container);
    let mut payload_edit = container.clone();
    payload_edit.encrypted_payload[0] ^= 1;
    assert!(payload_edit.encode().is_err());
    let mut appended = bytes;
    appended.push(0);
    assert_eq!(
        BackupContainer::decode(&appended),
        Err(CodecError::Trailing)
    );
}

#[test]
fn detached_signature_is_domain_separated_and_archive_is_never_rewritten() {
    let container = container();
    let bytes_before = container.encode().unwrap();
    let digest = container.content_digest().unwrap();
    let private = SigningKey::from_bytes(&[0x77; 32]);
    let signature = private.sign(&signature_message(container.header.signing_key_id, digest));
    let detached = DetachedBackupSignature {
        key_id: container.header.signing_key_id,
        content_digest: digest,
        signature: signature.to_bytes(),
    };
    detached
        .verify(&container.header, private.verifying_key().as_bytes())
        .unwrap();
    assert_eq!(
        DetachedBackupSignature::decode(&detached.encode().unwrap()).unwrap(),
        detached
    );
    let mut wrong_domain_digest = detached.clone();
    wrong_domain_digest.content_digest[0] ^= 1;
    assert!(
        wrong_domain_digest
            .verify(&container.header, private.verifying_key().as_bytes())
            .is_err()
    );
    assert_eq!(container.encode().unwrap(), bytes_before);
}

#[test]
fn unsigned_override_is_exact_and_invalid_signature_can_never_be_overridden() {
    let archive_digest = container().content_digest().unwrap();
    assert!(!allow_restore_signature(SignatureStatus::Valid, archive_digest, None).unwrap());
    assert!(allow_restore_signature(SignatureStatus::Absent, archive_digest, None).is_err());
    let reason = "recover checksummed unsigned archive after signer loss";
    let confirmation = unsigned_confirmation(archive_digest, reason);
    assert!(
        allow_restore_signature(
            SignatureStatus::Absent,
            archive_digest,
            Some(UnsignedOverride {
                allow_unsigned: true,
                reason,
                confirmation: &confirmation,
            }),
        )
        .unwrap()
    );
    assert!(
        allow_restore_signature(
            SignatureStatus::Invalid,
            archive_digest,
            Some(UnsignedOverride {
                allow_unsigned: true,
                reason,
                confirmation: &confirmation,
            }),
        )
        .is_err()
    );
}

#[test]
fn restore_always_bumps_credentials_and_newer_checkpoint_or_lineage_forces_fork() {
    let manifest = manifest();
    let normal = RecoveryEvidence {
        newest_checkpoint_epoch: 4,
        newest_checkpoint_sequence: 90,
        newest_lineage_generation: 6,
        lineage_digest: [1; 32],
    };
    assert_eq!(classify_restore(&manifest, &normal), RestoreMode::Normal);
    let plan = restore_epoch_plan(12, 4, RestoreMode::Normal, false).unwrap();
    assert_eq!((plan.credential_epoch, plan.audit_epoch), (13, 4));
    assert!(plan.replacement_control_credential_required);
    assert!(!plan.fork_genesis_required);

    for newer in [
        RecoveryEvidence {
            newest_checkpoint_sequence: 91,
            ..normal
        },
        RecoveryEvidence {
            newest_lineage_generation: 7,
            ..normal
        },
    ] {
        assert_eq!(
            classify_restore(&manifest, &newer),
            RestoreMode::RecoveryForkRequired
        );
    }
    assert!(restore_epoch_plan(12, 4, RestoreMode::RecoveryForkRequired, false).is_err());
    let fork = restore_epoch_plan(12, 4, RestoreMode::RecoveryForkRequired, true).unwrap();
    assert_eq!((fork.credential_epoch, fork.audit_epoch), (13, 5));
    assert!(fork.fork_genesis_required);
    assert!(restore_epoch_plan(12, 4, RestoreMode::Normal, true).is_err());
}

#[test]
fn golden_hashes_freeze_manifest_header_container_and_signature_domain() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/backup-format-v1.json")).unwrap();
    assert_eq!(fixture.schema, 1);
    let manifest = manifest();
    let container = container();
    let values = [
        blake3::hash(&manifest.encode().unwrap())
            .to_hex()
            .to_string(),
        blake3::hash(&container.header.encode().unwrap())
            .to_hex()
            .to_string(),
        blake3::hash(&container.encode().unwrap())
            .to_hex()
            .to_string(),
        blake3::hash(&signature_message(
            container.header.signing_key_id,
            container.content_digest().unwrap(),
        ))
        .to_hex()
        .to_string(),
    ];
    println!("{}\n{}\n{}\n{}", values[0], values[1], values[2], values[3]);
    assert_eq!(values[0], fixture.manifest_blake3);
    assert_eq!(values[1], fixture.header_blake3);
    assert_eq!(values[2], fixture.container_blake3);
    assert_eq!(values[3], fixture.signature_message_blake3);
}
