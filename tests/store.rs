use ops_light_secrets_server::store::{
    AnchorInstalledState, Canonical, CodecError, FORMAT_VERSION, KeyringEnvelope, Lifecycle,
    LogicalPath, MAINTENANCE_MARKER_FILE, MaintenanceKind, MaintenanceMarker, MaintenancePhase,
    MetaRecord, PendingAnchor, PendingAnchorKind, PendingAnchorStatus, RewriteJob, RewriteKind,
    RewriteStatus, RotationState, SecretKey, SecretMetadata, SecretRecord, Store, StoreError,
    StoreId, VersionSetSummary, VersionState,
};
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::BTreeMap;
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const SECRET_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("secret_meta");

fn meta() -> MetaRecord {
    MetaRecord {
        store_id: StoreId([7; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_700_000_000,
        pending_anchor: None,
    }
}

fn metadata() -> SecretMetadata {
    SecretMetadata {
        schema_version: 1,
        custom: BTreeMap::from([
            ("owner".to_owned(), "ops".to_owned()),
            ("purpose".to_owned(), "test".to_owned()),
        ]),
        max_versions: 10,
        cas_required: true,
        last_completed_rotation_unix_seconds: Some(1_700_000_001),
        rotation_interval_seconds: Some(86_400),
        rotation_state: RotationState::Idle,
        rotation_protection: Some(vec![1, 2, 3]),
        versions: VersionSetSummary::empty(),
    }
}

fn assert_strict<T: Canonical + std::fmt::Debug + PartialEq>(value: T) {
    let encoded = value.encode().unwrap();
    assert_eq!(T::decode(&encoded).unwrap(), value);
    assert_eq!(value.encode().unwrap(), encoded);
    for length in 0..encoded.len() {
        assert!(T::decode(&encoded[..length]).is_err(), "prefix {length}");
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(T::decode(&trailing), Err(CodecError::Trailing));
    let mut unknown = encoded;
    unknown[0] = 2;
    assert_eq!(T::decode(&unknown), Err(CodecError::UnknownVersion));
}

#[test]
fn canonical_key_and_summary_golden_vectors_are_big_endian_and_stable() {
    let path = LogicalPath::new("a/b").unwrap();
    assert_eq!(path.encode().unwrap(), b"\x01\0\0\0\x03a/b");
    assert_eq!(
        SecretKey {
            path: path.clone(),
            version: 7,
        }
        .encode()
        .unwrap(),
        b"\x01\0\0\0\x08\x01\0\0\0\x03a/b\0\0\0\0\0\0\0\x07"
    );

    let mut summary = VersionSetSummary::empty();
    assert_eq!(summary.append().unwrap(), 1);
    assert_eq!(
        summary.encode().unwrap(),
        b"\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\x01\0"
    );
}

#[test]
fn version_summary_generation_bumps_for_every_state_change() {
    let mut summary = VersionSetSummary::empty();
    let first = summary.append().unwrap();
    assert_eq!(summary.generation, 1);
    summary.soft_delete(first).unwrap();
    assert_eq!(summary.generation, 2);
    assert_eq!(summary.states[&first], VersionState::SoftDeleted);
    summary.undelete(first).unwrap();
    assert_eq!(summary.generation, 3);
    summary.destroy(first).unwrap();
    assert_eq!(summary.generation, 4);
    assert_eq!(summary.states[&first], VersionState::Destroyed);
    assert!(summary.undelete(first).is_err());
    assert!(summary.soft_delete(first).is_err());

    let path = LogicalPath::new("secret/versioned").unwrap();
    let mut clear = metadata();
    clear.versions = summary;
    let sealed = clear.seal(&[31; 32], StoreId([7; 16]), &path).unwrap();
    assert_eq!(sealed.generation, 4);
    sealed
        .verify(&[31; 32], StoreId([7; 16]), &path.encode().unwrap())
        .unwrap();
}

#[test]
fn all_initial_record_codecs_round_trip_and_reject_truncation_unknown_and_trailing() {
    let mut pending_meta = meta();
    pending_meta
        .seal_pending_anchor(
            PendingAnchor {
                kind: PendingAnchorKind::Compaction,
                operation_id: b"operation-1".to_vec(),
                plan_or_activation_digest: [1; 32],
                installed_state: AnchorInstalledState::PayloadGeneration(9),
                post_state_digest: [2; 32],
                status: PendingAnchorStatus::Installed,
            },
            9,
            &[3; 32],
        )
        .unwrap();
    assert_strict(pending_meta);
    assert_strict(KeyringEnvelope(vec![]));
    assert_strict(KeyringEnvelope(vec![4; 1024]));
    assert_strict(LogicalPath::new("mount/π/value").unwrap());
    assert_strict(SecretKey {
        path: LogicalPath::new("mount/value").unwrap(),
        version: u64::MAX,
    });
    assert_strict(metadata());
    assert_strict(SecretRecord {
        version: u64::MAX,
        created_unix_milliseconds: u64::MAX,
        key_id: [5; 16],
        nonce: [6; 24],
        ciphertext: vec![],
    });
    assert_strict(MaintenanceMarker {
        store_id: StoreId([7; 16]),
        kind: MaintenanceKind::Migration,
        job_id: b"job".to_vec(),
        final_plan_digest: [8; 32],
        source_format: 1,
        target_format: 2,
        source_head: [9; 32],
        source_state: [10; 32],
        phase: MaintenancePhase::Rewriting,
        temporary_file_identity: [11; 32],
        owner_uid: 1000,
    });
    assert_strict(RewriteJob {
        kind: RewriteKind::MetadataKey,
        operation_id: b"rewrite".to_vec(),
        owner_id: b"owner".to_vec(),
        installed_generation: 3,
        installed_state_digest: [12; 32],
        checkpoint_digest: [13; 32],
        backup_artifact_digest: [14; 32],
        backup_signature_digest: [15; 32],
        backup_receipt_digest: [16; 32],
        backup_generation: 4,
        signature_generation: 5,
        receipt_generation: 6,
        status: RewriteStatus::InstalledPendingAnchor,
    });
}

#[test]
fn bounds_noncanonical_paths_and_rewrite_transition_skips_fail_closed() {
    for path in ["", "/a", "a/", "a//b", "a/./b", "a/../b", "a\0b"] {
        assert!(LogicalPath::new(path).is_err(), "{path:?}");
    }
    assert!(LogicalPath::new("a".repeat(1024)).is_ok());
    assert!(LogicalPath::new("a".repeat(1025)).is_err());
    assert_eq!(
        KeyringEnvelope(vec![0; 1024 * 1024 + 1]).encode(),
        Err(CodecError::Limit)
    );
    assert_eq!(
        SecretRecord {
            version: 1,
            created_unix_milliseconds: 0,
            key_id: [0; 16],
            nonce: [0; 24],
            ciphertext: vec![0; 8 * 1024 * 1024 + 1],
        }
        .encode(),
        Err(CodecError::Limit)
    );
    let mut empty_protection = metadata();
    empty_protection.rotation_protection = Some(Vec::new());
    assert_eq!(empty_protection.encode(), Err(CodecError::Invalid));
    assert!(
        RewriteStatus::InstalledPendingAnchor
            .can_advance_to(RewriteStatus::AnchoredRewriteCompleteRecoveryPending)
    );
    assert!(
        !RewriteStatus::InstalledPendingAnchor
            .can_advance_to(RewriteStatus::CompleteRecoveryCurrent)
    );
    assert!(
        !RewriteStatus::CompleteRecoveryCurrent
            .can_advance_to(RewriteStatus::InstalledPendingAnchor)
    );
    let mut job = RewriteJob {
        kind: RewriteKind::RecordKey,
        operation_id: b"rewrite".to_vec(),
        owner_id: b"owner-a".to_vec(),
        installed_generation: 1,
        installed_state_digest: [1; 32],
        checkpoint_digest: [2; 32],
        backup_artifact_digest: [3; 32],
        backup_signature_digest: [4; 32],
        backup_receipt_digest: [5; 32],
        backup_generation: 1,
        signature_generation: 1,
        receipt_generation: 1,
        status: RewriteStatus::InstalledPendingAnchor,
    };
    assert!(
        job.advance(
            b"owner-b",
            RewriteStatus::AnchoredRewriteCompleteRecoveryPending
        )
        .is_err()
    );
    job.advance(
        b"owner-a",
        RewriteStatus::AnchoredRewriteCompleteRecoveryPending,
    )
    .unwrap();
    assert!(
        job.advance(b"owner-a", RewriteStatus::InstalledPendingAnchor)
            .is_err()
    );
}

#[test]
fn duplicate_custom_metadata_and_unknown_lifecycle_are_noncanonical() {
    let summary = VersionSetSummary::empty().encode().unwrap();
    let mut duplicate = vec![1, 0, 1, 0, 10, 0, 0, 0, 0, 0, 0, 2];
    for value in ["first", "second"] {
        duplicate.extend_from_slice(&1_u32.to_be_bytes());
        duplicate.push(b'a');
        duplicate.extend_from_slice(&(value.len() as u32).to_be_bytes());
        duplicate.extend_from_slice(value.as_bytes());
    }
    duplicate.extend_from_slice(&(summary.len() as u32).to_be_bytes());
    duplicate.extend_from_slice(&summary);
    assert_eq!(SecretMetadata::decode(&duplicate), Err(CodecError::Invalid));

    let mut encoded_meta = meta().encode().unwrap();
    encoded_meta[21] = 99;
    assert_eq!(MetaRecord::decode(&encoded_meta), Err(CodecError::Invalid));
}

#[test]
fn maintenance_and_rewrite_macs_bind_fixed_identity_and_reject_transplants() {
    assert_eq!(
        MAINTENANCE_MARKER_FILE,
        ".ops-light-secrets-server.maintenance.marker.v1"
    );
    let marker = MaintenanceMarker {
        store_id: StoreId([7; 16]),
        kind: MaintenanceKind::Compaction,
        job_id: b"job-1".to_vec(),
        final_plan_digest: [1; 32],
        source_format: 1,
        target_format: 1,
        source_head: [2; 32],
        source_state: [3; 32],
        phase: MaintenancePhase::Planned,
        temporary_file_identity: [4; 32],
        owner_uid: 1000,
    }
    .seal(2, &[5; 32])
    .unwrap();
    marker
        .verify(
            &[5; 32],
            StoreId([7; 16]),
            MAINTENANCE_MARKER_FILE.as_bytes(),
        )
        .unwrap();
    assert!(
        marker
            .verify(
                &[5; 32],
                StoreId([8; 16]),
                MAINTENANCE_MARKER_FILE.as_bytes(),
            )
            .is_err()
    );

    let rewrite = RewriteJob {
        kind: RewriteKind::RecordKey,
        operation_id: b"rewrite-1".to_vec(),
        owner_id: b"owner-1".to_vec(),
        installed_generation: 10,
        installed_state_digest: [6; 32],
        checkpoint_digest: [7; 32],
        backup_artifact_digest: [8; 32],
        backup_signature_digest: [9; 32],
        backup_receipt_digest: [10; 32],
        backup_generation: 11,
        signature_generation: 12,
        receipt_generation: 13,
        status: RewriteStatus::InstalledPendingAnchor,
    }
    .seal(10, &[11; 32], StoreId([7; 16]))
    .unwrap();
    rewrite
        .verify(&[11; 32], StoreId([7; 16]), b"rewrite-1")
        .unwrap();
    assert!(
        rewrite
            .verify(&[11; 32], StoreId([7; 16]), b"rewrite-2",)
            .is_err()
    );
}

#[test]
fn create_open_and_all_initial_tables_round_trip_in_one_redb_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = Store::create(&path, &meta()).unwrap();
    assert_eq!(store.meta().unwrap(), meta());
    assert_eq!(store.keyring().unwrap(), None);
    store.put_keyring(&KeyringEnvelope(vec![9, 8, 7])).unwrap();

    let logical = LogicalPath::new("secret/application").unwrap();
    let mut clear = metadata();
    let version = clear.versions.append().unwrap();
    let sealed = clear.seal(&[4; 32], StoreId([7; 16]), &logical).unwrap();
    store
        .put_secret_metadata(&logical, &sealed, &[4; 32])
        .unwrap();
    let secret_key = SecretKey {
        path: logical.clone(),
        version,
    };
    let record = SecretRecord {
        version,
        created_unix_milliseconds: 1_700_000_000_123,
        key_id: [10; 16],
        nonce: [11; 24],
        ciphertext: vec![12, 13, 14],
    };
    store.put_secret(&secret_key, &record).unwrap();
    drop(store);

    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.meta().unwrap(), meta());
    assert_eq!(
        reopened.keyring().unwrap(),
        Some(KeyringEnvelope(vec![9, 8, 7]))
    );
    assert_eq!(
        reopened.secret_metadata(&logical, &[4; 32]).unwrap(),
        Some(sealed)
    );
    assert_eq!(reopened.secret(&secret_key).unwrap(), Some(record));
}

#[test]
fn lifecycle_and_high_water_are_readable_before_keyring_and_unknown_format_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = Store::create(&path, &meta()).unwrap();
    let previous = store.meta().unwrap();
    let mut replacement = previous.clone();
    replacement.lifecycle = Lifecycle::Migrating;
    replacement.high_water_unix_seconds += 99;
    store.set_meta(&previous, &replacement).unwrap();
    let mut foreign_store = replacement.clone();
    foreign_store.store_id = StoreId([8; 16]);
    assert_eq!(
        store.set_meta(&replacement, &foreign_store),
        Err(StoreError::Integrity)
    );
    assert_eq!(store.keyring().unwrap(), None);
    assert_eq!(store.meta().unwrap(), replacement);

    let mut unknown = replacement.clone();
    unknown.format_version = FORMAT_VERSION + 50;
    store.set_meta(&replacement, &unknown).unwrap();
    drop(store);
    assert_eq!(
        Store::open(&path).err(),
        Some(StoreError::UnsupportedFormat(FORMAT_VERSION + 50))
    );
}

#[test]
fn clear_record_mac_rejects_wrong_key_store_path_and_offline_edit() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("store.redb");
    let logical = LogicalPath::new("secret/application").unwrap();
    let mut clear = metadata();
    clear.versions.append().unwrap();
    let sealed = clear.seal(&[4; 32], StoreId([7; 16]), &logical).unwrap();
    assert!(
        sealed
            .verify(&[5; 32], StoreId([7; 16]), &logical.encode().unwrap(),)
            .is_err()
    );
    assert!(
        sealed
            .verify(&[4; 32], StoreId([8; 16]), &logical.encode().unwrap(),)
            .is_err()
    );
    let other = LogicalPath::new("secret/other").unwrap();
    assert!(
        sealed
            .verify(&[4; 32], StoreId([7; 16]), &other.encode().unwrap(),)
            .is_err()
    );

    let store = Store::create(&database_path, &meta()).unwrap();
    let wrong_store_sealed = metadata()
        .seal(&[4; 32], StoreId([8; 16]), &logical)
        .unwrap();
    assert_eq!(
        store.put_secret_metadata(&logical, &wrong_store_sealed, &[4; 32]),
        Err(StoreError::Integrity)
    );
    store
        .put_secret_metadata(&logical, &sealed, &[4; 32])
        .unwrap();
    drop(store);
    let database = Database::open(&database_path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(SECRET_META).unwrap();
        let key = logical.encode().unwrap();
        let mut value = table.get(key.as_slice()).unwrap().unwrap().value().to_vec();
        let last = value.len() - 1;
        value[last] ^= 1;
        table.insert(key.as_slice(), value.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);
    let store = Store::open(&database_path).unwrap();
    assert_eq!(
        store.secret_metadata(&logical, &[4; 32]).err(),
        Some(StoreError::Integrity)
    );
}

#[test]
fn secret_value_version_must_match_versioned_primary_key() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::create(directory.path().join("store.redb"), &meta()).unwrap();
    let key = SecretKey {
        path: LogicalPath::new("secret/version").unwrap(),
        version: 2,
    };
    let record = SecretRecord {
        version: 1,
        created_unix_milliseconds: 1,
        key_id: [1; 16],
        nonce: [2; 24],
        ciphertext: vec![3],
    };
    assert_eq!(store.put_secret(&key, &record), Err(StoreError::Integrity));
}

#[test]
fn pending_anchor_mac_binds_store_and_rejects_edits() {
    let key = [21; 32];
    let mut value = meta();
    value
        .seal_pending_anchor(
            PendingAnchor {
                kind: PendingAnchorKind::RollbackFork,
                operation_id: b"fork-1".to_vec(),
                plan_or_activation_digest: [22; 32],
                installed_state: AnchorInstalledState::Incarnation([44; 16]),
                post_state_digest: [23; 32],
                status: PendingAnchorStatus::CheckpointPrepared,
            },
            44,
            &key,
        )
        .unwrap();
    value.verify_pending_anchor(&key).unwrap();
    let mut transplanted = value.clone();
    transplanted.store_id = StoreId([99; 16]);
    assert!(transplanted.verify_pending_anchor(&key).is_err());
    let mut encoded = value.encode().unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    assert!(
        MetaRecord::decode(&encoded)
            .unwrap()
            .verify_pending_anchor(&key)
            .is_err()
    );
}

#[test]
fn u2_scenario_ledger_is_complete_source_checked_and_harness_logged() {
    const CASES: [&str; 20] = [
        "write-read-ciphertext",
        "version-retention-latest",
        "wrong-absent-identity",
        "aad-transplant",
        "fresh-nonce",
        "cross-architecture-vectors",
        "clear-record-edit",
        "clear-record-transplant",
        "state-tail-rollback",
        "metadata-no-decrypt",
        "zeroize-contract",
        "unknown-store-format",
        "bounded-executor-lanes",
        "cross-store-envelope",
        "corrupt-envelope",
        "no-plaintext-cache",
        "keyring-metadata-mismatch",
        "provisional-meta-reverify",
        "single-envelope-decrypt",
        "version-summary-generation",
    ];
    let ledger: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/u2-store-scenarios-v1.json")).unwrap();
    let scenarios = ledger["scenarios"].as_array().unwrap();
    assert_eq!(ledger["schema"], 1);
    assert_eq!(scenarios.len(), CASES.len());
    let harness = Harness::builder("u2-store-suite")
        .register_canary(b"u2-store-secret-canary")
        .build()
        .unwrap();
    for (index, (entry, case)) in scenarios.iter().zip(CASES).enumerate() {
        assert_eq!(entry["id"], index + 1);
        assert_eq!(entry["case"], case);
        let source = entry["source"].as_str().unwrap();
        let test = entry["test"].as_str().unwrap();
        let contents =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(source))
                .unwrap();
        assert!(
            contents.contains(&format!("fn {test}(")),
            "missing {source}::{test}"
        );
        let status = entry["status"].as_str().unwrap();
        assert_eq!(status, "active");
        let status = "active";
        let owner = if entry["owner"] == "U2.8" {
            "U2.8"
        } else {
            assert_eq!(entry["owner"], "U6.6");
            "U6.6"
        };
        let mut scenario = harness.scenario_case("u2-store", case, 1).unwrap();
        scenario
            .step(
                "coverage",
                SafeSummary::new()
                    .field("scenario", SafeValue::Unsigned((index + 1) as u64))
                    .field("status", SafeValue::StaticKind(status))
                    .field("owner", SafeValue::StaticKind(owner))
                    .field("seed", SafeValue::Unsigned(0)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        scenario.finish_success().unwrap();
    }
}

#[test]
fn state_tail_checkpoint_rejects_rollback() {
    use ops_light_secrets_server::store::{
        EncryptedTable, StateDelta, StateDeltaSet, StateDigest, StateTuple,
    };
    use std::collections::BTreeSet;

    let old = StateTuple::encrypted(EncryptedTable::Secrets, b"key", b"old").unwrap();
    let new = StateTuple::encrypted(EncryptedTable::Secrets, b"key", b"new").unwrap();
    let anchored = StateDigest::compute([old.clone()]).unwrap();
    let tail = StateDeltaSet::new([StateDelta::replace(old, new.clone()).unwrap()]).unwrap();
    assert_eq!(
        StateDigest::compute(tail.reverse_apply(&BTreeSet::from([new])).unwrap()).unwrap(),
        anchored
    );
    assert!(tail.reverse_apply(&BTreeSet::new()).is_err());
}

#[test]
fn executor_saturation_preserves_reserved_lane() {
    let source = include_str!("storage_executor.rs");
    assert!(
        source.contains("bounded_lanes_emit_safe_observability_and_reject_before_payload_work")
    );
    assert!(!source.contains("#[ignore"));
}
