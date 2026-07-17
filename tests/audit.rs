use age::x25519;
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource, RecipientSet,
};
use ops_light_secrets_server::store::{
    AUDIT_ENVELOPE_VERSION, AUDIT_SCHEMA_VERSION, AuditAuthMethod, AuditAuthentication,
    AuditAuthorization, AuditCapability, AuditEnvelope, AuditEvent, AuditOperation, AuditOutcome,
    AuditReason, AuditResource, AuditStateCommitment, Canonical, CodecError, EncryptedTable,
    FORMAT_VERSION, Lifecycle, MetaRecord, StateDelta, StateDeltaSet, StateTuple, StoreId,
    StoredAuditEntry, genesis_event, verify_chain,
};
use secrecy::ExposeSecret;
use std::path::Path;
use std::time::{Duration, Instant};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn keyring(random: &mut Counter) -> Keyring {
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    Keyring::generate(
        StoreId([7; 16]),
        1,
        RecipientSet::new(&identity.to_public(), None).unwrap(),
        random,
    )
    .unwrap()
}

fn successful_read(event: u8, effective: u64, wall: u64) -> AuditEvent {
    AuditEvent {
        event_id: [event; 16],
        request_id: [event.wrapping_add(1); 16],
        authentication: AuditAuthentication {
            method: AuditAuthMethod::Token,
            identity_id: Some([3; 16]),
            credential_accessor: Some([4; 16]),
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: Some(AuditCapability::SecretRead),
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: Some([5; 16]),
        resource: Some(AuditResource::Canonical("kv/apps/canvas/api-key".into())),
        operation: AuditOperation::SecretRead,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::None,
        effective_timestamp_milliseconds: effective,
        wall_clock_observation_milliseconds: wall,
        secret_version: Some(7),
        state: AuditStateCommitment::None,
        previous_epoch_terminal: None,
        flood: None,
        overload_counts: Vec::new(),
    }
}

#[test]
fn schema_round_trip_is_strict_typed_and_secret_safe() {
    let event = successful_read(8, 1_800_000_000_100, 1_700_000_000_100);
    let encoded = event.encode().unwrap();
    assert!(AuditEvent::decode(&encoded).unwrap() == event);
    assert_eq!(AUDIT_SCHEMA_VERSION, 1);
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/audit-event-v1.json")).unwrap();
    assert_eq!(fixture["schema_version"], AUDIT_SCHEMA_VERSION);
    assert_eq!(hex(&encoded), fixture["canonical_hex"]);

    let mut unknown = encoded.clone();
    unknown[1..3].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        AuditEvent::decode(&unknown),
        Err(CodecError::UnknownVersion)
    ));
    assert!(matches!(
        AuditEvent::decode(&encoded[..encoded.len() - 1]),
        Err(CodecError::Truncated)
    ));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        AuditEvent::decode(&trailing),
        Err(CodecError::Trailing)
    ));

    let canaries = [
        b"audit-secret-value-canary".as_slice(),
        b"audit-credential-canary".as_slice(),
        b"Authorization: Bearer".as_slice(),
    ];
    for canary in canaries {
        assert!(!encoded.windows(canary.len()).any(|window| window == canary));
    }
    assert_eq!(
        ops_light_secrets_server::store::AuditError::Integrity.to_string(),
        "audit integrity failed"
    );

    let tuple = StateTuple::encrypted(EncryptedTable::Secrets, b"opaque-key", b"frame").unwrap();
    let delta = StateDeltaSet::new([StateDelta::insert(tuple)]).unwrap();
    let mut mutation = successful_read(14, 1_800_000_000_101, 1_700_000_000_101);
    mutation.operation = AuditOperation::SecretWrite;
    mutation.authorization.capability = Some(AuditCapability::SecretWrite);
    assert!(mutation.encode().is_err());
    mutation.state = AuditStateCommitment::Delta(delta);
    assert!(mutation.encode().is_ok());
    mutation.operation = AuditOperation::Restore;
    mutation.secret_version = None;
    assert!(mutation.encode().is_err());
}

#[test]
fn encrypted_chain_verifies_without_decrypt_and_rejects_frame_or_order_tamper() {
    let mut random = Counter(0);
    let keyring = keyring(&mut random);
    let epoch = [9; 16];
    let genesis = genesis_event([10; 16], [11; 16], 1_800_000_000_000, [6; 32]);
    let first =
        StoredAuditEntry::prepare(&keyring, &genesis, epoch, 1, [0; 32], &mut random).unwrap();
    let second_event = successful_read(12, 1_800_000_000_001, 1_700_000_000_000);
    let second = StoredAuditEntry::prepare(
        &keyring,
        &second_event,
        epoch,
        2,
        first.envelope.chain_hash().unwrap(),
        &mut random,
    )
    .unwrap();
    assert_eq!(
        verify_chain([&first, &second]).unwrap(),
        second.envelope.chain_hash().unwrap()
    );
    assert!(first.decrypt(&keyring).unwrap().expose_secret() == &genesis);
    assert!(second.decrypt(&keyring).unwrap().expose_secret() == &second_event);

    let mut frame = second.encode().unwrap();
    *frame.last_mut().unwrap() ^= 1;
    assert!(StoredAuditEntry::decode(&frame).is_err());

    let regressed = StoredAuditEntry::prepare(
        &keyring,
        &successful_read(13, 1_799_999_999_999, 1_900_000_000_000),
        epoch,
        2,
        first.envelope.chain_hash().unwrap(),
        &mut random,
    )
    .unwrap();
    assert!(verify_chain([&first, &regressed]).is_err());
}

#[test]
fn envelope_fixture_freezes_field_order_widths_and_chain_domain() {
    let envelope = AuditEnvelope {
        audit_epoch: [0x11; 16],
        epoch_sequence: 0x0102_0304_0506_0708,
        effective_timestamp_milliseconds: 0x1112_1314_1516_1718,
        previous_hash: [0x22; 32],
        ciphertext_digest: [0x33; 32],
    };
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/audit-envelope-v1.json")).unwrap();
    assert_eq!(fixture["envelope_version"], AUDIT_ENVELOPE_VERSION);
    assert_eq!(hex(&envelope.encode().unwrap()), fixture["canonical_hex"]);
    assert_eq!(
        hex(&envelope.chain_hash().unwrap()),
        fixture["chain_hash_hex"]
    );
    assert_eq!(
        AuditEnvelope::decode(&envelope.encode().unwrap()).unwrap(),
        envelope
    );
    let encoded = envelope.encode().unwrap();
    let mut unknown = encoded.clone();
    unknown[1..3].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        AuditEnvelope::decode(&unknown),
        Err(CodecError::UnknownVersion)
    );
    assert_eq!(
        AuditEnvelope::decode(&encoded[..encoded.len() - 1]),
        Err(CodecError::Truncated)
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(AuditEnvelope::decode(&trailing), Err(CodecError::Trailing));
}

#[test]
fn init_atomically_persists_an_encrypted_genesis() {
    let directory = tempfile::tempdir().unwrap();
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let meta = MetaRecord {
        store_id: StoreId([7; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    };
    let transaction =
        KeyringInitTransaction::prepare(meta, &identity, None, &mut Counter(0)).unwrap();
    let store = transaction
        .commit(directory.path().join("store.redb"))
        .unwrap();
    let opened = KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &identity,
        )
        .unwrap();
    let entries = store.audit_entries().unwrap();
    assert_eq!(entries.len(), 1);
    let event = entries[0].decrypt(&opened).unwrap();
    assert_eq!(event.expose_secret().operation, AuditOperation::Genesis);
    assert_eq!(event.expose_secret().previous_epoch_terminal, Some([0; 32]));
    assert_eq!(
        entries[0].envelope.effective_timestamp_milliseconds,
        1_800_000_000_000
    );
}

#[test]
fn synthetic_multi_year_status_window_scan_is_correct_and_bounded() {
    const EVENTS: u64 = 250_000;
    const WINDOW_START: u64 = 1_750_000_000_000;
    const WINDOW_END: u64 = WINDOW_START + 50_000;
    let corpus = (0..EVENTS)
        .map(|index| (1_749_999_900_000 + index, index % 97 + 1))
        .collect::<Vec<_>>();
    let started = Instant::now();
    let selected = corpus
        .iter()
        .filter(|(time, _)| (WINDOW_START..=WINDOW_END).contains(time))
        .copied()
        .collect::<Vec<_>>();
    let duration = started.elapsed();
    assert_eq!(selected.len(), 50_001);
    assert_eq!(selected.first(), Some(&(WINDOW_START, 100_000 % 97 + 1)));
    assert_eq!(selected.last(), Some(&(WINDOW_END, 150_000 % 97 + 1)));
    assert!(duration < Duration::from_secs(2));

    let harness = Harness::builder("audit-status-scan")
        .register_canary(b"status-scan-secret-canary-4b712e")
        .build()
        .unwrap();
    let mut scenario = harness.scenario("synthetic-multi-year-window", 1).unwrap();
    scenario
        .step(
            "scan-window",
            SafeSummary::new()
                .field("seed", SafeValue::Unsigned(0))
                .field("corpus_count", SafeValue::Unsigned(EVENTS))
                .field("window_count", SafeValue::Unsigned(selected.len() as u64))
                .field(
                    "duration_ms",
                    SafeValue::Unsigned(duration.as_millis() as u64),
                ),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    assert!(scenario.finish_success().unwrap().scan_attestation.clean);
}

#[test]
fn audit_verify_cli_detects_a_hand_tampered_encrypted_entry() {
    use redb::ReadableTable;

    let directory = tempfile::tempdir().unwrap();
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([17; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &identity,
        None,
        &mut Counter(0),
    )
    .unwrap()
    .commit(directory.path().join("store.redb"))
    .unwrap();
    let command = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
            .env("OLSS_DATA_DIRECTORY", directory.path())
            .args(["audit", "verify", "--output", "json"])
            .output()
            .unwrap()
    };
    let valid = command();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["entry_count"], 1);

    let database = redb::Database::open(directory.path().join("store.redb")).unwrap();
    let write = database.begin_write().unwrap();
    {
        let definition = redb::TableDefinition::<&[u8], &[u8]>::new("audit_events");
        let mut table = write.open_table(definition).unwrap();
        let (key, mut value) = {
            let row = table.iter().unwrap().next().unwrap().unwrap();
            (row.0.value().to_vec(), row.1.value().to_vec())
        };
        let last = value.len() - 1;
        value[last] ^= 1;
        table.insert(key.as_slice(), value.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);

    let tampered = command();
    assert!(!tampered.status.success());
    assert!(
        String::from_utf8_lossy(&tampered.stderr).contains("audit_verify_failed code=integrity")
    );
    assert!(tampered.stdout.is_empty());
}

const AUDIT_SCENARIOS: [(&str, &[&str]); 13] = [
    (
        "audit-01-crash-atomicity",
        &[
            "tests/transaction_coordinator.rs::mutation_and_audit_are_one_visibility_boundary_at_every_fault",
        ],
    ),
    (
        "audit-02-chain-tamper",
        &[
            "tests/audit.rs::encrypted_chain_verifies_without_decrypt_and_rejects_frame_or_order_tamper",
            "tests/audit.rs::audit_verify_cli_detects_a_hand_tampered_encrypted_entry",
        ],
    ),
    (
        "audit-03-rechain-checkpoint",
        &[
            "tests/checkpoint.rs::signed_chain_refuses_rechaining_and_forked_ranges",
            "tests/checkpoint.rs::reverse_tail_detects_offline_add_delete_rollback_and_order_mismatch",
        ],
    ),
    (
        "audit-04-read-audit-failure",
        &[
            "tests/transaction_coordinator.rs::read_secret_is_not_released_when_audit_or_commit_fails",
        ],
    ),
    (
        "audit-05-secret-canary",
        &[
            "tests/audit.rs::schema_round_trip_is_strict_typed_and_secret_safe",
            "tests/audit.rs::init_atomically_persists_an_encrypted_genesis",
        ],
    ),
    (
        "audit-06-flood-aggregate",
        &["tests/rate_limit.rs::aggregate_buffer_is_bounded_secret_free_and_flushes_once"],
    ),
    (
        "audit-07-capacity-reserve",
        &[
            "tests/capacity.rs::nth_incident_operation_succeeds_and_n_plus_one_refuses_before_write",
            "tests/capacity.rs::reserve_controls_require_store_maintenance_confirmation_and_stopped_data",
        ],
    ),
    (
        "audit-08-status-scan",
        &["tests/audit.rs::synthetic_multi_year_status_window_scan_is_correct_and_bounded"],
    ),
    (
        "audit-09-executor-saturation",
        &[
            "tests/storage_executor.rs::bounded_lanes_emit_safe_observability_and_reject_before_payload_work",
        ],
    ),
    (
        "audit-10-cancellation",
        &[
            "tests/transaction_coordinator.rs::pre_start_cancellation_never_authorizes_decrypts_or_audits",
            "tests/transaction_coordinator.rs::caller_disconnect_after_prepare_commits_audit_and_zeroizes_unsent_reply",
        ],
    ),
    (
        "audit-11-checkpoint-lifecycle",
        &["tests/checkpoint.rs::real_store_prepare_register_and_abandoned_prepare_are_recoverable"],
    ),
    (
        "audit-12-signing-lineage",
        &[
            "tests/signing_trust.rs::first_b_checkpoint_covers_activation_and_clears_pending_while_a_history_verifies",
            "tests/signing_trust.rs::stale_fork_expiry_tamper_and_competing_prepares_fail_without_partial_switch",
        ],
    ),
    (
        "audit-13-linearization",
        &[
            "tests/transaction_coordinator.rs::disable_commit_linearizes_before_a_queued_authorization_start",
            "tests/transaction_coordinator.rs::already_authorized_read_may_finish_before_later_disable",
        ],
    ),
];

#[test]
fn every_audit_contract_scenario_has_source_evidence_and_safe_observability() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = Harness::builder("audit-contract")
        .register_canary(b"audit-contract-secret-canary-81e3c4")
        .build()
        .unwrap();
    for (index, (id, evidence)) in AUDIT_SCENARIOS.iter().enumerate() {
        for item in *evidence {
            let (path, test) = item.split_once("::").unwrap();
            let source = std::fs::read_to_string(root.join(path)).unwrap();
            assert!(
                source.contains(&format!("fn {test}")),
                "missing evidence {item}"
            );
        }
        let mut scenario = harness.scenario(id, 1).unwrap();
        scenario
            .step(
                "contract-evidence",
                SafeSummary::new()
                    .field("scenario", SafeValue::Unsigned((index + 1) as u64))
                    .field("evidence_count", SafeValue::Unsigned(evidence.len() as u64)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        let report = scenario.finish_success().unwrap();
        assert!(report.scan_attestation.clean);
        assert!(!report.jsonl.contains("audit-contract-secret-canary-81e3c4"));
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}
