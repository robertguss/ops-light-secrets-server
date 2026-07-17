use age::x25519;
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::reencrypt::{
    BuildRequest, CurrentRecoveryEvidence, PlanRequest, abort_record_rotation,
    build_record_rotation, enter_record_rotation, install_built_store,
    mark_record_rotation_anchored, mark_record_rotation_recovery_current, plan_record_rotation,
};
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource,
};
use ops_light_secrets_server::store::{
    AuditOperation, AuditStateCommitment, BulkTransitionKind, Canonical, EncryptedRecord,
    FORMAT_VERSION, Lifecycle, LogicalPath, MetaRecord, PendingAnchorKind, PlaintextSecret, Store,
    StoreId,
};
use secrecy::ExposeSecret;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
const CANARY: &[u8] = b"never-render-record-rotation-canary";

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = self.0.wrapping_add(index as u8);
        }
        Ok(())
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    store: Store,
    active: x25519::Identity,
    recovery: x25519::Identity,
    keyring: Keyring,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let recovery = x25519::Identity::generate();
    let transaction = KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([0x81; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &active,
        Some(&recovery.to_public()),
        &mut Counter(0),
    )
    .unwrap();
    let store = transaction
        .commit(directory.path().join("store.redb"))
        .unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([0x81; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    let path = LogicalPath::new("rotation/canary").unwrap();
    for (value, timestamp) in [
        (b"first".as_slice(), 1_800_000_001),
        (CANARY, 1_800_000_002),
    ] {
        keyring
            .write_secret(
                &store,
                "secret",
                &path,
                &PlaintextSecret::new(value.to_vec()),
                timestamp,
                &mut Counter(timestamp as u8),
            )
            .unwrap();
    }
    Fixture {
        directory,
        store,
        active,
        recovery,
        keyring,
    }
}

fn evidence() -> CurrentRecoveryEvidence {
    CurrentRecoveryEvidence {
        archive_digest: [0x91; 32],
        signature_digest: [0x92; 32],
        recovery_receipt_digest: [0x93; 32],
        recovery_set_generation: 4,
        signature_registered: true,
        recovery_receipt_registered: true,
        tail_verified: true,
        clean_shutdown: true,
    }
}

fn plan(fixture: &Fixture) -> ops_light_secrets_server::reencrypt::RecordRotationPlan {
    plan_record_rotation(
        &fixture.store,
        &fixture.keyring,
        PlanRequest {
            expected_generation: fixture.keyring.generation(),
            reason: "scheduled record-key rotation",
            operation_id: [0xa1; 16],
            owner_id: [0xa2; 16],
            authorized_key_rotation: true,
            authorized_store_maintenance_override: false,
            control_credential_remaining_seconds: 7_200,
            required_job_abort_margin_seconds: 3_600,
            allow_without_current_dr_backup: false,
            evidence: evidence(),
        },
    )
    .unwrap()
}

#[test]
fn full_pass_reencrypts_every_version_with_fresh_nonce_and_installs_ready() {
    let fixture = fixture();
    let plan = plan(&fixture);
    let old_key = fixture.keyring.record_key_id();
    enter_record_rotation(
        &fixture.store,
        &fixture.keyring,
        &plan,
        &plan.confirmation,
        true,
        &mut Counter(150),
    )
    .unwrap();
    assert_eq!(
        fixture.store.meta().unwrap().lifecycle,
        Lifecycle::Reencrypting
    );
    let replacement = fixture.directory.path().join("store.redb.new");
    let active_recipient = fixture.active.to_public();
    let recovery_recipient = fixture.recovery.to_public();
    let (rotated, mut receipt) = build_record_rotation(
        &fixture.store,
        fixture.keyring,
        BuildRequest {
            plan: &plan,
            confirmation: &plan.confirmation,
            final_barrier_authorized: true,
            active_recipient: &active_recipient,
            recovery_recipient: Some(&recovery_recipient),
            source_path: &fixture.directory.path().join("store.redb"),
            target: &replacement,
        },
        &mut Counter(180),
    )
    .unwrap();
    assert_eq!(receipt.rewritten_records, 2);
    assert_ne!(receipt.old_key_id, receipt.new_key_id);
    assert_eq!(
        receipt.job.status,
        ops_light_secrets_server::store::RewriteStatus::InstalledPendingAnchor
    );
    assert_ne!(rotated.record_key_id(), old_key);
    let target = Store::open(&replacement).unwrap();
    assert_eq!(target.meta().unwrap().lifecycle, Lifecycle::Ready);
    assert_eq!(
        target.meta().unwrap().pending_anchor.unwrap().value.kind,
        PendingAnchorKind::RecordKey
    );
    let reopened = KeyringOpener::default()
        .open(
            StoreId([0x81; 16]),
            &target.keyring().unwrap().unwrap(),
            &target.keyring_metadata().unwrap().unwrap(),
            &fixture.recovery,
        )
        .unwrap();
    assert_eq!(reopened.record_key_id(), rotated.record_key_id());
    assert_eq!(
        target
            .rewrite_job(&plan.operation_id, &reopened)
            .unwrap()
            .unwrap(),
        receipt.job
    );
    let audit = target.audit_entries().unwrap();
    let completion = audit.last().unwrap();
    let event = completion.decrypt(&reopened).unwrap();
    assert_eq!(
        event.expose_secret().operation,
        AuditOperation::RecordKeyRotation
    );
    assert!(matches!(
        event.expose_secret().state,
        AuditStateCommitment::WholeState(ref transition)
            if transition.kind == BulkTransitionKind::RecordRewrite
                && transition.before == receipt.before_state_digest
                && transition.after == receipt.rewritten_state_digest
    ));
    assert_eq!(
        reopened
            .read_secret(
                &target,
                "secret",
                &LogicalPath::new("rotation/canary").unwrap(),
                None,
            )
            .unwrap()
            .unwrap()
            .expose_secret(),
        CANARY
    );
    let snapshot = target.logical_backup_snapshot().unwrap();
    let records = snapshot
        .tables
        .iter()
        .find(|table| table.table == "secrets")
        .unwrap()
        .entries
        .iter()
        .map(|(_, value)| EncryptedRecord::decode(value).unwrap())
        .collect::<Vec<_>>();
    assert!(
        records
            .iter()
            .all(|record| record.header().key_id() == reopened.record_key_id())
    );
    assert_ne!(records[0].header().nonce(), records[1].header().nonce());
    assert!(
        !std::fs::read(&replacement)
            .unwrap()
            .windows(CANARY.len())
            .any(|window| window == CANARY)
    );
    let installed_digest = receipt.job.installed_state_digest;
    let installed_job = receipt.job.clone();
    mark_record_rotation_anchored(
        &mut receipt.job,
        &[0xa2; 16],
        [0xc1; 32],
        true,
        installed_digest,
    )
    .unwrap();
    target
        .replace_rewrite_job(&installed_job, &receipt.job, &reopened)
        .unwrap();
    assert_eq!(
        receipt.job.status,
        ops_light_secrets_server::store::RewriteStatus::AnchoredRewriteCompleteRecoveryPending
    );
    let anchored_job = receipt.job.clone();
    mark_record_rotation_recovery_current(
        &mut receipt.job,
        &[0xa2; 16],
        [0xc2; 32],
        [0xc3; 32],
        [0xc4; 32],
        2,
        2,
        2,
        true,
        true,
        true,
    )
    .unwrap();
    target
        .replace_rewrite_job(&anchored_job, &receipt.job, &reopened)
        .unwrap();
    assert_eq!(
        receipt.job.status,
        ops_light_secrets_server::store::RewriteStatus::CompleteRecoveryCurrent
    );
    assert_eq!(
        target
            .rewrite_job(&plan.operation_id, &reopened)
            .unwrap()
            .unwrap(),
        receipt.job
    );
    drop(target);
    drop(fixture.store);
    install_built_store(&fixture.directory.path().join("store.redb"), &replacement).unwrap();
    let installed = Store::open(fixture.directory.path().join("store.redb")).unwrap();
    assert_eq!(installed.meta().unwrap().lifecycle, Lifecycle::Ready);
}

#[test]
fn interrupted_pass_abort_removes_partial_and_restores_original() {
    let fixture = fixture();
    let plan = plan(&fixture);
    enter_record_rotation(
        &fixture.store,
        &fixture.keyring,
        &plan,
        &plan.confirmation,
        true,
        &mut Counter(150),
    )
    .unwrap();
    let after_enter = fixture.store.audit_entries().unwrap();
    assert_eq!(after_enter.len(), 2);
    assert_eq!(
        after_enter
            .last()
            .unwrap()
            .decrypt(&fixture.keyring)
            .unwrap()
            .expose_secret()
            .operation,
        AuditOperation::KeyringChange
    );
    let partial = fixture.directory.path().join("store.redb.new");
    std::fs::write(&partial, b"partial").unwrap();
    abort_record_rotation(
        &fixture.store,
        &fixture.keyring,
        &plan,
        &partial,
        &mut Counter(160),
    )
    .unwrap();
    let after_abort = fixture.store.audit_entries().unwrap();
    assert_eq!(after_abort.len(), 3);
    assert_eq!(
        after_abort
            .last()
            .unwrap()
            .decrypt(&fixture.keyring)
            .unwrap()
            .expose_secret()
            .operation,
        AuditOperation::KeyringChange
    );
    assert!(!partial.exists());
    assert_eq!(fixture.store.meta().unwrap().lifecycle, Lifecycle::Ready);
    assert_eq!(
        fixture
            .keyring
            .read_secret(
                &fixture.store,
                "secret",
                &LogicalPath::new("rotation/canary").unwrap(),
                None,
            )
            .unwrap()
            .unwrap()
            .expose_secret(),
        CANARY
    );
}

#[test]
fn plan_is_read_only_and_requires_registered_recovery_evidence_or_dual_authority() {
    let fixture = fixture();
    let before = fixture.store.state_digest().unwrap();
    let mut missing = evidence();
    missing.recovery_receipt_registered = false;
    let denied = plan_record_rotation(
        &fixture.store,
        &fixture.keyring,
        PlanRequest {
            expected_generation: fixture.keyring.generation(),
            reason: "incident",
            operation_id: [0xb1; 16],
            owner_id: [0xb2; 16],
            authorized_key_rotation: true,
            authorized_store_maintenance_override: false,
            control_credential_remaining_seconds: 7_200,
            required_job_abort_margin_seconds: 3_600,
            allow_without_current_dr_backup: false,
            evidence: missing.clone(),
        },
    );
    assert!(denied.is_err());
    assert_eq!(fixture.store.state_digest().unwrap(), before);
    let override_plan = plan_record_rotation(
        &fixture.store,
        &fixture.keyring,
        PlanRequest {
            expected_generation: fixture.keyring.generation(),
            reason: "incident",
            operation_id: [0xb1; 16],
            owner_id: [0xb2; 16],
            authorized_key_rotation: true,
            authorized_store_maintenance_override: true,
            control_credential_remaining_seconds: 7_200,
            required_job_abort_margin_seconds: 3_600,
            allow_without_current_dr_backup: true,
            evidence: missing,
        },
    )
    .unwrap();
    assert_eq!(fixture.store.state_digest().unwrap(), before);
    assert_eq!(
        override_plan.expected_generation,
        fixture.keyring.generation()
    );
}
