use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use age::x25519;
use age::{Encryptor, Recipient};
use ed25519_dalek::SigningKey;
use ops_light_secrets_server::backup::{
    BackupCreateRequest, create_backup, decrypt_backup, sign_backup, summarize_frames,
};
use ops_light_secrets_server::backup_format::{
    BackupContainer, SourceObservation, SourceObservationStatus, TailStatus,
};
use ops_light_secrets_server::backup_verify::{
    BackupVerifyError, FullVerifyRequest, RegisterRehearsalRequest, RehearsalMode,
    RehearsalReceipt, RehearsalRegistry, verify_backup, verify_backup_full,
    write_rehearsal_receipt_atomic,
};
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::restore::RestoreSignature;
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource,
};
use ops_light_secrets_server::store::{
    Canonical, FORMAT_VERSION, Lifecycle, LogicalPath, MetaRecord, PlaintextSecret,
    SigningKeyCandidate, Store, StoreId,
};

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

struct Fixture {
    _directory: tempfile::TempDir,
    store: Store,
    active: x25519::Identity,
    recovery: x25519::Identity,
    keyring: Keyring,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let transaction = KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([0x31; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &active,
        None,
        &mut Counter(0),
    )
    .unwrap();
    let store = transaction
        .commit(directory.path().join("store.redb"))
        .unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([0x31; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    keyring
        .write_secret(
            &store,
            "secret",
            &LogicalPath::new("rehearsal/canary").unwrap(),
            &PlaintextSecret::new(b"never-render-this-rehearsal-canary".to_vec()),
            1_800_000_000_001,
            &mut Counter(30),
        )
        .unwrap();
    Fixture {
        _directory: directory,
        store,
        active,
        recovery: x25519::Identity::generate(),
        keyring,
    }
}

fn source(store: &Store) -> SourceObservation {
    let head = store.audit_head().unwrap().unwrap();
    SourceObservation {
        status: SourceObservationStatus::BarrierConfirmed,
        claimed_decommissioned: true,
        observed_epoch: Some(u64::from_be_bytes(
            head.audit_epoch[..8].try_into().unwrap(),
        )),
        observed_sequence: Some(head.epoch_sequence),
        observed_head: Some(head.chain_hash().unwrap()),
        observation_unix_milliseconds: Some(1_800_000_000_100),
        provenance_digest: Some([0x32; 32]),
        tail_status: TailStatus::Complete,
        tail_digest: Some([0x33; 32]),
        rpo_known: true,
        acknowledgment_digest: [0x34; 32],
    }
}

fn backup(
    fixture: &Fixture,
) -> (
    ops_light_secrets_server::backup::CreatedBackup,
    ops_light_secrets_server::backup_format::DetachedBackupSignature,
    SigningKeyCandidate,
) {
    let signing = SigningKey::from_bytes(&[0x41; 32]);
    let candidate = SigningKeyCandidate::new(signing.verifying_key().to_bytes()).unwrap();
    let created = create_backup(
        &fixture.store,
        BackupCreateRequest {
            archive_id: [0x42; 16],
            store_incarnation_id: [0x43; 16],
            keyring: &fixture.keyring,
            active_recipient: &fixture.active.to_public(),
            recovery_recipients: &[fixture.recovery.to_public()],
            recovery_set_generation: 7,
            signing_key_id: candidate.id,
            signing_lineage_generation: 1,
            signing_transition_digest: [0x44; 32],
            source: source(&fixture.store),
            authorized: true,
        },
    )
    .unwrap();
    let mut private = [0x41; 32];
    let detached = sign_backup(&created.container, &candidate.verifying_key, &mut private).unwrap();
    (created, detached, candidate)
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn active_and_recovery_paths_are_distinct_signed_receipts_and_cleanup_workspace() {
    let fixture = fixture();
    let (created, detached, candidate) = backup(&fixture);
    let workspace = private_directory();
    let receipt_signing = SigningKey::from_bytes(&[0x51; 32]);
    let receipt_candidate =
        SigningKeyCandidate::new(receipt_signing.verifying_key().to_bytes()).unwrap();

    let mut active_private = [0x51; 32];
    let active = verify_backup_full(
        &created.container,
        RestoreSignature::Signed {
            detached: &detached,
            authenticated_public_key: &candidate.verifying_key,
        },
        FullVerifyRequest {
            identity: &fixture.active,
            work_directory: workspace.path(),
            performed_at_unix_seconds: 1_800_000_100,
            receipt_signing_candidate: &receipt_candidate,
            receipt_private_key: &mut active_private,
        },
        &mut Counter(80),
    )
    .unwrap();
    assert_eq!(active.mode, RehearsalMode::ActiveRecipient);
    assert_eq!(
        active.mode.label(),
        "integrity-verified (active-recipient path)"
    );
    assert_eq!(active.verified_record_count, 1);
    assert_eq!(active_private, [0; 32]);
    assert_eq!(workspace.path().read_dir().unwrap().count(), 0);

    let mut recovery_private = [0x51; 32];
    let recovery = verify_backup_full(
        &created.container,
        RestoreSignature::Signed {
            detached: &detached,
            authenticated_public_key: &candidate.verifying_key,
        },
        FullVerifyRequest {
            identity: &fixture.recovery,
            work_directory: workspace.path(),
            performed_at_unix_seconds: 1_800_000_200,
            receipt_signing_candidate: &receipt_candidate,
            receipt_private_key: &mut recovery_private,
        },
        &mut Counter(90),
    )
    .unwrap();
    assert_eq!(recovery.mode, RehearsalMode::RecoveryRecipient);
    assert_eq!(recovery.mode.label(), "DR-rehearsed (recovery path)");
    assert_eq!(workspace.path().read_dir().unwrap().count(), 0);

    let receipt_path = workspace.path().join("receipt.bin");
    write_rehearsal_receipt_atomic(&receipt_path, &recovery).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&receipt_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        RehearsalReceipt::decode(&std::fs::read(&receipt_path).unwrap()).unwrap(),
        recovery
    );

    let mut registry = RehearsalRegistry::default();
    registry
        .register(RegisterRehearsalRequest {
            receipt: &recovery,
            current_signer: &receipt_candidate,
            expected_archive_digest: created.artifact_digest,
            expected_recovery_set_generation: 7,
            registered_at_effective_seconds: 1_800_000_300,
            service_owner: true,
            control_credential: true,
            backup_capability: true,
            final_barrier_current: true,
        })
        .unwrap();
    assert_eq!(
        registry.age_seconds(
            created.artifact_digest,
            RehearsalMode::RecoveryRecipient,
            1_800_000_360,
        ),
        Some(60)
    );
    assert_eq!(
        registry.age_seconds(
            created.artifact_digest,
            RehearsalMode::ActiveRecipient,
            1_800_000_360,
        ),
        None
    );
}

#[test]
fn wrong_recovery_identity_names_envelope_and_outer_tamper_stops_before_unwrap() {
    let fixture = fixture();
    let (created, detached, candidate) = backup(&fixture);
    let wrong = x25519::Identity::generate();
    assert!(matches!(
        verify_backup(
            &created.container,
            RestoreSignature::Signed {
                detached: &detached,
                authenticated_public_key: &candidate.verifying_key,
            },
            &wrong,
        ),
        Err(BackupVerifyError::RecoveryEnvelope)
    ));
    let mut tampered = created.container.clone();
    tampered.encrypted_payload[0] ^= 1;
    assert!(matches!(
        verify_backup(
            &tampered,
            RestoreSignature::Signed {
                detached: &detached,
                authenticated_public_key: &candidate.verifying_key,
            },
            &wrong,
        ),
        Err(BackupVerifyError::Outer)
    ));
}

#[test]
fn registration_requires_current_signer_exact_generation_and_full_authority() {
    let fixture = fixture();
    let (created, detached, candidate) = backup(&fixture);
    let workspace = private_directory();
    let receipt_signing = SigningKey::from_bytes(&[0x61; 32]);
    let receipt_candidate =
        SigningKeyCandidate::new(receipt_signing.verifying_key().to_bytes()).unwrap();
    let mut private = [0x61; 32];
    let receipt = verify_backup_full(
        &created.container,
        RestoreSignature::Signed {
            detached: &detached,
            authenticated_public_key: &candidate.verifying_key,
        },
        FullVerifyRequest {
            identity: &fixture.recovery,
            work_directory: workspace.path(),
            performed_at_unix_seconds: 1_800_000_400,
            receipt_signing_candidate: &receipt_candidate,
            receipt_private_key: &mut private,
        },
        &mut Counter(100),
    )
    .unwrap();
    let wrong_signer = SigningKey::from_bytes(&[0x62; 32]);
    let wrong_candidate =
        SigningKeyCandidate::new(wrong_signer.verifying_key().to_bytes()).unwrap();
    let mut registry = RehearsalRegistry::default();
    for (signer, generation, owner) in [
        (&wrong_candidate, 7, true),
        (&receipt_candidate, 8, true),
        (&receipt_candidate, 7, false),
    ] {
        assert!(
            registry
                .register(RegisterRehearsalRequest {
                    receipt: &receipt,
                    current_signer: signer,
                    expected_archive_digest: created.artifact_digest,
                    expected_recovery_set_generation: generation,
                    registered_at_effective_seconds: 1_800_000_500,
                    service_owner: owner,
                    control_credential: true,
                    backup_capability: true,
                    final_barrier_current: true,
                })
                .is_err()
        );
    }
}

#[test]
fn recomputed_checksums_still_fail_encrypted_record_authentication() {
    let fixture = fixture();
    let (created, detached, candidate) = backup(&fixture);
    let mut payload = decrypt_backup(&created.container, &fixture.active).unwrap();
    let secrets = payload
        .frames
        .iter_mut()
        .find(|frame| frame.table_id == 4)
        .unwrap();
    let record = &mut secrets.entries[0].value;
    *record.last_mut().unwrap() ^= 1;
    payload.manifest.tables = summarize_frames(&payload.frames).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let forged_store =
        Store::create_from_archive_frames(scratch.path().join("forged.redb"), &payload.frames)
            .unwrap();
    payload.manifest.state_digest = forged_store.state_digest().unwrap().0;
    drop(forged_store);

    let active_recipient = fixture.active.to_public();
    let recovery_recipient = fixture.recovery.to_public();
    let recipients: Vec<&dyn Recipient> = vec![&active_recipient, &recovery_recipient];
    let encryptor = Encryptor::with_recipients(recipients.into_iter()).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(&payload.encode().unwrap()).unwrap();
    writer.finish().unwrap();
    let mut header = created.container.header.clone();
    header.recovery_manifest_digest = payload.manifest.digest().unwrap();
    let forged = BackupContainer::new(header, encrypted).unwrap();
    let mut signing_private = [0x41; 32];
    let forged_signature =
        sign_backup(&forged, &candidate.verifying_key, &mut signing_private).unwrap();
    let receipt_signing = SigningKey::from_bytes(&[0x71; 32]);
    let receipt_candidate =
        SigningKeyCandidate::new(receipt_signing.verifying_key().to_bytes()).unwrap();
    let mut receipt_private = [0x71; 32];
    let workspace = private_directory();
    let error = verify_backup_full(
        &forged,
        RestoreSignature::Signed {
            detached: &forged_signature,
            authenticated_public_key: &candidate.verifying_key,
        },
        FullVerifyRequest {
            identity: &fixture.recovery,
            work_directory: workspace.path(),
            performed_at_unix_seconds: 1_800_000_600,
            receipt_signing_candidate: &receipt_candidate,
            receipt_private_key: &mut receipt_private,
        },
        &mut Counter(110),
    )
    .unwrap_err();
    assert_eq!(error, BackupVerifyError::Reconstruction);
    assert!(error.to_string().contains("encrypted record"));
    assert_eq!(workspace.path().read_dir().unwrap().count(), 0);
    assert!(
        !error
            .to_string()
            .contains("never-render-this-rehearsal-canary")
    );
    assert_ne!(detached, forged_signature);
}
