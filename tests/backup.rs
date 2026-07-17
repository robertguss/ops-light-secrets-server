use std::os::unix::fs::PermissionsExt;

use age::x25519;
use ed25519_dalek::SigningKey;
use ops_light_secrets_server::backup::{
    BackupCatalog, BackupCreateRequest, BackupError, BackupFilter, BackupRecord,
    ObservedPublication, PublicationState, ReceiptState, RecoveryRecipientCatalog,
    SignatureRegistration, abandon_confirmation, artifact_digest, create_backup, decrypt_backup,
    operational_preflight, prepare_output, publish_reserved, recipient_set_confirmation,
    sign_backup, write_detached_signature_atomic,
};
use ops_light_secrets_server::backup_format::{
    SourceObservation, SourceObservationStatus, TailStatus,
};
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource,
};
use ops_light_secrets_server::store::{
    Canonical, FORMAT_VERSION, Lifecycle, LogicalPath, MetaRecord, SecretKey, SecretRecord, Store,
    StoreId,
};

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

#[derive(Default)]
struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

#[test]
fn backup_during_concurrent_writes_contains_only_complete_records() {
    let (_directory, store, active, keyring) = fixture();
    let store = std::sync::Arc::new(store);
    let writer = store.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_barrier = barrier.clone();
    let thread = std::thread::spawn(move || {
        writer_barrier.wait();
        for version in 1..=64 {
            writer
                .put_secret(
                    &SecretKey {
                        path: LogicalPath::new(format!("concurrent/{version:03}")).unwrap(),
                        version,
                    },
                    &SecretRecord {
                        version,
                        created_unix_milliseconds: 1_800_000_000_000 + version,
                        key_id: [version as u8; 16],
                        nonce: [version as u8; 24],
                        ciphertext: vec![version as u8; 48],
                    },
                )
                .unwrap();
        }
    });
    barrier.wait();
    let recovery = x25519::Identity::generate();
    let created = create_backup(
        &store,
        BackupCreateRequest {
            archive_id: [0x61; 16],
            store_incarnation_id: [0x62; 16],
            keyring: &keyring,
            active_recipient: &active.to_public(),
            recovery_recipients: &[recovery.to_public()],
            recovery_set_generation: 1,
            signing_key_id: [0x63; 16],
            signing_lineage_generation: 1,
            signing_transition_digest: [0x64; 32],
            source: source(&store),
            authorized: true,
        },
    )
    .unwrap();
    thread.join().unwrap();
    let payload = decrypt_backup(&created.container, &recovery).unwrap();
    let secrets = payload
        .frames
        .iter()
        .find(|frame| frame.table_id == 4)
        .unwrap();
    assert!(secrets.entries.len() <= 64);
    for entry in &secrets.entries {
        SecretKey::decode(&entry.key).unwrap();
        SecretRecord::decode(&entry.value).unwrap();
    }
}

fn fixture() -> (tempfile::TempDir, Store, x25519::Identity, Keyring) {
    let directory = tempfile::tempdir().unwrap();
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let store = KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([7; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &active,
        None,
        &mut Counter::default(),
    )
    .unwrap()
    .commit(directory.path().join("store.redb"))
    .unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    (directory, store, active, keyring)
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
        observation_unix_milliseconds: Some(1_800_000_000_001),
        provenance_digest: Some([0x91; 32]),
        tail_status: TailStatus::Complete,
        tail_digest: Some([0x92; 32]),
        rpo_known: true,
        acknowledgment_digest: [0x93; 32],
    }
}

fn request<'a>(
    keyring: &'a Keyring,
    active: &'a x25519::Recipient,
    recipients: &'a [x25519::Recipient],
    source: SourceObservation,
    authorized: bool,
) -> BackupCreateRequest<'a> {
    BackupCreateRequest {
        archive_id: [0x21; 16],
        store_incarnation_id: [0x22; 16],
        keyring,
        active_recipient: active,
        recovery_recipients: recipients,
        recovery_set_generation: 1,
        signing_key_id: [0x23; 16],
        signing_lineage_generation: 1,
        signing_transition_digest: [0x24; 32],
        source,
        authorized,
    }
}

#[test]
fn one_snapshot_builds_recovery_openable_ciphertext_and_complete_manifest() {
    let (_directory, store, active, keyring) = fixture();
    let recovery = x25519::Identity::generate();
    let created = create_backup(
        &store,
        BackupCreateRequest {
            archive_id: [0x11; 16],
            store_incarnation_id: [0x12; 16],
            keyring: &keyring,
            active_recipient: &active.to_public(),
            recovery_recipients: &[recovery.to_public()],
            recovery_set_generation: 3,
            signing_key_id: [0x13; 16],
            signing_lineage_generation: 2,
            signing_transition_digest: [0x14; 32],
            source: source(&store),
            authorized: true,
        },
    )
    .unwrap();
    assert_eq!(created.manifest.tables.len(), 19);
    assert_eq!(
        created.manifest.state_digest,
        store.state_digest().unwrap().0
    );
    assert_eq!(
        created.artifact_digest,
        artifact_digest(&created.container).unwrap()
    );
    assert!(
        !created
            .container
            .encode()
            .unwrap()
            .windows(32)
            .any(|bytes| bytes == [7; 32])
    );

    let recovered = decrypt_backup(&created.container, &recovery).unwrap();
    let recovered_keyring =
        Keyring::open_backup_envelope(StoreId([7; 16]), &recovered.recovery_keyring, &recovery)
            .unwrap();
    assert_eq!(recovered_keyring.record_key_id(), keyring.record_key_id());
    assert!(decrypt_backup(&created.container, &x25519::Identity::generate()).is_err());

    let mut edited = created.container.clone();
    edited.encrypted_payload[0] ^= 1;
    assert!(decrypt_backup(&edited, &recovery).is_err());
    let mut recipient_confusion = created.container.clone();
    recipient_confusion.header.effective_recipient_digest[0] ^= 1;
    assert!(decrypt_backup(&recipient_confusion, &recovery).is_err());
}

#[test]
fn recipient_authority_and_snapshot_consistency_fail_closed() {
    let (_directory, store, active, keyring) = fixture();
    let recovery = x25519::Identity::generate();
    let active_recipient = active.to_public();
    assert_eq!(
        create_backup(
            &store,
            request(
                &keyring,
                &active_recipient,
                &[recovery.to_public()],
                source(&store),
                false,
            ),
        )
        .unwrap_err(),
        BackupError::Unauthorized
    );
    assert!(
        create_backup(
            &store,
            request(&keyring, &active_recipient, &[], source(&store), true),
        )
        .is_err()
    );
    assert!(
        create_backup(
            &store,
            request(
                &keyring,
                &active_recipient,
                &[active.to_public()],
                source(&store),
                true,
            ),
        )
        .is_err()
    );
    let eight = (0..8)
        .map(|_| x25519::Identity::generate().to_public())
        .collect::<Vec<_>>();
    assert!(
        create_backup(
            &store,
            request(&keyring, &active_recipient, &eight, source(&store), true),
        )
        .is_err()
    );

    let snapshot = store.logical_backup_snapshot().unwrap();
    let meta_frame = snapshot
        .tables
        .iter()
        .find(|frame| frame.table == "meta")
        .unwrap();
    assert!(
        meta_frame
            .entries
            .iter()
            .any(|(key, value)| key == b"\x01store" && value == &snapshot.meta.encode().unwrap())
    );
}

fn record(digest: [u8; 32]) -> BackupRecord {
    BackupRecord {
        artifact_digest: digest,
        inner_manifest_digest: [2; 32],
        output_id: [3; 16],
        owner_id: [4; 16],
        target_identity_digest: [5; 32],
        content_digest: [6; 32],
        snapshot_sequence: 7,
        snapshot_state_digest: [8; 32],
        signing_key_id: [9; 16],
        signing_lineage_generation: 2,
        keyring_generation: 3,
        recovery_set_generation: 4,
        effective_recipient_digest: [10; 32],
        publication: PublicationState::Publishing,
        signature_registered: false,
        active_receipt: ReceiptState::UnknownOffline,
        recovery_receipt: ReceiptState::UnknownOffline,
    }
}

#[test]
fn publication_catalog_is_idempotent_discoverable_and_two_phase() {
    let digest = [1; 32];
    let mut catalog = BackupCatalog::default();
    catalog.reserve(record(digest), true).unwrap();
    catalog.reserve(record(digest), true).unwrap();
    assert_eq!(
        catalog
            .list(None, 10, BackupFilter::default())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        catalog.resume(digest, ObservedPublication::Missing, true),
        Err(BackupError::AbandonRequired)
    );
    assert_eq!(
        catalog
            .resume(digest, ObservedPublication::ExactFinal, true)
            .unwrap(),
        PublicationState::Published
    );
    assert_eq!(
        catalog
            .resume(digest, ObservedPublication::ExactTemp, true)
            .unwrap(),
        PublicationState::Published
    );
    assert!(operational_preflight(catalog.show(digest).unwrap()).is_err());
    assert_eq!(
        catalog
            .list(
                None,
                10,
                BackupFilter {
                    publication: Some(PublicationState::Published),
                    ..BackupFilter::default()
                },
            )
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn detached_signing_zeroizes_and_registration_is_current_key_bound() {
    let (_directory, store, active, keyring) = fixture();
    let recovery = x25519::Identity::generate();
    let private = SigningKey::from_bytes(&[0x44; 32]);
    let public = private.verifying_key().to_bytes();
    let created = create_backup(
        &store,
        BackupCreateRequest {
            archive_id: [0x31; 16],
            store_incarnation_id: [0x32; 16],
            keyring: &keyring,
            active_recipient: &active.to_public(),
            recovery_recipients: &[recovery.to_public()],
            recovery_set_generation: 1,
            signing_key_id: [9; 16],
            signing_lineage_generation: 2,
            signing_transition_digest: [0x33; 32],
            source: source(&store),
            authorized: true,
        },
    )
    .unwrap();
    let mut secret = [0x44; 32];
    let signature = sign_backup(&created.container, &public, &mut secret).unwrap();
    assert_eq!(secret, [0; 32]);
    let mut wrong_secret = [0x45; 32];
    assert!(sign_backup(&created.container, &public, &mut wrong_secret).is_err());
    assert_eq!(wrong_secret, [0; 32]);
    let mut catalog = BackupCatalog::default();
    let mut descriptor = record(created.artifact_digest);
    descriptor.signing_key_id = [9; 16];
    descriptor.signing_lineage_generation = 2;
    catalog.reserve(descriptor, true).unwrap();
    catalog
        .resume(
            created.artifact_digest,
            ObservedPublication::ExactFinal,
            true,
        )
        .unwrap();
    assert!(
        catalog
            .register_signature(SignatureRegistration {
                digest: created.artifact_digest,
                container: &created.container,
                signature: &signature,
                public_key: &public,
                current_key_id: [8; 16],
                current_generation: 2,
                authorized: true,
            },)
            .is_err()
    );
    catalog
        .register_signature(SignatureRegistration {
            digest: created.artifact_digest,
            container: &created.container,
            signature: &signature,
            public_key: &public,
            current_key_id: [9; 16],
            current_generation: 2,
            authorized: true,
        })
        .unwrap();
    catalog
        .register_receipt(created.artifact_digest, true, true, true)
        .unwrap();
    operational_preflight(catalog.show(created.artifact_digest).unwrap()).unwrap();
    assert!(
        catalog
            .abandon(
                created.artifact_digest,
                "superseded",
                abandon_confirmation(created.artifact_digest, "superseded"),
                true,
            )
            .is_err()
    );
}

#[test]
fn recovery_recipient_set_is_cas_exact_confirmed_and_active_distinct() {
    let active = x25519::Identity::generate().to_public();
    let first = x25519::Identity::generate().to_public();
    let second = x25519::Identity::generate().to_public();
    let mut catalog = RecoveryRecipientCatalog::new(1, vec![first.clone()]).unwrap();
    let reason = "scheduled off-host custody rotation";
    let confirmation =
        recipient_set_confirmation(1, &active, std::slice::from_ref(&second), reason);
    assert_eq!(
        catalog
            .replace(1, &active, vec![second.clone()], reason, confirmation, true)
            .unwrap(),
        2
    );
    assert_eq!(catalog.fingerprints().len(), 1);
    assert!(
        catalog
            .replace(1, &active, vec![first], reason, confirmation, true)
            .is_err()
    );
    let active_confirmation =
        recipient_set_confirmation(2, &active, std::slice::from_ref(&active), reason);
    assert!(
        catalog
            .replace(
                2,
                &active,
                vec![active.clone()],
                reason,
                active_confirmation,
                true,
            )
            .is_err()
    );
}

#[test]
fn output_and_signature_publication_refuse_collisions_and_use_private_modes() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("backup.olss");
    let prepared = prepare_output(&output, b"immutable ciphertext", [1; 16]).unwrap();
    assert!(!output.exists());
    assert_ne!(prepared.target_identity_digest(), [0; 32]);
    let mut catalog = BackupCatalog::default();
    let digest = [0x71; 32];
    let mut descriptor = record(digest);
    descriptor.content_digest = prepared.bytes_digest();
    descriptor.target_identity_digest = prepared.target_identity_digest();
    catalog.reserve(descriptor, true).unwrap();
    assert_eq!(
        publish_reserved(&mut catalog, digest, prepared).unwrap(),
        PublicationState::Published
    );
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(prepare_output(&output, b"replacement", [2; 16]).is_err());

    let signature_path = directory.path().join("backup.sig");
    let signature = ops_light_secrets_server::backup_format::DetachedBackupSignature {
        key_id: [1; 16],
        content_digest: [2; 32],
        signature: [3; 64],
    };
    write_detached_signature_atomic(&signature_path, &signature).unwrap();
    assert_eq!(
        std::fs::metadata(&signature_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(write_detached_signature_atomic(&signature_path, &signature).is_err());
}
