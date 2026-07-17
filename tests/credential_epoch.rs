use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};

use age::x25519;
use ops_light_secrets_server::credential::{
    CredentialAudience, CredentialIssueMetadata, CredentialKind,
};
use ops_light_secrets_server::credential_epoch::{
    EpochRotationError, EpochRotationMode, EpochRotationRequest, InterruptedJobState,
    online_disclosure_ack, plan_epoch_rotation, prepare_clock_repair_epoch_rotation,
    prepare_restore_epoch_rotation, rotate_credential_epoch, verify_online_disclosure_ack,
};
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource,
};
use ops_light_secrets_server::store::{FORMAT_VERSION, Lifecycle, MetaRecord, Store, StoreId};

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

fn fixture() -> (tempfile::TempDir, Store, Keyring, String) {
    let directory = tempfile::tempdir().unwrap();
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let transaction = KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([7; 16]),
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
    let bootstrap = transaction.bootstrap_credential().unwrap().to_owned();
    let store = transaction
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
    (directory, store, keyring, bootstrap)
}

fn online() -> EpochRotationMode {
    EpochRotationMode::Online {
        owner_peer: true,
        key_rotation: true,
        identity_grant_manage: true,
        credential_issue: true,
    }
}

#[test]
fn disclosure_precedes_atomic_epoch_identity_grant_credential_and_audit_commit() {
    let (_directory, store, keyring, bootstrap) = fixture();
    assert!(
        keyring
            .verify_credential(
                &store,
                &bootstrap,
                CredentialKind::Token,
                CredentialAudience::Control,
                1_800_000_001,
            )
            .unwrap()
            .authenticated_id
            .is_some()
    );
    let existing = keyring.credential_records(&store).unwrap();
    let secret_id = keyring
        .prepare_credential(
            CredentialIssueMetadata {
                id: [0x31; 16],
                identity_id: [0x32; 16],
                kind: CredentialKind::SecretId,
                audience: CredentialAudience::Data,
                issue_epoch: 1,
                expires_at_effective_seconds: 1_800_003_600,
                created_at_effective_seconds: 1_800_000_001,
                issuer_identity_id: [0x33; 16],
                issuance_request_id: [0x34; 16],
                parent_accessor: None,
                consumer_instance_id: Some([0x35; 16]),
            },
            "pre-incident-secret-id".into(),
            &mut |accessor| {
                existing
                    .iter()
                    .any(|record| record.value.accessor == accessor)
            },
            &mut Counter(40),
        )
        .unwrap();
    let secret_id_wire = secret_id.expose_once().to_owned();
    keyring
        .commit_credential(
            &store,
            &keyring.seal_credential(secret_id.record.clone()).unwrap(),
            1,
        )
        .unwrap();
    let reason = "suspected credential disclosure";
    let plan = plan_epoch_rotation(&store, &keyring, 1, reason, online()).unwrap();
    assert_eq!(plan.active_tokens, 1);
    assert_eq!(plan.active_secret_ids, 1);
    assert!(plan.caller_credential_dies);
    let (mut sink, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let receipt = rotate_credential_epoch(
        &store,
        &keyring,
        EpochRotationRequest {
            expected_epoch: 1,
            effective_seconds: 1_800_000_010,
            reason,
            confirmation: plan.confirmation,
            mode: online(),
            interrupted_job: InterruptedJobState::None,
        },
        &mut sink,
        &mut Counter(100),
    )
    .unwrap();
    let mut replacement = String::new();
    let mut byte = [0; 1];
    while reader.read_exact(&mut byte).is_ok() {
        if byte[0] == b'\n' {
            break;
        }
        replacement.push(byte[0] as char);
    }
    assert_eq!(receipt.epoch, 2);
    assert!(!receipt.auth_recovery_stale);
    assert!(!replacement.is_empty());
    assert!(
        keyring
            .verify_credential(
                &store,
                &bootstrap,
                CredentialKind::Token,
                CredentialAudience::Control,
                1_800_000_011,
            )
            .unwrap()
            .authenticated_id
            .is_none()
    );
    let replacement_check = keyring
        .verify_credential(
            &store,
            &replacement,
            CredentialKind::Token,
            CredentialAudience::Control,
            1_800_000_011,
        )
        .unwrap();
    assert!(replacement_check.authenticated_id.is_some());
    assert!(
        keyring
            .verify_credential(
                &store,
                &secret_id_wire,
                CredentialKind::SecretId,
                CredentialAudience::Data,
                1_800_000_011,
            )
            .unwrap()
            .authenticated_id
            .is_none()
    );
    assert!(
        keyring
            .verify_credential(
                &store,
                &replacement,
                CredentialKind::Token,
                CredentialAudience::Data,
                1_800_000_011,
            )
            .unwrap()
            .authenticated_id
            .is_none()
    );
    assert!(
        keyring
            .verify_credential(
                &store,
                &replacement,
                CredentialKind::Token,
                CredentialAudience::Control,
                receipt.expires_at_effective_seconds,
            )
            .unwrap()
            .authenticated_id
            .is_none()
    );
    let identity_id = keyring
        .credential_records(&store)
        .unwrap()
        .into_iter()
        .find(|record| record.value.accessor.0 == receipt.credential_accessor)
        .unwrap()
        .value
        .identity_id;
    assert!(
        keyring
            .identity_records(&store)
            .unwrap()
            .iter()
            .any(|record| {
                record.value.id == identity_id && record.value.name.contains("epoch-2")
            })
    );
    assert_eq!(keyring.grant_records(&store, identity_id).unwrap().len(), 1);
    assert_eq!(store.audit_head().unwrap().unwrap().epoch_sequence, 2);
}

#[test]
fn authority_confirmation_sink_and_stale_epoch_fail_before_mutation() {
    let (directory, store, keyring, _bootstrap) = fixture();
    let reason = "incident response";
    let denied = EpochRotationMode::Online {
        owner_peer: true,
        key_rotation: true,
        identity_grant_manage: false,
        credential_issue: true,
    };
    assert_eq!(
        plan_epoch_rotation(&store, &keyring, 1, reason, denied).unwrap_err(),
        EpochRotationError::Unauthorized
    );
    let plan = plan_epoch_rotation(&store, &keyring, 1, reason, online()).unwrap();
    let mut file = std::fs::File::create(directory.path().join("unsafe-output")).unwrap();
    assert_eq!(
        rotate_credential_epoch(
            &store,
            &keyring,
            EpochRotationRequest {
                expected_epoch: 1,
                effective_seconds: 1_800_000_010,
                reason,
                confirmation: plan.confirmation,
                mode: online(),
                interrupted_job: InterruptedJobState::None,
            },
            &mut file,
            &mut Counter(90),
        )
        .unwrap_err(),
        EpochRotationError::UnsafeSink
    );
    let (mut sink, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(
        rotate_credential_epoch(
            &store,
            &keyring,
            EpochRotationRequest {
                expected_epoch: 1,
                effective_seconds: 1_800_000_010,
                reason,
                confirmation: [0; 32],
                mode: online(),
                interrupted_job: InterruptedJobState::None,
            },
            &mut sink,
            &mut Counter(90),
        )
        .unwrap_err(),
        EpochRotationError::Conflict
    );
    assert_eq!(keyring.credential_epoch(&store).unwrap().value.current, 1);
}

struct BrokenSink(std::os::unix::net::UnixStream);

impl Write for BrokenSink {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("seeded disclosure failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsFd for BrokenSink {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[test]
fn disclosure_failure_leaves_old_epoch_authoritative_and_orphan_unusable() {
    let (_directory, store, keyring, bootstrap) = fixture();
    let reason = "credential custody loss";
    let plan = plan_epoch_rotation(&store, &keyring, 1, reason, online()).unwrap();
    let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut sink = BrokenSink(socket);
    assert_eq!(
        rotate_credential_epoch(
            &store,
            &keyring,
            EpochRotationRequest {
                expected_epoch: 1,
                effective_seconds: 1_800_000_010,
                reason,
                confirmation: plan.confirmation,
                mode: online(),
                interrupted_job: InterruptedJobState::None,
            },
            &mut sink,
            &mut Counter(80),
        )
        .unwrap_err(),
        EpochRotationError::Disclosure
    );
    assert!(
        keyring
            .verify_credential(
                &store,
                &bootstrap,
                CredentialKind::Token,
                CredentialAudience::Control,
                1_800_000_011,
            )
            .unwrap()
            .authenticated_id
            .is_some()
    );
}

#[test]
fn offline_mode_and_interrupted_job_rules_are_distinct_and_fail_closed() {
    let (_directory, store, keyring, _) = fixture();
    let offline = EpochRotationMode::Offline {
        service_owner: true,
        daemon_absent: true,
        exclusive_lock: true,
        current_keyring_unwrapped: true,
    };
    let reason = "recover control during interrupted rewrite";
    let plan = plan_epoch_rotation(&store, &keyring, 1, reason, offline).unwrap();
    let (mut sink, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(
        rotate_credential_epoch(
            &store,
            &keyring,
            EpochRotationRequest {
                expected_epoch: 1,
                effective_seconds: 1_800_000_010,
                reason,
                confirmation: plan.confirmation,
                mode: offline,
                interrupted_job: InterruptedJobState::ForeignOrAmbiguous,
            },
            &mut sink,
            &mut Counter(70),
        )
        .unwrap_err(),
        EpochRotationError::Conflict
    );
}

#[test]
fn clock_restore_and_incident_share_one_prepared_type_and_barrier_cas() {
    let (_directory, store, keyring, _) = fixture();
    let reason = "shared recovery primitive proof";
    let plan = plan_epoch_rotation(&store, &keyring, 1, reason, online()).unwrap();
    let request = || EpochRotationRequest {
        expected_epoch: 1,
        effective_seconds: 1_800_000_010,
        reason,
        confirmation: plan.confirmation,
        mode: online(),
        interrupted_job: InterruptedJobState::None,
    };
    let clock = prepare_clock_repair_epoch_rotation(&store, &keyring, request(), &mut Counter(120))
        .unwrap();
    let restore =
        prepare_restore_epoch_rotation(&store, &keyring, request(), &mut Counter(140)).unwrap();
    let ack = online_disclosure_ack([9; 16], clock.replacement_credential.as_bytes()).unwrap();
    verify_online_disclosure_ack(ack, [9; 16], clock.replacement_credential.as_bytes()).unwrap();
    assert!(
        verify_online_disclosure_ack(ack, [8; 16], clock.replacement_credential.as_bytes(),)
            .is_err()
    );
    keyring
        .commit_credential_epoch_rotation(&store, clock)
        .unwrap();
    assert!(
        keyring
            .commit_credential_epoch_rotation(&store, restore)
            .is_err()
    );
    assert_eq!(keyring.credential_epoch(&store).unwrap().value.current, 2);
}
