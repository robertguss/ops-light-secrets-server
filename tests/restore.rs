use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use age::x25519;
use ed25519_dalek::SigningKey;
use ops_light_secrets_server::backup::{BackupCreateRequest, create_backup, sign_backup};
use ops_light_secrets_server::backup_format::{
    SourceObservation, SourceObservationStatus, TailStatus, unsigned_confirmation,
};
use ops_light_secrets_server::credential::{CredentialAudience, CredentialKind};
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::restore::{
    RestoreError, RestoreRequest, RestoreSignature, restore, restore_assertion_confirmation,
};
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource,
};
use ops_light_secrets_server::store::{
    FORMAT_VERSION, Lifecycle, LogicalPath, MetaRecord, SecretKey, SecretRecord, Store, StoreId,
};
use secrecy::ExposeSecret;

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
    _source_dir: tempfile::TempDir,
    source: Store,
    active: x25519::Identity,
    recovery: x25519::Identity,
    keyring: Keyring,
    old_credential: String,
}

fn fixture() -> Fixture {
    let source_dir = tempfile::tempdir().unwrap();
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
    let old_credential = transaction.bootstrap_credential().unwrap().to_owned();
    let source = transaction
        .commit(source_dir.path().join("store.redb"))
        .unwrap();
    source
        .put_secret(
            &SecretKey {
                path: LogicalPath::new("restored/value").unwrap(),
                version: 1,
            },
            &SecretRecord {
                version: 1,
                created_unix_milliseconds: 1_800_000_000_001,
                key_id: [0x41; 16],
                nonce: [0x42; 24],
                ciphertext: vec![0x43; 48],
            },
        )
        .unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &source.keyring().unwrap().unwrap(),
            &source.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    Fixture {
        _source_dir: source_dir,
        source,
        active,
        recovery: x25519::Identity::generate(),
        keyring,
        old_credential,
    }
}

fn source_observation(store: &Store) -> SourceObservation {
    let head = store.audit_head().unwrap().unwrap();
    SourceObservation {
        status: SourceObservationStatus::BarrierConfirmed,
        claimed_decommissioned: true,
        observed_epoch: Some(u64::from_be_bytes(
            head.audit_epoch[..8].try_into().unwrap(),
        )),
        observed_sequence: Some(head.epoch_sequence),
        observed_head: Some(head.chain_hash().unwrap()),
        observation_unix_milliseconds: Some(1_800_000_000_123),
        provenance_digest: Some([0x51; 32]),
        tail_status: TailStatus::Complete,
        tail_digest: Some([0x52; 32]),
        rpo_known: true,
        acknowledgment_digest: [0x53; 32],
    }
}

fn signed_backup(
    fixture: &Fixture,
) -> (
    ops_light_secrets_server::backup::CreatedBackup,
    ops_light_secrets_server::backup_format::DetachedBackupSignature,
    [u8; 32],
) {
    let signing = SigningKey::from_bytes(&[0x61; 32]);
    let public = signing.verifying_key().to_bytes();
    let key_id = ops_light_secrets_server::store::signing_key_id(&public);
    let created = create_backup(
        &fixture.source,
        BackupCreateRequest {
            archive_id: [0x62; 16],
            store_incarnation_id: [0x63; 16],
            keyring: &fixture.keyring,
            active_recipient: &fixture.active.to_public(),
            recovery_recipients: &[fixture.recovery.to_public()],
            recovery_set_generation: 1,
            signing_key_id: key_id,
            signing_lineage_generation: 1,
            signing_transition_digest: [0x64; 32],
            source: source_observation(&fixture.source),
            authorized: true,
        },
    )
    .unwrap();
    let mut private = [0x61; 32];
    let signature = sign_backup(&created.container, &public, &mut private).unwrap();
    (created, signature, public)
}

#[test]
fn signed_fresh_host_restore_rewraps_bumps_epoch_and_installs_only_after_disclosure() {
    let fixture = fixture();
    let (created, signature, public) = signed_backup(&fixture);
    let target_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(target_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = target_dir.path().join("restored.redb");
    let new_active = x25519::Identity::generate();
    let reason = "source decommissioned after final backup";
    let assertion = restore_assertion_confirmation(
        created.artifact_digest,
        &target,
        &new_active.to_public(),
        &fixture.recovery.to_public(),
        [0x70; 16],
        reason,
    )
    .unwrap();
    let (mut sink, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let receipt = restore(
        &created.container,
        RestoreRequest {
            target: &target,
            recovery_identity: &fixture.recovery,
            new_active_identity: &new_active,
            installed_recovery_recipient: None,
            signature: RestoreSignature::Signed {
                detached: &signature,
                authenticated_public_key: &public,
            },
            source_decommissioned: true,
            actor_id: [0x70; 16],
            reason,
            assertion_confirmation: assertion,
            temp_nonce: [0x71; 16],
        },
        &mut sink,
        &mut Counter(100),
    )
    .unwrap();
    assert!(target.exists());
    let mut replacement = String::new();
    let mut byte = [0; 1];
    while reader.read_exact(&mut byte).is_ok() {
        if byte[0] == b'\n' {
            break;
        }
        replacement.push(byte[0] as char);
    }
    let restored = Store::open(&target).unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &restored.keyring().unwrap().unwrap(),
            &restored.keyring_metadata().unwrap().unwrap(),
            &new_active,
        )
        .unwrap();
    KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &restored.keyring().unwrap().unwrap(),
            &restored.keyring_metadata().unwrap().unwrap(),
            &fixture.recovery,
        )
        .unwrap();
    assert!(
        KeyringOpener::default()
            .open(
                StoreId([7; 16]),
                &restored.keyring().unwrap().unwrap(),
                &restored.keyring_metadata().unwrap().unwrap(),
                &fixture.active,
            )
            .is_err()
    );
    assert_eq!(receipt.credential_epoch, 2);
    assert!(
        keyring
            .verify_credential(
                &restored,
                &fixture.old_credential,
                CredentialKind::Token,
                CredentialAudience::Control,
                1_800_000_001,
            )
            .unwrap()
            .authenticated_id
            .is_none()
    );
    assert!(
        keyring
            .verify_credential(
                &restored,
                &replacement,
                CredentialKind::Token,
                CredentialAudience::Control,
                1_800_000_001,
            )
            .unwrap()
            .authenticated_id
            .is_some()
    );
    assert!(
        restored
            .secret(&SecretKey {
                path: LogicalPath::new("restored/value").unwrap(),
                version: 1,
            })
            .unwrap()
            .is_some()
    );
    let entries = restored.audit_entries().unwrap();
    assert_eq!(entries.len(), 2);
    let activation = entries[1].decrypt(&keyring).unwrap();
    assert_eq!(
        activation.expose_secret().operation,
        ops_light_secrets_server::store::AuditOperation::Restore
    );
    assert!(matches!(
        activation.expose_secret().state,
        ops_light_secrets_server::store::AuditStateCommitment::WholeState(_)
    ));
    let meta = restored.meta().unwrap();
    assert_eq!(meta.lifecycle, Lifecycle::Ready);
    assert_eq!(
        meta.pending_anchor.unwrap().value.kind,
        ops_light_secrets_server::store::PendingAnchorKind::NormalRestore
    );
}

#[test]
fn invalid_signature_preexisting_target_and_broken_sink_leave_target_inert() {
    let fixture = fixture();
    let (created, signature, public) = signed_backup(&fixture);
    let mut invalid_signature = signature.clone();
    let target_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(target_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = target_dir.path().join("restored.redb");
    let new_active = x25519::Identity::generate();
    let reason = "source decommissioned";
    let assertion = restore_assertion_confirmation(
        created.artifact_digest,
        &target,
        &new_active.to_public(),
        &fixture.recovery.to_public(),
        [0x74; 16],
        reason,
    )
    .unwrap();
    invalid_signature.signature[0] ^= 1;
    let (mut sink, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(
        restore(
            &created.container,
            RestoreRequest {
                target: &target,
                recovery_identity: &fixture.recovery,
                new_active_identity: &new_active,
                installed_recovery_recipient: None,
                signature: RestoreSignature::Signed {
                    detached: &invalid_signature,
                    authenticated_public_key: &public,
                },
                source_decommissioned: true,
                actor_id: [0x74; 16],
                reason,
                assertion_confirmation: assertion,
                temp_nonce: [0x75; 16],
            },
            &mut sink,
            &mut Counter(100),
        )
        .unwrap_err(),
        RestoreError::Signature
    );
    assert!(!target.exists());
    std::fs::write(&target, b"untouched").unwrap();
    assert_eq!(
        restore(
            &created.container,
            RestoreRequest {
                target: &target,
                recovery_identity: &fixture.recovery,
                new_active_identity: &new_active,
                installed_recovery_recipient: None,
                signature: RestoreSignature::Signed {
                    detached: &signature,
                    authenticated_public_key: &public,
                },
                source_decommissioned: true,
                actor_id: [0x74; 16],
                reason,
                assertion_confirmation: assertion,
                temp_nonce: [0x76; 16],
            },
            &mut sink,
            &mut Counter(100),
        )
        .unwrap_err(),
        RestoreError::TargetExists
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
}

struct BrokenSink(std::os::unix::net::UnixStream);

impl Write for BrokenSink {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("seeded restore sink failure"))
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
fn unsigned_requires_full_ceremony_and_sink_failure_cleans_temp() {
    let fixture = fixture();
    let (created, _, _) = signed_backup(&fixture);
    let target_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(target_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = target_dir.path().join("restored.redb");
    let new_active = x25519::Identity::generate();
    let reason = "authorized unsigned recovery after signer loss";
    let assertion = restore_assertion_confirmation(
        created.artifact_digest,
        &target,
        &new_active.to_public(),
        &fixture.recovery.to_public(),
        [0x77; 16],
        reason,
    )
    .unwrap();
    let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut sink = BrokenSink(socket);
    assert_eq!(
        restore(
            &created.container,
            RestoreRequest {
                target: &target,
                recovery_identity: &fixture.recovery,
                new_active_identity: &new_active,
                installed_recovery_recipient: None,
                signature: RestoreSignature::Unsigned {
                    allow_unsigned: false,
                    reason,
                    confirmation: "wrong",
                },
                source_decommissioned: true,
                actor_id: [0x77; 16],
                reason,
                assertion_confirmation: assertion,
                temp_nonce: [0x78; 16],
            },
            &mut sink,
            &mut Counter(100),
        )
        .unwrap_err(),
        RestoreError::Signature
    );
    let unsigned = unsigned_confirmation(created.artifact_digest, reason);
    assert_eq!(
        restore(
            &created.container,
            RestoreRequest {
                target: &target,
                recovery_identity: &fixture.recovery,
                new_active_identity: &new_active,
                installed_recovery_recipient: None,
                signature: RestoreSignature::Unsigned {
                    allow_unsigned: true,
                    reason,
                    confirmation: &unsigned,
                },
                source_decommissioned: true,
                actor_id: [0x77; 16],
                reason,
                assertion_confirmation: assertion,
                temp_nonce: [0x79; 16],
            },
            &mut sink,
            &mut Counter(100),
        )
        .unwrap_err(),
        RestoreError::Credential
    );
    assert!(!target.exists());
    assert_eq!(target_dir.path().read_dir().unwrap().count(), 0);
}

#[test]
fn restore_cli_exposes_only_typed_identity_sources_and_preopened_sink() {
    let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args(["restore", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for required in [
        "--archive",
        "--recovery-identity-source",
        "--new-active-identity-source",
        "--credential-output-fd",
        "--source-decommissioned",
        "--allow-unsigned-manifest",
        "--unsigned-confirm",
    ] {
        assert!(help.contains(required), "missing {required}: {help}");
    }
    assert!(!help.contains("--recovery-identity "));
    assert!(!help.contains("--new-active-identity "));
}
