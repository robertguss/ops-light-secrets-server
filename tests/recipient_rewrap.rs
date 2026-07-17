use age::x25519;
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::store::keyring::{
    Keyring, KeyringError, KeyringOpener, RandomSource, RecipientRewrapFault,
    RecipientRewrapRequest, recipient_rewrap_confirmation,
};
use ops_light_secrets_server::store::{
    AuditAuthMethod, AuditAuthentication, AuditAuthorization, AuditCapability, AuditEvent,
    AuditOperation, AuditOutcome, AuditReason, AuditResource, AuditStateCommitment, FORMAT_VERSION,
    Lifecycle, LogicalPath, MetaRecord, SecretKey, SecretRecord, Store, StoreError, StoreId,
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

fn create_store(path: &std::path::Path, recovery: Option<&x25519::Recipient>) -> Store {
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([7; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &active,
        recovery,
        &mut Counter::default(),
    )
    .unwrap()
    .commit(path)
    .unwrap()
}

fn open(store: &Store, identity: &x25519::Identity) -> Keyring {
    KeyringOpener::default()
        .open(
            store.meta().unwrap().store_id,
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            identity,
        )
        .unwrap()
}

fn prepare(
    store: &Store,
    opened: Keyring,
    new_active: &x25519::Identity,
) -> (
    ops_light_secrets_server::store::keyring::PreparedRecipientRewrap,
    AuditEvent,
) {
    let old = opened.recipients();
    let new =
        ops_light_secrets_server::store::keyring::RecipientSet::new(&new_active.to_public(), None)
            .unwrap();
    let reason = "routine active recipient rotation";
    let confirmation =
        recipient_rewrap_confirmation(StoreId([7; 16]), 1, old, new, reason).unwrap();
    let current_metadata = store.keyring_metadata().unwrap().unwrap();
    let prepared = opened
        .prepare_recipient_rewrap(
            new_active,
            RecipientRewrapRequest {
                expected_generation: 1,
                new_recovery: None,
                audit_sequence: 2,
                reason,
                confirmation: &confirmation,
                authorized: true,
            },
        )
        .unwrap();
    let event = AuditEvent {
        event_id: [0x81; 16],
        request_id: [0x82; 16],
        authentication: AuditAuthentication {
            method: AuditAuthMethod::Token,
            identity_id: Some([0x83; 16]),
            credential_accessor: Some([0x84; 16]),
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: Some(AuditCapability::StoreKeyRotate),
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: None,
        resource: Some(AuditResource::Canonical("keyring/recipients".into())),
        operation: AuditOperation::KeyringChange,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::OperatorRequested,
        effective_timestamp_milliseconds: 1_800_000_000_001,
        wall_clock_observation_milliseconds: 1_800_000_000_001,
        secret_version: None,
        state: AuditStateCommitment::Delta(prepared.state_delta(&current_metadata).unwrap()),
        previous_epoch_terminal: None,
        flood: None,
        overload_counts: Vec::new(),
    };
    (prepared, event)
}

#[test]
fn rewrap_changes_only_envelope_metadata_and_matching_audit() {
    let directory = tempfile::tempdir().unwrap();
    let store = create_store(&directory.path().join("store.redb"), None);
    let key = SecretKey {
        path: LogicalPath::new("fixture/unchanged").unwrap(),
        version: 1,
    };
    let record = SecretRecord {
        version: 1,
        created_unix_milliseconds: 1_800_000_000_000,
        key_id: [0x91; 16],
        nonce: [0x92; 24],
        ciphertext: vec![0x93; 64],
    };
    store.put_secret(&key, &record).unwrap();
    let old_identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let old_envelope = store.keyring().unwrap().unwrap();
    let old_head = store.audit_head().unwrap().unwrap();
    let new_identity = x25519::Identity::generate();
    let (prepared, event) = prepare(&store, open(&store, &old_identity), &new_identity);
    let replacement = store
        .commit_recipient_rewrap(
            prepared,
            &event,
            &mut Counter(100),
            RecipientRewrapFault::None,
        )
        .unwrap();

    assert_eq!(replacement.generation(), 2);
    assert_eq!(store.secret(&key).unwrap(), Some(record));
    assert_ne!(store.keyring().unwrap().unwrap(), old_envelope);
    assert_eq!(store.audit_head().unwrap().unwrap().epoch_sequence, 2);
    assert_ne!(store.audit_head().unwrap().unwrap(), old_head);
    let entries = store.audit_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[1]
            .decrypt(&replacement)
            .unwrap()
            .expose_secret()
            .operation,
        AuditOperation::KeyringChange
    );
    KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &new_identity,
        )
        .unwrap();
    assert_eq!(
        KeyringOpener::default()
            .open(
                StoreId([7; 16]),
                &store.keyring().unwrap().unwrap(),
                &store.keyring_metadata().unwrap().unwrap(),
                &old_identity,
            )
            .err()
            .unwrap(),
        KeyringError::Decrypt
    );
}

#[test]
fn every_uncommitted_fault_point_leaves_old_envelope_and_head() {
    for fault in [
        RecipientRewrapFault::AfterEnvelopeStage,
        RecipientRewrapFault::AfterMetadataStage,
        RecipientRewrapFault::AfterAuditStage,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = create_store(&directory.path().join("store.redb"), None);
        let old_identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
        let old_envelope = store.keyring().unwrap().unwrap();
        let old_metadata = store.keyring_metadata().unwrap().unwrap();
        let old_head = store.audit_head().unwrap().unwrap();
        let new_identity = x25519::Identity::generate();
        let (prepared, event) = prepare(&store, open(&store, &old_identity), &new_identity);
        assert_eq!(
            store
                .commit_recipient_rewrap(prepared, &event, &mut Counter(100), fault)
                .err()
                .unwrap(),
            StoreError::Database
        );
        assert_eq!(store.keyring().unwrap().unwrap(), old_envelope);
        assert_eq!(store.keyring_metadata().unwrap().unwrap(), old_metadata);
        assert_eq!(store.audit_head().unwrap().unwrap(), old_head);
        open(&store, &old_identity);
    }
}

#[test]
fn recovery_identity_can_rewrap_and_generation_confirmation_is_exact() {
    let directory = tempfile::tempdir().unwrap();
    let recovery = x25519::Identity::generate();
    let store = create_store(
        &directory.path().join("store.redb"),
        Some(&recovery.to_public()),
    );
    let opened = open(&store, &recovery);
    let new_identity = x25519::Identity::generate();
    let old = opened.recipients();
    let new = ops_light_secrets_server::store::keyring::RecipientSet::new(
        &new_identity.to_public(),
        None,
    )
    .unwrap();
    let reason = "recovery-only recipient repair";
    let confirmation =
        recipient_rewrap_confirmation(StoreId([7; 16]), 1, old, new, reason).unwrap();
    assert_eq!(
        open(&store, &recovery)
            .prepare_recipient_rewrap(
                &new_identity,
                RecipientRewrapRequest {
                    expected_generation: 2,
                    new_recovery: None,
                    audit_sequence: 2,
                    reason,
                    confirmation: &confirmation,
                    authorized: true,
                },
            )
            .err()
            .unwrap(),
        KeyringError::GenerationMismatch
    );
    assert_eq!(
        open(&store, &recovery)
            .prepare_recipient_rewrap(
                &new_identity,
                RecipientRewrapRequest {
                    expected_generation: 1,
                    new_recovery: None,
                    audit_sequence: 2,
                    reason,
                    confirmation: "wrong",
                    authorized: true,
                },
            )
            .err()
            .unwrap(),
        KeyringError::Invalid
    );
    let current_metadata = store.keyring_metadata().unwrap().unwrap();
    let prepared = opened
        .prepare_recipient_rewrap(
            &new_identity,
            RecipientRewrapRequest {
                expected_generation: 1,
                new_recovery: None,
                audit_sequence: 2,
                reason,
                confirmation: &confirmation,
                authorized: true,
            },
        )
        .unwrap();
    let mut event = prepare_event(&prepared, &current_metadata);
    event.event_id = [0xa1; 16];
    let replacement = store
        .commit_recipient_rewrap(
            prepared,
            &event,
            &mut Counter(110),
            RecipientRewrapFault::None,
        )
        .unwrap();
    assert_eq!(replacement.recipients(), new);
}

#[test]
fn cli_requires_typed_secret_sources_and_never_accepts_private_identity_values() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args(["key", "recipient", "rewrap", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--expected-generation",
        "--current-identity-source",
        "--new-active-identity-source",
        "--control-credential-source",
        "--reason",
        "--confirm",
    ] {
        assert!(help.contains(flag), "missing {flag}");
    }
    assert!(!help.contains("--current-identity "));
    assert!(!help.contains("--new-active-identity "));
}

#[test]
fn real_offline_cli_plans_then_commits_with_bootstrap_key_rotation_authority() {
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
        &mut Counter::default(),
    )
    .unwrap();
    let control = transaction.bootstrap_credential().unwrap().to_owned();
    transaction
        .commit(directory.path().join("store.redb"))
        .unwrap();
    let credentials = tempfile::tempdir().unwrap();
    let new_identity = x25519::Identity::generate();
    std::fs::write(credentials.path().join("current"), ACTIVE_IDENTITY).unwrap();
    std::fs::write(
        credentials.path().join("new"),
        new_identity.to_string().expose_secret(),
    )
    .unwrap();
    std::fs::write(credentials.path().join("control"), control).unwrap();

    let command = |confirmation: Option<&str>| {
        let mut command =
            std::process::Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"));
        command
            .env("OLSS_DATA_DIRECTORY", directory.path())
            .env("CREDENTIALS_DIRECTORY", credentials.path())
            .args([
                "key",
                "recipient",
                "rewrap",
                "--expected-generation",
                "1",
                "--current-identity-source",
                "credential:current",
                "--new-active-identity-source",
                "credential:new",
                "--control-credential-source",
                "credential:control",
                "--reason",
                "routine fixture rotation",
                "--output",
                "json",
            ]);
        if let Some(value) = confirmation {
            command.args(["--confirm", value]);
        }
        command.output().unwrap()
    };
    let plan = command(None);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan["mutation"], false);
    let confirmation = plan["confirmation"].as_str().unwrap();
    let committed = command(Some(confirmation));
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let committed: serde_json::Value = serde_json::from_slice(&committed.stdout).unwrap();
    assert_eq!(committed["generation"], 2);
    assert_eq!(committed["already_installed"], false);

    std::fs::write(
        credentials.path().join("current"),
        new_identity.to_string().expose_secret(),
    )
    .unwrap();
    let retry = command(Some(confirmation));
    assert!(retry.status.success());
    let retry: serde_json::Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retry["generation"], 2);
    assert_eq!(retry["already_installed"], true);

    let store = Store::open(directory.path().join("store.redb")).unwrap();
    open(&store, &new_identity);
    assert_eq!(store.audit_entries().unwrap().len(), 2);
}

fn prepare_event(
    prepared: &ops_light_secrets_server::store::keyring::PreparedRecipientRewrap,
    current_metadata: &ops_light_secrets_server::store::Sealed<
        ops_light_secrets_server::store::keyring::KeyringMetadata,
    >,
) -> AuditEvent {
    AuditEvent {
        event_id: [0xb1; 16],
        request_id: [0xb2; 16],
        authentication: AuditAuthentication {
            method: AuditAuthMethod::Token,
            identity_id: Some([0xb3; 16]),
            credential_accessor: Some([0xb4; 16]),
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: Some(AuditCapability::StoreKeyRotate),
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: None,
        resource: Some(AuditResource::Canonical("keyring/recipients".into())),
        operation: AuditOperation::KeyringChange,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::OperatorRequested,
        effective_timestamp_milliseconds: 1_800_000_000_001,
        wall_clock_observation_milliseconds: 1_800_000_000_001,
        secret_version: None,
        state: AuditStateCommitment::Delta(prepared.state_delta(current_metadata).unwrap()),
        previous_epoch_terminal: None,
        flood: None,
        overload_counts: Vec::new(),
    }
}

use secrecy::ExposeSecret;
