use ed25519_dalek::SigningKey;
use ops_light_secrets_server::store::keyring::{
    KeyringError, KeyringOpener, RandomSource, prepare_keyring_for_init,
};
use ops_light_secrets_server::store::{
    AuditAuthMethod, AuditAuthentication, AuditAuthorization, AuditCapability, AuditEvent,
    AuditOperation, AuditOutcome, AuditReason, AuditStateCommitment, Canonical,
    CheckpointDescriptor, CheckpointKeyStatus, CheckpointPublicKey, CheckpointSignature,
    CheckpointTrust, CodecError, EncryptedTable, FORMAT_VERSION, Lifecycle, MetaRecord, StateDelta,
    StateDeltaSet, StateDigest, StateTuple, Store, StoreId, StoredAuditEntry, checkpoint_digest,
    reconcile_state, sign_checkpoint, sign_checkpoint_authorized, signing_key_id, stale_checkpoint,
    verify_audit_checkpoint, verify_checkpoint, verify_checkpoint_chain, write_checkpoint_atomic,
};
use std::collections::BTreeSet;

fn descriptor(key_id: [u8; 16]) -> CheckpointDescriptor {
    CheckpointDescriptor {
        store_id: StoreId([1; 16]),
        audit_epoch: [2; 16],
        range_start: 1,
        range_end: 7,
        prepare_event_id: [3; 16],
        chain_head: [4; 32],
        state_digest: StateDigest([5; 32]),
        effective_timestamp_milliseconds: 1_800_000_000_000,
        signing_key_id: key_id,
        previous_checkpoint_digest: None,
    }
}

fn signed(status: CheckpointKeyStatus) -> (CheckpointSignature, CheckpointTrust) {
    let mut private = [7; 32];
    let public = SigningKey::from_bytes(&private).verifying_key().to_bytes();
    let id = signing_key_id(&public);
    let checkpoint = sign_checkpoint(descriptor(id), &mut private).unwrap();
    assert_eq!(private, [0; 32]);
    let trust = CheckpointTrust::new([CheckpointPublicKey {
        id,
        verifying_key: public,
        status,
        valid_from_milliseconds: 1_700_000_000_000,
        valid_until_milliseconds: Some(1_900_000_000_000),
        previous_key_id: None,
    }])
    .unwrap();
    (checkpoint, trust)
}

#[test]
fn descriptor_vector_freezes_prepare_is_last_encoding() {
    let (checkpoint, _) = signed(CheckpointKeyStatus::Initial);
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/checkpoint-descriptor-v1.json")).unwrap();
    assert_eq!(fixture["descriptor_version"], 1);
    assert_eq!(fixture["range_end"], 7);
    assert_eq!(fixture["prepare_event_sequence"], fixture["range_end"]);
    assert_eq!(
        fixture["canonical_hex"],
        hex(&checkpoint.descriptor.encode().unwrap())
    );
    assert_eq!(
        CheckpointDescriptor::decode(&checkpoint.descriptor.encode().unwrap()).unwrap(),
        checkpoint.descriptor
    );
    let mut unknown = checkpoint.descriptor.encode().unwrap();
    unknown[1..3].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        CheckpointDescriptor::decode(&unknown),
        Err(CodecError::UnknownVersion)
    );
}

#[test]
fn sign_verify_accepts_initial_current_retired_and_rejects_tamper_expiry_unknown() {
    for status in [
        CheckpointKeyStatus::Initial,
        CheckpointKeyStatus::Current,
        CheckpointKeyStatus::Retired,
    ] {
        let (checkpoint, trust) = signed(status);
        assert_eq!(
            verify_checkpoint(&checkpoint, &trust).unwrap(),
            checkpoint_digest(&checkpoint).unwrap()
        );
        let mut tampered = checkpoint.clone();
        tampered.signature[0] ^= 1;
        assert!(verify_checkpoint(&tampered, &trust).is_err());
    }
    let (checkpoint, _) = signed(CheckpointKeyStatus::Current);
    let trust = CheckpointTrust::new([]).unwrap();
    assert!(verify_checkpoint(&checkpoint, &trust).is_err());
}

#[test]
fn offline_authorization_checks_public_descriptor_expiry_and_lineage_forks() {
    let private = [7; 32];
    let public_bytes = SigningKey::from_bytes(&private).verifying_key().to_bytes();
    let id = signing_key_id(&public_bytes);
    let public = CheckpointPublicKey {
        id,
        verifying_key: public_bytes,
        status: CheckpointKeyStatus::Current,
        valid_from_milliseconds: 1_700_000_000_000,
        valid_until_milliseconds: Some(1_799_999_999_999),
        previous_key_id: None,
    };
    let mut candidate = private;
    assert!(sign_checkpoint_authorized(descriptor(id), &public, &mut candidate).is_err());
    assert_eq!(candidate, [0; 32]);

    let child_private = [8; 32];
    let child_public = SigningKey::from_bytes(&child_private)
        .verifying_key()
        .to_bytes();
    let child_id = signing_key_id(&child_public);
    let child = CheckpointPublicKey {
        id: child_id,
        verifying_key: child_public,
        status: CheckpointKeyStatus::Current,
        valid_from_milliseconds: 1_800_000_000_001,
        valid_until_milliseconds: None,
        previous_key_id: Some(id),
    };
    let sibling_private = [9; 32];
    let sibling_public = SigningKey::from_bytes(&sibling_private)
        .verifying_key()
        .to_bytes();
    let sibling = CheckpointPublicKey {
        id: signing_key_id(&sibling_public),
        verifying_key: sibling_public,
        status: CheckpointKeyStatus::Retired,
        valid_from_milliseconds: 1_800_000_000_001,
        valid_until_milliseconds: None,
        previous_key_id: Some(id),
    };
    assert!(CheckpointTrust::new([public, child, sibling]).is_err());
}

#[test]
fn signed_chain_refuses_rechaining_and_forked_ranges() {
    let (first, trust) = signed(CheckpointKeyStatus::Current);
    let mut second_descriptor = first.descriptor.clone();
    second_descriptor.range_start = 8;
    second_descriptor.range_end = 9;
    second_descriptor.prepare_event_id = [8; 16];
    second_descriptor.chain_head = [9; 32];
    second_descriptor.previous_checkpoint_digest = Some(checkpoint_digest(&first).unwrap());
    let mut private = [7; 32];
    let second = sign_checkpoint(second_descriptor, &mut private).unwrap();
    assert_eq!(
        verify_checkpoint_chain([&first, &second], &trust).unwrap(),
        checkpoint_digest(&second).unwrap()
    );
    let mut fork = second.clone();
    fork.descriptor.previous_checkpoint_digest = Some([99; 32]);
    assert!(verify_checkpoint_chain([&first, &fork], &trust).is_err());
}

#[test]
fn reverse_tail_detects_offline_add_delete_rollback_and_order_mismatch() {
    let old = StateTuple::encrypted(EncryptedTable::Secrets, b"path/v1", b"old").unwrap();
    let middle = StateTuple::encrypted(EncryptedTable::Secrets, b"path/v1", b"middle").unwrap();
    let new = StateTuple::encrypted(EncryptedTable::Secrets, b"path/v1", b"new").unwrap();
    let extra = StateTuple::encrypted(EncryptedTable::Secrets, b"path/v2", b"extra").unwrap();
    let anchored = StateDigest::compute([old.clone()]).unwrap();
    let first =
        StateDeltaSet::new([StateDelta::replace(old.clone(), middle.clone()).unwrap()]).unwrap();
    let second = StateDeltaSet::new([
        StateDelta::replace(middle, new.clone()).unwrap(),
        StateDelta::insert(extra.clone()),
    ])
    .unwrap();
    let current = BTreeSet::from([new.clone(), extra.clone()]);
    assert!(reconcile_state(&current, &[first.clone(), second.clone()], anchored).is_ok());
    assert!(reconcile_state(&current, &[second.clone(), first.clone()], anchored).is_err());
    assert!(reconcile_state(&BTreeSet::from([new]), &[first.clone(), second], anchored).is_err());
    assert!(reconcile_state(&BTreeSet::from([old, extra]), &[first], anchored).is_err());
}

#[test]
fn state_digest_tuple_vector_is_cross_release_frozen() {
    let clear = StateTuple::Clear {
        class: ops_light_secrets_server::store::RecordClass::Identity,
        primary_key: b"identity-1".to_vec(),
        generation: 9,
        tag: [0xaa; 32],
    };
    let encrypted = StateTuple::encrypted(
        EncryptedTable::Secrets,
        b"path/v3",
        b"header-nonce-ciphertext",
    )
    .unwrap();
    let digest = StateDigest::compute([encrypted, clear]).unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/state-digest-v1.json")).unwrap();
    assert_eq!(fixture["state_digest_hex"], hex(&digest.0));
}

#[test]
fn staleness_flips_only_after_exact_thresholds() {
    assert!(!stale_checkpoint(11_000, 1_000, 110, 100, 10, 10).stale);
    assert!(stale_checkpoint(11_001, 1_000, 110, 100, 10, 10).stale);
    assert!(stale_checkpoint(11_000, 1_000, 111, 100, 10, 10).stale);
}

#[test]
fn atomic_output_is_private_no_follow_and_never_overwrites() {
    let (checkpoint, _) = signed(CheckpointKeyStatus::Current);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint.sig");
    write_checkpoint_atomic(&path, &checkpoint).unwrap();
    let decoded = CheckpointSignature::decode(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(decoded, checkpoint);
    assert!(write_checkpoint_atomic(&path, &checkpoint).is_err());
    let link = directory.path().join("link.sig");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(write_checkpoint_atomic(&link, &checkpoint).is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn checkpoint_event(id: u8, effective: u64) -> AuditEvent {
    AuditEvent {
        event_id: [id; 16],
        request_id: [id.wrapping_add(1); 16],
        authentication: AuditAuthentication {
            method: AuditAuthMethod::Token,
            identity_id: Some([41; 16]),
            credential_accessor: Some([42; 16]),
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: Some(AuditCapability::AuditCheckpointManage),
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: None,
        resource: None,
        operation: AuditOperation::Checkpoint,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::None,
        effective_timestamp_milliseconds: effective,
        wall_clock_observation_milliseconds: effective,
        secret_version: None,
        state: AuditStateCommitment::None,
        previous_epoch_terminal: None,
        flood: None,
        overload_counts: Vec::new(),
    }
}

#[test]
fn real_store_prepare_register_and_abandoned_prepare_are_recoverable() {
    const IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    let identity: age::x25519::Identity = IDENTITY.parse().unwrap();
    let meta = MetaRecord {
        store_id: StoreId([21; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    };
    let mut random = Counter(0);
    let prepared = prepare_keyring_for_init(
        ops_light_secrets_server::store::ProvisionalMetaRecord::from_meta(&meta),
        1,
        &identity,
        None,
        &mut random,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store =
        Store::create_with_keyring(directory.path().join("store.redb"), &meta, &prepared).unwrap();
    let keyring = KeyringOpener::default()
        .open(
            meta.store_id,
            &prepared.envelope,
            &prepared.metadata,
            &identity,
        )
        .unwrap();
    let mut private = [17; 32];
    let public = SigningKey::from_bytes(&private).verifying_key().to_bytes();
    let key_id = signing_key_id(&public);
    let trust = CheckpointTrust::new([CheckpointPublicKey {
        id: key_id,
        verifying_key: public,
        status: CheckpointKeyStatus::Current,
        valid_from_milliseconds: 1_700_000_000_000,
        valid_until_milliseconds: None,
        previous_key_id: None,
    }])
    .unwrap();

    let mut make_prepare = |event_id: u8, prior: Option<[u8; 32]>, range_start: u64| {
        let head = store.audit_head().unwrap().unwrap();
        let event = checkpoint_event(event_id, head.effective_timestamp_milliseconds + 1);
        let entry = StoredAuditEntry::prepare(
            &keyring,
            &event,
            head.audit_epoch,
            head.epoch_sequence + 1,
            head.chain_hash().unwrap(),
            &mut random,
        )
        .unwrap();
        let descriptor = CheckpointDescriptor {
            store_id: meta.store_id,
            audit_epoch: head.audit_epoch,
            range_start,
            range_end: entry.envelope.epoch_sequence,
            prepare_event_id: event.event_id,
            chain_head: entry.envelope.chain_hash().unwrap(),
            state_digest: store.state_digest().unwrap(),
            effective_timestamp_milliseconds: event.effective_timestamp_milliseconds,
            signing_key_id: key_id,
            previous_checkpoint_digest: prior,
        };
        store
            .commit_checkpoint_prepare(&entry, &descriptor)
            .unwrap();
        descriptor
    };

    let first_descriptor = make_prepare(51, None, 1);
    let first = sign_checkpoint(first_descriptor, &mut private).unwrap();
    let first_digest = store.register_checkpoint(&first, &trust).unwrap();
    assert_eq!(
        verify_audit_checkpoint(&store.audit_entries().unwrap(), &first, &trust).unwrap(),
        [
            ops_light_secrets_server::store::VerificationTier::FullyAnchored {
                through_sequence: 2,
            },
            ops_light_secrets_server::store::VerificationTier::UnanchoredTail {
                first_sequence: 3,
                count: 0,
            },
        ]
    );
    assert!(store.register_checkpoint(&first, &trust).is_err());

    let abandoned = make_prepare(52, Some(first_digest), 3);
    assert_eq!(store.prepared_checkpoints().unwrap().len(), 2);
    let health = store
        .checkpoint_health(1_800_000_100_000, 86_400, 10_000)
        .unwrap();
    assert_eq!(health.checkpoint_abandoned_prepares, 1);
    let health_json = serde_json::to_value(health).unwrap();
    assert_eq!(health_json["checkpoint_registered"], true);
    assert_eq!(health_json["checkpoint_stale"], false);
    assert_eq!(health_json["checkpoint_unanchored_events"], 1);
    let third_descriptor = make_prepare(53, Some(first_digest), 3);
    assert_eq!(
        third_descriptor.previous_checkpoint_digest,
        Some(first_digest)
    );
    assert!(third_descriptor.range_end > abandoned.range_end);
    private = [17; 32];
    let third = sign_checkpoint(third_descriptor, &mut private).unwrap();
    store.register_checkpoint(&third, &trust).unwrap();
    assert_eq!(store.registered_checkpoints().unwrap().len(), 2);

    let head = store.audit_head().unwrap().unwrap();
    let event = checkpoint_event(54, head.effective_timestamp_milliseconds + 1);
    let entry = StoredAuditEntry::prepare(
        &keyring,
        &event,
        head.audit_epoch,
        head.epoch_sequence + 1,
        head.chain_hash().unwrap(),
        &mut random,
    )
    .unwrap();
    let mut mismatch = CheckpointDescriptor {
        store_id: meta.store_id,
        audit_epoch: head.audit_epoch,
        range_start: 5,
        range_end: entry.envelope.epoch_sequence,
        prepare_event_id: event.event_id,
        chain_head: entry.envelope.chain_hash().unwrap(),
        state_digest: store.state_digest().unwrap(),
        effective_timestamp_milliseconds: event.effective_timestamp_milliseconds,
        signing_key_id: key_id,
        previous_checkpoint_digest: Some(checkpoint_digest(&third).unwrap()),
    };
    mismatch.state_digest.0[0] ^= 1;
    assert!(store.commit_checkpoint_prepare(&entry, &mismatch).is_err());
    assert_eq!(store.audit_head().unwrap().unwrap(), head);
}
