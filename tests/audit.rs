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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}
