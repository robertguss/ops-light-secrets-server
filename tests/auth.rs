use ops_light_secrets_server::credential::{
    ACCESSOR_COLLISION_ATTEMPTS, CredentialAudience, CredentialIssueMetadata, CredentialKind,
    CredentialRecord, CredentialRejectReason, CredentialVerificationContext, CredentialWire,
    DIRECT_TOKEN_MAX_TTL_SECONDS, DIRECT_TOKEN_MIN_TTL_SECONDS, SECRET_ID_MAX_USES, credential_mac,
    issue_credential, validate_secret_id_uses, validate_ttl, verify_credential,
};
use ops_light_secrets_server::identity::TokenStatus;
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::store::keyring::{KeyringError, KeyringOpener, RandomSource};
use ops_light_secrets_server::store::{
    Canonical, FORMAT_VERSION, Lifecycle, MetaRecord, StoreId, mac_conformance,
};

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn metadata(kind: CredentialKind, audience: CredentialAudience) -> CredentialIssueMetadata {
    CredentialIssueMetadata {
        id: [1; 16],
        identity_id: [2; 16],
        kind,
        audience,
        issue_epoch: 7,
        expires_at_effective_seconds: 200,
        created_at_effective_seconds: 100,
        issuer_identity_id: [3; 16],
        issuance_request_id: [4; 16],
        parent_accessor: None,
        consumer_instance_id: Some([5; 16]),
    }
}

fn issued(kind: CredentialKind, audience: CredentialAudience) -> (String, CredentialRecord) {
    let value = issue_credential(
        &[9; 32],
        StoreId([8; 16]),
        metadata(kind, audience),
        "deploy".into(),
        &mut |_| false,
        &mut Counter(0),
    )
    .unwrap();
    (value.expose_once().into(), value.record.clone())
}

fn verification_context<'a>(
    kind: CredentialKind,
    audience: CredentialAudience,
    epoch: u64,
    effective: u64,
    store_id: StoreId,
    key: &'a [u8; 32],
) -> CredentialVerificationContext<'a> {
    CredentialVerificationContext {
        expected_kind: kind,
        expected_audience: audience,
        current_epoch: epoch,
        effective_seconds: effective,
        store_id,
        verifier_key: key,
    }
}

#[test]
fn canonical_wire_round_trip_rejects_aliases_padding_truncation_and_oversize() {
    let (wire, record) = issued(CredentialKind::Token, CredentialAudience::Data);
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/credential-wire-v1.json")).unwrap();
    assert_eq!(fixture["wire"], wire);
    assert_eq!(fixture["verifier_hex"], hex(&record.verifier));
    assert_eq!(CredentialWire::parse(&wire).unwrap().encode(), wire);
    for invalid in [
        format!("{wire}="),
        wire[..wire.len() - 1].to_owned(),
        wire.replace("token", "TOKEN"),
        format!("{wire}.extra"),
        "token.data.short.short".into(),
        format!("token.data.{}.{}", "A".repeat(22), "A".repeat(44)),
    ] {
        assert!(
            CredentialWire::parse(&invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn verifier_domain_separates_store_kind_audience_epoch_and_runs_fixed_work() {
    let key = [9; 32];
    let store = StoreId([8; 16]);
    let (wire, record) = issued(CredentialKind::Token, CredentialAudience::Data);
    let lookup = |accessor| (accessor == record.accessor).then(|| record.clone());
    let accepted = verify_credential(
        &wire,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            150,
            store,
            &key,
        ),
        &lookup,
    );
    assert_eq!(accepted.authenticated_id, Some(record.id));
    let baseline = accepted.work;

    let secret_id = wire.replacen("token", "secret-id", 1);
    let control = wire.replacen("data", "control", 1);
    for (raw, kind, audience, epoch, expected) in [
        (
            wire.as_str(),
            CredentialKind::SecretId,
            CredentialAudience::Data,
            7,
            CredentialRejectReason::WrongKind,
        ),
        (
            wire.as_str(),
            CredentialKind::Token,
            CredentialAudience::Control,
            7,
            CredentialRejectReason::WrongAudience,
        ),
        (
            secret_id.as_str(),
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            CredentialRejectReason::WrongKind,
        ),
        (
            control.as_str(),
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            CredentialRejectReason::WrongAudience,
        ),
        (
            wire.as_str(),
            CredentialKind::Token,
            CredentialAudience::Data,
            8,
            CredentialRejectReason::EpochChanged,
        ),
        (
            "malformed",
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            CredentialRejectReason::Malformed,
        ),
    ] {
        let result = verify_credential(
            raw,
            verification_context(kind, audience, epoch, 150, store, &key),
            &lookup,
        );
        assert_eq!(result.reason, Some(expected));
        assert_eq!(result.work, baseline);
    }

    assert_ne!(
        record.verifier,
        credential_mac(
            &[10; 32],
            store,
            record.kind,
            record.audience,
            record.accessor,
            record.issue_epoch,
            &[2; 32],
        )
    );
    assert!(
        verify_credential(
            &wire,
            verification_context(
                CredentialKind::Token,
                CredentialAudience::Data,
                7,
                150,
                StoreId([99; 16]),
                &key,
            ),
            &lookup,
        )
        .authenticated_id
        .is_none()
    );
}

#[test]
fn unknown_bad_revoked_expired_and_stale_all_compute_mac_and_read_epoch() {
    let (wire, record) = issued(CredentialKind::Token, CredentialAudience::Data);
    let expected_work = verify_credential(
        &wire,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            150,
            StoreId([8; 16]),
            &[9; 32],
        ),
        &|accessor| (accessor == record.accessor).then(|| record.clone()),
    )
    .work;
    let unknown = verify_credential(
        &wire,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            150,
            StoreId([8; 16]),
            &[9; 32],
        ),
        &|_| None,
    );
    assert_eq!(
        unknown.reason,
        Some(CredentialRejectReason::UnknownAccessor)
    );
    assert_eq!(unknown.work, expected_work);

    let mut bad = wire.into_bytes();
    *bad.last_mut().unwrap() = if *bad.last().unwrap() == b'A' {
        b'B'
    } else {
        b'A'
    };
    let bad = String::from_utf8(bad).unwrap();
    let invalid = verify_credential(
        &bad,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            150,
            StoreId([8; 16]),
            &[9; 32],
        ),
        &|_| Some(record.clone()),
    );
    assert_eq!(invalid.reason, Some(CredentialRejectReason::InvalidSecret));
    assert_eq!(invalid.work, expected_work);

    for (mut candidate, now, reason) in [
        (record.clone(), 150, CredentialRejectReason::Revoked),
        (record.clone(), 200, CredentialRejectReason::Expired),
    ] {
        if reason == CredentialRejectReason::Revoked {
            candidate.status = TokenStatus::Revoked;
        }
        let result = verify_credential(
            &CredentialWire::new(record.kind, record.audience, record.accessor, [2; 32])
                .unwrap()
                .encode(),
            verification_context(
                CredentialKind::Token,
                CredentialAudience::Data,
                7,
                now,
                StoreId([8; 16]),
                &[9; 32],
            ),
            &|_| Some(candidate.clone()),
        );
        assert_eq!(result.reason, Some(reason));
        assert_eq!(result.work, expected_work);
    }
}

#[test]
fn collision_bound_metadata_mac_and_finite_bounds_fail_closed() {
    let mut attempts = 0;
    let value = issue_credential(
        &[9; 32],
        StoreId([8; 16]),
        metadata(CredentialKind::Token, CredentialAudience::Control),
        "bootstrap".into(),
        &mut |_| {
            attempts += 1;
            attempts < ACCESSOR_COLLISION_ATTEMPTS
        },
        &mut Counter(0),
    )
    .unwrap();
    assert_eq!(attempts, ACCESSOR_COLLISION_ATTEMPTS);
    assert!(
        issue_credential(
            &[9; 32],
            StoreId([8; 16]),
            metadata(CredentialKind::Token, CredentialAudience::Control),
            "bootstrap".into(),
            &mut |_| true,
            &mut Counter(0),
        )
        .is_err()
    );

    let mut edited = value.record.clone();
    edited.issue_epoch += 1;
    assert!(
        mac_conformance(
            &value.record,
            &edited,
            1,
            &[7; 32],
            StoreId([8; 16]),
            &value.record.accessor.0,
        )
        .unwrap()
        .passed()
    );
    assert_eq!(
        CredentialRecord::decode(&value.record.encode().unwrap()).unwrap(),
        value.record
    );
    assert!(
        validate_ttl(
            DIRECT_TOKEN_MIN_TTL_SECONDS,
            DIRECT_TOKEN_MIN_TTL_SECONDS,
            DIRECT_TOKEN_MAX_TTL_SECONDS
        )
        .is_ok()
    );
    assert!(
        validate_ttl(
            DIRECT_TOKEN_MIN_TTL_SECONDS - 1,
            DIRECT_TOKEN_MIN_TTL_SECONDS,
            DIRECT_TOKEN_MAX_TTL_SECONDS
        )
        .is_err()
    );
    assert!(validate_secret_id_uses(0).is_err());
    assert!(validate_secret_id_uses(SECRET_ID_MAX_USES).is_ok());
    assert!(validate_secret_id_uses(SECRET_ID_MAX_USES + 1).is_err());
}

#[test]
fn init_stages_control_bootstrap_verifier_atomically_and_never_persists_secret() {
    const IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    let identity: age::x25519::Identity = IDENTITY.parse().unwrap();
    let meta = MetaRecord {
        store_id: StoreId([31; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    };
    let transaction =
        KeyringInitTransaction::prepare(meta.clone(), &identity, None, &mut Counter(0)).unwrap();
    let bootstrap = transaction.bootstrap_credential().unwrap().to_owned();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = transaction.commit(&path).unwrap();
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .windows(bootstrap.len())
            .any(|window| window == bootstrap.as_bytes())
    );

    let envelope = store.keyring().unwrap().unwrap();
    let metadata = store.keyring_metadata().unwrap().unwrap();
    let keyring = KeyringOpener::default()
        .open(meta.store_id, &envelope, &metadata, &identity)
        .unwrap();
    let control = keyring
        .verify_credential(
            &store,
            &bootstrap,
            CredentialKind::Token,
            CredentialAudience::Control,
            1_800_000_001,
        )
        .unwrap();
    assert!(control.authenticated_id.is_some());
    let data = keyring
        .verify_credential(
            &store,
            &bootstrap,
            CredentialKind::Token,
            CredentialAudience::Data,
            1_800_000_001,
        )
        .unwrap();
    assert_eq!(data.reason, Some(CredentialRejectReason::WrongAudience));
    assert_eq!(control.work, data.work);
    let records = keyring.credential_records(&store).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value.label, "bootstrap-control");

    let mut existing = records
        .iter()
        .map(|record| record.value.accessor)
        .collect::<std::collections::BTreeSet<_>>();
    let issued = keyring
        .prepare_credential(
            CredentialIssueMetadata {
                id: [11; 16],
                identity_id: records[0].value.identity_id,
                kind: CredentialKind::Token,
                audience: CredentialAudience::Control,
                issue_epoch: 1,
                expires_at_effective_seconds: 1_800_003_600,
                created_at_effective_seconds: 1_800_000_000,
                issuer_identity_id: records[0].value.identity_id,
                issuance_request_id: [12; 16],
                parent_accessor: None,
                consumer_instance_id: None,
            },
            "operator".into(),
            &mut |accessor| existing.contains(&accessor),
            &mut Counter(80),
        )
        .unwrap();
    let disclosed = issued.expose_once().to_owned();
    existing.insert(issued.record.accessor);
    let sealed = keyring.seal_credential(issued.record.clone()).unwrap();
    keyring.commit_credential(&store, &sealed, 1).unwrap();
    assert!(keyring.commit_credential(&store, &sealed, 1).is_err());
    assert!(
        keyring
            .verify_credential(
                &store,
                &disclosed,
                CredentialKind::Token,
                CredentialAudience::Control,
                1_800_000_001,
            )
            .unwrap()
            .authenticated_id
            .is_some()
    );
    let listed = keyring.credential_records(&store).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|record| {
        record.value.id == [11; 16]
            && record.value.issuance_request_id == [12; 16]
            && record.value.label == "operator"
    }));
    let recovered = keyring
        .credential_by_issuance_request(&store, [12; 16])
        .unwrap()
        .unwrap();
    assert_eq!(recovered.id, [11; 16]);
    assert_eq!(recovered.accessor, sealed.value.accessor);
}

#[test]
fn secret_id_child_tokens_inherit_consumer_and_identity_only_is_explicit() {
    let (_, mut parent) = issued(CredentialKind::SecretId, CredentialAudience::Data);
    parent.consumer_instance_id = Some([44; 16]);
    let child =
        CredentialIssueMetadata::token_from_secret_id(&parent, [45; 16], 120, 180, [46; 16])
            .unwrap();
    assert_eq!(child.identity_id, parent.identity_id);
    assert_eq!(child.parent_accessor, Some(parent.accessor));
    assert_eq!(child.consumer_instance_id, Some([44; 16]));
    assert!(CredentialIssueMetadata::require_workload_tracking(None, false).is_err());
    assert_eq!(
        CredentialIssueMetadata::require_workload_tracking(None, true).unwrap(),
        None
    );
}
