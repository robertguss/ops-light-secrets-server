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
use std::path::Path;
use std::sync::{Arc, Barrier};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

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

#[test]
fn epoch_and_verifier_key_bumps_reject_stale_credentials_with_fixed_work() {
    let (wire, record) = issued(CredentialKind::Token, CredentialAudience::Data);
    let lookup = Arc::new(move |accessor| (accessor == record.accessor).then(|| record.clone()));
    let accepted = verify_credential(
        &wire,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            150,
            StoreId([8; 16]),
            &[9; 32],
        ),
        &*lookup,
    );
    let expected_work = accepted.work;
    assert!(accepted.authenticated_id.is_some());

    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let barrier = Arc::clone(&barrier);
        let lookup = Arc::clone(&lookup);
        let wire = wire.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            verify_credential(
                &wire,
                verification_context(
                    CredentialKind::Token,
                    CredentialAudience::Data,
                    8,
                    150,
                    StoreId([8; 16]),
                    &[9; 32],
                ),
                &*lookup,
            )
        }));
    }
    barrier.wait();
    for result in threads.into_iter().map(|thread| thread.join().unwrap()) {
        assert_eq!(result.authenticated_id, None);
        assert_eq!(result.reason, Some(CredentialRejectReason::EpochChanged));
        assert_eq!(result.work, expected_work);
    }

    let key_bumped = verify_credential(
        &wire,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            7,
            150,
            StoreId([8; 16]),
            &[10; 32],
        ),
        &*lookup,
    );
    let both_bumped = verify_credential(
        &wire,
        verification_context(
            CredentialKind::Token,
            CredentialAudience::Data,
            8,
            150,
            StoreId([8; 16]),
            &[10; 32],
        ),
        &*lookup,
    );
    assert_eq!(key_bumped.authenticated_id, None);
    assert_eq!(both_bumped.authenticated_id, None);
    assert_eq!(key_bumped.work, expected_work);
    assert_eq!(both_bumped.work, expected_work);
}

const AUTH_SCENARIOS: [(&str, &[&str]); 15] = [
    (
        "auth-01-approle-envelope",
        &[
            "tests/auth_api.rs::f3_login_token_and_lookup_self_use_role_ttl_and_hide_bearer",
            "tests/auth_api.rs::vault_routes_have_stable_envelopes_strict_json_and_explicit_renewal_refusal",
        ],
    ),
    (
        "auth-02-invalid-secret-audit",
        &[
            "tests/auth_api.rs::wrong_role_invalid_secret_and_deleted_role_have_one_normalized_failure",
            "tests/auth_api.rs::audit_events_are_secret_free_and_operation_specific",
        ],
    ),
    (
        "auth-03-one-record-fixed-work",
        &[
            "tests/auth.rs::unknown_bad_revoked_expired_and_stale_all_compute_mac_and_read_epoch",
            "tests/auth.rs::auth_path_has_no_password_kdf_dependency_or_call",
        ],
    ),
    (
        "auth-04-one-use-concurrent",
        &[
            "tests/auth_api.rs::one_use_concurrent_login_commits_once_and_lost_reply_never_rediscloses",
        ],
    ),
    (
        "auth-05-token-lifecycle",
        &[
            "tests/auth_api.rs::f3_login_token_and_lookup_self_use_role_ttl_and_hide_bearer",
            "tests/auth_api.rs::vault_routes_have_stable_envelopes_strict_json_and_explicit_renewal_refusal",
        ],
    ),
    (
        "auth-06-secret-nondisclosure",
        &[
            "tests/auth.rs::init_stages_control_bootstrap_verifier_atomically_and_never_persists_secret",
            "tests/control_mgmt.rs::token_disclosure_once_authenticate_revoke_and_lost_reply_recovery",
        ],
    ),
    (
        "auth-07-flood-and-size",
        &[
            "tests/rate_limit.rs::aggregate_buffer_is_bounded_secret_free_and_flushes_once",
            "tests/rate_limit.rs::oversized_and_malformed_login_drop_before_handler_and_feed_aggregates",
        ],
    ),
    (
        "auth-08-audience-cross-use",
        &[
            "tests/auth_api.rs::token_middleware_resolves_identity_and_separates_listener_audiences",
            "tests/control_mgmt.rs::wrong_surface_uid_credential_and_capability_are_denied_and_audited",
        ],
    ),
    (
        "auth-09-store-domain",
        &["tests/auth.rs::verifier_domain_separates_store_kind_audience_epoch_and_runs_fixed_work"],
    ),
    (
        "auth-10-epoch-linearization",
        &["tests/auth.rs::epoch_and_verifier_key_bumps_reject_stale_credentials_with_fixed_work"],
    ),
    (
        "auth-11-unix-peer",
        &[
            "tests/control_mgmt.rs::wrong_surface_uid_credential_and_capability_are_denied_and_audited",
        ],
    ),
    (
        "auth-12-kind-cross-use",
        &[
            "tests/auth.rs::verifier_domain_separates_store_kind_audience_epoch_and_runs_fixed_work",
            "tests/auth_api.rs::credential_kind_cross_use_is_normalized_and_audited",
        ],
    ),
    (
        "auth-13-role-binding",
        &[
            "tests/auth_api.rs::wrong_role_invalid_secret_and_deleted_role_have_one_normalized_failure",
            "tests/auth_api.rs::delete_login_race_is_linearized_and_never_accepts_after_delete",
        ],
    ),
    (
        "auth-14-forged-forwarding",
        &[
            "tests/rate_limit.rs::direct_ignores_forged_forwarding_and_proxy_uses_verified_forwarded_source",
        ],
    ),
    (
        "auth-15-identity-rate",
        &[
            "tests/rate_limit.rs::authenticated_identity_rate_and_global_concurrency_bound_looping_clients",
        ],
    ),
];

#[test]
fn every_auth_contract_scenario_has_source_evidence_and_safe_observability() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = Harness::builder("auth-contract")
        .register_canary(b"auth-contract-secret-canary-71e49f")
        .build()
        .unwrap();
    for (index, (id, evidence)) in AUTH_SCENARIOS.iter().enumerate() {
        assert!(!evidence.is_empty());
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
        assert!(report.jsonl.contains("\"event\":\"scenario_begin\""));
        assert!(report.jsonl.contains("\"event\":\"step\""));
        assert!(report.jsonl.contains("\"event\":\"scenario_end\""));
        assert!(!report.jsonl.contains("auth-contract-secret-canary-71e49f"));
    }
}

#[test]
fn auth_path_has_no_password_kdf_dependency_or_call() {
    let manifest = include_str!("../Cargo.toml");
    for dependency in ["argon2", "bcrypt", "pbkdf2", "scrypt"] {
        assert!(
            !manifest.lines().any(|line| {
                line.trim_start()
                    .strip_prefix(dependency)
                    .is_some_and(|tail| tail.trim_start().starts_with('='))
            }),
            "password KDF must not be a direct server dependency: {dependency}"
        );
    }
    let auth_source = include_str!("../src/auth.rs");
    let credential_source = include_str!("../src/credential.rs");
    for call in ["argon2::", "bcrypt::", "pbkdf2::", "scrypt::"] {
        assert!(!auth_source.contains(call), "auth path invokes {call}");
        assert!(
            !credential_source.contains(call),
            "credential path invokes {call}"
        );
    }
}

#[test]
#[ignore = "U5.6 owns the final scoped AppRole-to-KV read tail"]
fn scoped_approle_token_reads_authorized_kv_path() {
    panic!("replace with U5.6 assembled KV authorization evidence");
}

#[test]
#[ignore = "U5.6 owns the final expired-and-revoked KV rejection tail"]
fn scoped_expired_and_revoked_tokens_cannot_read_kv() {
    panic!("replace with U5.6 assembled KV authorization evidence");
}
