use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use ops_light_secrets_server::control::data_router;
use ops_light_secrets_server::control::management::{ManagementCatalog, ManagementPrincipal};
use ops_light_secrets_server::credential::CredentialAudience;
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::kv::{KvCatalog, KvService};
use ops_light_secrets_server::raw_target::parse_raw_target;
use ops_light_secrets_server::rotation::{
    RotationCatalog, RotationError, RotationLifecycle, RotationSnapshotInput,
};
use ops_light_secrets_server::store::StoreId;
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const ACTOR: [u8; 16] = [1; 16];

fn grant(id: u8, owner: [u8; 16], mount: &str, capabilities: &[Capability]) -> GrantRecord {
    GrantRecord::new(
        [id; 16],
        owner,
        mount.into(),
        if mount == "sys" {
            GrantScope::Exact
        } else {
            GrantScope::Subtree
        },
        Vec::new(),
        capabilities.iter().copied().collect::<BTreeSet<_>>(),
    )
    .unwrap()
}

fn fixtures() -> (
    ManagementCatalog,
    ManagementPrincipal,
    KvService,
    RotationCatalog,
) {
    let identity = IdentityRecord::new(ACTOR, "operator".into(), IdentityKind::Human).unwrap();
    let management = ManagementCatalog::new(
        [identity],
        [grant(2, ACTOR, "sys", &[Capability::RotationManage])],
    )
    .unwrap();
    let principal = ManagementPrincipal {
        identity_id: ACTOR,
        audience: CredentialAudience::Control,
        peer_uid: 1000,
        expected_uid: 1000,
        credential_active: true,
    };
    let mut kv = KvCatalog::new(false, 1_000);
    kv.replace_grants(vec![grant(
        3,
        ACTOR,
        "secret",
        &[
            Capability::SecretWrite,
            Capability::SecretReadCurrent,
            Capability::SecretReadHistory,
        ],
    )]);
    (
        management,
        principal,
        KvService::new(kv),
        RotationCatalog::new(StoreId([7; 16]), [8; 32]),
    )
}

fn endpoint() -> ops_light_secrets_server::raw_target::EndpointRequest {
    parse_raw_target(&Method::POST, "/v1/secret/data/apps/database").unwrap()
}

fn value(number: u64) -> Map<String, Value> {
    Map::from_iter([("value".into(), json!(number))])
}

fn snapshot(marker: u8) -> RotationSnapshotInput {
    RotationSnapshotInput {
        declared_consumers: [[marker; 16]].into_iter().collect(),
        authorized_identities: [[marker + 1; 16]].into_iter().collect(),
        active_instances: [[marker + 2; 16]].into_iter().collect(),
    }
}

#[test]
fn begin_writes_no_secret_and_double_begin_refuses() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    let before = kv.rotation_snapshot(&endpoint()).unwrap().current_version;
    let begun = rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    assert_eq!(begun.record.state, RotationLifecycle::Prepared);
    assert_eq!(
        kv.rotation_snapshot(&endpoint()).unwrap().current_version,
        before
    );
    assert_eq!(
        kv.rotation_snapshot(&endpoint()).unwrap().protection,
        Some(1)
    );
    assert_eq!(
        rotations.begin(
            &mut management,
            principal,
            [11; 16],
            [21; 16],
            "secret/apps/database".into(),
            snapshot(31),
            101,
            &kv,
        ),
        Err(RotationError::Conflict {
            state: RotationLifecycle::Prepared
        })
    );
}

#[test]
fn invalid_transition_input_is_rejected_before_kv_mutation() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    assert_eq!(
        rotations.begin(
            &mut management,
            principal,
            [9; 16],
            [19; 16],
            "secret/apps/database".into(),
            snapshot(29),
            0,
            &kv,
        ),
        Err(RotationError::Invalid)
    );
    assert_eq!(kv.rotation_snapshot(&endpoint()).unwrap().protection, None);

    rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    assert_eq!(
        rotations.cutover(
            &mut management,
            principal,
            [11; 16],
            [20; 16],
            1,
            value(2),
            0,
            &kv,
        ),
        Err(RotationError::Invalid)
    );
    assert_eq!(
        kv.rotation_snapshot(&endpoint()).unwrap().current_version,
        1
    );
}

#[test]
fn stale_cutover_stays_prepared_then_refresh_and_cutover_succeed() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    kv.write(ACTOR, &endpoint(), value(2), Some(1)).unwrap();
    assert_eq!(
        rotations.cutover(
            &mut management,
            principal,
            [11; 16],
            [20; 16],
            1,
            value(3),
            110,
            &kv,
        ),
        Err(RotationError::CasConflict)
    );
    assert_eq!(
        rotations
            .show(&mut management, principal, [12; 16], [20; 16])
            .unwrap()
            .record
            .state,
        RotationLifecycle::Prepared
    );
    rotations
        .refresh(
            &mut management,
            principal,
            [13; 16],
            [20; 16],
            1,
            snapshot(40),
            120,
            &kv,
        )
        .unwrap();
    let cutover = rotations
        .cutover(
            &mut management,
            principal,
            [14; 16],
            [20; 16],
            2,
            value(3),
            130,
            &kv,
        )
        .unwrap();
    assert_eq!(cutover.record.target_version, Some(3));
    assert_eq!(cutover.record.state, RotationLifecycle::Cutover);
}

#[test]
fn cancel_only_prepared_releases_protection_and_writes_nothing() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    let cancelled = rotations
        .cancel(
            &mut management,
            principal,
            [11; 16],
            [20; 16],
            1,
            110,
            "operator cancelled".into(),
            &kv,
        )
        .unwrap();
    assert_eq!(
        cancelled.record.state,
        RotationLifecycle::CancelledBeforeCutover
    );
    assert_eq!(
        kv.rotation_snapshot(&endpoint()).unwrap().current_version,
        1
    );
    assert_eq!(kv.rotation_snapshot(&endpoint()).unwrap().protection, None);
    assert!(matches!(
        rotations.cancel(
            &mut management,
            principal,
            [12; 16],
            [20; 16],
            2,
            120,
            "again".into(),
            &kv,
        ),
        Err(RotationError::Conflict {
            state: RotationLifecycle::CancelledBeforeCutover
        })
    ));
}

#[test]
fn rollback_is_server_side_copy_forward_and_never_moves_pointer_back() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    rotations
        .cutover(
            &mut management,
            principal,
            [11; 16],
            [20; 16],
            1,
            value(2),
            110,
            &kv,
        )
        .unwrap();
    let rolled = rotations
        .rollback(
            &mut management,
            principal,
            [12; 16],
            [20; 16],
            2,
            120,
            "upstream rejected new credential".into(),
            &kv,
        )
        .unwrap();
    assert_eq!(rolled.record.state, RotationLifecycle::Superseded);
    assert_eq!(
        kv.rotation_snapshot(&endpoint()).unwrap().current_version,
        3
    );
    let read = parse_raw_target(&Method::GET, "/v1/secret/data/apps/database").unwrap();
    assert_eq!(kv.read(ACTOR, &read).unwrap().data, json!({"value": 1}));
}

#[test]
fn plain_write_after_cutover_supersedes_and_releases_retention_hold() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    rotations
        .cutover(
            &mut management,
            principal,
            [11; 16],
            [20; 16],
            1,
            value(2),
            110,
            &kv,
        )
        .unwrap();
    kv.write(ACTOR, &endpoint(), value(3), Some(2)).unwrap();
    let superseded = rotations
        .supersede_after_plain_write([20; 16], 2, 120, &kv)
        .unwrap();
    assert_eq!(superseded.record.state, RotationLifecycle::Superseded);
    assert_eq!(kv.rotation_snapshot(&endpoint()).unwrap().protection, None);
}

#[test]
fn missing_deleted_destroyed_and_wrong_capability_refuse_begin() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    assert_eq!(
        rotations.begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv
        ),
        Err(RotationError::ProtectedVersionUnavailable)
    );
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    kv.with_catalog(|catalog| {
        catalog.set_version_state(
            "apps/database",
            1,
            ops_light_secrets_server::store::VersionState::Destroyed,
        )
    })
    .unwrap();
    assert!(matches!(
        rotations.begin(
            &mut management,
            principal,
            [11; 16],
            [21; 16],
            "secret/apps/database".into(),
            snapshot(31),
            101,
            &kv
        ),
        Err(RotationError::ProtectedVersionUnavailable)
    ));

    let identity = IdentityRecord::new(ACTOR, "operator".into(), IdentityKind::Human).unwrap();
    let mut denied = ManagementCatalog::new(
        [identity],
        [grant(9, ACTOR, "sys", &[Capability::ConsumerEnumerate])],
    )
    .unwrap();
    let empty = KvService::new(KvCatalog::new(false, 1));
    assert_eq!(
        rotations.begin(
            &mut denied,
            principal,
            [12; 16],
            [22; 16],
            "secret/apps/other".into(),
            snapshot(32),
            102,
            &empty
        ),
        Err(RotationError::Denied)
    );
    assert!(!denied.audit().last().unwrap().allowed);
}

#[test]
fn immutable_catalog_history_is_filtered_and_paginated() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    rotations
        .begin(
            &mut management,
            principal,
            [10; 16],
            [20; 16],
            "secret/apps/database".into(),
            snapshot(30),
            100,
            &kv,
        )
        .unwrap();
    rotations
        .cancel(
            &mut management,
            principal,
            [11; 16],
            [20; 16],
            1,
            110,
            "cancel".into(),
            &kv,
        )
        .unwrap();
    let page = rotations
        .list(
            &mut management,
            principal,
            [12; 16],
            None,
            1,
            Some("secret/apps/database"),
            Some(RotationLifecycle::CancelledBeforeCutover),
            Some(100),
            Some(100),
        )
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].record.history.len(), 2);
}

#[tokio::test]
async fn remote_listener_has_no_rotation_routes() {
    for uri in [
        "/v1/sys/rotation",
        "/v1/sys/rotation/cutover",
        "/v1/sys/rotation/status",
    ] {
        let response = data_router()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[test]
fn adoption_status_classifies_instances_and_ignores_lookback_for_class() {
    use ops_light_secrets_server::rotation::{
        AdoptionClass, ReadObservation, classify_adoption,
    };
    use std::collections::BTreeMap;

    let consumer_a = [0xA1; 16];
    let consumer_b = [0xA2; 16];
    let identity_a = [0xB1; 16];
    let identity_b = [0xB2; 16];
    let instance_a1 = [0xC1; 16];
    let instance_a2 = [0xC2; 16];
    let instance_b = [0xC3; 16];
    let snapshot = RotationSnapshotInput {
        declared_consumers: [consumer_a, consumer_b].into_iter().collect(),
        authorized_identities: [identity_a, identity_b].into_iter().collect(),
        active_instances: [instance_a1, instance_a2, instance_b].into_iter().collect(),
    };
    let mut instance_to_identity = BTreeMap::new();
    instance_to_identity.insert(instance_a1, identity_a);
    instance_to_identity.insert(instance_a2, identity_a);
    instance_to_identity.insert(instance_b, identity_b);
    let mut identity_to_consumer = BTreeMap::new();
    identity_to_consumer.insert(identity_a, consumer_a);
    identity_to_consumer.insert(identity_b, consumer_b);

    // cutover at seq 10, target version 3
    let observations = [
        ReadObservation {
            sequence: 5,
            identity_id: identity_a,
            consumer_instance_id: Some(instance_a1),
            version: 2,
            effective_unix_seconds: 50,
        },
        ReadObservation {
            sequence: 12,
            identity_id: identity_a,
            consumer_instance_id: Some(instance_a1),
            version: 3,
            effective_unix_seconds: 100,
        },
        ReadObservation {
            sequence: 13,
            identity_id: identity_a,
            consumer_instance_id: Some(instance_a2),
            version: 2,
            effective_unix_seconds: 101,
        },
        // old post-cutover current read; lookback would mark recency but class stays on-current
        ReadObservation {
            sequence: 14,
            identity_id: identity_b,
            consumer_instance_id: Some(instance_b),
            version: 3,
            effective_unix_seconds: 10,
        },
    ];

    let members = classify_adoption(
        &snapshot,
        3,
        10,
        100,
        &observations,
        &BTreeSet::new(),
        Some(30),
        200,
        &instance_to_identity,
        &identity_to_consumer,
    )
    .unwrap();

    let instance = |id: [u8; 16]| {
        members
            .iter()
            .find(|member| member.kind == "instance" && member.id == id)
            .unwrap()
            .clone()
    };
    assert_eq!(instance(instance_a1).class, AdoptionClass::OnCurrent);
    assert_eq!(instance(instance_a1).fetched_version, Some(3));
    assert_eq!(instance(instance_a2).class, AdoptionClass::OnPrior);
    assert_eq!(instance(instance_b).class, AdoptionClass::OnCurrent);
    assert!(instance(instance_b).recency_lookback_exceeded);

    let identity = |id: [u8; 16]| {
        members
            .iter()
            .find(|member| member.kind == "identity" && member.id == id)
            .unwrap()
            .clone()
    };
    // mixed replicas under identity_a → on-prior (never hide prior)
    assert_eq!(identity(identity_a).class, AdoptionClass::OnPrior);
    assert_eq!(identity(identity_b).class, AdoptionClass::OnCurrent);

    let silent = members
        .iter()
        .find(|member| member.kind == "instance" && member.class == AdoptionClass::SilentSinceWrite);
    assert!(silent.is_none());
}

#[test]
fn adoption_status_marks_retired_and_no_instance_and_ae11_silent() {
    use ops_light_secrets_server::rotation::{
        AdoptionClass, ReadObservation, classify_adoption,
    };
    use std::collections::BTreeMap;

    let consumer = [1; 16];
    let identity_read = [2; 16];
    let identity_silent = [3; 16];
    let identity_only = [4; 16];
    let instance_read = [5; 16];
    let instance_silent = [6; 16];
    let instance_retired = [7; 16];
    let snapshot = RotationSnapshotInput {
        declared_consumers: [consumer].into_iter().collect(),
        authorized_identities: [identity_read, identity_silent, identity_only]
            .into_iter()
            .collect(),
        active_instances: [instance_read, instance_silent, instance_retired]
            .into_iter()
            .collect(),
    };
    let mut instance_to_identity = BTreeMap::new();
    instance_to_identity.insert(instance_read, identity_read);
    instance_to_identity.insert(instance_silent, identity_silent);
    instance_to_identity.insert(instance_retired, identity_silent);
    let mut identity_to_consumer = BTreeMap::new();
    identity_to_consumer.insert(identity_read, consumer);
    identity_to_consumer.insert(identity_silent, consumer);
    identity_to_consumer.insert(identity_only, consumer);

    let observations = [ReadObservation {
        sequence: 20,
        identity_id: identity_read,
        consumer_instance_id: Some(instance_read),
        version: 9,
        effective_unix_seconds: 500,
    }];
    let retired = BTreeSet::from([instance_retired]);
    let members = classify_adoption(
        &snapshot,
        9,
        10,
        30,
        &observations,
        &retired,
        None,
        1000,
        &instance_to_identity,
        &identity_to_consumer,
    )
    .unwrap();

    assert_eq!(
        members
            .iter()
            .find(|m| m.id == instance_read)
            .unwrap()
            .class,
        AdoptionClass::OnCurrent
    );
    assert_eq!(
        members
            .iter()
            .find(|m| m.id == instance_silent)
            .unwrap()
            .class,
        AdoptionClass::SilentSinceWrite
    );
    assert_eq!(
        members
            .iter()
            .find(|m| m.id == instance_retired)
            .unwrap()
            .class,
        AdoptionClass::RetiredWithoutProof
    );
    assert_eq!(
        members
            .iter()
            .find(|m| m.kind == "identity" && m.id == identity_only)
            .unwrap()
            .class,
        AdoptionClass::NoInstanceObservation
    );
}

#[test]
fn rotation_status_command_requires_cutover_and_is_management_gated() {
    let (mut management, principal, kv, mut rotations) = fixtures();
    kv.write(ACTOR, &endpoint(), value(1), Some(0)).unwrap();
    let started = rotations
        .begin(
            &mut management,
            principal,
            [1; 16],
            [9; 16],
            "secret/apps/database".into(),
            snapshot(1),
            100,
            &kv,
        )
        .unwrap();
    // Prepared refuses status.
    let err = rotations
        .status(
            &mut management,
            principal,
            [2; 16],
            started.record.id,
            &[],
            &BTreeSet::new(),
            0,
            0,
            None,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        RotationError::Conflict {
            state: RotationLifecycle::Prepared
        }
    ));

    let cutover = rotations
        .cutover(
            &mut management,
            principal,
            [3; 16],
            started.record.id,
            started.generation,
            value(2),
            110,
            &kv,
        )
        .unwrap();
    let consumer = *cutover.record.declared_consumers.iter().next().unwrap();
    let identity = *cutover.record.authorized_identities.iter().next().unwrap();
    let instance = *cutover.record.active_instances.iter().next().unwrap();
    let mut instance_to_identity = BTreeMap::new();
    instance_to_identity.insert(instance, identity);
    let mut identity_to_consumer = BTreeMap::new();
    identity_to_consumer.insert(identity, consumer);
    let observations = [ops_light_secrets_server::rotation::ReadObservation {
        sequence: 5,
        identity_id: identity,
        consumer_instance_id: Some(instance),
        version: cutover.record.target_version.unwrap(),
        effective_unix_seconds: 120,
    }];
    let status = rotations
        .status(
            &mut management,
            principal,
            [4; 16],
            cutover.record.id,
            &observations,
            &BTreeSet::new(),
            1,
            10,
            None,
            200,
            &instance_to_identity,
            &identity_to_consumer,
        )
        .unwrap();
    assert_eq!(status.target_version, cutover.record.target_version.unwrap());
    assert_eq!(
        status.instances[0].class,
        ops_light_secrets_server::rotation::AdoptionClass::OnCurrent
    );
    assert_eq!(status.instances[0].fetched_version, Some(status.target_version));
}

#[test]
fn rotation_cli_help_includes_status() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args(["rotation", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("status"));
}

#[test]
fn secret_age_uses_completed_rotation_and_labels_hand_writes() {
    use ops_light_secrets_server::rotation::{
        RotationIntervalPolicy, clear_rotation_interval, secret_age_view, set_rotation_interval,
    };
    assert_eq!(set_rotation_interval(86400).unwrap(), 86400);
    assert!(set_rotation_interval(0).is_err());
    assert_eq!(clear_rotation_interval(), None);

    let never_rotated = RotationIntervalPolicy {
        interval_seconds: Some(100),
        last_completed_rotation_unix_seconds: None,
        created_unix_seconds: 1_000,
        last_non_rotation_write_unix_seconds: Some(1_050),
    };
    let view = secret_age_view(&never_rotated, 1_200);
    assert_eq!(view.age_basis, "creation");
    assert_eq!(view.age_seconds, 200);
    assert!(view.due);
    assert!(view.changed_since_last_completed_rotation);

    let rotated = RotationIntervalPolicy {
        interval_seconds: Some(1_000),
        last_completed_rotation_unix_seconds: Some(2_000),
        created_unix_seconds: 1_000,
        last_non_rotation_write_unix_seconds: Some(2_500),
    };
    let view = secret_age_view(&rotated, 2_400);
    assert_eq!(view.age_basis, "last_completed_rotation");
    assert_eq!(view.age_seconds, 400);
    assert!(!view.due);
    assert!(view.changed_since_last_completed_rotation);
}

#[test]
fn rotation_cli_help_includes_interval() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args(["rotation", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("interval"));
}
