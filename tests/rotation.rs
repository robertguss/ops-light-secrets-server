use std::collections::BTreeSet;

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
