use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ops_light_secrets_server::consumer::{
    ConsumerCatalog, ConsumerError, ConsumerInstanceRecord, ConsumerLifecycle, ConsumerRecord,
    ConsumerUpdate,
};
use ops_light_secrets_server::control::data_router;
use ops_light_secrets_server::control::management::{ManagementCatalog, ManagementPrincipal};
use ops_light_secrets_server::credential::CredentialAudience;
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::store::{Canonical, StoreId};
use tower::ServiceExt;

const ACTOR: [u8; 16] = [1; 16];

fn management_fixture(capabilities: &[Capability]) -> (ManagementCatalog, ManagementPrincipal) {
    let identity = IdentityRecord::new(ACTOR, "operator".into(), IdentityKind::Human).unwrap();
    let grant = GrantRecord::new(
        [2; 16],
        ACTOR,
        "sys".into(),
        GrantScope::Exact,
        Vec::new(),
        capabilities.iter().copied().collect::<BTreeSet<_>>(),
    )
    .unwrap();
    (
        ManagementCatalog::new([identity], [grant]).unwrap(),
        ManagementPrincipal {
            identity_id: ACTOR,
            audience: CredentialAudience::Control,
            peer_uid: 1000,
            expected_uid: 1000,
            credential_active: true,
        },
    )
}

fn consumer(id: u8, label: &str) -> ConsumerRecord {
    ConsumerRecord {
        id: [id; 16],
        label: label.into(),
        resource: "secret/apps/database".into(),
        owner: "platform".into(),
        environment: "production".into(),
        source: "migration-inventory".into(),
        identity_id: None,
        lifecycle: ConsumerLifecycle::Declared,
        last_verified_unix_seconds: None,
        note: "non-secret inventory fact".into(),
    }
}

fn instance(parent: u8, id: u8, label: &str) -> ConsumerInstanceRecord {
    ConsumerInstanceRecord {
        id: [id; 16],
        consumer_id: [parent; 16],
        label: label.into(),
        owner: "platform".into(),
        environment: "production".into(),
        source: "deployment".into(),
        identity_id: Some([9; 16]),
        lifecycle: ConsumerLifecycle::Declared,
        last_verified_unix_seconds: Some(100),
        note: "instance inventory".into(),
    }
}

fn catalog_fixture() -> ConsumerCatalog {
    ConsumerCatalog::new(StoreId([7; 16]), [8; 32])
}

#[test]
fn normalized_parent_and_multiple_instances_round_trip_with_mac() {
    let (mut management, principal) =
        management_fixture(&[Capability::RotationManage, Capability::ConsumerEnumerate]);
    let mut catalog = catalog_fixture();
    let parent = catalog
        .create_consumer(
            &mut management,
            principal,
            [10; 16],
            consumer(3, "database"),
        )
        .unwrap();
    assert_eq!(parent.generation, 1);
    for (id, label) in [(4, "blue"), (5, "green")] {
        catalog
            .create_instance(
                &mut management,
                principal,
                [id + 20; 16],
                instance(3, id, label),
            )
            .unwrap();
    }
    let page = catalog
        .list_instances(&mut management, principal, [30; 16], [3; 16], None, 10)
        .unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].record.consumer_id, [3; 16]);
    assert_eq!(
        ConsumerRecord::decode(&parent.record.encode().unwrap()).unwrap(),
        parent.record
    );
}

#[test]
fn capability_map_denies_mutation_and_enumeration_separately_and_audits() {
    let (mut management, principal) = management_fixture(&[Capability::ConsumerEnumerate]);
    let mut catalog = catalog_fixture();
    assert_eq!(
        catalog.create_consumer(&mut management, principal, [10; 16], consumer(3, "db")),
        Err(ConsumerError::Denied)
    );
    assert!(!management.audit().last().unwrap().allowed);

    let (mut management, principal) = management_fixture(&[Capability::RotationManage]);
    let mut catalog = catalog_fixture();
    catalog
        .create_consumer(&mut management, principal, [11; 16], consumer(3, "db"))
        .unwrap();
    assert_eq!(
        catalog.show_consumer(&mut management, principal, [12; 16], [3; 16]),
        Err(ConsumerError::Denied)
    );
    assert!(!management.audit().last().unwrap().allowed);
}

#[test]
fn duplicate_ids_labels_parent_races_and_stale_generations_refuse() {
    let (mut management, principal) =
        management_fixture(&[Capability::RotationManage, Capability::ConsumerEnumerate]);
    let mut catalog = catalog_fixture();
    catalog
        .create_consumer(&mut management, principal, [10; 16], consumer(3, "db"))
        .unwrap();
    assert_eq!(
        catalog.create_consumer(&mut management, principal, [11; 16], consumer(4, "db")),
        Err(ConsumerError::Conflict)
    );
    assert_eq!(
        catalog.create_instance(&mut management, principal, [12; 16], instance(9, 5, "one")),
        Err(ConsumerError::Conflict)
    );
    assert_eq!(
        catalog.update_consumer(
            &mut management,
            principal,
            [13; 16],
            [3; 16],
            7,
            ConsumerUpdate::default(),
        ),
        Err(ConsumerError::StaleGeneration)
    );
}

#[test]
fn lifecycle_is_closed_retire_requires_reason_and_parent_waits_for_children() {
    let (mut management, principal) =
        management_fixture(&[Capability::RotationManage, Capability::ConsumerEnumerate]);
    let mut catalog = catalog_fixture();
    catalog
        .create_consumer(&mut management, principal, [10; 16], consumer(3, "db"))
        .unwrap();
    catalog
        .create_instance(&mut management, principal, [11; 16], instance(3, 4, "blue"))
        .unwrap();
    let parent = catalog
        .update_consumer(
            &mut management,
            principal,
            [12; 16],
            [3; 16],
            1,
            ConsumerUpdate {
                lifecycle: Some(ConsumerLifecycle::Migrated),
                ..ConsumerUpdate::default()
            },
        )
        .unwrap();
    assert_eq!(parent.record.lifecycle, ConsumerLifecycle::Migrated);
    assert_eq!(
        catalog.retire_consumer(
            &mut management,
            principal,
            [13; 16],
            [3; 16],
            2,
            "done".into()
        ),
        Err(ConsumerError::Conflict)
    );
    assert_eq!(
        catalog.retire_instance(
            &mut management,
            principal,
            [14; 16],
            [3; 16],
            [4; 16],
            1,
            "".into()
        ),
        Err(ConsumerError::Invalid)
    );
    catalog
        .retire_instance(
            &mut management,
            principal,
            [15; 16],
            [3; 16],
            [4; 16],
            1,
            "deployment removed".into(),
        )
        .unwrap();
    let retired = catalog
        .retire_consumer(
            &mut management,
            principal,
            [16; 16],
            [3; 16],
            2,
            "application retired".into(),
        )
        .unwrap();
    assert_eq!(retired.record.lifecycle, ConsumerLifecycle::Retired);
    assert_eq!(
        management.audit().last().unwrap().reason.as_deref(),
        Some("application retired")
    );
}

#[test]
fn read_verifies_mac_and_pagination_filters_are_stable() {
    let (mut management, principal) =
        management_fixture(&[Capability::RotationManage, Capability::ConsumerEnumerate]);
    let mut catalog = catalog_fixture();
    for id in 3..=5 {
        let mut row = consumer(id, &format!("c{id}"));
        row.owner = if id == 4 { "other" } else { "platform" }.into();
        catalog
            .create_consumer(&mut management, principal, [id + 20; 16], row)
            .unwrap();
    }
    let first = catalog
        .list_consumers(
            &mut management,
            principal,
            [30; 16],
            None,
            1,
            None,
            Some(ConsumerLifecycle::Declared),
            Some("platform"),
        )
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(first.next_cursor.is_some());
    let second = catalog
        .list_consumers(
            &mut management,
            principal,
            [31; 16],
            Some([3; 16]),
            1,
            None,
            Some(ConsumerLifecycle::Declared),
            Some("platform"),
        )
        .unwrap();
    assert_eq!(second.items[0].record.id, [5; 16]);
    assert!(second.next_cursor.is_none());
    catalog.corrupt_consumer_note_for_fixture([3; 16]);
    assert_eq!(
        catalog.show_consumer(&mut management, principal, [32; 16], [3; 16]),
        Err(ConsumerError::Integrity)
    );
}

#[tokio::test]
async fn remote_listener_has_no_consumer_routes() {
    let response = data_router()
        .oneshot(
            Request::builder()
                .uri("/v1/sys/consumer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
