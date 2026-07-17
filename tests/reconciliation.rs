use std::collections::BTreeSet;

use ops_light_secrets_server::consumer::ConsumerLifecycle;
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::reconciliation::{
    ActionableFlag, AuthorizationState, DeclaredBinding, ObservationState, ReconciliationError,
    ReconciliationSnapshot, RegistryLifecycle, VerifiedReadObservation, reconcile,
};

const RESOURCE: &str = "secret/apps/database";

fn identity(id: u8) -> IdentityRecord {
    IdentityRecord::new([id; 16], format!("identity-{id}"), IdentityKind::Workload).unwrap()
}

fn grant(id: u8, owner: u8) -> GrantRecord {
    GrantRecord::new(
        [id; 16],
        [owner; 16],
        "secret".into(),
        GrantScope::Subtree,
        vec!["apps".into()],
        [Capability::SecretReadCurrent]
            .into_iter()
            .collect::<BTreeSet<_>>(),
    )
    .unwrap()
}

fn declaration(
    consumer: u8,
    instance: Option<u8>,
    identity: Option<u8>,
    lifecycle: ConsumerLifecycle,
) -> DeclaredBinding {
    DeclaredBinding {
        consumer_id: [consumer; 16],
        instance_id: instance.map(|id| [id; 16]),
        resource: RESOURCE.into(),
        identity_id: identity.map(|id| [id; 16]),
        lifecycle,
    }
}

fn observation(
    identity: u8,
    instance: Option<u8>,
    at: u64,
    version: u64,
) -> VerifiedReadObservation {
    VerifiedReadObservation {
        identity_id: [identity; 16],
        consumer_instance_id: instance.map(|id| [id; 16]),
        resource: RESOURCE.into(),
        effective_unix_seconds: at,
        version_served: version,
        authenticated: true,
    }
}

fn snapshot<'a>(
    declarations: &'a [DeclaredBinding],
    identities: &'a [IdentityRecord],
    grants: &'a [GrantRecord],
    observations: &'a [VerifiedReadObservation],
) -> ReconciliationSnapshot<'a> {
    ReconciliationSnapshot {
        cutoff_sequence: 44,
        effective_unix_seconds: 1_000,
        lookback_seconds: 100,
        declared_source_verified: true,
        authorization_source_verified: true,
        audit_source_verified: true,
        declarations,
        identities,
        grants,
        observations,
    }
}

#[test]
fn frozen_cross_product_keeps_all_three_dimensions_and_flags() {
    let declarations = vec![
        declaration(10, None, Some(1), ConsumerLifecycle::Declared),
        declaration(11, None, Some(2), ConsumerLifecycle::Migrated),
        declaration(12, None, Some(9), ConsumerLifecycle::Declared),
        declaration(13, None, Some(5), ConsumerLifecycle::Retired),
    ];
    let identities = vec![
        identity(1),
        identity(2),
        identity(3),
        identity(4),
        identity(5),
    ];
    let grants = vec![grant(21, 1), grant(22, 2), grant(23, 3), grant(24, 5)];
    let observations = vec![observation(4, None, 950, 7)];
    let page = reconcile(
        snapshot(&declarations, &identities, &grants, &observations),
        RESOURCE,
        None,
        100,
    )
    .unwrap();
    assert_eq!(page.cutoff_sequence, 44);
    assert_eq!(page.declared_count, 4);
    assert_eq!(page.authorized_count, 4);
    assert_eq!(page.observed_count, 1);

    let declared = page
        .rows
        .iter()
        .find(|row| row.consumer_id == Some([10; 16]))
        .unwrap();
    assert_eq!(declared.authorization, AuthorizationState::Authorized);
    assert_eq!(
        declared.observation,
        ObservationState::NotObservedCurrentWindow
    );
    assert!(declared.flags.contains(&ActionableFlag::DeclaredUnmigrated));

    let migrated = page
        .rows
        .iter()
        .find(|row| row.consumer_id == Some([11; 16]))
        .unwrap();
    assert!(migrated.flags.contains(&ActionableFlag::MigratedUnobserved));

    let missing = page
        .rows
        .iter()
        .find(|row| row.consumer_id == Some([12; 16]))
        .unwrap();
    assert_eq!(missing.authorization, AuthorizationState::IdentityMissing);
    assert!(
        missing
            .flags
            .contains(&ActionableFlag::DeclaredUnauthorized)
    );

    let retired = page
        .rows
        .iter()
        .find(|row| row.consumer_id == Some([13; 16]))
        .unwrap();
    assert_eq!(retired.registry_lifecycle, RegistryLifecycle::Retired);
    assert!(retired.flags.contains(&ActionableFlag::RetiredHistorical));

    let authorized_only = page
        .rows
        .iter()
        .find(|row| row.identity_id == Some([3; 16]))
        .unwrap();
    assert!(
        authorized_only
            .flags
            .contains(&ActionableFlag::AuthorizedUndeclared)
    );

    let observed_only = page
        .rows
        .iter()
        .find(|row| row.identity_id == Some([4; 16]))
        .unwrap();
    assert!(
        observed_only
            .flags
            .contains(&ActionableFlag::ObservedUndeclared)
    );
    assert_eq!(observed_only.version_served, Some(7));
}

#[test]
fn window_is_inclusive_and_authorized_rows_are_never_filtered() {
    let declarations = vec![declaration(10, None, Some(1), ConsumerLifecycle::Migrated)];
    let identities = vec![identity(1), identity(2)];
    let grants = vec![grant(21, 1), grant(22, 2)];
    for (at, expected) in [(899, false), (900, true), (1_000, true)] {
        let observations = vec![observation(1, None, at, 3)];
        let page = reconcile(
            snapshot(&declarations, &identities, &grants, &observations),
            RESOURCE,
            None,
            100,
        )
        .unwrap();
        let row = page
            .rows
            .iter()
            .find(|row| row.consumer_id == Some([10; 16]))
            .unwrap();
        assert_eq!(
            row.observation == ObservationState::ObservedCurrentWindow,
            expected
        );
        assert!(page.rows.iter().any(|row| row.identity_id == Some([2; 16])));
    }
}

#[test]
fn one_identity_with_disagreeing_instances_stays_separate() {
    let declarations = vec![
        declaration(10, Some(20), Some(1), ConsumerLifecycle::Migrated),
        declaration(10, Some(21), Some(1), ConsumerLifecycle::Migrated),
    ];
    let identities = vec![identity(1)];
    let grants = vec![grant(21, 1)];
    let observations = vec![observation(1, Some(20), 950, 8)];
    let page = reconcile(
        snapshot(&declarations, &identities, &grants, &observations),
        RESOURCE,
        None,
        100,
    )
    .unwrap();
    let observed = page
        .rows
        .iter()
        .find(|row| row.instance_id == Some([20; 16]))
        .unwrap();
    let stale = page
        .rows
        .iter()
        .find(|row| row.instance_id == Some([21; 16]))
        .unwrap();
    assert!(observed.flags.contains(&ActionableFlag::ReconciledObserved));
    assert!(stale.flags.contains(&ActionableFlag::MigratedUnobserved));
}

#[test]
fn disabled_observation_remains_until_aging_out_and_never_becomes_declared() {
    let retired = identity(1).retire(1).unwrap();
    let identities = vec![retired];
    let observations = vec![observation(1, None, 950, 2)];
    let page = reconcile(
        snapshot(&[], &identities, &[], &observations),
        RESOURCE,
        None,
        100,
    )
    .unwrap();
    let row = &page.rows[0];
    assert_eq!(row.registry_lifecycle, RegistryLifecycle::Absent);
    assert_eq!(row.authorization, AuthorizationState::Unauthorized);
    assert!(row.flags.contains(&ActionableFlag::ObservedUndeclared));

    let aged = vec![observation(1, None, 899, 2)];
    let page = reconcile(snapshot(&[], &identities, &[], &aged), RESOURCE, None, 100).unwrap();
    assert!(page.rows.is_empty());
}

#[test]
fn source_or_event_corruption_fails_whole_view() {
    let identities = vec![identity(1)];
    let grants = vec![grant(21, 1)];
    let mut observations = vec![observation(1, None, 950, 2)];
    observations[0].authenticated = false;
    assert_eq!(
        reconcile(
            snapshot(&[], &identities, &grants, &observations),
            RESOURCE,
            None,
            100,
        ),
        Err(ReconciliationError::ObservationIntegrity)
    );
    let mut value = snapshot(&[], &identities, &grants, &[]);
    value.authorization_source_verified = false;
    assert_eq!(
        reconcile(value, RESOURCE, None, 100),
        Err(ReconciliationError::SourceFailure)
    );
}

#[test]
fn ordering_and_cursor_pagination_are_deterministic() {
    let identities = vec![identity(1), identity(2), identity(3)];
    let grants = vec![grant(21, 1), grant(22, 2), grant(23, 3)];
    let first = reconcile(snapshot(&[], &identities, &grants, &[]), RESOURCE, None, 2).unwrap();
    assert_eq!(first.rows.len(), 2);
    let cursor = first.next_cursor.clone().unwrap();
    let second = reconcile(
        snapshot(&[], &identities, &grants, &[]),
        RESOURCE,
        Some(&cursor),
        2,
    )
    .unwrap();
    assert_eq!(second.rows.len(), 1);
    assert!(second.next_cursor.is_none());
    assert!(first.rows[1].key < second.rows[0].key);
}
