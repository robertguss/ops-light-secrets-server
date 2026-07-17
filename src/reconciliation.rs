//! Snapshot-consistent consumer reconciliation over declared, authorized, and observed sets.

use std::collections::{BTreeMap, BTreeSet};

use crate::consumer::ConsumerLifecycle;
use crate::identity::{
    AuthorizationOperation, AuthorizationRequest, AuthorizationResource, Capability, GrantRecord,
    IdentityRecord, IdentityStatus, authorize,
};

pub const MAX_RECONCILIATION_ROWS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredBinding {
    pub consumer_id: [u8; 16],
    pub instance_id: Option<[u8; 16]>,
    pub resource: String,
    pub identity_id: Option<[u8; 16]>,
    pub lifecycle: ConsumerLifecycle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReadObservation {
    pub identity_id: [u8; 16],
    pub consumer_instance_id: Option<[u8; 16]>,
    pub resource: String,
    pub effective_unix_seconds: u64,
    pub version_served: u64,
    pub authenticated: bool,
}

pub struct ReconciliationSnapshot<'a> {
    pub cutoff_sequence: u64,
    pub effective_unix_seconds: u64,
    pub lookback_seconds: u64,
    pub declared_source_verified: bool,
    pub authorization_source_verified: bool,
    pub audit_source_verified: bool,
    pub declarations: &'a [DeclaredBinding],
    pub identities: &'a [IdentityRecord],
    pub grants: &'a [GrantRecord],
    pub observations: &'a [VerifiedReadObservation],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryLifecycle {
    Absent,
    Declared,
    Migrated,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthorizationState {
    Authorized,
    Unauthorized,
    IdentityMissing,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservationState {
    ObservedCurrentWindow,
    NotObservedCurrentWindow,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActionableFlag {
    DeclaredUnmigrated,
    DeclaredUnauthorized,
    AuthorizedUndeclared,
    MigratedUnobserved,
    ObservedUndeclared,
    ReconciledObserved,
    RetiredHistorical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationRow {
    pub key: String,
    pub consumer_id: Option<[u8; 16]>,
    pub instance_id: Option<[u8; 16]>,
    pub identity_id: Option<[u8; 16]>,
    pub registry_lifecycle: RegistryLifecycle,
    pub authorization: AuthorizationState,
    pub observation: ObservationState,
    pub last_read_unix_seconds: Option<u64>,
    pub version_served: Option<u64>,
    pub flags: BTreeSet<ActionableFlag>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationPage {
    pub cutoff_sequence: u64,
    pub declared_count: usize,
    pub authorized_count: usize,
    pub observed_count: usize,
    pub rows: Vec<ReconciliationRow>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationError {
    Invalid,
    SourceFailure,
    ObservationIntegrity,
    Limit,
}

pub fn reconcile(
    snapshot: ReconciliationSnapshot<'_>,
    resource: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<ReconciliationPage, ReconciliationError> {
    if snapshot.cutoff_sequence == 0
        || snapshot.effective_unix_seconds == 0
        || snapshot.lookback_seconds == 0
        || resource.is_empty()
        || limit == 0
        || limit > MAX_RECONCILIATION_ROWS
    {
        return Err(ReconciliationError::Invalid);
    }
    if !(snapshot.declared_source_verified
        && snapshot.authorization_source_verified
        && snapshot.audit_source_verified)
    {
        return Err(ReconciliationError::SourceFailure);
    }
    let window_start = snapshot
        .effective_unix_seconds
        .saturating_sub(snapshot.lookback_seconds);
    if snapshot
        .observations
        .iter()
        .filter(|event| event.resource == resource && event.effective_unix_seconds >= window_start)
        .any(|event| {
            !event.authenticated
                || event.identity_id == [0; 16]
                || event.version_served == 0
                || event.effective_unix_seconds > snapshot.effective_unix_seconds
        })
    {
        return Err(ReconciliationError::ObservationIntegrity);
    }

    let identities: BTreeMap<_, _> = snapshot
        .identities
        .iter()
        .map(|identity| (identity.id, identity))
        .collect();
    if identities.len() != snapshot.identities.len() {
        return Err(ReconciliationError::SourceFailure);
    }
    let authorization_requests = read_requests(resource)?;
    let authorized: BTreeSet<_> = snapshot
        .identities
        .iter()
        .filter(|identity| identity.status == IdentityStatus::Active)
        .filter(|identity| {
            authorization_requests.iter().any(|request| {
                authorize(
                    request,
                    snapshot
                        .grants
                        .iter()
                        .filter(|grant| grant.owner_identity_id == identity.id),
                )
                .allow
            })
        })
        .map(|identity| identity.id)
        .collect();

    let mut observed: BTreeMap<([u8; 16], Option<[u8; 16]>), &VerifiedReadObservation> =
        BTreeMap::new();
    for event in snapshot
        .observations
        .iter()
        .filter(|event| event.resource == resource && event.effective_unix_seconds >= window_start)
    {
        let key = (event.identity_id, event.consumer_instance_id);
        if observed.get(&key).is_none_or(|current| {
            (current.effective_unix_seconds, current.version_served)
                < (event.effective_unix_seconds, event.version_served)
        }) {
            observed.insert(key, event);
        }
    }

    let declarations: Vec<_> = snapshot
        .declarations
        .iter()
        .filter(|row| row.resource == resource)
        .collect();
    let mut rows = Vec::new();
    for declaration in &declarations {
        let lifecycle = registry_lifecycle(declaration.lifecycle);
        let authorization =
            declaration
                .identity_id
                .map_or(AuthorizationState::IdentityMissing, |identity_id| {
                    if !identities.contains_key(&identity_id) {
                        AuthorizationState::IdentityMissing
                    } else if authorized.contains(&identity_id) {
                        AuthorizationState::Authorized
                    } else {
                        AuthorizationState::Unauthorized
                    }
                });
        let event = declaration.identity_id.and_then(|identity_id| {
            observed
                .get(&(identity_id, declaration.instance_id))
                .or_else(|| observed.get(&(identity_id, None)))
                .copied()
        });
        rows.push(build_row(
            Some(declaration.consumer_id),
            declaration.instance_id,
            declaration.identity_id,
            lifecycle,
            authorization,
            event,
        ));
    }

    for identity_id in &authorized {
        let has_active = declarations.iter().any(|declaration| {
            declaration.identity_id == Some(*identity_id)
                && declaration.lifecycle != ConsumerLifecycle::Retired
        });
        if !has_active {
            let event = observed
                .iter()
                .filter(|((identity, _), _)| identity == identity_id)
                .max_by_key(|(_, event)| event.effective_unix_seconds)
                .map(|(_, event)| *event);
            rows.push(build_row(
                None,
                event.and_then(|value| value.consumer_instance_id),
                Some(*identity_id),
                RegistryLifecycle::Absent,
                AuthorizationState::Authorized,
                event,
            ));
        }
    }

    for ((identity_id, instance_id), event) in &observed {
        let has_active = declarations.iter().any(|declaration| {
            declaration.identity_id == Some(*identity_id)
                && declaration.lifecycle != ConsumerLifecycle::Retired
                && (declaration.instance_id == *instance_id || declaration.instance_id.is_none())
        });
        if !has_active
            && !rows.iter().any(|row| {
                row.consumer_id.is_none()
                    && row.identity_id == Some(*identity_id)
                    && row.instance_id == *instance_id
            })
        {
            let authorization = if !identities.contains_key(identity_id) {
                AuthorizationState::IdentityMissing
            } else if authorized.contains(identity_id) {
                AuthorizationState::Authorized
            } else {
                AuthorizationState::Unauthorized
            };
            rows.push(build_row(
                None,
                *instance_id,
                Some(*identity_id),
                RegistryLifecycle::Absent,
                authorization,
                Some(*event),
            ));
        }
    }

    rows.sort_by(|left, right| left.key.cmp(&right.key));
    rows.dedup_by(|left, right| left.key == right.key);
    if rows.len() > MAX_RECONCILIATION_ROWS {
        return Err(ReconciliationError::Limit);
    }
    let declared_count = declarations.len();
    let authorized_count = authorized.len();
    let observed_count = observed.len();
    let mut eligible = rows
        .into_iter()
        .filter(|row| cursor.is_none_or(|cursor| row.key.as_str() > cursor));
    let mut page = eligible.by_ref().take(limit).collect::<Vec<_>>();
    let next_cursor = if eligible.next().is_some() {
        page.last().map(|row| row.key.clone())
    } else {
        None
    };
    Ok(ReconciliationPage {
        cutoff_sequence: snapshot.cutoff_sequence,
        declared_count,
        authorized_count,
        observed_count,
        rows: std::mem::take(&mut page),
        next_cursor,
    })
}

fn build_row(
    consumer_id: Option<[u8; 16]>,
    instance_id: Option<[u8; 16]>,
    identity_id: Option<[u8; 16]>,
    registry_lifecycle: RegistryLifecycle,
    authorization: AuthorizationState,
    event: Option<&VerifiedReadObservation>,
) -> ReconciliationRow {
    let observation = if event.is_some() {
        ObservationState::ObservedCurrentWindow
    } else {
        ObservationState::NotObservedCurrentWindow
    };
    let mut flags = BTreeSet::new();
    if registry_lifecycle == RegistryLifecycle::Declared {
        flags.insert(ActionableFlag::DeclaredUnmigrated);
    }
    if matches!(
        registry_lifecycle,
        RegistryLifecycle::Declared | RegistryLifecycle::Migrated
    ) && authorization != AuthorizationState::Authorized
    {
        flags.insert(ActionableFlag::DeclaredUnauthorized);
    }
    if registry_lifecycle == RegistryLifecycle::Absent
        && authorization == AuthorizationState::Authorized
    {
        flags.insert(ActionableFlag::AuthorizedUndeclared);
    }
    if registry_lifecycle == RegistryLifecycle::Migrated
        && authorization == AuthorizationState::Authorized
        && observation == ObservationState::NotObservedCurrentWindow
    {
        flags.insert(ActionableFlag::MigratedUnobserved);
    }
    if registry_lifecycle == RegistryLifecycle::Absent
        && observation == ObservationState::ObservedCurrentWindow
    {
        flags.insert(ActionableFlag::ObservedUndeclared);
    }
    if registry_lifecycle == RegistryLifecycle::Migrated
        && authorization == AuthorizationState::Authorized
        && observation == ObservationState::ObservedCurrentWindow
    {
        flags.insert(ActionableFlag::ReconciledObserved);
    }
    if registry_lifecycle == RegistryLifecycle::Retired {
        flags.insert(ActionableFlag::RetiredHistorical);
    }
    let key = format!(
        "{}:{}:{}",
        consumer_id.map_or_else(|| "-".into(), encode_id),
        instance_id.map_or_else(|| "-".into(), encode_id),
        identity_id.map_or_else(|| "-".into(), encode_id),
    );
    ReconciliationRow {
        key,
        consumer_id,
        instance_id,
        identity_id,
        registry_lifecycle,
        authorization,
        observation,
        last_read_unix_seconds: event.map(|value| value.effective_unix_seconds),
        version_served: event.map(|value| value.version_served),
        flags,
    }
}

fn registry_lifecycle(value: ConsumerLifecycle) -> RegistryLifecycle {
    match value {
        ConsumerLifecycle::Declared => RegistryLifecycle::Declared,
        ConsumerLifecycle::Migrated => RegistryLifecycle::Migrated,
        ConsumerLifecycle::Retired => RegistryLifecycle::Retired,
    }
}

fn read_requests(resource: &str) -> Result<[AuthorizationRequest; 2], ReconciliationError> {
    let mut segments = resource.split('/');
    let mount = segments.next().ok_or(ReconciliationError::Invalid)?;
    let segments = segments.map(str::to_owned).collect::<Vec<_>>();
    if mount.is_empty() || segments.is_empty() || segments.iter().any(String::is_empty) {
        return Err(ReconciliationError::Invalid);
    }
    let resource = AuthorizationResource {
        mount: mount.to_owned(),
        segments,
    };
    Ok([
        AuthorizationRequest {
            resource: resource.clone(),
            operation: AuthorizationOperation::ReadCurrent,
            capability: Capability::SecretReadCurrent,
        },
        AuthorizationRequest {
            resource,
            operation: AuthorizationOperation::ReadHistory,
            capability: Capability::SecretReadHistory,
        },
    ])
}

fn encode_id(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
