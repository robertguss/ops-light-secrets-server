//! Control-command authorization registry and identity/grant transaction model.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::credential::CredentialAudience;
use crate::identity::{
    AuthorizationDecision, AuthorizationRequest, Capability, DenyReason, GrantRecord, GrantScope,
    GrantStatus, IdentityKind, IdentityRecord, IdentityStatus, authorize,
};

pub const MANAGEMENT_OUTPUT_SCHEMA: u16 = 1;
pub const DEFAULT_PAGE_SIZE: usize = 50;
pub const MAX_PAGE_SIZE: usize = 100;
const MAX_REASON_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CommandPhase {
    Server,
    Local,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ControlCommand {
    IdentityCreate,
    IdentityList,
    IdentityShow,
    IdentityDisable,
    GrantAdd,
    GrantRemove,
    GrantList,
    AuthzExplain,
    CredentialIssue,
    CredentialRevoke,
    CheckpointPrepare,
    CheckpointRegister,
    CheckpointSign,
    SigningTrustEnroll,
    SigningTrustTransition,
    BackupCreate,
    BackupRecipientMutate,
    BackupSignatureRegister,
    BackupAbandon,
    BackupReceiptRegister,
    BackupList,
    BackupShow,
    BackupResume,
    AuditExportCreate,
    AuditExportRecipientMutate,
    AuditExportSignatureRegister,
    AuditExportAbandon,
    AuditExportList,
    AuditExportShow,
    AuditExportResume,
    TlsReload,
    StoreMigratePlan,
    StoreMigrateApply,
    StoreMigrateAbort,
    StoreCompactPlan,
    StoreCompactApply,
    StoreCompactAbort,
    StoreReserveStatus,
    StoreReserveRelease,
    StoreReserveRecreate,
    ConsumerList,
    ConsumerShow,
    ConsumerReconcile,
    ConsumerCreate,
    ConsumerUpdate,
    ConsumerRetire,
    RotationCreate,
    RotationUpdate,
    RotationRetire,
    RotationLifecycle,
    RotationCatalog,
    RotationStatus,
    RotationDue,
    RotationInterval,
    Doctor,
}

impl ControlCommand {
    pub const ALL: [Self; 55] = [
        Self::IdentityCreate,
        Self::IdentityList,
        Self::IdentityShow,
        Self::IdentityDisable,
        Self::GrantAdd,
        Self::GrantRemove,
        Self::GrantList,
        Self::AuthzExplain,
        Self::CredentialIssue,
        Self::CredentialRevoke,
        Self::CheckpointPrepare,
        Self::CheckpointRegister,
        Self::CheckpointSign,
        Self::SigningTrustEnroll,
        Self::SigningTrustTransition,
        Self::BackupCreate,
        Self::BackupRecipientMutate,
        Self::BackupSignatureRegister,
        Self::BackupAbandon,
        Self::BackupReceiptRegister,
        Self::BackupList,
        Self::BackupShow,
        Self::BackupResume,
        Self::AuditExportCreate,
        Self::AuditExportRecipientMutate,
        Self::AuditExportSignatureRegister,
        Self::AuditExportAbandon,
        Self::AuditExportList,
        Self::AuditExportShow,
        Self::AuditExportResume,
        Self::TlsReload,
        Self::StoreMigratePlan,
        Self::StoreMigrateApply,
        Self::StoreMigrateAbort,
        Self::StoreCompactPlan,
        Self::StoreCompactApply,
        Self::StoreCompactAbort,
        Self::StoreReserveStatus,
        Self::StoreReserveRelease,
        Self::StoreReserveRecreate,
        Self::ConsumerList,
        Self::ConsumerShow,
        Self::ConsumerReconcile,
        Self::ConsumerCreate,
        Self::ConsumerUpdate,
        Self::ConsumerRetire,
        Self::RotationCreate,
        Self::RotationUpdate,
        Self::RotationRetire,
        Self::RotationLifecycle,
        Self::RotationCatalog,
        Self::RotationStatus,
        Self::RotationDue,
        Self::RotationInterval,
        Self::Doctor,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandAuthorization {
    pub command: ControlCommand,
    pub phase: CommandPhase,
    pub capability: Option<Capability>,
}

pub fn command_authorization(command: ControlCommand) -> CommandAuthorization {
    use Capability as C;
    use ControlCommand as O;
    let (phase, capability) = match command {
        O::CheckpointSign => (CommandPhase::Local, None),
        O::IdentityCreate
        | O::IdentityList
        | O::IdentityShow
        | O::IdentityDisable
        | O::GrantAdd
        | O::GrantRemove
        | O::GrantList => (CommandPhase::Server, Some(C::IdentityGrantManage)),
        O::AuthzExplain | O::StoreMigratePlan | O::StoreCompactPlan | O::Doctor => {
            (CommandPhase::Server, Some(C::Diagnostics))
        }
        O::CredentialIssue => (CommandPhase::Server, Some(C::CredentialIssue)),
        O::CredentialRevoke => (CommandPhase::Server, Some(C::CredentialRevoke)),
        O::CheckpointPrepare
        | O::CheckpointRegister
        | O::SigningTrustEnroll
        | O::SigningTrustTransition => (CommandPhase::Server, Some(C::AuditCheckpointManage)),
        O::BackupCreate
        | O::BackupSignatureRegister
        | O::BackupAbandon
        | O::BackupReceiptRegister
        | O::BackupList
        | O::BackupShow
        | O::BackupResume => (CommandPhase::Server, Some(C::Backup)),
        O::BackupRecipientMutate => (CommandPhase::Server, Some(C::BackupRecipientManage)),
        O::AuditExportCreate
        | O::AuditExportSignatureRegister
        | O::AuditExportAbandon
        | O::AuditExportList
        | O::AuditExportShow
        | O::AuditExportResume => (CommandPhase::Server, Some(C::AuditExport)),
        O::AuditExportRecipientMutate => {
            (CommandPhase::Server, Some(C::AuditExportRecipientManage))
        }
        O::TlsReload => (CommandPhase::Server, Some(C::TransportManage)),
        O::StoreMigrateApply
        | O::StoreMigrateAbort
        | O::StoreCompactApply
        | O::StoreCompactAbort
        | O::StoreReserveStatus
        | O::StoreReserveRelease
        | O::StoreReserveRecreate => (CommandPhase::Server, Some(C::StoreMaintenance)),
        O::ConsumerList | O::ConsumerShow | O::ConsumerReconcile => {
            (CommandPhase::Server, Some(C::ConsumerEnumerate))
        }
        O::ConsumerCreate
        | O::ConsumerUpdate
        | O::ConsumerRetire
        | O::RotationCreate
        | O::RotationUpdate
        | O::RotationRetire
        | O::RotationLifecycle
        | O::RotationCatalog
        | O::RotationStatus
        | O::RotationDue
        | O::RotationInterval => (CommandPhase::Server, Some(C::RotationManage)),
    };
    CommandAuthorization {
        command,
        phase,
        capability,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementPrincipal {
    pub identity_id: [u8; 16],
    pub audience: CredentialAudience,
    pub peer_uid: u32,
    pub expected_uid: u32,
    pub credential_active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagementError {
    Denied,
    Invalid,
    Conflict,
    NotFound,
    StaleGeneration,
    Limit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityView {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub status: &'static str,
    pub generation: u64,
}

impl From<&IdentityRecord> for IdentityView {
    fn from(value: &IdentityRecord) -> Self {
        Self {
            id: encode_id(value.id),
            name: value.name.clone(),
            kind: match value.kind {
                IdentityKind::Human => "human",
                IdentityKind::Workload => "workload",
            },
            status: match value.status {
                IdentityStatus::Active => "active",
                IdentityStatus::Retired => "disabled",
            },
            generation: value.generation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GrantView {
    pub id: String,
    pub owner_identity_id: String,
    pub generation: u64,
    pub status: &'static str,
    pub mount: String,
    pub scope: &'static str,
    pub prefix_segments: Vec<String>,
    pub capabilities: Vec<u16>,
}

impl From<&GrantRecord> for GrantView {
    fn from(value: &GrantRecord) -> Self {
        Self {
            id: encode_id(value.id),
            owner_identity_id: encode_id(value.owner_identity_id),
            generation: value.generation,
            status: match value.status {
                GrantStatus::Active => "active",
                GrantStatus::Removed => "removed",
            },
            mount: value.mount.clone(),
            scope: match value.scope {
                GrantScope::Exact => "exact",
                GrantScope::Subtree => "subtree",
            },
            prefix_segments: value.prefix_segments.clone(),
            capabilities: value
                .capabilities
                .iter()
                .map(|value| *value as u16)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Page<T> {
    pub schema: u16,
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExplainView {
    pub schema: u16,
    pub allow: bool,
    pub resource_mount: String,
    pub resource_segments: Vec<String>,
    pub operation: &'static str,
    pub matched_grant: Option<String>,
    pub deny_reason: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementAudit {
    pub request_id: [u8; 16],
    pub actor_identity_id: [u8; 16],
    pub command: ControlCommand,
    pub allowed: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisableResult {
    pub identity: IdentityView,
    pub affected_grant_count: u64,
    pub affected_credential_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementCatalog {
    identities: BTreeMap<[u8; 16], IdentityRecord>,
    grants: BTreeMap<[u8; 16], GrantRecord>,
    completed_requests: BTreeMap<[u8; 16], (ControlCommand, [u8; 16])>,
    audit: Vec<ManagementAudit>,
}

impl ManagementCatalog {
    pub fn new(
        identities: impl IntoIterator<Item = IdentityRecord>,
        grants: impl IntoIterator<Item = GrantRecord>,
    ) -> Result<Self, ManagementError> {
        let mut identities_by_id = BTreeMap::new();
        for row in identities {
            if identities_by_id.insert(row.id, row).is_some() {
                return Err(ManagementError::Conflict);
            }
        }
        let mut grants_by_id = BTreeMap::new();
        for row in grants {
            if grants_by_id.insert(row.id, row).is_some() {
                return Err(ManagementError::Conflict);
            }
        }
        let value = Self {
            identities: identities_by_id,
            grants: grants_by_id,
            completed_requests: BTreeMap::new(),
            audit: Vec::new(),
        };
        crate::identity::validate_catalog(
            &value.identities.values().cloned().collect::<Vec<_>>(),
            &value.grants.values().cloned().collect::<Vec<_>>(),
        )
        .map_err(|_| ManagementError::Invalid)?;
        Ok(value)
    }

    pub fn audit(&self) -> &[ManagementAudit] {
        &self.audit
    }

    pub fn authorize_command(
        &mut self,
        principal: ManagementPrincipal,
        command: ControlCommand,
        request_id: [u8; 16],
    ) -> Result<(), ManagementError> {
        let mapping = command_authorization(command);
        let allowed = mapping.phase == CommandPhase::Server
            && principal.audience == CredentialAudience::Control
            && principal.peer_uid == principal.expected_uid
            && principal.credential_active
            && self
                .identities
                .get(&principal.identity_id)
                .is_some_and(|identity| identity.status == IdentityStatus::Active)
            && mapping.capability.is_some_and(|capability| {
                authorize(
                    &AuthorizationRequest::management(capability)
                        .expect("registry contains management capability"),
                    self.grants
                        .values()
                        .filter(|grant| grant.owner_identity_id == principal.identity_id),
                )
                .allow
            });
        if !allowed {
            self.audit.push(ManagementAudit {
                request_id,
                actor_identity_id: principal.identity_id,
                command,
                allowed: false,
                reason: None,
            });
            return Err(ManagementError::Denied);
        }
        Ok(())
    }

    pub fn create_identity(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        name: String,
        kind: IdentityKind,
    ) -> Result<IdentityView, ManagementError> {
        self.authorize_command(principal, ControlCommand::IdentityCreate, request_id)?;
        if self.completed(request_id, ControlCommand::IdentityCreate, id)? {
            return self
                .identities
                .get(&id)
                .map(IdentityView::from)
                .ok_or(ManagementError::Conflict);
        }
        if id == [0; 16]
            || self.identities.contains_key(&id)
            || self
                .identities
                .values()
                .any(|identity| identity.name == name)
        {
            return self.fail(
                principal,
                request_id,
                ControlCommand::IdentityCreate,
                ManagementError::Conflict,
            );
        }
        let identity = IdentityRecord::new(id, name, kind).map_err(|_| ManagementError::Invalid)?;
        self.identities.insert(id, identity);
        self.succeed(
            principal,
            request_id,
            ControlCommand::IdentityCreate,
            id,
            None,
        );
        Ok(IdentityView::from(
            self.identities.get(&id).expect("inserted"),
        ))
    }

    pub fn disable_identity(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        reason: String,
    ) -> Result<DisableResult, ManagementError> {
        self.authorize_command(principal, ControlCommand::IdentityDisable, request_id)?;
        if valid_reason(&reason).is_err() {
            return self.fail(
                principal,
                request_id,
                ControlCommand::IdentityDisable,
                ManagementError::Invalid,
            );
        }
        if self.completed(request_id, ControlCommand::IdentityDisable, id)? {
            let identity = self.identities.get(&id).ok_or(ManagementError::Conflict)?;
            return Ok(self.disable_result(identity));
        }
        let replacement = match self.identities.get(&id) {
            Some(identity) => match identity.retire(expected_generation) {
                Ok(replacement) => replacement,
                Err(_) => {
                    return self.fail(
                        principal,
                        request_id,
                        ControlCommand::IdentityDisable,
                        ManagementError::StaleGeneration,
                    );
                }
            },
            None => {
                return self.fail(
                    principal,
                    request_id,
                    ControlCommand::IdentityDisable,
                    ManagementError::NotFound,
                );
            }
        };
        self.identities.insert(id, replacement);
        self.succeed(
            principal,
            request_id,
            ControlCommand::IdentityDisable,
            id,
            Some(reason),
        );
        Ok(self.disable_result(self.identities.get(&id).expect("replaced")))
    }

    pub fn add_grant(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        grant: GrantRecord,
    ) -> Result<GrantView, ManagementError> {
        self.authorize_command(principal, ControlCommand::GrantAdd, request_id)?;
        if self.completed(request_id, ControlCommand::GrantAdd, grant.id)? {
            return self
                .grants
                .get(&grant.id)
                .map(GrantView::from)
                .ok_or(ManagementError::Conflict);
        }
        if !self.identities.contains_key(&grant.owner_identity_id)
            || self.grants.contains_key(&grant.id)
            || self.grants.values().any(|current| {
                current.status == GrantStatus::Active
                    && current.owner_identity_id == grant.owner_identity_id
                    && current.mount == grant.mount
                    && current.scope == grant.scope
                    && current.prefix_segments == grant.prefix_segments
                    && current.capabilities == grant.capabilities
            })
        {
            return self.fail(
                principal,
                request_id,
                ControlCommand::GrantAdd,
                ManagementError::Conflict,
            );
        }
        if grant.validate().is_err() {
            return self.fail(
                principal,
                request_id,
                ControlCommand::GrantAdd,
                ManagementError::Invalid,
            );
        }
        let id = grant.id;
        self.grants.insert(id, grant);
        self.succeed(principal, request_id, ControlCommand::GrantAdd, id, None);
        Ok(GrantView::from(self.grants.get(&id).expect("inserted")))
    }

    pub fn remove_grant(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
        expected_generation: u64,
        reason: String,
    ) -> Result<GrantView, ManagementError> {
        self.authorize_command(principal, ControlCommand::GrantRemove, request_id)?;
        if valid_reason(&reason).is_err() {
            return self.fail(
                principal,
                request_id,
                ControlCommand::GrantRemove,
                ManagementError::Invalid,
            );
        }
        if self.completed(request_id, ControlCommand::GrantRemove, id)? {
            return self
                .grants
                .get(&id)
                .map(GrantView::from)
                .ok_or(ManagementError::Conflict);
        }
        let replacement = match self.grants.get(&id) {
            Some(current) => match current.remove(current.owner_identity_id, expected_generation) {
                Ok(replacement) => replacement,
                Err(_) => {
                    return self.fail(
                        principal,
                        request_id,
                        ControlCommand::GrantRemove,
                        ManagementError::StaleGeneration,
                    );
                }
            },
            None => {
                return self.fail(
                    principal,
                    request_id,
                    ControlCommand::GrantRemove,
                    ManagementError::NotFound,
                );
            }
        };
        self.grants.insert(id, replacement);
        self.succeed(
            principal,
            request_id,
            ControlCommand::GrantRemove,
            id,
            Some(reason),
        );
        Ok(GrantView::from(self.grants.get(&id).expect("replaced")))
    }

    pub fn list_identities(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        cursor: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<Page<IdentityView>, ManagementError> {
        self.authorize_command(principal, ControlCommand::IdentityList, request_id)?;
        let result = page(self.identities.iter(), cursor, limit, |(_, value)| {
            IdentityView::from(value)
        });
        match result {
            Ok(value) => {
                self.succeed(
                    principal,
                    request_id,
                    ControlCommand::IdentityList,
                    cursor.unwrap_or([0; 16]),
                    None,
                );
                Ok(value)
            }
            Err(error) => self.fail(principal, request_id, ControlCommand::IdentityList, error),
        }
    }

    pub fn show_identity(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        id: [u8; 16],
    ) -> Result<IdentityView, ManagementError> {
        self.authorize_command(principal, ControlCommand::IdentityShow, request_id)?;
        let result = self
            .identities
            .get(&id)
            .map(IdentityView::from)
            .ok_or(ManagementError::NotFound);
        match result {
            Ok(value) => {
                self.succeed(
                    principal,
                    request_id,
                    ControlCommand::IdentityShow,
                    id,
                    None,
                );
                Ok(value)
            }
            Err(error) => self.fail(principal, request_id, ControlCommand::IdentityShow, error),
        }
    }

    pub fn list_grants(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        owner: [u8; 16],
        cursor: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<Page<GrantView>, ManagementError> {
        self.authorize_command(principal, ControlCommand::GrantList, request_id)?;
        let result = page(
            self.grants
                .iter()
                .filter(|(_, value)| value.owner_identity_id == owner),
            cursor,
            limit,
            |(_, value)| GrantView::from(value),
        );
        match result {
            Ok(value) => {
                self.succeed(
                    principal,
                    request_id,
                    ControlCommand::GrantList,
                    owner,
                    None,
                );
                Ok(value)
            }
            Err(error) => self.fail(principal, request_id, ControlCommand::GrantList, error),
        }
    }

    pub fn explain(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        identity_id: [u8; 16],
        request: &AuthorizationRequest,
    ) -> Result<ExplainView, ManagementError> {
        self.authorize_command(principal, ControlCommand::AuthzExplain, request_id)?;
        let identity = match self.identities.get(&identity_id) {
            Some(identity) => identity,
            None => {
                return self.fail(
                    principal,
                    request_id,
                    ControlCommand::AuthzExplain,
                    ManagementError::NotFound,
                );
            }
        };
        let decision = if identity.status == IdentityStatus::Active {
            authorize(
                request,
                self.grants
                    .values()
                    .filter(|grant| grant.owner_identity_id == identity_id),
            )
        } else {
            AuthorizationDecision {
                allow: false,
                resource: request.resource.clone(),
                operation: request.operation,
                matched_grant: None,
                deny_reason: Some(DenyReason::NoGrantForMount),
            }
        };
        let view = ExplainView {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            allow: decision.allow,
            resource_mount: decision.resource.mount,
            resource_segments: decision.resource.segments,
            operation: match decision.operation {
                crate::identity::AuthorizationOperation::ReadCurrent => "read-current",
                crate::identity::AuthorizationOperation::ReadHistory => "read-history",
                crate::identity::AuthorizationOperation::List => "list",
                crate::identity::AuthorizationOperation::Write => "write",
                crate::identity::AuthorizationOperation::SoftDelete => "soft-delete",
                crate::identity::AuthorizationOperation::Undelete => "undelete",
                crate::identity::AuthorizationOperation::Destroy => "destroy",
                crate::identity::AuthorizationOperation::DestroyAll => "destroy-all",
                crate::identity::AuthorizationOperation::Management => "management",
            },
            matched_grant: decision.matched_grant.map(encode_id),
            deny_reason: decision.deny_reason.map(|reason| match reason {
                DenyReason::NoGrantForMount => "no-grant-for-mount",
                DenyReason::PrefixBoundaryMiss => "prefix-boundary-miss",
                DenyReason::MissingCapability => "missing-capability",
            }),
        };
        self.succeed(
            principal,
            request_id,
            ControlCommand::AuthzExplain,
            identity_id,
            None,
        );
        Ok(view)
    }

    fn completed(
        &self,
        request_id: [u8; 16],
        command: ControlCommand,
        target: [u8; 16],
    ) -> Result<bool, ManagementError> {
        match self.completed_requests.get(&request_id) {
            Some(previous) if *previous == (command, target) => Ok(true),
            Some(_) => Err(ManagementError::Conflict),
            None => Ok(false),
        }
    }

    fn succeed(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        command: ControlCommand,
        target: [u8; 16],
        reason: Option<String>,
    ) {
        self.completed_requests
            .insert(request_id, (command, target));
        self.audit.push(ManagementAudit {
            request_id,
            actor_identity_id: principal.identity_id,
            command,
            allowed: true,
            reason,
        });
    }

    fn fail<T>(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        command: ControlCommand,
        error: ManagementError,
    ) -> Result<T, ManagementError> {
        self.audit.push(ManagementAudit {
            request_id,
            actor_identity_id: principal.identity_id,
            command,
            allowed: true,
            reason: None,
        });
        Err(error)
    }

    fn disable_result(&self, identity: &IdentityRecord) -> DisableResult {
        DisableResult {
            identity: IdentityView::from(identity),
            affected_grant_count: self
                .grants
                .values()
                .filter(|grant| {
                    grant.owner_identity_id == identity.id && grant.status == GrantStatus::Active
                })
                .count() as u64,
            affected_credential_count: 0,
        }
    }
}

fn valid_reason(reason: &str) -> Result<(), ManagementError> {
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.chars().any(char::is_control)
    {
        return Err(ManagementError::Invalid);
    }
    Ok(())
}

fn page<'a, I, V, F>(
    values: I,
    cursor: Option<[u8; 16]>,
    limit: usize,
    render: F,
) -> Result<Page<V>, ManagementError>
where
    I: IntoIterator<Item = (&'a [u8; 16], &'a V::Source)>,
    V: PageValue + 'a,
    F: Fn((&'a [u8; 16], &'a V::Source)) -> V,
{
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(ManagementError::Limit);
    }
    let mut eligible = values
        .into_iter()
        .filter(|(id, _)| cursor.is_none_or(|cursor| **id > cursor));
    let mut items = Vec::with_capacity(limit);
    let mut last = None;
    for value in eligible.by_ref().take(limit) {
        last = Some(*value.0);
        items.push(render(value));
    }
    let next_cursor = if eligible.next().is_some() {
        last.map(encode_id)
    } else {
        None
    };
    Ok(Page {
        schema: MANAGEMENT_OUTPUT_SCHEMA,
        items,
        next_cursor,
    })
}

trait PageValue {
    type Source;
}

impl PageValue for IdentityView {
    type Source = IdentityRecord;
}

impl PageValue for GrantView {
    type Source = GrantRecord;
}

fn encode_id(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
