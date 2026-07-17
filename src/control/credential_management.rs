//! Owner-only credential lifecycle transaction model.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::auth::{AppRoleRecord, AppRoleStatus, AuthCatalog, AuthError};
use crate::control::management::{
    ControlCommand, MANAGEMENT_OUTPUT_SCHEMA, MAX_PAGE_SIZE, ManagementCatalog, ManagementError,
    ManagementPrincipal,
};
use crate::credential::{
    CredentialAccessor, CredentialAudience, CredentialIssueMetadata, CredentialKind,
    DIRECT_TOKEN_MAX_TTL_SECONDS, DIRECT_TOKEN_MIN_TTL_SECONDS, IssuedCredential,
    SECRET_ID_MAX_TTL_SECONDS, SECRET_ID_MIN_TTL_SECONDS, issue_credential,
    validate_secret_id_uses, validate_ttl,
};
use crate::identity::{Capability, IdentityKind, TokenStatus};
use crate::store::keyring::RandomSource;

const MAX_LABEL_BYTES: usize = 255;
const MAX_REASON_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialView {
    pub schema: u16,
    pub accessor: String,
    pub id: String,
    pub label: String,
    pub kind: &'static str,
    pub audience: &'static str,
    pub identity_id: String,
    pub status: &'static str,
    pub generation: u64,
    pub created_at_effective_seconds: u64,
    pub expires_at_effective_seconds: u64,
    pub consumer_instance_id: Option<String>,
    pub remaining_uses: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoleView {
    pub schema: u16,
    pub id: String,
    pub role_id: String,
    pub name: String,
    pub identity_id: String,
    pub token_ttl_seconds: u64,
    pub status: &'static str,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialPage {
    pub schema: u16,
    pub items: Vec<CredentialView>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RolePage {
    pub schema: u16,
    pub items: Vec<RoleView>,
    pub next_cursor: Option<String>,
}

pub enum IssueResult {
    Disclosed(IssuedCredential),
    Existing(CredentialView),
}

pub struct CredentialManagementCatalog<R> {
    authorization: ManagementCatalog,
    auth: AuthCatalog,
    random: R,
    role_requests: BTreeMap<[u8; 16], [u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenIssueRequest {
    pub request_id: [u8; 16],
    pub id: [u8; 16],
    pub identity_id: [u8; 16],
    pub audience: CredentialAudience,
    pub ttl_seconds: u64,
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretIdIssueRequest {
    pub request_id: [u8; 16],
    pub id: [u8; 16],
    pub role_id: String,
    pub ttl_seconds: u64,
    pub use_count: u32,
    pub consumer_instance_id: Option<[u8; 16]>,
    pub identity_only_tracking_accepted: bool,
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDeleteRequest {
    pub request_id: [u8; 16],
    pub role_id: String,
    pub expected_generation: u64,
    pub invalidated_count: usize,
    pub reason: String,
    pub confirmation: String,
}

impl<R: RandomSource> CredentialManagementCatalog<R> {
    pub fn new(authorization: ManagementCatalog, auth: AuthCatalog, random: R) -> Self {
        Self {
            authorization,
            auth,
            random,
            role_requests: BTreeMap::new(),
        }
    }

    pub fn auth(&self) -> &AuthCatalog {
        &self.auth
    }

    pub fn auth_mut(&mut self) -> &mut AuthCatalog {
        &mut self.auth
    }

    pub fn management_audit(&self) -> &[crate::control::management::ManagementAudit] {
        self.authorization.audit()
    }

    pub fn token_issue(
        &mut self,
        principal: ManagementPrincipal,
        request: TokenIssueRequest,
    ) -> Result<IssueResult, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialIssue,
            request.request_id,
        )?;
        self.check_target(principal, request.identity_id, request.audience)?;
        validate_ttl(
            request.ttl_seconds,
            DIRECT_TOKEN_MIN_TTL_SECONDS,
            DIRECT_TOKEN_MAX_TTL_SECONDS,
        )
        .map_err(|_| ManagementError::Invalid)?;
        validate_label(&request.label)?;
        self.authorization.command_request_completed(
            request.request_id,
            ControlCommand::CredentialIssue,
            request.id,
        )?;
        if let Some(existing) = self.auth.credential_by_request(request.request_id) {
            return Ok(IssueResult::Existing(self.credential_view(existing)));
        }
        let expires = self
            .auth
            .effective_seconds()
            .checked_add(request.ttl_seconds)
            .ok_or(ManagementError::Invalid)?;
        let metadata = CredentialIssueMetadata {
            id: request.id,
            identity_id: request.identity_id,
            kind: CredentialKind::Token,
            audience: request.audience,
            issue_epoch: self.auth.current_epoch(),
            expires_at_effective_seconds: expires,
            created_at_effective_seconds: self.auth.effective_seconds(),
            issuer_identity_id: principal.identity_id,
            issuance_request_id: request.request_id,
            parent_accessor: None,
            consumer_instance_id: None,
        };
        let mut exists = |accessor| self.auth.credential(accessor).is_some();
        let issued = issue_credential(
            self.auth.verifier_key(),
            self.auth.store_id(),
            metadata,
            request.label,
            &mut exists,
            &mut self.random,
        )
        .map_err(|_| ManagementError::Invalid)?;
        self.auth
            .insert_token(issued.record.clone())
            .map_err(map_auth)?;
        self.authorization.record_command_success(
            principal,
            request.request_id,
            ControlCommand::CredentialIssue,
            request.id,
            None,
        )?;
        Ok(IssueResult::Disclosed(issued))
    }

    pub fn token_list(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        cursor: Option<CredentialAccessor>,
        limit: usize,
    ) -> Result<CredentialPage, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialRevoke,
            request_id,
        )?;
        self.credential_page(CredentialKind::Token, None, cursor, limit)
    }

    pub fn credential_revoke(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        accessor: CredentialAccessor,
        reason: &str,
    ) -> Result<CredentialView, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialRevoke,
            request_id,
        )?;
        validate_reason(reason)?;
        let current = self
            .auth
            .credential(accessor)
            .cloned()
            .ok_or(ManagementError::NotFound)?;
        if self.authorization.command_request_completed(
            request_id,
            ControlCommand::CredentialRevoke,
            current.id,
        )? {
            return Ok(self.credential_view(&current));
        }
        if current.status == TokenStatus::Active {
            let replacement = current
                .revoke(current.generation)
                .map_err(|_| ManagementError::Conflict)?;
            self.auth
                .replace_credential(replacement)
                .map_err(map_auth)?;
        }
        self.authorization.record_command_success(
            principal,
            request_id,
            ControlCommand::CredentialRevoke,
            current.id,
            Some(reason.to_owned()),
        )?;
        Ok(self.credential_view(self.auth.credential(accessor).expect("credential retained")))
    }

    pub fn role_create(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        role: AppRoleRecord,
    ) -> Result<RoleView, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialIssue,
            request_id,
        )?;
        self.check_target(principal, role.identity_id, CredentialAudience::Data)?;
        self.authorization.command_request_completed(
            request_id,
            ControlCommand::CredentialIssue,
            role.id,
        )?;
        if let Some(id) = self.role_requests.get(&request_id) {
            return self
                .auth
                .roles()
                .find(|role| &role.id == id)
                .map(role_view)
                .ok_or(ManagementError::Conflict);
        }
        let id = role.id;
        self.auth.insert_role(role).map_err(map_auth)?;
        self.role_requests.insert(request_id, id);
        self.authorization.record_command_success(
            principal,
            request_id,
            ControlCommand::CredentialIssue,
            id,
            None,
        )?;
        Ok(role_view(
            self.auth
                .roles()
                .find(|role| role.id == id)
                .expect("inserted role"),
        ))
    }

    pub fn role_list(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        cursor: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<RolePage, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialRevoke,
            request_id,
        )?;
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(ManagementError::Limit);
        }
        let mut values = self
            .auth
            .roles()
            .filter(|role| cursor.is_none_or(|cursor| role.id > cursor))
            .collect::<Vec<_>>();
        values.sort_by_key(|role| role.id);
        let has_more = values.len() > limit;
        values.truncate(limit);
        let next_cursor = has_more.then(|| encode_id(values.last().expect("nonempty").id));
        Ok(RolePage {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            items: values.into_iter().map(role_view).collect(),
            next_cursor,
        })
    }

    pub fn role_delete_confirmation(
        role_id: &str,
        generation: u64,
        invalidated_count: usize,
        reason: &str,
    ) -> String {
        let mut digest = blake3::Hasher::new();
        digest.update(b"ops-light-secrets-server.approle-delete.v1\0");
        for field in [
            role_id.as_bytes(),
            &generation.to_be_bytes(),
            &(invalidated_count as u64).to_be_bytes(),
            reason.as_bytes(),
        ] {
            digest.update(&(field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        digest.finalize().to_hex().to_string()
    }

    pub fn role_delete(
        &mut self,
        principal: ManagementPrincipal,
        request: RoleDeleteRequest,
    ) -> Result<RoleView, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialRevoke,
            request.request_id,
        )?;
        validate_reason(&request.reason)?;
        let role = self
            .auth
            .role(&request.role_id)
            .cloned()
            .ok_or(ManagementError::NotFound)?;
        if self.authorization.command_request_completed(
            request.request_id,
            ControlCommand::CredentialRevoke,
            role.id,
        )? {
            return Ok(role_view(&role));
        }
        let actual_count = self
            .auth
            .credentials()
            .filter(|credential| {
                credential.kind == CredentialKind::SecretId
                    && credential.status == TokenStatus::Active
                    && self
                        .auth
                        .usage(credential.accessor)
                        .is_some_and(|usage| usage.role_id == role.id)
            })
            .count();
        if role.status == AppRoleStatus::Deleted {
            return Ok(role_view(&role));
        }
        if request.expected_generation != role.generation
            || request.invalidated_count != actual_count
            || request.confirmation
                != Self::role_delete_confirmation(
                    &request.role_id,
                    request.expected_generation,
                    request.invalidated_count,
                    &request.reason,
                )
        {
            return Err(ManagementError::StaleGeneration);
        }
        self.auth
            .delete_role(&request.role_id, request.expected_generation)
            .map_err(map_auth)?;
        self.auth
            .remove_secret_ids_for_role(role.id)
            .map_err(map_auth)?;
        self.authorization.record_command_success(
            principal,
            request.request_id,
            ControlCommand::CredentialRevoke,
            role.id,
            Some(request.reason.clone()),
        )?;
        Ok(role_view(
            self.auth.role(&request.role_id).expect("role retained"),
        ))
    }

    pub fn secret_id_issue(
        &mut self,
        principal: ManagementPrincipal,
        request: SecretIdIssueRequest,
    ) -> Result<IssueResult, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialIssue,
            request.request_id,
        )?;
        validate_ttl(
            request.ttl_seconds,
            SECRET_ID_MIN_TTL_SECONDS,
            SECRET_ID_MAX_TTL_SECONDS,
        )
        .map_err(|_| ManagementError::Invalid)?;
        validate_secret_id_uses(request.use_count).map_err(|_| ManagementError::Invalid)?;
        validate_label(&request.label)?;
        let tracked = CredentialIssueMetadata::require_workload_tracking(
            request.consumer_instance_id,
            request.identity_only_tracking_accepted,
        )
        .map_err(|_| ManagementError::Invalid)?;
        let role = self
            .auth
            .role(&request.role_id)
            .filter(|role| role.status == AppRoleStatus::Active)
            .cloned()
            .ok_or(ManagementError::NotFound)?;
        self.check_target(principal, role.identity_id, CredentialAudience::Data)?;
        self.authorization.command_request_completed(
            request.request_id,
            ControlCommand::CredentialIssue,
            request.id,
        )?;
        if let Some(existing) = self.auth.credential_by_request(request.request_id) {
            return Ok(IssueResult::Existing(self.credential_view(existing)));
        }
        let metadata = CredentialIssueMetadata {
            id: request.id,
            identity_id: role.identity_id,
            kind: CredentialKind::SecretId,
            audience: CredentialAudience::Data,
            issue_epoch: self.auth.current_epoch(),
            expires_at_effective_seconds: self
                .auth
                .effective_seconds()
                .checked_add(request.ttl_seconds)
                .ok_or(ManagementError::Invalid)?,
            created_at_effective_seconds: self.auth.effective_seconds(),
            issuer_identity_id: principal.identity_id,
            issuance_request_id: request.request_id,
            parent_accessor: None,
            consumer_instance_id: tracked,
        };
        let mut exists = |accessor| self.auth.credential(accessor).is_some();
        let issued = issue_credential(
            self.auth.verifier_key(),
            self.auth.store_id(),
            metadata,
            request.label,
            &mut exists,
            &mut self.random,
        )
        .map_err(|_| ManagementError::Invalid)?;
        self.auth
            .insert_secret_id(role.id, issued.record.clone(), request.use_count)
            .map_err(map_auth)?;
        self.authorization.record_command_success(
            principal,
            request.request_id,
            ControlCommand::CredentialIssue,
            request.id,
            None,
        )?;
        Ok(IssueResult::Disclosed(issued))
    }

    pub fn secret_id_list(
        &mut self,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        role_id: &str,
        cursor: Option<CredentialAccessor>,
        limit: usize,
    ) -> Result<CredentialPage, ManagementError> {
        self.authorization.authorize_command(
            principal,
            ControlCommand::CredentialRevoke,
            request_id,
        )?;
        let role = self.auth.role(role_id).ok_or(ManagementError::NotFound)?;
        self.credential_page(CredentialKind::SecretId, Some(role.id), cursor, limit)
    }

    fn credential_page(
        &self,
        kind: CredentialKind,
        role: Option<[u8; 16]>,
        cursor: Option<CredentialAccessor>,
        limit: usize,
    ) -> Result<CredentialPage, ManagementError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(ManagementError::Limit);
        }
        let mut values = self
            .auth
            .credentials()
            .filter(|credential| {
                credential.kind == kind
                    && cursor.is_none_or(|cursor| credential.accessor > cursor)
                    && role.is_none_or(|role| {
                        self.auth
                            .usage(credential.accessor)
                            .is_some_and(|usage| usage.role_id == role)
                    })
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|credential| credential.accessor);
        let has_more = values.len() > limit;
        values.truncate(limit);
        let next_cursor = has_more.then(|| values.last().expect("nonempty").accessor.encode());
        Ok(CredentialPage {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            items: values
                .into_iter()
                .map(|credential| self.credential_view(credential))
                .collect(),
            next_cursor,
        })
    }

    fn credential_view(&self, value: &crate::credential::CredentialRecord) -> CredentialView {
        CredentialView {
            schema: MANAGEMENT_OUTPUT_SCHEMA,
            accessor: value.accessor.encode(),
            id: encode_id(value.id),
            label: value.label.clone(),
            kind: value.kind.label(),
            audience: value.audience.label(),
            identity_id: encode_id(value.identity_id),
            status: match value.status {
                TokenStatus::Active => "active",
                TokenStatus::Revoked => "revoked",
            },
            generation: value.generation,
            created_at_effective_seconds: value.created_at_effective_seconds,
            expires_at_effective_seconds: value.expires_at_effective_seconds,
            consumer_instance_id: value.consumer_instance_id.map(encode_id),
            remaining_uses: self
                .auth
                .usage(value.accessor)
                .map(|usage| usage.remaining_uses),
        }
    }

    fn check_target(
        &self,
        principal: ManagementPrincipal,
        target: [u8; 16],
        audience: CredentialAudience,
    ) -> Result<(), ManagementError> {
        let identity = self
            .auth
            .identity(target)
            .ok_or(ManagementError::NotFound)?;
        if identity.status != crate::identity::IdentityStatus::Active {
            return Err(ManagementError::Denied);
        }
        if target != principal.identity_id
            && !self
                .authorization
                .principal_has_capability(principal, Capability::IdentityGrantManage)
        {
            return Err(ManagementError::Denied);
        }
        if audience == CredentialAudience::Control
            && (target != principal.identity_id || identity.kind != IdentityKind::Human)
        {
            return Err(ManagementError::Denied);
        }
        Ok(())
    }
}

fn role_view(value: &AppRoleRecord) -> RoleView {
    RoleView {
        schema: MANAGEMENT_OUTPUT_SCHEMA,
        id: encode_id(value.id),
        role_id: value.role_id.clone(),
        name: value.name.clone(),
        identity_id: encode_id(value.identity_id),
        token_ttl_seconds: value.token_ttl_seconds,
        status: match value.status {
            AppRoleStatus::Active => "active",
            AppRoleStatus::Deleted => "deleted",
        },
        generation: value.generation,
    }
}

fn validate_label(value: &str) -> Result<(), ManagementError> {
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.chars().any(char::is_control)
        || value.contains('/')
    {
        Err(ManagementError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_reason(value: &str) -> Result<(), ManagementError> {
    if value.is_empty() || value.len() > MAX_REASON_BYTES || value.chars().any(char::is_control) {
        Err(ManagementError::Invalid)
    } else {
        Ok(())
    }
}

fn map_auth(error: AuthError) -> ManagementError {
    match error {
        AuthError::Conflict | AuthError::AlreadyCommitted { .. } => ManagementError::Conflict,
        _ => ManagementError::Invalid,
    }
}

fn encode_id(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
