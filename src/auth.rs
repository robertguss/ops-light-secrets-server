//! Vault-compatible AppRole login and token self-inspection.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, middleware, routing};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::credential::{
    ACCESSOR_COLLISION_ATTEMPTS, CredentialAccessor, CredentialAudience, CredentialError,
    CredentialIssueMetadata, CredentialKind, CredentialRecord, CredentialVerificationContext,
    IssuedCredential, ROLE_TOKEN_DEFAULT_TTL_SECONDS, ROLE_TOKEN_MAX_TTL_SECONDS,
    ROLE_TOKEN_MIN_TTL_SECONDS, issue_credential, validate_ttl, verify_credential,
};
use crate::identity::{IdentityRecord, IdentityStatus};
use crate::input_hygiene::{
    InputHygieneState, StrictJsonBody, ValidatedToken, input_hygiene_guard,
};
use crate::store::keyring::{KeyringError, RandomSource};
use crate::store::{
    Canonical, ClearRecord, CodecError, Decoder, Encoder, RecordClass, Sealed, StoreId,
};

pub const APPROLE_SCHEMA_VERSION: u16 = 3;
pub const SECRET_ID_USAGE_SCHEMA_VERSION: u16 = 4;
const MAX_ROLE_ID: usize = 255;
const MAX_ROLE_NAME: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AppRoleStatus {
    Active = 1,
    Deleted = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppRoleRecord {
    pub id: [u8; 16],
    pub role_id: String,
    pub name: String,
    pub identity_id: [u8; 16],
    pub token_ttl_seconds: u64,
    pub status: AppRoleStatus,
    pub generation: u64,
}

impl AppRoleRecord {
    pub fn new(
        id: [u8; 16],
        role_id: String,
        name: String,
        identity_id: [u8; 16],
        token_ttl_seconds: Option<u64>,
    ) -> Result<Self, AuthError> {
        let token_ttl_seconds = validate_ttl(
            token_ttl_seconds.unwrap_or(ROLE_TOKEN_DEFAULT_TTL_SECONDS),
            ROLE_TOKEN_MIN_TTL_SECONDS,
            ROLE_TOKEN_MAX_TTL_SECONDS,
        )
        .map_err(|_| AuthError::InvalidInput)?;
        let value = Self {
            id,
            role_id,
            name,
            identity_id,
            token_ttl_seconds,
            status: AppRoleStatus::Active,
            generation: 1,
        };
        value.validate().map_err(|_| AuthError::InvalidInput)?;
        Ok(value)
    }

    pub fn delete(&self, expected_generation: u64) -> Result<Self, AuthError> {
        if self.status != AppRoleStatus::Active || self.generation != expected_generation {
            return Err(AuthError::Conflict);
        }
        let mut replacement = self.clone();
        replacement.status = AppRoleStatus::Deleted;
        replacement.generation = replacement
            .generation
            .checked_add(1)
            .ok_or(AuthError::InvalidInput)?;
        Ok(replacement)
    }

    pub fn seal(self, key: &[u8; 32], store_id: StoreId) -> Result<Sealed<Self>, CodecError> {
        self.validate()?;
        let generation = self.generation;
        let id = self.id;
        Sealed::seal(self, generation, key, store_id, &id)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.id == [0; 16]
            || self.identity_id == [0; 16]
            || self.generation == 0
            || !valid_public_label(&self.role_id, MAX_ROLE_ID)
            || !valid_public_label(&self.name, MAX_ROLE_NAME)
            || validate_ttl(
                self.token_ttl_seconds,
                ROLE_TOKEN_MIN_TTL_SECONDS,
                ROLE_TOKEN_MAX_TTL_SECONDS,
            )
            .is_err()
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for AppRoleRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(APPROLE_SCHEMA_VERSION);
        out.fixed(&self.id);
        out.string(&self.role_id, MAX_ROLE_ID)?;
        out.string(&self.name, MAX_ROLE_NAME)?;
        out.fixed(&self.identity_id);
        out.u64(self.token_ttl_seconds);
        out.u8(self.status as u8);
        out.u64(self.generation);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != APPROLE_SCHEMA_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            id: input.fixed()?,
            role_id: input.string(MAX_ROLE_ID)?,
            name: input.string(MAX_ROLE_NAME)?,
            identity_id: input.fixed()?,
            token_ttl_seconds: input.u64()?,
            status: match input.u8()? {
                1 => AppRoleStatus::Active,
                2 => AppRoleStatus::Deleted,
                _ => return Err(CodecError::Invalid),
            },
            generation: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl ClearRecord for AppRoleRecord {
    const CLASS: RecordClass = RecordClass::CredentialMetadata;
    const SCHEMA_VERSION: u16 = APPROLE_SCHEMA_VERSION;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretIdUsageRecord {
    pub accessor: CredentialAccessor,
    pub role_id: [u8; 16],
    pub initial_uses: u32,
    pub remaining_uses: u32,
    pub generation: u64,
}

impl SecretIdUsageRecord {
    pub fn new(
        accessor: CredentialAccessor,
        role_id: [u8; 16],
        uses: u32,
    ) -> Result<Self, AuthError> {
        crate::credential::validate_secret_id_uses(uses).map_err(|_| AuthError::InvalidInput)?;
        if accessor.0 == [0; 16] || role_id == [0; 16] {
            return Err(AuthError::InvalidInput);
        }
        Ok(Self {
            accessor,
            role_id,
            initial_uses: uses,
            remaining_uses: uses,
            generation: 1,
        })
    }

    fn consume(&self) -> Result<Self, AuthError> {
        if self.remaining_uses == 0 {
            return Err(AuthError::InvalidCredentials);
        }
        let mut replacement = self.clone();
        replacement.remaining_uses -= 1;
        replacement.generation = replacement
            .generation
            .checked_add(1)
            .ok_or(AuthError::InvalidInput)?;
        Ok(replacement)
    }

    pub fn seal(self, key: &[u8; 32], store_id: StoreId) -> Result<Sealed<Self>, CodecError> {
        self.validate()?;
        let generation = self.generation;
        let accessor = self.accessor;
        Sealed::seal(self, generation, key, store_id, &accessor.0)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.accessor.0 == [0; 16]
            || self.role_id == [0; 16]
            || self.generation == 0
            || crate::credential::validate_secret_id_uses(self.initial_uses).is_err()
            || self.remaining_uses > self.initial_uses
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for SecretIdUsageRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(SECRET_ID_USAGE_SCHEMA_VERSION);
        out.fixed(&self.accessor.0);
        out.fixed(&self.role_id);
        out.u32(self.initial_uses);
        out.u32(self.remaining_uses);
        out.u64(self.generation);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != SECRET_ID_USAGE_SCHEMA_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            accessor: CredentialAccessor(input.fixed()?),
            role_id: input.fixed()?,
            initial_uses: input.u32()?,
            remaining_uses: input.u32()?,
            generation: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl ClearRecord for SecretIdUsageRecord {
    const CLASS: RecordClass = RecordClass::CredentialMetadata;
    const SCHEMA_VERSION: u16 = SECRET_ID_USAGE_SCHEMA_VERSION;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    InvalidInput,
    InvalidCredentials,
    Unauthenticated,
    AlreadyCommitted { accessor: CredentialAccessor },
    Conflict,
    Random,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "authentication input invalid",
            Self::InvalidCredentials => "AppRole credentials invalid",
            Self::Unauthenticated => "token authentication failed",
            Self::AlreadyCommitted { .. } => "login already committed; revoke and retry",
            Self::Conflict => "authentication state conflict",
            Self::Random => "credential generation failed",
        })
    }
}

impl std::error::Error for AuthError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditOutcome {
    Succeeded,
    Denied,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthAuditEvent {
    pub request_id: [u8; 16],
    pub operation: AuthOperation,
    pub outcome: AuthAuditOutcome,
    pub credential_accessor: Option<CredentialAccessor>,
    pub identity_id: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthOperation {
    AppRoleLogin,
    LookupSelf,
    RenewSelf,
}

pub struct LoginSuccess {
    pub credential: IssuedCredential,
    pub lease_duration: u64,
    pub role_name: String,
    pub identity_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LookupSelfData {
    pub accessor: String,
    pub creation_time: u64,
    pub display_name: String,
    pub entity_id: String,
    pub expire_time: u64,
    pub issue_time: u64,
    pub lease_duration: u64,
    pub renewable: bool,
    pub ttl: u64,
    #[serde(rename = "type")]
    pub token_type: &'static str,
}

pub struct AuthCatalog {
    store_id: StoreId,
    verifier_key: Zeroizing<[u8; 32]>,
    current_epoch: u64,
    effective_seconds: u64,
    roles_by_public_id: BTreeMap<String, AppRoleRecord>,
    identities: BTreeMap<[u8; 16], IdentityRecord>,
    credentials: BTreeMap<CredentialAccessor, CredentialRecord>,
    usages: BTreeMap<CredentialAccessor, SecretIdUsageRecord>,
    audit: Vec<AuthAuditEvent>,
}

impl AuthCatalog {
    pub fn new(
        store_id: StoreId,
        verifier_key: [u8; 32],
        current_epoch: u64,
        effective_seconds: u64,
    ) -> Result<Self, AuthError> {
        if store_id.0 == [0; 16]
            || verifier_key == [0; 32]
            || current_epoch == 0
            || effective_seconds == 0
        {
            return Err(AuthError::InvalidInput);
        }
        Ok(Self {
            store_id,
            verifier_key: Zeroizing::new(verifier_key),
            current_epoch,
            effective_seconds,
            roles_by_public_id: BTreeMap::new(),
            identities: BTreeMap::new(),
            credentials: BTreeMap::new(),
            usages: BTreeMap::new(),
            audit: Vec::new(),
        })
    }

    pub fn set_effective_seconds(&mut self, value: u64) -> Result<(), AuthError> {
        if value < self.effective_seconds {
            return Err(AuthError::InvalidInput);
        }
        self.effective_seconds = value;
        Ok(())
    }

    pub fn store_id(&self) -> StoreId {
        self.store_id
    }

    pub fn verifier_key(&self) -> &[u8; 32] {
        &self.verifier_key
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn effective_seconds(&self) -> u64 {
        self.effective_seconds
    }

    pub fn insert_role(&mut self, role: AppRoleRecord) -> Result<(), AuthError> {
        role.validate().map_err(|_| AuthError::InvalidInput)?;
        if !self
            .identities
            .get(&role.identity_id)
            .is_some_and(|identity| identity.status == IdentityStatus::Active)
            || self.roles_by_public_id.contains_key(&role.role_id)
            || self
                .roles_by_public_id
                .values()
                .any(|existing| existing.id == role.id || existing.name == role.name)
        {
            return Err(AuthError::Conflict);
        }
        self.roles_by_public_id.insert(role.role_id.clone(), role);
        Ok(())
    }

    pub fn insert_identity(&mut self, identity: IdentityRecord) -> Result<(), AuthError> {
        identity.encode().map_err(|_| AuthError::InvalidInput)?;
        if self.identities.contains_key(&identity.id) {
            return Err(AuthError::Conflict);
        }
        self.identities.insert(identity.id, identity);
        Ok(())
    }

    pub fn replace_identity(&mut self, identity: IdentityRecord) -> Result<(), AuthError> {
        identity.encode().map_err(|_| AuthError::InvalidInput)?;
        let current = self
            .identities
            .get(&identity.id)
            .ok_or(AuthError::Conflict)?;
        if identity.generation
            != current
                .generation
                .checked_add(1)
                .ok_or(AuthError::Conflict)?
            || identity.name != current.name
            || identity.kind != current.kind
        {
            return Err(AuthError::Conflict);
        }
        self.identities.insert(identity.id, identity);
        Ok(())
    }

    pub fn delete_role(
        &mut self,
        role_id: &str,
        expected_generation: u64,
    ) -> Result<(), AuthError> {
        let current = self
            .roles_by_public_id
            .get(role_id)
            .ok_or(AuthError::Conflict)?;
        let replacement = current.delete(expected_generation)?;
        self.roles_by_public_id
            .insert(role_id.to_owned(), replacement);
        Ok(())
    }

    pub fn insert_secret_id(
        &mut self,
        role_record_id: [u8; 16],
        credential: CredentialRecord,
        uses: u32,
    ) -> Result<(), AuthError> {
        if credential.kind != CredentialKind::SecretId
            || credential.audience != CredentialAudience::Data
            || !self.roles_by_public_id.values().any(|role| {
                role.id == role_record_id
                    && role.identity_id == credential.identity_id
                    && role.status == AppRoleStatus::Active
            })
            || self.credentials.contains_key(&credential.accessor)
        {
            return Err(AuthError::InvalidInput);
        }
        let usage = SecretIdUsageRecord::new(credential.accessor, role_record_id, uses)?;
        self.usages.insert(credential.accessor, usage);
        self.credentials.insert(credential.accessor, credential);
        Ok(())
    }

    pub fn insert_token(&mut self, credential: CredentialRecord) -> Result<(), AuthError> {
        if credential.kind != CredentialKind::Token
            || !self
                .identities
                .get(&credential.identity_id)
                .is_some_and(|identity| identity.status == IdentityStatus::Active)
            || self.credentials.contains_key(&credential.accessor)
        {
            return Err(AuthError::InvalidInput);
        }
        self.credentials.insert(credential.accessor, credential);
        Ok(())
    }

    pub fn audit(&self) -> &[AuthAuditEvent] {
        &self.audit
    }

    pub fn usage(&self, accessor: CredentialAccessor) -> Option<&SecretIdUsageRecord> {
        self.usages.get(&accessor)
    }

    pub fn credential_by_request(&self, request_id: [u8; 16]) -> Option<&CredentialRecord> {
        self.credentials
            .values()
            .find(|credential| credential.issuance_request_id == request_id)
    }

    pub fn identity(&self, id: [u8; 16]) -> Option<&IdentityRecord> {
        self.identities.get(&id)
    }

    pub fn role(&self, public_role_id: &str) -> Option<&AppRoleRecord> {
        self.roles_by_public_id.get(public_role_id)
    }

    pub fn roles(&self) -> impl Iterator<Item = &AppRoleRecord> {
        self.roles_by_public_id.values()
    }

    pub fn credentials(&self) -> impl Iterator<Item = &CredentialRecord> {
        self.credentials.values()
    }

    pub fn credential(&self, accessor: CredentialAccessor) -> Option<&CredentialRecord> {
        self.credentials.get(&accessor)
    }

    pub fn replace_credential(&mut self, replacement: CredentialRecord) -> Result<(), AuthError> {
        let current = self
            .credentials
            .get(&replacement.accessor)
            .ok_or(AuthError::Conflict)?;
        if replacement.id != current.id
            || replacement.generation
                != current
                    .generation
                    .checked_add(1)
                    .ok_or(AuthError::Conflict)?
        {
            return Err(AuthError::Conflict);
        }
        self.credentials.insert(replacement.accessor, replacement);
        Ok(())
    }

    pub fn remove_secret_ids_for_role(
        &mut self,
        role_record_id: [u8; 16],
    ) -> Result<usize, AuthError> {
        let accessors = self
            .usages
            .values()
            .filter(|usage| usage.role_id == role_record_id)
            .map(|usage| usage.accessor)
            .collect::<Vec<_>>();
        for accessor in &accessors {
            if let Some(current) = self.credentials.get(accessor).cloned() {
                if current.status == crate::identity::TokenStatus::Active {
                    self.replace_credential(
                        current
                            .revoke(current.generation)
                            .map_err(|_| AuthError::Conflict)?,
                    )?;
                }
            }
        }
        Ok(accessors.len())
    }

    pub fn login(
        &mut self,
        role_id: &str,
        secret_id: &str,
        request_id: [u8; 16],
        random: &mut impl RandomSource,
    ) -> Result<LoginSuccess, AuthError> {
        if request_id == [0; 16] || !valid_public_label(role_id, MAX_ROLE_ID) {
            return self.login_denied(request_id, None);
        }
        if let Some(existing) = self.credential_by_request(request_id) {
            return Err(AuthError::AlreadyCommitted {
                accessor: existing.accessor,
            });
        }
        let parsed_accessor = crate::credential::CredentialWire::parse(secret_id)
            .ok()
            .map(|wire| wire.accessor);
        let accessor = parsed_accessor.unwrap_or(CredentialAccessor([0; 16]));
        let role = self.roles_by_public_id.get(role_id).cloned();
        let verification = verify_credential(
            secret_id,
            CredentialVerificationContext {
                expected_kind: CredentialKind::SecretId,
                expected_audience: CredentialAudience::Data,
                current_epoch: self.current_epoch,
                effective_seconds: self.effective_seconds,
                store_id: self.store_id,
                verifier_key: &self.verifier_key,
            },
            &|accessor| self.credentials.get(&accessor).cloned(),
        );
        let parent = self.credentials.get(&accessor).cloned();
        let usage = self.usages.get(&accessor).cloned();
        let valid = verification.reason.is_none()
            && parsed_accessor.is_some()
            && role.as_ref().is_some_and(|role| {
                role.status == AppRoleStatus::Active
                    && usage.as_ref().is_some_and(|usage| role.id == usage.role_id)
                    && parent
                        .as_ref()
                        .is_some_and(|parent| role.identity_id == parent.identity_id)
                    && usage.as_ref().is_some_and(|usage| usage.remaining_uses > 0)
            });
        if !valid {
            return self.login_denied(request_id, parsed_accessor);
        }
        let role = role.expect("validated role");
        let parent = parent.expect("validated parent");
        let usage = usage.expect("validated usage");

        let replacement_usage = usage.consume()?;
        let id = unique_id(&self.credentials, random)?;
        let expires = self
            .effective_seconds
            .checked_add(role.token_ttl_seconds)
            .ok_or(AuthError::InvalidInput)?;
        let metadata = CredentialIssueMetadata::token_from_secret_id(
            &parent,
            id,
            self.effective_seconds,
            expires,
            request_id,
        )?;
        let mut exists = |candidate| self.credentials.contains_key(&candidate);
        let issued = issue_credential(
            &self.verifier_key,
            self.store_id,
            metadata,
            format!("approle:{}", role.name),
            &mut exists,
            random,
        )?;
        self.usages.insert(accessor, replacement_usage);
        self.credentials
            .insert(issued.record.accessor, issued.record.clone());
        self.audit.push(AuthAuditEvent {
            request_id,
            operation: AuthOperation::AppRoleLogin,
            outcome: AuthAuditOutcome::Succeeded,
            credential_accessor: Some(accessor),
            identity_id: Some(role.identity_id),
        });
        Ok(LoginSuccess {
            credential: issued,
            lease_duration: role.token_ttl_seconds,
            role_name: role.name,
            identity_id: role.identity_id,
        })
    }

    pub fn lookup_self(
        &mut self,
        token: &str,
        request_id: [u8; 16],
    ) -> Result<LookupSelfData, AuthError> {
        let parsed_accessor = crate::credential::CredentialWire::parse(token)
            .ok()
            .map(|wire| wire.accessor);
        let Some((accessor, record)) =
            self.authenticated_credential(token, CredentialAudience::Data)
        else {
            self.audit.push(AuthAuditEvent {
                request_id,
                operation: AuthOperation::LookupSelf,
                outcome: AuthAuditOutcome::Denied,
                credential_accessor: parsed_accessor,
                identity_id: None,
            });
            return Err(AuthError::Unauthenticated);
        };
        let ttl = record
            .expires_at_effective_seconds
            .checked_sub(self.effective_seconds)
            .ok_or(AuthError::Unauthenticated)?;
        let data = LookupSelfData {
            accessor: accessor.encode(),
            creation_time: record.created_at_effective_seconds,
            display_name: record.label.clone(),
            entity_id: encode_id(record.identity_id),
            expire_time: record.expires_at_effective_seconds,
            issue_time: record.created_at_effective_seconds,
            lease_duration: record
                .expires_at_effective_seconds
                .saturating_sub(record.created_at_effective_seconds),
            renewable: false,
            ttl,
            token_type: "service",
        };
        self.audit.push(AuthAuditEvent {
            request_id,
            operation: AuthOperation::LookupSelf,
            outcome: AuthAuditOutcome::Succeeded,
            credential_accessor: Some(accessor),
            identity_id: Some(record.identity_id),
        });
        Ok(data)
    }

    pub fn authenticated_credential(
        &self,
        token: &str,
        audience: CredentialAudience,
    ) -> Option<(CredentialAccessor, CredentialRecord)> {
        let accessor = crate::credential::CredentialWire::parse(token)
            .ok()
            .map(|wire| wire.accessor)?;
        let verification = verify_credential(
            token,
            CredentialVerificationContext {
                expected_kind: CredentialKind::Token,
                expected_audience: audience,
                current_epoch: self.current_epoch,
                effective_seconds: self.effective_seconds,
                store_id: self.store_id,
                verifier_key: &self.verifier_key,
            },
            &|candidate| self.credentials.get(&candidate).cloned(),
        );
        if verification.reason.is_some() {
            return None;
        }
        let record = self.credentials.get(&accessor)?;
        if !self
            .identities
            .get(&record.identity_id)
            .is_some_and(|identity| identity.status == IdentityStatus::Active)
        {
            return None;
        }
        Some((accessor, record.clone()))
    }

    pub fn renew_unsupported(&mut self, request_id: [u8; 16]) {
        self.audit.push(AuthAuditEvent {
            request_id,
            operation: AuthOperation::RenewSelf,
            outcome: AuthAuditOutcome::Unsupported,
            credential_accessor: None,
            identity_id: None,
        });
    }

    fn login_denied<T>(
        &mut self,
        request_id: [u8; 16],
        accessor: Option<CredentialAccessor>,
    ) -> Result<T, AuthError> {
        self.audit.push(AuthAuditEvent {
            request_id,
            operation: AuthOperation::AppRoleLogin,
            outcome: AuthAuditOutcome::Denied,
            credential_accessor: accessor,
            identity_id: None,
        });
        Err(AuthError::InvalidCredentials)
    }
}

impl From<CredentialError> for AuthError {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::Random(_) | CredentialError::CollisionExhausted => Self::Random,
            CredentialError::Conflict => Self::Conflict,
            CredentialError::Invalid => Self::InvalidInput,
        }
    }
}

#[derive(Clone)]
pub struct AuthService {
    catalog: Arc<Mutex<AuthCatalog>>,
    random: Arc<Mutex<Box<dyn RandomSource + Send>>>,
}

impl AuthService {
    pub fn new(catalog: AuthCatalog, random: impl RandomSource + Send + 'static) -> Self {
        Self {
            catalog: Arc::new(Mutex::new(catalog)),
            random: Arc::new(Mutex::new(Box::new(random))),
        }
    }

    pub fn with_catalog<T>(&self, action: impl FnOnce(&mut AuthCatalog) -> T) -> T {
        let mut catalog = self.catalog.lock().expect("auth catalog lock");
        action(&mut catalog)
    }

    pub fn login(
        &self,
        role_id: &str,
        secret_id: &str,
        request_id: [u8; 16],
    ) -> Result<LoginSuccess, AuthError> {
        let mut catalog = self.catalog.lock().map_err(|_| AuthError::Conflict)?;
        let mut random = self.random.lock().map_err(|_| AuthError::Conflict)?;
        catalog.login(role_id, secret_id, request_id, &mut *random)
    }

    pub fn lookup_self(
        &self,
        token: &str,
        request_id: [u8; 16],
    ) -> Result<LookupSelfData, AuthError> {
        self.catalog
            .lock()
            .map_err(|_| AuthError::Conflict)?
            .lookup_self(token, request_id)
    }

    pub fn authenticate(
        &self,
        token: &str,
        audience: CredentialAudience,
    ) -> Result<AuthenticatedToken, AuthError> {
        let catalog = self.catalog.lock().map_err(|_| AuthError::Conflict)?;
        let (_, record) = catalog
            .authenticated_credential(token, audience)
            .ok_or(AuthError::Unauthenticated)?;
        Ok(AuthenticatedToken {
            identity_id: record.identity_id,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedToken {
    pub identity_id: [u8; 16],
}

pub fn auth_router(service: AuthService, hygiene: InputHygieneState) -> Router {
    let limits = crate::rate_limit::RateLimitService::new(
        crate::rate_limit::RateLimitConfig::default(),
        [0x41; 32],
    )
    .expect("default rate limit configuration is valid");
    auth_router_with_limits(service, hygiene, limits)
}

pub fn auth_router_with_limits(
    service: AuthService,
    hygiene: InputHygieneState,
    limits: crate::rate_limit::RateLimitService,
) -> Router {
    let login = Router::new().route(
        "/v1/auth/approle/login",
        routing::post(approle_login).put(approle_login),
    );
    let protected = Router::new()
        .route("/v1/auth/token/lookup-self", routing::get(lookup_self))
        .route(
            "/v1/auth/token/renew-self",
            routing::post(renew_self).put(renew_self),
        )
        .route_layer(middleware::from_fn_with_state(
            limits.clone(),
            crate::rate_limit::authenticated_guard,
        ))
        .route_layer(middleware::from_fn_with_state(
            service.clone(),
            token_auth_guard,
        ));
    login
        .merge(protected)
        .layer(middleware::from_fn_with_state(hygiene, input_hygiene_guard))
        .layer(middleware::from_fn_with_state(
            limits,
            crate::rate_limit::pre_verifier_guard,
        ))
        .layer(middleware::from_fn(vault_error_normalizer))
        .with_state(service)
}

async fn vault_error_normalizer(request: Request<axum::body::Body>, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        let is_json = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"));
        if !is_json {
            return vault_error(response.status(), "invalid request");
        }
    }
    response
}

pub async fn token_auth_guard(
    State(service): State<AuthService>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(token) = request.extensions().get::<ValidatedToken>() else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    let Ok(token) = std::str::from_utf8(&token.0) else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    let result = service.authenticate(token, CredentialAudience::Data);
    let Ok(authenticated) = result else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    request.extensions_mut().insert(authenticated);
    next.run(request).await
}

pub async fn control_token_auth_guard(
    State(service): State<AuthService>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(token) = request.extensions().get::<ValidatedToken>() else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    let Ok(token) = std::str::from_utf8(&token.0) else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    let Ok(authenticated) = service.authenticate(token, CredentialAudience::Control) else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    request.extensions_mut().insert(authenticated);
    next.run(request).await
}

async fn approle_login(
    State(service): State<AuthService>,
    headers: HeaderMap,
    body: Option<Extension<StrictJsonBody>>,
) -> Response {
    let Some(Extension(mut body)) = body else {
        return vault_error(StatusCode::BAD_REQUEST, "invalid request");
    };
    let Some(object) = body.0.as_object_mut() else {
        zeroize_json(&mut body.0);
        return vault_error(StatusCode::BAD_REQUEST, "invalid request");
    };
    if object.len() != 2 {
        zeroize_json(&mut body.0);
        return vault_error(StatusCode::BAD_REQUEST, "invalid request");
    }
    let (Some(Value::String(role_id)), Some(Value::String(secret_id))) =
        (object.remove("role_id"), object.remove("secret_id"))
    else {
        zeroize_json(&mut body.0);
        return vault_error(StatusCode::BAD_REQUEST, "invalid request");
    };
    let secret_id = Zeroizing::new(secret_id);
    match service.login(&role_id, &secret_id, request_id(&headers)) {
        Ok(success) => {
            let body = json!({
                "auth": {
                    "accessor": success.credential.record.accessor.encode(),
                    "client_token": success.credential.expose_once(),
                    "entity_id": encode_id(success.identity_id),
                    "lease_duration": success.lease_duration,
                    "metadata": {"role_name": success.role_name},
                    "mfa_requirement": Value::Null,
                    "num_uses": 0,
                    "orphan": true,
                    "policies": [],
                    "renewable": false,
                    "token_policies": [],
                    "token_type": "service"
                }
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(_) => vault_error(StatusCode::BAD_REQUEST, "invalid role_id or secret_id"),
    }
}

async fn lookup_self(
    State(service): State<AuthService>,
    headers: HeaderMap,
    token: Option<Extension<ValidatedToken>>,
) -> Response {
    let Some(Extension(token)) = token else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    let Ok(token) = std::str::from_utf8(&token.0) else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    match service.lookup_self(token, request_id(&headers)) {
        Ok(data) => (StatusCode::OK, Json(json!({"data": data}))).into_response(),
        Err(_) => vault_error(StatusCode::FORBIDDEN, "permission denied"),
    }
}

async fn renew_self(
    State(service): State<AuthService>,
    headers: HeaderMap,
    token: Option<Extension<ValidatedToken>>,
) -> Response {
    let Some(Extension(token)) = token else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    let Ok(token) = std::str::from_utf8(&token.0) else {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    };
    if service
        .authenticate(token, CredentialAudience::Data)
        .is_err()
    {
        return vault_error(StatusCode::FORBIDDEN, "permission denied");
    }
    service.with_catalog(|catalog| catalog.renew_unsupported(request_id(&headers)));
    vault_error(
        StatusCode::NOT_IMPLEMENTED,
        "token renewal is not supported",
    )
}

fn vault_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"errors": [message]}))).into_response()
}

fn request_id(headers: &HeaderMap) -> [u8; 16] {
    if let Some(value) = headers.get("x-vault-request") {
        let digest = blake3::hash(value.as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        if id != [0; 16] {
            return id;
        }
    }
    let mut id = [0; 16];
    if getrandom::fill(&mut id).is_err() || id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn unique_id(
    credentials: &BTreeMap<CredentialAccessor, CredentialRecord>,
    random: &mut impl RandomSource,
) -> Result<[u8; 16], AuthError> {
    for _ in 0..ACCESSOR_COLLISION_ATTEMPTS {
        let mut id = [0; 16];
        random.fill(&mut id).map_err(|_| AuthError::Random)?;
        if id != [0; 16] && credentials.values().all(|record| record.id != id) {
            return Ok(id);
        }
    }
    Err(AuthError::Random)
}

fn valid_public_label(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && !value.contains(['/', '\\'])
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => values.values_mut().for_each(zeroize_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn encode_id(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Drop for AuthCatalog {
    fn drop(&mut self) {
        self.verifier_key.zeroize();
    }
}

impl From<KeyringError> for AuthError {
    fn from(_: KeyringError) -> Self {
        Self::Random
    }
}

impl RandomSource for Box<dyn RandomSource + Send> {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.as_mut().fill(output)
    }
}
