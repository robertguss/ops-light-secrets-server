//! Closed identity, grant, capability, and structured authorization model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::raw_target::{EndpointKind, EndpointRequest, Resource};
use crate::store::{
    Canonical, ClearRecord, CodecError, Decoder, Encoder, RecordClass, Sealed, StoreId,
};

pub const IDENTITY_SCHEMA_VERSION: u16 = 1;
pub const GRANT_SCHEMA_VERSION: u16 = 1;
pub const CAPABILITY_REGISTRY_VERSION: u16 = 1;
pub const MANAGEMENT_MOUNT: &str = "sys";
pub const BOOTSTRAP_IDENTITY_NAME: &str = "bootstrap-management";
pub const TOKEN_MODEL_VERSION: u16 = 1;
const MAX_NAME: usize = 255;
const MAX_MOUNT: usize = 128;
const MAX_SEGMENT: usize = 1024;
const MAX_SEGMENTS: usize = 256;
const MAX_CAPABILITIES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IdentityKind {
    Human = 1,
    Workload = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IdentityStatus {
    Active = 1,
    Retired = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GrantStatus {
    Active = 1,
    Removed = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenStatus {
    Active,
    Revoked,
}

/// Server-authoritative token state. Bearer bytes and verifier/accessor
/// encoding intentionally belong to U4.1 and cannot carry these fields.
///
/// ```compile_fail
/// use ops_light_secrets_server::identity::TokenServerRecord;
/// fn bake_grants(mut token: TokenServerRecord) { token.grants = Vec::new(); }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenServerRecord {
    pub id: [u8; 16],
    pub identity_id: [u8; 16],
    pub issued_at_effective_seconds: u64,
    pub expires_at_effective_seconds: u64,
    pub issue_epoch: u64,
    pub status: TokenStatus,
    pub generation: u64,
    pub display_name: String,
}

impl TokenServerRecord {
    pub fn issue(
        id: [u8; 16],
        identity_id: [u8; 16],
        issued_at_effective_seconds: u64,
        ttl_seconds: u64,
        issue_epoch: u64,
        display_name: String,
    ) -> Result<Self, TokenError> {
        let expires_at_effective_seconds = issued_at_effective_seconds
            .checked_add(ttl_seconds)
            .ok_or(TokenError::Invalid)?;
        if id == [0; 16]
            || identity_id == [0; 16]
            || issued_at_effective_seconds == 0
            || ttl_seconds == 0
            || issue_epoch == 0
            || !valid_label(&display_name)
        {
            return Err(TokenError::Invalid);
        }
        Ok(Self {
            id,
            identity_id,
            issued_at_effective_seconds,
            expires_at_effective_seconds,
            issue_epoch,
            status: TokenStatus::Active,
            generation: 1,
            display_name,
        })
    }

    pub fn revoke(&self, expected_generation: u64) -> Result<Self, TokenError> {
        if self.status != TokenStatus::Active || self.generation != expected_generation {
            return Err(TokenError::StaleGeneration);
        }
        let mut replacement = self.clone();
        replacement.status = TokenStatus::Revoked;
        replacement.generation = replacement
            .generation
            .checked_add(1)
            .ok_or(TokenError::Invalid)?;
        Ok(replacement)
    }
}

/// Opaque credential material only. No identity, expiry, epoch, or grant API.
/// Wrapper is non-Clone and non-Debug and clears its allocation on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TokenBearer(Vec<u8>);

impl TokenBearer {
    pub fn new(bytes: Vec<u8>) -> Result<Self, TokenError> {
        if bytes.is_empty() {
            return Err(TokenError::Invalid);
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenDenyReason {
    CredentialNotFound,
    Revoked,
    Expired,
    EpochChanged,
    IdentityNotFound,
    IdentityDisabled,
    NoGrantForMount,
    PrefixBoundaryMiss,
    MissingCapability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAuthorizationDecision {
    pub allow: bool,
    pub identity_id: Option<[u8; 16]>,
    pub matched_grant: Option<[u8; 16]>,
    pub deny_reason: Option<TokenDenyReason>,
    /// Denials are security events and must be appended before commit/reply.
    pub audit_required: bool,
}

/// Immutable view loaded inside one storage transaction. Creating a new view
/// after an admin commit necessarily supplies current identity and grant rows.
pub struct TokenAuthorizationSnapshot<'a> {
    token: Option<&'a TokenServerRecord>,
    identity: Option<&'a IdentityRecord>,
    grants: &'a [GrantRecord],
    effective_seconds: u64,
    credential_epoch: u64,
}

impl<'a> TokenAuthorizationSnapshot<'a> {
    pub fn new(
        token: Option<&'a TokenServerRecord>,
        identity: Option<&'a IdentityRecord>,
        grants: &'a [GrantRecord],
        effective_seconds: u64,
        credential_epoch: u64,
    ) -> Self {
        Self {
            token,
            identity,
            grants,
            effective_seconds,
            credential_epoch,
        }
    }

    pub fn authorize(&self, request: &AuthorizationRequest) -> TokenAuthorizationDecision {
        let Some(token) = self.token else {
            return denied(None, TokenDenyReason::CredentialNotFound);
        };
        if token.status == TokenStatus::Revoked {
            return denied(Some(token.identity_id), TokenDenyReason::Revoked);
        }
        if self.effective_seconds >= token.expires_at_effective_seconds {
            return denied(Some(token.identity_id), TokenDenyReason::Expired);
        }
        if self.credential_epoch != token.issue_epoch {
            return denied(Some(token.identity_id), TokenDenyReason::EpochChanged);
        }
        let Some(identity) = self
            .identity
            .filter(|identity| identity.id == token.identity_id)
        else {
            return denied(Some(token.identity_id), TokenDenyReason::IdentityNotFound);
        };
        if identity.status != IdentityStatus::Active {
            return denied(Some(token.identity_id), TokenDenyReason::IdentityDisabled);
        }
        let decision = authorize(
            request,
            self.grants
                .iter()
                .filter(|grant| grant.owner_identity_id == identity.id),
        );
        if decision.allow {
            TokenAuthorizationDecision {
                allow: true,
                identity_id: Some(identity.id),
                matched_grant: decision.matched_grant,
                deny_reason: None,
                audit_required: true,
            }
        } else {
            denied(
                Some(identity.id),
                match decision.deny_reason.expect("denial always has reason") {
                    DenyReason::NoGrantForMount => TokenDenyReason::NoGrantForMount,
                    DenyReason::PrefixBoundaryMiss => TokenDenyReason::PrefixBoundaryMiss,
                    DenyReason::MissingCapability => TokenDenyReason::MissingCapability,
                },
            )
        }
    }
}

fn denied(identity_id: Option<[u8; 16]>, reason: TokenDenyReason) -> TokenAuthorizationDecision {
    TokenAuthorizationDecision {
        allow: false,
        identity_id,
        matched_grant: None,
        deny_reason: Some(reason),
        audit_required: true,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenError {
    Invalid,
    StaleGeneration,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "token record invalid",
            Self::StaleGeneration => "token generation stale",
        })
    }
}

impl std::error::Error for TokenError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum Capability {
    SecretReadCurrent = 1,
    SecretReadHistory = 2,
    SecretList = 3,
    SecretWrite = 4,
    SecretSoftDelete = 5,
    SecretUndelete = 6,
    SecretDestroy = 7,
    SecretDestroyAll = 8,
    IdentityGrantManage = 101,
    CredentialIssue = 102,
    CredentialRevoke = 103,
    RotationManage = 104,
    ConsumerEnumerate = 105,
    AuditRead = 106,
    AuditExport = 107,
    AuditExportRecipientManage = 108,
    AuditCheckpointManage = 109,
    Backup = 110,
    BackupRecipientManage = 111,
    KeyRotation = 112,
    StoreMaintenance = 113,
    TransportManage = 114,
    Diagnostics = 115,
}

impl Capability {
    pub const ALL: [Self; 23] = [
        Self::SecretReadCurrent,
        Self::SecretReadHistory,
        Self::SecretList,
        Self::SecretWrite,
        Self::SecretSoftDelete,
        Self::SecretUndelete,
        Self::SecretDestroy,
        Self::SecretDestroyAll,
        Self::IdentityGrantManage,
        Self::CredentialIssue,
        Self::CredentialRevoke,
        Self::RotationManage,
        Self::ConsumerEnumerate,
        Self::AuditRead,
        Self::AuditExport,
        Self::AuditExportRecipientManage,
        Self::AuditCheckpointManage,
        Self::Backup,
        Self::BackupRecipientManage,
        Self::KeyRotation,
        Self::StoreMaintenance,
        Self::TransportManage,
        Self::Diagnostics,
    ];

    pub const fn is_secret(self) -> bool {
        (self as u16) < 100
    }

    pub const fn is_management(self) -> bool {
        !self.is_secret()
    }

    fn decode(value: u16) -> Result<Self, CodecError> {
        Self::ALL
            .into_iter()
            .find(|capability| *capability as u16 == value)
            .ok_or(CodecError::Invalid)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GrantScope {
    Exact = 1,
    Subtree = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRecord {
    pub id: [u8; 16],
    pub name: String,
    pub kind: IdentityKind,
    pub status: IdentityStatus,
    pub generation: u64,
}

impl IdentityRecord {
    pub fn new(id: [u8; 16], name: String, kind: IdentityKind) -> Result<Self, IdentityError> {
        let value = Self {
            id,
            name,
            kind,
            status: IdentityStatus::Active,
            generation: 1,
        };
        value.validate().map_err(|_| IdentityError::Invalid)?;
        Ok(value)
    }

    pub fn seal(self, key: &[u8; 32], store_id: StoreId) -> Result<Sealed<Self>, CodecError> {
        self.validate()?;
        let generation = self.generation;
        let id = self.id;
        Sealed::seal(self, generation, key, store_id, &id)
    }

    pub fn retire(&self, expected_generation: u64) -> Result<Self, IdentityError> {
        if self.status != IdentityStatus::Active || self.generation != expected_generation {
            return Err(IdentityError::StaleGeneration);
        }
        let mut replacement = self.clone();
        replacement.status = IdentityStatus::Retired;
        replacement.generation = replacement
            .generation
            .checked_add(1)
            .ok_or(IdentityError::Invalid)?;
        Ok(replacement)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.id == [0; 16] || self.generation == 0 || !valid_label(&self.name) {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for IdentityRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(IDENTITY_SCHEMA_VERSION);
        out.fixed(&self.id);
        out.string(&self.name, MAX_NAME)?;
        out.u8(self.kind as u8);
        out.u8(self.status as u8);
        out.u64(self.generation);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != IDENTITY_SCHEMA_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            id: input.fixed()?,
            name: input.string(MAX_NAME)?,
            kind: match input.u8()? {
                1 => IdentityKind::Human,
                2 => IdentityKind::Workload,
                _ => return Err(CodecError::Invalid),
            },
            status: match input.u8()? {
                1 => IdentityStatus::Active,
                2 => IdentityStatus::Retired,
                _ => return Err(CodecError::Invalid),
            },
            generation: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl ClearRecord for IdentityRecord {
    const CLASS: RecordClass = RecordClass::Identity;
    const SCHEMA_VERSION: u16 = IDENTITY_SCHEMA_VERSION;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRecord {
    pub id: [u8; 16],
    pub owner_identity_id: [u8; 16],
    pub generation: u64,
    pub status: GrantStatus,
    pub mount: String,
    pub scope: GrantScope,
    pub prefix_segments: Vec<String>,
    pub capabilities: BTreeSet<Capability>,
}

impl GrantRecord {
    pub fn new(
        id: [u8; 16],
        owner_identity_id: [u8; 16],
        mount: String,
        scope: GrantScope,
        prefix_segments: Vec<String>,
        capabilities: BTreeSet<Capability>,
    ) -> Result<Self, IdentityError> {
        let value = Self {
            id,
            owner_identity_id,
            generation: 1,
            status: GrantStatus::Active,
            mount,
            scope,
            prefix_segments,
            capabilities,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn bootstrap_admin(id: [u8; 16], owner: [u8; 16]) -> Result<Self, IdentityError> {
        Self::new(
            id,
            owner,
            MANAGEMENT_MOUNT.into(),
            GrantScope::Exact,
            Vec::new(),
            CapabilityBundle::AdminV1.expand(),
        )
    }

    pub fn seal(self, key: &[u8; 32], store_id: StoreId) -> Result<Sealed<Self>, CodecError> {
        self.validate().map_err(|_| CodecError::Invalid)?;
        let generation = self.generation;
        let id = self.id;
        Sealed::seal(self, generation, key, store_id, &id)
    }

    pub fn remove(&self, owner: [u8; 16], expected_generation: u64) -> Result<Self, IdentityError> {
        if self.owner_identity_id != owner {
            return Err(IdentityError::WrongOwner);
        }
        if self.status != GrantStatus::Active || self.generation != expected_generation {
            return Err(IdentityError::StaleGeneration);
        }
        let mut replacement = self.clone();
        replacement.status = GrantStatus::Removed;
        replacement.generation = replacement
            .generation
            .checked_add(1)
            .ok_or(IdentityError::Invalid)?;
        Ok(replacement)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.id == [0; 16]
            || self.owner_identity_id == [0; 16]
            || self.generation == 0
            || !valid_mount(&self.mount)
            || self.prefix_segments.len() > MAX_SEGMENTS
            || self
                .prefix_segments
                .iter()
                .any(|segment| !valid_segment(segment))
            || self.capabilities.is_empty()
            || self.capabilities.len() > MAX_CAPABILITIES
        {
            return Err(IdentityError::Invalid);
        }
        let management = self.mount == MANAGEMENT_MOUNT;
        if (management
            && (!self
                .capabilities
                .iter()
                .all(|capability| capability.is_management())
                || self.scope != GrantScope::Exact
                || !self.prefix_segments.is_empty()))
            || (!management
                && !self
                    .capabilities
                    .iter()
                    .all(|capability| capability.is_secret()))
        {
            return Err(IdentityError::CrossPlane);
        }
        Ok(())
    }

    fn shape_matches(&self, resource: &AuthorizationResource) -> bool {
        self.mount == resource.mount
            && match self.scope {
                GrantScope::Exact => self.prefix_segments == resource.segments,
                GrantScope::Subtree => resource.segments.starts_with(&self.prefix_segments),
            }
    }
}

impl Canonical for GrantRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate().map_err(|_| CodecError::Invalid)?;
        let mut out = Encoder::version(1);
        out.u16(GRANT_SCHEMA_VERSION);
        out.fixed(&self.id);
        out.fixed(&self.owner_identity_id);
        out.u64(self.generation);
        out.u8(self.status as u8);
        out.string(&self.mount, MAX_MOUNT)?;
        out.u8(self.scope as u8);
        out.u16(self.prefix_segments.len() as u16);
        for segment in &self.prefix_segments {
            out.string(segment, MAX_SEGMENT)?;
        }
        out.u16(self.capabilities.len() as u16);
        for capability in &self.capabilities {
            out.u16(*capability as u16);
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != GRANT_SCHEMA_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let id = input.fixed()?;
        let owner_identity_id = input.fixed()?;
        let generation = input.u64()?;
        let status = match input.u8()? {
            1 => GrantStatus::Active,
            2 => GrantStatus::Removed,
            _ => return Err(CodecError::Invalid),
        };
        let mount = input.string(MAX_MOUNT)?;
        let scope = match input.u8()? {
            1 => GrantScope::Exact,
            2 => GrantScope::Subtree,
            _ => return Err(CodecError::Invalid),
        };
        let segment_count = input.u16()? as usize;
        if segment_count > MAX_SEGMENTS {
            return Err(CodecError::Limit);
        }
        let mut prefix_segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            prefix_segments.push(input.string(MAX_SEGMENT)?);
        }
        let capability_count = input.u16()? as usize;
        if capability_count == 0 || capability_count > MAX_CAPABILITIES {
            return Err(CodecError::Limit);
        }
        let mut capabilities = BTreeSet::new();
        let mut previous = None;
        for _ in 0..capability_count {
            let capability = Capability::decode(input.u16()?)?;
            if previous.is_some_and(|old| old >= capability) || !capabilities.insert(capability) {
                return Err(CodecError::Invalid);
            }
            previous = Some(capability);
        }
        input.finish()?;
        let value = Self {
            id,
            owner_identity_id,
            generation,
            status,
            mount,
            scope,
            prefix_segments,
            capabilities,
        };
        value.validate().map_err(|_| CodecError::Invalid)?;
        Ok(value)
    }
}

impl ClearRecord for GrantRecord {
    const CLASS: RecordClass = RecordClass::Grant;
    const SCHEMA_VERSION: u16 = GRANT_SCHEMA_VERSION;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityBundle {
    AdminV1,
    AuditorV1,
}

impl CapabilityBundle {
    pub fn expand(self) -> BTreeSet<Capability> {
        match self {
            Self::AdminV1 => Capability::ALL
                .into_iter()
                .filter(|capability| capability.is_management())
                .collect(),
            Self::AuditorV1 => [Capability::AuditRead, Capability::AuditExport]
                .into_iter()
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationResource {
    pub mount: String,
    pub segments: Vec<String>,
}

impl From<&Resource> for AuthorizationResource {
    fn from(resource: &Resource) -> Self {
        Self {
            mount: resource.mount.clone(),
            segments: resource.canonical_segments.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationOperation {
    ReadCurrent,
    ReadHistory,
    List,
    Write,
    SoftDelete,
    Undelete,
    Destroy,
    DestroyAll,
    Management,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretAction {
    Read,
    Metadata,
    List,
    Write,
    SoftDelete,
    Undelete,
    Destroy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    pub resource: AuthorizationResource,
    pub operation: AuthorizationOperation,
    pub capability: Capability,
}

impl AuthorizationRequest {
    pub fn secret(endpoint: &EndpointRequest, action: SecretAction) -> Result<Self, IdentityError> {
        let (operation, capability) = match action {
            SecretAction::Read if endpoint.kind == EndpointKind::Data => {
                if endpoint.version.is_some() {
                    (
                        AuthorizationOperation::ReadHistory,
                        Capability::SecretReadHistory,
                    )
                } else {
                    (
                        AuthorizationOperation::ReadCurrent,
                        Capability::SecretReadCurrent,
                    )
                }
            }
            SecretAction::List if endpoint.kind == EndpointKind::List => {
                (AuthorizationOperation::List, Capability::SecretList)
            }
            SecretAction::Metadata if endpoint.kind == EndpointKind::Metadata => {
                (AuthorizationOperation::List, Capability::SecretList)
            }
            SecretAction::Write if endpoint.kind == EndpointKind::Data => {
                (AuthorizationOperation::Write, Capability::SecretWrite)
            }
            SecretAction::SoftDelete if endpoint.kind == EndpointKind::Delete => (
                AuthorizationOperation::SoftDelete,
                Capability::SecretSoftDelete,
            ),
            SecretAction::Undelete if endpoint.kind == EndpointKind::Undelete => {
                (AuthorizationOperation::Undelete, Capability::SecretUndelete)
            }
            SecretAction::Destroy if endpoint.kind == EndpointKind::Destroy => {
                (AuthorizationOperation::Destroy, Capability::SecretDestroy)
            }
            _ => return Err(IdentityError::InvalidRequestShape),
        };
        Ok(Self {
            resource: (&endpoint.resource).into(),
            operation,
            capability,
        })
    }

    pub fn local_destroy_all(resource: &Resource) -> Result<Self, IdentityError> {
        if resource.mount == MANAGEMENT_MOUNT {
            return Err(IdentityError::CrossPlane);
        }
        Ok(Self {
            resource: resource.into(),
            operation: AuthorizationOperation::DestroyAll,
            capability: Capability::SecretDestroyAll,
        })
    }

    pub fn management(capability: Capability) -> Result<Self, IdentityError> {
        if !capability.is_management() {
            return Err(IdentityError::CrossPlane);
        }
        Ok(Self {
            resource: AuthorizationResource {
                mount: MANAGEMENT_MOUNT.into(),
                segments: Vec::new(),
            },
            operation: AuthorizationOperation::Management,
            capability,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyReason {
    NoGrantForMount,
    PrefixBoundaryMiss,
    MissingCapability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    pub allow: bool,
    pub resource: AuthorizationResource,
    pub operation: AuthorizationOperation,
    pub matched_grant: Option<[u8; 16]>,
    pub deny_reason: Option<DenyReason>,
}

pub fn authorize<'a, I>(request: &AuthorizationRequest, grants: I) -> AuthorizationDecision
where
    I: IntoIterator<Item = &'a GrantRecord>,
{
    let applicable = grants
        .into_iter()
        .filter(|grant| grant.status == GrantStatus::Active)
        .collect::<Vec<_>>();
    let same_mount = applicable
        .iter()
        .copied()
        .filter(|grant| grant.mount == request.resource.mount)
        .collect::<Vec<_>>();
    let matching = same_mount
        .iter()
        .copied()
        .filter(|grant| grant.shape_matches(&request.resource))
        .collect::<Vec<_>>();
    let matched = matching
        .iter()
        .copied()
        .find(|grant| grant.capabilities.contains(&request.capability));
    let (allow, matched_grant, deny_reason) = match matched {
        Some(grant) => (true, Some(grant.id), None),
        None if same_mount.is_empty() => (false, None, Some(DenyReason::NoGrantForMount)),
        None if matching.is_empty() => (false, None, Some(DenyReason::PrefixBoundaryMiss)),
        None => (false, None, Some(DenyReason::MissingCapability)),
    };
    AuthorizationDecision {
        allow,
        resource: request.resource.clone(),
        operation: request.operation,
        matched_grant,
        deny_reason,
    }
}

pub fn validate_catalog(
    identities: &[IdentityRecord],
    grants: &[GrantRecord],
) -> Result<(), IdentityError> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let by_id = identities
        .iter()
        .map(|identity| (identity.id, identity))
        .collect::<BTreeMap<_, _>>();
    for identity in identities {
        identity.validate().map_err(|_| IdentityError::Invalid)?;
        if !ids.insert(identity.id) || !names.insert(identity.name.as_str()) {
            return Err(IdentityError::DuplicateIdentity);
        }
    }
    let mut grant_ids = BTreeSet::new();
    for grant in grants {
        grant.validate()?;
        if !grant_ids.insert(grant.id) {
            return Err(IdentityError::DuplicateGrant);
        }
        if !by_id.contains_key(&grant.owner_identity_id) {
            return Err(IdentityError::WrongOwner);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    Invalid,
    CrossPlane,
    StaleGeneration,
    WrongOwner,
    DuplicateIdentity,
    DuplicateGrant,
    InvalidRequestShape,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "identity record invalid",
            Self::CrossPlane => "grant plane invalid",
            Self::StaleGeneration => "record generation stale",
            Self::WrongOwner => "grant owner invalid",
            Self::DuplicateIdentity => "identity id or name already used",
            Self::DuplicateGrant => "grant id already used",
            Self::InvalidRequestShape => "authorization request shape invalid",
        })
    }
}

impl std::error::Error for IdentityError {}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_mount(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MOUNT
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SEGMENT && !value.contains(['/', '\0'])
}
