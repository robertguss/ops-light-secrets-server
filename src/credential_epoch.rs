//! Shared credential-epoch rotation and emergency control recovery primitive.

use std::fmt;
use std::io::Write;
use std::os::fd::AsFd;

use zeroize::Zeroizing;

use crate::credential::{
    CredentialAudience, CredentialEpoch, CredentialIssueMetadata, CredentialKind,
};
use crate::identity::{
    BOOTSTRAP_IDENTITY_NAME, GrantRecord, IdentityKind, IdentityRecord, TokenStatus,
};
use crate::init::validate_secret_sink;
use crate::store::keyring::{Keyring, RandomSource};
use crate::store::{
    AuditAuthMethod, AuditAuthentication, AuditAuthorization, AuditCapability, AuditEvent,
    AuditOperation, AuditOutcome, AuditReason, AuditResource, AuditStateCommitment, Lifecycle,
    Sealed, StateDelta, StateDeltaSet, Store, StoreError, StoredAuditEntry,
};

pub const EMERGENCY_CONTROL_TTL_SECONDS: u64 = 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochRotationMode {
    Online {
        owner_peer: bool,
        key_rotation: bool,
        identity_grant_manage: bool,
        credential_issue: bool,
    },
    Offline {
        service_owner: bool,
        daemon_absent: bool,
        exclusive_lock: bool,
        current_keyring_unwrapped: bool,
    },
}

impl EpochRotationMode {
    fn authorized(self) -> bool {
        match self {
            Self::Online {
                owner_peer,
                key_rotation,
                identity_grant_manage,
                credential_issue,
            } => owner_peer && key_rotation && identity_grant_manage && credential_issue,
            Self::Offline {
                service_owner,
                daemon_absent,
                exclusive_lock,
                current_keyring_unwrapped,
            } => service_owner && daemon_absent && exclusive_lock && current_keyring_unwrapped,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Online { .. } => 1,
            Self::Offline { .. } => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptedJobState {
    None,
    AuthenticatedOriginal,
    ForeignOrAmbiguous,
    PostRename,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochRotationPlan {
    pub current_epoch: u64,
    pub next_epoch: u64,
    pub active_tokens: u64,
    pub active_secret_ids: u64,
    pub confirmation: [u8; 32],
    pub caller_credential_dies: bool,
    pub replacement_ttl_seconds: u64,
}

pub struct EpochRotationRequest<'a> {
    pub expected_epoch: u64,
    pub effective_seconds: u64,
    pub reason: &'a str,
    pub confirmation: [u8; 32],
    pub mode: EpochRotationMode,
    pub interrupted_job: InterruptedJobState,
}

#[derive(Debug, Eq, PartialEq)]
pub enum EpochRotationError {
    Invalid,
    Unauthorized,
    Conflict,
    UnsafeSink,
    Disclosure,
    Store,
    Crypto,
}

impl fmt::Display for EpochRotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "credential epoch rotation input invalid",
            Self::Unauthorized => "credential epoch rotation unauthorized",
            Self::Conflict => "credential epoch rotation conflict",
            Self::UnsafeSink => "credential epoch rotation sink unsafe",
            Self::Disclosure => "credential epoch replacement disclosure failed",
            Self::Store => "credential epoch transaction failed",
            Self::Crypto => "credential epoch cryptographic preparation failed",
        })
    }
}

impl std::error::Error for EpochRotationError {}

impl From<StoreError> for EpochRotationError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

pub struct PreparedEpochRotation {
    pub replacement_credential: Zeroizing<String>,
    pub plan: EpochRotationPlan,
    pub auth_recovery_stale: bool,
    pub(crate) expected_epoch: Sealed<CredentialEpoch>,
    pub(crate) replacement_epoch: Sealed<CredentialEpoch>,
    pub(crate) identity: Sealed<IdentityRecord>,
    pub(crate) grant: Sealed<GrantRecord>,
    pub(crate) credential: Sealed<crate::credential::CredentialRecord>,
    pub(crate) audit: StoredAuditEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochRotationReceipt {
    pub epoch: u64,
    pub credential_accessor: [u8; 16],
    pub expires_at_effective_seconds: u64,
    pub auth_recovery_stale: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnlineDisclosureAck {
    pub request_nonce: [u8; 16],
    pub credential_digest: [u8; 32],
}

pub fn online_disclosure_ack(
    request_nonce: [u8; 16],
    credential: &[u8],
) -> Result<OnlineDisclosureAck, EpochRotationError> {
    if request_nonce == [0; 16] || credential.is_empty() {
        return Err(EpochRotationError::Invalid);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.epoch-disclosure-ack.v1\0");
    hasher.update(&request_nonce);
    hasher.update(&(credential.len() as u64).to_be_bytes());
    hasher.update(credential);
    Ok(OnlineDisclosureAck {
        request_nonce,
        credential_digest: *hasher.finalize().as_bytes(),
    })
}

pub fn verify_online_disclosure_ack(
    ack: OnlineDisclosureAck,
    expected_nonce: [u8; 16],
    credential: &[u8],
) -> Result<(), EpochRotationError> {
    if ack == online_disclosure_ack(expected_nonce, credential)? {
        Ok(())
    } else {
        Err(EpochRotationError::Disclosure)
    }
}

pub fn plan_epoch_rotation(
    store: &Store,
    keyring: &Keyring,
    expected_epoch: u64,
    reason: &str,
    mode: EpochRotationMode,
) -> Result<EpochRotationPlan, EpochRotationError> {
    if !mode.authorized() || !valid_reason(reason) {
        return Err(EpochRotationError::Unauthorized);
    }
    let epoch = store.credential_epoch(keyring.metadata_integrity_key())?;
    if epoch.value.current != expected_epoch {
        return Err(EpochRotationError::Conflict);
    }
    let records = keyring.credential_records(store)?;
    let active_tokens = records
        .iter()
        .filter(|record| {
            record.value.status == TokenStatus::Active && record.value.kind == CredentialKind::Token
        })
        .count() as u64;
    let active_secret_ids = records
        .iter()
        .filter(|record| {
            record.value.status == TokenStatus::Active
                && record.value.kind == CredentialKind::SecretId
        })
        .count() as u64;
    let next_epoch = expected_epoch
        .checked_add(1)
        .ok_or(EpochRotationError::Invalid)?;
    Ok(EpochRotationPlan {
        current_epoch: expected_epoch,
        next_epoch,
        active_tokens,
        active_secret_ids,
        confirmation: epoch_rotation_confirmation(
            store.meta()?.store_id.0,
            expected_epoch,
            active_tokens,
            active_secret_ids,
            reason,
            mode,
        ),
        caller_credential_dies: true,
        replacement_ttl_seconds: EMERGENCY_CONTROL_TTL_SECONDS,
    })
}

pub fn prepare_epoch_rotation(
    store: &Store,
    keyring: &Keyring,
    request: EpochRotationRequest<'_>,
    random: &mut impl RandomSource,
) -> Result<PreparedEpochRotation, EpochRotationError> {
    let plan = plan_epoch_rotation(
        store,
        keyring,
        request.expected_epoch,
        request.reason,
        request.mode,
    )?;
    let lifecycle = store.meta()?.lifecycle;
    let lifecycle_allowed = matches!(
        (lifecycle, request.interrupted_job),
        (Lifecycle::Ready, InterruptedJobState::None)
            | (
                Lifecycle::Reencrypting | Lifecycle::Migrating | Lifecycle::Compacting,
                InterruptedJobState::AuthenticatedOriginal
            )
    );
    if request.confirmation != plan.confirmation
        || request.effective_seconds == 0
        || !lifecycle_allowed
    {
        return Err(EpochRotationError::Conflict);
    }
    let current_epoch = store.credential_epoch(keyring.metadata_integrity_key())?;
    if current_epoch.value.current != plan.current_epoch {
        return Err(EpochRotationError::Conflict);
    }
    let mut identity_id = [0; 16];
    let mut grant_id = [0; 16];
    let mut credential_id = [0; 16];
    let mut issuance_request_id = [0; 16];
    let mut event_id = [0; 16];
    let mut request_id = [0; 16];
    for output in [
        &mut identity_id,
        &mut grant_id,
        &mut credential_id,
        &mut issuance_request_id,
        &mut event_id,
        &mut request_id,
    ] {
        random
            .fill(output)
            .map_err(|_| EpochRotationError::Crypto)?;
        if *output == [0; 16] {
            return Err(EpochRotationError::Crypto);
        }
    }
    let store_id = store.meta()?.store_id;
    let identity = IdentityRecord::new(
        identity_id,
        format!("{BOOTSTRAP_IDENTITY_NAME}-epoch-{}", plan.next_epoch),
        IdentityKind::Human,
    )
    .map_err(|_| EpochRotationError::Invalid)?
    .seal(keyring.metadata_integrity_key(), store_id)
    .map_err(|_| EpochRotationError::Crypto)?;
    let grant = GrantRecord::bootstrap_admin(grant_id, identity_id)
        .map_err(|_| EpochRotationError::Invalid)?
        .seal(keyring.metadata_integrity_key(), store_id)
        .map_err(|_| EpochRotationError::Crypto)?;
    let existing = keyring.credential_records(store)?;
    let issued = keyring
        .prepare_credential(
            CredentialIssueMetadata {
                id: credential_id,
                identity_id,
                kind: CredentialKind::Token,
                audience: CredentialAudience::Control,
                issue_epoch: plan.next_epoch,
                expires_at_effective_seconds: request
                    .effective_seconds
                    .checked_add(EMERGENCY_CONTROL_TTL_SECONDS)
                    .ok_or(EpochRotationError::Invalid)?,
                created_at_effective_seconds: request.effective_seconds,
                issuer_identity_id: identity_id,
                issuance_request_id,
                parent_accessor: None,
                consumer_instance_id: None,
            },
            "emergency-control".into(),
            &mut |accessor| {
                existing
                    .iter()
                    .any(|record| record.value.accessor == accessor)
            },
            random,
        )
        .map_err(|_| EpochRotationError::Crypto)?;
    let credential = keyring
        .seal_clear(
            issued.record.clone(),
            issued.record.generation,
            &issued.record.accessor.0,
        )
        .map_err(|_| EpochRotationError::Crypto)?;
    let next = current_epoch
        .value
        .bump(plan.current_epoch)
        .map_err(|_| EpochRotationError::Conflict)?;
    let replacement_epoch = keyring
        .seal_clear(next, plan.next_epoch, crate::store::CREDENTIAL_EPOCH_KEY)
        .map_err(|_| EpochRotationError::Crypto)?;
    let state = StateDeltaSet::new([
        StateDelta::replace(
            current_epoch
                .state_tuple(crate::store::CREDENTIAL_EPOCH_KEY)
                .map_err(|_| EpochRotationError::Crypto)?,
            replacement_epoch
                .state_tuple(crate::store::CREDENTIAL_EPOCH_KEY)
                .map_err(|_| EpochRotationError::Crypto)?,
        )
        .map_err(|_| EpochRotationError::Crypto)?,
        StateDelta::insert(
            identity
                .state_tuple(&identity_id)
                .map_err(|_| EpochRotationError::Crypto)?,
        ),
        StateDelta::insert(
            grant
                .state_tuple(&grant_id)
                .map_err(|_| EpochRotationError::Crypto)?,
        ),
        StateDelta::insert(
            credential
                .state_tuple(&credential.value.accessor.0)
                .map_err(|_| EpochRotationError::Crypto)?,
        ),
    ])
    .map_err(|_| EpochRotationError::Crypto)?;
    let head = store.audit_head()?.ok_or(EpochRotationError::Store)?;
    let reason_digest = blake3::hash(request.reason.as_bytes()).to_hex();
    let event = AuditEvent {
        event_id,
        request_id,
        authentication: AuditAuthentication {
            method: match request.mode {
                EpochRotationMode::Online { .. } => AuditAuthMethod::Token,
                EpochRotationMode::Offline { .. } => AuditAuthMethod::Recovery,
            },
            identity_id: None,
            credential_accessor: None,
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: Some(AuditCapability::RecoveryManage),
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: None,
        resource: Some(AuditResource::Canonical(format!(
            "credential/epoch/{}/reason-{}",
            plan.next_epoch,
            &reason_digest[..16]
        ))),
        operation: AuditOperation::CredentialChange,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::OperatorRequested,
        effective_timestamp_milliseconds: request
            .effective_seconds
            .checked_mul(1_000)
            .ok_or(EpochRotationError::Invalid)?,
        wall_clock_observation_milliseconds: request
            .effective_seconds
            .checked_mul(1_000)
            .ok_or(EpochRotationError::Invalid)?,
        secret_version: None,
        state: AuditStateCommitment::Delta(state),
        previous_epoch_terminal: None,
        flood: None,
        overload_counts: Vec::new(),
    };
    let audit = StoredAuditEntry::prepare(
        keyring,
        &event,
        head.audit_epoch,
        head.epoch_sequence
            .checked_add(1)
            .ok_or(EpochRotationError::Invalid)?,
        head.chain_hash().map_err(|_| EpochRotationError::Crypto)?,
        random,
    )
    .map_err(|_| EpochRotationError::Crypto)?;
    Ok(PreparedEpochRotation {
        replacement_credential: Zeroizing::new(issued.expose_once().to_owned()),
        plan,
        auth_recovery_stale: request.interrupted_job == InterruptedJobState::AuthenticatedOriginal,
        expected_epoch: current_epoch,
        replacement_epoch,
        identity,
        grant,
        credential,
        audit,
    })
}

/// Clock repair shares the exact preparation and commit representation. Its
/// caller contributes the clock-state mutation to the same coordinator
/// transaction; it must never mint a second emergency credential itself.
pub fn prepare_clock_repair_epoch_rotation(
    store: &Store,
    keyring: &Keyring,
    request: EpochRotationRequest<'_>,
    random: &mut impl RandomSource,
) -> Result<PreparedEpochRotation, EpochRotationError> {
    prepare_epoch_rotation(store, keyring, request, random)
}

/// Restore supplies its verified target store/keyring context to this same
/// primitive after archive verification and before activation.
pub fn prepare_restore_epoch_rotation(
    store: &Store,
    keyring: &Keyring,
    request: EpochRotationRequest<'_>,
    random: &mut impl RandomSource,
) -> Result<PreparedEpochRotation, EpochRotationError> {
    prepare_epoch_rotation(store, keyring, request, random)
}

pub fn rotate_credential_epoch<W: Write + AsFd>(
    store: &Store,
    keyring: &Keyring,
    request: EpochRotationRequest<'_>,
    sink: &mut W,
    random: &mut impl RandomSource,
) -> Result<EpochRotationReceipt, EpochRotationError> {
    validate_secret_sink(sink.as_fd()).map_err(|_| EpochRotationError::UnsafeSink)?;
    let prepared = prepare_epoch_rotation(store, keyring, request, random)?;
    sink.write_all(prepared.replacement_credential.as_bytes())
        .and_then(|()| sink.write_all(b"\n"))
        .and_then(|()| sink.flush())
        .map_err(|_| EpochRotationError::Disclosure)?;
    let receipt = EpochRotationReceipt {
        epoch: prepared.plan.next_epoch,
        credential_accessor: prepared.credential.value.accessor.0,
        expires_at_effective_seconds: prepared.credential.value.expires_at_effective_seconds,
        auth_recovery_stale: prepared.auth_recovery_stale,
    };
    keyring.commit_credential_epoch_rotation(store, prepared)?;
    Ok(receipt)
}

pub fn epoch_rotation_confirmation(
    store_id: [u8; 16],
    expected_epoch: u64,
    active_tokens: u64,
    active_secret_ids: u64,
    reason: &str,
    mode: EpochRotationMode,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.credential-epoch-rotate.v1\0");
    hasher.update(&store_id);
    hasher.update(&expected_epoch.to_be_bytes());
    hasher.update(&active_tokens.to_be_bytes());
    hasher.update(&active_secret_ids.to_be_bytes());
    hasher.update(&[mode.code()]);
    hasher.update(&(reason.len() as u64).to_be_bytes());
    hasher.update(reason.as_bytes());
    *hasher.finalize().as_bytes()
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= 1024 && !reason.chars().any(char::is_control)
}
