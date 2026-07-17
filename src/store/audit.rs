use super::codec::{Decoder, Encoder};
use super::keyring::{Keyring, KeyringError, RandomSource};
use super::{
    Canonical, CodecError, EncryptedRecord, LogicalPath, RecordBinding, RecordCryptoError,
    RecordDomain, StateDeltaSet, WholeStateTransition,
};
use secrecy::{ExposeSecret, SecretBox};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroize;

use crate::storage_executor::OverloadSnapshot;
use crate::transaction_coordinator::TransactionAudit;

pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const AUDIT_ENVELOPE_VERSION: u16 = 1;
pub const MAX_AUDIT_EVENT_BYTES: usize = 256 * 1024;
pub const MAX_AUDIT_FRAME_BYTES: usize = 512 * 1024;
const MAX_RESOURCE: usize = 4096;
const MAX_OVERLOAD_COUNTS: usize = 128;
const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AuditAuthMethod {
    None = 0,
    Token = 1,
    AppRole = 2,
    LocalPeer = 3,
    Recovery = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AuditCapability {
    SecretRead = 1,
    SecretWrite = 2,
    SecretDelete = 3,
    SecretDestroy = 4,
    IdentityManage = 5,
    GrantManage = 6,
    CredentialManage = 7,
    AuditRead = 8,
    AuditExport = 9,
    AuditCheckpointManage = 10,
    DiagnosticsRead = 11,
    BackupManage = 12,
    StoreKeyRotate = 13,
    TransportManage = 14,
    ConsumerManage = 15,
    RotationManage = 16,
    RecoveryManage = 17,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AuditOperation {
    Genesis = 1,
    InitializedStoreRefused = 2,
    SecretRead = 3,
    SecretWrite = 4,
    SecretDelete = 5,
    SecretDestroy = 6,
    ClockHighWaterCheckpoint = 7,
    RateLimitAggregate = 8,
    IdentityChange = 9,
    GrantChange = 10,
    CredentialChange = 11,
    KeyringChange = 12,
    Checkpoint = 13,
    RecoveryFork = 14,
    Restore = 15,
    Migration = 16,
    Compaction = 17,
    Backup = 18,
    AuditExport = 19,
    TransportReload = 20,
    Shutdown = 21,
}

impl AuditOperation {
    fn is_state_mutation(self) -> bool {
        matches!(
            self,
            Self::SecretWrite
                | Self::SecretDelete
                | Self::SecretDestroy
                | Self::ClockHighWaterCheckpoint
                | Self::IdentityChange
                | Self::GrantChange
                | Self::CredentialChange
                | Self::KeyringChange
                | Self::RecoveryFork
                | Self::Restore
                | Self::Migration
                | Self::Compaction
                | Self::TransportReload
        )
    }

    fn is_bulk(self) -> bool {
        matches!(self, Self::Restore | Self::Migration | Self::Compaction)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AuditOutcome {
    Succeeded = 1,
    Denied = 2,
    Failed = 3,
    Aggregated = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AuditReason {
    None = 0,
    AuthenticationFailed = 1,
    AuthorizationDenied = 2,
    InvalidTarget = 3,
    Conflict = 4,
    NotFound = 5,
    RateLimited = 6,
    IntegrityFailure = 7,
    InternalFailure = 8,
    OperatorRequested = 9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RawTargetReason {
    InvalidEncoding = 1,
    InvalidSeparator = 2,
    InvalidSegment = 3,
    TooLong = 4,
}

macro_rules! decode_enum {
    ($name:ident, $value:expr, [$($variant:ident),+ $(,)?]) => {{
        match $value {
            $(value if value == $name::$variant as u16 => Ok($name::$variant),)+
            _ => Err(CodecError::Invalid),
        }
    }};
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditAuthentication {
    pub method: AuditAuthMethod,
    pub identity_id: Option<[u8; 16]>,
    pub credential_accessor: Option<[u8; 16]>,
    pub succeeded: bool,
    pub failure_reason: Option<AuditReason>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditAuthorization {
    pub capability: Option<AuditCapability>,
    pub allowed: bool,
    pub reason: AuditReason,
}

#[derive(Clone, Eq, PartialEq)]
pub enum AuditResource {
    Canonical(String),
    Rejected {
        reason: RawTargetReason,
        digest: [u8; 32],
        offset: u16,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub struct FloodAggregate {
    pub source_bucket: [u8; 16],
    pub count: u64,
    pub window_start_milliseconds: u64,
    pub window_end_milliseconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuditOverloadCount {
    pub lane: u8,
    pub operation: u16,
    pub class: u16,
    pub count: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub enum AuditStateCommitment {
    None,
    Delta(StateDeltaSet),
    WholeState(WholeStateTransition),
}

/// Secret-safe by construction at the public boundary: no request body, header,
/// credential, or secret-value field exists. This type intentionally has no
/// `Debug` implementation.
///
/// ```compile_fail
/// use ops_light_secrets_server::store::AuditEvent;
/// fn leak(event: AuditEvent) { println!("{event:?}"); }
/// ```
///
/// ```compile_fail
/// use ops_light_secrets_server::store::AuditEvent;
/// fn inject(mut event: AuditEvent) { event.secret_value = vec![1]; }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct AuditEvent {
    pub event_id: [u8; 16],
    pub request_id: [u8; 16],
    pub authentication: AuditAuthentication,
    pub authorization: AuditAuthorization,
    pub consumer_instance_id: Option<[u8; 16]>,
    pub resource: Option<AuditResource>,
    pub operation: AuditOperation,
    pub outcome: AuditOutcome,
    pub reason: AuditReason,
    pub effective_timestamp_milliseconds: u64,
    pub wall_clock_observation_milliseconds: u64,
    pub secret_version: Option<u64>,
    pub state: AuditStateCommitment,
    pub previous_epoch_terminal: Option<[u8; 32]>,
    pub flood: Option<FloodAggregate>,
    pub overload_counts: Vec<AuditOverloadCount>,
}

impl Zeroize for AuditEvent {
    fn zeroize(&mut self) {
        self.event_id.zeroize();
        self.request_id.zeroize();
        self.authentication.identity_id.zeroize();
        self.authentication.credential_accessor.zeroize();
        self.consumer_instance_id.zeroize();
        if let Some(AuditResource::Canonical(resource)) = &mut self.resource {
            resource.zeroize();
        }
        self.resource = None;
        self.secret_version.zeroize();
        self.state = AuditStateCommitment::None;
        self.previous_epoch_terminal.zeroize();
        if let Some(flood) = &mut self.flood {
            flood.source_bucket.zeroize();
            flood.count.zeroize();
            flood.window_start_milliseconds.zeroize();
            flood.window_end_milliseconds.zeroize();
        }
        self.flood = None;
        for count in &mut self.overload_counts {
            count.lane.zeroize();
            count.operation.zeroize();
            count.class.zeroize();
            count.count.zeroize();
        }
        self.overload_counts.clear();
    }
}

impl AuditEvent {
    pub(crate) fn attach_overloads(
        &mut self,
        snapshot: &OverloadSnapshot,
    ) -> Result<(), CodecError> {
        let mut counts = Vec::with_capacity(snapshot.counts.len());
        for value in &snapshot.counts {
            if counts.len() >= MAX_OVERLOAD_COUNTS || value.count == 0 {
                return Err(CodecError::Limit);
            }
            let (lane, operation, class) = value.bucket.map_or((0, 0, 0), |bucket| {
                (
                    bucket.lane as u8 + 1,
                    bucket.operation as u16 + 1,
                    bucket.class,
                )
            });
            counts.push(AuditOverloadCount {
                lane,
                operation,
                class,
                count: value.count,
            });
        }
        counts.sort_unstable();
        if counts.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CodecError::Invalid);
        }
        self.overload_counts = counts;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CodecError> {
        if self.event_id == [0; 16]
            || self.request_id == [0; 16]
            || self.secret_version == Some(0)
            || (self.authentication.succeeded && self.authentication.failure_reason.is_some())
            || (!self.authentication.succeeded
                && (self.authentication.identity_id.is_some()
                    || self.authentication.failure_reason.is_none()))
            || (self.authorization.allowed && self.authorization.reason != AuditReason::None)
            || (!self.authorization.allowed && self.authorization.reason == AuditReason::None)
            || (self.operation == AuditOperation::Genesis) != self.previous_epoch_terminal.is_some()
            || (self.operation == AuditOperation::RateLimitAggregate) != self.flood.is_some()
        {
            return Err(CodecError::Invalid);
        }
        if let Some(AuditResource::Canonical(resource)) = &self.resource {
            if resource.is_empty() || resource.len() > MAX_RESOURCE || resource.contains('\0') {
                return Err(CodecError::Invalid);
            }
        }
        if let Some(flood) = &self.flood {
            if flood.count == 0 || flood.window_start_milliseconds > flood.window_end_milliseconds {
                return Err(CodecError::Invalid);
            }
        }
        if self.overload_counts.len() > MAX_OVERLOAD_COUNTS
            || self.overload_counts.iter().any(|count| count.count == 0)
            || self
                .overload_counts
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(CodecError::Invalid);
        }
        let successful = self.outcome == AuditOutcome::Succeeded;
        let version_required = successful
            && matches!(
                self.operation,
                AuditOperation::SecretRead | AuditOperation::SecretWrite
            );
        if version_required != self.secret_version.is_some() {
            return Err(CodecError::Invalid);
        }
        match (
            &self.state,
            successful && self.operation.is_state_mutation(),
        ) {
            (AuditStateCommitment::WholeState(_), true) if self.operation.is_bulk() => {}
            (AuditStateCommitment::Delta(_), true) if !self.operation.is_bulk() => {}
            (AuditStateCommitment::None, false) => {}
            _ => return Err(CodecError::Invalid),
        }
        Ok(())
    }
}

impl TransactionAudit for AuditEvent {
    fn state_delta(&self) -> Option<&StateDeltaSet> {
        match &self.state {
            AuditStateCommitment::Delta(delta) => Some(delta),
            AuditStateCommitment::None | AuditStateCommitment::WholeState(_) => None,
        }
    }

    fn whole_state_transition(&self) -> Option<&WholeStateTransition> {
        match &self.state {
            AuditStateCommitment::WholeState(transition) => Some(transition),
            AuditStateCommitment::None | AuditStateCommitment::Delta(_) => None,
        }
    }
}

impl Canonical for AuditEvent {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(AUDIT_SCHEMA_VERSION);
        out.fixed(&self.event_id);
        out.fixed(&self.request_id);
        out.u16(self.authentication.method as u16);
        encode_optional_fixed(&mut out, self.authentication.identity_id.as_ref());
        encode_optional_fixed(&mut out, self.authentication.credential_accessor.as_ref());
        out.bool(self.authentication.succeeded);
        encode_optional_reason(&mut out, self.authentication.failure_reason);
        encode_optional_capability(&mut out, self.authorization.capability);
        out.bool(self.authorization.allowed);
        out.u16(self.authorization.reason as u16);
        encode_optional_fixed(&mut out, self.consumer_instance_id.as_ref());
        encode_resource(&mut out, self.resource.as_ref())?;
        out.u16(self.operation as u16);
        out.u16(self.outcome as u16);
        out.u16(self.reason as u16);
        out.u64(self.effective_timestamp_milliseconds);
        out.u64(self.wall_clock_observation_milliseconds);
        encode_optional_u64(&mut out, self.secret_version);
        match &self.state {
            AuditStateCommitment::None => out.u8(0),
            AuditStateCommitment::Delta(delta) => {
                out.u8(1);
                out.bytes(&delta.encode()?, MAX_AUDIT_EVENT_BYTES)?;
            }
            AuditStateCommitment::WholeState(transition) => {
                out.u8(2);
                out.bytes(&transition.encode()?, MAX_AUDIT_EVENT_BYTES)?;
            }
        }
        encode_optional_fixed(&mut out, self.previous_epoch_terminal.as_ref());
        match &self.flood {
            None => out.u8(0),
            Some(flood) => {
                out.u8(1);
                out.fixed(&flood.source_bucket);
                out.u64(flood.count);
                out.u64(flood.window_start_milliseconds);
                out.u64(flood.window_end_milliseconds);
            }
        }
        out.u16(self.overload_counts.len() as u16);
        for count in &self.overload_counts {
            out.u8(count.lane);
            out.u16(count.operation);
            out.u16(count.class);
            out.u64(count.count);
        }
        let bytes = out.finish();
        if bytes.len() > MAX_AUDIT_EVENT_BYTES {
            return Err(CodecError::Limit);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_AUDIT_EVENT_BYTES {
            return Err(CodecError::Limit);
        }
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != AUDIT_SCHEMA_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let event_id = input.fixed()?;
        let request_id = input.fixed()?;
        let method = decode_enum!(
            AuditAuthMethod,
            input.u16()?,
            [None, Token, AppRole, LocalPeer, Recovery]
        )?;
        let identity_id = decode_optional_fixed(&mut input)?;
        let credential_accessor = decode_optional_fixed(&mut input)?;
        let auth_succeeded = input.bool()?;
        let failure_reason = decode_optional_reason(&mut input)?;
        let capability = decode_optional_capability(&mut input)?;
        let allowed = input.bool()?;
        let authorization_reason = decode_reason(input.u16()?)?;
        let consumer_instance_id = decode_optional_fixed(&mut input)?;
        let resource = decode_resource(&mut input)?;
        let operation = decode_operation(input.u16()?)?;
        let outcome = decode_outcome(input.u16()?)?;
        let reason = decode_reason(input.u16()?)?;
        let effective_timestamp_milliseconds = input.u64()?;
        let wall_clock_observation_milliseconds = input.u64()?;
        let secret_version = decode_optional_u64(&mut input)?;
        let state = match input.u8()? {
            0 => AuditStateCommitment::None,
            1 => AuditStateCommitment::Delta(StateDeltaSet::decode(
                &input.bytes(MAX_AUDIT_EVENT_BYTES)?,
            )?),
            2 => AuditStateCommitment::WholeState(WholeStateTransition::decode(
                &input.bytes(MAX_AUDIT_EVENT_BYTES)?,
            )?),
            _ => return Err(CodecError::Invalid),
        };
        let previous_epoch_terminal = decode_optional_fixed(&mut input)?;
        let flood = match input.u8()? {
            0 => None,
            1 => Some(FloodAggregate {
                source_bucket: input.fixed()?,
                count: input.u64()?,
                window_start_milliseconds: input.u64()?,
                window_end_milliseconds: input.u64()?,
            }),
            _ => return Err(CodecError::Invalid),
        };
        let overload_count = input.u16()? as usize;
        if overload_count > MAX_OVERLOAD_COUNTS {
            return Err(CodecError::Limit);
        }
        let mut overload_counts = Vec::with_capacity(overload_count);
        for _ in 0..overload_count {
            overload_counts.push(AuditOverloadCount {
                lane: input.u8()?,
                operation: input.u16()?,
                class: input.u16()?,
                count: input.u64()?,
            });
        }
        input.finish()?;
        let value = Self {
            event_id,
            request_id,
            authentication: AuditAuthentication {
                method,
                identity_id,
                credential_accessor,
                succeeded: auth_succeeded,
                failure_reason,
            },
            authorization: AuditAuthorization {
                capability,
                allowed,
                reason: authorization_reason,
            },
            consumer_instance_id,
            resource,
            operation,
            outcome,
            reason,
            effective_timestamp_milliseconds,
            wall_clock_observation_milliseconds,
            secret_version,
            state,
            previous_epoch_terminal,
            flood,
            overload_counts,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEnvelope {
    pub audit_epoch: [u8; 16],
    pub epoch_sequence: u64,
    pub effective_timestamp_milliseconds: u64,
    pub previous_hash: [u8; 32],
    pub ciphertext_digest: [u8; 32],
}

impl AuditEnvelope {
    pub fn chain_hash(&self) -> Result<[u8; 32], CodecError> {
        let encoded = self.encode()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ops-light-secrets-server.audit-chain.v1\0");
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl Canonical for AuditEnvelope {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.audit_epoch == [0; 16] || self.epoch_sequence == 0 {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u16(AUDIT_ENVELOPE_VERSION);
        out.fixed(&self.audit_epoch);
        out.u64(self.epoch_sequence);
        out.u64(self.effective_timestamp_milliseconds);
        out.fixed(&self.previous_hash);
        out.fixed(&self.ciphertext_digest);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != AUDIT_ENVELOPE_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            audit_epoch: input.fixed()?,
            epoch_sequence: input.u64()?,
            effective_timestamp_milliseconds: input.u64()?,
            previous_hash: input.fixed()?,
            ciphertext_digest: input.fixed()?,
        };
        input.finish()?;
        if value.audit_epoch == [0; 16] || value.epoch_sequence == 0 {
            return Err(CodecError::Invalid);
        }
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredAuditEntry {
    pub envelope: AuditEnvelope,
    pub encrypted_payload: EncryptedRecord,
}

impl StoredAuditEntry {
    pub fn prepare(
        keyring: &Keyring,
        event: &AuditEvent,
        audit_epoch: [u8; 16],
        epoch_sequence: u64,
        previous_hash: [u8; 32],
        random: &mut impl RandomSource,
    ) -> Result<Self, AuditError> {
        event.validate()?;
        let binding = audit_binding(
            audit_epoch,
            epoch_sequence,
            event.event_id,
            event.effective_timestamp_milliseconds,
            previous_hash,
        )?;
        let plaintext = event.encode()?;
        let encrypted_payload = keyring.encrypt_record(&binding, &plaintext, random)?;
        let frame = encrypted_payload.encode()?;
        let envelope = AuditEnvelope {
            audit_epoch,
            epoch_sequence,
            effective_timestamp_milliseconds: event.effective_timestamp_milliseconds,
            previous_hash,
            ciphertext_digest: *blake3::hash(&frame).as_bytes(),
        };
        Ok(Self {
            envelope,
            encrypted_payload,
        })
    }

    pub fn decrypt(&self, keyring: &Keyring) -> Result<SecretBox<AuditEvent>, AuditError> {
        self.verify_frame()?;
        let expected = audit_binding_from_entry(self)?;
        let plaintext = keyring.decrypt_record(&expected, &self.encrypted_payload)?;
        let event = AuditEvent::decode(plaintext.expose_secret())?;
        if event.event_id
            != self
                .encrypted_payload
                .header()
                .binding()
                .logical_record_id()[..16]
            || event.effective_timestamp_milliseconds
                != self.envelope.effective_timestamp_milliseconds
        {
            return Err(AuditError::Integrity);
        }
        Ok(SecretBox::new(Box::new(event)))
    }

    pub fn verify_frame(&self) -> Result<(), AuditError> {
        let frame = self.encrypted_payload.encode()?;
        if *blake3::hash(&frame).as_bytes() != self.envelope.ciphertext_digest {
            return Err(AuditError::Integrity);
        }
        let binding = audit_binding_from_entry(self)?;
        if self.encrypted_payload.header().binding() != &binding {
            return Err(AuditError::Integrity);
        }
        Ok(())
    }
}

impl Canonical for StoredAuditEntry {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.bytes(&self.envelope.encode()?, 256)?;
        out.bytes(
            &self
                .encrypted_payload
                .encode()
                .map_err(|_| CodecError::Invalid)?,
            MAX_AUDIT_FRAME_BYTES,
        )?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let envelope = AuditEnvelope::decode(&input.bytes(256)?)?;
        let encrypted_payload = EncryptedRecord::decode(&input.bytes(MAX_AUDIT_FRAME_BYTES)?)
            .map_err(|_| CodecError::Invalid)?;
        input.finish()?;
        let value = Self {
            envelope,
            encrypted_payload,
        };
        value.verify_frame().map_err(|_| CodecError::Invalid)?;
        Ok(value)
    }
}

pub fn verify_chain<'a, I>(entries: I) -> Result<[u8; 32], AuditError>
where
    I: IntoIterator<Item = &'a StoredAuditEntry>,
{
    let mut epochs: BTreeMap<[u8; 16], Vec<&StoredAuditEntry>> = BTreeMap::new();
    for entry in entries {
        entry.verify_frame()?;
        epochs
            .entry(entry.envelope.audit_epoch)
            .or_default()
            .push(entry);
    }
    if epochs.len() != 1 {
        return Err(AuditError::Sequence);
    }
    let entries = epochs.values_mut().next().ok_or(AuditError::Sequence)?;
    entries.sort_by_key(|entry| entry.envelope.epoch_sequence);
    let mut previous = ZERO_HASH;
    for (index, entry) in entries.iter().enumerate() {
        if entry.envelope.epoch_sequence != index as u64 + 1
            || entry.envelope.previous_hash != previous
            || (index > 0
                && entry.envelope.effective_timestamp_milliseconds
                    < entries[index - 1].envelope.effective_timestamp_milliseconds)
        {
            return Err(AuditError::Sequence);
        }
        previous = entry.envelope.chain_hash()?;
    }
    Ok(previous)
}

pub fn genesis_event(
    event_id: [u8; 16],
    request_id: [u8; 16],
    effective_timestamp_milliseconds: u64,
    previous_epoch_terminal: [u8; 32],
) -> AuditEvent {
    AuditEvent {
        event_id,
        request_id,
        authentication: AuditAuthentication {
            method: AuditAuthMethod::None,
            identity_id: None,
            credential_accessor: None,
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: None,
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: None,
        resource: None,
        operation: AuditOperation::Genesis,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::None,
        effective_timestamp_milliseconds,
        wall_clock_observation_milliseconds: effective_timestamp_milliseconds,
        secret_version: None,
        state: AuditStateCommitment::None,
        previous_epoch_terminal: Some(previous_epoch_terminal),
        flood: None,
        overload_counts: Vec::new(),
    }
}

fn audit_binding(
    epoch: [u8; 16],
    sequence: u64,
    event_id: [u8; 16],
    effective: u64,
    previous_hash: [u8; 32],
) -> Result<RecordBinding, AuditError> {
    let mut logical_id = Vec::with_capacity(72);
    logical_id.extend_from_slice(&event_id);
    logical_id.extend_from_slice(&epoch);
    logical_id.extend_from_slice(&sequence.to_be_bytes());
    logical_id.extend_from_slice(&effective.to_be_bytes());
    logical_id.extend_from_slice(&previous_hash);
    RecordBinding::new(
        RecordDomain::AuditPayload,
        "audit",
        LogicalPath::new("events/payload")?,
        &logical_id,
        None,
        effective,
    )
    .map_err(Into::into)
}

fn audit_binding_from_entry(entry: &StoredAuditEntry) -> Result<RecordBinding, AuditError> {
    let logical_id = entry
        .encrypted_payload
        .header()
        .binding()
        .logical_record_id();
    if logical_id.len() != 80
        || logical_id[16..32] != entry.envelope.audit_epoch
        || logical_id[32..40] != entry.envelope.epoch_sequence.to_be_bytes()
        || logical_id[40..48]
            != entry
                .envelope
                .effective_timestamp_milliseconds
                .to_be_bytes()
        || logical_id[48..80] != entry.envelope.previous_hash
    {
        return Err(AuditError::Integrity);
    }
    audit_binding(
        entry.envelope.audit_epoch,
        entry.envelope.epoch_sequence,
        logical_id[..16].try_into().unwrap(),
        entry.envelope.effective_timestamp_milliseconds,
        entry.envelope.previous_hash,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    Codec(CodecError),
    Crypto(RecordCryptoError),
    Keyring(KeyringError),
    Integrity,
    Sequence,
}

impl From<CodecError> for AuditError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<RecordCryptoError> for AuditError {
    fn from(value: RecordCryptoError) -> Self {
        Self::Crypto(value)
    }
}
impl From<KeyringError> for AuditError {
    fn from(value: KeyringError) -> Self {
        Self::Keyring(value)
    }
}
impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Codec(_) => "audit encoding failed",
            Self::Crypto(_) | Self::Keyring(_) => "audit cryptography failed",
            Self::Integrity => "audit integrity failed",
            Self::Sequence => "audit sequence failed",
        })
    }
}
impl std::error::Error for AuditError {}

fn encode_optional_fixed<const N: usize>(out: &mut Encoder, value: Option<&[u8; N]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(value);
        }
    }
}
fn decode_optional_fixed<const N: usize>(
    input: &mut Decoder<'_>,
) -> Result<Option<[u8; N]>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => Err(CodecError::Invalid),
    }
}
fn encode_optional_u64(out: &mut Encoder, value: Option<u64>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u64(value);
        }
    }
}
fn decode_optional_u64(input: &mut Decoder<'_>) -> Result<Option<u64>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.u64()?)),
        _ => Err(CodecError::Invalid),
    }
}
fn encode_optional_reason(out: &mut Encoder, value: Option<AuditReason>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u16(value as u16);
        }
    }
}
fn decode_optional_reason(input: &mut Decoder<'_>) -> Result<Option<AuditReason>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_reason(input.u16()?)?)),
        _ => Err(CodecError::Invalid),
    }
}
fn encode_optional_capability(out: &mut Encoder, value: Option<AuditCapability>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u16(value as u16);
        }
    }
}
fn decode_optional_capability(
    input: &mut Decoder<'_>,
) -> Result<Option<AuditCapability>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_capability(input.u16()?)?)),
        _ => Err(CodecError::Invalid),
    }
}
fn encode_resource(out: &mut Encoder, value: Option<&AuditResource>) -> Result<(), CodecError> {
    match value {
        None => out.u8(0),
        Some(AuditResource::Canonical(value)) => {
            out.u8(1);
            out.string(value, MAX_RESOURCE)?;
        }
        Some(AuditResource::Rejected {
            reason,
            digest,
            offset,
        }) => {
            out.u8(2);
            out.u16(*reason as u16);
            out.fixed(digest);
            out.u16(*offset);
        }
    }
    Ok(())
}
fn decode_resource(input: &mut Decoder<'_>) -> Result<Option<AuditResource>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(AuditResource::Canonical(input.string(MAX_RESOURCE)?))),
        2 => Ok(Some(AuditResource::Rejected {
            reason: decode_enum!(
                RawTargetReason,
                input.u16()?,
                [InvalidEncoding, InvalidSeparator, InvalidSegment, TooLong]
            )?,
            digest: input.fixed()?,
            offset: input.u16()?,
        })),
        _ => Err(CodecError::Invalid),
    }
}
fn decode_reason(value: u16) -> Result<AuditReason, CodecError> {
    decode_enum!(
        AuditReason,
        value,
        [
            None,
            AuthenticationFailed,
            AuthorizationDenied,
            InvalidTarget,
            Conflict,
            NotFound,
            RateLimited,
            IntegrityFailure,
            InternalFailure,
            OperatorRequested
        ]
    )
}
fn decode_outcome(value: u16) -> Result<AuditOutcome, CodecError> {
    decode_enum!(AuditOutcome, value, [Succeeded, Denied, Failed, Aggregated])
}
fn decode_operation(value: u16) -> Result<AuditOperation, CodecError> {
    decode_enum!(
        AuditOperation,
        value,
        [
            Genesis,
            InitializedStoreRefused,
            SecretRead,
            SecretWrite,
            SecretDelete,
            SecretDestroy,
            ClockHighWaterCheckpoint,
            RateLimitAggregate,
            IdentityChange,
            GrantChange,
            CredentialChange,
            KeyringChange,
            Checkpoint,
            RecoveryFork,
            Restore,
            Migration,
            Compaction,
            Backup,
            AuditExport,
            TransportReload,
            Shutdown
        ]
    )
}
fn decode_capability(value: u16) -> Result<AuditCapability, CodecError> {
    decode_enum!(
        AuditCapability,
        value,
        [
            SecretRead,
            SecretWrite,
            SecretDelete,
            SecretDestroy,
            IdentityManage,
            GrantManage,
            CredentialManage,
            AuditRead,
            AuditExport,
            AuditCheckpointManage,
            DiagnosticsRead,
            BackupManage,
            StoreKeyRotate,
            TransportManage,
            ConsumerManage,
            RotationManage,
            RecoveryManage
        ]
    )
}
