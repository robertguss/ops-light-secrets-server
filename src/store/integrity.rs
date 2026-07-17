use super::codec::{Decoder, Encoder};
use super::{Canonical, CodecError, MAX_CIPHERTEXT, Sealed, StoreId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

pub const MAC_FORMAT_VERSION: u16 = 1;
const MAX_STATE_KEY: usize = 4096;
const MAX_STATE_TUPLES: usize = 1_000_000;
const MAX_STATE_DELTAS: usize = 4096;
const MAX_STATE_TUPLE_BYTES: usize = MAX_STATE_KEY + 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum RecordClass {
    ProvisionalMeta = 1,
    SchemaMetadata = 2,
    ClockHighWater = 3,
    KeyringMetadata = 4,
    PendingAnchor = 5,
    SecretMetadata = 6,
    Identity = 7,
    Grant = 8,
    CredentialMetadata = 9,
    RotationState = 10,
    ConsumerDeclaration = 11,
    MaintenanceMarker = 12,
    RewriteJob = 13,
    RecoveryReserveMetadata = 14,
    CheckpointTrustMetadata = 15,
}

impl RecordClass {
    pub const ALL: [Self; 15] = [
        Self::ProvisionalMeta,
        Self::SchemaMetadata,
        Self::ClockHighWater,
        Self::KeyringMetadata,
        Self::PendingAnchor,
        Self::SecretMetadata,
        Self::Identity,
        Self::Grant,
        Self::CredentialMetadata,
        Self::RotationState,
        Self::ConsumerDeclaration,
        Self::MaintenanceMarker,
        Self::RewriteJob,
        Self::RecoveryReserveMetadata,
        Self::CheckpointTrustMetadata,
    ];

    pub const fn code(self) -> u16 {
        self as u16
    }

    pub const fn table_code(self) -> u16 {
        match self {
            Self::ProvisionalMeta
            | Self::SchemaMetadata
            | Self::ClockHighWater
            | Self::KeyringMetadata
            | Self::PendingAnchor => 1,
            Self::SecretMetadata => 2,
            Self::Identity => 3,
            Self::Grant => 4,
            Self::CredentialMetadata => 5,
            Self::RotationState => 6,
            Self::ConsumerDeclaration => 7,
            Self::MaintenanceMarker => 8,
            Self::RewriteJob => 9,
            Self::RecoveryReserveMetadata => 10,
            Self::CheckpointTrustMetadata => 11,
        }
    }

    pub const fn table(self) -> &'static str {
        match self {
            Self::ProvisionalMeta
            | Self::SchemaMetadata
            | Self::ClockHighWater
            | Self::KeyringMetadata
            | Self::PendingAnchor => "meta",
            Self::SecretMetadata => "secret_meta",
            Self::Identity => "identities",
            Self::Grant => "grants",
            Self::CredentialMetadata => "credentials",
            Self::RotationState => "rotations",
            Self::ConsumerDeclaration => "consumers",
            Self::MaintenanceMarker => "maintenance_marker",
            Self::RewriteJob => "rewrite_jobs",
            Self::RecoveryReserveMetadata => "recovery_reserve",
            Self::CheckpointTrustMetadata => "checkpoint_trust",
        }
    }

    pub const fn domain(self) -> &'static str {
        match self {
            Self::ProvisionalMeta => "provisional-meta.v1",
            Self::SchemaMetadata => "schema-metadata.v1",
            Self::ClockHighWater => "clock-high-water.v1",
            Self::KeyringMetadata => "keyring-metadata.v1",
            Self::PendingAnchor => "pending-anchor.v1",
            Self::SecretMetadata => "secret-metadata.v1",
            Self::Identity => "identity.v1",
            Self::Grant => "grant.v1",
            Self::CredentialMetadata => "credential-metadata.v1",
            Self::RotationState => "rotation-state.v1",
            Self::ConsumerDeclaration => "consumer-declaration.v1",
            Self::MaintenanceMarker => "maintenance-marker.v1",
            Self::RewriteJob => "rewrite-job.v1",
            Self::RecoveryReserveMetadata => "recovery-reserve-metadata.v1",
            Self::CheckpointTrustMetadata => "checkpoint-trust-metadata.v1",
        }
    }

    pub(crate) fn from_code(code: u16) -> Result<Self, CodecError> {
        Self::ALL
            .into_iter()
            .find(|class| class.code() == code)
            .ok_or(CodecError::Invalid)
    }
}

pub trait ClearRecord: Canonical {
    const CLASS: RecordClass;
    const SCHEMA_VERSION: u16;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacVerification {
    pub valid: bool,
    pub comparison_work_bytes: usize,
}

/// Re-MAC a sealed clear-record blob under a new integrity key without decoding domain type T.
///
/// Verifies the existing MAC with `old_key`, then returns an identically framed blob whose MAC
/// was produced with `new_key`. Non-sealed values return `Ok(None)`.
pub fn reseal_clear_blob(
    bytes: &[u8],
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    store_id: StoreId,
    primary_key: &[u8],
) -> Result<Option<Vec<u8>>, CodecError> {
    if bytes.first().copied() != Some(1) {
        return Ok(None);
    }
    let mut input = Decoder::version(bytes, 1)?;
    let mac_format_version = input.u16()?;
    if mac_format_version != MAC_FORMAT_VERSION {
        return Ok(None);
    }
    let class_code = input.u16()?;
    let Ok(class) = RecordClass::from_code(class_code) else {
        return Ok(None);
    };
    let schema_version = input.u16()?;
    let generation = input.u64()?;
    let value = input.bytes(MAX_CIPHERTEXT)?;
    let mac = input.fixed()?;
    if input.finish().is_err() {
        return Ok(None);
    }
    let expected = record_mac(
        old_key,
        class,
        schema_version,
        store_id,
        primary_key,
        generation,
        &value,
    )?;
    if !compare_tag(&mac, &expected).valid {
        return Err(CodecError::Invalid);
    }
    let replacement = record_mac(
        new_key,
        class,
        schema_version,
        store_id,
        primary_key,
        generation,
        &value,
    )?;
    let mut out = Encoder::version(1);
    out.u16(mac_format_version);
    out.u16(class.code());
    out.u16(schema_version);
    out.u64(generation);
    out.bytes(&value, MAX_CIPHERTEXT)?;
    out.fixed(&replacement);
    Ok(Some(out.finish()))
}

pub(crate) fn record_mac(
    key: &[u8; 32],
    class: RecordClass,
    schema_version: u16,
    store_id: StoreId,
    primary_key: &[u8],
    generation: u64,
    value: &[u8],
) -> Result<[u8; 32], CodecError> {
    if primary_key.is_empty() || primary_key.len() > MAX_STATE_KEY {
        return Err(CodecError::Limit);
    }
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"ops-light-secrets-server.clear-record-mac.v1\0");
    for field in [
        &MAC_FORMAT_VERSION.to_be_bytes()[..],
        &class.table_code().to_be_bytes(),
        &class.code().to_be_bytes(),
        class.domain().as_bytes(),
        &schema_version.to_be_bytes(),
        &store_id.0,
        primary_key,
        &generation.to_be_bytes(),
        value,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn compare_tag(left: &[u8; 32], right: &[u8; 32]) -> MacVerification {
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        });
    MacVerification {
        valid: difference == 0,
        comparison_work_bytes: 32,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacConformanceReport {
    pub edit_rejected: bool,
    pub primary_key_transplant_rejected: bool,
    pub store_transplant_rejected: bool,
    pub generation_regression_rejected: bool,
    pub wrong_class_rejected: bool,
    pub wrong_schema_rejected: bool,
    pub unknown_mac_version_rejected: bool,
    pub trailing_bytes_rejected: bool,
    pub truncated_tag_rejected: bool,
    pub comparison_work_bytes: usize,
}

impl MacConformanceReport {
    pub fn passed(&self) -> bool {
        self.edit_rejected
            && self.primary_key_transplant_rejected
            && self.store_transplant_rejected
            && self.generation_regression_rejected
            && self.wrong_class_rejected
            && self.wrong_schema_rejected
            && self.unknown_mac_version_rejected
            && self.trailing_bytes_rejected
            && self.truncated_tag_rejected
            && self.comparison_work_bytes == 32
    }
}

pub fn mac_conformance<T: ClearRecord + Clone>(
    original: &T,
    edited: &T,
    generation: u64,
    key: &[u8; 32],
    store_id: StoreId,
    primary_key: &[u8],
) -> Result<MacConformanceReport, CodecError> {
    let sealed = Sealed::seal(original.clone(), generation, key, store_id, primary_key)?;
    let mut edit = sealed.clone();
    edit.value = edited.clone();
    let edit_verification = edit.verify_with_work(key, store_id, primary_key)?;
    let mut regression = sealed.clone();
    regression.generation = generation.wrapping_sub(1);
    let mut wrong_class = sealed.clone();
    wrong_class.class = if T::CLASS == RecordClass::Grant {
        RecordClass::Identity
    } else {
        RecordClass::Grant
    };
    let mut wrong_schema = sealed.clone();
    wrong_schema.schema_version = T::SCHEMA_VERSION.wrapping_add(1);
    let encoded = sealed.encode()?;
    let mut unknown = encoded.clone();
    unknown[1..3].copy_from_slice(&MAC_FORMAT_VERSION.wrapping_add(1).to_be_bytes());
    let mut trailing = encoded.clone();
    trailing.push(0);
    let mut transplanted_key = primary_key.to_vec();
    if transplanted_key.len() < MAX_STATE_KEY {
        transplanted_key.push(0xff);
    } else {
        transplanted_key[0] ^= 0xff;
    }
    Ok(MacConformanceReport {
        edit_rejected: !edit_verification.valid,
        primary_key_transplant_rejected: sealed.verify(key, store_id, &transplanted_key).is_err(),
        store_transplant_rejected: sealed
            .verify(
                key,
                StoreId([store_id.0[0].wrapping_add(1); 16]),
                primary_key,
            )
            .is_err(),
        generation_regression_rejected: regression.verify(key, store_id, primary_key).is_err(),
        wrong_class_rejected: wrong_class.verify(key, store_id, primary_key).is_err(),
        wrong_schema_rejected: wrong_schema.verify(key, store_id, primary_key).is_err(),
        unknown_mac_version_rejected: Sealed::<T>::decode(&unknown).is_err(),
        trailing_bytes_rejected: Sealed::<T>::decode(&trailing).is_err(),
        truncated_tag_rejected: Sealed::<T>::decode(&encoded[..encoded.len() - 1]).is_err(),
        comparison_work_bytes: edit_verification.comparison_work_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityOperation {
    Data,
    ManagementMutation,
    BulkMutation,
    Diagnostics,
    ReadOnlyRecovery,
    OrderlyShutdown,
    OfflineRestoreRepair,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityDiagnostic {
    pub code: &'static str,
    pub table: &'static str,
    pub masked_key_id: String,
}

impl fmt::Display for IntegrityDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "code={} table={} key_id={}",
            self.code, self.table, self.masked_key_id
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrityStatus {
    Healthy,
    Failed(IntegrityDiagnostic),
}

#[derive(Clone, Default)]
pub(crate) struct IntegrityMonitor {
    failure: Arc<Mutex<Option<IntegrityDiagnostic>>>,
}

impl IntegrityMonitor {
    pub(crate) fn trip(&self, class: RecordClass, primary_key: &[u8], diagnostic_key: &[u8; 32]) {
        self.trip_named(
            class.table(),
            &class.code().to_be_bytes(),
            primary_key,
            diagnostic_key,
        );
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn trip_table(
        &self,
        table: &'static str,
        primary_key: &[u8],
        diagnostic_key: &[u8; 32],
    ) {
        self.trip_named(table, table.as_bytes(), primary_key, diagnostic_key);
    }

    fn trip_named(
        &self,
        table: &'static str,
        diagnostic_domain: &[u8],
        primary_key: &[u8],
        diagnostic_key: &[u8; 32],
    ) {
        let mut hasher = blake3::Hasher::new_keyed(diagnostic_key);
        hasher.update(b"ops-light-secrets-server.integrity-key-id.v1\0");
        hasher.update(&(diagnostic_domain.len() as u64).to_be_bytes());
        hasher.update(diagnostic_domain);
        hasher.update(&(primary_key.len() as u64).to_be_bytes());
        hasher.update(primary_key);
        let masked_key_id = encode_hex(&hasher.finalize().as_bytes()[..8]);
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        failure.get_or_insert(IntegrityDiagnostic {
            code: "clear_record_integrity_failure",
            table,
            masked_key_id,
        });
    }

    pub(crate) fn status(&self) -> IntegrityStatus {
        self.failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .map_or(IntegrityStatus::Healthy, IntegrityStatus::Failed)
    }

    pub(crate) fn operation_allowed(&self, operation: IntegrityOperation) -> bool {
        match self.status() {
            IntegrityStatus::Healthy => true,
            IntegrityStatus::Failed(_) => matches!(
                operation,
                IntegrityOperation::Diagnostics
                    | IntegrityOperation::ReadOnlyRecovery
                    | IntegrityOperation::OrderlyShutdown
                    | IntegrityOperation::OfflineRestoreRepair
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum EncryptedTable {
    Secrets = 1,
    AuditPayloads = 2,
    CredentialMaterial = 3,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StateTuple {
    Clear {
        class: RecordClass,
        primary_key: Vec<u8>,
        generation: u64,
        tag: [u8; 32],
    },
    Encrypted {
        table: EncryptedTable,
        primary_key: Vec<u8>,
        record_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum StateIdentity {
    Clear(RecordClass, Vec<u8>),
    Encrypted(EncryptedTable, Vec<u8>),
}

impl StateTuple {
    pub fn encrypted(
        table: EncryptedTable,
        primary_key: &[u8],
        header_nonce_ciphertext: &[u8],
    ) -> Result<Self, CodecError> {
        validate_state_key(primary_key)?;
        Ok(Self::Encrypted {
            table,
            primary_key: primary_key.to_vec(),
            record_digest: *blake3::hash(header_nonce_ciphertext).as_bytes(),
        })
    }

    fn identity(&self) -> StateIdentity {
        match self {
            Self::Clear {
                class, primary_key, ..
            } => StateIdentity::Clear(*class, primary_key.clone()),
            Self::Encrypted {
                table, primary_key, ..
            } => StateIdentity::Encrypted(*table, primary_key.clone()),
        }
    }

    fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Clear { primary_key, .. } | Self::Encrypted { primary_key, .. } => {
                validate_state_key(primary_key)
            }
        }
    }

    fn encode_for_digest(&self, out: &mut Encoder) -> Result<(), CodecError> {
        match self {
            Self::Clear {
                class,
                primary_key,
                generation,
                tag,
            } => {
                out.u8(0);
                out.u16(class.code());
                out.bytes(primary_key, MAX_STATE_KEY)?;
                out.u64(*generation);
                out.fixed(tag);
            }
            Self::Encrypted {
                table,
                primary_key,
                record_digest,
            } => {
                out.u8(1);
                out.u16(*table as u16);
                out.bytes(primary_key, MAX_STATE_KEY)?;
                out.fixed(record_digest);
            }
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        self.encode_for_digest(&mut out)?;
        Ok(out.finish())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = super::Decoder::version(bytes, 1)?;
        let value = match input.u8()? {
            0 => {
                let class = RecordClass::from_code(input.u16()?)?;
                let primary_key = input.bytes(MAX_STATE_KEY)?;
                validate_state_key(&primary_key)?;
                Self::Clear {
                    class,
                    primary_key,
                    generation: input.u64()?,
                    tag: input.fixed()?,
                }
            }
            1 => {
                let table = EncryptedTable::from_code(input.u16()?)?;
                let primary_key = input.bytes(MAX_STATE_KEY)?;
                validate_state_key(&primary_key)?;
                Self::Encrypted {
                    table,
                    primary_key,
                    record_digest: input.fixed()?,
                }
            }
            _ => return Err(CodecError::Invalid),
        };
        input.finish()?;
        Ok(value)
    }
}

impl EncryptedTable {
    fn from_code(code: u16) -> Result<Self, CodecError> {
        match code {
            1 => Ok(Self::Secrets),
            2 => Ok(Self::AuditPayloads),
            3 => Ok(Self::CredentialMaterial),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateDigest(pub [u8; 32]);

impl StateDigest {
    pub fn compute<I: IntoIterator<Item = StateTuple>>(tuples: I) -> Result<Self, CodecError> {
        let mut collected: Vec<StateTuple> = Vec::new();
        for tuple in tuples {
            if collected.len() >= MAX_STATE_TUPLES {
                return Err(CodecError::Limit);
            }
            tuple.validate()?;
            collected.push(tuple);
        }
        let sorted = collected.iter().cloned().collect::<BTreeSet<_>>();
        if sorted.len() != collected.len() {
            return Err(CodecError::Invalid);
        }
        let mut identities = BTreeSet::new();
        if sorted
            .iter()
            .any(|tuple| !identities.insert(tuple.identity()))
        {
            return Err(CodecError::Invalid);
        }
        let mut encoded = Encoder::version(1);
        encoded.u32(sorted.len() as u32);
        for tuple in sorted {
            tuple.encode_for_digest(&mut encoded)?;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ops-light-secrets-server.state-digest.v1\0");
        hasher.update(&encoded.finish());
        Ok(Self(*hasher.finalize().as_bytes()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateDelta {
    before: Option<StateTuple>,
    after: Option<StateTuple>,
}

impl StateDelta {
    pub fn replace(before: StateTuple, after: StateTuple) -> Result<Self, CodecError> {
        before.validate()?;
        after.validate()?;
        if before.identity() != after.identity() || before == after {
            return Err(CodecError::Invalid);
        }
        Ok(Self {
            before: Some(before),
            after: Some(after),
        })
    }

    pub fn delete(before: StateTuple) -> Self {
        Self {
            before: Some(before),
            after: None,
        }
    }

    pub fn insert(after: StateTuple) -> Self {
        Self {
            before: None,
            after: Some(after),
        }
    }

    fn identity(&self) -> StateIdentity {
        self.before
            .as_ref()
            .or(self.after.as_ref())
            .expect("constructors always set one side")
            .identity()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateDeltaSet(Vec<StateDelta>);

impl StateDeltaSet {
    pub fn new<I: IntoIterator<Item = StateDelta>>(deltas: I) -> Result<Self, CodecError> {
        let mut bounded = Vec::new();
        for delta in deltas {
            if bounded.len() >= MAX_STATE_DELTAS {
                return Err(CodecError::Limit);
            }
            if let Some(before) = &delta.before {
                before.validate()?;
            }
            if let Some(after) = &delta.after {
                after.validate()?;
            }
            bounded.push(delta);
        }
        if bounded.is_empty() {
            return Err(CodecError::Limit);
        }
        bounded.sort_by_key(StateDelta::identity);
        if bounded
            .windows(2)
            .any(|pair| pair[0].identity() == pair[1].identity())
        {
            return Err(CodecError::Invalid);
        }
        Ok(Self(bounded))
    }

    pub fn reverse_apply(
        &self,
        current: &BTreeSet<StateTuple>,
    ) -> Result<BTreeSet<StateTuple>, CodecError> {
        let mut tuples = BTreeMap::new();
        for tuple in current {
            if tuples.insert(tuple.identity(), tuple.clone()).is_some() {
                return Err(CodecError::Invalid);
            }
        }
        for delta in self.0.iter().rev() {
            let identity = delta.identity();
            match &delta.after {
                Some(after) if tuples.get(&identity) == Some(after) => {
                    tuples.remove(&identity);
                }
                None if !tuples.contains_key(&identity) => {}
                _ => return Err(CodecError::Invalid),
            }
            if let Some(before) = &delta.before {
                tuples.insert(identity, before.clone());
            }
        }
        Ok(tuples.into_values().collect())
    }
}

impl Canonical for StateDeltaSet {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.u32(self.0.len() as u32);
        for delta in &self.0 {
            encode_optional_tuple(&mut out, delta.before.as_ref())?;
            encode_optional_tuple(&mut out, delta.after.as_ref())?;
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = super::Decoder::version(bytes, 1)?;
        let count = input.u32()? as usize;
        if count == 0 || count > MAX_STATE_DELTAS {
            return Err(CodecError::Limit);
        }
        let mut deltas = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let before = decode_optional_tuple(&mut input)?;
            let after = decode_optional_tuple(&mut input)?;
            if before.is_none() && after.is_none() {
                return Err(CodecError::Invalid);
            }
            if before.as_ref().map(StateTuple::identity) != after.as_ref().map(StateTuple::identity)
                && before.is_some()
                && after.is_some()
            {
                return Err(CodecError::Invalid);
            }
            let delta = StateDelta { before, after };
            let identity = delta.identity();
            if previous.as_ref().is_some_and(|value| value >= &identity) {
                return Err(CodecError::Invalid);
            }
            previous = Some(identity);
            deltas.push(delta);
        }
        input.finish()?;
        Ok(Self(deltas))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkTransitionKind {
    RecordRewrite = 1,
    MetadataRemac = 2,
    Restore = 3,
    Migration = 4,
    Compaction = 5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeStateTransition {
    pub kind: BulkTransitionKind,
    pub operation_id: Vec<u8>,
    pub before: StateDigest,
    pub after: StateDigest,
}

impl Canonical for WholeStateTransition {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.operation_id.is_empty() || self.before == self.after {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u8(self.kind as u8);
        out.bytes(&self.operation_id, 1024)?;
        out.fixed(&self.before.0);
        out.fixed(&self.after.0);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = super::Decoder::version(bytes, 1)?;
        let kind = match input.u8()? {
            1 => BulkTransitionKind::RecordRewrite,
            2 => BulkTransitionKind::MetadataRemac,
            3 => BulkTransitionKind::Restore,
            4 => BulkTransitionKind::Migration,
            5 => BulkTransitionKind::Compaction,
            _ => return Err(CodecError::Invalid),
        };
        let value = Self {
            kind,
            operation_id: input.bytes(1024)?,
            before: StateDigest(input.fixed()?),
            after: StateDigest(input.fixed()?),
        };
        input.finish()?;
        if value.operation_id.is_empty() || value.before == value.after {
            return Err(CodecError::Invalid);
        }
        Ok(value)
    }
}

fn encode_optional_tuple(out: &mut Encoder, tuple: Option<&StateTuple>) -> Result<(), CodecError> {
    match tuple {
        None => out.u8(0),
        Some(tuple) => {
            out.u8(1);
            out.bytes(&tuple.canonical_bytes()?, MAX_STATE_TUPLE_BYTES)?;
        }
    }
    Ok(())
}

fn decode_optional_tuple(input: &mut super::Decoder<'_>) -> Result<Option<StateTuple>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(StateTuple::decode_canonical(
            &input.bytes(MAX_STATE_TUPLE_BYTES)?,
        )?)),
        _ => Err(CodecError::Invalid),
    }
}

pub(crate) fn validate_state_key(primary_key: &[u8]) -> Result<(), CodecError> {
    if primary_key.is_empty() || primary_key.len() > MAX_STATE_KEY {
        Err(CodecError::Limit)
    } else {
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
