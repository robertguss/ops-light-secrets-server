//! Versioned canonical codecs and the single-file redb schema.

mod aead;
mod codec;
mod integrity;
pub mod keyring;

pub use aead::{
    CIPHER_SUITE_XCHACHA20_POLY1305, EncryptedRecord, PlaintextSecret, RECORD_FORMAT_VERSION,
    RecordBinding, RecordCryptoError, RecordDomain, RecordHeader,
};
pub use codec::{Canonical, CodecError};
pub use integrity::{
    BulkTransitionKind, ClearRecord, EncryptedTable, IntegrityDiagnostic, IntegrityOperation,
    IntegrityStatus, MAC_FORMAT_VERSION, MacConformanceReport, MacVerification, RecordClass,
    StateDelta, StateDeltaSet, StateDigest, StateTuple, WholeStateTransition, mac_conformance,
};

use crate::clock::WatermarkCommand;
use codec::{Decoder, Encoder};
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

pub const FORMAT_VERSION: u32 = 1;
pub const METADATA_SCHEMA_VERSION: u16 = 1;
pub const MAINTENANCE_MARKER_FILE: &str = ".ops-light-secrets-server.maintenance.marker.v1";
const MAX_PATH: usize = 1024;
const MAX_OPAQUE: usize = 1024;
const MAX_CUSTOM_ENTRIES: usize = 64;
const MAX_CUSTOM_KEY: usize = 128;
const MAX_CUSTOM_VALUE: usize = 1024;
const MAX_ENVELOPE: usize = 1024 * 1024;
const MAX_CIPHERTEXT: usize = 8 * 1024 * 1024;

const META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta");
const SYSTEM_KEYRING: TableDefinition<&[u8], &[u8]> = TableDefinition::new("system_keyring");
const SECRET_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("secret_meta");
const SECRETS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("secrets");
const META_KEY: &[u8] = b"\x01store";
const KEYRING_KEY: &[u8] = b"\x01current";
pub(crate) const KEYRING_METADATA_KEY: &[u8] = b"\x01keyring_metadata";
pub(crate) const PROVISIONAL_META_KEY: &[u8] = b"\x01provisional_meta";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StoreId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Lifecycle {
    Ready = 0,
    Reencrypting = 1,
    Restoring = 2,
    Migrating = 3,
    Compacting = 4,
}

impl Lifecycle {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Reencrypting),
            2 => Ok(Self::Restoring),
            3 => Ok(Self::Migrating),
            4 => Ok(Self::Compacting),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PendingAnchorKind {
    RecordKey = 0,
    MetadataKey = 1,
    Migration = 2,
    Compaction = 3,
    NormalRestore = 4,
    RollbackFork = 5,
}

impl PendingAnchorKind {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::RecordKey),
            1 => Ok(Self::MetadataKey),
            2 => Ok(Self::Migration),
            3 => Ok(Self::Compaction),
            4 => Ok(Self::NormalRestore),
            5 => Ok(Self::RollbackFork),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PendingAnchorStatus {
    Installed = 0,
    CheckpointPrepared = 1,
    CheckpointRegistered = 2,
}

impl PendingAnchorStatus {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Installed),
            1 => Ok(Self::CheckpointPrepared),
            2 => Ok(Self::CheckpointRegistered),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorInstalledState {
    Schema(u32),
    KeyringGeneration(u64),
    PayloadGeneration(u64),
    Incarnation([u8; 16]),
}

impl AnchorInstalledState {
    fn encode(self, out: &mut Encoder) {
        match self {
            Self::Schema(value) => {
                out.u8(0);
                out.u32(value);
            }
            Self::KeyringGeneration(value) => {
                out.u8(1);
                out.u64(value);
            }
            Self::PayloadGeneration(value) => {
                out.u8(2);
                out.u64(value);
            }
            Self::Incarnation(value) => {
                out.u8(3);
                out.fixed(&value);
            }
        }
    }

    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        match input.u8()? {
            0 => Ok(Self::Schema(input.u32()?)),
            1 => Ok(Self::KeyringGeneration(input.u64()?)),
            2 => Ok(Self::PayloadGeneration(input.u64()?)),
            3 => Ok(Self::Incarnation(input.fixed()?)),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAnchor {
    pub kind: PendingAnchorKind,
    pub operation_id: Vec<u8>,
    pub plan_or_activation_digest: [u8; 32],
    pub installed_state: AnchorInstalledState,
    pub post_state_digest: [u8; 32],
    pub status: PendingAnchorStatus,
}

impl Canonical for PendingAnchor {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.u8(self.kind as u8);
        out.bytes(&self.operation_id, MAX_OPAQUE)?;
        out.fixed(&self.plan_or_activation_digest);
        self.installed_state.encode(&mut out);
        out.fixed(&self.post_state_digest);
        out.u8(self.status as u8);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            kind: PendingAnchorKind::decode(input.u8()?)?,
            operation_id: input.bytes(MAX_OPAQUE)?,
            plan_or_activation_digest: input.fixed()?,
            installed_state: AnchorInstalledState::decode(&mut input)?,
            post_state_digest: input.fixed()?,
            status: PendingAnchorStatus::decode(input.u8()?)?,
        };
        if value.operation_id.is_empty() {
            return Err(CodecError::Invalid);
        }
        input.finish()?;
        Ok(value)
    }
}

impl ClearRecord for PendingAnchor {
    const CLASS: RecordClass = RecordClass::PendingAnchor;
    const SCHEMA_VERSION: u16 = 1;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sealed<T> {
    pub generation: u64,
    pub value: T,
    class: RecordClass,
    schema_version: u16,
    mac_format_version: u16,
    mac: [u8; 32],
}

impl<T: ClearRecord> Sealed<T> {
    pub fn seal(
        value: T,
        generation: u64,
        key: &[u8; 32],
        store_id: StoreId,
        primary_key: &[u8],
    ) -> Result<Self, CodecError> {
        let encoded = value.encode()?;
        let mac = integrity::record_mac(
            key,
            T::CLASS,
            T::SCHEMA_VERSION,
            store_id,
            primary_key,
            generation,
            &encoded,
        )?;
        Ok(Self {
            generation,
            value,
            class: T::CLASS,
            schema_version: T::SCHEMA_VERSION,
            mac_format_version: MAC_FORMAT_VERSION,
            mac,
        })
    }

    pub fn verify(
        &self,
        key: &[u8; 32],
        store_id: StoreId,
        primary_key: &[u8],
    ) -> Result<(), CodecError> {
        let verification = self.verify_with_work(key, store_id, primary_key)?;
        verification.valid.then_some(()).ok_or(CodecError::Invalid)
    }

    pub fn verify_with_work(
        &self,
        key: &[u8; 32],
        store_id: StoreId,
        primary_key: &[u8],
    ) -> Result<MacVerification, CodecError> {
        if self.mac_format_version != MAC_FORMAT_VERSION
            || self.class != T::CLASS
            || self.schema_version != T::SCHEMA_VERSION
        {
            return Err(CodecError::Invalid);
        }
        let encoded = self.value.encode()?;
        let expected = integrity::record_mac(
            key,
            self.class,
            self.schema_version,
            store_id,
            primary_key,
            self.generation,
            &encoded,
        )?;
        Ok(integrity::compare_tag(&self.mac, &expected))
    }

    pub fn state_tuple(&self, primary_key: &[u8]) -> Result<StateTuple, CodecError> {
        integrity::validate_state_key(primary_key)?;
        Ok(StateTuple::Clear {
            class: self.class,
            primary_key: primary_key.to_vec(),
            generation: self.generation,
            tag: self.mac,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let value = self.value.encode()?;
        let mut out = Encoder::version(1);
        out.u16(self.mac_format_version);
        out.u16(self.class.code());
        out.u16(self.schema_version);
        out.u64(self.generation);
        out.bytes(&value, MAX_CIPHERTEXT)?;
        out.fixed(&self.mac);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let mac_format_version = input.u16()?;
        if mac_format_version != MAC_FORMAT_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let class = RecordClass::from_code(input.u16()?)?;
        let schema_version = input.u16()?;
        if class != T::CLASS || schema_version != T::SCHEMA_VERSION {
            return Err(CodecError::Invalid);
        }
        let generation = input.u64()?;
        let value = T::decode(&input.bytes(MAX_CIPHERTEXT)?)?;
        let mac = input.fixed()?;
        input.finish()?;
        Ok(Self {
            generation,
            value,
            class,
            schema_version,
            mac_format_version,
            mac,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaRecord {
    pub store_id: StoreId,
    pub format_version: u32,
    pub lifecycle: Lifecycle,
    pub high_water_unix_seconds: u64,
    pub pending_anchor: Option<Sealed<PendingAnchor>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionalMetaRecord {
    pub store_id: StoreId,
    pub format_version: u32,
    pub lifecycle: Lifecycle,
    pub high_water_unix_seconds: u64,
}

impl ProvisionalMetaRecord {
    pub fn from_meta(meta: &MetaRecord) -> Self {
        Self {
            store_id: meta.store_id,
            format_version: meta.format_version,
            lifecycle: meta.lifecycle,
            high_water_unix_seconds: meta.high_water_unix_seconds,
        }
    }
}

impl Canonical for ProvisionalMetaRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.fixed(&self.store_id.0);
        out.u32(self.format_version);
        out.u8(self.lifecycle as u8);
        out.u64(self.high_water_unix_seconds);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            store_id: StoreId(input.fixed()?),
            format_version: input.u32()?,
            lifecycle: Lifecycle::decode(input.u8()?)?,
            high_water_unix_seconds: input.u64()?,
        };
        input.finish()?;
        Ok(value)
    }
}

impl ClearRecord for ProvisionalMetaRecord {
    const CLASS: RecordClass = RecordClass::ProvisionalMeta;
    const SCHEMA_VERSION: u16 = 1;
}

impl MetaRecord {
    pub fn seal_pending_anchor(
        &mut self,
        anchor: PendingAnchor,
        generation: u64,
        mac_key: &[u8; 32],
    ) -> Result<(), CodecError> {
        self.pending_anchor = Some(Sealed::seal(
            anchor,
            generation,
            mac_key,
            self.store_id,
            META_KEY,
        )?);
        Ok(())
    }

    pub fn verify_pending_anchor(&self, mac_key: &[u8; 32]) -> Result<(), CodecError> {
        match &self.pending_anchor {
            None => Ok(()),
            Some(anchor) => anchor.verify(mac_key, self.store_id, META_KEY),
        }
    }
}

impl Canonical for MetaRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.fixed(&self.store_id.0);
        out.u32(self.format_version);
        out.u8(self.lifecycle as u8);
        out.u64(self.high_water_unix_seconds);
        match &self.pending_anchor {
            None => out.u8(0),
            Some(anchor) => {
                out.u8(1);
                out.bytes(&anchor.encode()?, MAX_OPAQUE * 2)?;
            }
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            store_id: StoreId(input.fixed()?),
            format_version: input.u32()?,
            lifecycle: Lifecycle::decode(input.u8()?)?,
            high_water_unix_seconds: input.u64()?,
            pending_anchor: match input.u8()? {
                0 => None,
                1 => Some(Sealed::decode(&input.bytes(MAX_OPAQUE * 2)?)?),
                _ => return Err(CodecError::Invalid),
            },
        };
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyringEnvelope(pub Vec<u8>);

impl Canonical for KeyringEnvelope {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.bytes(&self.0, MAX_ENVELOPE)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self(input.bytes(MAX_ENVELOPE)?);
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogicalPath(String);

impl LogicalPath {
    pub fn new(value: impl Into<String>) -> Result<Self, CodecError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PATH
            || value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
            || value
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(CodecError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Canonical for LogicalPath {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.string(&self.0, MAX_PATH)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self::new(input.string(MAX_PATH)?)?;
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VersionState {
    Live = 0,
    SoftDeleted = 1,
    Destroyed = 2,
}

impl VersionState {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Live),
            1 => Ok(Self::SoftDeleted),
            2 => Ok(Self::Destroyed),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionSetSummary {
    pub generation: u64,
    pub current_version: u64,
    pub max_version: u64,
    pub states: BTreeMap<u64, VersionState>,
}

impl VersionSetSummary {
    pub fn empty() -> Self {
        Self {
            generation: 0,
            current_version: 0,
            max_version: 0,
            states: BTreeMap::new(),
        }
    }

    pub fn append(&mut self) -> Result<u64, CodecError> {
        let version = self.max_version.checked_add(1).ok_or(CodecError::Limit)?;
        self.max_version = version;
        self.current_version = version;
        self.states.insert(version, VersionState::Live);
        self.bump()?;
        Ok(version)
    }

    pub fn soft_delete(&mut self, version: u64) -> Result<(), CodecError> {
        let state = self.states.get_mut(&version).ok_or(CodecError::Invalid)?;
        if *state == VersionState::Destroyed {
            return Err(CodecError::Invalid);
        }
        *state = VersionState::SoftDeleted;
        self.bump()
    }

    pub fn undelete(&mut self, version: u64) -> Result<(), CodecError> {
        let state = self.states.get_mut(&version).ok_or(CodecError::Invalid)?;
        if *state != VersionState::SoftDeleted {
            return Err(CodecError::Invalid);
        }
        *state = VersionState::Live;
        self.bump()
    }

    pub fn destroy(&mut self, version: u64) -> Result<(), CodecError> {
        let state = self.states.get_mut(&version).ok_or(CodecError::Invalid)?;
        *state = VersionState::Destroyed;
        self.bump()
    }

    fn bump(&mut self) -> Result<(), CodecError> {
        self.generation = self.generation.checked_add(1).ok_or(CodecError::Limit)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.current_version > self.max_version
            || (self.max_version > 0 && self.current_version != self.max_version)
            || self.states.len() > u32::MAX as usize
            || (self.max_version == 0) != self.states.is_empty()
            || self.states.keys().copied().ne(1..=self.max_version)
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for VersionSetSummary {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u64(self.generation);
        out.u64(self.current_version);
        out.u64(self.max_version);
        out.u32(self.states.len() as u32);
        for (version, state) in &self.states {
            out.u64(*version);
            out.u8(*state as u8);
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let generation = input.u64()?;
        let current_version = input.u64()?;
        let max_version = input.u64()?;
        let count = input.u32()?;
        let mut states = BTreeMap::new();
        let mut previous = 0;
        for _ in 0..count {
            let version = input.u64()?;
            if version <= previous
                || states
                    .insert(version, VersionState::decode(input.u8()?)?)
                    .is_some()
            {
                return Err(CodecError::Invalid);
            }
            previous = version;
        }
        let value = Self {
            generation,
            current_version,
            max_version,
            states,
        };
        value.validate()?;
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RotationState {
    Idle = 0,
    Pending = 1,
    Running = 2,
}

impl RotationState {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Pending),
            2 => Ok(Self::Running),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMetadata {
    pub schema_version: u16,
    pub custom: BTreeMap<String, String>,
    pub max_versions: u16,
    pub cas_required: bool,
    pub last_completed_rotation_unix_seconds: Option<u64>,
    pub rotation_interval_seconds: Option<u64>,
    pub rotation_state: RotationState,
    pub rotation_protection: Option<Vec<u8>>,
    pub versions: VersionSetSummary,
}

impl SecretMetadata {
    pub fn seal(
        self,
        mac_key: &[u8; 32],
        store_id: StoreId,
        path: &LogicalPath,
    ) -> Result<Sealed<Self>, CodecError> {
        let generation = self.versions.generation;
        Sealed::seal(self, generation, mac_key, store_id, &path.encode()?)
    }
}

impl Canonical for SecretMetadata {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.schema_version != METADATA_SCHEMA_VERSION
            || self.custom.len() > MAX_CUSTOM_ENTRIES
            || self.rotation_protection.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u16(self.schema_version);
        out.u16(self.max_versions);
        out.bool(self.cas_required);
        encode_optional_u64(&mut out, self.last_completed_rotation_unix_seconds);
        encode_optional_u64(&mut out, self.rotation_interval_seconds);
        out.u8(self.rotation_state as u8);
        match &self.rotation_protection {
            None => out.u8(0),
            Some(value) => {
                out.u8(1);
                out.bytes(value, MAX_OPAQUE)?;
            }
        }
        out.u16(self.custom.len() as u16);
        for (key, value) in &self.custom {
            if key.is_empty() {
                return Err(CodecError::Invalid);
            }
            out.string(key, MAX_CUSTOM_KEY)?;
            out.string(value, MAX_CUSTOM_VALUE)?;
        }
        out.bytes(&self.versions.encode()?, MAX_OPAQUE * 64)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let schema_version = input.u16()?;
        if schema_version != METADATA_SCHEMA_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let max_versions = input.u16()?;
        let cas_required = input.bool()?;
        let last_completed_rotation_unix_seconds = decode_optional_u64(&mut input)?;
        let rotation_interval_seconds = decode_optional_u64(&mut input)?;
        let rotation_state = RotationState::decode(input.u8()?)?;
        let rotation_protection = match input.u8()? {
            0 => None,
            1 => {
                let value = input.bytes(MAX_OPAQUE)?;
                if value.is_empty() {
                    return Err(CodecError::Invalid);
                }
                Some(value)
            }
            _ => return Err(CodecError::Invalid),
        };
        let count = input.u16()? as usize;
        if count > MAX_CUSTOM_ENTRIES {
            return Err(CodecError::Limit);
        }
        let mut custom = BTreeMap::new();
        let mut previous: Option<String> = None;
        for _ in 0..count {
            let key = input.string(MAX_CUSTOM_KEY)?;
            if key.is_empty() || previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(CodecError::Invalid);
            }
            let value = input.string(MAX_CUSTOM_VALUE)?;
            previous = Some(key.clone());
            if custom.insert(key, value).is_some() {
                return Err(CodecError::Invalid);
            }
        }
        let versions = VersionSetSummary::decode(&input.bytes(MAX_OPAQUE * 64)?)?;
        input.finish()?;
        Ok(Self {
            schema_version,
            custom,
            max_versions,
            cas_required,
            last_completed_rotation_unix_seconds,
            rotation_interval_seconds,
            rotation_state,
            rotation_protection,
            versions,
        })
    }
}

impl ClearRecord for SecretMetadata {
    const CLASS: RecordClass = RecordClass::SecretMetadata;
    const SCHEMA_VERSION: u16 = METADATA_SCHEMA_VERSION;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey {
    pub path: LogicalPath,
    pub version: u64,
}

impl Canonical for SecretKey {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.version == 0 {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.bytes(&self.path.encode()?, MAX_PATH + 5)?;
        out.u64(self.version);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            path: LogicalPath::decode(&input.bytes(MAX_PATH + 5)?)?,
            version: input.u64()?,
        };
        if value.version == 0 {
            return Err(CodecError::Invalid);
        }
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRecord {
    pub version: u64,
    pub created_unix_milliseconds: u64,
    pub key_id: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MaintenanceKind {
    Migration = 0,
    Compaction = 1,
}

impl MaintenanceKind {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Migration),
            1 => Ok(Self::Compaction),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MaintenancePhase {
    Planned = 0,
    Rewriting = 1,
    Verified = 2,
    Installed = 3,
}

impl MaintenancePhase {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Planned),
            1 => Ok(Self::Rewriting),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Installed),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceMarker {
    pub store_id: StoreId,
    pub kind: MaintenanceKind,
    pub job_id: Vec<u8>,
    pub final_plan_digest: [u8; 32],
    pub source_format: u32,
    pub target_format: u32,
    pub source_head: [u8; 32],
    pub source_state: [u8; 32],
    pub phase: MaintenancePhase,
    pub temporary_file_identity: [u8; 32],
    pub owner_uid: u32,
}

impl MaintenanceMarker {
    pub fn seal(self, generation: u64, mac_key: &[u8; 32]) -> Result<Sealed<Self>, CodecError> {
        let store_id = self.store_id;
        Sealed::seal(
            self,
            generation,
            mac_key,
            store_id,
            MAINTENANCE_MARKER_FILE.as_bytes(),
        )
    }
}

impl Canonical for MaintenanceMarker {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.job_id.is_empty() {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.fixed(&self.store_id.0);
        out.u8(self.kind as u8);
        out.bytes(&self.job_id, MAX_OPAQUE)?;
        out.fixed(&self.final_plan_digest);
        out.u32(self.source_format);
        out.u32(self.target_format);
        out.fixed(&self.source_head);
        out.fixed(&self.source_state);
        out.u8(self.phase as u8);
        out.fixed(&self.temporary_file_identity);
        out.u32(self.owner_uid);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            store_id: StoreId(input.fixed()?),
            kind: MaintenanceKind::decode(input.u8()?)?,
            job_id: input.bytes(MAX_OPAQUE)?,
            final_plan_digest: input.fixed()?,
            source_format: input.u32()?,
            target_format: input.u32()?,
            source_head: input.fixed()?,
            source_state: input.fixed()?,
            phase: MaintenancePhase::decode(input.u8()?)?,
            temporary_file_identity: input.fixed()?,
            owner_uid: input.u32()?,
        };
        if value.job_id.is_empty() {
            return Err(CodecError::Invalid);
        }
        input.finish()?;
        Ok(value)
    }
}

impl ClearRecord for MaintenanceMarker {
    const CLASS: RecordClass = RecordClass::MaintenanceMarker;
    const SCHEMA_VERSION: u16 = 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RewriteKind {
    RecordKey = 0,
    MetadataKey = 1,
    AuditPayloadKey = 2,
}

impl RewriteKind {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::RecordKey),
            1 => Ok(Self::MetadataKey),
            2 => Ok(Self::AuditPayloadKey),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RewriteStatus {
    InstalledPendingAnchor = 0,
    AnchoredRewriteCompleteRecoveryPending = 1,
    CompleteRecoveryCurrent = 2,
}

impl RewriteStatus {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::InstalledPendingAnchor),
            1 => Ok(Self::AnchoredRewriteCompleteRecoveryPending),
            2 => Ok(Self::CompleteRecoveryCurrent),
            _ => Err(CodecError::Invalid),
        }
    }

    pub fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::InstalledPendingAnchor,
                Self::AnchoredRewriteCompleteRecoveryPending
            ) | (
                Self::AnchoredRewriteCompleteRecoveryPending,
                Self::CompleteRecoveryCurrent
            )
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewriteJob {
    pub kind: RewriteKind,
    pub operation_id: Vec<u8>,
    pub owner_id: Vec<u8>,
    pub installed_generation: u64,
    pub installed_state_digest: [u8; 32],
    pub checkpoint_digest: [u8; 32],
    pub backup_artifact_digest: [u8; 32],
    pub backup_signature_digest: [u8; 32],
    pub backup_receipt_digest: [u8; 32],
    pub backup_generation: u64,
    pub signature_generation: u64,
    pub receipt_generation: u64,
    pub status: RewriteStatus,
}

impl RewriteJob {
    pub fn advance(&mut self, owner_id: &[u8], next: RewriteStatus) -> Result<(), CodecError> {
        if owner_id != self.owner_id || !self.status.can_advance_to(next) {
            return Err(CodecError::Invalid);
        }
        self.status = next;
        Ok(())
    }

    pub fn seal(
        self,
        generation: u64,
        mac_key: &[u8; 32],
        store_id: StoreId,
    ) -> Result<Sealed<Self>, CodecError> {
        let primary_key = self.operation_id.clone();
        Sealed::seal(self, generation, mac_key, store_id, &primary_key)
    }
}

impl Canonical for RewriteJob {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.operation_id.is_empty() || self.owner_id.is_empty() {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u8(self.kind as u8);
        out.bytes(&self.operation_id, MAX_OPAQUE)?;
        out.bytes(&self.owner_id, MAX_OPAQUE)?;
        out.u64(self.installed_generation);
        out.fixed(&self.installed_state_digest);
        out.fixed(&self.checkpoint_digest);
        out.fixed(&self.backup_artifact_digest);
        out.fixed(&self.backup_signature_digest);
        out.fixed(&self.backup_receipt_digest);
        out.u64(self.backup_generation);
        out.u64(self.signature_generation);
        out.u64(self.receipt_generation);
        out.u8(self.status as u8);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            kind: RewriteKind::decode(input.u8()?)?,
            operation_id: input.bytes(MAX_OPAQUE)?,
            owner_id: input.bytes(MAX_OPAQUE)?,
            installed_generation: input.u64()?,
            installed_state_digest: input.fixed()?,
            checkpoint_digest: input.fixed()?,
            backup_artifact_digest: input.fixed()?,
            backup_signature_digest: input.fixed()?,
            backup_receipt_digest: input.fixed()?,
            backup_generation: input.u64()?,
            signature_generation: input.u64()?,
            receipt_generation: input.u64()?,
            status: RewriteStatus::decode(input.u8()?)?,
        };
        if value.operation_id.is_empty() || value.owner_id.is_empty() {
            return Err(CodecError::Invalid);
        }
        input.finish()?;
        Ok(value)
    }
}

impl ClearRecord for RewriteJob {
    const CLASS: RecordClass = RecordClass::RewriteJob;
    const SCHEMA_VERSION: u16 = 1;
}

impl Canonical for SecretRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.version == 0 {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u64(self.version);
        out.u64(self.created_unix_milliseconds);
        out.fixed(&self.key_id);
        out.fixed(&self.nonce);
        out.bytes(&self.ciphertext, MAX_CIPHERTEXT)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            version: input.u64()?,
            created_unix_milliseconds: input.u64()?,
            key_id: input.fixed()?,
            nonce: input.fixed()?,
            ciphertext: input.bytes(MAX_CIPHERTEXT)?,
        };
        if value.version == 0 {
            return Err(CodecError::Invalid);
        }
        input.finish()?;
        Ok(value)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum StoreError {
    Database,
    Codec(CodecError),
    Uninitialized,
    AlreadyInitialized,
    UnsupportedFormat(u32),
    Integrity,
}

#[derive(Debug)]
pub enum SecretDataError {
    Store(StoreError),
    Crypto(RecordCryptoError),
}

impl fmt::Display for SecretDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Store(_) => "secret storage operation failed",
            Self::Crypto(_) => "secret cryptographic operation failed",
        })
    }
}

impl std::error::Error for SecretDataError {}

impl From<StoreError> for SecretDataError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<RecordCryptoError> for SecretDataError {
    fn from(error: RecordCryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<CodecError> for SecretDataError {
    fn from(error: CodecError) -> Self {
        Self::Store(StoreError::Codec(error))
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database => "store database operation failed",
            Self::Codec(_) => "store canonical record invalid",
            Self::Uninitialized => "store is uninitialized",
            Self::AlreadyInitialized => "store is already initialized",
            Self::UnsupportedFormat(_) => "store format is unsupported",
            Self::Integrity => "store integrity verification failed",
        })
    }
}

impl std::error::Error for StoreError {}

impl From<CodecError> for StoreError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

pub struct Store {
    database: Database,
    integrity: integrity::IntegrityMonitor,
}

impl Store {
    pub fn create_with_keyring(
        path: impl AsRef<Path>,
        meta: &MetaRecord,
        prepared: &keyring::PreparedKeyring,
    ) -> Result<Self, StoreError> {
        if meta.format_version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedFormat(meta.format_version));
        }
        if prepared.store_id != meta.store_id {
            return Err(StoreError::Integrity);
        }
        let database = Database::create(path).map_err(|_| StoreError::Database)?;
        let write = database.begin_write().map_err(|_| StoreError::Database)?;
        {
            let mut meta_table = write.open_table(META).map_err(|_| StoreError::Database)?;
            if meta_table
                .get(META_KEY)
                .map_err(|_| StoreError::Database)?
                .is_some()
            {
                return Err(StoreError::AlreadyInitialized);
            }
            let encoded_meta = meta.encode()?;
            let encoded_keyring_metadata = prepared.metadata.encode()?;
            let encoded_provisional_meta = prepared
                .provisional_meta
                .as_ref()
                .ok_or(StoreError::Integrity)?
                .encode()?;
            meta_table
                .insert(META_KEY, encoded_meta.as_slice())
                .map_err(|_| StoreError::Database)?;
            meta_table
                .insert(KEYRING_METADATA_KEY, encoded_keyring_metadata.as_slice())
                .map_err(|_| StoreError::Database)?;
            meta_table
                .insert(PROVISIONAL_META_KEY, encoded_provisional_meta.as_slice())
                .map_err(|_| StoreError::Database)?;
            let mut keyring_table = write
                .open_table(SYSTEM_KEYRING)
                .map_err(|_| StoreError::Database)?;
            let envelope = prepared.envelope.encode()?;
            keyring_table
                .insert(KEYRING_KEY, envelope.as_slice())
                .map_err(|_| StoreError::Database)?;
            write
                .open_table(SECRET_META)
                .map_err(|_| StoreError::Database)?;
            write
                .open_table(SECRETS)
                .map_err(|_| StoreError::Database)?;
        }
        write.commit().map_err(|_| StoreError::Database)?;
        Ok(Self {
            database,
            integrity: integrity::IntegrityMonitor::default(),
        })
    }

    pub fn create(path: impl AsRef<Path>, meta: &MetaRecord) -> Result<Self, StoreError> {
        if meta.format_version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedFormat(meta.format_version));
        }
        let database = Database::create(path).map_err(|_| StoreError::Database)?;
        let write = database.begin_write().map_err(|_| StoreError::Database)?;
        {
            let mut table = write.open_table(META).map_err(|_| StoreError::Database)?;
            if table
                .get(META_KEY)
                .map_err(|_| StoreError::Database)?
                .is_some()
            {
                return Err(StoreError::AlreadyInitialized);
            }
            let encoded = meta.encode()?;
            table
                .insert(META_KEY, encoded.as_slice())
                .map_err(|_| StoreError::Database)?;
            write
                .open_table(SYSTEM_KEYRING)
                .map_err(|_| StoreError::Database)?;
            write
                .open_table(SECRET_META)
                .map_err(|_| StoreError::Database)?;
            write
                .open_table(SECRETS)
                .map_err(|_| StoreError::Database)?;
        }
        write.commit().map_err(|_| StoreError::Database)?;
        Ok(Self {
            database,
            integrity: integrity::IntegrityMonitor::default(),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let database = Database::open(path).map_err(|_| StoreError::Database)?;
        let store = Self {
            database,
            integrity: integrity::IntegrityMonitor::default(),
        };
        let meta = store.meta()?;
        if meta.format_version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedFormat(meta.format_version));
        }
        Ok(store)
    }

    pub fn meta(&self) -> Result<MetaRecord, StoreError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| StoreError::Database)?;
        let table = read
            .open_table(META)
            .map_err(|_| StoreError::Uninitialized)?;
        let value = table
            .get(META_KEY)
            .map_err(|_| StoreError::Database)?
            .ok_or(StoreError::Uninitialized)?;
        Ok(MetaRecord::decode(value.value())?)
    }

    pub fn set_meta(
        &self,
        expected: &MetaRecord,
        replacement: &MetaRecord,
    ) -> Result<(), StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::ManagementMutation)?;
        if replacement.store_id != expected.store_id {
            return Err(StoreError::Integrity);
        }
        if self.provisional_meta()?.is_some()
            && ProvisionalMetaRecord::from_meta(expected)
                != ProvisionalMetaRecord::from_meta(replacement)
        {
            return Err(StoreError::Integrity);
        }
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        {
            let mut table = write.open_table(META).map_err(|_| StoreError::Database)?;
            let current = table
                .get(META_KEY)
                .map_err(|_| StoreError::Database)?
                .ok_or(StoreError::Uninitialized)?
                .value()
                .to_vec();
            if current != expected.encode()? {
                return Err(StoreError::Integrity);
            }
            let encoded = replacement.encode()?;
            table
                .insert(META_KEY, encoded.as_slice())
                .map_err(|_| StoreError::Database)?;
        }
        write.commit().map_err(|_| StoreError::Database)
    }

    pub fn set_meta_authenticated(
        &self,
        expected: &MetaRecord,
        replacement: &MetaRecord,
        mac_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::ManagementMutation)?;
        if replacement.store_id != expected.store_id {
            return Err(StoreError::Integrity);
        }
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        {
            let mut table = write.open_table(META).map_err(|_| StoreError::Database)?;
            let current = table
                .get(META_KEY)
                .map_err(|_| StoreError::Database)?
                .ok_or(StoreError::Uninitialized)?
                .value()
                .to_vec();
            if current != expected.encode()? {
                return Err(StoreError::Integrity);
            }
            let sealed_bytes = table
                .get(PROVISIONAL_META_KEY)
                .map_err(|_| StoreError::Database)?
                .ok_or(StoreError::Integrity)?
                .value()
                .to_vec();
            let current_sealed = Sealed::<ProvisionalMetaRecord>::decode(&sealed_bytes)?;
            if current_sealed.value != ProvisionalMetaRecord::from_meta(expected)
                || current_sealed
                    .verify(mac_key, expected.store_id, PROVISIONAL_META_KEY)
                    .is_err()
            {
                self.integrity
                    .trip(RecordClass::ProvisionalMeta, PROVISIONAL_META_KEY, mac_key);
                return Err(StoreError::Integrity);
            }
            let next_generation = current_sealed
                .generation
                .checked_add(1)
                .ok_or(StoreError::Integrity)?;
            let replacement_sealed = Sealed::seal(
                ProvisionalMetaRecord::from_meta(replacement),
                next_generation,
                mac_key,
                replacement.store_id,
                PROVISIONAL_META_KEY,
            )?;
            let encoded_meta = replacement.encode()?;
            let encoded_sealed = replacement_sealed.encode()?;
            table
                .insert(META_KEY, encoded_meta.as_slice())
                .map_err(|_| StoreError::Database)?;
            table
                .insert(PROVISIONAL_META_KEY, encoded_sealed.as_slice())
                .map_err(|_| StoreError::Database)?;
        }
        write.commit().map_err(|_| StoreError::Database)
    }

    pub fn commit_clock_watermark(&self, command: &WatermarkCommand) -> Result<(), StoreError> {
        let expected = self.meta()?;
        if expected.high_water_unix_seconds != command.expected_high_water_unix_seconds
            || command.replacement_high_water_unix_seconds < expected.high_water_unix_seconds
            || command.effective_unix_seconds > command.replacement_high_water_unix_seconds
        {
            return Err(StoreError::Integrity);
        }
        let mut replacement = expected.clone();
        replacement.high_water_unix_seconds = command.replacement_high_water_unix_seconds;
        self.set_meta(&expected, &replacement)
    }

    pub fn commit_clock_watermark_authenticated(
        &self,
        command: &WatermarkCommand,
        mac_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        let expected = self.meta()?;
        if expected.high_water_unix_seconds != command.expected_high_water_unix_seconds
            || command.replacement_high_water_unix_seconds < expected.high_water_unix_seconds
            || command.effective_unix_seconds > command.replacement_high_water_unix_seconds
        {
            return Err(StoreError::Integrity);
        }
        let mut replacement = expected.clone();
        replacement.high_water_unix_seconds = command.replacement_high_water_unix_seconds;
        self.set_meta_authenticated(&expected, &replacement, mac_key)
    }

    pub fn put_keyring(&self, envelope: &KeyringEnvelope) -> Result<(), StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::ManagementMutation)?;
        self.put(SYSTEM_KEYRING, KEYRING_KEY, &envelope.encode()?)
    }

    pub fn keyring(&self) -> Result<Option<KeyringEnvelope>, StoreError> {
        self.get(SYSTEM_KEYRING, KEYRING_KEY)?
            .map(|bytes| KeyringEnvelope::decode(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn keyring_metadata(&self) -> Result<Option<Sealed<keyring::KeyringMetadata>>, StoreError> {
        self.get(META, KEYRING_METADATA_KEY)?
            .map(|bytes| Sealed::decode(&bytes).map_err(StoreError::from))
            .transpose()
    }

    pub fn provisional_meta(&self) -> Result<Option<Sealed<ProvisionalMetaRecord>>, StoreError> {
        self.get(META, PROVISIONAL_META_KEY)?
            .map(|bytes| Sealed::decode(&bytes).map_err(StoreError::from))
            .transpose()
    }

    pub fn put_secret_metadata(
        &self,
        path: &LogicalPath,
        metadata: &Sealed<SecretMetadata>,
        mac_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::ManagementMutation)?;
        let key = path.encode()?;
        let store_id = self.meta()?.store_id;
        if metadata.generation != metadata.value.versions.generation {
            return Err(StoreError::Integrity);
        }
        metadata
            .verify(mac_key, store_id, &key)
            .map_err(|_| StoreError::Integrity)?;
        self.put(SECRET_META, &key, &metadata.encode()?)
    }

    pub fn secret_metadata(
        &self,
        path: &LogicalPath,
        mac_key: &[u8; 32],
    ) -> Result<Option<Sealed<SecretMetadata>>, StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::Data)?;
        let key = path.encode()?;
        let store_id = self.meta()?.store_id;
        let Some(bytes) = self.get(SECRET_META, &key)? else {
            return Ok(None);
        };
        let value = Sealed::decode(&bytes)?;
        if value.verify(mac_key, store_id, &key).is_err() {
            self.integrity
                .trip(RecordClass::SecretMetadata, &key, mac_key);
            return Err(StoreError::Integrity);
        }
        Ok(Some(value))
    }

    pub(crate) fn commit_encrypted_secret_append(
        &self,
        path: &LogicalPath,
        expected: Option<&Sealed<SecretMetadata>>,
        replacement: &Sealed<SecretMetadata>,
        record: &EncryptedRecord,
        mac_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::ManagementMutation)?;
        let metadata_key = path.encode()?;
        let store_id = self.meta()?.store_id;
        replacement.verify(mac_key, store_id, &metadata_key)?;
        let version = replacement.value.versions.current_version;
        if version == 0
            || replacement.generation != replacement.value.versions.generation
            || record.header().store_id() != store_id
            || record.header().binding().version() != Some(version)
        {
            return Err(StoreError::Integrity);
        }
        match expected {
            None if replacement.generation != 1 || version != 1 => {
                return Err(StoreError::Integrity);
            }
            Some(previous)
                if replacement.generation
                    != previous
                        .generation
                        .checked_add(1)
                        .ok_or(StoreError::Integrity)?
                    || version
                        != previous
                            .value
                            .versions
                            .max_version
                            .checked_add(1)
                            .ok_or(StoreError::Integrity)? =>
            {
                return Err(StoreError::Integrity);
            }
            _ => {}
        }
        let secret_key = SecretKey {
            path: path.clone(),
            version,
        }
        .encode()?;
        let expected_bytes = expected.map(|value| value.encode()).transpose()?;
        let replacement_bytes = replacement.encode()?;
        let record_bytes = record.encode()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        {
            let mut metadata_table = write
                .open_table(SECRET_META)
                .map_err(|_| StoreError::Database)?;
            let current = metadata_table
                .get(metadata_key.as_slice())
                .map_err(|_| StoreError::Database)?
                .map(|value| value.value().to_vec());
            if current != expected_bytes {
                return Err(StoreError::Integrity);
            }
            let mut secrets = write
                .open_table(SECRETS)
                .map_err(|_| StoreError::Database)?;
            if secrets
                .get(secret_key.as_slice())
                .map_err(|_| StoreError::Database)?
                .is_some()
            {
                return Err(StoreError::Integrity);
            }
            metadata_table
                .insert(metadata_key.as_slice(), replacement_bytes.as_slice())
                .map_err(|_| StoreError::Database)?;
            secrets
                .insert(secret_key.as_slice(), record_bytes.as_slice())
                .map_err(|_| StoreError::Database)?;
        }
        write.commit().map_err(|_| StoreError::Database)
    }

    pub(crate) fn encrypted_secret_version(
        &self,
        path: &LogicalPath,
        requested: Option<u64>,
        mac_key: &[u8; 32],
    ) -> Result<Option<(u64, EncryptedRecord)>, StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::Data)?;
        let Some(metadata) = self.secret_metadata(path, mac_key)? else {
            return Ok(None);
        };
        let selected = requested.unwrap_or(metadata.value.versions.current_version);
        if selected == 0 || selected > metadata.value.versions.max_version {
            return Ok(None);
        }
        let read = self
            .database
            .begin_read()
            .map_err(|_| StoreError::Database)?;
        let table = read.open_table(SECRETS).map_err(|_| StoreError::Database)?;
        let mut rows = BTreeMap::new();
        let iterator = table.iter().map_err(|_| StoreError::Database)?;
        for entry in iterator {
            let (key, value) = entry.map_err(|_| StoreError::Database)?;
            let key = SecretKey::decode(key.value())?;
            if key.path == *path
                && (key.version > metadata.value.versions.max_version
                    || rows
                        .insert(key.version, EncryptedRecord::decode(value.value())?)
                        .is_some())
            {
                self.integrity
                    .trip_table("secrets", &path.encode()?, mac_key);
                return Err(StoreError::Integrity);
            }
        }
        for (version, state) in &metadata.value.versions.states {
            if *state != VersionState::Destroyed && !rows.contains_key(version) {
                self.integrity
                    .trip_table("secrets", &path.encode()?, mac_key);
                return Err(StoreError::Integrity);
            }
        }
        Ok(rows.remove(&selected).map(|record| (selected, record)))
    }

    pub fn put_secret(&self, key: &SecretKey, record: &SecretRecord) -> Result<(), StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::ManagementMutation)?;
        if record.version != key.version {
            return Err(StoreError::Integrity);
        }
        self.put(SECRETS, &key.encode()?, &record.encode()?)
    }

    pub fn secret(&self, key: &SecretKey) -> Result<Option<SecretRecord>, StoreError> {
        self.ensure_integrity_operation(IntegrityOperation::Data)?;
        let value = self
            .get(SECRETS, &key.encode()?)?
            .map(|bytes| SecretRecord::decode(&bytes).map_err(StoreError::from))
            .transpose()?;
        if value
            .as_ref()
            .is_some_and(|record| record.version != key.version)
        {
            return Err(StoreError::Integrity);
        }
        Ok(value)
    }

    pub fn integrity_status(&self) -> IntegrityStatus {
        self.integrity.status()
    }

    pub fn integrity_operation_allowed(&self, operation: IntegrityOperation) -> bool {
        self.integrity.operation_allowed(operation)
    }

    pub(crate) fn record_integrity_failure(
        &self,
        class: RecordClass,
        primary_key: &[u8],
        diagnostic_key: &[u8; 32],
    ) {
        self.integrity.trip(class, primary_key, diagnostic_key);
    }

    fn ensure_integrity_operation(&self, operation: IntegrityOperation) -> Result<(), StoreError> {
        self.integrity
            .operation_allowed(operation)
            .then_some(())
            .ok_or(StoreError::Integrity)
    }

    fn put(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StoreError> {
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        {
            let mut table = write
                .open_table(definition)
                .map_err(|_| StoreError::Database)?;
            table.insert(key, value).map_err(|_| StoreError::Database)?;
        }
        write.commit().map_err(|_| StoreError::Database)
    }

    fn get(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| StoreError::Database)?;
        let table = read
            .open_table(definition)
            .map_err(|_| StoreError::Database)?;
        Ok(table
            .get(key)
            .map_err(|_| StoreError::Database)?
            .map(|value| value.value().to_vec()))
    }
}
