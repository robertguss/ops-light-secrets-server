//! G3-frozen logical backup container, manifest, and restore epoch rules.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::store::{Canonical, CodecError, Decoder, Encoder, StoreId};

pub const BACKUP_FORMAT_VERSION: u16 = 1;
pub const BACKUP_MANIFEST_VERSION: u16 = 1;
pub const BACKUP_SIGNATURE_VERSION: u16 = 1;
pub const BACKUP_SIGNING_DOMAIN_ID: u16 = 1;
pub const MAX_ARCHIVE_TABLES: usize = 32;
pub const MAX_TABLE_ENTRIES: usize = 1_000_000;
pub const MAX_ENTRY_KEY_BYTES: usize = 4096;
pub const MAX_ENTRY_VALUE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_EFFECTIVE_RECIPIENTS: usize = 8;
pub const MAX_RECOVERY_RECIPIENTS: usize = 7;
pub const BACKUP_SIGNATURE_DOMAIN: &[u8] =
    b"ops-light-secrets-server.backup-manifest-signature.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum RecoveryEventType {
    BackupPublishing = 1,
    BackupPublished = 2,
    ManifestSignatureRegistered = 3,
    ManifestAbandoned = 4,
    RecoveryReceiptRegistered = 5,
    RestoreActivated = 6,
    UnsignedRestoreOverride = 7,
    RecoveryForkGenesis = 8,
    BackupRecipientSetChanged = 9,
    EmergencyCredentialIssued = 10,
}

impl RecoveryEventType {
    pub const ALL: [Self; 10] = [
        Self::BackupPublishing,
        Self::BackupPublished,
        Self::ManifestSignatureRegistered,
        Self::ManifestAbandoned,
        Self::RecoveryReceiptRegistered,
        Self::RestoreActivated,
        Self::UnsignedRestoreOverride,
        Self::RecoveryForkGenesis,
        Self::BackupRecipientSetChanged,
        Self::EmergencyCredentialIssued,
    ];
}

impl Canonical for RecoveryEventType {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.u16(*self as u16);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = match input.u16()? {
            1 => Self::BackupPublishing,
            2 => Self::BackupPublished,
            3 => Self::ManifestSignatureRegistered,
            4 => Self::ManifestAbandoned,
            5 => Self::RecoveryReceiptRegistered,
            6 => Self::RestoreActivated,
            7 => Self::UnsignedRestoreOverride,
            8 => Self::RecoveryForkGenesis,
            9 => Self::BackupRecipientSetChanged,
            10 => Self::EmergencyCredentialIssued,
            _ => return Err(CodecError::Invalid),
        };
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecipientSet {
    pub generation: u64,
    pub recovery_fingerprints: Vec<[u8; 32]>,
}

impl RecoveryRecipientSet {
    pub fn effective(
        &self,
        active_fingerprint: [u8; 32],
    ) -> Result<EffectiveRecipientSet, CodecError> {
        self.validate()?;
        if active_fingerprint == [0; 32]
            || self
                .recovery_fingerprints
                .binary_search(&active_fingerprint)
                .is_ok()
        {
            return Err(CodecError::Invalid);
        }
        let mut fingerprints = self.recovery_fingerprints.clone();
        fingerprints.push(active_fingerprint);
        fingerprints.sort_unstable();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ops-light-secrets-server.backup-effective-recipients.v1\0");
        for fingerprint in &fingerprints {
            hasher.update(&(fingerprint.len() as u64).to_be_bytes());
            hasher.update(fingerprint);
        }
        Ok(EffectiveRecipientSet {
            recovery_generation: self.generation,
            fingerprints,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.generation == 0
            || !(1..=MAX_RECOVERY_RECIPIENTS).contains(&self.recovery_fingerprints.len())
            || self.recovery_fingerprints.contains(&[0; 32])
            || self
                .recovery_fingerprints
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for RecoveryRecipientSet {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u64(self.generation);
        out.u8(self.recovery_fingerprints.len() as u8);
        for fingerprint in &self.recovery_fingerprints {
            out.fixed(fingerprint);
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let generation = input.u64()?;
        let count = input.u8()? as usize;
        if !(1..=MAX_RECOVERY_RECIPIENTS).contains(&count) {
            return Err(CodecError::Limit);
        }
        let mut recovery_fingerprints = Vec::with_capacity(count);
        for _ in 0..count {
            recovery_fingerprints.push(input.fixed()?);
        }
        input.finish()?;
        let value = Self {
            generation,
            recovery_fingerprints,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveRecipientSet {
    pub recovery_generation: u64,
    pub fingerprints: Vec<[u8; 32]>,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveCodec {
    pub id: u16,
    pub table: &'static str,
    pub codec_version: u16,
    pub required: bool,
    pub owner: &'static str,
}

pub const ARCHIVE_REGISTRY: [ArchiveCodec; 24] = [
    codec(1, "meta", true, "U2"),
    codec(2, "system_keyring", true, "U2"),
    codec(3, "secret_meta", true, "U2"),
    codec(4, "secrets", true, "U2"),
    codec(5, "audit_events", true, "U6"),
    codec(6, "audit_head", true, "U6"),
    codec(7, "identities", true, "U3"),
    codec(8, "grants", true, "U3"),
    codec(9, "credentials", true, "U4"),
    codec(10, "credential_epoch", true, "U4"),
    codec(11, "checkpoint_prepared", true, "U6"),
    codec(12, "checkpoint_registered", true, "U6"),
    codec(13, "signing_trust", true, "U6"),
    codec(14, "approle_roles", true, "U4"),
    codec(15, "secret_id_usage", true, "U4"),
    codec(16, "recovery_reserve", true, "U6"),
    codec(17, "consumers", true, "U7"),
    codec(18, "rotations", true, "U7"),
    codec(19, "maintenance_marker", false, "U8/U10"),
    codec(20, "rewrite_jobs", false, "U8/U10"),
    codec(21, "output_publications", false, "U6/U10"),
    codec(22, "backup_registry", false, "U10"),
    codec(23, "audit_export_registry", false, "U6"),
    codec(24, "recovery_receipts", false, "U10"),
];

const fn codec(id: u16, table: &'static str, required: bool, owner: &'static str) -> ArchiveCodec {
    ArchiveCodec {
        id,
        table,
        codec_version: 1,
        required,
        owner,
    }
}

pub fn archive_codec(id: u16) -> Option<&'static ArchiveCodec> {
    ARCHIVE_REGISTRY.iter().find(|codec| codec.id == id)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveFrame {
    pub table_id: u16,
    pub codec_version: u16,
    pub entries: Vec<ArchiveEntry>,
}

impl ArchiveFrame {
    fn validate(&self) -> Result<(), CodecError> {
        let codec = archive_codec(self.table_id).ok_or(CodecError::UnknownVersion)?;
        if self.codec_version != codec.codec_version
            || self.entries.len() > MAX_TABLE_ENTRIES
            || self.entries.iter().any(|entry| {
                entry.key.is_empty()
                    || entry.key.len() > MAX_ENTRY_KEY_BYTES
                    || entry.value.len() > MAX_ENTRY_VALUE_BYTES
            })
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for ArchiveFrame {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(self.table_id);
        out.u16(self.codec_version);
        out.u32(self.entries.len() as u32);
        for entry in &self.entries {
            out.bytes(&entry.key, MAX_ENTRY_KEY_BYTES)?;
            out.bytes(&entry.value, MAX_ENTRY_VALUE_BYTES)?;
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let table_id = input.u16()?;
        let codec_version = input.u16()?;
        let count = input.u32()? as usize;
        if count > MAX_TABLE_ENTRIES {
            return Err(CodecError::Limit);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(ArchiveEntry {
                key: input.bytes(MAX_ENTRY_KEY_BYTES)?,
                value: input.bytes(MAX_ENTRY_VALUE_BYTES)?,
            });
        }
        input.finish()?;
        let value = Self {
            table_id,
            codec_version,
            entries,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableSummary {
    pub table_id: u16,
    pub codec_version: u16,
    pub entry_count: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SourceObservationStatus {
    BarrierConfirmed = 1,
    LastKnown = 2,
    Unavailable = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TailStatus {
    Complete = 1,
    Partial = 2,
    Unavailable = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceObservation {
    pub status: SourceObservationStatus,
    pub claimed_decommissioned: bool,
    pub observed_epoch: Option<u64>,
    pub observed_sequence: Option<u64>,
    pub observed_head: Option<[u8; 32]>,
    pub observation_unix_milliseconds: Option<u64>,
    pub provenance_digest: Option<[u8; 32]>,
    pub tail_status: TailStatus,
    pub tail_digest: Option<[u8; 32]>,
    pub rpo_known: bool,
    pub acknowledgment_digest: [u8; 32],
}

impl SourceObservation {
    fn validate(&self, cutoff_epoch: u64, cutoff_sequence: u64) -> Result<(), CodecError> {
        let tuple_complete = self.observed_epoch.is_some()
            && self.observed_sequence.is_some()
            && self.observed_head.is_some();
        let tuple_empty = self.observed_epoch.is_none()
            && self.observed_sequence.is_none()
            && self.observed_head.is_none();
        if self.acknowledgment_digest == [0; 32]
            || (!tuple_complete && !tuple_empty)
            || self.status == SourceObservationStatus::BarrierConfirmed && !tuple_complete
            || self.status == SourceObservationStatus::BarrierConfirmed
                && !self.claimed_decommissioned
            || self.status == SourceObservationStatus::Unavailable && !tuple_empty
            || self.tail_status == TailStatus::Complete && self.tail_digest.is_none()
            || self.tail_status == TailStatus::Unavailable && self.tail_digest.is_some()
            || tuple_complete
                && (self.observed_epoch.unwrap() < cutoff_epoch
                    || (self.observed_epoch.unwrap() == cutoff_epoch
                        && self.observed_sequence.unwrap() < cutoff_sequence))
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryManifest {
    pub archive_id: [u8; 16],
    pub store_id: StoreId,
    pub store_incarnation_id: [u8; 16],
    pub keyring_generation: u64,
    pub recovery_set_generation: u64,
    pub effective_recipient_fingerprints: Vec<[u8; 32]>,
    pub state_digest: [u8; 32],
    pub audit_epoch: u64,
    pub audit_sequence: u64,
    pub audit_head: [u8; 32],
    pub latest_checkpoint_digest: Option<[u8; 32]>,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub signing_transition_digest: [u8; 32],
    pub creator_audit_epoch: u64,
    pub creator_audit_sequence: u64,
    pub creator_audit_head: [u8; 32],
    pub tables: Vec<TableSummary>,
    pub source: SourceObservation,
}

impl RecoveryManifest {
    fn validate(&self) -> Result<(), CodecError> {
        if self.archive_id == [0; 16]
            || self.store_id.0 == [0; 16]
            || self.store_incarnation_id == [0; 16]
            || self.keyring_generation == 0
            || self.recovery_set_generation == 0
            || !(2..=MAX_EFFECTIVE_RECIPIENTS)
                .contains(&self.effective_recipient_fingerprints.len())
            || self
                .effective_recipient_fingerprints
                .windows(2)
                .any(|p| p[0] >= p[1])
            || self.state_digest == [0; 32]
            || self.audit_epoch == 0
            || self.audit_head == [0; 32]
            || self.signing_key_id == [0; 16]
            || self.signing_lineage_generation == 0
            || self.creator_audit_epoch != self.audit_epoch
            || self.creator_audit_sequence != self.audit_sequence
            || self.creator_audit_head != self.audit_head
            || self.tables.is_empty()
            || self.tables.len() > MAX_ARCHIVE_TABLES
            || self
                .tables
                .windows(2)
                .any(|pair| pair[0].table_id >= pair[1].table_id)
            || self.tables.iter().any(|summary| {
                archive_codec(summary.table_id)
                    .is_none_or(|codec| codec.codec_version != summary.codec_version)
                    || summary.digest == [0; 32]
            })
        {
            return Err(CodecError::Invalid);
        }
        let present = self
            .tables
            .iter()
            .map(|summary| summary.table_id)
            .collect::<BTreeSet<_>>();
        if ARCHIVE_REGISTRY
            .iter()
            .any(|codec| codec.required && !present.contains(&codec.id))
        {
            return Err(CodecError::Invalid);
        }
        self.source.validate(self.audit_epoch, self.audit_sequence)
    }

    pub fn digest(&self) -> Result<[u8; 32], CodecError> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}

impl Canonical for RecoveryManifest {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(BACKUP_MANIFEST_VERSION);
        out.fixed(&self.archive_id);
        out.fixed(&self.store_id.0);
        out.fixed(&self.store_incarnation_id);
        out.u64(self.keyring_generation);
        out.u64(self.recovery_set_generation);
        out.u8(self.effective_recipient_fingerprints.len() as u8);
        for fingerprint in &self.effective_recipient_fingerprints {
            out.fixed(fingerprint);
        }
        out.fixed(&self.state_digest);
        out.u64(self.audit_epoch);
        out.u64(self.audit_sequence);
        out.fixed(&self.audit_head);
        encode_optional_fixed(&mut out, self.latest_checkpoint_digest);
        out.fixed(&self.signing_key_id);
        out.u64(self.signing_lineage_generation);
        out.fixed(&self.signing_transition_digest);
        out.u64(self.creator_audit_epoch);
        out.u64(self.creator_audit_sequence);
        out.fixed(&self.creator_audit_head);
        out.u16(self.tables.len() as u16);
        for summary in &self.tables {
            out.u16(summary.table_id);
            out.u16(summary.codec_version);
            out.u64(summary.entry_count);
            out.fixed(&summary.digest);
        }
        encode_source(&mut out, self.source);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != BACKUP_MANIFEST_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let archive_id = input.fixed()?;
        let store_id = StoreId(input.fixed()?);
        let store_incarnation_id = input.fixed()?;
        let keyring_generation = input.u64()?;
        let recovery_set_generation = input.u64()?;
        let recipient_count = input.u8()? as usize;
        if !(2..=MAX_EFFECTIVE_RECIPIENTS).contains(&recipient_count) {
            return Err(CodecError::Limit);
        }
        let mut effective_recipient_fingerprints = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            effective_recipient_fingerprints.push(input.fixed()?);
        }
        let state_digest = input.fixed()?;
        let audit_epoch = input.u64()?;
        let audit_sequence = input.u64()?;
        let audit_head = input.fixed()?;
        let latest_checkpoint_digest = decode_optional_fixed(&mut input)?;
        let signing_key_id = input.fixed()?;
        let signing_lineage_generation = input.u64()?;
        let signing_transition_digest = input.fixed()?;
        let creator_audit_epoch = input.u64()?;
        let creator_audit_sequence = input.u64()?;
        let creator_audit_head = input.fixed()?;
        let table_count = input.u16()? as usize;
        if table_count == 0 || table_count > MAX_ARCHIVE_TABLES {
            return Err(CodecError::Limit);
        }
        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            tables.push(TableSummary {
                table_id: input.u16()?,
                codec_version: input.u16()?,
                entry_count: input.u64()?,
                digest: input.fixed()?,
            });
        }
        let source = decode_source(&mut input)?;
        input.finish()?;
        let value = Self {
            archive_id,
            store_id,
            store_incarnation_id,
            keyring_generation,
            recovery_set_generation,
            effective_recipient_fingerprints,
            state_digest,
            audit_epoch,
            audit_sequence,
            audit_head,
            latest_checkpoint_digest,
            signing_key_id,
            signing_lineage_generation,
            signing_transition_digest,
            creator_audit_epoch,
            creator_audit_sequence,
            creator_audit_head,
            tables,
            source,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSigningHeader {
    pub archive_id: [u8; 16],
    pub store_incarnation_id: [u8; 16],
    pub signing_key_id: [u8; 16],
    pub signing_domain: u16,
    pub signing_lineage_generation: u64,
    pub recovery_set_generation: u64,
    pub effective_recipient_digest: [u8; 32],
    pub encrypted_payload_length: u64,
    pub encrypted_payload_digest: [u8; 32],
    pub recovery_manifest_digest: [u8; 32],
}

impl Canonical for BackupSigningHeader {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.archive_id == [0; 16]
            || self.store_incarnation_id == [0; 16]
            || self.signing_key_id == [0; 16]
            || self.signing_domain != BACKUP_SIGNING_DOMAIN_ID
            || self.signing_lineage_generation == 0
            || self.recovery_set_generation == 0
            || self.effective_recipient_digest == [0; 32]
            || self.encrypted_payload_length == 0
            || self.encrypted_payload_length > MAX_ENCRYPTED_PAYLOAD_BYTES as u64
            || self.encrypted_payload_digest == [0; 32]
            || self.recovery_manifest_digest == [0; 32]
        {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u16(BACKUP_FORMAT_VERSION);
        out.fixed(&self.archive_id);
        out.fixed(&self.store_incarnation_id);
        out.fixed(&self.signing_key_id);
        out.u16(self.signing_domain);
        out.u64(self.signing_lineage_generation);
        out.u64(self.recovery_set_generation);
        out.fixed(&self.effective_recipient_digest);
        out.u64(self.encrypted_payload_length);
        out.fixed(&self.encrypted_payload_digest);
        out.fixed(&self.recovery_manifest_digest);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != BACKUP_FORMAT_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            archive_id: input.fixed()?,
            store_incarnation_id: input.fixed()?,
            signing_key_id: input.fixed()?,
            signing_domain: input.u16()?,
            signing_lineage_generation: input.u64()?,
            recovery_set_generation: input.u64()?,
            effective_recipient_digest: input.fixed()?,
            encrypted_payload_length: input.u64()?,
            encrypted_payload_digest: input.fixed()?,
            recovery_manifest_digest: input.fixed()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupContainer {
    pub header: BackupSigningHeader,
    pub encrypted_payload: Vec<u8>,
}

impl BackupContainer {
    pub fn new(
        mut header: BackupSigningHeader,
        encrypted_payload: Vec<u8>,
    ) -> Result<Self, CodecError> {
        if encrypted_payload.is_empty() || encrypted_payload.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
            return Err(CodecError::Limit);
        }
        header.encrypted_payload_length = encrypted_payload.len() as u64;
        header.encrypted_payload_digest = *blake3::hash(&encrypted_payload).as_bytes();
        header.encode()?;
        Ok(Self {
            header,
            encrypted_payload,
        })
    }

    pub fn content_digest(&self) -> Result<[u8; 32], CodecError> {
        let encoded = self.encode()?;
        Ok(*blake3::hash(&encoded).as_bytes())
    }
}

impl Canonical for BackupContainer {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.encrypted_payload.len() as u64 != self.header.encrypted_payload_length
            || *blake3::hash(&self.encrypted_payload).as_bytes()
                != self.header.encrypted_payload_digest
        {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.bytes(&self.header.encode()?, 512)?;
        out.bytes(&self.encrypted_payload, MAX_ENCRYPTED_PAYLOAD_BYTES)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let header = BackupSigningHeader::decode(&input.bytes(512)?)?;
        let encrypted_payload = input.bytes(MAX_ENCRYPTED_PAYLOAD_BYTES)?;
        input.finish()?;
        let value = Self {
            header,
            encrypted_payload,
        };
        value.encode()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedBackupSignature {
    pub key_id: [u8; 16],
    pub content_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl DetachedBackupSignature {
    pub fn verify(
        &self,
        header: &BackupSigningHeader,
        public_key: &[u8; 32],
    ) -> Result<(), CodecError> {
        if self.key_id != header.signing_key_id {
            return Err(CodecError::Invalid);
        }
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| CodecError::Invalid)?;
        key.verify(
            &signature_message(self.key_id, self.content_digest),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| CodecError::Invalid)
    }
}

impl Canonical for DetachedBackupSignature {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.key_id == [0; 16] || self.content_digest == [0; 32] || self.signature == [0; 64] {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u16(BACKUP_SIGNATURE_VERSION);
        out.fixed(&self.key_id);
        out.fixed(&self.content_digest);
        out.fixed(&self.signature);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != BACKUP_SIGNATURE_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            key_id: input.fixed()?,
            content_digest: input.fixed()?,
            signature: input.fixed()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }
}

pub fn signature_message(key_id: [u8; 16], content_digest: [u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(BACKUP_SIGNATURE_DOMAIN.len() + 8 + 16 + 8 + 32);
    message.extend_from_slice(BACKUP_SIGNATURE_DOMAIN);
    message.extend_from_slice(&(key_id.len() as u64).to_be_bytes());
    message.extend_from_slice(&key_id);
    message.extend_from_slice(&(content_digest.len() as u64).to_be_bytes());
    message.extend_from_slice(&content_digest);
    message
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureStatus {
    Valid,
    Absent,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedOverride<'a> {
    pub allow_unsigned: bool,
    pub reason: &'a str,
    pub confirmation: &'a str,
}

pub fn unsigned_confirmation(archive_digest: [u8; 32], reason: &str) -> String {
    let mut digest = blake3::Hasher::new();
    digest.update(b"ops-light-secrets-server.unsigned-backup-override.v1\0");
    digest.update(&(archive_digest.len() as u64).to_be_bytes());
    digest.update(&archive_digest);
    digest.update(&(reason.len() as u64).to_be_bytes());
    digest.update(reason.as_bytes());
    digest.finalize().to_hex().to_string()
}

pub fn allow_restore_signature(
    status: SignatureStatus,
    archive_digest: [u8; 32],
    override_request: Option<UnsignedOverride<'_>>,
) -> Result<bool, CodecError> {
    match status {
        SignatureStatus::Valid => Ok(false),
        SignatureStatus::Invalid => Err(CodecError::Invalid),
        SignatureStatus::Absent => {
            let request = override_request.ok_or(CodecError::Invalid)?;
            if !request.allow_unsigned
                || request.reason.is_empty()
                || request.reason.len() > 1024
                || request.reason.chars().any(char::is_control)
                || request.confirmation != unsigned_confirmation(archive_digest, request.reason)
            {
                return Err(CodecError::Invalid);
            }
            Ok(true)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreMode {
    Normal,
    RecoveryForkRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEvidence {
    pub newest_checkpoint_epoch: u64,
    pub newest_checkpoint_sequence: u64,
    pub newest_lineage_generation: u64,
    pub lineage_digest: [u8; 32],
}

pub fn classify_restore(manifest: &RecoveryManifest, evidence: &RecoveryEvidence) -> RestoreMode {
    if evidence.newest_checkpoint_epoch > manifest.audit_epoch
        || (evidence.newest_checkpoint_epoch == manifest.audit_epoch
            && evidence.newest_checkpoint_sequence > manifest.audit_sequence)
        || evidence.newest_lineage_generation > manifest.signing_lineage_generation
    {
        RestoreMode::RecoveryForkRequired
    } else {
        RestoreMode::Normal
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreEpochPlan {
    pub credential_epoch: u64,
    pub audit_epoch: u64,
    pub fork_genesis_required: bool,
    pub replacement_control_credential_required: bool,
}

pub fn restore_epoch_plan(
    current_credential_epoch: u64,
    archived_audit_epoch: u64,
    mode: RestoreMode,
    start_recovery_epoch: bool,
) -> Result<RestoreEpochPlan, CodecError> {
    let credential_epoch = current_credential_epoch
        .checked_add(1)
        .ok_or(CodecError::Limit)?;
    match mode {
        RestoreMode::Normal if !start_recovery_epoch => Ok(RestoreEpochPlan {
            credential_epoch,
            audit_epoch: archived_audit_epoch,
            fork_genesis_required: false,
            replacement_control_credential_required: true,
        }),
        RestoreMode::RecoveryForkRequired if start_recovery_epoch => Ok(RestoreEpochPlan {
            credential_epoch,
            audit_epoch: archived_audit_epoch
                .checked_add(1)
                .ok_or(CodecError::Limit)?,
            fork_genesis_required: true,
            replacement_control_credential_required: true,
        }),
        _ => Err(CodecError::Invalid),
    }
}

fn encode_optional_fixed(out: &mut Encoder, value: Option<[u8; 32]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(&value);
        }
    }
}

fn decode_optional_fixed(input: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => Err(CodecError::Invalid),
    }
}

fn encode_source(out: &mut Encoder, source: SourceObservation) {
    out.u8(source.status as u8);
    out.bool(source.claimed_decommissioned);
    encode_optional_u64(out, source.observed_epoch);
    encode_optional_u64(out, source.observed_sequence);
    encode_optional_fixed(out, source.observed_head);
    encode_optional_u64(out, source.observation_unix_milliseconds);
    encode_optional_fixed(out, source.provenance_digest);
    out.u8(source.tail_status as u8);
    encode_optional_fixed(out, source.tail_digest);
    out.bool(source.rpo_known);
    out.fixed(&source.acknowledgment_digest);
}

fn decode_source(input: &mut Decoder<'_>) -> Result<SourceObservation, CodecError> {
    Ok(SourceObservation {
        status: match input.u8()? {
            1 => SourceObservationStatus::BarrierConfirmed,
            2 => SourceObservationStatus::LastKnown,
            3 => SourceObservationStatus::Unavailable,
            _ => return Err(CodecError::Invalid),
        },
        claimed_decommissioned: input.bool()?,
        observed_epoch: decode_optional_u64(input)?,
        observed_sequence: decode_optional_u64(input)?,
        observed_head: decode_optional_fixed(input)?,
        observation_unix_milliseconds: decode_optional_u64(input)?,
        provenance_digest: decode_optional_fixed(input)?,
        tail_status: match input.u8()? {
            1 => TailStatus::Complete,
            2 => TailStatus::Partial,
            3 => TailStatus::Unavailable,
            _ => return Err(CodecError::Invalid),
        },
        tail_digest: decode_optional_fixed(input)?,
        rpo_known: input.bool()?,
        acknowledgment_digest: input.fixed()?,
    })
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
