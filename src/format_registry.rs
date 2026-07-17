//! G2-frozen cross-release format registry and shared canonical codecs.

use std::collections::BTreeSet;

use crate::backup_format::ARCHIVE_REGISTRY;
use crate::store::{
    Canonical, CodecError, DURABLE_TABLE_NAMES, Decoder, Encoder, RecordClass, StoreId,
};

pub const FORMAT_REGISTRY_VERSION: u16 = 1;
pub const SIGNER_ELIGIBILITY_VERSION: u16 = 1;
pub const MAINTENANCE_PREFLIGHT_VERSION: u16 = 1;
pub const OUTPUT_PUBLICATION_VERSION: u16 = 1;
pub const RECOVERY_ACTIVATION_VERSION: u16 = 1;
pub const MAX_MAINTENANCE_DELTAS: usize = 4096;
pub const MAX_OUTPUT_OWNER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenFormat {
    pub id: u16,
    pub name: &'static str,
    pub version: u16,
    pub domain: &'static str,
    pub owner: &'static str,
    pub vector: &'static str,
}

const fn format(
    id: u16,
    name: &'static str,
    version: u16,
    domain: &'static str,
    owner: &'static str,
    vector: &'static str,
) -> FrozenFormat {
    FrozenFormat {
        id,
        name,
        version,
        domain,
        owner,
        vector,
    }
}

pub const FORMAT_REGISTRY: [FrozenFormat; 21] = [
    format(
        1,
        "record-header",
        1,
        "record-header.v1",
        "U2.2",
        "crypto-vectors-v1.json",
    ),
    format(
        2,
        "encrypted-record",
        1,
        "encrypted-record.v1",
        "U2.2",
        "crypto-vectors-v1.json",
    ),
    format(
        3,
        "clear-record-mac",
        1,
        "clear-record-mac.v1",
        "U2.5",
        "crypto-vectors-v1.json",
    ),
    format(
        4,
        "state-tuple-digest",
        1,
        "state-digest.v1",
        "U2.5",
        "state-digest-v1.json",
    ),
    format(
        5,
        "state-delta",
        1,
        "state-delta.v1",
        "U6.3",
        "format-freeze-v1.json",
    ),
    format(
        6,
        "whole-state-transition",
        1,
        "whole-state-transition.v1",
        "U6.3",
        "format-freeze-v1.json",
    ),
    format(
        7,
        "audit-event",
        1,
        "audit-event.v1",
        "U6.3",
        "audit-event-v1.json",
    ),
    format(
        8,
        "audit-envelope",
        1,
        "audit-envelope.v1",
        "U6.3",
        "audit-envelope-v1.json",
    ),
    format(
        9,
        "checkpoint-descriptor",
        2,
        "audit-checkpoint.v1",
        "U6.4",
        "checkpoint-descriptor-v2.json",
    ),
    format(
        10,
        "checkpoint-signature",
        1,
        "checkpoint-signature.v1",
        "U6.4",
        "format-freeze-v1.json",
    ),
    format(
        11,
        "signing-key-candidate",
        1,
        "signing-key-candidate.v1",
        "U6.8",
        "signing-trust-v1.json",
    ),
    format(
        12,
        "signing-lineage",
        1,
        "signing-lineage.v1",
        "U6.8",
        "signing-trust-v1.json",
    ),
    format(
        13,
        "signing-transition",
        1,
        "signing-transition.v1",
        "U6.8",
        "signing-trust-v1.json",
    ),
    format(
        14,
        "backup-archive-frame",
        1,
        "backup-archive-frame.v1",
        "U10.1",
        "backup-format-v1.json",
    ),
    format(
        15,
        "recovery-manifest",
        1,
        "recovery-manifest.v1",
        "U10.1",
        "backup-format-v1.json",
    ),
    format(
        16,
        "backup-container",
        1,
        "backup-container.v1",
        "U10.1",
        "backup-format-v1.json",
    ),
    format(
        17,
        "backup-signature",
        1,
        "backup-signature.v1",
        "U10.1",
        "backup-format-v1.json",
    ),
    format(
        18,
        "signer-eligibility",
        1,
        "signer-eligibility.v1",
        "G2",
        "format-freeze-v1.json",
    ),
    format(
        19,
        "maintenance-preflight",
        1,
        "maintenance-preflight.v1",
        "G2",
        "format-freeze-v1.json",
    ),
    format(
        20,
        "output-publication",
        1,
        "output-publication.v1",
        "G2",
        "format-freeze-v1.json",
    ),
    format(
        21,
        "recovery-activation",
        1,
        "recovery-activation.v1",
        "G2/U10.1",
        "format-freeze-v1.json",
    ),
];

/// Fails when a frozen id/domain is reused or a durable table lacks backup coverage.
pub fn verify_format_registry() -> Result<(), CodecError> {
    verify_format_entries(&FORMAT_REGISTRY)?;
    verify_storage_registries()
}

pub fn verify_format_entries(entries: &[FrozenFormat]) -> Result<(), CodecError> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for entry in entries {
        if entry.id == 0
            || entry.id >= 0x8000
            || entry.name.is_empty()
            || entry.version == 0
            || entry.domain.is_empty()
            || entry.owner.is_empty()
            || entry.vector.is_empty()
            || !ids.insert(entry.id)
            || !names.insert(entry.name)
            || !domains.insert(entry.domain)
        {
            return Err(CodecError::Invalid);
        }
    }
    Ok(())
}

fn verify_storage_registries() -> Result<(), CodecError> {
    let mut class_ids = BTreeSet::new();
    let mut class_domains = BTreeSet::new();
    for class in RecordClass::ALL {
        if !class_ids.insert(class.code()) || !class_domains.insert(class.domain()) {
            return Err(CodecError::Invalid);
        }
    }
    let mut archive_ids = BTreeSet::new();
    let mut archive_tables = BTreeSet::new();
    for codec in ARCHIVE_REGISTRY {
        if codec.id == 0
            || codec.codec_version == 0
            || codec.owner.is_empty()
            || !archive_ids.insert(codec.id)
            || !archive_tables.insert(codec.table)
        {
            return Err(CodecError::Invalid);
        }
    }
    if DURABLE_TABLE_NAMES
        .iter()
        .any(|table| !archive_tables.contains(table))
    {
        return Err(CodecError::Invalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ArtifactDomain {
    Checkpoint = 1,
    BackupManifest = 2,
    AuditExport = 3,
    RecoveryReceipt = 4,
}

impl ArtifactDomain {
    fn decode(value: u16) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Checkpoint),
            2 => Ok(Self::BackupManifest),
            3 => Ok(Self::AuditExport),
            4 => Ok(Self::RecoveryReceipt),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerEligibility {
    pub domain: ArtifactDomain,
    pub creator_epoch: [u8; 16],
    pub creator_sequence: u64,
    pub creator_head: [u8; 32],
    pub lineage_generation: u64,
    pub transition_digest: Option<[u8; 32]>,
    pub expected_signer_id: [u8; 16],
}

impl SignerEligibility {
    fn validate(&self) -> Result<(), CodecError> {
        if self.creator_epoch == [0; 16]
            || self.creator_sequence == 0
            || self.creator_head == [0; 32]
            || self.lineage_generation == 0
            || self.expected_signer_id == [0; 16]
            || (self.lineage_generation == 1) != self.transition_digest.is_none()
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for SignerEligibility {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(SIGNER_ELIGIBILITY_VERSION);
        out.u16(self.domain as u16);
        out.fixed(&self.creator_epoch);
        out.u64(self.creator_sequence);
        out.fixed(&self.creator_head);
        out.u64(self.lineage_generation);
        encode_optional_digest(&mut out, self.transition_digest);
        out.fixed(&self.expected_signer_id);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != SIGNER_ELIGIBILITY_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            domain: ArtifactDomain::decode(input.u16()?)?,
            creator_epoch: input.fixed()?,
            creator_sequence: input.u64()?,
            creator_head: input.fixed()?,
            lineage_generation: input.u64()?,
            transition_digest: decode_optional_digest(&mut input)?,
            expected_signer_id: input.fixed()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum MaintenanceOperation {
    BackupOutput = 1,
    BackupSignature = 2,
    BackupReceipt = 3,
    CheckpointBookkeeping = 4,
    AuditReadVerification = 5,
    ClockWatermark = 6,
    CleanShutdown = 7,
}

impl MaintenanceOperation {
    fn decode(value: u16) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::BackupOutput),
            2 => Ok(Self::BackupSignature),
            3 => Ok(Self::BackupReceipt),
            4 => Ok(Self::CheckpointBookkeeping),
            5 => Ok(Self::AuditReadVerification),
            6 => Ok(Self::ClockWatermark),
            7 => Ok(Self::CleanShutdown),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenancePreflight {
    pub store_incarnation: [u8; 16],
    pub audit_epoch: [u8; 16],
    pub checkpoint_sequence: u64,
    pub head_sequence: u64,
    pub head_digest: [u8; 32],
    pub tail_digest: [u8; 32],
    pub state_digest_at_checkpoint: [u8; 32],
    pub operations: Vec<MaintenanceOperation>,
}

impl MaintenancePreflight {
    fn validate(&self) -> Result<(), CodecError> {
        if self.store_incarnation == [0; 16]
            || self.audit_epoch == [0; 16]
            || self.checkpoint_sequence == 0
            || self.head_sequence < self.checkpoint_sequence
            || self.head_digest == [0; 32]
            || self.tail_digest == [0; 32]
            || self.state_digest_at_checkpoint == [0; 32]
            || self.operations.len() != (self.head_sequence - self.checkpoint_sequence) as usize
            || self.operations.len() > MAX_MAINTENANCE_DELTAS
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for MaintenancePreflight {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(MAINTENANCE_PREFLIGHT_VERSION);
        out.fixed(&self.store_incarnation);
        out.fixed(&self.audit_epoch);
        out.u64(self.checkpoint_sequence);
        out.u64(self.head_sequence);
        out.fixed(&self.head_digest);
        out.fixed(&self.tail_digest);
        out.fixed(&self.state_digest_at_checkpoint);
        out.u32(self.operations.len() as u32);
        for operation in &self.operations {
            out.u16(*operation as u16);
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != MAINTENANCE_PREFLIGHT_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let store_incarnation = input.fixed()?;
        let audit_epoch = input.fixed()?;
        let checkpoint_sequence = input.u64()?;
        let head_sequence = input.u64()?;
        let head_digest = input.fixed()?;
        let tail_digest = input.fixed()?;
        let state_digest_at_checkpoint = input.fixed()?;
        let count = input.u32()? as usize;
        if count > MAX_MAINTENANCE_DELTAS {
            return Err(CodecError::Limit);
        }
        let mut operations = Vec::with_capacity(count);
        for _ in 0..count {
            operations.push(MaintenanceOperation::decode(input.u16()?)?);
        }
        input.finish()?;
        let value = Self {
            store_incarnation,
            audit_epoch,
            checkpoint_sequence,
            head_sequence,
            head_digest,
            tail_digest,
            state_digest_at_checkpoint,
            operations,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationState {
    Publishing = 1,
    Published = 2,
    Abandoned = 3,
}

impl PublicationState {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Publishing),
            2 => Ok(Self::Published),
            3 => Ok(Self::Abandoned),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputPublication {
    pub domain: ArtifactDomain,
    pub opaque_output_id: [u8; 16],
    pub owner: Vec<u8>,
    pub header_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub target_identity_digest: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub inner_manifest_digest: [u8; 32],
    pub signer_id: [u8; 16],
    pub lineage_generation: u64,
    pub created_sequence: u64,
    pub state: PublicationState,
    pub file_identity_digest: Option<[u8; 32]>,
    pub parent_fsync_sequence: Option<u64>,
    pub abandonment_digest: Option<[u8; 32]>,
}

impl OutputPublication {
    fn validate(&self) -> Result<(), CodecError> {
        if !matches!(
            self.domain,
            ArtifactDomain::BackupManifest | ArtifactDomain::AuditExport
        ) || self.opaque_output_id == [0; 16]
            || self.owner.is_empty()
            || self.owner.len() > MAX_OUTPUT_OWNER_BYTES
            || self.header_digest == [0; 32]
            || self.content_digest == [0; 32]
            || self.target_identity_digest == [0; 32]
            || self.artifact_digest == [0; 32]
            || self.inner_manifest_digest == [0; 32]
            || self.signer_id == [0; 16]
            || self.lineage_generation == 0
            || self.created_sequence == 0
        {
            return Err(CodecError::Invalid);
        }
        let valid_state = match self.state {
            PublicationState::Publishing => {
                self.file_identity_digest.is_none()
                    && self.parent_fsync_sequence.is_none()
                    && self.abandonment_digest.is_none()
            }
            PublicationState::Published => {
                self.file_identity_digest.is_some()
                    && self
                        .parent_fsync_sequence
                        .is_some_and(|sequence| sequence >= self.created_sequence)
                    && self.abandonment_digest.is_none()
            }
            PublicationState::Abandoned => {
                self.parent_fsync_sequence.is_none() && self.abandonment_digest.is_some()
            }
        };
        if !valid_state {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }

    pub fn publish(
        &mut self,
        file_identity_digest: [u8; 32],
        parent_fsync_sequence: u64,
    ) -> Result<(), CodecError> {
        if self.state != PublicationState::Publishing || file_identity_digest == [0; 32] {
            return Err(CodecError::Invalid);
        }
        self.state = PublicationState::Published;
        self.file_identity_digest = Some(file_identity_digest);
        self.parent_fsync_sequence = Some(parent_fsync_sequence);
        self.validate()
    }

    pub fn abandon(&mut self, abandonment_digest: [u8; 32]) -> Result<(), CodecError> {
        if self.state == PublicationState::Abandoned || abandonment_digest == [0; 32] {
            return Err(CodecError::Invalid);
        }
        self.state = PublicationState::Abandoned;
        self.parent_fsync_sequence = None;
        self.abandonment_digest = Some(abandonment_digest);
        self.validate()
    }
}

impl Canonical for OutputPublication {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(OUTPUT_PUBLICATION_VERSION);
        out.u16(self.domain as u16);
        out.fixed(&self.opaque_output_id);
        out.bytes(&self.owner, MAX_OUTPUT_OWNER_BYTES)?;
        out.fixed(&self.header_digest);
        out.fixed(&self.content_digest);
        out.fixed(&self.target_identity_digest);
        out.fixed(&self.artifact_digest);
        out.fixed(&self.inner_manifest_digest);
        out.fixed(&self.signer_id);
        out.u64(self.lineage_generation);
        out.u64(self.created_sequence);
        out.u8(self.state as u8);
        encode_optional_digest(&mut out, self.file_identity_digest);
        encode_optional_u64(&mut out, self.parent_fsync_sequence);
        encode_optional_digest(&mut out, self.abandonment_digest);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != OUTPUT_PUBLICATION_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            domain: ArtifactDomain::decode(input.u16()?)?,
            opaque_output_id: input.fixed()?,
            owner: input.bytes(MAX_OUTPUT_OWNER_BYTES)?,
            header_digest: input.fixed()?,
            content_digest: input.fixed()?,
            target_identity_digest: input.fixed()?,
            artifact_digest: input.fixed()?,
            inner_manifest_digest: input.fixed()?,
            signer_id: input.fixed()?,
            lineage_generation: input.u64()?,
            created_sequence: input.u64()?,
            state: PublicationState::decode(input.u8()?)?,
            file_identity_digest: decode_optional_digest(&mut input)?,
            parent_fsync_sequence: decode_optional_u64(&mut input)?,
            abandonment_digest: decode_optional_digest(&mut input)?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

pub fn artifact_digest(
    domain: ArtifactDomain,
    signing_header: &[u8],
    encrypted_payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"ops-light-secrets-server.output-publication-artifact.v1\0");
    hash.update(&(domain as u16).to_be_bytes());
    hash.update(&(signing_header.len() as u64).to_be_bytes());
    hash.update(signing_header);
    hash.update(&(encrypted_payload_digest.len() as u64).to_be_bytes());
    hash.update(&encrypted_payload_digest);
    *hash.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvidenceCompleteness {
    Complete = 1,
    Partial = 2,
    Unavailable = 3,
}

impl EvidenceCompleteness {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Complete),
            2 => Ok(Self::Partial),
            3 => Ok(Self::Unavailable),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryActivation {
    pub store_id: StoreId,
    pub source_incarnation: [u8; 16],
    pub target_incarnation: [u8; 16],
    pub archive_epoch: u64,
    pub archive_sequence: u64,
    pub archive_head: [u8; 32],
    pub claimed_decommissioned: bool,
    pub source_observation_digest: [u8; 32],
    pub unarchived_tail_digest: Option<[u8; 32]>,
    pub rpo_acknowledgment_digest: [u8; 32],
    pub checkpoint_set_digest: [u8; 32],
    pub trust_evidence_digest: [u8; 32],
    pub imported_lineage_digest: Option<[u8; 32]>,
    pub imported_lineage_generation: Option<u64>,
    pub imported_current_signer: Option<[u8; 16]>,
    pub recipient_binding_digest: [u8; 32],
    pub assertion_digest: [u8; 32],
    pub completeness: EvidenceCompleteness,
    pub recovery_fork: bool,
}

impl RecoveryActivation {
    fn validate(&self) -> Result<(), CodecError> {
        let import_count = usize::from(self.imported_lineage_digest.is_some())
            + usize::from(self.imported_lineage_generation.is_some())
            + usize::from(self.imported_current_signer.is_some());
        if self.store_id.0 == [0; 16]
            || self.source_incarnation == [0; 16]
            || self.target_incarnation == [0; 16]
            || self.source_incarnation == self.target_incarnation
            || self.archive_epoch == 0
            || self.archive_head == [0; 32]
            || self.source_observation_digest == [0; 32]
            || self.rpo_acknowledgment_digest == [0; 32]
            || self.checkpoint_set_digest == [0; 32]
            || self.trust_evidence_digest == [0; 32]
            || self.recipient_binding_digest == [0; 32]
            || self.assertion_digest == [0; 32]
            || !matches!(import_count, 0 | 3)
            || (!self.recovery_fork && import_count != 0)
            || (self.recovery_fork && import_count != 3)
            || self.imported_lineage_generation == Some(0)
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for RecoveryActivation {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(RECOVERY_ACTIVATION_VERSION);
        out.fixed(&self.store_id.0);
        out.fixed(&self.source_incarnation);
        out.fixed(&self.target_incarnation);
        out.u64(self.archive_epoch);
        out.u64(self.archive_sequence);
        out.fixed(&self.archive_head);
        out.bool(self.claimed_decommissioned);
        out.fixed(&self.source_observation_digest);
        encode_optional_digest(&mut out, self.unarchived_tail_digest);
        out.fixed(&self.rpo_acknowledgment_digest);
        out.fixed(&self.checkpoint_set_digest);
        out.fixed(&self.trust_evidence_digest);
        encode_optional_digest(&mut out, self.imported_lineage_digest);
        encode_optional_u64(&mut out, self.imported_lineage_generation);
        encode_optional_fixed16(&mut out, self.imported_current_signer);
        out.fixed(&self.recipient_binding_digest);
        out.fixed(&self.assertion_digest);
        out.u8(self.completeness as u8);
        out.bool(self.recovery_fork);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != RECOVERY_ACTIVATION_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            store_id: StoreId(input.fixed()?),
            source_incarnation: input.fixed()?,
            target_incarnation: input.fixed()?,
            archive_epoch: input.u64()?,
            archive_sequence: input.u64()?,
            archive_head: input.fixed()?,
            claimed_decommissioned: input.bool()?,
            source_observation_digest: input.fixed()?,
            unarchived_tail_digest: decode_optional_digest(&mut input)?,
            rpo_acknowledgment_digest: input.fixed()?,
            checkpoint_set_digest: input.fixed()?,
            trust_evidence_digest: input.fixed()?,
            imported_lineage_digest: decode_optional_digest(&mut input)?,
            imported_lineage_generation: decode_optional_u64(&mut input)?,
            imported_current_signer: decode_optional_fixed16(&mut input)?,
            recipient_binding_digest: input.fixed()?,
            assertion_digest: input.fixed()?,
            completeness: EvidenceCompleteness::decode(input.u8()?)?,
            recovery_fork: input.bool()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

fn encode_optional_digest(out: &mut Encoder, value: Option<[u8; 32]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(&value);
        }
    }
}

fn decode_optional_digest(input: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, CodecError> {
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

fn encode_optional_fixed16(out: &mut Encoder, value: Option<[u8; 16]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(&value);
        }
    }
}

fn decode_optional_fixed16(input: &mut Decoder<'_>) -> Result<Option<[u8; 16]>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => Err(CodecError::Invalid),
    }
}
