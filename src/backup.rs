//! Consistent logical backup creation and authenticated publication lifecycle.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::x25519;
use age::{Encryptor, Recipient};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::backup_format::{
    ARCHIVE_REGISTRY, ArchiveEntry, ArchiveFrame, BACKUP_SIGNING_DOMAIN_ID, BackupContainer,
    BackupSigningHeader, DetachedBackupSignature, EffectiveRecipientSet, MAX_ARCHIVE_TABLES,
    RecoveryManifest, RecoveryRecipientSet, SourceObservation, TableSummary, signature_message,
};
use crate::store::keyring::{Keyring, KeyringError, RecipientFingerprint};
use crate::store::{Canonical, CodecError, Decoder, Encoder, KeyringEnvelope, Store, StoreError};

const BACKUP_PAYLOAD_VERSION: u16 = 1;
const MAX_RECOVERY_KEYRING_BYTES: usize = 1024 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const ARTIFACT_DOMAIN: &[u8] = b"backup-artifact-v1";

#[derive(Debug, Eq, PartialEq)]
pub enum BackupError {
    Invalid,
    Unauthorized,
    Conflict,
    NotFound,
    AbandonRequired,
    Store,
    Codec,
    Crypto,
    Io,
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "backup input invalid",
            Self::Unauthorized => "backup authorization refused",
            Self::Conflict => "backup state conflict",
            Self::NotFound => "backup artifact not found",
            Self::AbandonRequired => "backup publication requires owner abandonment",
            Self::Store => "backup store snapshot failed",
            Self::Codec => "backup canonical encoding failed",
            Self::Crypto => "backup cryptographic operation failed",
            Self::Io => "backup output operation failed",
        })
    }
}

impl std::error::Error for BackupError {}

impl From<CodecError> for BackupError {
    fn from(_: CodecError) -> Self {
        Self::Codec
    }
}

impl From<StoreError> for BackupError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

impl From<KeyringError> for BackupError {
    fn from(_: KeyringError) -> Self {
        Self::Crypto
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupPayload {
    pub manifest: RecoveryManifest,
    pub recovery_keyring: KeyringEnvelope,
    pub frames: Vec<ArchiveFrame>,
}

impl BackupPayload {
    fn validate(&self) -> Result<(), CodecError> {
        if self.recovery_keyring.0.is_empty()
            || self.recovery_keyring.0.len() > MAX_RECOVERY_KEYRING_BYTES
            || self.frames.is_empty()
            || self.frames.len() > MAX_ARCHIVE_TABLES
            || self
                .frames
                .windows(2)
                .any(|pair| pair[0].table_id >= pair[1].table_id)
        {
            return Err(CodecError::Invalid);
        }
        let summaries = summarize_frames(&self.frames)?;
        if summaries != self.manifest.tables {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for BackupPayload {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(BACKUP_PAYLOAD_VERSION);
        out.bytes(&self.manifest.encode()?, 1024 * 1024)?;
        out.bytes(&self.recovery_keyring.0, MAX_RECOVERY_KEYRING_BYTES)?;
        out.u16(self.frames.len() as u16);
        for frame in &self.frames {
            out.bytes(&frame.encode()?, MAX_FRAME_BYTES)?;
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != BACKUP_PAYLOAD_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let manifest = RecoveryManifest::decode(&input.bytes(1024 * 1024)?)?;
        let recovery_keyring = KeyringEnvelope(input.bytes(MAX_RECOVERY_KEYRING_BYTES)?);
        let count = input.u16()? as usize;
        if count == 0 || count > MAX_ARCHIVE_TABLES {
            return Err(CodecError::Limit);
        }
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            frames.push(ArchiveFrame::decode(&input.bytes(MAX_FRAME_BYTES)?)?);
        }
        input.finish()?;
        let value = Self {
            manifest,
            recovery_keyring,
            frames,
        };
        value.validate()?;
        Ok(value)
    }
}

pub struct BackupCreateRequest<'a> {
    pub archive_id: [u8; 16],
    pub store_incarnation_id: [u8; 16],
    pub keyring: &'a Keyring,
    pub active_recipient: &'a x25519::Recipient,
    pub recovery_recipients: &'a [x25519::Recipient],
    pub recovery_set_generation: u64,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub signing_transition_digest: [u8; 32],
    pub source: SourceObservation,
    pub authorized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedBackup {
    pub container: BackupContainer,
    pub artifact_digest: [u8; 32],
    pub manifest: RecoveryManifest,
    pub effective_recipients: EffectiveRecipientSet,
}

pub fn create_backup(
    store: &Store,
    request: BackupCreateRequest<'_>,
) -> Result<CreatedBackup, BackupError> {
    if !request.authorized
        || request.archive_id == [0; 16]
        || request.store_incarnation_id == [0; 16]
        || request.signing_key_id == [0; 16]
        || request.signing_lineage_generation == 0
        || RecipientFingerprint::of(request.active_recipient) != request.keyring.recipients().active
    {
        return Err(BackupError::Unauthorized);
    }
    let mut recovery_fingerprints = request
        .recovery_recipients
        .iter()
        .map(|recipient| RecipientFingerprint::of(recipient).0)
        .collect::<Vec<_>>();
    recovery_fingerprints.sort_unstable();
    let recovery_set = RecoveryRecipientSet {
        generation: request.recovery_set_generation,
        recovery_fingerprints,
    };
    let active_fingerprint = RecipientFingerprint::of(request.active_recipient).0;
    let effective = recovery_set.effective(active_fingerprint)?;
    let snapshot = store.logical_backup_snapshot()?;
    if snapshot.meta.store_id != request.keyring.store_id() {
        return Err(BackupError::Conflict);
    }
    let mut frames = Vec::with_capacity(snapshot.tables.len());
    for table in snapshot.tables {
        let codec = ARCHIVE_REGISTRY
            .iter()
            .find(|codec| codec.table == table.table)
            .ok_or(BackupError::Invalid)?;
        frames.push(ArchiveFrame {
            table_id: codec.id,
            codec_version: codec.codec_version,
            entries: table
                .entries
                .into_iter()
                .map(|(key, value)| ArchiveEntry { key, value })
                .collect(),
        });
    }
    // G3 freezes required owners before every owner has a live table in schema
    // v1. Preserve those required frames explicitly as empty rather than
    // omitting them or inventing state; once an owner adds its durable table,
    // the registry coverage gate makes its real rows flow through this path.
    for codec in ARCHIVE_REGISTRY.iter().filter(|codec| codec.required) {
        if !frames.iter().any(|frame| frame.table_id == codec.id) {
            frames.push(ArchiveFrame {
                table_id: codec.id,
                codec_version: codec.codec_version,
                entries: Vec::new(),
            });
        }
    }
    frames.sort_by_key(|frame| frame.table_id);
    let tables = summarize_frames(&frames)?;
    let audit_head = snapshot.audit_head;
    let audit_chain_head = audit_head.chain_hash()?;
    let manifest = RecoveryManifest {
        archive_id: request.archive_id,
        store_id: snapshot.meta.store_id,
        store_incarnation_id: request.store_incarnation_id,
        keyring_generation: request.keyring.generation(),
        recovery_set_generation: request.recovery_set_generation,
        effective_recipient_fingerprints: effective.fingerprints.clone(),
        state_digest: snapshot.state_digest.0,
        audit_epoch: u64::from_be_bytes(audit_head.audit_epoch[..8].try_into().unwrap()),
        audit_sequence: audit_head.epoch_sequence,
        audit_head: audit_chain_head,
        latest_checkpoint_digest: snapshot.latest_checkpoint_digest,
        signing_key_id: request.signing_key_id,
        signing_lineage_generation: request.signing_lineage_generation,
        signing_transition_digest: request.signing_transition_digest,
        creator_audit_epoch: u64::from_be_bytes(audit_head.audit_epoch[..8].try_into().unwrap()),
        creator_audit_sequence: audit_head.epoch_sequence,
        creator_audit_head: audit_chain_head,
        tables,
        source: request.source,
    };
    let recovery_keyring = request
        .keyring
        .wrap_for_backup(request.active_recipient, request.recovery_recipients)?;
    let payload = BackupPayload {
        manifest: manifest.clone(),
        recovery_keyring,
        frames,
    };
    let plaintext = Zeroizing::new(payload.encode()?);
    let mut recipients: Vec<(RecipientFingerprint, &dyn Recipient)> = vec![(
        RecipientFingerprint::of(request.active_recipient),
        request.active_recipient,
    )];
    recipients.extend(request.recovery_recipients.iter().map(|recipient| {
        (
            RecipientFingerprint::of(recipient),
            recipient as &dyn Recipient,
        )
    }));
    recipients.sort_by_key(|(fingerprint, _)| *fingerprint);
    let encryptor =
        Encryptor::with_recipients(recipients.into_iter().map(|(_, recipient)| recipient))
            .map_err(|_| BackupError::Crypto)?;
    let mut encrypted_payload = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted_payload)
        .map_err(|_| BackupError::Crypto)?;
    writer
        .write_all(&plaintext)
        .and_then(|()| writer.finish())
        .map_err(|_| BackupError::Crypto)?;
    let container = BackupContainer::new(
        BackupSigningHeader {
            archive_id: request.archive_id,
            store_incarnation_id: request.store_incarnation_id,
            signing_key_id: request.signing_key_id,
            signing_domain: BACKUP_SIGNING_DOMAIN_ID,
            signing_lineage_generation: request.signing_lineage_generation,
            recovery_set_generation: request.recovery_set_generation,
            effective_recipient_digest: effective.digest,
            encrypted_payload_length: 1,
            encrypted_payload_digest: [1; 32],
            recovery_manifest_digest: manifest.digest()?,
        },
        encrypted_payload,
    )?;
    let artifact_digest = artifact_digest(&container)?;
    Ok(CreatedBackup {
        container,
        artifact_digest,
        manifest,
        effective_recipients: effective,
    })
}

pub fn decrypt_backup(
    container: &BackupContainer,
    identity: &x25519::Identity,
) -> Result<BackupPayload, BackupError> {
    container.encode()?;
    let plaintext = Zeroizing::new(
        age::decrypt(identity, &container.encrypted_payload).map_err(|_| BackupError::Crypto)?,
    );
    let payload = BackupPayload::decode(&plaintext)?;
    let mut recipient_hasher = blake3::Hasher::new();
    recipient_hasher.update(b"ops-light-secrets-server.backup-effective-recipients.v1\0");
    for fingerprint in &payload.manifest.effective_recipient_fingerprints {
        recipient_hasher.update(&(fingerprint.len() as u64).to_be_bytes());
        recipient_hasher.update(fingerprint);
    }
    if payload.manifest.digest()? != container.header.recovery_manifest_digest
        || payload.manifest.archive_id != container.header.archive_id
        || payload.manifest.signing_key_id != container.header.signing_key_id
        || payload.manifest.recovery_set_generation != container.header.recovery_set_generation
        || *recipient_hasher.finalize().as_bytes() != container.header.effective_recipient_digest
    {
        return Err(BackupError::Invalid);
    }
    Ok(payload)
}

pub fn summarize_frames(frames: &[ArchiveFrame]) -> Result<Vec<TableSummary>, CodecError> {
    let mut summaries = Vec::with_capacity(frames.len());
    for frame in frames {
        let encoded = frame.encode()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ops-light-secrets-server.backup-table.v1\0");
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
        summaries.push(TableSummary {
            table_id: frame.table_id,
            codec_version: frame.codec_version,
            entry_count: frame.entries.len() as u64,
            digest: *hasher.finalize().as_bytes(),
        });
    }
    Ok(summaries)
}

pub fn artifact_digest(container: &BackupContainer) -> Result<[u8; 32], BackupError> {
    let header = container.header.encode()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARTIFACT_DOMAIN);
    hasher.update(&(header.len() as u64).to_be_bytes());
    hasher.update(&header);
    hasher.update(&container.header.encrypted_payload_digest);
    Ok(*hasher.finalize().as_bytes())
}

pub fn sign_backup(
    container: &BackupContainer,
    expected_public_key: &[u8; 32],
    private_key: &mut [u8; 32],
) -> Result<DetachedBackupSignature, BackupError> {
    let secret = Zeroizing::new(*private_key);
    private_key.zeroize();
    let signing_key = SigningKey::from_bytes(&secret);
    if signing_key.verifying_key().as_bytes() != expected_public_key {
        return Err(BackupError::Crypto);
    }
    let digest = artifact_digest(container)?;
    let signature = signing_key.sign(&signature_message(container.header.signing_key_id, digest));
    Ok(DetachedBackupSignature {
        key_id: container.header.signing_key_id,
        content_digest: digest,
        signature: signature.to_bytes(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecipientCatalog {
    generation: u64,
    recipients: Vec<x25519::Recipient>,
}

impl RecoveryRecipientCatalog {
    pub fn new(
        generation: u64,
        mut recipients: Vec<x25519::Recipient>,
    ) -> Result<Self, BackupError> {
        recipients.sort_by_key(RecipientFingerprint::of);
        if generation == 0
            || recipients.is_empty()
            || recipients.len() > 7
            || recipients.windows(2).any(|pair| {
                RecipientFingerprint::of(&pair[0]) == RecipientFingerprint::of(&pair[1])
            })
        {
            return Err(BackupError::Invalid);
        }
        Ok(Self {
            generation,
            recipients,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn fingerprints(&self) -> Vec<[u8; 32]> {
        self.recipients
            .iter()
            .map(|recipient| RecipientFingerprint::of(recipient).0)
            .collect()
    }

    pub fn recipients(&self) -> &[x25519::Recipient] {
        &self.recipients
    }

    pub fn replace(
        &mut self,
        expected_generation: u64,
        active: &x25519::Recipient,
        recipients: Vec<x25519::Recipient>,
        reason: &str,
        confirmation: [u8; 32],
        authorized: bool,
    ) -> Result<u64, BackupError> {
        let candidate = Self::new(
            expected_generation
                .checked_add(1)
                .ok_or(BackupError::Invalid)?,
            recipients,
        )?;
        if !authorized
            || self.generation != expected_generation
            || candidate.recipients.iter().any(|recipient| {
                RecipientFingerprint::of(recipient) == RecipientFingerprint::of(active)
            })
            || !valid_reason(reason)
            || confirmation
                != recipient_set_confirmation(
                    expected_generation,
                    active,
                    &candidate.recipients,
                    reason,
                )
        {
            return Err(BackupError::Unauthorized);
        }
        *self = candidate;
        Ok(self.generation)
    }
}

pub fn recipient_set_confirmation(
    expected_generation: u64,
    active: &x25519::Recipient,
    recovery: &[x25519::Recipient],
    reason: &str,
) -> [u8; 32] {
    let mut fingerprints = recovery
        .iter()
        .map(|recipient| RecipientFingerprint::of(recipient).0)
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.backup-recipient-set.v1\0");
    hasher.update(&expected_generation.to_be_bytes());
    hasher.update(&RecipientFingerprint::of(active).0);
    for fingerprint in fingerprints {
        hasher.update(&fingerprint);
    }
    hasher.update(&(reason.len() as u64).to_be_bytes());
    hasher.update(reason.as_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    Publishing,
    Published,
    Registered,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptState {
    Missing,
    UnknownOffline,
    Registered,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRecord {
    pub artifact_digest: [u8; 32],
    pub inner_manifest_digest: [u8; 32],
    pub output_id: [u8; 16],
    pub owner_id: [u8; 16],
    pub target_identity_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub snapshot_sequence: u64,
    pub snapshot_state_digest: [u8; 32],
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub keyring_generation: u64,
    pub recovery_set_generation: u64,
    pub effective_recipient_digest: [u8; 32],
    pub publication: PublicationState,
    pub signature_registered: bool,
    pub active_receipt: ReceiptState,
    pub recovery_receipt: ReceiptState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupView {
    pub artifact_digest_prefix: String,
    pub output_id: [u8; 16],
    pub snapshot_sequence: u64,
    pub state_digest_prefix: String,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub keyring_generation: u64,
    pub recovery_set_generation: u64,
    pub publication: PublicationState,
    pub signature_registered: bool,
    pub active_receipt: ReceiptState,
    pub recovery_receipt: ReceiptState,
    pub file_status: &'static str,
    pub next_action: &'static str,
}

impl BackupRecord {
    pub fn safe_view(&self, exact_file_present: bool) -> BackupView {
        let next_action = match self.publication {
            PublicationState::Publishing if exact_file_present => "backup resume <manifest-digest>",
            PublicationState::Publishing => "backup manifest abandon <manifest-digest>",
            PublicationState::Published if !self.signature_registered => {
                "backup manifest sign --archive <file>"
            }
            PublicationState::Published | PublicationState::Registered
                if self.recovery_receipt != ReceiptState::Registered =>
            {
                "backup rehearse --mode recovery"
            }
            PublicationState::Published => "none",
            PublicationState::Registered => "none",
            PublicationState::Abandoned => "none",
        };
        BackupView {
            artifact_digest_prefix: hex(&self.artifact_digest[..8]),
            output_id: self.output_id,
            snapshot_sequence: self.snapshot_sequence,
            state_digest_prefix: hex(&self.snapshot_state_digest[..8]),
            signing_key_id: self.signing_key_id,
            signing_lineage_generation: self.signing_lineage_generation,
            keyring_generation: self.keyring_generation,
            recovery_set_generation: self.recovery_set_generation,
            publication: self.publication,
            signature_registered: self.signature_registered,
            active_receipt: self.active_receipt,
            recovery_receipt: self.recovery_receipt,
            file_status: if exact_file_present {
                "exact"
            } else {
                "missing"
            },
            next_action,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackupFilter {
    pub publication: Option<PublicationState>,
    pub signature_registered: Option<bool>,
    pub recovery_receipt: Option<ReceiptState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedPublication {
    ExactTemp,
    ExactFinal,
    Missing,
    Corrupt,
    TargetSubstituted,
}

pub struct SignatureRegistration<'a> {
    pub digest: [u8; 32],
    pub container: &'a BackupContainer,
    pub signature: &'a DetachedBackupSignature,
    pub public_key: &'a [u8; 32],
    pub current_key_id: [u8; 16],
    pub current_generation: u64,
    pub authorized: bool,
}

#[derive(Default)]
pub struct BackupCatalog {
    records: BTreeMap<[u8; 32], BackupRecord>,
}

impl BackupCatalog {
    pub fn reserve(&mut self, record: BackupRecord, authorized: bool) -> Result<(), BackupError> {
        if !authorized
            || record.artifact_digest == [0; 32]
            || record.output_id == [0; 16]
            || record.owner_id == [0; 16]
            || record.target_identity_digest == [0; 32]
            || record.content_digest == [0; 32]
            || record.publication != PublicationState::Publishing
            || record.signature_registered
        {
            return Err(BackupError::Unauthorized);
        }
        match self.records.get(&record.artifact_digest) {
            Some(existing) if existing == &record => Ok(()),
            Some(_) => Err(BackupError::Conflict),
            None => {
                self.records.insert(record.artifact_digest, record);
                Ok(())
            }
        }
    }

    pub fn show(&self, digest: [u8; 32]) -> Result<&BackupRecord, BackupError> {
        self.records.get(&digest).ok_or(BackupError::NotFound)
    }

    pub fn list(
        &self,
        after: Option<[u8; 32]>,
        limit: usize,
        filter: BackupFilter,
    ) -> Result<Vec<&BackupRecord>, BackupError> {
        if !(1..=100).contains(&limit) {
            return Err(BackupError::Invalid);
        }
        Ok(self
            .records
            .iter()
            .filter(|(digest, _)| after.is_none_or(|cursor| **digest > cursor))
            .map(|(_, record)| record)
            .filter(|record| {
                filter
                    .publication
                    .is_none_or(|value| record.publication == value)
                    && filter
                        .signature_registered
                        .is_none_or(|value| record.signature_registered == value)
                    && filter
                        .recovery_receipt
                        .is_none_or(|value| record.recovery_receipt == value)
            })
            .take(limit)
            .collect())
    }

    pub fn resume(
        &mut self,
        digest: [u8; 32],
        observation: ObservedPublication,
        current_caller_authorized: bool,
    ) -> Result<PublicationState, BackupError> {
        if !current_caller_authorized {
            return Err(BackupError::Unauthorized);
        }
        let record = self.records.get_mut(&digest).ok_or(BackupError::NotFound)?;
        if record.publication == PublicationState::Published
            || record.publication == PublicationState::Registered
        {
            return Ok(record.publication);
        }
        if record.publication != PublicationState::Publishing {
            return Err(BackupError::Conflict);
        }
        match observation {
            ObservedPublication::ExactTemp | ObservedPublication::ExactFinal => {
                record.publication = PublicationState::Published;
                Ok(record.publication)
            }
            ObservedPublication::Missing
            | ObservedPublication::Corrupt
            | ObservedPublication::TargetSubstituted => Err(BackupError::AbandonRequired),
        }
    }

    pub fn register_signature(
        &mut self,
        request: SignatureRegistration<'_>,
    ) -> Result<(), BackupError> {
        if !request.authorized || artifact_digest(request.container)? != request.digest {
            return Err(BackupError::Unauthorized);
        }
        let record = self
            .records
            .get_mut(&request.digest)
            .ok_or(BackupError::NotFound)?;
        if record.signature_registered {
            return Ok(());
        }
        if record.publication != PublicationState::Published
            || record.signing_key_id != request.current_key_id
            || record.signing_lineage_generation != request.current_generation
            || request.signature.content_digest != request.digest
        {
            return Err(BackupError::Conflict);
        }
        request
            .signature
            .verify(&request.container.header, request.public_key)
            .map_err(|_| BackupError::Crypto)?;
        record.signature_registered = true;
        record.publication = PublicationState::Registered;
        Ok(())
    }

    pub fn register_receipt(
        &mut self,
        digest: [u8; 32],
        recovery: bool,
        cryptographically_valid: bool,
        authorized: bool,
    ) -> Result<(), BackupError> {
        if !authorized || !cryptographically_valid {
            return Err(BackupError::Unauthorized);
        }
        let record = self.records.get_mut(&digest).ok_or(BackupError::NotFound)?;
        if recovery {
            record.recovery_receipt = ReceiptState::Registered;
        } else {
            record.active_receipt = ReceiptState::Registered;
        }
        Ok(())
    }

    pub fn abandon(
        &mut self,
        digest: [u8; 32],
        reason: &str,
        confirmation: [u8; 32],
        authorized: bool,
    ) -> Result<(), BackupError> {
        if !authorized
            || !valid_reason(reason)
            || confirmation != abandon_confirmation(digest, reason)
        {
            return Err(BackupError::Unauthorized);
        }
        let record = self.records.get_mut(&digest).ok_or(BackupError::NotFound)?;
        if record.publication == PublicationState::Registered || record.signature_registered {
            return Err(BackupError::Conflict);
        }
        if record.publication == PublicationState::Abandoned {
            return Ok(());
        }
        record.publication = PublicationState::Abandoned;
        Ok(())
    }
}

pub fn abandon_confirmation(digest: [u8; 32], reason: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.backup-abandon.v1\0");
    hasher.update(&digest);
    hasher.update(&(reason.len() as u64).to_be_bytes());
    hasher.update(reason.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn operational_preflight(record: &BackupRecord) -> Result<(), BackupError> {
    if record.publication != PublicationState::Registered
        || !record.signature_registered
        || record.recovery_receipt != ReceiptState::Registered
    {
        return Err(BackupError::Conflict);
    }
    Ok(())
}

pub struct PreparedOutput {
    temp_path: PathBuf,
    final_path: PathBuf,
    bytes_digest: [u8; 32],
    target_identity_digest: [u8; 32],
}

impl PreparedOutput {
    pub fn bytes_digest(&self) -> [u8; 32] {
        self.bytes_digest
    }

    pub fn target_identity_digest(&self) -> [u8; 32] {
        self.target_identity_digest
    }

    fn publish(self) -> Result<(), BackupError> {
        if self.final_path.exists() {
            return Err(BackupError::Conflict);
        }
        std::fs::rename(&self.temp_path, &self.final_path).map_err(|_| BackupError::Io)?;
        let parent = self.final_path.parent().ok_or(BackupError::Io)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| BackupError::Io)
    }
}

pub fn publish_reserved(
    catalog: &mut BackupCatalog,
    digest: [u8; 32],
    prepared: PreparedOutput,
) -> Result<PublicationState, BackupError> {
    let record = catalog.show(digest)?;
    if record.publication != PublicationState::Publishing
        || record.content_digest != prepared.bytes_digest
        || record.target_identity_digest != prepared.target_identity_digest
    {
        return Err(BackupError::Conflict);
    }
    prepared.publish()?;
    catalog.resume(digest, ObservedPublication::ExactFinal, true)
}

impl Drop for PreparedOutput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

pub fn prepare_output(
    path: &Path,
    bytes: &[u8],
    nonce: [u8; 16],
) -> Result<PreparedOutput, BackupError> {
    if bytes.is_empty() || path.symlink_metadata().is_ok() {
        return Err(BackupError::Conflict);
    }
    let parent = path.parent().ok_or(BackupError::Invalid)?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(BackupError::Invalid)?;
    let temp_path = parent.join(format!(".{filename}.{}.publishing", hex(&nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|_| BackupError::Io)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
        return Err(BackupError::Io);
    }
    let metadata = file.metadata().map_err(|_| BackupError::Io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
    {
        let _ = std::fs::remove_file(&temp_path);
        return Err(BackupError::Io);
    }
    let canonical_parent = parent.canonicalize().map_err(|_| BackupError::Io)?;
    let mut target_hasher = blake3::Hasher::new();
    target_hasher.update(b"ops-light-secrets-server.backup-target.v1\0");
    target_hasher.update(canonical_parent.as_os_str().as_encoded_bytes());
    target_hasher.update(filename.as_bytes());
    Ok(PreparedOutput {
        temp_path,
        final_path: path.to_path_buf(),
        bytes_digest: *blake3::hash(bytes).as_bytes(),
        target_identity_digest: *target_hasher.finalize().as_bytes(),
    })
}

pub fn write_detached_signature_atomic(
    path: &Path,
    signature: &DetachedBackupSignature,
) -> Result<(), BackupError> {
    let bytes = signature.encode()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| BackupError::Io)?;
    if file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = std::fs::remove_file(path);
        return Err(BackupError::Io);
    }
    File::open(path.parent().ok_or(BackupError::Io)?)
        .and_then(|parent| parent.sync_all())
        .map_err(|_| BackupError::Io)
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= 1024 && !reason.chars().any(char::is_control)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
