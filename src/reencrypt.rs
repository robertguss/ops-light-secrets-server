//! Offline whole-store record-key rewrite and atomic installation.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use age::x25519;
use secrecy::ExposeSecret;

use crate::backup_format::{ARCHIVE_REGISTRY, ArchiveEntry, ArchiveFrame};
use crate::store::keyring::{
    Keyring, KeyringError, PreparedRecordKeyRotation, RandomSource, RecipientFingerprint,
};
use crate::store::{
    AuditOperation, AuditResource, Canonical, EncryptedRecord, KEYRING_KEY, KEYRING_METADATA_KEY,
    Lifecycle, LogicalPath, RecordDomain, RewriteJob, RewriteKind, RewriteStatus, SecretKey,
    StateDigest, Store, StoreError,
};

const CONFIRMATION_DOMAIN: &[u8] = b"ops-light-secrets-server.record-key-rotation-plan.v1\0";
const MIN_HEADROOM: u64 = 16 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub enum RecordRotationError {
    Invalid,
    Identity,
    Authority,
    Evidence,
    Capacity,
    Store,
    Crypto,
    Io,
}

impl std::fmt::Display for RecordRotationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "record-key rotation plan invalid or stale",
            Self::Identity => "record-key rotation identity/recipient mismatch",
            Self::Authority => "record-key rotation authority refused",
            Self::Evidence => "record-key rotation current DR evidence missing",
            Self::Capacity => "record-key rotation sibling capacity unsafe",
            Self::Store => "record-key rotation store verification failed",
            Self::Crypto => "record-key rotation encrypted record failed",
            Self::Io => "record-key rotation filesystem operation failed",
        })
    }
}

impl std::error::Error for RecordRotationError {}

impl From<StoreError> for RecordRotationError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

impl From<KeyringError> for RecordRotationError {
    fn from(_: KeyringError) -> Self {
        Self::Crypto
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentRecoveryEvidence {
    pub archive_digest: [u8; 32],
    pub signature_digest: [u8; 32],
    pub recovery_receipt_digest: [u8; 32],
    pub recovery_set_generation: u64,
    pub signature_registered: bool,
    pub recovery_receipt_registered: bool,
    pub tail_verified: bool,
    pub clean_shutdown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordRotationPlan {
    pub store_id: [u8; 16],
    pub expected_generation: u64,
    pub before_state_digest: [u8; 32],
    pub audit_head: [u8; 32],
    pub evidence: CurrentRecoveryEvidence,
    pub reason: String,
    pub operation_id: [u8; 16],
    pub owner_id: [u8; 16],
    pub confirmation: String,
}

pub struct PlanRequest<'a> {
    pub expected_generation: u64,
    pub reason: &'a str,
    pub operation_id: [u8; 16],
    pub owner_id: [u8; 16],
    pub authorized_key_rotation: bool,
    pub authorized_store_maintenance_override: bool,
    pub control_credential_remaining_seconds: u64,
    pub required_job_abort_margin_seconds: u64,
    pub allow_without_current_dr_backup: bool,
    pub evidence: CurrentRecoveryEvidence,
}

pub fn plan_record_rotation(
    store: &Store,
    keyring: &Keyring,
    request: PlanRequest<'_>,
) -> Result<RecordRotationPlan, RecordRotationError> {
    let meta = store.meta()?;
    if meta.lifecycle != Lifecycle::Ready
        || meta.pending_anchor.is_some()
        || keyring.store_id() != meta.store_id
        || keyring.generation() != request.expected_generation
        || request.operation_id == [0; 16]
        || request.owner_id == [0; 16]
        || request.reason.is_empty()
        || request.reason.len() > 1024
        || request.reason.chars().any(char::is_control)
        || !request.authorized_key_rotation
        || request.control_credential_remaining_seconds <= request.required_job_abort_margin_seconds
    {
        return Err(RecordRotationError::Invalid);
    }
    let current_evidence = request.evidence.signature_registered
        && request.evidence.recovery_receipt_registered
        && request.evidence.tail_verified
        && request.evidence.clean_shutdown
        && request.evidence.archive_digest != [0; 32]
        && request.evidence.signature_digest != [0; 32]
        && request.evidence.recovery_receipt_digest != [0; 32]
        && request.evidence.recovery_set_generation != 0;
    if !(current_evidence
        || request.allow_without_current_dr_backup && request.authorized_store_maintenance_override)
    {
        return Err(RecordRotationError::Evidence);
    }
    let before = store.state_digest()?.0;
    let head = store.audit_head()?.ok_or(RecordRotationError::Store)?;
    let audit_head = head.chain_hash().map_err(|_| RecordRotationError::Store)?;
    let mut plan = RecordRotationPlan {
        store_id: meta.store_id.0,
        expected_generation: request.expected_generation,
        before_state_digest: before,
        audit_head,
        evidence: request.evidence,
        reason: request.reason.to_owned(),
        operation_id: request.operation_id,
        owner_id: request.owner_id,
        confirmation: String::new(),
    };
    plan.confirmation = plan_confirmation(&plan);
    Ok(plan)
}

fn plan_confirmation(plan: &RecordRotationPlan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONFIRMATION_DOMAIN);
    for field in [
        &plan.store_id[..],
        &plan.expected_generation.to_be_bytes(),
        &plan.before_state_digest,
        &plan.audit_head,
        &plan.evidence.archive_digest,
        &plan.evidence.signature_digest,
        &plan.evidence.recovery_receipt_digest,
        &plan.evidence.recovery_set_generation.to_be_bytes(),
        plan.reason.as_bytes(),
        &plan.operation_id,
        &plan.owner_id,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_hex().to_string()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationBuildReceipt {
    pub old_key_id: [u8; 16],
    pub new_key_id: [u8; 16],
    pub rewritten_records: u64,
    pub before_state_digest: StateDigest,
    pub rewritten_state_digest: StateDigest,
    pub job: RewriteJob,
}

pub struct BuildRequest<'a> {
    pub plan: &'a RecordRotationPlan,
    pub confirmation: &'a str,
    pub final_barrier_authorized: bool,
    pub active_recipient: &'a x25519::Recipient,
    pub recovery_recipient: Option<&'a x25519::Recipient>,
    pub source_path: &'a Path,
    pub target: &'a Path,
}

pub fn build_record_rotation(
    source: &Store,
    keyring: Keyring,
    request: BuildRequest<'_>,
    random: &mut impl RandomSource,
) -> Result<(Keyring, RotationBuildReceipt), RecordRotationError> {
    if request.confirmation != request.plan.confirmation
        || !request.final_barrier_authorized
        || request.plan.confirmation != plan_confirmation(request.plan)
        || source.meta()?.store_id.0 != request.plan.store_id
        || source.meta()?.lifecycle != Lifecycle::Reencrypting
        || keyring.generation() != request.plan.expected_generation
        || RecipientFingerprint::of(request.active_recipient) != keyring.recipients().active
        || request.recovery_recipient.map(RecipientFingerprint::of) != keyring.recipients().recovery
        || request.source_path.parent() != request.target.parent()
        || request.target.symlink_metadata().is_ok()
    {
        return Err(RecordRotationError::Invalid);
    }
    let entries = source.audit_entries()?;
    let entered = entries.last().ok_or(RecordRotationError::Store)?;
    let entered_event = entered
        .decrypt(&keyring)
        .map_err(|_| RecordRotationError::Store)?;
    if entered.envelope.previous_hash != request.plan.audit_head
        || entered_event.expose_secret().event_id != phase_id(request.plan.operation_id, b"enter")
        || entered_event.expose_secret().operation != AuditOperation::KeyringChange
        || entered_event.expose_secret().authentication.identity_id != Some(request.plan.owner_id)
        || entered_event.expose_secret().resource
            != Some(AuditResource::Canonical("store/record-key/enter".into()))
    {
        return Err(RecordRotationError::Invalid);
    }
    validate_capacity(request.source_path, request.target, source)?;
    let PreparedRecordKeyRotation {
        mut keyring,
        old_key_id,
        new_key_id,
    } = keyring.prepare_record_key_rotation(request.plan.expected_generation, random)?;
    let snapshot = source.logical_backup_snapshot()?;
    let mut frames = Vec::with_capacity(snapshot.tables.len());
    let mut rewritten_records = 0u64;
    for table in snapshot.tables {
        let codec = ARCHIVE_REGISTRY
            .iter()
            .find(|codec| codec.table == table.table)
            .ok_or(RecordRotationError::Store)?;
        let mut entries = Vec::with_capacity(table.entries.len());
        for (raw_key, raw_value) in table.entries {
            let value = if codec.id == 4 {
                let key = SecretKey::decode(&raw_key).map_err(|_| RecordRotationError::Store)?;
                let record =
                    EncryptedRecord::decode(&raw_value).map_err(|_| RecordRotationError::Store)?;
                let binding = record.header().binding();
                if binding.domain() != RecordDomain::SecretValue
                    || binding.version() != Some(key.version)
                    || LogicalPath::new(format!("{}/{}", binding.mount(), binding.path().as_str()))
                        .map_err(|_| RecordRotationError::Store)?
                        != key.path
                {
                    return Err(RecordRotationError::Store);
                }
                let plaintext = keyring
                    .decrypt_record(binding, &record)
                    .map_err(|_| RecordRotationError::Crypto)?;
                let replacement = keyring
                    .encrypt_record(binding, plaintext.expose_secret(), random)
                    .map_err(|_| RecordRotationError::Crypto)?;
                rewritten_records = rewritten_records
                    .checked_add(1)
                    .ok_or(RecordRotationError::Store)?;
                replacement
                    .encode()
                    .map_err(|_| RecordRotationError::Store)?
            } else {
                raw_value
            };
            entries.push(ArchiveEntry {
                key: raw_key,
                value,
            });
        }
        frames.push(ArchiveFrame {
            table_id: codec.id,
            codec_version: codec.codec_version,
            entries,
        });
    }
    let (envelope, metadata) = keyring.finish_record_key_rotation(
        request.active_recipient,
        request.recovery_recipient,
        snapshot.audit_head.epoch_sequence.saturating_add(1),
    )?;
    let keyring_frame = frames
        .iter_mut()
        .find(|frame| frame.table_id == 2)
        .ok_or(RecordRotationError::Store)?;
    let envelope_row = keyring_frame
        .entries
        .iter_mut()
        .find(|entry| entry.key == KEYRING_KEY)
        .ok_or(RecordRotationError::Store)?;
    envelope_row.value = envelope.encode().map_err(|_| RecordRotationError::Store)?;
    let meta_frame = frames
        .iter_mut()
        .find(|frame| frame.table_id == 1)
        .ok_or(RecordRotationError::Store)?;
    let metadata_row = meta_frame
        .entries
        .iter_mut()
        .find(|entry| entry.key == KEYRING_METADATA_KEY)
        .ok_or(RecordRotationError::Store)?;
    metadata_row.value = metadata.encode().map_err(|_| RecordRotationError::Store)?;
    let target = Store::create_from_archive_frames(request.target, &frames)?;
    let rewritten_state_digest = target.commit_record_rotation_completion(
        &keyring,
        request.plan.operation_id,
        request.plan.owner_id,
        decode_confirmation(&request.plan.confirmation)?,
        StateDigest(request.plan.before_state_digest),
        snapshot
            .audit_head
            .effective_timestamp_milliseconds
            .saturating_add(1),
        random,
    )?;
    keyring.verify_encrypted_records(&target)?;
    let installed_generation = keyring.generation();
    Ok((
        keyring,
        RotationBuildReceipt {
            old_key_id: old_key_id.0,
            new_key_id: new_key_id.0,
            rewritten_records,
            before_state_digest: StateDigest(request.plan.before_state_digest),
            rewritten_state_digest,
            job: RewriteJob {
                kind: RewriteKind::RecordKey,
                operation_id: request.plan.operation_id.to_vec(),
                owner_id: request.plan.owner_id.to_vec(),
                installed_generation,
                installed_state_digest: rewritten_state_digest.0,
                checkpoint_digest: [0; 32],
                backup_artifact_digest: [0; 32],
                backup_signature_digest: [0; 32],
                backup_receipt_digest: [0; 32],
                backup_generation: 0,
                signature_generation: 0,
                receipt_generation: 0,
                status: RewriteStatus::InstalledPendingAnchor,
            },
        },
    ))
}

pub fn mark_record_rotation_anchored(
    job: &mut RewriteJob,
    owner_id: &[u8],
    checkpoint_digest: [u8; 32],
    checkpoint_registered: bool,
    verified_state_digest: [u8; 32],
) -> Result<(), RecordRotationError> {
    if job.kind != RewriteKind::RecordKey
        || checkpoint_digest == [0; 32]
        || !checkpoint_registered
        || verified_state_digest != job.installed_state_digest
    {
        return Err(RecordRotationError::Evidence);
    }
    job.checkpoint_digest = checkpoint_digest;
    job.advance(
        owner_id,
        RewriteStatus::AnchoredRewriteCompleteRecoveryPending,
    )
    .map_err(|_| RecordRotationError::Authority)
}

#[allow(clippy::too_many_arguments)]
pub fn mark_record_rotation_recovery_current(
    job: &mut RewriteJob,
    owner_id: &[u8],
    archive_digest: [u8; 32],
    signature_digest: [u8; 32],
    recovery_receipt_digest: [u8; 32],
    backup_generation: u64,
    signature_generation: u64,
    receipt_generation: u64,
    published: bool,
    signature_registered: bool,
    recovery_receipt_registered: bool,
) -> Result<(), RecordRotationError> {
    if job.kind != RewriteKind::RecordKey
        || archive_digest == [0; 32]
        || signature_digest == [0; 32]
        || recovery_receipt_digest == [0; 32]
        || backup_generation == 0
        || signature_generation == 0
        || receipt_generation == 0
        || !(published && signature_registered && recovery_receipt_registered)
    {
        return Err(RecordRotationError::Evidence);
    }
    job.backup_artifact_digest = archive_digest;
    job.backup_signature_digest = signature_digest;
    job.backup_receipt_digest = recovery_receipt_digest;
    job.backup_generation = backup_generation;
    job.signature_generation = signature_generation;
    job.receipt_generation = receipt_generation;
    job.advance(owner_id, RewriteStatus::CompleteRecoveryCurrent)
        .map_err(|_| RecordRotationError::Authority)
}

fn decode_confirmation(value: &str) -> Result<[u8; 32], RecordRotationError> {
    if value.len() != 64 {
        return Err(RecordRotationError::Invalid);
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| RecordRotationError::Invalid)?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| RecordRotationError::Invalid)?;
    }
    Ok(bytes)
}

pub fn enter_record_rotation(
    store: &Store,
    keyring: &Keyring,
    plan: &RecordRotationPlan,
    confirmation: &str,
    final_barrier_authorized: bool,
    random: &mut impl RandomSource,
) -> Result<(), RecordRotationError> {
    if confirmation != plan.confirmation
        || !final_barrier_authorized
        || plan.confirmation != plan_confirmation(plan)
        || store.state_digest()?.0 != plan.before_state_digest
        || store.meta()?.store_id.0 != plan.store_id
        || keyring.generation() != plan.expected_generation
    {
        return Err(RecordRotationError::Invalid);
    }
    let head = store.audit_head()?.ok_or(RecordRotationError::Store)?;
    store.commit_record_rotation_lifecycle(
        keyring,
        Lifecycle::Ready,
        Lifecycle::Reencrypting,
        phase_id(plan.operation_id, b"enter"),
        phase_id(plan.operation_id, b"enter-request"),
        plan.owner_id,
        head.effective_timestamp_milliseconds.saturating_add(1),
        random,
    )?;
    Ok(())
}

fn phase_id(operation_id: [u8; 16], phase: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.record-key-phase-id.v1\0");
    hasher.update(&operation_id);
    hasher.update(phase);
    let mut id = [0; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

fn validate_capacity(
    source_path: &Path,
    target: &Path,
    source: &Store,
) -> Result<(), RecordRotationError> {
    let parent = target.parent().ok_or(RecordRotationError::Io)?;
    let metadata = parent
        .symlink_metadata()
        .map_err(|_| RecordRotationError::Io)?;
    let source_metadata = source_path
        .symlink_metadata()
        .map_err(|_| RecordRotationError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || !source_metadata.is_file()
        || source_metadata.file_type().is_symlink()
        || source_metadata.uid() != unsafe { libc::geteuid() }
        || source_metadata.nlink() != 1
        || source_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RecordRotationError::Io);
    }
    let projected = source
        .logical_backup_snapshot()?
        .tables
        .iter()
        .flat_map(|table| &table.entries)
        .fold(MIN_HEADROOM, |total, (key, value)| {
            total.saturating_add((key.len() + value.len()) as u64)
        });
    let c_path = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
        .map_err(|_| RecordRotationError::Io)?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(RecordRotationError::Io);
    }
    let stats = unsafe { stats.assume_init() };
    if projected > stats.f_bavail.saturating_mul(stats.f_frsize) / 2 {
        return Err(RecordRotationError::Capacity);
    }
    Ok(())
}

pub fn install_built_store(original: &Path, replacement: &Path) -> Result<(), RecordRotationError> {
    let original_meta = original
        .symlink_metadata()
        .map_err(|_| RecordRotationError::Io)?;
    let replacement_meta = replacement
        .symlink_metadata()
        .map_err(|_| RecordRotationError::Io)?;
    if !original_meta.is_file()
        || !replacement_meta.is_file()
        || original_meta.file_type().is_symlink()
        || replacement_meta.file_type().is_symlink()
        || original_meta.uid() != unsafe { libc::geteuid() }
        || replacement_meta.uid() != original_meta.uid()
        || original_meta.nlink() != 1
        || replacement_meta.nlink() != 1
        || replacement.parent() != original.parent()
    {
        return Err(RecordRotationError::Io);
    }
    std::fs::set_permissions(
        replacement,
        std::fs::Permissions::from_mode(original_meta.permissions().mode() & 0o777),
    )
    .map_err(|_| RecordRotationError::Io)?;
    File::open(replacement)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecordRotationError::Io)?;
    std::fs::rename(replacement, original).map_err(|_| RecordRotationError::Io)?;
    File::open(original.parent().ok_or(RecordRotationError::Io)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecordRotationError::Io)
}

pub fn abort_record_rotation(
    store: &Store,
    keyring: &Keyring,
    plan: &RecordRotationPlan,
    replacement: &Path,
    random: &mut impl RandomSource,
) -> Result<(), RecordRotationError> {
    if keyring.generation() != plan.expected_generation
        || store.meta()?.store_id.0 != plan.store_id
        || plan.confirmation != plan_confirmation(plan)
    {
        return Err(RecordRotationError::Invalid);
    }
    let entries = store.audit_entries()?;
    let entered = entries.last().ok_or(RecordRotationError::Store)?;
    let event = entered
        .decrypt(keyring)
        .map_err(|_| RecordRotationError::Store)?;
    if entered.envelope.previous_hash != plan.audit_head
        || event.expose_secret().event_id != phase_id(plan.operation_id, b"enter")
        || event.expose_secret().authentication.identity_id != Some(plan.owner_id)
    {
        return Err(RecordRotationError::Invalid);
    }
    if replacement.symlink_metadata().is_ok() {
        let metadata = replacement
            .symlink_metadata()
            .map_err(|_| RecordRotationError::Io)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(RecordRotationError::Io);
        }
        std::fs::remove_file(replacement).map_err(|_| RecordRotationError::Io)?;
    }
    let head = store.audit_head()?.ok_or(RecordRotationError::Store)?;
    store.commit_record_rotation_lifecycle(
        keyring,
        Lifecycle::Reencrypting,
        Lifecycle::Ready,
        phase_id(plan.operation_id, b"abort"),
        phase_id(plan.operation_id, b"abort-request"),
        plan.owner_id,
        head.effective_timestamp_milliseconds.saturating_add(1),
        random,
    )?;
    Ok(())
}

pub fn create_private_sibling(path: &Path) -> Result<File, RecordRotationError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| RecordRotationError::Io)
}
