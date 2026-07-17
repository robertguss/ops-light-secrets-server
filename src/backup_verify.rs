//! Offline backup verification and signed disaster-recovery rehearsal receipts.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::x25519;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

use crate::backup::{BackupPayload, artifact_digest, decrypt_backup};
use crate::backup_format::{BackupContainer, SignatureStatus};
use crate::restore::{RestoreSignature, reconstruct_and_verify, verify_backup_gate};
use crate::store::keyring::{Keyring, RandomSource, RecipientFingerprint};
use crate::store::{Canonical, CodecError, Decoder, Encoder, SigningKeyCandidate, StoreId};

const RECEIPT_DOMAIN: &[u8] = b"ops-light-secrets-server.backup-rehearsal-receipt.v1\0";
const MAX_RECEIPT_BYTES: usize = 4096;
const MIN_WORKSPACE_HEADROOM: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RehearsalMode {
    ActiveRecipient = 1,
    RecoveryRecipient = 2,
}

impl RehearsalMode {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::ActiveRecipient),
            2 => Ok(Self::RecoveryRecipient),
            _ => Err(CodecError::Invalid),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ActiveRecipient => "integrity-verified (active-recipient path)",
            Self::RecoveryRecipient => "DR-rehearsed (recovery path)",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum BackupVerifyError {
    Outer,
    Signature,
    RecoveryEnvelope,
    Workspace,
    Capacity,
    Reconstruction,
    Receipt,
    Registration,
}

impl std::fmt::Display for BackupVerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Outer => "backup outer manifest/frame verification failed",
            Self::Signature => "backup detached signature/trust verification failed",
            Self::RecoveryEnvelope => "backup recovery envelope identity unwrap failed",
            Self::Workspace => "backup rehearsal workspace unsafe or unavailable",
            Self::Capacity => "backup rehearsal projected temporary usage exceeds safety headroom",
            Self::Reconstruction => {
                "backup rehearsal encrypted record/table MAC/AEAD/audit verification failed"
            }
            Self::Receipt => "backup rehearsal receipt signing or output failed",
            Self::Registration => "backup rehearsal receipt registration refused",
        })
    }
}

impl std::error::Error for BackupVerifyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicVerification {
    pub archive_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub store_id: StoreId,
    pub signature_status: SignatureStatus,
    pub mode: RehearsalMode,
    pub recovery_set_generation: u64,
    pub keyring_generation: u64,
}

pub fn verify_backup(
    container: &BackupContainer,
    signature: RestoreSignature<'_>,
    identity: &x25519::Identity,
) -> Result<(BasicVerification, BackupPayload, Keyring), BackupVerifyError> {
    let (archive_digest, signature_status) =
        verify_backup_gate(container, signature).map_err(|error| match error {
            crate::restore::RestoreError::Signature => BackupVerifyError::Signature,
            _ => BackupVerifyError::Outer,
        })?;
    let payload =
        decrypt_backup(container, identity).map_err(|_| BackupVerifyError::RecoveryEnvelope)?;
    let keyring = Keyring::open_backup_envelope(
        payload.manifest.store_id,
        &payload.recovery_keyring,
        identity,
    )
    .map_err(|_| BackupVerifyError::RecoveryEnvelope)?;
    let supplied = RecipientFingerprint::of(&identity.to_public());
    let mode = if supplied == keyring.recipients().active {
        RehearsalMode::ActiveRecipient
    } else {
        RehearsalMode::RecoveryRecipient
    };
    Ok((
        BasicVerification {
            archive_digest,
            manifest_digest: payload
                .manifest
                .digest()
                .map_err(|_| BackupVerifyError::Outer)?,
            store_id: payload.manifest.store_id,
            signature_status,
            mode,
            recovery_set_generation: payload.manifest.recovery_set_generation,
            keyring_generation: payload.manifest.keyring_generation,
        },
        payload,
        keyring,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RehearsalReceipt {
    pub archive_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub store_id: StoreId,
    pub mode: RehearsalMode,
    pub recovery_set_generation: u64,
    pub keyring_generation: u64,
    pub verified_record_count: u64,
    pub performed_at_unix_seconds: u64,
    pub tool_version: String,
    pub signing_key_id: [u8; 16],
    pub signature: [u8; 64],
}

impl RehearsalReceipt {
    fn unsigned_bytes(&self) -> Result<Vec<u8>, CodecError> {
        if self.archive_digest == [0; 32]
            || self.manifest_digest == [0; 32]
            || self.store_id.0 == [0; 16]
            || self.recovery_set_generation == 0
            || self.keyring_generation == 0
            || self.performed_at_unix_seconds == 0
            || self.tool_version.is_empty()
            || self.signing_key_id == [0; 16]
        {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.fixed(&self.archive_digest);
        out.fixed(&self.manifest_digest);
        out.fixed(&self.store_id.0);
        out.u8(self.mode as u8);
        out.u64(self.recovery_set_generation);
        out.u64(self.keyring_generation);
        out.u64(self.verified_record_count);
        out.u64(self.performed_at_unix_seconds);
        out.string(&self.tool_version, 128)?;
        out.fixed(&self.signing_key_id);
        Ok(out.finish())
    }

    fn signing_message(&self) -> Result<Vec<u8>, CodecError> {
        let bytes = self.unsigned_bytes()?;
        let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len() + 8 + bytes.len());
        message.extend_from_slice(RECEIPT_DOMAIN);
        message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        message.extend_from_slice(&bytes);
        Ok(message)
    }

    pub fn verify(&self, candidate: &SigningKeyCandidate) -> Result<(), BackupVerifyError> {
        if candidate.id != self.signing_key_id {
            return Err(BackupVerifyError::Receipt);
        }
        VerifyingKey::from_bytes(&candidate.verifying_key)
            .map_err(|_| BackupVerifyError::Receipt)?
            .verify(
                &self
                    .signing_message()
                    .map_err(|_| BackupVerifyError::Receipt)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| BackupVerifyError::Receipt)
    }
}

impl Canonical for RehearsalReceipt {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.signature == [0; 64] {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.bytes(&self.unsigned_bytes()?, MAX_RECEIPT_BYTES)?;
        out.fixed(&self.signature);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let unsigned = input.bytes(MAX_RECEIPT_BYTES)?;
        let signature = input.fixed()?;
        input.finish()?;
        let mut fields = Decoder::version(&unsigned, 1)?;
        let value = Self {
            archive_digest: fields.fixed()?,
            manifest_digest: fields.fixed()?,
            store_id: StoreId(fields.fixed()?),
            mode: RehearsalMode::decode(fields.u8()?)?,
            recovery_set_generation: fields.u64()?,
            keyring_generation: fields.u64()?,
            verified_record_count: fields.u64()?,
            performed_at_unix_seconds: fields.u64()?,
            tool_version: fields.string(128)?,
            signing_key_id: fields.fixed()?,
            signature,
        };
        fields.finish()?;
        value.encode()?;
        Ok(value)
    }
}

pub struct FullVerifyRequest<'a> {
    pub identity: &'a x25519::Identity,
    pub work_directory: &'a Path,
    pub performed_at_unix_seconds: u64,
    pub receipt_signing_candidate: &'a SigningKeyCandidate,
    pub receipt_private_key: &'a mut [u8; 32],
}

pub fn verify_backup_full(
    container: &BackupContainer,
    signature: RestoreSignature<'_>,
    request: FullVerifyRequest<'_>,
    random: &mut impl RandomSource,
) -> Result<RehearsalReceipt, BackupVerifyError> {
    let (verification, payload, keyring) = verify_backup(container, signature, request.identity)?;
    validate_workspace(request.work_directory, projected_usage(container, &payload))?;
    let mut nonce = [0; 16];
    random
        .fill(&mut nonce)
        .map_err(|_| BackupVerifyError::Workspace)?;
    let guard = WorkDirectory::create(request.work_directory, nonce)?;
    let store_path = guard.path.join("rehearsal.redb");
    let (store, verified_record_count) = reconstruct_and_verify(&store_path, &payload, &keyring)
        .map_err(|_| BackupVerifyError::Reconstruction)?;
    drop(store);
    File::open(&store_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| BackupVerifyError::Workspace)?;
    let signing = SigningKey::from_bytes(request.receipt_private_key);
    request.receipt_private_key.zeroize();
    if signing.verifying_key().to_bytes() != request.receipt_signing_candidate.verifying_key {
        return Err(BackupVerifyError::Receipt);
    }
    let mut receipt = RehearsalReceipt {
        archive_digest: verification.archive_digest,
        manifest_digest: verification.manifest_digest,
        store_id: verification.store_id,
        mode: verification.mode,
        recovery_set_generation: verification.recovery_set_generation,
        keyring_generation: verification.keyring_generation,
        verified_record_count,
        performed_at_unix_seconds: request.performed_at_unix_seconds,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        signing_key_id: request.receipt_signing_candidate.id,
        signature: [0; 64],
    };
    receipt.signature = signing
        .sign(
            &receipt
                .signing_message()
                .map_err(|_| BackupVerifyError::Receipt)?,
        )
        .to_bytes();
    receipt.verify(request.receipt_signing_candidate)?;
    Ok(receipt)
}

pub fn write_rehearsal_receipt_atomic(
    path: &Path,
    receipt: &RehearsalReceipt,
) -> Result<(), BackupVerifyError> {
    if path.symlink_metadata().is_ok() {
        return Err(BackupVerifyError::Receipt);
    }
    let parent = path.parent().ok_or(BackupVerifyError::Receipt)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(BackupVerifyError::Receipt)?;
    let temp = parent.join(format!(".{name}.tmp"));
    if temp.symlink_metadata().is_ok() {
        return Err(BackupVerifyError::Receipt);
    }
    let bytes = receipt.encode().map_err(|_| BackupVerifyError::Receipt)?;
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| BackupVerifyError::Receipt)?;
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| BackupVerifyError::Receipt)?;
        std::fs::rename(&temp, path).map_err(|_| BackupVerifyError::Receipt)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| BackupVerifyError::Receipt)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredRehearsal {
    pub receipt: RehearsalReceipt,
    pub registered_at_effective_seconds: u64,
}

#[derive(Default)]
pub struct RehearsalRegistry {
    records: BTreeMap<([u8; 32], RehearsalMode), RegisteredRehearsal>,
}

pub struct RegisterRehearsalRequest<'a> {
    pub receipt: &'a RehearsalReceipt,
    pub current_signer: &'a SigningKeyCandidate,
    pub expected_archive_digest: [u8; 32],
    pub expected_recovery_set_generation: u64,
    pub registered_at_effective_seconds: u64,
    pub service_owner: bool,
    pub control_credential: bool,
    pub backup_capability: bool,
    pub final_barrier_current: bool,
}

impl RehearsalRegistry {
    pub fn register(
        &mut self,
        request: RegisterRehearsalRequest<'_>,
    ) -> Result<&RegisteredRehearsal, BackupVerifyError> {
        request.receipt.verify(request.current_signer)?;
        if request.expected_archive_digest != request.receipt.archive_digest
            || request.expected_recovery_set_generation != request.receipt.recovery_set_generation
            || request.registered_at_effective_seconds == 0
            || !request.service_owner
            || !request.control_credential
            || !request.backup_capability
            || !request.final_barrier_current
        {
            return Err(BackupVerifyError::Registration);
        }
        let key = (request.receipt.archive_digest, request.receipt.mode);
        match self.records.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                if entry.get().receipt != *request.receipt {
                    return Err(BackupVerifyError::Registration);
                }
                Ok(entry.into_mut())
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                Ok(entry.insert(RegisteredRehearsal {
                    receipt: request.receipt.clone(),
                    registered_at_effective_seconds: request.registered_at_effective_seconds,
                }))
            }
        }
    }

    pub fn age_seconds(
        &self,
        archive_digest: [u8; 32],
        mode: RehearsalMode,
        now_effective_seconds: u64,
    ) -> Option<u64> {
        self.records.get(&(archive_digest, mode)).map(|record| {
            now_effective_seconds.saturating_sub(record.registered_at_effective_seconds)
        })
    }
}

fn projected_usage(container: &BackupContainer, payload: &BackupPayload) -> u64 {
    payload.frames.iter().fold(
        container.encrypted_payload.len() as u64 + MIN_WORKSPACE_HEADROOM,
        |total, frame| {
            frame.entries.iter().fold(total, |total, entry| {
                total.saturating_add((entry.key.len() + entry.value.len()) as u64)
            })
        },
    )
}

fn validate_workspace(path: &Path, projected: u64) -> Result<(), BackupVerifyError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| BackupVerifyError::Workspace)?;
    let mode = metadata.permissions().mode();
    let private_owner_directory = metadata.uid() == unsafe { libc::geteuid() } && mode & 0o077 == 0;
    let root_sticky_directory = metadata.uid() == 0 && mode & libc::S_ISVTX != 0;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (!private_owner_directory && !root_sticky_directory)
    {
        return Err(BackupVerifyError::Workspace);
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| BackupVerifyError::Workspace)?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(BackupVerifyError::Workspace);
    }
    let stats = unsafe { stats.assume_init() };
    let available = stats.f_bavail.saturating_mul(stats.f_frsize);
    if projected > available / 2 {
        return Err(BackupVerifyError::Capacity);
    }
    Ok(())
}

struct WorkDirectory {
    path: PathBuf,
}

impl WorkDirectory {
    fn create(parent: &Path, nonce: [u8; 16]) -> Result<Self, BackupVerifyError> {
        if nonce == [0; 16] {
            return Err(BackupVerifyError::Workspace);
        }
        let path = parent.join(format!(
            ".ops-light-secrets-server-rehearsal-{}",
            hex(&nonce)
        ));
        std::fs::create_dir(&path).map_err(|_| BackupVerifyError::Workspace)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| BackupVerifyError::Workspace)?;
        Ok(Self { path })
    }
}

impl Drop for WorkDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn receipt_artifact_digest(receipt: &RehearsalReceipt) -> Result<[u8; 32], BackupVerifyError> {
    Ok(*blake3::hash(&receipt.encode().map_err(|_| BackupVerifyError::Receipt)?).as_bytes())
}

pub fn archive_digest(container: &BackupContainer) -> Result<[u8; 32], BackupVerifyError> {
    artifact_digest(container).map_err(|_| BackupVerifyError::Outer)
}
