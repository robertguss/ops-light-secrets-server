//! Verify-first fresh-host restore into an absent target.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::x25519;

use crate::backup::{BackupError, BackupPayload, artifact_digest, decrypt_backup};
use crate::backup_format::{
    BackupContainer, DetachedBackupSignature, SignatureStatus, UnsignedOverride,
    allow_restore_signature,
};
use crate::credential_epoch::{
    EpochRotationMode, EpochRotationRequest, InterruptedJobState, plan_epoch_rotation,
    prepare_restore_epoch_rotation,
};
use crate::init::validate_secret_sink;
use crate::store::keyring::{
    Keyring, RandomSource, RecipientRewrapRequest, RecipientSet, recipient_rewrap_confirmation,
};
use crate::store::{
    Canonical, NormalRestoreActivation, StateDigest, Store, StoreError, StoreId, checkpoint_digest,
};

#[derive(Debug, Eq, PartialEq)]
pub enum RestoreError {
    Invalid,
    TargetExists,
    ParentUnsafe,
    Locked,
    Signature,
    Unwrap,
    Frame,
    AuditChain,
    RecordIntegrity,
    StateDigest,
    Recipient,
    Credential,
    Install,
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "restore assertion invalid",
            Self::TargetExists => "restore target path already exists",
            Self::ParentUnsafe => "restore target parent unsafe",
            Self::Locked => "restore parent lock unavailable",
            Self::Signature => "restore manifest signature check failed",
            Self::Unwrap => "restore archive identity unwrap failed",
            Self::Frame => "restore logical frame reconstruction failed",
            Self::AuditChain => "restore audit_events/audit_head chain verification failed",
            Self::RecordIntegrity => {
                "restore authenticated identity/grant/credential record verification failed"
            }
            Self::StateDigest => "restore reconstructed state digest mismatch",
            Self::Recipient => "restore target recipient installation failed",
            Self::Credential => "restore emergency credential activation failed",
            Self::Install => "restore atomic target installation failed",
        })
    }
}

impl std::error::Error for RestoreError {}

impl From<StoreError> for RestoreError {
    fn from(_: StoreError) -> Self {
        Self::Frame
    }
}

impl From<BackupError> for RestoreError {
    fn from(error: BackupError) -> Self {
        match error {
            BackupError::Crypto => Self::Unwrap,
            _ => Self::Frame,
        }
    }
}

pub enum RestoreSignature<'a> {
    Signed {
        detached: &'a DetachedBackupSignature,
        authenticated_public_key: &'a [u8; 32],
    },
    Unsigned {
        allow_unsigned: bool,
        reason: &'a str,
        confirmation: &'a str,
    },
}

pub struct RestoreRequest<'a> {
    pub target: &'a Path,
    pub recovery_identity: &'a x25519::Identity,
    pub new_active_identity: &'a x25519::Identity,
    pub installed_recovery_recipient: Option<&'a x25519::Recipient>,
    pub signature: RestoreSignature<'a>,
    pub source_decommissioned: bool,
    pub actor_id: [u8; 16],
    pub reason: &'a str,
    pub assertion_confirmation: [u8; 32],
    pub temp_nonce: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreReceipt {
    pub archive_digest: [u8; 32],
    pub installed_store_id: StoreId,
    pub credential_epoch: u64,
    pub credential_accessor: [u8; 16],
    pub new_active_fingerprint: [u8; 32],
    pub recovery_fingerprint: [u8; 32],
    pub signature_status: SignatureStatus,
}

pub fn restore_assertion_confirmation(
    archive_digest: [u8; 32],
    target: &Path,
    active: &x25519::Recipient,
    recovery: &x25519::Recipient,
    actor_id: [u8; 16],
    reason: &str,
) -> Result<[u8; 32], RestoreError> {
    if actor_id == [0; 16] || !valid_reason(reason) {
        return Err(RestoreError::Invalid);
    }
    let parent = target.parent().ok_or(RestoreError::Invalid)?;
    let mut target_hasher = blake3::Hasher::new();
    target_hasher.update(parent.as_os_str().as_encoded_bytes());
    target_hasher.update(
        target
            .file_name()
            .ok_or(RestoreError::Invalid)?
            .as_encoded_bytes(),
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.normal-restore-assertion.v1\0");
    hasher.update(&archive_digest);
    hasher.update(target_hasher.finalize().as_bytes());
    hasher.update(&crate::store::keyring::RecipientFingerprint::of(active).0);
    hasher.update(&crate::store::keyring::RecipientFingerprint::of(recovery).0);
    hasher.update(&actor_id);
    hasher.update(&(reason.len() as u64).to_be_bytes());
    hasher.update(reason.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

pub fn verify_backup_gate(
    container: &BackupContainer,
    signature: RestoreSignature<'_>,
) -> Result<([u8; 32], SignatureStatus), RestoreError> {
    container.encode().map_err(|_| RestoreError::Frame)?;
    let archive_digest = artifact_digest(container).map_err(|_| RestoreError::Frame)?;
    let status = match signature {
        RestoreSignature::Signed {
            detached,
            authenticated_public_key,
        } => {
            if detached.content_digest != archive_digest {
                return Err(RestoreError::Signature);
            }
            detached
                .verify(&container.header, authenticated_public_key)
                .map_err(|_| RestoreError::Signature)?;
            SignatureStatus::Valid
        }
        RestoreSignature::Unsigned {
            allow_unsigned,
            reason,
            confirmation,
        } => {
            allow_restore_signature(
                SignatureStatus::Absent,
                archive_digest,
                Some(UnsignedOverride {
                    allow_unsigned,
                    reason,
                    confirmation,
                }),
            )
            .map_err(|_| RestoreError::Signature)?;
            SignatureStatus::Absent
        }
    };
    Ok((archive_digest, status))
}

pub(crate) fn reconstruct_and_verify(
    path: &Path,
    payload: &BackupPayload,
    keyring: &Keyring,
) -> Result<(Store, u64), RestoreError> {
    let store = Store::create_from_archive_frames(path, &payload.frames)?;
    if store
        .state_digest()
        .map_err(|_| RestoreError::StateDigest)?
        .0
        != payload.manifest.state_digest
    {
        return Err(RestoreError::StateDigest);
    }
    let entries = store
        .audit_entries()
        .map_err(|_| RestoreError::AuditChain)?;
    let head = store.audit_head()?.ok_or(RestoreError::AuditChain)?;
    if entries.len() as u64 != payload.manifest.audit_sequence
        || head.chain_hash().map_err(|_| RestoreError::AuditChain)? != payload.manifest.audit_head
    {
        return Err(RestoreError::AuditChain);
    }
    for entry in &entries {
        entry
            .decrypt(keyring)
            .map_err(|_| RestoreError::AuditChain)?;
    }
    let checkpoints = store
        .registered_checkpoints()
        .map_err(|_| RestoreError::AuditChain)?;
    let mut previous: Option<(u64, [u8; 32])> = None;
    for checkpoint in &checkpoints {
        let descriptor = &checkpoint.descriptor;
        let anchored = entries
            .iter()
            .find(|entry| {
                entry.envelope.audit_epoch == descriptor.audit_epoch
                    && entry.envelope.epoch_sequence == descriptor.range_end
            })
            .ok_or(RestoreError::AuditChain)?;
        let digest = checkpoint_digest(checkpoint).map_err(|_| RestoreError::AuditChain)?;
        if descriptor.store_id != payload.manifest.store_id
            || descriptor.audit_epoch != head.audit_epoch
            || anchored
                .envelope
                .chain_hash()
                .map_err(|_| RestoreError::AuditChain)?
                != descriptor.chain_head
        {
            return Err(RestoreError::AuditChain);
        }
        match previous {
            None if descriptor.previous_checkpoint_digest.is_some() => {
                return Err(RestoreError::AuditChain);
            }
            Some((range_end, prior_digest))
                if descriptor.range_start != range_end.saturating_add(1)
                    || descriptor.previous_checkpoint_digest != Some(prior_digest) =>
            {
                return Err(RestoreError::AuditChain);
            }
            _ => {}
        }
        previous = Some((descriptor.range_end, digest));
    }
    if previous.map(|(_, digest)| digest) != payload.manifest.latest_checkpoint_digest {
        return Err(RestoreError::AuditChain);
    }
    let identities = keyring
        .identity_records(&store)
        .map_err(|_| RestoreError::RecordIntegrity)?;
    for identity in &identities {
        keyring
            .grant_records(&store, identity.value.id)
            .map_err(|_| RestoreError::RecordIntegrity)?;
    }
    keyring
        .credential_records(&store)
        .map_err(|_| RestoreError::RecordIntegrity)?;
    keyring
        .credential_epoch(&store)
        .map_err(|_| RestoreError::RecordIntegrity)?;
    let records = keyring
        .verify_encrypted_records(&store)
        .map_err(|_| RestoreError::RecordIntegrity)?;
    Ok((store, records))
}

pub fn restore<W: Write + std::os::fd::AsFd>(
    container: &BackupContainer,
    request: RestoreRequest<'_>,
    credential_sink: &mut W,
    random: &mut impl RandomSource,
) -> Result<RestoreReceipt, RestoreError> {
    // Cheap outer/authentication gate precedes every identity/decode hook.
    let (archive_digest, signature_status) = verify_backup_gate(container, request.signature)?;
    if !request.source_decommissioned
        || request.actor_id == [0; 16]
        || request.temp_nonce == [0; 16]
        || !valid_reason(request.reason)
    {
        return Err(RestoreError::Invalid);
    }
    if request.target.symlink_metadata().is_ok() {
        return Err(RestoreError::TargetExists);
    }
    let parent = request.target.parent().ok_or(RestoreError::ParentUnsafe)?;
    let parent_meta = parent
        .symlink_metadata()
        .map_err(|_| RestoreError::ParentUnsafe)?;
    if !parent_meta.is_dir()
        || parent_meta.file_type().is_symlink()
        || parent_meta.uid() != unsafe { libc::geteuid() }
        || parent_meta.permissions().mode() & 0o077 != 0
    {
        return Err(RestoreError::ParentUnsafe);
    }
    let recovery_recipient = request
        .installed_recovery_recipient
        .cloned()
        .unwrap_or_else(|| request.recovery_identity.to_public());
    let new_active = request.new_active_identity.to_public();
    let expected_assertion = restore_assertion_confirmation(
        archive_digest,
        request.target,
        &new_active,
        &recovery_recipient,
        request.actor_id,
        request.reason,
    )?;
    if request.assertion_confirmation != expected_assertion
        || RecipientSet::new(&new_active, Some(&recovery_recipient)).is_err()
    {
        return Err(RestoreError::Recipient);
    }
    let _lock = RestoreLock::acquire(parent)?;
    if request.target.symlink_metadata().is_ok() {
        return Err(RestoreError::TargetExists);
    }
    let payload = decrypt_backup(container, request.recovery_identity)?;
    let recovered_keyring = Keyring::open_backup_envelope(
        payload.manifest.store_id,
        &payload.recovery_keyring,
        request.recovery_identity,
    )
    .map_err(|_| RestoreError::Unwrap)?;
    let filename = request
        .target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RestoreError::Invalid)?;
    let temp = parent.join(format!(
        ".{filename}.{}.restoring",
        hex(&request.temp_nonce)
    ));
    let result = (|| {
        let (store, _) = reconstruct_and_verify(&temp, &payload, &recovered_keyring)?;
        let head = store.audit_head()?.ok_or(RestoreError::Frame)?;
        if !payload.manifest.source.claimed_decommissioned {
            return Err(RestoreError::Invalid);
        }
        store
            .enter_restore_build(&recovered_keyring)
            .map_err(|_| RestoreError::Invalid)?;
        let reason = "install fresh-host restore recipients";
        let new_set = RecipientSet::new(&new_active, Some(&recovery_recipient))
            .map_err(|_| RestoreError::Recipient)?;
        let confirmation = recipient_rewrap_confirmation(
            payload.manifest.store_id,
            recovered_keyring.generation(),
            recovered_keyring.recipients(),
            new_set,
            reason,
        )
        .map_err(|_| RestoreError::Recipient)?;
        let prepared = recovered_keyring
            .prepare_recipient_rewrap(
                request.new_active_identity,
                RecipientRewrapRequest {
                    expected_generation: payload.manifest.keyring_generation,
                    new_recovery: Some(&recovery_recipient),
                    audit_sequence: head.epoch_sequence + 1,
                    reason,
                    confirmation: &confirmation,
                    authorized: true,
                },
            )
            .map_err(|_| RestoreError::Recipient)?;
        let epoch = prepared
            .keyring
            .credential_epoch(&store)
            .map_err(|_| RestoreError::Credential)?
            .value
            .current;
        let audit_effective_seconds =
            head.effective_timestamp_milliseconds.saturating_add(1_000) / 1_000;
        let epoch_reason = "invalidate credentials during normal restore";
        let authority = EpochRotationMode::Offline {
            service_owner: true,
            daemon_absent: true,
            exclusive_lock: true,
            current_keyring_unwrapped: true,
        };
        let plan = plan_epoch_rotation(&store, &prepared.keyring, epoch, epoch_reason, authority)
            .map_err(|_| RestoreError::Credential)?;
        let epoch_prepared = prepare_restore_epoch_rotation(
            &store,
            &prepared.keyring,
            EpochRotationRequest {
                expected_epoch: epoch,
                effective_seconds: store
                    .meta()
                    .map_err(|_| RestoreError::Credential)?
                    .high_water_unix_seconds
                    .max(audit_effective_seconds)
                    .max(
                        payload
                            .manifest
                            .source
                            .observation_unix_milliseconds
                            .unwrap_or(1)
                            / 1_000,
                    ),
                reason: epoch_reason,
                confirmation: plan.confirmation,
                mode: authority,
                interrupted_job: InterruptedJobState::None,
            },
            random,
        )
        .map_err(|_| RestoreError::Credential)?;
        validate_secret_sink(credential_sink.as_fd()).map_err(|_| RestoreError::Credential)?;
        let credential_epoch = epoch_prepared.plan.next_epoch;
        let credential_accessor = epoch_prepared.credential.value.accessor.0;
        credential_sink
            .write_all(epoch_prepared.replacement_credential.as_bytes())
            .and_then(|()| credential_sink.write_all(b"\n"))
            .and_then(|()| credential_sink.flush())
            .map_err(|_| RestoreError::Credential)?;
        let mut restore_incarnation = [0; 16];
        random
            .fill(&mut restore_incarnation)
            .map_err(|_| RestoreError::Credential)?;
        if restore_incarnation == [0; 16]
            || request.new_active_identity.to_public() != new_active
            || request.recovery_identity.to_public() == new_active
            || restore_assertion_confirmation(
                archive_digest,
                request.target,
                &new_active,
                &recovery_recipient,
                request.actor_id,
                request.reason,
            )? != request.assertion_confirmation
            || prepared.keyring.generation() != payload.manifest.keyring_generation + 1
        {
            return Err(RestoreError::Recipient);
        }
        let event_resource = format!(
            "restore_activation/archive={}/assertion={}/incarnation={}/source_incarnation={}/cutoff={}:{}/source_status={:?}/claimed_decommissioned={}/observed={}:{}:{}/observation_ms={}/provenance={}/tail_status={:?}/tail_digest={}/rpo_known={}/rpo_ack={}/active={}/recovery={}/keyring_generation={}/actor={}/reason_digest={}/emergency_accessor={}",
            hex(&archive_digest),
            hex(&request.assertion_confirmation),
            hex(&restore_incarnation),
            hex(&payload.manifest.store_incarnation_id),
            payload.manifest.audit_epoch,
            payload.manifest.audit_sequence,
            payload.manifest.source.status,
            payload.manifest.source.claimed_decommissioned,
            optional_u64(payload.manifest.source.observed_epoch),
            optional_u64(payload.manifest.source.observed_sequence),
            optional_hex(payload.manifest.source.observed_head.as_ref()),
            optional_u64(payload.manifest.source.observation_unix_milliseconds),
            optional_hex(payload.manifest.source.provenance_digest.as_ref()),
            payload.manifest.source.tail_status,
            optional_hex(payload.manifest.source.tail_digest.as_ref()),
            payload.manifest.source.rpo_known,
            hex(&payload.manifest.source.acknowledgment_digest),
            hex(&crate::store::keyring::RecipientFingerprint::of(&new_active).0),
            hex(&crate::store::keyring::RecipientFingerprint::of(&recovery_recipient).0),
            prepared.keyring.generation(),
            hex(&request.actor_id),
            blake3::hash(request.reason.as_bytes()).to_hex(),
            hex(&credential_accessor),
        );
        let (installed_keyring, _) = store
            .commit_normal_restore_activation(
                NormalRestoreActivation {
                    rewrap: prepared,
                    epoch: epoch_prepared,
                    archived_state_digest: StateDigest(payload.manifest.state_digest),
                    assertion_digest: request.assertion_confirmation,
                    restore_incarnation,
                    event_resource,
                    effective_timestamp_milliseconds: audit_effective_seconds * 1_000,
                },
                random,
            )
            .map_err(|_| RestoreError::Credential)?;
        store
            .audit_entries()
            .map_err(|_| RestoreError::AuditChain)?;
        crate::fault_inject::hit("restore.temp_fsync");
        File::open(&temp)
            .and_then(|file| file.sync_all())
            .map_err(|_| RestoreError::Install)?;
        drop(installed_keyring);
        drop(store);
        crate::fault_inject::hit("restore.install.rename");
        std::fs::rename(&temp, request.target).map_err(|_| RestoreError::Install)?;
        crate::fault_inject::hit("restore.install.parent_fsync");
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| RestoreError::Install)?;
        Ok(RestoreReceipt {
            archive_digest,
            installed_store_id: payload.manifest.store_id,
            credential_epoch,
            credential_accessor,
            new_active_fingerprint: crate::store::keyring::RecipientFingerprint::of(&new_active).0,
            recovery_fingerprint: crate::store::keyring::RecipientFingerprint::of(
                &recovery_recipient,
            )
            .0,
            signature_status,
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

struct RestoreLock {
    path: PathBuf,
    _file: File,
}

impl RestoreLock {
    fn acquire(parent: &Path) -> Result<Self, RestoreError> {
        let path = parent.join(".ops-light-secrets-server.restore.lock");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| RestoreError::Locked)?;
        file.sync_all().map_err(|_| RestoreError::Locked)?;
        Ok(Self { path, _file: file })
    }
}

impl Drop for RestoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= 1024 && !reason.chars().any(char::is_control)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn optional_hex<const N: usize>(value: Option<&[u8; N]>) -> String {
    value.map_or_else(|| "none".into(), |bytes| hex(bytes))
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "none".into(), |number| number.to_string())
}
