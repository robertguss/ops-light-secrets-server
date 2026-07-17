//! Rollback classification and explicit recovery-fork ceremony.

use std::collections::BTreeSet;
use std::fmt;

use crate::store::{
    AnchorInstalledState, Canonical, CheckpointSignature, CheckpointTrust, CodecError,
    PendingAnchor, PendingAnchorKind, PendingAnchorStatus, SigningLineage, StateDigest, StoreId,
    verify_checkpoint,
};

pub const MAX_ROLLBACK_CHECKPOINTS: usize = 256;

#[derive(Debug, Eq, PartialEq)]
pub enum RecoveryForkError {
    Invalid,
    Evidence,
    Inconsistent,
    RollbackRefused,
    Unauthorized,
    Overflow,
}

impl fmt::Display for RecoveryForkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "recovery-fork input invalid",
            Self::Evidence => "recovery-fork evidence invalid",
            Self::Inconsistent => "recovery-fork evidence inconsistent",
            Self::RollbackRefused => "rollback requires explicit recovery epoch",
            Self::Unauthorized => "recovery-fork authority refused",
            Self::Overflow => "recovery-fork epoch exhausted",
        })
    }
}

impl std::error::Error for RecoveryForkError {}

impl From<CodecError> for RecoveryForkError {
    fn from(_: CodecError) -> Self {
        Self::Evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveRecoveryTuple {
    pub store_id: StoreId,
    pub source_incarnation: [u8; 16],
    pub audit_epoch: [u8; 16],
    pub sequence: u64,
    pub chain_head: [u8; 32],
    pub state_digest: StateDigest,
    pub lineage_generation: u64,
    pub current_signer: [u8; 16],
    pub trust_root: [u8; 16],
}

pub struct SuppliedCheckpoint<'a> {
    /// Checkpoint v2 predates incarnation framing. The authenticated evidence
    /// package supplies and binds the source incarnation alongside it.
    pub source_incarnation: [u8; 16],
    pub checkpoint: &'a CheckpointSignature,
}

pub struct RollbackEvidence<'a> {
    pub checkpoint_trust: &'a CheckpointTrust,
    pub checkpoints: &'a [SuppliedCheckpoint<'a>],
    /// The caller authenticates this canonical public bundle out-of-band. Its
    /// internal transition chain was verified when the lineage was activated.
    pub lineage_source_incarnation: Option<[u8; 16]>,
    pub lineage: Option<&'a SigningLineage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceCompleteness {
    OperatorSupplied,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RollbackTrigger {
    NewerCheckpoint,
    NewerSigningLineage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackClassification {
    pub rollback_required: bool,
    pub triggers: Vec<RollbackTrigger>,
    pub evidence_completeness: EvidenceCompleteness,
    pub evidence_digest: [u8; 32],
    pub latest_supplied_sequence: Option<u64>,
    pub selected_lineage_generation: u64,
    pub selected_current_signer: [u8; 16],
    pub missing_anchored_range: Option<(u64, u64)>,
}

pub fn classify_rollback(
    archive: ArchiveRecoveryTuple,
    evidence: RollbackEvidence<'_>,
) -> Result<RollbackClassification, RecoveryForkError> {
    validate_archive(archive)?;
    if evidence.checkpoints.len() > MAX_ROLLBACK_CHECKPOINTS
        || evidence.lineage.is_some() != evidence.lineage_source_incarnation.is_some()
    {
        return Err(RecoveryForkError::Evidence);
    }
    let mut encoded_evidence = Vec::new();
    let mut prior: Option<(&CheckpointSignature, [u8; 32])> = None;
    let mut latest_sequence = None;
    let mut triggers = BTreeSet::new();
    for supplied in evidence.checkpoints {
        let checkpoint = supplied.checkpoint;
        let descriptor = &checkpoint.descriptor;
        if supplied.source_incarnation != archive.source_incarnation
            || descriptor.store_id != archive.store_id
            || descriptor.audit_epoch != archive.audit_epoch
        {
            return Err(RecoveryForkError::Inconsistent);
        }
        let digest = verify_checkpoint(checkpoint, evidence.checkpoint_trust)
            .map_err(|_| RecoveryForkError::Evidence)?;
        if let Some((previous, previous_digest)) = prior {
            if descriptor.range_start != previous.descriptor.range_end.saturating_add(1)
                || descriptor.previous_checkpoint_digest != Some(previous_digest)
            {
                return Err(RecoveryForkError::Inconsistent);
            }
        }
        if descriptor.range_end == archive.sequence && descriptor.chain_head != archive.chain_head {
            return Err(RecoveryForkError::Inconsistent);
        }
        if descriptor.range_end > archive.sequence {
            triggers.insert(RollbackTrigger::NewerCheckpoint);
        }
        latest_sequence = Some(latest_sequence.map_or(descriptor.range_end, |value: u64| {
            value.max(descriptor.range_end)
        }));
        encoded_evidence.extend_from_slice(&supplied.source_incarnation);
        encoded_evidence.extend_from_slice(&digest);
        encoded_evidence.extend_from_slice(&checkpoint.encode()?);
        prior = Some((checkpoint, digest));
    }

    let mut selected_generation = archive.lineage_generation;
    let mut selected_signer = archive.current_signer;
    if let Some(lineage) = evidence.lineage {
        if evidence.lineage_source_incarnation != Some(archive.source_incarnation) {
            return Err(RecoveryForkError::Inconsistent);
        }
        let encoded = lineage.encode()?;
        let Some(root) = lineage.entries.first() else {
            return Err(RecoveryForkError::Evidence);
        };
        let Some(current) = lineage.current() else {
            return Err(RecoveryForkError::Evidence);
        };
        if root.candidate.id != archive.trust_root
            || current.generation < archive.lineage_generation
            || (current.generation == archive.lineage_generation
                && current.candidate.id != archive.current_signer)
            || lineage.entries.iter().any(|entry| {
                entry.effective_audit_epoch != archive.audit_epoch
                    || (entry.generation > archive.lineage_generation
                        && entry.effective_sequence <= archive.sequence)
            })
        {
            return Err(RecoveryForkError::Inconsistent);
        }
        if current.generation > archive.lineage_generation {
            triggers.insert(RollbackTrigger::NewerSigningLineage);
        }
        selected_generation = current.generation;
        selected_signer = current.candidate.id;
        encoded_evidence.extend_from_slice(&archive.source_incarnation);
        encoded_evidence.extend_from_slice(&encoded);
    }
    let evidence_digest = evidence_digest(&encoded_evidence);
    let missing_anchored_range = latest_sequence
        .filter(|value| *value > archive.sequence)
        .map(|value| (archive.sequence.saturating_add(1), value));
    Ok(RollbackClassification {
        rollback_required: !triggers.is_empty(),
        triggers: triggers.into_iter().collect(),
        evidence_completeness: EvidenceCompleteness::OperatorSupplied,
        evidence_digest,
        latest_supplied_sequence: latest_sequence,
        selected_lineage_generation: selected_generation,
        selected_current_signer: selected_signer,
        missing_anchored_range,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryForkAuthority {
    pub restore_authorized: bool,
    pub source_decommissioned: bool,
    pub rpo_asserted: bool,
    pub target_and_recipient_revalidated: bool,
    pub current_signer_possession_proved: bool,
}

pub struct RecoveryForkActivationRequest<'a> {
    pub archive: ArchiveRecoveryTuple,
    pub classification: &'a RollbackClassification,
    pub start_recovery_epoch: bool,
    pub reason: &'a str,
    pub assertion_digest: [u8; 32],
    pub archive_digest: [u8; 32],
    pub container_digest: [u8; 32],
    pub signature_digest: [u8; 32],
    pub actor_id: [u8; 16],
    pub installed_state_digest: StateDigest,
    pub expected_credential_epoch: u64,
    pub expected_audit_epoch: u64,
    pub new_incarnation: [u8; 16],
    pub authority: RecoveryForkAuthority,
    pub confirmation: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryForkGenesis {
    pub operation_id: [u8; 16],
    pub source_incarnation: [u8; 16],
    pub installed_incarnation: [u8; 16],
    pub archived_sequence: u64,
    pub archived_head: [u8; 32],
    pub archived_state_digest: StateDigest,
    pub installed_state_digest: StateDigest,
    pub evidence_digest: [u8; 32],
    pub imported_lineage_digest: [u8; 32],
    pub imported_current_signer: [u8; 16],
    pub imported_lineage_generation: u64,
    pub missing_anchored_range: Option<(u64, u64)>,
    pub assertion_digest: [u8; 32],
    pub archive_digest: [u8; 32],
    pub container_digest: [u8; 32],
    pub signature_digest: [u8; 32],
    pub actor_id: [u8; 16],
    pub reason_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedRecoveryFork {
    pub credential_epoch: u64,
    pub audit_epoch: u64,
    pub genesis: RecoveryForkGenesis,
    pub pending_anchor: PendingAnchor,
}

pub fn activation_confirmation(
    archive: ArchiveRecoveryTuple,
    classification: &RollbackClassification,
    assertion_digest: [u8; 32],
    actor_id: [u8; 16],
    new_incarnation: [u8; 16],
    reason: &str,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&archive.store_id.0);
    bytes.extend_from_slice(&archive.source_incarnation);
    bytes.extend_from_slice(&archive.audit_epoch);
    bytes.extend_from_slice(&archive.sequence.to_be_bytes());
    bytes.extend_from_slice(&archive.chain_head);
    bytes.extend_from_slice(&classification.evidence_digest);
    bytes.extend_from_slice(&classification.selected_lineage_generation.to_be_bytes());
    bytes.extend_from_slice(&classification.selected_current_signer);
    bytes.extend_from_slice(&assertion_digest);
    bytes.extend_from_slice(&actor_id);
    bytes.extend_from_slice(&new_incarnation);
    bytes.extend_from_slice(reason.as_bytes());
    evidence_digest(&bytes)
}

pub fn activate_recovery_fork(
    request: RecoveryForkActivationRequest<'_>,
) -> Result<ActivatedRecoveryFork, RecoveryForkError> {
    validate_archive(request.archive)?;
    if !request.classification.rollback_required {
        return Err(RecoveryForkError::Invalid);
    }
    if !request.start_recovery_epoch {
        return Err(RecoveryForkError::RollbackRefused);
    }
    if request.reason.is_empty()
        || request.reason.len() > 1024
        || request.reason.chars().any(char::is_control)
        || request.assertion_digest == [0; 32]
        || request.archive_digest == [0; 32]
        || request.container_digest == [0; 32]
        || request.signature_digest == [0; 32]
        || request.actor_id == [0; 16]
        || request.new_incarnation == [0; 16]
        || request.installed_state_digest.0 == [0; 32]
    {
        return Err(RecoveryForkError::Invalid);
    }
    let authority = request.authority;
    if !authority.restore_authorized
        || !authority.source_decommissioned
        || !authority.rpo_asserted
        || !authority.target_and_recipient_revalidated
        || !authority.current_signer_possession_proved
        || request.confirmation
            != activation_confirmation(
                request.archive,
                request.classification,
                request.assertion_digest,
                request.actor_id,
                request.new_incarnation,
                request.reason,
            )
    {
        return Err(RecoveryForkError::Unauthorized);
    }
    let credential_epoch = request
        .expected_credential_epoch
        .checked_add(1)
        .ok_or(RecoveryForkError::Overflow)?;
    let audit_epoch = request
        .expected_audit_epoch
        .checked_add(1)
        .ok_or(RecoveryForkError::Overflow)?;
    let imported_lineage_digest = lineage_import_digest(request.classification);
    let genesis = RecoveryForkGenesis {
        operation_id: request.new_incarnation,
        source_incarnation: request.archive.source_incarnation,
        installed_incarnation: request.new_incarnation,
        archived_sequence: request.archive.sequence,
        archived_head: request.archive.chain_head,
        archived_state_digest: request.archive.state_digest,
        installed_state_digest: request.installed_state_digest,
        evidence_digest: request.classification.evidence_digest,
        imported_lineage_digest,
        imported_current_signer: request.classification.selected_current_signer,
        imported_lineage_generation: request.classification.selected_lineage_generation,
        missing_anchored_range: request.classification.missing_anchored_range,
        assertion_digest: request.assertion_digest,
        archive_digest: request.archive_digest,
        container_digest: request.container_digest,
        signature_digest: request.signature_digest,
        actor_id: request.actor_id,
        reason_digest: *blake3::hash(request.reason.as_bytes()).as_bytes(),
    };
    let activation_digest = genesis_digest(&genesis);
    let pending_anchor = PendingAnchor {
        kind: PendingAnchorKind::RollbackFork,
        operation_id: request.new_incarnation.to_vec(),
        plan_or_activation_digest: activation_digest,
        installed_state: AnchorInstalledState::Incarnation(request.new_incarnation),
        post_state_digest: request.installed_state_digest.0,
        status: PendingAnchorStatus::Installed,
    };
    Ok(ActivatedRecoveryFork {
        credential_epoch,
        audit_epoch,
        genesis,
        pending_anchor,
    })
}

fn validate_archive(value: ArchiveRecoveryTuple) -> Result<(), RecoveryForkError> {
    if value.store_id.0 == [0; 16]
        || value.source_incarnation == [0; 16]
        || value.audit_epoch == [0; 16]
        || value.sequence == 0
        || value.chain_head == [0; 32]
        || value.state_digest.0 == [0; 32]
        || value.lineage_generation == 0
        || value.current_signer == [0; 16]
        || value.trust_root == [0; 16]
    {
        return Err(RecoveryForkError::Invalid);
    }
    Ok(())
}

fn evidence_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.rollback-evidence.v1\0");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn lineage_import_digest(value: &RollbackClassification) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&value.evidence_digest);
    bytes.extend_from_slice(&value.selected_lineage_generation.to_be_bytes());
    bytes.extend_from_slice(&value.selected_current_signer);
    evidence_digest(&bytes)
}

fn genesis_digest(value: &RecoveryForkGenesis) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&value.operation_id);
    bytes.extend_from_slice(&value.source_incarnation);
    bytes.extend_from_slice(&value.installed_incarnation);
    bytes.extend_from_slice(&value.archived_sequence.to_be_bytes());
    bytes.extend_from_slice(&value.archived_head);
    bytes.extend_from_slice(&value.archived_state_digest.0);
    bytes.extend_from_slice(&value.installed_state_digest.0);
    bytes.extend_from_slice(&value.evidence_digest);
    bytes.extend_from_slice(&value.imported_lineage_digest);
    bytes.extend_from_slice(&value.assertion_digest);
    bytes.extend_from_slice(&value.archive_digest);
    bytes.extend_from_slice(&value.container_digest);
    bytes.extend_from_slice(&value.signature_digest);
    bytes.extend_from_slice(&value.actor_id);
    bytes.extend_from_slice(&value.reason_digest);
    evidence_digest(&bytes)
}
