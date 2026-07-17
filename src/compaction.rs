//! Authenticated offline physical compaction contracts.

use crate::backup_format::ArchiveFrame;
use crate::migration::{
    MigrationError, RegisteredRecoveryEvidence, anchored_history_unchanged, validate_frames,
};

const CONFIRMATION_DOMAIN: &[u8] = b"ops-light-secrets-server.store-compaction-plan.v1\0";
const MIN_HEADROOM: u64 = 16 * 1024 * 1024;
pub const LOW_BENEFIT_PERCENT: u64 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanMode {
    Preliminary,
    OfflineFinal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionPlan {
    pub mode: PlanMode,
    pub store_id: [u8; 16],
    pub incarnation: [u8; 16],
    pub generation: u64,
    pub source_head: [u8; 32],
    pub source_state: [u8; 32],
    pub plan_event_id: Option<[u8; 16]>,
    pub owner_id: [u8; 16],
    pub reason: String,
    pub file_bytes: u64,
    pub live_bytes: u64,
    pub reclaimable_bytes: u64,
    pub required_bytes: u64,
    pub low_benefit_warning: bool,
    pub record_counts: Vec<(u16, u64)>,
    pub evidence: Option<RegisteredRecoveryEvidence>,
    pub confirmation: String,
}

pub struct PlanRequest<'a> {
    pub mode: PlanMode,
    pub store_id: [u8; 16],
    pub incarnation: [u8; 16],
    pub generation: u64,
    pub source_head: [u8; 32],
    pub source_state: [u8; 32],
    pub plan_event_id: Option<[u8; 16]>,
    pub owner_id: [u8; 16],
    pub reason: &'a str,
    pub file_bytes: u64,
    pub live_bytes: u64,
    pub record_counts: &'a [(u16, u64)],
    pub free_bytes_after_reserve: u64,
    pub local_diagnostics_authorized: bool,
    pub local_maintenance_authorized: bool,
    pub daemon_absent_and_locked: bool,
    pub control_ttl_seconds: u64,
    pub worst_case_job_abort_seconds: u64,
    pub evidence: Option<RegisteredRecoveryEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionError {
    InvalidPlan,
    Authority,
    Evidence,
    Capacity,
    InvalidFrames,
}

pub fn plan(request: PlanRequest<'_>) -> Result<CompactionPlan, CompactionError> {
    if request.store_id == [0; 16]
        || request.incarnation == [0; 16]
        || request.generation == 0
        || request.source_head == [0; 32]
        || request.source_state == [0; 32]
        || request.owner_id == [0; 16]
        || request.reason.is_empty()
        || request.reason.len() > 1024
        || request.reason.chars().any(char::is_control)
        || request.file_bytes == 0
        || request.live_bytes == 0
        || request.live_bytes > request.file_bytes
        || !request.local_diagnostics_authorized
        || request.control_ttl_seconds <= request.worst_case_job_abort_seconds
    {
        return Err(CompactionError::InvalidPlan);
    }
    let reclaimable_bytes = request.file_bytes - request.live_bytes;
    let required_bytes = request
        .live_bytes
        .checked_add(MIN_HEADROOM)
        .ok_or(CompactionError::Capacity)?;
    if request.free_bytes_after_reserve < required_bytes {
        return Err(CompactionError::Capacity);
    }
    if request.mode == PlanMode::OfflineFinal {
        if !request.local_maintenance_authorized || !request.daemon_absent_and_locked {
            return Err(CompactionError::Authority);
        }
        if request
            .evidence
            .as_ref()
            .is_none_or(|evidence| !valid_evidence(evidence))
            || request.plan_event_id.is_none()
        {
            return Err(CompactionError::Evidence);
        }
    } else if request.evidence.is_some() || request.plan_event_id.is_some() {
        return Err(CompactionError::InvalidPlan);
    }
    let mut result = CompactionPlan {
        mode: request.mode,
        store_id: request.store_id,
        incarnation: request.incarnation,
        generation: request.generation,
        source_head: request.source_head,
        source_state: request.source_state,
        plan_event_id: request.plan_event_id,
        owner_id: request.owner_id,
        reason: request.reason.to_owned(),
        file_bytes: request.file_bytes,
        live_bytes: request.live_bytes,
        reclaimable_bytes,
        required_bytes,
        low_benefit_warning: reclaimable_bytes.saturating_mul(100)
            < request.file_bytes.saturating_mul(LOW_BENEFIT_PERCENT),
        record_counts: request.record_counts.to_vec(),
        evidence: request.evidence,
        confirmation: String::new(),
    };
    result.confirmation = confirmation(&result);
    Ok(result)
}

pub fn validate_apply(
    plan: &CompactionPlan,
    supplied_confirmation: &str,
    final_barrier_authorized: bool,
    daemon_absent_and_locked: bool,
    actual_generation: u64,
    actual_head: [u8; 32],
    free_bytes_after_reserve: u64,
) -> Result<(), CompactionError> {
    if plan.mode != PlanMode::OfflineFinal
        || supplied_confirmation != plan.confirmation
        || confirmation(plan) != plan.confirmation
        || actual_generation != plan.generation
        || actual_head != plan.source_head
    {
        return Err(CompactionError::InvalidPlan);
    }
    if !final_barrier_authorized || !daemon_absent_and_locked {
        return Err(CompactionError::Authority);
    }
    if plan.evidence.as_ref().is_none_or(|e| !valid_evidence(e)) {
        return Err(CompactionError::Evidence);
    }
    if free_bytes_after_reserve < plan.required_bytes {
        return Err(CompactionError::Capacity);
    }
    Ok(())
}

/// A physical rewrite copies the complete logical snapshot. It removes only
/// storage-engine obsolete/free pages; logical tombstones and history remain.
pub fn compact_frames(frames: &[ArchiveFrame]) -> Result<Vec<ArchiveFrame>, CompactionError> {
    validate_frames(frames).map_err(map_frame_error)?;
    let after = frames.to_vec();
    anchored_history_unchanged(frames, &after).map_err(map_frame_error)?;
    Ok(after)
}

fn map_frame_error(_: MigrationError) -> CompactionError {
    CompactionError::InvalidFrames
}

fn valid_evidence(value: &RegisteredRecoveryEvidence) -> bool {
    value.archive_digest != [0; 32]
        && value.signature_record_digest != [0; 32]
        && value.receipt_record_digest != [0; 32]
        && value.tail_digest != [0; 32]
        && value.archive_generation != 0
        && value.archive_generation == value.signature_generation
        && value.signature_generation == value.receipt_generation
        && value.signature_registered
        && value.receipt_registered
        && value.tail_verified
        && value.clean_shutdown
        && value.allowlist_version != 0
}

fn confirmation(plan: &CompactionPlan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONFIRMATION_DOMAIN);
    let mode = [u8::from(plan.mode == PlanMode::OfflineFinal)];
    for field in [
        &mode[..],
        &plan.store_id,
        &plan.incarnation,
        &plan.generation.to_be_bytes(),
        &plan.source_head,
        &plan.source_state,
        &plan.owner_id,
        plan.reason.as_bytes(),
        &plan.file_bytes.to_be_bytes(),
        &plan.live_bytes.to_be_bytes(),
        &plan.required_bytes.to_be_bytes(),
    ] {
        hash_field(&mut hasher, field);
    }
    if let Some(id) = plan.plan_event_id {
        hash_field(&mut hasher, &id);
    }
    if let Some(evidence) = &plan.evidence {
        for field in [
            &evidence.archive_digest[..],
            &evidence.signature_record_digest,
            &evidence.receipt_record_digest,
            &evidence.archive_generation.to_be_bytes(),
            &evidence.signature_generation.to_be_bytes(),
            &evidence.receipt_generation.to_be_bytes(),
            &evidence.allowlist_version.to_be_bytes(),
            &evidence.tail_digest,
        ] {
            hash_field(&mut hasher, field);
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}
