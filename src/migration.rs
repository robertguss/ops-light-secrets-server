//! Forward-only offline store migration contracts.
//!
//! Version zero is a synthetic release fixture used only to exercise the first
//! adjacent hop.  It has the same durable codecs as v1; consequently the v0 to
//! v1 transform is deliberately byte preserving.  A real release fixture must
//! replace the synthetic source for the next release.

use std::collections::{BTreeMap, BTreeSet};

use crate::backup_format::{
    ARCHIVE_REGISTRY, ArchiveFrame, MAX_ENTRY_KEY_BYTES, MAX_ENTRY_VALUE_BYTES, MAX_TABLE_ENTRIES,
};
use crate::store::FORMAT_VERSION;

const CONFIRMATION_DOMAIN: &[u8] = b"ops-light-secrets-server.store-migration-plan.v1\0";
const MIN_HEADROOM: u64 = 16 * 1024 * 1024;

/// Historical tables whose signed or hash-linked bytes may never be rewritten
/// by an ordinary migration.
pub const ANCHORED_HISTORY_TABLE_IDS: [u16; 8] = [5, 6, 11, 12, 13, 22, 23, 24];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationStep {
    pub id: &'static str,
    pub from: u32,
    pub to: u32,
    pub codec_version: u16,
    pub synthetic_source: bool,
}

pub const MIGRATION_STEPS: [MigrationStep; 1] = [MigrationStep {
    id: "synthetic-v0-to-v1",
    from: 0,
    to: 1,
    codec_version: 1,
    synthetic_source: true,
}];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanMode {
    Preliminary,
    OfflineFinal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredRecoveryEvidence {
    pub archive_digest: [u8; 32],
    pub signature_record_digest: [u8; 32],
    pub receipt_record_digest: [u8; 32],
    pub archive_generation: u64,
    pub signature_generation: u64,
    pub receipt_generation: u64,
    pub signature_registered: bool,
    pub receipt_registered: bool,
    pub tail_verified: bool,
    pub clean_shutdown: bool,
    pub allowlist_version: u16,
    pub tail_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationPlan {
    pub mode: PlanMode,
    pub from: u32,
    pub to: u32,
    pub step_ids: Vec<&'static str>,
    pub store_id: [u8; 16],
    pub incarnation: [u8; 16],
    pub generation: u64,
    pub source_head: [u8; 32],
    pub source_state: [u8; 32],
    pub plan_event_id: Option<[u8; 16]>,
    pub owner_id: [u8; 16],
    pub reason: String,
    pub record_counts: Vec<(u16, u64)>,
    pub required_bytes: u64,
    pub evidence: Option<RegisteredRecoveryEvidence>,
    pub confirmation: String,
}

pub struct PlanRequest<'a> {
    pub mode: PlanMode,
    pub from: u32,
    pub to: u32,
    pub store_id: [u8; 16],
    pub incarnation: [u8; 16],
    pub generation: u64,
    pub source_head: [u8; 32],
    pub source_state: [u8; 32],
    pub plan_event_id: Option<[u8; 16]>,
    pub owner_id: [u8; 16],
    pub reason: &'a str,
    pub record_counts: &'a [(u16, u64)],
    pub source_bytes: u64,
    pub free_bytes_after_reserve: u64,
    pub local_diagnostics_authorized: bool,
    pub local_maintenance_authorized: bool,
    pub daemon_absent_and_locked: bool,
    pub control_ttl_seconds: u64,
    pub worst_case_job_abort_seconds: u64,
    pub evidence: Option<RegisteredRecoveryEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationError {
    MigrationRequired { from: u32, to: u32 },
    UnsupportedStoreVersion,
    InvalidPlan,
    Authority,
    Evidence,
    Capacity,
    InvalidFrames,
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MigrationRequired { .. } => "store migration required",
            Self::UnsupportedStoreVersion => "unsupported store version",
            Self::InvalidPlan => "migration plan invalid or stale",
            Self::Authority => "store-maintenance authority refused",
            Self::Evidence => "registered recovery evidence refused",
            Self::Capacity => "migration sibling capacity unsafe",
            Self::InvalidFrames => "migration archive frames invalid",
        })
    }
}

impl std::error::Error for MigrationError {}

pub fn version_admission(observed: u32) -> Result<(), MigrationError> {
    if observed == FORMAT_VERSION {
        return Ok(());
    }
    if registered_path(observed, FORMAT_VERSION).is_ok() {
        return Err(MigrationError::MigrationRequired {
            from: observed,
            to: FORMAT_VERSION,
        });
    }
    Err(MigrationError::UnsupportedStoreVersion)
}

pub fn registered_path(from: u32, to: u32) -> Result<Vec<MigrationStep>, MigrationError> {
    if from >= to {
        return Err(MigrationError::UnsupportedStoreVersion);
    }
    let mut at = from;
    let mut path = Vec::new();
    while at < to {
        let step = MIGRATION_STEPS
            .iter()
            .copied()
            .find(|step| step.from == at && step.to == at.saturating_add(1))
            .ok_or(MigrationError::UnsupportedStoreVersion)?;
        path.push(step);
        at = step.to;
    }
    Ok(path)
}

pub fn plan(request: PlanRequest<'_>) -> Result<MigrationPlan, MigrationError> {
    let path = registered_path(request.from, request.to)?;
    let reason_valid = !request.reason.is_empty()
        && request.reason.len() <= 1024
        && !request.reason.chars().any(char::is_control);
    if request.store_id == [0; 16]
        || request.incarnation == [0; 16]
        || request.generation == 0
        || request.source_head == [0; 32]
        || request.source_state == [0; 32]
        || request.owner_id == [0; 16]
        || !reason_valid
        || !request.local_diagnostics_authorized
        || request.control_ttl_seconds <= request.worst_case_job_abort_seconds
    {
        return Err(MigrationError::InvalidPlan);
    }
    let mut seen = BTreeSet::new();
    if request.record_counts.iter().any(|(id, count)| {
        !seen.insert(*id)
            || !ARCHIVE_REGISTRY.iter().any(|codec| codec.id == *id)
            || *count as usize > MAX_TABLE_ENTRIES
    }) {
        return Err(MigrationError::InvalidPlan);
    }
    let required_bytes = request
        .source_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(MIN_HEADROOM))
        .ok_or(MigrationError::Capacity)?;
    if required_bytes > request.free_bytes_after_reserve {
        return Err(MigrationError::Capacity);
    }
    if request.mode == PlanMode::OfflineFinal {
        if !request.local_maintenance_authorized || !request.daemon_absent_and_locked {
            return Err(MigrationError::Authority);
        }
        let evidence = request.evidence.as_ref().ok_or(MigrationError::Evidence)?;
        if !valid_evidence(evidence) || request.plan_event_id.is_none() {
            return Err(MigrationError::Evidence);
        }
    } else if request.plan_event_id.is_some() || request.evidence.is_some() {
        return Err(MigrationError::InvalidPlan);
    }
    let mut result = MigrationPlan {
        mode: request.mode,
        from: request.from,
        to: request.to,
        step_ids: path.iter().map(|step| step.id).collect(),
        store_id: request.store_id,
        incarnation: request.incarnation,
        generation: request.generation,
        source_head: request.source_head,
        source_state: request.source_state,
        plan_event_id: request.plan_event_id,
        owner_id: request.owner_id,
        reason: request.reason.to_owned(),
        record_counts: request.record_counts.to_vec(),
        required_bytes,
        evidence: request.evidence,
        confirmation: String::new(),
    };
    result.confirmation = confirmation(&result);
    Ok(result)
}

pub fn validate_apply(
    plan: &MigrationPlan,
    confirmation_value: &str,
    final_barrier_authorized: bool,
    daemon_absent_and_locked: bool,
    actual_generation: u64,
    actual_head: [u8; 32],
    free_bytes_after_reserve: u64,
) -> Result<(), MigrationError> {
    if plan.mode != PlanMode::OfflineFinal
        || confirmation_value != plan.confirmation
        || confirmation(plan) != plan.confirmation
        || actual_generation != plan.generation
        || actual_head != plan.source_head
    {
        return Err(MigrationError::InvalidPlan);
    }
    if !final_barrier_authorized || !daemon_absent_and_locked {
        return Err(MigrationError::Authority);
    }
    if plan
        .evidence
        .as_ref()
        .is_none_or(|value| !valid_evidence(value))
    {
        return Err(MigrationError::Evidence);
    }
    if free_bytes_after_reserve < plan.required_bytes {
        return Err(MigrationError::Capacity);
    }
    Ok(())
}

/// Apply the registered adjacent transforms to one frozen logical snapshot.
/// The synthetic v0->v1 transform intentionally returns every frame byte-for-
/// byte; later steps may replace only explicitly registered non-anchored rows.
pub fn transform_frames(
    from: u32,
    to: u32,
    frames: &[ArchiveFrame],
) -> Result<Vec<ArchiveFrame>, MigrationError> {
    registered_path(from, to)?;
    validate_frames(frames)?;
    Ok(frames.to_vec())
}

pub fn validate_frames(frames: &[ArchiveFrame]) -> Result<(), MigrationError> {
    let registry: BTreeMap<_, _> = ARCHIVE_REGISTRY
        .iter()
        .map(|codec| (codec.id, codec))
        .collect();
    let mut seen = BTreeSet::new();
    for frame in frames {
        let codec = registry
            .get(&frame.table_id)
            .ok_or(MigrationError::InvalidFrames)?;
        if !seen.insert(frame.table_id)
            || frame.codec_version != codec.codec_version
            || frame.entries.len() > MAX_TABLE_ENTRIES
            || frame.entries.iter().any(|entry| {
                entry.key.len() > MAX_ENTRY_KEY_BYTES || entry.value.len() > MAX_ENTRY_VALUE_BYTES
            })
        {
            return Err(MigrationError::InvalidFrames);
        }
    }
    if ARCHIVE_REGISTRY
        .iter()
        .filter(|codec| codec.required)
        .any(|codec| !seen.contains(&codec.id))
    {
        return Err(MigrationError::InvalidFrames);
    }
    Ok(())
}

pub fn anchored_history_unchanged(
    before: &[ArchiveFrame],
    after: &[ArchiveFrame],
) -> Result<(), MigrationError> {
    for id in ANCHORED_HISTORY_TABLE_IDS {
        if before.iter().find(|frame| frame.table_id == id)
            != after.iter().find(|frame| frame.table_id == id)
        {
            return Err(MigrationError::InvalidFrames);
        }
    }
    Ok(())
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

fn confirmation(plan: &MigrationPlan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONFIRMATION_DOMAIN);
    hash_field(
        &mut hasher,
        &[match plan.mode {
            PlanMode::Preliminary => 0,
            PlanMode::OfflineFinal => 1,
        }],
    );
    for field in [
        &plan.from.to_be_bytes()[..],
        &plan.to.to_be_bytes(),
        &plan.store_id,
        &plan.incarnation,
        &plan.generation.to_be_bytes(),
        &plan.source_head,
        &plan.source_state,
        &plan.owner_id,
        plan.reason.as_bytes(),
        &plan.required_bytes.to_be_bytes(),
    ] {
        hash_field(&mut hasher, field);
    }
    for step in &plan.step_ids {
        hash_field(&mut hasher, step.as_bytes());
    }
    for (id, count) in &plan.record_counts {
        hash_field(&mut hasher, &id.to_be_bytes());
        hash_field(&mut hasher, &count.to_be_bytes());
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
