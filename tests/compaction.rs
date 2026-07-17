use ops_light_secrets_server::backup_format::{ARCHIVE_REGISTRY, ArchiveFrame};
use ops_light_secrets_server::compaction::{
    CompactionError, LOW_BENEFIT_PERCENT, PlanMode, PlanRequest, compact_frames, plan,
    validate_apply,
};
use ops_light_secrets_server::migration::RegisteredRecoveryEvidence;

fn evidence() -> RegisteredRecoveryEvidence {
    RegisteredRecoveryEvidence {
        archive_digest: [1; 32],
        signature_record_digest: [2; 32],
        receipt_record_digest: [3; 32],
        archive_generation: 4,
        signature_generation: 4,
        receipt_generation: 4,
        signature_registered: true,
        receipt_registered: true,
        tail_verified: true,
        clean_shutdown: true,
        allowlist_version: 1,
        tail_digest: [5; 32],
    }
}

fn counts() -> Vec<(u16, u64)> {
    ARCHIVE_REGISTRY.iter().map(|codec| (codec.id, 0)).collect()
}

fn request<'a>(mode: PlanMode, counts: &'a [(u16, u64)]) -> PlanRequest<'a> {
    PlanRequest {
        mode,
        store_id: [1; 16],
        incarnation: [2; 16],
        generation: 3,
        source_head: [4; 32],
        source_state: [5; 32],
        plan_event_id: (mode == PlanMode::OfflineFinal).then_some([6; 16]),
        owner_id: [7; 16],
        reason: "reclaim obsolete redb pages",
        file_bytes: 100 * 1024 * 1024,
        live_bytes: 50 * 1024 * 1024,
        record_counts: counts,
        free_bytes_after_reserve: 128 * 1024 * 1024,
        local_diagnostics_authorized: true,
        local_maintenance_authorized: mode == PlanMode::OfflineFinal,
        daemon_absent_and_locked: mode == PlanMode::OfflineFinal,
        control_ttl_seconds: 3600,
        worst_case_job_abort_seconds: 600,
        evidence: (mode == PlanMode::OfflineFinal).then(evidence),
    }
}

fn frames() -> Vec<ArchiveFrame> {
    ARCHIVE_REGISTRY
        .iter()
        .map(|codec| ArchiveFrame {
            table_id: codec.id,
            codec_version: codec.codec_version,
            entries: vec![],
        })
        .collect()
}

#[test]
fn plans_exact_physical_benefit_and_is_deterministic() {
    let counts = counts();
    let first = plan(request(PlanMode::Preliminary, &counts)).unwrap();
    let second = plan(request(PlanMode::Preliminary, &counts)).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.reclaimable_bytes, 50 * 1024 * 1024);
    assert!(!first.low_benefit_warning);
}

#[test]
fn dense_store_warns_without_claiming_reclamation() {
    let counts = counts();
    let mut request = request(PlanMode::Preliminary, &counts);
    request.live_bytes = request.file_bytes * (100 - LOW_BENEFIT_PERCENT + 1) / 100;
    let result = plan(request).unwrap();
    assert!(result.low_benefit_warning);
}

#[test]
fn preliminary_token_and_stale_final_barriers_refuse() {
    let counts = counts();
    let preliminary = plan(request(PlanMode::Preliminary, &counts)).unwrap();
    assert_eq!(
        validate_apply(
            &preliminary,
            &preliminary.confirmation,
            true,
            true,
            preliminary.generation,
            preliminary.source_head,
            preliminary.required_bytes,
        ),
        Err(CompactionError::InvalidPlan)
    );
    let final_plan = plan(request(PlanMode::OfflineFinal, &counts)).unwrap();
    assert_eq!(
        validate_apply(
            &final_plan,
            &final_plan.confirmation,
            true,
            true,
            final_plan.generation + 1,
            final_plan.source_head,
            final_plan.required_bytes,
        ),
        Err(CompactionError::InvalidPlan)
    );
}

#[test]
fn final_plan_requires_registered_recovery_evidence_and_authority() {
    let counts = counts();
    let mut missing = request(PlanMode::OfflineFinal, &counts);
    missing.evidence = None;
    assert_eq!(plan(missing), Err(CompactionError::Evidence));

    let final_plan = plan(request(PlanMode::OfflineFinal, &counts)).unwrap();
    assert!(
        validate_apply(
            &final_plan,
            &final_plan.confirmation,
            true,
            true,
            final_plan.generation,
            final_plan.source_head,
            final_plan.required_bytes,
        )
        .is_ok()
    );
    assert_eq!(
        validate_apply(
            &final_plan,
            &final_plan.confirmation,
            false,
            true,
            final_plan.generation,
            final_plan.source_head,
            final_plan.required_bytes,
        ),
        Err(CompactionError::Authority)
    );
}

#[test]
fn exact_capacity_boundary_passes_and_n_minus_one_refuses() {
    let counts = counts();
    let mut exact = request(PlanMode::OfflineFinal, &counts);
    exact.free_bytes_after_reserve = exact.live_bytes + 16 * 1024 * 1024;
    let exact = plan(exact).unwrap();
    assert!(
        validate_apply(
            &exact,
            &exact.confirmation,
            true,
            true,
            exact.generation,
            exact.source_head,
            exact.required_bytes,
        )
        .is_ok()
    );
    assert_eq!(
        validate_apply(
            &exact,
            &exact.confirmation,
            true,
            true,
            exact.generation,
            exact.source_head,
            exact.required_bytes - 1,
        ),
        Err(CompactionError::Capacity)
    );
}

#[test]
fn physical_rewrite_preserves_every_logical_and_anchored_byte() {
    let before = frames();
    let after = compact_frames(&before).unwrap();
    assert_eq!(after, before);
}

#[test]
fn malformed_registry_snapshot_refuses() {
    let mut malformed = frames();
    malformed.push(malformed[0].clone());
    assert_eq!(
        compact_frames(&malformed),
        Err(CompactionError::InvalidFrames)
    );
}

#[test]
fn impossible_size_ttl_and_reserve_conditions_refuse() {
    let counts = counts();
    let mut impossible = request(PlanMode::OfflineFinal, &counts);
    impossible.live_bytes = impossible.file_bytes + 1;
    assert_eq!(plan(impossible), Err(CompactionError::InvalidPlan));

    let mut expired = request(PlanMode::OfflineFinal, &counts);
    expired.control_ttl_seconds = expired.worst_case_job_abort_seconds;
    assert_eq!(plan(expired), Err(CompactionError::InvalidPlan));

    let mut full = request(PlanMode::OfflineFinal, &counts);
    full.free_bytes_after_reserve = 1;
    assert_eq!(plan(full), Err(CompactionError::Capacity));
}
