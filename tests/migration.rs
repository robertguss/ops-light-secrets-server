use ops_light_secrets_server::backup_format::{ARCHIVE_REGISTRY, ArchiveEntry, ArchiveFrame};
use ops_light_secrets_server::migration::{
    ANCHORED_HISTORY_TABLE_IDS, MIGRATION_STEPS, MigrationError, PlanMode, PlanRequest,
    RegisteredRecoveryEvidence, anchored_history_unchanged, plan, registered_path,
    transform_frames, validate_apply, version_admission,
};
use ops_light_secrets_server::store::FORMAT_VERSION;

fn evidence() -> RegisteredRecoveryEvidence {
    RegisteredRecoveryEvidence {
        archive_digest: [1; 32],
        signature_record_digest: [2; 32],
        receipt_record_digest: [3; 32],
        archive_generation: 7,
        signature_generation: 7,
        receipt_generation: 7,
        signature_registered: true,
        receipt_registered: true,
        tail_verified: true,
        clean_shutdown: true,
        allowlist_version: 1,
        tail_digest: [4; 32],
    }
}

fn counts() -> Vec<(u16, u64)> {
    ARCHIVE_REGISTRY.iter().map(|codec| (codec.id, 0)).collect()
}

fn request<'a>(mode: PlanMode, counts: &'a [(u16, u64)]) -> PlanRequest<'a> {
    PlanRequest {
        mode,
        from: 0,
        to: FORMAT_VERSION,
        store_id: [1; 16],
        incarnation: [2; 16],
        generation: 9,
        source_head: [3; 32],
        source_state: [4; 32],
        plan_event_id: (mode == PlanMode::OfflineFinal).then_some([5; 16]),
        owner_id: [6; 16],
        reason: "release fixture migration",
        record_counts: counts,
        source_bytes: 1024,
        free_bytes_after_reserve: 32 * 1024 * 1024,
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
fn v01_has_one_retained_adjacent_synthetic_step() {
    assert_eq!(FORMAT_VERSION, 1);
    assert_eq!(MIGRATION_STEPS.len(), 1);
    assert_eq!(registered_path(0, 1).unwrap(), MIGRATION_STEPS);
    assert!(MIGRATION_STEPS[0].synthetic_source);
    assert_eq!(
        version_admission(0),
        Err(MigrationError::MigrationRequired { from: 0, to: 1 })
    );
    assert_eq!(version_admission(1), Ok(()));
}

#[test]
fn no_op_downgrade_gap_and_newer_refuse_without_guessing() {
    for (from, to) in [(1, 1), (1, 0), (0, 2), (2, 3)] {
        assert_eq!(
            registered_path(from, to),
            Err(MigrationError::UnsupportedStoreVersion)
        );
    }
    assert_eq!(
        version_admission(2),
        Err(MigrationError::UnsupportedStoreVersion)
    );
}

#[test]
fn repeated_preliminary_plan_is_deterministic_and_not_applyable() {
    let counts = counts();
    let first = plan(request(PlanMode::Preliminary, &counts)).unwrap();
    let second = plan(request(PlanMode::Preliminary, &counts)).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        validate_apply(
            &first,
            &first.confirmation,
            true,
            true,
            first.generation,
            first.source_head,
            first.required_bytes,
        ),
        Err(MigrationError::InvalidPlan)
    );
}

#[test]
fn final_plan_binds_registered_evidence_confirmation_and_final_barrier() {
    let counts = counts();
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
            "wrong",
            true,
            true,
            final_plan.generation,
            final_plan.source_head,
            final_plan.required_bytes,
        ),
        Err(MigrationError::InvalidPlan)
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
        Err(MigrationError::Authority)
    );
}

#[test]
fn disposition_generation_and_tail_evidence_are_mandatory() {
    let counts = counts();
    let mut cases = Vec::new();
    let mut value = evidence();
    value.signature_registered = false;
    cases.push(value);
    let mut value = evidence();
    value.receipt_registered = false;
    cases.push(value);
    let mut value = evidence();
    value.receipt_generation += 1;
    cases.push(value);
    let mut value = evidence();
    value.tail_verified = false;
    cases.push(value);
    let mut value = evidence();
    value.clean_shutdown = false;
    cases.push(value);
    for bad in cases {
        let mut request = request(PlanMode::OfflineFinal, &counts);
        request.evidence = Some(bad);
        assert_eq!(plan(request), Err(MigrationError::Evidence));
    }
}

#[test]
fn ttl_capacity_counts_and_cas_are_fail_closed() {
    let counts = counts();
    let mut low_ttl = request(PlanMode::OfflineFinal, &counts);
    low_ttl.control_ttl_seconds = low_ttl.worst_case_job_abort_seconds;
    assert_eq!(plan(low_ttl), Err(MigrationError::InvalidPlan));

    let mut low_space = request(PlanMode::OfflineFinal, &counts);
    low_space.free_bytes_after_reserve = 1;
    assert_eq!(plan(low_space), Err(MigrationError::Capacity));

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
        Err(MigrationError::InvalidPlan)
    );
    assert_eq!(
        validate_apply(
            &final_plan,
            &final_plan.confirmation,
            true,
            true,
            final_plan.generation,
            final_plan.source_head,
            final_plan.required_bytes - 1,
        ),
        Err(MigrationError::Capacity)
    );
}

#[test]
fn registry_complete_transform_preserves_all_frames_and_anchored_history() {
    let before = frames();
    let after = transform_frames(0, 1, &before).unwrap();
    assert_eq!(after, before);
    anchored_history_unchanged(&before, &after).unwrap();
    assert!(
        ANCHORED_HISTORY_TABLE_IDS
            .iter()
            .all(|id| ARCHIVE_REGISTRY.iter().any(|codec| codec.id == *id))
    );
}

#[test]
fn unknown_duplicate_omitted_and_oversized_frames_refuse() {
    let original = frames();
    let mut unknown = original.clone();
    unknown.push(ArchiveFrame {
        table_id: u16::MAX,
        codec_version: 1,
        entries: vec![],
    });
    assert_eq!(
        transform_frames(0, 1, &unknown),
        Err(MigrationError::InvalidFrames)
    );

    let mut duplicate = original.clone();
    duplicate.push(original[0].clone());
    assert_eq!(
        transform_frames(0, 1, &duplicate),
        Err(MigrationError::InvalidFrames)
    );

    let omitted: Vec<_> = original
        .iter()
        .filter(|frame| frame.table_id != 1)
        .cloned()
        .collect();
    assert_eq!(
        transform_frames(0, 1, &omitted),
        Err(MigrationError::InvalidFrames)
    );

    let mut oversized = original;
    oversized[0].entries.push(ArchiveEntry {
        key: vec![0; 4097],
        value: vec![],
    });
    assert_eq!(
        transform_frames(0, 1, &oversized),
        Err(MigrationError::InvalidFrames)
    );
}

#[test]
fn anchored_history_byte_change_is_rejected() {
    let before = frames();
    let mut after = before.clone();
    let audit = after.iter_mut().find(|frame| frame.table_id == 5).unwrap();
    audit.entries.push(ArchiveEntry {
        key: vec![1],
        value: vec![2],
    });
    assert_eq!(
        anchored_history_unchanged(&before, &after),
        Err(MigrationError::InvalidFrames)
    );
}
