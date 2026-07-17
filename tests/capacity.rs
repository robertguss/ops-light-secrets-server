use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;

use ops_light_secrets_server::capacity::{
    ANNUAL_IDLE_CLOCK_BYTES, CapacityBand, CapacityError, CapacityGuard, CapacityOperation,
    DATA_INFLIGHT_HEADROOM_BYTES, DATA_LANE_DEPTH, DATA_STOP_FLOOR_BYTES,
    MAX_IDLE_CLOCK_EVENT_BYTES, MAX_INCIDENT_INVESTIGATIONS, MAX_TRANSACTION_BYTES,
    RECOVERY_OPERATION_SLOTS, RECOVERY_RESERVE_BYTES, ReconcileAction, RecoveryReservePhase,
    RecoveryReserveRecord, ReserveMutationRequest, SHUTDOWN_RELEASE_FLOOR_BYTES,
    WARNING_FLOOR_BYTES, authorize_reserve_status, band, confirmation, inspect_reserve,
    provision_reserve, reconcile, release_reserve, reserve_recreate_transition,
    reserve_release_transition,
};
use ops_light_secrets_server::control::management::{ManagementCatalog, ManagementPrincipal};
use ops_light_secrets_server::credential::CredentialAudience;
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::store::Canonical;

const _: () = assert!(WARNING_FLOOR_BYTES > DATA_STOP_FLOOR_BYTES);
const _: () = assert!(DATA_STOP_FLOOR_BYTES > SHUTDOWN_RELEASE_FLOOR_BYTES);

#[test]
fn published_budget_is_conservative_closed_and_includes_idle_growth() {
    assert_eq!(
        DATA_INFLIGHT_HEADROOM_BYTES,
        DATA_LANE_DEPTH * MAX_TRANSACTION_BYTES
    );
    assert_eq!(MAX_INCIDENT_INVESTIGATIONS, 8);
    assert_eq!(RECOVERY_OPERATION_SLOTS, 64);
    assert_eq!(RECOVERY_RESERVE_BYTES, 576 * 1024 * 1024);
    assert_eq!(MAX_IDLE_CLOCK_EVENT_BYTES, 512);
    assert_eq!(ANNUAL_IDLE_CLOCK_BYTES, 538_214_400);
    assert_eq!(band(WARNING_FLOOR_BYTES + 1), CapacityBand::Healthy);
    assert_eq!(band(WARNING_FLOOR_BYTES), CapacityBand::Warning);
    assert_eq!(band(DATA_STOP_FLOOR_BYTES), CapacityBand::DataStopped);
    assert_eq!(
        band(SHUTDOWN_RELEASE_FLOOR_BYTES),
        CapacityBand::ShutdownOnly
    );
    assert_eq!(band(MAX_TRANSACTION_BYTES - 1), CapacityBand::Exhausted);
}

#[test]
fn data_headroom_and_control_floor_hold_at_exact_boundaries() {
    let guard = CapacityGuard::default();
    assert!(matches!(
        guard.admit(
            CapacityOperation::Data,
            DATA_STOP_FLOOR_BYTES,
            MAX_TRANSACTION_BYTES
        ),
        Err(CapacityError::DataStopped)
    ));
    let permits = (0..DATA_LANE_DEPTH)
        .map(|_| {
            guard
                .admit(
                    CapacityOperation::Data,
                    DATA_STOP_FLOOR_BYTES + 1,
                    MAX_TRANSACTION_BYTES,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        guard.snapshot(DATA_STOP_FLOOR_BYTES + 1).data_inflight,
        DATA_LANE_DEPTH
    );
    assert!(matches!(
        guard.admit(
            CapacityOperation::Data,
            DATA_STOP_FLOOR_BYTES + 1,
            MAX_TRANSACTION_BYTES
        ),
        Err(CapacityError::DataStopped)
    ));
    drop(permits);
    assert_eq!(guard.snapshot(DATA_STOP_FLOOR_BYTES).data_inflight, 0);

    assert!(
        guard
            .admit(
                CapacityOperation::Shutdown,
                MAX_TRANSACTION_BYTES,
                MAX_TRANSACTION_BYTES
            )
            .is_ok()
    );
    assert!(matches!(
        guard.admit(
            CapacityOperation::AuditExport,
            SHUTDOWN_RELEASE_FLOOR_BYTES,
            MAX_TRANSACTION_BYTES
        ),
        Err(CapacityError::ControlStopped)
    ));
    assert!(matches!(
        guard.admit(
            CapacityOperation::Data,
            WARNING_FLOOR_BYTES + 1,
            MAX_TRANSACTION_BYTES + 1
        ),
        Err(CapacityError::TransactionTooLarge)
    ));
}

#[test]
fn publication_budget_is_held_through_outcome_or_abandonment() {
    let guard = CapacityGuard::default();
    let available = SHUTDOWN_RELEASE_FLOOR_BYTES + 2 * MAX_TRANSACTION_BYTES;
    guard
        .hold_publication([1; 16], available, 2 * MAX_TRANSACTION_BYTES)
        .unwrap();
    let snapshot = guard.snapshot(available);
    assert_eq!(snapshot.held_publication_bytes, 2 * MAX_TRANSACTION_BYTES);
    assert_eq!(snapshot.band, CapacityBand::ShutdownOnly);
    assert!(matches!(
        guard.hold_publication([2; 16], available, MAX_TRANSACTION_BYTES),
        Err(CapacityError::ControlStopped)
    ));
    assert!(matches!(
        guard.hold_publication([1; 16], available * 2, MAX_TRANSACTION_BYTES),
        Err(CapacityError::PublicationExists)
    ));
    guard.finish_publication([1; 16]).unwrap();
    assert_eq!(guard.snapshot(available).held_publication_bytes, 0);
    assert!(matches!(
        guard.finish_publication([1; 16]),
        Err(CapacityError::PublicationUnknown)
    ));
}

#[test]
fn nth_incident_operation_succeeds_and_n_plus_one_refuses_before_write() {
    let guard = CapacityGuard::default();
    let mut available =
        SHUTDOWN_RELEASE_FLOOR_BYTES + MAX_INCIDENT_INVESTIGATIONS * MAX_TRANSACTION_BYTES;
    for _ in 0..MAX_INCIDENT_INVESTIGATIONS {
        guard
            .admit(
                CapacityOperation::AuditExport,
                available,
                MAX_TRANSACTION_BYTES,
            )
            .unwrap();
        available -= MAX_TRANSACTION_BYTES;
    }
    assert_eq!(available, SHUTDOWN_RELEASE_FLOOR_BYTES);
    assert!(matches!(
        guard.admit(
            CapacityOperation::AuditQuery,
            available,
            MAX_TRANSACTION_BYTES
        ),
        Err(CapacityError::ControlStopped)
    ));
    assert!(
        guard
            .admit(
                CapacityOperation::ReserveRelease,
                available,
                MAX_TRANSACTION_BYTES
            )
            .is_ok()
    );
}

#[test]
fn reserve_record_and_reconciliation_cover_every_crash_boundary() {
    let healthy = RecoveryReserveRecord::healthy(1024 * 1024).unwrap();
    let encoded = healthy.encode().unwrap();
    assert_eq!(RecoveryReserveRecord::decode(&encoded).unwrap(), healthy);
    assert_eq!(
        reconcile(&healthy, true, false).unwrap(),
        ReconcileAction::Ready
    );
    assert!(reconcile(&healthy, false, false).is_err());

    let release = healthy.request_release(1, [1; 16]).unwrap();
    assert_eq!(release.phase, RecoveryReservePhase::ReleaseRequested);
    assert_eq!(release.request_release(1, [1; 16]).unwrap(), release);
    assert_eq!(
        reconcile(&release, true, false).unwrap(),
        ReconcileAction::FinishRelease
    );
    assert_eq!(
        reconcile(&release, false, false).unwrap(),
        ReconcileAction::CommitReleased
    );
    let released = release.mark_released().unwrap();
    assert_eq!(released.phase, RecoveryReservePhase::Released);
    assert_eq!(
        reconcile(&released, false, false).unwrap(),
        ReconcileAction::Recreate
    );
    let recreate = released.request_recreate(3, [2; 16]).unwrap();
    assert_eq!(
        reconcile(&recreate, false, false).unwrap(),
        ReconcileAction::Recreate
    );
    assert_eq!(
        reconcile(&recreate, true, false).unwrap(),
        ReconcileAction::CommitHealthy
    );
    assert_eq!(
        recreate.mark_healthy().unwrap().phase,
        RecoveryReservePhase::Healthy
    );
    assert!(reconcile(&recreate, true, true).is_err());

    let reason = "recover capacity after audited cleanup";
    let digest = confirmation("release", 1, 1024 * 1024, reason).unwrap();
    assert_eq!(digest.len(), 64);
    assert_ne!(
        digest,
        confirmation("recreate", 1, 1024 * 1024, reason).unwrap()
    );
    assert!(confirmation("release", 1, 1024, "bad\nreason").is_err());
}

#[test]
fn reserve_file_has_real_blocks_safe_identity_and_release_protocol() {
    let directory = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let bytes = 1024 * 1024;
    let status = provision_reserve(directory.path(), bytes, uid).unwrap();
    assert_eq!(status.expected_bytes, bytes);
    assert!(status.allocated_bytes >= bytes);
    assert_eq!(status.mode, 0o600);
    assert_eq!(status.owner_uid, uid);
    let metadata = std::fs::metadata(directory.path().join("recovery.reserve")).unwrap();
    assert!(metadata.blocks() * 512 >= bytes);
    release_reserve(directory.path(), bytes, uid, [3; 16]).unwrap();
    assert!(!directory.path().join("recovery.reserve").exists());
}

#[test]
fn sparse_symlink_foreign_owner_and_mode_deception_fail_closed() {
    let uid = unsafe { libc::geteuid() };
    let sparse = tempfile::tempdir().unwrap();
    let path = sparse.path().join("recovery.reserve");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        inspect_reserve(sparse.path(), 64 * 1024 * 1024, uid),
        Err(CapacityError::Allocation)
    ));

    let linked = tempfile::tempdir().unwrap();
    symlink("target", linked.path().join("recovery.reserve")).unwrap();
    assert!(matches!(
        inspect_reserve(linked.path(), 1, uid),
        Err(CapacityError::UnsafeReserve)
    ));

    let wrong_mode = tempfile::tempdir().unwrap();
    let status = provision_reserve(wrong_mode.path(), 1024 * 1024, uid).unwrap();
    assert!(status.allocated_bytes >= 1024 * 1024);
    std::fs::set_permissions(
        wrong_mode.path().join("recovery.reserve"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(matches!(
        inspect_reserve(wrong_mode.path(), 1024 * 1024, uid),
        Err(CapacityError::UnsafeReserve)
    ));
}

fn management(capability: Capability) -> ManagementCatalog {
    ManagementCatalog::new(
        [IdentityRecord::new([1; 16], "operator".into(), IdentityKind::Human).unwrap()],
        [GrantRecord::new(
            [2; 16],
            [1; 16],
            "sys".into(),
            GrantScope::Exact,
            Vec::new(),
            BTreeSet::from([capability]),
        )
        .unwrap()],
    )
    .unwrap()
}

fn principal() -> ManagementPrincipal {
    ManagementPrincipal {
        identity_id: [1; 16],
        audience: CredentialAudience::Control,
        peer_uid: 1000,
        expected_uid: 1000,
        credential_active: true,
    }
}

#[test]
fn reserve_controls_require_store_maintenance_confirmation_and_stopped_data() {
    let healthy = RecoveryReserveRecord::healthy(1024 * 1024).unwrap();
    let mut wrong = management(Capability::Diagnostics);
    assert!(matches!(
        authorize_reserve_status(&mut wrong, principal(), [1; 16]),
        Err(CapacityError::Unauthorized)
    ));
    let mut authorized = management(Capability::StoreMaintenance);
    authorize_reserve_status(&mut authorized, principal(), [2; 16]).unwrap();

    let reason = "free reserve for audited incident cleanup";
    let request = ReserveMutationRequest {
        request_id: [3; 16],
        operation_id: [4; 16],
        expected_generation: 1,
        reason: reason.into(),
        confirmation: confirmation("release", 1, healthy.expected_bytes, reason).unwrap(),
        observed_available_bytes: DATA_STOP_FLOOR_BYTES,
    };
    let release =
        reserve_release_transition(&mut authorized, principal(), &healthy, &request).unwrap();
    assert_eq!(release.phase, RecoveryReservePhase::ReleaseRequested);

    let mut healthy_refusal = request.clone();
    healthy_refusal.request_id = [5; 16];
    healthy_refusal.operation_id = [6; 16];
    healthy_refusal.observed_available_bytes = WARNING_FLOOR_BYTES + 1;
    assert!(matches!(
        reserve_release_transition(&mut authorized, principal(), &healthy, &healthy_refusal),
        Err(CapacityError::Invalid)
    ));

    let released = release.mark_released().unwrap();
    let recreate_reason = "restore allocated reserve after cleanup";
    let recreate = ReserveMutationRequest {
        request_id: [7; 16],
        operation_id: [8; 16],
        expected_generation: released.generation,
        reason: recreate_reason.into(),
        confirmation: confirmation(
            "recreate",
            released.generation,
            released.expected_bytes,
            recreate_reason,
        )
        .unwrap(),
        observed_available_bytes: released.expected_bytes + DATA_STOP_FLOOR_BYTES,
    };
    assert_eq!(
        reserve_recreate_transition(&mut authorized, principal(), &released, &recreate,)
            .unwrap()
            .phase,
        RecoveryReservePhase::RecreateRequested
    );
}

#[test]
fn reserve_cli_surface_is_exact_and_never_accepts_secret_argv() {
    for (arguments, expected) in [
        (vec!["store", "reserve", "status", "--help"], "Usage:"),
        (
            vec!["store", "reserve", "release", "--help"],
            "--expected-generation",
        ),
        (vec!["store", "reserve", "recreate", "--help"], "--confirm"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(expected));
        assert!(!stdout.contains("--token"));
        assert!(!stdout.contains("--age-identity"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args(["store", "--help"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--control-credential-source")
    );
}
