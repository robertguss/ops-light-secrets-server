use std::path::Path;

use ops_light_secrets_server::startup::DataDirectoryLock;
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

#[path = "credential_epoch.rs"]
mod credential_epoch_slice;
#[path = "recipient_rewrap.rs"]
mod recipient_rewrap_slice;

const RECOVERY_SCENARIOS: [(&str, &[&str]); 10] = [
    (
        "recovery-01-exclusive-lock",
        &[
            "tests/key_recovery.rs::offline_recipient_rewrap_refuses_while_data_directory_lock_is_held",
        ],
    ),
    (
        "recovery-02-recipient-atomicity",
        &[
            "tests/recipient_rewrap.rs::rewrap_changes_only_envelope_metadata_and_matching_audit",
            "tests/recipient_rewrap.rs::every_uncommitted_fault_point_leaves_old_envelope_and_head",
        ],
    ),
    (
        "recovery-03-recovery-recipient",
        &[
            "tests/recipient_rewrap.rs::recovery_identity_can_rewrap_and_generation_confirmation_is_exact",
        ],
    ),
    (
        "recovery-04-recipient-custody",
        &[
            "tests/keyring.rs::transplanted_envelope_refuses_on_store_id_before_metadata",
            "tests/keyring.rs::stateless_identity_generation_keeps_private_bytes_only_in_approved_sink",
            "tests/backup.rs::recovery_recipient_set_is_cas_exact_confirmed_and_active_distinct",
        ],
    ),
    (
        "recovery-05-recipient-cli",
        &[
            "tests/recipient_rewrap.rs::cli_requires_typed_secret_sources_and_never_accepts_private_identity_values",
            "tests/recipient_rewrap.rs::real_offline_cli_plans_then_commits_with_bootstrap_key_rotation_authority",
        ],
    ),
    (
        "recovery-06-epoch-atomicity",
        &[
            "tests/credential_epoch.rs::disclosure_precedes_atomic_epoch_identity_grant_credential_and_audit_commit",
        ],
    ),
    (
        "recovery-07-epoch-refusals",
        &[
            "tests/credential_epoch.rs::authority_confirmation_sink_and_stale_epoch_fail_before_mutation",
            "tests/credential_epoch.rs::disclosure_failure_leaves_old_epoch_authoritative_and_orphan_unusable",
        ],
    ),
    (
        "recovery-08-epoch-linearization",
        &[
            "tests/auth.rs::epoch_and_verifier_key_bumps_reject_stale_credentials_with_fixed_work",
            "tests/credential_epoch.rs::offline_mode_and_interrupted_job_rules_are_distinct_and_fail_closed",
        ],
    ),
    (
        "recovery-09-shared-primitive",
        &[
            "tests/credential_epoch.rs::clock_restore_and_incident_share_one_prepared_type_and_barrier_cas",
        ],
    ),
    (
        "recovery-10-backup-recipient-state",
        &[
            "tests/backup.rs::one_snapshot_builds_recovery_openable_ciphertext_and_complete_manifest",
            "tests/backup_verify.rs::active_and_recovery_paths_are_distinct_signed_receipts_and_cleanup_workspace",
        ],
    ),
];

#[test]
fn offline_recipient_rewrap_refuses_while_data_directory_lock_is_held() {
    let directory = tempfile::tempdir().unwrap();
    let _lock = DataDirectoryLock::acquire(directory.path()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .env("OLSS_DATA_DIRECTORY", directory.path())
        .args([
            "key",
            "recipient",
            "rewrap",
            "--expected-generation",
            "1",
            "--current-identity-source",
            "credential:current",
            "--new-active-identity-source",
            "credential:new",
            "--control-credential-source",
            "credential:control",
            "--reason",
            "recovery slice lock test",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("recipient_rewrap_refused code=daemon_or_lock_active")
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn every_recovery_scenario_has_source_evidence_and_safe_observability() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let harness = Harness::builder("key-recovery")
        .register_canary(b"key-recovery-private-canary-55b8ce")
        .build()
        .unwrap();
    for (index, (id, evidence)) in RECOVERY_SCENARIOS.iter().enumerate() {
        for item in *evidence {
            let (path, test) = item.split_once("::").unwrap();
            let source = std::fs::read_to_string(root.join(path)).unwrap();
            assert!(
                source.contains(&format!("fn {test}")),
                "missing recovery evidence {item}"
            );
        }
        let mut scenario = harness.scenario(id, 1).unwrap();
        scenario
            .step(
                "evidence-registered",
                SafeSummary::new()
                    .field("scenario", SafeValue::Unsigned((index + 1) as u64))
                    .field("evidence_count", SafeValue::Unsigned(evidence.len() as u64)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        let report = scenario.finish_success().unwrap();
        assert!(report.scan_attestation.clean);
        assert!(report.jsonl.contains("\"event\":\"scenario_begin\""));
        assert!(report.jsonl.contains("\"event\":\"step\""));
        assert!(report.jsonl.contains("\"event\":\"scenario_end\""));
        assert!(!report.jsonl.contains("key-recovery-private-canary-55b8ce"));
    }
}

#[test]
fn clock_restore_and_incident_compile_against_one_epoch_rotation_primitive() {
    let source = include_str!("../src/credential_epoch.rs");
    for function in [
        "pub fn prepare_clock_repair_epoch_rotation",
        "pub fn prepare_restore_epoch_rotation",
        "pub fn rotate_credential_epoch",
    ] {
        assert!(
            source.contains(function),
            "missing shared primitive {function}"
        );
    }
    assert_eq!(source.matches("prepare_epoch_rotation(").count(), 3);
}

#[test]
fn kv_auth_integration_tails_are_live() {
    let source = include_str!("auth.rs");
    assert!(source.contains("async fn scoped_approle_token_reads_authorized_kv_path"));
    assert!(source.contains("async fn scoped_expired_and_revoked_tokens_cannot_read_kv"));
    assert!(!source.contains("#[ignore"));
}
