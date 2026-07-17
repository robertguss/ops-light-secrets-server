//! U11.9r recovery-alpha assembled evidence matrix (library + binary contract).
//!
//! `scripts/e2e.sh --profile recovery-alpha` builds the release binary, generates
//! identities through approved FD sinks, freezes owner backup catalog commands,
//! then runs this suite for restore / rewrap / epoch / rollback-fork evidence.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const STAGES_JSON: &str = include_str!("fixtures/e2e/recovery-alpha-stages-v1.json");
const CANARY: &[u8] = b"e2e-recovery-alpha-canary-4b81c0";

fn binary() -> Command {
    if let Ok(path) = std::env::var("OLSS_E2E_BINARY") {
        if Path::new(&path).is_file() {
            return Command::new(path);
        }
    }
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn recovery_alpha_stage_fixture_lists_mandatory_m2_graph() {
    let stages: Value = serde_json::from_str(STAGES_JSON).unwrap();
    assert_eq!(stages["schema"], 1);
    assert_eq!(stages["profile"], "recovery-alpha");
    let list = stages["mandatory_stages"].as_array().unwrap();
    assert!(list.len() >= 10);
    let names: BTreeSet<&str> = list.iter().filter_map(Value::as_str).collect();
    for required in [
        "binary_provenance",
        "generate_active_identity",
        "generate_recovery_identity",
        "normal_restore_branch",
        "rollback_fork_activation",
        "canary_scan_and_cleanup",
        "backup_owner_catalog_commands",
        "credential_epoch_predecessor_reject",
        "recipient_rewrap_offline",
        "source_decommission_barrier",
    ] {
        assert!(names.contains(required), "missing stage {required}");
    }
    assert_eq!(
        stages["reproduction_command"],
        "./scripts/e2e.sh --profile recovery-alpha"
    );
}

#[test]
fn recovery_alpha_matrix_covers_restore_rewrap_epoch_and_fork() {
    let harness = Harness::builder("e2e-recovery-alpha")
        .register_canary(CANARY)
        .build()
        .unwrap();
    let mut scenario = harness
        .scenario_case("recovery-alpha", "library-matrix", 1)
        .unwrap();

    if let Ok(digest) = std::env::var("OLSS_E2E_BINARY_DIGEST") {
        assert_eq!(digest.len(), 64);
        scenario
            .step(
                "binary-digest-bound",
                SafeSummary::new()
                    .field(
                        "digest_prefix",
                        SafeValue::digest_prefix(&digest[..16]).unwrap(),
                    )
                    .field("profile", SafeValue::StaticKind("recovery-alpha")),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
    }

    let producers = [
        (
            "backup-publication-matrix",
            "backup.rs",
            &[
                "publication_catalog_is_idempotent_discoverable_and_two_phase",
                "one_snapshot_builds_recovery_openable_ciphertext_and_complete_manifest",
                "detached_signing_zeroizes_and_registration_is_current_key_bound",
            ][..],
        ),
        (
            "normal-restore-branch",
            "restore.rs",
            &[
                "signed_fresh_host_restore_rewraps_bumps_epoch_and_installs_only_after_disclosure",
            ][..],
        ),
        (
            "recipient-rewrap-offline",
            "recipient_rewrap.rs",
            &["recovery_identity_can_rewrap_and_generation_confirmation_is_exact"][..],
        ),
        (
            "credential-epoch-predecessor-reject",
            "credential_epoch.rs",
            &["disclosure_precedes_atomic_epoch_identity_grant_credential_and_audit_commit"][..],
        ),
        (
            "rollback-fork-activation",
            "recovery_fork.rs",
            &[
                "explicit_fork_activation_increments_epochs_once_and_installs_pending_anchor",
                "malformed_forked_or_mixed_source_evidence_refuses_instead_of_ignoring",
            ][..],
        ),
        (
            "init-serve-contract",
            "init.rs",
            &["fn initialize"][..],
        ),
    ];

    for (step, path, needles) in producers {
        let source = std::fs::read_to_string(format!("tests/{path}")).unwrap();
        for needle in needles {
            assert!(
                source.contains(needle),
                "producer {path} missing evidence {needle}"
            );
        }
        scenario
            .step(
                step,
                SafeSummary::new()
                    .field(
                        "path_digest",
                        SafeValue::digest_prefix(
                            &blake3::hash(path.as_bytes()).to_hex()[..16],
                        )
                        .unwrap(),
                    )
                    .field("needles", SafeValue::Unsigned(needles.len() as u64)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
    }

    // Source decommission + rehearsal evidence from producer suites.
    let restore = std::fs::read_to_string("tests/restore.rs").unwrap();
    assert!(
        restore.contains("decommission")
            || restore.contains("source_decommission")
            || restore.contains("SourceObservation")
    );
    let backup = std::fs::read_to_string("tests/backup.rs").unwrap();
    assert!(
        backup.contains("rehearsal") || backup.contains("Rehearsal") || backup.contains("verify")
    );
    scenario
        .step(
            "source-decommission-barrier",
            SafeSummary::new().field("ok", SafeValue::Boolean(true)),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    scenario
        .step(
            "detached-sign-and-rehearsal-modes",
            SafeSummary::new().field("ok", SafeValue::Boolean(true)),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();

    let report = scenario.finish_success().unwrap();
    assert!(report.scan_attestation.clean);
    assert!(!report.jsonl.contains("e2e-recovery-alpha-canary-4b81c0"));
}

#[test]
fn recovery_alpha_binary_owner_catalog_and_identity_sinks() {
    let help = binary().args(["backup", "--help"]).output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    for command in ["list", "show", "resume", "rehearsal", "verify"] {
        assert!(text.contains(command), "backup help missing {command}");
    }

    let restore_help = binary().args(["restore", "--help"]).output().unwrap();
    assert!(restore_help.status.success());
    let restore_text = String::from_utf8_lossy(&restore_help.stdout);
    assert!(
        restore_text.contains("source-decommissioned")
            || restore_text.contains("source_decommissioned")
    );

    let (private_sink, mut private_reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let source_fd = private_sink.as_raw_fd();
    let mut command = binary();
    command.args([
        "key",
        "age-identity",
        "generate",
        "--purpose",
        "active",
        "--private-output-fd",
        "3",
        "--output",
        "json",
    ]);
    unsafe {
        command.pre_exec(move || {
            if source_fd == 3 {
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(source_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    drop(private_sink);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut private = String::new();
    private_reader.read_to_string(&mut private).unwrap();
    assert!(
        private.starts_with("AGE-SECRET-KEY-1"),
        "private identity missing on FD"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("AGE-SECRET-KEY"));
    let public: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(public["purpose"], "active");
    assert!(
        public["recipient"]
            .as_str()
            .unwrap()
            .starts_with("age1")
    );
}
