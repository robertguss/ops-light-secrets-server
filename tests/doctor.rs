use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use ops_light_secrets_server::doctor::{CheckSeverity, run_offline};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

#[test]
fn doctor_exit_codes_and_offline_report_are_stable() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let report = run_offline(directory.path());
    assert_eq!(report.schema, 1);
    assert_eq!(report.mode, "offline");
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "data_dir_permissions" && check.severity == CheckSeverity::Ok)
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.severity == CheckSeverity::Skip
                && check.reason == Some("mode_unavailable"))
    );
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("AGE-SECRET-KEY"));
    assert!(matches!(report.exit_code, 0 | 1));
}

#[test]
fn doctor_cli_emits_json_and_stable_exit() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args([
            "doctor",
            "--data-directory",
            directory.path().to_str().unwrap(),
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    // Exit 0 or 1 for healthy/warn offline preflight.
    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"schema\": 1") || stdout.contains("\"schema\":1"));
    assert!(stdout.contains("data_dir_permissions"));
    assert!(!stdout.contains("AGE-SECRET-KEY"));

    let harness = Harness::builder("doctor-cli")
        .register_canary(b"doctor-canary-never-present")
        .build()
        .unwrap();
    let mut scenario = harness.scenario_case("doctor", "cli-json", 1).unwrap();
    scenario
        .step(
            "json-ok",
            SafeSummary::new().field(
                "exit",
                SafeValue::Unsigned(output.status.code().unwrap_or(99) as u64),
            ),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    assert!(scenario.finish_success().unwrap().scan_attestation.clean);
}
