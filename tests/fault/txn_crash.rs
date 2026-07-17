#[path = "../transaction_coordinator.rs"]
mod coordinator_faults;

use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

#[test]
fn crash_suite_registers_atomicity_read_safety_cancellation_and_linearization() {
    let source = include_str!("../transaction_coordinator.rs");
    let cases = [
        (
            "mutation-atomicity",
            "mutation_and_audit_are_one_visibility_boundary_at_every_fault",
        ),
        (
            "read-audit-failure",
            "read_secret_is_not_released_when_audit_or_commit_fails",
        ),
        (
            "post-start-disconnect",
            "caller_disconnect_after_prepare_commits_audit_and_zeroizes_unsent_reply",
        ),
        (
            "pre-start-cancel",
            "pre_start_cancellation_never_authorizes_decrypts_or_audits",
        ),
        (
            "panic-after-prepare",
            "panic_after_prepare_rolls_back_and_zeroizes_response",
        ),
        (
            "post-disable-denial",
            "disable_commit_linearizes_before_a_queued_authorization_start",
        ),
        (
            "pre-disable-completion",
            "already_authorized_read_may_finish_before_later_disable",
        ),
    ];
    let harness = Harness::builder("txn-crash")
        .register_canary(b"txn-crash-secret-canary-2c91d8")
        .build()
        .unwrap();
    for (index, (case, function)) in cases.into_iter().enumerate() {
        assert!(source.contains(&format!("fn {function}")));
        let mut scenario = harness.scenario_case("coordinator-fault", case, 1).unwrap();
        scenario
            .step(
                "evidence-registered",
                SafeSummary::new().field("point", SafeValue::Unsigned((index + 1) as u64)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        let report = scenario.finish_success().unwrap();
        assert!(report.scan_attestation.clean);
        assert!(!report.jsonl.contains("txn-crash-secret-canary-2c91d8"));
    }
}
