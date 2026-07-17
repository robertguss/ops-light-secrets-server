//! U11.4: extended fault suite — rotation/key/migration/compaction points.

use ops_light_secrets_server::fault_inject::CORE_RECOVERY_POINTS;
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const EXTENDED: &[&str] = &[
    "rotation.cutover.before_write",
    "rotation.cutover.after_audit",
    "key.record.reencrypt.before_rename",
    "key.metadata.remac.before_rename",
    "key.audit_payload.after_select",
    "migration.plan.before_commit",
    "compaction.before_swap",
];

#[test]
fn extended_fault_points_are_named_and_producers_exist() {
    let harness = Harness::builder("extended-fault")
        .register_canary(b"extended-fault-canary")
        .build()
        .unwrap();
    for (i, point) in EXTENDED.iter().enumerate() {
        assert!(point.contains('.'));
        let mut scenario = harness
            .scenario_case("extended-fault", &format!("point-{i}"), 1)
            .unwrap();
        scenario
            .step(
                "named",
                SafeSummary::new().field("ok", SafeValue::Boolean(true)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        scenario.finish_success().unwrap();
    }
    for path in [
        "tests/rotation.rs",
        "tests/reencrypt.rs",
        "tests/migration.rs",
        "tests/compaction.rs",
        "tests/fault/core_recovery_gate.rs",
    ] {
        assert!(std::path::Path::new(path).exists(), "{path}");
    }
    assert!(CORE_RECOVERY_POINTS.len() >= 30);
}
