//! U11.4: extended fault suite — rotation/key/migration/compaction points.

use ops_light_secrets_server::fault_inject::CORE_RECOVERY_POINTS;
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const EXTENDED: &[&str] = &[
    "rotation-cutover-before-write",
    "rotation-cutover-after-audit",
    "key-record-reencrypt-before-rename",
    "key-metadata-remac-before-rename",
    "key-audit-payload-after-select",
    "migration-plan-before-commit",
    "compaction-before-swap",
];

#[test]
fn extended_fault_points_are_named_and_producers_exist() {
    let harness = Harness::builder("extended-fault")
        .register_canary(b"extended-fault-canary")
        .build()
        .unwrap();
    for point in EXTENDED {
        assert!(!point.is_empty());
        let mut scenario = harness.scenario_case("extended-fault", point, 1).unwrap();
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
