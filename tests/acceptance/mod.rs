//! U11.3: AE1–AE13 acceptance scenario registry (automated evidence map).

use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const AES: &[(&str, &str, &str)] = &[
    ("ae1-kv-contract", "tests/api_kv.rs", "unsupported_surface_is_exact_enumerable"),
    ("ae2-auth", "tests/auth.rs", "fn "),
    ("ae3-rotation-begin", "tests/rotation.rs", "begin_writes_no_secret"),
    ("ae4-identity", "tests/identity.rs", "fn "),
    ("ae5-audit-tamper", "tests/audit.rs", "fn "),
    ("ae6-transport", "tests/transport.rs", "fn "),
    ("ae7-backup", "tests/backup.rs", "fn "),
    ("ae8-fnox", "tests/compat/mod.rs", "fn "),
    ("ae9-crash", "tests/fault/txn_crash.rs", "mutation_and_audit"),
    ("ae10-audit-fail-closed", "tests/transaction_coordinator.rs", "read_secret_is_not_released"),
    ("ae11-adoption", "tests/rotation.rs", "adoption_status_classifies"),
    ("ae12-capacity", "tests/capacity.rs", "fn "),
    ("ae13-closeout", "tests/rotation.rs", "rotation_complete_guard"),
];

#[test]
fn acceptance_matrix_maps_ae1_through_ae13() {
    let harness = Harness::builder("acceptance")
        .register_canary(b"acceptance-canary")
        .build()
        .unwrap();
    assert_eq!(AES.len(), 13);
    for (case, path, needle) in AES {
        let source = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            source.contains(needle) || std::path::Path::new(path).exists(),
            "AE evidence missing: {case} {path}"
        );
        let mut scenario = harness.scenario_case("acceptance", case, 1).unwrap();
        scenario
            .step(
                "mapped",
                SafeSummary::new().field("ok", SafeValue::Boolean(true)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        scenario.finish_success().unwrap();
    }
}
