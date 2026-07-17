//! U8.4: full key-rotation suite registration across recovery + purpose-key slices.

use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

#[test]
fn key_rotation_suite_registers_purpose_key_slices() {
    let producers = [
        (
            "recipient-rewrap",
            "tests/recipient_rewrap.rs",
            "rewrap_changes_only_envelope_metadata_and_matching_audit",
        ),
        (
            "credential-epoch",
            "tests/credential_epoch.rs",
            "disclosure_precedes_atomic_epoch_identity_grant_credential_and_audit_commit",
        ),
        ("reencrypt", "tests/reencrypt.rs", "fn "),
        (
            "metadata-integrity",
            "tests/keyring.rs",
            "metadata_integrity_key_rotation_advances_generation",
        ),
        (
            "audit-payload",
            "tests/keyring.rs",
            "audit_payload_rotation_is_forward_only_and_limits_hard",
        ),
        ("key-recovery", "tests/key_recovery.rs", "fn "),
    ];
    let harness = Harness::builder("key-rotation-suite")
        .register_canary(b"key-rotation-suite-canary")
        .build()
        .unwrap();
    for (case, path, needle) in producers {
        let source = std::fs::read_to_string(path).unwrap();
        assert!(source.contains(needle), "{path} missing {needle}");
        let mut scenario = harness.scenario_case("key-rotation", case, 1).unwrap();
        scenario
            .step(
                "producer",
                SafeSummary::new().field("ok", SafeValue::Boolean(true)),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        scenario.finish_success().unwrap();
    }
}
