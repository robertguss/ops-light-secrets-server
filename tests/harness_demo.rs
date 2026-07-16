use test_support::{
    ActualOutcome, ArtifactKind, AuditEnvelopeSummary, ExpectedOutcome, Harness, RedactedCommand,
    SafeSummary, SafeValue,
};

#[test]
fn demo_emits_typed_and_human_failure_context_after_clean_scan() {
    let harness = Harness::builder("harness-demo")
        .register_canary(b"registered-secret-value")
        .build()
        .expect("create harness");
    let mut scenario = harness.scenario("demo-failure", 1).expect("start scenario");

    scenario
        .step(
            "start-server",
            SafeSummary::new().field("attempt", SafeValue::Unsigned(1)),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .expect("record step");
    scenario
        .capture(
            ArtifactKind::ServerStderr,
            b"safe server line one\nsafe server line two\n",
        )
        .expect("capture private output");

    let reproduction = RedactedCommand::new("cargo")
        .literal("test")
        .literal("--test")
        .literal("harness_demo")
        .placeholder("--config", "<CONFIG_PATH>");
    let audit = [
        AuditEnvelopeSummary::new(1, 7, 42, "2026-07-16T20:00:00Z", "a1b2c3d4")
            .expect("safe envelope"),
    ];

    let report = scenario
        .finish_failure(reproduction, &audit)
        .expect("scan and render failure");
    println!("{}", report.human);

    assert!(report.scan_attestation.clean);
    assert!(
        report
            .jsonl
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );
    assert!(report.jsonl.contains("\"event\":\"scenario_begin\""));
    assert!(report.jsonl.contains("\"event\":\"step\""));
    assert!(report.jsonl.contains("\"event\":\"scenario_end\""));
    assert!(report.human.contains("demo-failure"));
    assert!(report.human.contains("safe server line two"));
    assert!(
        report
            .human
            .contains("cargo test --test harness_demo --config <CONFIG_PATH>")
    );
    assert!(report.human.contains(
        "audit envelope_version=1 epoch=7 sequence=42 effective_timestamp=2026-07-16T20:00:00Z digest_prefix=a1b2c3d4"
    ));
    assert!(report.human.contains("data entry="));
    assert!(!report.human.contains("operation"));
    assert!(!report.jsonl.contains("registered-secret-value"));
    assert!(!report.human.contains("registered-secret-value"));
}
