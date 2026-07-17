use std::collections::BTreeSet;
use std::path::Path;

use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary};

const SCENARIO_IDS: [&str; 28] = [
    "startup-01-no-key-material",
    "startup-02-init-state-and-exclusion",
    "startup-03-remote-plaintext",
    "startup-04-second-instance-lock",
    "startup-05-lifecycle-and-schema",
    "startup-06-argv-and-config-refusal",
    "startup-07-init-disclosure-failures",
    "startup-08-runtime-credential-source",
    "startup-09-clock-behind-override",
    "startup-10-clock-future-jump",
    "startup-10b-clock-rollback",
    "startup-11-clock-repair",
    "startup-12-management-local-only",
    "startup-13-valid-health-bind",
    "startup-14-data-directory-safety",
    "startup-15-keyring-store-id",
    "startup-16-lock-fault",
    "startup-17-init-while-serving",
    "startup-18-graceful-shutdown",
    "startup-19-unsafe-environment",
    "startup-20-stdin-and-fd",
    "startup-21-real-pty",
    "startup-22-foreign-init-artifacts",
    "startup-config-precedence",
    "startup-control-socket-safety",
    "startup-shutdown-forced",
    "startup-mount-config",
    "startup-reserve-recovery",
];

#[test]
fn scenario_manifest_has_exact_evidence_owned_tails_and_no_silent_ignores() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/startup-scenarios.json")).unwrap();
    let ledger: serde_json::Value =
        serde_json::from_str(include_str!("../docs/integration-tail-ledger.json")).unwrap();
    assert_eq!(manifest["schema"], 1);
    assert_eq!(manifest["ignored_scenarios"], serde_json::json!([]));

    let ledger_contracts = ledger["tails"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tail| tail["contract"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let scenarios = manifest["scenarios"].as_array().unwrap();
    let manifest_ids = scenarios
        .iter()
        .map(|scenario| scenario["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(manifest_ids, SCENARIO_IDS);

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for scenario in scenarios {
        let evidence = scenario["evidence"].as_array().unwrap();
        assert!(!evidence.is_empty());
        for item in evidence {
            let item = item.as_str().unwrap();
            let (path, test) = item.split_once("::").unwrap();
            let source = std::fs::read_to_string(root.join(path)).unwrap();
            assert!(
                source.contains(&format!("fn {test}")),
                "missing evidence {item}"
            );
        }
        for tail in scenario["tails"].as_array().unwrap() {
            assert!(ledger_contracts.contains(tail.as_str().unwrap()));
        }
    }

    for path in [
        "tests/startup.rs",
        "tests/startup_skeleton.rs",
        "tests/init.rs",
        "tests/control_socket.rs",
        "tests/clock.rs",
        "tests/tty_secret_input.rs",
    ] {
        let source = std::fs::read_to_string(root.join(path)).unwrap();
        assert!(
            !source.contains("#[ignore"),
            "unregistered ignore in {path}"
        );
    }
}

#[test]
fn every_startup_contract_scenario_emits_observability_events() {
    let harness = Harness::builder("startup-contract")
        .register_canary(b"startup-contract-canary-9d612a")
        .build()
        .unwrap();
    for id in SCENARIO_IDS {
        let mut scenario = harness.scenario(id, 1).unwrap();
        scenario
            .step(
                "evidence-registered",
                SafeSummary::new(),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
        let report = scenario.finish_success().unwrap();
        assert!(report.jsonl.contains("\"event\":\"scenario_begin\""));
        assert!(report.jsonl.contains("\"event\":\"step\""));
        assert!(report.jsonl.contains("\"event\":\"scenario_end\""));
    }
}
