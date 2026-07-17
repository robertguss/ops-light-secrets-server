#[test]
fn verification_contract_lists_required_checks() {
    let raw = include_str!("../scripts/verify-checks.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    let ids: Vec<&str> = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for required in [
        "compat-pins",
        "differential",
        "deny",
        "fuzz",
        "compatibility-doc",
        "test",
        "canary-gate",
    ] {
        assert!(ids.contains(&required), "missing {required}");
    }
    assert!(std::path::Path::new("docs/verification-contract.md").exists());
}
