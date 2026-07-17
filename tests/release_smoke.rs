#[test]
fn release_smoke_script_and_docs_exist() {
    let script = std::fs::read_to_string("scripts/release/smoke-artifact.sh").unwrap();
    assert!(script.contains("sha256sum"));
    assert!(script.contains("OLSS_RELEASE_ARTIFACT_ONLY"));
    let docs = std::fs::read_to_string("docs/release.md").unwrap();
    assert!(docs.contains("smoke-artifact"));
    assert!(docs.contains("artifact-smoke"));
}
