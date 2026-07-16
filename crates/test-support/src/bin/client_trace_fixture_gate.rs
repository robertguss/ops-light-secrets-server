use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use test_support::{
    ActualOutcome, ArtifactKind, ArtifactScanner, ExpectedOutcome, FullScanner, Harness,
    SafeSummary, SafeValue, ScanRequest,
};
use zeroize::Zeroizing;

const CANARIES: &[&[u8]] = &[
    b"OLSS_SYNTHETIC_TOKEN_7d9f3c2a1b8e6d4f",
    b"OLSS_SYNTHETIC_ROLE_18f3a9",
    b"OLSS_SYNTHETIC_SECRET_ID_42d8b7",
    b"OLSS_SYNTHETIC_VALUE_482f1a",
    b"OLSS_SYNTHETIC_ACCESSOR_9c21",
];

fn files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut output = BTreeMap::new();
    for entry in fs::read_dir(root).map_err(|_| "candidate read failure")? {
        let entry = entry.map_err(|_| "candidate entry failure")?;
        let file_type = entry.file_type().map_err(|_| "candidate type failure")?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err("candidate contains non-regular entry".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "candidate filename is not UTF-8")?;
        if !name.ends_with(".json") || name.contains('/') || name.starts_with('.') {
            return Err("candidate filename rejected".into());
        }
        let bytes = fs::read(entry.path()).map_err(|_| "candidate file read failure")?;
        output.insert(name, bytes);
    }
    if output.len() != 7 || !output.contains_key("manifest.json") {
        return Err("candidate inventory mismatch".into());
    }
    Ok(output)
}

fn gate(candidate: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let inventory = files(candidate)?;
    let canaries: Vec<Zeroizing<Vec<u8>>> = CANARIES
        .iter()
        .map(|value| Zeroizing::new(value.to_vec()))
        .collect();
    let direct = FullScanner
        .scan(ScanRequest {
            root: candidate,
            run_key: &[0x42; 32],
            canaries: &canaries,
        })
        .map_err(|_| "candidate full scan failed")?;
    if !direct.clean || direct.scanner != "full-artifact-v1" {
        return Err("candidate scan attestation invalid".into());
    }

    let mut builder = Harness::builder("client-trace-fixture");
    for canary in CANARIES {
        builder = builder.register_canary(canary);
    }
    let harness = builder
        .build()
        .map_err(|_| "typed harness registration failed")?;
    let mut scenario = harness
        .scenario("normalize-client-traces", 1)
        .map_err(|_| "typed scenario failed")?;
    for bytes in inventory.values() {
        scenario
            .capture(ArtifactKind::Fixture, bytes)
            .map_err(|_| "typed fixture capture failed")?;
    }
    let digest = blake3::hash(
        &inventory
            .values()
            .flat_map(|bytes| bytes.iter().copied())
            .collect::<Vec<_>>(),
    )
    .to_hex()
    .to_string();
    scenario
        .step(
            "candidate-scan",
            SafeSummary::new()
                .field("file_count", SafeValue::Unsigned(inventory.len() as u64))
                .field(
                    "tree_digest",
                    SafeValue::digest_prefix(digest[..16].to_owned())
                        .map_err(|_| "typed digest failed")?,
                ),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .map_err(|_| "typed step failed")?;
    let report = scenario
        .finish_success()
        .map_err(|_| "typed full scan failed")?;
    if !report.scan_attestation.clean || report.scan_attestation.scanner != "full-artifact-v1" {
        return Err("typed scan attestation invalid".into());
    }
    println!(
        "{{\"schema\":1,\"event\":\"fixture_gate_pass\",\"files\":{},\"scanner\":\"full-artifact-v1\"}}",
        inventory.len()
    );
    Ok(inventory)
}

fn compare(candidate: &BTreeMap<String, Vec<u8>>, output: &Path) -> Result<(), String> {
    let retained = files(output)?;
    if *candidate != retained {
        return Err("retained fixtures differ from gated candidate".into());
    }
    Ok(())
}

fn promote(candidate: &BTreeMap<String, Vec<u8>>, output: &Path) -> Result<(), String> {
    let parent = output.parent().ok_or("output has no parent")?;
    fs::create_dir_all(parent).map_err(|_| "output parent failure")?;
    let staging = parent.join(format!(".client-traces-promote-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|_| "stale staging removal failed")?;
    }
    fs::create_dir(&staging).map_err(|_| "staging create failure")?;
    for (name, bytes) in candidate {
        fs::write(staging.join(name), bytes).map_err(|_| "staging write failure")?;
    }
    if output.exists() {
        fs::remove_dir_all(output).map_err(|_| "old fixture removal failed")?;
    }
    fs::rename(staging, output).map_err(|_| "fixture activation failed".to_owned())
}

fn main() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 4 || !matches!(arguments[1].as_str(), "check" | "promote") {
        return Err("usage: client_trace_fixture_gate <check|promote> <candidate> <output>".into());
    }
    let candidate_path = PathBuf::from(&arguments[2]);
    let output = PathBuf::from(&arguments[3]);
    let candidate = gate(&candidate_path)?;
    if arguments[1] == "check" {
        compare(&candidate, &output)
    } else {
        promote(&candidate, &output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn candidate(payload_name: &str, payload: &[u8]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let safe_count = if payload_name == "manifest.json" {
            6
        } else {
            5
        };
        for index in 0..safe_count {
            fs::write(directory.path().join(format!("safe-{index}.json")), b"{}").unwrap();
        }
        if payload_name != "manifest.json" {
            fs::write(directory.path().join("manifest.json"), b"{}").unwrap();
        }
        fs::write(directory.path().join(payload_name), payload).unwrap();
        directory
    }

    #[test]
    fn gate_rejects_base64_encoded_registered_canary() {
        let directory = candidate("manifest.json", b"T0xTU19TWU5USEVUSUNfVkFMVUVfNDgyZjFh");
        assert!(gate(directory.path()).is_err());
    }

    #[test]
    fn gate_rejects_hostile_encoded_filename() {
        let directory = candidate("T0xTU19TWU5USEVUSUNfVkFMVUVfNDgyZjFh.json", b"{}");
        assert!(gate(directory.path()).is_err());
    }
}
