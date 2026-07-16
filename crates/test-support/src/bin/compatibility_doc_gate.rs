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

fn gate(candidate: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(candidate).map_err(|_| "candidate metadata failure")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("candidate must be a regular file".into());
    }
    let root = candidate.parent().ok_or("candidate has no parent")?;
    let canaries: Vec<Zeroizing<Vec<u8>>> = CANARIES
        .iter()
        .map(|value| Zeroizing::new(value.to_vec()))
        .collect();
    let direct = FullScanner
        .scan(ScanRequest {
            root,
            run_key: &[0x43; 32],
            canaries: &canaries,
        })
        .map_err(|_| "candidate full scan failed")?;
    if !direct.clean || direct.scanner != "full-artifact-v1" {
        return Err("candidate scan attestation invalid".into());
    }

    let bytes = fs::read(candidate).map_err(|_| "candidate read failure")?;
    let mut builder = Harness::builder("compatibility-document");
    for canary in CANARIES {
        builder = builder.register_canary(canary);
    }
    let harness = builder
        .build()
        .map_err(|_| "typed harness registration failed")?;
    let mut scenario = harness
        .scenario("generate-compatibility-document", 1)
        .map_err(|_| "typed scenario failed")?;
    scenario
        .capture(ArtifactKind::Data, &bytes)
        .map_err(|_| "typed document capture failed")?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    scenario
        .step(
            "candidate-scan",
            SafeSummary::new()
                .field("byte_count", SafeValue::Unsigned(bytes.len() as u64))
                .field(
                    "document_digest",
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
        "{{\"schema\":1,\"event\":\"compatibility_doc_gate_pass\",\"bytes\":{},\"scanner\":\"full-artifact-v1\"}}",
        bytes.len()
    );
    Ok(bytes)
}

fn compare(candidate: &[u8], output: &Path) -> Result<(), String> {
    let retained = fs::read(output).map_err(|_| "retained document read failure")?;
    if candidate != retained {
        return Err("retained document differs from gated candidate".into());
    }
    Ok(())
}

fn promote(candidate: &[u8], output: &Path) -> Result<(), String> {
    let parent = output.parent().ok_or("output has no parent")?;
    fs::create_dir_all(parent).map_err(|_| "output parent failure")?;
    let staging = parent.join(format!(".compatibility-promote-{}.md", std::process::id()));
    fs::write(&staging, candidate).map_err(|_| "staging write failure")?;
    fs::rename(staging, output).map_err(|_| "document activation failure".to_owned())
}

fn main() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 4 || !matches!(arguments[1].as_str(), "check" | "promote") {
        return Err("usage: compatibility_doc_gate <check|promote> <candidate> <output>".into());
    }
    let bytes = gate(Path::new(&arguments[2]))?;
    let output = PathBuf::from(&arguments[3]);
    if arguments[1] == "check" {
        compare(&bytes, &output)
    } else {
        promote(&bytes, &output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_rejects_base64_encoded_registered_canary() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("compatibility.md");
        fs::write(&candidate, b"T0xTU19TWU5USEVUSUNfVkFMVUVfNDgyZjFh").unwrap();
        assert_eq!(gate(&candidate).unwrap_err(), "candidate full scan failed");
    }

    #[test]
    fn gate_rejects_hostile_encoded_filename() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory
            .path()
            .join("T0xTU19TWU5USEVUSUNfVkFMVUVfNDgyZjFh.md");
        fs::write(&candidate, b"safe").unwrap();
        assert_eq!(gate(&candidate).unwrap_err(), "candidate full scan failed");
    }
}
