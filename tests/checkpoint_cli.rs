use ed25519_dalek::SigningKey;
use ops_light_secrets_server::store::{
    Canonical, CheckpointDescriptor, CheckpointKeyStatus, CheckpointPublicKey, CheckpointSignature,
    StateDigest, StoreId, signing_key_id,
};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn offline_sign_command_uses_typed_source_and_creates_detached_file() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor_path = directory.path().join("descriptor.bin");
    let output_path = directory.path().join("checkpoint.sig");
    let public_path = directory.path().join("checkpoint-public.bin");
    let private = [23; 32];
    let id = signing_key_id(&SigningKey::from_bytes(&private).verifying_key().to_bytes());
    let descriptor = CheckpointDescriptor {
        store_id: StoreId([1; 16]),
        audit_epoch: [2; 16],
        range_start: 1,
        range_end: 2,
        prepare_event_id: [3; 16],
        chain_head: [4; 32],
        state_digest: StateDigest([5; 32]),
        effective_timestamp_milliseconds: 1_800_000_000_000,
        signing_key_id: id,
        previous_checkpoint_digest: None,
    };
    std::fs::write(&descriptor_path, descriptor.encode().unwrap()).unwrap();
    std::fs::write(
        &public_path,
        CheckpointPublicKey {
            id,
            verifying_key: SigningKey::from_bytes(&private).verifying_key().to_bytes(),
            status: CheckpointKeyStatus::Current,
            valid_from_milliseconds: 1_700_000_000_000,
            valid_until_milliseconds: Some(1_900_000_000_000),
            previous_key_id: None,
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args([
            "audit",
            "checkpoint",
            "sign",
            "--descriptor",
            descriptor_path.to_str().unwrap(),
            "--public-key-descriptor",
            public_path.to_str().unwrap(),
            "--private-key-source",
            "stdin",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&private).unwrap();
    assert!(child.wait().unwrap().success());
    let checkpoint = CheckpointSignature::decode(&std::fs::read(output_path).unwrap()).unwrap();
    assert_eq!(checkpoint.descriptor, descriptor);
}

#[test]
fn sign_help_names_exact_offline_surface_without_raw_key_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
        .args(["audit", "checkpoint", "sign", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--private-key-source"));
    assert!(!help.contains("--private-key <"));
}
