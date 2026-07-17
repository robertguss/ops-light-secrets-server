use std::io::Write;
use std::process::{Command, Stdio};

use ed25519_dalek::SigningKey;
use ops_light_secrets_server::backup::artifact_digest;
use ops_light_secrets_server::backup_format::{
    BACKUP_SIGNING_DOMAIN_ID, BackupContainer, BackupSigningHeader, DetachedBackupSignature,
};
use ops_light_secrets_server::store::{Canonical, SigningKeyCandidate};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn backup_help_freezes_catalog_recipient_and_manifest_commands() {
    let output = binary().args(["backup", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "create",
        "list",
        "show",
        "resume",
        "verify",
        "rehearsal",
        "recipient",
        "manifest",
    ] {
        assert!(help.contains(command));
    }
    let recipient = binary()
        .args(["backup", "recipient", "--help"])
        .output()
        .unwrap();
    let recipient = String::from_utf8(recipient.stdout).unwrap();
    assert!(recipient.contains("list"));
    assert!(recipient.contains("set"));
    let manifest = binary()
        .args(["backup", "manifest", "--help"])
        .output()
        .unwrap();
    let manifest = String::from_utf8(manifest.stdout).unwrap();
    assert!(manifest.contains("sign"));
    assert!(manifest.contains("abandon"));
    let verify = binary()
        .args(["backup", "verify", "--help"])
        .output()
        .unwrap();
    let verify = String::from_utf8(verify.stdout).unwrap();
    assert!(verify.contains("--full"));
    assert!(verify.contains("--identity-source"));
    assert!(verify.contains("--receipt-signing-key-source"));
    let rehearsal = binary()
        .args(["backup", "rehearsal", "--help"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8(rehearsal.stdout)
            .unwrap()
            .contains("record")
    );
}

#[test]
fn offline_manifest_sign_uses_typed_source_and_writes_detached_file() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive.olss");
    let public_path = directory.path().join("public.bin");
    let signature_path = directory.path().join("archive.sig");
    let private = [0x55; 32];
    let public =
        SigningKeyCandidate::new(SigningKey::from_bytes(&private).verifying_key().to_bytes())
            .unwrap();
    let container = BackupContainer::new(
        BackupSigningHeader {
            archive_id: [1; 16],
            store_incarnation_id: [2; 16],
            signing_key_id: public.id,
            signing_domain: BACKUP_SIGNING_DOMAIN_ID,
            signing_lineage_generation: 1,
            recovery_set_generation: 1,
            effective_recipient_digest: [3; 32],
            encrypted_payload_length: 1,
            encrypted_payload_digest: [4; 32],
            recovery_manifest_digest: [5; 32],
        },
        b"age-encrypted-payload".to_vec(),
    )
    .unwrap();
    std::fs::write(&archive, container.encode().unwrap()).unwrap();
    std::fs::write(&public_path, public.encode().unwrap()).unwrap();
    let mut child = binary()
        .args([
            "backup",
            "manifest",
            "sign",
            "--control-socket",
            "/run/unused.sock",
            "--control-credential-source",
            "stdin",
            "--archive",
            archive.to_str().unwrap(),
            "--public-key-candidate",
            public_path.to_str().unwrap(),
            "--private-key-source",
            "stdin",
            "--signature-output",
            signature_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&private).unwrap();
    assert!(child.wait().unwrap().success());
    let signature =
        DetachedBackupSignature::decode(&std::fs::read(signature_path).unwrap()).unwrap();
    assert_eq!(signature.key_id, public.id);
    assert_eq!(
        signature.content_digest,
        artifact_digest(&container).unwrap()
    );
    signature
        .verify(&container.header, &public.verifying_key)
        .unwrap();
}
