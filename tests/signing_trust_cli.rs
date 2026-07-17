use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use ops_light_secrets_server::store::{
    Canonical, SignedSigningTransition, SigningKeyCandidate, SigningTransition, StoreId,
    verify_signing_transition,
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn signing_key_help_freezes_generate_enroll_list_and_three_step_rotation() {
    let output = binary()
        .args(["audit", "signing-key", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in ["generate", "enroll", "list", "rotate"] {
        assert!(help.contains(command));
    }
    let output = binary()
        .args(["audit", "signing-key", "rotate", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    for command in ["prepare", "sign", "register"] {
        assert!(help.contains(command));
    }
    assert!(!help.contains("--private-key <"));
}

#[test]
fn stateless_generate_writes_raw_private_only_to_fd_and_public_json_to_stdout() {
    let (private_sink, mut private_reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let source_fd = private_sink.as_raw_fd();
    let mut command = binary();
    command.args([
        "--config",
        "/definitely/not/a/config/file",
        "audit",
        "signing-key",
        "generate",
        "--private-output-fd",
        "3",
        "--output",
        "json",
    ]);
    unsafe {
        command.pre_exec(move || {
            if source_fd == 3 {
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(source_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    drop(private_sink);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut private = Vec::new();
    private_reader.read_to_end(&mut private).unwrap();
    assert_eq!(private.len(), 32);
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata["algorithm"], "ed25519");
    assert_eq!(metadata["domain"], "external-signing-trust-v1");
    assert_eq!(metadata["key_id"], metadata["fingerprint"]);
    assert!(
        !output
            .stdout
            .windows(private.len())
            .any(|window| window == private)
    );
    assert!(
        !output
            .stderr
            .windows(private.len())
            .any(|window| window == private)
    );
}

#[test]
fn offline_rotate_sign_consumes_typed_old_key_source_and_creates_atomic_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let transition_path = directory.path().join("transition.bin");
    let old_public_path = directory.path().join("old-public.bin");
    let output_path = directory.path().join("transition.sig");
    let old_private = [10; 32];
    let old = SigningKeyCandidate::new(
        ed25519_dalek::SigningKey::from_bytes(&old_private)
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let new = SigningKeyCandidate::new(
        ed25519_dalek::SigningKey::from_bytes(&[11; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let transition = SigningTransition {
        transition_id: [20; 16],
        store_id: StoreId([1; 16]),
        incarnation: [2; 16],
        audit_epoch: [3; 16],
        old_key_id: old.id,
        new_key: new,
        prepared_head: [4; 32],
        prepare_event_id: [5; 16],
        prepare_sequence: 10,
        previous_registered_checkpoint: Some([6; 32]),
        expected_generation: 1,
        nonce: [7; 32],
        expires_at_milliseconds: 1_000,
    };
    std::fs::write(&transition_path, transition.encode().unwrap()).unwrap();
    std::fs::write(&old_public_path, old.encode().unwrap()).unwrap();
    let mut child = binary()
        .args([
            "audit",
            "signing-key",
            "rotate",
            "sign",
            "--transition",
            transition_path.to_str().unwrap(),
            "--old-public-key-candidate",
            old_public_path.to_str().unwrap(),
            "--private-key-source",
            "stdin",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&old_private).unwrap();
    assert!(child.wait().unwrap().success());
    let signed = SignedSigningTransition::decode(&std::fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(signed.transition, transition);
    verify_signing_transition(&signed, &old).unwrap();
    assert!(
        std::fs::symlink_metadata(output_path)
            .unwrap()
            .file_type()
            .is_file()
    );
}
