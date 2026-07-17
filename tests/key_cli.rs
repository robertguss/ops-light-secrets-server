use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn age_identity_help_freezes_closed_purpose_sink_and_output_contract() {
    let output = binary()
        .args(["key", "age-identity", "generate", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--purpose <PURPOSE>"));
    assert!(stdout.contains("active"));
    assert!(stdout.contains("recovery"));
    assert!(stdout.contains("audit-export"));
    assert!(stdout.contains("--private-output-fd"));
    assert!(stdout.contains("--output"));
}

#[test]
fn record_key_rotation_help_requires_typed_custody_and_exact_evidence() {
    let key = binary().args(["key", "--help"]).output().unwrap();
    assert!(String::from_utf8(key.stdout).unwrap().contains("record"));
    let rotate = binary()
        .args(["key", "record", "rotate", "--help"])
        .output()
        .unwrap();
    assert!(rotate.status.success());
    let rotate = String::from_utf8(rotate.stdout).unwrap();
    for field in [
        "--identity-source",
        "--control-credential-source",
        "--active-recipient",
        "--archive-digest",
        "--signature-digest",
        "--recovery-receipt-digest",
        "--expected-generation",
        "--confirm",
    ] {
        assert!(rotate.contains(field));
    }
    assert!(!rotate.contains("--identity <"));
    let abort = binary()
        .args(["key", "record", "abort", "--help"])
        .output()
        .unwrap();
    let abort = String::from_utf8(abort.stdout).unwrap();
    assert!(abort.contains("--identity-source"));
    assert!(abort.contains("--control-credential-source"));
}

#[test]
fn stateless_cli_writes_private_identity_only_to_fd_and_public_json_to_stdout() {
    let (private_sink, mut private_reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let source_fd = private_sink.as_raw_fd();
    let mut command = binary();
    command.args([
        "--config",
        "/definitely/not/a/config/file",
        "key",
        "age-identity",
        "generate",
        "--purpose",
        "active",
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
    let mut private = String::new();
    private_reader.read_to_string(&mut private).unwrap();
    assert!(private.starts_with("AGE-SECRET-KEY-1"));

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata["purpose"], "active");
    assert_eq!(metadata["algorithm"], "age-x25519");
    assert!(metadata["recipient"].as_str().unwrap().starts_with("age1"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("AGE-SECRET-KEY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("AGE-SECRET-KEY"));
}

#[test]
fn unknown_purpose_is_rejected_before_private_fd_is_touched() {
    let output = binary()
        .args([
            "key",
            "age-identity",
            "generate",
            "--purpose",
            "unknown",
            "--private-output-fd",
            "999999",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid value 'unknown'"));
    assert!(!stderr.contains("private sink unsafe"));
}
