use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn cli_help_is_stable_json_capable_and_avoids_argv_secret_flags() {
    for args in [
        vec!["--help"],
        vec!["doctor", "--help"],
        vec!["rotation", "--help"],
        vec!["backup", "--help"],
        vec!["restore", "--help"],
        vec!["key", "--help"],
        vec!["credential", "epoch", "rotate", "--help"],
    ] {
        let out = bin().args(&args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("--token "), "{args:?}");
        assert!(!text.contains("--password"));
        assert!(!text.contains("AGE-SECRET-KEY"));
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = bin()
        .args([
            "doctor",
            "--data-directory",
            dir.path().to_str().unwrap(),
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"schema\""));
    assert!(stdout.contains("exit_code") || stdout.contains("\"checks\""));
}
