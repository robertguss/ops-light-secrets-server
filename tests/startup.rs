use std::process::Command;
use tempfile::NamedTempFile;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn help_documents_config_and_secret_source_rules() {
    let output = binary().arg("--help").output().expect("run binary");
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("stdin, fd:N, credential:NAME, tty"));
    assert!(stdout.contains("OLSS_MOUNTS_SECRET_MAX_VERSIONS"));
    assert!(stdout.contains("Usage: ops-light-secrets-server"));
}

#[test]
fn serve_refuses_unknown_config_key_without_echoing_value() {
    use std::io::Write;

    let mut config = NamedTempFile::new().expect("temporary config");
    writeln!(config, "typoed_security_setting = 'do-not-print-me'").expect("write config");

    let output = binary()
        .args([
            "--config",
            config.path().to_str().expect("UTF-8 path"),
            "serve",
        ])
        .output()
        .expect("run binary");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");

    assert!(!output.status.success());
    assert!(stderr.contains("typoed_security_setting"));
    assert!(!stderr.contains("do-not-print-me"));
}

#[test]
fn secret_value_flags_are_refused_with_setting_name() {
    let output = binary()
        .args(["serve", "--age-identity", "do-not-print-me"])
        .output()
        .expect("run binary");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");

    assert!(!output.status.success());
    assert!(stderr.contains("age_identity"));
    assert!(!stderr.contains("do-not-print-me"));
}

#[test]
fn command_line_config_path_overrides_environment_path() {
    use std::io::Write;

    let good = NamedTempFile::new().expect("good config");
    let mut bad = NamedTempFile::new().expect("bad config");
    writeln!(bad, "unknown = true").expect("write bad config");

    let output = binary()
        .env("OLSS_CONFIG", bad.path())
        .args([
            "--config",
            good.path().to_str().expect("UTF-8 path"),
            "serve",
        ])
        .output()
        .expect("run binary");

    assert!(output.status.success());
}

#[test]
fn unknown_prefixed_environment_key_is_fatal_and_value_is_redacted() {
    let output = binary()
        .env("OLSS_TYPOED_SECURITY_SETTING", "do-not-print-me")
        .arg("serve")
        .output()
        .expect("run binary");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");

    assert!(!output.status.success());
    assert!(stderr.contains("OLSS_TYPOED_SECURITY_SETTING"));
    assert!(!stderr.contains("do-not-print-me"));
}

#[test]
fn environment_secret_descriptor_needs_explicit_unsafe_flag() {
    let refused = binary()
        .env("OLSS_AGE_IDENTITY_SOURCE", "env:DEVELOPMENT_IDENTITY")
        .arg("serve")
        .output()
        .expect("run binary");
    assert!(!refused.status.success());

    let allowed = binary()
        .env("OLSS_AGE_IDENTITY_SOURCE", "env:DEVELOPMENT_IDENTITY")
        .args(["--unsafe-dev-secret-env", "serve"])
        .output()
        .expect("run binary");
    assert!(allowed.status.success());
}
