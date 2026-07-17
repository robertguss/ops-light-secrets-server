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
fn init_help_freezes_ttl_and_approved_sink_flags() {
    let output = binary()
        .args(["init", "--help"])
        .output()
        .expect("run binary");
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("--bootstrap-ttl"));
    assert!(stdout.contains("--credential-output-fd"));
    assert!(stdout.contains("--recovery-recipient"));
    assert!(stdout.contains("5m minimum, 7d maximum"));
    assert!(stdout.contains("TTY, pipe, socket, or anonymous memory FD"));
}

#[test]
fn init_refuses_invalid_ttl_and_missing_sink_without_secret_output() {
    let invalid = binary()
        .args(["init", "--bootstrap-ttl", "0"])
        .output()
        .expect("run binary");
    let invalid_stderr = String::from_utf8(invalid.stderr).unwrap();
    assert!(!invalid.status.success());
    assert!(invalid_stderr.contains("invalid_bootstrap_ttl"));

    let missing = binary().arg("init").output().expect("run binary");
    let missing_stderr = String::from_utf8(missing.stderr).unwrap();
    assert!(!missing.status.success());
    assert!(missing_stderr.contains("credential_sink_required"));
    assert!(!missing_stderr.contains("disclosed-once"));
}

#[test]
fn clock_repair_help_and_pending_adapter_are_fail_closed() {
    let help = binary()
        .args(["clock", "repair", "--help"])
        .output()
        .expect("run binary");
    let stdout = String::from_utf8(help.stdout).unwrap();
    assert!(help.status.success());
    assert!(stdout.contains("--exact-old-unix-seconds"));
    assert!(stdout.contains("--replacement-unix-seconds"));
    assert!(stdout.contains("--reason"));
    assert!(stdout.contains("--credential-output-fd"));

    let refused = binary()
        .args([
            "clock",
            "repair",
            "--exact-old-unix-seconds",
            "2000",
            "--replacement-unix-seconds",
            "1000",
            "--reason",
            "operator correction",
            "--credential-output-fd",
            "3",
        ])
        .output()
        .expect("run binary");
    let stderr = String::from_utf8(refused.stderr).unwrap();
    assert!(!refused.status.success());
    assert!(stderr.contains("integration_pending"));
    assert!(stderr.contains("U8.3"));
    assert!(!stderr.contains("operator correction"));
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

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(!output.status.success());
    assert!(stderr.contains("missing_key_material"));
    assert!(!stderr.contains("unknown setting"));
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
    let stderr = String::from_utf8(allowed.stderr).expect("stderr is UTF-8");
    assert!(!allowed.status.success());
    assert!(stderr.contains("uninitialized_store"));
    assert!(!stderr.contains("DEVELOPMENT_IDENTITY"));
}
