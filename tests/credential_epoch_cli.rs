use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

use age::x25519;
use ops_light_secrets_server::credential::{CredentialAudience, CredentialKind};
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::store::keyring::{KeyringError, KeyringOpener, RandomSource};
use ops_light_secrets_server::store::{FORMAT_VERSION, Lifecycle, MetaRecord, Store, StoreId};

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
}

#[test]
fn help_freezes_explicit_online_offline_epoch_rotation_surface() {
    let output = binary()
        .args(["credential", "epoch", "rotate", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--mode",
        "--identity-source",
        "--control-socket",
        "--control-credential-source",
        "--expected-epoch",
        "--reason",
        "--confirm",
        "--credential-output-fd",
    ] {
        assert!(help.contains(flag), "missing {flag}");
    }
}

#[test]
fn real_offline_cli_plans_discloses_to_fd_and_commits_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let credentials = tempfile::tempdir().unwrap();
    std::fs::write(credentials.path().join("active"), ACTIVE_IDENTITY).unwrap();
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let transaction = KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([7; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &active,
        None,
        &mut Counter(0),
    )
    .unwrap();
    let old = transaction.bootstrap_credential().unwrap().to_owned();
    transaction
        .commit(directory.path().join("store.redb"))
        .unwrap();
    let args = [
        "credential",
        "epoch",
        "rotate",
        "--mode",
        "offline",
        "--identity-source",
        "credential:active",
        "--expected-epoch",
        "1",
        "--reason",
        "incident response fixture",
        "--output",
        "json",
    ];
    let plan = binary()
        .env("OLSS_DATA_DIRECTORY", directory.path())
        .env("CREDENTIALS_DIRECTORY", credentials.path())
        .args(args)
        .output()
        .unwrap();
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan["mutation"], false);
    assert_eq!(plan["caller_credential_dies"], true);
    let confirmation = plan["confirmation"].as_str().unwrap();
    let (private_sink, mut private_reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let source_fd = private_sink.as_raw_fd();
    let mut command = binary();
    command
        .env("OLSS_DATA_DIRECTORY", directory.path())
        .env("CREDENTIALS_DIRECTORY", credentials.path())
        .args(args)
        .args(["--confirm", confirmation, "--credential-output-fd", "3"]);
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
    let committed = command.output().unwrap();
    drop(private_sink);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let mut replacement = String::new();
    private_reader.read_to_string(&mut replacement).unwrap();
    let replacement = replacement.trim();
    assert!(!replacement.is_empty());
    assert!(
        !committed
            .stdout
            .windows(replacement.len())
            .any(|value| value == replacement.as_bytes())
    );
    let store = Store::open(directory.path().join("store.redb")).unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([7; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    assert!(
        keyring
            .verify_credential(
                &store,
                &old,
                CredentialKind::Token,
                CredentialAudience::Control,
                u64::MAX - 1,
            )
            .unwrap()
            .authenticated_id
            .is_none()
    );
    assert!(
        keyring
            .verify_credential(
                &store,
                replacement,
                CredentialKind::Token,
                CredentialAudience::Control,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap()
            .authenticated_id
            .is_some()
    );
}
