use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::str::FromStr;

use age::x25519;
use ops_light_secrets_server::config::{SecretInput, SecretSource, SystemSecretInput};
use ops_light_secrets_server::init::{KeyringInitSourceError, prepare_keyring_init_from_source};
use ops_light_secrets_server::startup::{KeyringBootError, open_store_keyring};
use ops_light_secrets_server::store::keyring::{
    AgeIdentityError, IdentityPurpose, KeyringError, KeyringOpener, RandomSource,
    generate_age_identity,
};
use ops_light_secrets_server::store::{FORMAT_VERSION, Lifecycle, MetaRecord, Store, StoreId};
use secrecy::ExposeSecret;

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

fn meta(id: u8) -> MetaRecord {
    MetaRecord {
        store_id: StoreId([id; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    }
}

struct Inputs {
    bytes: Vec<u8>,
    call: Option<String>,
}

impl Inputs {
    fn identity(value: &str) -> Self {
        Self {
            bytes: value.as_bytes().to_vec(),
            call: None,
        }
    }

    fn take(&mut self, call: String) -> io::Result<Vec<u8>> {
        self.call = Some(call);
        Ok(std::mem::take(&mut self.bytes))
    }
}

impl SecretInput for Inputs {
    fn read_stdin(&mut self) -> io::Result<Vec<u8>> {
        self.take("stdin".into())
    }

    fn read_file_descriptor(&mut self, fd: u32) -> io::Result<Vec<u8>> {
        self.take(format!("fd:{fd}"))
    }

    fn read_credential(&mut self, name: &str) -> io::Result<Vec<u8>> {
        self.take(format!("credential:{name}"))
    }

    fn read_tty(&mut self) -> io::Result<Vec<u8>> {
        self.take("tty".into())
    }

    fn read_environment(&mut self, variable: &str) -> io::Result<Vec<u8>> {
        self.take(format!("env:{variable}"))
    }
}

fn create_store(path: &std::path::Path, id: u8) -> Store {
    let mut input = Inputs::identity(ACTIVE_IDENTITY);
    let transaction = prepare_keyring_init_from_source(
        meta(id),
        &SecretSource::Credential("active-age-identity".into()),
        &mut input,
        None,
        &mut Counter(0),
    )
    .unwrap();
    assert_eq!(
        input.call.as_deref(),
        Some("credential:active-age-identity")
    );
    assert!(!path.exists(), "prepare must not create store state");
    transaction.commit(path).unwrap()
}

#[test]
fn init_commits_envelope_and_metadata_atomically_then_boot_opens_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let store = create_store(&path, 7);
    assert!(store.keyring().unwrap().is_some());
    assert!(store.keyring_metadata().unwrap().is_some());

    let mut input = Inputs::identity(ACTIVE_IDENTITY);
    let opener = KeyringOpener::default();
    let opened = open_store_keyring(
        &store,
        &SecretSource::Credential("active-age-identity".into()),
        &mut input,
        &opener,
    )
    .unwrap();
    assert_eq!(
        input.call.as_deref(),
        Some("credential:active-age-identity")
    );
    assert_eq!(opened.store_id(), StoreId([7; 16]));
    assert_eq!(opener.attempts(), 1);

    let mut second = Inputs::identity(ACTIVE_IDENTITY);
    assert_eq!(
        open_store_keyring(&store, &SecretSource::Stdin, &mut second, &opener,)
            .err()
            .unwrap(),
        KeyringBootError::Keyring(KeyringError::AlreadyOpened)
    );
}

#[test]
fn every_typed_source_reaches_real_decrypt_and_failures_are_closed() {
    for (source, expected) in [
        (SecretSource::Stdin, "stdin"),
        (SecretSource::FileDescriptor(9), "fd:9"),
        (
            SecretSource::Credential("age-key".into()),
            "credential:age-key",
        ),
        (SecretSource::Tty, "tty"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = create_store(&directory.path().join("store.redb"), 7);
        let mut input = Inputs::identity(ACTIVE_IDENTITY);
        open_store_keyring(&store, &source, &mut input, &KeyringOpener::default()).unwrap();
        assert_eq!(input.call.as_deref(), Some(expected));
    }

    let directory = tempfile::tempdir().unwrap();
    let store = create_store(&directory.path().join("store.redb"), 7);
    let mut absent = Inputs::identity("");
    assert_eq!(
        open_store_keyring(
            &store,
            &SecretSource::Stdin,
            &mut absent,
            &KeyringOpener::default(),
        )
        .err()
        .unwrap(),
        KeyringBootError::IdentitySource
    );
    let canary = "private-key-canary-u23-do-not-emit";
    let mut invalid = Inputs::identity(canary);
    let error = open_store_keyring(
        &store,
        &SecretSource::Stdin,
        &mut invalid,
        &KeyringOpener::default(),
    )
    .err()
    .unwrap();
    assert!(!error.to_string().contains(canary));
    assert!(!format!("{error:?}").contains(canary));
    let wrong_identity = x25519::Identity::generate().to_string();
    let mut wrong = Inputs::identity(wrong_identity.expose_secret());
    assert_eq!(
        open_store_keyring(
            &store,
            &SecretSource::Tty,
            &mut wrong,
            &KeyringOpener::default(),
        )
        .err()
        .unwrap(),
        KeyringBootError::Keyring(KeyringError::Decrypt)
    );
}

#[test]
fn runtime_credential_and_inherited_fd_reach_real_decrypt_without_plaintext_sidecar() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let credential_directory = tempfile::tempdir().unwrap();
    std::fs::write(
        credential_directory.path().join("active-age-identity"),
        ACTIVE_IDENTITY,
    )
    .unwrap();
    let store_directory = tempfile::tempdir().unwrap();
    let store = create_store(&store_directory.path().join("store.redb"), 7);
    let mut credential_input =
        SystemSecretInput::from_credentials_directory(Some(credential_directory.path().to_owned()));
    open_store_keyring(
        &store,
        &SecretSource::Credential("active-age-identity".into()),
        &mut credential_input,
        &KeyringOpener::default(),
    )
    .unwrap();
    assert!(!store_directory.path().join("active-age-identity").exists());

    let store_directory = tempfile::tempdir().unwrap();
    let store = create_store(&store_directory.path().join("store.redb"), 7);
    let (mut writer, reader) = UnixStream::pair().unwrap();
    writer.write_all(ACTIVE_IDENTITY.as_bytes()).unwrap();
    writer.shutdown(std::net::Shutdown::Write).unwrap();
    let mut fd_input = SystemSecretInput::from_credentials_directory(None);
    open_store_keyring(
        &store,
        &SecretSource::FileDescriptor(reader.as_raw_fd() as u32),
        &mut fd_input,
        &KeyringOpener::default(),
    )
    .unwrap();
}

#[test]
fn init_rejects_equal_recovery_recipient_before_store_creation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let active = x25519::Identity::from_str(ACTIVE_IDENTITY).unwrap();
    let mut input = Inputs::identity(ACTIVE_IDENTITY);
    assert_eq!(
        prepare_keyring_init_from_source(
            meta(7),
            &SecretSource::Stdin,
            &mut input,
            Some(&active.to_public()),
            &mut Counter(0),
        )
        .err()
        .unwrap(),
        KeyringInitSourceError::Keyring(KeyringError::RecipientSet)
    );
    assert!(!path.exists());
}

#[test]
fn transplanted_envelope_refuses_on_store_id_before_metadata() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let source = create_store(&first.path().join("store.redb"), 7);
    let target = create_store(&second.path().join("store.redb"), 8);
    target
        .put_keyring(&source.keyring().unwrap().unwrap())
        .unwrap();

    let mut input = Inputs::identity(ACTIVE_IDENTITY);
    assert_eq!(
        open_store_keyring(
            &target,
            &SecretSource::Stdin,
            &mut input,
            &KeyringOpener::default(),
        )
        .err()
        .unwrap(),
        KeyringBootError::Keyring(KeyringError::StoreMismatch)
    );
}

#[test]
fn corrupt_and_truncated_envelopes_fail_closed_without_secret_output() {
    let directory = tempfile::tempdir().unwrap();
    let store = create_store(&directory.path().join("store.redb"), 7);
    let metadata = store.keyring_metadata().unwrap().unwrap();
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let envelope = store.keyring().unwrap().unwrap();
    let mut edited = envelope.clone();
    let last = edited.0.len() - 1;
    edited.0[last] ^= 1;
    let truncated = ops_light_secrets_server::store::KeyringEnvelope(
        envelope.0[..envelope.0.len() - 1].to_vec(),
    );
    for candidate in [&edited, &truncated] {
        let error = KeyringOpener::default()
            .open(StoreId([7; 16]), candidate, &metadata, &identity)
            .err()
            .unwrap();
        assert_eq!(error, KeyringError::Decrypt);
        assert!(!error.to_string().contains(ACTIVE_IDENTITY));
    }
}

struct FailingRandom {
    calls: usize,
}

impl RandomSource for FailingRandom {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), KeyringError> {
        self.calls += 1;
        Err(KeyringError::Random)
    }
}

struct Sink<'a> {
    stream: &'a mut std::os::unix::net::UnixStream,
    limit: Option<usize>,
    written: usize,
    fail_flush: bool,
}

impl Write for Sink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.limit.is_some_and(|limit| self.written >= limit) {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "injected"));
        }
        let permitted = self
            .limit
            .map_or(bytes.len(), |limit| (limit - self.written).min(bytes.len()));
        let written = self.stream.write(&bytes[..permitted])?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected"));
        }
        self.stream.flush()
    }
}

impl AsFd for Sink<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

#[test]
fn stateless_identity_generation_keeps_private_bytes_only_in_approved_sink() {
    let (mut output, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let metadata = {
        let mut sink = Sink {
            stream: &mut output,
            limit: None,
            written: 0,
            fail_flush: false,
        };
        generate_age_identity(IdentityPurpose::Active, &mut sink, &mut Counter(40)).unwrap()
    };
    drop(output);
    let mut private = String::new();
    reader.read_to_string(&mut private).unwrap();
    assert!(private.starts_with("AGE-SECRET-KEY-1"));
    assert!(private.ends_with('\n'));
    assert_eq!(metadata.purpose, "active");
    assert_eq!(metadata.algorithm, "age-x25519");
    assert!(metadata.recipient.starts_with("age1"));
    assert_eq!(metadata.fingerprint.len(), 64);
    assert_eq!(metadata.sink_outcome_id.len(), 16);
    let public_json = serde_json::to_string(&metadata).unwrap();
    assert!(!public_json.contains("AGE-SECRET-KEY"));
    assert!(!public_json.contains(private.trim()));
}

#[test]
fn unknown_purpose_rng_unsafe_sink_and_short_write_have_stable_outcomes() {
    assert!(IdentityPurpose::from_str("unknown").is_err());

    let mut unsafe_file = tempfile::tempfile().unwrap();
    let mut random = FailingRandom { calls: 0 };
    assert_eq!(
        generate_age_identity(IdentityPurpose::Recovery, &mut unsafe_file, &mut random)
            .unwrap_err(),
        AgeIdentityError::UnsafeSink
    );
    assert_eq!(random.calls, 0, "sink validation must precede RNG");

    let (mut output, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut sink = Sink {
        stream: &mut output,
        limit: None,
        written: 0,
        fail_flush: false,
    };
    assert_eq!(
        generate_age_identity(IdentityPurpose::AuditExport, &mut sink, &mut random).unwrap_err(),
        AgeIdentityError::Random
    );

    let (mut output, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut sink = Sink {
        stream: &mut output,
        limit: Some(8),
        written: 0,
        fail_flush: false,
    };
    assert_eq!(
        generate_age_identity(IdentityPurpose::Active, &mut sink, &mut Counter(90)).unwrap_err(),
        AgeIdentityError::Disclosure
    );

    let (mut output, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut sink = Sink {
        stream: &mut output,
        limit: None,
        written: 0,
        fail_flush: true,
    };
    assert_eq!(
        generate_age_identity(IdentityPurpose::Active, &mut sink, &mut Counter(120)).unwrap_err(),
        AgeIdentityError::Disclosure
    );
}
