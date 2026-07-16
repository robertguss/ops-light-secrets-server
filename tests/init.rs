use std::ffi::{OsStr, OsString};
use std::fs::{self, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;

use ops_light_secrets_server::init::{
    ArtifactDisposition, BootstrapTtl, DEFAULT_BOOTSTRAP_TTL, InitBackend, InitBackendError,
    InitCode, MAX_BOOTSTRAP_TTL, MIN_BOOTSTRAP_TTL, PreparedInit, ROLLOVER_NEXT_STEP, initialize,
    parse_bootstrap_ttl,
};
use zeroize::Zeroizing;

const KEY: [u8; 32] = [0x51; 32];

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[derive(Default)]
struct SpyBackend {
    events: Vec<&'static str>,
    initialized: bool,
    commit_fails: bool,
    prepare_fails: bool,
}

impl InitBackend for SpyBackend {
    type Transaction = ();

    fn inspect_artifact(&mut self, name: &OsStr, _: &Metadata) -> ArtifactDisposition {
        match name.to_str() {
            Some("store.redb") if self.initialized => ArtifactDisposition::InitializedStore,
            Some("store.redb") => ArtifactDisposition::UncommittedStore,
            Some("recovery.reserve") | Some(".recovery.reserve.init") => {
                ArtifactDisposition::ValidReserveArtifact
            }
            _ => ArtifactDisposition::Foreign,
        }
    }

    fn audit_initialized_refusal(&mut self) -> Result<(), InitBackendError> {
        self.events.push("audit-refusal");
        Ok(())
    }

    fn prepare(
        &mut self,
        _: BootstrapTtl,
    ) -> Result<PreparedInit<Self::Transaction>, InitBackendError> {
        self.events.push("prepare-self-test-stage");
        if self.prepare_fails {
            return Err(InitBackendError);
        }
        Ok(PreparedInit {
            credential: Zeroizing::new(b"disclosed-once".to_vec()),
            expires_at_unix: 1_800_000_000,
            transaction: (),
        })
    }

    fn commit(&mut self, _: Self::Transaction) -> Result<(), InitBackendError> {
        self.events.push("commit");
        if self.commit_fails {
            Err(InitBackendError)
        } else {
            Ok(())
        }
    }
}

struct RecordingWriter<'a> {
    stream: &'a mut UnixStream,
    events: &'a mut Vec<&'static str>,
}

impl Write for RecordingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.events.push("write");
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.events.push("flush");
        self.stream.flush()
    }
}

impl AsFd for RecordingWriter<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

#[test]
fn disclosure_is_flushed_before_commit_and_receipt_is_finite() {
    let directory = private_directory();
    let (mut output, mut reader) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let mut writer_events = Vec::new();
    let mut writer = RecordingWriter {
        stream: &mut output,
        events: &mut writer_events,
    };
    let mut backend = SpyBackend::default();

    let receipt = initialize(
        directory.path(),
        &mut writer,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap();

    let mut disclosed = String::new();
    reader.read_to_string(&mut disclosed).ok();
    assert_eq!(disclosed, "disclosed-once\n");
    assert_eq!(writer_events, ["write", "write", "flush"]);
    assert_eq!(backend.events, ["prepare-self-test-stage", "commit"]);
    assert_eq!(receipt.expires_at_unix, 1_800_000_000);
    assert_eq!(receipt.rollover_next_step, ROLLOVER_NEXT_STEP);
    assert!(receipt.rollover_next_step.contains("issue"));
    assert!(receipt.rollover_next_step.contains("verify"));
    assert!(receipt.rollover_next_step.contains("revoke"));
}

#[test]
fn unsafe_or_broken_sink_never_prepares_or_commits_and_retry_succeeds() {
    let directory = private_directory();
    let mut regular = tempfile::tempfile().unwrap();
    let mut backend = SpyBackend::default();
    let error = initialize(
        directory.path(),
        &mut regular,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::UnsafeCredentialSink);
    assert!(backend.events.is_empty());

    struct Broken(UnixStream);
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl AsFd for Broken {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }
    let (stream, _peer) = UnixStream::pair().unwrap();
    let mut broken = Broken(stream);
    let error = initialize(
        directory.path(),
        &mut broken,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::DisclosureFailed);
    assert_eq!(backend.events, ["prepare-self-test-stage"]);

    backend.events.clear();
    let (mut stream, _peer) = UnixStream::pair().unwrap();
    initialize(
        directory.path(),
        &mut stream,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap();
    assert_eq!(backend.events, ["prepare-self-test-stage", "commit"]);
}

#[test]
fn unsafe_data_directory_refuses_before_lock_or_preparation() {
    let directory = private_directory();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
    let (mut output, _reader) = UnixStream::pair().unwrap();
    let mut backend = SpyBackend::default();
    let error = initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::UnsafeDataDirectory);
    assert!(backend.events.is_empty());
    assert!(
        !directory
            .path()
            .join(".ops-light-secrets-server.lock")
            .exists()
    );
}

#[test]
fn commit_failure_happens_after_disclosure_and_leaves_retryable_artifacts() {
    let directory = private_directory();
    fs::write(directory.path().join("store.redb"), b"uncommitted").unwrap();
    fs::write(
        directory.path().join(".recovery.reserve.init"),
        b"allocated",
    )
    .unwrap();
    let (mut output, mut reader) = UnixStream::pair().unwrap();
    let mut backend = SpyBackend {
        commit_fails: true,
        ..SpyBackend::default()
    };
    let error = initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::CommitFailed);
    let mut credential = [0_u8; 15];
    reader.read_exact(&mut credential).unwrap();
    assert_eq!(&credential, b"disclosed-once\n");

    backend.commit_fails = false;
    let (mut output, _reader) = UnixStream::pair().unwrap();
    initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap();
}

#[test]
fn initialized_store_refusal_is_audited_only_after_lock() {
    let directory = private_directory();
    fs::write(directory.path().join("store.redb"), b"initialized").unwrap();
    let (mut output, _reader) = UnixStream::pair().unwrap();
    let mut backend = SpyBackend {
        initialized: true,
        ..SpyBackend::default()
    };
    let error = initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::AlreadyInitialized);
    assert_eq!(backend.events, ["audit-refusal"]);
}

#[test]
fn foreign_names_are_never_rendered_and_diagnostics_are_bounded() {
    let directory = private_directory();
    let hostile = OsString::from_vec(b"RAW_CREDENTIAL_CANARY_91af\n\xff".to_vec());
    fs::write(directory.path().join(&hostile), b"foreign").unwrap();
    fs::create_dir(directory.path().join("lost+found")).unwrap();
    let (mut output, _reader) = UnixStream::pair().unwrap();
    let mut backend = SpyBackend::default();
    let error = initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    let rendered = error.to_string();
    assert_eq!(error.code(), InitCode::ForeignArtifact);
    assert!(rendered.contains("kind="));
    assert!(rendered.contains("artifact_id="));
    assert!(rendered.contains("name_digest="));
    assert!(rendered.contains("count=2"));
    assert!(!rendered.contains("RAW_CREDENTIAL"));
    assert!(!rendered.contains("lost+found"));
    assert!(!rendered.contains('\n'));
    assert!(backend.events.is_empty());
}

#[test]
fn symlink_hardlink_and_rename_race_fail_closed_without_names() {
    for kind in ["symlink", "hardlink"] {
        let directory = private_directory();
        let target = directory.path().join("target-canary");
        fs::write(&target, b"foreign").unwrap();
        if kind == "symlink" {
            symlink(&target, directory.path().join("SYMLINK_RAW_CANARY")).unwrap();
        } else {
            fs::hard_link(&target, directory.path().join("HARDLINK_RAW_CANARY")).unwrap();
        }
        let (mut output, _reader) = UnixStream::pair().unwrap();
        let mut backend = SpyBackend::default();
        let rendered = initialize(
            directory.path(),
            &mut output,
            &mut backend,
            BootstrapTtl::default(),
            &KEY,
        )
        .unwrap_err()
        .to_string();
        assert!(!rendered.contains("RAW_CANARY"));
        assert!(rendered.contains("foreign_artifact"));
    }

    struct RacingBackend(std::path::PathBuf);
    impl InitBackend for RacingBackend {
        type Transaction = ();
        fn inspect_artifact(&mut self, _: &OsStr, _: &Metadata) -> ArtifactDisposition {
            fs::rename(&self.0, self.0.with_extension("moved")).unwrap();
            ArtifactDisposition::UncommittedStore
        }
        fn audit_initialized_refusal(&mut self) -> Result<(), InitBackendError> {
            Ok(())
        }
        fn prepare(&mut self, _: BootstrapTtl) -> Result<PreparedInit<()>, InitBackendError> {
            unreachable!()
        }
        fn commit(&mut self, _: ()) -> Result<(), InitBackendError> {
            unreachable!()
        }
    }
    let directory = private_directory();
    let path = directory.path().join("race-raw-canary");
    fs::write(&path, b"uncommitted").unwrap();
    let (mut output, _reader) = UnixStream::pair().unwrap();
    let mut backend = RacingBackend(path);
    let error = initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::ArtifactRace);
    assert!(!error.to_string().contains("race-raw-canary"));
}

#[test]
fn ttl_boundaries_and_overflow_are_frozen() {
    assert_eq!(BootstrapTtl::default().duration(), DEFAULT_BOOTSTRAP_TTL);
    assert_eq!(
        parse_bootstrap_ttl("5m").unwrap().duration(),
        MIN_BOOTSTRAP_TTL
    );
    assert_eq!(
        parse_bootstrap_ttl("24h").unwrap().duration(),
        DEFAULT_BOOTSTRAP_TTL
    );
    assert_eq!(
        parse_bootstrap_ttl("7d").unwrap().duration(),
        MAX_BOOTSTRAP_TTL
    );
    for invalid in ["0", "299", "8d", "18446744073709551615d", "forever"] {
        assert_eq!(
            parse_bootstrap_ttl(invalid).unwrap_err().code(),
            InitCode::InvalidBootstrapTtl
        );
    }
}

struct BlockingBackend {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
}

impl InitBackend for BlockingBackend {
    type Transaction = ();
    fn inspect_artifact(&mut self, _: &OsStr, _: &Metadata) -> ArtifactDisposition {
        ArtifactDisposition::Foreign
    }
    fn audit_initialized_refusal(&mut self) -> Result<(), InitBackendError> {
        Ok(())
    }
    fn prepare(&mut self, _: BootstrapTtl) -> Result<PreparedInit<()>, InitBackendError> {
        self.entered.take().unwrap().send(()).unwrap();
        self.release.recv().unwrap();
        Ok(PreparedInit {
            credential: Zeroizing::new(b"first".to_vec()),
            expires_at_unix: 1,
            transaction: (),
        })
    }
    fn commit(&mut self, _: ()) -> Result<(), InitBackendError> {
        Ok(())
    }
}

#[test]
fn concurrent_initializers_admit_exactly_one() {
    let directory = private_directory();
    let path = directory.path().to_owned();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first = std::thread::spawn(move || {
        let (mut output, _reader) = UnixStream::pair().unwrap();
        let mut backend = BlockingBackend {
            entered: Some(entered_tx),
            release: release_rx,
        };
        initialize(
            &path,
            &mut output,
            &mut backend,
            BootstrapTtl::default(),
            &KEY,
        )
    });
    entered_rx.recv().unwrap();

    let (mut output, _reader) = UnixStream::pair().unwrap();
    let mut second = SpyBackend::default();
    let error = initialize(
        directory.path(),
        &mut output,
        &mut second,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::LockUnavailable);
    assert!(second.events.is_empty());
    release_tx.send(()).unwrap();
    first.join().unwrap().unwrap();
}

#[test]
fn preparation_self_test_failure_discloses_nothing() {
    let directory = private_directory();
    let (mut output, mut reader) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let mut backend = SpyBackend {
        prepare_fails: true,
        ..SpyBackend::default()
    };
    let error = initialize(
        directory.path(),
        &mut output,
        &mut backend,
        BootstrapTtl::default(),
        &KEY,
    )
    .unwrap_err();
    assert_eq!(error.code(), InitCode::PreparationFailed);
    let mut buffer = [0_u8; 1];
    assert_eq!(
        reader.read(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(backend.events, ["prepare-self-test-stage"]);
}
