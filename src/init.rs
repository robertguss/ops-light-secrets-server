//! Failure-safe local initialization frame.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, Metadata};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::config::{SecretInput, SecretSource};
use crate::startup::{DataDirectoryLock, DirectoryState, inspect_data_directory};
use crate::store::keyring::parse_identity;
use crate::store::keyring::{
    KeyringError, PreparedKeyring, RandomSource, prepare_keyring_for_init,
};
use crate::store::{MetaRecord, ProvisionalMetaRecord, Store, StoreError};
use age::x25519;

pub const MIN_BOOTSTRAP_TTL: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_BOOTSTRAP_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const ROLLOVER_NEXT_STEP: &str = "issue a labeled bounded control token; verify it on an authenticated control command; revoke the bootstrap accessor";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapTtl(Duration);

impl BootstrapTtl {
    pub fn new(value: Duration) -> Result<Self, InitError> {
        if !(MIN_BOOTSTRAP_TTL..=MAX_BOOTSTRAP_TTL).contains(&value) {
            return Err(InitError::new(InitCode::InvalidBootstrapTtl));
        }
        Ok(Self(value))
    }

    pub fn duration(self) -> Duration {
        self.0
    }
}

impl Default for BootstrapTtl {
    fn default() -> Self {
        Self(DEFAULT_BOOTSTRAP_TTL)
    }
}

pub fn parse_bootstrap_ttl(value: &str) -> Result<BootstrapTtl, InitError> {
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b'm') => (&value[..value.len() - 1], 60_u64),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        _ => (value, 1),
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|_| InitError::new(InitCode::InvalidBootstrapTtl))?;
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| InitError::new(InitCode::InvalidBootstrapTtl))?;
    BootstrapTtl::new(Duration::from_secs(seconds))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitCode {
    LockUnavailable,
    UnsafeDataDirectory,
    UnsafeCredentialSink,
    InvalidBootstrapTtl,
    ForeignArtifact,
    ArtifactRace,
    AlreadyInitialized,
    AuditFailed,
    PreparationFailed,
    DisclosureFailed,
    CommitFailed,
}

impl InitCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::LockUnavailable => "lock_unavailable",
            Self::UnsafeDataDirectory => "unsafe_data_directory",
            Self::UnsafeCredentialSink => "unsafe_credential_sink",
            Self::InvalidBootstrapTtl => "invalid_bootstrap_ttl",
            Self::ForeignArtifact => "foreign_artifact",
            Self::ArtifactRace => "artifact_race",
            Self::AlreadyInitialized => "already_initialized",
            Self::AuditFailed => "audit_failed",
            Self::PreparationFailed => "preparation_failed",
            Self::DisclosureFailed => "disclosure_failed",
            Self::CommitFailed => "commit_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitError {
    code: InitCode,
    foreign: Option<ForeignArtifact>,
}

impl InitError {
    fn new(code: InitCode) -> Self {
        Self {
            code,
            foreign: None,
        }
    }

    fn foreign(detail: ForeignArtifact) -> Self {
        Self {
            code: InitCode::ForeignArtifact,
            foreign: Some(detail),
        }
    }

    pub fn code(&self) -> InitCode {
        self.code
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "init_refused code={}", self.code.as_str())?;
        if let Some(detail) = &self.foreign {
            write!(
                formatter,
                " kind={} artifact_id={} name_digest={} count={} remediation='inspect local data directory'",
                detail.kind.as_str(),
                detail.artifact_id,
                detail.name_digest,
                detail.count
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for InitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    File,
    Directory,
    Symlink,
    Other,
}

impl ArtifactKind {
    fn from(metadata: &Metadata) -> Self {
        if metadata.file_type().is_symlink() {
            Self::Symlink
        } else if metadata.is_file() {
            Self::File
        } else if metadata.is_dir() {
            Self::Directory
        } else {
            Self::Other
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ForeignArtifact {
    kind: ArtifactKind,
    artifact_id: String,
    name_digest: String,
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactDisposition {
    UncommittedStore,
    InitializedStore,
    ValidReserveArtifact,
    Foreign,
}

pub struct PreparedInit<T> {
    pub credential: Zeroizing<Vec<u8>>,
    pub expires_at_unix: u64,
    pub transaction: T,
}

pub struct KeyringInitTransaction {
    meta: MetaRecord,
    prepared: PreparedKeyring,
}

impl KeyringInitTransaction {
    pub fn prepare(
        meta: MetaRecord,
        active_identity: &x25519::Identity,
        recovery_recipient: Option<&x25519::Recipient>,
        random: &mut impl RandomSource,
    ) -> Result<Self, KeyringError> {
        let prepared = prepare_keyring_for_init(
            ProvisionalMetaRecord::from_meta(&meta),
            1,
            active_identity,
            recovery_recipient,
            random,
        )?;
        Ok(Self { meta, prepared })
    }

    pub fn commit(self, path: impl AsRef<Path>) -> Result<Store, StoreError> {
        Store::create_with_keyring(path, &self.meta, &self.prepared)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyringInitSourceError {
    IdentitySource,
    Keyring(KeyringError),
}

impl fmt::Display for KeyringInitSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentitySource => "init age identity source failed",
            Self::Keyring(_) => "init keyring preparation failed",
        })
    }
}

impl std::error::Error for KeyringInitSourceError {}

/// Prepares the keyring portion of U1.2's outer staged transaction. No store
/// bytes are created until `KeyringInitTransaction::commit` joins the atomic
/// redb creation transaction.
pub fn prepare_keyring_init_from_source<I: SecretInput>(
    meta: MetaRecord,
    active_source: &SecretSource,
    input: &mut I,
    recovery_recipient: Option<&x25519::Recipient>,
    random: &mut impl RandomSource,
) -> Result<KeyringInitTransaction, KeyringInitSourceError> {
    let bytes = active_source
        .read("secrets.age_identity", input)
        .map_err(|_| KeyringInitSourceError::IdentitySource)?;
    let identity =
        parse_identity(bytes.into_zeroizing()).map_err(KeyringInitSourceError::Keyring)?;
    KeyringInitTransaction::prepare(meta, &identity, recovery_recipient, random)
        .map_err(KeyringInitSourceError::Keyring)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitBackendError;

pub trait InitBackend {
    type Transaction;

    fn inspect_artifact(&mut self, name: &OsStr, metadata: &Metadata) -> ArtifactDisposition;
    fn audit_initialized_refusal(&mut self) -> Result<(), InitBackendError>;
    /// Generates and self-tests the active-recipient envelope, then stages the
    /// store id, schema, keyring, audit genesis, identity, grant, and verifier.
    fn prepare(
        &mut self,
        ttl: BootstrapTtl,
    ) -> Result<PreparedInit<Self::Transaction>, InitBackendError>;
    fn commit(&mut self, transaction: Self::Transaction) -> Result<(), InitBackendError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitReceipt {
    pub expires_at_unix: u64,
    pub rollover_next_step: &'static str,
}

pub fn initialize<B: InitBackend, W: Write + AsFd>(
    directory: &Path,
    sink: &mut W,
    backend: &mut B,
    ttl: BootstrapTtl,
    diagnostic_key: &[u8; 32],
) -> Result<InitReceipt, InitError> {
    if inspect_data_directory(directory)
        .map_err(|_| InitError::new(InitCode::UnsafeDataDirectory))?
        != DirectoryState::Safe
    {
        return Err(InitError::new(InitCode::UnsafeDataDirectory));
    }
    let _lock = DataDirectoryLock::acquire(directory)
        .map_err(|_| InitError::new(InitCode::LockUnavailable))?;
    inspect_init_directory(directory, backend, diagnostic_key)?;
    validate_secret_sink(sink.as_fd())?;

    let prepared = backend
        .prepare(ttl)
        .map_err(|_| InitError::new(InitCode::PreparationFailed))?;
    sink.write_all(&prepared.credential)
        .and_then(|()| sink.write_all(b"\n"))
        .and_then(|()| sink.flush())
        .map_err(|_| InitError::new(InitCode::DisclosureFailed))?;
    let receipt = InitReceipt {
        expires_at_unix: prepared.expires_at_unix,
        rollover_next_step: ROLLOVER_NEXT_STEP,
    };
    backend
        .commit(prepared.transaction)
        .map_err(|_| InitError::new(InitCode::CommitFailed))?;
    Ok(receipt)
}

fn inspect_init_directory<B: InitBackend>(
    directory: &Path,
    backend: &mut B,
    key: &[u8; 32],
) -> Result<(), InitError> {
    let mut foreign_count = 0_usize;
    let mut first_foreign = None;
    let mut initialized = false;
    for entry in fs::read_dir(directory).map_err(|_| InitError::new(InitCode::ArtifactRace))? {
        let entry = entry.map_err(|_| InitError::new(InitCode::ArtifactRace))?;
        let name = entry.file_name();
        if name == OsStr::new(".ops-light-secrets-server.lock") {
            continue;
        }
        let before = fs::symlink_metadata(entry.path())
            .map_err(|_| InitError::new(InitCode::ArtifactRace))?;
        let disposition = if before.file_type().is_symlink() || before.nlink() != 1 {
            ArtifactDisposition::Foreign
        } else {
            backend.inspect_artifact(&name, &before)
        };
        let after = fs::symlink_metadata(entry.path())
            .map_err(|_| InitError::new(InitCode::ArtifactRace))?;
        if changed(&before, &after) {
            return Err(InitError::new(InitCode::ArtifactRace));
        }
        match disposition {
            ArtifactDisposition::UncommittedStore | ArtifactDisposition::ValidReserveArtifact => {}
            ArtifactDisposition::InitializedStore => initialized = true,
            ArtifactDisposition::Foreign => {
                foreign_count = foreign_count.saturating_add(1).min(999);
                if first_foreign.is_none() {
                    first_foreign = Some(foreign_detail(&name, &before, key, 0));
                }
            }
        }
    }
    if let Some(mut detail) = first_foreign {
        detail.count = foreign_count;
        return Err(InitError::foreign(detail));
    }
    if initialized {
        backend
            .audit_initialized_refusal()
            .map_err(|_| InitError::new(InitCode::AuditFailed))?;
        return Err(InitError::new(InitCode::AlreadyInitialized));
    }
    Ok(())
}

fn changed(before: &Metadata, after: &Metadata) -> bool {
    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
}

fn foreign_detail(
    name: &OsStr,
    metadata: &Metadata,
    key: &[u8; 32],
    count: usize,
) -> ForeignArtifact {
    let mut artifact = blake3::Hasher::new_keyed(key);
    artifact.update(b"init-artifact-id\0");
    artifact.update(&metadata.dev().to_le_bytes());
    artifact.update(&metadata.ino().to_le_bytes());
    let mut digest = blake3::Hasher::new_keyed(key);
    digest.update(b"init-name-digest\0");
    digest.update(name.as_bytes());
    ForeignArtifact {
        kind: ArtifactKind::from(metadata),
        artifact_id: artifact.finalize().to_hex()[..16].to_owned(),
        name_digest: digest.finalize().to_hex()[..16].to_owned(),
        count,
    }
}

pub fn validate_secret_sink(fd: BorrowedFd<'_>) -> Result<(), InitError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(InitError::new(InitCode::UnsafeCredentialSink));
    }
    let status = unsafe { status.assume_init() };
    let kind = status.st_mode & libc::S_IFMT;
    let safe_stream = matches!(kind, libc::S_IFCHR | libc::S_IFIFO | libc::S_IFSOCK);
    let anonymous_memory =
        kind == libc::S_IFREG && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) } >= 0;
    if !safe_stream && !anonymous_memory {
        return Err(InitError::new(InitCode::UnsafeCredentialSink));
    }
    Ok(())
}
