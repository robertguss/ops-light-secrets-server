//! Fail-closed startup admission and graceful-shutdown skeleton.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use axum::{Json, Router, routing::get};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::clock::{
    BootOverrideAudit, BootOverrideAuditError, ClockError, ClockMonitor, ClockReading,
};
use crate::config::Config;
use crate::proxy::is_loopback;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;
pub const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryState {
    Safe,
    UnsafeMode,
    UnsafeOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportState {
    Plaintext,
    Tls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaState {
    Current,
    OlderSupported(u32),
    Newer(u32),
    Unknown(u32),
    NoPath(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Ready,
    Reencrypting,
    Restoring,
    Migrating,
    Compacting,
}

impl LifecycleState {
    pub const NON_READY: [Self; 4] = [
        Self::Reencrypting,
        Self::Restoring,
        Self::Migrating,
        Self::Compacting,
    ];

    fn code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Reencrypting => "reencrypting",
            Self::Restoring => "restoring",
            Self::Migrating => "migrating",
            Self::Compacting => "compacting",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarkerState {
    None,
    Operation {
        lifecycle: LifecycleState,
        recovery_id: String,
    },
    Foreign,
}

impl MarkerState {
    pub fn operation(lifecycle: LifecycleState, recovery_id: &str) -> Result<Self, StartupRefusal> {
        if lifecycle == LifecycleState::Ready || !valid_opaque_id(recovery_id) {
            return Err(StartupRefusal::new(
                StartupCode::IntegrityFailure,
                "operation_marker",
                Detail::None,
            ));
        }
        Ok(Self::Operation {
            lifecycle,
            recovery_id: recovery_id.to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingAnchorKind {
    RecordKeyRotation,
    MetadataKeyRotation,
    AuditPayloadKeyRotation,
    Restore,
    Migration,
    Compaction,
}

impl PendingAnchorKind {
    pub const ALL: [Self; 6] = [
        Self::RecordKeyRotation,
        Self::MetadataKeyRotation,
        Self::AuditPayloadKeyRotation,
        Self::Restore,
        Self::Migration,
        Self::Compaction,
    ];

    fn code(self) -> &'static str {
        match self {
            Self::RecordKeyRotation => "record_key_rotation",
            Self::MetadataKeyRotation => "metadata_key_rotation",
            Self::AuditPayloadKeyRotation => "audit_payload_key_rotation",
            Self::Restore => "restore",
            Self::Migration => "migration",
            Self::Compaction => "compaction",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockState {
    Sound,
    BehindTolerance,
    ImplausiblyAhead,
}

struct RefuseOverrideAudit;

impl BootOverrideAudit for RefuseOverrideAudit {
    fn commit_boot_override(
        &mut self,
        _event: crate::clock::BootOverrideEvent,
    ) -> Result<(), BootOverrideAuditError> {
        Err(BootOverrideAuditError)
    }
}

pub fn assess_startup_clock(
    reading: ClockReading,
    persisted_high_water_unix_seconds: u64,
) -> ClockState {
    match ClockMonitor::boot(
        reading,
        persisted_high_water_unix_seconds,
        false,
        &mut RefuseOverrideAudit,
    ) {
        Ok(_) => ClockState::Sound,
        Err(ClockError::PersistedMarkImplausiblyAhead) => ClockState::ImplausiblyAhead,
        Err(_) => ClockState::BehindTolerance,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockState {
    Acquired,
    HeldByOther,
    Unsupported,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveState {
    Healthy,
    Released,
    RecreateRequested,
    Mismatch,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreIdentity {
    clear: [u8; 16],
    embedded: [u8; 16],
}

impl StoreIdentity {
    pub fn new(clear: [u8; 16], embedded: [u8; 16]) -> Self {
        Self { clear, embedded }
    }

    pub fn matching(identifier: [u8; 16]) -> Self {
        Self::new(identifier, identifier)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupSnapshot {
    pub key_material_configured: bool,
    pub initialized: bool,
    pub listener: SocketAddr,
    pub transport: TransportState,
    pub directory: DirectoryState,
    pub store_identity: StoreIdentity,
    pub schema: SchemaState,
    pub lifecycle: LifecycleState,
    pub marker: MarkerState,
    pub pending_anchor: Option<PendingAnchorKind>,
    pub clock: ClockState,
    pub lock: LockState,
    pub reserve: ReserveState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupCode {
    MissingKeyMaterial,
    UninitializedStore,
    RemotePlaintextListener,
    UnsafeDataDirectory,
    StoreKeyringMismatch,
    MigrationRequired,
    UnsupportedStoreVersion,
    LifecycleRecoveryRequired,
    LifecycleMarkerMismatch,
    OrphanOperationMarker,
    ClockUnsafe,
    DataLockUnavailable,
    ReserveRecoveryRequired,
    IntegrityFailure,
    ListenerBindFailed,
}

impl StartupCode {
    fn code(self) -> &'static str {
        match self {
            Self::MissingKeyMaterial => "missing_key_material",
            Self::UninitializedStore => "uninitialized_store",
            Self::RemotePlaintextListener => "remote_plaintext_listener",
            Self::UnsafeDataDirectory => "unsafe_data_directory",
            Self::StoreKeyringMismatch => "store_keyring_mismatch",
            Self::MigrationRequired => "migration_required",
            Self::UnsupportedStoreVersion => "unsupported_store_version",
            Self::LifecycleRecoveryRequired => "lifecycle_recovery_required",
            Self::LifecycleMarkerMismatch => "lifecycle_marker_mismatch",
            Self::OrphanOperationMarker => "orphan_operation_marker",
            Self::ClockUnsafe => "clock_unsafe",
            Self::DataLockUnavailable => "data_lock_unavailable",
            Self::ReserveRecoveryRequired => "reserve_recovery_required",
            Self::IntegrityFailure => "integrity_failure",
            Self::ListenerBindFailed => "listener_bind_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Detail {
    None,
    Migration {
        from: u32,
        to: u32,
    },
    Lifecycle {
        operation: &'static str,
        recovery_id: String,
    },
    PathDigest(String),
    ReserveRemediation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupRefusal {
    code: StartupCode,
    setting: &'static str,
    detail: Detail,
}

impl StartupRefusal {
    fn new(code: StartupCode, setting: &'static str, detail: Detail) -> Self {
        Self {
            code,
            setting,
            detail,
        }
    }

    pub fn code(&self) -> StartupCode {
        self.code
    }
}

impl fmt::Display for StartupRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "startup_refused code={} setting={}",
            self.code.code(),
            self.setting
        )?;
        match &self.detail {
            Detail::None => Ok(()),
            Detail::Migration { from, to } => {
                write!(
                    formatter,
                    " from={from} to={to} remediation=offline migrate"
                )
            }
            Detail::Lifecycle {
                operation,
                recovery_id,
            } => write!(
                formatter,
                " operation={operation} recovery_id={recovery_id}"
            ),
            Detail::PathDigest(digest) => write!(formatter, " path_digest={digest}"),
            Detail::ReserveRemediation => write!(
                formatter,
                " inspect='store reserve status' remediation='store reserve recreate'"
            ),
        }
    }
}

impl std::error::Error for StartupRefusal {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationClass {
    NormalTraffic,
    Diagnostics,
    CompleteAnchor(PendingAnchorKind),
    BackupReadOnly,
    EmergencyLever,
    BulkRewrite,
    Migration,
    Compaction,
    RestoreActivation,
    KeyJob,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupAdmission {
    pending_anchor: Option<PendingAnchorKind>,
}

impl StartupAdmission {
    pub fn warning(&self) -> Option<String> {
        self.pending_anchor.map(|kind| {
            format!(
                "ready_with_pending_anchor kind={} completion='checkpoint complete --kind {}'",
                kind.code(),
                kind.code()
            )
        })
    }

    pub fn operation_allowed(&self, operation: OperationClass) -> bool {
        let Some(anchor) = self.pending_anchor else {
            return true;
        };
        matches!(
            operation,
            OperationClass::NormalTraffic
                | OperationClass::Diagnostics
                | OperationClass::BackupReadOnly
                | OperationClass::EmergencyLever
        ) || operation == OperationClass::CompleteAnchor(anchor)
    }
}

pub fn validate_startup(snapshot: &StartupSnapshot) -> Result<StartupAdmission, StartupRefusal> {
    if !snapshot.key_material_configured {
        return Err(StartupRefusal::new(
            StartupCode::MissingKeyMaterial,
            "secrets.age_identity",
            Detail::None,
        ));
    }
    if !snapshot.initialized {
        return Err(StartupRefusal::new(
            StartupCode::UninitializedStore,
            "data.directory",
            Detail::None,
        ));
    }
    if !is_loopback(snapshot.listener.ip()) && snapshot.transport == TransportState::Plaintext {
        return Err(StartupRefusal::new(
            StartupCode::RemotePlaintextListener,
            "listener.transport",
            Detail::None,
        ));
    }
    if snapshot.directory != DirectoryState::Safe {
        return Err(StartupRefusal::new(
            StartupCode::UnsafeDataDirectory,
            "data.directory",
            Detail::None,
        ));
    }
    if snapshot.store_identity.clear != snapshot.store_identity.embedded {
        return Err(StartupRefusal::new(
            StartupCode::StoreKeyringMismatch,
            "store.id",
            Detail::None,
        ));
    }
    match snapshot.schema {
        SchemaState::Current => {}
        SchemaState::OlderSupported(from) => {
            return Err(StartupRefusal::new(
                StartupCode::MigrationRequired,
                "store.schema",
                Detail::Migration {
                    from,
                    to: CURRENT_SCHEMA_VERSION,
                },
            ));
        }
        SchemaState::Newer(_) | SchemaState::Unknown(_) | SchemaState::NoPath(_) => {
            return Err(StartupRefusal::new(
                StartupCode::UnsupportedStoreVersion,
                "store.schema",
                Detail::None,
            ));
        }
    }
    match (&snapshot.lifecycle, &snapshot.marker) {
        (_, MarkerState::Foreign) => {
            return Err(StartupRefusal::new(
                StartupCode::IntegrityFailure,
                "operation_marker",
                Detail::None,
            ));
        }
        (LifecycleState::Ready, MarkerState::Operation { .. }) => {
            return Err(StartupRefusal::new(
                StartupCode::OrphanOperationMarker,
                "operation_marker",
                Detail::None,
            ));
        }
        (LifecycleState::Ready, MarkerState::None) => {}
        (
            lifecycle,
            MarkerState::Operation {
                lifecycle: marked, ..
            },
        ) if lifecycle != marked => {
            return Err(StartupRefusal::new(
                StartupCode::LifecycleMarkerMismatch,
                "store.lifecycle",
                Detail::None,
            ));
        }
        (_, MarkerState::None) => {
            return Err(StartupRefusal::new(
                StartupCode::LifecycleMarkerMismatch,
                "store.lifecycle",
                Detail::None,
            ));
        }
        (lifecycle, MarkerState::Operation { recovery_id, .. }) => {
            return Err(StartupRefusal::new(
                StartupCode::LifecycleRecoveryRequired,
                "store.lifecycle",
                Detail::Lifecycle {
                    operation: lifecycle.code(),
                    recovery_id: recovery_id.clone(),
                },
            ));
        }
    }
    if snapshot.clock != ClockState::Sound {
        return Err(StartupRefusal::new(
            StartupCode::ClockUnsafe,
            "store.clock_high_water",
            Detail::None,
        ));
    }
    if snapshot.lock != LockState::Acquired {
        return Err(StartupRefusal::new(
            StartupCode::DataLockUnavailable,
            "data.lock",
            Detail::None,
        ));
    }
    match snapshot.reserve {
        ReserveState::Healthy => {}
        ReserveState::Released | ReserveState::RecreateRequested | ReserveState::Mismatch => {
            return Err(StartupRefusal::new(
                StartupCode::ReserveRecoveryRequired,
                "recovery.reserve",
                Detail::ReserveRemediation,
            ));
        }
        ReserveState::Unknown => {
            return Err(StartupRefusal::new(
                StartupCode::IntegrityFailure,
                "recovery.reserve",
                Detail::None,
            ));
        }
    }
    Ok(StartupAdmission {
        pending_anchor: snapshot.pending_anchor,
    })
}

/// Performs the startup checks available before the store adapter lands.
///
/// A safe directory is still reported as uninitialized: this seam never
/// guesses at a temporary store format or treats filesystem presence as proof
/// of a committed initialization transaction.
pub fn validate_serve_shell(config: &Config) -> Result<(), StartupRefusal> {
    if config.age_identity.is_none() {
        return Err(StartupRefusal::new(
            StartupCode::MissingKeyMaterial,
            "secrets.age_identity",
            Detail::None,
        ));
    }
    if config.data_directory.exists() {
        let state = inspect_data_directory(&config.data_directory)?;
        if state != DirectoryState::Safe {
            return Err(StartupRefusal::new(
                StartupCode::UnsafeDataDirectory,
                "data.directory",
                Detail::None,
            ));
        }
    }
    Err(StartupRefusal::new(
        StartupCode::UninitializedStore,
        "data.directory",
        Detail::None,
    ))
}

pub fn inspect_data_directory(path: &Path) -> Result<DirectoryState, StartupRefusal> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => continue,
            _ => current.push(component.as_os_str()),
        }
        if current.as_os_str().is_empty() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| path_refusal(path))?;
        if metadata.file_type().is_symlink() {
            return Err(path_refusal(path));
        }
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| path_refusal(path))?;
    if !metadata.is_dir() {
        return Err(path_refusal(path));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Ok(DirectoryState::UnsafeOwner);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Ok(DirectoryState::UnsafeMode);
    }
    Ok(DirectoryState::Safe)
}

fn path_refusal(path: &Path) -> StartupRefusal {
    let digest = blake3::hash(path.as_os_str().as_bytes()).to_hex()[..16].to_owned();
    StartupRefusal::new(
        StartupCode::UnsafeDataDirectory,
        "data.directory",
        Detail::PathDigest(digest),
    )
}

#[derive(Debug)]
pub struct DataDirectoryLock {
    _file: File,
}

impl DataDirectoryLock {
    pub fn acquire(directory: &Path) -> Result<Self, StartupRefusal> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(directory.join(".ops-light-secrets-server.lock"))
            .map_err(|_| lock_refusal())?;
        let metadata = file.metadata().map_err(|_| lock_refusal())?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(lock_refusal());
        }
        let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if status != 0 {
            return Err(lock_refusal());
        }
        Ok(Self { _file: file })
    }
}

fn lock_refusal() -> StartupRefusal {
    StartupRefusal::new(StartupCode::DataLockUnavailable, "data.lock", Detail::None)
}

pub async fn bind_validated(
    snapshot: &StartupSnapshot,
    address: SocketAddr,
) -> Result<TcpListener, StartupRefusal> {
    validate_startup(snapshot)?;
    TcpListener::bind(address).await.map_err(|_| {
        StartupRefusal::new(
            StartupCode::ListenerBindFailed,
            "listener.address",
            Detail::None,
        )
    })
}

#[derive(Serialize)]
struct Health {
    initialized: bool,
    sealed: bool,
    standby: bool,
}

pub async fn serve_health<F>(listener: TcpListener, shutdown: F) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let application = Router::new().route(
        "/v1/sys/health",
        get(|| async {
            Json(Health {
                initialized: true,
                sealed: false,
                standby: false,
            })
        }),
    );
    axum::serve(listener, application)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(std::io::Error::other)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DrainResult {
    #[default]
    Drained,
    Deadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownTrigger {
    FirstSignal,
    SecondSignal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownHookError;

pub trait ShutdownHooks {
    /// Stops admission and cancels queued work that has not begun.
    fn stop_admission_and_cancel_queued(&mut self);
    /// Lets begun transactions complete only inside the supplied deadline.
    fn drain_begun(&mut self, deadline: Duration) -> DrainResult;
    fn flush(&mut self) -> Result<(), ShutdownHookError>;
    fn commit_unsigned_shutdown(&mut self) -> Result<(), ShutdownHookError>;
    fn mark_unclean(&mut self);
    fn zeroize_keys(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    pub exit_status: i32,
    pub clean_marker: bool,
}

pub fn run_shutdown<H: ShutdownHooks>(hooks: &mut H, trigger: ShutdownTrigger) -> ShutdownReport {
    hooks.stop_admission_and_cancel_queued();
    if trigger == ShutdownTrigger::SecondSignal {
        hooks.mark_unclean();
        hooks.zeroize_keys();
        return ShutdownReport {
            exit_status: 130,
            clean_marker: false,
        };
    }
    if hooks.drain_begun(DRAIN_DEADLINE) == DrainResult::Deadline {
        hooks.mark_unclean();
        hooks.zeroize_keys();
        return ShutdownReport {
            exit_status: 75,
            clean_marker: false,
        };
    }
    if hooks.flush().is_err() || hooks.commit_unsigned_shutdown().is_err() {
        hooks.mark_unclean();
        hooks.zeroize_keys();
        return ShutdownReport {
            exit_status: 75,
            clean_marker: false,
        };
    }
    hooks.zeroize_keys();
    ShutdownReport {
        exit_status: 0,
        clean_marker: true,
    }
}

fn valid_opaque_id(value: &str) -> bool {
    (16..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
