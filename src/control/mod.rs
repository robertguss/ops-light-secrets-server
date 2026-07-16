//! Owner-only control-plane listener and router separation.

use axum::serve::Listener;
use axum::{Json, Router, routing::get};
use serde::Serialize;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

const SOCKET_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE_MASK: u32 = 0o077;
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Router reachable by remote data-plane transports.
pub fn data_router() -> Router {
    Router::new().route("/v1/sys/health", get(health))
}

/// Router reachable only through the owner control socket.
pub fn control_router() -> Router {
    Router::new()
        .route("/v1/sys/health", get(health))
        .route("/v1/sys/control/status", get(control_status))
}

#[derive(Serialize)]
struct Health {
    initialized: bool,
    sealed: bool,
}

async fn health() -> Json<Health> {
    Json(Health {
        initialized: false,
        sealed: true,
    })
}

#[derive(Serialize)]
struct ControlStatus {
    control_plane: &'static str,
}

async fn control_status() -> Json<ControlStatus> {
    Json(ControlStatus {
        control_plane: "ready",
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRefusalReason {
    CredentialUnavailable,
    WrongOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerRefusal {
    pub expected_uid: u32,
    pub observed_uid: Option<u32>,
    pub reason: PeerRefusalReason,
}

/// Required audit seam for rejected kernel peer credentials.
pub trait PeerAudit: Send + Sync + 'static {
    fn peer_refused(&self, refusal: PeerRefusal);
}

#[derive(Debug, Eq, PartialEq)]
pub enum ControlSocketError {
    ParentUnavailable,
    ParentNotDirectory,
    ParentWrongOwner,
    ParentPermissions,
    PathSymlink,
    PathWrongType,
    PathWrongOwner,
    PathPermissions,
    ActiveListener,
    PathChanged,
    Bind,
    Verify,
}

impl fmt::Display for ControlSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::ParentUnavailable => "control socket parent unavailable",
            Self::ParentNotDirectory => "control socket parent is not a directory",
            Self::ParentWrongOwner => "control socket parent has wrong owner",
            Self::ParentPermissions => "control socket parent is not owner-only",
            Self::PathSymlink => "control socket path is a symlink",
            Self::PathWrongType => "control socket path has wrong type",
            Self::PathWrongOwner => "control socket path has wrong owner",
            Self::PathPermissions => "control socket path is not owner-only",
            Self::ActiveListener => "control socket already has an active listener",
            Self::PathChanged => "control socket path changed during stale cleanup",
            Self::Bind => "control socket bind failed",
            Self::Verify => "control socket post-bind verification failed",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for ControlSocketError {}

/// Bound socket whose inode is removed only if it is still the one we created.
pub struct ControlSocket {
    listener: Option<OwnerListener>,
    cleanup: SocketInode,
}

impl ControlSocket {
    pub fn bind(
        path: impl AsRef<Path>,
        expected_uid: u32,
        audit: Arc<dyn PeerAudit>,
    ) -> Result<Self, ControlSocketError> {
        let path = path.as_ref();
        validate_parent(path, expected_uid)?;
        reconcile_existing(path, expected_uid)?;

        let _umask_guard = UMASK_LOCK.lock().map_err(|_| ControlSocketError::Bind)?;
        let old_umask = unsafe { libc::umask(0o077) };
        let bound = UnixListener::bind(path);
        unsafe { libc::umask(old_umask) };
        drop(_umask_guard);
        let listener = bound.map_err(|_| ControlSocketError::Bind)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|_| ControlSocketError::Verify)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| ControlSocketError::Verify)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != expected_uid
            || metadata.permissions().mode() & 0o777 != SOCKET_MODE
        {
            let _ = fs::remove_file(path);
            return Err(ControlSocketError::Verify);
        }

        Ok(Self {
            listener: Some(OwnerListener {
                inner: listener,
                expected_uid,
                audit,
            }),
            cleanup: SocketInode::new(path.to_owned(), &metadata),
        })
    }

    pub async fn serve(mut self) -> io::Result<()> {
        let listener = self.listener.take().expect("listener consumed once");
        let result = axum::serve(listener, control_router()).await;
        drop(self.cleanup);
        result
    }
}

fn validate_parent(path: &Path, expected_uid: u32) -> Result<(), ControlSocketError> {
    let parent = path.parent().ok_or(ControlSocketError::ParentUnavailable)?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| ControlSocketError::ParentUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControlSocketError::ParentNotDirectory);
    }
    if metadata.uid() != expected_uid {
        return Err(ControlSocketError::ParentWrongOwner);
    }
    if metadata.permissions().mode() & PRIVATE_DIRECTORY_MODE_MASK != 0 {
        return Err(ControlSocketError::ParentPermissions);
    }
    Ok(())
}

fn reconcile_existing(path: &Path, expected_uid: u32) -> Result<(), ControlSocketError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ControlSocketError::Bind),
    };
    if metadata.file_type().is_symlink() {
        return Err(ControlSocketError::PathSymlink);
    }
    if !metadata.file_type().is_socket() {
        return Err(ControlSocketError::PathWrongType);
    }
    if metadata.uid() != expected_uid {
        return Err(ControlSocketError::PathWrongOwner);
    }
    if metadata.permissions().mode() & 0o777 != SOCKET_MODE {
        return Err(ControlSocketError::PathPermissions);
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => return Err(ControlSocketError::ActiveListener),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(_) => return Err(ControlSocketError::ActiveListener),
    }
    let current = fs::symlink_metadata(path).map_err(|_| ControlSocketError::PathChanged)?;
    if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
        return Err(ControlSocketError::PathChanged);
    }
    fs::remove_file(path).map_err(|_| ControlSocketError::PathChanged)
}

struct OwnerListener {
    inner: UnixListener,
    expected_uid: u32,
    audit: Arc<dyn PeerAudit>,
}

impl Listener for OwnerListener {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, address)) => {
                    let observed_uid = stream.peer_cred().ok().map(|credentials| credentials.uid());
                    if peer_allowed(self.expected_uid, observed_uid, self.audit.as_ref()) {
                        return (stream, address);
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn peer_allowed(expected_uid: u32, observed_uid: Option<u32>, audit: &dyn PeerAudit) -> bool {
    if observed_uid == Some(expected_uid) {
        return true;
    }
    audit.peer_refused(PeerRefusal {
        expected_uid,
        observed_uid,
        reason: if observed_uid.is_some() {
            PeerRefusalReason::WrongOwner
        } else {
            PeerRefusalReason::CredentialUnavailable
        },
    });
    false
}

struct SocketInode {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketInode {
    fn new(path: PathBuf, metadata: &fs::Metadata) -> Self {
        Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl Drop for SocketInode {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.file_type().is_socket()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingAudit(Mutex<Vec<PeerRefusal>>);

    impl PeerAudit for RecordingAudit {
        fn peer_refused(&self, refusal: PeerRefusal) {
            self.0.lock().expect("audit lock").push(refusal);
        }
    }

    #[test]
    fn wrong_and_unknown_peers_are_rejected_and_audited() {
        let audit = RecordingAudit::default();
        assert!(!peer_allowed(1000, Some(1001), &audit));
        assert!(!peer_allowed(1000, None, &audit));
        assert!(peer_allowed(1000, Some(1000), &audit));
        assert_eq!(
            *audit.0.lock().expect("audit lock"),
            vec![
                PeerRefusal {
                    expected_uid: 1000,
                    observed_uid: Some(1001),
                    reason: PeerRefusalReason::WrongOwner,
                },
                PeerRefusal {
                    expected_uid: 1000,
                    observed_uid: None,
                    reason: PeerRefusalReason::CredentialUnavailable,
                },
            ]
        );
    }
}
