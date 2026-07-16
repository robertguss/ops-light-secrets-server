use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ops_light_secrets_server::control::{
    ControlSocket, ControlSocketError, PeerAudit, PeerRefusal, control_router, data_router,
};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

#[derive(Default)]
struct Audit(Mutex<Vec<PeerRefusal>>);

impl PeerAudit for Audit {
    fn peer_refused(&self, refusal: PeerRefusal) {
        self.0.lock().expect("audit lock").push(refusal);
    }
}

fn private_directory() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    directory
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[tokio::test]
async fn management_surface_is_absent_remotely_and_present_locally() {
    let request = || {
        Request::builder()
            .uri("/v1/sys/control/status")
            .body(Body::empty())
            .expect("request")
    };
    let remote = data_router()
        .oneshot(request())
        .await
        .expect("remote response");
    let local = control_router()
        .oneshot(request())
        .await
        .expect("local response");

    assert_eq!(remote.status(), StatusCode::NOT_FOUND);
    assert_eq!(local.status(), StatusCode::OK);
    let body = to_bytes(local.into_body(), 1024).await.expect("local body");
    assert_eq!(body, r#"{"control_plane":"ready"}"#);
}

#[tokio::test]
async fn socket_is_owner_only_and_removed_on_drop() {
    let directory = private_directory();
    let path = directory.path().join("control.sock");
    let socket = ControlSocket::bind(&path, effective_uid(), Arc::new(Audit::default()))
        .expect("bind socket");
    let metadata = fs::symlink_metadata(&path).expect("socket metadata");

    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), effective_uid());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    drop(socket);
    assert!(!path.exists());
}

#[tokio::test]
async fn owner_peer_reaches_control_router_over_unix_socket() {
    let directory = private_directory();
    let path = directory.path().join("control.sock");
    let socket = ControlSocket::bind(&path, effective_uid(), Arc::new(Audit::default()))
        .expect("bind socket");
    let server = tokio::spawn(socket.serve());
    let mut client = tokio::net::UnixStream::connect(&path)
        .await
        .expect("connect owner peer");
    client
        .write_all(
            b"GET /v1/sys/control/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write request");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(r#"{"control_plane":"ready"}"#));
    server.abort();
    let _ = server.await;
    assert!(!path.exists());
}

#[tokio::test]
async fn active_socket_symlink_foreign_file_and_public_parent_are_refused() {
    let directory = private_directory();
    let path = directory.path().join("control.sock");
    let audit: Arc<dyn PeerAudit> = Arc::new(Audit::default());
    let _active = ControlSocket::bind(&path, effective_uid(), Arc::clone(&audit)).expect("active");
    assert_eq!(
        ControlSocket::bind(&path, effective_uid(), Arc::clone(&audit)).err(),
        Some(ControlSocketError::ActiveListener)
    );
    drop(_active);

    fs::write(&path, b"foreign").expect("foreign file");
    assert_eq!(
        ControlSocket::bind(&path, effective_uid(), Arc::clone(&audit)).err(),
        Some(ControlSocketError::PathWrongType)
    );
    fs::remove_file(&path).expect("remove foreign file");

    std::os::unix::fs::symlink("target", &path).expect("symlink");
    assert_eq!(
        ControlSocket::bind(&path, effective_uid(), Arc::clone(&audit)).err(),
        Some(ControlSocketError::PathSymlink)
    );
    fs::remove_file(&path).expect("remove symlink");

    let stale = std::os::unix::net::UnixListener::bind(&path).expect("unsafe stale socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("unsafe socket mode");
    drop(stale);
    assert_eq!(
        ControlSocket::bind(&path, effective_uid(), Arc::clone(&audit)).err(),
        Some(ControlSocketError::PathPermissions)
    );
    fs::remove_file(&path).expect("remove unsafe stale socket");

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770))
        .expect("public permissions");
    assert_eq!(
        ControlSocket::bind(&path, effective_uid(), Arc::clone(&audit)).err(),
        Some(ControlSocketError::ParentPermissions)
    );

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("restore permissions");
    assert_eq!(
        ControlSocket::bind(&path, effective_uid() + 1, audit).err(),
        Some(ControlSocketError::ParentWrongOwner)
    );
}

#[tokio::test]
async fn stale_socket_is_replaced_but_replacement_inode_is_never_removed() {
    let directory = private_directory();
    let path = directory.path().join("control.sock");
    let stale = std::os::unix::net::UnixListener::bind(&path).expect("stale socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("stale socket mode");
    drop(stale);

    let socket = ControlSocket::bind(&path, effective_uid(), Arc::new(Audit::default()))
        .expect("replace stale socket");
    fs::remove_file(&path).expect("unlink owned socket");
    fs::write(&path, b"replacement").expect("replacement file");
    drop(socket);
    assert_eq!(
        fs::read(&path).expect("replacement remains"),
        b"replacement"
    );
}
