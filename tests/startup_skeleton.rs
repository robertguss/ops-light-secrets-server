use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdListener, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ops_light_secrets_server::startup::{
    CURRENT_SCHEMA_VERSION, ClockState, DataDirectoryLock, DirectoryState, DrainResult,
    LifecycleState, LockState, MarkerState, OperationClass, PendingAnchorKind, ReserveState,
    SchemaState, ShutdownHookError, ShutdownHooks, ShutdownTrigger, StartupCode, StartupSnapshot,
    StoreIdentity, TransportState, bind_validated, inspect_data_directory, run_shutdown,
    serve_health, validate_startup,
};

fn valid() -> StartupSnapshot {
    StartupSnapshot {
        key_material_configured: true,
        initialized: true,
        listener: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        transport: TransportState::Plaintext,
        directory: DirectoryState::Safe,
        store_identity: StoreIdentity::matching([7; 16]),
        schema: SchemaState::Current,
        lifecycle: LifecycleState::Ready,
        marker: MarkerState::None,
        pending_anchor: None,
        clock: ClockState::Sound,
        lock: LockState::Acquired,
        reserve: ReserveState::Healthy,
    }
}

fn code(snapshot: &StartupSnapshot) -> StartupCode {
    validate_startup(snapshot).unwrap_err().code()
}

#[test]
fn refusal_matrix_is_closed_stable_and_safe() {
    let mut snapshot = valid();
    snapshot.key_material_configured = false;
    assert_eq!(code(&snapshot), StartupCode::MissingKeyMaterial);
    snapshot = valid();
    snapshot.initialized = false;
    assert_eq!(code(&snapshot), StartupCode::UninitializedStore);
    snapshot = valid();
    snapshot.listener = "192.0.2.1:8200".parse().unwrap();
    assert_eq!(code(&snapshot), StartupCode::RemotePlaintextListener);
    snapshot = valid();
    snapshot.directory = DirectoryState::UnsafeMode;
    assert_eq!(code(&snapshot), StartupCode::UnsafeDataDirectory);
    snapshot = valid();
    snapshot.store_identity = StoreIdentity::new([1; 16], [2; 16]);
    assert_eq!(code(&snapshot), StartupCode::StoreKeyringMismatch);
    snapshot = valid();
    snapshot.schema = SchemaState::OlderSupported(0);
    let error = validate_startup(&snapshot).unwrap_err();
    assert_eq!(error.code(), StartupCode::MigrationRequired);
    assert!(error.to_string().contains("from=0 to=1"));
    assert!(error.to_string().contains("offline migrate"));
    for state in [
        SchemaState::Newer(2),
        SchemaState::Unknown(99),
        SchemaState::NoPath(0),
    ] {
        snapshot = valid();
        snapshot.schema = state;
        assert_eq!(code(&snapshot), StartupCode::UnsupportedStoreVersion);
    }
    for lifecycle in [
        LifecycleState::Reencrypting,
        LifecycleState::Restoring,
        LifecycleState::Migrating,
        LifecycleState::Compacting,
    ] {
        snapshot = valid();
        snapshot.lifecycle = lifecycle;
        snapshot.marker = MarkerState::operation(lifecycle, "0123456789abcdef").unwrap();
        assert_eq!(code(&snapshot), StartupCode::LifecycleRecoveryRequired);
    }
    for clock in [ClockState::BehindTolerance, ClockState::ImplausiblyAhead] {
        snapshot = valid();
        snapshot.clock = clock;
        assert_eq!(code(&snapshot), StartupCode::ClockUnsafe);
    }
    for lock in [
        LockState::HeldByOther,
        LockState::Unsupported,
        LockState::Unavailable,
    ] {
        snapshot = valid();
        snapshot.lock = lock;
        assert_eq!(code(&snapshot), StartupCode::DataLockUnavailable);
    }
    for reserve in [
        ReserveState::Released,
        ReserveState::RecreateRequested,
        ReserveState::Mismatch,
    ] {
        snapshot = valid();
        snapshot.reserve = reserve;
        let error = validate_startup(&snapshot).unwrap_err();
        assert_eq!(error.code(), StartupCode::ReserveRecoveryRequired);
        assert!(error.to_string().contains("store reserve status"));
        assert!(error.to_string().contains("store reserve recreate"));
    }
    snapshot = valid();
    snapshot.reserve = ReserveState::Unknown;
    assert_eq!(code(&snapshot), StartupCode::IntegrityFailure);
}

#[test]
fn ipv4_mapped_loopback_is_allowed_for_plaintext_startup() {
    let mut snapshot = valid();
    snapshot.listener = "[::ffff:127.0.0.1]:8200".parse().unwrap();
    assert!(validate_startup(&snapshot).is_ok());
}

#[test]
fn lifecycle_marker_agreement_and_pending_anchor_policy_are_explicit() {
    let mut snapshot = valid();
    snapshot.lifecycle = LifecycleState::Reencrypting;
    assert_eq!(code(&snapshot), StartupCode::LifecycleMarkerMismatch);
    snapshot = valid();
    snapshot.marker =
        MarkerState::operation(LifecycleState::Migrating, "0123456789abcdef").unwrap();
    assert_eq!(code(&snapshot), StartupCode::OrphanOperationMarker);
    snapshot = valid();
    snapshot.marker = MarkerState::Foreign;
    assert_eq!(code(&snapshot), StartupCode::IntegrityFailure);

    for anchor in PendingAnchorKind::ALL {
        snapshot = valid();
        snapshot.pending_anchor = Some(anchor);
        let admission = validate_startup(&snapshot).unwrap();
        assert!(admission.warning().is_some());
        assert!(admission.operation_allowed(OperationClass::NormalTraffic));
        assert!(admission.operation_allowed(OperationClass::Diagnostics));
        assert!(admission.operation_allowed(OperationClass::CompleteAnchor(anchor)));
        assert!(!admission.operation_allowed(OperationClass::BulkRewrite));
        assert!(!admission.operation_allowed(OperationClass::Migration));
        assert!(!admission.operation_allowed(OperationClass::Compaction));
        assert!(!admission.operation_allowed(OperationClass::RestoreActivation));
        assert!(!admission.operation_allowed(OperationClass::KeyJob));
    }
}

#[test]
fn directory_checks_reject_mode_owner_and_symlink_without_raw_path_echo() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        inspect_data_directory(directory.path()).unwrap(),
        DirectoryState::Safe
    );
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        inspect_data_directory(directory.path()).unwrap(),
        DirectoryState::UnsafeMode
    );

    let parent = tempfile::tempdir().unwrap();
    let hostile = parent.path().join("RAW_DIRECTORY_CANARY_91af");
    symlink(directory.path(), &hostile).unwrap();
    let error = inspect_data_directory(&hostile).unwrap_err().to_string();
    assert!(!error.contains("RAW_DIRECTORY_CANARY_91af"));
}

#[test]
fn real_exclusive_lock_refuses_second_instance() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first = DataDirectoryLock::acquire(directory.path()).unwrap();
    let second = DataDirectoryLock::acquire(directory.path()).unwrap_err();
    assert_eq!(second.code(), StartupCode::DataLockUnavailable);
    drop(first);
    DataDirectoryLock::acquire(directory.path()).unwrap();
    let lock_path = directory.path().join(".ops-light-secrets-server.lock");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(DataDirectoryLock::acquire(directory.path()).is_err());
}

#[tokio::test]
async fn invalid_state_never_binds_and_valid_state_serves_health() {
    let probe = StdListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let mut invalid = valid();
    invalid.key_material_configured = false;
    assert!(bind_validated(&invalid, address).await.is_err());
    let reusable = StdListener::bind(address).unwrap();
    drop(reusable);

    let listener = bind_validated(&valid(), address).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        serve_health(listener, async move {
            let _ = stop_receiver.await;
        })
        .await
        .unwrap();
    });
    let response = tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(
                b"GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    })
    .await
    .unwrap();
    assert!(response.contains("200 OK"));
    assert!(response.contains("\"initialized\":true"));
    stop_sender.send(()).unwrap();
    task.await.unwrap();
}

#[test]
fn schema_refusals_are_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("store.bin");
    fs::write(&store, b"immutable-store-sentinel").unwrap();
    let before = fs::read(&store).unwrap();
    for schema in [
        SchemaState::OlderSupported(0),
        SchemaState::Newer(2),
        SchemaState::Unknown(8),
        SchemaState::NoPath(0),
    ] {
        let mut snapshot = valid();
        snapshot.schema = schema;
        assert!(validate_startup(&snapshot).is_err());
        assert_eq!(fs::read(&store).unwrap(), before);
    }
}

struct Hooks {
    events: Arc<Mutex<Vec<&'static str>>>,
    drain: DrainResult,
    flush_ok: bool,
    commit_ok: bool,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            events: Arc::default(),
            drain: DrainResult::Drained,
            flush_ok: true,
            commit_ok: true,
        }
    }
}

impl ShutdownHooks for Hooks {
    fn stop_admission_and_cancel_queued(&mut self) {
        self.events.lock().unwrap().push("stop");
    }
    fn drain_begun(&mut self, deadline: Duration) -> DrainResult {
        assert_eq!(deadline, Duration::from_secs(30));
        self.events.lock().unwrap().push("drain");
        self.drain
    }
    fn flush(&mut self) -> Result<(), ShutdownHookError> {
        self.events.lock().unwrap().push("flush");
        self.flush_ok.then_some(()).ok_or(ShutdownHookError)
    }
    fn commit_unsigned_shutdown(&mut self) -> Result<(), ShutdownHookError> {
        self.events.lock().unwrap().push("commit");
        self.commit_ok.then_some(()).ok_or(ShutdownHookError)
    }
    fn mark_unclean(&mut self) {
        self.events.lock().unwrap().push("unclean");
    }
    fn zeroize_keys(&mut self) {
        self.events.lock().unwrap().push("zeroize");
    }
}

#[test]
fn shutdown_order_deadline_and_second_signal_are_frozen() {
    let mut clean = Hooks {
        drain: DrainResult::Drained,
        ..Hooks::default()
    };
    let result = run_shutdown(&mut clean, ShutdownTrigger::FirstSignal);
    assert_eq!(result.exit_status, 0);
    assert!(result.clean_marker);
    assert_eq!(
        *clean.events.lock().unwrap(),
        ["stop", "drain", "flush", "commit", "zeroize"]
    );

    let mut deadline = Hooks {
        drain: DrainResult::Deadline,
        ..Hooks::default()
    };
    let result = run_shutdown(&mut deadline, ShutdownTrigger::FirstSignal);
    assert_eq!(result.exit_status, 75);
    assert!(!result.clean_marker);
    assert_eq!(
        *deadline.events.lock().unwrap(),
        ["stop", "drain", "unclean", "zeroize"]
    );

    let mut second = Hooks {
        drain: DrainResult::Drained,
        ..Hooks::default()
    };
    let result = run_shutdown(&mut second, ShutdownTrigger::SecondSignal);
    assert_eq!(result.exit_status, 130);
    assert!(!result.clean_marker);
    assert_eq!(
        *second.events.lock().unwrap(),
        ["stop", "unclean", "zeroize"]
    );

    let mut flush_failure = Hooks {
        flush_ok: false,
        ..Hooks::default()
    };
    let result = run_shutdown(&mut flush_failure, ShutdownTrigger::FirstSignal);
    assert_eq!(result.exit_status, 75);
    assert_eq!(
        *flush_failure.events.lock().unwrap(),
        ["stop", "drain", "flush", "unclean", "zeroize"]
    );

    let mut commit_failure = Hooks {
        commit_ok: false,
        ..Hooks::default()
    };
    let result = run_shutdown(&mut commit_failure, ShutdownTrigger::FirstSignal);
    assert_eq!(result.exit_status, 75);
    assert_eq!(
        *commit_failure.events.lock().unwrap(),
        ["stop", "drain", "flush", "commit", "unclean", "zeroize"]
    );
}

#[test]
fn integration_tail_ledger_has_unique_concrete_owners() {
    let ledger: serde_json::Value =
        serde_json::from_str(include_str!("../docs/integration-tail-ledger.json")).unwrap();
    assert_eq!(ledger["schema"], 1);
    let tails = ledger["tails"].as_array().unwrap();
    assert!(tails.len() >= 10);
    let mut contracts = std::collections::BTreeSet::new();
    for tail in tails {
        let contract = tail["contract"].as_str().unwrap();
        let owner = tail["owner"].as_str().unwrap();
        let verification = tail["verification"].as_str().unwrap();
        assert!(contracts.insert(contract));
        assert!(owner.starts_with("olss-charter-qul."));
        assert!(verification.len() >= 40);
    }
}

#[test]
fn lifecycle_closed_set_and_schema_version_are_frozen() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 1);
    assert_eq!(
        LifecycleState::NON_READY,
        [
            LifecycleState::Reencrypting,
            LifecycleState::Restoring,
            LifecycleState::Migrating,
            LifecycleState::Compacting,
        ]
    );
}
