use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Router, middleware};
use axum_server::accept::Accept;
use ops_light_secrets_server::config::{
    CheckpointConfig, Config, DEFAULT_CHECKPOINT_MAX_AGE_SECONDS,
    DEFAULT_CHECKPOINT_MAX_UNANCHORED_EVENTS, SecretMount, TlsFiles,
};
use ops_light_secrets_server::control::management::{ManagementCatalog, ManagementPrincipal};
use ops_light_secrets_server::credential::CredentialAudience;
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::rate_limit::{RateLimitConfig, RateLimitService};
use ops_light_secrets_server::sys_api::{ReadinessState, public_router};
use ops_light_secrets_server::transport::{
    ConnectionCapAcceptor, ControlTlsReloadError, DrainAdmission, PreparedTlsConfig, TlsReason,
    TlsReloader, TlsSetting, TransportCommitError, TransportFingerprint,
    TransportFingerprintCommit, drain_admission_guard,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, version};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const KEY: [u8; 32] = [0x73; 32];
static SIGNAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn plaintext_request(address: SocketAddr, path: &str) -> String {
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    response
}

struct Pair {
    cert_pem: String,
    key_pem: String,
    cert_der: CertificateDer<'static>,
}

fn pair() -> Pair {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    Pair {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert_der: cert.der().clone(),
    }
}

struct PairFiles {
    _directory: tempfile::TempDir,
    cert: PathBuf,
    key: PathBuf,
}

impl PairFiles {
    fn new(pair: &Pair) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let files = Self {
            cert: directory.path().join("cert.pem"),
            key: directory.path().join("key.pem"),
            _directory: directory,
        };
        files.replace(pair);
        files
    }

    fn replace(&self, pair: &Pair) {
        replace(&self.cert, pair.cert_pem.as_bytes(), 0o644);
        replace(&self.key, pair.key_pem.as_bytes(), 0o600);
    }
}

fn replace(path: &Path, bytes: &[u8], mode: u32) {
    let staging = path.with_extension(format!("stage-{}", std::process::id()));
    fs::write(&staging, bytes).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(mode)).unwrap();
    fs::rename(staging, path).unwrap();
}

#[derive(Default)]
struct CommitSpy {
    count: AtomicUsize,
    reject: AtomicBool,
    values: Mutex<Vec<TransportFingerprint>>,
}

impl TransportFingerprintCommit for CommitSpy {
    fn commit_expected_fingerprint(
        &self,
        fingerprint: TransportFingerprint,
    ) -> Result<(), TransportCommitError> {
        if self.reject.load(Ordering::SeqCst) {
            return Err(TransportCommitError);
        }
        self.values.lock().unwrap().push(fingerprint);
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn configured_paths_feed_the_single_reload_primitive() {
    let certificate = pair();
    let files = PairFiles::new(&certificate);
    let config = Config {
        data_directory: PathBuf::from("data"),
        age_identity: None,
        tls_key_passphrase: None,
        tls: TlsFiles {
            certificate: Some(files.cert.clone()),
            private_key: Some(files.key.clone()),
        },
        mount: SecretMount {
            cas_required: false,
            max_versions: 10,
        },
        checkpoint: CheckpointConfig {
            max_age_seconds: DEFAULT_CHECKPOINT_MAX_AGE_SECONDS,
            max_unanchored_events: DEFAULT_CHECKPOINT_MAX_UNANCHORED_EVENTS,
        },
    };
    let commit = CommitSpy::default();
    let reloader = TlsReloader::start_configured(&config, KEY, None, &commit).unwrap();
    assert_eq!(reloader.current_fingerprint().unwrap().hex().len(), 64);

    let mut missing = config;
    missing.tls = TlsFiles::default();
    let error = TlsReloader::start_configured(&missing, KEY, None, &commit)
        .err()
        .expect("missing TLS files");
    assert_eq!(error.reason(), TlsReason::MissingConfiguration);
}

#[test]
fn malformed_mismatched_unsafe_and_hostile_files_fail_safely() {
    let first = pair();
    let second = pair();
    let files = PairFiles::new(&first);

    replace(&files.cert, b"not a certificate", 0o644);
    let error = PreparedTlsConfig::load(&files.cert, &files.key, &KEY).unwrap_err();
    assert_eq!(error.setting(), TlsSetting::Cert);
    assert!(matches!(
        error.reason(),
        TlsReason::ParseFailed | TlsReason::MissingCertificate
    ));

    replace(
        &files.cert,
        format!("{}{}", first.cert_pem, first.key_pem).as_bytes(),
        0o644,
    );
    assert_eq!(
        PreparedTlsConfig::load(&files.cert, &files.key, &KEY)
            .unwrap_err()
            .reason(),
        TlsReason::ParseFailed
    );

    files.replace(&first);
    replace(&files.key, second.key_pem.as_bytes(), 0o600);
    let error = PreparedTlsConfig::load(&files.cert, &files.key, &KEY).unwrap_err();
    assert_eq!(error.setting(), TlsSetting::Pair);
    assert_eq!(error.reason(), TlsReason::KeyCertificateMismatch);

    files.replace(&first);
    replace(
        &files.key,
        format!("{}{}", first.key_pem, second.key_pem).as_bytes(),
        0o600,
    );
    assert_eq!(
        PreparedTlsConfig::load(&files.cert, &files.key, &KEY)
            .unwrap_err()
            .reason(),
        TlsReason::MultiplePrivateKeys
    );

    files.replace(&first);
    fs::set_permissions(&files.key, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        PreparedTlsConfig::load(&files.cert, &files.key, &KEY)
            .unwrap_err()
            .reason(),
        TlsReason::UnsafeFile
    );

    let hostile_directory = tempfile::tempdir().unwrap();
    let hostile = hostile_directory
        .path()
        .join("RAW_TLS_PATH_CANARY_91af\n.pem");
    symlink(&files.cert, &hostile).unwrap();
    let rendered = PreparedTlsConfig::load(&hostile, &files.key, &KEY)
        .unwrap_err()
        .to_string();
    assert!(!rendered.contains("RAW_TLS_PATH_CANARY"));
    assert!(rendered.contains("setting=tls.cert"));
    assert!(rendered.contains("path_digest="));
}

#[tokio::test]
async fn failed_parse_mismatch_or_audit_commit_preserves_old_config() {
    let first = pair();
    let second = pair();
    let files = PairFiles::new(&first);
    let commit = CommitSpy::default();
    let reloader =
        TlsReloader::start(files.cert.clone(), files.key.clone(), KEY, None, &commit).unwrap();
    let original = reloader.current_fingerprint().unwrap();

    replace(&files.cert, b"half-written", 0o644);
    assert!(reloader.reload(&commit).await.is_err());
    assert_eq!(reloader.current_fingerprint().unwrap(), original);

    files.replace(&first);
    replace(&files.key, second.key_pem.as_bytes(), 0o600);
    assert!(reloader.reload(&commit).await.is_err());
    assert_eq!(reloader.current_fingerprint().unwrap(), original);

    files.replace(&second);
    commit.reject.store(true, Ordering::SeqCst);
    let error = reloader.reload(&commit).await.unwrap_err();
    assert_eq!(error.setting(), TlsSetting::Audit);
    assert_eq!(error.reason(), TlsReason::CommitRejected);
    assert_eq!(reloader.current_fingerprint().unwrap(), original);
    assert_eq!(commit.count.load(Ordering::SeqCst), 1);
}

#[test]
fn committed_before_swap_crash_reconciles_by_expected_fingerprint() {
    let next = pair();
    let files = PairFiles::new(&next);
    let commit = CommitSpy::default();
    let prepared = PreparedTlsConfig::load(&files.cert, &files.key, &KEY).unwrap();
    let expected = prepared.fingerprint();
    files.replace(&pair());
    let committed = prepared.commit(&commit).unwrap();
    assert_eq!(committed.fingerprint(), expected);
    drop(committed); // simulated crash before live Arc swap

    let restart_commit = CommitSpy::default();
    files.replace(&next);
    let restarted = TlsReloader::start(
        files.cert.clone(),
        files.key.clone(),
        KEY,
        Some(expected),
        &restart_commit,
    )
    .unwrap();
    assert_eq!(restarted.current_fingerprint().unwrap(), expected);
    assert_eq!(restart_commit.count.load(Ordering::SeqCst), 0);

    files.replace(&pair());
    let error = TlsReloader::start(
        files.cert.clone(),
        files.key.clone(),
        KEY,
        Some(expected),
        &restart_commit,
    )
    .err()
    .expect("expected mismatch");
    assert_eq!(error.setting(), TlsSetting::ExpectedFingerprint);
    assert_eq!(error.reason(), TlsReason::ExpectedFingerprintMismatch);
    let rendered = error.to_string();
    assert!(rendered.contains("expected_fingerprint="));
    assert!(rendered.contains("observed_fingerprint="));
    assert!(rendered.contains("audited live reload"));
}

fn tls_request(
    address: SocketAddr,
    trust: CertificateDer<'static>,
    path: &str,
) -> (CertificateDer<'static>, String) {
    let mut roots = RootCertStore::empty();
    roots.add(trust).unwrap();
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap().to_owned(),
    )
    .unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut stream = StreamOwned::new(connection, socket);
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: synthetic\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let peer = stream.conn.peer_certificates().unwrap()[0]
        .clone()
        .into_owned();
    (peer, response)
}

#[derive(Clone)]
struct SlowState {
    started: Arc<AtomicUsize>,
    started_notify: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

async fn fast(headers: HeaderMap) -> StatusCode {
    if headers
        .get("x-vault-token")
        .is_some_and(|value| value == "synthetic")
    {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

async fn slow(State(state): State<SlowState>, headers: HeaderMap) -> StatusCode {
    state.started.fetch_add(1, Ordering::SeqCst);
    state.started_notify.notify_one();
    state.release.acquire().await.unwrap().forget();
    fast(headers).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_plaintext_refusal_and_reload_preserve_inflight_request() {
    let first = pair();
    let second = pair();
    let files = PairFiles::new(&first);
    let commit = Arc::new(CommitSpy::default());
    let reloader = Arc::new(
        TlsReloader::start(
            files.cert.clone(),
            files.key.clone(),
            KEY,
            None,
            commit.as_ref(),
        )
        .unwrap(),
    );
    let state = SlowState {
        started: Arc::new(AtomicUsize::new(0)),
        started_notify: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Semaphore::new(0)),
    };
    let application = Router::new()
        .route("/fast", get(fast))
        .route("/slow", get(slow))
        .with_state(state.clone());
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let acceptor = reloader.rustls_acceptor_with(128, Duration::from_millis(100));
    let server = tokio::spawn(async move {
        axum_server::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .acceptor(acceptor)
            .handle(server_handle)
            .serve(application.into_make_service())
            .await
            .unwrap();
    });
    let address = handle.listening().await.unwrap();

    let (peer, response) = tokio::task::spawn_blocking({
        let trust = first.cert_der.clone();
        move || tls_request(address, trust, "/fast")
    })
    .await
    .unwrap();
    assert_eq!(peer, first.cert_der);
    assert!(response.contains("200 OK"));

    let plaintext_started = std::time::Instant::now();
    let plaintext = tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        socket.write_all(b"GET /fast HTTP/1.0\r\n\r\n").unwrap();
        let mut response = Vec::new();
        let _ = socket.read_to_end(&mut response);
        response
    })
    .await
    .unwrap();
    assert!(!plaintext.windows(6).any(|window| window == b"200 OK"));
    assert!(plaintext_started.elapsed() < Duration::from_millis(500));

    let mut inflight = Vec::new();
    for _ in 0..12 {
        inflight.push(tokio::task::spawn_blocking({
            let trust = first.cert_der.clone();
            move || tls_request(address, trust, "/slow")
        }));
    }
    while state.started.load(Ordering::SeqCst) < inflight.len() {
        state.started_notify.notified().await;
    }
    files.replace(&second);
    let next = reloader.reload(commit.as_ref()).await.unwrap();
    assert_eq!(next.hex().len(), 64);
    state.release.add_permits(inflight.len());
    for request in inflight {
        let (_, response) = request.await.unwrap();
        assert!(response.contains("200 OK"));
    }

    let (peer, response) = tokio::task::spawn_blocking({
        let trust = second.cert_der.clone();
        move || tls_request(address, trust, "/fast")
    })
    .await
    .unwrap();
    assert_eq!(peer, second.cert_der);
    assert!(response.contains("200 OK"));

    let harness = Harness::builder("tls-reload-transport")
        .register_canary(b"TLS_RELOAD_TEST_CANARY")
        .build()
        .unwrap();
    let mut scenario = harness.scenario("atomic-reload", 1).unwrap();
    scenario
        .step(
            "transport",
            SafeSummary::new()
                .field("https_ok", SafeValue::Boolean(true))
                .field(
                    "reload_commits",
                    SafeValue::Unsigned(commit.count.load(Ordering::SeqCst) as u64),
                ),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    assert!(scenario.finish_success().unwrap().scan_attestation.clean);

    handle.graceful_shutdown(Some(Duration::from_secs(2)));
    server.await.unwrap();
}

fn open_tls_file_descriptors(paths: &[&Path]) -> usize {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter(|target| paths.iter().any(|path| target == *path))
        .count()
}

#[tokio::test]
async fn concurrent_reloads_coalesce_repeated_files_close_and_sighup_uses_same_primitive() {
    let _signal_guard = SIGNAL_LOCK.lock().await;
    let first = pair();
    let second = pair();
    let files = PairFiles::new(&first);
    let commit = Arc::new(CommitSpy::default());
    let reloader = Arc::new(
        TlsReloader::start(
            files.cert.clone(),
            files.key.clone(),
            KEY,
            None,
            commit.as_ref(),
        )
        .unwrap(),
    );
    files.replace(&second);
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let reloader = reloader.clone();
        let commit = commit.clone();
        tasks.push(tokio::spawn(async move {
            reloader.reload(commit.as_ref()).await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(commit.count.load(Ordering::SeqCst), 2);

    for index in 0..20 {
        files.replace(if index % 2 == 0 { &first } else { &second });
        reloader.reload(commit.as_ref()).await.unwrap();
        assert_eq!(open_tls_file_descriptors(&[&files.cert, &files.key]), 0);
    }

    files.replace(&first);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(2);
    let listener = reloader
        .clone()
        .install_sighup(commit.clone(), events_tx)
        .unwrap();
    unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
    tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    listener.abort();
}

fn reload_catalog(capability: Capability) -> ManagementCatalog {
    let identity = IdentityRecord::new([1; 16], "operator".into(), IdentityKind::Human).unwrap();
    let grant = GrantRecord::new(
        [2; 16],
        identity.id,
        "sys".into(),
        GrantScope::Exact,
        Vec::new(),
        BTreeSet::from([capability]),
    )
    .unwrap();
    ManagementCatalog::new([identity], [grant]).unwrap()
}

fn reload_principal() -> ManagementPrincipal {
    ManagementPrincipal {
        identity_id: [1; 16],
        audience: CredentialAudience::Control,
        peer_uid: 1000,
        expected_uid: 1000,
        credential_active: true,
    }
}

#[tokio::test]
async fn owner_control_reload_requires_exact_transport_capability_and_preserves_old_on_denial() {
    for capability in Capability::ALL
        .into_iter()
        .filter(|candidate| candidate.is_management())
    {
        let first = pair();
        let second = pair();
        let files = PairFiles::new(&first);
        let commit = CommitSpy::default();
        let reloader =
            TlsReloader::start(files.cert.clone(), files.key.clone(), KEY, None, &commit).unwrap();
        let old = reloader.current_fingerprint().unwrap();
        files.replace(&second);
        let mut catalog = reload_catalog(capability);
        let result = reloader
            .reload_control(
                &mut catalog,
                reload_principal(),
                [capability as u8; 16],
                &commit,
            )
            .await;
        if capability == Capability::TransportManage {
            assert_ne!(result.unwrap(), old);
        } else {
            assert!(matches!(result, Err(ControlTlsReloadError::Denied)));
            assert_eq!(reloader.current_fingerprint().unwrap(), old);
        }
    }

    for mutate in [
        |principal: &mut ManagementPrincipal| principal.peer_uid = 2000,
        |principal: &mut ManagementPrincipal| principal.audience = CredentialAudience::Data,
        |principal: &mut ManagementPrincipal| principal.credential_active = false,
    ] {
        let first = pair();
        let second = pair();
        let files = PairFiles::new(&first);
        let commit = CommitSpy::default();
        let reloader =
            TlsReloader::start(files.cert.clone(), files.key.clone(), KEY, None, &commit).unwrap();
        let old = reloader.current_fingerprint().unwrap();
        files.replace(&second);
        let mut catalog = reload_catalog(Capability::TransportManage);
        let mut principal = reload_principal();
        mutate(&mut principal);
        assert!(matches!(
            reloader
                .reload_control(&mut catalog, principal, [9; 16], &commit)
                .await,
            Err(ControlTlsReloadError::Denied)
        ));
        assert_eq!(reloader.current_fingerprint().unwrap(), old);
    }
}

#[tokio::test]
async fn live_acceptor_connection_cap_is_bounded() {
    let acceptor = ConnectionCapAcceptor::new(1);
    let (first_stream, _) = tokio::io::duplex(16);
    let (guarded, ()) = acceptor.accept(first_stream, ()).await.unwrap();
    let (refused_stream, _) = tokio::io::duplex(16);
    let refusal = acceptor.accept(refused_stream, ()).await.err().unwrap();
    assert_eq!(refusal.kind(), std::io::ErrorKind::ConnectionRefused);
    drop(guarded);
    let (next_stream, _) = tokio::io::duplex(16);
    assert!(acceptor.accept(next_stream, ()).await.is_ok());
}

#[tokio::test]
async fn drain_keeps_tcp_accept_alive_but_health_and_ordinary_work_return_503() {
    let readiness = ReadinessState::default();
    let admission = DrainAdmission::default();
    let limits = RateLimitService::new(RateLimitConfig::default(), [0x91; 32]).unwrap();
    let application = public_router(readiness.clone(), limits)
        .route("/ordinary", get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn_with_state(
            admission.clone(),
            drain_admission_guard,
        ));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, application)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    assert!(
        tokio::task::spawn_blocking(move || plaintext_request(address, "/ordinary"))
            .await
            .unwrap()
            .contains("200 OK")
    );
    readiness.set_draining();
    admission.begin();
    for path in ["/ordinary", "/v1/sys/health"] {
        let response = tokio::task::spawn_blocking(move || plaintext_request(address, path))
            .await
            .unwrap();
        assert!(
            response.contains("503 Service Unavailable"),
            "{path}: {response}"
        );
    }
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}
use std::collections::BTreeSet;
