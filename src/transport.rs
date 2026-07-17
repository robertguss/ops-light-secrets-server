//! Validated, all-or-old TLS configuration and reload primitive.

use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::future::Future;
use std::io::{self, BufReader, Cursor, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, version};
use rustls_pemfile::Item;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::control::management::ControlCommand;
use crate::control::management::{ManagementCatalog, ManagementPrincipal};

const MAX_CERT_BYTES: u64 = 1024 * 1024;
const MAX_KEY_BYTES: u64 = 64 * 1024;
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_PENDING_TLS_HANDSHAKES: usize = 128;

#[derive(Clone, Debug, Default)]
pub struct DrainAdmission(Arc<AtomicU8>);

impl DrainAdmission {
    pub fn begin(&self) {
        self.0.store(1, Ordering::Release);
    }

    pub fn close(&self) {
        self.0.store(2, Ordering::Release);
    }

    pub fn is_draining(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }
}

/// Keeps health observable during drain while refusing all ordinary work.
pub async fn drain_admission_guard(
    State(admission): State<DrainAdmission>,
    request: Request,
    next: Next,
) -> Response {
    if admission.is_draining() && request.uri().path() != "/v1/sys/health" {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(request).await
}

#[derive(Clone, Debug)]
pub struct ConnectionCapAcceptor {
    permits: Arc<Semaphore>,
}

impl Default for ConnectionCapAcceptor {
    fn default() -> Self {
        Self::new(MAX_PENDING_TLS_HANDSHAKES)
    }
}

impl ConnectionCapAcceptor {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity != 0);
        Self {
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }
}

pub struct CapacityGuardedStream<I> {
    inner: I,
    _permit: OwnedSemaphorePermit,
}

impl<I: AsyncRead + Unpin> AsyncRead for CapacityGuardedStream<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for CapacityGuardedStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl<I, S> Accept<I, S> for ConnectionCapAcceptor
where
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = CapacityGuardedStream<I>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, S)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let permit = self.permits.clone().try_acquire_owned();
        Box::pin(async move {
            let permit = permit.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "connection capacity reached",
                )
            })?;
            Ok((
                CapacityGuardedStream {
                    inner: stream,
                    _permit: permit,
                },
                service,
            ))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsSetting {
    Cert,
    Key,
    Pair,
    ExpectedFingerprint,
    Audit,
}

impl TlsSetting {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cert => "tls.cert",
            Self::Key => "tls.key",
            Self::Pair => "tls.cert_key_pair",
            Self::ExpectedFingerprint => "tls.expected_fingerprint",
            Self::Audit => "tls.audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsReason {
    ReadFailed,
    UnsafeFile,
    TooLarge,
    ChangedDuringRead,
    ParseFailed,
    MissingCertificate,
    MissingPrivateKey,
    MultiplePrivateKeys,
    KeyCertificateMismatch,
    ExpectedFingerprintMismatch,
    CommitRejected,
    StatePoisoned,
    MissingConfiguration,
}

impl TlsReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadFailed => "read_failed",
            Self::UnsafeFile => "unsafe_file",
            Self::TooLarge => "too_large",
            Self::ChangedDuringRead => "changed_during_read",
            Self::ParseFailed => "parse_failed",
            Self::MissingCertificate => "missing_certificate",
            Self::MissingPrivateKey => "missing_private_key",
            Self::MultiplePrivateKeys => "multiple_private_keys",
            Self::KeyCertificateMismatch => "key_certificate_mismatch",
            Self::ExpectedFingerprintMismatch => "expected_fingerprint_mismatch",
            Self::CommitRejected => "commit_rejected",
            Self::StatePoisoned => "state_poisoned",
            Self::MissingConfiguration => "missing_configuration",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsReloadError {
    setting: TlsSetting,
    reason: TlsReason,
    path_digest: Option<String>,
    fingerprint_detail: Option<(String, String)>,
}

impl TlsReloadError {
    fn new(setting: TlsSetting, reason: TlsReason) -> Self {
        Self {
            setting,
            reason,
            path_digest: None,
            fingerprint_detail: None,
        }
    }

    fn path(setting: TlsSetting, reason: TlsReason, path: &Path, key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(b"tls-path\0");
        hasher.update(path.as_os_str().as_bytes());
        Self {
            setting,
            reason,
            path_digest: Some(hasher.finalize().to_hex()[..16].to_owned()),
            fingerprint_detail: None,
        }
    }

    fn fingerprint_mismatch(
        expected: TransportFingerprint,
        observed: TransportFingerprint,
    ) -> Self {
        Self {
            setting: TlsSetting::ExpectedFingerprint,
            reason: TlsReason::ExpectedFingerprintMismatch,
            path_digest: None,
            fingerprint_detail: Some((expected.hex(), observed.hex())),
        }
    }

    pub fn setting(&self) -> TlsSetting {
        self.setting
    }

    pub fn reason(&self) -> TlsReason {
        self.reason
    }
}

impl fmt::Display for TlsReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tls_reload_refused setting={} reason={}",
            self.setting.as_str(),
            self.reason.as_str()
        )?;
        if let Some(digest) = &self.path_digest {
            write!(formatter, " path_digest={digest}")?;
        }
        if let Some((expected, observed)) = &self.fingerprint_detail {
            write!(
                formatter,
                " expected_fingerprint={expected} observed_fingerprint={observed} remediation='restore configured files or perform an audited live reload'"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for TlsReloadError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportFingerprint([u8; 32]);

impl TransportFingerprint {
    pub fn hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCommitError;

pub trait TransportFingerprintCommit: Send + Sync {
    /// Reauthorizes the trigger and atomically commits the audit event plus
    /// expected transport fingerprint. No live TLS swap has happened yet.
    fn commit_expected_fingerprint(
        &self,
        fingerprint: TransportFingerprint,
    ) -> Result<(), TransportCommitError>;
}

#[derive(Debug)]
pub struct PreparedTlsConfig {
    config: Arc<ServerConfig>,
    fingerprint: TransportFingerprint,
}

impl PreparedTlsConfig {
    pub fn load(
        cert_path: &Path,
        key_path: &Path,
        diagnostic_key: &[u8; 32],
    ) -> Result<Self, TlsReloadError> {
        let cert_bytes = read_bounded(
            cert_path,
            TlsSetting::Cert,
            MAX_CERT_BYTES,
            false,
            diagnostic_key,
        )?;
        let key_bytes = Zeroizing::new(read_bounded(
            key_path,
            TlsSetting::Key,
            MAX_KEY_BYTES,
            true,
            diagnostic_key,
        )?);
        let certificates = parse_certificates(&cert_bytes)?;
        let fingerprint = fingerprint(&certificates);
        let key = parse_private_key(&key_bytes)?;
        let provider = rustls::crypto::ring::default_provider();
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .map_err(|_| TlsReloadError::new(TlsSetting::Pair, TlsReason::ParseFailed))?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|_| {
                TlsReloadError::new(TlsSetting::Pair, TlsReason::KeyCertificateMismatch)
            })?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
            fingerprint,
        })
    }

    pub fn fingerprint(&self) -> TransportFingerprint {
        self.fingerprint
    }

    pub fn commit<C: TransportFingerprintCommit>(
        self,
        commit: &C,
    ) -> Result<CommittedTlsConfig, TlsReloadError> {
        commit
            .commit_expected_fingerprint(self.fingerprint)
            .map_err(|_| TlsReloadError::new(TlsSetting::Audit, TlsReason::CommitRejected))?;
        Ok(CommittedTlsConfig(self))
    }

    fn accept_expected(
        self,
        expected: TransportFingerprint,
    ) -> Result<CommittedTlsConfig, TlsReloadError> {
        if self.fingerprint != expected {
            return Err(TlsReloadError::fingerprint_mismatch(
                expected,
                self.fingerprint,
            ));
        }
        Ok(CommittedTlsConfig(self))
    }
}

pub struct CommittedTlsConfig(PreparedTlsConfig);

impl CommittedTlsConfig {
    pub fn fingerprint(&self) -> TransportFingerprint {
        self.0.fingerprint
    }
}

pub struct TlsReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    diagnostic_key: [u8; 32],
    config: RustlsConfig,
    current: RwLock<TransportFingerprint>,
    serial: Mutex<()>,
}

#[derive(Debug)]
pub enum ControlTlsReloadError {
    Denied,
    Tls(TlsReloadError),
}

impl From<TlsReloadError> for ControlTlsReloadError {
    fn from(value: TlsReloadError) -> Self {
        Self::Tls(value)
    }
}

impl TlsReloader {
    pub fn start_configured<C: TransportFingerprintCommit>(
        config: &Config,
        diagnostic_key: [u8; 32],
        expected: Option<TransportFingerprint>,
        commit: &C,
    ) -> Result<Self, TlsReloadError> {
        let cert_path = config.tls.certificate.clone().ok_or_else(|| {
            TlsReloadError::new(TlsSetting::Cert, TlsReason::MissingConfiguration)
        })?;
        let key_path =
            config.tls.private_key.clone().ok_or_else(|| {
                TlsReloadError::new(TlsSetting::Key, TlsReason::MissingConfiguration)
            })?;
        Self::start(cert_path, key_path, diagnostic_key, expected, commit)
    }

    pub fn start<C: TransportFingerprintCommit>(
        cert_path: PathBuf,
        key_path: PathBuf,
        diagnostic_key: [u8; 32],
        expected: Option<TransportFingerprint>,
        commit: &C,
    ) -> Result<Self, TlsReloadError> {
        let prepared = PreparedTlsConfig::load(&cert_path, &key_path, &diagnostic_key)?;
        let committed = if let Some(expected) = expected {
            prepared.accept_expected(expected)?
        } else {
            prepared.commit(commit)?
        };
        let fingerprint = committed.fingerprint();
        Ok(Self {
            cert_path,
            key_path,
            diagnostic_key,
            config: RustlsConfig::from_config(committed.0.config),
            current: RwLock::new(fingerprint),
            serial: Mutex::new(()),
        })
    }

    pub fn rustls_config(&self) -> RustlsConfig {
        self.config.clone()
    }

    pub fn rustls_acceptor(&self) -> RustlsAcceptor<ConnectionCapAcceptor> {
        self.rustls_acceptor_with(MAX_PENDING_TLS_HANDSHAKES, TLS_HANDSHAKE_TIMEOUT)
    }

    #[doc(hidden)]
    pub fn rustls_acceptor_with(
        &self,
        capacity: usize,
        handshake_timeout: Duration,
    ) -> RustlsAcceptor<ConnectionCapAcceptor> {
        RustlsAcceptor::new(self.rustls_config())
            .handshake_timeout(handshake_timeout)
            .acceptor(ConnectionCapAcceptor::new(capacity))
    }

    pub fn current_fingerprint(&self) -> Result<TransportFingerprint, TlsReloadError> {
        self.current
            .read()
            .map(|value| *value)
            .map_err(|_| TlsReloadError::new(TlsSetting::Pair, TlsReason::StatePoisoned))
    }

    pub async fn reload<C: TransportFingerprintCommit>(
        &self,
        commit: &C,
    ) -> Result<TransportFingerprint, TlsReloadError> {
        let _guard = self.serial.lock().await;
        let prepared =
            PreparedTlsConfig::load(&self.cert_path, &self.key_path, &self.diagnostic_key)?;
        let current = self.current_fingerprint()?;
        if prepared.fingerprint == current {
            return Ok(current);
        }
        let committed = prepared.commit(commit)?;
        let fingerprint = committed.fingerprint();
        self.config.reload_from_config(committed.0.config);
        *self
            .current
            .write()
            .map_err(|_| TlsReloadError::new(TlsSetting::Pair, TlsReason::StatePoisoned))? =
            fingerprint;
        Ok(fingerprint)
    }

    /// Owner-control-socket reload path. Authorization is checked after the
    /// serial reload barrier and immediately before the audited fingerprint
    /// commit; the only fallible certificate work happens before the live swap.
    pub async fn reload_control<C: TransportFingerprintCommit>(
        &self,
        catalog: &mut ManagementCatalog,
        principal: ManagementPrincipal,
        request_id: [u8; 16],
        commit: &C,
    ) -> Result<TransportFingerprint, ControlTlsReloadError> {
        let _guard = self.serial.lock().await;
        let prepared =
            PreparedTlsConfig::load(&self.cert_path, &self.key_path, &self.diagnostic_key)?;
        let current = self.current_fingerprint()?;
        catalog
            .authorize_command(principal, ControlCommand::TlsReload, request_id)
            .map_err(|_| ControlTlsReloadError::Denied)?;
        if prepared.fingerprint == current {
            return Ok(current);
        }
        let committed = prepared.commit(commit)?;
        let fingerprint = committed.fingerprint();
        self.config.reload_from_config(committed.0.config);
        *self
            .current
            .write()
            .map_err(|_| TlsReloadError::new(TlsSetting::Pair, TlsReason::StatePoisoned))? =
            fingerprint;
        Ok(fingerprint)
    }

    pub fn install_sighup<C>(
        self: Arc<Self>,
        commit: Arc<C>,
        events: tokio::sync::mpsc::Sender<Result<TransportFingerprint, TlsReloadError>>,
    ) -> Result<tokio::task::JoinHandle<()>, TlsReloadError>
    where
        C: TransportFingerprintCommit + 'static,
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|_| TlsReloadError::new(TlsSetting::Pair, TlsReason::ReadFailed))?;
        Ok(tokio::spawn(async move {
            while signal.recv().await.is_some() {
                let result = self.reload(commit.as_ref()).await;
                if events.send(result).await.is_err() {
                    break;
                }
            }
        }))
    }
}

fn read_bounded(
    path: &Path,
    setting: TlsSetting,
    limit: u64,
    private: bool,
    diagnostic_key: &[u8; 32],
) -> Result<Vec<u8>, TlsReloadError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| TlsReloadError::path(setting, TlsReason::ReadFailed, path, diagnostic_key))?;
    let before = file
        .metadata()
        .map_err(|_| TlsReloadError::path(setting, TlsReason::ReadFailed, path, diagnostic_key))?;
    if !before.is_file()
        || before.nlink() != 1
        || (private
            && (before.uid() != unsafe { libc::geteuid() }
                || before.permissions().mode() & 0o077 != 0))
    {
        return Err(TlsReloadError::path(
            setting,
            TlsReason::UnsafeFile,
            path,
            diagnostic_key,
        ));
    }
    if before.len() > limit {
        return Err(TlsReloadError::path(
            setting,
            TlsReason::TooLarge,
            path,
            diagnostic_key,
        ));
    }
    let bytes = read_limit(&file, limit)
        .map_err(|reason| TlsReloadError::path(setting, reason, path, diagnostic_key))?;
    let after = file
        .metadata()
        .map_err(|_| TlsReloadError::path(setting, TlsReason::ReadFailed, path, diagnostic_key))?;
    if metadata_changed(&before, &after) {
        return Err(TlsReloadError::path(
            setting,
            TlsReason::ChangedDuringRead,
            path,
            diagnostic_key,
        ));
    }
    Ok(bytes)
}

fn read_limit(file: &File, limit: u64) -> Result<Vec<u8>, TlsReason> {
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TlsReason::ReadFailed)?;
    if bytes.len() as u64 > limit {
        return Err(TlsReason::TooLarge);
    }
    Ok(bytes)
}

fn metadata_changed(before: &Metadata, after: &Metadata) -> bool {
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

fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsReloadError> {
    let mut certificates = Vec::new();
    for item in rustls_pemfile::read_all(&mut BufReader::new(Cursor::new(bytes))) {
        let item =
            item.map_err(|_| TlsReloadError::new(TlsSetting::Cert, TlsReason::ParseFailed))?;
        if let Item::X509Certificate(certificate) = item {
            certificates.push(certificate);
        } else {
            return Err(TlsReloadError::new(
                TlsSetting::Cert,
                TlsReason::ParseFailed,
            ));
        }
    }
    if certificates.is_empty() {
        return Err(TlsReloadError::new(
            TlsSetting::Cert,
            TlsReason::MissingCertificate,
        ));
    }
    Ok(certificates)
}

fn parse_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, TlsReloadError> {
    let mut keys = Vec::new();
    for item in rustls_pemfile::read_all(&mut BufReader::new(Cursor::new(bytes))) {
        let item =
            item.map_err(|_| TlsReloadError::new(TlsSetting::Key, TlsReason::ParseFailed))?;
        match item {
            Item::Pkcs1Key(key) => keys.push(PrivateKeyDer::Pkcs1(key)),
            Item::Pkcs8Key(key) => keys.push(PrivateKeyDer::Pkcs8(key)),
            Item::Sec1Key(key) => keys.push(PrivateKeyDer::Sec1(key)),
            _ => {
                return Err(TlsReloadError::new(TlsSetting::Key, TlsReason::ParseFailed));
            }
        }
    }
    match keys.len() {
        0 => Err(TlsReloadError::new(
            TlsSetting::Key,
            TlsReason::MissingPrivateKey,
        )),
        1 => Ok(keys.pop().expect("one key")),
        _ => Err(TlsReloadError::new(
            TlsSetting::Key,
            TlsReason::MultiplePrivateKeys,
        )),
    }
}

fn fingerprint(certificates: &[CertificateDer<'_>]) -> TransportFingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server transport certificate v1\0");
    for certificate in certificates {
        hasher.update(&(certificate.len() as u64).to_le_bytes());
        hasher.update(certificate.as_ref());
    }
    TransportFingerprint(*hasher.finalize().as_bytes())
}
