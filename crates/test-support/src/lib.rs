//! Shared, redaction-by-default observability for repository tests.
//!
//! Suites create a [`Harness`], register exact canary bytes before starting any
//! child, and record only typed [`SafeValue`] fields. Child output is captured
//! privately and never teed. [`Scenario::finish_failure`] freezes and scans the
//! run tree before it can render a bounded tail. Arbitrary `Debug`, argv,
//! environment, headers, bodies, secret values, and raw paths have no logging
//! API. U11.6 replaces the bootstrap raw-literal scanner through the scanner
//! interface without changing the event schema.

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::TempDir;
use zeroize::Zeroizing;

const SCHEMA: u8 = 1;
const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCAN_FILES: usize = 256;
const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TAIL_BYTES: usize = 16 * 1024;
const MAX_TAIL_LINES: usize = 40;

#[derive(Debug)]
pub enum HarnessError {
    Io,
    InvalidSafeValue(&'static str),
    Serialization,
    Scanner,
    Quarantined(Box<SanitizedManifest>),
    State,
}

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => formatter.write_str("test harness I/O failure"),
            Self::InvalidSafeValue(kind) => write!(formatter, "invalid safe {kind}"),
            Self::Serialization => formatter.write_str("test harness serialization failure"),
            Self::Scanner => {
                formatter.write_str("test harness scanner failure; raw output withheld")
            }
            Self::Quarantined(manifest) => write!(
                formatter,
                "test artifact quarantined: artifact={} check={} offset={}",
                manifest.artifact_id, manifest.check_id, manifest.byte_offset
            ),
            Self::State => formatter.write_str("invalid test harness state"),
        }
    }
}

impl std::error::Error for HarnessError {}

impl From<std::io::Error> for HarnessError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<serde_json::Error> for HarnessError {
    fn from(_: serde_json::Error) -> Self {
        Self::Serialization
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SafeValue {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    OpaqueId(String),
    DigestPrefix(String),
    StaticKind(&'static str),
}

#[derive(Clone, Debug, Serialize)]
pub struct MaskedAccessor {
    display: &'static str,
    length_class: &'static str,
}

pub fn mask_accessor(accessor: &[u8]) -> MaskedAccessor {
    let length_class = match accessor.len() {
        0 => "empty",
        1..=7 => "short",
        8..=32 => "standard",
        _ => "long",
    };
    MaskedAccessor {
        display: "****",
        length_class,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DigestOnly(String);

pub fn digest_only(bytes: &[u8]) -> DigestOnly {
    DigestOnly(blake3::hash(bytes).to_hex().to_string())
}

#[derive(Clone, Debug, Serialize)]
pub struct PropertyEvidence {
    seed: u64,
    corpus_hash: String,
    minimized_case_digest: String,
    artifact_id: String,
}

impl PropertyEvidence {
    pub fn new(
        seed: u64,
        corpus_hash: impl Into<String>,
        minimized_case_digest: impl Into<String>,
        artifact_id: impl Into<String>,
    ) -> Result<Self, HarnessError> {
        let corpus_hash = corpus_hash.into();
        let minimized_case_digest = minimized_case_digest.into();
        let artifact_id = artifact_id.into();
        if !valid_hex(&corpus_hash, 16, 64)
            || !valid_hex(&minimized_case_digest, 16, 64)
            || !valid_hex(&artifact_id, 16, 64)
        {
            return Err(HarnessError::InvalidSafeValue("property evidence"));
        }
        Ok(Self {
            seed,
            corpus_hash,
            minimized_case_digest,
            artifact_id,
        })
    }
}

impl SafeValue {
    pub fn opaque_id(value: String) -> Result<Self, HarnessError> {
        valid_hex(&value, 16, 64)
            .then_some(Self::OpaqueId(value))
            .ok_or(HarnessError::InvalidSafeValue("opaque id"))
    }

    pub fn digest_prefix(value: impl Into<String>) -> Result<Self, HarnessError> {
        let value = value.into();
        valid_hex(&value, 8, 32)
            .then_some(Self::DigestPrefix(value))
            .ok_or(HarnessError::InvalidSafeValue("digest prefix"))
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SafeSummary {
    fields: Vec<SafeField>,
}

#[derive(Clone, Debug, Serialize)]
struct SafeField {
    key: &'static str,
    value: SafeValue,
}

impl SafeSummary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field(mut self, key: &'static str, value: SafeValue) -> Self {
        self.fields.push(SafeField { key, value });
        self
    }

    fn validate(&self) -> Result<(), HarnessError> {
        if self.fields.len() > 32
            || self
                .fields
                .iter()
                .any(|field| !valid_static_name(field.key))
        {
            return Err(HarnessError::InvalidSafeValue("summary"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Success,
    Failure,
    Timeout,
    ExitCode(i32),
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualOutcome {
    Success,
    Failure,
    Panic,
    Timeout,
    Signal(i32),
    ExitCode(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ServerStdout,
    ServerStderr,
    ClientStdout,
    ClientStderr,
    Panic,
    Crash,
    Data,
}

impl ArtifactKind {
    fn file_stem(self) -> &'static str {
        match self {
            Self::ServerStdout => "server-stdout",
            Self::ServerStderr => "server-stderr",
            Self::ClientStdout => "client-stdout",
            Self::ClientStderr => "client-stderr",
            Self::Panic => "panic",
            Self::Crash => "crash",
            Self::Data => "data",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEnvelopeSummary {
    envelope_version: u16,
    epoch: u64,
    sequence: u64,
    effective_timestamp: String,
    digest_prefix: String,
}

impl AuditEnvelopeSummary {
    pub fn new(
        envelope_version: u16,
        epoch: u64,
        sequence: u64,
        effective_timestamp: impl Into<String>,
        digest_prefix: impl Into<String>,
    ) -> Result<Self, HarnessError> {
        let effective_timestamp = effective_timestamp.into();
        let digest_prefix = digest_prefix.into();
        if chrono::DateTime::parse_from_rfc3339(&effective_timestamp).is_err()
            || !valid_hex(&digest_prefix, 8, 32)
        {
            return Err(HarnessError::InvalidSafeValue("audit envelope"));
        }
        Ok(Self {
            envelope_version,
            epoch,
            sequence,
            effective_timestamp,
            digest_prefix,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RedactedCommand {
    program: &'static str,
    arguments: Vec<RedactedArgument>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RedactedArgument {
    Literal {
        value: &'static str,
    },
    Placeholder {
        flag: &'static str,
        value: &'static str,
    },
}

impl RedactedCommand {
    pub fn new(program: &'static str) -> Self {
        Self {
            program,
            arguments: Vec::new(),
        }
    }

    pub fn literal(mut self, value: &'static str) -> Self {
        self.arguments.push(RedactedArgument::Literal { value });
        self
    }

    pub fn placeholder(mut self, flag: &'static str, value: &'static str) -> Self {
        self.arguments
            .push(RedactedArgument::Placeholder { flag, value });
        self
    }

    pub fn render(&self) -> Result<String, HarnessError> {
        if !valid_command_token(self.program) {
            return Err(HarnessError::InvalidSafeValue("reproduction command"));
        }
        let mut parts = vec![self.program];
        for argument in &self.arguments {
            match argument {
                RedactedArgument::Literal { value } if valid_command_token(value) => {
                    parts.push(value)
                }
                RedactedArgument::Placeholder { flag, value }
                    if allowed_placeholder_flag(flag) && valid_placeholder(value) =>
                {
                    parts.push(flag);
                    parts.push(value);
                }
                _ => return Err(HarnessError::InvalidSafeValue("reproduction command")),
            }
        }
        Ok(parts.join(" "))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EnvironmentFingerprint {
    rustc: String,
    os: String,
    arch: String,
    clients: Vec<ClientFingerprint>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientFingerprint {
    name: &'static str,
    version: String,
    binary_digest: String,
}

pub struct HarnessBuilder {
    suite: &'static str,
    canaries: Vec<Zeroizing<Vec<u8>>>,
    clients: Vec<ClientFingerprint>,
    scanner: Arc<dyn ArtifactScanner>,
    lifecycle: Arc<dyn ArtifactLifecycle>,
    global_timeout: std::time::Duration,
}

impl HarnessBuilder {
    pub fn register_canary(mut self, canary: &[u8]) -> Self {
        self.canaries.push(Zeroizing::new(canary.to_vec()));
        self
    }

    pub fn scanner(mut self, scanner: Arc<dyn ArtifactScanner>) -> Self {
        self.scanner = scanner;
        self
    }

    pub fn lifecycle(mut self, lifecycle: Arc<dyn ArtifactLifecycle>) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    pub fn global_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.global_timeout = timeout;
        self
    }

    pub fn client_fingerprint(
        mut self,
        name: &'static str,
        version: impl Into<String>,
        binary_digest: impl Into<String>,
    ) -> Result<Self, HarnessError> {
        let version = version.into();
        let binary_digest = binary_digest.into();
        if !valid_static_name(name)
            || !valid_version(&version)
            || !valid_hex(&binary_digest, 16, 64)
        {
            return Err(HarnessError::InvalidSafeValue("client fingerprint"));
        }
        self.clients.push(ClientFingerprint {
            name,
            version,
            binary_digest,
        });
        Ok(self)
    }

    pub fn build(self) -> Result<Harness, HarnessError> {
        if !valid_static_name(self.suite)
            || self.canaries.is_empty()
            || self.canaries.iter().any(|value| value.is_empty())
        {
            return Err(HarnessError::InvalidSafeValue("harness registration"));
        }
        Harness::create(self)
    }
}

#[derive(Clone)]
pub struct Harness {
    inner: Arc<Inner>,
}

struct Inner {
    _directory: TempDir,
    root: PathBuf,
    jsonl_path: PathBuf,
    events: Mutex<File>,
    run_id: String,
    suite: &'static str,
    started: Instant,
    key: [u8; 32],
    canaries: Vec<Zeroizing<Vec<u8>>>,
    scanner: Arc<dyn ArtifactScanner>,
    lifecycle: Arc<dyn ArtifactLifecycle>,
    global_timeout: std::time::Duration,
    artifact_counter: Mutex<u64>,
}

impl Harness {
    pub fn builder(suite: &'static str) -> HarnessBuilder {
        HarnessBuilder {
            suite,
            canaries: Vec::new(),
            clients: Vec::new(),
            scanner: Arc::new(BootstrapScanner),
            lifecycle: Arc::new(DefaultArtifactLifecycle),
            global_timeout: std::time::Duration::from_secs(300),
        }
    }

    fn create(builder: HarnessBuilder) -> Result<Self, HarnessError> {
        let directory = tempfile::Builder::new().prefix("olss-test-").tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let root = directory.path().to_path_buf();
        let jsonl_path = root.join("events.jsonl");
        let events = private_file(&jsonl_path)?;
        let run_id = random_hex(16)?;
        let key = random_key()?;
        let harness = Self {
            inner: Arc::new(Inner {
                _directory: directory,
                root,
                jsonl_path,
                events: Mutex::new(events),
                run_id: run_id.clone(),
                suite: builder.suite,
                started: Instant::now(),
                key,
                canaries: builder.canaries,
                scanner: builder.scanner,
                lifecycle: builder.lifecycle,
                global_timeout: builder.global_timeout,
                artifact_counter: Mutex::new(0),
            }),
        };
        let fingerprint = EnvironmentFingerprint {
            rustc: rustc_version(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            clients: builder.clients,
        };
        harness.write(EventData::RunBegin { fingerprint }, None, None, None, 1)?;
        Ok(harness)
    }

    pub fn scenario(&self, name: &'static str, attempt: u32) -> Result<Scenario, HarnessError> {
        self.start_scenario(name, name, attempt)
    }

    pub fn scenario_case(
        &self,
        name: &'static str,
        case: &'static str,
        attempt: u32,
    ) -> Result<Scenario, HarnessError> {
        self.start_scenario(name, case, attempt)
    }

    pub fn unit_case(&self, name: &'static str) -> Result<Scenario, HarnessError> {
        self.start_scenario("unit-case", name, 1)
    }

    fn start_scenario(
        &self,
        name: &'static str,
        case: &'static str,
        attempt: u32,
    ) -> Result<Scenario, HarnessError> {
        if !valid_static_name(name) || !valid_static_name(case) || attempt == 0 {
            return Err(HarnessError::InvalidSafeValue("scenario"));
        }
        let scenario_id = keyed_id(&self.inner.key, name.as_bytes());
        let case_id = keyed_id(&self.inner.key, case.as_bytes());
        self.write(
            EventData::ScenarioBegin { name },
            Some(&scenario_id),
            Some(&case_id),
            None,
            attempt,
        )?;
        Ok(Scenario {
            harness: self.clone(),
            name,
            scenario_id,
            case_id,
            attempt,
            started: Instant::now(),
            finished: false,
            captures: Vec::new(),
            reproduction: None,
            children: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    fn write(
        &self,
        data: EventData<'_>,
        scenario_id: Option<&str>,
        case_id: Option<&str>,
        step_id: Option<&str>,
        attempt: u32,
    ) -> Result<(), HarnessError> {
        let event = Event {
            schema: SCHEMA,
            run_id: &self.inner.run_id,
            suite: self.inner.suite,
            scenario_id,
            case_id,
            step_id,
            attempt,
            wall_time: wall_time(),
            monotonic_offset_ms: millis(self.inner.started.elapsed()),
            data,
        };
        let mut file = self.inner.events.lock().map_err(|_| HarnessError::State)?;
        serde_json::to_writer(&mut *file, &event)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn sync(&self) -> Result<(), HarnessError> {
        let mut file = self.inner.events.lock().map_err(|_| HarnessError::State)?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }
}

pub struct Scenario {
    harness: Harness,
    name: &'static str,
    scenario_id: String,
    case_id: String,
    attempt: u32,
    started: Instant,
    finished: bool,
    captures: Vec<(ArtifactKind, PathBuf)>,
    reproduction: Option<String>,
    children: Arc<Mutex<BTreeSet<u32>>>,
}

impl Scenario {
    pub fn set_reproduction(&mut self, command: RedactedCommand) -> Result<(), HarnessError> {
        self.reproduction = Some(command.render()?);
        Ok(())
    }

    pub fn step(
        &mut self,
        name: &'static str,
        inputs: SafeSummary,
        expected: ExpectedOutcome,
        actual: ActualOutcome,
    ) -> Result<(), HarnessError> {
        if self.harness.inner.started.elapsed() > self.harness.inner.global_timeout {
            return Err(HarnessError::State);
        }
        if !valid_static_name(name) {
            return Err(HarnessError::InvalidSafeValue("step"));
        }
        inputs.validate()?;
        let step_id = keyed_id(&self.harness.inner.key, name.as_bytes());
        self.harness.write(
            EventData::Step {
                name,
                inputs,
                expected,
                actual,
                duration_ms: 0,
                process: None,
                property: None,
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            Some(&step_id),
            self.attempt,
        )
    }

    pub fn property_step(
        &mut self,
        name: &'static str,
        inputs: SafeSummary,
        expected: ExpectedOutcome,
        actual: ActualOutcome,
        property: PropertyEvidence,
    ) -> Result<(), HarnessError> {
        if !valid_static_name(name) {
            return Err(HarnessError::InvalidSafeValue("property step"));
        }
        inputs.validate()?;
        let step_id = keyed_id(&self.harness.inner.key, name.as_bytes());
        self.harness.write(
            EventData::Step {
                name,
                inputs,
                expected,
                actual,
                duration_ms: 0,
                process: None,
                property: Some(property),
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            Some(&step_id),
            self.attempt,
        )
    }

    pub fn capture(&mut self, kind: ArtifactKind, bytes: &[u8]) -> Result<(), HarnessError> {
        if bytes.len() > MAX_CAPTURE_BYTES {
            return Err(HarnessError::InvalidSafeValue("capture size"));
        }
        let (mut file, path) = self.allocate_capture(kind)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_data()?;
        self.captures.push((kind, path));
        Ok(())
    }

    pub fn spawn_child(&mut self, spec: ChildSpec) -> Result<ManagedChild, HarnessError> {
        spec.validate()?;
        let (stdout, stdout_path) = self.allocate_capture(spec.stdout_kind)?;
        let (stderr, stderr_path) = self.allocate_capture(spec.stderr_kind)?;
        self.captures.push((spec.stdout_kind, stdout_path));
        self.captures.push((spec.stderr_kind, stderr_path));

        let mut command = Command::new(spec.program);
        command
            .args(&spec.arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0);
        let child = command.spawn()?;
        self.children
            .lock()
            .map_err(|_| HarnessError::State)?
            .insert(child.id());
        Ok(ManagedChild {
            child,
            started: Instant::now(),
            finished: false,
            registry: self.children.clone(),
        })
    }

    pub fn process_step(
        &mut self,
        name: &'static str,
        inputs: SafeSummary,
        expected: ExpectedOutcome,
        process: ProcessOutcome,
    ) -> Result<(), HarnessError> {
        if !valid_static_name(name)
            || self.harness.inner.started.elapsed() > self.harness.inner.global_timeout
        {
            return Err(HarnessError::InvalidSafeValue("process step"));
        }
        inputs.validate()?;
        let actual = if process.timed_out {
            ActualOutcome::Timeout
        } else if let Some(signal) = process.signal {
            ActualOutcome::Signal(signal)
        } else {
            ActualOutcome::ExitCode(process.exit_code.unwrap_or(-1))
        };
        let step_id = keyed_id(&self.harness.inner.key, name.as_bytes());
        self.harness.write(
            EventData::Step {
                name,
                inputs,
                expected,
                actual,
                duration_ms: process.duration_ms,
                process: Some(process),
                property: None,
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            Some(&step_id),
            self.attempt,
        )
    }

    fn allocate_capture(&mut self, kind: ArtifactKind) -> Result<(File, PathBuf), HarnessError> {
        let mut counter = self
            .harness
            .inner
            .artifact_counter
            .lock()
            .map_err(|_| HarnessError::State)?;
        *counter += 1;
        let path = self
            .harness
            .inner
            .root
            .join(format!("{}-{}.raw", kind.file_stem(), *counter));
        Ok((private_file(&path)?, path))
    }

    pub fn finish_success(mut self) -> Result<Report, HarnessError> {
        self.stop_registered_children()?;
        self.harness.write(
            EventData::ScenarioEnd {
                name: self.name,
                actual: ActualOutcome::Success,
                duration_ms: millis(self.started.elapsed()),
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            None,
            self.attempt,
        )?;
        self.finished = true;
        self.harness.sync()?;
        if self
            .harness
            .inner
            .lifecycle
            .freeze(&self.harness.inner.root)
            .is_err()
        {
            let _ = self
                .harness
                .inner
                .lifecycle
                .teardown_raw(&self.harness.inner.root);
            return Err(HarnessError::Scanner);
        }
        let scan_attestation = match self.harness.inner.scanner.scan(ScanRequest {
            root: &self.harness.inner.root,
            run_key: &self.harness.inner.key,
            canaries: &self.harness.inner.canaries,
        }) {
            Ok(attestation) => attestation,
            Err(error) => {
                let _ = self
                    .harness
                    .inner
                    .lifecycle
                    .teardown_raw(&self.harness.inner.root);
                return Err(error);
            }
        };
        let jsonl = std::fs::read_to_string(&self.harness.inner.jsonl_path)?;
        let inventory = inventory(&self.harness.inner.root, &self.harness.inner.key)?;
        let human = render_human(&jsonl)?;
        self.harness
            .inner
            .lifecycle
            .teardown_raw(&self.harness.inner.root)
            .map_err(|_| HarnessError::Scanner)?;
        Ok(Report {
            jsonl,
            human,
            scan_attestation,
            inventory,
        })
    }

    pub fn finish_failure(
        mut self,
        reproduction: RedactedCommand,
        audit: &[AuditEnvelopeSummary],
    ) -> Result<Report, HarnessError> {
        self.stop_registered_children()?;
        let reproduction = reproduction.render()?;
        self.harness.write(
            EventData::FailureContext {
                reproduction: &reproduction,
                audit,
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            None,
            self.attempt,
        )?;
        self.harness.write(
            EventData::ScenarioEnd {
                name: self.name,
                actual: ActualOutcome::Failure,
                duration_ms: millis(self.started.elapsed()),
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            None,
            self.attempt,
        )?;
        self.finished = true;
        self.harness.sync()?;
        if self
            .harness
            .inner
            .lifecycle
            .freeze(&self.harness.inner.root)
            .is_err()
        {
            let _ = self
                .harness
                .inner
                .lifecycle
                .teardown_raw(&self.harness.inner.root);
            return Err(HarnessError::Scanner);
        }

        let scan_result = self.harness.inner.scanner.scan(ScanRequest {
            root: &self.harness.inner.root,
            run_key: &self.harness.inner.key,
            canaries: &self.harness.inner.canaries,
        });
        let scan_attestation = match scan_result {
            Ok(attestation) => attestation,
            Err(error) => {
                let _ = self
                    .harness
                    .inner
                    .lifecycle
                    .teardown_raw(&self.harness.inner.root);
                return Err(error);
            }
        };
        if !scan_attestation.clean {
            return Err(HarnessError::Scanner);
        }

        let jsonl = std::fs::read_to_string(&self.harness.inner.jsonl_path)?;
        let inventory = inventory(&self.harness.inner.root, &self.harness.inner.key)?;
        let mut human = render_human(&jsonl)?;
        human.push_str("failure context:\n");
        for entry in &inventory {
            human.push_str(&format!(
                "  data entry={} kind={} size={} mode={:03o}\n",
                entry.opaque_entry_id, entry.kind, entry.size, entry.mode
            ));
        }
        for (_, path) in &self.captures {
            let tail = safe_tail(path)?;
            if !tail.is_empty() {
                human.push_str(&tail);
                if !tail.ends_with('\n') {
                    human.push('\n');
                }
            }
        }
        self.harness
            .inner
            .lifecycle
            .teardown_raw(&self.harness.inner.root)
            .map_err(|_| HarnessError::Scanner)?;

        Ok(Report {
            jsonl,
            human,
            scan_attestation,
            inventory,
        })
    }

    fn stop_registered_children(&self) -> Result<(), HarnessError> {
        let pids: Vec<u32> = self
            .children
            .lock()
            .map_err(|_| HarnessError::State)?
            .iter()
            .copied()
            .collect();
        for pid in &pids {
            signal_group(*pid, nix::sys::signal::Signal::SIGTERM)?;
        }
        let grace = Instant::now() + std::time::Duration::from_millis(100);
        while Instant::now() < grace {
            if pids.iter().all(|pid| process_stopped(*pid)) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for pid in pids.iter().filter(|pid| !process_stopped(**pid)) {
            signal_group(*pid, nix::sys::signal::Signal::SIGKILL)?;
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        while Instant::now() < deadline {
            if pids.iter().all(|pid| process_stopped(*pid)) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err(HarnessError::State)
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let actual = if std::thread::panicking() {
            ActualOutcome::Panic
        } else {
            ActualOutcome::Failure
        };
        let _ = self.stop_registered_children();
        if let Some(reproduction) = self.reproduction.as_deref() {
            let _ = self.harness.write(
                EventData::FailureContext {
                    reproduction,
                    audit: &[],
                },
                Some(&self.scenario_id),
                Some(&self.case_id),
                None,
                self.attempt,
            );
        }
        let _ = self.harness.write(
            EventData::ScenarioEnd {
                name: self.name,
                actual,
                duration_ms: millis(self.started.elapsed()),
            },
            Some(&self.scenario_id),
            Some(&self.case_id),
            None,
            self.attempt,
        );
        let _ = self.harness.sync();
        let scan_result = if self
            .harness
            .inner
            .lifecycle
            .freeze(&self.harness.inner.root)
            .is_ok()
        {
            self.harness.inner.scanner.scan(ScanRequest {
                root: &self.harness.inner.root,
                run_key: &self.harness.inner.key,
                canaries: &self.harness.inner.canaries,
            })
        } else {
            Err(HarnessError::Scanner)
        };
        match scan_result {
            Ok(attestation) if attestation.clean => {
                if let Ok(jsonl) = std::fs::read_to_string(&self.harness.inner.jsonl_path) {
                    if let Ok(mut human) = render_human(&jsonl) {
                        for (_, path) in &self.captures {
                            if let Ok(tail) = safe_tail(path) {
                                human.push_str(&tail);
                            }
                        }
                        eprintln!("{human}");
                    }
                }
            }
            Err(error) => eprintln!("{error}"),
            _ => eprintln!("test harness scan incomplete; raw output withheld"),
        }
        let _ = self
            .harness
            .inner
            .lifecycle
            .teardown_raw(&self.harness.inner.root);
    }
}

#[derive(Debug)]
pub struct Report {
    pub jsonl: String,
    pub human: String,
    pub scan_attestation: ScanAttestation,
    pub inventory: Vec<InventoryEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanAttestation {
    pub clean: bool,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub scanner: &'static str,
    pub tree_digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SanitizedManifest {
    pub artifact_id: String,
    pub path_digest: String,
    pub structural_parent: &'static str,
    pub artifact_kind: &'static str,
    pub check_id: &'static str,
    pub byte_offset: u64,
    pub match_id: String,
}

pub struct ScanRequest<'a> {
    pub root: &'a Path,
    pub run_key: &'a [u8; 32],
    pub canaries: &'a [Zeroizing<Vec<u8>>],
}

pub trait ArtifactScanner: Send + Sync {
    fn scan(&self, request: ScanRequest<'_>) -> Result<ScanAttestation, HarnessError>;
}

pub trait ArtifactLifecycle: Send + Sync {
    fn freeze(&self, root: &Path) -> Result<(), HarnessError>;
    fn teardown_raw(&self, root: &Path) -> Result<(), HarnessError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultArtifactLifecycle;

impl ArtifactLifecycle for DefaultArtifactLifecycle {
    fn freeze(&self, root: &Path) -> Result<(), HarnessError> {
        let root_mode = std::fs::metadata(root)?.permissions().mode() & 0o777;
        if root_mode != 0o700 {
            return Err(HarnessError::Scanner);
        }
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.is_file() {
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    return Err(HarnessError::Scanner);
                }
                File::open(entry.path())?.sync_all()?;
            }
        }
        Ok(())
    }

    fn teardown_raw(&self, root: &Path) -> Result<(), HarnessError> {
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name() == "events.jsonl" {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.is_file() || metadata.file_type().is_symlink() {
                std::fs::remove_file(entry.path())?;
            } else {
                return Err(HarnessError::Scanner);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BootstrapScanner;

impl ArtifactScanner for BootstrapScanner {
    fn scan(&self, request: ScanRequest<'_>) -> Result<ScanAttestation, HarnessError> {
        scan_tree(request.root, request.run_key, request.canaries)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InventoryEntry {
    pub opaque_entry_id: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
}

#[derive(Serialize)]
struct Event<'a> {
    schema: u8,
    run_id: &'a str,
    suite: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step_id: Option<&'a str>,
    attempt: u32,
    wall_time: String,
    monotonic_offset_ms: u64,
    #[serde(flatten)]
    data: EventData<'a>,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum EventData<'a> {
    RunBegin {
        fingerprint: EnvironmentFingerprint,
    },
    ScenarioBegin {
        name: &'static str,
    },
    Step {
        name: &'static str,
        inputs: SafeSummary,
        expected: ExpectedOutcome,
        actual: ActualOutcome,
        duration_ms: u64,
        process: Option<ProcessOutcome>,
        property: Option<PropertyEvidence>,
    },
    FailureContext {
        reproduction: &'a str,
        audit: &'a [AuditEnvelopeSummary],
    },
    ScenarioEnd {
        name: &'static str,
        actual: ActualOutcome,
        duration_ms: u64,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessOutcome {
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ChildSpec {
    program: &'static str,
    arguments: Vec<&'static str>,
    stdout_kind: ArtifactKind,
    stderr_kind: ArtifactKind,
}

impl ChildSpec {
    pub fn new(program: &'static str) -> Self {
        Self {
            program,
            arguments: Vec::new(),
            stdout_kind: ArtifactKind::ServerStdout,
            stderr_kind: ArtifactKind::ServerStderr,
        }
    }

    pub fn arg(mut self, argument: &'static str) -> Self {
        self.arguments.push(argument);
        self
    }

    pub fn artifact_kinds(mut self, stdout: ArtifactKind, stderr: ArtifactKind) -> Self {
        self.stdout_kind = stdout;
        self.stderr_kind = stderr;
        self
    }

    fn validate(&self) -> Result<(), HarnessError> {
        if !self.program.starts_with('/')
            || !valid_command_token(self.program)
            || self.arguments.len() > 32
            || self
                .arguments
                .iter()
                .any(|argument| !valid_command_token(argument))
        {
            return Err(HarnessError::InvalidSafeValue("child command"));
        }
        Ok(())
    }
}

pub enum Readiness {
    Ready,
    Exited(ProcessOutcome),
    TimedOut(ProcessOutcome),
}

pub struct ManagedChild {
    child: Child,
    started: Instant,
    finished: bool,
    registry: Arc<Mutex<BTreeSet<u32>>>,
}

impl ManagedChild {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn wait(mut self, timeout: std::time::Duration) -> Result<ProcessOutcome, HarnessError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.finished = true;
                self.deregister();
                return Ok(process_outcome(
                    self.child.id(),
                    status,
                    false,
                    self.started.elapsed(),
                ));
            }
            if Instant::now() >= deadline {
                let outcome = self.stop_for_timeout()?;
                self.finished = true;
                self.deregister();
                return Ok(outcome);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pub fn poll_readiness<F>(
        &mut self,
        timeout: std::time::Duration,
        mut ready: F,
    ) -> Result<Readiness, HarnessError>
    where
        F: FnMut() -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if ready() {
                return Ok(Readiness::Ready);
            }
            if let Some(status) = self.child.try_wait()? {
                self.finished = true;
                self.deregister();
                return Ok(Readiness::Exited(process_outcome(
                    self.child.id(),
                    status,
                    false,
                    self.started.elapsed(),
                )));
            }
            if Instant::now() >= deadline {
                let outcome = self.stop_for_timeout()?;
                self.finished = true;
                self.deregister();
                return Ok(Readiness::TimedOut(outcome));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pub fn terminate(&mut self) -> Result<(), HarnessError> {
        signal_group(self.child.id(), nix::sys::signal::Signal::SIGTERM)
    }

    pub fn kill(&mut self) -> Result<(), HarnessError> {
        signal_group(self.child.id(), nix::sys::signal::Signal::SIGKILL)
    }

    fn stop_for_timeout(&mut self) -> Result<ProcessOutcome, HarnessError> {
        signal_group(self.child.id(), nix::sys::signal::Signal::SIGTERM)?;
        let grace = Instant::now() + std::time::Duration::from_millis(100);
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(process_outcome(
                    self.child.id(),
                    status,
                    true,
                    self.started.elapsed(),
                ));
            }
            if Instant::now() >= grace {
                signal_group(self.child.id(), nix::sys::signal::Signal::SIGKILL)?;
                let status = self.child.wait()?;
                return Ok(process_outcome(
                    self.child.id(),
                    status,
                    true,
                    self.started.elapsed(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn deregister(&self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.remove(&self.child.id());
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = signal_group(self.child.id(), nix::sys::signal::Signal::SIGKILL);
        let _ = self.child.wait();
        self.deregister();
    }
}

fn signal_group(pid: u32, signal: nix::sys::signal::Signal) -> Result<(), HarnessError> {
    let pid = i32::try_from(pid).map_err(|_| HarnessError::State)?;
    match nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(_) => Err(HarnessError::Io),
    }
}

fn process_outcome(
    pid: u32,
    status: std::process::ExitStatus,
    timed_out: bool,
    duration: std::time::Duration,
) -> ProcessOutcome {
    ProcessOutcome {
        pid,
        exit_code: status.code(),
        signal: status.signal(),
        timed_out,
        duration_ms: millis(duration),
    }
}

fn process_stopped(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.as_bytes().first().copied())
        == Some(b'Z')
}

fn scan_tree(
    root: &Path,
    key: &[u8; 32],
    canaries: &[Zeroizing<Vec<u8>>],
) -> Result<ScanAttestation, HarnessError> {
    let mut paths = Vec::new();
    collect_paths(root, &mut paths)?;
    if paths.len() > MAX_SCAN_FILES {
        return Err(HarnessError::Scanner);
    }
    paths.sort();
    let mut bytes_scanned = 0_u64;
    let mut tree_hasher = blake3::Hasher::new_keyed(key);

    for path in &paths {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HarnessError::Scanner);
        }
        bytes_scanned = bytes_scanned
            .checked_add(metadata.len())
            .ok_or(HarnessError::Scanner)?;
        if bytes_scanned > MAX_SCAN_BYTES {
            return Err(HarnessError::Scanner);
        }
        let relative = path.strip_prefix(root).map_err(|_| HarnessError::Scanner)?;
        let relative_bytes = path_bytes(relative);
        tree_hasher.update(&relative_bytes);
        let bytes = std::fs::read(path)?;
        tree_hasher.update(&bytes);
        for canary in canaries {
            if find_bytes(&relative_bytes, canary).is_some() {
                return Err(HarnessError::Quarantined(Box::new(sanitized_finding(
                    key, relative, "filename", 0, canary,
                ))));
            }
            if let Some(offset) = find_bytes(&bytes, canary) {
                return Err(HarnessError::Quarantined(Box::new(sanitized_finding(
                    key,
                    relative,
                    "raw_literal",
                    offset as u64,
                    canary,
                ))));
            }
        }
        let after = std::fs::symlink_metadata(path)?;
        if after.len() != metadata.len() || after.modified().ok() != metadata.modified().ok() {
            return Err(HarnessError::Scanner);
        }
    }

    Ok(ScanAttestation {
        clean: true,
        files_scanned: paths.len(),
        bytes_scanned,
        scanner: "bootstrap-raw-literal-v1",
        tree_digest: tree_hasher.finalize().to_hex().to_string(),
    })
}

fn sanitized_finding(
    key: &[u8; 32],
    relative: &Path,
    check_id: &'static str,
    byte_offset: u64,
    canary: &[u8],
) -> SanitizedManifest {
    let path = path_bytes(relative);
    SanitizedManifest {
        artifact_id: keyed_id(key, &[b"artifact", path.as_slice()].concat()),
        path_digest: keyed_id(key, &[b"path", path.as_slice()].concat()),
        structural_parent: "run_root",
        artifact_kind: "private_file",
        check_id,
        byte_offset,
        match_id: keyed_id(key, &[b"match", canary].concat()),
    }
}

fn collect_paths(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), HarnessError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_symlink() {
            return Err(HarnessError::Scanner);
        }
        if metadata.is_dir() {
            collect_paths(&entry.path(), output)?;
        } else if metadata.is_file() {
            output.push(entry.path());
        } else {
            return Err(HarnessError::Scanner);
        }
    }
    Ok(())
}

fn inventory(root: &Path, key: &[u8; 32]) -> Result<Vec<InventoryEntry>, HarnessError> {
    let mut paths = Vec::new();
    collect_paths(root, &mut paths)?;
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let metadata = std::fs::metadata(&path)?;
            let relative = path.strip_prefix(root).map_err(|_| HarnessError::Scanner)?;
            Ok(InventoryEntry {
                opaque_entry_id: keyed_id(key, &path_bytes(relative)),
                kind: "file",
                size: metadata.len(),
                mode: metadata.permissions().mode() & 0o777,
            })
        })
        .collect()
}

fn safe_tail(path: &Path) -> Result<String, HarnessError> {
    let mut bytes = std::fs::read(path)?;
    if bytes.len() > MAX_TAIL_BYTES {
        bytes = bytes.split_off(bytes.len() - MAX_TAIL_BYTES);
    }
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(MAX_TAIL_LINES);
    let mut output = lines[start..].join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    Ok(output)
}

fn render_human(jsonl: &str) -> Result<String, HarnessError> {
    let mut output = String::new();
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        let event = value
            .get("event")
            .and_then(serde_json::Value::as_str)
            .ok_or(HarnessError::Serialization)?;
        match event {
            "scenario_begin" => {
                let name = value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(HarnessError::Serialization)?;
                output.push_str(&format!("scenario {name}: begin\n"));
            }
            "step" => {
                let name = value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(HarnessError::Serialization)?;
                output.push_str(&format!("  step {name}\n"));
            }
            "scenario_end" => {
                let name = value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(HarnessError::Serialization)?;
                output.push_str(&format!("scenario {name}: end\n"));
            }
            "failure_context" => {
                let reproduction = value
                    .get("reproduction")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(HarnessError::Serialization)?;
                if let Some(audit) = value.get("audit").and_then(serde_json::Value::as_array) {
                    for envelope in audit {
                        output.push_str(&format!(
                            "  audit envelope_version={} epoch={} sequence={} effective_timestamp={} digest_prefix={}\n",
                            envelope["envelope_version"],
                            envelope["epoch"],
                            envelope["sequence"],
                            envelope["effective_timestamp"].as_str().ok_or(HarnessError::Serialization)?,
                            envelope["digest_prefix"].as_str().ok_or(HarnessError::Serialization)?
                        ));
                    }
                }
                output.push_str("reproduce: ");
                output.push_str(reproduction);
                output.push('\n');
            }
            _ => {}
        }
    }
    Ok(output)
}

fn private_file(path: &Path) -> Result<File, HarnessError> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .open(path)
        .map_err(Into::into)
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn random_key() -> Result<[u8; 32], HarnessError> {
    let mut key = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut key)?;
    Ok(key)
}

fn random_hex(bytes: usize) -> Result<String, HarnessError> {
    let mut value = vec![0_u8; bytes];
    File::open("/dev/urandom")?.read_exact(&mut value)?;
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn keyed_id(key: &[u8; 32], bytes: &[u8]) -> String {
    blake3::keyed_hash(key, bytes).to_hex()[..24].to_owned()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

fn wall_time() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn valid_hex(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value.len() % 2 == 0
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_static_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn valid_command_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
        && !matches!(
            value,
            "--age-identity" | "--tls-key-passphrase" | "--token" | "--secret"
        )
}

fn allowed_placeholder_flag(value: &str) -> bool {
    matches!(
        value,
        "--config" | "--test" | "--scenario" | "--case" | "--seed" | "--credential-source"
    )
}

fn valid_placeholder(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 64
        && value.starts_with('<')
        && value.ends_with('>')
        && value[1..value.len() - 1]
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn harness(canary: &[u8]) -> Harness {
        Harness::builder("self-test")
            .register_canary(canary)
            .build()
            .expect("harness")
    }

    fn reproduction() -> RedactedCommand {
        RedactedCommand::new("cargo")
            .literal("test")
            .placeholder("--test", "<TEST_NAME>")
    }

    fn finish(scenario: Scenario) -> Result<Report, HarnessError> {
        scenario.finish_failure(reproduction(), &[])
    }

    #[test]
    fn successful_unit_case_is_compact_and_has_all_stable_ids() {
        let harness = harness(b"unit-canary");
        let mut case = harness.unit_case("parses-valid-input").unwrap();
        case.property_step(
            "property-case",
            SafeSummary::new().field("count", SafeValue::Unsigned(1)),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
            PropertyEvidence::new(
                7,
                "0011223344556677",
                "8899aabbccddeeff",
                "0123456789abcdef",
            )
            .unwrap(),
        )
        .unwrap();
        let report = case.finish_success().unwrap();
        let values: Vec<serde_json::Value> = report
            .jsonl
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let scenario_events: Vec<&serde_json::Value> = values
            .iter()
            .filter(|value| value["event"] != "run_begin")
            .collect();
        assert!(scenario_events.iter().all(|value| {
            value["run_id"].is_string()
                && value["scenario_id"].is_string()
                && value["case_id"].is_string()
                && value["attempt"] == 1
        }));
        assert!(
            scenario_events
                .iter()
                .filter(|value| value["event"] == "step")
                .all(|value| value["step_id"].is_string())
        );
        assert!(report.jsonl.contains("\"seed\":7"));
        assert!(!report.human.contains("failure context"));
        let run_begin = &values[0];
        chrono::DateTime::parse_from_rfc3339(run_begin["wall_time"].as_str().unwrap()).unwrap();
        assert!(run_begin["monotonic_offset_ms"].is_u64());
        assert!(run_begin["fingerprint"]["rustc"].is_string());
        assert!(run_begin["fingerprint"]["os"].is_string());
        assert!(run_begin["fingerprint"]["arch"].is_string());
    }

    #[test]
    fn registered_literal_in_raw_output_is_quarantined_without_context() {
        let harness = harness(b"exact-canary");
        let mut scenario = harness.scenario("raw-leak", 1).unwrap();
        scenario
            .capture(ArtifactKind::ServerStderr, b"before exact-canary after")
            .unwrap();

        let error = finish(scenario).expect_err("must quarantine");
        let HarnessError::Quarantined(manifest) = error else {
            panic!("unexpected safe error variant")
        };
        let rendered = manifest_to_json(&manifest);
        assert_eq!(manifest.check_id, "raw_literal");
        assert!(manifest.byte_offset > 0);
        assert!(!rendered.contains("exact-canary"));
        assert!(!rendered.contains("server-stderr"));
        assert_eq!(std::fs::read_dir(&harness.inner.root).unwrap().count(), 1);
    }

    #[test]
    fn registered_literal_in_filename_is_quarantined() {
        let harness = harness(b"filename-canary");
        let scenario = harness.scenario("filename-leak", 1).unwrap();
        let path = harness.inner.root.join("filename-canary.raw");
        private_file(&path).unwrap();

        let error = finish(scenario).expect_err("must quarantine filename");
        let HarnessError::Quarantined(manifest) = error else {
            panic!("unexpected safe error variant")
        };
        assert_eq!(manifest.check_id, "filename");
        assert!(!manifest_to_json(&manifest).contains("filename-canary"));
    }

    #[test]
    fn every_raw_artifact_class_is_withheld_on_seeded_leak() {
        for kind in [
            ArtifactKind::ServerStdout,
            ArtifactKind::ServerStderr,
            ArtifactKind::ClientStdout,
            ArtifactKind::ClientStderr,
            ArtifactKind::Panic,
            ArtifactKind::Crash,
            ArtifactKind::Data,
        ] {
            let mut scenario = harness(b"class-canary").scenario("class-leak", 1).unwrap();
            scenario.capture(kind, b"class-canary").unwrap();
            assert!(matches!(
                finish(scenario),
                Err(HarnessError::Quarantined(_))
            ));
        }
    }

    #[test]
    fn invalid_utf8_tail_is_lossy_and_bounded_only_after_scan() {
        let mut bytes = vec![b'a'; MAX_TAIL_BYTES + 4096];
        bytes.extend_from_slice(b"\nlast-safe-line-");
        bytes.push(0xff);
        bytes.push(b'\n');
        let mut scenario = harness(b"absent-canary")
            .scenario("invalid-utf8", 1)
            .unwrap();
        scenario.capture(ArtifactKind::Crash, &bytes).unwrap();

        let report = finish(scenario).unwrap();
        assert!(report.human.contains("last-safe-line-�"));
        assert!(report.human.len() <= MAX_TAIL_BYTES + 4096);
        assert!(report.scan_attestation.clean);
    }

    #[test]
    fn secret_bearing_reproduction_flag_is_rejected() {
        let scenario = harness(b"absent-canary").scenario("bad-repro", 1).unwrap();
        let command = RedactedCommand::new("cargo").literal("--token");
        let error = scenario
            .finish_failure(command, &[])
            .expect_err("secret flag must fail");
        assert!(matches!(error, HarnessError::InvalidSafeValue(_)));
    }

    #[test]
    fn masking_and_digest_helpers_never_render_source_bytes() {
        let accessor = b"accessor-sensitive-value";
        let masked = serde_json::to_string(&mask_accessor(accessor)).unwrap();
        let digest = serde_json::to_string(&digest_only(accessor)).unwrap();
        assert!(!masked.contains("accessor-sensitive-value"));
        assert!(!digest.contains("accessor-sensitive-value"));
        assert!(masked.contains("****"));
    }

    #[test]
    fn parallel_harnesses_have_unique_run_ids() {
        let reports: Vec<Report> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let scenario = harness(b"parallel-canary").scenario("parallel", 1).unwrap();
                    finish(scenario).unwrap()
                })
            })
            .map(|thread| thread.join().unwrap())
            .collect();
        let run_ids: BTreeSet<String> = reports
            .iter()
            .map(|report| {
                serde_json::from_str::<serde_json::Value>(report.jsonl.lines().next().unwrap())
                    .unwrap()["run_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(run_ids.len(), 4);
    }

    struct CountingScanner {
        calls: Arc<AtomicUsize>,
    }

    impl ArtifactScanner for CountingScanner {
        fn scan(&self, request: ScanRequest<'_>) -> Result<ScanAttestation, HarnessError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            BootstrapScanner.scan(request)
        }
    }

    #[test]
    fn panic_drop_still_invokes_scanner() {
        let calls = Arc::new(AtomicUsize::new(0));
        let harness = Harness::builder("panic-test")
            .register_canary(b"panic-canary")
            .scanner(Arc::new(CountingScanner {
                calls: calls.clone(),
            }))
            .build()
            .unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut scenario = harness.scenario("panic", 1).unwrap();
            scenario.set_reproduction(reproduction()).unwrap();
            panic!("seeded safe panic");
        }));
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    struct FailingScanner;

    impl ArtifactScanner for FailingScanner {
        fn scan(&self, _: ScanRequest<'_>) -> Result<ScanAttestation, HarnessError> {
            Err(HarnessError::Scanner)
        }
    }

    #[test]
    fn scanner_failure_withholds_report() {
        let harness = Harness::builder("scanner-failure")
            .register_canary(b"scanner-canary")
            .scanner(Arc::new(FailingScanner))
            .build()
            .unwrap();
        let scenario = harness.scenario("scanner-failure", 1).unwrap();
        assert!(matches!(finish(scenario), Err(HarnessError::Scanner)));
    }

    struct FailingTeardown;

    impl ArtifactLifecycle for FailingTeardown {
        fn freeze(&self, root: &Path) -> Result<(), HarnessError> {
            DefaultArtifactLifecycle.freeze(root)
        }

        fn teardown_raw(&self, _: &Path) -> Result<(), HarnessError> {
            Err(HarnessError::Io)
        }
    }

    #[test]
    fn teardown_failure_withholds_report() {
        let harness = Harness::builder("teardown-failure")
            .register_canary(b"teardown-canary")
            .lifecycle(Arc::new(FailingTeardown))
            .build()
            .unwrap();
        let mut scenario = harness.scenario("teardown-failure", 1).unwrap();
        scenario.capture(ArtifactKind::Data, b"safe").unwrap();
        assert!(matches!(finish(scenario), Err(HarnessError::Scanner)));
    }

    #[test]
    fn symlink_in_artifact_tree_fails_closed() {
        let harness = harness(b"symlink-canary");
        let scenario = harness.scenario("symlink", 1).unwrap();
        std::os::unix::fs::symlink("events.jsonl", harness.inner.root.join("link")).unwrap();
        assert!(matches!(finish(scenario), Err(HarnessError::Scanner)));
    }

    #[test]
    fn nonzero_child_exit_is_typed_and_captured() {
        let mut scenario = harness(b"child-canary").scenario("child-exit", 1).unwrap();
        let child = scenario.spawn_child(ChildSpec::new("/bin/false")).unwrap();
        let outcome = child.wait(Duration::from_secs(1)).unwrap();
        assert_eq!(outcome.exit_code, Some(1));
        scenario
            .process_step(
                "child-exit",
                SafeSummary::new(),
                ExpectedOutcome::Success,
                outcome,
            )
            .unwrap();
        let report = finish(scenario).unwrap();
        assert!(report.jsonl.contains("\"exit_code\":1"));
    }

    #[test]
    fn readiness_detects_early_exit_and_timeout() {
        let mut early = harness(b"ready-canary").scenario("ready-exit", 1).unwrap();
        let mut child = early.spawn_child(ChildSpec::new("/bin/false")).unwrap();
        assert!(matches!(
            child
                .poll_readiness(Duration::from_secs(1), || false)
                .unwrap(),
            Readiness::Exited(_)
        ));
        finish(early).unwrap();

        let mut timeout = harness(b"timeout-canary")
            .scenario("ready-timeout", 1)
            .unwrap();
        let mut child = timeout
            .spawn_child(ChildSpec::new("/bin/sleep").arg("5"))
            .unwrap();
        let Readiness::TimedOut(outcome) = child
            .poll_readiness(Duration::from_millis(20), || false)
            .unwrap()
        else {
            panic!("expected timeout")
        };
        assert!(outcome.timed_out);
        finish(timeout).unwrap();

        let mut ready = harness(b"ready-success-canary")
            .scenario("ready-success", 1)
            .unwrap();
        let mut child = ready
            .spawn_child(ChildSpec::new("/bin/sleep").arg("5"))
            .unwrap();
        assert!(matches!(
            child
                .poll_readiness(Duration::from_secs(1), || true)
                .unwrap(),
            Readiness::Ready
        ));
        child.kill().unwrap();
        child.wait(Duration::from_secs(1)).unwrap();
        finish(ready).unwrap();
    }

    #[test]
    fn term_kill_and_drop_stop_process_groups() {
        for kill in [false, true] {
            let mut scenario = harness(b"signal-canary").scenario("signal", 1).unwrap();
            let mut child = scenario
                .spawn_child(ChildSpec::new("/bin/sleep").arg("5"))
                .unwrap();
            if kill {
                child.kill().unwrap();
            } else {
                child.terminate().unwrap();
            }
            let outcome = child.wait(Duration::from_secs(1)).unwrap();
            assert!(matches!(outcome.signal, Some(9 | 15)));
            finish(scenario).unwrap();
        }

        let mut scenario = harness(b"drop-canary").scenario("drop", 1).unwrap();
        let child = scenario
            .spawn_child(ChildSpec::new("/bin/sleep").arg("5"))
            .unwrap();
        let pid = i32::try_from(child.pid()).unwrap();
        drop(child);
        let result = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None);
        assert_eq!(result, Err(nix::errno::Errno::ESRCH));
        finish(scenario).unwrap();
    }

    #[test]
    fn finalizing_scenario_stops_still_live_child_before_scan() {
        let mut scenario = harness(b"live-child-canary")
            .scenario("live-child", 1)
            .unwrap();
        let child = scenario
            .spawn_child(ChildSpec::new("/bin/sleep").arg("5"))
            .unwrap();
        let report = finish(scenario).unwrap();
        assert!(report.scan_attestation.clean);
        let outcome = child.wait(Duration::from_secs(1)).unwrap();
        assert!(matches!(outcome.signal, Some(9 | 15)));
    }

    #[test]
    fn invalid_child_secret_flag_is_refused_before_spawn() {
        let mut scenario = harness(b"child-command-canary")
            .scenario("bad-child", 1)
            .unwrap();
        let result = scenario.spawn_child(ChildSpec::new("/bin/echo").arg("--token"));
        assert!(matches!(result, Err(HarnessError::InvalidSafeValue(_))));
        finish(scenario).unwrap();
    }

    #[test]
    fn inventory_contains_only_opaque_ids_kinds_sizes_and_modes() {
        let mut scenario = harness(b"inventory-canary")
            .scenario("inventory", 1)
            .unwrap();
        scenario
            .capture(ArtifactKind::ServerStderr, b"safe")
            .unwrap();
        let report = finish(scenario).unwrap();
        let serialized = serde_json::to_string(&report.inventory).unwrap();
        assert!(!serialized.contains("server-stderr"));
        assert!(report.inventory.iter().all(|entry| entry.mode == 0o600));
    }

    #[test]
    fn run_root_is_private_and_global_timeout_fails_closed() {
        let harness = Harness::builder("timeout-test")
            .register_canary(b"global-timeout-canary")
            .global_timeout(Duration::ZERO)
            .build()
            .unwrap();
        assert_eq!(
            std::fs::metadata(&harness.inner.root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let mut scenario = harness.scenario("global-timeout", 1).unwrap();
        assert!(
            scenario
                .step(
                    "late-step",
                    SafeSummary::new(),
                    ExpectedOutcome::Success,
                    ActualOutcome::Success,
                )
                .is_err()
        );
    }

    fn manifest_to_json(manifest: &SanitizedManifest) -> String {
        serde_json::to_string(manifest).unwrap()
    }
}
