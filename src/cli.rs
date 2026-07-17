use clap::{Parser, Subcommand, ValueEnum};
use ops_light_secrets_server::clock::{ClockRepairRequest, validate_repair};
use ops_light_secrets_server::config::{Config, SecretSource, SystemSecretInput};
use ops_light_secrets_server::startup::validate_serve_shell;
use ops_light_secrets_server::store::keyring::{
    AgeIdentityMetadata, IdentityPurpose, SystemRandom, generate_age_identity,
};
use ops_light_secrets_server::store::{
    Canonical, CheckpointDescriptor, CheckpointPublicKey, SignedSigningTransition,
    SigningKeyCandidate, SigningTransition, generate_signing_key, sign_checkpoint_authorized,
    sign_signing_transition, write_checkpoint_atomic, write_signed_transition_atomic,
};
use std::ffi::OsString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::path::PathBuf;

const LONG_ABOUT: &str = "Local secrets service. Configuration comes from --config and OLSS_* environment settings.\n\
Secret settings accept descriptors only: stdin, fd:N, credential:NAME, tty, or env:NAME with --unsafe-dev-secret-env.\n\
TLS files: OLSS_TLS_CERTIFICATE and OLSS_TLS_PRIVATE_KEY. Mount settings: OLSS_MOUNTS_SECRET_CAS_REQUIRED and OLSS_MOUNTS_SECRET_MAX_VERSIONS.
Checkpoint settings: OLSS_CHECKPOINT_MAX_AGE_SECONDS and OLSS_CHECKPOINT_MAX_UNANCHORED_EVENTS.";

#[derive(Debug, Parser)]
#[command(name = "ops-light-secrets-server", version, about, long_about = LONG_ABOUT)]
struct Cli {
    /// TOML configuration file; overrides OLSS_CONFIG
    #[arg(long, global = true, env = "OLSS_CONFIG")]
    config: Option<PathBuf>,

    /// Permit development-only env:NAME secret descriptors
    #[arg(long, global = true)]
    unsafe_dev_secret_env: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a new local store
    Init {
        /// Short-lived first control credential lifetime (5m minimum, 7d maximum)
        #[arg(long, default_value = "24h")]
        bootstrap_ttl: String,

        /// Pre-opened TTY, pipe, socket, or anonymous memory FD for credential custody
        #[arg(long)]
        credential_output_fd: Option<i32>,

        /// Optional distinct public age recovery recipient
        #[arg(long)]
        recovery_recipient: Option<String>,
    },
    /// Validate configuration and serve requests
    Serve,
    /// Offline clock recovery operations
    Clock {
        #[command(subcommand)]
        command: ClockCommand,
    },
    /// Stateless key bootstrap operations
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// External audit checkpoint operations
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Manage identities through the owner-only control socket
    Identity {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Manage grants through the owner-only control socket
    Grant {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// Explain an authorization decision through the owner-only control socket
    Authz {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[command(subcommand)]
        command: AuthzCommand,
    },
    /// Issue, list, and revoke direct tokens through the owner-only control socket
    Token {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Manage AppRole roles and disclosure-once secret IDs
    Approle {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[command(subcommand)]
        command: AppRoleCommand,
    },
    /// Local store maintenance operations
    Store {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[command(subcommand)]
        command: StoreCommand,
    },
}

#[derive(Debug, Subcommand)]
enum StoreCommand {
    /// Inspect or recover the allocated capacity reserve
    Reserve {
        #[command(subcommand)]
        command: StoreReserveCommand,
    },
}

#[derive(Debug, Subcommand)]
enum StoreReserveCommand {
    /// Show authenticated reserve generation, allocation, and capacity band
    Status,
    /// Release allocated blocks after data admission has stopped
    Release {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: String,
    },
    /// Reallocate and verify the reserve before restoring readiness
    Recreate {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: String,
    },
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    Issue {
        #[arg(long)]
        identity_id: String,
        #[arg(long, value_parser = ["data", "control"])]
        audience: String,
        #[arg(long)]
        ttl: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        request_id: String,
        /// Approved TTY, pipe, socket, or anonymous-memory FD; stdout gets metadata only
        #[arg(long, value_parser = parse_private_fd)]
        credential_output_fd: i32,
    },
    List {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        label: Option<String>,
    },
    Revoke {
        accessor: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
enum AppRoleCommand {
    Role {
        #[command(subcommand)]
        command: AppRoleRoleCommand,
    },
    SecretId {
        #[command(subcommand)]
        command: AppRoleSecretIdCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AppRoleRoleCommand {
    Create {
        #[arg(long)]
        role_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        identity_id: String,
        #[arg(long)]
        token_ttl: String,
        #[arg(long)]
        request_id: String,
    },
    List {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Delete {
        role_id: String,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        invalidated_secret_id_count: usize,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirmation: String,
    },
}

#[derive(Debug, Subcommand)]
enum AppRoleSecretIdCommand {
    Issue {
        #[arg(long)]
        role_id: String,
        #[arg(long)]
        ttl: String,
        #[arg(long)]
        use_count: u32,
        #[arg(long)]
        consumer_instance_id: Option<String>,
        #[arg(long)]
        accept_identity_only_tracking: bool,
        #[arg(long)]
        label: String,
        #[arg(long)]
        request_id: String,
        /// Approved TTY, pipe, socket, or anonymous-memory FD; stdout gets metadata only
        #[arg(long, value_parser = parse_private_fd)]
        credential_output_fd: i32,
    },
    List {
        #[arg(long)]
        role_id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Revoke {
        accessor: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, clap::Args)]
struct ControlConnectionArgs {
    /// Owner-only Unix control socket
    #[arg(long)]
    control_socket: PathBuf,

    /// Control-audience credential source descriptor; never pass bearer bytes in argv
    #[arg(long)]
    control_credential_source: SecretSource,

    /// Stable machine output or concise operator output
    #[arg(long, value_enum, default_value = "human")]
    output: OutputFormat,
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_enum)]
        kind: IdentityKindArg,
    },
    List {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Show {
        identity_id: String,
    },
    Disable {
        identity_id: String,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IdentityKindArg {
    Human,
    Workload,
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    Add {
        #[arg(long)]
        identity_id: String,
        #[arg(long)]
        mount: String,
        #[arg(long, value_parser = ["exact", "subtree"])]
        scope: String,
        #[arg(long = "prefix-segment")]
        prefix_segments: Vec<String>,
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
    },
    Remove {
        grant_id: String,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        reason: String,
    },
    List {
        #[arg(long)]
        identity_id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum AuthzCommand {
    Explain {
        #[arg(long)]
        identity_id: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        operation: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Checkpoint preparation, offline signing, and registration
    Checkpoint {
        #[command(subcommand)]
        command: CheckpointCommand,
    },
    /// External signing-key trust generation, enrollment, inspection, and rollover
    SigningKey {
        #[command(subcommand)]
        command: SigningKeyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SigningKeyCommand {
    /// Generate an Ed25519 key; private bytes go only to the approved FD
    Generate {
        #[arg(long, value_parser = parse_private_fd)]
        private_output_fd: i32,
        #[arg(long, value_enum, default_value = "human")]
        output: OutputFormat,
    },
    /// Enroll the first public signing key through the owner control socket
    Enroll {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirmation: String,
        #[arg(long)]
        custody_attested: bool,
    },
    /// List current and retired public signing lineage
    List {
        #[command(flatten)]
        connection: ControlConnectionArgs,
    },
    /// Prepare, sign, or register an old-key-authorized rollover
    Rotate {
        #[command(subcommand)]
        command: SigningKeyRotateCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SigningKeyRotateCommand {
    /// Commit a public-only rollover intent and emit its canonical statement
    Prepare {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        new_candidate: PathBuf,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        expires_at_milliseconds: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        custody_attested: bool,
    },
    /// Sign a prepared transition offline with the old private key
    Sign {
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        old_public_key_candidate: PathBuf,
        #[arg(long)]
        private_key_source: SecretSource,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify and atomically activate a signed transition
    Register {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        signed_transition: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirmation: String,
    },
}

#[derive(Debug, Subcommand)]
enum CheckpointCommand {
    /// Sign a canonical prepared descriptor without contacting daemon
    Sign {
        /// Canonical descriptor emitted by checkpoint prepare
        #[arg(long)]
        descriptor: PathBuf,

        /// Canonical retained public-key descriptor, including validity window
        #[arg(long)]
        public_key_descriptor: PathBuf,

        /// Approved typed source: stdin, fd:N, credential:NAME, tty, or guarded env:NAME
        #[arg(long)]
        private_key_source: SecretSource,

        /// New detached checkpoint file; existing paths and symlinks are refused
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate separately custodied age identities
    AgeIdentity {
        #[command(subcommand)]
        command: AgeIdentityCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AgeIdentityCommand {
    /// Generate one age identity and disclose its private value only to an approved FD
    Generate {
        /// Independent custody purpose
        #[arg(long, value_enum)]
        purpose: IdentityPurposeArg,

        /// Pre-opened TTY, pipe, socket, or anonymous-memory FD for the private identity
        #[arg(long, value_parser = parse_private_fd)]
        private_output_fd: i32,

        /// Public metadata rendering
        #[arg(long, value_enum, default_value = "human")]
        output: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IdentityPurposeArg {
    Active,
    Recovery,
    AuditExport,
}

impl From<IdentityPurposeArg> for IdentityPurpose {
    fn from(value: IdentityPurposeArg) -> Self {
        match value {
            IdentityPurposeArg::Active => Self::Active,
            IdentityPurposeArg::Recovery => Self::Recovery,
            IdentityPurposeArg::AuditExport => Self::AuditExport,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
enum ClockCommand {
    /// Replace a known-bad persisted clock mark (offline)
    Repair {
        /// Exact persisted mark expected in the store
        #[arg(long)]
        exact_old_unix_seconds: u64,

        /// Replacement Unix time in seconds
        #[arg(long)]
        replacement_unix_seconds: u64,

        /// Audited operator reason
        #[arg(long)]
        reason: String,

        /// Pre-opened TTY, pipe, socket, or anonymous memory FD for replacement credential
        #[arg(long)]
        credential_output_fd: Option<i32>,
    },
}

pub fn run() -> Result<(), String> {
    let args: Vec<OsString> = std::env::args_os().collect();
    reject_secret_argv(&args)?;
    let cli = Cli::parse_from(args);

    if let Some(Command::Key {
        command:
            KeyCommand::AgeIdentity {
                command:
                    AgeIdentityCommand::Generate {
                        purpose,
                        private_output_fd,
                        output,
                    },
            },
    }) = &cli.command
    {
        return run_age_identity_generate((*purpose).into(), *private_output_fd, *output);
    }
    if let Some(Command::Audit {
        command:
            AuditCommand::Checkpoint {
                command:
                    CheckpointCommand::Sign {
                        descriptor,
                        public_key_descriptor,
                        private_key_source,
                        output,
                    },
            },
    }) = &cli.command
    {
        return run_checkpoint_sign(
            descriptor,
            public_key_descriptor,
            private_key_source,
            output,
            cli.unsafe_dev_secret_env,
        );
    }
    if let Some(Command::Audit {
        command:
            AuditCommand::SigningKey {
                command:
                    SigningKeyCommand::Generate {
                        private_output_fd,
                        output,
                    },
            },
    }) = &cli.command
    {
        return run_signing_key_generate(*private_output_fd, *output);
    }
    if let Some(Command::Audit {
        command:
            AuditCommand::SigningKey {
                command:
                    SigningKeyCommand::Rotate {
                        command:
                            SigningKeyRotateCommand::Sign {
                                transition,
                                old_public_key_candidate,
                                private_key_source,
                                output,
                            },
                    },
            },
    }) = &cli.command
    {
        return run_signing_key_rotate_sign(
            transition,
            old_public_key_candidate,
            private_key_source,
            output,
            cli.unsafe_dev_secret_env,
        );
    }

    if let Some(command) = &cli.command {
        let config = Config::load(cli.config.as_deref(), cli.unsafe_dev_secret_env)
            .map_err(|error| error.to_string())?;
        match command {
            Command::Serve => {
                validate_serve_shell(&config).map_err(|error| error.to_string())?;
            }
            Command::Init {
                bootstrap_ttl,
                credential_output_fd,
                recovery_recipient,
            } => {
                ops_light_secrets_server::init::parse_bootstrap_ttl(bootstrap_ttl)
                    .map_err(|error| error.to_string())?;
                if credential_output_fd.is_none() {
                    return Err("init_refused code=credential_sink_required setting=credential_output_fd remediation='pass a pre-opened TTY, pipe, socket, or anonymous memory FD'".into());
                }
                if config.age_identity.is_none() {
                    return Err(
                        "init_refused code=missing_key_material setting=secrets.age_identity"
                            .into(),
                    );
                }
                if recovery_recipient
                    .as_deref()
                    .map(str::parse::<age::x25519::Recipient>)
                    .transpose()
                    .is_err()
                {
                    return Err(
                        "init_refused code=invalid_recovery_recipient setting=recovery_recipient"
                            .into(),
                    );
                }
                return Err(
                    "init_refused code=integration_pending setting=store.transaction".into(),
                );
            }
            Command::Clock {
                command:
                    ClockCommand::Repair {
                        exact_old_unix_seconds,
                        replacement_unix_seconds,
                        reason,
                        credential_output_fd,
                    },
            } => {
                if credential_output_fd.is_none() {
                    return Err("clock_repair_refused code=credential_sink_required setting=credential_output_fd remediation='pass a pre-opened TTY, pipe, socket, or anonymous memory FD'".into());
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "clock_repair_refused code=system_clock_before_epoch")?
                    .as_secs();
                validate_repair(
                    &ClockRepairRequest {
                        exact_old_high_water_unix_seconds: *exact_old_unix_seconds,
                        replacement_unix_seconds: *replacement_unix_seconds,
                        reason: reason.clone(),
                    },
                    now,
                )
                .map_err(|error| error.to_string())?;
                return Err("clock_repair_refused code=integration_pending setting=credential_epoch_replacement remediation='complete U8.3 R41 primitive'".into());
            }
            Command::Key { .. } => unreachable!("stateless key command handled before config"),
            Command::Audit { .. } => {
                return Err("signing_trust_refused code=integration_pending setting=authenticated_control_coordinator remediation='complete live signing-trust persistence adapter'".into());
            }
            Command::Identity { .. }
            | Command::Grant { .. }
            | Command::Authz { .. }
            | Command::Token { .. }
            | Command::Approle { .. }
            | Command::Store { .. } => {
                return Err("control_command_refused code=integration_pending setting=authenticated_request_coordinator remediation='complete U4.2 control-credential middleware and coordinator adapter'".into());
            }
        }
    }
    Ok(())
}

fn run_checkpoint_sign(
    descriptor_path: &std::path::Path,
    public_key_descriptor_path: &std::path::Path,
    source: &SecretSource,
    output: &std::path::Path,
    unsafe_environment: bool,
) -> Result<(), String> {
    if matches!(source, SecretSource::UnsafeEnvironment(_)) && !unsafe_environment {
        return Err(
            "checkpoint signing key environment source requires --unsafe-dev-secret-env".into(),
        );
    }
    let descriptor = std::fs::read(descriptor_path)
        .map_err(|_| "checkpoint descriptor read failed")
        .and_then(|bytes| {
            CheckpointDescriptor::decode(&bytes)
                .map_err(|_| "checkpoint descriptor verification failed")
        })?;
    let public = std::fs::read(public_key_descriptor_path)
        .map_err(|_| "checkpoint public key descriptor read failed")
        .and_then(|bytes| {
            CheckpointPublicKey::decode(&bytes)
                .map_err(|_| "checkpoint public key descriptor verification failed")
        })?;
    let mut input = SystemSecretInput::from_environment();
    let secret = source
        .read("checkpoint.private_key_source", &mut input)
        .map_err(|_| "checkpoint private key source failed")?;
    let mut private: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "checkpoint private key must be exactly 32 raw bytes")?;
    let checkpoint = sign_checkpoint_authorized(descriptor, &public, &mut private)
        .map_err(|error| error.to_string())?;
    write_checkpoint_atomic(output, &checkpoint).map_err(|error| error.to_string())
}

fn run_signing_key_generate(private_output_fd: i32, output: OutputFormat) -> Result<(), String> {
    let duplicate = unsafe { libc::fcntl(private_output_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err("signing key private sink unavailable".into());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a new descriptor owned by us.
    let mut sink = unsafe { std::fs::File::from_raw_fd(duplicate) };
    let metadata =
        generate_signing_key(&mut sink, &mut SystemRandom).map_err(|error| error.to_string())?;
    let rendered = match output {
        OutputFormat::Json => serde_json::to_string(&metadata)
            .map_err(|_| "signing key public metadata encoding failed".to_owned())?,
        OutputFormat::Human => format!(
            "algorithm: {}\ndomain: {}\nkey id: {}\nfingerprint: {}\npublic key: {}\ncandidate: {}\nsink outcome: {}\ncustody: {}",
            metadata.algorithm,
            metadata.domain,
            metadata.key_id,
            metadata.fingerprint,
            metadata.public_key,
            metadata.candidate,
            metadata.sink_outcome_id,
            metadata.custody,
        ),
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| "signing key public metadata write failed".into())
}

fn run_signing_key_rotate_sign(
    transition_path: &std::path::Path,
    old_public_path: &std::path::Path,
    source: &SecretSource,
    output: &std::path::Path,
    unsafe_environment: bool,
) -> Result<(), String> {
    if matches!(source, SecretSource::UnsafeEnvironment(_)) && !unsafe_environment {
        return Err("signing key environment source requires --unsafe-dev-secret-env".into());
    }
    let transition = std::fs::read(transition_path)
        .map_err(|_| "signing transition read failed")
        .and_then(|bytes| {
            SigningTransition::decode(&bytes).map_err(|_| "signing transition verification failed")
        })?;
    let old_public = std::fs::read(old_public_path)
        .map_err(|_| "old signing public key read failed")
        .and_then(|bytes| {
            SigningKeyCandidate::decode(&bytes)
                .map_err(|_| "old signing public key verification failed")
        })?;
    if old_public.id != transition.old_key_id {
        return Err("old signing public key does not match transition".into());
    }
    let mut input = SystemSecretInput::from_environment();
    let secret = source
        .read("signing_trust.old_private_key_source", &mut input)
        .map_err(|_| "old signing private key source failed")?;
    let mut private: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "old signing private key must be exactly 32 raw bytes")?;
    let signed: SignedSigningTransition =
        sign_signing_transition(transition, &mut private).map_err(|error| error.to_string())?;
    write_signed_transition_atomic(output, &signed).map_err(|error| error.to_string())
}

fn parse_private_fd(value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .ok()
        .filter(|fd| *fd >= 3)
        .ok_or_else(|| "private output descriptor must be at least 3".into())
}

fn run_age_identity_generate(
    purpose: IdentityPurpose,
    private_output_fd: i32,
    output: OutputFormat,
) -> Result<(), String> {
    let duplicate = unsafe { libc::fcntl(private_output_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err("age identity private sink unavailable".into());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a new descriptor owned by us.
    let mut sink = unsafe { std::fs::File::from_raw_fd(duplicate) };
    let metadata = generate_age_identity(purpose, &mut sink, &mut SystemRandom)
        .map_err(|error| error.to_string())?;
    write_public_metadata(&metadata, output)
}

fn write_public_metadata(
    metadata: &AgeIdentityMetadata,
    output: OutputFormat,
) -> Result<(), String> {
    let rendered = match output {
        OutputFormat::Json => serde_json::to_string(metadata)
            .map_err(|_| "age identity public metadata encoding failed".to_owned())?,
        OutputFormat::Human => format!(
            "purpose: {}\nalgorithm: {}\nrecipient: {}\nfingerprint: {}\nsink outcome: {}\ncustody: protect the private identity independently; never place it in argv, environment, logs, or the store",
            metadata.purpose,
            metadata.algorithm,
            metadata.recipient,
            metadata.fingerprint,
            metadata.sink_outcome_id,
        ),
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| "age identity public metadata write failed".into())
}

fn reject_secret_argv(args: &[OsString]) -> Result<(), String> {
    const FORBIDDEN: [(&str, &str); 2] = [
        ("--age-identity", "age_identity"),
        ("--tls-key-passphrase", "tls_key_passphrase"),
    ];

    for arg in args.iter().skip(1) {
        let arg = arg.to_string_lossy();
        for (flag, setting) in FORBIDDEN {
            if arg == flag || arg.starts_with(&format!("{flag}=")) {
                return Err(format!(
                    "secret setting {setting} may not be supplied via argv; use a secret-source descriptor"
                ));
            }
        }
    }
    Ok(())
}
