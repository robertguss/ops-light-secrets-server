use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, Verifier};
use ops_light_secrets_server::backup::{sign_backup, write_detached_signature_atomic};
use ops_light_secrets_server::backup_format::{
    BackupContainer, DetachedBackupSignature, unsigned_confirmation,
};
use ops_light_secrets_server::backup_verify::{
    FullVerifyRequest, RehearsalMode, verify_backup, verify_backup_full,
    write_rehearsal_receipt_atomic,
};
use ops_light_secrets_server::clock::{ClockRepairRequest, validate_repair};
use ops_light_secrets_server::config::{Config, SecretSource, SystemSecretInput};
use ops_light_secrets_server::control::management::{
    ControlCommand, ManagementCatalog, ManagementPrincipal,
};
use ops_light_secrets_server::credential::{CredentialAudience, CredentialKind};
use ops_light_secrets_server::credential_epoch::{
    EpochRotationMode, EpochRotationRequest, InterruptedJobState, plan_epoch_rotation,
    rotate_credential_epoch,
};
use ops_light_secrets_server::restore::{
    RestoreRequest, RestoreSignature, restore, restore_assertion_confirmation,
};
use ops_light_secrets_server::startup::DataDirectoryLock;
use ops_light_secrets_server::startup::validate_serve_shell;
use ops_light_secrets_server::store::keyring::{
    AgeIdentityMetadata, IdentityPurpose, KeyringError, KeyringOpener, RandomSource,
    RecipientRewrapFault, RecipientRewrapRequest, RecipientSet, SystemRandom,
    generate_age_identity, parse_identity, recipient_rewrap_confirmation,
};
use ops_light_secrets_server::store::{
    AuditAuthMethod, AuditAuthentication, AuditAuthorization, AuditCapability, AuditEvent,
    AuditOperation, AuditOutcome, AuditReason, AuditResource, AuditStateCommitment, Canonical,
    CheckpointDescriptor, CheckpointPublicKey, SignedSigningTransition, SigningKeyCandidate,
    SigningTransition, Store, generate_signing_key, sign_checkpoint_authorized,
    sign_signing_transition, write_checkpoint_atomic, write_signed_transition_atomic,
};
use std::ffi::OsString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    /// Create, inspect, sign, and recover logical backup artifacts
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Verify and atomically install a logical backup on a fresh host
    Restore {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        public_key_candidate: PathBuf,
        #[arg(long)]
        signing_private_key_source: SecretSource,
        #[arg(long)]
        recovery_identity_source: SecretSource,
        #[arg(long)]
        new_active_identity_source: SecretSource,
        #[arg(long)]
        keyring_recovery_recipient: Option<String>,
        #[arg(long)]
        target: PathBuf,
        #[arg(long, value_parser = parse_private_fd)]
        credential_output_fd: i32,
        #[arg(long)]
        source_decommissioned: bool,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        allow_unsigned_manifest: bool,
        #[arg(long)]
        unsigned_confirm: Option<String>,
        #[arg(long, value_enum, default_value = "human")]
        output: OutputFormat,
    },
    /// Incident credential invalidation and emergency control recovery
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    Epoch {
        #[command(subcommand)]
        command: CredentialEpochCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CredentialEpochCommand {
    Rotate {
        #[arg(long, value_enum)]
        mode: EpochModeArg,
        #[arg(long)]
        identity_source: Option<SecretSource>,
        #[arg(long)]
        control_socket: Option<PathBuf>,
        #[arg(long)]
        control_credential_source: Option<SecretSource>,
        #[arg(long)]
        expected_epoch: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long, value_parser = parse_private_fd)]
        credential_output_fd: Option<i32>,
        #[arg(long, value_enum, default_value = "human")]
        output: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EpochModeArg {
    Online,
    Offline,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    Create {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long = "archive-output")]
        archive_output: PathBuf,
    },
    List {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        publication: Option<String>,
        #[arg(long)]
        signature: Option<String>,
        #[arg(long)]
        rehearsal: Option<String>,
        #[arg(long)]
        disposition: Option<String>,
    },
    Show {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        manifest_digest: String,
    },
    Resume {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        manifest_digest: String,
    },
    Verify {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        public_key_candidate: PathBuf,
        #[arg(long)]
        identity_source: SecretSource,
        #[arg(long)]
        full: bool,
        #[arg(long, value_enum)]
        identity_kind: Option<RehearsalPathArg>,
        #[arg(long)]
        work_directory: Option<PathBuf>,
        #[arg(long)]
        receipt_signing_key_source: Option<SecretSource>,
        #[arg(long)]
        receipt_public_key_candidate: Option<PathBuf>,
        #[arg(long)]
        receipt_output: Option<PathBuf>,
        #[arg(long)]
        allow_unsigned_manifest: bool,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        unsigned_confirm: Option<String>,
        #[arg(long, value_enum, default_value = "human")]
        output: OutputFormat,
    },
    Rehearsal {
        #[command(subcommand)]
        command: BackupRehearsalCommand,
    },
    Recipient {
        #[command(subcommand)]
        command: BackupRecipientCommand,
    },
    Manifest {
        #[command(subcommand)]
        command: BackupManifestCommand,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RehearsalPathArg {
    Active,
    Recovery,
}

impl From<RehearsalPathArg> for RehearsalMode {
    fn from(value: RehearsalPathArg) -> Self {
        match value {
            RehearsalPathArg::Active => Self::ActiveRecipient,
            RehearsalPathArg::Recovery => Self::RecoveryRecipient,
        }
    }
}

#[derive(Debug, Subcommand)]
enum BackupRehearsalCommand {
    Record {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        receipt: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BackupRecipientCommand {
    List {
        #[command(flatten)]
        connection: ControlConnectionArgs,
    },
    Set {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long = "recovery-recipient", required = true, num_args = 1..=7)]
        recovery_recipients: Vec<String>,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: String,
    },
}

#[derive(Debug, Subcommand)]
enum BackupManifestCommand {
    Sign {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        public_key_candidate: PathBuf,
        #[arg(long)]
        private_key_source: SecretSource,
        #[arg(long = "signature-output")]
        signature_output: PathBuf,
    },
    Abandon {
        #[command(flatten)]
        connection: ControlConnectionArgs,
        manifest_digest: String,
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: String,
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
    /// Rotate the active age recipient without touching protected records
    Recipient {
        #[command(subcommand)]
        command: RecipientCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RecipientCommand {
    /// Offline atomic recipient rewrap under the key-rotation capability
    Rewrap {
        #[arg(long)]
        expected_generation: u64,
        #[arg(long)]
        current_identity_source: SecretSource,
        #[arg(long)]
        new_active_identity_source: SecretSource,
        #[arg(long)]
        recovery_recipient: Option<String>,
        #[arg(long)]
        control_credential_source: SecretSource,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long, value_enum, default_value = "human")]
        output: OutputFormat,
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
    if let Some(Command::Backup {
        command:
            BackupCommand::Manifest {
                command:
                    BackupManifestCommand::Sign {
                        archive,
                        public_key_candidate,
                        private_key_source,
                        signature_output,
                        ..
                    },
            },
    }) = &cli.command
    {
        return run_backup_manifest_sign(
            archive,
            public_key_candidate,
            private_key_source,
            signature_output,
            cli.unsafe_dev_secret_env,
        );
    }
    if let Some(Command::Backup {
        command:
            BackupCommand::Verify {
                archive,
                signature,
                public_key_candidate,
                identity_source,
                full,
                identity_kind,
                work_directory,
                receipt_signing_key_source,
                receipt_public_key_candidate,
                receipt_output,
                allow_unsigned_manifest,
                reason,
                unsigned_confirm,
                output,
            },
    }) = &cli.command
    {
        return run_backup_verify(BackupVerifyCli {
            archive,
            signature: signature.as_deref(),
            public_key_candidate,
            identity_source,
            full: *full,
            identity_kind: *identity_kind,
            work_directory: work_directory.as_deref(),
            receipt_signing_key_source: receipt_signing_key_source.as_ref(),
            receipt_public_key_candidate: receipt_public_key_candidate.as_deref(),
            receipt_output: receipt_output.as_deref(),
            allow_unsigned_manifest: *allow_unsigned_manifest,
            reason: reason.as_deref(),
            unsigned_confirm: unsigned_confirm.as_deref(),
            output: *output,
            unsafe_environment: cli.unsafe_dev_secret_env,
        });
    }
    if let Some(Command::Restore {
        archive,
        signature,
        public_key_candidate,
        signing_private_key_source,
        recovery_identity_source,
        new_active_identity_source,
        keyring_recovery_recipient,
        target,
        credential_output_fd,
        source_decommissioned,
        actor_id,
        reason,
        confirm,
        allow_unsigned_manifest,
        unsigned_confirm,
        output,
    }) = &cli.command
    {
        return run_restore(RestoreCli {
            archive,
            signature: signature.as_deref(),
            public_key_candidate,
            signing_private_key_source,
            recovery_identity_source,
            new_active_identity_source,
            keyring_recovery_recipient: keyring_recovery_recipient.as_deref(),
            target,
            credential_output_fd: *credential_output_fd,
            source_decommissioned: *source_decommissioned,
            actor_id,
            reason,
            confirm,
            allow_unsigned_manifest: *allow_unsigned_manifest,
            unsigned_confirm: unsigned_confirm.as_deref(),
            output: *output,
            unsafe_environment: cli.unsafe_dev_secret_env,
        });
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
            Command::Key {
                command: KeyCommand::AgeIdentity { .. },
            } => unreachable!("stateless key command handled before config"),
            Command::Key {
                command:
                    KeyCommand::Recipient {
                        command:
                            RecipientCommand::Rewrap {
                                expected_generation,
                                current_identity_source,
                                new_active_identity_source,
                                recovery_recipient,
                                control_credential_source,
                                reason,
                                confirm,
                                output,
                            },
                    },
            } => {
                return run_recipient_rewrap(
                    &config,
                    RecipientRewrapCli {
                        expected_generation: *expected_generation,
                        current_identity_source,
                        new_active_identity_source,
                        recovery_recipient: recovery_recipient.as_deref(),
                        control_credential_source,
                        reason,
                        confirm: confirm.as_deref(),
                        output: *output,
                        unsafe_environment: cli.unsafe_dev_secret_env,
                    },
                );
            }
            Command::Credential {
                command:
                    CredentialCommand::Epoch {
                        command:
                            CredentialEpochCommand::Rotate {
                                mode,
                                identity_source,
                                control_socket,
                                control_credential_source,
                                expected_epoch,
                                reason,
                                confirm,
                                credential_output_fd,
                                output,
                            },
                    },
            } => {
                return run_credential_epoch_rotate(
                    &config,
                    *mode,
                    identity_source.as_ref(),
                    control_socket.as_deref(),
                    control_credential_source.as_ref(),
                    *expected_epoch,
                    reason,
                    confirm.as_deref(),
                    *credential_output_fd,
                    *output,
                    cli.unsafe_dev_secret_env,
                );
            }
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
            Command::Backup { .. } => {
                return Err("backup_refused code=live_control_adapter_pending artifact_bytes_unchanged=true remediation='retry after authenticated backup control adapter is available'".into());
            }
            Command::Restore { .. } => unreachable!("offline restore handled before config"),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_credential_epoch_rotate(
    config: &Config,
    mode: EpochModeArg,
    identity_source: Option<&SecretSource>,
    control_socket: Option<&std::path::Path>,
    control_credential_source: Option<&SecretSource>,
    expected_epoch: u64,
    reason: &str,
    confirmation: Option<&str>,
    credential_output_fd: Option<i32>,
    output: OutputFormat,
    unsafe_environment: bool,
) -> Result<(), String> {
    if matches!(mode, EpochModeArg::Online) {
        if control_socket.is_none() || control_credential_source.is_none() {
            return Err("credential_epoch_refused code=online_connection_required".into());
        }
        return Err("credential_epoch_refused code=live_control_adapter_pending remediation='use authenticated online adapter after final assembly or explicitly select offline mode with daemon stopped'".into());
    }
    if control_socket.is_some() || control_credential_source.is_some() {
        return Err("credential_epoch_refused code=mode_authority_confusion".into());
    }
    let identity_source = identity_source
        .ok_or_else(|| "credential_epoch_refused code=identity_source_required".to_owned())?;
    if matches!(identity_source, SecretSource::UnsafeEnvironment(_)) && !unsafe_environment {
        return Err("credential_epoch_refused code=unsafe_environment_source".into());
    }
    let _lock = DataDirectoryLock::acquire(&config.data_directory)
        .map_err(|_| "credential_epoch_refused code=daemon_or_lock_active".to_owned())?;
    let store_path = config.data_directory.join("store.redb");
    let metadata = std::fs::symlink_metadata(&store_path)
        .map_err(|_| "credential_epoch_refused code=store_path".to_owned())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("credential_epoch_refused code=unsafe_store_path".into());
    }
    let store = Store::open(&store_path)
        .map_err(|_| "credential_epoch_refused code=store_open".to_owned())?;
    let mut input = SystemSecretInput::from_environment();
    let identity = identity_source
        .read("credential_epoch.identity_source", &mut input)
        .map_err(|_| "credential_epoch_refused code=identity_source".to_owned())?;
    let identity = parse_identity(identity.into_zeroizing())
        .map_err(|_| "credential_epoch_refused code=identity_invalid".to_owned())?;
    let keyring = KeyringOpener::default()
        .open(
            store
                .meta()
                .map_err(|_| "credential_epoch_refused code=meta".to_owned())?
                .store_id,
            &store
                .keyring()
                .map_err(|_| "credential_epoch_refused code=keyring".to_owned())?
                .ok_or_else(|| "credential_epoch_refused code=uninitialized".to_owned())?,
            &store
                .keyring_metadata()
                .map_err(|_| "credential_epoch_refused code=keyring_metadata".to_owned())?
                .ok_or_else(|| "credential_epoch_refused code=uninitialized".to_owned())?,
            &identity,
        )
        .map_err(|_| "credential_epoch_refused code=identity_rejected".to_owned())?;
    let authority = EpochRotationMode::Offline {
        service_owner: true,
        daemon_absent: true,
        exclusive_lock: true,
        current_keyring_unwrapped: true,
    };
    let plan = plan_epoch_rotation(&store, &keyring, expected_epoch, reason, authority)
        .map_err(|error| format!("credential_epoch_refused code=plan cause={error}"))?;
    let Some(confirmation) = confirmation else {
        return render_epoch_plan(output, &plan);
    };
    let confirmation = parse_hex_32(confirmation)
        .ok_or_else(|| "credential_epoch_refused code=confirmation".to_owned())?;
    let fd = credential_output_fd
        .ok_or_else(|| "credential_epoch_refused code=credential_sink_required".to_owned())?;
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err("credential_epoch_refused code=credential_sink".into());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a new descriptor owned here.
    let mut sink = unsafe { std::fs::File::from_raw_fd(duplicate) };
    let effective_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "credential_epoch_refused code=clock".to_owned())?
        .as_secs()
        .max(
            store
                .meta()
                .map_err(|_| "credential_epoch_refused code=meta".to_owned())?
                .high_water_unix_seconds,
        );
    let receipt = rotate_credential_epoch(
        &store,
        &keyring,
        EpochRotationRequest {
            expected_epoch,
            effective_seconds,
            reason,
            confirmation,
            mode: authority,
            interrupted_job: InterruptedJobState::None,
        },
        &mut sink,
        &mut SystemRandom,
    )
    .map_err(|error| format!("credential_epoch_refused code=rotate cause={error}"))?;
    let value = serde_json::json!({
        "schema": 1,
        "epoch": receipt.epoch,
        "credential_accessor": hex(&receipt.credential_accessor),
        "expires_at_effective_seconds": receipt.expires_at_effective_seconds,
        "auth_recovery_stale": receipt.auth_recovery_stale,
        "prior_credentials_invalidated": true,
    });
    let rendered = match output {
        OutputFormat::Json => serde_json::to_string(&value)
            .map_err(|_| "credential epoch output encoding failed".to_owned())?,
        OutputFormat::Human => format!(
            "epoch: {}\ncredential accessor: {}\nexpires: {}\nprior credentials invalidated: true",
            receipt.epoch,
            hex(&receipt.credential_accessor),
            receipt.expires_at_effective_seconds,
        ),
    };
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .and_then(|()| std::io::stdout().write_all(b"\n"))
        .map_err(|_| "credential epoch output failed".to_owned())
}

fn render_epoch_plan(
    output: OutputFormat,
    plan: &ops_light_secrets_server::credential_epoch::EpochRotationPlan,
) -> Result<(), String> {
    let value = serde_json::json!({
        "schema": 1,
        "current_epoch": plan.current_epoch,
        "next_epoch": plan.next_epoch,
        "active_tokens": plan.active_tokens,
        "active_secret_ids": plan.active_secret_ids,
        "caller_credential_dies": plan.caller_credential_dies,
        "replacement_ttl_seconds": plan.replacement_ttl_seconds,
        "confirmation": hex(&plan.confirmation),
        "mutation": false,
    });
    let rendered = match output {
        OutputFormat::Json => serde_json::to_string(&value)
            .map_err(|_| "credential epoch plan encoding failed".to_owned())?,
        OutputFormat::Human => format!(
            "current epoch: {}\nnext epoch: {}\nactive tokens: {}\nactive secret ids: {}\ncaller credential dies: true\nconfirmation: {}\nmutation: false",
            plan.current_epoch,
            plan.next_epoch,
            plan.active_tokens,
            plan.active_secret_ids,
            hex(&plan.confirmation),
        ),
    };
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .and_then(|()| std::io::stdout().write_all(b"\n"))
        .map_err(|_| "credential epoch plan output failed".to_owned())
}

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        output[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

fn parse_hex_16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut output = [0; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(output)
}

fn run_backup_manifest_sign(
    archive_path: &std::path::Path,
    public_key_path: &std::path::Path,
    source: &SecretSource,
    output: &std::path::Path,
    unsafe_environment: bool,
) -> Result<(), String> {
    if matches!(source, SecretSource::UnsafeEnvironment(_)) && !unsafe_environment {
        return Err(
            "backup signing key environment source requires --unsafe-dev-secret-env".into(),
        );
    }
    let container = std::fs::read(archive_path)
        .map_err(|_| "backup archive read failed")
        .and_then(|bytes| {
            BackupContainer::decode(&bytes).map_err(|_| "backup archive verification failed")
        })?;
    let public = std::fs::read(public_key_path)
        .map_err(|_| "backup public key candidate read failed")
        .and_then(|bytes| {
            SigningKeyCandidate::decode(&bytes)
                .map_err(|_| "backup public key candidate verification failed")
        })?;
    if public.id != container.header.signing_key_id {
        return Err("backup signing key does not match frozen header".into());
    }
    let mut input = SystemSecretInput::from_environment();
    let secret = source
        .read("backup.private_key_source", &mut input)
        .map_err(|_| "backup private key source failed")?;
    let mut private: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| "backup private key must be exactly 32 raw bytes")?;
    let signature = sign_backup(&container, &public.verifying_key, &mut private)
        .map_err(|error| error.to_string())?;
    write_detached_signature_atomic(output, &signature).map_err(|error| error.to_string())
}

struct BackupVerifyCli<'a> {
    archive: &'a std::path::Path,
    signature: Option<&'a std::path::Path>,
    public_key_candidate: &'a std::path::Path,
    identity_source: &'a SecretSource,
    full: bool,
    identity_kind: Option<RehearsalPathArg>,
    work_directory: Option<&'a std::path::Path>,
    receipt_signing_key_source: Option<&'a SecretSource>,
    receipt_public_key_candidate: Option<&'a std::path::Path>,
    receipt_output: Option<&'a std::path::Path>,
    allow_unsigned_manifest: bool,
    reason: Option<&'a str>,
    unsigned_confirm: Option<&'a str>,
    output: OutputFormat,
    unsafe_environment: bool,
}

fn run_backup_verify(request: BackupVerifyCli<'_>) -> Result<(), String> {
    if !request.unsafe_environment
        && std::iter::once(request.identity_source)
            .chain(request.receipt_signing_key_source)
            .any(|source| matches!(source, SecretSource::UnsafeEnvironment(_)))
    {
        return Err("backup_verify_refused code=unsafe_environment_source".into());
    }
    let container = std::fs::read(request.archive)
        .map_err(|_| "backup_verify_refused code=archive_read".to_owned())
        .and_then(|bytes| {
            BackupContainer::decode(&bytes)
                .map_err(|_| "backup_verify_refused code=outer_archive".to_owned())
        })?;
    let candidate = std::fs::read(request.public_key_candidate)
        .map_err(|_| "backup_verify_refused code=public_key_candidate_read".to_owned())
        .and_then(|bytes| {
            SigningKeyCandidate::decode(&bytes)
                .map_err(|_| "backup_verify_refused code=public_key_candidate_decode".to_owned())
        })?;
    if candidate.id != container.header.signing_key_id {
        return Err("backup_verify_refused code=public_key_candidate_id_mismatch".into());
    }
    let detached = request
        .signature
        .map(|path| {
            std::fs::read(path)
                .map_err(|_| "backup_verify_refused code=signature_read".to_owned())
                .and_then(|bytes| {
                    DetachedBackupSignature::decode(&bytes)
                        .map_err(|_| "backup_verify_refused code=signature_decode".to_owned())
                })
        })
        .transpose()?;
    let reason = request.reason.unwrap_or("");
    let signature = match &detached {
        Some(detached) => RestoreSignature::Signed {
            detached,
            authenticated_public_key: &candidate.verifying_key,
        },
        None => RestoreSignature::Unsigned {
            allow_unsigned: request.allow_unsigned_manifest,
            reason,
            confirmation: request.unsigned_confirm.unwrap_or(""),
        },
    };
    let mut input = SystemSecretInput::from_environment();
    let identity = parse_identity(
        request
            .identity_source
            .read("backup.verify.identity_source", &mut input)
            .map_err(|_| "backup_verify_refused code=identity_source".to_owned())?
            .into_zeroizing(),
    )
    .map_err(|_| "backup_verify_refused code=identity_invalid".to_owned())?;
    let verification = if request.full {
        let expected_mode = request
            .identity_kind
            .ok_or_else(|| "backup_verify_refused code=identity_kind_required".to_owned())?;
        let signing_source = request.receipt_signing_key_source.ok_or_else(|| {
            "backup_verify_refused code=receipt_signing_key_source_required".to_owned()
        })?;
        let receipt_candidate_path = request.receipt_public_key_candidate.ok_or_else(|| {
            "backup_verify_refused code=receipt_public_key_candidate_required".to_owned()
        })?;
        let receipt_output = request
            .receipt_output
            .ok_or_else(|| "backup_verify_refused code=receipt_output_required".to_owned())?;
        let receipt_candidate = std::fs::read(receipt_candidate_path)
            .map_err(|_| "backup_verify_refused code=receipt_public_key_read".to_owned())
            .and_then(|bytes| {
                SigningKeyCandidate::decode(&bytes)
                    .map_err(|_| "backup_verify_refused code=receipt_public_key_decode".to_owned())
            })?;
        let secret = signing_source
            .read("backup.verify.receipt_signing_key_source", &mut input)
            .map_err(|_| "backup_verify_refused code=receipt_signing_key_source".to_owned())?;
        let mut private: [u8; 32] = secret
            .expose()
            .try_into()
            .map_err(|_| "backup_verify_refused code=receipt_signing_key_length".to_owned())?;
        let default_workspace = std::env::temp_dir();
        let workspace = request.work_directory.unwrap_or(&default_workspace);
        if workspace
            == request
                .archive
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
        {
            eprintln!(
                "WARNING: rehearsal workspace shares archive filesystem and can pressure live capacity"
            );
        }
        let performed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "backup_verify_refused code=clock".to_owned())?
            .as_secs();
        let receipt = verify_backup_full(
            &container,
            signature,
            FullVerifyRequest {
                identity: &identity,
                work_directory: workspace,
                performed_at_unix_seconds: performed_at,
                receipt_signing_candidate: &receipt_candidate,
                receipt_private_key: &mut private,
            },
            &mut SystemRandom,
        )
        .map_err(|error| format!("backup_verify_refused code={error}"))?;
        if receipt.mode != expected_mode.into() {
            return Err(format!(
                "backup_verify_refused code=identity_kind_mismatch actual={}",
                receipt.mode.label()
            ));
        }
        write_rehearsal_receipt_atomic(receipt_output, &receipt)
            .map_err(|error| format!("backup_verify_refused code={error}"))?;
        serde_json::json!({
            "schema": 1,
            "archive_digest": hex(&receipt.archive_digest),
            "mode": receipt.mode.label(),
            "record_count": receipt.verified_record_count,
            "receipt": receipt_output,
            "registration_status": "unknown_offline",
            "performed_at_claimed_unix_seconds": receipt.performed_at_unix_seconds,
        })
    } else {
        if request.identity_kind.is_some()
            || request.work_directory.is_some()
            || request.receipt_signing_key_source.is_some()
            || request.receipt_public_key_candidate.is_some()
            || request.receipt_output.is_some()
        {
            return Err("backup_verify_refused code=full_only_argument".into());
        }
        let (verified, _, _) = verify_backup(&container, signature, &identity)
            .map_err(|error| format!("backup_verify_refused code={error}"))?;
        serde_json::json!({
            "schema": 1,
            "archive_digest": hex(&verified.archive_digest),
            "manifest_digest": hex(&verified.manifest_digest),
            "mode": verified.mode.label(),
            "signature_status": format!("{:?}", verified.signature_status).to_lowercase(),
            "full": false,
        })
    };
    let rendered = match request.output {
        OutputFormat::Json => serde_json::to_string(&verification)
            .map_err(|_| "backup_verify_refused code=output_encoding".to_owned())?,
        OutputFormat::Human => serde_json::to_string_pretty(&verification)
            .map_err(|_| "backup_verify_refused code=output_encoding".to_owned())?,
    };
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .and_then(|()| std::io::stdout().write_all(b"\n"))
        .map_err(|_| "backup_verify_refused code=output".to_owned())
}

struct RestoreCli<'a> {
    archive: &'a std::path::Path,
    signature: Option<&'a std::path::Path>,
    public_key_candidate: &'a std::path::Path,
    signing_private_key_source: &'a SecretSource,
    recovery_identity_source: &'a SecretSource,
    new_active_identity_source: &'a SecretSource,
    keyring_recovery_recipient: Option<&'a str>,
    target: &'a std::path::Path,
    credential_output_fd: i32,
    source_decommissioned: bool,
    actor_id: &'a str,
    reason: &'a str,
    confirm: &'a str,
    allow_unsigned_manifest: bool,
    unsigned_confirm: Option<&'a str>,
    output: OutputFormat,
    unsafe_environment: bool,
}

fn run_restore(request: RestoreCli<'_>) -> Result<(), String> {
    if !request.unsafe_environment
        && [
            request.recovery_identity_source,
            request.new_active_identity_source,
            request.signing_private_key_source,
        ]
        .into_iter()
        .any(|source| matches!(source, SecretSource::UnsafeEnvironment(_)))
    {
        return Err("restore_refused code=unsafe_environment_source".into());
    }
    let bytes = std::fs::read(request.archive)
        .map_err(|_| "restore_refused code=archive_read".to_owned())?;
    let container = BackupContainer::decode(&bytes)
        .map_err(|_| "restore_refused code=outer_archive_verification".to_owned())?;
    let detached = request
        .signature
        .map(|path| {
            std::fs::read(path)
                .map_err(|_| "restore_refused code=signature_read".to_owned())
                .and_then(|bytes| {
                    DetachedBackupSignature::decode(&bytes)
                        .map_err(|_| "restore_refused code=signature_decode".to_owned())
                })
        })
        .transpose()?;
    let public = std::fs::read(request.public_key_candidate)
        .map_err(|_| "restore_refused code=public_key_candidate_read".to_owned())
        .and_then(|bytes| {
            SigningKeyCandidate::decode(&bytes)
                .map_err(|_| "restore_refused code=public_key_candidate_decode".to_owned())
        })?;
    if public.id != container.header.signing_key_id {
        return Err("restore_refused code=signer_lineage_key_id".into());
    }
    let signature = match &detached {
        Some(detached) => RestoreSignature::Signed {
            detached,
            authenticated_public_key: &public.verifying_key,
        },
        None => {
            let confirmation = request
                .unsigned_confirm
                .ok_or_else(|| "restore_refused code=unsigned_confirmation_required".to_owned())?;
            eprintln!("HIGH SEVERITY: unsigned restore authorized; archive digest will be audited");
            RestoreSignature::Unsigned {
                allow_unsigned: request.allow_unsigned_manifest,
                reason: request.reason,
                confirmation,
            }
        }
    };
    let mut input = SystemSecretInput::from_environment();
    let recovery_identity = parse_identity(
        request
            .recovery_identity_source
            .read("restore.recovery_identity_source", &mut input)
            .map_err(|_| "restore_refused code=recovery_identity_source".to_owned())?
            .into_zeroizing(),
    )
    .map_err(|_| "restore_refused code=recovery_identity_invalid".to_owned())?;
    let new_active_identity = parse_identity(
        request
            .new_active_identity_source
            .read("restore.new_active_identity_source", &mut input)
            .map_err(|_| "restore_refused code=new_active_identity_source".to_owned())?
            .into_zeroizing(),
    )
    .map_err(|_| "restore_refused code=new_active_identity_invalid".to_owned())?;
    let private = request
        .signing_private_key_source
        .read("restore.signing_private_key_source", &mut input)
        .map_err(|_| "restore_refused code=signing_private_key_source".to_owned())?;
    let private: [u8; 32] = private
        .expose()
        .try_into()
        .map_err(|_| "restore_refused code=signing_private_key_length expected=32".to_owned())?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&private);
    if signing.verifying_key().to_bytes() != public.verifying_key {
        return Err("restore_refused code=signing_private_key_mismatch".into());
    }
    let installed_recovery = request
        .keyring_recovery_recipient
        .map(str::parse::<age::x25519::Recipient>)
        .transpose()
        .map_err(|_| "restore_refused code=keyring_recovery_recipient".to_owned())?;
    let actor_id = parse_hex_16(request.actor_id)
        .ok_or_else(|| "restore_refused code=actor_id expected=32_hex".to_owned())?;
    let assertion = parse_hex_32(request.confirm)
        .ok_or_else(|| "restore_refused code=confirmation expected=64_hex".to_owned())?;
    let recovery_recipient = installed_recovery
        .clone()
        .unwrap_or_else(|| recovery_identity.to_public());
    let archive_digest = ops_light_secrets_server::backup::artifact_digest(&container)
        .map_err(|_| "restore_refused code=archive_digest".to_owned())?;
    let expected = restore_assertion_confirmation(
        archive_digest,
        request.target,
        &new_active_identity.to_public(),
        &recovery_recipient,
        actor_id,
        request.reason,
    )
    .map_err(|_| "restore_refused code=assertion".to_owned())?;
    if assertion != expected {
        return Err(format!(
            "restore_refused code=confirmation_mismatch expected={}",
            hex(&expected)
        ));
    }
    let mut challenge = blake3::Hasher::new();
    challenge.update(b"ops-light-secrets-server.restore-signer-custody.v1\0");
    challenge.update(&archive_digest);
    challenge.update(&assertion);
    challenge.update(request.target.as_os_str().as_encoded_bytes());
    let challenge = challenge.finalize();
    let challenge_signature = signing.sign(challenge.as_bytes());
    signing
        .verifying_key()
        .verify(challenge.as_bytes(), &challenge_signature)
        .map_err(|_| "restore_refused code=signer_custody_challenge".to_owned())?;
    if detached.is_none() {
        let expected_unsigned = unsigned_confirmation(archive_digest, request.reason);
        if request.unsigned_confirm != Some(expected_unsigned.as_str()) {
            return Err(format!(
                "restore_refused code=unsigned_confirmation_mismatch expected={expected_unsigned}"
            ));
        }
    }
    let duplicate = unsafe { libc::fcntl(request.credential_output_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err("restore_refused code=credential_sink_unavailable".into());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a new descriptor owned here.
    let mut sink = unsafe { std::fs::File::from_raw_fd(duplicate) };
    let mut temp_nonce = [0; 16];
    SystemRandom
        .fill(&mut temp_nonce)
        .map_err(|_| "restore_refused code=random".to_owned())?;
    let receipt = restore(
        &container,
        RestoreRequest {
            target: request.target,
            recovery_identity: &recovery_identity,
            new_active_identity: &new_active_identity,
            installed_recovery_recipient: installed_recovery.as_ref(),
            signature,
            source_decommissioned: request.source_decommissioned,
            actor_id,
            reason: request.reason,
            assertion_confirmation: assertion,
            temp_nonce,
        },
        &mut sink,
        &mut SystemRandom,
    )
    .map_err(|error| format!("restore_refused code={error}"))?;
    let value = serde_json::json!({
        "schema": 1,
        "archive_digest": hex(&receipt.archive_digest),
        "store_id": hex(&receipt.installed_store_id.0),
        "credential_epoch": receipt.credential_epoch,
        "credential_accessor": hex(&receipt.credential_accessor),
        "new_active_fingerprint": hex(&receipt.new_active_fingerprint),
        "recovery_fingerprint": hex(&receipt.recovery_fingerprint),
        "pending_anchor": "normal-restore",
    });
    let rendered = match request.output {
        OutputFormat::Json => serde_json::to_string(&value)
            .map_err(|_| "restore_refused code=output_encoding".to_owned())?,
        OutputFormat::Human => format!(
            "restore installed\nstore id: {}\ncredential epoch: {}\npending anchor: normal-restore",
            hex(&receipt.installed_store_id.0),
            receipt.credential_epoch,
        ),
    };
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .and_then(|()| std::io::stdout().write_all(b"\n"))
        .map_err(|_| "restore_refused code=output".to_owned())
}

struct RecipientRewrapCli<'a> {
    expected_generation: u64,
    current_identity_source: &'a SecretSource,
    new_active_identity_source: &'a SecretSource,
    recovery_recipient: Option<&'a str>,
    control_credential_source: &'a SecretSource,
    reason: &'a str,
    confirm: Option<&'a str>,
    output: OutputFormat,
    unsafe_environment: bool,
}

fn run_recipient_rewrap(config: &Config, request: RecipientRewrapCli<'_>) -> Result<(), String> {
    if !request.unsafe_environment
        && [
            request.current_identity_source,
            request.new_active_identity_source,
            request.control_credential_source,
        ]
        .into_iter()
        .any(|source| matches!(source, SecretSource::UnsafeEnvironment(_)))
    {
        return Err("recipient_rewrap_refused code=unsafe_environment_source".into());
    }
    let _lock = DataDirectoryLock::acquire(&config.data_directory)
        .map_err(|_| "recipient_rewrap_refused code=daemon_or_lock_active".to_owned())?;
    let store_path = config.data_directory.join("store.redb");
    let store_metadata = std::fs::symlink_metadata(&store_path)
        .map_err(|_| "recipient_rewrap_refused code=store_path".to_owned())?;
    if !store_metadata.is_file()
        || store_metadata.file_type().is_symlink()
        || store_metadata.uid() != unsafe { libc::geteuid() }
        || store_metadata.permissions().mode() & 0o077 != 0
        || store_metadata.nlink() != 1
    {
        return Err("recipient_rewrap_refused code=unsafe_store_path".into());
    }
    let store = Store::open(&store_path)
        .map_err(|_| "recipient_rewrap_refused code=store_open_failed".to_owned())?;
    let mut input = SystemSecretInput::from_environment();
    let current_secret = request
        .current_identity_source
        .read("key.current_identity_source", &mut input)
        .map_err(|_| "recipient_rewrap_refused code=current_identity_source".to_owned())?;
    let current_identity = parse_identity(current_secret.into_zeroizing())
        .map_err(|_| "recipient_rewrap_refused code=current_identity_invalid".to_owned())?;
    let new_secret = request
        .new_active_identity_source
        .read("key.new_active_identity_source", &mut input)
        .map_err(|_| "recipient_rewrap_refused code=new_identity_source".to_owned())?;
    let new_identity = parse_identity(new_secret.into_zeroizing())
        .map_err(|_| "recipient_rewrap_refused code=new_identity_invalid".to_owned())?;
    let recovery = request
        .recovery_recipient
        .map(str::parse::<age::x25519::Recipient>)
        .transpose()
        .map_err(|_| "recipient_rewrap_refused code=recovery_recipient_invalid".to_owned())?;
    let metadata = store
        .keyring_metadata()
        .map_err(|_| "recipient_rewrap_refused code=metadata_read".to_owned())?
        .ok_or_else(|| "recipient_rewrap_refused code=uninitialized".to_owned())?;
    let envelope = store
        .keyring()
        .map_err(|_| "recipient_rewrap_refused code=envelope_read".to_owned())?
        .ok_or_else(|| "recipient_rewrap_refused code=uninitialized".to_owned())?;
    let opened = KeyringOpener::default()
        .open(
            store
                .meta()
                .map_err(|_| "recipient_rewrap_refused code=meta_read")?
                .store_id,
            &envelope,
            &metadata,
            &current_identity,
        )
        .map_err(|_| "recipient_rewrap_refused code=current_identity_rejected".to_owned())?;
    let credential = request
        .control_credential_source
        .read("key.control_credential_source", &mut input)
        .map_err(|_| "recipient_rewrap_refused code=credential_source".to_owned())?;
    let raw_credential = std::str::from_utf8(credential.expose())
        .map_err(|_| "recipient_rewrap_refused code=credential_invalid".to_owned())?;
    let effective_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "recipient_rewrap_refused code=clock")?
        .as_secs()
        .max(
            store
                .meta()
                .map_err(|_| "recipient_rewrap_refused code=meta_read")?
                .high_water_unix_seconds,
        );
    let verification = opened
        .verify_credential(
            &store,
            raw_credential,
            CredentialKind::Token,
            CredentialAudience::Control,
            effective_seconds,
        )
        .map_err(|_| "recipient_rewrap_refused code=credential_verify".to_owned())?;
    let credential_id = verification
        .authenticated_id
        .ok_or_else(|| "recipient_rewrap_refused code=credential_denied".to_owned())?;
    let identity_id = opened
        .credential_records(&store)
        .map_err(|_| "recipient_rewrap_refused code=credential_reload".to_owned())?
        .into_iter()
        .find(|record| record.value.id == credential_id)
        .map(|record| record.value.identity_id)
        .ok_or_else(|| "recipient_rewrap_refused code=credential_identity".to_owned())?;
    let mut random = SystemRandom;
    let mut request_id = [0_u8; 16];
    let mut event_id = [0_u8; 16];
    random
        .fill(&mut request_id)
        .and_then(|()| random.fill(&mut event_id))
        .map_err(|_| "recipient_rewrap_refused code=random".to_owned())?;
    authorize_recipient_rewrap(&opened, &store, identity_id, request_id)?;
    let head = store
        .audit_head()
        .map_err(|_| "recipient_rewrap_refused code=audit_head".to_owned())?
        .ok_or_else(|| "recipient_rewrap_refused code=audit_head_missing".to_owned())?;
    let audit_sequence = head
        .epoch_sequence
        .checked_add(1)
        .ok_or_else(|| "recipient_rewrap_refused code=sequence_limit".to_owned())?;
    let old_recipients = opened.recipients();
    let new_recipients = RecipientSet::new(&new_identity.to_public(), recovery.as_ref())
        .map_err(|_| "recipient_rewrap_refused code=recipient_set".to_owned())?;
    let expected_confirmation = recipient_rewrap_confirmation(
        store
            .meta()
            .map_err(|_| "recipient_rewrap_refused code=meta_read")?
            .store_id,
        request.expected_generation,
        old_recipients,
        new_recipients,
        request.reason,
    )
    .map_err(|_| "recipient_rewrap_refused code=reason".to_owned())?;
    let Some(confirmation) = request.confirm else {
        return render_recipient_plan(
            request.output,
            request.expected_generation,
            old_recipients,
            new_recipients,
            &expected_confirmation,
        );
    };
    let prepared = match opened.prepare_recipient_rewrap(
        &new_identity,
        RecipientRewrapRequest {
            expected_generation: request.expected_generation,
            new_recovery: recovery.as_ref(),
            audit_sequence,
            reason: request.reason,
            confirmation,
            authorized: true,
        },
    ) {
        Ok(value) => value,
        Err(KeyringError::AlreadyInstalled) => {
            return render_recipient_rewrap(
                request.output,
                metadata.value.generation,
                old_recipients,
                new_recipients,
                true,
            );
        }
        Err(error) => {
            return Err(format!(
                "recipient_rewrap_refused code=prepare cause={error}"
            ));
        }
    };
    // Final barrier: re-read credential, identity, and grants after expensive
    // envelope construction and new-identity self-test.
    let final_verification = prepared
        .keyring
        .verify_credential(
            &store,
            raw_credential,
            CredentialKind::Token,
            CredentialAudience::Control,
            effective_seconds,
        )
        .map_err(|_| "recipient_rewrap_refused code=final_credential_verify".to_owned())?;
    if final_verification.authenticated_id != Some(credential_id) {
        return Err("recipient_rewrap_refused code=final_credential_denied".into());
    }
    authorize_recipient_rewrap(&prepared.keyring, &store, identity_id, request_id)?;
    let reason_digest = blake3::hash(request.reason.as_bytes()).to_hex();
    let event = AuditEvent {
        event_id,
        request_id,
        authentication: AuditAuthentication {
            method: AuditAuthMethod::Token,
            identity_id: Some(identity_id),
            credential_accessor: None,
            succeeded: true,
            failure_reason: None,
        },
        authorization: AuditAuthorization {
            capability: Some(AuditCapability::StoreKeyRotate),
            allowed: true,
            reason: AuditReason::None,
        },
        consumer_instance_id: None,
        resource: Some(AuditResource::Canonical(format!(
            "keyring/recipients/reason-{}",
            &reason_digest[..16]
        ))),
        operation: AuditOperation::KeyringChange,
        outcome: AuditOutcome::Succeeded,
        reason: AuditReason::OperatorRequested,
        effective_timestamp_milliseconds: effective_seconds
            .checked_mul(1_000)
            .ok_or_else(|| "recipient_rewrap_refused code=clock_limit".to_owned())?,
        wall_clock_observation_milliseconds: effective_seconds
            .checked_mul(1_000)
            .ok_or_else(|| "recipient_rewrap_refused code=clock_limit".to_owned())?,
        secret_version: None,
        state: AuditStateCommitment::Delta(
            prepared
                .state_delta(&metadata)
                .map_err(|_| "recipient_rewrap_refused code=state_delta".to_owned())?,
        ),
        previous_epoch_terminal: None,
        flood: None,
        overload_counts: Vec::new(),
    };
    let replacement = store
        .commit_recipient_rewrap(prepared, &event, &mut random, RecipientRewrapFault::None)
        .map_err(|_| "recipient_rewrap_refused code=commit".to_owned())?;
    drop(credential);
    render_recipient_rewrap(
        request.output,
        replacement.generation(),
        old_recipients,
        replacement.recipients(),
        false,
    )
}

fn authorize_recipient_rewrap(
    keyring: &ops_light_secrets_server::store::keyring::Keyring,
    store: &Store,
    identity_id: [u8; 16],
    request_id: [u8; 16],
) -> Result<(), String> {
    let identities = keyring
        .identity_records(store)
        .map_err(|_| "recipient_rewrap_refused code=identity_reload".to_owned())?
        .into_iter()
        .map(|record| record.value);
    let grants = keyring
        .grant_records(store, identity_id)
        .map_err(|_| "recipient_rewrap_refused code=grant_reload".to_owned())?
        .into_iter()
        .map(|record| record.value);
    let mut catalog = ManagementCatalog::new(identities, grants)
        .map_err(|_| "recipient_rewrap_refused code=authorization_catalog".to_owned())?;
    let uid = unsafe { libc::geteuid() };
    catalog
        .authorize_command(
            ManagementPrincipal {
                identity_id,
                audience: CredentialAudience::Control,
                peer_uid: uid,
                expected_uid: uid,
                credential_active: true,
            },
            ControlCommand::RecipientRewrap,
            request_id,
        )
        .map_err(|_| "recipient_rewrap_refused code=authorization_denied".to_owned())
}

fn render_recipient_rewrap(
    output: OutputFormat,
    generation: u64,
    old: RecipientSet,
    new: RecipientSet,
    already_installed: bool,
) -> Result<(), String> {
    let value = serde_json::json!({
        "schema": 1,
        "generation": generation,
        "old_active_fingerprint": hex(&old.active.0),
        "old_recovery_fingerprint": old.recovery.map(|value| hex(&value.0)),
        "new_active_fingerprint": hex(&new.active.0),
        "new_recovery_fingerprint": new.recovery.map(|value| hex(&value.0)),
        "already_installed": already_installed,
        "blast_radius": "old active identity loses keyring access; prior active-path backup receipts become stale",
    });
    let rendered = match output {
        OutputFormat::Json => serde_json::to_string(&value)
            .map_err(|_| "recipient rewrap output encoding failed".to_owned())?,
        OutputFormat::Human => format!(
            "generation: {}\nold active: {}\nnew active: {}\nalready installed: {}\nblast radius: old active identity loses access; prior active-path backup receipts become stale",
            generation,
            hex(&old.active.0),
            hex(&new.active.0),
            already_installed,
        ),
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|_| "recipient rewrap output failed".to_owned())
}

fn render_recipient_plan(
    output: OutputFormat,
    generation: u64,
    old: RecipientSet,
    new: RecipientSet,
    confirmation: &str,
) -> Result<(), String> {
    let value = serde_json::json!({
        "schema": 1,
        "expected_generation": generation,
        "old_active_fingerprint": hex(&old.active.0),
        "old_recovery_fingerprint": old.recovery.map(|value| hex(&value.0)),
        "new_active_fingerprint": hex(&new.active.0),
        "new_recovery_fingerprint": new.recovery.map(|value| hex(&value.0)),
        "confirmation": confirmation,
        "mutation": false,
        "blast_radius": "old active identity loses keyring access; prior active-path backup receipts become stale",
    });
    let rendered = match output {
        OutputFormat::Json => serde_json::to_string(&value)
            .map_err(|_| "recipient rewrap plan encoding failed".to_owned())?,
        OutputFormat::Human => format!(
            "expected generation: {}\nold active: {}\nnew active: {}\nconfirmation: {}\nmutation: false\nblast radius: old active identity loses access; prior active-path backup receipts become stale",
            generation,
            hex(&old.active.0),
            hex(&new.active.0),
            confirmation,
        ),
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|_| "recipient rewrap plan output failed".to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
