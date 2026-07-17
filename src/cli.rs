use clap::{Parser, Subcommand};
use ops_light_secrets_server::clock::{ClockRepairRequest, validate_repair};
use ops_light_secrets_server::config::Config;
use ops_light_secrets_server::startup::validate_serve_shell;
use std::ffi::OsString;
use std::path::PathBuf;

const LONG_ABOUT: &str = "Local secrets service. Configuration comes from --config and OLSS_* environment settings.\n\
Secret settings accept descriptors only: stdin, fd:N, credential:NAME, tty, or env:NAME with --unsafe-dev-secret-env.\n\
TLS files: OLSS_TLS_CERTIFICATE and OLSS_TLS_PRIVATE_KEY. Mount settings: OLSS_MOUNTS_SECRET_CAS_REQUIRED and OLSS_MOUNTS_SECRET_MAX_VERSIONS.";

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
    },
    /// Validate configuration and serve requests
    Serve,
    /// Offline clock recovery operations
    Clock {
        #[command(subcommand)]
        command: ClockCommand,
    },
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
            } => {
                ops_light_secrets_server::init::parse_bootstrap_ttl(bootstrap_ttl)
                    .map_err(|error| error.to_string())?;
                if credential_output_fd.is_none() {
                    return Err("init_refused code=credential_sink_required setting=credential_output_fd remediation='pass a pre-opened TTY, pipe, socket, or anonymous memory FD'".into());
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
        }
    }
    Ok(())
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
