use clap::{Parser, Subcommand};
use ops_light_secrets_server::config::Config;
use ops_light_secrets_server::startup::validate_serve_shell;
use std::ffi::OsString;
use std::path::PathBuf;

const LONG_ABOUT: &str = "Local secrets service. Configuration comes from --config and OLSS_* environment settings.\n\
Secret settings accept descriptors only: stdin, fd:N, credential:NAME, tty, or env:NAME with --unsafe-dev-secret-env.\n\
Mount settings: OLSS_MOUNTS_SECRET_CAS_REQUIRED and OLSS_MOUNTS_SECRET_MAX_VERSIONS.";

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
    Init,
    /// Validate configuration and serve requests
    Serve,
}

pub fn run() -> Result<(), String> {
    let args: Vec<OsString> = std::env::args_os().collect();
    reject_secret_argv(&args)?;
    let cli = Cli::parse_from(args);

    if let Some(command) = &cli.command {
        let config = Config::load(cli.config.as_deref(), cli.unsafe_dev_secret_env)
            .map_err(|error| error.to_string())?;
        if matches!(command, Command::Serve) {
            validate_serve_shell(&config).map_err(|error| error.to_string())?;
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
