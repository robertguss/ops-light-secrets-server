//! Strict configuration and secret-source descriptors.

use serde::Deserialize;
use std::env;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use zeroize::Zeroizing;

const DEFAULT_MAX_VERSIONS: u16 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretSource {
    Stdin,
    FileDescriptor(u32),
    Credential(String),
    Tty,
    UnsafeEnvironment(String),
}

impl SecretSource {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Stdin => "stdin",
            Self::FileDescriptor(_) => "file-descriptor",
            Self::Credential(_) => "credential",
            Self::Tty => "tty",
            Self::UnsafeEnvironment(_) => "environment",
        }
    }

    pub fn read<I: SecretInput>(
        &self,
        setting: &'static str,
        input: &mut I,
    ) -> Result<SecretBytes, ConfigError> {
        let bytes = match self {
            Self::Stdin => input.read_stdin(),
            Self::FileDescriptor(fd) => input.read_file_descriptor(*fd),
            Self::Credential(name) => input.read_credential(name),
            Self::Tty => input.read_tty(),
            Self::UnsafeEnvironment(variable) => input.read_environment(variable),
        }
        .map_err(|_| ConfigError::invalid(setting, self.kind()))?;

        if bytes.is_empty() {
            return Err(ConfigError::invalid(setting, self.kind()));
        }
        Ok(SecretBytes(Zeroizing::new(bytes)))
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

pub trait SecretInput {
    fn read_stdin(&mut self) -> io::Result<Vec<u8>>;
    fn read_file_descriptor(&mut self, fd: u32) -> io::Result<Vec<u8>>;
    fn read_credential(&mut self, name: &str) -> io::Result<Vec<u8>>;
    fn read_tty(&mut self) -> io::Result<Vec<u8>>;
    fn read_environment(&mut self, variable: &str) -> io::Result<Vec<u8>>;
}

pub struct SystemSecretInput {
    credentials_directory: Option<PathBuf>,
}

impl SystemSecretInput {
    pub fn from_environment() -> Self {
        Self {
            credentials_directory: env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
        }
    }
}

impl SecretInput for SystemSecretInput {
    fn read_stdin(&mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn read_file_descriptor(&mut self, fd: u32) -> io::Result<Vec<u8>> {
        let mut file = std::fs::File::open(format!("/proc/self/fd/{fd}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn read_credential(&mut self, name: &str) -> io::Result<Vec<u8>> {
        let directory = self
            .credentials_directory
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "credentials unavailable"))?;
        std::fs::read(directory.join(name))
    }

    fn read_tty(&mut self) -> io::Result<Vec<u8>> {
        rpassword::prompt_password("Secret: ").map(String::into_bytes)
    }

    fn read_environment(&mut self, variable: &str) -> io::Result<Vec<u8>> {
        env::var(variable)
            .map(String::into_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "development secret unavailable"))
    }
}

impl fmt::Display for SecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdin => formatter.write_str("stdin"),
            Self::FileDescriptor(fd) => write!(formatter, "fd:{fd}"),
            Self::Credential(name) => write!(formatter, "credential:{name}"),
            Self::Tty => formatter.write_str("tty"),
            Self::UnsafeEnvironment(variable) => write!(formatter, "env:{variable}"),
        }
    }
}

impl FromStr for SecretSource {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "stdin" {
            return Ok(Self::Stdin);
        }
        if value == "tty" {
            return Ok(Self::Tty);
        }
        if let Some(fd) = value.strip_prefix("fd:") {
            return fd
                .parse::<u32>()
                .ok()
                .filter(|fd| *fd >= 3)
                .map(Self::FileDescriptor)
                .ok_or_else(|| ConfigError::invalid("secret source", "file-descriptor"));
        }
        if let Some(name) = value.strip_prefix("credential:") {
            if valid_name(name) {
                return Ok(Self::Credential(name.to_owned()));
            }
            return Err(ConfigError::invalid("secret source", "credential"));
        }
        if let Some(variable) = value.strip_prefix("env:") {
            if valid_env_name(variable) {
                return Ok(Self::UnsafeEnvironment(variable.to_owned()));
            }
            return Err(ConfigError::invalid("secret source", "environment"));
        }
        Err(ConfigError::invalid("secret source", "descriptor"))
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub data_directory: PathBuf,
    pub age_identity: Option<SecretSource>,
    pub tls_key_passphrase: Option<SecretSource>,
    pub mount: SecretMount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretMount {
    pub cas_required: bool,
    pub max_versions: u16,
}

impl Config {
    pub fn load(path: Option<&Path>, unsafe_environment: bool) -> Result<Self, ConfigError> {
        let raw = match path {
            Some(path) => {
                let contents = std::fs::read_to_string(path)
                    .map_err(|_| ConfigError::invalid("config", "file"))?;
                deserialize(&contents)?
            }
            None => RawConfig::default(),
        };

        let mut config = Self::try_from(raw)?;
        config.apply_environment(env::vars())?;
        config.validate(unsafe_environment)?;
        Ok(config)
    }

    fn apply_environment<I>(&mut self, variables: I) -> Result<(), ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (key, value) in variables
            .into_iter()
            .filter(|(key, _)| key.starts_with("OLSS_"))
        {
            match key.as_str() {
                "OLSS_CONFIG" => {}
                "OLSS_DATA_DIRECTORY" => self.data_directory = PathBuf::from(value),
                "OLSS_AGE_IDENTITY_SOURCE" => self.age_identity = Some(parse_source(&key, &value)?),
                "OLSS_TLS_KEY_PASSPHRASE_SOURCE" => {
                    self.tls_key_passphrase = Some(parse_source(&key, &value)?)
                }
                "OLSS_MOUNTS_SECRET_CAS_REQUIRED" => {
                    self.mount.cas_required = parse_bool(&key, &value)?
                }
                "OLSS_MOUNTS_SECRET_MAX_VERSIONS" => {
                    self.mount.max_versions = parse_max_versions(&key, &value)?
                }
                _ => return Err(ConfigError::unknown(&key)),
            }
        }
        Ok(())
    }

    fn validate(&mut self, unsafe_environment: bool) -> Result<(), ConfigError> {
        let stdin_count = [&self.age_identity, &self.tls_key_passphrase]
            .into_iter()
            .flatten()
            .filter(|source| **source == SecretSource::Stdin)
            .count();
        if stdin_count > 1 {
            return Err(ConfigError::invalid("secrets", "multiple stdin consumers"));
        }

        for (setting, source) in [
            ("secrets.age_identity", &self.age_identity),
            ("secrets.tls_key_passphrase", &self.tls_key_passphrase),
        ] {
            if let Some(source @ SecretSource::UnsafeEnvironment(_)) = source {
                if !unsafe_environment {
                    return Err(ConfigError::invalid(setting, source.kind()));
                }
            }
        }

        if self.mount.max_versions == 0 {
            self.mount.max_versions = DEFAULT_MAX_VERSIONS;
        }
        if self.mount.max_versions > 1024 {
            return Err(ConfigError::invalid(
                "mounts.secret.max_versions",
                "outside 0..=1024",
            ));
        }
        Ok(())
    }
}

fn parse_source(setting: &str, value: &str) -> Result<SecretSource, ConfigError> {
    value
        .parse()
        .map_err(|_| ConfigError::invalid(setting, "secret-source descriptor"))
}

fn parse_bool(setting: &str, value: &str) -> Result<bool, ConfigError> {
    value
        .parse()
        .map_err(|_| ConfigError::invalid(setting, "boolean"))
}

fn parse_max_versions(setting: &str, value: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|_| ConfigError::invalid(setting, "integer 0..=1024"))
}

fn deserialize(contents: &str) -> Result<RawConfig, ConfigError> {
    let deserializer = toml::Deserializer::parse(contents).map_err(|error| {
        let setting = error
            .message()
            .contains("duplicate key")
            .then(|| duplicate_key(contents, &error))
            .flatten()
            .unwrap_or("config");
        ConfigError::invalid(setting, "TOML syntax")
    })?;
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let path = error.path().to_string();
        let message = error.inner().message();
        let setting = unknown_field(message)
            .or_else(|| (!path.is_empty() && path != ".").then_some(path.as_str()))
            .unwrap_or("config");
        ConfigError::invalid(setting, "invalid declaration")
    })
}

fn unknown_field(message: &str) -> Option<&str> {
    let rest = message.strip_prefix("unknown field `")?;
    rest.split('`').next()
}

fn duplicate_key<'a>(contents: &'a str, error: &toml::de::Error) -> Option<&'a str> {
    let token = contents.get(error.span()?)?.trim_matches(['\'', '"']);
    valid_name(token).then_some(token)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    data: RawData,
    secrets: RawSecrets,
    mounts: RawMounts,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawData {
    directory: PathBuf,
}

impl Default for RawData {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("data"),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSecrets {
    age_identity: Option<String>,
    tls_key_passphrase: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawMounts {
    secret: RawSecretMount,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSecretMount {
    cas_required: bool,
    max_versions: u16,
}

impl Default for RawSecretMount {
    fn default() -> Self {
        Self {
            cas_required: false,
            max_versions: DEFAULT_MAX_VERSIONS,
        }
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            data_directory: raw.data.directory,
            age_identity: raw
                .secrets
                .age_identity
                .map(|source| parse_source("secrets.age_identity", &source))
                .transpose()?,
            tls_key_passphrase: raw
                .secrets
                .tls_key_passphrase
                .map(|source| parse_source("secrets.tls_key_passphrase", &source))
                .transpose()?,
            mount: SecretMount {
                cas_required: raw.mounts.secret.cas_required,
                max_versions: raw.mounts.secret.max_versions,
            },
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigError(String);

impl ConfigError {
    fn unknown(setting: &str) -> Self {
        Self(format!("unknown setting {setting}"))
    }

    fn invalid(setting: &str, kind: &str) -> Self {
        Self(format!("invalid setting {setting} ({kind})"))
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct Inputs {
        next: io::Result<Vec<u8>>,
        call: Option<String>,
    }

    impl Inputs {
        fn containing(bytes: &[u8]) -> Self {
            Self {
                next: Ok(bytes.to_vec()),
                call: None,
            }
        }

        fn take(&mut self, call: String) -> io::Result<Vec<u8>> {
            self.call = Some(call);
            std::mem::replace(&mut self.next, Ok(Vec::new()))
        }
    }

    impl SecretInput for Inputs {
        fn read_stdin(&mut self) -> io::Result<Vec<u8>> {
            self.take("stdin".into())
        }

        fn read_file_descriptor(&mut self, fd: u32) -> io::Result<Vec<u8>> {
            self.take(format!("fd:{fd}"))
        }

        fn read_credential(&mut self, name: &str) -> io::Result<Vec<u8>> {
            self.take(format!("credential:{name}"))
        }

        fn read_tty(&mut self) -> io::Result<Vec<u8>> {
            self.take("tty".into())
        }

        fn read_environment(&mut self, variable: &str) -> io::Result<Vec<u8>> {
            self.take(format!("env:{variable}"))
        }
    }

    #[test]
    fn secret_source_descriptors_round_trip_every_channel() {
        for descriptor in [
            "stdin",
            "fd:3",
            "credential:age-identity",
            "tty",
            "env:DEVELOPMENT_IDENTITY",
        ] {
            let parsed: SecretSource = descriptor.parse().expect("valid descriptor");
            assert_eq!(parsed.to_string(), descriptor);
        }
    }

    #[test]
    fn secret_source_descriptor_rejects_invalid_or_ambiguous_forms() {
        for descriptor in [
            "",
            "fd:2",
            "fd:not-a-number",
            "credential:",
            "credential:../secret",
            "env:lowercase",
            "stdin:fd:3",
        ] {
            let error = descriptor.parse::<SecretSource>().expect_err("must refuse");
            if !descriptor.is_empty() {
                assert!(!error.to_string().contains(descriptor));
            }
        }
    }

    #[test]
    fn secret_sources_dispatch_each_channel_and_redact_debug() {
        for descriptor in [
            "stdin",
            "fd:7",
            "credential:age-identity",
            "tty",
            "env:DEVELOPMENT_IDENTITY",
        ] {
            let source: SecretSource = descriptor.parse().expect("valid descriptor");
            let mut input = Inputs::containing(b"sensitive bytes");
            let secret = source.read("test.secret", &mut input).expect("read secret");

            assert_eq!(input.call.as_deref(), Some(descriptor));
            assert_eq!(secret.expose(), b"sensitive bytes");
            assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
        }
    }

    #[test]
    fn eof_or_cancel_is_refused_by_source_kind_without_secret_content() {
        for descriptor in ["stdin", "tty"] {
            let source: SecretSource = descriptor.parse().expect("valid descriptor");
            let mut input = Inputs::containing(b"");
            let error = source
                .read("test.secret", &mut input)
                .expect_err("empty input must fail")
                .to_string();

            assert!(error.contains(source.kind()));
            assert!(!error.contains("sensitive"));
        }
    }

    #[test]
    fn environment_overrides_file_deterministically() {
        let raw = deserialize("[mounts.secret]\ncas_required = false\nmax_versions = 7\n")
            .expect("valid config");
        let mut config = Config::try_from(raw).expect("typed config");
        config
            .apply_environment([
                ("OLSS_MOUNTS_SECRET_CAS_REQUIRED".into(), "true".into()),
                ("OLSS_MOUNTS_SECRET_MAX_VERSIONS".into(), "21".into()),
            ])
            .expect("valid environment");
        config.validate(false).expect("valid effective config");

        assert!(config.mount.cas_required);
        assert_eq!(config.mount.max_versions, 21);
    }

    #[test]
    fn duplicate_and_unknown_declarations_are_fatal() {
        let duplicate = deserialize("[mounts.secret]\ncas_required = true\ncas_required = false\n")
            .expect_err("duplicate must fail");
        assert!(duplicate.to_string().contains("cas_required"));

        for contents in [
            "[mounts.secret]\nunknown = true\n",
            "[mounts.other]\ncas_required = true\n",
        ] {
            assert!(deserialize(contents).is_err());
        }
    }

    #[test]
    fn only_one_secret_setting_may_consume_stdin() {
        let raw = deserialize("[secrets]\nage_identity = 'stdin'\ntls_key_passphrase = 'stdin'\n")
            .expect("valid syntax");
        let mut config = Config::try_from(raw).expect("typed config");
        let error = config.validate(false).expect_err("must refuse");

        assert!(error.to_string().contains("secrets"));
    }

    #[test]
    fn environment_secret_source_requires_explicit_unsafe_flag() {
        let raw =
            deserialize("[secrets]\nage_identity = 'env:DEV_IDENTITY'\n").expect("valid syntax");
        let mut config = Config::try_from(raw).expect("typed config");
        assert!(config.validate(false).is_err());
        config.validate(true).expect("explicit unsafe opt-in");
    }

    #[test]
    fn mount_defaults_and_zero_use_builtin_ten() {
        let mut defaults =
            Config::try_from(deserialize("").expect("defaults")).expect("typed defaults");
        defaults.validate(false).expect("valid defaults");
        assert_eq!(defaults.mount.max_versions, 10);
        assert!(!defaults.mount.cas_required);

        let raw = deserialize("[mounts.secret]\nmax_versions = 0\n").expect("valid zero");
        let mut zero = Config::try_from(raw).expect("typed config");
        zero.validate(false).expect("zero selects default");
        assert_eq!(zero.mount.max_versions, 10);
    }

    #[test]
    fn mount_version_bounds_and_types_are_fatal_without_echoing_values() {
        for contents in [
            "[mounts.secret]\nmax_versions = -1\n",
            "[mounts.secret]\nmax_versions = 1025\n",
            "[mounts.secret]\nmax_versions = 99999999999999999999\n",
            "[mounts.secret]\nmax_versions = 'do-not-print-me'\n",
            "[mounts.secret]\ncas_required = 'do-not-print-me'\n",
        ] {
            let result = deserialize(contents).and_then(|raw| {
                let mut config = Config::try_from(raw)?;
                config.validate(false)?;
                Ok(config)
            });
            let error = result.expect_err("must refuse").to_string();
            assert!(!error.contains("do-not-print-me"));
        }
    }

    #[test]
    fn unknown_prefixed_environment_setting_is_fatal() {
        let mut config =
            Config::try_from(deserialize("").expect("defaults")).expect("typed defaults");
        let error = config
            .apply_environment([("OLSS_TYPOED_SETTING".into(), "do-not-print-me".into())])
            .expect_err("must refuse");

        assert!(error.to_string().contains("OLSS_TYPOED_SETTING"));
        assert!(!error.to_string().contains("do-not-print-me"));
    }
}
