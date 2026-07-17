use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use ops_light_secrets_server::auth::{AppRoleRecord, AuthCatalog, AuthService};
use ops_light_secrets_server::control::data_router_with_auth_and_kv;
use ops_light_secrets_server::credential::{
    CredentialAudience, CredentialIssueMetadata, CredentialKind, issue_credential,
};
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::input_hygiene::InputHygieneState;
use ops_light_secrets_server::kv::{KvCatalog, KvService};
use ops_light_secrets_server::store::StoreId;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};
use zeroize::Zeroize;

const IDENTITY: [u8; 16] = [0x72; 16];
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CLIENT_OUTPUT: u64 = 1024 * 1024;
const CONNECT_TCP: u64 = 1 << 1;
const NET_PORT_RULE: libc::c_int = 2;

#[repr(C)]
struct LandlockRuleset {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockNetPort {
    allowed_access: u64,
    port: u64,
}

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

struct ClientOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration: Duration,
}

impl Drop for ClientOutput {
    fn drop(&mut self) {
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

struct ClientEnv<'a> {
    home: &'a Path,
    endpoint: &'a str,
    token: &'a str,
    cert: &'a Path,
    path: &'a OsStr,
    port: u16,
}

fn services() -> (AuthService, KvService, String) {
    let store_id = StoreId([0x31; 16]);
    let verifier_key = [0x41; 32];
    let mut auth = AuthCatalog::new(store_id, verifier_key, 1, 100).unwrap();
    auth.insert_identity(
        IdentityRecord::new(IDENTITY, "compat-client".into(), IdentityKind::Workload).unwrap(),
    )
    .unwrap();
    auth.insert_role(
        AppRoleRecord::new(
            [0x51; 16],
            "compat-role".into(),
            "compat".into(),
            IDENTITY,
            Some(600),
        )
        .unwrap(),
    )
    .unwrap();
    let secret_id = issue_credential(
        &verifier_key,
        store_id,
        CredentialIssueMetadata {
            id: [0x61; 16],
            identity_id: IDENTITY,
            kind: CredentialKind::SecretId,
            audience: CredentialAudience::Data,
            issue_epoch: 1,
            expires_at_effective_seconds: 1_000,
            created_at_effective_seconds: 100,
            issuer_identity_id: [0x62; 16],
            issuance_request_id: [0x63; 16],
            parent_accessor: None,
            consumer_instance_id: Some([0x64; 16]),
        },
        "compat".into(),
        &mut |_| false,
        &mut Counter(0x70),
    )
    .unwrap();
    let secret = secret_id.expose_once().to_owned();
    auth.insert_secret_id([0x51; 16], secret_id.record.clone(), 1)
        .unwrap();
    let auth = AuthService::new(auth, Counter(0x80));
    let token = auth
        .login("compat-role", &secret, [0x65; 16])
        .unwrap()
        .credential
        .expose_once()
        .to_owned();

    let mut kv = KvCatalog::new(false, 1_800_000_000_000);
    kv.replace_grants(vec![
        GrantRecord::new(
            [0x53; 16],
            IDENTITY,
            "secret".into(),
            GrantScope::Subtree,
            Vec::new(),
            [
                Capability::SecretList,
                Capability::SecretReadCurrent,
                Capability::SecretWrite,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        )
        .unwrap(),
    ]);
    (auth, KvService::new(kv), token)
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

fn verify_archives(directory: &Path) -> Result<Vec<(String, String, String)>, &'static str> {
    let matrix: serde_json::Value =
        serde_json::from_str(include_str!("../../research/compat/client-matrix.json")).unwrap();
    matrix["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|client| {
            let product = client["product"].as_str().unwrap().to_owned();
            let version = client["version"].as_str().unwrap().to_owned();
            let expected = client["sha256"].as_str().unwrap();
            let archive = directory.join(client["archive"].as_str().unwrap());
            if !archive.is_file() {
                return Err("staged compatibility archive missing");
            }
            if sha256(&archive) != expected {
                return Err("staged archive digest mismatch");
            }
            Ok((product, version, expected.to_owned()))
        })
        .collect()
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn optional_fingerprint(path: &Path) -> Option<([u8; 32], u64)> {
    let metadata = fs::metadata(path).ok()?;
    let bytes = fs::read(path).unwrap();
    let digest = *blake3::hash(&bytes).as_bytes();
    Some((digest, metadata.len()))
}

fn assert_tree_clean(directory: &Path, canaries: &[&[u8]]) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            assert_tree_clean(&entry.path(), canaries);
        } else {
            assert!(file_type.is_file());
            let bytes = fs::read(entry.path()).unwrap();
            for canary in canaries {
                assert!(!bytes.windows(canary.len()).any(|window| window == *canary));
            }
        }
    }
}

unsafe fn restrict_tcp_connect(port: u16) -> std::io::Result<()> {
    let ruleset = LandlockRuleset {
        handled_access_fs: 0,
        handled_access_net: CONNECT_TCP,
    };
    // SAFETY: pointers reference the fixed-layout kernel ABI structures for
    // the duration of each syscall; all return values are checked.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset,
            std::mem::size_of::<LandlockRuleset>(),
            0,
        )
    } as libc::c_int;
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rule = LandlockNetPort {
        allowed_access: CONNECT_TCP,
        port: u64::from(port),
    };
    let added = unsafe { libc::syscall(libc::SYS_landlock_add_rule, fd, NET_PORT_RULE, &rule, 0) };
    let no_new_privileges = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    let restricted = if added == 0 && no_new_privileges == 0 {
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd, 0) }
    } else {
        -1
    };
    let saved = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if restricted == 0 { Ok(()) } else { Err(saved) }
}

fn read_bounded(mut pipe: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    pipe.by_ref()
        .take(MAX_CLIENT_OUTPUT + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() <= MAX_CLIENT_OUTPUT as usize,
        "client output limit"
    );
    bytes
}

fn run_client(
    program: &Path,
    arguments: &[&str],
    environment: &ClientEnv<'_>,
    input: Option<&[u8]>,
) -> ClientOutput {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("HOME", environment.home)
        .env("XDG_CONFIG_HOME", environment.home.join(".config"))
        .env("XDG_CACHE_HOME", environment.home.join(".cache"))
        .env("XDG_DATA_HOME", environment.home.join(".local/share"))
        .env("PATH", environment.path)
        .env("VAULT_ADDR", environment.endpoint)
        .env("VAULT_TOKEN", environment.token)
        .env("VAULT_CACERT", environment.cert)
        .env("CHECKPOINT_DISABLE", "1")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let port = environment.port;
    // SAFETY: pre_exec performs only async-signal-safe syscalls and captures a
    // Copy port. It installs a deny-by-default TCP-connect Landlock ruleset.
    unsafe {
        command.pre_exec(move || restrict_tcp_connect(port));
    }
    let started = Instant::now();
    let mut child = command.spawn().unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let status = child.wait().unwrap();
            panic!("pinned client timed out: status={status}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    ClientOutput {
        status,
        stdout: stdout_reader.join().unwrap(),
        stderr: stderr_reader.join().unwrap(),
        duration: started.elapsed(),
    }
}

fn assert_success(output: &ClientOutput, operation: &str) {
    assert!(
        output.status.success(),
        "pinned client failed: operation={operation} code={:?} stderr_digest={}",
        output.status.code(),
        blake3::hash(&output.stderr).to_hex()
    );
    assert!(output.duration <= CLIENT_TIMEOUT);
}

fn wrapper(directory: &Path, client: &Path) -> PathBuf {
    private_directory(directory);
    let path = directory.join("vault");
    fs::write(
        &path,
        format!("#!/bin/sh\nexec '{}' \"$@\"\n", client.display()),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn archive_digest_mismatch_refuses_before_any_client_execution() {
    let directory = tempfile::tempdir().unwrap();
    let matrix: serde_json::Value =
        serde_json::from_str(include_str!("../../research/compat/client-matrix.json")).unwrap();
    for client in matrix["clients"].as_array().unwrap() {
        fs::write(
            directory.path().join(client["archive"].as_str().unwrap()),
            b"digest-mismatch",
        )
        .unwrap();
    }
    let result = verify_archives(directory.path());
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_clients_drive_tls_kv_with_hermetic_state_and_no_external_tcp() {
    if std::env::var_os("FNOX_E2E_RUN").as_deref() != Some("1".as_ref()) {
        return;
    }
    let binaries = std::env::var_os("FNOX_E2E_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/olss-compat-bin"));
    let archives = std::env::var_os("FNOX_E2E_ARCHIVE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/olss-compat-clients"));
    let pins = verify_archives(&archives).unwrap();
    let vault = binaries.join("vault/vault");
    let bao = binaries.join("bao/bao");
    let fnoxes = [
        ("1.29.0", binaries.join("fnox-1.29/fnox")),
        ("1.30.0", binaries.join("fnox-1.30/fnox")),
    ];
    assert!(vault.is_file() && bao.is_file());
    assert!(fnoxes.iter().all(|(_, path)| path.is_file()));

    let real_home = std::env::var_os("HOME").map(PathBuf::from);
    let token_before = real_home
        .as_deref()
        .and_then(|home| optional_fingerprint(&home.join(".vault-token")));
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let client_home = directory.path().join("home");
    private_directory(&client_home);
    private_directory(&client_home.join(".config"));
    private_directory(&client_home.join(".cache"));
    private_directory(&client_home.join(".local/share"));
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let (auth, kv, token) = services();
    let value = format!("compat-value-{}", std::process::id());
    assert_eq!(pins.len(), 4);
    let harness = Harness::builder("compat-real-clients")
        .register_canary(value.as_bytes())
        .register_canary(token.as_bytes())
        .global_timeout(Duration::from_secs(180))
        .client_fingerprint("vault", "2.0.3", sha256(&vault))
        .unwrap()
        .client_fingerprint("bao", "2.6.0", sha256(&bao))
        .unwrap()
        .client_fingerprint("fnox", "1.29.0", sha256(&fnoxes[0].1))
        .unwrap()
        .client_fingerprint("fnox", "1.30.0", sha256(&fnoxes[1].1))
        .unwrap();
    let harness = harness.build().unwrap();
    let mut scenario = harness.scenario("actual-pinned-matrix", 1).unwrap();
    let app = data_router_with_auth_and_kv(auth, kv, InputHygieneState::new([0x54; 32]));
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .unwrap();
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        axum_server::bind_rustls(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), tls)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    let address = handle.listening().await.unwrap();
    let endpoint = format!("https://localhost:{}", address.port());
    let direct_path = OsStr::new("/usr/bin:/bin");
    let direct = ClientEnv {
        home: &client_home,
        endpoint: &endpoint,
        token: &token,
        cert: &cert_path,
        path: direct_path,
        port: address.port(),
    };

    for (name, client) in [("vault", &vault), ("bao", &bao)] {
        let path = format!("secret/apps/{name}");
        let put = run_client(
            client,
            &["kv", "put", &path, "value=-"],
            &direct,
            Some(value.as_bytes()),
        );
        assert_success(&put, "kv-put");
        let get = run_client(client, &["kv", "get", "-field=value", &path], &direct, None);
        assert_success(&get, "kv-get");
        assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), value);
        let list = run_client(
            client,
            &["kv", "list", "-format=json", "secret/apps"],
            &direct,
            None,
        );
        assert_success(&list, "kv-list");
        assert!(String::from_utf8_lossy(&list.stdout).contains(name));
    }

    let cross = run_client(
        &bao,
        &["kv", "get", "-field=value", "secret/apps/vault"],
        &direct,
        None,
    );
    assert_success(&cross, "bao-cross-read");
    assert_eq!(String::from_utf8_lossy(&cross.stdout).trim(), value);

    let fnox_seed = run_client(
        &bao,
        &["kv", "put", "secret/apps", "value=-"],
        &direct,
        Some(value.as_bytes()),
    );
    assert_success(&fnox_seed, "fnox-seed");

    for (version, fnox) in fnoxes {
        for (backend, client) in [("vault", &vault), ("bao", &bao)] {
            let bin = directory.path().join(format!("bin-{version}-{backend}"));
            wrapper(&bin, client);
            let config = directory
                .path()
                .join(format!("fnox-{version}-{backend}.toml"));
            fs::write(
                &config,
                format!(
                    "[providers.vault]\ntype = \"vault\"\naddress = \"{endpoint}\"\npath = \"secret\"\ntoken = \"{token}\"\n\n[secrets.COMPAT]\nprovider = \"vault\"\nvalue = \"apps/value\"\n"
                ),
            )
            .unwrap();
            fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
            let fnox_path = format!("{}:/usr/bin:/bin", bin.display());
            let fnox_env = ClientEnv {
                path: OsStr::new(&fnox_path),
                ..direct
            };
            let output = run_client(
                &fnox,
                &[
                    "--config",
                    config.to_str().unwrap(),
                    "--no-daemon",
                    "--non-interactive",
                    "get",
                    "COMPAT",
                ],
                &fnox_env,
                None,
            );
            assert_success(&output, "fnox-get");
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), value);
            fs::remove_file(config).unwrap();
        }
    }

    assert!(!client_home.join(".vault-token").exists());
    let token_after = real_home
        .as_deref()
        .and_then(|home| optional_fingerprint(&home.join(".vault-token")));
    assert_eq!(token_after, token_before);

    let mismatch_tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .unwrap();
    let mismatch_app = Router::new()
        .route(
            "/v1/sys/internal/ui/mounts/{*path}",
            get(|| async {
                Json(serde_json::json!({
                    "data": {"path":"secret/", "type":"kv", "options":{"version":"1"}}
                }))
            }),
        )
        .fallback(|| async { StatusCode::NOT_FOUND });
    let mismatch_handle = axum_server::Handle::new();
    let mismatch_server_handle = mismatch_handle.clone();
    let mismatch_server = tokio::spawn(async move {
        axum_server::bind_rustls(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), mismatch_tls)
            .handle(mismatch_server_handle)
            .serve(mismatch_app.into_make_service())
            .await
            .unwrap();
    });
    let mismatch_address = mismatch_handle.listening().await.unwrap();
    let mismatch_endpoint = format!("https://localhost:{}", mismatch_address.port());
    let mismatch_env = ClientEnv {
        endpoint: &mismatch_endpoint,
        port: mismatch_address.port(),
        ..direct
    };
    let mismatch = run_client(
        &vault,
        &["kv", "get", "-field=value", "secret/apps"],
        &mismatch_env,
        None,
    );
    assert!(!mismatch.status.success());
    mismatch_handle.graceful_shutdown(Some(Duration::from_secs(2)));
    mismatch_server.await.unwrap();

    handle.graceful_shutdown(Some(Duration::from_secs(2)));
    server.await.unwrap();
    assert_tree_clean(directory.path(), &[value.as_bytes(), token.as_bytes()]);
    fs::remove_dir_all(directory.path()).unwrap();

    scenario
        .step(
            "pinned-matrix",
            SafeSummary::new()
                .field("client_runs", SafeValue::Unsigned(15))
                .field(
                    "network_policy",
                    SafeValue::StaticKind("landlock-port-only"),
                )
                .field("home_isolation", SafeValue::Boolean(true))
                .field("preflight", SafeValue::StaticKind("v2-and-mismatch-caught")),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    let report = scenario.finish_success().unwrap();
    assert!(report.scan_attestation.clean);
    assert!(!report.jsonl.contains(&value));
    assert!(!report.jsonl.contains(&token));
}
