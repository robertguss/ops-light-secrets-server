use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ops_light_secrets_server::auth::{AppRoleRecord, AuthCatalog, AuthService};
use ops_light_secrets_server::control::data_router_with_auth_and_kv;
use ops_light_secrets_server::credential::{
    CredentialAudience, CredentialIssueMetadata, CredentialKind, issue_credential,
};
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::input_hygiene::InputHygieneState;
use ops_light_secrets_server::kv::{KvAuditOperation, KvAuditOutcome, KvCatalog, KvService};
use ops_light_secrets_server::store::StoreId;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};

const IDENTITY: [u8; 16] = [0x52; 16];

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn services() -> (AuthService, KvService, String) {
    let store_id = StoreId([0x31; 16]);
    let verifier_key = [0x41; 32];
    let mut auth = AuthCatalog::new(store_id, verifier_key, 1, 100).unwrap();
    auth.insert_identity(
        IdentityRecord::new(IDENTITY, "vertical-client".into(), IdentityKind::Workload).unwrap(),
    )
    .unwrap();
    auth.insert_role(
        AppRoleRecord::new(
            [0x51; 16],
            "vertical-role".into(),
            "vertical".into(),
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
        "vertical".into(),
        &mut |_| false,
        &mut Counter(0x70),
    )
    .unwrap();
    let secret = secret_id.expose_once().to_owned();
    auth.insert_secret_id([0x51; 16], secret_id.record.clone(), 1)
        .unwrap();
    let auth = AuthService::new(auth, Counter(0x80));
    let token = auth
        .login("vertical-role", &secret, [0x65; 16])
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

fn assert_pin_manifest() {
    let matrix: serde_json::Value =
        serde_json::from_str(include_str!("../research/compat/client-matrix.json")).unwrap();
    let clients = matrix["clients"].as_array().unwrap();
    assert!(clients.iter().any(|client| {
        client["product"] == "fnox"
            && client["version"] == "1.30.0"
            && client["sha256"]
                == "2479e045a8b9bac203d499d24693ce98e3724706d22ebdd76d812c2b66dcc321"
    }));
    assert!(clients.iter().any(|client| {
        client["product"] == "bao"
            && client["version"] == "2.6.0"
            && client["sha256"]
                == "42d83073f2d7a28ed408840138b0312111a8d4b2f5617086f009150336dad6d4"
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_fnox_reads_written_secret_over_real_tls_and_committed_audit() {
    let started = Instant::now();
    assert_pin_manifest();
    if std::env::var_os("FNOX_E2E_RUN").as_deref() != Some("1".as_ref()) {
        return;
    }
    let binaries = std::env::var_os("FNOX_E2E_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/olss-compat-bin"));
    let fnox = binaries.join("fnox-1.30/fnox");
    let bao = binaries.join("bao/bao");
    assert!(fnox.is_file() && bao.is_file());

    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let (auth, kv, token) = services();
    let app = data_router_with_auth_and_kv(auth, kv.clone(), InputHygieneState::new([0x54; 32]));
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

    let value = format!("vertical-{}", std::process::id());
    let mut write = Command::new(&bao)
        .args(["kv", "put", "secret/apps", "value=-"])
        .env("VAULT_ADDR", &endpoint)
        .env("VAULT_TOKEN", &token)
        .env("VAULT_CACERT", &cert_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let write = write.wait_with_output().unwrap();
    assert!(
        write.status.success(),
        "bao write failed: {}",
        String::from_utf8_lossy(&write.stderr)
    );

    let wrapper_dir = directory.path().join("bin");
    fs::create_dir(&wrapper_dir).unwrap();
    fs::set_permissions(&wrapper_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let wrapper = wrapper_dir.join("vault");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\nexec '{}' \"$@\"\n", bao.display()),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let config = directory.path().join("fnox.toml");
    fs::write(
        &config,
        format!(
            "[providers.vault]\ntype = \"vault\"\naddress = \"{endpoint}\"\npath = \"secret\"\ntoken = \"{token}\"\n\n[secrets.VERTICAL]\nprovider = \"vault\"\nvalue = \"apps/value\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let path = format!(
        "{}:{}",
        wrapper_dir.display(),
        std::env::var("PATH").unwrap()
    );
    let read = Command::new(&fnox)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--no-daemon",
            "--non-interactive",
            "get",
            "VERTICAL",
        ])
        .env("PATH", path)
        .env("VAULT_CACERT", &cert_path)
        .output()
        .unwrap();
    assert!(
        read.status.success(),
        "fnox read failed: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(String::from_utf8(read.stdout).unwrap().trim(), value);

    kv.with_catalog(|catalog| {
        let successful = catalog
            .audit()
            .iter()
            .filter(|event| event.outcome == KvAuditOutcome::Succeeded)
            .collect::<Vec<_>>();
        assert!(successful.iter().any(|event| {
            event.operation == KvAuditOperation::Write && event.version == Some(1)
        }));
        assert!(successful.iter().any(|event| {
            event.operation == KvAuditOperation::Read && event.version == Some(1)
        }));
    });

    let harness = Harness::builder("vertical-slice")
        .register_canary(value.as_bytes())
        .build()
        .unwrap();
    let mut scenario = harness.scenario("m1-real-fnox", 1).unwrap();
    scenario
        .step(
            "pinned-client-tls-read",
            SafeSummary::new()
                .field("fnox_version", SafeValue::StaticKind("1.30.0"))
                .field(
                    "fnox_digest",
                    SafeValue::digest_prefix(&sha256(&fnox)[..16]).unwrap(),
                )
                .field("bao_version", SafeValue::StaticKind("2.6.0"))
                .field(
                    "bao_digest",
                    SafeValue::digest_prefix(&sha256(&bao)[..16]).unwrap(),
                )
                .field(
                    "server_digest",
                    SafeValue::digest_prefix(
                        &sha256(Path::new(env!("CARGO_BIN_EXE_ops-light-secrets-server")))[..16],
                    )
                    .unwrap(),
                )
                .field("ephemeral_port", SafeValue::Unsigned(address.port().into()))
                .field("served_version", SafeValue::Unsigned(1))
                .field("audit_sequence", SafeValue::Unsigned(2))
                .field(
                    "duration_ms",
                    SafeValue::Unsigned(started.elapsed().as_millis().try_into().unwrap()),
                ),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();
    let report = scenario.finish_success().unwrap();
    assert!(report.scan_attestation.clean);
    assert!(!report.jsonl.contains(&value));

    handle.graceful_shutdown(Some(Duration::from_secs(2)));
    server.await.unwrap();
}
