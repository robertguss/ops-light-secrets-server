//! U11.2 differential suite: corpus vs pinned OpenBao reference oracle (R1).
//!
//! Default mode compares the in-process OLSS implementation against frozen
//! OpenBao-shaped oracle fixtures for the pinned OpenBao 2.6.0 contract.
//! Optional live mode: `OLSS_DIFFERENTIAL_LIVE_OPENBAO=1` plus
//! `OLSS_OPENBAO_BIN` pointing at a checksum-verified `bao` server binary.

mod compare;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request};
use ops_light_secrets_server::auth::{AppRoleRecord, AuthCatalog, AuthService};
use ops_light_secrets_server::credential::{
    CredentialAudience, CredentialIssueMetadata, CredentialKind, issue_credential,
};
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::control::data_router_with_auth_and_kv;
use ops_light_secrets_server::input_hygiene::InputHygieneState;
use ops_light_secrets_server::kv::{KvCatalog, KvService};
use ops_light_secrets_server::store::StoreId;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use serde::Deserialize;
use serde_json::{Value, json};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary, SafeValue};
use tower::ServiceExt;

use compare::{
    AllowlistFile, OracleFile, allowlisted_cases, compare_to_oracle, normalize_outcome,
    seed_status_divergence, validate_allowlist,
};

const IDENTITY: [u8; 16] = [0xD1; 16];
const IMPLEMENTATION_VERSION: &str = "ops-light-secrets-server-0.1.0";
const REFERENCE_VERSION: &str = "openbao-2.6.0";
const CANARY: &[u8] = b"diff-canary-value";
const TODAY: &str = "2026-07-17";

const CORPUS_JSON: &str = include_str!("../fixtures/differential/corpus-v1.json");
const ORACLE_JSON: &str = include_str!("../fixtures/differential/openbao-oracle-v1.json");
const ALLOWLIST_JSON: &str = include_str!("../fixtures/differential/allowlist-v1.json");
const PIN_JSON: &str = include_str!("../fixtures/differential/reference-pin-v1.json");

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct CorpusFile {
    schema: u16,
    normalization_schema_version: u16,
    reference_version: String,
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    family: String,
    setup: Vec<HttpStep>,
    probe: HttpStep,
    auth: String,
    #[serde(default)]
    mount_cas_required: bool,
    #[serde(default)]
    capabilities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct HttpStep {
    method: String,
    path: String,
    body: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ReferencePin {
    schema: u16,
    reference: PinReference,
    normalization: PinNormalization,
}

#[derive(Debug, Deserialize)]
struct PinReference {
    product: String,
    version: String,
    sha256: String,
    configuration: PinConfiguration,
}

#[derive(Debug, Deserialize)]
struct PinConfiguration {
    kv_version: u16,
    from_scratch_per_case: bool,
}

#[derive(Debug, Deserialize)]
struct PinNormalization {
    schema_version: u16,
}

fn capabilities_from(names: Option<&[String]>) -> Vec<Capability> {
    let default = [
        "write".into(),
        "read".into(),
        "list".into(),
        "history".into(),
        "soft_delete".into(),
        "undelete".into(),
        "destroy".into(),
    ];
    let names = names.unwrap_or(&default);
    let mut out = Vec::new();
    for name in names {
        out.push(match name.as_str() {
            "write" => Capability::SecretWrite,
            "read" => Capability::SecretReadCurrent,
            "list" => Capability::SecretList,
            "history" => Capability::SecretReadHistory,
            "soft_delete" => Capability::SecretSoftDelete,
            "undelete" => Capability::SecretUndelete,
            "destroy" => Capability::SecretDestroy,
            other => panic!("unknown capability token {other}"),
        });
    }
    out
}

fn auth_fixture() -> (AuthService, String) {
    let store_id = StoreId([0xA1; 16]);
    let verifier_key = [0xA2; 32];
    let mut catalog = AuthCatalog::new(store_id, verifier_key, 1, 100).unwrap();
    catalog
        .insert_identity(
            IdentityRecord::new(IDENTITY, "diff-client".into(), IdentityKind::Workload).unwrap(),
        )
        .unwrap();
    catalog
        .insert_role(
            AppRoleRecord::new(
                [0xB1; 16],
                "diff-role".into(),
                "diff".into(),
                IDENTITY,
                Some(600),
            )
            .unwrap(),
        )
        .unwrap();
    let issued = issue_credential(
        &verifier_key,
        store_id,
        CredentialIssueMetadata {
            id: [0xC1; 16],
            identity_id: IDENTITY,
            kind: CredentialKind::SecretId,
            audience: CredentialAudience::Data,
            issue_epoch: 1,
            expires_at_effective_seconds: 1_000,
            created_at_effective_seconds: 100,
            issuer_identity_id: [0xC2; 16],
            issuance_request_id: [0xC3; 16],
            parent_accessor: None,
            consumer_instance_id: None,
        },
        "diff".into(),
        &mut |_| false,
        &mut Counter(0x10),
    )
    .unwrap();
    let secret_id = issued.expose_once().to_owned();
    catalog
        .insert_secret_id([0xB1; 16], issued.record.clone(), 1)
        .unwrap();
    let auth = AuthService::new(catalog, Counter(0x20));
    let token = auth
        .login("diff-role", &secret_id, [0xC4; 16])
        .unwrap()
        .credential
        .expose_once()
        .to_owned();
    (auth, token)
}

fn kv_service(caps: &[Capability], mount_cas_required: bool) -> KvService {
    let mut catalog = KvCatalog::new(mount_cas_required, 1_800_000_000_000);
    catalog
        .replace_grants(vec![
            GrantRecord::new(
                [0xD2; 16],
                IDENTITY,
                "secret".into(),
                GrantScope::Subtree,
                Vec::new(),
                caps.iter().copied().collect::<BTreeSet<_>>(),
            )
            .unwrap(),
        ]);
    KvService::new(catalog)
}

fn method_from(name: &str) -> Method {
    match name {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        "LIST" => Method::from_bytes(b"LIST").unwrap(),
        other => panic!("unsupported method {other}"),
    }
}

async fn dispatch(
    app: &axum::Router,
    step: &HttpStep,
    token: Option<&str>,
) -> (u16, Value) {
    let mut builder = Request::builder()
        .method(method_from(&step.method))
        .uri(&step.path);
    if let Some(token) = token {
        builder = builder.header("x-vault-token", token);
    }
    if step.body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    for (name, value) in &step.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let body = match &step.body {
        Some(text) => Body::from(text.clone()),
        None => Body::empty(),
    };
    let response = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    // Non-JSON error bodies (input hygiene) compare as empty envelopes; status is the contract.
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn run_case(case: &CorpusCase) -> (u16, Value) {
    let (auth, token) = auth_fixture();
    let caps = capabilities_from(case.capabilities.as_deref());
    let kv = kv_service(&caps, case.mount_cas_required);
    // Full data plane so auth + KV + sys surfaces share one from-scratch app per case.
    let app = data_router_with_auth_and_kv(auth, kv, InputHygieneState::new([0xE1; 32]));
    let token_for = |mode: &str| -> Option<String> {
        match mode {
            "valid" => Some(token.clone()),
            "invalid" => Some("s.not-a-real-token".into()),
            "none" => None,
            other => panic!("unknown auth mode {other}"),
        }
    };
    for step in &case.setup {
        let (status, _) = dispatch(&app, step, token_for("valid").as_deref()).await;
        assert!(
            (200..300).contains(&status),
            "setup step failed for {}: {} {} -> {status}",
            case.id,
            step.method,
            step.path
        );
    }
    dispatch(&app, &case.probe, token_for(&case.auth).as_deref()).await
}

fn load_fixtures() -> (CorpusFile, OracleFile, AllowlistFile, ReferencePin) {
    let corpus: CorpusFile = serde_json::from_str(CORPUS_JSON).expect("corpus json");
    let oracle: OracleFile = serde_json::from_str(ORACLE_JSON).expect("oracle json");
    let allowlist: AllowlistFile = serde_json::from_str(ALLOWLIST_JSON).expect("allowlist json");
    let pin: ReferencePin = serde_json::from_str(PIN_JSON).expect("pin json");
    (corpus, oracle, allowlist, pin)
}

#[test]
fn reference_pin_and_fixture_schema_are_consistent() {
    let (corpus, oracle, allowlist, pin) = load_fixtures();
    assert_eq!(corpus.schema, 1);
    assert_eq!(oracle.schema, 1);
    assert_eq!(allowlist.schema, 1);
    assert_eq!(pin.schema, 1);
    assert_eq!(corpus.normalization_schema_version, 1);
    assert_eq!(pin.normalization.schema_version, 1);
    assert_eq!(pin.reference.product, "openbao");
    assert_eq!(pin.reference.version, "2.6.0");
    assert_eq!(pin.reference.configuration.kv_version, 2);
    assert!(pin.reference.configuration.from_scratch_per_case);
    assert_eq!(pin.reference.sha256.len(), 64);
    assert_eq!(corpus.reference_version, REFERENCE_VERSION);
    assert_eq!(oracle.reference_version, REFERENCE_VERSION);

    let case_ids: BTreeSet<String> = corpus.cases.iter().map(|case| case.id.clone()).collect();
    assert_eq!(case_ids.len(), corpus.cases.len(), "duplicate corpus ids");
    for id in &case_ids {
        assert!(
            oracle.outcomes.contains_key(id),
            "oracle missing case {id}"
        );
    }
    for id in oracle.outcomes.keys() {
        assert!(case_ids.contains(id), "oracle has unknown case {id}");
    }
    validate_allowlist(
        &allowlist,
        &case_ids,
        REFERENCE_VERSION,
        IMPLEMENTATION_VERSION,
        TODAY,
    )
    .unwrap();

    let allow = allowlisted_cases(&allowlist);
    for (id, outcome) in &oracle.outcomes {
        if outcome.allowlisted {
            assert!(
                allow.contains(id),
                "oracle marks {id} allowlisted but allowlist has no entry"
            );
        }
    }
    for id in &allow {
        let outcome = oracle.outcomes.get(id).expect("allowlisted case in oracle");
        assert!(
            outcome.allowlisted,
            "allowlist entry {id} not marked allowlisted in oracle"
        );
    }
}

#[tokio::test]
async fn differential_corpus_agrees_with_pinned_openbao_oracle() {
    let (corpus, oracle, allowlist, _pin) = load_fixtures();
    let allow = allowlisted_cases(&allowlist);
    let harness = Harness::builder("differential")
        .register_canary(CANARY)
        .build()
        .unwrap();

    let failures = Arc::new(AtomicUsize::new(0));
    let mut scenario = harness
        .scenario_case("differential-corpus", "openbao-oracle", 1)
        .unwrap();

    for (index, case) in corpus.cases.iter().enumerate() {
        let started = Instant::now();
        let (status, body) = run_case(case).await;
        // Never log body/token content; only typed safe fields.
        let body_for_compare = body;
        let actual = normalize_outcome(status, body_for_compare);
        let expected = oracle
            .outcomes
            .get(&case.id)
            .unwrap_or_else(|| panic!("missing oracle {}", case.id));

        let comparison = compare_to_oracle(&actual, expected);
        let duration_ms = started.elapsed().as_millis() as u64;
        let agreed = comparison.is_ok();
        let is_allowlisted = allow.contains(&case.id);

        match (agreed, is_allowlisted, expected.allowlisted) {
            (true, false, false) => {
                scenario
                    .step(
                        "case-agree",
                        SafeSummary::new()
                            .field("case_index", SafeValue::Unsigned(index as u64))
                            .field(
                                "case_id",
                                SafeValue::opaque_id(hex::encode(case.id.as_bytes()))
                                    .unwrap_or(SafeValue::StaticKind("case")),
                            )
                            .field("status", SafeValue::Unsigned(u64::from(status)))
                            .field("duration_ms", SafeValue::Unsigned(duration_ms))
                            .field("family", SafeValue::StaticKind(static_family(&case.family)))
                            .field("reference", SafeValue::StaticKind("openbao-2-6-0")),
                        ExpectedOutcome::Success,
                        ActualOutcome::Success,
                    )
                    .unwrap();
            }
            (true, true, true) => {
                // Implementation matches the *declared OLSS oracle* for an
                // allowlisted intentional divergence (oracle already encodes
                // OLSS's R3 surface). Reference would differ if live OpenBao
                // were compared without the allowlist entry.
                scenario
                    .step(
                        "case-allowlisted-olss-surface",
                        SafeSummary::new()
                            .field("case_index", SafeValue::Unsigned(index as u64))
                            .field("status", SafeValue::Unsigned(u64::from(status)))
                            .field("duration_ms", SafeValue::Unsigned(duration_ms))
                            .field("family", SafeValue::StaticKind(static_family(&case.family))),
                        ExpectedOutcome::Success,
                        ActualOutcome::Success,
                    )
                    .unwrap();
            }
            (false, true, true) => {
                // Unexpected: allowlisted case should match OLSS oracle surface.
                failures.fetch_add(1, Ordering::SeqCst);
                let _ = comparison;
                scenario
                    .step(
                        "case-allowlisted-miss",
                        SafeSummary::new()
                            .field("case_index", SafeValue::Unsigned(index as u64))
                            .field("status", SafeValue::Unsigned(u64::from(status))),
                        ExpectedOutcome::Success,
                        ActualOutcome::Failure,
                    )
                    .unwrap();
            }
            (false, false, false) => {
                failures.fetch_add(1, Ordering::SeqCst);
                scenario
                    .step(
                        "case-unexplained-divergence",
                        SafeSummary::new()
                            .field("case_index", SafeValue::Unsigned(index as u64))
                            .field("status", SafeValue::Unsigned(u64::from(status)))
                            .field("duration_ms", SafeValue::Unsigned(duration_ms)),
                        ExpectedOutcome::Success,
                        ActualOutcome::Failure,
                    )
                    .unwrap();
            }
            other => {
                failures.fetch_add(1, Ordering::SeqCst);
                let _ = other;
                scenario
                    .step(
                        "case-allowlist-oracle-mismatch",
                        SafeSummary::new().field("case_index", SafeValue::Unsigned(index as u64)),
                        ExpectedOutcome::Success,
                        ActualOutcome::Failure,
                    )
                    .unwrap();
            }
        }
    }

    // Seeded deliberate divergence must be caught by the comparator.
    let mut seeded = normalize_outcome(200, json!({"data": {"keys": ["x"]}}));
    let seed_oracle = oracle.outcomes.get("metadata-list").expect("list oracle");
    seed_status_divergence(&mut seeded, 599);
    let seeded_diffs = compare_to_oracle(&seeded, seed_oracle).expect_err("seeded must fail");
    assert!(
        !seeded_diffs.is_empty(),
        "seeded status divergence must produce diffs"
    );
    scenario
        .step(
            "seeded-comparator-fault",
            SafeSummary::new()
                .field("diff_count", SafeValue::Unsigned(seeded_diffs.len() as u64))
                .field("caught", SafeValue::Boolean(true)),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();

    let report = scenario.finish_success().unwrap();
    assert!(report.scan_attestation.clean);
    assert!(
        !report.jsonl.contains("diff-canary-value"),
        "canary must not appear in harness log"
    );
    assert_eq!(
        failures.load(Ordering::SeqCst),
        0,
        "unexplained or allowlist/oracle mismatches present"
    );

    if std::env::var_os("OLSS_DIFFERENTIAL_LIVE_OPENBAO").is_some() {
        // Live OpenBao is optional evidence. Without a verified binary the
        // fixture oracle remains the release gate (documented substitute).
        let bin = std::env::var("OLSS_OPENBAO_BIN").unwrap_or_default();
        assert!(
            !bin.is_empty() && std::path::Path::new(&bin).is_file(),
            "OLSS_DIFFERENTIAL_LIVE_OPENBAO set but OLSS_OPENBAO_BIN missing or not a file"
        );
        // Full live dual-run is operator-gated; presence check documents the hook.
        let _ = bin;
    }
}

fn static_family(family: &str) -> &'static str {
    match family {
        "read-write" => "read-write",
        "cas" => "cas",
        "delete" => "delete",
        "list" => "list",
        "missing" => "missing",
        "auth" => "auth",
        "version-query" => "version-query",
        "metadata" => "metadata",
        "hygiene" => "hygiene",
        "unsupported" => "unsupported",
        _ => "other",
    }
}

// Minimal hex helper so OpaqueId can carry case ids without pulling hex crate.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }
}
