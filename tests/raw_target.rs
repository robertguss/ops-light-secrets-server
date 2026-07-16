use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::Extension,
    http::{Method, Request, StatusCode},
    middleware,
    routing::any,
};
use ops_light_secrets_server::raw_target::{
    EndpointKind, EndpointRequest, MAX_RAW_TARGET_BYTES, ParseReason, parse_raw_target,
    raw_target_guard,
};
use serde_json::Value;
use test_support::{
    ActualOutcome, ExpectedOutcome, Harness, PropertyEvidence, RedactedCommand, SafeSummary,
};
use tower::ServiceExt;

fn parsed(method: &Method, target: &str) -> EndpointRequest {
    parse_raw_target(method, target).unwrap()
}

#[test]
fn corpus_rejects_ambiguous_and_noncanonical_targets() {
    let cases = [
        "/v1/secret/data/a%2Fb",
        "/v1/secret/data/a%2fb",
        "/v1/secret/data/a%5Cb",
        "/v1/secret/data/a%5cb",
        "/v1/secret/data/a%25b",
        "/v1/secret/data/%252F",
        "/v1/secret/data/%2E",
        "/v1/secret/data/%2e",
        "/v1/secret/data/.",
        "/v1/secret/data/..",
        "/v1/secret/data/a//b",
        "/v1/secret/data/a/",
        "/v1/secret/data/%",
        "/v1/secret/data/%2",
        "/v1/secret/data/%GG",
        "/v1/secret/data/%00",
        "/v1/secret/data/%FF",
        "/v1/secret/data/%61",
        "/v1/secret/data/%2B",
        "/v1/secret/data/caf%c3%a9",
    ];
    for target in cases {
        assert!(
            parse_raw_target(&Method::GET, target).is_err(),
            "accepted {target}"
        );
    }
}

#[test]
fn boundary_plus_utf8_and_unicode_byte_identity_are_explicit() {
    let plus = parsed(&Method::GET, "/v1/secret/data/plus+sign");
    assert_eq!(plus.resource.canonical_segments, ["plus+sign"]);
    let composed = parsed(&Method::GET, "/v1/secret/data/caf%C3%A9");
    assert_eq!(composed.resource.canonical_segments, ["café"]);
    let decomposed = parsed(&Method::GET, "/v1/secret/data/cafe%CC%81");
    assert_ne!(
        composed.resource.canonical_segments,
        decomposed.resource.canonical_segments
    );

    let prefix = "/v1/secret/data/";
    for length in [MAX_RAW_TARGET_BYTES - 1, MAX_RAW_TARGET_BYTES] {
        let target = format!("{prefix}{}", "a".repeat(length - prefix.len()));
        assert!(parse_raw_target(&Method::GET, &target).is_ok());
    }
    let target = format!(
        "{prefix}{}",
        "a".repeat(MAX_RAW_TARGET_BYTES + 1 - prefix.len())
    );
    let error = parse_raw_target(&Method::GET, &target).unwrap_err();
    assert_eq!(error.reason(), ParseReason::TargetTooLong);
    assert!(error.to_string().len() < 160);
    assert!(!error.to_string().contains(&"a".repeat(64)));
    let canary = "RAW_TARGET_DIAGNOSTIC_CANARY_8f21";
    let error = parse_raw_target(&Method::GET, &format!("/v1/secret/data/{canary}@"))
        .unwrap_err()
        .to_string();
    assert!(!error.contains(canary));
}

#[test]
fn list_root_and_trailing_empty_are_scoped_to_explicit_list_forms() {
    let list = Method::from_bytes(b"LIST").unwrap();
    for target in [
        "/v1/secret/metadata",
        "/v1/secret/metadata/",
        "/v1/secret/metadata/apps/",
        "/v1/secret/metadata/apps?list=true",
    ] {
        let request = parsed(&list, target);
        assert_eq!(request.kind, EndpointKind::List);
    }
    assert_eq!(
        parsed(&Method::GET, "/v1/secret/metadata/?list=true").kind,
        EndpointKind::List
    );
    for target in [
        "/v1/secret/data/apps/",
        "/v1/secret/delete/apps/",
        "/v1/secret/undelete/apps/",
        "/v1/secret/destroy/apps/",
        "/v1/secret/metadata/apps/",
    ] {
        assert!(
            parse_raw_target(&Method::GET, target).is_err(),
            "accepted {target}"
        );
    }
}

#[test]
fn query_contract_rejects_duplicates_aliases_and_noncanonical_values() {
    let rejected = [
        "/v1/secret/data/a?version=1&version=2",
        "/v1/secret/data/a?Version=1",
        "/v1/secret/data/a?vers%69on=1",
        "/v1/secret/data/a?version=01",
        "/v1/secret/data/a?version=0",
        "/v1/secret/metadata/a?list=true&list=true",
        "/v1/secret/metadata/a?list=True",
        "/v1/secret/metadata/a?unknown=1",
    ];
    for target in rejected {
        assert!(
            parse_raw_target(&Method::GET, target).is_err(),
            "accepted {target}"
        );
    }
    assert_eq!(
        parsed(&Method::GET, "/v1/secret/data/a?version=12").version,
        Some(12)
    );
}

#[test]
fn every_endpoint_form_maps_one_logical_path_to_one_resource() {
    let targets = [
        "/v1/secret/data/apps/caf%C3%A9",
        "/v1/secret/metadata/apps/caf%C3%A9",
        "/v1/secret/delete/apps/caf%C3%A9",
        "/v1/secret/undelete/apps/caf%C3%A9",
        "/v1/secret/destroy/apps/caf%C3%A9",
        "/v1/secret/metadata/apps/caf%C3%A9?list=true",
    ];
    let resources: Vec<_> = targets
        .iter()
        .map(|target| parsed(&Method::GET, target).resource)
        .collect();
    assert!(resources.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn generated_endpoint_forms_share_one_resource_with_typed_property_evidence() {
    let harness = Harness::builder("raw-target-property")
        .register_canary(b"raw-target-property-canary")
        .build()
        .unwrap();
    let mut scenario = harness
        .scenario_case("raw-target-property", "all-endpoint-forms", 1)
        .unwrap();
    scenario
        .set_reproduction(
            RedactedCommand::new("cargo")
                .literal("test")
                .literal("--locked")
                .literal("--test")
                .literal("raw_target"),
        )
        .unwrap();
    let seed = 0x5eed_cafe_u64;
    let mut state = seed;
    let mut corpus = Vec::new();
    for _ in 0..512 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let left = format!("app-{}", state % 10_000);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let right = format!("item+{}", state % 10_000);
        let suffix = format!("{left}/{right}");
        let targets = [
            format!("/v1/secret/data/{suffix}"),
            format!("/v1/secret/metadata/{suffix}"),
            format!("/v1/secret/delete/{suffix}"),
            format!("/v1/secret/undelete/{suffix}"),
            format!("/v1/secret/destroy/{suffix}"),
            format!("/v1/secret/metadata/{suffix}?list=true"),
        ];
        let resources: Vec<_> = targets
            .iter()
            .map(|target| parsed(&Method::GET, target).resource)
            .collect();
        assert!(resources.windows(2).all(|pair| pair[0] == pair[1]));
        corpus.extend(targets);
    }
    let corpus_digest = blake3::hash(corpus.join("\n").as_bytes())
        .to_hex()
        .to_string();
    let minimized = blake3::hash(b"/v1/m/d/a").to_hex().to_string();
    let artifact = blake3::hash(b"raw-target-generated-corpus")
        .to_hex()
        .to_string();
    scenario
        .property_step(
            "all-endpoint-forms",
            SafeSummary::new(),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
            PropertyEvidence::new(seed, corpus_digest, minimized, artifact).unwrap(),
        )
        .unwrap();
    let report = scenario.finish_success().unwrap();
    assert!(report.scan_attestation.clean);
}

#[test]
fn normalized_capture_fixtures_govern_emitted_data_targets() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/client-traces/vault-2.0.3-direct.json"
    ))
    .unwrap();
    let paths = fixture["paths"].as_array().unwrap();
    for path in paths {
        let case = path["case"].as_str().unwrap();
        let requests = path["requests"].as_array().unwrap();
        if requests.len() < 2 {
            continue;
        }
        let target =
            String::from_utf8(hex_decode(requests[1]["raw_target_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let outcome = parse_raw_target(&Method::GET, &target);
        if matches!(case, "percent-slash" | "percent-percent" | "dot" | "dotdot") {
            assert!(
                outcome.is_err(),
                "fixture case {case} unexpectedly accepted"
            );
        } else {
            assert!(outcome.is_ok(), "fixture case {case} unexpectedly rejected");
        }
    }
}

#[tokio::test]
async fn guard_rejects_before_dispatch_and_inserts_only_typed_resource() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let application = Router::new()
        .fallback(any({
            let dispatches = dispatches.clone();
            move |Extension(request): Extension<EndpointRequest>| {
                let dispatches = dispatches.clone();
                async move {
                    dispatches.fetch_add(1, Ordering::SeqCst);
                    request.resource.mount
                }
            }
        }))
        .layer(middleware::from_fn(raw_target_guard));

    let rejected = application
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/secret/data/a%2Fb")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);

    let accepted = application
        .oneshot(
            Request::builder()
                .uri("/v1/secret/data/a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| ())?;
            u8::from_str_radix(text, 16).map_err(|_| ())
        })
        .collect()
}
