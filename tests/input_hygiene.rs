use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware;
use axum::{Extension, Router, routing::any};
use ops_light_secrets_server::input_hygiene::{
    HygieneReason, InputHygieneState, MAX_HEADER_BYTES, MAX_HEADER_FIELDS, MAX_JSON_BODY_BYTES,
    MAX_JSON_DEPTH, MAX_JSON_KEYS, MAX_JSON_VALUES, MAX_QUERY_PARAMETERS, QueryShapeReason,
    StrictJsonBody, ValidatedToken, input_hygiene_guard, parse_strict_json,
    validate_sensitive_query, validate_token_headers,
};
use tower::ServiceExt;

const KEY: [u8; 32] = [0x62; 32];

#[test]
fn duplicate_json_keys_are_rejected_at_every_depth_after_unescaping() {
    let cases = [
        br#"{"cas":0,"cas":1}"#.as_slice(),
        br#"{"cas":0,"\u0063as":1}"#.as_slice(),
        br#"{"options":{"cas":0,"cas":1}}"#.as_slice(),
        br#"{"data":{"nested":[{"role_id":"a","role_id":"b"}]}}"#.as_slice(),
        br#"{"secret_id":"a","secret_id":"b"}"#.as_slice(),
        br#"{"versions":[1],"versions":[2]}"#.as_slice(),
    ];
    for body in cases {
        let error = parse_strict_json(body, &KEY).unwrap_err();
        assert_eq!(error.reason(), HygieneReason::DuplicateJsonKey);
        assert!(error.to_string().contains("input_digest="));
        assert!(!error.to_string().contains("secret_id"));
    }
    assert!(parse_strict_json(br#"{"cas":0,"data":{"cas":1}}"#, &KEY).is_ok());
}

#[test]
fn malformed_control_and_invalid_utf8_json_are_safe_refusals() {
    for body in [
        b"{\"x\":\"line\nraw\"}".as_slice(),
        b"{\"x\":\xff}".as_slice(),
        b"{\"x\":1} trailing".as_slice(),
    ] {
        let error = parse_strict_json(body, &KEY).unwrap_err();
        assert_eq!(error.reason(), HygieneReason::InvalidJson);
        assert!(!error.to_string().contains("line"));
        assert!(error.to_string().len() < 140);
    }
}

#[test]
fn json_depth_key_value_and_byte_bounds_are_exact() {
    for depth in [MAX_JSON_DEPTH - 1, MAX_JSON_DEPTH, MAX_JSON_DEPTH + 1] {
        let body = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let result = parse_strict_json(body.as_bytes(), &KEY);
        if depth <= MAX_JSON_DEPTH {
            assert!(result.is_ok(), "depth {depth}");
        } else {
            assert_eq!(result.unwrap_err().reason(), HygieneReason::JsonTooDeep);
        }
    }

    for keys in [MAX_JSON_KEYS - 1, MAX_JSON_KEYS, MAX_JSON_KEYS + 1] {
        let fields = (0..keys)
            .map(|index| format!("\"k{index}\":0"))
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_strict_json(format!("{{{fields}}}").as_bytes(), &KEY);
        if keys <= MAX_JSON_KEYS {
            assert!(result.is_ok(), "keys {keys}");
        } else {
            assert_eq!(result.unwrap_err().reason(), HygieneReason::TooManyJsonKeys);
        }
    }

    for total_values in [MAX_JSON_VALUES - 1, MAX_JSON_VALUES, MAX_JSON_VALUES + 1] {
        let elements = "0,".repeat(total_values.saturating_sub(2));
        let body = format!("[{elements}0]");
        let result = parse_strict_json(body.as_bytes(), &KEY);
        if total_values <= MAX_JSON_VALUES {
            assert!(result.is_ok(), "values {total_values}");
        } else {
            assert_eq!(
                result.unwrap_err().reason(),
                HygieneReason::TooManyJsonValues
            );
        }
    }

    let overhead = br#"{"x":""}"#.len();
    let at_limit = format!(
        "{{\"x\":\"{}\"}}",
        "a".repeat(MAX_JSON_BODY_BYTES - overhead)
    );
    assert_eq!(at_limit.len(), MAX_JSON_BODY_BYTES);
    assert!(parse_strict_json(at_limit.as_bytes(), &KEY).is_ok());
    let over_limit = format!("{at_limit} ");
    assert_eq!(
        parse_strict_json(over_limit.as_bytes(), &KEY)
            .unwrap_err()
            .reason(),
        HygieneReason::BodyTooLarge
    );
}

#[test]
fn query_corpus_is_closed_canonical_and_bounded() {
    for valid in [
        None,
        Some("version=1"),
        Some("list=true"),
        Some("version=1&list=true"),
    ] {
        assert!(validate_sensitive_query(valid).is_ok());
    }
    let rejected = [
        ("version=1&version=2", QueryShapeReason::Duplicate),
        ("list=true&list=false", QueryShapeReason::Duplicate),
        ("Version=1", QueryShapeReason::NoncanonicalName),
        ("vers%69on=1", QueryShapeReason::NoncanonicalName),
        ("unknown=1", QueryShapeReason::UnknownName),
        ("version", QueryShapeReason::Invalid),
        ("ver\nsion=1", QueryShapeReason::UnknownName),
    ];
    for (query, reason) in rejected {
        assert_eq!(
            validate_sensitive_query(Some(query)).unwrap_err().reason,
            reason
        );
    }
    assert_eq!(MAX_QUERY_PARAMETERS, 2);
    assert_eq!(
        validate_sensitive_query(Some("version=1&list=true&version=2"))
            .unwrap_err()
            .reason,
        QueryShapeReason::TooMany
    );
}

fn header_inventory(count: usize) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for index in 0..count {
        let name = HeaderName::from_bytes(format!("x-safe-{index}").as_bytes()).unwrap();
        headers.insert(name, HeaderValue::from_static("1"));
    }
    headers
}

#[test]
fn token_header_case_combining_encoding_and_count_ambiguity_refuse() {
    for count in [MAX_HEADER_FIELDS - 1, MAX_HEADER_FIELDS] {
        assert!(validate_token_headers(&header_inventory(count), &KEY).is_ok());
    }
    assert_eq!(
        validate_token_headers(&header_inventory(MAX_HEADER_FIELDS + 1), &KEY)
            .unwrap_err()
            .reason(),
        HygieneReason::TooManyHeaders
    );

    let mut multiple = HeaderMap::new();
    multiple.append("X-Vault-Token", HeaderValue::from_static("first"));
    multiple.append("x-vault-token", HeaderValue::from_static("second"));
    assert_eq!(
        validate_token_headers(&multiple, &KEY)
            .unwrap_err()
            .reason(),
        HygieneReason::MultipleTokenHeaders
    );
    let mut combined = HeaderMap::new();
    combined.insert("x-vault-token", HeaderValue::from_static("first, second"));
    assert_eq!(
        validate_token_headers(&combined, &KEY)
            .unwrap_err()
            .reason(),
        HygieneReason::CombinedTokenHeader
    );
    let mut invalid = HeaderMap::new();
    invalid.insert("x-vault-token", HeaderValue::from_bytes(&[0xff]).unwrap());
    assert_eq!(
        validate_token_headers(&invalid, &KEY).unwrap_err().reason(),
        HygieneReason::InvalidTokenHeader
    );
}

#[test]
fn total_header_bytes_hold_at_n_minus_one_n_and_n_plus_one() {
    let name = HeaderName::from_static("x-size");
    for total in [MAX_HEADER_BYTES - 1, MAX_HEADER_BYTES] {
        let mut headers = HeaderMap::new();
        headers.insert(
            name.clone(),
            HeaderValue::from_bytes(&vec![b'a'; total - name.as_str().len()]).unwrap(),
        );
        assert!(validate_token_headers(&headers, &KEY).is_ok());
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        name.clone(),
        HeaderValue::from_bytes(&vec![b'a'; MAX_HEADER_BYTES + 1 - name.as_str().len()]).unwrap(),
    );
    assert_eq!(
        validate_token_headers(&headers, &KEY).unwrap_err().reason(),
        HygieneReason::HeaderBytesTooLarge
    );
}

#[tokio::test]
async fn middleware_rejects_before_state_access_and_inserts_only_validated_types() {
    let accesses = Arc::new(AtomicUsize::new(0));
    let application = Router::new()
        .fallback(any({
            let accesses = accesses.clone();
            move |Extension(json): Extension<StrictJsonBody>,
                  Extension(token): Extension<ValidatedToken>| {
                let accesses = accesses.clone();
                async move {
                    accesses.fetch_add(1, Ordering::SeqCst);
                    format!("{}:{}", json.0["ok"], token.0.len())
                }
            }
        }))
        .layer(middleware::from_fn_with_state(
            InputHygieneState::new(KEY),
            input_hygiene_guard,
        ));

    for request in [
        Request::builder()
            .uri("/v1/secret/data/a?version=1&version=2")
            .header("x-vault-token", "TOKEN_SECRET_CANARY_91af")
            .body(Body::from(r#"{"ok":true}"#))
            .unwrap(),
        Request::builder()
            .uri("/v1/secret/data/a")
            .header("x-vault-token", "TOKEN_SECRET_CANARY_91af")
            .header("x-vault-token", "TOKEN_SECRET_CANARY_22be")
            .body(Body::from(r#"{"ok":true}"#))
            .unwrap(),
        Request::builder()
            .uri("/v1/secret/data/a")
            .header("x-vault-token", "TOKEN_SECRET_CANARY_91af")
            .body(Body::from(r#"{"ok":true,"ok":false}"#))
            .unwrap(),
    ] {
        let response = application.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("TOKEN_SECRET_CANARY"));
        assert_eq!(accesses.load(Ordering::SeqCst), 0);
    }

    let accepted = application
        .oneshot(
            Request::builder()
                .uri("/v1/secret/data/a?version=1")
                .header("x-vault-token", "TOKEN_SECRET_CANARY_91af")
                .body(Body::from(r#"{"ok":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accesses.load(Ordering::SeqCst), 1);
}
