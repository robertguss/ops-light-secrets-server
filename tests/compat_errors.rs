use axum::body::to_bytes;
use axum::http::{Method, StatusCode};
use ops_light_secrets_server::compat_error::{ErrorCase, SafeRoute, contract, response};
use serde_json::{Value, json};

#[test]
fn frozen_machine_contract_matches_every_case_and_enumerated_safe_route() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/compat-error-contract-v1.json")).unwrap();
    let cases = [
        ErrorCase::UnsupportedOperation,
        ErrorCase::MetadataDelete,
        ErrorCase::UnsupportedMount,
        ErrorCase::Namespace,
        ErrorCase::TokenRenewal,
        ErrorCase::SecretNotFound,
    ];
    let generated = cases
        .into_iter()
        .map(|case| {
            let value = contract(case, Some(&Method::PATCH), Some(SafeRoute::KvData));
            json!({"case": value.case, "status": value.status})
        })
        .collect::<Vec<_>>();
    assert_eq!(fixture["cases"], serde_json::to_value(generated).unwrap());
    assert_eq!(
        fixture["safe_routes"],
        serde_json::to_value(SafeRoute::ALL_UNSUPPORTED).unwrap()
    );
}

#[tokio::test]
async fn errors_are_exact_vault_envelopes_and_never_echo_raw_targets() {
    for route in SafeRoute::ALL_UNSUPPORTED {
        let contract = contract(
            ErrorCase::UnsupportedOperation,
            Some(&Method::PATCH),
            Some(route),
        );
        assert!(!contract.message.contains("attacker-canary"));
        let response = response(
            ErrorCase::UnsupportedOperation,
            Some(&Method::PATCH),
            Some(route),
        );
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body, json!({"errors": [contract.message]}));
    }

    let missing = response(ErrorCase::SecretNotFound, None, None);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let body: Value =
        serde_json::from_slice(&to_bytes(missing.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body, json!({"errors": ["secret not found"]}));
}
