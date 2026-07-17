use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, Request, StatusCode};
use axum::response::IntoResponse;
use axum::{Router, middleware, routing};
use ops_light_secrets_server::http_security::{SECURITY_LAYER_ORDER, apply_with_timeout};
use ops_light_secrets_server::input_hygiene::{
    InputHygieneState, MAX_HEADER_FIELDS, input_hygiene_guard,
};
use ops_light_secrets_server::raw_target::raw_target_guard;
use tower::ServiceExt;

#[derive(Clone, Default)]
struct Probe(Arc<Mutex<Vec<String>>>);

async fn observed(State(probe): State<Probe>, headers: HeaderMap) -> impl IntoResponse {
    let token = headers.get("x-vault-token").unwrap();
    assert!(token.is_sensitive());
    assert!(headers.contains_key("x-vault-request"));
    probe.0.lock().unwrap().push(format!("{headers:?}"));
    StatusCode::OK
}

fn representative(probe: Probe, timeout: Duration) -> Router {
    apply_with_timeout(
        Router::new()
            .route("/v1/{*path}", routing::get(observed))
            .with_state(probe),
        timeout,
    )
    .layer(middleware::from_fn_with_state(
        InputHygieneState::new([7; 32]),
        input_hygiene_guard,
    ))
    .layer(middleware::from_fn(raw_target_guard))
}

#[tokio::test]
async fn order_marks_credentials_before_trace_and_raw_refusals_reach_nothing_inner() {
    assert_eq!(
        SECURITY_LAYER_ORDER,
        [
            "raw-target",
            "input-bounds",
            "sensitive-headers",
            "request-id",
            "trace",
            "request-deadline",
            "route-auth-and-limits",
            "handler",
        ]
    );
    let probe = Probe::default();
    let app = representative(probe.clone(), Duration::from_secs(1));
    let token = "middleware-private-token-canary";
    let response = app
        .clone()
        .oneshot(
            Request::get("/v1/secret/data/app/key")
                .header("x-vault-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let observed = probe.0.lock().unwrap().clone();
    assert_eq!(observed.len(), 1);
    assert!(!observed[0].contains(token));
    assert!(observed[0].contains("Sensitive"));

    let refused = app
        .oneshot(
            Request::get("/v1/secret/data/%2Fhidden")
                .header("x-vault-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(probe.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn header_bounds_run_before_observability_and_request_deadline_is_bounded() {
    let probe = Probe::default();
    let app = representative(probe.clone(), Duration::from_millis(1));
    let mut request = Request::get("/v1/secret/data/app/key")
        .header("x-vault-token", "token")
        .body(Body::empty())
        .unwrap();
    for index in 0..MAX_HEADER_FIELDS {
        request.headers_mut().insert(
            format!("x-bound-{index}").parse::<HeaderName>().unwrap(),
            "v".parse().unwrap(),
        );
    }
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(probe.0.lock().unwrap().is_empty());

    let slow = apply_with_timeout(
        Router::new().route(
            "/slow",
            routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(25)).await;
                StatusCode::OK
            }),
        ),
        Duration::from_millis(1),
    );
    let response = slow
        .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
}
