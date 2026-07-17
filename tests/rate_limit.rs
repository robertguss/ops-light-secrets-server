use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::{Router, middleware, routing};
use ops_light_secrets_server::auth::AuthenticatedToken;
use ops_light_secrets_server::input_hygiene::{InputHygieneState, input_hygiene_guard};
use ops_light_secrets_server::proxy::{ListenerType, PeerIdentity, resolve_client_source};
use ops_light_secrets_server::rate_limit::{
    AggregateClass, DropReason, RateLimitConfig, RateLimitError, RateLimitService,
    UnauthenticatedClass, authenticated_guard, pre_verifier_guard,
};
use tower::ServiceExt;

fn config() -> RateLimitConfig {
    RateLimitConfig {
        window_milliseconds: 100,
        global_attempts: 20,
        login_attempts: 2,
        probe_attempts: 3,
        identity_attempts: 2,
        source_shards: 4,
        identity_shards: 4,
        max_aggregates: 4,
        unauthenticated_body_bytes: 32,
        authenticated_body_bytes: 32,
        authenticated_concurrency: 1,
    }
}

fn limiter() -> RateLimitService {
    RateLimitService::new(config(), [7; 32]).unwrap()
}

#[test]
fn windows_have_exact_n_minus_one_n_n_plus_one_boundaries_and_separate_classes() {
    let limiter = RateLimitService::new(config(), [11; 32]).unwrap();
    let source: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Login, Some(source), 99)
            .is_ok()
    );
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Login, Some(source), 99)
            .is_ok()
    );
    assert_eq!(
        limiter.check_unauthenticated(UnauthenticatedClass::Login, Some(source), 99),
        Err(RateLimitError::RateLimited)
    );
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Probe, Some(source), 99)
            .is_ok()
    );
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Login, Some(source), 100)
            .is_ok()
    );
}

#[test]
fn rotating_sources_never_allocate_and_overflow_shards_do_not_refresh_allowance() {
    let limiter = limiter();
    let fixed = limiter.fixed_bucket_count();
    let mut refused = 0;
    for host in 1..=200_u8 {
        let source = IpAddr::from([198, 51, 100, host]);
        if limiter
            .check_unauthenticated(UnauthenticatedClass::Login, Some(source), 1)
            .is_err()
        {
            refused += 1;
        }
    }
    assert_eq!(limiter.fixed_bucket_count(), fixed);
    assert!(refused > 190, "fixed shards must share fate under churn");
    assert!(limiter.aggregate_slots() <= config().max_aggregates);
}

#[test]
fn global_cap_stops_both_classes_without_cross_consuming_class_allowance() {
    let mut cfg = config();
    cfg.global_attempts = 3;
    cfg.login_attempts = 10;
    cfg.probe_attempts = 10;
    let limiter = RateLimitService::new(cfg, [8; 32]).unwrap();
    let source = Some("203.0.113.1".parse().unwrap());
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Login, source, 1)
            .is_ok()
    );
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Login, source, 1)
            .is_ok()
    );
    assert!(
        limiter
            .check_unauthenticated(UnauthenticatedClass::Probe, source, 1)
            .is_ok()
    );
    assert_eq!(
        limiter.check_unauthenticated(UnauthenticatedClass::Probe, source, 1),
        Err(RateLimitError::RateLimited)
    );
    assert_eq!(
        limiter.check_unauthenticated(UnauthenticatedClass::Login, source, 1),
        Err(RateLimitError::RateLimited)
    );
}

#[test]
fn direct_ignores_forged_forwarding_and_proxy_uses_verified_forwarded_source() {
    let direct_peer: SocketAddr = "192.0.2.9:1234".parse().unwrap();
    let mut first_headers = HeaderMap::new();
    first_headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    let mut second_headers = HeaderMap::new();
    second_headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
    let first = resolve_client_source(
        ListenerType::Direct,
        PeerIdentity::Tcp(direct_peer),
        &first_headers,
    )
    .unwrap();
    let second = resolve_client_source(
        ListenerType::Direct,
        PeerIdentity::Tcp(direct_peer),
        &second_headers,
    )
    .unwrap();
    assert_eq!(first.rate_limit_key(), second.rate_limit_key());

    let listener = ListenerType::ReverseProxyTcp {
        trusted_peer: "127.0.0.1".parse().unwrap(),
    };
    let peer = PeerIdentity::Tcp("127.0.0.1:4321".parse().unwrap());
    let first = resolve_client_source(listener, peer, &first_headers).unwrap();
    let second = resolve_client_source(listener, peer, &second_headers).unwrap();
    assert_ne!(first.rate_limit_key(), second.rate_limit_key());

    let shared = limiter();
    assert!(
        shared
            .check_unauthenticated(UnauthenticatedClass::Login, None, 1)
            .is_ok()
    );
    assert!(
        shared
            .check_unauthenticated(UnauthenticatedClass::Login, None, 1)
            .is_ok()
    );
    assert_eq!(
        shared.check_unauthenticated(UnauthenticatedClass::Login, None, 1),
        Err(RateLimitError::RateLimited)
    );
}

#[test]
fn aggregate_buffer_is_bounded_secret_free_and_flushes_once() {
    let limiter = limiter();
    for window in 0..20 {
        limiter.record_drop(
            AggregateClass::Login,
            DropReason::Malformed,
            u16::try_from(window).unwrap(),
            window * 100,
        );
    }
    assert!(limiter.aggregate_slots() <= config().max_aggregates);
    let aggregates = limiter.take_aggregates();
    assert!(!aggregates.is_empty());
    assert!(aggregates.len() <= config().max_aggregates);
    assert_eq!(aggregates.iter().map(|entry| entry.count).sum::<u64>(), 20);
    assert!(limiter.take_aggregates().is_empty());
    let rendered = format!("{aggregates:?}");
    assert!(!rendered.contains("192.0.2"));
}

#[tokio::test]
async fn oversized_and_malformed_login_drop_before_handler_and_feed_aggregates() {
    let limiter = limiter();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let app = Router::new()
        .route(
            "/v1/auth/approle/login",
            routing::post(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::Relaxed);
                    StatusCode::OK
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            InputHygieneState::new([9; 32]),
            input_hygiene_guard,
        ))
        .layer(middleware::from_fn_with_state(
            limiter.clone(),
            pre_verifier_guard,
        ));
    let oversized = Request::builder()
        .method("POST")
        .uri("/v1/auth/approle/login")
        .header("content-length", "33")
        .body(Body::from(vec![b'x'; 33]))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(oversized).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let malformed = Request::builder()
        .method("POST")
        .uri("/v1/auth/approle/login")
        .body(Body::from("{"))
        .unwrap();
    assert_eq!(
        app.oneshot(malformed).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let aggregates = limiter.take_aggregates();
    assert!(
        aggregates
            .iter()
            .any(|entry| entry.reason == DropReason::Oversize)
    );
    assert!(
        aggregates
            .iter()
            .any(|entry| entry.reason == DropReason::Malformed)
    );

    let limiter = RateLimitService::new(config(), [11; 32]).unwrap();
    let app = Router::new()
        .route(
            "/v1/auth/approle/login",
            routing::post(|| async { StatusCode::OK }),
        )
        .layer(middleware::from_fn_with_state(
            InputHygieneState::new([9; 32]),
            input_hygiene_guard,
        ))
        .layer(middleware::from_fn_with_state(
            limiter.clone(),
            pre_verifier_guard,
        ));
    let no_length = Request::builder()
        .method("POST")
        .uri("/v1/auth/approle/login")
        .body(Body::from(vec![b'x'; 33]))
        .unwrap();
    assert_eq!(
        app.oneshot(no_length).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(
        limiter
            .take_aggregates()
            .iter()
            .any(|entry| entry.reason == DropReason::Oversize)
    );
}

async fn slow_handler() -> StatusCode {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    StatusCode::OK
}

#[tokio::test]
async fn authenticated_identity_rate_and_global_concurrency_bound_looping_clients() {
    let limiter = limiter();
    assert!(limiter.check_authenticated([1; 16], 1).is_ok());
    assert!(limiter.check_authenticated([1; 16], 1).is_ok());
    assert_eq!(
        limiter.check_authenticated([1; 16], 1),
        Err(RateLimitError::RateLimited)
    );
    assert!(limiter.check_authenticated([2; 16], 1).is_ok());

    let mut cfg = config();
    cfg.identity_attempts = 10;
    let limiter = RateLimitService::new(cfg, [10; 32]).unwrap();
    let app = Router::new()
        .route("/protected", routing::get(slow_handler))
        .layer(middleware::from_fn_with_state(
            limiter.clone(),
            authenticated_guard,
        ))
        .layer(Extension(AuthenticatedToken {
            identity_id: [3; 16],
        }));
    let oversized = app
        .clone()
        .oneshot(
            Request::get("/protected")
                .body(Body::from(vec![b'x'; 33]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let first_app = app.clone();
    let first = tokio::spawn(async move {
        first_app
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let second = app
        .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    assert!(
        limiter
            .take_aggregates()
            .iter()
            .any(|entry| entry.reason == DropReason::Concurrency)
    );
}
