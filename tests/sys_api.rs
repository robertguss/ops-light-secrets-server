use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ops_light_secrets_server::auth::{AppRoleRecord, AuthCatalog, AuthService};
use ops_light_secrets_server::control::data_router_with_auth_and_limits_and_readiness;
use ops_light_secrets_server::credential::{
    CredentialAudience, CredentialIssueMetadata, CredentialKind, issue_credential,
};
use ops_light_secrets_server::identity::{IdentityKind, IdentityRecord};
use ops_light_secrets_server::input_hygiene::InputHygieneState;
use ops_light_secrets_server::rate_limit::{RateLimitConfig, RateLimitService};
use ops_light_secrets_server::store::StoreId;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use ops_light_secrets_server::sys_api::{ReadinessSnapshot, ReadinessState};
use serde_json::{Value, json};
use tower::ServiceExt;

const IDENTITY: [u8; 16] = [2; 16];

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn auth_fixture() -> (AuthService, String) {
    let store_id = StoreId([7; 16]);
    let verifier_key = [8; 32];
    let mut catalog = AuthCatalog::new(store_id, verifier_key, 1, 100).unwrap();
    catalog
        .insert_identity(
            IdentityRecord::new(IDENTITY, "workload".into(), IdentityKind::Workload).unwrap(),
        )
        .unwrap();
    catalog
        .insert_role(
            AppRoleRecord::new([1; 16], "role-a".into(), "role".into(), IDENTITY, Some(600))
                .unwrap(),
        )
        .unwrap();
    let metadata = CredentialIssueMetadata {
        id: [3; 16],
        identity_id: IDENTITY,
        kind: CredentialKind::SecretId,
        audience: CredentialAudience::Data,
        issue_epoch: 1,
        expires_at_effective_seconds: 1_000,
        created_at_effective_seconds: 100,
        issuer_identity_id: [4; 16],
        issuance_request_id: [5; 16],
        parent_accessor: None,
        consumer_instance_id: None,
    };
    let issued = issue_credential(
        &verifier_key,
        store_id,
        metadata,
        "runtime".into(),
        &mut |_| false,
        &mut Counter(10),
    )
    .unwrap();
    let secret_id = issued.expose_once().to_owned();
    catalog
        .insert_secret_id([1; 16], issued.record.clone(), 2)
        .unwrap();
    let auth = AuthService::new(catalog, Counter(100));
    let token = auth
        .login("role-a", &secret_id, [9; 16])
        .unwrap()
        .credential
        .expose_once()
        .to_owned();
    (auth, token)
}

fn router(
    readiness: ReadinessState,
    config: RateLimitConfig,
) -> (axum::Router, String, RateLimitService) {
    let (auth, token) = auth_fixture();
    let limits = RateLimitService::new(config, [11; 32]).unwrap();
    (
        data_router_with_auth_and_limits_and_readiness(
            auth,
            InputHygieneState::new([12; 32]),
            limits.clone(),
            readiness,
        ),
        token,
        limits,
    )
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
}

#[tokio::test]
async fn frozen_probe_and_mount_shapes_match_and_mount_requires_token() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/sys-api-contract-v1.json")).unwrap();
    let (app, token, _) = router(ReadinessState::default(), RateLimitConfig::default());
    for route in ["/v1/sys/health", "/v1/sys/seal-status"] {
        let response = app
            .clone()
            .oneshot(Request::get(route).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await, fixture["probe"]);
    }
    let leader = app
        .clone()
        .oneshot(Request::get("/v1/sys/leader").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(leader.status(), StatusCode::OK);
    assert_eq!(json_body(leader).await, fixture["leader"]);

    let route = "/v1/sys/internal/ui/mounts/secret/apps/key";
    let denied = app
        .clone()
        .oneshot(Request::get(route).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let allowed = app
        .oneshot(
            Request::get(route)
                .header("x-vault-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let body = json_body(allowed).await;
    assert_eq!(body, fixture["mount_preflight"]);
    let mut mismatch = body;
    mismatch["data"]["options"]["version"] = json!("1");
    assert_ne!(mismatch, fixture["mount_preflight"]);
}

#[tokio::test]
async fn every_critical_failure_and_drain_flip_health_but_checkpoint_age_does_not() {
    let readiness = ReadinessState::default();
    let (app, _, _) = router(readiness.clone(), RateLimitConfig::default());
    for degraded in [
        ReadinessSnapshot {
            keyring: false,
            ..ReadinessSnapshot::default()
        },
        ReadinessSnapshot {
            schema: false,
            ..ReadinessSnapshot::default()
        },
        ReadinessSnapshot {
            transaction_audit: false,
            ..ReadinessSnapshot::default()
        },
        ReadinessSnapshot {
            capacity: false,
            ..ReadinessSnapshot::default()
        },
        ReadinessSnapshot {
            draining: true,
            ..ReadinessSnapshot::default()
        },
    ] {
        readiness.replace(degraded);
        let response = app
            .clone()
            .oneshot(Request::get("/v1/sys/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await,
            json!({"initialized":true,"sealed":false,"standby":false,"version":"0.1.0"})
        );
    }
    readiness.replace(ReadinessSnapshot {
        checkpoint_current: false,
        ..ReadinessSnapshot::default()
    });
    let response = app
        .oneshot(Request::get("/v1/sys/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_flood_does_not_spend_probe_bucket_and_probe_bodies_are_bounded() {
    let config = RateLimitConfig {
        login_attempts: 1,
        probe_attempts: 2,
        global_attempts: 10,
        unauthenticated_body_bytes: 32,
        ..RateLimitConfig::default()
    };
    let (app, _, limits) = router(ReadinessState::default(), config);
    for expected in [StatusCode::BAD_REQUEST, StatusCode::TOO_MANY_REQUESTS] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/approle/login")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let health = app
        .clone()
        .oneshot(Request::get("/v1/sys/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let oversized = app
        .oneshot(
            Request::get("/v1/sys/seal-status")
                .header("content-length", "33")
                .body(Body::from(vec![0; 33]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(limits.aggregate_slots() <= config.max_aggregates);
}

#[tokio::test]
async fn remote_probe_disclosure_is_allowlisted_and_namespace_is_never_echoed() {
    let (app, _, _) = router(ReadinessState::default(), RateLimitConfig::default());
    let response = app
        .oneshot(
            Request::get("/v1/sys/health")
                .header("x-vault-namespace", "attacker-canary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rendered = json_body(response).await.to_string();
    assert!(!rendered.contains("attacker-canary"));
    for forbidden in ["path", "identity", "capacity", "key_id", "audit", "reserve"] {
        assert!(!rendered.contains(forbidden));
    }
}
