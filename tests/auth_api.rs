use std::sync::{Arc, Barrier};

use axum::body::{Body, to_bytes};
use axum::extract::Extension;
use axum::http::{Request, StatusCode};
use axum::{Json, Router, middleware, routing};
use ops_light_secrets_server::auth::{
    APPROLE_SCHEMA_VERSION, AppRoleRecord, AuthAuditOutcome, AuthCatalog, AuthError, AuthOperation,
    AuthService, AuthenticatedToken, SECRET_ID_USAGE_SCHEMA_VERSION, SecretIdUsageRecord,
    control_token_auth_guard, token_auth_guard,
};
use ops_light_secrets_server::control::data_router_with_auth;
use ops_light_secrets_server::credential::{
    CredentialAccessor, CredentialAudience, CredentialIssueMetadata, CredentialKind,
    ROLE_TOKEN_MAX_TTL_SECONDS, ROLE_TOKEN_MIN_TTL_SECONDS, issue_credential,
};
use ops_light_secrets_server::identity::{IdentityKind, IdentityRecord};
use ops_light_secrets_server::input_hygiene::{InputHygieneState, input_hygiene_guard};
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use ops_light_secrets_server::store::{Canonical, StoreId};
use tower::ServiceExt;

async fn protected(Extension(token): Extension<AuthenticatedToken>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"identity_id": token.identity_id}))
}

const STORE_ID: StoreId = StoreId([7; 16]);
const VERIFIER_KEY: [u8; 32] = [8; 32];

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn fixture(uses: u32, token_ttl: u64) -> (AuthService, String, CredentialAccessor) {
    let mut catalog = AuthCatalog::new(STORE_ID, VERIFIER_KEY, 1, 100).unwrap();
    catalog
        .insert_identity(
            IdentityRecord::new([2; 16], "payments-workload".into(), IdentityKind::Workload)
                .unwrap(),
        )
        .unwrap();
    let role = AppRoleRecord::new(
        [1; 16],
        "public-role-a".into(),
        "payments".into(),
        [2; 16],
        Some(token_ttl),
    )
    .unwrap();
    catalog.insert_role(role).unwrap();
    let metadata = CredentialIssueMetadata {
        id: [3; 16],
        identity_id: [2; 16],
        kind: CredentialKind::SecretId,
        audience: CredentialAudience::Data,
        issue_epoch: 1,
        expires_at_effective_seconds: 1_000,
        created_at_effective_seconds: 100,
        issuer_identity_id: [4; 16],
        issuance_request_id: [5; 16],
        parent_accessor: None,
        consumer_instance_id: Some([6; 16]),
    };
    let mut random = Counter(10);
    let issued = issue_credential(
        &VERIFIER_KEY,
        STORE_ID,
        metadata,
        "payments-runtime".into(),
        &mut |_| false,
        &mut random,
    )
    .unwrap();
    let secret = issued.expose_once().to_owned();
    let accessor = issued.record.accessor;
    catalog
        .insert_secret_id([1; 16], issued.record.clone(), uses)
        .unwrap();
    (AuthService::new(catalog, Counter(100)), secret, accessor)
}

#[test]
fn role_and_usage_records_are_canonical_and_bounds_are_frozen() {
    assert_eq!(APPROLE_SCHEMA_VERSION, 3);
    assert_eq!(SECRET_ID_USAGE_SCHEMA_VERSION, 4);
    assert!(
        AppRoleRecord::new(
            [1; 16],
            "role".into(),
            "name".into(),
            [2; 16],
            Some(ROLE_TOKEN_MIN_TTL_SECONDS - 1),
        )
        .is_err()
    );
    assert_eq!(
        AppRoleRecord::new(
            [1; 16],
            "role-default".into(),
            "name-default".into(),
            [2; 16],
            None,
        )
        .unwrap()
        .token_ttl_seconds,
        3_600
    );
    assert!(
        AppRoleRecord::new(
            [1; 16],
            "role".into(),
            "name".into(),
            [2; 16],
            Some(ROLE_TOKEN_MAX_TTL_SECONDS + 1),
        )
        .is_err()
    );
    let role =
        AppRoleRecord::new([1; 16], "role".into(), "name".into(), [2; 16], Some(3_600)).unwrap();
    let encoded = role.encode().unwrap();
    assert_eq!(AppRoleRecord::decode(&encoded).unwrap(), role);
    let sealed = role.clone().seal(&[4; 32], STORE_ID).unwrap();
    sealed.verify(&[4; 32], STORE_ID, &role.id).unwrap();
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(AppRoleRecord::decode(&trailing).is_err());

    let usage = SecretIdUsageRecord::new(CredentialAccessor([3; 16]), [1; 16], 1).unwrap();
    let encoded = usage.encode().unwrap();
    assert_eq!(SecretIdUsageRecord::decode(&encoded).unwrap(), usage);
    let sealed = usage.clone().seal(&[4; 32], STORE_ID).unwrap();
    sealed
        .verify(&[4; 32], STORE_ID, &usage.accessor.0)
        .unwrap();
    assert!(SecretIdUsageRecord::new(CredentialAccessor([3; 16]), [1; 16], 0).is_err());
    assert!(SecretIdUsageRecord::new(CredentialAccessor([3; 16]), [1; 16], 1_001).is_err());
}

#[test]
fn f3_login_token_and_lookup_self_use_role_ttl_and_hide_bearer() {
    let (service, secret, accessor) = fixture(2, 600);
    let login = service.login("public-role-a", &secret, [20; 16]).unwrap();
    let token = login.credential.expose_once().to_owned();
    assert_eq!(login.lease_duration, 600);
    assert_eq!(login.credential.record.parent_accessor, Some(accessor));
    assert_eq!(login.credential.record.consumer_instance_id, Some([6; 16]));
    assert_eq!(
        service.with_catalog(|catalog| catalog.usage(accessor).unwrap().remaining_uses),
        1
    );
    service.with_catalog(|catalog| catalog.set_effective_seconds(120).unwrap());
    let lookup = service.lookup_self(&token, [21; 16]).unwrap();
    assert_eq!(lookup.ttl, 580);
    assert_eq!(lookup.lease_duration, 600);
    assert_eq!(lookup.entity_id, "02020202020202020202020202020202");
    let json = serde_json::to_string(&lookup).unwrap();
    assert!(!json.contains(&token));
    assert!(!json.contains("\"id\""));
    service.with_catalog(|catalog| catalog.set_effective_seconds(699).unwrap());
    assert_eq!(service.lookup_self(&token, [22; 16]).unwrap().ttl, 1);
    service.with_catalog(|catalog| catalog.set_effective_seconds(700).unwrap());
    assert_eq!(
        service.lookup_self(&token, [23; 16]),
        Err(AuthError::Unauthenticated)
    );
}

#[test]
fn wrong_role_invalid_secret_and_deleted_role_have_one_normalized_failure() {
    let (wrong_role, secret, _) = fixture(1, 600);
    wrong_role.with_catalog(|catalog| {
        catalog
            .insert_role(
                AppRoleRecord::new(
                    [9; 16],
                    "public-role-b".into(),
                    "billing".into(),
                    [2; 16],
                    Some(600),
                )
                .unwrap(),
            )
            .unwrap()
    });
    let wrong = wrong_role
        .login("public-role-b", &secret, [30; 16])
        .err()
        .unwrap();
    let (invalid, _, _) = fixture(1, 600);
    let bad = invalid
        .login("public-role-a", "secret-id.data.bad.bad", [31; 16])
        .err()
        .unwrap();
    assert_eq!(wrong, AuthError::InvalidCredentials);
    assert_eq!(wrong, bad);

    let (deleted, secret, _) = fixture(1, 600);
    deleted.with_catalog(|catalog| catalog.delete_role("public-role-a", 1).unwrap());
    assert_eq!(
        deleted
            .login("public-role-a", &secret, [32; 16])
            .err()
            .unwrap(),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        deleted.with_catalog(|catalog| catalog.audit().last().unwrap().outcome),
        AuthAuditOutcome::Denied
    );
}

#[test]
fn one_use_concurrent_login_commits_once_and_lost_reply_never_rediscloses() {
    let (service, secret, accessor) = fixture(1, 600);
    let service = Arc::new(service);
    let secret = Arc::new(secret);
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for request in [40_u8, 41] {
        let service = Arc::clone(&service);
        let secret = Arc::clone(&secret);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            service.login("public-role-a", &secret, [request; 16])
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        service.with_catalog(|catalog| catalog.usage(accessor).unwrap().remaining_uses),
        0
    );

    let committed_request = if results[0].is_ok() {
        [40; 16]
    } else {
        [41; 16]
    };
    assert!(matches!(
        service
            .login("public-role-a", &secret, committed_request)
            .err()
            .unwrap(),
        AuthError::AlreadyCommitted { .. }
    ));
    assert!(
        service.with_catalog(|catalog| catalog.credential_by_request(committed_request).is_some())
    );
}

#[test]
fn deleting_role_does_not_revoke_already_issued_token() {
    let (service, secret, _) = fixture(2, 600);
    let login = service.login("public-role-a", &secret, [50; 16]).unwrap();
    let token = login.credential.expose_once().to_owned();
    service.with_catalog(|catalog| catalog.delete_role("public-role-a", 1).unwrap());
    assert!(service.lookup_self(&token, [51; 16]).is_ok());
    assert_eq!(
        service
            .login("public-role-a", &secret, [52; 16])
            .err()
            .unwrap(),
        AuthError::InvalidCredentials
    );
}

#[test]
fn identity_disable_invalidates_token_at_next_linearized_authentication() {
    let (service, secret, _) = fixture(2, 600);
    let login = service.login("public-role-a", &secret, [53; 16]).unwrap();
    let token = login.credential.expose_once().to_owned();
    assert!(
        service
            .authenticate(&token, CredentialAudience::Data)
            .is_ok()
    );
    let retired = IdentityRecord::new([2; 16], "payments-workload".into(), IdentityKind::Workload)
        .unwrap()
        .retire(1)
        .unwrap();
    service.with_catalog(|catalog| catalog.replace_identity(retired).unwrap());
    assert!(matches!(
        service.authenticate(&token, CredentialAudience::Data),
        Err(AuthError::Unauthenticated)
    ));
}

#[test]
fn delete_login_race_is_linearized_and_never_accepts_after_delete() {
    let (service, secret, _) = fixture(2, 600);
    let secret_after = secret.clone();
    let service = Arc::new(service);
    let barrier = Arc::new(Barrier::new(3));
    let login_service = Arc::clone(&service);
    let login_barrier = Arc::clone(&barrier);
    let login = std::thread::spawn(move || {
        login_barrier.wait();
        login_service.login("public-role-a", &secret, [54; 16])
    });
    let delete_service = Arc::clone(&service);
    let delete_barrier = Arc::clone(&barrier);
    let delete = std::thread::spawn(move || {
        delete_barrier.wait();
        delete_service.with_catalog(|catalog| catalog.delete_role("public-role-a", 1))
    });
    barrier.wait();
    let _ = login.join().unwrap();
    delete.join().unwrap().unwrap();
    assert_eq!(
        service
            .login("public-role-a", &secret_after, [56; 16])
            .err()
            .unwrap(),
        AuthError::InvalidCredentials
    );
}

#[tokio::test]
async fn token_middleware_resolves_identity_and_separates_listener_audiences() {
    let (service, secret, _) = fixture(2, 600);
    let login = service.login("public-role-a", &secret, [55; 16]).unwrap();
    let token = login.credential.expose_once().to_owned();
    let data = Router::new()
        .route("/protected", routing::get(protected))
        .layer(middleware::from_fn_with_state(
            service.clone(),
            token_auth_guard,
        ))
        .layer(middleware::from_fn_with_state(
            InputHygieneState::new([9; 32]),
            input_hygiene_guard,
        ));
    let response = data
        .oneshot(
            Request::get("/protected")
                .header("x-vault-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let control = Router::new()
        .route("/protected", routing::get(protected))
        .layer(middleware::from_fn_with_state(
            service,
            control_token_auth_guard,
        ))
        .layer(middleware::from_fn_with_state(
            InputHygieneState::new([9; 32]),
            input_hygiene_guard,
        ));
    let response = control
        .oneshot(
            Request::get("/protected")
                .header("x-vault-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn vault_routes_have_stable_envelopes_strict_json_and_explicit_renewal_refusal() {
    let (service, secret, _) = fixture(3, 600);
    service.with_catalog(|catalog| {
        catalog
            .insert_role(
                AppRoleRecord::new(
                    [9; 16],
                    "public-role-b".into(),
                    "billing".into(),
                    [2; 16],
                    Some(600),
                )
                .unwrap(),
            )
            .unwrap()
    });
    let router = data_router_with_auth(service, InputHygieneState::new([9; 32]));
    let login_body = serde_json::to_vec(&serde_json::json!({
        "role_id": "public-role-a",
        "secret_id": secret,
    }))
    .unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::put("/v1/auth/approle/login")
                .header("content-type", "application/json")
                .header("x-vault-request", "request-a")
                .header("x-vault-token", "ambient-client-token")
                .body(Body::from(login_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelope["auth"]["lease_duration"], 600);
    assert_eq!(envelope["auth"]["renewable"], false);
    let token = envelope["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    envelope["auth"]["accessor"] = serde_json::json!("<accessor>");
    envelope["auth"]["client_token"] = serde_json::json!("<token>");
    assert_eq!(
        serde_json::to_string(&envelope).unwrap(),
        include_str!("fixtures/auth-login-v1.json").trim()
    );

    let response = router
        .clone()
        .oneshot(
            Request::get("/v1/auth/token/lookup-self")
                .header("x-vault-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let mut lookup: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(lookup["data"].get("id").is_none());
    assert_eq!(lookup["data"]["ttl"], 600);
    lookup["data"]["accessor"] = serde_json::json!("<accessor>");
    assert_eq!(
        serde_json::to_string(&lookup).unwrap(),
        include_str!("fixtures/auth-lookup-v1.json").trim()
    );

    let response = router
        .clone()
        .oneshot(
            Request::post("/v1/auth/token/renew-self")
                .header("x-vault-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    assert_eq!(
        body.as_ref(),
        br#"{"errors":["token renewal is not supported"]}"#
    );

    let duplicate = format!(
        r#"{{"role_id":"public-role-a","role_id":"other","secret_id":{}}}"#,
        serde_json::to_string(&secret).unwrap()
    );
    let response = router
        .clone()
        .oneshot(
            Request::post("/v1/auth/approle/login")
                .header("content-type", "application/json")
                .body(Body::from(duplicate))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    assert_eq!(body.as_ref(), br#"{"errors":["invalid request"]}"#);

    let request = |role: &str, secret_id: &str| {
        Request::post("/v1/auth/approle/login")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "role_id": role,
                    "secret_id": secret_id,
                }))
                .unwrap(),
            ))
            .unwrap()
    };
    let wrong = router
        .clone()
        .oneshot(request("public-role-b", &secret))
        .await
        .unwrap();
    let bad = router
        .clone()
        .oneshot(request("public-role-a", "not-a-secret"))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        to_bytes(wrong.into_body(), 64 * 1024).await.unwrap(),
        to_bytes(bad.into_body(), 64 * 1024).await.unwrap()
    );

    let response = router
        .oneshot(
            Request::post("/v1/sys/bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn audit_events_are_secret_free_and_operation_specific() {
    let (service, secret, _) = fixture(1, 600);
    let login = service.login("public-role-a", &secret, [60; 16]).unwrap();
    let token = login.credential.expose_once().to_owned();
    service.lookup_self(&token, [61; 16]).unwrap();
    service.with_catalog(|catalog| catalog.renew_unsupported([62; 16]));
    let events = service.with_catalog(|catalog| catalog.audit().to_vec());
    assert_eq!(
        events
            .iter()
            .map(|event| event.operation)
            .collect::<Vec<_>>(),
        [
            AuthOperation::AppRoleLogin,
            AuthOperation::LookupSelf,
            AuthOperation::RenewSelf,
        ]
    );
    let rendered = format!("{events:?}");
    assert!(!rendered.contains(&secret));
    assert!(!rendered.contains(&token));
}

#[test]
fn credential_kind_cross_use_is_normalized_and_audited() {
    let (service, secret_id, _) = fixture(3, 600);
    let login = service
        .login("public-role-a", &secret_id, [70; 16])
        .unwrap();
    let token = login.credential.expose_once().to_owned();

    assert!(matches!(
        service.authenticate_with_request(&secret_id, CredentialAudience::Data, [69; 16]),
        Err(AuthError::Unauthenticated)
    ));
    assert!(matches!(
        service.login("public-role-a", &token, [71; 16]),
        Err(AuthError::InvalidCredentials)
    ));
    let events = service.with_catalog(|catalog| catalog.audit().to_vec());
    assert!(events.iter().rev().take(2).all(|event| {
        event.outcome == AuthAuditOutcome::Denied
            && matches!(
                event.operation,
                AuthOperation::Authenticate | AuthOperation::AppRoleLogin
            )
    }));
    let rendered = format!("{events:?}");
    assert!(!rendered.contains(&secret_id));
    assert!(!rendered.contains(&token));
}
