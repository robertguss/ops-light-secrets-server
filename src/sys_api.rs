//! Bounded Vault-compatible system probes and authenticated mount preflight.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, middleware, routing};
use serde::Serialize;

use crate::auth::{AuthService, token_auth_guard};
use crate::compat_error::{ErrorCase, SafeRoute};
use crate::input_hygiene::{InputHygieneState, input_hygiene_guard};
use crate::rate_limit::{RateLimitService, authenticated_guard, pre_verifier_guard};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessSnapshot {
    pub keyring: bool,
    pub schema: bool,
    pub transaction_audit: bool,
    pub capacity: bool,
    pub draining: bool,
    /// Warning-only evidence quality; intentionally excluded from readiness.
    pub checkpoint_current: bool,
}

impl Default for ReadinessSnapshot {
    fn default() -> Self {
        Self {
            keyring: true,
            schema: true,
            transaction_audit: true,
            capacity: true,
            draining: false,
            checkpoint_current: true,
        }
    }
}

impl ReadinessSnapshot {
    pub fn ready(self) -> bool {
        self.keyring && self.schema && self.transaction_audit && self.capacity && !self.draining
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReadinessState(Arc<Mutex<ReadinessSnapshot>>);

impl ReadinessState {
    pub fn snapshot(&self) -> ReadinessSnapshot {
        *self.0.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub fn replace(&self, value: ReadinessSnapshot) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = value;
    }

    pub fn set_draining(&self) {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .draining = true;
    }
}

#[derive(Serialize)]
struct ProbeBody {
    initialized: bool,
    sealed: bool,
    standby: bool,
    version: &'static str,
}

#[derive(Serialize)]
struct LeaderBody {
    ha_enabled: bool,
    is_self: bool,
    leader_address: &'static str,
    leader_cluster_address: &'static str,
    performance_standby: bool,
}

pub fn public_router(readiness: ReadinessState, limits: RateLimitService) -> Router {
    crate::http_security::apply(
        Router::new()
            .route("/v1/sys/health", routing::get(health))
            .route("/v1/sys/seal-status", routing::get(seal_status))
            .route("/v1/sys/leader", routing::get(leader))
            .layer(middleware::from_fn_with_state(limits, pre_verifier_guard))
            .with_state(readiness),
    )
    .layer(middleware::from_fn(namespace_guard))
}

pub fn protected_router(
    auth: AuthService,
    hygiene: InputHygieneState,
    limits: RateLimitService,
) -> Router {
    crate::http_security::apply(
        Router::new()
            .route(
                "/v1/sys/internal/ui/mounts/{*path}",
                routing::get(mount_preflight),
            )
            .route_layer(middleware::from_fn_with_state(limits, authenticated_guard))
            .route_layer(middleware::from_fn_with_state(auth, token_auth_guard)),
    )
    .layer(middleware::from_fn_with_state(hygiene, input_hygiene_guard))
    .layer(middleware::from_fn(namespace_guard))
}

async fn health(State(readiness): State<ReadinessState>) -> Response {
    let status = if readiness.snapshot().ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(probe_body())).into_response()
}

async fn seal_status() -> Json<ProbeBody> {
    Json(probe_body())
}

async fn leader() -> Json<LeaderBody> {
    Json(LeaderBody {
        ha_enabled: false,
        is_self: true,
        leader_address: "",
        leader_cluster_address: "",
        performance_standby: false,
    })
}

async fn mount_preflight(Path(_path): Path<String>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"data": {
        "path": "secret/",
        "type": "kv",
        "options": {"version": "2"}
    }}))
}

fn probe_body() -> ProbeBody {
    ProbeBody {
        initialized: true,
        sealed: false,
        standby: false,
        version: env!("CARGO_PKG_VERSION"),
    }
}

async fn namespace_guard(request: Request<axum::body::Body>, next: Next) -> Response {
    if request
        .headers()
        .get("x-vault-namespace")
        .is_some_and(|value| !value.as_bytes().is_empty())
    {
        return crate::compat_error::response(
            ErrorCase::Namespace,
            Some(request.method()),
            Some(SafeRoute::Namespaced),
        );
    }
    next.run(request).await
}
