//! Shared secret-safe observability and request-deadline layers.
//!
//! Callers install request-target and input bounds outside this stack. The
//! resulting order is: target guard, bounds, sensitive marking, request id,
//! tracing, deadline, route-scoped limits/authentication, handler.

use std::time::Duration;

use axum::Router;
use axum::http::{HeaderName, StatusCode, header};
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const SECURITY_LAYER_ORDER: [&str; 8] = [
    "raw-target",
    "input-bounds",
    "sensitive-headers",
    "request-id",
    "trace",
    "request-deadline",
    "route-auth-and-limits",
    "handler",
];

pub fn apply<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    apply_with_timeout(router, REQUEST_TIMEOUT)
}

#[doc(hidden)]
pub fn apply_with_timeout<S>(router: Router<S>, timeout: Duration) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-vault-request"),
            MakeRequestUuid,
        ))
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            HeaderName::from_static("x-vault-token"),
        ]))
}
