//! Evidence-frozen Vault error envelopes and safe unsupported-route names.

use axum::Json;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::raw_target::EndpointKind;

pub const COMPAT_ERROR_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafeRoute {
    KvData,
    KvMetadata,
    KvList,
    KvDelete,
    KvUndelete,
    KvDestroy,
    KvUnknown,
    Namespaced,
    TokenRenewSelf,
}

impl SafeRoute {
    pub const ALL_UNSUPPORTED: [Self; 9] = [
        Self::KvData,
        Self::KvMetadata,
        Self::KvList,
        Self::KvDelete,
        Self::KvUndelete,
        Self::KvDestroy,
        Self::KvUnknown,
        Self::Namespaced,
        Self::TokenRenewSelf,
    ];

    pub fn template(self) -> &'static str {
        match self {
            Self::KvData => "/v1/:mount/data/:path",
            Self::KvMetadata => "/v1/:mount/metadata/:path",
            Self::KvList => "/v1/:mount/metadata/:path?list=true",
            Self::KvDelete => "/v1/:mount/delete/:path",
            Self::KvUndelete => "/v1/:mount/undelete/:path",
            Self::KvDestroy => "/v1/:mount/destroy/:path",
            Self::KvUnknown => "/v1/:mount/:operation/:path",
            Self::Namespaced => "namespaced /v1 request",
            Self::TokenRenewSelf => "/v1/auth/token/renew-self",
        }
    }
}

impl From<EndpointKind> for SafeRoute {
    fn from(value: EndpointKind) -> Self {
        match value {
            EndpointKind::Data => Self::KvData,
            EndpointKind::Metadata => Self::KvMetadata,
            EndpointKind::List => Self::KvList,
            EndpointKind::Delete => Self::KvDelete,
            EndpointKind::Undelete => Self::KvUndelete,
            EndpointKind::Destroy => Self::KvDestroy,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCase {
    UnsupportedOperation,
    MetadataDelete,
    UnsupportedMount,
    Namespace,
    TokenRenewal,
    SecretNotFound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ErrorContract {
    pub schema_version: u16,
    pub case: ErrorCase,
    pub status: u16,
    pub message: String,
    pub route: Option<SafeRoute>,
}

pub fn contract(
    case: ErrorCase,
    method: Option<&Method>,
    route: Option<SafeRoute>,
) -> ErrorContract {
    let status = match case {
        ErrorCase::UnsupportedOperation => StatusCode::METHOD_NOT_ALLOWED,
        ErrorCase::MetadataDelete | ErrorCase::TokenRenewal => StatusCode::NOT_IMPLEMENTED,
        ErrorCase::UnsupportedMount | ErrorCase::SecretNotFound => StatusCode::NOT_FOUND,
        ErrorCase::Namespace => StatusCode::BAD_REQUEST,
    };
    let message = match case {
        ErrorCase::SecretNotFound => "secret not found".to_owned(),
        _ => format!(
            "unsupported endpoint: {} {}",
            method.map(safe_method).unwrap_or("ANY"),
            route.unwrap_or(SafeRoute::KvUnknown).template()
        ),
    };
    ErrorContract {
        schema_version: COMPAT_ERROR_SCHEMA_VERSION,
        case,
        status: status.as_u16(),
        message,
        route,
    }
}

pub fn response(case: ErrorCase, method: Option<&Method>, route: Option<SafeRoute>) -> Response {
    let value = contract(case, method, route);
    (
        StatusCode::from_u16(value.status).expect("frozen status is valid"),
        Json(serde_json::json!({"errors": [value.message]})),
    )
        .into_response()
}

fn safe_method(value: &Method) -> &'static str {
    match value.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "LIST" => "LIST",
        _ => "OTHER",
    }
}
