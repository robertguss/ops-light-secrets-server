//! Transactional KV v2 data surface.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::auth::{AuthService, AuthenticatedToken, token_auth_guard};
use crate::identity::{AuthorizationRequest, GrantRecord, SecretAction, authorize};
use crate::input_hygiene::{InputHygieneState, StrictJsonBody, input_hygiene_guard};
use crate::raw_target::{EndpointKind, EndpointRequest, raw_target_guard};
use crate::store::VersionState;

pub const SECRET_MOUNT: &str = "secret";
pub const DEFAULT_MAX_VERSIONS: u16 = 10;
pub const MAX_VERSIONS: u16 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasSource {
    PathOverride,
    MountDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveCasRequired {
    pub effective: bool,
    pub source: CasSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvAuditOutcome {
    Succeeded,
    Denied,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvAuditOperation {
    Read,
    Write,
    List,
}

/// Secret-safe operation evidence. Values and request bodies have no field here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KvAuditEvent {
    pub identity_id: [u8; 16],
    pub resource: String,
    pub operation: KvAuditOperation,
    pub outcome: KvAuditOutcome,
    pub version: Option<u64>,
    pub reason: Option<&'static str>,
}

struct VersionValue {
    encoded: Zeroizing<Vec<u8>>,
    created_unix_milliseconds: u64,
    state: VersionState,
}

struct Entry {
    current_version: u64,
    versions: BTreeMap<u64, VersionValue>,
    cas_required: Option<bool>,
    max_versions: Option<u16>,
    protected_version: Option<u64>,
    retention_deferred: bool,
}

impl Entry {
    fn new(cas_required: Option<bool>) -> Self {
        Self {
            current_version: 0,
            versions: BTreeMap::new(),
            cas_required,
            max_versions: None,
            protected_version: None,
            retention_deferred: false,
        }
    }
}

/// State owned by the single KV transaction boundary.
pub struct KvCatalog {
    mount_cas_required: bool,
    mount_max_versions: u16,
    effective_unix_milliseconds: u64,
    entries: BTreeMap<String, Entry>,
    grants: Vec<GrantRecord>,
    audit: Vec<KvAuditEvent>,
}

impl KvCatalog {
    pub fn new(mount_cas_required: bool, effective_unix_milliseconds: u64) -> Self {
        Self {
            mount_cas_required,
            mount_max_versions: DEFAULT_MAX_VERSIONS,
            effective_unix_milliseconds,
            entries: BTreeMap::new(),
            grants: Vec::new(),
            audit: Vec::new(),
        }
    }

    pub fn replace_grants(&mut self, grants: Vec<GrantRecord>) {
        self.grants = grants;
    }

    pub fn set_mount_cas_required(&mut self, value: bool) {
        self.mount_cas_required = value;
    }

    pub fn set_mount_max_versions(&mut self, value: u16) -> Result<(), KvError> {
        if !(1..=MAX_VERSIONS).contains(&value) {
            return Err(KvError::Invalid);
        }
        self.mount_max_versions = value;
        let paths = self.entries.keys().cloned().collect::<Vec<_>>();
        for path in paths {
            self.prune(&path)?;
        }
        Ok(())
    }

    pub fn set_effective_unix_milliseconds(&mut self, value: u64) {
        self.effective_unix_milliseconds = value;
    }

    pub fn set_path_cas_required(&mut self, path: &str, value: Option<bool>) {
        self.entries
            .entry(path.to_owned())
            .or_insert_with(|| Entry::new(value))
            .cas_required = value;
    }

    pub fn set_path_max_versions(&mut self, path: &str, value: Option<u16>) -> Result<(), KvError> {
        if value.is_some_and(|value| !(1..=MAX_VERSIONS).contains(&value)) {
            return Err(KvError::Invalid);
        }
        self.entries
            .entry(path.to_owned())
            .or_insert_with(|| Entry::new(None))
            .max_versions = value;
        self.prune(path)
    }

    pub fn set_rotation_protection(
        &mut self,
        path: &str,
        version: Option<u64>,
    ) -> Result<(), KvError> {
        let entry = self.entries.get_mut(path).ok_or(KvError::NotFound)?;
        if version.is_some_and(|version| !entry.versions.contains_key(&version)) {
            return Err(KvError::NotFound);
        }
        entry.protected_version = version;
        self.prune(path)
    }

    pub fn retention_deferred_by_rotation(&self, path: &str) -> bool {
        self.entries
            .get(path)
            .is_some_and(|entry| entry.retention_deferred)
    }

    pub fn effective_cas_required(&self, path: &str) -> EffectiveCasRequired {
        match self.entries.get(path).and_then(|entry| entry.cas_required) {
            Some(effective) => EffectiveCasRequired {
                effective,
                source: CasSource::PathOverride,
            },
            None => EffectiveCasRequired {
                effective: self.mount_cas_required,
                source: CasSource::MountDefault,
            },
        }
    }

    pub fn set_version_state(
        &mut self,
        path: &str,
        version: u64,
        state: VersionState,
    ) -> Result<(), KvError> {
        let value = self
            .entries
            .get_mut(path)
            .and_then(|entry| entry.versions.get_mut(&version))
            .ok_or(KvError::NotFound)?;
        value.state = state;
        Ok(())
    }

    pub fn current_version(&self, path: &str) -> Option<u64> {
        self.entries.get(path).map(|entry| entry.current_version)
    }

    pub fn audit(&self) -> &[KvAuditEvent] {
        &self.audit
    }

    fn prune(&mut self, path: &str) -> Result<(), KvError> {
        let mount_max = self.mount_max_versions;
        let entry = self.entries.get_mut(path).ok_or(KvError::NotFound)?;
        let max = usize::from(entry.max_versions.unwrap_or(mount_max));
        entry.retention_deferred = false;
        while entry.versions.len() > max {
            let candidate = entry.versions.keys().copied().find(|version| {
                Some(*version) != entry.protected_version && *version != entry.current_version
            });
            let Some(oldest) = candidate else {
                entry.retention_deferred = true;
                break;
            };
            entry.versions.remove(&oldest);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct KvService {
    catalog: Arc<Mutex<KvCatalog>>,
}

impl KvService {
    pub fn new(catalog: KvCatalog) -> Self {
        Self {
            catalog: Arc::new(Mutex::new(catalog)),
        }
    }

    pub fn with_catalog<T>(&self, f: impl FnOnce(&mut KvCatalog) -> T) -> T {
        f(&mut self.catalog.lock().expect("KV catalog lock poisoned"))
    }

    pub fn write(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        data: Map<String, Value>,
        cas: Option<u64>,
    ) -> Result<WriteResult, KvError> {
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        validate_endpoint(endpoint, EndpointKind::Data)?;
        authorize_operation(&mut catalog, identity_id, endpoint, SecretAction::Write)?;
        let path = logical_path(endpoint);
        let effective = catalog.effective_cas_required(&path);
        let exists = catalog.entries.contains_key(&path);
        let current = catalog
            .entries
            .get(&path)
            .map_or(0, |entry| entry.current_version);
        let conflict = match cas {
            None => effective.effective,
            Some(0) => exists,
            Some(expected) => expected != current,
        };
        if conflict {
            catalog.audit.push(audit_event(
                identity_id,
                &path,
                KvAuditOperation::Write,
                KvAuditOutcome::Failed,
                None,
                Some("cas-conflict"),
            ));
            return Err(KvError::CasConflict);
        }
        let encoded = serde_json::to_vec(&Value::Object(data)).map_err(|_| KvError::Invalid)?;
        let created = catalog.effective_unix_milliseconds;
        let entry = catalog
            .entries
            .entry(path.clone())
            .or_insert_with(|| Entry::new(None));
        let version = entry
            .current_version
            .checked_add(1)
            .ok_or(KvError::Internal)?;
        entry.current_version = version;
        entry.versions.insert(
            version,
            VersionValue {
                encoded: Zeroizing::new(encoded),
                created_unix_milliseconds: created,
                state: VersionState::Live,
            },
        );
        catalog.prune(&path)?;
        catalog.audit.push(audit_event(
            identity_id,
            &path,
            KvAuditOperation::Write,
            KvAuditOutcome::Succeeded,
            Some(version),
            None,
        ));
        Ok(WriteResult { version, created })
    }

    pub fn read(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
    ) -> Result<ReadResult, KvError> {
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        validate_endpoint(endpoint, EndpointKind::Data)?;
        authorize_operation(&mut catalog, identity_id, endpoint, SecretAction::Read)?;
        let path = logical_path(endpoint);
        let Some(entry) = catalog.entries.get(&path) else {
            catalog.audit.push(audit_event(
                identity_id,
                &path,
                KvAuditOperation::Read,
                KvAuditOutcome::Failed,
                None,
                Some("not-found"),
            ));
            return Err(KvError::NotFound);
        };
        let version = endpoint.version.unwrap_or(entry.current_version);
        let selected = entry.versions.get(&version).and_then(|value| {
            (value.state == VersionState::Live).then(|| {
                (
                    serde_json::from_slice(&value.encoded),
                    value.created_unix_milliseconds,
                )
            })
        });
        let Some((data, created)) = selected else {
            catalog.audit.push(audit_event(
                identity_id,
                &path,
                KvAuditOperation::Read,
                KvAuditOutcome::Failed,
                Some(version),
                Some("not-found"),
            ));
            return Err(KvError::NotFound);
        };
        let data = data.map_err(|_| KvError::Internal)?;
        catalog.audit.push(audit_event(
            identity_id,
            &path,
            KvAuditOperation::Read,
            KvAuditOutcome::Succeeded,
            Some(version),
            None,
        ));
        Ok(ReadResult {
            data,
            version,
            created,
        })
    }

    pub fn list(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
    ) -> Result<Vec<String>, KvError> {
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        validate_endpoint(endpoint, EndpointKind::List)?;
        authorize_operation(&mut catalog, identity_id, endpoint, SecretAction::List)?;
        let prefix = endpoint.resource.canonical_segments.join("/");
        let prefix_with_slash = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        let mut keys = BTreeSet::new();
        for path in catalog.entries.keys() {
            let Some(rest) = path.strip_prefix(&prefix_with_slash) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            match rest.split_once('/') {
                Some((directory, _)) => {
                    keys.insert(format!("{directory}/"));
                }
                None => {
                    keys.insert(rest.to_owned());
                }
            }
        }
        catalog.audit.push(audit_event(
            identity_id,
            &prefix,
            KvAuditOperation::List,
            KvAuditOutcome::Succeeded,
            None,
            None,
        ));
        Ok(keys.into_iter().collect())
    }
}

pub struct WriteResult {
    pub version: u64,
    pub created: u64,
}

pub struct ReadResult {
    pub data: Value,
    pub version: u64,
    pub created: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvError {
    Invalid,
    UnsupportedMount,
    PermissionDenied,
    CasConflict,
    NotFound,
    Internal,
}

fn validate_endpoint(endpoint: &EndpointRequest, expected: EndpointKind) -> Result<(), KvError> {
    if endpoint.resource.mount != SECRET_MOUNT {
        return Err(KvError::UnsupportedMount);
    }
    if endpoint.kind != expected {
        return Err(KvError::Invalid);
    }
    Ok(())
}

fn authorize_operation(
    catalog: &mut KvCatalog,
    identity_id: [u8; 16],
    endpoint: &EndpointRequest,
    action: SecretAction,
) -> Result<(), KvError> {
    let request = AuthorizationRequest::secret(endpoint, action).map_err(|_| KvError::Invalid)?;
    let decision = authorize(
        &request,
        catalog
            .grants
            .iter()
            .filter(|grant| grant.owner_identity_id == identity_id),
    );
    if decision.allow {
        return Ok(());
    }
    let operation = match action {
        SecretAction::Read => KvAuditOperation::Read,
        SecretAction::List => KvAuditOperation::List,
        SecretAction::Write => KvAuditOperation::Write,
        _ => return Err(KvError::Invalid),
    };
    catalog.audit.push(audit_event(
        identity_id,
        &logical_path(endpoint),
        operation,
        KvAuditOutcome::Denied,
        None,
        Some("permission-denied"),
    ));
    Err(KvError::PermissionDenied)
}

fn logical_path(endpoint: &EndpointRequest) -> String {
    endpoint.resource.canonical_segments.join("/")
}

fn audit_event(
    identity_id: [u8; 16],
    resource: &str,
    operation: KvAuditOperation,
    outcome: KvAuditOutcome,
    version: Option<u64>,
    reason: Option<&'static str>,
) -> KvAuditEvent {
    KvAuditEvent {
        identity_id,
        resource: format!("{SECRET_MOUNT}/{resource}"),
        operation,
        outcome,
        version,
        reason,
    }
}

#[derive(Clone)]
struct KvRouterState {
    service: KvService,
}

pub fn kv_router(auth: AuthService, service: KvService, hygiene: InputHygieneState) -> Router {
    Router::new()
        .route("/v1/{*path}", routing::any(dispatch))
        .layer(middleware::from_fn_with_state(auth, token_auth_guard))
        .layer(middleware::from_fn(raw_target_guard))
        .layer(middleware::from_fn_with_state(hygiene, input_hygiene_guard))
        .with_state(KvRouterState { service })
}

async fn dispatch(
    State(state): State<KvRouterState>,
    Extension(token): Extension<AuthenticatedToken>,
    Extension(endpoint): Extension<EndpointRequest>,
    headers: HeaderMap,
    method: Method,
    body: Option<Extension<StrictJsonBody>>,
) -> Response {
    if headers
        .get("x-vault-namespace")
        .is_some_and(|value| !value.as_bytes().is_empty())
    {
        return vault_error(StatusCode::BAD_REQUEST, "namespaces are not supported");
    }
    match (endpoint.kind, method.as_str()) {
        (EndpointKind::Data, "GET") => match state.service.read(token.identity_id, &endpoint) {
            Ok(result) => (
                StatusCode::OK,
                Json(json!({"data": {
                    "data": result.data,
                    "metadata": version_metadata(result.created, result.version)
                }})),
            )
                .into_response(),
            Err(error) => error_response(error),
        },
        (EndpointKind::Data, "POST" | "PUT") => {
            let Some(Extension(body)) = body else {
                return vault_error(StatusCode::BAD_REQUEST, "invalid request");
            };
            let Ok((data, cas)) = parse_write(body.0) else {
                return vault_error(StatusCode::BAD_REQUEST, "invalid request");
            };
            match state.service.write(token.identity_id, &endpoint, data, cas) {
                Ok(result) => (
                    StatusCode::OK,
                    Json(json!({"data": version_metadata(result.created, result.version)})),
                )
                    .into_response(),
                Err(error) => error_response(error),
            }
        }
        (EndpointKind::List, "LIST" | "GET") => {
            match state.service.list(token.identity_id, &endpoint) {
                Ok(keys) => (StatusCode::OK, Json(json!({"data": {"keys": keys}}))).into_response(),
                Err(error) => error_response(error),
            }
        }
        _ => vault_error(StatusCode::METHOD_NOT_ALLOWED, "unsupported operation"),
    }
}

fn parse_write(value: Value) -> Result<(Map<String, Value>, Option<u64>), KvError> {
    let Value::Object(mut root) = value else {
        return Err(KvError::Invalid);
    };
    if !root
        .keys()
        .all(|key| matches!(key.as_str(), "data" | "options"))
    {
        return Err(KvError::Invalid);
    }
    let Some(Value::Object(data)) = root.remove("data") else {
        return Err(KvError::Invalid);
    };
    let cas = match root.remove("options") {
        None => None,
        Some(Value::Object(mut options)) if options.len() == 1 => match options.remove("cas") {
            Some(Value::Number(value)) => value.as_u64().ok_or(KvError::Invalid).map(Some)?,
            _ => return Err(KvError::Invalid),
        },
        _ => return Err(KvError::Invalid),
    };
    Ok((data, cas))
}

fn version_metadata(created: u64, version: u64) -> Value {
    json!({
        "created_time": created.to_string(),
        "custom_metadata": Value::Null,
        "deletion_time": "",
        "destroyed": false,
        "version": version
    })
}

fn error_response(error: KvError) -> Response {
    match error {
        KvError::Invalid => vault_error(StatusCode::BAD_REQUEST, "invalid request"),
        KvError::UnsupportedMount => vault_error(StatusCode::NOT_FOUND, "unsupported mount"),
        KvError::PermissionDenied => vault_error(StatusCode::FORBIDDEN, "permission denied"),
        KvError::CasConflict => vault_error(
            StatusCode::BAD_REQUEST,
            "check-and-set parameter did not match the current version",
        ),
        KvError::NotFound => vault_error(StatusCode::NOT_FOUND, "secret not found"),
        KvError::Internal => vault_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn vault_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"errors": [message]}))).into_response()
}
