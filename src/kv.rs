//! Transactional KV v2 data surface.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{AuthService, AuthenticatedToken, token_auth_guard};
use crate::identity::{AuthorizationRequest, GrantRecord, SecretAction, authorize};
use crate::input_hygiene::{InputHygieneState, StrictJsonBody, input_hygiene_guard};
use crate::raw_target::{EndpointKind, EndpointRequest, raw_target_guard};
use crate::store::VersionState;

pub const SECRET_MOUNT: &str = "secret";
pub const DEFAULT_MAX_VERSIONS: u16 = 10;
pub const MAX_VERSIONS: u16 = 1_024;
pub const MAX_VERSION_BATCH: usize = 64;
pub const MAX_SECRET_ENCODED_BYTES: usize = 512 * 1024;
pub const MAX_SECRET_FIELDS: usize = 256;
pub const MAX_SECRET_FIELD_NAME_CHARS: usize = 256;
pub const MAX_SECRET_NESTING_DEPTH: usize = 32;
pub const MAX_LIST_RESULTS: usize = 1_024;
pub const MAX_CUSTOM_METADATA_KEYS: usize = 64;
pub const MAX_CUSTOM_METADATA_KEY_CHARS: usize = 128;
pub const MAX_CUSTOM_METADATA_VALUE_CHARS: usize = 512;

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
pub enum MaxVersionsSource {
    PathOverride,
    MountDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveMaxVersions {
    pub effective: u16,
    pub source: MaxVersionsSource,
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
    MetadataRead,
    MetadataWrite,
    SoftDelete,
    Undelete,
    Destroy,
    RotationCutover,
    RotationRollback,
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
    deletion_unix_milliseconds: Option<u64>,
}

struct Entry {
    current_version: u64,
    versions: BTreeMap<u64, VersionValue>,
    cas_required: Option<bool>,
    max_versions: Option<u16>,
    protected_version: Option<u64>,
    retention_deferred: bool,
    custom_metadata: BTreeMap<String, String>,
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
            custom_metadata: BTreeMap::new(),
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
    fail_next_read_audit_commit: bool,
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
            fail_next_read_audit_commit: false,
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
        Ok(())
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

    pub fn effective_max_versions(&self, path: &str) -> EffectiveMaxVersions {
        match self.entries.get(path).and_then(|entry| entry.max_versions) {
            Some(effective) => EffectiveMaxVersions {
                effective,
                source: MaxVersionsSource::PathOverride,
            },
            None => EffectiveMaxVersions {
                effective: self.mount_max_versions,
                source: MaxVersionsSource::MountDefault,
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

    /// Fault-injection seam for proving that reads disclose nothing before audit commit.
    #[doc(hidden)]
    pub fn fail_next_read_audit_commit(&mut self) {
        self.fail_next_read_audit_commit = true;
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

    pub fn rotation_snapshot(
        &self,
        endpoint: &EndpointRequest,
    ) -> Result<RotationSnapshot, KvError> {
        validate_endpoint(endpoint, EndpointKind::Data)?;
        let catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        let path = logical_path(endpoint);
        let entry = catalog.entries.get(&path).ok_or(KvError::NotFound)?;
        let current = entry
            .versions
            .get(&entry.current_version)
            .ok_or(KvError::NotFound)?;
        if current.state != VersionState::Live || current.encoded.is_empty() {
            return Err(KvError::VersionUnavailable {
                version: entry.current_version,
                deletion_time: current.deletion_unix_milliseconds.unwrap_or(0),
                destroyed: current.state == VersionState::Destroyed,
            });
        }
        Ok(RotationSnapshot {
            current_version: entry.current_version,
            protection: entry.protected_version,
        })
    }

    pub fn set_rotation_snapshot_protection(
        &self,
        endpoint: &EndpointRequest,
        expected_current: u64,
        protected: bool,
    ) -> Result<(), KvError> {
        validate_endpoint(endpoint, EndpointKind::Data)?;
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        let path = logical_path(endpoint);
        let entry = catalog.entries.get_mut(&path).ok_or(KvError::NotFound)?;
        if protected {
            if entry.current_version != expected_current {
                return Err(KvError::CasConflict);
            }
            let value = entry
                .versions
                .get(&expected_current)
                .ok_or(KvError::NotFound)?;
            if value.state != VersionState::Live || value.encoded.is_empty() {
                return Err(KvError::VersionUnavailable {
                    version: expected_current,
                    deletion_time: value.deletion_unix_milliseconds.unwrap_or(0),
                    destroyed: value.state == VersionState::Destroyed,
                });
            }
            entry.protected_version = Some(expected_current);
        } else {
            if entry.protected_version != Some(expected_current) {
                return Err(KvError::CasConflict);
            }
            entry.protected_version = None;
            catalog.prune(&path)?;
        }
        Ok(())
    }

    pub fn rotation_cutover(
        &self,
        actor_identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        data: Map<String, Value>,
        expected_current: u64,
    ) -> Result<WriteResult, KvError> {
        validate_endpoint(endpoint, EndpointKind::Data)?;
        validate_secret_value(&data)?;
        let encoded = serde_json::to_vec(&Value::Object(data)).map_err(|_| KvError::Invalid)?;
        if encoded.len() > MAX_SECRET_ENCODED_BYTES {
            return Err(KvError::BoundExceeded("secret_encoded_bytes"));
        }
        self.rotation_write_encoded(
            actor_identity_id,
            endpoint,
            Zeroizing::new(encoded),
            expected_current,
            KvAuditOperation::RotationCutover,
        )
    }

    pub fn rotation_rollback_copy_forward(
        &self,
        actor_identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        expected_current: u64,
        protected_version: u64,
    ) -> Result<WriteResult, KvError> {
        validate_endpoint(endpoint, EndpointKind::Data)?;
        let encoded = {
            let catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
            let entry = catalog
                .entries
                .get(&logical_path(endpoint))
                .ok_or(KvError::NotFound)?;
            if entry.current_version != expected_current
                || entry.protected_version != Some(protected_version)
            {
                return Err(KvError::CasConflict);
            }
            let value = entry
                .versions
                .get(&protected_version)
                .ok_or(KvError::NotFound)?;
            if value.state == VersionState::Destroyed || value.encoded.is_empty() {
                return Err(KvError::VersionUnavailable {
                    version: protected_version,
                    deletion_time: value.deletion_unix_milliseconds.unwrap_or(0),
                    destroyed: value.state == VersionState::Destroyed,
                });
            }
            Zeroizing::new(value.encoded.to_vec())
        };
        self.rotation_write_encoded(
            actor_identity_id,
            endpoint,
            encoded,
            expected_current,
            KvAuditOperation::RotationRollback,
        )
    }

    fn rotation_write_encoded(
        &self,
        actor_identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        encoded: Zeroizing<Vec<u8>>,
        expected_current: u64,
        operation: KvAuditOperation,
    ) -> Result<WriteResult, KvError> {
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        let path = logical_path(endpoint);
        let created = catalog.effective_unix_milliseconds;
        let entry = catalog.entries.get_mut(&path).ok_or(KvError::NotFound)?;
        if entry.current_version != expected_current
            || entry.protected_version.is_none()
            || !matches!(
                operation,
                KvAuditOperation::RotationCutover | KvAuditOperation::RotationRollback
            )
        {
            return Err(KvError::CasConflict);
        }
        let version = entry
            .current_version
            .checked_add(1)
            .ok_or(KvError::Internal)?;
        entry.current_version = version;
        entry.versions.insert(
            version,
            VersionValue {
                encoded,
                created_unix_milliseconds: created,
                state: VersionState::Live,
                deletion_unix_milliseconds: None,
            },
        );
        catalog.audit.push(audit_event(
            actor_identity_id,
            &path,
            operation,
            KvAuditOutcome::Succeeded,
            Some(version),
            None,
        ));
        Ok(WriteResult { version, created })
    }

    pub fn write(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        data: Map<String, Value>,
        cas: Option<u64>,
    ) -> Result<WriteResult, KvError> {
        validate_endpoint(endpoint, EndpointKind::Data)?;
        validate_secret_value(&data)?;
        let encoded = serde_json::to_vec(&Value::Object(data)).map_err(|_| KvError::Invalid)?;
        if encoded.len() > MAX_SECRET_ENCODED_BYTES {
            return Err(KvError::BoundExceeded("secret_encoded_bytes"));
        }
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
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
                deletion_unix_milliseconds: None,
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
        let Some(value) = entry.versions.get(&version) else {
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
        if value.state != VersionState::Live {
            let unavailable = KvError::VersionUnavailable {
                version,
                deletion_time: value.deletion_unix_milliseconds.unwrap_or(0),
                destroyed: value.state == VersionState::Destroyed,
            };
            catalog.audit.push(audit_event(
                identity_id,
                &path,
                KvAuditOperation::Read,
                KvAuditOutcome::Failed,
                Some(version),
                Some("not-found"),
            ));
            return Err(unavailable);
        }
        if catalog.fail_next_read_audit_commit {
            catalog.fail_next_read_audit_commit = false;
            return Err(KvError::Internal);
        }
        let data = serde_json::from_slice(&value.encoded).map_err(|_| KvError::Internal)?;
        let created = value.created_unix_milliseconds;
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
            if keys.len() > MAX_LIST_RESULTS {
                catalog.audit.push(audit_event(
                    identity_id,
                    &prefix,
                    KvAuditOperation::List,
                    KvAuditOutcome::Failed,
                    None,
                    Some("list-result-limit"),
                ));
                return Err(KvError::BoundExceeded("list_results"));
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

    pub fn mutate_versions(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        versions: &[u64],
        action: SecretAction,
    ) -> Result<(), KvError> {
        let expected = match action {
            SecretAction::SoftDelete => EndpointKind::Delete,
            SecretAction::Undelete => EndpointKind::Undelete,
            SecretAction::Destroy => EndpointKind::Destroy,
            _ => return Err(KvError::Invalid),
        };
        validate_endpoint(endpoint, expected)?;
        validate_versions(versions)?;
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        authorize_operation(&mut catalog, identity_id, endpoint, action)?;
        let path = logical_path(endpoint);
        mutate_versions_locked(&mut catalog, identity_id, &path, versions, action)
    }

    pub fn soft_delete_latest(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
    ) -> Result<(), KvError> {
        validate_endpoint(endpoint, EndpointKind::Data)?;
        let mut delete = endpoint.clone();
        delete.kind = EndpointKind::Delete;
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        authorize_operation(&mut catalog, identity_id, &delete, SecretAction::SoftDelete)?;
        let path = logical_path(endpoint);
        let version = catalog
            .entries
            .get(&path)
            .map(|entry| entry.current_version)
            .ok_or(KvError::NotFound)?;
        mutate_versions_locked(
            &mut catalog,
            identity_id,
            &path,
            &[version],
            SecretAction::SoftDelete,
        )
    }

    pub fn metadata(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
    ) -> Result<Value, KvError> {
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        validate_endpoint(endpoint, EndpointKind::Metadata)?;
        authorize_operation(&mut catalog, identity_id, endpoint, SecretAction::Metadata)?;
        let path = logical_path(endpoint);
        let entry = catalog.entries.get(&path).ok_or(KvError::NotFound)?;
        let versions = entry
            .versions
            .iter()
            .map(|(version, value)| {
                (
                    version.to_string(),
                    json!({
                        "created_time": value.created_unix_milliseconds.to_string(),
                        "deletion_time": value.deletion_unix_milliseconds.map_or_else(String::new, |time| time.to_string()),
                        "destroyed": value.state == VersionState::Destroyed,
                    }),
                )
            })
            .collect::<Map<String, Value>>();
        let oldest = entry.versions.keys().next().copied().unwrap_or(0);
        let custom = entry
            .custom_metadata
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect::<Map<String, Value>>();
        let result = json!({
            "cas_required": entry.cas_required.unwrap_or(catalog.mount_cas_required),
            "current_version": entry.current_version,
            "custom_metadata": custom,
            "delete_version_after": "0s",
            "max_versions": entry.max_versions.unwrap_or(0),
            "oldest_version": oldest,
            "versions": versions,
        });
        catalog.audit.push(audit_event(
            identity_id,
            &path,
            KvAuditOperation::MetadataRead,
            KvAuditOutcome::Succeeded,
            None,
            None,
        ));
        Ok(result)
    }

    pub fn update_metadata(
        &self,
        identity_id: [u8; 16],
        endpoint: &EndpointRequest,
        update: MetadataUpdate,
    ) -> Result<(), KvError> {
        if let Some(custom) = &update.custom_metadata {
            validate_custom_metadata(custom)?;
        }
        let mut catalog = self.catalog.lock().map_err(|_| KvError::Internal)?;
        validate_endpoint(endpoint, EndpointKind::Metadata)?;
        authorize_operation(&mut catalog, identity_id, endpoint, SecretAction::Write)?;
        if update
            .delete_version_after
            .as_deref()
            .is_some_and(|value| value != "0s")
        {
            return Err(KvError::UnsupportedField);
        }
        if update
            .max_versions
            .is_some_and(|value| value > MAX_VERSIONS)
        {
            return Err(KvError::Invalid);
        }
        let path = logical_path(endpoint);
        let entry = catalog
            .entries
            .entry(path.clone())
            .or_insert_with(|| Entry::new(None));
        if let Some(value) = update.cas_required {
            entry.cas_required = Some(value);
        }
        if let Some(value) = update.max_versions {
            entry.max_versions = (value != 0).then_some(value);
        }
        if let Some(custom) = update.custom_metadata {
            entry.custom_metadata = custom;
        }
        catalog.audit.push(audit_event(
            identity_id,
            &path,
            KvAuditOperation::MetadataWrite,
            KvAuditOutcome::Succeeded,
            None,
            None,
        ));
        Ok(())
    }
}

fn mutate_versions_locked(
    catalog: &mut KvCatalog,
    identity_id: [u8; 16],
    path: &str,
    versions: &[u64],
    action: SecretAction,
) -> Result<(), KvError> {
    let now = catalog.effective_unix_milliseconds;
    let entry = catalog.entries.get_mut(path).ok_or(KvError::NotFound)?;
    if versions
        .iter()
        .any(|version| !entry.versions.contains_key(version))
    {
        return Err(KvError::NotFound);
    }
    if action == SecretAction::SoftDelete
        && versions
            .iter()
            .any(|version| entry.versions[version].state == VersionState::Destroyed)
    {
        return Err(KvError::Invalid);
    }
    for version in versions {
        let value = entry.versions.get_mut(version).ok_or(KvError::Internal)?;
        match action {
            SecretAction::SoftDelete => {
                value.state = VersionState::SoftDeleted;
                value.deletion_unix_milliseconds = Some(now);
            }
            SecretAction::Undelete if value.state == VersionState::SoftDeleted => {
                value.state = VersionState::Live;
                value.deletion_unix_milliseconds = None;
            }
            SecretAction::Undelete => {}
            SecretAction::Destroy => {
                value.encoded.zeroize();
                value.state = VersionState::Destroyed;
                value.deletion_unix_milliseconds = None;
            }
            _ => return Err(KvError::Invalid),
        }
    }
    let operation = match action {
        SecretAction::SoftDelete => KvAuditOperation::SoftDelete,
        SecretAction::Undelete => KvAuditOperation::Undelete,
        SecretAction::Destroy => KvAuditOperation::Destroy,
        _ => return Err(KvError::Invalid),
    };
    for version in versions {
        catalog.audit.push(audit_event(
            identity_id,
            path,
            operation,
            KvAuditOutcome::Succeeded,
            Some(*version),
            None,
        ));
    }
    Ok(())
}

pub struct MetadataUpdate {
    pub cas_required: Option<bool>,
    pub max_versions: Option<u16>,
    pub delete_version_after: Option<String>,
    pub custom_metadata: Option<BTreeMap<String, String>>,
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
pub struct RotationSnapshot {
    pub current_version: u64,
    pub protection: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KvError {
    Invalid,
    UnsupportedMount,
    PermissionDenied,
    CasConflict,
    NotFound,
    VersionUnavailable {
        version: u64,
        deletion_time: u64,
        destroyed: bool,
    },
    UnsupportedField,
    BoundExceeded(&'static str),
    Internal,
}

fn validate_secret_value(data: &Map<String, Value>) -> Result<(), KvError> {
    fn walk(value: &Value, depth: usize, fields: &mut usize) -> Result<(), KvError> {
        if depth > MAX_SECRET_NESTING_DEPTH {
            return Err(KvError::BoundExceeded("secret_nesting_depth"));
        }
        match value {
            Value::Object(values) => {
                *fields = fields
                    .checked_add(values.len())
                    .ok_or(KvError::BoundExceeded("secret_field_count"))?;
                if *fields > MAX_SECRET_FIELDS {
                    return Err(KvError::BoundExceeded("secret_field_count"));
                }
                for (key, value) in values {
                    if key.chars().count() > MAX_SECRET_FIELD_NAME_CHARS {
                        return Err(KvError::BoundExceeded("secret_field_name_chars"));
                    }
                    walk(value, depth + 1, fields)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, depth + 1, fields)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut fields = data.len();
    if fields > MAX_SECRET_FIELDS {
        return Err(KvError::BoundExceeded("secret_field_count"));
    }
    for (key, value) in data {
        if key.chars().count() > MAX_SECRET_FIELD_NAME_CHARS {
            return Err(KvError::BoundExceeded("secret_field_name_chars"));
        }
        walk(value, 2, &mut fields)?;
    }
    Ok(())
}

fn validate_custom_metadata(values: &BTreeMap<String, String>) -> Result<(), KvError> {
    if values.len() > MAX_CUSTOM_METADATA_KEYS {
        return Err(KvError::BoundExceeded("custom_metadata_keys"));
    }
    for (key, value) in values {
        if key.is_empty() || key.chars().count() > MAX_CUSTOM_METADATA_KEY_CHARS {
            return Err(KvError::BoundExceeded("custom_metadata_key_chars"));
        }
        if value.chars().count() > MAX_CUSTOM_METADATA_VALUE_CHARS {
            return Err(KvError::BoundExceeded("custom_metadata_value_chars"));
        }
    }
    Ok(())
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
        SecretAction::Metadata => KvAuditOperation::MetadataRead,
        SecretAction::List => KvAuditOperation::List,
        SecretAction::Write => KvAuditOperation::Write,
        SecretAction::SoftDelete => KvAuditOperation::SoftDelete,
        SecretAction::Undelete => KvAuditOperation::Undelete,
        SecretAction::Destroy => KvAuditOperation::Destroy,
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
    let limits = crate::rate_limit::RateLimitService::new(
        crate::rate_limit::RateLimitConfig::default(),
        [0x4b; 32],
    )
    .expect("default rate limit configuration is valid");
    kv_router_with_limits(auth, service, hygiene, limits)
}

pub fn kv_router_with_limits(
    auth: AuthService,
    service: KvService,
    hygiene: InputHygieneState,
    limits: crate::rate_limit::RateLimitService,
) -> Router {
    crate::http_security::apply(
        Router::new()
            .route("/v1/{*path}", routing::any(dispatch))
            .layer(middleware::from_fn_with_state(
                limits,
                crate::rate_limit::authenticated_guard,
            ))
            .layer(middleware::from_fn_with_state(auth, token_auth_guard))
            .with_state(KvRouterState { service }),
    )
    .layer(middleware::from_fn_with_state(hygiene, input_hygiene_guard))
    .layer(middleware::from_fn(raw_target_guard))
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
        return crate::compat_error::response(
            crate::compat_error::ErrorCase::Namespace,
            Some(&method),
            Some(crate::compat_error::SafeRoute::Namespaced),
        );
    }
    let response = match (endpoint.kind, method.as_str()) {
        (EndpointKind::Data, "GET") => match state.service.read(token.identity_id, &endpoint) {
            Ok(result) => (
                StatusCode::OK,
                Json(json!({"data": {
                    "data": result.data,
                    "metadata": version_metadata(result.created, result.version)
                }})),
            )
                .into_response(),
            Err(error) => error_response(error, &method, endpoint.kind),
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
                Err(error) => error_response(error, &method, endpoint.kind),
            }
        }
        (EndpointKind::Data, "DELETE") => {
            match state
                .service
                .soft_delete_latest(token.identity_id, &endpoint)
            {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => error_response(error, &method, endpoint.kind),
            }
        }
        (EndpointKind::Delete | EndpointKind::Undelete | EndpointKind::Destroy, "POST") => {
            let Some(Extension(body)) = body else {
                return vault_error(StatusCode::BAD_REQUEST, "invalid request");
            };
            let Ok(versions) = parse_versions(body.0) else {
                return vault_error(StatusCode::BAD_REQUEST, "invalid request");
            };
            let action = match endpoint.kind {
                EndpointKind::Delete => SecretAction::SoftDelete,
                EndpointKind::Undelete => SecretAction::Undelete,
                EndpointKind::Destroy => SecretAction::Destroy,
                _ => unreachable!(),
            };
            match state
                .service
                .mutate_versions(token.identity_id, &endpoint, &versions, action)
            {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => error_response(error, &method, endpoint.kind),
            }
        }
        (EndpointKind::Metadata, "GET") => {
            match state.service.metadata(token.identity_id, &endpoint) {
                Ok(metadata) => (StatusCode::OK, Json(json!({"data": metadata}))).into_response(),
                Err(error) => error_response(error, &method, endpoint.kind),
            }
        }
        (EndpointKind::Metadata, "POST" | "PUT") => {
            let Some(Extension(body)) = body else {
                return vault_error(StatusCode::BAD_REQUEST, "invalid request");
            };
            let Ok(update) = parse_metadata(body.0) else {
                return vault_error(StatusCode::BAD_REQUEST, "invalid request");
            };
            match state
                .service
                .update_metadata(token.identity_id, &endpoint, update)
            {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => error_response(error, &method, endpoint.kind),
            }
        }
        (EndpointKind::Metadata, "DELETE") => crate::compat_error::response(
            crate::compat_error::ErrorCase::MetadataDelete,
            Some(&method),
            Some(crate::compat_error::SafeRoute::KvMetadata),
        ),
        (EndpointKind::List, "LIST" | "GET") => {
            match state.service.list(token.identity_id, &endpoint) {
                Ok(keys) => (StatusCode::OK, Json(json!({"data": {"keys": keys}}))).into_response(),
                Err(error) => error_response(error, &method, endpoint.kind),
            }
        }
        _ => crate::compat_error::response(
            crate::compat_error::ErrorCase::UnsupportedOperation,
            Some(&method),
            Some(endpoint.kind.into()),
        ),
    };
    secret_response_hygiene(response)
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
        Some(Value::Object(options)) if options.is_empty() => None,
        Some(Value::Object(mut options)) if options.len() == 1 => match options.remove("cas") {
            Some(Value::Number(value)) => value.as_u64().ok_or(KvError::Invalid).map(Some)?,
            _ => return Err(KvError::Invalid),
        },
        _ => return Err(KvError::Invalid),
    };
    Ok((data, cas))
}

fn parse_versions(value: Value) -> Result<Vec<u64>, KvError> {
    let Value::Object(mut root) = value else {
        return Err(KvError::Invalid);
    };
    if root.len() != 1 {
        return Err(KvError::Invalid);
    }
    let Some(Value::Array(values)) = root.remove("versions") else {
        return Err(KvError::Invalid);
    };
    let versions = values
        .into_iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or(KvError::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_versions(&versions)?;
    Ok(versions)
}

fn validate_versions(versions: &[u64]) -> Result<(), KvError> {
    if versions.len() > MAX_VERSION_BATCH {
        return Err(KvError::BoundExceeded("version_batch"));
    }
    if versions.is_empty() {
        return Err(KvError::Invalid);
    }
    let unique = versions.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != versions.len() || unique.contains(&0) {
        return Err(KvError::Invalid);
    }
    Ok(())
}

fn parse_metadata(value: Value) -> Result<MetadataUpdate, KvError> {
    let Value::Object(mut root) = value else {
        return Err(KvError::Invalid);
    };
    if !root.keys().all(|key| {
        matches!(
            key.as_str(),
            "cas_required" | "max_versions" | "delete_version_after" | "custom_metadata"
        )
    }) {
        return Err(KvError::Invalid);
    }
    let cas_required = root
        .remove("cas_required")
        .map(|value| value.as_bool().ok_or(KvError::Invalid))
        .transpose()?;
    let max_versions = root
        .remove("max_versions")
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(KvError::Invalid)
        })
        .transpose()?;
    let delete_version_after = root
        .remove("delete_version_after")
        .map(|value| value.as_str().map(str::to_owned).ok_or(KvError::Invalid))
        .transpose()?;
    let custom_metadata = root
        .remove("custom_metadata")
        .map(|value| {
            let Value::Object(values) = value else {
                return Err(KvError::Invalid);
            };
            let result = values
                .into_iter()
                .map(|(key, value)| {
                    let value = value.as_str().ok_or(KvError::Invalid)?.to_owned();
                    Ok((key, value))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            validate_custom_metadata(&result)?;
            Ok(result)
        })
        .transpose()?;
    Ok(MetadataUpdate {
        cas_required,
        max_versions,
        delete_version_after,
        custom_metadata,
    })
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

fn error_response(error: KvError, method: &Method, kind: EndpointKind) -> Response {
    match error {
        KvError::Invalid => vault_error(StatusCode::BAD_REQUEST, "invalid request"),
        KvError::UnsupportedMount => crate::compat_error::response(
            crate::compat_error::ErrorCase::UnsupportedMount,
            Some(method),
            Some(kind.into()),
        ),
        KvError::PermissionDenied => vault_error(StatusCode::FORBIDDEN, "permission denied"),
        KvError::CasConflict => vault_error(
            StatusCode::BAD_REQUEST,
            "check-and-set parameter did not match the current version",
        ),
        KvError::NotFound => crate::compat_error::response(
            crate::compat_error::ErrorCase::SecretNotFound,
            None,
            None,
        ),
        KvError::VersionUnavailable {
            version,
            deletion_time,
            destroyed,
        } => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errors": ["secret not found"],
                "data": {"metadata": {
                    "version": version,
                    "deletion_time": if deletion_time == 0 { String::new() } else { deletion_time.to_string() },
                    "destroyed": destroyed,
                }}
            })),
        )
            .into_response(),
        KvError::UnsupportedField => vault_error(
            StatusCode::BAD_REQUEST,
            "delete_version_after is not supported",
        ),
        KvError::BoundExceeded(id) => bounded_error(id),
        KvError::Internal => vault_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn bounded_error(id: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errors": [format!("request exceeds {id} bound")]})),
    )
        .into_response()
}

fn secret_response_hygiene(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().remove(header::CONTENT_ENCODING);
    response
}

fn vault_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"errors": [message]}))).into_response()
}
