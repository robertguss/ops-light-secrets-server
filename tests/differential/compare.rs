//! Normalization and differential comparison for the OpenBao reference suite.
//!
//! Volatile fields are stripped with a versioned schema. Over-normalization
//! sentinels must remain distinct after normalize. Allowlist entries are
//! structured and fail closed when stale/unknown/reasonless.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const VOLATILE_KEYS: &[&str] = &[
    "request_id",
    "lease_id",
    "lease_duration",
    "renewable",
    "created_time",
    "deletion_time",
    "updated_time",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedOutcome {
    pub status: u16,
    pub status_class: &'static str,
    pub envelope_keys: BTreeSet<String>,
    pub field_presence: BTreeMap<String, bool>,
    pub errors_count: Option<usize>,
    pub body: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareMode {
    ExactStatus,
    StatusClass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffKind {
    Status,
    StatusClass,
    EnvelopeKeys,
    FieldPresence { path: String },
    ErrorsCount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDiff {
    pub kind: DiffKind,
    pub left: String,
    pub right: String,
}

#[derive(Debug, Deserialize)]
pub struct AllowlistFile {
    pub schema: u16,
    pub reference_version: String,
    pub implementation_version: String,
    pub entries: Vec<AllowlistEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AllowlistEntry {
    pub case: String,
    pub reference_version: String,
    pub implementation_version: String,
    pub divergence: AllowlistDivergence,
    pub reason: String,
    pub owner: String,
    pub review_by: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AllowlistDivergence {
    pub kind: String,
    pub field: String,
    pub reference: String,
    pub implementation: String,
}

#[derive(Debug, Deserialize)]
pub struct OracleFile {
    pub schema: u16,
    pub reference_version: String,
    pub outcomes: BTreeMap<String, OracleOutcome>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OracleOutcome {
    pub status: u16,
    pub status_class: String,
    pub envelope_keys: Vec<String>,
    pub field_presence: BTreeMap<String, bool>,
    pub errors_count: Option<usize>,
    pub compare_mode: Option<String>,
    #[serde(default)]
    pub allowlisted: bool,
}

pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    }
}

pub fn normalize_body(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                if VOLATILE_KEYS.contains(&key.as_str()) {
                    continue;
                }
                out.insert(key, normalize_body(child));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(normalize_body).collect()),
        other => other,
    }
}

pub fn field_present(body: &Value, path: &str) -> bool {
    let mut cursor = body;
    for segment in path.split('.') {
        match cursor {
            Value::Object(map) => match map.get(segment) {
                Some(next) => cursor = next,
                None => return false,
            },
            _ => return false,
        }
    }
    !cursor.is_null()
}

pub fn normalize_outcome(status: u16, body: Value) -> NormalizedOutcome {
    let body = normalize_body(body);
    let envelope_keys = match &body {
        Value::Object(map) => map.keys().cloned().collect(),
        _ => BTreeSet::new(),
    };
    let errors_count = body
        .get("errors")
        .and_then(Value::as_array)
        .map(|items| items.len());
    let mut field_presence = BTreeMap::new();
    for path in [
        "data",
        "data.data",
        "data.data.value",
        "data.metadata",
        "data.metadata.version",
        "data.keys",
        "data.versions",
        "errors",
    ] {
        field_presence.insert(path.to_owned(), field_present(&body, path));
    }
    NormalizedOutcome {
        status,
        status_class: status_class(status),
        envelope_keys,
        field_presence,
        errors_count,
        body,
    }
}

pub fn parse_compare_mode(raw: Option<&str>) -> CompareMode {
    match raw {
        Some("status_class") => CompareMode::StatusClass,
        _ => CompareMode::ExactStatus,
    }
}

pub fn compare_to_oracle(
    actual: &NormalizedOutcome,
    oracle: &OracleOutcome,
) -> Result<(), Vec<FieldDiff>> {
    let mode = parse_compare_mode(oracle.compare_mode.as_deref());
    let mut diffs = Vec::new();

    match mode {
        CompareMode::ExactStatus if actual.status != oracle.status => {
            diffs.push(FieldDiff {
                kind: DiffKind::Status,
                left: actual.status.to_string(),
                right: oracle.status.to_string(),
            });
        }
        CompareMode::StatusClass if actual.status_class != oracle.status_class => {
            diffs.push(FieldDiff {
                kind: DiffKind::StatusClass,
                left: actual.status_class.to_owned(),
                right: oracle.status_class.clone(),
            });
        }
        _ => {}
    }

    let expected_keys: BTreeSet<String> = oracle.envelope_keys.iter().cloned().collect();
    if actual.envelope_keys != expected_keys {
        diffs.push(FieldDiff {
            kind: DiffKind::EnvelopeKeys,
            left: format!("{:?}", actual.envelope_keys),
            right: format!("{expected_keys:?}"),
        });
    }

    for (path, expected) in &oracle.field_presence {
        let present = field_present(&actual.body, path);
        if present != *expected {
            diffs.push(FieldDiff {
                kind: DiffKind::FieldPresence { path: path.clone() },
                left: present.to_string(),
                right: expected.to_string(),
            });
        }
    }

    if actual.errors_count != oracle.errors_count {
        diffs.push(FieldDiff {
            kind: DiffKind::ErrorsCount,
            left: format!("{:?}", actual.errors_count),
            right: format!("{:?}", oracle.errors_count),
        });
    }

    if diffs.is_empty() { Ok(()) } else { Err(diffs) }
}

/// Inject a deliberate status mismatch so the suite proves the comparator fires.
pub fn seed_status_divergence(outcome: &mut NormalizedOutcome, status: u16) {
    outcome.status = status;
    outcome.status_class = status_class(status);
}

pub fn validate_allowlist(
    allowlist: &AllowlistFile,
    known_cases: &BTreeSet<String>,
    reference_version: &str,
    implementation_version: &str,
    today: &str,
) -> Result<(), String> {
    if allowlist.schema != 1 {
        return Err(format!("unsupported allowlist schema {}", allowlist.schema));
    }
    if allowlist.reference_version != reference_version {
        return Err(format!(
            "allowlist reference_version {} != pin {reference_version}",
            allowlist.reference_version
        ));
    }
    if allowlist.implementation_version != implementation_version {
        return Err(format!(
            "allowlist implementation_version {} != {implementation_version}",
            allowlist.implementation_version
        ));
    }

    let mut seen = BTreeSet::new();
    for entry in &allowlist.entries {
        if !seen.insert(entry.case.clone()) {
            return Err(format!("duplicate allowlist case {}", entry.case));
        }
        if !known_cases.contains(&entry.case) {
            return Err(format!("unknown allowlist case {}", entry.case));
        }
        if entry.reason.trim().is_empty() {
            return Err(format!("allowlist case {} missing reason", entry.case));
        }
        if entry.owner.trim().is_empty() {
            return Err(format!("allowlist case {} missing owner", entry.case));
        }
        if entry.reference_version != reference_version {
            return Err(format!(
                "allowlist case {} stale reference_version {}",
                entry.case, entry.reference_version
            ));
        }
        if entry.implementation_version != implementation_version {
            return Err(format!(
                "allowlist case {} stale implementation_version {}",
                entry.case, entry.implementation_version
            ));
        }
        if entry.review_by.as_str() < today {
            return Err(format!(
                "allowlist case {} expired review_by {}",
                entry.case, entry.review_by
            ));
        }
        if entry.divergence.kind.trim().is_empty()
            || entry.divergence.field.trim().is_empty()
            || entry.divergence.reference.trim().is_empty()
            || entry.divergence.implementation.trim().is_empty()
        {
            return Err(format!(
                "allowlist case {} incomplete divergence record",
                entry.case
            ));
        }
    }
    Ok(())
}

pub fn allowlisted_cases(allowlist: &AllowlistFile) -> BTreeSet<String> {
    allowlist
        .entries
        .iter()
        .map(|entry| entry.case.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_strips_volatile_but_keeps_version_and_errors() {
        let body = json!({
            "request_id": "aaaa",
            "data": {
                "data": {"value": "x"},
                "metadata": {
                    "version": 2,
                    "created_time": "2020-01-01T00:00:00Z",
                    "deletion_time": ""
                }
            }
        });
        let normalized = normalize_body(body);
        assert!(normalized.get("request_id").is_none());
        assert_eq!(normalized["data"]["metadata"]["version"], 2);
        assert!(normalized["data"]["metadata"].get("created_time").is_none());
        assert_eq!(normalized["data"]["data"]["value"], "x");
    }

    #[test]
    fn over_normalization_sentinels_remain_distinct() {
        let left = normalize_body(json!({
            "request_id": "same",
            "errors": ["secret not found"],
            "data": {"metadata": {"version": 1, "created_time": "t1"}}
        }));
        let right = normalize_body(json!({
            "request_id": "same",
            "errors": ["permission denied"],
            "data": {"metadata": {"version": 2, "created_time": "t2"}}
        }));
        // Volatile fields stripped, but version + error text must remain distinct.
        assert!(left.get("request_id").is_none());
        assert!(right.get("request_id").is_none());
        assert_ne!(left, right);
        assert_ne!(left["errors"][0], right["errors"][0]);
        assert_ne!(
            left["data"]["metadata"]["version"],
            right["data"]["metadata"]["version"]
        );
        assert!(left["data"]["metadata"].get("created_time").is_none());
    }

    #[test]
    fn comparator_detects_status_field_and_envelope_mismatches() {
        let actual = normalize_outcome(
            200,
            json!({"data": {"data": {"value": 1}, "metadata": {"version": 1}}}),
        );
        let mut oracle = OracleOutcome {
            status: 404,
            status_class: "4xx".into(),
            envelope_keys: vec!["errors".into()],
            field_presence: BTreeMap::from([
                ("errors".into(), true),
                ("data.data.value".into(), false),
            ]),
            errors_count: Some(1),
            compare_mode: Some("exact_status".into()),
            allowlisted: false,
        };
        let diffs = compare_to_oracle(&actual, &oracle).unwrap_err();
        assert!(
            diffs
                .iter()
                .any(|diff| matches!(diff.kind, DiffKind::Status))
        );
        assert!(
            diffs
                .iter()
                .any(|diff| matches!(diff.kind, DiffKind::EnvelopeKeys))
        );
        assert!(diffs.iter().any(|diff| matches!(
            &diff.kind,
            DiffKind::FieldPresence { path } if path == "errors"
        )));

        oracle.status = 200;
        oracle.status_class = "2xx".into();
        oracle.envelope_keys = vec!["data".into()];
        oracle.field_presence =
            BTreeMap::from([("data.data.value".into(), true), ("errors".into(), false)]);
        oracle.errors_count = None;
        assert!(compare_to_oracle(&actual, &oracle).is_ok());
    }

    #[test]
    fn seeded_status_divergence_is_detected() {
        let mut actual = normalize_outcome(200, json!({"data": {"keys": ["a"]}}));
        let oracle = OracleOutcome {
            status: 200,
            status_class: "2xx".into(),
            envelope_keys: vec!["data".into()],
            field_presence: BTreeMap::from([("data.keys".into(), true)]),
            errors_count: None,
            compare_mode: Some("exact_status".into()),
            allowlisted: false,
        };
        seed_status_divergence(&mut actual, 500);
        let diffs = compare_to_oracle(&actual, &oracle).unwrap_err();
        assert!(
            diffs
                .iter()
                .any(|diff| matches!(diff.kind, DiffKind::Status))
        );
    }

    #[test]
    fn allowlist_rejects_unknown_stale_and_reasonless_entries() {
        let known = BTreeSet::from(["namespace-header".into()]);
        let mut file = AllowlistFile {
            schema: 1,
            reference_version: "openbao-2.6.0".into(),
            implementation_version: "ops-light-secrets-server-0.1.0".into(),
            entries: vec![AllowlistEntry {
                case: "not-a-case".into(),
                reference_version: "openbao-2.6.0".into(),
                implementation_version: "ops-light-secrets-server-0.1.0".into(),
                divergence: AllowlistDivergence {
                    kind: "status".into(),
                    field: "status".into(),
                    reference: "200".into(),
                    implementation: "400".into(),
                },
                reason: "because".into(),
                owner: "unit-u11".into(),
                review_by: "2099-01-01".into(),
            }],
        };
        assert!(
            validate_allowlist(
                &file,
                &known,
                "openbao-2.6.0",
                "ops-light-secrets-server-0.1.0",
                "2026-07-17",
            )
            .unwrap_err()
            .contains("unknown")
        );

        file.entries[0].case = "namespace-header".into();
        file.entries[0].reason.clear();
        assert!(
            validate_allowlist(
                &file,
                &known,
                "openbao-2.6.0",
                "ops-light-secrets-server-0.1.0",
                "2026-07-17",
            )
            .unwrap_err()
            .contains("reason")
        );

        file.entries[0].reason = "R3".into();
        file.entries[0].reference_version = "openbao-9.9.9".into();
        assert!(
            validate_allowlist(
                &file,
                &known,
                "openbao-2.6.0",
                "ops-light-secrets-server-0.1.0",
                "2026-07-17",
            )
            .unwrap_err()
            .contains("stale")
        );
    }
}
