use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use ops_light_secrets_server::auth::{AppRoleRecord, AuthCatalog, AuthService};
use ops_light_secrets_server::credential::{
    CredentialAudience, CredentialIssueMetadata, CredentialKind, issue_credential,
};
use ops_light_secrets_server::identity::{
    Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
};
use ops_light_secrets_server::input_hygiene::InputHygieneState;
use ops_light_secrets_server::kv::{
    CasSource, KvAuditOperation, KvAuditOutcome, KvCatalog, KvError, KvService,
    MAX_CUSTOM_METADATA_KEY_CHARS, MAX_CUSTOM_METADATA_KEYS, MAX_CUSTOM_METADATA_VALUE_CHARS,
    MAX_LIST_RESULTS, MAX_SECRET_ENCODED_BYTES, MAX_SECRET_FIELD_NAME_CHARS, MAX_SECRET_FIELDS,
    MAX_SECRET_NESTING_DEPTH, MAX_VERSION_BATCH, MAX_VERSIONS, MaxVersionsSource, MetadataUpdate,
    kv_router,
};
use ops_light_secrets_server::raw_target::parse_raw_target;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use ops_light_secrets_server::store::{StoreId, VersionState};
use serde_json::{Map, Value, json};
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

fn endpoint(
    method: &Method,
    target: &str,
) -> ops_light_secrets_server::raw_target::EndpointRequest {
    parse_raw_target(method, target).unwrap()
}

fn grant(id: u8, capabilities: &[Capability]) -> GrantRecord {
    GrantRecord::new(
        [id; 16],
        IDENTITY,
        "secret".into(),
        GrantScope::Subtree,
        Vec::new(),
        capabilities.iter().copied().collect::<BTreeSet<_>>(),
    )
    .unwrap()
}

fn data(value: i64) -> Map<String, Value> {
    Map::from_iter([("value".into(), json!(value))])
}

fn service(capabilities: &[Capability], mount_cas_required: bool) -> KvService {
    let mut catalog = KvCatalog::new(mount_cas_required, 1_800_000_000_000);
    catalog.replace_grants(vec![grant(1, capabilities)]);
    KvService::new(catalog)
}

#[test]
fn cas_matrix_is_monotonic_and_failures_are_audited_without_success() {
    let service = service(
        &[Capability::SecretWrite, Capability::SecretReadCurrent],
        false,
    );
    let request = endpoint(&Method::POST, "/v1/secret/data/apps/key");
    assert_eq!(
        service
            .write(IDENTITY, &request, data(1), Some(0))
            .unwrap()
            .version,
        1
    );
    assert!(matches!(
        service.write(IDENTITY, &request, data(2), Some(0)),
        Err(KvError::CasConflict)
    ));
    assert!(matches!(
        service.write(IDENTITY, &request, data(2), Some(7)),
        Err(KvError::CasConflict)
    ));
    assert_eq!(
        service.with_catalog(|catalog| catalog.current_version("apps/key")),
        Some(1)
    );
    assert_eq!(
        service
            .write(IDENTITY, &request, data(2), Some(1))
            .unwrap()
            .version,
        2
    );
    service.with_catalog(|catalog| {
        assert_eq!(catalog.audit().len(), 4);
        assert_eq!(catalog.audit()[1].outcome, KvAuditOutcome::Failed);
        assert_eq!(catalog.audit()[1].reason, Some("cas-conflict"));
        assert_eq!(catalog.audit()[2].outcome, KvAuditOutcome::Failed);
        assert_eq!(catalog.audit()[3].outcome, KvAuditOutcome::Succeeded);
    });
}

#[test]
fn deletion_state_never_changes_cas_comparand_or_reopens_create_only() {
    for state in [VersionState::SoftDeleted, VersionState::Destroyed] {
        let service = service(&[Capability::SecretWrite], false);
        let request = endpoint(&Method::POST, "/v1/secret/data/apps/key");
        service.write(IDENTITY, &request, data(1), None).unwrap();
        service
            .with_catalog(|catalog| catalog.set_version_state("apps/key", 1, state))
            .unwrap();
        assert!(matches!(
            service.write(IDENTITY, &request, data(2), Some(0)),
            Err(KvError::CasConflict)
        ));
        assert_eq!(
            service
                .write(IDENTITY, &request, data(2), Some(1))
                .unwrap()
                .version,
            2
        );
    }
}

#[test]
fn concurrent_same_cas_cutover_succeeds_exactly_once() {
    let service = service(&[Capability::SecretWrite], false);
    let request = endpoint(&Method::POST, "/v1/secret/data/cutover");
    service.write(IDENTITY, &request, data(1), None).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let workers = [2, 3].map(|value| {
        let service = service.clone();
        let request = request.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            service.write(IDENTITY, &request, data(value), Some(1))
        })
    });
    barrier.wait();
    let results = workers.map(|worker| worker.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(KvError::CasConflict)))
            .count(),
        1
    );
    assert_eq!(
        service.with_catalog(|catalog| catalog.current_version("cutover")),
        Some(2)
    );
}

#[test]
fn ordinary_history_prunes_but_rotation_protection_survives_until_clear() {
    let service = service(
        &[Capability::SecretWrite, Capability::SecretReadHistory],
        false,
    );
    service.with_catalog(|catalog| catalog.set_mount_max_versions(1).unwrap());
    let write = endpoint(&Method::POST, "/v1/secret/data/rotation");
    service.write(IDENTITY, &write, data(1), None).unwrap();
    service
        .with_catalog(|catalog| catalog.set_rotation_protection("rotation", Some(1)))
        .unwrap();
    for value in 2..=4 {
        let expected = u64::try_from(value - 1).unwrap();
        service
            .write(IDENTITY, &write, data(value), Some(expected))
            .unwrap();
    }
    let first = endpoint(&Method::GET, "/v1/secret/data/rotation?version=1");
    let second = endpoint(&Method::GET, "/v1/secret/data/rotation?version=2");
    assert_eq!(
        service.read(IDENTITY, &first).unwrap().data,
        json!({"value": 1})
    );
    assert!(matches!(
        service.read(IDENTITY, &second),
        Err(KvError::NotFound)
    ));
    assert!(service.with_catalog(|catalog| catalog.retention_deferred_by_rotation("rotation")));
    service
        .with_catalog(|catalog| catalog.set_rotation_protection("rotation", None))
        .unwrap();
    assert!(matches!(
        service.read(IDENTITY, &first),
        Err(KvError::NotFound)
    ));
    service.with_catalog(|catalog| {
        assert!(!catalog.retention_deferred_by_rotation("rotation"));
        assert_eq!(catalog.set_mount_max_versions(0), Err(KvError::Invalid));
    });
}

#[test]
fn mount_default_is_dynamic_and_path_override_wins_in_both_directions() {
    let service = service(&[Capability::SecretWrite], false);
    let inherited = endpoint(&Method::POST, "/v1/secret/data/inherited");
    service.write(IDENTITY, &inherited, data(1), None).unwrap();
    service.with_catalog(|catalog| catalog.set_mount_cas_required(true));
    assert!(matches!(
        service.write(IDENTITY, &inherited, data(2), None),
        Err(KvError::CasConflict)
    ));
    service.with_catalog(|catalog| catalog.set_path_cas_required("inherited", Some(false)));
    assert_eq!(
        service
            .write(IDENTITY, &inherited, data(2), None)
            .unwrap()
            .version,
        2
    );
    service.with_catalog(|catalog| {
        let effective = catalog.effective_cas_required("inherited");
        assert!(!effective.effective);
        assert_eq!(effective.source, CasSource::PathOverride);
        catalog.set_path_cas_required("inherited", None);
        assert_eq!(
            catalog.effective_cas_required("inherited").source,
            CasSource::MountDefault
        );
        catalog.set_mount_cas_required(false);
        assert_eq!(
            catalog.effective_max_versions("inherited").source,
            MaxVersionsSource::MountDefault
        );
        assert_eq!(catalog.effective_max_versions("inherited").effective, 10);
    });
    assert_eq!(
        service
            .write(IDENTITY, &inherited, data(3), None)
            .unwrap()
            .version,
        3
    );
}

#[test]
fn explicit_version_even_current_requires_history_capability() {
    let service = service(
        &[Capability::SecretWrite, Capability::SecretReadCurrent],
        false,
    );
    let write = endpoint(&Method::POST, "/v1/secret/data/apps/key");
    service.write(IDENTITY, &write, data(1), None).unwrap();
    let current = endpoint(&Method::GET, "/v1/secret/data/apps/key");
    assert_eq!(
        service.read(IDENTITY, &current).unwrap().data,
        json!({"value": 1})
    );
    let explicit = endpoint(&Method::GET, "/v1/secret/data/apps/key?version=1");
    assert!(matches!(
        service.read(IDENTITY, &explicit),
        Err(KvError::PermissionDenied)
    ));
    service.with_catalog(|catalog| {
        catalog.replace_grants(vec![grant(2, &[Capability::SecretReadHistory])]);
    });
    assert_eq!(service.read(IDENTITY, &explicit).unwrap().version, 1);
    assert!(matches!(
        service.read(IDENTITY, &current),
        Err(KvError::PermissionDenied)
    ));
}

#[test]
fn list_returns_sorted_immediate_children_and_has_its_own_capability() {
    let service = service(&[Capability::SecretWrite], false);
    for path in ["apps/a", "apps/team/b", "apps/team/c", "other/z"] {
        let request = endpoint(&Method::POST, &format!("/v1/secret/data/{path}"));
        service.write(IDENTITY, &request, data(1), None).unwrap();
    }
    let list_method = Method::from_bytes(b"LIST").unwrap();
    let list = endpoint(&list_method, "/v1/secret/metadata/apps");
    assert_eq!(
        service.list(IDENTITY, &list),
        Err(KvError::PermissionDenied)
    );
    service
        .with_catalog(|catalog| catalog.replace_grants(vec![grant(3, &[Capability::SecretList])]));
    assert_eq!(service.list(IDENTITY, &list).unwrap(), ["a", "team/"]);
    service.with_catalog(|catalog| {
        assert_eq!(
            catalog.audit().last().unwrap().operation,
            KvAuditOperation::List
        );
    });
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
    let mut random = Counter(10);
    let issued = issue_credential(
        &verifier_key,
        store_id,
        metadata,
        "runtime".into(),
        &mut |_| false,
        &mut random,
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

#[tokio::test]
async fn final_router_dispatches_literal_list_and_get_list_true_with_strict_shapes() {
    let (auth, token) = auth_fixture();
    let kv = service(
        &[
            Capability::SecretWrite,
            Capability::SecretReadCurrent,
            Capability::SecretList,
        ],
        false,
    );
    let app = kv_router(auth, kv, InputHygieneState::new([9; 32]));

    let write = Request::builder()
        .method(Method::POST)
        .uri("/v1/secret/data/apps/key")
        .header("x-vault-token", &token)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"data":{"value":"secret"},"options":{"cas":0}}"#,
        ))
        .unwrap();
    let response = app.clone().oneshot(write).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let read = Request::builder()
        .uri("/v1/secret/data/apps/key")
        .header("x-vault-token", &token)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(read).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!response.headers().contains_key("content-encoding"));
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["data"]["data"]["value"], "secret");
    assert_eq!(body["data"]["metadata"]["version"], 1);

    for (method, uri) in [
        (
            Method::from_bytes(b"LIST").unwrap(),
            "/v1/secret/metadata/apps",
        ),
        (Method::GET, "/v1/secret/metadata/apps?list=true"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-vault-token", &token)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body, json!({"data": {"keys": ["key"]}}));
    }

    let duplicate = Request::builder()
        .method(Method::POST)
        .uri("/v1/secret/data/apps/key")
        .header("x-vault-token", &token)
        .body(Body::from(r#"{"data":{"a":1},"data":{"a":2}}"#))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let namespace = Request::builder()
        .uri("/v1/secret/data/apps/key")
        .header("x-vault-token", &token)
        .header("x-vault-namespace", "team")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(namespace).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn kv_value_bounds_hold_at_n_minus_one_n_and_n_plus_one() {
    let service = service(&[Capability::SecretWrite], false);
    let request = endpoint(&Method::POST, "/v1/secret/data/bounds");

    for count in [MAX_SECRET_FIELDS - 1, MAX_SECRET_FIELDS] {
        let data = (0..count)
            .map(|index| (format!("k{index}"), Value::Null))
            .collect();
        service.write(IDENTITY, &request, data, None).unwrap();
    }
    let over_fields = (0..=MAX_SECRET_FIELDS)
        .map(|index| (format!("k{index}"), Value::Null))
        .collect();
    assert!(matches!(
        service.write(IDENTITY, &request, over_fields, None),
        Err(KvError::BoundExceeded("secret_field_count"))
    ));

    for chars in [MAX_SECRET_FIELD_NAME_CHARS - 1, MAX_SECRET_FIELD_NAME_CHARS] {
        service
            .write(
                IDENTITY,
                &request,
                Map::from_iter([("é".repeat(chars), Value::Null)]),
                None,
            )
            .unwrap();
    }
    assert!(matches!(
        service.write(
            IDENTITY,
            &request,
            Map::from_iter([("é".repeat(MAX_SECRET_FIELD_NAME_CHARS + 1), Value::Null,)]),
            None,
        ),
        Err(KvError::BoundExceeded("secret_field_name_chars"))
    ));

    for payload in [MAX_SECRET_ENCODED_BYTES - 9, MAX_SECRET_ENCODED_BYTES - 8] {
        service
            .write(
                IDENTITY,
                &request,
                Map::from_iter([("v".into(), Value::String("x".repeat(payload)))]),
                None,
            )
            .unwrap();
    }
    assert!(matches!(
        service.write(
            IDENTITY,
            &request,
            Map::from_iter([(
                "v".into(),
                Value::String("x".repeat(MAX_SECRET_ENCODED_BYTES - 7)),
            )]),
            None,
        ),
        Err(KvError::BoundExceeded("secret_encoded_bytes"))
    ));
}

#[test]
fn kv_depth_metadata_and_list_bounds_are_explicit() {
    fn nested(depth: usize) -> Value {
        (0..depth).fold(Value::Null, |value, _| json!({"n": value}))
    }
    let service = service(
        &[
            Capability::SecretWrite,
            Capability::SecretList,
            Capability::SecretReadCurrent,
        ],
        false,
    );
    let write = endpoint(&Method::POST, "/v1/secret/data/depth");
    for depth in [MAX_SECRET_NESTING_DEPTH - 3, MAX_SECRET_NESTING_DEPTH - 2] {
        service
            .write(
                IDENTITY,
                &write,
                Map::from_iter([("root".into(), nested(depth))]),
                None,
            )
            .unwrap();
    }
    assert!(matches!(
        service.write(
            IDENTITY,
            &write,
            Map::from_iter([("root".into(), nested(MAX_SECRET_NESTING_DEPTH - 1),)]),
            None,
        ),
        Err(KvError::BoundExceeded("secret_nesting_depth"))
    ));

    let metadata = endpoint(&Method::GET, "/v1/secret/metadata/depth");
    let at_limit = (0..MAX_CUSTOM_METADATA_KEYS)
        .map(|index| {
            (
                format!("{index}{}", "é".repeat(MAX_CUSTOM_METADATA_KEY_CHARS - 3)),
                "é".repeat(MAX_CUSTOM_METADATA_VALUE_CHARS),
            )
        })
        .collect();
    service
        .update_metadata(
            IDENTITY,
            &metadata,
            MetadataUpdate {
                cas_required: None,
                max_versions: None,
                delete_version_after: None,
                custom_metadata: Some(at_limit),
            },
        )
        .unwrap();
    let over = (0..=MAX_CUSTOM_METADATA_KEYS)
        .map(|index| (index.to_string(), String::new()))
        .collect();
    assert_eq!(
        service.update_metadata(
            IDENTITY,
            &metadata,
            MetadataUpdate {
                cas_required: None,
                max_versions: None,
                delete_version_after: None,
                custom_metadata: Some(over),
            },
        ),
        Err(KvError::BoundExceeded("custom_metadata_keys"))
    );

    for chars in [
        MAX_CUSTOM_METADATA_KEY_CHARS - 1,
        MAX_CUSTOM_METADATA_KEY_CHARS,
    ] {
        service
            .update_metadata(
                IDENTITY,
                &metadata,
                MetadataUpdate {
                    cas_required: None,
                    max_versions: None,
                    delete_version_after: None,
                    custom_metadata: Some(std::collections::BTreeMap::from([(
                        "é".repeat(chars),
                        String::new(),
                    )])),
                },
            )
            .unwrap();
    }
    assert_eq!(
        service.update_metadata(
            IDENTITY,
            &metadata,
            MetadataUpdate {
                cas_required: None,
                max_versions: None,
                delete_version_after: None,
                custom_metadata: Some(std::collections::BTreeMap::from([(
                    "é".repeat(MAX_CUSTOM_METADATA_KEY_CHARS + 1),
                    String::new(),
                )])),
            },
        ),
        Err(KvError::BoundExceeded("custom_metadata_key_chars"))
    );
    for chars in [
        MAX_CUSTOM_METADATA_VALUE_CHARS - 1,
        MAX_CUSTOM_METADATA_VALUE_CHARS,
    ] {
        service
            .update_metadata(
                IDENTITY,
                &metadata,
                MetadataUpdate {
                    cas_required: None,
                    max_versions: None,
                    delete_version_after: None,
                    custom_metadata: Some(std::collections::BTreeMap::from([(
                        "k".into(),
                        "é".repeat(chars),
                    )])),
                },
            )
            .unwrap();
    }
    assert_eq!(
        service.update_metadata(
            IDENTITY,
            &metadata,
            MetadataUpdate {
                cas_required: None,
                max_versions: None,
                delete_version_after: None,
                custom_metadata: Some(std::collections::BTreeMap::from([(
                    "k".into(),
                    "é".repeat(MAX_CUSTOM_METADATA_VALUE_CHARS + 1),
                )])),
            },
        ),
        Err(KvError::BoundExceeded("custom_metadata_value_chars"))
    );

    for index in 0..=MAX_LIST_RESULTS {
        let item = endpoint(
            &Method::POST,
            &format!("/v1/secret/data/list/item-{index:04}"),
        );
        service.write(IDENTITY, &item, data(1), None).unwrap();
        if index + 1 == MAX_LIST_RESULTS - 1 || index + 1 == MAX_LIST_RESULTS {
            let list_method = Method::from_bytes(b"LIST").unwrap();
            let list = endpoint(&list_method, "/v1/secret/metadata/list");
            assert_eq!(service.list(IDENTITY, &list).unwrap().len(), index + 1);
        }
    }
    let list_method = Method::from_bytes(b"LIST").unwrap();
    let list = endpoint(&list_method, "/v1/secret/metadata/list");
    assert_eq!(
        service.list(IDENTITY, &list),
        Err(KvError::BoundExceeded("list_results"))
    );
    service.with_catalog(|catalog| {
        let event = catalog.audit().last().unwrap();
        assert_eq!(event.outcome, KvAuditOutcome::Failed);
        assert_eq!(event.reason, Some("list-result-limit"));
    });
}

#[test]
fn deletion_batch_bound_holds_at_n_minus_one_n_and_n_plus_one() {
    let service = service(
        &[Capability::SecretWrite, Capability::SecretSoftDelete],
        false,
    );
    service.with_catalog(|catalog| catalog.set_mount_max_versions(MAX_VERSIONS).unwrap());
    let write = endpoint(&Method::POST, "/v1/secret/data/delete-bounds");
    for version in 1..=MAX_VERSION_BATCH {
        service
            .write(
                IDENTITY,
                &write,
                data(version as i64),
                (version > 1).then_some((version - 1) as u64),
            )
            .unwrap();
    }
    let delete = endpoint(&Method::POST, "/v1/secret/delete/delete-bounds");
    for count in [MAX_VERSION_BATCH - 1, MAX_VERSION_BATCH] {
        let versions = (1..=count as u64).collect::<Vec<_>>();
        service
            .mutate_versions(
                IDENTITY,
                &delete,
                &versions,
                ops_light_secrets_server::identity::SecretAction::SoftDelete,
            )
            .unwrap();
    }
    assert_eq!(
        service.mutate_versions(
            IDENTITY,
            &delete,
            &(1..=MAX_VERSION_BATCH as u64 + 1).collect::<Vec<_>>(),
            ops_light_secrets_server::identity::SecretAction::SoftDelete,
        ),
        Err(KvError::BoundExceeded("version_batch"))
    );
}

#[tokio::test]
async fn content_encoding_is_rejected_before_body_processing() {
    let (auth, token) = auth_fixture();
    let app = kv_router(
        auth,
        service(&[Capability::SecretWrite], false),
        InputHygieneState::new([9; 32]),
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/secret/data/compressed")
        .header("x-vault-token", token)
        .header("content-encoding", "gzip")
        .body(Body::from("not-even-gzip"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("content_encoding_not_supported"));
}

#[test]
fn audit_type_has_no_secret_value_or_body_fields() {
    let service = service(&[Capability::SecretWrite], false);
    let request = endpoint(&Method::POST, "/v1/secret/data/canary");
    service
        .write(
            IDENTITY,
            &request,
            Map::from_iter([("PRIVATE_CANARY".into(), json!(true))]),
            None,
        )
        .unwrap();
    service.with_catalog(|catalog| {
        let rendered = format!("{:?}", catalog.audit());
        assert!(!rendered.contains("PRIVATE_CANARY"));
    });
}

#[test]
fn deletion_metadata_and_retention_state_machine_is_atomic_and_bounded() {
    let service = service(
        &[
            Capability::SecretWrite,
            Capability::SecretReadCurrent,
            Capability::SecretReadHistory,
            Capability::SecretList,
            Capability::SecretSoftDelete,
            Capability::SecretUndelete,
            Capability::SecretDestroy,
        ],
        false,
    );
    let write = endpoint(&Method::POST, "/v1/secret/data/lifecycle");
    for value in 1..=3 {
        service
            .write(
                IDENTITY,
                &write,
                data(value),
                (value > 1).then_some((value - 1) as u64),
            )
            .unwrap();
    }
    let delete = endpoint(&Method::POST, "/v1/secret/delete/lifecycle");
    let undelete = endpoint(&Method::POST, "/v1/secret/undelete/lifecycle");
    let destroy = endpoint(&Method::POST, "/v1/secret/destroy/lifecycle");
    service
        .mutate_versions(
            IDENTITY,
            &delete,
            &[1, 2],
            ops_light_secrets_server::identity::SecretAction::SoftDelete,
        )
        .unwrap();
    assert!(matches!(
        service.mutate_versions(
            IDENTITY,
            &undelete,
            &[1, 99],
            ops_light_secrets_server::identity::SecretAction::Undelete
        ),
        Err(KvError::NotFound)
    ));
    let first = endpoint(&Method::GET, "/v1/secret/data/lifecycle?version=1");
    assert!(matches!(
        service.read(IDENTITY, &first),
        Err(KvError::VersionUnavailable {
            destroyed: false,
            ..
        })
    ));
    service
        .mutate_versions(
            IDENTITY,
            &undelete,
            &[1],
            ops_light_secrets_server::identity::SecretAction::Undelete,
        )
        .unwrap();
    assert_eq!(
        service.read(IDENTITY, &first).unwrap().data,
        json!({"value": 1})
    );
    service
        .mutate_versions(
            IDENTITY,
            &destroy,
            &[1],
            ops_light_secrets_server::identity::SecretAction::Destroy,
        )
        .unwrap();
    service
        .mutate_versions(
            IDENTITY,
            &undelete,
            &[1],
            ops_light_secrets_server::identity::SecretAction::Undelete,
        )
        .unwrap();
    assert!(matches!(
        service.read(IDENTITY, &first),
        Err(KvError::VersionUnavailable {
            destroyed: true,
            ..
        })
    ));

    let metadata_endpoint = endpoint(&Method::GET, "/v1/secret/metadata/lifecycle");
    service
        .update_metadata(
            IDENTITY,
            &metadata_endpoint,
            MetadataUpdate {
                cas_required: Some(true),
                max_versions: Some(1),
                delete_version_after: Some("0s".into()),
                custom_metadata: Some(std::collections::BTreeMap::from([(
                    "owner".into(),
                    "platform".into(),
                )])),
            },
        )
        .unwrap();
    assert!(
        matches!(
            service.read(IDENTITY, &first),
            Err(KvError::VersionUnavailable {
                destroyed: true,
                ..
            })
        ),
        "metadata update must not eagerly prune"
    );
    let metadata = service.metadata(IDENTITY, &metadata_endpoint).unwrap();
    assert_eq!(metadata["max_versions"], 1);
    assert_eq!(metadata["custom_metadata"]["owner"], "platform");
    assert_eq!(metadata["versions"]["1"]["destroyed"], true);
    assert_eq!(MAX_VERSIONS, 1_024);
    assert_eq!(
        service.update_metadata(
            IDENTITY,
            &metadata_endpoint,
            MetadataUpdate {
                cas_required: None,
                max_versions: Some(MAX_VERSIONS + 1),
                delete_version_after: None,
                custom_metadata: None,
            }
        ),
        Err(KvError::Invalid)
    );
    assert_eq!(
        service.mutate_versions(
            IDENTITY,
            &delete,
            &vec![1; MAX_VERSION_BATCH + 1],
            ops_light_secrets_server::identity::SecretAction::SoftDelete,
        ),
        Err(KvError::BoundExceeded("version_batch"))
    );
}

#[tokio::test]
async fn router_supports_all_delete_forms_metadata_and_remote_purge_refusal() {
    let (auth, token) = auth_fixture();
    let kv = service(
        &[
            Capability::SecretWrite,
            Capability::SecretReadCurrent,
            Capability::SecretReadHistory,
            Capability::SecretList,
            Capability::SecretSoftDelete,
            Capability::SecretUndelete,
            Capability::SecretDestroy,
        ],
        false,
    );
    let app = kv_router(auth, kv, InputHygieneState::new([9; 32]));
    let request = |method: Method, uri: &str, body: &'static str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("x-vault-token", &token)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    for cas in [0, 1] {
        let body = if cas == 0 {
            r#"{"data":{"value":1},"options":{"cas":0}}"#
        } else {
            r#"{"data":{"value":2},"options":{"cas":1}}"#
        };
        assert_eq!(
            app.clone()
                .oneshot(request(Method::POST, "/v1/secret/data/wire", body))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    for (method, uri, body) in [
        (Method::DELETE, "/v1/secret/data/wire", ""),
        (
            Method::POST,
            "/v1/secret/undelete/wire",
            r#"{"versions":[2]}"#,
        ),
        (
            Method::POST,
            "/v1/secret/delete/wire",
            r#"{"versions":[1,2]}"#,
        ),
        (
            Method::POST,
            "/v1/secret/destroy/wire",
            r#"{"versions":[1]}"#,
        ),
        (
            Method::POST,
            "/v1/secret/undelete/wire",
            r#"{"versions":[1]}"#,
        ),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(method, uri, body))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let response = app
        .clone()
        .oneshot(request(Method::GET, "/v1/secret/metadata/wire", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(metadata["data"]["versions"]["1"]["destroyed"], true);
    assert_eq!(metadata["data"]["versions"]["2"]["destroyed"], false);

    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                "/v1/secret/metadata/wire",
                r#"{"cas_required":false,"max_versions":0,"delete_version_after":"0s","custom_metadata":{"team":"platform"}}"#,
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let unsupported = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/v1/secret/metadata/wire",
            r#"{"delete_version_after":"1h"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&to_bytes(unsupported.into_body(), 1024).await.unwrap())
            .contains("delete_version_after")
    );
    assert_eq!(
        app.oneshot(request(Method::DELETE, "/v1/secret/metadata/wire", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_IMPLEMENTED
    );
}
