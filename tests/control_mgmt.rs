use std::collections::BTreeSet;
use std::process::Command;

use axum::body::Body;
use axum::http::Method;
use axum::http::{Request, StatusCode};
use ops_light_secrets_server::auth::{AppRoleRecord, AuthCatalog};
use ops_light_secrets_server::control::credential_management::{
    CredentialManagementCatalog, IssueResult, RoleDeleteRequest, SecretIdIssueRequest,
    TokenIssueRequest,
};
use ops_light_secrets_server::control::data_router;
use ops_light_secrets_server::control::management::{
    CommandPhase, ControlCommand, MANAGEMENT_OUTPUT_SCHEMA, MAX_PAGE_SIZE, ManagementCatalog,
    ManagementError, ManagementPrincipal, command_authorization,
};
use ops_light_secrets_server::credential::{
    CredentialAudience, DIRECT_TOKEN_MIN_TTL_SECONDS, SECRET_ID_MIN_TTL_SECONDS,
};
use ops_light_secrets_server::identity::{
    AuthorizationRequest, Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
    SecretAction,
};
use ops_light_secrets_server::raw_target::parse_raw_target;
use ops_light_secrets_server::store::StoreId;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary};
use tower::ServiceExt;

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn capabilities(values: &[Capability]) -> BTreeSet<Capability> {
    values.iter().copied().collect()
}

fn grant(id: u8, owner: u8, capabilities: &[Capability]) -> GrantRecord {
    GrantRecord::new(
        [id; 16],
        [owner; 16],
        "sys".into(),
        GrantScope::Exact,
        Vec::new(),
        self::capabilities(capabilities),
    )
    .unwrap()
}

fn principal(identity: u8) -> ManagementPrincipal {
    ManagementPrincipal {
        identity_id: [identity; 16],
        audience: CredentialAudience::Control,
        peer_uid: 1000,
        expected_uid: 1000,
        credential_active: true,
    }
}

fn catalog(capabilities: &[Capability]) -> ManagementCatalog {
    ManagementCatalog::new(
        [IdentityRecord::new([1; 16], "operator".into(), IdentityKind::Human).unwrap()],
        [grant(1, 1, capabilities)],
    )
    .unwrap()
}

fn credential_catalog(capabilities: &[Capability]) -> CredentialManagementCatalog<Counter> {
    let operator = IdentityRecord::new([1; 16], "operator".into(), IdentityKind::Human).unwrap();
    let workload = IdentityRecord::new([2; 16], "workload".into(), IdentityKind::Workload).unwrap();
    let authorization = ManagementCatalog::new(
        [operator.clone(), workload.clone()],
        [grant(1, 1, capabilities)],
    )
    .unwrap();
    let mut auth = AuthCatalog::new(StoreId([7; 16]), [8; 32], 1, 100).unwrap();
    auth.insert_identity(operator).unwrap();
    auth.insert_identity(workload).unwrap();
    CredentialManagementCatalog::new(authorization, auth, Counter(10))
}

#[test]
fn exhaustive_command_registry_has_one_mapping_and_no_server_aliases() {
    assert_eq!(
        ControlCommand::ALL
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        ControlCommand::ALL.len()
    );
    for command in ControlCommand::ALL {
        let mapping = command_authorization(command);
        assert_eq!(mapping.command, command);
        assert_eq!(
            mapping.phase == CommandPhase::Local,
            mapping.capability.is_none()
        );
        if let Some(capability) = mapping.capability {
            assert!(capability.is_management());
        }
    }

    assert_eq!(
        command_authorization(ControlCommand::AuthzExplain).capability,
        Some(Capability::Diagnostics)
    );
    for command in [
        ControlCommand::StoreReserveStatus,
        ControlCommand::StoreReserveRelease,
        ControlCommand::StoreReserveRecreate,
    ] {
        assert_eq!(
            command_authorization(command).capability,
            Some(Capability::StoreMaintenance)
        );
    }
    assert_eq!(
        command_authorization(ControlCommand::RecipientRewrap).capability,
        Some(Capability::KeyRotation)
    );
    for command in [
        ControlCommand::BackupList,
        ControlCommand::BackupShow,
        ControlCommand::BackupResume,
    ] {
        assert_eq!(
            command_authorization(command).capability,
            Some(Capability::Backup)
        );
    }
    for command in [
        ControlCommand::AuditExportList,
        ControlCommand::AuditExportShow,
        ControlCommand::AuditExportResume,
    ] {
        assert_eq!(
            command_authorization(command).capability,
            Some(Capability::AuditExport)
        );
    }
}

#[test]
fn every_server_command_rejects_every_wrong_management_capability() {
    for command in ControlCommand::ALL {
        let mapping = command_authorization(command);
        let Some(required) = mapping.capability else {
            let mut state = catalog(&[Capability::Diagnostics]);
            assert_eq!(
                state.authorize_command(principal(1), command, [90; 16]),
                Err(ManagementError::Denied)
            );
            continue;
        };
        for candidate in Capability::ALL
            .into_iter()
            .filter(|capability| capability.is_management())
        {
            let mut state = catalog(&[candidate]);
            assert_eq!(
                state.authorize_command(principal(1), command, [candidate as u8; 16]),
                if candidate == required {
                    Ok(())
                } else {
                    Err(ManagementError::Denied)
                },
                "command={command:?} candidate={candidate:?} required={required:?}"
            );
        }
    }
}

#[test]
fn identity_and_grant_lifecycle_is_id_based_terminal_and_idempotent() {
    let mut state = catalog(&[Capability::IdentityGrantManage, Capability::Diagnostics]);
    let actor = principal(1);
    let created = state
        .create_identity(
            actor,
            [10; 16],
            [2; 16],
            "workload-a".into(),
            IdentityKind::Workload,
        )
        .unwrap();
    assert_eq!(created.id, "02020202020202020202020202020202");
    assert_eq!(created.kind, "workload");
    assert_eq!(
        state
            .create_identity(
                actor,
                [10; 16],
                [2; 16],
                "workload-a".into(),
                IdentityKind::Workload
            )
            .unwrap(),
        created
    );
    assert_eq!(
        state.create_identity(
            actor,
            [11; 16],
            [3; 16],
            "workload-a".into(),
            IdentityKind::Human
        ),
        Err(ManagementError::Conflict)
    );

    let workload_grant = GrantRecord::new(
        [2; 16],
        [2; 16],
        "kv".into(),
        GrantScope::Subtree,
        vec!["apps".into()],
        capabilities(&[Capability::SecretReadCurrent]),
    )
    .unwrap();
    let added = state
        .add_grant(actor, [12; 16], workload_grant.clone())
        .unwrap();
    assert_eq!(added.generation, 1);
    assert_eq!(
        state.add_grant(actor, [13; 16], workload_grant),
        Err(ManagementError::Conflict)
    );
    assert_eq!(
        state
            .list_grants(actor, [18; 16], [2; 16], None, 1)
            .unwrap()
            .items
            .len(),
        1
    );

    let removed = state
        .remove_grant(actor, [14; 16], [2; 16], 1, "access retired".into())
        .unwrap();
    assert_eq!(removed.status, "removed");
    assert_eq!(removed.generation, 2);
    assert_eq!(
        state
            .remove_grant(actor, [14; 16], [2; 16], 1, "access retired".into())
            .unwrap(),
        removed
    );
    assert_eq!(
        state.remove_grant(actor, [15; 16], [2; 16], 1, "again".into()),
        Err(ManagementError::StaleGeneration)
    );

    let disabled = state
        .disable_identity(actor, [16; 16], [2; 16], 1, "host decommissioned".into())
        .unwrap();
    assert_eq!(disabled.identity.status, "disabled");
    assert_eq!(disabled.affected_grant_count, 0);
    assert_eq!(
        state.disable_identity(actor, [17; 16], [2; 16], 1, "cannot re-enable".into()),
        Err(ManagementError::StaleGeneration)
    );
    assert!(state.audit().iter().any(|event| {
        event.command == ControlCommand::IdentityDisable
            && event.reason.as_deref() == Some("host decommissioned")
    }));
}

#[test]
fn wrong_surface_uid_credential_and_capability_are_denied_and_audited() {
    for mutate in [
        |principal: &mut ManagementPrincipal| principal.audience = CredentialAudience::Data,
        |principal: &mut ManagementPrincipal| principal.peer_uid = 2000,
        |principal: &mut ManagementPrincipal| principal.credential_active = false,
    ] {
        let mut state = catalog(&[Capability::IdentityGrantManage]);
        let mut actor = principal(1);
        mutate(&mut actor);
        assert_eq!(
            state.create_identity(
                actor,
                [20; 16],
                [2; 16],
                "denied".into(),
                IdentityKind::Human
            ),
            Err(ManagementError::Denied)
        );
        assert!(!state.audit().last().unwrap().allowed);
    }

    let mut state = catalog(&[Capability::AuditRead]);
    assert_eq!(
        state.create_identity(
            principal(1),
            [21; 16],
            [2; 16],
            "wrong-capability".into(),
            IdentityKind::Human,
        ),
        Err(ManagementError::Denied)
    );
    assert!(!state.audit().last().unwrap().allowed);

    let retired = IdentityRecord::new([1; 16], "retired".into(), IdentityKind::Human)
        .unwrap()
        .retire(1)
        .unwrap();
    let mut state =
        ManagementCatalog::new([retired], [grant(1, 1, &[Capability::IdentityGrantManage])])
            .unwrap();
    assert_eq!(
        state.authorize_command(principal(1), ControlCommand::IdentityList, [22; 16]),
        Err(ManagementError::Denied)
    );
}

#[test]
fn diagnostics_only_explain_is_structured_and_observes_next_snapshot_reduction() {
    let target = IdentityRecord::new([2; 16], "target".into(), IdentityKind::Workload).unwrap();
    let diagnostic = grant(1, 1, &[Capability::Diagnostics]);
    let manager = grant(3, 3, &[Capability::IdentityGrantManage]);
    let access = GrantRecord::new(
        [2; 16],
        [2; 16],
        "kv".into(),
        GrantScope::Subtree,
        vec!["apps".into()],
        capabilities(&[Capability::SecretReadCurrent]),
    )
    .unwrap();
    let mut state = ManagementCatalog::new(
        [
            IdentityRecord::new([1; 16], "diagnostic".into(), IdentityKind::Human).unwrap(),
            target,
            IdentityRecord::new([3; 16], "manager".into(), IdentityKind::Human).unwrap(),
        ],
        [diagnostic, access, manager],
    )
    .unwrap();
    let endpoint = parse_raw_target(&Method::GET, "/v1/kv/data/apps/service/key").unwrap();
    let request = AuthorizationRequest::secret(&endpoint, SecretAction::Read).unwrap();

    let allowed = state
        .explain(principal(1), [30; 16], [2; 16], &request)
        .unwrap();
    assert!(allowed.allow);
    assert_eq!(
        allowed.matched_grant.as_deref(),
        Some("02020202020202020202020202020202")
    );
    assert_eq!(allowed.deny_reason, None);

    state
        .remove_grant(principal(3), [33; 16], [2; 16], 1, "grant reduced".into())
        .unwrap();
    let denied = state
        .explain(principal(1), [31; 16], [2; 16], &request)
        .unwrap();
    assert!(!denied.allow);
    assert_eq!(denied.deny_reason, Some("no-grant-for-mount"));

    let mut manager_only = catalog(&[Capability::IdentityGrantManage]);
    assert_eq!(
        manager_only.explain(principal(1), [32; 16], [1; 16], &request),
        Err(ManagementError::Denied)
    );
}

#[test]
fn lists_are_bounded_paginated_and_json_schema_is_stable() {
    let mut state = catalog(&[Capability::IdentityGrantManage]);
    for id in 2..=4 {
        state
            .create_identity(
                principal(1),
                [id + 40; 16],
                [id; 16],
                format!("identity-{id}"),
                IdentityKind::Human,
            )
            .unwrap();
    }
    assert_eq!(
        state.list_identities(principal(1), [50; 16], None, MAX_PAGE_SIZE + 1),
        Err(ManagementError::Limit)
    );
    let first = state
        .list_identities(principal(1), [51; 16], None, 2)
        .unwrap();
    assert_eq!(first.schema, MANAGEMENT_OUTPUT_SCHEMA);
    assert_eq!(first.items.len(), 2);
    let cursor = decode_id(first.next_cursor.as_deref().unwrap());
    let second = state
        .list_identities(principal(1), [52; 16], Some(cursor), 2)
        .unwrap();
    assert_eq!(second.items.len(), 2);
    assert_eq!(second.next_cursor, None);
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        r#"{"schema":1,"items":[{"id":"01010101010101010101010101010101","name":"operator","kind":"human","status":"active","generation":1},{"id":"02020202020202020202020202020202","name":"identity-2","kind":"human","status":"active","generation":1}],"next_cursor":"02020202020202020202020202020202"}"#
    );
}

#[test]
fn actual_binary_freezes_control_cli_surface_without_argv_bearers() {
    let harness = Harness::builder("control-mgmt")
        .register_canary(b"control-management-secret-canary")
        .build()
        .expect("create harness");
    let mut scenario = harness
        .scenario("binary-control-help", 1)
        .expect("start scenario");
    for (group, step) in [
        ("identity", "identity-help"),
        ("grant", "grant-help"),
        ("authz", "authz-help"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
            .args([group, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("--control-socket"));
        assert!(stdout.contains("--control-credential-source"));
        assert!(!stdout.contains("--token"));
        assert!(!stdout.contains("--secret"));
        scenario
            .step(
                step,
                SafeSummary::new(),
                ExpectedOutcome::Success,
                ActualOutcome::Success,
            )
            .unwrap();
    }
    assert!(scenario.finish_success().unwrap().scan_attestation.clean);
}

#[tokio::test]
async fn remote_router_has_no_identity_grant_or_explain_routes() {
    for path in [
        "/v1/sys/identities",
        "/v1/sys/identities/01010101010101010101010101010101",
        "/v1/sys/grants",
        "/v1/sys/authz/explain",
        "/v1/sys/tokens",
        "/v1/sys/approle/roles",
        "/v1/sys/approle/secret-ids",
    ] {
        let response = data_router()
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[test]
fn token_disclosure_once_authenticate_revoke_and_lost_reply_recovery() {
    let mut state = credential_catalog(&[
        Capability::CredentialIssue,
        Capability::CredentialRevoke,
        Capability::IdentityGrantManage,
    ]);
    let request = TokenIssueRequest {
        request_id: [11; 16],
        id: [12; 16],
        identity_id: [1; 16],
        audience: CredentialAudience::Control,
        ttl_seconds: DIRECT_TOKEN_MIN_TTL_SECONDS,
        label: "operator-successor".into(),
    };
    let issued = match state.token_issue(principal(1), request.clone()).unwrap() {
        IssueResult::Disclosed(value) => value,
        IssueResult::Existing(_) => panic!("first issuance must disclose"),
    };
    let raw = issued.expose_once().to_owned();
    let accessor = issued.record.accessor;
    assert!(
        state
            .auth()
            .authenticated_credential(&raw, CredentialAudience::Control)
            .is_some()
    );

    let retry = state.token_issue(principal(1), request).unwrap();
    let existing = match retry {
        IssueResult::Existing(value) => value,
        IssueResult::Disclosed(_) => panic!("retry must never redisclose"),
    };
    assert_eq!(existing.accessor, accessor.encode());
    let metadata_json = serde_json::to_string(&existing).unwrap();
    assert!(!metadata_json.contains(&raw));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&metadata_json).unwrap()["schema"],
        1
    );

    let listed = state.token_list(principal(1), [13; 16], None, 50).unwrap();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].label, "operator-successor");
    let revoked = state
        .credential_revoke(
            principal(1),
            [14; 16],
            accessor,
            "successor validation complete",
        )
        .unwrap();
    assert_eq!(revoked.status, "revoked");
    assert!(
        state
            .auth()
            .authenticated_credential(&raw, CredentialAudience::Control)
            .is_none()
    );
    assert_eq!(
        state
            .credential_revoke(principal(1), [15; 16], accessor, "idempotent retry")
            .unwrap()
            .status,
        "revoked"
    );
    assert!(
        state
            .management_audit()
            .iter()
            .any(|event| event.allowed && event.command == ControlCommand::CredentialIssue)
    );
    assert!(
        state
            .management_audit()
            .iter()
            .any(|event| event.allowed && event.reason.as_deref() == Some("idempotent retry"))
    );
}

#[test]
fn approle_secret_id_is_consumed_listed_revoked_and_role_delete_is_confirmed() {
    let mut state = credential_catalog(&[
        Capability::CredentialIssue,
        Capability::CredentialRevoke,
        Capability::IdentityGrantManage,
    ]);
    let role = AppRoleRecord::new(
        [21; 16],
        "payments-role".into(),
        "payments".into(),
        [2; 16],
        Some(300),
    )
    .unwrap();
    state.role_create(principal(1), [22; 16], role).unwrap();
    let issue = |request_id, id, instance| SecretIdIssueRequest {
        request_id: [request_id; 16],
        id: [id; 16],
        role_id: "payments-role".into(),
        ttl_seconds: SECRET_ID_MIN_TTL_SECONDS,
        use_count: 2,
        consumer_instance_id: Some([instance; 16]),
        identity_only_tracking_accepted: false,
        label: format!("payments-{id}"),
    };
    let first = match state
        .secret_id_issue(principal(1), issue(23, 24, 25))
        .unwrap()
    {
        IssueResult::Disclosed(value) => value,
        IssueResult::Existing(_) => panic!("first issuance"),
    };
    let first_raw = first.expose_once().to_owned();
    let first_accessor = first.record.accessor;
    let login = state
        .auth_mut()
        .login("payments-role", &first_raw, [26; 16], &mut Counter(100))
        .unwrap();
    assert_eq!(login.identity_id, [2; 16]);
    assert_eq!(
        state.auth().usage(first_accessor).unwrap().remaining_uses,
        1
    );

    let orphan = match state
        .secret_id_issue(principal(1), issue(27, 28, 29))
        .unwrap()
    {
        IssueResult::Disclosed(value) => value,
        IssueResult::Existing(_) => panic!("first issuance"),
    };
    let orphan_accessor = orphan.record.accessor;
    drop(orphan);
    let listed = state
        .secret_id_list(principal(1), [30; 16], "payments-role", None, 50)
        .unwrap();
    assert_eq!(listed.items.len(), 2);
    assert!(
        listed
            .items
            .iter()
            .any(|item| item.accessor == orphan_accessor.encode())
    );
    state
        .credential_revoke(
            principal(1),
            [31; 16],
            orphan_accessor,
            "issuance response lost",
        )
        .unwrap();

    let confirmation = CredentialManagementCatalog::<Counter>::role_delete_confirmation(
        "payments-role",
        1,
        1,
        "retire workload login",
    );
    let deleted = state
        .role_delete(
            principal(1),
            RoleDeleteRequest {
                request_id: [32; 16],
                role_id: "payments-role".into(),
                expected_generation: 1,
                invalidated_count: 1,
                reason: "retire workload login".into(),
                confirmation,
            },
        )
        .unwrap();
    assert_eq!(deleted.status, "deleted");
    assert!(
        state
            .auth_mut()
            .login("payments-role", &first_raw, [33; 16], &mut Counter(120))
            .is_err()
    );
}

#[test]
fn credential_capability_and_anti_impersonation_boundaries_fail_closed() {
    let request = TokenIssueRequest {
        request_id: [41; 16],
        id: [42; 16],
        identity_id: [1; 16],
        audience: CredentialAudience::Data,
        ttl_seconds: DIRECT_TOKEN_MIN_TTL_SECONDS,
        label: "self".into(),
    };
    let mut wrong = credential_catalog(&[Capability::AuditRead]);
    assert!(matches!(
        wrong.token_issue(principal(1), request.clone()),
        Err(ManagementError::Denied)
    ));

    let mut issue_only = credential_catalog(&[Capability::CredentialIssue]);
    let crossing = TokenIssueRequest {
        identity_id: [2; 16],
        ..request
    };
    assert!(matches!(
        issue_only.token_issue(principal(1), crossing),
        Err(ManagementError::Denied)
    ));
    let role = AppRoleRecord::new(
        [43; 16],
        "crossing".into(),
        "crossing".into(),
        [2; 16],
        Some(300),
    )
    .unwrap();
    assert_eq!(
        issue_only.role_create(principal(1), [44; 16], role),
        Err(ManagementError::Denied)
    );
}

#[test]
fn credential_cli_surface_requires_descriptors_and_raw_output_fds() {
    for (arguments, expected) in [
        (vec!["token", "issue", "--help"], "--credential-output-fd"),
        (
            vec!["approle", "secret-id", "issue", "--help"],
            "--credential-output-fd",
        ),
        (vec!["token", "revoke", "--help"], "--reason"),
        (
            vec!["approle", "role", "delete", "--help"],
            "--confirmation",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(expected));
        assert!(!stdout.contains("--token-value"));
        assert!(!stdout.contains("--secret-id-value"));
    }
    for group in ["token", "approle"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ops-light-secrets-server"))
            .args([group, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("--control-credential-source")
        );
    }
}

fn decode_id(value: &str) -> [u8; 16] {
    let mut output = [0; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}
