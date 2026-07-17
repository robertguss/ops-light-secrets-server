use std::collections::BTreeSet;
use std::process::Command;

use axum::body::Body;
use axum::http::Method;
use axum::http::{Request, StatusCode};
use ops_light_secrets_server::control::data_router;
use ops_light_secrets_server::control::management::{
    CommandPhase, ControlCommand, MANAGEMENT_OUTPUT_SCHEMA, MAX_PAGE_SIZE, ManagementCatalog,
    ManagementError, ManagementPrincipal, command_authorization,
};
use ops_light_secrets_server::credential::CredentialAudience;
use ops_light_secrets_server::identity::{
    AuthorizationRequest, Capability, GrantRecord, GrantScope, IdentityKind, IdentityRecord,
    SecretAction,
};
use ops_light_secrets_server::raw_target::parse_raw_target;
use test_support::{ActualOutcome, ExpectedOutcome, Harness, SafeSummary};
use tower::ServiceExt;

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
    ] {
        let response = data_router()
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

fn decode_id(value: &str) -> [u8; 16] {
    let mut output = [0; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}
