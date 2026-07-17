use std::collections::BTreeSet;

use age::x25519;
use axum::http::Method;
use ops_light_secrets_server::identity::{
    AuthorizationRequest, BOOTSTRAP_IDENTITY_NAME, CAPABILITY_REGISTRY_VERSION, Capability,
    CapabilityBundle, DenyReason, GrantRecord, GrantScope, GrantStatus, IdentityError,
    IdentityKind, IdentityRecord, IdentityStatus, MANAGEMENT_MOUNT, SecretAction,
    TOKEN_MODEL_VERSION, TokenAuthorizationSnapshot, TokenBearer, TokenDenyReason,
    TokenServerRecord, authorize, validate_catalog,
};
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::raw_target::parse_raw_target;
use ops_light_secrets_server::store::keyring::{KeyringError, KeyringOpener, RandomSource};
use ops_light_secrets_server::store::{
    Canonical, CodecError, FORMAT_VERSION, Lifecycle, MetaRecord, StoreId, mac_conformance,
};
use zeroize::Zeroize;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

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

fn grant(
    id: u8,
    owner: u8,
    mount: &str,
    scope: GrantScope,
    prefix: &[&str],
    values: &[Capability],
) -> GrantRecord {
    GrantRecord::new(
        [id; 16],
        [owner; 16],
        mount.into(),
        scope,
        prefix.iter().map(|value| (*value).into()).collect(),
        capabilities(values),
    )
    .unwrap()
}

fn identity(id: u8, name: &str) -> IdentityRecord {
    IdentityRecord {
        id: [id; 16],
        name: name.into(),
        kind: IdentityKind::Human,
        status: IdentityStatus::Active,
        generation: 1,
    }
}

fn read_request(path: &str) -> AuthorizationRequest {
    let endpoint = parse_raw_target(&Method::GET, path).unwrap();
    AuthorizationRequest::secret(&endpoint, SecretAction::Read).unwrap()
}

#[test]
fn token_ttl_revocation_identity_and_epoch_are_server_authoritative() {
    assert_eq!(TOKEN_MODEL_VERSION, 1);
    let identity = identity(2, "alice");
    let grant = grant(
        7,
        2,
        "kv",
        GrantScope::Subtree,
        &["apps"],
        &[Capability::SecretReadCurrent],
    );
    let request = read_request("/v1/kv/data/apps/canvas/key");
    let token =
        TokenServerRecord::issue([9; 16], identity.id, 100, 100, 4, "deploy".into()).unwrap();

    let at = |effective, epoch, token: &TokenServerRecord, identity: &IdentityRecord| {
        TokenAuthorizationSnapshot::new(
            Some(token),
            Some(identity),
            std::slice::from_ref(&grant),
            effective,
            epoch,
        )
        .authorize(&request)
    };
    assert!(at(199, 4, &token, &identity).allow);
    for effective in [200, 201] {
        let denied = at(effective, 4, &token, &identity);
        assert_eq!(denied.deny_reason, Some(TokenDenyReason::Expired));
        assert!(denied.audit_required);
    }
    let revoked = token.revoke(1).unwrap();
    assert_eq!(
        at(150, 4, &revoked, &identity).deny_reason,
        Some(TokenDenyReason::Revoked)
    );
    let retired = identity.retire(1).unwrap();
    assert_eq!(
        at(150, 4, &token, &retired).deny_reason,
        Some(TokenDenyReason::IdentityDisabled)
    );
    assert_eq!(
        at(150, 5, &token, &identity).deny_reason,
        Some(TokenDenyReason::EpochChanged)
    );
}

#[test]
fn transaction_snapshots_prove_next_request_observes_grant_reduction() {
    let identity = identity(2, "alice");
    let broad = grant(
        7,
        2,
        "kv",
        GrantScope::Subtree,
        &["apps"],
        &[Capability::SecretReadCurrent],
    );
    let reduced = grant(
        8,
        2,
        "kv",
        GrantScope::Subtree,
        &["apps", "other"],
        &[Capability::SecretReadCurrent],
    );
    let token =
        TokenServerRecord::issue([9; 16], identity.id, 100, 100, 4, "deploy".into()).unwrap();
    let request = read_request("/v1/kv/data/apps/canvas/key");
    let broad_rows = [broad];
    let reduced_rows = [reduced];

    let before_admin_commit =
        TokenAuthorizationSnapshot::new(Some(&token), Some(&identity), &broad_rows, 150, 4);
    let after_admin_commit =
        TokenAuthorizationSnapshot::new(Some(&token), Some(&identity), &reduced_rows, 150, 4);

    assert!(before_admin_commit.authorize(&request).allow);
    let next = after_admin_commit.authorize(&request);
    assert!(!next.allow);
    assert_eq!(next.deny_reason, Some(TokenDenyReason::PrefixBoundaryMiss));
    assert!(next.audit_required);
}

#[test]
fn committed_orphan_remains_discoverable_revocable_and_bearer_cleans_up() {
    let identity = identity(2, "alice");
    let committed =
        TokenServerRecord::issue([9; 16], identity.id, 100, 100, 4, "orphan".into()).unwrap();
    let mut bearer = TokenBearer::new(b"opaque-token-canary".to_vec()).unwrap();
    assert_eq!(bearer.expose(), b"opaque-token-canary");
    bearer.zeroize();
    assert!(bearer.expose().is_empty());

    assert_eq!(committed.id, [9; 16]);
    assert_eq!(committed.revoke(1).unwrap().generation, 2);
    let missing = TokenAuthorizationSnapshot::new(None, None, &[], 150, 4)
        .authorize(&read_request("/v1/kv/data/apps/canvas/key"));
    assert_eq!(
        missing.deny_reason,
        Some(TokenDenyReason::CredentialNotFound)
    );
    assert!(missing.audit_required);
}

#[test]
fn capability_registry_aliases_and_planes_are_closed_and_versioned() {
    assert_eq!(CAPABILITY_REGISTRY_VERSION, 1);
    assert_eq!(Capability::ALL.len(), 23);
    assert_eq!(
        Capability::ALL.into_iter().collect::<BTreeSet<_>>().len(),
        23
    );
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/capability-registry-v1.json")).unwrap();
    let fixture_codes = fixture["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["code"].as_u64().unwrap() as u16)
        .collect::<Vec<_>>();
    assert_eq!(
        fixture_codes,
        Capability::ALL
            .into_iter()
            .map(|capability| capability as u16)
            .collect::<Vec<_>>()
    );

    let admin = CapabilityBundle::AdminV1.expand();
    assert!(admin.iter().all(|capability| capability.is_management()));
    assert_eq!(admin.len(), 15);
    assert_eq!(
        CapabilityBundle::AuditorV1.expand(),
        capabilities(&[Capability::AuditRead, Capability::AuditExport])
    );

    assert_eq!(
        GrantRecord::new(
            [1; 16],
            [2; 16],
            MANAGEMENT_MOUNT.into(),
            GrantScope::Exact,
            Vec::new(),
            capabilities(&[Capability::SecretReadCurrent]),
        ),
        Err(IdentityError::CrossPlane)
    );
    assert_eq!(
        GrantRecord::new(
            [1; 16],
            [2; 16],
            "kv".into(),
            GrantScope::Subtree,
            Vec::new(),
            capabilities(&[Capability::SecretReadCurrent, Capability::Diagnostics]),
        ),
        Err(IdentityError::CrossPlane)
    );
    assert_eq!(
        GrantRecord::new(
            [1; 16],
            [2; 16],
            "kv".into(),
            GrantScope::Subtree,
            Vec::new(),
            capabilities(&[Capability::Diagnostics]),
        ),
        Err(IdentityError::CrossPlane)
    );
    assert_eq!(
        GrantRecord::new(
            [1; 16],
            [2; 16],
            MANAGEMENT_MOUNT.into(),
            GrantScope::Subtree,
            Vec::new(),
            capabilities(&[Capability::Diagnostics]),
        ),
        Err(IdentityError::CrossPlane)
    );
}

#[test]
fn matcher_uses_segment_boundaries_and_request_shape_for_explicit_versions() {
    let subtree = grant(
        7,
        2,
        "kv",
        GrantScope::Subtree,
        &["apps", "canvas"],
        &[
            Capability::SecretReadCurrent,
            Capability::SecretList,
            Capability::SecretWrite,
        ],
    );
    for raw in [
        "/v1/kv/data/apps/populi/api-key",
        "/v1/kv/metadata/apps/populi/api-key",
        "/v1/kv/metadata/apps/populi/api-key?list=true",
    ] {
        let endpoint = parse_raw_target(&Method::GET, raw).unwrap();
        let action = if raw.contains("list=true") {
            SecretAction::List
        } else if raw.contains("/data/") {
            SecretAction::Read
        } else {
            SecretAction::Metadata
        };
        let request = AuthorizationRequest::secret(&endpoint, action).unwrap();
        let decision = authorize(&request, [&subtree]);
        assert!(!decision.allow);
        assert_eq!(decision.deny_reason, Some(DenyReason::PrefixBoundaryMiss));
    }

    let equal = parse_raw_target(&Method::GET, "/v1/kv/data/apps/canvas").unwrap();
    let equal_request = AuthorizationRequest::secret(&equal, SecretAction::Read).unwrap();
    assert!(authorize(&equal_request, [&subtree]).allow);

    let explicit_current =
        parse_raw_target(&Method::GET, "/v1/kv/data/apps/canvas?version=7").unwrap();
    let history = AuthorizationRequest::secret(&explicit_current, SecretAction::Read).unwrap();
    assert_eq!(history.capability, Capability::SecretReadHistory);
    assert_eq!(
        authorize(&history, [&subtree]).deny_reason,
        Some(DenyReason::MissingCapability)
    );

    let destroy = parse_raw_target(&Method::POST, "/v1/kv/destroy/apps/canvas").unwrap();
    let destroy = AuthorizationRequest::secret(&destroy, SecretAction::Destroy).unwrap();
    assert_eq!(
        authorize(&destroy, [&subtree]).deny_reason,
        Some(DenyReason::MissingCapability)
    );

    let root = grant(
        8,
        2,
        "kv",
        GrantScope::Subtree,
        &[],
        &[Capability::SecretList],
    );
    let root_list = parse_raw_target(&Method::GET, "/v1/kv/metadata/?list=true").unwrap();
    let root_list = AuthorizationRequest::secret(&root_list, SecretAction::List).unwrap();
    assert!(authorize(&root_list, [&root]).allow);

    let metadata = parse_raw_target(&Method::GET, "/v1/kv/metadata/apps/canvas").unwrap();
    assert_eq!(
        AuthorizationRequest::secret(&metadata, SecretAction::Destroy),
        Err(IdentityError::InvalidRequestShape)
    );
    let local_purge = AuthorizationRequest::local_destroy_all(&metadata.resource).unwrap();
    assert_eq!(local_purge.capability, Capability::SecretDestroyAll);
}

#[test]
fn management_capabilities_are_pairwise_separate_and_decisions_are_structured() {
    let identity_manager = GrantRecord::bootstrap_admin([9; 16], [2; 16]).unwrap();
    let only_audit_read = grant(
        10,
        2,
        MANAGEMENT_MOUNT,
        GrantScope::Exact,
        &[],
        &[Capability::AuditRead],
    );
    for capability in [
        Capability::AuditExport,
        Capability::AuditCheckpointManage,
        Capability::Backup,
        Capability::BackupRecipientManage,
        Capability::Diagnostics,
        Capability::StoreMaintenance,
        Capability::KeyRotation,
        Capability::TransportManage,
        Capability::CredentialIssue,
    ] {
        let request = AuthorizationRequest::management(capability).unwrap();
        let denied = authorize(&request, [&only_audit_read]);
        assert!(!denied.allow);
        assert_eq!(denied.resource.mount, MANAGEMENT_MOUNT);
        assert_eq!(denied.deny_reason, Some(DenyReason::MissingCapability));
        assert!(authorize(&request, [&identity_manager]).allow);
    }
    let read = AuthorizationRequest::management(Capability::AuditRead).unwrap();
    let allowed = authorize(&read, [&only_audit_read]);
    assert!(allowed.allow);
    assert_eq!(allowed.matched_grant, Some([10; 16]));
    assert_eq!(allowed.deny_reason, None);
}

#[test]
fn identity_and_grant_codecs_macs_lifecycle_and_catalog_fail_closed() {
    let key = [0x44; 32];
    let store_id = StoreId([0x55; 16]);
    let original_identity = identity(1, "alice");
    let mut edited_identity = original_identity.clone();
    edited_identity.name = "mallory".into();
    assert!(
        mac_conformance(
            &original_identity,
            &edited_identity,
            1,
            &key,
            store_id,
            &original_identity.id,
        )
        .unwrap()
        .passed()
    );
    let encoded = original_identity.encode().unwrap();
    assert_eq!(IdentityRecord::decode(&encoded).unwrap(), original_identity);
    strict_record_negatives::<IdentityRecord>(&encoded);

    let original_grant = grant(
        2,
        1,
        "kv",
        GrantScope::Exact,
        &["apps", "canvas"],
        &[Capability::SecretReadCurrent],
    );
    let mut edited_grant = original_grant.clone();
    edited_grant.capabilities.insert(Capability::SecretDestroy);
    assert!(
        mac_conformance(
            &original_grant,
            &edited_grant,
            1,
            &key,
            store_id,
            &original_grant.id,
        )
        .unwrap()
        .passed()
    );
    let encoded = original_grant.encode().unwrap();
    assert_eq!(GrantRecord::decode(&encoded).unwrap(), original_grant);
    strict_record_negatives::<GrantRecord>(&encoded);

    assert_eq!(
        original_identity.retire(2),
        Err(IdentityError::StaleGeneration)
    );
    assert_eq!(
        original_grant.remove([9; 16], 1),
        Err(IdentityError::WrongOwner)
    );
    let removed = original_grant.remove([1; 16], 1).unwrap();
    assert_eq!(removed.status, GrantStatus::Removed);
    assert_eq!(removed.generation, 2);

    let retired_alice = original_identity.retire(1).unwrap();
    let reused_alice = identity(3, "alice");
    assert_eq!(
        validate_catalog(&[retired_alice, reused_alice], &[]),
        Err(IdentityError::DuplicateIdentity)
    );
    assert_eq!(
        validate_catalog(
            &[original_identity],
            &[grant(
                4,
                9,
                "kv",
                GrantScope::Subtree,
                &[],
                &[Capability::SecretList]
            )]
        ),
        Err(IdentityError::WrongOwner)
    );
}

#[test]
fn fresh_init_atomically_stages_bootstrap_identity_and_expanded_admin_grant() {
    let directory = tempfile::tempdir().unwrap();
    let identity_key: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let meta = MetaRecord {
        store_id: StoreId([7; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    };
    let transaction =
        KeyringInitTransaction::prepare(meta.clone(), &identity_key, None, &mut Counter(0))
            .unwrap();
    let store = transaction
        .commit(directory.path().join("store.redb"))
        .unwrap();
    let keyring = KeyringOpener::default()
        .open(
            meta.store_id,
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &identity_key,
        )
        .unwrap();
    let identities = keyring.identity_records(&store).unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].value.name, BOOTSTRAP_IDENTITY_NAME);
    assert_eq!(identities[0].value.kind, IdentityKind::Human);
    let grants = keyring
        .grant_records(&store, identities[0].value.id)
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].value.capabilities,
        CapabilityBundle::AdminV1.expand()
    );
    for capability in [
        Capability::IdentityGrantManage,
        Capability::CredentialIssue,
        Capability::CredentialRevoke,
    ] {
        assert!(
            authorize(
                &AuthorizationRequest::management(capability).unwrap(),
                [&grants[0].value]
            )
            .allow
        );
    }
}

fn strict_record_negatives<T: Canonical + std::fmt::Debug + PartialEq>(encoded: &[u8]) {
    let mut unknown = encoded.to_vec();
    unknown[1..3].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        T::decode(&unknown),
        Err(CodecError::UnknownVersion)
    ));
    assert!(matches!(
        T::decode(&encoded[..encoded.len() - 1]),
        Err(CodecError::Truncated)
    ));
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(matches!(T::decode(&trailing), Err(CodecError::Trailing)));
}
