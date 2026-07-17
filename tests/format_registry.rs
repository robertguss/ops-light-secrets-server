use std::collections::BTreeSet;

use ops_light_secrets_server::backup_format::RecoveryEventType;
use ops_light_secrets_server::format_registry::{
    ArtifactDomain, EvidenceCompleteness, FORMAT_REGISTRY, FrozenFormat, MaintenanceOperation,
    MaintenancePreflight, OutputPublication, PublicationState, RecoveryActivation,
    SignerEligibility, artifact_digest, verify_format_entries, verify_format_registry,
};
use ops_light_secrets_server::store::{Canonical, CodecError, StoreId};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/format-freeze-v1.json")).unwrap()
}

fn signer() -> SignerEligibility {
    SignerEligibility {
        domain: ArtifactDomain::BackupManifest,
        creator_epoch: [0x11; 16],
        creator_sequence: 17,
        creator_head: [0x12; 32],
        lineage_generation: 2,
        transition_digest: Some([0x13; 32]),
        expected_signer_id: [0x14; 16],
    }
}

fn maintenance() -> MaintenancePreflight {
    MaintenancePreflight {
        store_incarnation: [0x21; 16],
        audit_epoch: [0x22; 16],
        checkpoint_sequence: 40,
        head_sequence: 43,
        head_digest: [0x23; 32],
        tail_digest: [0x24; 32],
        state_digest_at_checkpoint: [0x25; 32],
        operations: vec![
            MaintenanceOperation::BackupOutput,
            MaintenanceOperation::ClockWatermark,
            MaintenanceOperation::CleanShutdown,
        ],
    }
}

fn publication() -> OutputPublication {
    OutputPublication {
        domain: ArtifactDomain::BackupManifest,
        opaque_output_id: [0x31; 16],
        owner: b"fixture-owner".to_vec(),
        header_digest: [0x32; 32],
        content_digest: [0x33; 32],
        target_identity_digest: [0x34; 32],
        artifact_digest: [0x35; 32],
        inner_manifest_digest: [0x36; 32],
        signer_id: [0x37; 16],
        lineage_generation: 3,
        created_sequence: 44,
        state: PublicationState::Publishing,
        file_identity_digest: None,
        parent_fsync_sequence: None,
        abandonment_digest: None,
    }
}

fn recovery() -> RecoveryActivation {
    RecoveryActivation {
        store_id: StoreId([0x41; 16]),
        source_incarnation: [0x42; 16],
        target_incarnation: [0x43; 16],
        archive_epoch: 5,
        archive_sequence: 99,
        archive_head: [0x44; 32],
        claimed_decommissioned: true,
        source_observation_digest: [0x45; 32],
        unarchived_tail_digest: Some([0x46; 32]),
        rpo_acknowledgment_digest: [0x47; 32],
        checkpoint_set_digest: [0x48; 32],
        trust_evidence_digest: [0x49; 32],
        imported_lineage_digest: Some([0x4a; 32]),
        imported_lineage_generation: Some(4),
        imported_current_signer: Some([0x4b; 16]),
        recipient_binding_digest: [0x4c; 32],
        assertion_digest: [0x4d; 32],
        completeness: EvidenceCompleteness::Complete,
        recovery_fork: true,
    }
}

#[test]
fn registry_is_unique_complete_owned_and_matches_manifest() {
    verify_format_registry().unwrap();
    let fixture = fixture();
    let entries = fixture["formats"].as_array().unwrap();
    assert_eq!(entries.len(), FORMAT_REGISTRY.len());
    for (actual, frozen) in entries.iter().zip(FORMAT_REGISTRY) {
        assert_eq!(actual["id"], frozen.id);
        assert_eq!(actual["name"], frozen.name);
        assert_eq!(actual["version"], frozen.version);
        assert_eq!(actual["domain"], frozen.domain);
        assert_eq!(actual["owner"], frozen.owner);
        assert_eq!(actual["vector"], frozen.vector);
    }
    assert_eq!(RecoveryEventType::EmergencyCredentialIssued as u16, 10);
    assert_eq!(
        RecoveryEventType::ALL
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
        RecoveryEventType::ALL.len()
    );
    for event in RecoveryEventType::ALL {
        assert_eq!(
            RecoveryEventType::decode(&event.encode().unwrap()).unwrap(),
            event
        );
    }
    assert_eq!(
        RecoveryEventType::decode(&[1, 0, 11]),
        Err(CodecError::Invalid)
    );

    let mutations: [fn(&mut FrozenFormat); 6] = [
        |entry: &mut _| entry.id = 0,
        |entry: &mut _| entry.id = 0x8000,
        |entry: &mut _| entry.name = "",
        |entry: &mut _| entry.domain = "",
        |entry: &mut _| entry.owner = "",
        |entry: &mut _| entry.vector = "",
    ];
    for mutation in mutations {
        let mut entries = FORMAT_REGISTRY;
        mutation(&mut entries[0]);
        assert_eq!(verify_format_entries(&entries), Err(CodecError::Invalid));
    }
    let mut duplicate_id = FORMAT_REGISTRY;
    duplicate_id[1].id = duplicate_id[0].id;
    assert_eq!(
        verify_format_entries(&duplicate_id),
        Err(CodecError::Invalid)
    );
    let mut duplicate_domain = FORMAT_REGISTRY;
    duplicate_domain[1].domain = duplicate_domain[0].domain;
    assert_eq!(
        verify_format_entries(&duplicate_domain),
        Err(CodecError::Invalid)
    );
}

#[test]
fn signer_eligibility_freezes_domain_lineage_and_current_key() {
    let value = signer();
    let bytes = value.encode().unwrap();
    assert_eq!(hex(&bytes), fixture()["signer_eligibility_hex"]);
    assert_eq!(SignerEligibility::decode(&bytes).unwrap(), value);
    for domain in [
        ArtifactDomain::Checkpoint,
        ArtifactDomain::BackupManifest,
        ArtifactDomain::AuditExport,
        ArtifactDomain::RecoveryReceipt,
    ] {
        let mut candidate = value;
        candidate.domain = domain;
        assert_eq!(
            SignerEligibility::decode(&candidate.encode().unwrap()).unwrap(),
            candidate
        );
    }
    let mut missing_transition = value;
    missing_transition.transition_digest = None;
    assert_eq!(missing_transition.encode(), Err(CodecError::Invalid));
    strict_negative::<SignerEligibility>(&bytes);
}

#[test]
fn maintenance_preflight_accepts_only_closed_operational_allowlist() {
    let value = maintenance();
    let bytes = value.encode().unwrap();
    assert_eq!(hex(&bytes), fixture()["maintenance_preflight_hex"]);
    assert_eq!(MaintenancePreflight::decode(&bytes).unwrap(), value);
    let mut count_mismatch = value;
    count_mismatch.head_sequence += 1;
    assert_eq!(count_mismatch.encode(), Err(CodecError::Invalid));
    let mut forbidden = bytes.clone();
    let last = forbidden.len() - 1;
    forbidden[last] = 8;
    assert_eq!(
        MaintenancePreflight::decode(&forbidden),
        Err(CodecError::Invalid)
    );
    strict_negative::<MaintenancePreflight>(&bytes);
}

#[test]
fn publication_state_machine_is_forward_only_and_identity_bound() {
    let mut value = publication();
    let bytes = value.encode().unwrap();
    assert_eq!(hex(&bytes), fixture()["output_publication_hex"]);
    assert_eq!(OutputPublication::decode(&bytes).unwrap(), value);
    value.publish([0x61; 32], 45).unwrap();
    assert_eq!(
        OutputPublication::decode(&value.encode().unwrap()).unwrap(),
        value
    );
    assert!(value.publish([0x62; 32], 46).is_err());
    value.abandon([0x63; 32]).unwrap();
    assert!(value.publish([0x64; 32], 47).is_err());
    assert!(value.abandon([0x65; 32]).is_err());
    let mut wrong_domain = publication();
    wrong_domain.domain = ArtifactDomain::Checkpoint;
    assert_eq!(wrong_domain.encode(), Err(CodecError::Invalid));
    strict_negative::<OutputPublication>(&bytes);
}

#[test]
fn canonical_artifact_identity_separates_domain_header_and_payload() {
    let digest = artifact_digest(
        ArtifactDomain::BackupManifest,
        b"fixture-signing-header",
        [0x55; 32],
    );
    assert_eq!(hex(&digest), fixture()["artifact_digest_hex"]);
    assert_ne!(
        digest,
        artifact_digest(
            ArtifactDomain::AuditExport,
            b"fixture-signing-header",
            [0x55; 32]
        )
    );
    assert_ne!(
        digest,
        artifact_digest(ArtifactDomain::BackupManifest, b"other", [0x55; 32])
    );
    assert_ne!(
        digest,
        artifact_digest(
            ArtifactDomain::BackupManifest,
            b"fixture-signing-header",
            [0x56; 32]
        )
    );
}

#[test]
fn recovery_activation_forbids_silent_trust_import_on_normal_restore() {
    let fork = recovery();
    let bytes = fork.encode().unwrap();
    assert_eq!(hex(&bytes), fixture()["recovery_activation_hex"]);
    assert_eq!(RecoveryActivation::decode(&bytes).unwrap(), fork);
    let mut normal = fork.clone();
    normal.recovery_fork = false;
    normal.imported_lineage_digest = None;
    normal.imported_lineage_generation = None;
    normal.imported_current_signer = None;
    assert_eq!(
        RecoveryActivation::decode(&normal.encode().unwrap()).unwrap(),
        normal
    );
    normal.imported_lineage_digest = Some([0x70; 32]);
    assert_eq!(normal.encode(), Err(CodecError::Invalid));
    let mut partial = fork;
    partial.imported_current_signer = None;
    assert_eq!(partial.encode(), Err(CodecError::Invalid));
    strict_negative::<RecoveryActivation>(&bytes);
}

fn strict_negative<T: Canonical + std::fmt::Debug + PartialEq>(bytes: &[u8]) {
    let mut unknown = bytes.to_vec();
    unknown[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(T::decode(&unknown), Err(CodecError::UnknownVersion));
    assert!(matches!(
        T::decode(&bytes[..bytes.len() - 1]),
        Err(CodecError::Truncated)
    ));
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(T::decode(&trailing), Err(CodecError::Trailing));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
