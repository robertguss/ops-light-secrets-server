use ops_light_secrets_server::format_registry::{
    ArtifactDomain, EvidenceCompleteness, FORMAT_REGISTRY, MaintenanceOperation,
    MaintenancePreflight, OutputPublication, PublicationState, RecoveryActivation,
    SignerEligibility, artifact_digest,
};
use ops_light_secrets_server::store::{Canonical, StoreId};
use serde_json::json;

fn main() {
    let signer = SignerEligibility {
        domain: ArtifactDomain::BackupManifest,
        creator_epoch: [0x11; 16],
        creator_sequence: 17,
        creator_head: [0x12; 32],
        lineage_generation: 2,
        transition_digest: Some([0x13; 32]),
        expected_signer_id: [0x14; 16],
    };
    let maintenance = MaintenancePreflight {
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
    };
    let publication = OutputPublication {
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
    };
    let recovery = RecoveryActivation {
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
    };
    let registry = FORMAT_REGISTRY
        .iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "name": entry.name,
                "version": entry.version,
                "domain": entry.domain,
                "owner": entry.owner,
                "vector": entry.vector,
            })
        })
        .collect::<Vec<_>>();
    let payload_digest = [0x55; 32];
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": 1,
            "generator": "examples/format_fixture_generator.rs@v1",
            "byte_order": "network-big-endian",
            "formats": registry,
            "signer_eligibility_hex": hex(&signer.encode().unwrap()),
            "maintenance_preflight_hex": hex(&maintenance.encode().unwrap()),
            "output_publication_hex": hex(&publication.encode().unwrap()),
            "recovery_activation_hex": hex(&recovery.encode().unwrap()),
            "artifact_digest_hex": hex(&artifact_digest(
                ArtifactDomain::BackupManifest,
                b"fixture-signing-header",
                payload_digest,
            )),
            "negative_cases": [
                "duplicate-format-id", "duplicate-format-domain", "missing-owner",
                "missing-vector", "durable-table-without-backup-codec",
                "unknown-version", "unknown-artifact-domain", "retired-signer-registration",
                "missing-transition-digest", "maintenance-forbidden-delta",
                "maintenance-tail-count-mismatch", "publication-backward-transition",
                "publication-byte-substitution", "publication-target-substitution",
                "publication-after-abandon", "normal-restore-trust-import",
                "partial-fork-import", "truncated", "trailing-bytes"
            ]
        }))
        .unwrap()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
