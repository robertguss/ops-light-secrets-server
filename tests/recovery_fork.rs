use ed25519_dalek::SigningKey;
use ops_light_secrets_server::recovery_fork::{
    ArchiveRecoveryTuple, EvidenceCompleteness, RecoveryForkActivationRequest,
    RecoveryForkAuthority, RecoveryForkError, RollbackEvidence, RollbackTrigger,
    SuppliedCheckpoint, activate_recovery_fork, activation_confirmation, classify_rollback,
};
use ops_light_secrets_server::store::{
    CheckpointDescriptor, CheckpointKeyStatus, CheckpointPublicKey, CheckpointTrust,
    PendingAnchorKind, PendingAnchorStatus, SigningKeyCandidate, SigningKeyLineageEntry,
    SigningKeyState, SigningLineage, StateDigest, StoreId, sign_checkpoint, signing_key_id,
};

const STORE: StoreId = StoreId([1; 16]);
const INCARNATION: [u8; 16] = [2; 16];
const EPOCH: [u8; 16] = [3; 16];

fn checkpoint(
    end: u64,
) -> (
    ops_light_secrets_server::store::CheckpointSignature,
    CheckpointTrust,
    [u8; 16],
) {
    let mut private = [7; 32];
    let public = SigningKey::from_bytes(&private).verifying_key().to_bytes();
    let key_id = signing_key_id(&public);
    let signed = sign_checkpoint(
        CheckpointDescriptor {
            store_id: STORE,
            audit_epoch: EPOCH,
            range_start: 1,
            range_end: end,
            prepare_event_id: [4; 16],
            chain_head: [u8::try_from(end).unwrap(); 32],
            state_digest: StateDigest([5; 32]),
            effective_timestamp_milliseconds: 1_800_000_000_000,
            signing_key_id: key_id,
            signing_lineage_generation: 1,
            signing_transition_digest: None,
            previous_checkpoint_digest: None,
        },
        &mut private,
    )
    .unwrap();
    let trust = CheckpointTrust::new([CheckpointPublicKey {
        id: key_id,
        verifying_key: public,
        status: CheckpointKeyStatus::Initial,
        valid_from_milliseconds: 1_700_000_000_000,
        valid_until_milliseconds: None,
        previous_key_id: None,
    }])
    .unwrap();
    (signed, trust, key_id)
}

fn archive(key_id: [u8; 16]) -> ArchiveRecoveryTuple {
    ArchiveRecoveryTuple {
        store_id: STORE,
        source_incarnation: INCARNATION,
        audit_epoch: EPOCH,
        sequence: 5,
        chain_head: [5; 32],
        state_digest: StateDigest([6; 32]),
        lineage_generation: 1,
        current_signer: key_id,
        trust_root: key_id,
    }
}

fn lineage(root_id: [u8; 16]) -> SigningLineage {
    let root_public = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    assert_eq!(signing_key_id(&root_public), root_id);
    let next =
        SigningKeyCandidate::new(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())
            .unwrap();
    SigningLineage::new(
        vec![
            SigningKeyLineageEntry {
                candidate: SigningKeyCandidate::new(root_public).unwrap(),
                state: SigningKeyState::Retired,
                generation: 1,
                effective_audit_epoch: EPOCH,
                effective_sequence: 1,
                effective_milliseconds: 100,
                retired_sequence: Some(6),
                previous_key_id: None,
                transition_digest: None,
                last_use_sequence: Some(6),
                custody_attested: true,
            },
            SigningKeyLineageEntry {
                candidate: next,
                state: SigningKeyState::Current,
                generation: 2,
                effective_audit_epoch: EPOCH,
                effective_sequence: 6,
                effective_milliseconds: 200,
                retired_sequence: None,
                previous_key_id: Some(root_id),
                transition_digest: Some([9; 32]),
                last_use_sequence: None,
                custody_attested: true,
            },
        ],
        false,
    )
    .unwrap()
}

#[test]
fn checkpoint_lineage_and_withheld_evidence_classify_honestly() {
    let (signed, trust, key_id) = checkpoint(7);
    let archive = archive(key_id);
    let supplied = [SuppliedCheckpoint {
        source_incarnation: INCARNATION,
        checkpoint: &signed,
    }];
    let checkpoint_only = classify_rollback(
        archive,
        RollbackEvidence {
            checkpoint_trust: &trust,
            checkpoints: &supplied,
            lineage_source_incarnation: None,
            lineage: None,
        },
    )
    .unwrap();
    assert_eq!(
        checkpoint_only.triggers,
        vec![RollbackTrigger::NewerCheckpoint]
    );
    assert_eq!(checkpoint_only.missing_anchored_range, Some((6, 7)));

    let lineage = lineage(key_id);
    let no_checkpoints = classify_rollback(
        archive,
        RollbackEvidence {
            checkpoint_trust: &trust,
            checkpoints: &[],
            lineage_source_incarnation: Some(INCARNATION),
            lineage: Some(&lineage),
        },
    )
    .unwrap();
    assert_eq!(
        no_checkpoints.triggers,
        vec![RollbackTrigger::NewerSigningLineage]
    );
    assert_eq!(no_checkpoints.selected_lineage_generation, 2);

    let withheld = classify_rollback(
        archive,
        RollbackEvidence {
            checkpoint_trust: &trust,
            checkpoints: &[],
            lineage_source_incarnation: None,
            lineage: None,
        },
    )
    .unwrap();
    assert!(!withheld.rollback_required);
    assert_eq!(
        withheld.evidence_completeness,
        EvidenceCompleteness::OperatorSupplied
    );
}

#[test]
fn malformed_forked_or_mixed_source_evidence_refuses_instead_of_ignoring() {
    let (mut signed, trust, key_id) = checkpoint(7);
    let archive = archive(key_id);
    signed.signature[0] ^= 1;
    let supplied = [SuppliedCheckpoint {
        source_incarnation: INCARNATION,
        checkpoint: &signed,
    }];
    assert_eq!(
        classify_rollback(
            archive,
            RollbackEvidence {
                checkpoint_trust: &trust,
                checkpoints: &supplied,
                lineage_source_incarnation: None,
                lineage: None
            }
        ),
        Err(RecoveryForkError::Evidence)
    );
    let (signed, trust, _) = checkpoint(7);
    let mixed = [SuppliedCheckpoint {
        source_incarnation: [99; 16],
        checkpoint: &signed,
    }];
    assert_eq!(
        classify_rollback(
            archive,
            RollbackEvidence {
                checkpoint_trust: &trust,
                checkpoints: &mixed,
                lineage_source_incarnation: None,
                lineage: None
            }
        ),
        Err(RecoveryForkError::Inconsistent)
    );
}

#[test]
fn explicit_fork_activation_increments_epochs_once_and_installs_pending_anchor() {
    let (signed, trust, key_id) = checkpoint(7);
    let archive = archive(key_id);
    let supplied = [SuppliedCheckpoint {
        source_incarnation: INCARNATION,
        checkpoint: &signed,
    }];
    let classification = classify_rollback(
        archive,
        RollbackEvidence {
            checkpoint_trust: &trust,
            checkpoints: &supplied,
            lineage_source_incarnation: None,
            lineage: None,
        },
    )
    .unwrap();
    let reason = "canonical source retired after rollback discovery";
    let confirmation = activation_confirmation(
        archive,
        &classification,
        [10; 32],
        [11; 16],
        [12; 16],
        reason,
    );
    let make = |start, authority, credential_epoch, audit_epoch, confirmation| {
        RecoveryForkActivationRequest {
            archive,
            classification: &classification,
            start_recovery_epoch: start,
            reason,
            assertion_digest: [10; 32],
            archive_digest: [13; 32],
            container_digest: [14; 32],
            signature_digest: [15; 32],
            actor_id: [11; 16],
            installed_state_digest: StateDigest([16; 32]),
            expected_credential_epoch: credential_epoch,
            expected_audit_epoch: audit_epoch,
            new_incarnation: [12; 16],
            authority,
            confirmation,
        }
    };
    let authority = RecoveryForkAuthority {
        restore_authorized: true,
        source_decommissioned: true,
        rpo_asserted: true,
        target_and_recipient_revalidated: true,
        current_signer_possession_proved: true,
    };
    assert_eq!(
        activate_recovery_fork(make(false, authority, 8, 9, confirmation)),
        Err(RecoveryForkError::RollbackRefused)
    );
    let activated = activate_recovery_fork(make(true, authority, 8, 9, confirmation)).unwrap();
    assert_eq!((activated.credential_epoch, activated.audit_epoch), (9, 10));
    assert_eq!(
        activated.pending_anchor.kind,
        PendingAnchorKind::RollbackFork
    );
    assert_eq!(
        activated.pending_anchor.status,
        PendingAnchorStatus::Installed
    );
    assert_eq!(activated.genesis.missing_anchored_range, Some((6, 7)));
    assert_eq!(
        activate_recovery_fork(make(
            true,
            RecoveryForkAuthority {
                current_signer_possession_proved: false,
                ..authority
            },
            8,
            9,
            confirmation
        )),
        Err(RecoveryForkError::Unauthorized)
    );
    assert_eq!(
        activate_recovery_fork(make(true, authority, u64::MAX, 9, confirmation)),
        Err(RecoveryForkError::Overflow)
    );
}
