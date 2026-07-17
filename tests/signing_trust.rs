use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};

use ed25519_dalek::SigningKey;
use ops_light_secrets_server::store::keyring::{KeyringError, RandomSource};
use ops_light_secrets_server::store::{
    CHECKPOINT_PUBLIC_KEY_WARNING, Canonical, DescriptorDisposition, MAX_CHECKPOINT_PUBLIC_KEYS,
    SignableDomain, SigningContext, SigningEnrollmentRequest, SigningKeyCandidate, SigningKeyState,
    SigningLineage, SigningRotationPrepareRequest, SigningTrustCatalog, SigningTrustError, StoreId,
    enrollment_confirmation, generate_signing_key, sign_signing_transition,
    verify_signing_transition,
};

const STORE: StoreId = StoreId([1; 16]);
const INCARNATION: [u8; 16] = [2; 16];
const EPOCH: [u8; 16] = [3; 16];

fn candidate(private: u8) -> SigningKeyCandidate {
    SigningKeyCandidate::new(
        SigningKey::from_bytes(&[private; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn context(sequence: u64, time: u64) -> SigningContext {
    SigningContext {
        store_id: STORE,
        incarnation: INCARNATION,
        audit_epoch: EPOCH,
        sequence,
        head: [u8::try_from(sequence).unwrap_or(255); 32],
        effective_milliseconds: time,
    }
}

fn prepare_request(
    transition_id: [u8; 16],
    new_key: SigningKeyCandidate,
    nonce: [u8; 32],
    expires_at_milliseconds: u64,
    prepare_event_id: [u8; 16],
    context_after_prepare: SigningContext,
) -> SigningRotationPrepareRequest {
    SigningRotationPrepareRequest {
        transition_id,
        new_key,
        expected_generation: 1,
        nonce,
        expires_at_milliseconds,
        prepare_event_id,
        context_after_prepare,
        authorized: true,
    }
}

fn enrolled() -> SigningTrustCatalog {
    let mut catalog = SigningTrustCatalog::new(STORE, INCARNATION, EPOCH).unwrap();
    let key = candidate(10);
    let reason = "initial external checkpoint trust";
    let confirmation = enrollment_confirmation(STORE, &key, reason).unwrap();
    catalog
        .enroll(SigningEnrollmentRequest {
            candidate: key,
            fingerprint: key.id,
            reason,
            confirmation,
            custody_attested: true,
            context: context(1, 100),
            authorized: true,
        })
        .unwrap();
    catalog
}

#[test]
fn candidate_and_lineage_codecs_are_canonical_bounded_and_public_only() {
    let candidate = candidate(10);
    let encoded = candidate.encode().unwrap();
    assert_eq!(SigningKeyCandidate::decode(&encoded).unwrap(), candidate);
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(SigningKeyCandidate::decode(&trailing).is_err());

    let catalog = enrolled();
    let lineage = catalog.lineage();
    assert_eq!(lineage.entries.len(), 1);
    assert_eq!(lineage.current().unwrap().state, SigningKeyState::Current);
    let encoded = lineage.encode().unwrap();
    assert_eq!(SigningLineage::decode(&encoded).unwrap(), *lineage);
    assert_eq!(MAX_CHECKPOINT_PUBLIC_KEYS, 16);
    assert_eq!(CHECKPOINT_PUBLIC_KEY_WARNING, 12);
    assert!(!format!("{lineage:?}").contains("private"));
}

#[test]
fn enrollment_is_exactly_once_and_binds_fingerprint_reason_confirmation_and_custody() {
    let key = candidate(10);
    let reason = "initial trust";
    let confirmation = enrollment_confirmation(STORE, &key, reason).unwrap();
    for (fingerprint, confirmation, custody, authorized) in [
        ([9; 16], confirmation, true, true),
        (key.id, [9; 32], true, true),
        (key.id, confirmation, false, true),
        (key.id, confirmation, true, false),
    ] {
        let mut catalog = SigningTrustCatalog::new(STORE, INCARNATION, EPOCH).unwrap();
        assert_eq!(
            catalog.enroll(SigningEnrollmentRequest {
                candidate: key,
                fingerprint,
                reason,
                confirmation,
                custody_attested: custody,
                context: context(1, 100),
                authorized,
            }),
            Err(SigningTrustError::Denied)
        );
    }
    let mut catalog = enrolled();
    assert!(
        catalog
            .enroll(SigningEnrollmentRequest {
                candidate: key,
                fingerprint: key.id,
                reason,
                confirmation,
                custody_attested: true,
                context: context(2, 110),
                authorized: true,
            })
            .is_err()
    );
}

#[test]
fn noncyclic_prepare_old_sign_and_activation_make_b_current_idempotently() {
    let mut catalog = enrolled();
    let transition = catalog
        .prepare_rotation(prepare_request(
            [20; 16],
            candidate(11),
            [21; 32],
            1_000,
            [22; 16],
            context(2, 200),
        ))
        .unwrap();
    assert_eq!(transition.prepared_head, context(2, 200).head);
    let mut old_private = [10; 32];
    let signed = sign_signing_transition(transition.clone(), &mut old_private).unwrap();
    assert_eq!(old_private, [0; 32]);
    assert_eq!(
        verify_signing_transition(&signed, &candidate(10)).unwrap(),
        transition.digest().unwrap()
    );
    let digest = catalog
        .register_rotation(&signed, context(3, 300), true, true)
        .unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/signing-trust-v1.json")).unwrap();
    assert_eq!(hex(&candidate(10).encode().unwrap()), fixture["candidate"]);
    assert_eq!(hex(&transition.encode().unwrap()), fixture["transition"]);
    assert_eq!(hex(&signed.encode().unwrap()), fixture["signed"]);
    assert_eq!(hex(&digest), fixture["digest"]);
    assert_eq!(
        hex(&catalog.lineage().encode().unwrap()),
        fixture["lineage"]
    );
    assert_eq!(
        catalog.register_rotation(&signed, context(3, 300), true, true),
        Ok(digest)
    );
    assert_eq!(catalog.lineage().entries[0].state, SigningKeyState::Retired);
    assert_eq!(
        catalog.lineage().current().unwrap().candidate,
        candidate(11)
    );
    assert!(catalog.lineage().transition_registered_checkpoint_pending);
}

#[test]
fn first_b_checkpoint_covers_activation_and_clears_pending_while_a_history_verifies() {
    let mut catalog = enrolled();
    let transition = catalog
        .prepare_rotation(prepare_request(
            [20; 16],
            candidate(11),
            [21; 32],
            1_000,
            [22; 16],
            context(2, 200),
        ))
        .unwrap();
    let mut old_private = [10; 32];
    let signed = sign_signing_transition(transition, &mut old_private).unwrap();
    catalog
        .register_rotation(&signed, context(3, 300), true, true)
        .unwrap();
    let descriptor = catalog
        .create_descriptor([30; 16], SignableDomain::AuditCheckpoint, [31; 32])
        .unwrap();
    assert_eq!(descriptor.signing_key_id, candidate(11).id);
    assert_eq!(
        descriptor.transition_digest,
        Some(signed.transition.digest().unwrap())
    );
    catalog
        .resolve_descriptor([30; 16], DescriptorDisposition::Registered, 4)
        .unwrap();
    assert!(!catalog.lineage().transition_registered_checkpoint_pending);
    assert!(verify_signing_transition(&signed, &candidate(10)).is_ok());
}

#[test]
fn descriptor_creation_races_are_deterministic_and_inventory_is_domain_bounded() {
    let mut blocked = enrolled();
    let old_descriptor = blocked
        .create_descriptor([40; 16], SignableDomain::BackupManifest, [41; 32])
        .unwrap();
    let inventory = blocked.outstanding_for(old_descriptor.signing_key_id);
    assert_eq!(inventory.counts[&SignableDomain::BackupManifest], 1);
    assert_eq!(inventory.digests, [[41; 32]]);
    assert!(
        blocked
            .prepare_rotation(prepare_request(
                [20; 16],
                candidate(11),
                [21; 32],
                1_000,
                [22; 16],
                context(2, 200),
            ))
            .is_err()
    );
    blocked
        .resolve_descriptor([40; 16], DescriptorDisposition::Abandoned, 2)
        .unwrap();
    assert!(
        blocked
            .outstanding_for(old_descriptor.signing_key_id)
            .is_empty()
    );

    let mut switched = enrolled();
    let transition = switched
        .prepare_rotation(prepare_request(
            [20; 16],
            candidate(11),
            [21; 32],
            1_000,
            [22; 16],
            context(2, 200),
        ))
        .unwrap();
    let mut private = [10; 32];
    let signed = sign_signing_transition(transition, &mut private).unwrap();
    switched
        .register_rotation(&signed, context(3, 300), true, true)
        .unwrap();
    assert_eq!(
        switched
            .create_descriptor([42; 16], SignableDomain::AuditExport, [43; 32])
            .unwrap()
            .signing_key_id,
        candidate(11).id
    );
}

#[test]
fn stale_fork_expiry_tamper_and_competing_prepares_fail_without_partial_switch() {
    let mut catalog = enrolled();
    let first = catalog
        .prepare_rotation(prepare_request(
            [20; 16],
            candidate(11),
            [21; 32],
            250,
            [22; 16],
            context(2, 200),
        ))
        .unwrap();
    let second = catalog
        .prepare_rotation(prepare_request(
            [23; 16],
            candidate(12),
            [24; 32],
            1_000,
            [25; 16],
            context(3, 210),
        ))
        .unwrap();
    let mut private = [10; 32];
    let first = sign_signing_transition(first, &mut private).unwrap();
    assert!(
        catalog
            .register_rotation(&first, context(4, 300), true, true)
            .is_err()
    );
    let mut private = [10; 32];
    let mut second = sign_signing_transition(second, &mut private).unwrap();
    second.signature[0] ^= 1;
    assert!(
        catalog
            .register_rotation(&second, context(4, 300), true, true)
            .is_err()
    );
    assert_eq!(
        catalog.lineage().current().unwrap().candidate,
        candidate(10)
    );
    let mut fork = context(4, 220);
    fork.incarnation = [99; 16];
    assert!(
        catalog
            .register_rotation(&second, fork, true, true)
            .is_err()
    );
}

#[test]
fn multiple_rotations_preserve_old_verification_and_hard_limit_refuses_before_mutation() {
    let mut catalog = enrolled();
    let mut signed_history = Vec::new();
    for generation in 1..MAX_CHECKPOINT_PUBLIC_KEYS as u64 {
        let private_byte = u8::try_from(9 + generation).unwrap();
        let next_byte = private_byte + 1;
        let prepare_sequence = generation * 2;
        let transition = catalog
            .prepare_rotation(SigningRotationPrepareRequest {
                transition_id: [u8::try_from(30 + generation).unwrap(); 16],
                new_key: candidate(next_byte),
                expected_generation: generation,
                nonce: [u8::try_from(60 + generation).unwrap(); 32],
                expires_at_milliseconds: 10_000,
                prepare_event_id: [u8::try_from(90 + generation).unwrap(); 16],
                context_after_prepare: context(prepare_sequence, 100 + prepare_sequence),
                authorized: true,
            })
            .unwrap();
        let mut private = [private_byte; 32];
        let signed = sign_signing_transition(transition, &mut private).unwrap();
        catalog
            .register_rotation(
                &signed,
                context(prepare_sequence + 1, 101 + prepare_sequence),
                true,
                true,
            )
            .unwrap();
        signed_history.push((signed, candidate(private_byte)));
    }
    assert_eq!(catalog.lineage().entries.len(), MAX_CHECKPOINT_PUBLIC_KEYS);
    assert!(catalog.lineage().warning());
    for (signed, old) in &signed_history {
        verify_signing_transition(signed, old).unwrap();
    }
    let before = catalog.lineage().clone();
    assert!(
        catalog
            .prepare_rotation(SigningRotationPrepareRequest {
                transition_id: [120; 16],
                new_key: candidate(26),
                expected_generation: MAX_CHECKPOINT_PUBLIC_KEYS as u64,
                nonce: [121; 32],
                expires_at_milliseconds: 20_000,
                prepare_event_id: [122; 16],
                context_after_prepare: context(40, 1_000),
                authorized: true,
            })
            .is_err()
    );
    assert_eq!(catalog.lineage(), &before);
}

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

struct ShortSink {
    socket: std::os::unix::net::UnixStream,
    remaining: usize,
}

impl Write for ShortSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short sink"));
        }
        let count = bytes.len().min(self.remaining);
        self.remaining -= count;
        self.socket.write(&bytes[..count])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl AsFd for ShortSink {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

#[test]
fn stateless_generation_discloses_private_only_to_validated_sink_and_handles_short_write() {
    let (socket, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let metadata = generate_signing_key(
        &mut ShortSink {
            socket,
            remaining: 32,
        },
        &mut Counter(0),
    )
    .unwrap();
    let mut private = [0; 32];
    std::io::Read::read_exact(&mut reader, &mut private).unwrap();
    assert_eq!(private, [1; 32]);
    assert_eq!(metadata.algorithm, "ed25519");
    assert!(!format!("{metadata:?}").contains(&hex(&private)));

    let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(
        generate_signing_key(
            &mut ShortSink {
                socket,
                remaining: 5,
            },
            &mut Counter(0),
        ),
        Err(SigningTrustError::Disclosure)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
