//! Public-only signing trust lineage and external rollover ceremony.

use super::codec::{Decoder, Encoder};
use super::keyring::{KeyringError, RandomSource};
use super::{Canonical, CodecError, StoreId, signing_key_id};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const SIGNING_KEY_CANDIDATE_VERSION: u16 = 1;
pub const SIGNING_LINEAGE_VERSION: u16 = 1;
pub const SIGNING_TRANSITION_VERSION: u16 = 1;
pub const MAX_CHECKPOINT_PUBLIC_KEYS: usize = 16;
pub const CHECKPOINT_PUBLIC_KEY_WARNING: usize = 12;
pub const MAX_SIGNING_LINEAGE_BYTES: usize = 32 * 1024;
const TRANSITION_DOMAIN: &[u8] = b"ops-light-secrets-server.signing-trust-transition.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SigningKeyState {
    Current = 1,
    Retired = 2,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SignableDomain {
    AuditCheckpoint = 1,
    BackupManifest = 2,
    AuditExport = 3,
    RecoveryReceipt = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DescriptorDisposition {
    Outstanding = 1,
    Registered = 2,
    Abandoned = 3,
    Superseded = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningKeyCandidate {
    pub id: [u8; 16],
    pub verifying_key: [u8; 32],
}

impl SigningKeyCandidate {
    pub fn new(verifying_key: [u8; 32]) -> Result<Self, SigningTrustError> {
        VerifyingKey::from_bytes(&verifying_key).map_err(|_| SigningTrustError::Invalid)?;
        Ok(Self {
            id: signing_key_id(&verifying_key),
            verifying_key,
        })
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.id == [0; 16] || signing_key_id(&self.verifying_key) != self.id {
            return Err(CodecError::Invalid);
        }
        VerifyingKey::from_bytes(&self.verifying_key).map_err(|_| CodecError::Invalid)?;
        Ok(())
    }
}

impl Canonical for SigningKeyCandidate {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(SIGNING_KEY_CANDIDATE_VERSION);
        out.fixed(&self.id);
        out.fixed(&self.verifying_key);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != SIGNING_KEY_CANDIDATE_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            id: input.fixed()?,
            verifying_key: input.fixed()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKeyLineageEntry {
    pub candidate: SigningKeyCandidate,
    pub state: SigningKeyState,
    pub generation: u64,
    pub effective_audit_epoch: [u8; 16],
    pub effective_sequence: u64,
    pub effective_milliseconds: u64,
    pub retired_sequence: Option<u64>,
    pub previous_key_id: Option<[u8; 16]>,
    pub transition_digest: Option<[u8; 32]>,
    pub last_use_sequence: Option<u64>,
    pub custody_attested: bool,
}

impl SigningKeyLineageEntry {
    fn validate(&self) -> Result<(), CodecError> {
        self.candidate.validate()?;
        if self.generation == 0
            || self.effective_audit_epoch == [0; 16]
            || self.effective_sequence == 0
            || self.effective_milliseconds == 0
            || !self.custody_attested
            || self.previous_key_id == Some(self.candidate.id)
            || (self.generation == 1
                && (self.previous_key_id.is_some() || self.transition_digest.is_some()))
            || (self.generation > 1
                && (self.previous_key_id.is_none() || self.transition_digest.is_none()))
            || (self.state == SigningKeyState::Current && self.retired_sequence.is_some())
            || self
                .retired_sequence
                .is_some_and(|value| value < self.effective_sequence)
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningLineage {
    pub entries: Vec<SigningKeyLineageEntry>,
    pub transition_registered_checkpoint_pending: bool,
}

impl SigningLineage {
    pub fn new(
        entries: Vec<SigningKeyLineageEntry>,
        pending: bool,
    ) -> Result<Self, SigningTrustError> {
        let value = Self {
            entries,
            transition_registered_checkpoint_pending: pending,
        };
        value.validate().map_err(|_| SigningTrustError::Invalid)?;
        Ok(value)
    }

    pub fn current(&self) -> Option<&SigningKeyLineageEntry> {
        self.entries
            .iter()
            .find(|entry| entry.state == SigningKeyState::Current)
    }

    pub fn warning(&self) -> bool {
        self.entries.len() >= CHECKPOINT_PUBLIC_KEY_WARNING
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.entries.len() > MAX_CHECKPOINT_PUBLIC_KEYS {
            return Err(CodecError::Limit);
        }
        if !self.entries.is_empty()
            && self
                .entries
                .iter()
                .filter(|entry| entry.state == SigningKeyState::Current)
                .count()
                != 1
        {
            return Err(CodecError::Invalid);
        }
        let mut ids = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if entry.generation != index as u64 + 1 || !ids.insert(entry.candidate.id) {
                return Err(CodecError::Invalid);
            }
            if index == 0 {
                if entry.previous_key_id.is_some() {
                    return Err(CodecError::Invalid);
                }
            } else if entry.previous_key_id != Some(self.entries[index - 1].candidate.id) {
                return Err(CodecError::Invalid);
            }
        }
        Ok(())
    }
}

impl Canonical for SigningLineage {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(SIGNING_LINEAGE_VERSION);
        out.bool(self.transition_registered_checkpoint_pending);
        out.u8(self.entries.len() as u8);
        for entry in &self.entries {
            out.bytes(&encode_entry(entry)?, 512)?;
        }
        let bytes = out.finish();
        if bytes.len() > MAX_SIGNING_LINEAGE_BYTES {
            return Err(CodecError::Limit);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_SIGNING_LINEAGE_BYTES {
            return Err(CodecError::Limit);
        }
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != SIGNING_LINEAGE_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let pending = input.bool()?;
        let count = input.u8()? as usize;
        if count > MAX_CHECKPOINT_PUBLIC_KEYS {
            return Err(CodecError::Limit);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(decode_entry(&input.bytes(512)?)?);
        }
        input.finish()?;
        let value = Self {
            entries,
            transition_registered_checkpoint_pending: pending,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningTransition {
    pub transition_id: [u8; 16],
    pub store_id: StoreId,
    pub incarnation: [u8; 16],
    pub audit_epoch: [u8; 16],
    pub old_key_id: [u8; 16],
    pub new_key: SigningKeyCandidate,
    pub prepared_head: [u8; 32],
    pub prepare_event_id: [u8; 16],
    pub prepare_sequence: u64,
    pub previous_registered_checkpoint: Option<[u8; 32]>,
    pub expected_generation: u64,
    pub nonce: [u8; 32],
    pub expires_at_milliseconds: u64,
}

impl SigningTransition {
    fn validate(&self) -> Result<(), CodecError> {
        self.new_key.validate()?;
        if self.transition_id == [0; 16]
            || self.store_id.0 == [0; 16]
            || self.incarnation == [0; 16]
            || self.audit_epoch == [0; 16]
            || self.old_key_id == [0; 16]
            || self.old_key_id == self.new_key.id
            || self.prepared_head == [0; 32]
            || self.prepare_event_id == [0; 16]
            || self.prepare_sequence == 0
            || self.expected_generation == 0
            || self.nonce == [0; 32]
            || self.expires_at_milliseconds == 0
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SigningTrustError> {
        let encoded = self.encode()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(TRANSITION_DOMAIN);
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl Canonical for SigningTransition {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(SIGNING_TRANSITION_VERSION);
        out.fixed(&self.transition_id);
        out.fixed(&self.store_id.0);
        out.fixed(&self.incarnation);
        out.fixed(&self.audit_epoch);
        out.fixed(&self.old_key_id);
        out.bytes(&self.new_key.encode()?, 128)?;
        out.fixed(&self.prepared_head);
        out.fixed(&self.prepare_event_id);
        out.u64(self.prepare_sequence);
        encode_optional_fixed(&mut out, self.previous_registered_checkpoint.as_ref());
        out.u64(self.expected_generation);
        out.fixed(&self.nonce);
        out.u64(self.expires_at_milliseconds);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != SIGNING_TRANSITION_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            transition_id: input.fixed()?,
            store_id: StoreId(input.fixed()?),
            incarnation: input.fixed()?,
            audit_epoch: input.fixed()?,
            old_key_id: input.fixed()?,
            new_key: SigningKeyCandidate::decode(&input.bytes(128)?)?,
            prepared_head: input.fixed()?,
            prepare_event_id: input.fixed()?,
            prepare_sequence: input.u64()?,
            previous_registered_checkpoint: decode_optional_fixed(&mut input)?,
            expected_generation: input.u64()?,
            nonce: input.fixed()?,
            expires_at_milliseconds: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSigningTransition {
    pub transition: SigningTransition,
    pub signature: [u8; 64],
}

impl Canonical for SignedSigningTransition {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.bytes(&self.transition.encode()?, 1024)?;
        out.fixed(&self.signature);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            transition: SigningTransition::decode(&input.bytes(1024)?)?,
            signature: input.fixed()?,
        };
        input.finish()?;
        Ok(value)
    }
}

pub fn sign_signing_transition(
    transition: SigningTransition,
    private_key: &mut [u8; 32],
) -> Result<SignedSigningTransition, SigningTrustError> {
    let signing = SigningKey::from_bytes(private_key);
    if signing_key_id(&signing.verifying_key().to_bytes()) != transition.old_key_id {
        private_key.zeroize();
        return Err(SigningTrustError::Trust);
    }
    let message = transition_message(&transition)?;
    let signature = signing.sign(&message).to_bytes();
    private_key.zeroize();
    Ok(SignedSigningTransition {
        transition,
        signature,
    })
}

pub fn verify_signing_transition(
    signed: &SignedSigningTransition,
    old_key: &SigningKeyCandidate,
) -> Result<[u8; 32], SigningTrustError> {
    if old_key.id != signed.transition.old_key_id {
        return Err(SigningTrustError::Trust);
    }
    VerifyingKey::from_bytes(&old_key.verifying_key)
        .map_err(|_| SigningTrustError::Trust)?
        .verify(
            &transition_message(&signed.transition)?,
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| SigningTrustError::Signature)?;
    signed.transition.digest()
}

pub fn write_signed_transition_atomic(
    path: &Path,
    signed: &SignedSigningTransition,
) -> Result<(), SigningTrustError> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(SigningTrustError::Disclosure);
    }
    let parent = path.parent().ok_or(SigningTrustError::Disclosure)?;
    let name = path
        .file_name()
        .ok_or(SigningTrustError::Disclosure)?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| SigningTrustError::Disclosure)?;
        file.write_all(&signed.encode()?)
            .and_then(|()| file.sync_all())
            .map_err(|_| SigningTrustError::Disclosure)?;
        std::fs::rename(&temporary, path).map_err(|_| SigningTrustError::Disclosure)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| SigningTrustError::Disclosure)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignableDescriptor {
    pub id: [u8; 16],
    pub domain: SignableDomain,
    pub digest: [u8; 32],
    pub signing_key_id: [u8; 16],
    pub lineage_generation: u64,
    pub transition_digest: Option<[u8; 32]>,
    pub disposition: DescriptorDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutstandingInventory {
    pub counts: BTreeMap<SignableDomain, u32>,
    pub digests: Vec<[u8; 32]>,
}

impl OutstandingInventory {
    pub fn is_empty(&self) -> bool {
        self.counts.values().all(|count| *count == 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningContext {
    pub store_id: StoreId,
    pub incarnation: [u8; 16],
    pub audit_epoch: [u8; 16],
    pub sequence: u64,
    pub head: [u8; 32],
    pub effective_milliseconds: u64,
}

pub struct SigningEnrollmentRequest<'a> {
    pub candidate: SigningKeyCandidate,
    pub fingerprint: [u8; 16],
    pub reason: &'a str,
    pub confirmation: [u8; 32],
    pub custody_attested: bool,
    pub context: SigningContext,
    pub authorized: bool,
}

pub struct SigningRotationPrepareRequest {
    pub transition_id: [u8; 16],
    pub new_key: SigningKeyCandidate,
    pub expected_generation: u64,
    pub nonce: [u8; 32],
    pub expires_at_milliseconds: u64,
    pub prepare_event_id: [u8; 16],
    pub context_after_prepare: SigningContext,
    pub authorized: bool,
}

pub struct SigningTrustCatalog {
    context_store_id: StoreId,
    incarnation: [u8; 16],
    audit_epoch: [u8; 16],
    lineage: SigningLineage,
    prepared: BTreeMap<[u8; 16], SigningTransition>,
    registered_transitions: BTreeMap<[u8; 32], u64>,
    descriptors: BTreeMap<[u8; 16], SignableDescriptor>,
    checkpoint_registered: bool,
    previous_checkpoint: Option<[u8; 32]>,
}

impl SigningTrustCatalog {
    pub fn new(
        store_id: StoreId,
        incarnation: [u8; 16],
        audit_epoch: [u8; 16],
    ) -> Result<Self, SigningTrustError> {
        if store_id.0 == [0; 16] || incarnation == [0; 16] || audit_epoch == [0; 16] {
            return Err(SigningTrustError::Invalid);
        }
        Ok(Self {
            context_store_id: store_id,
            incarnation,
            audit_epoch,
            lineage: SigningLineage::new(Vec::new(), false)?,
            prepared: BTreeMap::new(),
            registered_transitions: BTreeMap::new(),
            descriptors: BTreeMap::new(),
            checkpoint_registered: false,
            previous_checkpoint: None,
        })
    }

    pub fn lineage(&self) -> &SigningLineage {
        &self.lineage
    }

    pub fn enroll(
        &mut self,
        request: SigningEnrollmentRequest<'_>,
    ) -> Result<(), SigningTrustError> {
        self.check_context(request.context)?;
        let expected =
            enrollment_confirmation(self.context_store_id, &request.candidate, request.reason)?;
        if !request.authorized
            || !request.custody_attested
            || !valid_reason(request.reason)
            || request.fingerprint != request.candidate.id
            || request.confirmation != expected
            || !self.lineage.entries.is_empty()
            || self.checkpoint_registered
        {
            return Err(SigningTrustError::Denied);
        }
        self.lineage.entries.push(SigningKeyLineageEntry {
            candidate: request.candidate,
            state: SigningKeyState::Current,
            generation: 1,
            effective_audit_epoch: request.context.audit_epoch,
            effective_sequence: request.context.sequence,
            effective_milliseconds: request.context.effective_milliseconds,
            retired_sequence: None,
            previous_key_id: None,
            transition_digest: None,
            last_use_sequence: None,
            custody_attested: request.custody_attested,
        });
        self.lineage.validate()?;
        Ok(())
    }

    pub fn prepare_rotation(
        &mut self,
        request: SigningRotationPrepareRequest,
    ) -> Result<SigningTransition, SigningTrustError> {
        self.check_context(request.context_after_prepare)?;
        let current = self
            .lineage
            .current()
            .ok_or(SigningTrustError::NotEnrolled)?;
        if !request.authorized
            || self.lineage.entries.len() >= MAX_CHECKPOINT_PUBLIC_KEYS
            || self.lineage.encode()?.len() >= MAX_SIGNING_LINEAGE_BYTES
            || current.generation != request.expected_generation
            || self
                .lineage
                .entries
                .iter()
                .any(|entry| entry.candidate.id == request.new_key.id)
            || request.transition_id == [0; 16]
            || request.nonce == [0; 32]
            || request.expires_at_milliseconds
                <= request.context_after_prepare.effective_milliseconds
            || !self.outstanding_for(current.candidate.id).is_empty()
        {
            return Err(SigningTrustError::Conflict);
        }
        let transition = SigningTransition {
            transition_id: request.transition_id,
            store_id: self.context_store_id,
            incarnation: self.incarnation,
            audit_epoch: self.audit_epoch,
            old_key_id: current.candidate.id,
            new_key: request.new_key,
            prepared_head: request.context_after_prepare.head,
            prepare_event_id: request.prepare_event_id,
            prepare_sequence: request.context_after_prepare.sequence,
            previous_registered_checkpoint: self.previous_checkpoint,
            expected_generation: request.expected_generation,
            nonce: request.nonce,
            expires_at_milliseconds: request.expires_at_milliseconds,
        };
        transition.validate()?;
        if self
            .prepared
            .insert(request.transition_id, transition.clone())
            .is_some()
        {
            return Err(SigningTrustError::Conflict);
        }
        Ok(transition)
    }

    pub fn register_rotation(
        &mut self,
        signed: &SignedSigningTransition,
        context: SigningContext,
        authenticated_descendant: bool,
        authorized: bool,
    ) -> Result<[u8; 32], SigningTrustError> {
        let digest = signed.transition.digest()?;
        if self.registered_transitions.contains_key(&digest) {
            return Ok(digest);
        }
        self.check_context(context)?;
        let current = self
            .lineage
            .current()
            .ok_or(SigningTrustError::NotEnrolled)?
            .clone();
        let prepared = self
            .prepared
            .get(&signed.transition.transition_id)
            .ok_or(SigningTrustError::Conflict)?;
        if !authorized
            || !authenticated_descendant
            || prepared != &signed.transition
            || context.effective_milliseconds > signed.transition.expires_at_milliseconds
            || context.sequence < signed.transition.prepare_sequence
            || current.candidate.id != signed.transition.old_key_id
            || current.generation != signed.transition.expected_generation
            || !self.outstanding_for(current.candidate.id).is_empty()
        {
            return Err(SigningTrustError::Conflict);
        }
        verify_signing_transition(signed, &current.candidate)?;
        let old = self
            .lineage
            .entries
            .last_mut()
            .ok_or(SigningTrustError::NotEnrolled)?;
        old.state = SigningKeyState::Retired;
        old.retired_sequence = Some(context.sequence);
        self.lineage.entries.push(SigningKeyLineageEntry {
            candidate: signed.transition.new_key,
            state: SigningKeyState::Current,
            generation: current.generation + 1,
            effective_audit_epoch: context.audit_epoch,
            effective_sequence: context.sequence,
            effective_milliseconds: context.effective_milliseconds,
            retired_sequence: None,
            previous_key_id: Some(current.candidate.id),
            transition_digest: Some(digest),
            last_use_sequence: None,
            custody_attested: true,
        });
        self.lineage.transition_registered_checkpoint_pending = true;
        self.lineage.validate()?;
        self.registered_transitions.insert(digest, context.sequence);
        Ok(digest)
    }

    pub fn create_descriptor(
        &mut self,
        id: [u8; 16],
        domain: SignableDomain,
        digest: [u8; 32],
    ) -> Result<SignableDescriptor, SigningTrustError> {
        if id == [0; 16] || digest == [0; 32] {
            return Err(SigningTrustError::Invalid);
        }
        let current = self
            .lineage
            .current()
            .ok_or(SigningTrustError::NotEnrolled)?;
        let descriptor = SignableDescriptor {
            id,
            domain,
            digest,
            signing_key_id: current.candidate.id,
            lineage_generation: current.generation,
            transition_digest: current.transition_digest,
            disposition: DescriptorDisposition::Outstanding,
        };
        if self.descriptors.insert(id, descriptor.clone()).is_some() {
            return Err(SigningTrustError::Conflict);
        }
        Ok(descriptor)
    }

    pub fn resolve_descriptor(
        &mut self,
        id: [u8; 16],
        disposition: DescriptorDisposition,
        sequence: u64,
    ) -> Result<(), SigningTrustError> {
        if disposition == DescriptorDisposition::Outstanding {
            return Err(SigningTrustError::Invalid);
        }
        let descriptor = self
            .descriptors
            .get_mut(&id)
            .ok_or(SigningTrustError::Invalid)?;
        if descriptor.disposition != DescriptorDisposition::Outstanding {
            return Err(SigningTrustError::Conflict);
        }
        descriptor.disposition = disposition;
        if disposition == DescriptorDisposition::Registered {
            if let Some(entry) = self
                .lineage
                .entries
                .iter_mut()
                .find(|entry| entry.candidate.id == descriptor.signing_key_id)
            {
                entry.last_use_sequence = Some(sequence);
            }
            if descriptor.domain == SignableDomain::AuditCheckpoint {
                self.checkpoint_registered = true;
                self.previous_checkpoint = Some(descriptor.digest);
                if descriptor.transition_digest
                    == self
                        .lineage
                        .current()
                        .and_then(|entry| entry.transition_digest)
                {
                    self.lineage.transition_registered_checkpoint_pending = false;
                }
            }
        }
        Ok(())
    }

    pub fn outstanding_for(&self, key_id: [u8; 16]) -> OutstandingInventory {
        let mut counts = BTreeMap::new();
        let mut digests = Vec::new();
        for descriptor in self.descriptors.values().filter(|descriptor| {
            descriptor.signing_key_id == key_id
                && descriptor.disposition == DescriptorDisposition::Outstanding
        }) {
            *counts.entry(descriptor.domain).or_insert(0) += 1;
            digests.push(descriptor.digest);
        }
        digests.sort_unstable();
        OutstandingInventory { counts, digests }
    }

    fn check_context(&self, context: SigningContext) -> Result<(), SigningTrustError> {
        if context.store_id != self.context_store_id
            || context.incarnation != self.incarnation
            || context.audit_epoch != self.audit_epoch
            || context.sequence == 0
            || context.head == [0; 32]
            || context.effective_milliseconds == 0
        {
            return Err(SigningTrustError::Fork);
        }
        Ok(())
    }
}

pub fn enrollment_confirmation(
    store_id: StoreId,
    candidate: &SigningKeyCandidate,
    reason: &str,
) -> Result<[u8; 32], SigningTrustError> {
    if !valid_reason(reason) {
        return Err(SigningTrustError::Invalid);
    }
    let encoded = candidate.encode()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.signing-key-enroll.v1\0");
    hasher.update(&store_id.0);
    hasher.update(&(encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    hasher.update(&(reason.len() as u64).to_be_bytes());
    hasher.update(reason.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedSigningKey {
    pub algorithm: &'static str,
    pub domain: &'static str,
    pub key_id: String,
    pub fingerprint: String,
    pub public_key: String,
    pub candidate: String,
    pub sink_outcome_id: String,
    pub custody: &'static str,
}

pub fn generate_signing_key<W: Write + AsFd>(
    sink: &mut W,
    random: &mut impl RandomSource,
) -> Result<GeneratedSigningKey, SigningTrustError> {
    crate::init::validate_secret_sink(sink.as_fd()).map_err(|_| SigningTrustError::UnsafeSink)?;
    let mut private = Zeroizing::new([0_u8; 32]);
    random
        .fill(private.as_mut())
        .map_err(|_| SigningTrustError::Random)?;
    let signing = SigningKey::from_bytes(&private);
    let candidate = SigningKeyCandidate::new(signing.verifying_key().to_bytes())?;
    sink.write_all(private.as_ref())
        .and_then(|()| sink.flush())
        .map_err(|_| SigningTrustError::Disclosure)?;
    let candidate_bytes = candidate.encode()?;
    let key_id = hex(&candidate.id);
    let public_key = hex(&candidate.verifying_key);
    let candidate_encoded = hex(&candidate_bytes);
    let mut outcome = blake3::Hasher::new();
    outcome.update(b"ops-light-secrets-server.signing-key-sink.v1\0");
    outcome.update(&candidate.id);
    Ok(GeneratedSigningKey {
        algorithm: "ed25519",
        domain: "external-signing-trust-v1",
        key_id: key_id.clone(),
        fingerprint: key_id,
        public_key,
        candidate: candidate_encoded,
        sink_outcome_id: hex(&outcome.finalize().as_bytes()[..8]),
        custody: "retain at least one independently protected off-host copy; never place private signing material in argv, environment, logs, archives, or daemon storage",
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningTrustError {
    Invalid,
    Denied,
    NotEnrolled,
    Conflict,
    Trust,
    Signature,
    Fork,
    UnsafeSink,
    Random,
    Disclosure,
    Codec,
}

impl From<CodecError> for SigningTrustError {
    fn from(_: CodecError) -> Self {
        Self::Codec
    }
}

impl From<KeyringError> for SigningTrustError {
    fn from(_: KeyringError) -> Self {
        Self::Random
    }
}

impl std::fmt::Display for SigningTrustError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("signing trust operation failed")
    }
}

impl std::error::Error for SigningTrustError {}

fn transition_message(transition: &SigningTransition) -> Result<Vec<u8>, SigningTrustError> {
    let encoded = transition.encode()?;
    let mut message = Vec::with_capacity(TRANSITION_DOMAIN.len() + 8 + encoded.len());
    message.extend_from_slice(TRANSITION_DOMAIN);
    message.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    message.extend_from_slice(&encoded);
    Ok(message)
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= 1024 && !reason.chars().any(char::is_control)
}

fn encode_entry(entry: &SigningKeyLineageEntry) -> Result<Vec<u8>, CodecError> {
    entry.validate()?;
    let mut out = Encoder::version(1);
    out.bytes(&entry.candidate.encode()?, 128)?;
    out.u8(entry.state as u8);
    out.u64(entry.generation);
    out.fixed(&entry.effective_audit_epoch);
    out.u64(entry.effective_sequence);
    out.u64(entry.effective_milliseconds);
    encode_optional_u64(&mut out, entry.retired_sequence);
    encode_optional_fixed(&mut out, entry.previous_key_id.as_ref());
    encode_optional_fixed(&mut out, entry.transition_digest.as_ref());
    encode_optional_u64(&mut out, entry.last_use_sequence);
    out.bool(entry.custody_attested);
    Ok(out.finish())
}

fn decode_entry(bytes: &[u8]) -> Result<SigningKeyLineageEntry, CodecError> {
    let mut input = Decoder::version(bytes, 1)?;
    let value = SigningKeyLineageEntry {
        candidate: SigningKeyCandidate::decode(&input.bytes(128)?)?,
        state: match input.u8()? {
            1 => SigningKeyState::Current,
            2 => SigningKeyState::Retired,
            _ => return Err(CodecError::Invalid),
        },
        generation: input.u64()?,
        effective_audit_epoch: input.fixed()?,
        effective_sequence: input.u64()?,
        effective_milliseconds: input.u64()?,
        retired_sequence: decode_optional_u64(&mut input)?,
        previous_key_id: decode_optional_fixed(&mut input)?,
        transition_digest: decode_optional_fixed(&mut input)?,
        last_use_sequence: decode_optional_u64(&mut input)?,
        custody_attested: input.bool()?,
    };
    input.finish()?;
    value.validate()?;
    Ok(value)
}

fn encode_optional_fixed<const N: usize>(out: &mut Encoder, value: Option<&[u8; N]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(value);
        }
    }
}

fn decode_optional_fixed<const N: usize>(
    input: &mut Decoder<'_>,
) -> Result<Option<[u8; N]>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => Err(CodecError::Invalid),
    }
}

fn encode_optional_u64(out: &mut Encoder, value: Option<u64>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u64(value);
        }
    }
}

fn decode_optional_u64(input: &mut Decoder<'_>) -> Result<Option<u64>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.u64()?)),
        _ => Err(CodecError::Invalid),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
