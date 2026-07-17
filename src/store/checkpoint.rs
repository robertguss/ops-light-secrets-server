//! Frozen external checkpoint formats and verification primitives.

use super::codec::{Decoder, Encoder};
use super::keyring::KeyringMetadata;
use super::{
    AUDIT_EVENTS, AUDIT_HEAD, AUDIT_HEAD_KEY, CHECKPOINT_PREPARED, CHECKPOINT_REGISTERED,
    CREDENTIAL_EPOCH, CREDENTIAL_EPOCH_KEY, CREDENTIALS, Canonical, CodecError, EncryptedTable,
    GRANTS, IDENTITIES, META, META_KEY, MetaRecord, PROVISIONAL_META_KEY, ProvisionalMetaRecord,
    ReadableTable, SECRET_META, SECRETS, Sealed, SecretMetadata, StateDeltaSet, StateDigest,
    StateTuple, Store, StoreError, StoreId, StoredAuditEntry, audit_key,
};
use crate::identity::{GrantRecord, IdentityRecord};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroize;

const PREPARED_KEY_PREFIX: u8 = 1;

pub const CHECKPOINT_DESCRIPTOR_VERSION: u16 = 2;
pub const CHECKPOINT_FILE_VERSION: u16 = 1;
const CHECKPOINT_DOMAIN: &[u8] = b"ops-light-secrets-server.audit-checkpoint.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointDescriptor {
    pub store_id: StoreId,
    pub audit_epoch: [u8; 16],
    pub range_start: u64,
    pub range_end: u64,
    pub prepare_event_id: [u8; 16],
    pub chain_head: [u8; 32],
    pub state_digest: StateDigest,
    pub effective_timestamp_milliseconds: u64,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub signing_transition_digest: Option<[u8; 32]>,
    pub previous_checkpoint_digest: Option<[u8; 32]>,
}

impl CheckpointDescriptor {
    fn validate(&self) -> Result<(), CodecError> {
        if self.store_id.0 == [0; 16]
            || self.audit_epoch == [0; 16]
            || self.range_start == 0
            || self.range_start > self.range_end
            || self.prepare_event_id == [0; 16]
            || self.chain_head == [0; 32]
            || self.effective_timestamp_milliseconds == 0
            || self.signing_key_id == [0; 16]
            || self.signing_lineage_generation == 0
            || (self.signing_lineage_generation == 1 && self.signing_transition_digest.is_some())
            || (self.signing_lineage_generation > 1 && self.signing_transition_digest.is_none())
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }
}

impl Canonical for CheckpointDescriptor {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(CHECKPOINT_DESCRIPTOR_VERSION);
        out.fixed(&self.store_id.0);
        out.fixed(&self.audit_epoch);
        out.u64(self.range_start);
        out.u64(self.range_end);
        out.fixed(&self.prepare_event_id);
        out.fixed(&self.chain_head);
        out.fixed(&self.state_digest.0);
        out.u64(self.effective_timestamp_milliseconds);
        out.fixed(&self.signing_key_id);
        out.u64(self.signing_lineage_generation);
        match self.signing_transition_digest {
            None => out.u8(0),
            Some(value) => {
                out.u8(1);
                out.fixed(&value);
            }
        }
        match self.previous_checkpoint_digest {
            None => out.u8(0),
            Some(value) => {
                out.u8(1);
                out.fixed(&value);
            }
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != CHECKPOINT_DESCRIPTOR_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            store_id: StoreId(input.fixed()?),
            audit_epoch: input.fixed()?,
            range_start: input.u64()?,
            range_end: input.u64()?,
            prepare_event_id: input.fixed()?,
            chain_head: input.fixed()?,
            state_digest: StateDigest(input.fixed()?),
            effective_timestamp_milliseconds: input.u64()?,
            signing_key_id: input.fixed()?,
            signing_lineage_generation: input.u64()?,
            signing_transition_digest: match input.u8()? {
                0 => None,
                1 => Some(input.fixed()?),
                _ => return Err(CodecError::Invalid),
            },
            previous_checkpoint_digest: match input.u8()? {
                0 => None,
                1 => Some(input.fixed()?),
                _ => return Err(CodecError::Invalid),
            },
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointSignature {
    pub descriptor: CheckpointDescriptor,
    pub signature: [u8; 64],
}

impl Canonical for CheckpointSignature {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let descriptor = self.descriptor.encode()?;
        let mut out = Encoder::version(1);
        out.u16(CHECKPOINT_FILE_VERSION);
        out.bytes(&descriptor, 1024)?;
        out.fixed(&self.signature);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != CHECKPOINT_FILE_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            descriptor: CheckpointDescriptor::decode(&input.bytes(1024)?)?,
            signature: input.fixed()?,
        };
        input.finish()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointKeyStatus {
    Initial,
    Current,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointPublicKey {
    pub id: [u8; 16],
    pub verifying_key: [u8; 32],
    pub status: CheckpointKeyStatus,
    pub valid_from_milliseconds: u64,
    pub valid_until_milliseconds: Option<u64>,
    pub previous_key_id: Option<[u8; 16]>,
}

impl Canonical for CheckpointPublicKey {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate().map_err(|_| CodecError::Invalid)?;
        let mut out = Encoder::version(1);
        out.fixed(&self.id);
        out.fixed(&self.verifying_key);
        out.u8(match self.status {
            CheckpointKeyStatus::Initial => 1,
            CheckpointKeyStatus::Current => 2,
            CheckpointKeyStatus::Retired => 3,
        });
        out.u64(self.valid_from_milliseconds);
        match self.valid_until_milliseconds {
            None => out.u8(0),
            Some(value) => {
                out.u8(1);
                out.u64(value);
            }
        }
        match self.previous_key_id {
            None => out.u8(0),
            Some(value) => {
                out.u8(1);
                out.fixed(&value);
            }
        }
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            id: input.fixed()?,
            verifying_key: input.fixed()?,
            status: match input.u8()? {
                1 => CheckpointKeyStatus::Initial,
                2 => CheckpointKeyStatus::Current,
                3 => CheckpointKeyStatus::Retired,
                _ => return Err(CodecError::Invalid),
            },
            valid_from_milliseconds: input.u64()?,
            valid_until_milliseconds: match input.u8()? {
                0 => None,
                1 => Some(input.u64()?),
                _ => return Err(CodecError::Invalid),
            },
            previous_key_id: match input.u8()? {
                0 => None,
                1 => Some(input.fixed()?),
                _ => return Err(CodecError::Invalid),
            },
        };
        input.finish()?;
        value.validate().map_err(|_| CodecError::Invalid)?;
        Ok(value)
    }
}

impl CheckpointPublicKey {
    fn validate(&self) -> Result<(), CheckpointError> {
        if self.id == [0; 16]
            || signing_key_id(&self.verifying_key) != self.id
            || self.valid_from_milliseconds == 0
            || self
                .valid_until_milliseconds
                .is_some_and(|end| end < self.valid_from_milliseconds)
            || self.previous_key_id == Some(self.id)
        {
            return Err(CheckpointError::Trust);
        }
        VerifyingKey::from_bytes(&self.verifying_key).map_err(|_| CheckpointError::Trust)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointTrust(BTreeMap<[u8; 16], CheckpointPublicKey>);

impl CheckpointTrust {
    pub fn new(
        keys: impl IntoIterator<Item = CheckpointPublicKey>,
    ) -> Result<Self, CheckpointError> {
        let mut map = BTreeMap::new();
        for key in keys {
            key.validate()?;
            if map.insert(key.id, key).is_some() {
                return Err(CheckpointError::Trust);
            }
        }
        let mut children = BTreeSet::new();
        for key in map.values() {
            if let Some(previous) = key.previous_key_id {
                if !map.contains_key(&previous) || !children.insert(previous) {
                    return Err(CheckpointError::Trust);
                }
            }
            let mut seen = BTreeSet::new();
            let mut cursor = Some(key.id);
            while let Some(id) = cursor {
                if !seen.insert(id) {
                    return Err(CheckpointError::Trust);
                }
                cursor = map.get(&id).and_then(|candidate| candidate.previous_key_id);
            }
        }
        Ok(Self(map))
    }

    fn key(&self, id: &[u8; 16], at: u64) -> Result<&CheckpointPublicKey, CheckpointError> {
        let key = self.0.get(id).ok_or(CheckpointError::Trust)?;
        if at < key.valid_from_milliseconds
            || key.valid_until_milliseconds.is_some_and(|until| at > until)
        {
            return Err(CheckpointError::Expired);
        }
        Ok(key)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationTier {
    FullyAnchored { through_sequence: u64 },
    UnanchoredTail { first_sequence: u64, count: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointFreshness {
    pub stale: bool,
    pub age_milliseconds: u64,
    pub unanchored_events: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CheckpointHealth {
    pub checkpoint_registered: bool,
    pub checkpoint_stale: bool,
    pub checkpoint_age_milliseconds: Option<u64>,
    pub checkpoint_unanchored_events: u64,
    pub checkpoint_abandoned_prepares: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    Codec,
    Trust,
    Expired,
    Signature,
    Chain,
    State,
    Output,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("checkpoint operation failed")
    }
}

impl std::error::Error for CheckpointError {}

impl From<CodecError> for CheckpointError {
    fn from(_: CodecError) -> Self {
        Self::Codec
    }
}

fn signing_message(descriptor: &CheckpointDescriptor) -> Result<Vec<u8>, CheckpointError> {
    let encoded = descriptor.encode()?;
    let mut message = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + 8 + encoded.len());
    message.extend_from_slice(CHECKPOINT_DOMAIN);
    message.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    message.extend_from_slice(&encoded);
    Ok(message)
}

pub fn sign_checkpoint(
    descriptor: CheckpointDescriptor,
    private_key: &mut [u8; 32],
) -> Result<CheckpointSignature, CheckpointError> {
    let signing = SigningKey::from_bytes(private_key);
    let derived_id = signing_key_id(&signing.verifying_key().to_bytes());
    if derived_id != descriptor.signing_key_id {
        private_key.zeroize();
        return Err(CheckpointError::Trust);
    }
    let signature = signing.sign(&signing_message(&descriptor)?).to_bytes();
    private_key.zeroize();
    Ok(CheckpointSignature {
        descriptor,
        signature,
    })
}

pub fn sign_checkpoint_authorized(
    descriptor: CheckpointDescriptor,
    public: &CheckpointPublicKey,
    private_key: &mut [u8; 32],
) -> Result<CheckpointSignature, CheckpointError> {
    public.validate()?;
    if public.id != descriptor.signing_key_id
        || descriptor.effective_timestamp_milliseconds < public.valid_from_milliseconds
        || public
            .valid_until_milliseconds
            .is_some_and(|until| descriptor.effective_timestamp_milliseconds > until)
    {
        private_key.zeroize();
        return Err(CheckpointError::Expired);
    }
    let signing = SigningKey::from_bytes(private_key);
    if signing.verifying_key().to_bytes() != public.verifying_key {
        private_key.zeroize();
        return Err(CheckpointError::Trust);
    }
    sign_checkpoint(descriptor, private_key)
}

pub fn verify_checkpoint(
    checkpoint: &CheckpointSignature,
    trust: &CheckpointTrust,
) -> Result<[u8; 32], CheckpointError> {
    let public = trust.key(
        &checkpoint.descriptor.signing_key_id,
        checkpoint.descriptor.effective_timestamp_milliseconds,
    )?;
    let key =
        VerifyingKey::from_bytes(&public.verifying_key).map_err(|_| CheckpointError::Trust)?;
    if signing_key_id(&public.verifying_key) != public.id {
        return Err(CheckpointError::Trust);
    }
    key.verify(
        &signing_message(&checkpoint.descriptor)?,
        &Signature::from_bytes(&checkpoint.signature),
    )
    .map_err(|_| CheckpointError::Signature)?;
    checkpoint_digest(checkpoint)
}

pub fn verify_checkpoint_chain<'a>(
    checkpoints: impl IntoIterator<Item = &'a CheckpointSignature>,
    trust: &CheckpointTrust,
) -> Result<[u8; 32], CheckpointError> {
    let mut previous: Option<(&CheckpointDescriptor, [u8; 32])> = None;
    for checkpoint in checkpoints {
        let digest = verify_checkpoint(checkpoint, trust)?;
        match previous {
            None if checkpoint.descriptor.previous_checkpoint_digest.is_some() => {
                return Err(CheckpointError::Chain);
            }
            Some((prior, prior_digest))
                if checkpoint.descriptor.store_id != prior.store_id
                    || checkpoint.descriptor.audit_epoch != prior.audit_epoch
                    || checkpoint.descriptor.range_start != prior.range_end.saturating_add(1)
                    || checkpoint.descriptor.previous_checkpoint_digest != Some(prior_digest) =>
            {
                return Err(CheckpointError::Chain);
            }
            _ => {}
        }
        previous = Some((&checkpoint.descriptor, digest));
    }
    previous
        .map(|(_, digest)| digest)
        .ok_or(CheckpointError::Chain)
}

pub fn verify_audit_checkpoint(
    entries: &[StoredAuditEntry],
    checkpoint: &CheckpointSignature,
    trust: &CheckpointTrust,
) -> Result<[VerificationTier; 2], CheckpointError> {
    verify_checkpoint(checkpoint, trust)?;
    super::verify_chain(entries).map_err(|_| CheckpointError::Chain)?;
    let anchored = entries
        .iter()
        .find(|entry| {
            entry.envelope.audit_epoch == checkpoint.descriptor.audit_epoch
                && entry.envelope.epoch_sequence == checkpoint.descriptor.range_end
        })
        .ok_or(CheckpointError::Chain)?;
    if anchored
        .envelope
        .chain_hash()
        .map_err(|_| CheckpointError::Chain)?
        != checkpoint.descriptor.chain_head
    {
        return Err(CheckpointError::Chain);
    }
    let current = entries
        .last()
        .ok_or(CheckpointError::Chain)?
        .envelope
        .epoch_sequence;
    if current < checkpoint.descriptor.range_end {
        return Err(CheckpointError::Chain);
    }
    Ok([
        VerificationTier::FullyAnchored {
            through_sequence: checkpoint.descriptor.range_end,
        },
        VerificationTier::UnanchoredTail {
            first_sequence: checkpoint.descriptor.range_end.saturating_add(1),
            count: current - checkpoint.descriptor.range_end,
        },
    ])
}

pub fn signing_key_id(public_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.checkpoint-key-id.v1\0");
    hasher.update(public_key);
    let mut id = [0; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

pub fn checkpoint_digest(checkpoint: &CheckpointSignature) -> Result<[u8; 32], CheckpointError> {
    let bytes = checkpoint.encode()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.checkpoint-file-digest.v1\0");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

pub fn reconcile_state(
    current: &BTreeSet<StateTuple>,
    tail_oldest_to_newest: &[StateDeltaSet],
    anchored: StateDigest,
) -> Result<(), CheckpointError> {
    let mut reconstructed = current.clone();
    for delta in tail_oldest_to_newest.iter().rev() {
        reconstructed = delta
            .reverse_apply(&reconstructed)
            .map_err(|_| CheckpointError::State)?;
    }
    (StateDigest::compute(reconstructed).map_err(|_| CheckpointError::State)? == anchored)
        .then_some(())
        .ok_or(CheckpointError::State)
}

pub fn stale_checkpoint(
    now_milliseconds: u64,
    registered_milliseconds: u64,
    current_sequence: u64,
    registered_sequence: u64,
    max_age_seconds: u64,
    max_unanchored_events: u64,
) -> CheckpointFreshness {
    let age_milliseconds = now_milliseconds.saturating_sub(registered_milliseconds);
    let unanchored_events = current_sequence.saturating_sub(registered_sequence);
    CheckpointFreshness {
        stale: age_milliseconds > max_age_seconds.saturating_mul(1_000)
            || unanchored_events > max_unanchored_events,
        age_milliseconds,
        unanchored_events,
    }
}

pub fn write_checkpoint_atomic(
    path: &Path,
    checkpoint: &CheckpointSignature,
) -> Result<(), CheckpointError> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(CheckpointError::Output);
    }
    let parent = path.parent().ok_or(CheckpointError::Output)?;
    let name = path
        .file_name()
        .ok_or(CheckpointError::Output)?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| CheckpointError::Output)?;
        file.write_all(&checkpoint.encode()?)
            .map_err(|_| CheckpointError::Output)?;
        file.sync_all().map_err(|_| CheckpointError::Output)?;
        std::fs::rename(&temporary, path).map_err(|_| CheckpointError::Output)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CheckpointError::Output)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

impl Store {
    /// Atomically append the already-encrypted prepare event, advance the audit
    /// head, and persist its descriptor. State digest is recomputed from rows in
    /// this same write transaction; audit/checkpoint tables are excluded.
    pub fn commit_checkpoint_prepare(
        &self,
        entry: &StoredAuditEntry,
        descriptor: &CheckpointDescriptor,
    ) -> Result<[u8; 32], StoreError> {
        descriptor.validate()?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        let current_head = {
            let table = write
                .open_table(AUDIT_HEAD)
                .map_err(|_| StoreError::Database)?;
            let bytes = table
                .get(AUDIT_HEAD_KEY)
                .map_err(|_| StoreError::Database)?
                .ok_or(StoreError::Integrity)?
                .value()
                .to_vec();
            super::AuditEnvelope::decode(&bytes)?
        };
        let final_head = entry.envelope.chain_hash()?;
        let event_id = entry
            .encrypted_payload
            .header()
            .binding()
            .logical_record_id();
        let state = state_digest_in_write(&write)?;
        let last = last_registered_in_write(&write)?;
        let expected_start = last.as_ref().map_or(1, |checkpoint| {
            checkpoint.descriptor.range_end.saturating_add(1)
        });
        let expected_previous = last
            .as_ref()
            .map(checkpoint_digest)
            .transpose()
            .map_err(|_| StoreError::Integrity)?;
        if entry.envelope.previous_hash != current_head.chain_hash()?
            || entry.envelope.audit_epoch != current_head.audit_epoch
            || entry.envelope.epoch_sequence != current_head.epoch_sequence.saturating_add(1)
            || descriptor.audit_epoch != entry.envelope.audit_epoch
            || descriptor.range_start != expected_start
            || descriptor.range_end != entry.envelope.epoch_sequence
            || descriptor.prepare_event_id.as_slice() != &event_id[..16]
            || descriptor.chain_head != final_head
            || descriptor.state_digest != state
            || descriptor.effective_timestamp_milliseconds
                != entry.envelope.effective_timestamp_milliseconds
            || descriptor.previous_checkpoint_digest != expected_previous
        {
            return Err(StoreError::Integrity);
        }
        let descriptor_bytes = descriptor.encode()?;
        let descriptor_digest = unsigned_descriptor_digest(&descriptor_bytes);
        let mut prepared_key = Vec::with_capacity(33);
        prepared_key.push(PREPARED_KEY_PREFIX);
        prepared_key.extend_from_slice(&descriptor_digest);
        {
            let mut events = write
                .open_table(AUDIT_EVENTS)
                .map_err(|_| StoreError::Database)?;
            let key = audit_key(&entry.envelope);
            if events
                .get(key.as_slice())
                .map_err(|_| StoreError::Database)?
                .is_some()
            {
                return Err(StoreError::Integrity);
            }
            events
                .insert(key.as_slice(), entry.encode()?.as_slice())
                .map_err(|_| StoreError::Database)?;
        }
        write
            .open_table(AUDIT_HEAD)
            .map_err(|_| StoreError::Database)?
            .insert(AUDIT_HEAD_KEY, entry.envelope.encode()?.as_slice())
            .map_err(|_| StoreError::Database)?;
        write
            .open_table(CHECKPOINT_PREPARED)
            .map_err(|_| StoreError::Database)?
            .insert(prepared_key.as_slice(), descriptor_bytes.as_slice())
            .map_err(|_| StoreError::Database)?;
        write.commit().map_err(|_| StoreError::Database)?;
        Ok(descriptor_digest)
    }

    pub fn prepared_checkpoints(&self) -> Result<Vec<CheckpointDescriptor>, StoreError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| StoreError::Database)?;
        let table = read
            .open_table(CHECKPOINT_PREPARED)
            .map_err(|_| StoreError::Database)?;
        table
            .iter()
            .map_err(|_| StoreError::Database)?
            .map(|row| {
                let (_, value) = row.map_err(|_| StoreError::Database)?;
                CheckpointDescriptor::decode(value.value()).map_err(StoreError::from)
            })
            .collect()
    }

    pub fn register_checkpoint(
        &self,
        checkpoint: &CheckpointSignature,
        trust: &CheckpointTrust,
    ) -> Result<[u8; 32], StoreError> {
        let digest = verify_checkpoint(checkpoint, trust).map_err(|_| StoreError::Integrity)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        let last = last_registered_in_write(&write)?;
        if checkpoint.descriptor.previous_checkpoint_digest
            != last
                .as_ref()
                .map(checkpoint_digest)
                .transpose()
                .map_err(|_| StoreError::Integrity)?
        {
            return Err(StoreError::Integrity);
        }
        let descriptor_bytes = checkpoint.descriptor.encode()?;
        let mut prepared_key = Vec::with_capacity(33);
        prepared_key.push(PREPARED_KEY_PREFIX);
        prepared_key.extend_from_slice(&unsigned_descriptor_digest(&descriptor_bytes));
        if write
            .open_table(CHECKPOINT_PREPARED)
            .map_err(|_| StoreError::Database)?
            .get(prepared_key.as_slice())
            .map_err(|_| StoreError::Database)?
            .is_none()
        {
            return Err(StoreError::Integrity);
        }
        let mut table = write
            .open_table(CHECKPOINT_REGISTERED)
            .map_err(|_| StoreError::Database)?;
        if table
            .get(digest.as_slice())
            .map_err(|_| StoreError::Database)?
            .is_some()
        {
            return Err(StoreError::Integrity);
        }
        table
            .insert(digest.as_slice(), checkpoint.encode()?.as_slice())
            .map_err(|_| StoreError::Database)?;
        drop(table);
        write.commit().map_err(|_| StoreError::Database)?;
        Ok(digest)
    }

    pub fn registered_checkpoints(&self) -> Result<Vec<CheckpointSignature>, StoreError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| StoreError::Database)?;
        let table = read
            .open_table(CHECKPOINT_REGISTERED)
            .map_err(|_| StoreError::Database)?;
        let mut values: Vec<_> = table
            .iter()
            .map_err(|_| StoreError::Database)?
            .map(|row| {
                let (_, value) = row.map_err(|_| StoreError::Database)?;
                CheckpointSignature::decode(value.value()).map_err(StoreError::from)
            })
            .collect::<Result<_, _>>()?;
        values.sort_by_key(|value| value.descriptor.range_end);
        Ok(values)
    }

    pub fn state_digest(&self) -> Result<StateDigest, StoreError> {
        let write = self
            .database
            .begin_write()
            .map_err(|_| StoreError::Database)?;
        let digest = state_digest_in_write(&write)?;
        write.abort().map_err(|_| StoreError::Database)?;
        Ok(digest)
    }

    pub fn checkpoint_health(
        &self,
        now_milliseconds: u64,
        max_age_seconds: u64,
        max_unanchored_events: u64,
    ) -> Result<CheckpointHealth, StoreError> {
        let head = self.audit_head()?.ok_or(StoreError::Integrity)?;
        let registered = self.registered_checkpoints()?;
        let prepared = self.prepared_checkpoints()?;
        let registered_descriptors: BTreeSet<Vec<u8>> = registered
            .iter()
            .map(|checkpoint| checkpoint.descriptor.encode())
            .collect::<Result<_, _>>()?;
        let abandoned = prepared
            .iter()
            .map(Canonical::encode)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|descriptor| !registered_descriptors.contains(descriptor))
            .count() as u64;
        let Some(last) = registered.last() else {
            return Ok(CheckpointHealth {
                checkpoint_registered: false,
                checkpoint_stale: true,
                checkpoint_age_milliseconds: None,
                checkpoint_unanchored_events: head.epoch_sequence,
                checkpoint_abandoned_prepares: abandoned,
            });
        };
        let freshness = stale_checkpoint(
            now_milliseconds,
            last.descriptor.effective_timestamp_milliseconds,
            head.epoch_sequence,
            last.descriptor.range_end,
            max_age_seconds,
            max_unanchored_events,
        );
        Ok(CheckpointHealth {
            checkpoint_registered: true,
            checkpoint_stale: freshness.stale,
            checkpoint_age_milliseconds: Some(freshness.age_milliseconds),
            checkpoint_unanchored_events: freshness.unanchored_events,
            checkpoint_abandoned_prepares: abandoned,
        })
    }
}

fn unsigned_descriptor_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.checkpoint-descriptor-digest.v1\0");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn last_registered_in_write(
    write: &redb::WriteTransaction,
) -> Result<Option<CheckpointSignature>, StoreError> {
    let table = write
        .open_table(CHECKPOINT_REGISTERED)
        .map_err(|_| StoreError::Database)?;
    let mut last: Option<CheckpointSignature> = None;
    for row in table.iter().map_err(|_| StoreError::Database)? {
        let (_, value) = row.map_err(|_| StoreError::Database)?;
        let checkpoint = CheckpointSignature::decode(value.value())?;
        if last
            .as_ref()
            .is_none_or(|old| old.descriptor.range_end < checkpoint.descriptor.range_end)
        {
            last = Some(checkpoint);
        }
    }
    Ok(last)
}

pub(super) fn state_digest_in_write(
    write: &redb::WriteTransaction,
) -> Result<StateDigest, StoreError> {
    let mut tuples = Vec::new();
    {
        let table = write.open_table(META).map_err(|_| StoreError::Database)?;
        for row in table.iter().map_err(|_| StoreError::Database)? {
            let (key, value) = row.map_err(|_| StoreError::Database)?;
            match key.value() {
                super::KEYRING_METADATA_KEY => tuples.push(
                    Sealed::<KeyringMetadata>::decode(value.value())?.state_tuple(key.value())?,
                ),
                PROVISIONAL_META_KEY => tuples.push(
                    Sealed::<ProvisionalMetaRecord>::decode(value.value())?
                        .state_tuple(key.value())?,
                ),
                META_KEY => {
                    if let Some(anchor) = MetaRecord::decode(value.value())?.pending_anchor {
                        tuples.push(anchor.state_tuple(b"\x01pending_anchor")?);
                    }
                }
                _ => return Err(StoreError::Integrity),
            }
        }
    }
    collect_clear::<SecretMetadata>(write, SECRET_META, &mut tuples)?;
    collect_clear::<IdentityRecord>(write, IDENTITIES, &mut tuples)?;
    collect_clear::<GrantRecord>(write, GRANTS, &mut tuples)?;
    collect_clear::<crate::credential::CredentialRecord>(write, CREDENTIALS, &mut tuples)?;
    {
        let table = write
            .open_table(CREDENTIAL_EPOCH)
            .map_err(|_| StoreError::Database)?;
        let value = table
            .get(CREDENTIAL_EPOCH_KEY)
            .map_err(|_| StoreError::Database)?
            .ok_or(StoreError::Integrity)?;
        tuples.push(
            Sealed::<crate::credential::CredentialEpoch>::decode(value.value())?
                .state_tuple(CREDENTIAL_EPOCH_KEY)?,
        );
    }
    {
        let table = write
            .open_table(SECRETS)
            .map_err(|_| StoreError::Database)?;
        for row in table.iter().map_err(|_| StoreError::Database)? {
            let (key, value) = row.map_err(|_| StoreError::Database)?;
            tuples.push(StateTuple::encrypted(
                EncryptedTable::Secrets,
                key.value(),
                value.value(),
            )?);
        }
    }
    StateDigest::compute(tuples).map_err(StoreError::from)
}

fn collect_clear<T: super::ClearRecord>(
    write: &redb::WriteTransaction,
    definition: redb::TableDefinition<&[u8], &[u8]>,
    tuples: &mut Vec<StateTuple>,
) -> Result<(), StoreError> {
    let table = write
        .open_table(definition)
        .map_err(|_| StoreError::Database)?;
    for row in table.iter().map_err(|_| StoreError::Database)? {
        let (key, value) = row.map_err(|_| StoreError::Database)?;
        tuples.push(Sealed::<T>::decode(value.value())?.state_tuple(key.value())?);
    }
    Ok(())
}
