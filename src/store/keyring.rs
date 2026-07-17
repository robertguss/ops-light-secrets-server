//! Fixed-purpose keyring protected by an age v0.12 envelope.

use super::codec::{Canonical, CodecError, Decoder, Encoder};
use super::{
    ClearRecord, EncryptedRecord, KeyringEnvelope, LogicalPath, METADATA_SCHEMA_VERSION,
    MetaRecord, PlaintextSecret, ProvisionalMetaRecord, RecordBinding, RecordClass,
    RecordCryptoError, RecordDomain, RotationState, Sealed, SecretDataError, SecretMetadata, Store,
    StoreError, StoreId, VersionSetSummary,
};
use crate::clock::WatermarkCommand;
use age::x25519;
use age::{Encryptor, Recipient};
use secrecy::{ExposeSecret, SecretBox};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::os::fd::AsFd;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

pub const KEYRING_FORMAT_VERSION: u16 = 1;
pub const MAX_AUDIT_PAYLOAD_GENERATIONS: usize = 32;
pub const AUDIT_PAYLOAD_WARNING_THRESHOLD: usize = 24;
const MAX_RECORD_GENERATIONS: usize = 8;
const MAX_KEYRING_PLAINTEXT: usize = 64 * 1024;
const MAX_AGE_ENVELOPE: usize = 1024 * 1024;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyId(pub [u8; 16]);

impl fmt::Debug for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyId([REDACTED])")
    }
}

pub struct PurposeKey {
    id: KeyId,
    material: SecretBox<[u8; 32]>,
}

impl PurposeKey {
    pub fn id(&self) -> KeyId {
        self.id
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.material.expose_secret()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecipientFingerprint(pub [u8; 32]);

impl RecipientFingerprint {
    pub fn of(recipient: &x25519::Recipient) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ops-light-secrets-server.age-recipient.v1\0");
        hasher.update(recipient.to_string().as_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientSet {
    pub active: RecipientFingerprint,
    pub recovery: Option<RecipientFingerprint>,
}

impl RecipientSet {
    pub fn new(
        active: &x25519::Recipient,
        recovery: Option<&x25519::Recipient>,
    ) -> Result<Self, KeyringError> {
        let active = RecipientFingerprint::of(active);
        let recovery = recovery.map(RecipientFingerprint::of);
        if recovery == Some(active) {
            return Err(KeyringError::RecipientSet);
        }
        Ok(Self { active, recovery })
    }

    fn ordered<'a>(
        self,
        active: &'a x25519::Recipient,
        recovery: Option<&'a x25519::Recipient>,
    ) -> Vec<(RecipientFingerprint, &'a dyn Recipient)> {
        let mut recipients: Vec<(RecipientFingerprint, &'a dyn Recipient)> =
            vec![(self.active, active)];
        if let (Some(fingerprint), Some(recipient)) = (self.recovery, recovery) {
            recipients.push((fingerprint, recipient));
        }
        recipients.sort_by_key(|(fingerprint, _)| *fingerprint);
        recipients
    }
}

pub trait RandomSource {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError>;
}

pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        getrandom::fill(output).map_err(|_| KeyringError::Random)
    }
}

pub struct Keyring {
    store_id: StoreId,
    generation: u64,
    recipients: RecipientSet,
    record_current: PurposeKey,
    record_predecessors: Vec<PurposeKey>,
    credential_verifier: PurposeKey,
    metadata_integrity: PurposeKey,
    audit_payload: Vec<PurposeKey>,
    audit_index: PurposeKey,
    record_decrypt_attempts: AtomicUsize,
}

impl Keyring {
    pub fn generate(
        store_id: StoreId,
        generation: u64,
        recipients: RecipientSet,
        random: &mut impl RandomSource,
    ) -> Result<Self, KeyringError> {
        if generation == 0 {
            return Err(KeyringError::Invalid);
        }
        let mut ids = BTreeSet::new();
        Ok(Self {
            store_id,
            generation,
            recipients,
            record_current: generate_key(random, &mut ids)?,
            record_predecessors: Vec::new(),
            credential_verifier: generate_key(random, &mut ids)?,
            metadata_integrity: generate_key(random, &mut ids)?,
            audit_payload: vec![generate_key(random, &mut ids)?],
            audit_index: generate_key(random, &mut ids)?,
            record_decrypt_attempts: AtomicUsize::new(0),
        })
    }

    pub fn store_id(&self) -> StoreId {
        self.store_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn recipients(&self) -> RecipientSet {
        self.recipients
    }

    pub fn record_key_id(&self) -> KeyId {
        self.record_current.id()
    }

    pub fn credential_verifier_key_id(&self) -> KeyId {
        self.credential_verifier.id()
    }

    pub fn metadata_integrity_key_id(&self) -> KeyId {
        self.metadata_integrity.id()
    }

    pub fn audit_payload_generations(&self) -> usize {
        self.audit_payload.len()
    }

    pub fn audit_index_key_id(&self) -> KeyId {
        self.audit_index.id()
    }

    pub fn audit_capacity_warning(&self) -> bool {
        self.audit_payload.len() >= AUDIT_PAYLOAD_WARNING_THRESHOLD
    }

    pub fn encrypt_record(
        &self,
        binding: &RecordBinding,
        plaintext: &[u8],
        random: &mut impl RandomSource,
    ) -> Result<EncryptedRecord, RecordCryptoError> {
        let key = self.encryption_key(binding.domain());
        super::aead::encrypt(
            self.store_id,
            binding,
            key.id(),
            key.expose(),
            plaintext,
            random,
        )
    }

    pub fn decrypt_record(
        &self,
        binding: &RecordBinding,
        record: &EncryptedRecord,
    ) -> Result<SecretBox<Vec<u8>>, RecordCryptoError> {
        self.record_decrypt_attempts.fetch_add(1, Ordering::Relaxed);
        if record.header().store_id() != self.store_id || record.header().binding() != binding {
            return Err(RecordCryptoError::Binding);
        }
        let key = match binding.domain() {
            RecordDomain::AuditPayload => self
                .audit_payload
                .iter()
                .find(|key| key.id() == record.header().key_id()),
            RecordDomain::SecretValue | RecordDomain::CredentialMaterial => {
                std::iter::once(&self.record_current)
                    .chain(self.record_predecessors.iter())
                    .find(|key| key.id() == record.header().key_id())
            }
        }
        .ok_or(RecordCryptoError::KeyUnavailable)?;
        super::aead::decrypt(self.store_id, binding, record, key.expose())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn record_decrypt_attempts(&self) -> usize {
        self.record_decrypt_attempts.load(Ordering::Relaxed)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn write_secret(
        &self,
        store: &Store,
        mount: &str,
        path: &LogicalPath,
        plaintext: &PlaintextSecret,
        created_unix_milliseconds: u64,
        random: &mut impl RandomSource,
    ) -> Result<u64, SecretDataError> {
        let storage_path = storage_path(mount, path)?;
        let expected = store.secret_metadata(&storage_path, self.metadata_integrity_key())?;
        let mut metadata = expected
            .as_ref()
            .map_or_else(default_secret_metadata, |sealed| sealed.value.clone());
        let version = metadata.versions.append()?;
        let replacement =
            metadata.seal(self.metadata_integrity_key(), self.store_id, &storage_path)?;
        let binding = RecordBinding::new(
            RecordDomain::SecretValue,
            mount,
            path.clone(),
            b"secret-value.v1",
            Some(version),
            created_unix_milliseconds,
        )?;
        let record = self.encrypt_record(&binding, plaintext.expose_secret(), random)?;
        store.commit_encrypted_secret_append(
            &storage_path,
            expected.as_ref(),
            &replacement,
            &record,
            self.metadata_integrity_key(),
        )?;
        Ok(version)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_secret(
        &self,
        store: &Store,
        mount: &str,
        path: &LogicalPath,
        version: Option<u64>,
    ) -> Result<Option<PlaintextSecret>, SecretDataError> {
        let storage_path = storage_path(mount, path)?;
        let Some((version, record)) = store.encrypted_secret_version(
            &storage_path,
            version,
            self.metadata_integrity_key(),
        )?
        else {
            return Ok(None);
        };
        let binding = RecordBinding::new(
            RecordDomain::SecretValue,
            mount,
            path.clone(),
            b"secret-value.v1",
            Some(version),
            record.header().binding().created_unix_milliseconds(),
        )?;
        Ok(Some(PlaintextSecret::from_secret_box(
            self.decrypt_record(&binding, &record)?,
        )))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn secret_metadata_query(
        &self,
        store: &Store,
        mount: &str,
        path: &LogicalPath,
    ) -> Result<Option<SecretMetadata>, SecretDataError> {
        let storage_path = storage_path(mount, path)?;
        Ok(store
            .secret_metadata(&storage_path, self.metadata_integrity_key())?
            .map(|sealed| sealed.value))
    }

    pub fn append_audit_payload_key(
        &mut self,
        expected_generation: u64,
        random: &mut impl RandomSource,
    ) -> Result<KeyId, KeyringError> {
        if self.generation != expected_generation {
            return Err(KeyringError::GenerationMismatch);
        }
        if self.audit_payload.len() >= MAX_AUDIT_PAYLOAD_GENERATIONS {
            return Err(KeyringError::Limit);
        }
        let mut ids = self.all_keys().map(PurposeKey::id).collect::<BTreeSet<_>>();
        let key = generate_key(random, &mut ids)?;
        let id = key.id();
        self.audit_payload.push(key);
        self.generation = self.generation.checked_add(1).ok_or(KeyringError::Limit)?;
        Ok(id)
    }

    pub(crate) fn metadata_integrity_key(&self) -> &[u8; 32] {
        self.metadata_integrity.expose()
    }

    pub fn set_meta_authenticated(
        &self,
        store: &Store,
        expected: &MetaRecord,
        replacement: &MetaRecord,
    ) -> Result<(), StoreError> {
        store.set_meta_authenticated(expected, replacement, self.metadata_integrity_key())
    }

    pub fn commit_clock_watermark(
        &self,
        store: &Store,
        command: &WatermarkCommand,
    ) -> Result<(), StoreError> {
        store.commit_clock_watermark_authenticated(command, self.metadata_integrity_key())
    }

    pub(crate) fn seal_clear<T: ClearRecord>(
        &self,
        value: T,
        generation: u64,
        primary_key: &[u8],
    ) -> Result<Sealed<T>, CodecError> {
        Sealed::seal(
            value,
            generation,
            self.metadata_integrity_key(),
            self.store_id,
            primary_key,
        )
    }

    pub fn wrap(
        &self,
        active: &x25519::Recipient,
        recovery: Option<&x25519::Recipient>,
    ) -> Result<KeyringEnvelope, KeyringError> {
        if RecipientSet::new(active, recovery)? != self.recipients {
            return Err(KeyringError::RecipientSet);
        }
        let plaintext = Zeroizing::new(self.encode_plaintext()?);
        let recipients = self
            .recipients
            .ordered(active, recovery)
            .into_iter()
            .map(|(_, recipient)| recipient);
        let encryptor =
            Encryptor::with_recipients(recipients).map_err(|_| KeyringError::Encrypt)?;
        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|_| KeyringError::Encrypt)?;
        writer
            .write_all(&plaintext)
            .and_then(|()| writer.finish())
            .map_err(|_| KeyringError::Encrypt)?;
        if ciphertext.len() > MAX_AGE_ENVELOPE {
            return Err(KeyringError::Limit);
        }
        Ok(KeyringEnvelope(ciphertext))
    }

    fn encode_plaintext(&self) -> Result<Vec<u8>, KeyringError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.fixed(&self.store_id.0);
        out.u16(KEYRING_FORMAT_VERSION);
        out.u64(self.generation);
        encode_recipients(&mut out, self.recipients);
        encode_key(&mut out, &self.record_current);
        out.u8(self.record_predecessors.len() as u8);
        for key in &self.record_predecessors {
            encode_key(&mut out, key);
        }
        encode_key(&mut out, &self.credential_verifier);
        encode_key(&mut out, &self.metadata_integrity);
        out.u8(self.audit_payload.len() as u8);
        for key in &self.audit_payload {
            encode_key(&mut out, key);
        }
        encode_key(&mut out, &self.audit_index);
        let encoded = out.finish();
        if encoded.len() > MAX_KEYRING_PLAINTEXT {
            return Err(KeyringError::Limit);
        }
        Ok(encoded)
    }

    fn decode_plaintext(bytes: &[u8]) -> Result<Self, KeyringError> {
        if bytes.len() > MAX_KEYRING_PLAINTEXT {
            return Err(KeyringError::Limit);
        }
        let mut input = Decoder::version(bytes, 1)?;
        let store_id = StoreId(input.fixed()?);
        if input.u16()? != KEYRING_FORMAT_VERSION {
            return Err(KeyringError::Version);
        }
        let generation = input.u64()?;
        let recipients = decode_recipients(&mut input)?;
        let record_current = decode_key(&mut input)?;
        let predecessor_count = input.u8()? as usize;
        if predecessor_count > MAX_RECORD_GENERATIONS {
            return Err(KeyringError::Limit);
        }
        let mut record_predecessors = Vec::with_capacity(predecessor_count);
        for _ in 0..predecessor_count {
            record_predecessors.push(decode_key(&mut input)?);
        }
        let credential_verifier = decode_key(&mut input)?;
        let metadata_integrity = decode_key(&mut input)?;
        let audit_count = input.u8()? as usize;
        if !(1..=MAX_AUDIT_PAYLOAD_GENERATIONS).contains(&audit_count) {
            return Err(KeyringError::Limit);
        }
        let mut audit_payload = Vec::with_capacity(audit_count);
        for _ in 0..audit_count {
            audit_payload.push(decode_key(&mut input)?);
        }
        let audit_index = decode_key(&mut input)?;
        input.finish()?;
        let value = Self {
            store_id,
            generation,
            recipients,
            record_current,
            record_predecessors,
            credential_verifier,
            metadata_integrity,
            audit_payload,
            audit_index,
            record_decrypt_attempts: AtomicUsize::new(0),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), KeyringError> {
        if self.generation == 0
            || self.record_predecessors.len() > MAX_RECORD_GENERATIONS
            || !(1..=MAX_AUDIT_PAYLOAD_GENERATIONS).contains(&self.audit_payload.len())
        {
            return Err(KeyringError::Limit);
        }
        let ids = self.all_keys().map(PurposeKey::id).collect::<BTreeSet<_>>();
        let count = 4 + self.record_predecessors.len() + self.audit_payload.len();
        if ids.len() != count {
            return Err(KeyringError::DuplicateKeyId);
        }
        Ok(())
    }

    fn all_keys(&self) -> impl Iterator<Item = &PurposeKey> {
        std::iter::once(&self.record_current)
            .chain(&self.record_predecessors)
            .chain(std::iter::once(&self.credential_verifier))
            .chain(std::iter::once(&self.metadata_integrity))
            .chain(&self.audit_payload)
            .chain(std::iter::once(&self.audit_index))
    }

    fn encryption_key(&self, domain: RecordDomain) -> &PurposeKey {
        match domain {
            RecordDomain::AuditPayload => self
                .audit_payload
                .last()
                .expect("keyring validation requires one audit key"),
            RecordDomain::SecretValue | RecordDomain::CredentialMaterial => &self.record_current,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn storage_path(mount: &str, path: &LogicalPath) -> Result<LogicalPath, SecretDataError> {
    Ok(LogicalPath::new(format!("{mount}/{}", path.as_str()))?)
}

#[cfg_attr(not(test), allow(dead_code))]
fn default_secret_metadata() -> SecretMetadata {
    SecretMetadata {
        schema_version: METADATA_SCHEMA_VERSION,
        custom: Default::default(),
        max_versions: 10,
        cas_required: false,
        last_completed_rotation_unix_seconds: None,
        rotation_interval_seconds: None,
        rotation_state: RotationState::Idle,
        rotation_protection: None,
        versions: VersionSetSummary::empty(),
    }
}

fn generate_key(
    random: &mut impl RandomSource,
    ids: &mut BTreeSet<KeyId>,
) -> Result<PurposeKey, KeyringError> {
    for _ in 0..16 {
        let mut id = [0; 16];
        let mut material = [0; 32];
        random.fill(&mut id)?;
        random.fill(&mut material)?;
        let id = KeyId(id);
        if ids.insert(id) {
            return Ok(PurposeKey {
                id,
                material: SecretBox::new(Box::new(material)),
            });
        }
        material.fill(0);
    }
    Err(KeyringError::DuplicateKeyId)
}

fn encode_key(out: &mut Encoder, key: &PurposeKey) {
    out.fixed(&key.id.0);
    out.fixed(key.expose());
}

fn decode_key(input: &mut Decoder<'_>) -> Result<PurposeKey, KeyringError> {
    Ok(PurposeKey {
        id: KeyId(input.fixed()?),
        material: SecretBox::new(Box::new(input.fixed()?)),
    })
}

fn encode_recipients(out: &mut Encoder, recipients: RecipientSet) {
    out.fixed(&recipients.active.0);
    match recipients.recovery {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(&value.0);
        }
    }
}

fn decode_recipients(input: &mut Decoder<'_>) -> Result<RecipientSet, KeyringError> {
    let active = RecipientFingerprint(input.fixed()?);
    let recovery = match input.u8()? {
        0 => None,
        1 => Some(RecipientFingerprint(input.fixed()?)),
        _ => return Err(KeyringError::Invalid),
    };
    if recovery == Some(active) {
        return Err(KeyringError::RecipientSet);
    }
    Ok(RecipientSet { active, recovery })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyringMetadata {
    pub generation: u64,
    pub format_version: u16,
    pub recipients: RecipientSet,
    pub last_rewrap_audit_sequence: u64,
}

impl Canonical for KeyringMetadata {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.u64(self.generation);
        out.u16(self.format_version);
        encode_recipients(&mut out, self.recipients);
        out.u64(self.last_rewrap_audit_sequence);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            generation: input.u64()?,
            format_version: input.u16()?,
            recipients: decode_recipients(&mut input).map_err(|_| CodecError::Invalid)?,
            last_rewrap_audit_sequence: input.u64()?,
        };
        input.finish()?;
        Ok(value)
    }
}

impl ClearRecord for KeyringMetadata {
    const CLASS: RecordClass = RecordClass::KeyringMetadata;
    const SCHEMA_VERSION: u16 = 1;
}

pub struct PreparedKeyring {
    pub store_id: StoreId,
    pub envelope: KeyringEnvelope,
    pub metadata: Sealed<KeyringMetadata>,
    pub provisional_meta: Option<Sealed<ProvisionalMetaRecord>>,
}

pub fn prepare_keyring(
    store_id: StoreId,
    generation: u64,
    active: &x25519::Recipient,
    recovery: Option<&x25519::Recipient>,
    random: &mut impl RandomSource,
) -> Result<PreparedKeyring, KeyringError> {
    let recipients = RecipientSet::new(active, recovery)?;
    let keyring = Keyring::generate(store_id, generation, recipients, random)?;
    let envelope = keyring.wrap(active, recovery)?;
    let metadata = Sealed::seal(
        KeyringMetadata {
            generation,
            format_version: KEYRING_FORMAT_VERSION,
            recipients,
            last_rewrap_audit_sequence: 0,
        },
        generation,
        keyring.metadata_integrity_key(),
        store_id,
        super::KEYRING_METADATA_KEY,
    )?;
    Ok(PreparedKeyring {
        store_id,
        envelope,
        metadata,
        provisional_meta: None,
    })
}

pub fn prepare_keyring_for_init(
    provisional_meta: ProvisionalMetaRecord,
    generation: u64,
    active_identity: &x25519::Identity,
    recovery: Option<&x25519::Recipient>,
    random: &mut impl RandomSource,
) -> Result<PreparedKeyring, KeyringError> {
    let store_id = provisional_meta.store_id;
    let active = active_identity.to_public();
    let mut prepared = prepare_keyring(store_id, generation, &active, recovery, random)?;
    let opened = KeyringOpener::default().open(
        store_id,
        &prepared.envelope,
        &prepared.metadata,
        active_identity,
    )?;
    prepared.provisional_meta =
        Some(opened.seal_clear(provisional_meta, generation, super::PROVISIONAL_META_KEY)?);
    Ok(prepared)
}

pub struct KeyringOpener {
    attempts: AtomicUsize,
}

impl Default for KeyringOpener {
    fn default() -> Self {
        Self {
            attempts: AtomicUsize::new(0),
        }
    }
}

impl KeyringOpener {
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Acquire)
    }

    pub fn open(
        &self,
        clear_store_id: StoreId,
        envelope: &KeyringEnvelope,
        metadata: &Sealed<KeyringMetadata>,
        identity: &x25519::Identity,
    ) -> Result<Keyring, KeyringError> {
        self.open_with_metadata_integrity_handler(
            clear_store_id,
            envelope,
            metadata,
            identity,
            |_| {},
        )
    }

    pub(crate) fn open_with_metadata_integrity_handler<F: FnOnce(&[u8; 32])>(
        &self,
        clear_store_id: StoreId,
        envelope: &KeyringEnvelope,
        metadata: &Sealed<KeyringMetadata>,
        identity: &x25519::Identity,
        on_integrity_failure: F,
    ) -> Result<Keyring, KeyringError> {
        if self
            .attempts
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(KeyringError::AlreadyOpened);
        }
        if envelope.0.len() > MAX_AGE_ENVELOPE {
            return Err(KeyringError::Limit);
        }
        let plaintext =
            Zeroizing::new(age::decrypt(identity, &envelope.0).map_err(|_| KeyringError::Decrypt)?);
        let keyring = Keyring::decode_plaintext(&plaintext)?;
        if keyring.store_id != clear_store_id {
            return Err(KeyringError::StoreMismatch);
        }
        if metadata
            .verify(
                keyring.metadata_integrity_key(),
                clear_store_id,
                super::KEYRING_METADATA_KEY,
            )
            .is_err()
        {
            on_integrity_failure(keyring.metadata_integrity_key());
            return Err(KeyringError::MetadataIntegrity);
        }
        if metadata.generation != keyring.generation
            || metadata.value.generation != keyring.generation
            || metadata.value.format_version != KEYRING_FORMAT_VERSION
            || metadata.value.recipients != keyring.recipients
        {
            return Err(KeyringError::MetadataMismatch);
        }
        Ok(keyring)
    }
}

pub fn parse_identity(bytes: Zeroizing<Vec<u8>>) -> Result<x25519::Identity, KeyringError> {
    let value = std::str::from_utf8(&bytes).map_err(|_| KeyringError::Identity)?;
    value.trim().parse().map_err(|_| KeyringError::Identity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityPurpose {
    Active,
    Recovery,
    AuditExport,
}

impl IdentityPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Recovery => "recovery",
            Self::AuditExport => "audit-export",
        }
    }
}

impl FromStr for IdentityPurpose {
    type Err = AgeIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "recovery" => Ok(Self::Recovery),
            "audit-export" => Ok(Self::AuditExport),
            _ => Err(AgeIdentityError::Purpose),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgeIdentityMetadata {
    pub purpose: &'static str,
    pub algorithm: &'static str,
    pub recipient: String,
    pub fingerprint: String,
    pub sink_outcome_id: String,
}

pub fn generate_age_identity<W: Write + AsFd>(
    purpose: IdentityPurpose,
    sink: &mut W,
    random: &mut impl RandomSource,
) -> Result<AgeIdentityMetadata, AgeIdentityError> {
    crate::init::validate_secret_sink(sink.as_fd()).map_err(|_| AgeIdentityError::UnsafeSink)?;

    let mut seed = Zeroizing::new([0_u8; 32]);
    random
        .fill(seed.as_mut())
        .map_err(|_| AgeIdentityError::Random)?;
    let hrp = bech32::Hrp::parse("age-secret-key-").map_err(|_| AgeIdentityError::Encoding)?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, seed.as_ref())
        .map_err(|_| AgeIdentityError::Encoding)?;
    let encoded = Zeroizing::new(encoded.to_uppercase());
    let identity = x25519::Identity::from_str(&encoded).map_err(|_| AgeIdentityError::Encoding)?;
    let recipient = identity.to_public();
    let fingerprint = RecipientFingerprint::of(&recipient);
    let fingerprint = encode_hex(&fingerprint.0);
    let mut outcome = blake3::Hasher::new();
    outcome.update(b"ops-light-secrets-server.age-identity-sink.v1\0");
    outcome.update(purpose.as_str().as_bytes());
    outcome.update(fingerprint.as_bytes());
    let sink_outcome_id = encode_hex(&outcome.finalize().as_bytes()[..8]);

    let private = identity.to_string();
    sink.write_all(private.expose_secret().as_bytes())
        .and_then(|()| sink.write_all(b"\n"))
        .and_then(|()| sink.flush())
        .map_err(|_| AgeIdentityError::Disclosure)?;

    Ok(AgeIdentityMetadata {
        purpose: purpose.as_str(),
        algorithm: "age-x25519",
        recipient: recipient.to_string(),
        fingerprint,
        sink_outcome_id,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgeIdentityError {
    Purpose,
    UnsafeSink,
    Random,
    Encoding,
    Disclosure,
}

impl fmt::Display for AgeIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Purpose => "age identity purpose invalid",
            Self::UnsafeSink => "age identity private sink unsafe",
            Self::Random => "age identity random source failed",
            Self::Encoding => "age identity encoding failed",
            Self::Disclosure => "age identity private disclosure failed",
        })
    }
}

impl std::error::Error for AgeIdentityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyringError {
    Random,
    Invalid,
    Limit,
    Version,
    DuplicateKeyId,
    RecipientSet,
    Encrypt,
    Decrypt,
    Identity,
    AlreadyOpened,
    StoreMismatch,
    MetadataIntegrity,
    MetadataMismatch,
    GenerationMismatch,
    Codec,
}

impl fmt::Display for KeyringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Random => "keyring random source failed",
            Self::Invalid => "keyring is invalid",
            Self::Limit => "keyring limit exceeded",
            Self::Version => "keyring version unsupported",
            Self::DuplicateKeyId => "keyring key ids are not unique",
            Self::RecipientSet => "keyring recipient set invalid",
            Self::Encrypt => "keyring envelope encryption failed",
            Self::Decrypt => "keyring envelope decryption failed",
            Self::Identity => "age identity invalid",
            Self::AlreadyOpened => "keyring open already attempted",
            Self::StoreMismatch => "keyring store id mismatch",
            Self::MetadataIntegrity => "keyring metadata integrity failed",
            Self::MetadataMismatch => "keyring metadata mismatch",
            Self::GenerationMismatch => "keyring generation mismatch",
            Self::Codec => "keyring canonical encoding invalid",
        })
    }
}

impl std::error::Error for KeyringError {}

impl From<CodecError> for KeyringError {
    fn from(_: CodecError) -> Self {
        Self::Codec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    struct Counter(u8);

    impl RandomSource for Counter {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
            self.0 = self.0.wrapping_add(1);
            output.fill(self.0);
            Ok(())
        }
    }

    struct Collision;

    impl RandomSource for Collision {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
            output.fill(0);
            Ok(())
        }
    }

    fn generated() -> (x25519::Identity, Keyring) {
        let identity: x25519::Identity = IDENTITY.parse().unwrap();
        let recipient = identity.to_public();
        let set = RecipientSet::new(&recipient, None).unwrap();
        let keyring = Keyring::generate(StoreId([7; 16]), 1, set, &mut Counter(0)).unwrap();
        (identity, keyring)
    }

    #[test]
    fn purpose_keys_are_unique_and_plaintext_codec_is_strict() {
        let (_, keyring) = generated();
        assert_eq!(
            keyring
                .all_keys()
                .map(PurposeKey::id)
                .collect::<BTreeSet<_>>()
                .len(),
            5
        );
        let encoded = keyring.encode_plaintext().unwrap();
        let decoded = Keyring::decode_plaintext(&encoded).unwrap();
        assert_eq!(decoded.store_id(), StoreId([7; 16]));
        assert_eq!(decoded.generation(), 1);
        assert_eq!(
            decoded.all_keys().map(PurposeKey::id).collect::<Vec<_>>(),
            keyring.all_keys().map(PurposeKey::id).collect::<Vec<_>>()
        );
        for length in 0..encoded.len() {
            assert!(Keyring::decode_plaintext(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Keyring::decode_plaintext(&trailing).is_err());
        let mut unknown = encoded;
        unknown[0] = 2;
        assert_eq!(
            Keyring::decode_plaintext(&unknown).err(),
            Some(KeyringError::Codec)
        );

        assert_eq!(
            Keyring::generate(StoreId([7; 16]), 1, keyring.recipients(), &mut Collision,).err(),
            Some(KeyringError::DuplicateKeyId)
        );
    }

    #[test]
    fn envelope_opens_once_and_binds_store_and_metadata() {
        let (identity, keyring) = generated();
        let recipient = identity.to_public();
        let envelope = keyring.wrap(&recipient, None).unwrap();
        let metadata = Sealed::seal(
            KeyringMetadata {
                generation: 1,
                format_version: 1,
                recipients: keyring.recipients(),
                last_rewrap_audit_sequence: 0,
            },
            1,
            keyring.metadata_integrity_key(),
            StoreId([7; 16]),
            super::super::KEYRING_METADATA_KEY,
        )
        .unwrap();
        let opener = KeyringOpener::default();
        let opened = opener
            .open(StoreId([7; 16]), &envelope, &metadata, &identity)
            .unwrap();
        assert_eq!(opened.record_key_id(), keyring.record_key_id());
        assert_eq!(opener.attempts(), 1);
        assert_eq!(
            opener
                .open(StoreId([7; 16]), &envelope, &metadata, &identity)
                .err(),
            Some(KeyringError::AlreadyOpened)
        );

        let mismatch_opener = KeyringOpener::default();
        assert_eq!(
            mismatch_opener
                .open(StoreId([8; 16]), &envelope, &metadata, &identity)
                .err(),
            Some(KeyringError::StoreMismatch)
        );
        let wrong_identity = x25519::Identity::generate();
        assert_eq!(
            KeyringOpener::default()
                .open(StoreId([7; 16]), &envelope, &metadata, &wrong_identity)
                .err(),
            Some(KeyringError::Decrypt)
        );
    }

    #[test]
    fn metadata_mismatch_and_mac_edit_fail_after_decrypt() {
        let (identity, keyring) = generated();
        let recipient = identity.to_public();
        let envelope = keyring.wrap(&recipient, None).unwrap();
        let mismatched = Sealed::seal(
            KeyringMetadata {
                generation: 2,
                format_version: 1,
                recipients: keyring.recipients(),
                last_rewrap_audit_sequence: 0,
            },
            2,
            keyring.metadata_integrity_key(),
            StoreId([7; 16]),
            super::super::KEYRING_METADATA_KEY,
        )
        .unwrap();
        assert_eq!(
            KeyringOpener::default()
                .open(StoreId([7; 16]), &envelope, &mismatched, &identity)
                .err(),
            Some(KeyringError::MetadataMismatch)
        );
        let wrong_mac = Sealed::seal(
            KeyringMetadata {
                generation: 1,
                format_version: 1,
                recipients: keyring.recipients(),
                last_rewrap_audit_sequence: 0,
            },
            1,
            &[99; 32],
            StoreId([7; 16]),
            super::super::KEYRING_METADATA_KEY,
        )
        .unwrap();
        assert_eq!(
            KeyringOpener::default()
                .open(StoreId([7; 16]), &envelope, &wrong_mac, &identity)
                .err(),
            Some(KeyringError::MetadataIntegrity)
        );
    }

    #[test]
    fn audit_generation_capacity_and_final_slot_cas_are_bounded() {
        let (_, mut keyring) = generated();
        let mut random = Counter(20);
        while keyring.audit_payload_generations() < 23 {
            let generation = keyring.generation();
            keyring
                .append_audit_payload_key(generation, &mut random)
                .unwrap();
        }
        assert!(!keyring.audit_capacity_warning());
        keyring
            .append_audit_payload_key(keyring.generation(), &mut random)
            .unwrap();
        assert!(keyring.audit_capacity_warning());
        while keyring.audit_payload_generations() < 31 {
            let generation = keyring.generation();
            keyring
                .append_audit_payload_key(generation, &mut random)
                .unwrap();
        }
        assert_eq!(keyring.audit_payload_generations(), 31);
        let final_generation = keyring.generation();
        keyring
            .append_audit_payload_key(final_generation, &mut random)
            .unwrap();
        assert_eq!(keyring.audit_payload_generations(), 32);
        assert_eq!(
            keyring
                .append_audit_payload_key(final_generation, &mut random)
                .err(),
            Some(KeyringError::GenerationMismatch)
        );
        assert_eq!(
            keyring
                .append_audit_payload_key(keyring.generation(), &mut random)
                .err(),
            Some(KeyringError::Limit)
        );
        assert!(keyring.encode_plaintext().is_ok());

        let oversized = vec![0; MAX_KEYRING_PLAINTEXT + 1];
        assert_eq!(
            Keyring::decode_plaintext(&oversized).err(),
            Some(KeyringError::Limit)
        );
    }

    #[test]
    fn recipient_set_rejects_equality_and_both_recipients_decrypt() {
        let active: x25519::Identity = IDENTITY.parse().unwrap();
        let active_recipient = active.to_public();
        assert_eq!(
            RecipientSet::new(&active_recipient, Some(&active_recipient)).err(),
            Some(KeyringError::RecipientSet)
        );
        let recovery = x25519::Identity::generate();
        let recovery_recipient = recovery.to_public();
        let set = RecipientSet::new(&active_recipient, Some(&recovery_recipient)).unwrap();
        let keyring = Keyring::generate(StoreId([7; 16]), 1, set, &mut Counter(0)).unwrap();
        let envelope = keyring
            .wrap(&active_recipient, Some(&recovery_recipient))
            .unwrap();
        let active_plain = Zeroizing::new(age::decrypt(&active, &envelope.0).unwrap());
        let recovery_plain = Zeroizing::new(age::decrypt(&recovery, &envelope.0).unwrap());
        assert_eq!(&*active_plain, &*recovery_plain);
    }

    #[test]
    fn recipient_stanzas_use_canonical_fingerprint_order() {
        let active: x25519::Identity = IDENTITY.parse().unwrap();
        let recovery = x25519::Identity::generate();
        let active_recipient = active.to_public();
        let recovery_recipient = recovery.to_public();
        let set = RecipientSet::new(&active_recipient, Some(&recovery_recipient)).unwrap();
        let actual = set
            .ordered(&active_recipient, Some(&recovery_recipient))
            .into_iter()
            .map(|(fingerprint, _)| fingerprint)
            .collect::<Vec<_>>();
        let mut expected = vec![set.active, set.recovery.unwrap()];
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn two_final_slot_contenders_cannot_exceed_capacity() {
        use std::sync::{Arc, Barrier, Mutex};

        let (_, mut keyring) = generated();
        let mut random = Counter(20);
        while keyring.audit_payload_generations() < 31 {
            let generation = keyring.generation();
            keyring
                .append_audit_payload_key(generation, &mut random)
                .unwrap();
        }
        let expected_generation = keyring.generation();
        let shared = Arc::new(Mutex::new(keyring));
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for seed in [100, 150] {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                shared
                    .lock()
                    .unwrap()
                    .append_audit_payload_key(expected_generation, &mut Counter(seed))
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(KeyringError::GenerationMismatch))
                .count(),
            1
        );
        assert_eq!(shared.lock().unwrap().audit_payload_generations(), 32);
    }
}
