//! Bounded audit reads and authenticated, recipient-fixed audit exports.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;

use age::x25519;
use age::{Encryptor, Recipient};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::backup::{ObservedPublication, PublicationState};
use crate::store::keyring::{Keyring, RecipientFingerprint};
use crate::store::{
    AuditEvent, AuditOperation, AuditOutcome, AuditResource, Canonical, CodecError, Decoder,
    Encoder, StoredAuditEntry,
};

pub const MAX_QUERY_PAGE: usize = 100;
pub const MAX_EXPORT_MEMBERS: usize = 10_000;
pub const MAX_EXPORT_EVIDENCE: usize = 256;
pub const MAX_EXPORT_RECIPIENTS: usize = 8;
pub const AUDIT_EXPORT_SIGNING_DOMAIN_ID: u16 = 3;
const MAX_MEMBER_BYTES: usize = 512 * 1024;
const MAX_VIEW_BYTES: usize = 8192;
const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024 * 1024;
const ARTIFACT_DOMAIN: &[u8] = b"audit-export-artifact-v1";
const SIGNATURE_DOMAIN: &[u8] = b"ops-light-secrets-server.audit-export-signature.v1\0";

#[derive(Debug, Eq, PartialEq)]
pub enum AuditExportError {
    Invalid,
    Unauthorized,
    Conflict,
    NotFound,
    AbandonRequired,
    Codec,
    Crypto,
}

impl fmt::Display for AuditExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "audit export input invalid",
            Self::Unauthorized => "audit export authorization refused",
            Self::Conflict => "audit export state conflict",
            Self::NotFound => "audit export not found",
            Self::AbandonRequired => "audit export owner abandonment required",
            Self::Codec => "audit export canonical codec failed",
            Self::Crypto => "audit export cryptographic verification failed",
        })
    }
}

impl std::error::Error for AuditExportError {}

impl From<CodecError> for AuditExportError {
    fn from(_: CodecError) -> Self {
        Self::Codec
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditFilter {
    pub minimum_timestamp_milliseconds: Option<u64>,
    pub maximum_timestamp_milliseconds: Option<u64>,
    pub identity_id: Option<[u8; 16]>,
    pub canonical_path_prefix: Option<String>,
    pub outcome: Option<AuditOutcome>,
    pub operation: Option<AuditOperation>,
    pub minimum_sequence: Option<u64>,
    pub maximum_sequence: Option<u64>,
}

impl AuditFilter {
    pub fn validate(&self) -> Result<(), AuditExportError> {
        if self.minimum_timestamp_milliseconds > self.maximum_timestamp_milliseconds
            || self.minimum_sequence > self.maximum_sequence
            || self.minimum_sequence == Some(0)
            || self
                .canonical_path_prefix
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
        {
            return Err(AuditExportError::Invalid);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], AuditExportError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        optional_u64(&mut out, self.minimum_timestamp_milliseconds);
        optional_u64(&mut out, self.maximum_timestamp_milliseconds);
        optional_fixed(&mut out, self.identity_id.as_ref());
        optional_string(&mut out, self.canonical_path_prefix.as_deref())?;
        optional_u16(&mut out, self.outcome.map(|value| value as u16));
        optional_u16(&mut out, self.operation.map(|value| value as u16));
        optional_u64(&mut out, self.minimum_sequence);
        optional_u64(&mut out, self.maximum_sequence);
        Ok(domain_digest(
            b"ops-light-secrets-server.audit-filter.v1\0",
            &out.finish(),
        ))
    }

    fn matches(&self, entry: &StoredAuditEntry, event: &AuditEvent) -> bool {
        let sequence = entry.envelope.epoch_sequence;
        let timestamp = event.effective_timestamp_milliseconds;
        self.minimum_timestamp_milliseconds.is_none_or(|value| timestamp >= value)
            && self.maximum_timestamp_milliseconds.is_none_or(|value| timestamp <= value)
            && self.minimum_sequence.is_none_or(|value| sequence >= value)
            && self.maximum_sequence.is_none_or(|value| sequence <= value)
            && self.identity_id.is_none_or(|value| {
                event.authentication.identity_id == Some(value)
            })
            && self.outcome.is_none_or(|value| event.outcome == value)
            && self.operation.is_none_or(|value| event.operation == value)
            && self.canonical_path_prefix.as_ref().is_none_or(|prefix| {
                matches!(&event.resource, Some(AuditResource::Canonical(path)) if path.starts_with(prefix))
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCursor {
    pub store_incarnation_id: [u8; 16],
    pub cutoff_sequence: u64,
    pub filter_digest: [u8; 32],
    pub after_sequence: u64,
    pub authenticator: [u8; 32],
}

impl AuditCursor {
    pub fn new(
        key: &[u8; 32],
        store_incarnation_id: [u8; 16],
        cutoff_sequence: u64,
        filter_digest: [u8; 32],
        after_sequence: u64,
    ) -> Self {
        let authenticator = cursor_authenticator(
            key,
            store_incarnation_id,
            cutoff_sequence,
            filter_digest,
            after_sequence,
        );
        Self {
            store_incarnation_id,
            cutoff_sequence,
            filter_digest,
            after_sequence,
            authenticator,
        }
    }

    fn verify(&self, key: &[u8; 32]) -> bool {
        self.authenticator
            == cursor_authenticator(
                key,
                self.store_incarnation_id,
                self.cutoff_sequence,
                self.filter_digest,
                self.after_sequence,
            )
    }
}

/// Deliberately safe decoded projection. It has no credential, request body, or
/// secret-value field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditView {
    pub epoch: [u8; 16],
    pub sequence: u64,
    pub event_id: [u8; 16],
    pub request_id: [u8; 16],
    pub identity_id: Option<[u8; 16]>,
    pub credential_accessor: Option<[u8; 16]>,
    pub consumer_instance_id: Option<[u8; 16]>,
    pub canonical_resource: Option<String>,
    pub operation: u16,
    pub outcome: u16,
    pub reason: u16,
    pub effective_timestamp_milliseconds: u64,
    pub wall_clock_observation_milliseconds: u64,
    pub secret_version: Option<u64>,
}

impl AuditView {
    fn from_event(entry: &StoredAuditEntry, event: &AuditEvent) -> Self {
        Self {
            epoch: entry.envelope.audit_epoch,
            sequence: entry.envelope.epoch_sequence,
            event_id: event.event_id,
            request_id: event.request_id,
            identity_id: event.authentication.identity_id,
            credential_accessor: event.authentication.credential_accessor,
            consumer_instance_id: event.consumer_instance_id,
            canonical_resource: match &event.resource {
                Some(AuditResource::Canonical(value)) => Some(value.clone()),
                _ => None,
            },
            operation: event.operation as u16,
            outcome: event.outcome as u16,
            reason: event.reason as u16,
            effective_timestamp_milliseconds: event.effective_timestamp_milliseconds,
            wall_clock_observation_milliseconds: event.wall_clock_observation_milliseconds,
            secret_version: event.secret_version,
        }
    }
}

impl Zeroize for AuditView {
    fn zeroize(&mut self) {
        self.event_id.zeroize();
        self.request_id.zeroize();
        self.identity_id.zeroize();
        self.credential_accessor.zeroize();
        self.consumer_instance_id.zeroize();
        self.canonical_resource.zeroize();
        self.secret_version.zeroize();
    }
}

impl Canonical for AuditView {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Encoder::version(1);
        out.fixed(&self.epoch);
        out.u64(self.sequence);
        out.fixed(&self.event_id);
        out.fixed(&self.request_id);
        optional_fixed(&mut out, self.identity_id.as_ref());
        optional_fixed(&mut out, self.credential_accessor.as_ref());
        optional_fixed(&mut out, self.consumer_instance_id.as_ref());
        optional_string(&mut out, self.canonical_resource.as_deref())?;
        out.u16(self.operation);
        out.u16(self.outcome);
        out.u16(self.reason);
        out.u64(self.effective_timestamp_milliseconds);
        out.u64(self.wall_clock_observation_milliseconds);
        optional_u64(&mut out, self.secret_version);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            epoch: input.fixed()?,
            sequence: input.u64()?,
            event_id: input.fixed()?,
            request_id: input.fixed()?,
            identity_id: decode_optional_fixed(&mut input)?,
            credential_accessor: decode_optional_fixed(&mut input)?,
            consumer_instance_id: decode_optional_fixed(&mut input)?,
            canonical_resource: decode_optional_string(&mut input)?,
            operation: input.u16()?,
            outcome: input.u16()?,
            reason: input.u16()?,
            effective_timestamp_milliseconds: input.u64()?,
            wall_clock_observation_milliseconds: input.u64()?,
            secret_version: decode_optional_u64(&mut input)?,
        };
        input.finish()?;
        if value.epoch == [0; 16] || value.sequence == 0 || value.event_id == [0; 16] {
            return Err(CodecError::Invalid);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPage {
    pub cutoff_sequence: u64,
    pub views: Vec<AuditView>,
    pub next_cursor: Option<AuditCursor>,
}

pub struct AuditQueryRequest<'a> {
    pub store_incarnation_id: [u8; 16],
    pub filter: &'a AuditFilter,
    pub limit: usize,
    pub cursor: Option<&'a AuditCursor>,
    pub cursor_key: &'a [u8; 32],
    pub authorized: bool,
}

/// Builds a page privately, then invokes the final authorization+audit barrier.
/// An error from that barrier releases no page.
pub fn query_snapshot(
    entries: &[StoredAuditEntry],
    keyring: &Keyring,
    request: AuditQueryRequest<'_>,
    final_barrier: impl FnOnce() -> Result<(), AuditExportError>,
) -> Result<AuditPage, AuditExportError> {
    request.filter.validate()?;
    if !request.authorized
        || request.store_incarnation_id == [0; 16]
        || !(1..=MAX_QUERY_PAGE).contains(&request.limit)
    {
        return Err(AuditExportError::Unauthorized);
    }
    let filter_digest = request.filter.digest()?;
    let cutoff = entries
        .iter()
        .map(|entry| entry.envelope.epoch_sequence)
        .max()
        .unwrap_or(0);
    let after = match request.cursor {
        None => 0,
        Some(cursor)
            if cursor.verify(request.cursor_key)
                && cursor.store_incarnation_id == request.store_incarnation_id
                && cursor.cutoff_sequence == cutoff
                && cursor.filter_digest == filter_digest =>
        {
            cursor.after_sequence
        }
        Some(_) => return Err(AuditExportError::Conflict),
    };
    let mut views = Zeroizing::new(Vec::with_capacity(request.limit));
    let mut has_more = false;
    for entry in entries.iter().filter(|entry| {
        entry.envelope.epoch_sequence > after && entry.envelope.epoch_sequence <= cutoff
    }) {
        let event = entry
            .decrypt(keyring)
            .map_err(|_| AuditExportError::Crypto)?;
        if request.filter.matches(entry, event.expose_secret()) {
            if views.len() == request.limit {
                has_more = true;
                break;
            }
            views.push(AuditView::from_event(entry, event.expose_secret()));
        }
    }
    final_barrier()?;
    let last = views.last().map(|view| view.sequence).unwrap_or(after);
    let next_cursor = has_more.then(|| {
        AuditCursor::new(
            request.cursor_key,
            request.store_incarnation_id,
            cutoff,
            filter_digest,
            last,
        )
    });
    Ok(AuditPage {
        cutoff_sequence: cutoff,
        views: std::mem::take(&mut *views),
        next_cursor,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportRecipientCatalog {
    generation: u64,
    recipients: Vec<x25519::Recipient>,
}

impl AuditExportRecipientCatalog {
    pub fn new(
        generation: u64,
        mut recipients: Vec<x25519::Recipient>,
    ) -> Result<Self, AuditExportError> {
        recipients.sort_by_key(RecipientFingerprint::of);
        if generation == 0
            || !(1..=MAX_EXPORT_RECIPIENTS).contains(&recipients.len())
            || recipients.windows(2).any(|pair| {
                RecipientFingerprint::of(&pair[0]) == RecipientFingerprint::of(&pair[1])
            })
        {
            return Err(AuditExportError::Invalid);
        }
        Ok(Self {
            generation,
            recipients,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn recipients(&self) -> &[x25519::Recipient] {
        &self.recipients
    }
    pub fn fingerprints(&self) -> Vec<[u8; 32]> {
        self.recipients
            .iter()
            .map(|value| RecipientFingerprint::of(value).0)
            .collect()
    }

    pub fn replace(
        &mut self,
        request: RecipientMutation,
        final_barrier: impl FnOnce() -> Result<(), AuditExportError>,
    ) -> Result<u64, AuditExportError> {
        let candidate = Self::new(
            request
                .expected_generation
                .checked_add(1)
                .ok_or(AuditExportError::Invalid)?,
            request.recipients,
        )?;
        if !request.authorized
            || self.generation != request.expected_generation
            || !valid_reason(request.reason)
            || !valid_reason(request.blast_radius)
            || request.confirmation
                != recipient_confirmation(
                    request.expected_generation,
                    &candidate.recipients,
                    request.reason,
                    request.blast_radius,
                )
        {
            return Err(AuditExportError::Unauthorized);
        }
        final_barrier()?;
        *self = candidate;
        Ok(self.generation)
    }
}

pub struct RecipientMutation<'a> {
    pub expected_generation: u64,
    pub recipients: Vec<x25519::Recipient>,
    pub reason: &'a str,
    pub blast_radius: &'a str,
    pub confirmation: [u8; 32],
    pub authorized: bool,
}

pub fn recipient_confirmation(
    expected_generation: u64,
    recipients: &[x25519::Recipient],
    reason: &str,
    blast_radius: &str,
) -> [u8; 32] {
    let mut fingerprints = recipients
        .iter()
        .map(|value| RecipientFingerprint::of(value).0)
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ops-light-secrets-server.audit-export-recipients.v1\0");
    hasher.update(&expected_generation.to_be_bytes());
    for fingerprint in fingerprints {
        hasher.update(&fingerprint);
    }
    hasher.update(&(reason.len() as u64).to_be_bytes());
    hasher.update(reason.as_bytes());
    hasher.update(&(blast_radius.len() as u64).to_be_bytes());
    hasher.update(blast_radius.as_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    Checkpoint = 1,
    TrustTransition = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportEvidence {
    pub epoch: [u8; 16],
    pub kind: EvidenceKind,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportMember {
    pub epoch: [u8; 16],
    pub sequence: u64,
    pub event_id: [u8; 16],
    pub ciphertext_digest: [u8; 32],
    pub original_digest: [u8; 32],
    pub view_digest: [u8; 32],
    pub original: Vec<u8>,
    pub view: AuditView,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportManifest {
    pub bundle_id: [u8; 16],
    pub store_incarnation_id: [u8; 16],
    pub minimum_sequence: u64,
    pub maximum_sequence: u64,
    pub cutoff_sequence: u64,
    pub filter_digest: [u8; 32],
    pub recipient_generation: u64,
    pub recipient_fingerprints: Vec<[u8; 32]>,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub signing_transition_digest: [u8; 32],
    pub anchored_epochs: Vec<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportPayload {
    pub manifest: AuditExportManifest,
    pub members: Vec<ExportMember>,
    pub evidence: Vec<ExportEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportHeader {
    pub bundle_id: [u8; 16],
    pub store_incarnation_id: [u8; 16],
    pub signing_key_id: [u8; 16],
    pub signing_domain: u16,
    pub signing_lineage_generation: u64,
    pub recipient_generation: u64,
    pub encrypted_payload_length: u64,
    pub encrypted_payload_digest: [u8; 32],
    pub inner_manifest_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportContainer {
    pub header: AuditExportHeader,
    pub encrypted_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedAuditExport {
    pub container: AuditExportContainer,
    pub artifact_digest: [u8; 32],
    pub manifest: AuditExportManifest,
}

pub struct AuditExportCreateRequest<'a> {
    pub bundle_id: [u8; 16],
    pub store_incarnation_id: [u8; 16],
    pub minimum_sequence: u64,
    pub maximum_sequence: u64,
    pub filter: &'a AuditFilter,
    pub recipients: &'a AuditExportRecipientCatalog,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub signing_transition_digest: [u8; 32],
    pub evidence: Vec<ExportEvidence>,
    pub authorized: bool,
}

pub fn create_export(
    entries: &[StoredAuditEntry],
    keyring: &Keyring,
    request: AuditExportCreateRequest<'_>,
    final_barrier: impl FnOnce() -> Result<(), AuditExportError>,
) -> Result<CreatedAuditExport, AuditExportError> {
    request.filter.validate()?;
    if !request.authorized
        || request.bundle_id == [0; 16]
        || request.store_incarnation_id == [0; 16]
        || request.signing_key_id == [0; 16]
        || request.signing_lineage_generation == 0
        || request.minimum_sequence == 0
        || request.minimum_sequence > request.maximum_sequence
        || request.maximum_sequence - request.minimum_sequence >= MAX_EXPORT_MEMBERS as u64
    {
        return Err(AuditExportError::Unauthorized);
    }
    validate_evidence(&request.evidence)?;
    let cutoff = entries
        .iter()
        .map(|entry| entry.envelope.epoch_sequence)
        .max()
        .unwrap_or(0);
    if request.maximum_sequence > cutoff {
        return Err(AuditExportError::Conflict);
    }
    let mut members = Vec::new();
    for entry in entries.iter().filter(|entry| {
        (request.minimum_sequence..=request.maximum_sequence)
            .contains(&entry.envelope.epoch_sequence)
    }) {
        let event = entry
            .decrypt(keyring)
            .map_err(|_| AuditExportError::Crypto)?;
        if !request.filter.matches(entry, event.expose_secret()) {
            continue;
        }
        let view = AuditView::from_event(entry, event.expose_secret());
        let original = entry.encode()?;
        let view_bytes = Zeroizing::new(view.encode()?);
        members.push(ExportMember {
            epoch: entry.envelope.audit_epoch,
            sequence: entry.envelope.epoch_sequence,
            event_id: event.expose_secret().event_id,
            ciphertext_digest: entry.envelope.ciphertext_digest,
            original_digest: domain_digest(
                b"ops-light-secrets-server.audit-export-original.v1\0",
                &original,
            ),
            view_digest: domain_digest(
                b"ops-light-secrets-server.audit-export-view.v1\0",
                &view_bytes,
            ),
            original,
            view,
        });
    }
    validate_members(&members)?;
    let anchored_epochs = anchored_epochs(&members, &request.evidence);
    let manifest = AuditExportManifest {
        bundle_id: request.bundle_id,
        store_incarnation_id: request.store_incarnation_id,
        minimum_sequence: request.minimum_sequence,
        maximum_sequence: request.maximum_sequence,
        cutoff_sequence: cutoff,
        filter_digest: request.filter.digest()?,
        recipient_generation: request.recipients.generation(),
        recipient_fingerprints: request.recipients.fingerprints(),
        signing_key_id: request.signing_key_id,
        signing_lineage_generation: request.signing_lineage_generation,
        signing_transition_digest: request.signing_transition_digest,
        anchored_epochs,
    };
    let payload = AuditExportPayload {
        manifest: manifest.clone(),
        members,
        evidence: request.evidence,
    };
    let plaintext = Zeroizing::new(payload.encode()?);
    let recipients: Vec<&dyn Recipient> = request
        .recipients
        .recipients()
        .iter()
        .map(|value| value as &dyn Recipient)
        .collect();
    let encryptor =
        Encryptor::with_recipients(recipients.into_iter()).map_err(|_| AuditExportError::Crypto)?;
    let mut encrypted_payload = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted_payload)
        .map_err(|_| AuditExportError::Crypto)?;
    writer
        .write_all(&plaintext)
        .and_then(|()| writer.finish())
        .map_err(|_| AuditExportError::Crypto)?;
    let header = AuditExportHeader {
        bundle_id: request.bundle_id,
        store_incarnation_id: request.store_incarnation_id,
        signing_key_id: request.signing_key_id,
        signing_domain: AUDIT_EXPORT_SIGNING_DOMAIN_ID,
        signing_lineage_generation: request.signing_lineage_generation,
        recipient_generation: request.recipients.generation(),
        encrypted_payload_length: encrypted_payload.len() as u64,
        encrypted_payload_digest: *blake3::hash(&encrypted_payload).as_bytes(),
        inner_manifest_digest: manifest.digest()?,
    };
    let container = AuditExportContainer {
        header,
        encrypted_payload,
    };
    let artifact_digest = artifact_digest(&container)?;
    final_barrier()?;
    Ok(CreatedAuditExport {
        container,
        artifact_digest,
        manifest,
    })
}

pub fn decrypt_export(
    container: &AuditExportContainer,
    identity: &x25519::Identity,
) -> Result<AuditExportPayload, AuditExportError> {
    container.validate()?;
    let plaintext = Zeroizing::new(
        age::decrypt(identity, &container.encrypted_payload)
            .map_err(|_| AuditExportError::Crypto)?,
    );
    let payload = AuditExportPayload::decode(&plaintext)?;
    verify_payload_bindings(container, &payload)?;
    Ok(payload)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedAuditExportSignature {
    pub key_id: [u8; 16],
    pub content_digest: [u8; 32],
    pub signature: [u8; 64],
}

pub fn sign_export(
    container: &AuditExportContainer,
    expected_public_key: &[u8; 32],
    private_key: &mut [u8; 32],
) -> Result<DetachedAuditExportSignature, AuditExportError> {
    let secret = Zeroizing::new(*private_key);
    private_key.zeroize();
    let key = SigningKey::from_bytes(&secret);
    if key.verifying_key().as_bytes() != expected_public_key {
        return Err(AuditExportError::Crypto);
    }
    let digest = artifact_digest(container)?;
    Ok(DetachedAuditExportSignature {
        key_id: container.header.signing_key_id,
        content_digest: digest,
        signature: key
            .sign(&signature_message(container.header.signing_key_id, digest))
            .to_bytes(),
    })
}

pub fn verify_export(
    container: &AuditExportContainer,
    signature: Option<&DetachedAuditExportSignature>,
    public_key: &[u8; 32],
    trusted_key_id: [u8; 16],
    trusted_lineage_generation: u64,
    allow_unsigned_confirmation: Option<[u8; 32]>,
) -> Result<(), AuditExportError> {
    container.validate()?;
    if container.header.signing_key_id != trusted_key_id
        || container.header.signing_lineage_generation > trusted_lineage_generation
    {
        return Err(AuditExportError::Crypto);
    }
    let digest = artifact_digest(container)?;
    match signature {
        Some(value) => {
            if value.key_id != trusted_key_id || value.content_digest != digest {
                return Err(AuditExportError::Crypto);
            }
            let key = VerifyingKey::from_bytes(public_key).map_err(|_| AuditExportError::Crypto)?;
            key.verify(
                &signature_message(value.key_id, digest),
                &Signature::from_bytes(&value.signature),
            )
            .map_err(|_| AuditExportError::Crypto)
        }
        None if allow_unsigned_confirmation == Some(unsigned_confirmation(digest)) => Ok(()),
        None => Err(AuditExportError::Unauthorized),
    }
}

pub fn unsigned_confirmation(digest: [u8; 32]) -> [u8; 32] {
    domain_digest(
        b"ops-light-secrets-server.audit-export-allow-unsigned.v1\0",
        &digest,
    )
}

pub fn artifact_digest(container: &AuditExportContainer) -> Result<[u8; 32], AuditExportError> {
    container.validate()?;
    let header = container.header.encode()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARTIFACT_DOMAIN);
    hasher.update(&(header.len() as u64).to_be_bytes());
    hasher.update(&header);
    hasher.update(&container.header.encrypted_payload_digest);
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditExportRecord {
    pub artifact_digest: [u8; 32],
    pub inner_manifest_digest: [u8; 32],
    pub output_id: [u8; 16],
    pub owner_id: [u8; 16],
    pub target_identity_digest: [u8; 32],
    pub content_digest: [u8; 32],
    pub minimum_sequence: u64,
    pub maximum_sequence: u64,
    pub signing_key_id: [u8; 16],
    pub signing_lineage_generation: u64,
    pub recipient_generation: u64,
    pub publication: PublicationState,
    pub signature_registered: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditExportCatalogFilter {
    pub publication: Option<PublicationState>,
    pub signature_registered: Option<bool>,
}

#[derive(Default)]
pub struct AuditExportCatalog {
    records: BTreeMap<[u8; 32], AuditExportRecord>,
}

pub struct ExportSignatureRegistration<'a> {
    pub digest: [u8; 32],
    pub container: &'a AuditExportContainer,
    pub signature: &'a DetachedAuditExportSignature,
    pub public_key: &'a [u8; 32],
    pub current_key_id: [u8; 16],
    pub current_generation: u64,
    pub authorized: bool,
}

impl AuditExportCatalog {
    pub fn reserve(
        &mut self,
        record: AuditExportRecord,
        authorized: bool,
    ) -> Result<(), AuditExportError> {
        if !authorized
            || record.artifact_digest == [0; 32]
            || record.output_id == [0; 16]
            || record.owner_id == [0; 16]
            || record.target_identity_digest == [0; 32]
            || record.content_digest == [0; 32]
            || record.publication != PublicationState::Publishing
            || record.signature_registered
        {
            return Err(AuditExportError::Unauthorized);
        }
        match self.records.get(&record.artifact_digest) {
            Some(existing) if existing == &record => Ok(()),
            Some(_) => Err(AuditExportError::Conflict),
            None => {
                self.records.insert(record.artifact_digest, record);
                Ok(())
            }
        }
    }

    pub fn show(&self, digest: [u8; 32]) -> Result<&AuditExportRecord, AuditExportError> {
        self.records.get(&digest).ok_or(AuditExportError::NotFound)
    }

    pub fn list(
        &self,
        after: Option<[u8; 32]>,
        limit: usize,
        filter: AuditExportCatalogFilter,
    ) -> Result<Vec<&AuditExportRecord>, AuditExportError> {
        if !(1..=MAX_QUERY_PAGE).contains(&limit) {
            return Err(AuditExportError::Invalid);
        }
        Ok(self
            .records
            .iter()
            .filter(|(digest, _)| after.is_none_or(|value| **digest > value))
            .map(|(_, record)| record)
            .filter(|record| {
                filter
                    .publication
                    .is_none_or(|value| record.publication == value)
                    && filter
                        .signature_registered
                        .is_none_or(|value| record.signature_registered == value)
            })
            .take(limit)
            .collect())
    }

    pub fn resume(
        &mut self,
        digest: [u8; 32],
        observation: ObservedPublication,
        authorized: bool,
    ) -> Result<PublicationState, AuditExportError> {
        if !authorized {
            return Err(AuditExportError::Unauthorized);
        }
        let record = self
            .records
            .get_mut(&digest)
            .ok_or(AuditExportError::NotFound)?;
        if matches!(
            record.publication,
            PublicationState::Published | PublicationState::Registered
        ) {
            return Ok(record.publication);
        }
        if record.publication != PublicationState::Publishing {
            return Err(AuditExportError::Conflict);
        }
        match observation {
            ObservedPublication::ExactTemp | ObservedPublication::ExactFinal => {
                record.publication = PublicationState::Published;
                Ok(record.publication)
            }
            _ => Err(AuditExportError::AbandonRequired),
        }
    }

    pub fn register_signature(
        &mut self,
        request: ExportSignatureRegistration<'_>,
    ) -> Result<(), AuditExportError> {
        if !request.authorized || artifact_digest(request.container)? != request.digest {
            return Err(AuditExportError::Unauthorized);
        }
        let record = self
            .records
            .get_mut(&request.digest)
            .ok_or(AuditExportError::NotFound)?;
        if record.signature_registered {
            return Ok(());
        }
        if record.publication != PublicationState::Published
            || record.signing_key_id != request.current_key_id
            || record.signing_lineage_generation != request.current_generation
        {
            return Err(AuditExportError::Conflict);
        }
        verify_export(
            request.container,
            Some(request.signature),
            request.public_key,
            request.current_key_id,
            request.current_generation,
            None,
        )?;
        record.signature_registered = true;
        record.publication = PublicationState::Registered;
        Ok(())
    }

    pub fn abandon(
        &mut self,
        digest: [u8; 32],
        expected_generation: u64,
        reason: &str,
        confirmation: [u8; 32],
        authorized: bool,
    ) -> Result<(), AuditExportError> {
        if !authorized
            || !valid_reason(reason)
            || confirmation != abandon_confirmation(digest, expected_generation, reason)
        {
            return Err(AuditExportError::Unauthorized);
        }
        let record = self
            .records
            .get_mut(&digest)
            .ok_or(AuditExportError::NotFound)?;
        if record.signing_lineage_generation != expected_generation {
            return Err(AuditExportError::Conflict);
        }
        if record.signature_registered || record.publication == PublicationState::Registered {
            return Err(AuditExportError::Conflict);
        }
        record.publication = PublicationState::Abandoned;
        Ok(())
    }
}

pub fn abandon_confirmation(digest: [u8; 32], generation: u64, reason: &str) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(40 + reason.len());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(reason.as_bytes());
    domain_digest(
        b"ops-light-secrets-server.audit-export-abandon.v1\0",
        &bytes,
    )
}

impl Canonical for AuditExportManifest {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.bundle_id == [0; 16]
            || self.store_incarnation_id == [0; 16]
            || self.minimum_sequence == 0
            || self.minimum_sequence > self.maximum_sequence
            || self.maximum_sequence > self.cutoff_sequence
            || self.recipient_generation == 0
            || !(1..=MAX_EXPORT_RECIPIENTS).contains(&self.recipient_fingerprints.len())
            || self
                .recipient_fingerprints
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.signing_key_id == [0; 16]
            || self.signing_lineage_generation == 0
            || self
                .anchored_epochs
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.fixed(&self.bundle_id);
        out.fixed(&self.store_incarnation_id);
        out.u64(self.minimum_sequence);
        out.u64(self.maximum_sequence);
        out.u64(self.cutoff_sequence);
        out.fixed(&self.filter_digest);
        out.u64(self.recipient_generation);
        out.u8(self.recipient_fingerprints.len() as u8);
        for value in &self.recipient_fingerprints {
            out.fixed(value);
        }
        out.fixed(&self.signing_key_id);
        out.u64(self.signing_lineage_generation);
        out.fixed(&self.signing_transition_digest);
        out.u16(self.anchored_epochs.len() as u16);
        for value in &self.anchored_epochs {
            out.fixed(value);
        }
        Ok(out.finish())
    }
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let bundle_id = input.fixed()?;
        let store_incarnation_id = input.fixed()?;
        let minimum_sequence = input.u64()?;
        let maximum_sequence = input.u64()?;
        let cutoff_sequence = input.u64()?;
        let filter_digest = input.fixed()?;
        let recipient_generation = input.u64()?;
        let count = input.u8()? as usize;
        if !(1..=MAX_EXPORT_RECIPIENTS).contains(&count) {
            return Err(CodecError::Limit);
        }
        let mut recipient_fingerprints = Vec::with_capacity(count);
        for _ in 0..count {
            recipient_fingerprints.push(input.fixed()?);
        }
        let signing_key_id = input.fixed()?;
        let signing_lineage_generation = input.u64()?;
        let signing_transition_digest = input.fixed()?;
        let count = input.u16()? as usize;
        if count > MAX_EXPORT_EVIDENCE {
            return Err(CodecError::Limit);
        }
        let mut anchored_epochs = Vec::with_capacity(count);
        for _ in 0..count {
            anchored_epochs.push(input.fixed()?);
        }
        input.finish()?;
        let value = Self {
            bundle_id,
            store_incarnation_id,
            minimum_sequence,
            maximum_sequence,
            cutoff_sequence,
            filter_digest,
            recipient_generation,
            recipient_fingerprints,
            signing_key_id,
            signing_lineage_generation,
            signing_transition_digest,
            anchored_epochs,
        };
        value.encode()?;
        Ok(value)
    }
}

impl AuditExportManifest {
    pub fn digest(&self) -> Result<[u8; 32], CodecError> {
        Ok(domain_digest(
            b"ops-light-secrets-server.audit-export-manifest.v1\0",
            &self.encode()?,
        ))
    }
}

impl Canonical for AuditExportPayload {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        validate_members(&self.members).map_err(|_| CodecError::Invalid)?;
        validate_evidence(&self.evidence).map_err(|_| CodecError::Invalid)?;
        let mut out = Encoder::version(1);
        out.bytes(&self.manifest.encode()?, 64 * 1024)?;
        out.u32(self.members.len() as u32);
        for member in &self.members {
            out.bytes(&encode_member(member)?, MAX_MEMBER_BYTES)?;
        }
        out.u16(self.evidence.len() as u16);
        for evidence in &self.evidence {
            out.bytes(&encode_evidence(evidence)?, MAX_EVIDENCE_BYTES)?;
        }
        let bytes = out.finish();
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(CodecError::Limit);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(CodecError::Limit);
        }
        let mut input = Decoder::version(bytes, 1)?;
        let manifest = AuditExportManifest::decode(&input.bytes(64 * 1024)?)?;
        let count = input.u32()? as usize;
        if count == 0 || count > MAX_EXPORT_MEMBERS {
            return Err(CodecError::Limit);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(decode_member(&input.bytes(MAX_MEMBER_BYTES)?)?)
        }
        let count = input.u16()? as usize;
        if count > MAX_EXPORT_EVIDENCE {
            return Err(CodecError::Limit);
        }
        let mut evidence = Vec::with_capacity(count);
        for _ in 0..count {
            evidence.push(decode_evidence(&input.bytes(MAX_EVIDENCE_BYTES)?)?)
        }
        input.finish()?;
        let value = Self {
            manifest,
            members,
            evidence,
        };
        value.encode()?;
        Ok(value)
    }
}

impl Canonical for AuditExportHeader {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.bundle_id == [0; 16]
            || self.store_incarnation_id == [0; 16]
            || self.signing_key_id == [0; 16]
            || self.signing_domain != AUDIT_EXPORT_SIGNING_DOMAIN_ID
            || self.signing_lineage_generation == 0
            || self.recipient_generation == 0
            || self.encrypted_payload_length == 0
            || self.encrypted_payload_length > MAX_PAYLOAD_BYTES as u64
        {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.fixed(&self.bundle_id);
        out.fixed(&self.store_incarnation_id);
        out.fixed(&self.signing_key_id);
        out.u16(self.signing_domain);
        out.u64(self.signing_lineage_generation);
        out.u64(self.recipient_generation);
        out.u64(self.encrypted_payload_length);
        out.fixed(&self.encrypted_payload_digest);
        out.fixed(&self.inner_manifest_digest);
        Ok(out.finish())
    }
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            bundle_id: input.fixed()?,
            store_incarnation_id: input.fixed()?,
            signing_key_id: input.fixed()?,
            signing_domain: input.u16()?,
            signing_lineage_generation: input.u64()?,
            recipient_generation: input.u64()?,
            encrypted_payload_length: input.u64()?,
            encrypted_payload_digest: input.fixed()?,
            inner_manifest_digest: input.fixed()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }
}

impl AuditExportContainer {
    fn validate(&self) -> Result<(), AuditExportError> {
        self.header.encode()?;
        if self.encrypted_payload.len() as u64 != self.header.encrypted_payload_length
            || *blake3::hash(&self.encrypted_payload).as_bytes()
                != self.header.encrypted_payload_digest
        {
            return Err(AuditExportError::Invalid);
        }
        Ok(())
    }
}
impl Canonical for AuditExportContainer {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate().map_err(|_| CodecError::Invalid)?;
        let mut out = Encoder::version(1);
        out.bytes(&self.header.encode()?, 1024)?;
        out.bytes(&self.encrypted_payload, MAX_PAYLOAD_BYTES)?;
        Ok(out.finish())
    }
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let header = AuditExportHeader::decode(&input.bytes(1024)?)?;
        let encrypted_payload = input.bytes(MAX_PAYLOAD_BYTES)?;
        input.finish()?;
        let value = Self {
            header,
            encrypted_payload,
        };
        value.validate().map_err(|_| CodecError::Invalid)?;
        Ok(value)
    }
}

impl Canonical for DetachedAuditExportSignature {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.key_id == [0; 16] || self.content_digest == [0; 32] {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.fixed(&self.key_id);
        out.fixed(&self.content_digest);
        out.fixed(&self.signature);
        Ok(out.finish())
    }
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            key_id: input.fixed()?,
            content_digest: input.fixed()?,
            signature: input.fixed()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }
}

fn encode_member(value: &ExportMember) -> Result<Vec<u8>, CodecError> {
    let view = value.view.encode()?;
    let original = StoredAuditEntry::decode(&value.original)?;
    if value.epoch != original.envelope.audit_epoch
        || value.sequence != original.envelope.epoch_sequence
        || value.ciphertext_digest != original.envelope.ciphertext_digest
        || value.original_digest
            != domain_digest(
                b"ops-light-secrets-server.audit-export-original.v1\0",
                &value.original,
            )
        || value.view_digest
            != domain_digest(b"ops-light-secrets-server.audit-export-view.v1\0", &view)
        || value.epoch != value.view.epoch
        || value.sequence != value.view.sequence
        || value.event_id != value.view.event_id
    {
        return Err(CodecError::Invalid);
    }
    let mut out = Encoder::version(1);
    out.fixed(&value.epoch);
    out.u64(value.sequence);
    out.fixed(&value.event_id);
    out.fixed(&value.ciphertext_digest);
    out.fixed(&value.original_digest);
    out.fixed(&value.view_digest);
    out.bytes(&value.original, MAX_MEMBER_BYTES)?;
    out.bytes(&view, MAX_VIEW_BYTES)?;
    Ok(out.finish())
}
fn decode_member(bytes: &[u8]) -> Result<ExportMember, CodecError> {
    let mut input = Decoder::version(bytes, 1)?;
    let value = ExportMember {
        epoch: input.fixed()?,
        sequence: input.u64()?,
        event_id: input.fixed()?,
        ciphertext_digest: input.fixed()?,
        original_digest: input.fixed()?,
        view_digest: input.fixed()?,
        original: input.bytes(MAX_MEMBER_BYTES)?,
        view: AuditView::decode(&input.bytes(MAX_VIEW_BYTES)?)?,
    };
    input.finish()?;
    encode_member(&value)?;
    Ok(value)
}
fn encode_evidence(value: &ExportEvidence) -> Result<Vec<u8>, CodecError> {
    if value.epoch == [0; 16] || value.bytes.is_empty() {
        return Err(CodecError::Invalid);
    }
    let mut out = Encoder::version(1);
    out.fixed(&value.epoch);
    out.u8(value.kind as u8);
    out.bytes(&value.bytes, MAX_EVIDENCE_BYTES)?;
    Ok(out.finish())
}
fn decode_evidence(bytes: &[u8]) -> Result<ExportEvidence, CodecError> {
    let mut input = Decoder::version(bytes, 1)?;
    let epoch = input.fixed()?;
    let kind = match input.u8()? {
        1 => EvidenceKind::Checkpoint,
        2 => EvidenceKind::TrustTransition,
        _ => return Err(CodecError::Invalid),
    };
    let bytes = input.bytes(MAX_EVIDENCE_BYTES)?;
    input.finish()?;
    let value = ExportEvidence { epoch, kind, bytes };
    encode_evidence(&value)?;
    Ok(value)
}

fn validate_members(values: &[ExportMember]) -> Result<(), AuditExportError> {
    if values.is_empty()
        || values.len() > MAX_EXPORT_MEMBERS
        || values
            .windows(2)
            .any(|pair| (pair[0].epoch, pair[0].sequence) >= (pair[1].epoch, pair[1].sequence))
    {
        return Err(AuditExportError::Invalid);
    }
    for value in values {
        encode_member(value)?;
    }
    Ok(())
}
fn validate_evidence(values: &[ExportEvidence]) -> Result<(), AuditExportError> {
    if values.len() > MAX_EXPORT_EVIDENCE
        || values
            .windows(2)
            .any(|pair| (pair[0].epoch, pair[0].kind as u8) >= (pair[1].epoch, pair[1].kind as u8))
    {
        return Err(AuditExportError::Invalid);
    }
    for value in values {
        encode_evidence(value)?;
    }
    Ok(())
}
fn anchored_epochs(members: &[ExportMember], evidence: &[ExportEvidence]) -> Vec<[u8; 16]> {
    let checkpoints: BTreeSet<_> = evidence
        .iter()
        .filter(|value| value.kind == EvidenceKind::Checkpoint)
        .map(|value| value.epoch)
        .collect();
    let epochs: BTreeSet<_> = members.iter().map(|value| value.epoch).collect();
    epochs.intersection(&checkpoints).copied().collect()
}
fn verify_payload_bindings(
    container: &AuditExportContainer,
    payload: &AuditExportPayload,
) -> Result<(), AuditExportError> {
    payload.encode()?;
    if payload.manifest.digest()? != container.header.inner_manifest_digest
        || payload.manifest.bundle_id != container.header.bundle_id
        || payload.manifest.store_incarnation_id != container.header.store_incarnation_id
        || payload.manifest.signing_key_id != container.header.signing_key_id
        || payload.manifest.signing_lineage_generation
            != container.header.signing_lineage_generation
        || payload.manifest.recipient_generation != container.header.recipient_generation
        || payload.manifest.anchored_epochs != anchored_epochs(&payload.members, &payload.evidence)
    {
        return Err(AuditExportError::Invalid);
    }
    for pair in payload.members.windows(2) {
        let previous = StoredAuditEntry::decode(&pair[0].original)?;
        let current = StoredAuditEntry::decode(&pair[1].original)?;
        if previous.envelope.audit_epoch == current.envelope.audit_epoch
            && (current.envelope.epoch_sequence != previous.envelope.epoch_sequence + 1
                || current.envelope.previous_hash != previous.envelope.chain_hash()?)
        {
            return Err(AuditExportError::Crypto);
        }
    }
    Ok(())
}
fn signature_message(key_id: [u8; 16], digest: [u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 48);
    value.extend_from_slice(SIGNATURE_DOMAIN);
    value.extend_from_slice(&key_id);
    value.extend_from_slice(&digest);
    value
}
fn cursor_authenticator(
    key: &[u8; 32],
    store: [u8; 16],
    cutoff: u64,
    filter: [u8; 32],
    after: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"ops-light-secrets-server.audit-cursor.v1\0");
    hasher.update(&store);
    hasher.update(&cutoff.to_be_bytes());
    hasher.update(&filter);
    hasher.update(&after.to_be_bytes());
    *hasher.finalize().as_bytes()
}
fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
fn valid_reason(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn optional_u64(out: &mut Encoder, value: Option<u64>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u64(value)
        }
    }
}
fn optional_u16(out: &mut Encoder, value: Option<u16>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.u16(value)
        }
    }
}
fn optional_fixed<const N: usize>(out: &mut Encoder, value: Option<&[u8; N]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(value)
        }
    }
}
fn optional_string(out: &mut Encoder, value: Option<&str>) -> Result<(), CodecError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.string(value, 4096)?
        }
    }
    Ok(())
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
fn decode_optional_string(input: &mut Decoder<'_>) -> Result<Option<String>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.string(4096)?)),
        _ => Err(CodecError::Invalid),
    }
}
fn decode_optional_u64(input: &mut Decoder<'_>) -> Result<Option<u64>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.u64()?)),
        _ => Err(CodecError::Invalid),
    }
}
