//! Canonical high-entropy credential wire format and fixed-work verifier.

use base64ct::{Base64UrlUnpadded, Encoding};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::identity::TokenStatus;
use crate::store::keyring::{KeyringError, RandomSource};
use crate::store::{Canonical, ClearRecord, CodecError, Decoder, Encoder, RecordClass, StoreId};

pub const CREDENTIAL_FORMAT_VERSION: u16 = 1;
pub const ACCESSOR_BYTES: usize = 16;
pub const SECRET_BYTES: usize = 32;
pub const ACCESSOR_TEXT_BYTES: usize = 22;
pub const SECRET_TEXT_BYTES: usize = 43;
pub const ACCESSOR_COLLISION_ATTEMPTS: usize = 8;

pub const DIRECT_TOKEN_MIN_TTL_SECONDS: u64 = 300;
pub const DIRECT_TOKEN_DEFAULT_TTL_SECONDS: u64 = 86_400;
pub const DIRECT_TOKEN_MAX_TTL_SECONDS: u64 = 2_592_000;
pub const ROLE_TOKEN_MIN_TTL_SECONDS: u64 = 60;
pub const ROLE_TOKEN_DEFAULT_TTL_SECONDS: u64 = 3_600;
pub const ROLE_TOKEN_MAX_TTL_SECONDS: u64 = 86_400;
pub const SECRET_ID_MIN_TTL_SECONDS: u64 = 300;
pub const SECRET_ID_DEFAULT_TTL_SECONDS: u64 = 86_400;
pub const SECRET_ID_MAX_TTL_SECONDS: u64 = 2_592_000;
pub const SECRET_ID_MIN_USES: u32 = 1;
pub const SECRET_ID_MAX_USES: u32 = 1_000;

const MAX_LABEL: usize = 255;
const DUMMY_ACCESSOR: CredentialAccessor = CredentialAccessor([0; ACCESSOR_BYTES]);
const DUMMY_SECRET: [u8; SECRET_BYTES] = [0; SECRET_BYTES];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialKind {
    Token = 1,
    SecretId = 2,
}

impl CredentialKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::SecretId => "secret-id",
        }
    }

    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Token),
            2 => Ok(Self::SecretId),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialAudience {
    Control = 1,
    Data = 2,
}

impl CredentialAudience {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
        }
    }

    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Data),
            _ => Err(CodecError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialAccessor(pub [u8; ACCESSOR_BYTES]);

impl fmt::Display for CredentialAccessor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = Base64UrlUnpadded::encode_string(&self.0);
        write!(formatter, "{}…", &encoded[..8])
    }
}

#[derive(Eq, PartialEq)]
pub struct CredentialWire {
    pub kind: CredentialKind,
    pub audience: CredentialAudience,
    pub accessor: CredentialAccessor,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl CredentialWire {
    pub fn new(
        kind: CredentialKind,
        audience: CredentialAudience,
        accessor: CredentialAccessor,
        secret: [u8; SECRET_BYTES],
    ) -> Result<Self, CredentialError> {
        if accessor == DUMMY_ACCESSOR || secret == DUMMY_SECRET {
            return Err(CredentialError::Invalid);
        }
        Ok(Self {
            kind,
            audience,
            accessor,
            secret: Zeroizing::new(secret),
        })
    }

    pub fn parse(value: &str) -> Result<Self, CredentialError> {
        let mut fields = value.split('.');
        let kind = match fields.next() {
            Some("token") => CredentialKind::Token,
            Some("secret-id") => CredentialKind::SecretId,
            _ => return Err(CredentialError::Invalid),
        };
        let audience = match fields.next() {
            Some("control") => CredentialAudience::Control,
            Some("data") => CredentialAudience::Data,
            _ => return Err(CredentialError::Invalid),
        };
        let accessor_text = fields.next().ok_or(CredentialError::Invalid)?;
        let secret_text = fields.next().ok_or(CredentialError::Invalid)?;
        if fields.next().is_some()
            || accessor_text.len() != ACCESSOR_TEXT_BYTES
            || secret_text.len() != SECRET_TEXT_BYTES
            || accessor_text.contains('=')
            || secret_text.contains('=')
        {
            return Err(CredentialError::Invalid);
        }
        let mut accessor = [0; ACCESSOR_BYTES];
        let mut secret = [0; SECRET_BYTES];
        Base64UrlUnpadded::decode(accessor_text, &mut accessor)
            .map_err(|_| CredentialError::Invalid)?;
        Base64UrlUnpadded::decode(secret_text, &mut secret)
            .map_err(|_| CredentialError::Invalid)?;
        let wire = Self::new(kind, audience, CredentialAccessor(accessor), secret)?;
        if wire.encode() != value {
            return Err(CredentialError::Invalid);
        }
        Ok(wire)
    }

    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.kind.label(),
            self.audience.label(),
            Base64UrlUnpadded::encode_string(&self.accessor.0),
            Base64UrlUnpadded::encode_string(&self.secret[..])
        )
    }

    fn secret(&self) -> &[u8; SECRET_BYTES] {
        &self.secret
    }
}

impl fmt::Debug for CredentialWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialWire([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRecord {
    pub id: [u8; 16],
    pub accessor: CredentialAccessor,
    pub verifier: [u8; 32],
    pub kind: CredentialKind,
    pub audience: CredentialAudience,
    pub identity_id: [u8; 16],
    pub issue_epoch: u64,
    pub expires_at_effective_seconds: u64,
    pub status: TokenStatus,
    pub generation: u64,
    pub label: String,
    pub created_at_effective_seconds: u64,
    pub issuer_identity_id: [u8; 16],
    pub issuance_request_id: [u8; 16],
    pub parent_accessor: Option<CredentialAccessor>,
    pub consumer_instance_id: Option<[u8; 16]>,
}

impl CredentialRecord {
    fn validate(&self) -> Result<(), CodecError> {
        if self.id == [0; 16]
            || self.accessor == DUMMY_ACCESSOR
            || self.identity_id == [0; 16]
            || self.issue_epoch == 0
            || self.generation == 0
            || self.label.is_empty()
            || self.label.len() > MAX_LABEL
            || self.label.contains(['\0', '/', '\n', '\r'])
            || self.created_at_effective_seconds == 0
            || self.expires_at_effective_seconds <= self.created_at_effective_seconds
            || self.issuer_identity_id == [0; 16]
            || self.issuance_request_id == [0; 16]
        {
            return Err(CodecError::Invalid);
        }
        Ok(())
    }

    pub fn revoke(&self, expected_generation: u64) -> Result<Self, CredentialError> {
        if self.status != TokenStatus::Active || self.generation != expected_generation {
            return Err(CredentialError::Conflict);
        }
        let mut replacement = self.clone();
        replacement.status = TokenStatus::Revoked;
        replacement.generation = replacement
            .generation
            .checked_add(1)
            .ok_or(CredentialError::Invalid)?;
        Ok(replacement)
    }
}

impl Canonical for CredentialRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Encoder::version(1);
        out.u16(CREDENTIAL_FORMAT_VERSION);
        out.fixed(&self.id);
        out.fixed(&self.accessor.0);
        out.fixed(&self.verifier);
        out.u8(self.kind as u8);
        out.u8(self.audience as u8);
        out.fixed(&self.identity_id);
        out.u64(self.issue_epoch);
        out.u64(self.expires_at_effective_seconds);
        out.u8(match self.status {
            TokenStatus::Active => 1,
            TokenStatus::Revoked => 2,
        });
        out.u64(self.generation);
        out.string(&self.label, MAX_LABEL)?;
        out.u64(self.created_at_effective_seconds);
        out.fixed(&self.issuer_identity_id);
        out.fixed(&self.issuance_request_id);
        encode_optional_accessor(&mut out, self.parent_accessor);
        encode_optional_fixed(&mut out, self.consumer_instance_id);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        if input.u16()? != CREDENTIAL_FORMAT_VERSION {
            return Err(CodecError::UnknownVersion);
        }
        let value = Self {
            id: input.fixed()?,
            accessor: CredentialAccessor(input.fixed()?),
            verifier: input.fixed()?,
            kind: CredentialKind::decode(input.u8()?)?,
            audience: CredentialAudience::decode(input.u8()?)?,
            identity_id: input.fixed()?,
            issue_epoch: input.u64()?,
            expires_at_effective_seconds: input.u64()?,
            status: match input.u8()? {
                1 => TokenStatus::Active,
                2 => TokenStatus::Revoked,
                _ => return Err(CodecError::Invalid),
            },
            generation: input.u64()?,
            label: input.string(MAX_LABEL)?,
            created_at_effective_seconds: input.u64()?,
            issuer_identity_id: input.fixed()?,
            issuance_request_id: input.fixed()?,
            parent_accessor: decode_optional_accessor(&mut input)?,
            consumer_instance_id: decode_optional_fixed(&mut input)?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl ClearRecord for CredentialRecord {
    const CLASS: RecordClass = RecordClass::CredentialMetadata;
    const SCHEMA_VERSION: u16 = CREDENTIAL_FORMAT_VERSION;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialEpoch {
    pub current: u64,
    pub generation: u64,
}

impl CredentialEpoch {
    pub fn bump(&self, expected: u64) -> Result<Self, CredentialError> {
        if self.current != expected || self.generation != expected {
            return Err(CredentialError::Conflict);
        }
        let next = expected.checked_add(1).ok_or(CredentialError::Invalid)?;
        Ok(Self {
            current: next,
            generation: next,
        })
    }
}

impl Canonical for CredentialEpoch {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.current == 0 || self.generation != self.current {
            return Err(CodecError::Invalid);
        }
        let mut out = Encoder::version(1);
        out.u64(self.current);
        out.u64(self.generation);
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = Decoder::version(bytes, 1)?;
        let value = Self {
            current: input.u64()?,
            generation: input.u64()?,
        };
        input.finish()?;
        if value.current == 0 || value.generation != value.current {
            return Err(CodecError::Invalid);
        }
        Ok(value)
    }
}

impl ClearRecord for CredentialEpoch {
    const CLASS: RecordClass = RecordClass::CredentialMetadata;
    const SCHEMA_VERSION: u16 = 2;
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IssuedCredential {
    wire: String,
    #[zeroize(skip)]
    pub record: CredentialRecord,
}

impl IssuedCredential {
    pub fn expose_once(&self) -> &str {
        &self.wire
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIssueMetadata {
    pub id: [u8; 16],
    pub identity_id: [u8; 16],
    pub kind: CredentialKind,
    pub audience: CredentialAudience,
    pub issue_epoch: u64,
    pub expires_at_effective_seconds: u64,
    pub created_at_effective_seconds: u64,
    pub issuer_identity_id: [u8; 16],
    pub issuance_request_id: [u8; 16],
    pub parent_accessor: Option<CredentialAccessor>,
    pub consumer_instance_id: Option<[u8; 16]>,
}

impl CredentialIssueMetadata {
    pub fn token_from_secret_id(
        parent: &CredentialRecord,
        id: [u8; 16],
        created_at_effective_seconds: u64,
        expires_at_effective_seconds: u64,
        issuance_request_id: [u8; 16],
    ) -> Result<Self, CredentialError> {
        if parent.kind != CredentialKind::SecretId || parent.status != TokenStatus::Active {
            return Err(CredentialError::Invalid);
        }
        Ok(Self {
            id,
            identity_id: parent.identity_id,
            kind: CredentialKind::Token,
            audience: CredentialAudience::Data,
            issue_epoch: parent.issue_epoch,
            expires_at_effective_seconds,
            created_at_effective_seconds,
            issuer_identity_id: parent.identity_id,
            issuance_request_id,
            parent_accessor: Some(parent.accessor),
            consumer_instance_id: parent.consumer_instance_id,
        })
    }

    pub fn require_workload_tracking(
        consumer_instance_id: Option<[u8; 16]>,
        identity_only_accepted: bool,
    ) -> Result<Option<[u8; 16]>, CredentialError> {
        if consumer_instance_id.is_none() && !identity_only_accepted {
            Err(CredentialError::Invalid)
        } else {
            Ok(consumer_instance_id)
        }
    }
}

pub fn issue_credential(
    verifier_key: &[u8; 32],
    store_id: StoreId,
    metadata: CredentialIssueMetadata,
    label: String,
    accessor_exists: &mut impl FnMut(CredentialAccessor) -> bool,
    random: &mut impl RandomSource,
) -> Result<IssuedCredential, CredentialError> {
    let mut accessor = None;
    for _ in 0..ACCESSOR_COLLISION_ATTEMPTS {
        let mut bytes = [0; ACCESSOR_BYTES];
        random.fill(&mut bytes).map_err(CredentialError::Random)?;
        let candidate = CredentialAccessor(bytes);
        if candidate != DUMMY_ACCESSOR && !accessor_exists(candidate) {
            accessor = Some(candidate);
            break;
        }
    }
    let accessor = accessor.ok_or(CredentialError::CollisionExhausted)?;
    let mut secret = Zeroizing::new([0; SECRET_BYTES]);
    random.fill(&mut *secret).map_err(CredentialError::Random)?;
    if *secret == DUMMY_SECRET {
        return Err(CredentialError::Random(KeyringError::Random));
    }
    let verifier = credential_mac(
        verifier_key,
        store_id,
        metadata.kind,
        metadata.audience,
        accessor,
        metadata.issue_epoch,
        &secret,
    );
    let wire = CredentialWire::new(metadata.kind, metadata.audience, accessor, *secret)?.encode();
    let record = CredentialRecord {
        id: metadata.id,
        accessor,
        verifier,
        kind: metadata.kind,
        audience: metadata.audience,
        identity_id: metadata.identity_id,
        issue_epoch: metadata.issue_epoch,
        expires_at_effective_seconds: metadata.expires_at_effective_seconds,
        status: TokenStatus::Active,
        generation: 1,
        label,
        created_at_effective_seconds: metadata.created_at_effective_seconds,
        issuer_identity_id: metadata.issuer_identity_id,
        issuance_request_id: metadata.issuance_request_id,
        parent_accessor: metadata.parent_accessor,
        consumer_instance_id: metadata.consumer_instance_id,
    };
    record.validate()?;
    Ok(IssuedCredential { wire, record })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRejectReason {
    Malformed,
    WrongKind,
    WrongAudience,
    UnknownAccessor,
    InvalidSecret,
    EpochChanged,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierWork {
    pub accessor_lookups: u8,
    pub epoch_reads: u8,
    pub mac_computations: u8,
    pub compared_bytes: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialVerification {
    pub authenticated_id: Option<[u8; 16]>,
    pub reason: Option<CredentialRejectReason>,
    pub work: VerifierWork,
}

#[derive(Clone, Copy)]
pub struct CredentialVerificationContext<'a> {
    pub expected_kind: CredentialKind,
    pub expected_audience: CredentialAudience,
    pub current_epoch: u64,
    pub effective_seconds: u64,
    pub store_id: StoreId,
    pub verifier_key: &'a [u8; 32],
}

pub fn verify_credential(
    raw: &str,
    context: CredentialVerificationContext<'_>,
    lookup: &impl Fn(CredentialAccessor) -> Option<CredentialRecord>,
) -> CredentialVerification {
    let parsed = CredentialWire::parse(raw);
    let (accessor, secret, surface_ok, parse_reason) = match &parsed {
        Ok(wire) => (
            wire.accessor,
            *wire.secret(),
            wire.kind == context.expected_kind && wire.audience == context.expected_audience,
            if wire.kind != context.expected_kind {
                Some(CredentialRejectReason::WrongKind)
            } else if wire.audience != context.expected_audience {
                Some(CredentialRejectReason::WrongAudience)
            } else {
                None
            },
        ),
        Err(_) => (
            DUMMY_ACCESSOR,
            DUMMY_SECRET,
            false,
            Some(CredentialRejectReason::Malformed),
        ),
    };
    let found = surface_ok.then(|| lookup(accessor)).flatten();
    let (record, expected, exists) = match found {
        Some(record) => {
            let expected = record.verifier;
            (Some(record), expected, true)
        }
        None => (None, [0; 32], false),
    };
    let actual = record.as_ref().map_or_else(
        || {
            credential_mac(
                context.verifier_key,
                context.store_id,
                context.expected_kind,
                context.expected_audience,
                DUMMY_ACCESSOR,
                context.current_epoch,
                &secret,
            )
        },
        |record| {
            credential_mac(
                context.verifier_key,
                context.store_id,
                record.kind,
                record.audience,
                record.accessor,
                record.issue_epoch,
                &secret,
            )
        },
    );
    let mac_valid = constant_time_equal(&actual, &expected);
    let reason = parse_reason.or_else(|| {
        let record = record.as_ref()?;
        if !exists {
            Some(CredentialRejectReason::UnknownAccessor)
        } else if !mac_valid {
            Some(CredentialRejectReason::InvalidSecret)
        } else if record.issue_epoch != context.current_epoch {
            Some(CredentialRejectReason::EpochChanged)
        } else if record.status == TokenStatus::Revoked {
            Some(CredentialRejectReason::Revoked)
        } else if context.effective_seconds >= record.expires_at_effective_seconds {
            Some(CredentialRejectReason::Expired)
        } else {
            None
        }
    });
    let reason = reason.or((!exists).then_some(CredentialRejectReason::UnknownAccessor));
    CredentialVerification {
        authenticated_id: reason.is_none().then(|| record.as_ref().unwrap().id),
        reason,
        work: VerifierWork {
            accessor_lookups: 1,
            epoch_reads: 1,
            mac_computations: 1,
            compared_bytes: 32,
        },
    }
}

pub fn credential_mac(
    key: &[u8; 32],
    store_id: StoreId,
    kind: CredentialKind,
    audience: CredentialAudience,
    accessor: CredentialAccessor,
    issue_epoch: u64,
    secret: &[u8; SECRET_BYTES],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"ops-light-secrets-server.credential-verifier.v1\0");
    for field in [
        &store_id.0[..],
        &[kind as u8],
        &[audience as u8],
        &accessor.0,
        &issue_epoch.to_be_bytes(),
        secret,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub fn validate_ttl(value: u64, minimum: u64, maximum: u64) -> Result<u64, CredentialError> {
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or(CredentialError::Invalid)
}

pub fn validate_secret_id_uses(value: u32) -> Result<u32, CredentialError> {
    (SECRET_ID_MIN_USES..=SECRET_ID_MAX_USES)
        .contains(&value)
        .then_some(value)
        .ok_or(CredentialError::Invalid)
}

#[derive(Debug)]
pub enum CredentialError {
    Invalid,
    Conflict,
    CollisionExhausted,
    Random(KeyringError),
}

impl From<CodecError> for CredentialError {
    fn from(_: CodecError) -> Self {
        Self::Invalid
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential operation failed")
    }
}

impl std::error::Error for CredentialError {}

fn encode_optional_accessor(out: &mut Encoder, value: Option<CredentialAccessor>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(&value.0);
        }
    }
}

fn decode_optional_accessor(
    input: &mut Decoder<'_>,
) -> Result<Option<CredentialAccessor>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(CredentialAccessor(input.fixed()?))),
        _ => Err(CodecError::Invalid),
    }
}

fn encode_optional_fixed(out: &mut Encoder, value: Option<[u8; 16]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.fixed(&value);
        }
    }
}

fn decode_optional_fixed(input: &mut Decoder<'_>) -> Result<Option<[u8; 16]>, CodecError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.fixed()?)),
        _ => Err(CodecError::Invalid),
    }
}
