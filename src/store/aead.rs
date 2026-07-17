use super::keyring::{KeyId, KeyringError, RandomSource};
use super::{Canonical, CodecError, LogicalPath, StoreId};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const RECORD_FORMAT_VERSION: u16 = 1;
pub const CIPHER_SUITE_XCHACHA20_POLY1305: u16 = 1;
const RECORD_MAGIC: &[u8; 8] = b"OLSSREC\0";
const MAX_MOUNT: usize = 128;
const MAX_PATH: usize = 1024;
const MAX_PATH_SEGMENTS: usize = 256;
const MAX_LOGICAL_ID: usize = 256;
const MAX_HEADER: usize = 4096;
const MAX_CIPHERTEXT: usize = 8 * 1024 * 1024;

/// Owned server plaintext with no `Clone` or `Debug` implementation.
///
/// ```compile_fail
/// use ops_light_secrets_server::store::PlaintextSecret;
/// let secret = PlaintextSecret::new(vec![1]);
/// let _copy = secret.clone();
/// ```
///
/// ```compile_fail
/// use ops_light_secrets_server::store::PlaintextSecret;
/// let secret = PlaintextSecret::new(vec![1]);
/// println!("{secret:?}");
/// ```
pub struct PlaintextSecret(SecretBox<Vec<u8>>);

impl PlaintextSecret {
    pub fn new(value: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }

    pub(crate) fn from_secret_box(value: SecretBox<Vec<u8>>) -> Self {
        Self(value)
    }
}

impl ExposeSecret<Vec<u8>> for PlaintextSecret {
    fn expose_secret(&self) -> &Vec<u8> {
        self.0.expose_secret()
    }
}

impl Zeroize for PlaintextSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PlaintextSecret {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecordDomain {
    SecretValue = 1,
    AuditPayload = 2,
    CredentialMaterial = 3,
}

impl RecordDomain {
    fn decode(value: u16) -> Result<Self, RecordCryptoError> {
        match value {
            1 => Ok(Self::SecretValue),
            2 => Ok(Self::AuditPayload),
            3 => Ok(Self::CredentialMaterial),
            _ => Err(RecordCryptoError::UnknownDomain),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordBinding {
    domain: RecordDomain,
    mount: String,
    path: LogicalPath,
    logical_record_id: Vec<u8>,
    version: Option<u64>,
    created_unix_milliseconds: u64,
}

impl RecordBinding {
    pub fn new(
        domain: RecordDomain,
        mount: &str,
        path: LogicalPath,
        logical_record_id: &[u8],
        version: Option<u64>,
        created_unix_milliseconds: u64,
    ) -> Result<Self, RecordCryptoError> {
        let value = Self {
            domain,
            mount: mount.to_owned(),
            path,
            logical_record_id: logical_record_id.to_vec(),
            version,
            created_unix_milliseconds,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn domain(&self) -> RecordDomain {
        self.domain
    }

    pub fn version(&self) -> Option<u64> {
        self.version
    }

    pub fn created_unix_milliseconds(&self) -> u64 {
        self.created_unix_milliseconds
    }

    fn validate(&self) -> Result<(), RecordCryptoError> {
        if self.mount.is_empty()
            || self.mount.len() > MAX_MOUNT
            || self.mount.bytes().any(|byte| {
                byte == b'/' || byte == 0 || byte.is_ascii_control() || !byte.is_ascii()
            })
            || self.logical_record_id.is_empty()
            || self.logical_record_id.len() > MAX_LOGICAL_ID
            || self.path.as_str().len() > MAX_PATH
            || self.path.as_str().split('/').count() > MAX_PATH_SEGMENTS
            || matches!(self.version, Some(0))
            || (self.domain == RecordDomain::SecretValue) != self.version.is_some()
        {
            return Err(RecordCryptoError::Binding);
        }
        Ok(())
    }
}

impl fmt::Debug for RecordBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordBinding")
            .field("domain", &self.domain)
            .field("mount", &"[REDACTED]")
            .field("path", &"[REDACTED]")
            .field("logical_record_id", &"[REDACTED]")
            .field("version", &self.version)
            .field("created_unix_milliseconds", &self.created_unix_milliseconds)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordHeader {
    store_id: StoreId,
    binding: RecordBinding,
    key_id: KeyId,
    nonce: [u8; 24],
}

impl RecordHeader {
    #[doc(hidden)]
    pub fn new_for_test(
        store_id: StoreId,
        binding: RecordBinding,
        key_id: [u8; 16],
        nonce: [u8; 24],
    ) -> Result<Self, RecordCryptoError> {
        Self::new(store_id, binding, KeyId(key_id), nonce)
    }

    pub fn decode_strict(bytes: &[u8]) -> Result<Self, RecordCryptoError> {
        let mut input = HeaderDecoder::new(bytes);
        if input.fixed::<8>()? != *RECORD_MAGIC {
            return Err(RecordCryptoError::Magic);
        }
        if input.u16()? != RECORD_FORMAT_VERSION {
            return Err(RecordCryptoError::UnknownFormat);
        }
        if input.u16()? != CIPHER_SUITE_XCHACHA20_POLY1305 {
            return Err(RecordCryptoError::UnknownSuite);
        }
        let store_id = StoreId(input.fixed()?);
        let domain = RecordDomain::decode(input.u16()?)?;
        let key_id = KeyId(input.fixed()?);
        let nonce = input.fixed()?;
        let mount = input.string(MAX_MOUNT)?;
        let segment_count = input.u16()? as usize;
        if segment_count == 0 || segment_count > MAX_PATH_SEGMENTS {
            return Err(RecordCryptoError::Binding);
        }
        let mut segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            segments.push(input.string(MAX_PATH)?);
        }
        let path = LogicalPath::new(segments.join("/"))?;
        let logical_record_id = input.bytes(MAX_LOGICAL_ID)?;
        let version = match input.u8()? {
            0 => None,
            1 => Some(input.u64()?),
            _ => return Err(RecordCryptoError::Binding),
        };
        let created_unix_milliseconds = input.u64()?;
        input.finish()?;
        let binding = RecordBinding::new(
            domain,
            &mount,
            path,
            &logical_record_id,
            version,
            created_unix_milliseconds,
        )?;
        Self::new(store_id, binding, key_id, nonce)
    }

    pub fn nonce(&self) -> [u8; 24] {
        self.nonce
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn store_id(&self) -> StoreId {
        self.store_id
    }

    pub fn binding(&self) -> &RecordBinding {
        &self.binding
    }

    fn new(
        store_id: StoreId,
        binding: RecordBinding,
        key_id: KeyId,
        nonce: [u8; 24],
    ) -> Result<Self, RecordCryptoError> {
        binding.validate()?;
        Ok(Self {
            store_id,
            binding,
            key_id,
            nonce,
        })
    }

    fn encode_strict(&self) -> Result<Vec<u8>, RecordCryptoError> {
        self.binding.validate()?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(RECORD_MAGIC);
        put_u16(&mut out, RECORD_FORMAT_VERSION);
        put_u16(&mut out, CIPHER_SUITE_XCHACHA20_POLY1305);
        out.extend_from_slice(&self.store_id.0);
        put_u16(&mut out, self.binding.domain as u16);
        out.extend_from_slice(&self.key_id.0);
        out.extend_from_slice(&self.nonce);
        put_bytes(&mut out, self.binding.mount.as_bytes(), MAX_MOUNT)?;
        let segments = self.binding.path.as_str().split('/').collect::<Vec<_>>();
        put_u16(&mut out, segments.len() as u16);
        for segment in segments {
            put_bytes(&mut out, segment.as_bytes(), MAX_PATH)?;
        }
        put_bytes(&mut out, &self.binding.logical_record_id, MAX_LOGICAL_ID)?;
        match self.binding.version {
            None => out.push(0),
            Some(version) => {
                out.push(1);
                put_u64(&mut out, version);
            }
        }
        put_u64(&mut out, self.binding.created_unix_milliseconds);
        if out.len() > MAX_HEADER {
            return Err(RecordCryptoError::Limit);
        }
        Ok(out)
    }
}

impl fmt::Debug for RecordHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordHeader")
            .field("store_id", &self.store_id)
            .field("binding", &self.binding)
            .field("key_id", &self.key_id)
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl Canonical for RecordHeader {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.encode_strict().map_err(RecordCryptoError::codec)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_strict(bytes).map_err(RecordCryptoError::codec)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedRecord {
    header: RecordHeader,
    ciphertext: Vec<u8>,
}

impl EncryptedRecord {
    #[doc(hidden)]
    pub fn new_for_test(
        header: RecordHeader,
        ciphertext: Vec<u8>,
    ) -> Result<Self, RecordCryptoError> {
        if ciphertext.len() < 16 || ciphertext.len() > MAX_CIPHERTEXT {
            return Err(RecordCryptoError::Limit);
        }
        Ok(Self { header, ciphertext })
    }

    pub fn header(&self) -> &RecordHeader {
        &self.header
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn authenticated_bytes_for_state_digest(&self) -> Result<Vec<u8>, CodecError> {
        let header = self.header.encode()?;
        let mut bytes = Vec::with_capacity(header.len() + self.ciphertext.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }
}

impl fmt::Debug for EncryptedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedRecord")
            .field("header", &self.header)
            .field("ciphertext_length", &self.ciphertext.len())
            .finish()
    }
}

impl Canonical for EncryptedRecord {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let header = self.header.encode()?;
        if header.len() > MAX_HEADER
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > MAX_CIPHERTEXT
        {
            return Err(CodecError::Limit);
        }
        let mut out = Vec::with_capacity(8 + header.len() + self.ciphertext.len());
        put_bytes(&mut out, &header, MAX_HEADER).map_err(RecordCryptoError::codec)?;
        put_bytes(&mut out, &self.ciphertext, MAX_CIPHERTEXT).map_err(RecordCryptoError::codec)?;
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut input = HeaderDecoder::new(bytes);
        let header =
            RecordHeader::decode(&input.bytes(MAX_HEADER).map_err(RecordCryptoError::codec)?)?;
        let ciphertext = input
            .bytes(MAX_CIPHERTEXT)
            .map_err(RecordCryptoError::codec)?;
        input.finish().map_err(RecordCryptoError::codec)?;
        if ciphertext.len() < 16 {
            return Err(CodecError::Invalid);
        }
        Ok(Self { header, ciphertext })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordCryptoError {
    Random,
    Binding,
    Authentication,
    KeyUnavailable,
    Magic,
    UnknownFormat,
    UnknownSuite,
    UnknownDomain,
    Limit,
    Truncated,
    Trailing,
}

impl RecordCryptoError {
    fn codec(self) -> CodecError {
        match self {
            Self::UnknownFormat | Self::UnknownSuite | Self::UnknownDomain => {
                CodecError::UnknownVersion
            }
            Self::Limit => CodecError::Limit,
            Self::Truncated => CodecError::Truncated,
            Self::Trailing => CodecError::Trailing,
            _ => CodecError::Invalid,
        }
    }
}

impl fmt::Display for RecordCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Random => "record nonce generation failed",
            Self::Binding => "record binding mismatch",
            Self::Authentication => "record authentication failed",
            Self::KeyUnavailable => "record key unavailable",
            Self::Magic => "record magic invalid",
            Self::UnknownFormat => "record format version unsupported",
            Self::UnknownSuite => "record cipher suite unsupported",
            Self::UnknownDomain => "record domain unsupported",
            Self::Limit => "record exceeds canonical limit",
            Self::Truncated => "record is truncated",
            Self::Trailing => "record has trailing bytes",
        })
    }
}

impl std::error::Error for RecordCryptoError {}

impl From<CodecError> for RecordCryptoError {
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::Limit => Self::Limit,
            CodecError::Truncated => Self::Truncated,
            CodecError::Trailing => Self::Trailing,
            CodecError::UnknownVersion => Self::UnknownFormat,
            CodecError::Invalid => Self::Binding,
        }
    }
}

pub(crate) fn encrypt(
    store_id: StoreId,
    binding: &RecordBinding,
    key_id: KeyId,
    key: &[u8; 32],
    plaintext: &[u8],
    random: &mut impl RandomSource,
) -> Result<EncryptedRecord, RecordCryptoError> {
    if plaintext.len() > MAX_CIPHERTEXT - 16 {
        return Err(RecordCryptoError::Limit);
    }
    let mut nonce = [0_u8; 24];
    random.fill(&mut nonce).map_err(|error| match error {
        KeyringError::Random => RecordCryptoError::Random,
        _ => RecordCryptoError::Random,
    })?;
    let header = RecordHeader::new(store_id, binding.clone(), key_id, nonce)?;
    let aad = header.encode_strict()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| RecordCryptoError::Limit)?;
    EncryptedRecord::new_for_test(header, ciphertext)
}

pub(crate) fn decrypt(
    store_id: StoreId,
    expected: &RecordBinding,
    record: &EncryptedRecord,
    key: &[u8; 32],
) -> Result<SecretBox<Vec<u8>>, RecordCryptoError> {
    expected.validate()?;
    if record.header.store_id != store_id || record.header.binding != *expected {
        return Err(RecordCryptoError::Binding);
    }
    let aad = record.header.encode_strict()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&record.header.nonce),
            Payload {
                msg: &record.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RecordCryptoError::Authentication)?;
    Ok(SecretBox::new(Box::new(plaintext)))
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8], maximum: usize) -> Result<(), RecordCryptoError> {
    if value.len() > maximum || value.len() > u32::MAX as usize {
        return Err(RecordCryptoError::Limit);
    }
    put_u32(output, value.len() as u32);
    output.extend_from_slice(value);
    Ok(())
}

struct HeaderDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> HeaderDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RecordCryptoError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(RecordCryptoError::Limit)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(RecordCryptoError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RecordCryptoError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RecordCryptoError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RecordCryptoError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RecordCryptoError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RecordCryptoError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, RecordCryptoError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(RecordCryptoError::Limit);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, maximum: usize) -> Result<String, RecordCryptoError> {
        String::from_utf8(self.bytes(maximum)?).map_err(|_| RecordCryptoError::Binding)
    }

    fn finish(self) -> Result<(), RecordCryptoError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(RecordCryptoError::Trailing)
        }
    }
}
