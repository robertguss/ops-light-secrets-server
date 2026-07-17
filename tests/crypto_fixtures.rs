use age::x25519;
use ops_light_secrets_server::store::keyring::{Keyring, KeyringError, RandomSource, RecipientSet};
use ops_light_secrets_server::store::{
    Canonical, EncryptedRecord, LogicalPath, RecordBinding, RecordCryptoError, RecordDomain,
    RecordHeader, Sealed, SecretMetadata, StoreId,
};
use secrecy::ExposeSecret;
use serde::Deserialize;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
const PLAINTEXT: &[u8] = b"ops-light crypto fixture plaintext v1";

#[derive(Deserialize)]
struct Vectors {
    schema: u16,
    generator: String,
    record_format: u16,
    cipher_suite: u16,
    mac_format: u16,
    store_id_hex: String,
    record_header_hex: String,
    encrypted_record_hex: String,
    plaintext_blake3: String,
    clear_record: ClearVector,
}

#[derive(Deserialize)]
struct ClearVector {
    class: String,
    generation: u64,
    primary_key_hex: String,
    sealed_hex: String,
}

#[derive(Default)]
struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("fixtures/crypto-vectors-v1.json")).unwrap()
}

fn keyring() -> Keyring {
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    Keyring::generate(
        StoreId([0x11; 16]),
        1,
        RecipientSet::new(&identity.to_public(), None).unwrap(),
        &mut Counter::default(),
    )
    .unwrap()
}

fn binding(
    domain: RecordDomain,
    mount: &str,
    path: &str,
    logical_id: &[u8],
    version: Option<u64>,
    created: u64,
) -> RecordBinding {
    RecordBinding::new(
        domain,
        mount,
        LogicalPath::new(path).unwrap(),
        logical_id,
        version,
        created,
    )
    .unwrap()
}

fn canonical_binding() -> RecordBinding {
    binding(
        RecordDomain::SecretValue,
        "secret",
        "fixtures/cross-architecture",
        b"fixture-version-7",
        Some(7),
        1_800_000_000_123,
    )
}

#[test]
fn frozen_header_encrypted_record_and_clear_mac_decode_and_verify() {
    let vectors = vectors();
    assert_eq!(vectors.schema, 1);
    assert_eq!(vectors.generator, "examples/crypto_fixture_generator.rs@v1");
    assert_eq!(
        (
            vectors.record_format,
            vectors.cipher_suite,
            vectors.mac_format
        ),
        (1, 1, 1)
    );
    assert_eq!(vectors.store_id_hex, "11".repeat(16));

    let header_bytes = decode_hex(&vectors.record_header_hex).unwrap();
    let record_bytes = decode_hex(&vectors.encrypted_record_hex).unwrap();
    let header = RecordHeader::decode_strict(&header_bytes).unwrap();
    let record = EncryptedRecord::decode(&record_bytes).unwrap();
    assert_eq!(record.header(), &header);
    assert_eq!(record.encode().unwrap(), record_bytes);
    let plaintext = keyring()
        .decrypt_record(&canonical_binding(), &record)
        .unwrap();
    assert_eq!(plaintext.expose_secret(), PLAINTEXT);
    assert_eq!(
        blake3::hash(plaintext.expose_secret()).to_hex().to_string(),
        vectors.plaintext_blake3
    );

    assert_eq!(vectors.clear_record.class, "secret-metadata.v1");
    let primary_key = decode_hex(&vectors.clear_record.primary_key_hex).unwrap();
    let sealed_bytes = decode_hex(&vectors.clear_record.sealed_hex).unwrap();
    let sealed = Sealed::<SecretMetadata>::decode_for_fixture(&sealed_bytes).unwrap();
    assert_eq!(sealed.generation, vectors.clear_record.generation);
    sealed
        .verify(&[0x42; 32], StoreId([0x11; 16]), &primary_key)
        .unwrap();
    assert_eq!(sealed.encode_for_fixture().unwrap(), sealed_bytes);
}

#[test]
fn every_aad_field_key_nonce_ciphertext_and_created_time_tamper_rejects() {
    let vectors = vectors();
    let record_bytes = decode_hex(&vectors.encrypted_record_hex).unwrap();
    let record = EncryptedRecord::decode(&record_bytes).unwrap();
    let keyring = keyring();
    for changed in [
        binding(
            RecordDomain::AuditPayload,
            "secret",
            "fixtures/cross-architecture",
            b"fixture-version-7",
            None,
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "other",
            "fixtures/cross-architecture",
            b"fixture-version-7",
            Some(7),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "secret",
            "fixtures/other",
            b"fixture-version-7",
            Some(7),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "secret",
            "fixtures/cross-architecture",
            b"other-id",
            Some(7),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "secret",
            "fixtures/cross-architecture",
            b"fixture-version-7",
            Some(8),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "secret",
            "fixtures/cross-architecture",
            b"fixture-version-7",
            Some(7),
            1_800_000_000_124,
        ),
    ] {
        assert_eq!(
            keyring.decrypt_record(&changed, &record).unwrap_err(),
            RecordCryptoError::Binding
        );
    }
    assert_eq!(
        Keyring::generate(
            StoreId([0x12; 16]),
            1,
            RecipientSet::new(
                &ACTIVE_IDENTITY
                    .parse::<x25519::Identity>()
                    .unwrap()
                    .to_public(),
                None,
            )
            .unwrap(),
            &mut Counter::default(),
        )
        .unwrap()
        .decrypt_record(&canonical_binding(), &record)
        .unwrap_err(),
        RecordCryptoError::Binding
    );

    let header_offset = 4;
    let key_id_offset = header_offset + 8 + 2 + 2 + 16 + 2;
    let nonce_offset = key_id_offset + 16;
    for offset in [key_id_offset, nonce_offset, record_bytes.len() - 1] {
        let mut changed = record_bytes.clone();
        changed[offset] ^= 1;
        let changed = EncryptedRecord::decode(&changed).unwrap();
        assert!(
            keyring
                .decrypt_record(&canonical_binding(), &changed)
                .is_err()
        );
    }
}

#[test]
fn strict_header_record_and_clear_codecs_reject_aliases_and_byte_drift() {
    let vectors = vectors();
    let header = decode_hex(&vectors.record_header_hex).unwrap();
    for end in 0..header.len() {
        assert!(RecordHeader::decode_strict(&header[..end]).is_err());
    }
    let mut trailing = header.clone();
    trailing.push(0);
    assert_eq!(
        RecordHeader::decode_strict(&trailing),
        Err(RecordCryptoError::Trailing)
    );
    for (offset, value, expected) in [
        (0, 0_u8, RecordCryptoError::Magic),
        (8, 1_u8, RecordCryptoError::UnknownFormat),
        (10, 1_u8, RecordCryptoError::UnknownSuite),
        (29, 99_u8, RecordCryptoError::UnknownDomain),
    ] {
        let mut changed = header.clone();
        changed[offset] = value;
        assert_eq!(RecordHeader::decode_strict(&changed), Err(expected));
    }
    let mut little_endian_version = header.clone();
    little_endian_version[8..10].copy_from_slice(&1_u16.to_le_bytes());
    assert_eq!(
        RecordHeader::decode_strict(&little_endian_version),
        Err(RecordCryptoError::UnknownFormat)
    );
    let mut altered_mount_length = header.clone();
    altered_mount_length[70..74].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        RecordHeader::decode_strict(&altered_mount_length),
        Err(RecordCryptoError::Limit)
    );

    let record = decode_hex(&vectors.encrypted_record_hex).unwrap();
    for end in 0..record.len() {
        assert!(EncryptedRecord::decode(&record[..end]).is_err());
    }
    let mut record_trailing = record;
    record_trailing.push(0);
    assert!(EncryptedRecord::decode(&record_trailing).is_err());

    let primary_key = decode_hex(&vectors.clear_record.primary_key_hex).unwrap();
    let sealed_bytes = decode_hex(&vectors.clear_record.sealed_hex).unwrap();
    let sealed = Sealed::<SecretMetadata>::decode_for_fixture(&sealed_bytes).unwrap();
    assert!(
        sealed
            .verify(&[0x42; 32], StoreId([0x12; 16]), &primary_key)
            .is_err()
    );
    assert!(
        sealed
            .verify(&[0x42; 32], StoreId([0x11; 16]), b"other-key")
            .is_err()
    );
    let mut tag_edit = sealed_bytes.clone();
    *tag_edit.last_mut().unwrap() ^= 1;
    let tag_edit = Sealed::<SecretMetadata>::decode_for_fixture(&tag_edit).unwrap();
    assert!(
        tag_edit
            .verify(&[0x42; 32], StoreId([0x11; 16]), &primary_key)
            .is_err()
    );
    let mut generation_edit = sealed_bytes.clone();
    generation_edit[14] ^= 1;
    let generation_edit = Sealed::<SecretMetadata>::decode_for_fixture(&generation_edit).unwrap();
    assert!(
        generation_edit
            .verify(&[0x42; 32], StoreId([0x11; 16]), &primary_key)
            .is_err()
    );
    let mut value_edit = sealed_bytes.clone();
    let fixture_offset = value_edit
        .windows(b"fixture".len())
        .position(|window| window == b"fixture")
        .unwrap();
    value_edit[fixture_offset + b"fixture".len() - 1] ^= 1;
    let value_edit = Sealed::<SecretMetadata>::decode_for_fixture(&value_edit).unwrap();
    assert!(
        value_edit
            .verify(&[0x42; 32], StoreId([0x11; 16]), &primary_key)
            .is_err()
    );
    for offset in [1_usize, 3, 5] {
        let mut wrong_domain = sealed_bytes.clone();
        wrong_domain[offset] ^= 1;
        assert!(Sealed::<SecretMetadata>::decode_for_fixture(&wrong_domain).is_err());
    }
    for end in 0..sealed_bytes.len() {
        assert!(Sealed::<SecretMetadata>::decode_for_fixture(&sealed_bytes[..end]).is_err());
    }
    let mut sealed_trailing = sealed_bytes;
    sealed_trailing.push(0);
    assert!(Sealed::<SecretMetadata>::decode_for_fixture(&sealed_trailing).is_err());
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

fn digit(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}
