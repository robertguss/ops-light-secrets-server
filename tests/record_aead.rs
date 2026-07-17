use age::x25519;
use ops_light_secrets_server::store::keyring::{Keyring, KeyringError, RandomSource, RecipientSet};
use ops_light_secrets_server::store::{
    CIPHER_SUITE_XCHACHA20_POLY1305, Canonical, EncryptedRecord, LogicalPath,
    RECORD_FORMAT_VERSION, RecordBinding, RecordCryptoError, RecordDomain, RecordHeader, StoreId,
};
use secrecy::ExposeSecret;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

#[derive(Default)]
struct CountingRandom {
    calls: Vec<usize>,
    next: u8,
}

impl RandomSource for CountingRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.calls.push(output.len());
        self.next = self.next.wrapping_add(1);
        output.fill(self.next);
        Ok(())
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), KeyringError> {
        Err(KeyringError::Random)
    }
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

fn make_keyring(store_id: StoreId, random: &mut CountingRandom) -> Keyring {
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    Keyring::generate(
        store_id,
        1,
        RecipientSet::new(&identity.to_public(), None).unwrap(),
        random,
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

#[test]
fn round_trip_and_every_identical_rewrite_draws_a_fresh_192_bit_nonce() {
    let mut random = CountingRandom::default();
    let keyring = make_keyring(StoreId([1; 16]), &mut random);
    let before = random.calls.len();
    let binding = binding(
        RecordDomain::SecretValue,
        "kv",
        "apps/canvas/api-key",
        b"secret-version",
        Some(7),
        1_800_000_000_123,
    );

    let first = keyring
        .encrypt_record(&binding, b"same plaintext", &mut random)
        .unwrap();
    let second = keyring
        .encrypt_record(&binding, b"same plaintext", &mut random)
        .unwrap();

    assert_eq!(&random.calls[before..], &[24, 24]);
    assert_ne!(first.header().nonce(), second.header().nonce());
    assert_ne!(first.ciphertext(), second.ciphertext());
    assert_eq!(
        keyring
            .decrypt_record(&binding, &first)
            .unwrap()
            .expose_secret(),
        b"same plaintext"
    );
}

#[test]
fn every_bound_field_and_cross_store_transplant_fails_closed() {
    let mut random = CountingRandom::default();
    let keyring = make_keyring(StoreId([1; 16]), &mut random);
    let original = binding(
        RecordDomain::SecretValue,
        "kv",
        "apps/canvas/api-key",
        b"secret-version",
        Some(7),
        1_800_000_000_123,
    );
    let record = keyring
        .encrypt_record(&original, b"private-canary", &mut random)
        .unwrap();

    for changed in [
        binding(
            RecordDomain::AuditPayload,
            "kv",
            "apps/canvas/api-key",
            b"secret-version",
            None,
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "other",
            "apps/canvas/api-key",
            b"secret-version",
            Some(7),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "kv",
            "apps/populi/api-key",
            b"secret-version",
            Some(7),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "kv",
            "apps/canvas/api-key",
            b"other-record",
            Some(7),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "kv",
            "apps/canvas/api-key",
            b"secret-version",
            Some(8),
            1_800_000_000_123,
        ),
        binding(
            RecordDomain::SecretValue,
            "kv",
            "apps/canvas/api-key",
            b"secret-version",
            Some(7),
            1_800_000_000_124,
        ),
    ] {
        assert_eq!(
            keyring.decrypt_record(&changed, &record).unwrap_err(),
            RecordCryptoError::Binding
        );
    }

    let mut same_keys = CountingRandom::default();
    let other_store = make_keyring(StoreId([2; 16]), &mut same_keys);
    assert_eq!(
        other_store.decrypt_record(&original, &record).unwrap_err(),
        RecordCryptoError::Binding
    );
}

#[test]
fn key_id_swap_uses_the_named_retained_key_and_still_fails_authentication() {
    let mut random = CountingRandom::default();
    let mut keyring = make_keyring(StoreId([1; 16]), &mut random);
    let binding = binding(
        RecordDomain::AuditPayload,
        "audit",
        "events/42",
        b"audit-sequence-42",
        None,
        1_800_000_000_123,
    );
    let record = keyring
        .encrypt_record(&binding, b"encrypted audit payload", &mut random)
        .unwrap();
    let replacement_key_id = keyring
        .append_audit_payload_key(keyring.generation(), &mut random)
        .unwrap();
    let mut encoded = record.encode().unwrap();
    let header_offset = 4;
    let key_id_offset = header_offset + 8 + 2 + 2 + 16 + 2;
    encoded[key_id_offset..key_id_offset + 16].copy_from_slice(&replacement_key_id.0);
    let transplanted = EncryptedRecord::decode(&encoded).unwrap();
    assert_eq!(
        keyring.decrypt_record(&binding, &transplanted).unwrap_err(),
        RecordCryptoError::Authentication
    );
}

#[test]
fn nonce_ciphertext_and_safe_diagnostics_reject_without_disclosure() {
    let mut random = CountingRandom::default();
    let keyring = make_keyring(StoreId([1; 16]), &mut random);
    let binding = binding(
        RecordDomain::SecretValue,
        "kv",
        "canary/must-not-appear",
        b"private-logical-id",
        Some(1),
        10,
    );
    let record = keyring
        .encrypt_record(&binding, b"private-plaintext-canary", &mut random)
        .unwrap();
    let encoded = record.encode().unwrap();

    let mut nonce_edit = encoded.clone();
    let nonce_offset = 4 + 8 + 2 + 2 + 16 + 2 + 16;
    nonce_edit[nonce_offset] ^= 1;
    let nonce_edit = EncryptedRecord::decode(&nonce_edit).unwrap();
    assert_eq!(
        keyring.decrypt_record(&binding, &nonce_edit).unwrap_err(),
        RecordCryptoError::Authentication
    );

    let mut ciphertext_edit = encoded;
    *ciphertext_edit.last_mut().unwrap() ^= 1;
    let ciphertext_edit = EncryptedRecord::decode(&ciphertext_edit).unwrap();
    let error = keyring
        .decrypt_record(&binding, &ciphertext_edit)
        .unwrap_err();
    assert_eq!(error, RecordCryptoError::Authentication);
    let rendered = format!("{error:?} {error} {record:?}");
    for canary in [
        "canary/must-not-appear",
        "private-logical-id",
        "private-plaintext-canary",
    ] {
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn nonce_source_failure_is_typed_and_never_falls_back() {
    let mut random = CountingRandom::default();
    let keyring = make_keyring(StoreId([1; 16]), &mut random);
    let binding = binding(
        RecordDomain::SecretValue,
        "kv",
        "apps/canvas/api-key",
        b"secret-version",
        Some(7),
        1_800_000_000_123,
    );
    assert_eq!(
        keyring
            .encrypt_record(&binding, b"private-canary", &mut FailingRandom)
            .unwrap_err(),
        RecordCryptoError::Random
    );
}

#[test]
fn header_and_record_codecs_are_fixed_strict_and_typed() {
    assert_eq!(RECORD_FORMAT_VERSION, 1);
    assert_eq!(CIPHER_SUITE_XCHACHA20_POLY1305, 1);
    let header = RecordHeader::new_for_test(
        StoreId([1; 16]),
        binding(RecordDomain::SecretValue, "kv", "a/b", b"id", Some(9), 10),
        [2; 16],
        [3; 24],
    )
    .unwrap();
    let encoded = header.encode().unwrap();
    assert_eq!(RecordHeader::decode_strict(&encoded).unwrap(), header);
    assert_eq!(
        encode_hex(&encoded),
        concat!(
            "4f4c53535245430000010001",
            "01010101010101010101010101010101",
            "0001",
            "02020202020202020202020202020202",
            "030303030303030303030303030303030303030303030303",
            "000000026b76",
            "0002",
            "0000000161",
            "0000000162",
            "000000026964",
            "01",
            "0000000000000009",
            "000000000000000a"
        )
    );

    let mut unknown_version = encoded.clone();
    unknown_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        RecordHeader::decode_strict(&unknown_version),
        Err(RecordCryptoError::UnknownFormat)
    );
    let mut unknown_suite = encoded.clone();
    unknown_suite[10..12].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        RecordHeader::decode_strict(&unknown_suite),
        Err(RecordCryptoError::UnknownSuite)
    );
    let mut unknown_domain = encoded.clone();
    unknown_domain[28..30].copy_from_slice(&99_u16.to_be_bytes());
    assert_eq!(
        RecordHeader::decode_strict(&unknown_domain),
        Err(RecordCryptoError::UnknownDomain)
    );
    let mut wrong_magic = encoded.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        RecordHeader::decode_strict(&wrong_magic),
        Err(RecordCryptoError::Magic)
    );
    for end in 0..encoded.len() {
        assert!(RecordHeader::decode_strict(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        RecordHeader::decode_strict(&trailing),
        Err(RecordCryptoError::Trailing)
    );

    let record = EncryptedRecord::new_for_test(header, vec![7; 16]).unwrap();
    let encoded_record = record.encode().unwrap();
    assert_eq!(EncryptedRecord::decode(&encoded_record).unwrap(), record);
    for end in 0..encoded_record.len() {
        assert!(EncryptedRecord::decode(&encoded_record[..end]).is_err());
    }
    let mut record_trailing = encoded_record;
    record_trailing.push(0);
    assert!(EncryptedRecord::decode(&record_trailing).is_err());

    assert_eq!(
        RecordBinding::new(
            RecordDomain::SecretValue,
            "bad/mount",
            LogicalPath::new("a/b").unwrap(),
            b"id",
            Some(1),
            10,
        ),
        Err(RecordCryptoError::Binding)
    );
    assert_eq!(
        RecordBinding::new(
            RecordDomain::SecretValue,
            "kv",
            LogicalPath::new("a/b").unwrap(),
            b"id",
            None,
            10,
        ),
        Err(RecordCryptoError::Binding)
    );
}
