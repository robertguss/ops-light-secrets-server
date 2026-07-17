use std::collections::BTreeMap;

use age::x25519;
use ops_light_secrets_server::store::keyring::{Keyring, KeyringError, RandomSource, RecipientSet};
use ops_light_secrets_server::store::{
    Canonical, LogicalPath, RecordBinding, RecordDomain, RotationState, SecretMetadata, StoreId,
    VersionSetSummary,
};
use serde_json::json;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

#[derive(Default)]
struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

fn main() {
    let store_id = StoreId([0x11; 16]);
    let identity: x25519::Identity = ACTIVE_IDENTITY.parse().expect("fixture identity");
    let mut random = Counter::default();
    let keyring = Keyring::generate(
        store_id,
        1,
        RecipientSet::new(&identity.to_public(), None).expect("recipient set"),
        &mut random,
    )
    .expect("keyring");
    let binding = RecordBinding::new(
        RecordDomain::SecretValue,
        "secret",
        LogicalPath::new("fixtures/cross-architecture").expect("path"),
        b"fixture-version-7",
        Some(7),
        1_800_000_000_123,
    )
    .expect("binding");
    let plaintext = b"ops-light crypto fixture plaintext v1";
    let encrypted = keyring
        .encrypt_record(&binding, plaintext, &mut random)
        .expect("encrypt fixture");

    let mut states = VersionSetSummary::empty();
    states.append().expect("version 1");
    states.append().expect("version 2");
    states.soft_delete(1).expect("soft delete");
    let metadata = SecretMetadata {
        schema_version: 1,
        custom: BTreeMap::from([
            ("owner".into(), "fixture".into()),
            ("purpose".into(), "cross-version".into()),
        ]),
        max_versions: 10,
        cas_required: true,
        last_completed_rotation_unix_seconds: Some(1_700_000_000),
        rotation_interval_seconds: Some(86_400),
        rotation_state: RotationState::Idle,
        rotation_protection: None,
        versions: states,
    };
    let metadata_path = LogicalPath::new("fixtures/metadata").expect("metadata path");
    let sealed = metadata
        .seal(&[0x42; 32], store_id, &metadata_path)
        .expect("seal metadata");

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": 1,
            "generator": "examples/crypto_fixture_generator.rs@v1",
            "record_format": 1,
            "cipher_suite": 1,
            "mac_format": 1,
            "store_id_hex": hex(&store_id.0),
            "record_binding": {
                "domain": "secret-value.v1",
                "mount": "secret",
                "path": "fixtures/cross-architecture",
                "logical_record_id_hex": hex(b"fixture-version-7"),
                "version": 7,
                "created_unix_milliseconds": 1_800_000_000_123_u64
            },
            "record_header_hex": hex(&encrypted.header().encode().expect("header encode")),
            "encrypted_record_hex": hex(&encrypted.encode().expect("record encode")),
            "plaintext_blake3": blake3::hash(plaintext).to_hex().to_string(),
            "clear_record": {
                "class": "secret-metadata.v1",
                "primary_key_hex": hex(&metadata_path.encode().expect("path encode")),
                "generation": sealed.generation,
                "sealed_hex": hex(&sealed.encode_for_fixture().expect("sealed encode"))
            }
        }))
        .expect("JSON")
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
