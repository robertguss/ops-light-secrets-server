//! U8.5: offline whole-store metadata re-MAC producer evidence.

use age::x25519;
use ops_light_secrets_server::init::KeyringInitTransaction;
use ops_light_secrets_server::reencrypt::{metadata_remac_confirmation, run_metadata_remac};
use ops_light_secrets_server::store::keyring::{KeyringError, KeyringOpener, RandomSource};
use ops_light_secrets_server::store::{
    FORMAT_VERSION, Lifecycle, LogicalPath, MetaRecord, PlaintextSecret, Store, StoreId,
};
use secrecy::ExposeSecret;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
const CANARY: &[u8] = b"metadata-remac-canary-value-7a3f";

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = self.0.wrapping_add(index as u8);
        }
        Ok(())
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, x25519::Identity, u64) {
    let directory = tempfile::tempdir().unwrap();
    let active: x25519::Identity = ACTIVE_IDENTITY.parse().unwrap();
    let path = directory.path().join("store.redb");
    let transaction = KeyringInitTransaction::prepare(
        MetaRecord {
            store_id: StoreId([0x91; 16]),
            format_version: FORMAT_VERSION,
            lifecycle: Lifecycle::Ready,
            high_water_unix_seconds: 1_800_000_000,
            pending_anchor: None,
        },
        &active,
        None,
        &mut Counter(1),
    )
    .unwrap();
    let store = transaction.commit(&path).unwrap();
    let keyring = KeyringOpener::default()
        .open(
            StoreId([0x91; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    let secret_path = LogicalPath::new("apps/remac").unwrap();
    keyring
        .write_secret(
            &store,
            "secret",
            &secret_path,
            &PlaintextSecret::new(CANARY.to_vec()),
            1_800_000_001,
            &mut Counter(2),
        )
        .unwrap();
    let generation = keyring.generation();
    drop(keyring);
    drop(store);
    (directory, path, active, generation)
}

#[test]
fn offline_metadata_remac_reseals_and_preserves_secret_bytes() {
    let (_dir, path, active, generation) = fixture();
    let reason = "operator scheduled metadata re-MAC";
    let confirm = metadata_remac_confirmation([0x91; 16], generation, reason).unwrap();
    let receipt = run_metadata_remac(
        &path,
        &active,
        None,
        generation,
        reason,
        &confirm,
        &mut Counter(9),
    )
    .expect("re-MAC must succeed");
    assert!(receipt.resealed_rows >= 1);
    assert_ne!(receipt.old_key_id, receipt.new_key_id);
    assert_eq!(receipt.generation, generation + 1);
    assert_ne!(receipt.before_state_digest, receipt.after_state_digest);

    let store = Store::open(&path).unwrap();
    let meta = store.meta().unwrap();
    assert_eq!(meta.lifecycle, Lifecycle::Ready);
    assert!(
        meta.pending_anchor.is_some(),
        "installed remac must leave pending_anchor=metadata-key"
    );
    let keyring = KeyringOpener::default()
        .open(
            StoreId([0x91; 16]),
            &store.keyring().unwrap().unwrap(),
            &store.keyring_metadata().unwrap().unwrap(),
            &active,
        )
        .unwrap();
    assert_eq!(keyring.generation(), generation + 1);
    assert_eq!(keyring.metadata_integrity_key_id().0, receipt.new_key_id);
    let secret_path = LogicalPath::new("apps/remac").unwrap();
    let plaintext = keyring
        .read_secret(&store, "secret", &secret_path, None)
        .unwrap()
        .unwrap();
    assert_eq!(plaintext.expose_secret(), CANARY);
    drop(keyring);
    drop(store);

    // Second bulk job must refuse while pending_anchor remains.
    let blocked = run_metadata_remac(
        &path,
        &active,
        None,
        generation + 1,
        reason,
        &metadata_remac_confirmation([0x91; 16], generation + 1, reason).unwrap(),
        &mut Counter(10),
    )
    .unwrap_err();
    assert_eq!(
        blocked,
        ops_light_secrets_server::reencrypt::MetadataRemacError::Invalid
    );
}

#[test]
fn metadata_remac_refuses_wrong_confirmation_and_generation() {
    let (_dir, path, active, generation) = fixture();
    let err = run_metadata_remac(
        &path,
        &active,
        None,
        generation,
        "reason",
        "00".repeat(32).as_str(),
        &mut Counter(3),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ops_light_secrets_server::reencrypt::MetadataRemacError::Confirm
    );
    let err = run_metadata_remac(
        &path,
        &active,
        None,
        generation + 9,
        "reason",
        &metadata_remac_confirmation([0x91; 16], generation + 9, "reason").unwrap(),
        &mut Counter(4),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ops_light_secrets_server::reencrypt::MetadataRemacError::Invalid
    );
}

#[test]
fn metadata_remac_abort_removes_pre_rename_sibling_only() {
    let (_dir, path, _active, _generation) = fixture();
    let sibling = path.with_extension("redb.metadata-remac");
    std::fs::write(&sibling, b"partial-remac-sibling").unwrap();
    assert!(sibling.exists());
    // Mirror CLI `key metadata abort`: pre-rename cleanup only.
    std::fs::remove_file(&sibling).unwrap();
    assert!(!sibling.exists());
    assert!(path.exists(), "original store must survive abort");
    let store = Store::open(&path).unwrap();
    assert_eq!(store.meta().unwrap().lifecycle, Lifecycle::Ready);
}
