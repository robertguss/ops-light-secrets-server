use std::io;

use crate::config::{SecretInput, SecretSource};
use crate::init::prepare_keyring_init_from_source;
use crate::startup::open_store_keyring;
use crate::store::keyring::{Keyring, KeyringError, KeyringOpener, RandomSource};
use crate::store::{
    Canonical, FORMAT_VERSION, IntegrityStatus, Lifecycle, LogicalPath, MetaRecord,
    PlaintextSecret, SecretKey, Store, StoreError, StoreId,
};
use secrecy::ExposeSecret;
use zeroize::Zeroize;

const ACTIVE_IDENTITY: &str =
    "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

struct Counter(u8);

impl RandomSource for Counter {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), KeyringError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

struct IdentityInput(Vec<u8>);

impl SecretInput for IdentityInput {
    fn read_stdin(&mut self) -> io::Result<Vec<u8>> {
        Ok(std::mem::take(&mut self.0))
    }

    fn read_file_descriptor(&mut self, _: u32) -> io::Result<Vec<u8>> {
        unreachable!()
    }

    fn read_credential(&mut self, _: &str) -> io::Result<Vec<u8>> {
        unreachable!()
    }

    fn read_tty(&mut self) -> io::Result<Vec<u8>> {
        unreachable!()
    }

    fn read_environment(&mut self, _: &str) -> io::Result<Vec<u8>> {
        unreachable!()
    }
}

fn initialized() -> (tempfile::TempDir, Store, Keyring, Counter) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.redb");
    let meta = MetaRecord {
        store_id: StoreId([7; 16]),
        format_version: FORMAT_VERSION,
        lifecycle: Lifecycle::Ready,
        high_water_unix_seconds: 1_800_000_000,
        pending_anchor: None,
    };
    let mut source = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    let transaction = prepare_keyring_init_from_source(
        meta,
        &SecretSource::Stdin,
        &mut source,
        None,
        &mut Counter(0),
    )
    .unwrap();
    drop(transaction.commit(&path).unwrap());
    let store = Store::open(&path).unwrap();
    let mut source = IdentityInput(ACTIVE_IDENTITY.as_bytes().to_vec());
    let keyring = open_store_keyring(
        &store,
        &SecretSource::Stdin,
        &mut source,
        &KeyringOpener::default(),
    )
    .unwrap();
    (directory, store, keyring, Counter(20))
}

#[test]
fn two_appends_round_trip_both_versions_latest_and_disk_has_no_plaintext() {
    let (directory, store, keyring, mut random) = initialized();
    let path = LogicalPath::new("apps/canvas/api-key").unwrap();
    let first_canary = b"u26-first-private-canary";
    let second_canary = b"u26-second-private-canary";
    assert_eq!(
        keyring
            .write_secret(
                &store,
                "kv",
                &path,
                &PlaintextSecret::new(first_canary.to_vec()),
                1_800_000_000_100,
                &mut random,
            )
            .unwrap(),
        1
    );
    assert_eq!(
        keyring
            .write_secret(
                &store,
                "kv",
                &path,
                &PlaintextSecret::new(second_canary.to_vec()),
                1_800_000_000_200,
                &mut random,
            )
            .unwrap(),
        2
    );

    assert_eq!(
        keyring
            .read_secret(&store, "kv", &path, Some(1))
            .unwrap()
            .unwrap()
            .expose_secret(),
        first_canary
    );
    assert_eq!(
        keyring
            .read_secret(&store, "kv", &path, Some(2))
            .unwrap()
            .unwrap()
            .expose_secret(),
        second_canary
    );
    assert_eq!(
        keyring
            .read_secret(&store, "kv", &path, None)
            .unwrap()
            .unwrap()
            .expose_secret(),
        second_canary
    );

    drop(store);
    let bytes = std::fs::read(directory.path().join("store.redb")).unwrap();
    assert!(
        !bytes
            .windows(first_canary.len())
            .any(|part| part == first_canary)
    );
    assert!(
        !bytes
            .windows(second_canary.len())
            .any(|part| part == second_canary)
    );
}

#[test]
fn metadata_queries_never_decrypt_and_each_value_read_decrypts_again() {
    let (_, store, keyring, mut random) = initialized();
    let path = LogicalPath::new("apps/canvas/api-key").unwrap();
    keyring
        .write_secret(
            &store,
            "kv",
            &path,
            &PlaintextSecret::new(b"private".to_vec()),
            1_800_000_000_100,
            &mut random,
        )
        .unwrap();
    let before = keyring.record_decrypt_attempts();
    let metadata = keyring
        .secret_metadata_query(&store, "kv", &path)
        .unwrap()
        .unwrap();
    assert_eq!(metadata.versions.current_version, 1);
    assert_eq!(keyring.record_decrypt_attempts(), before);
    keyring.read_secret(&store, "kv", &path, None).unwrap();
    keyring.read_secret(&store, "kv", &path, None).unwrap();
    assert_eq!(keyring.record_decrypt_attempts(), before + 2);
}

#[test]
fn plaintext_owner_explicit_zeroize_erases_in_place() {
    let mut value = PlaintextSecret::new(b"zeroize-canary".to_vec());
    value.zeroize();
    assert!(value.expose_secret().iter().all(|byte| *byte == 0));
}

#[test]
fn missing_newest_ciphertext_never_falls_back_to_an_older_version() {
    let (directory, store, keyring, mut random) = initialized();
    let path = LogicalPath::new("apps/canvas/api-key").unwrap();
    for value in [b"first".as_slice(), b"second".as_slice()] {
        keyring
            .write_secret(
                &store,
                "kv",
                &path,
                &PlaintextSecret::new(value.to_vec()),
                1_800_000_000_100,
                &mut random,
            )
            .unwrap();
    }
    drop(store);

    let database = redb::Database::open(directory.path().join("store.redb")).unwrap();
    let write = database.begin_write().unwrap();
    {
        use redb::TableDefinition;
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new("secrets");
        let mut table = write.open_table(definition).unwrap();
        let key = SecretKey {
            path: LogicalPath::new("kv/apps/canvas/api-key").unwrap(),
            version: 2,
        }
        .encode()
        .unwrap();
        table.remove(key.as_slice()).unwrap();
    }
    write.commit().unwrap();
    drop(database);

    let store = Store::open(directory.path().join("store.redb")).unwrap();
    let error = keyring
        .read_secret(&store, "kv", &path, None)
        .err()
        .unwrap();
    assert!(matches!(
        error,
        crate::store::SecretDataError::Store(StoreError::Integrity)
    ));
    let IntegrityStatus::Failed(diagnostic) = store.integrity_status() else {
        panic!("summary/row mismatch must fail readiness");
    };
    assert_eq!(diagnostic.table, "secrets");
}
