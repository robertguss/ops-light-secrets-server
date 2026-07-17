#![no_main]

use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::store::{Canonical, EncryptedRecord, RecordHeader};

fuzz_target!(|data: &[u8]| {
    let _ = RecordHeader::decode_strict(data);
    let _ = EncryptedRecord::decode(data);
});
