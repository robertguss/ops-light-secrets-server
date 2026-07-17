#![no_main]

use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::store::{Canonical, CheckpointDescriptor, CheckpointSignature};

fuzz_target!(|data: &[u8]| {
    let _ = CheckpointDescriptor::decode(data);
    let _ = CheckpointSignature::decode(data);
});
