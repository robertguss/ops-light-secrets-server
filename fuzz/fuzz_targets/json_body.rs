#![no_main]

use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::input_hygiene::parse_strict_json;

fuzz_target!(|data: &[u8]| {
    let key = [0x11u8; 32];
    // Duplicate-key / depth / size rejection must not panic.
    let _ = parse_strict_json(data, &key);
});
