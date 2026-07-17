#![no_main]

use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::credential::CredentialWire;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Must never panic on attacker-controlled credential strings.
    let _ = CredentialWire::parse(text);
});
