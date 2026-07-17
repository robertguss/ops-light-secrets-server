#![no_main]

use axum::http::Method;
use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::raw_target::parse_raw_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Methods cycle over a small set so path parsing dominates.
    for method in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
    ] {
        let _ = parse_raw_target(&method, text);
    }
});
