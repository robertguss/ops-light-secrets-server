#![no_main]

use libfuzzer_sys::fuzz_target;
use ops_light_secrets_server::audit_export::AuditView;
use ops_light_secrets_server::store::Canonical;

fuzz_target!(|data: &[u8]| {
    let _ = AuditView::decode(data);
});
