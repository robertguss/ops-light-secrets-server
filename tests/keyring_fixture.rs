use std::str::FromStr;

use age::x25519;
use serde::Deserialize;
use zeroize::Zeroizing;

const IDENTITY: &str = "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

#[derive(Deserialize)]
struct Fixture {
    age_version: String,
    envelope_hex: String,
    plaintext_blake3: String,
}

#[test]
fn pinned_age_v012_fixture_decrypts_and_malformed_versions_fail_closed() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/keyring-age-v0.12.json")).unwrap();
    assert_eq!(fixture.age_version, "0.12.0");
    let envelope = decode_hex(&fixture.envelope_hex).unwrap();
    let identity = x25519::Identity::from_str(IDENTITY).unwrap();
    let plaintext = Zeroizing::new(age::decrypt(&identity, &envelope).unwrap());
    assert_eq!(
        blake3::hash(&plaintext).to_hex().to_string(),
        fixture.plaintext_blake3
    );

    for malformed in [
        envelope[..envelope.len() - 1].to_vec(),
        [b"age-encryption.org/v2\n".as_slice(), &envelope[22..]].concat(),
        vec![0_u8; 64],
    ] {
        assert!(age::decrypt(&identity, &malformed).is_err());
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = digit(pair[0])?;
            let low = digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn digit(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}
