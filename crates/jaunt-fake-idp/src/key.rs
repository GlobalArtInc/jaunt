use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use jsonwebtoken::EncodingKey;

pub const KEY_ID: &str = "fake-idp-test-only-key";

const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

pub struct TestOnlySigningKey {
    encoding: EncodingKey,
    jwks: String,
}

impl TestOnlySigningKey {
    pub fn generate() -> TestOnlySigningKey {
        let seed: [u8; 32] = rand::random();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut der = PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&seed);
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "use": "sig",
                "alg": "EdDSA",
                "kid": KEY_ID,
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public),
            }]
        })
        .to_string();
        TestOnlySigningKey {
            encoding: EncodingKey::from_ed_der(&der),
            jwks,
        }
    }

    pub fn encoding(&self) -> &EncodingKey {
        &self.encoding
    }

    pub fn jwks(&self) -> &str {
        &self.jwks
    }
}
