use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::SubjectPublicKey;
use jaunt_ca::ssh_key::{Algorithm, HashAlg, PublicKey};

use crate::token::hex_digest;

const ED25519_SPKI_LEN: usize = 44;
const MAX_TLS_KEY_TEXT_LEN: usize = 64;
const MAX_SSH_KEY_TEXT_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub(crate) struct TlsKey {
    pub(crate) canonical: String,
    pub(crate) subject: SubjectPublicKey,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SshHostKey {
    pub(crate) canonical: String,
    pub(crate) key: PublicKey,
    pub(crate) fingerprint: String,
}

pub(crate) fn parse_tls(text: &str) -> Option<TlsKey> {
    if text.len() > MAX_TLS_KEY_TEXT_LEN {
        return None;
    }
    let der = STANDARD.decode(text).ok()?;
    if der.len() != ED25519_SPKI_LEN {
        return None;
    }
    let subject = SubjectPublicKey::from_spki_der(&der).ok()?;
    Some(TlsKey {
        canonical: STANDARD.encode(&der),
        subject,
        sha256: hex_digest(&der),
    })
}

pub(crate) fn parse_ssh(text: &str) -> Option<SshHostKey> {
    let text = text.trim_end_matches(['\r', '\n']);
    if text.len() > MAX_SSH_KEY_TEXT_LEN || text.chars().any(char::is_control) {
        return None;
    }
    let parsed = PublicKey::from_openssh(text).ok()?;
    if parsed.algorithm() != Algorithm::Ed25519 {
        return None;
    }
    let key = PublicKey::from(parsed.key_data().clone());
    SubjectPublicKey::from_ssh_key(&key).ok()?;
    Some(SshHostKey {
        canonical: key.to_openssh().ok()?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        key,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use jaunt_ca::ssh_key::rand_core::OsRng;
    use jaunt_ca::ssh_key::{Algorithm, PrivateKey};

    use super::{parse_ssh, parse_tls};

    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn spki_of(raw: &[u8; 32]) -> Vec<u8> {
        [SPKI_PREFIX.as_slice(), raw.as_slice()].concat()
    }

    fn fresh_raw() -> [u8; 32] {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .key_data()
            .ed25519()
            .unwrap()
            .0
    }

    #[test]
    fn a_tls_key_must_be_a_canonical_ed25519_spki() {
        let der = spki_of(&fresh_raw());
        let encoded = STANDARD.encode(&der);
        let parsed = parse_tls(&encoded).unwrap();
        assert_eq!(parsed.canonical, encoded);
        assert_eq!(parsed.sha256.len(), 64);

        let mut trailing = der.clone();
        trailing.push(0);
        let mut wrong_oid = der.clone();
        wrong_oid[8] = 0x71;
        for (label, text) in [
            ("empty", String::new()),
            ("garbage", "not base64!".to_owned()),
            ("raw key", STANDARD.encode(fresh_raw())),
            ("trailing data", STANDARD.encode(trailing)),
            ("other algorithm", STANDARD.encode(wrong_oid)),
            ("weak key", STANDARD.encode(spki_of(&[0; 32]))),
            ("unpadded", encoded.trim_end_matches('=').to_owned()),
            ("oversized", "A".repeat(65)),
        ] {
            assert!(parse_tls(&text).is_none(), "{label}");
        }
    }

    #[test]
    fn an_ssh_host_key_must_be_an_ed25519_line_and_its_comment_is_dropped() {
        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut public = private.public_key().clone();
        let bare = public.to_openssh().unwrap();
        public.set_comment("root@web-01");
        let line = public.to_openssh().unwrap();

        let parsed = parse_ssh(&format!("{line}\n")).unwrap();
        assert_eq!(parsed.canonical, bare);
        assert!(parsed.fingerprint.starts_with("SHA256:"));

        for (label, text) in [
            ("empty", String::new()),
            ("garbage", "ssh-ed25519 !!!".to_owned()),
            ("two lines", format!("{bare}\n{bare}")),
            ("control character", format!("{bare}\u{7}")),
            ("oversized", format!("{bare} {}", "c".repeat(1100))),
        ] {
            assert!(parse_ssh(&text).is_none(), "{label}");
        }
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7";
        assert!(parse_ssh(rsa).is_none());
    }
}
