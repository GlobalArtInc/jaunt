#![no_main]

use std::sync::OnceLock;

use jaunt_ssh::{UserCaKeys, verify_user_certificate};
use libfuzzer_sys::fuzz_target;
use russh::keys::Certificate;

const SEED_CA: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaXY+9iERFJaC924oDq5cMwzwvat4VmDdi/vHWOdndN";
const SEED_NOW: u64 = 1_767_229_200;

static CAS: OnceLock<UserCaKeys> = OnceLock::new();

fn parse(data: &[u8]) -> Option<Certificate> {
    match std::str::from_utf8(data) {
        Ok(text) if text.starts_with("ssh-") => Certificate::from_openssh(text).ok(),
        _ => Certificate::from_bytes(data).ok(),
    }
}

fuzz_target!(|data: &[u8]| {
    let cas = CAS.get_or_init(|| {
        UserCaKeys::from_openssh_lines([SEED_CA]).expect("the seed authority parses")
    });
    let Some(certificate) = parse(data) else {
        return;
    };
    for now in [SEED_NOW, 0, u64::MAX] {
        if let Ok(identity) = verify_user_certificate(&certificate, cas, now) {
            assert_eq!(identity.serial, certificate.serial());
            assert_eq!(identity.valid_before, certificate.valid_before());
            assert!(certificate.valid_after() <= now && now < certificate.valid_before());
            assert_eq!(certificate.valid_principals(), [identity.user_id.clone()]);
            assert_eq!(identity.key_id, certificate.key_id());
            assert!(!identity.email.is_empty());
        }
    }
});
