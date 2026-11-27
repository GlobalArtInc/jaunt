use axum::http::Uri;
use jaunt_ca::ssh_key::certificate::{Builder, CertType};
use jaunt_ca::ssh_key::public::{KeyData, SkEd25519};
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{
    Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, Signature, SigningKey,
};
use jaunt_ca::{BACKDATE, MAX_USER_VALIDITY, ORIGIN_EXTENSION, TrustSet};
use jaunt_store::Certificate as CertificateRow;

use super::{Reason, certificate_holder, is_user_id, signature_holds, target_uri, validity};

const USER: &str = "3f2b1c9e-7a44-4d0e-9c58-0a6b8f1d2e77";
const SERIAL: u64 = 42;
const AFTER: u64 = 1_700_000_000;
const BEFORE: u64 = AFTER + 3_600;

struct Draft {
    subject: KeyData,
    cert_type: CertType,
    principals: Vec<String>,
    key_id: String,
    after: u64,
    before: u64,
    critical: Option<(&'static str, &'static str)>,
    extension: Option<(&'static str, &'static str)>,
}

fn new_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

fn draft(subject: &PrivateKey) -> Draft {
    Draft {
        subject: subject.public_key().key_data().clone(),
        cert_type: CertType::User,
        principals: vec![USER.to_owned()],
        key_id: format!("jaunt:ada@example.com:{SERIAL}"),
        after: AFTER,
        before: BEFORE,
        critical: None,
        extension: None,
    }
}

fn issue(draft: Draft, ca: &PrivateKey) -> Certificate {
    let mut builder =
        Builder::new_with_random_nonce(&mut OsRng, draft.subject, draft.after, draft.before)
            .unwrap();
    builder.serial(SERIAL).unwrap();
    builder.cert_type(draft.cert_type).unwrap();
    builder.key_id(draft.key_id).unwrap();
    for principal in draft.principals {
        builder.valid_principal(principal).unwrap();
    }
    if let Some((name, value)) = draft.critical {
        builder.critical_option(name, value).unwrap();
    }
    if let Some((name, value)) = draft.extension {
        builder.extension(name, value).unwrap();
    }
    builder.sign(ca).unwrap()
}

fn with_broken_signature(certificate: &Certificate) -> Certificate {
    let mut bytes = certificate.to_bytes().unwrap();
    let nonce_at = 4 + "ssh-ed25519-cert-v01@openssh.com".len() + 4;
    bytes[nonce_at] ^= 0xff;
    Certificate::from_bytes(&bytes).unwrap()
}

#[test]
fn the_certificate_form_is_checked_rule_by_rule() {
    let ca = new_key();
    let trust = TrustSet::new(
        vec![ca.public_key().clone()],
        ca.public_key().fingerprint(HashAlg::Sha256),
    )
    .unwrap();
    let subject = new_key();
    let stranger_ca = new_key();
    let sk = SkEd25519::new(*subject.public_key().key_data().ed25519().unwrap(), "ssh:");
    let longest = MAX_USER_VALIDITY.saturating_add(BACKDATE).as_secs();
    let good = issue(draft(&subject), &ca);
    let cases: Vec<(&str, Certificate, Result<String, Reason>)> = vec![
        ("issued shape", good.clone(), Ok(USER.to_owned())),
        (
            "window at the cap",
            issue(
                Draft {
                    before: AFTER + longest,
                    ..draft(&subject)
                },
                &ca,
            ),
            Ok(USER.to_owned()),
        ),
        (
            "foreign authority",
            issue(draft(&subject), &stranger_ca),
            Err(Reason::UntrustedCa),
        ),
        (
            "broken signature of a trusted authority",
            with_broken_signature(&good),
            Err(Reason::UntrustedCa),
        ),
        (
            "host certificate",
            issue(
                Draft {
                    cert_type: CertType::Host,
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::NotUserCertificate),
        ),
        (
            "security key subject",
            issue(
                Draft {
                    subject: KeyData::SkEd25519(sk),
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::KeyAlgorithm),
        ),
        (
            "forced command",
            issue(
                Draft {
                    critical: Some(("force-command", "/bin/true")),
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::CriticalOptions),
        ),
        (
            "two principals",
            issue(
                Draft {
                    principals: vec![USER.to_owned(), "root".to_owned()],
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::Principal),
        ),
        (
            "principal that is not a user id",
            issue(
                Draft {
                    principals: vec!["root".to_owned()],
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::Principal),
        ),
        (
            "key id of another shape",
            issue(
                Draft {
                    key_id: format!("user:ada:{SERIAL}"),
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::CertificateKeyId),
        ),
        (
            "key id naming another serial",
            issue(
                Draft {
                    key_id: format!("jaunt:ada@example.com:{}", SERIAL + 1),
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::CertificateKeyId),
        ),
        (
            "web terminal origin",
            issue(
                Draft {
                    extension: Some((ORIGIN_EXTENSION, "web")),
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::WebOrigin),
        ),
        (
            "window past the cap",
            issue(
                Draft {
                    before: AFTER + longest + 1,
                    ..draft(&subject)
                },
                &ca,
            ),
            Err(Reason::Window),
        ),
    ];
    for (case, certificate, expected) in cases {
        assert_eq!(certificate_holder(&certificate, &trust), expected, "{case}");
    }
}

fn row(valid_after: i64, valid_before: i64) -> CertificateRow {
    CertificateRow {
        serial: 42,
        user_id: USER.to_owned(),
        kind: "user".to_owned(),
        key_id: "jaunt:ada@example.com:42".to_owned(),
        valid_after,
        valid_before,
        issued_at: valid_after,
        ca_fingerprint: None,
        host_trust_id: None,
        subject_fingerprint: None,
        parent_serial: None,
    }
}

#[test]
fn the_validity_is_the_narrower_of_the_certificate_and_its_row() {
    let after = i64::try_from(AFTER).unwrap();
    let before = i64::try_from(BEFORE).unwrap();
    let same = row(after, before);
    let narrower = row(after + 10, before - 10);
    for (case, stored, now, expected) in [
        (
            "before valid_after",
            &same,
            after - 1,
            Err(Reason::NotYetValid),
        ),
        ("at valid_after", &same, after, Ok(())),
        ("one second before valid_before", &same, before - 1, Ok(())),
        ("at valid_before", &same, before, Err(Reason::Expired)),
        (
            "before the row starts",
            &narrower,
            after + 9,
            Err(Reason::NotYetValid),
        ),
        (
            "when the row ends",
            &narrower,
            before - 10,
            Err(Reason::Expired),
        ),
        ("inside both", &narrower, before - 11, Ok(())),
    ] {
        assert_eq!(validity(AFTER, BEFORE, stored, now), expected, "{case}");
    }
    let wide = row(after - 100, before + 100);
    assert_eq!(validity(AFTER, BEFORE, &wide, before), Err(Reason::Expired));
    assert_eq!(
        validity(AFTER, BEFORE, &wide, after - 1),
        Err(Reason::NotYetValid)
    );
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
}

fn raw_sign<S: SigningKey>(key: &S, data: &[u8]) -> Signature {
    key.try_sign(data).unwrap()
}

struct Blob<'a> {
    version: u32,
    namespace: &'a str,
    reserved: &'a [u8],
    hash: HashAlg,
}

const PROPER: Blob<'static> = Blob {
    version: 1,
    namespace: "jaunt-admin@1",
    reserved: b"",
    hash: HashAlg::Sha512,
};

fn sshsig(key: &PrivateKey, blob: &Blob<'_>, message: &[u8]) -> Vec<u8> {
    let mut signed = b"SSHSIG".to_vec();
    put_string(&mut signed, blob.namespace.as_bytes());
    put_string(&mut signed, blob.reserved);
    put_string(&mut signed, blob.hash.as_str().as_bytes());
    put_string(&mut signed, &blob.hash.digest(message));
    let signature = Vec::<u8>::try_from(raw_sign(key, &signed)).unwrap();
    let mut out = b"SSHSIG".to_vec();
    out.extend_from_slice(&blob.version.to_be_bytes());
    put_string(
        &mut out,
        &PublicKey::from(key.public_key().key_data().clone())
            .to_bytes()
            .unwrap(),
    );
    put_string(&mut out, blob.namespace.as_bytes());
    put_string(&mut out, blob.reserved);
    put_string(&mut out, blob.hash.as_str().as_bytes());
    put_string(&mut out, &signature);
    out
}

#[test]
fn the_sshsig_blob_is_checked_field_by_field() {
    let key = new_key();
    let stranger = new_key();
    let subject = key.public_key().key_data();
    let base = b"the signature base";
    let proper = sshsig(&key, &PROPER, base);
    let mut trailing = proper.clone();
    trailing.push(0);
    let cases: Vec<(&str, Vec<u8>, &[u8], bool)> = vec![
        ("proper", proper.clone(), base, true),
        ("trailing byte", trailing, base, false),
        (
            "version zero",
            sshsig(
                &key,
                &Blob {
                    version: 0,
                    ..PROPER
                },
                base,
            ),
            base,
            false,
        ),
        (
            "reserved data",
            sshsig(
                &key,
                &Blob {
                    reserved: b"x",
                    ..PROPER
                },
                base,
            ),
            base,
            false,
        ),
        (
            "other namespace",
            sshsig(
                &key,
                &Blob {
                    namespace: "file",
                    ..PROPER
                },
                base,
            ),
            base,
            false,
        ),
        (
            "sha256",
            sshsig(
                &key,
                &Blob {
                    hash: HashAlg::Sha256,
                    ..PROPER
                },
                base,
            ),
            base,
            false,
        ),
        ("other key", sshsig(&stranger, &PROPER, base), base, false),
        ("other base", proper, b"another base", false),
        ("garbage", vec![1, 2, 3], base, false),
    ];
    for (case, blob, message, expected) in cases {
        assert_eq!(signature_holds(&blob, subject, message), expected, "{case}");
    }
}

#[test]
fn the_target_is_the_public_origin_with_the_received_path_and_query() {
    let origin = "https://jaunt.example";
    assert_eq!(
        target_uri(origin, &Uri::from_static("/v1/admin/audit?limit=5")),
        Some("https://jaunt.example/v1/admin/audit?limit=5".to_owned())
    );
    assert_eq!(
        target_uri(
            origin,
            &Uri::from_static("http://evil.example/v1/admin/whoami")
        ),
        Some("https://jaunt.example/v1/admin/whoami".to_owned())
    );
    assert_eq!(target_uri(origin, &Uri::from_static("*")), None);
}

#[test]
fn principals_are_single_lowercase_user_ids() {
    assert!(is_user_id(USER));
    for bad in [
        "3F2B1C9E-7A44-4D0E-9C58-0A6B8F1D2E77",
        "3f2b1c9e7a444d0e9c580a6b8f1d2e77",
        "00000000-0000-0000-0000-000000000000",
        "root",
        "",
    ] {
        assert!(!is_user_id(bad), "{bad}");
    }
}
