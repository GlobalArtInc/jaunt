use jaunt::issued::{VerifiedLogin, VerifyError, verify};
use jaunt::key::SessionKey;
use jaunt::profile::ProfileName;
use jaunt_proto::FinishResponse;
use ssh_key::certificate::CertType;

use crate::support::{
    CertSpec, DEFAULT_VALIDITY_SECS, EMAIL, USER_ID, ca_key, new_key_data, response_for, sign,
};

const NOW: u64 = 1_800_000_000;
const WEEK: u64 = 7 * 24 * 3600;

fn spec_at(key: &SessionKey) -> CertSpec {
    let mut spec = CertSpec::user(key.key_data().clone(), DEFAULT_VALIDITY_SECS);
    spec.valid_after = NOW - 120;
    spec.valid_before = NOW + DEFAULT_VALIDITY_SECS;
    spec
}

fn run(
    edit_spec: impl FnOnce(&mut CertSpec),
    edit_response: impl FnOnce(&mut FinishResponse),
) -> Result<VerifiedLogin, VerifyError> {
    let key = SessionKey::generate(&ProfileName::default_name()).unwrap();
    let mut spec = spec_at(&key);
    edit_spec(&mut spec);
    let certificate = sign(&ca_key(), &spec);
    let mut response = response_for(&certificate, &spec);
    edit_response(&mut response);
    verify(response, &key, NOW)
}

#[test]
fn a_matching_certificate_is_accepted_and_host_keys_are_stored_without_comments() {
    let verified = run(
        |_| {},
        |response| {
            let line = response.host_ca_keys[0].clone();
            response.host_ca_keys = vec![format!("{line} some-comment")];
        },
    )
    .unwrap();
    assert_eq!(verified.meta.user_id, USER_ID);
    assert_eq!(verified.meta.email, EMAIL);
    assert_eq!(verified.meta.serial, 7);
    assert_eq!(verified.meta.host_ca_keys.len(), 1);
    assert!(verified.meta.host_ca_keys[0].starts_with("ssh-ed25519 "));
    assert_eq!(verified.meta.host_ca_keys[0].split(' ').count(), 2);
    assert!(
        verified
            .certificate_line
            .starts_with("ssh-ed25519-cert-v01@openssh.com ")
    );
}

#[test]
fn the_validity_window_boundaries_are_inclusive_where_documented() {
    let at_skew_limit = run(
        |spec| {
            spec.valid_after = NOW + 300;
            spec.valid_before = NOW + 3600;
        },
        |_| {},
    );
    assert!(at_skew_limit.is_ok());
    let one_second_left = run(|spec| spec.valid_before = NOW + 1, |_| {});
    assert!(one_second_left.is_ok());
    let exactly_a_week = run(
        |spec| {
            spec.valid_after = NOW;
            spec.valid_before = NOW + WEEK;
        },
        |_| {},
    );
    assert!(exactly_a_week.is_ok());
}

#[test]
fn unsuitable_certificates_and_responses_are_refused() {
    let many_keys = |response: &mut FinishResponse| {
        response.host_ca_keys = vec![response.host_ca_keys[0].clone(); 17];
    };
    let cases: Vec<(&str, Result<VerifiedLogin, VerifyError>, VerifyError)> = vec![
        (
            "certificate for another key",
            run(|spec| spec.subject = new_key_data(), |_| {}),
            VerifyError::WrongKey,
        ),
        (
            "different principal",
            run(
                |spec| spec.principals = vec!["someone-else".to_owned()],
                |_| {},
            ),
            VerifyError::WrongPrincipals,
        ),
        (
            "two principals",
            run(
                |spec| spec.principals = vec![USER_ID.to_owned(), "extra".to_owned()],
                |_| {},
            ),
            VerifyError::WrongPrincipals,
        ),
        (
            "principal differs from the reported user id",
            run(
                |_| {},
                |response| response.user_id = "other-user".to_owned(),
            ),
            VerifyError::WrongPrincipals,
        ),
        (
            "host certificate",
            run(|spec| spec.cert_type = CertType::Host, |_| {}),
            VerifyError::NotUserCertificate,
        ),
        (
            "already expired",
            run(
                |spec| {
                    spec.valid_after = NOW - 600;
                    spec.valid_before = NOW - 10;
                },
                |_| {},
            ),
            VerifyError::Expired,
        ),
        (
            "expires exactly now",
            run(
                |spec| {
                    spec.valid_after = NOW - 600;
                    spec.valid_before = NOW;
                },
                |_| {},
            ),
            VerifyError::Expired,
        ),
        (
            "valid only in the far future",
            run(
                |spec| {
                    spec.valid_after = NOW + 301;
                    spec.valid_before = NOW + 3600;
                },
                |_| {},
            ),
            VerifyError::NotYetValid,
        ),
        (
            "longer than a week",
            run(
                |spec| {
                    spec.valid_after = NOW;
                    spec.valid_before = NOW + WEEK + 1;
                },
                |_| {},
            ),
            VerifyError::LifetimeTooLong,
        ),
        (
            "absurdly long",
            run(|spec| spec.valid_before = NOW + 400 * 24 * 3600, |_| {}),
            VerifyError::LifetimeTooLong,
        ),
        (
            "serial mismatch",
            run(|_| {}, |response| response.serial += 1),
            VerifyError::Inconsistent,
        ),
        (
            "key id mismatch",
            run(|_| {}, |response| response.key_id = "jaunt:x:7".to_owned()),
            VerifyError::Inconsistent,
        ),
        (
            "valid_before mismatch",
            run(|_| {}, |response| response.valid_before += 1),
            VerifyError::Inconsistent,
        ),
        (
            "valid_after mismatch",
            run(|_| {}, |response| response.valid_after += 1),
            VerifyError::Inconsistent,
        ),
        (
            "unparsable certificate",
            run(
                |_| {},
                |response| response.certificate = "garbage".to_owned(),
            ),
            VerifyError::CertificateUnreadable,
        ),
        (
            "certificate line with an embedded newline",
            run(
                |_| {},
                |response| response.certificate = format!("{}\nextra", response.certificate),
            ),
            VerifyError::CertificateUnreadable,
        ),
        (
            "certificate line with a control character in its comment",
            run(
                |_| {},
                |response| {
                    response.certificate = format!("{} \u{1b}[31mevil", response.certificate)
                },
            ),
            VerifyError::CertificateUnreadable,
        ),
        (
            "empty token",
            run(|_| {}, |response| response.api_token = String::new()),
            VerifyError::BadToken,
        ),
        (
            "token with a space",
            run(|_| {}, |response| response.api_token = "jt bad".to_owned()),
            VerifyError::BadToken,
        ),
        (
            "email with an escape sequence",
            run(
                |_| {},
                |response| response.email = "a\u{1b}[31m@x".to_owned(),
            ),
            VerifyError::BadIdentity,
        ),
        (
            "host key that is not a key",
            run(
                |_| {},
                |response| response.host_ca_keys = vec!["nope".to_owned()],
            ),
            VerifyError::BadHostKey,
        ),
        (
            "host key with an embedded newline",
            run(
                |_| {},
                |response| {
                    response.host_ca_keys =
                        vec![format!("{}\nssh-rsa AAAA", response.host_ca_keys[0])];
                },
            ),
            VerifyError::BadHostKey,
        ),
        (
            "too many host keys",
            run(|_| {}, many_keys),
            VerifyError::BadHostKey,
        ),
    ];
    for (name, outcome, expected) in cases {
        assert_eq!(outcome.err(), Some(expected), "{name}");
    }
}
