use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::ExtendedKeyUsagePurpose;
use rustls::{CertificateError, Error as TlsError};
use uuid::Uuid;

use super::issuance::{
    authority_key_id, is_expired, is_not_yet_valid, sans, subject_key_id, usages, verify_server,
};
use super::{
    DAY, Fixture, NOW_SECS, common_names, der_serial, now, openssl, openssl_verify, parsed, pem,
    subject,
};
use crate::cert::window;
use crate::error::CaError;
use crate::kind::CaKind;
use crate::test_support::{ClientAuthority, authority, client_authority, verify_client};
use crate::x509::{
    CLIENT_ROOT_VALIDITY, ClientCa, DEFAULT_NODE_VALIDITY, DbClientParams, IssuedCertificate,
    MAX_USER_X509_VALIDITY, SubjectPublicKey, UserX509Params,
};

const USER_ID: &str = "0b7d1c52-3f4e-4a8b-9c6d-2e1f0a9b8c7d";
const EMAIL: &str = "ada@example.com";
const ROLE: &str = "app_reader";
const HOUR: u64 = 60 * 60;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn user_params(valid_before: SystemTime) -> UserX509Params {
    UserX509Params {
        subject_public_key: subject(),
        user_id: Uuid::parse_str(USER_ID).unwrap(),
        email: EMAIL.to_owned(),
        serial: 42,
        valid_before,
    }
}

fn db_params(role: &str) -> DbClientParams {
    DbClientParams {
        subject_public_key: subject(),
        role: role.to_owned(),
        serial: 77,
    }
}

fn user_cert(authority: &ClientAuthority) -> IssuedCertificate {
    authority
        .slot
        .ca
        .issue_user_certificate(user_params(at(NOW_SECS + 8 * HOUR)), now())
        .unwrap()
}

fn db_cert(authority: &ClientAuthority) -> IssuedCertificate {
    authority
        .slot
        .ca
        .issue_db_client_certificate(db_params(ROLE), now())
        .unwrap()
}

fn root(authority: &ClientAuthority) -> &[u8] {
    authority.slot.ca.root_der()
}

fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn user_certificate_carries_the_user_profile() {
    let authority = client_authority(CaKind::UserX509, now());
    let issued = user_cert(&authority);
    let root_certificate = parsed(root(&authority));
    let leaf = parsed(&issued.certificate_der);

    assert_eq!(common_names(&leaf), [EMAIL]);
    assert_eq!(sans(&leaf), [format!("URI(urn:jaunt:user:{USER_ID})")]);
    assert_eq!(usages(&leaf), (true, false, false));
    let constraints = leaf.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical && !constraints.value.ca);
    let usage = leaf.key_usage().unwrap().unwrap();
    assert!(usage.critical);
    assert_eq!(usage.value.flags, 1);
    assert_eq!(leaf.issuer().as_raw(), root_certificate.subject().as_raw());
    assert_eq!(authority_key_id(&leaf), subject_key_id(&root_certificate));
    assert_eq!(der_serial(&leaf), 42);
    assert_eq!(issued.serial, 42);
    let validity = leaf.validity();
    assert_eq!(
        validity.not_before.timestamp(),
        i64::try_from(NOW_SECS - 120).unwrap()
    );
    assert_eq!(
        validity.not_after.timestamp(),
        i64::try_from(NOW_SECS + 8 * HOUR).unwrap()
    );
    assert_eq!(issued.not_after, at(NOW_SECS + 8 * HOUR));

    let mut params = user_params(at(NOW_SECS + HOUR));
    params.serial = u64::MAX;
    let highest = authority
        .slot
        .ca
        .issue_user_certificate(params, now())
        .unwrap();
    assert_eq!(
        der_serial(&parsed(&highest.certificate_der)),
        u128::from(u64::MAX)
    );
    assert!(verify_client(root(&authority), &highest.certificate_der, NOW_SECS).is_ok());
}

#[test]
fn db_client_certificate_carries_the_database_profile() {
    let authority = client_authority(CaKind::DbClient, now());
    let issued = db_cert(&authority);
    let leaf = parsed(&issued.certificate_der);

    assert_eq!(common_names(&leaf), [ROLE]);
    assert!(leaf.subject_alternative_name().unwrap().is_none());
    assert_eq!(usages(&leaf), (true, false, false));
    assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
    let validity = leaf.validity();
    assert_eq!(
        validity.not_before.timestamp(),
        i64::try_from(NOW_SECS - 60).unwrap()
    );
    assert_eq!(
        validity.not_after.timestamp(),
        i64::try_from(NOW_SECS + 300).unwrap()
    );
    assert_eq!(issued.not_before, at(NOW_SECS - 60));
    assert_eq!(issued.not_after, at(NOW_SECS + 300));
    assert_eq!(der_serial(&leaf), 77);
    assert_eq!(issued.serial, 77);

    let mut params = db_params(ROLE);
    params.serial = u64::MAX;
    let highest = authority
        .slot
        .ca
        .issue_db_client_certificate(params, now())
        .unwrap();
    assert_eq!(
        der_serial(&parsed(&highest.certificate_der)),
        u128::from(u64::MAX)
    );
    let mut params = db_params(ROLE);
    params.serial = 0;
    assert!(matches!(
        authority.slot.ca.issue_db_client_certificate(params, now()),
        Err(CaError::InvalidSerial)
    ));
}

#[test]
fn client_roots_have_the_authority_profile_and_only_their_own_key() {
    for (kind, name) in [
        (CaKind::UserX509, "Jaunt User X.509 CA"),
        (CaKind::DbClient, "Jaunt Database Client CA"),
    ] {
        let authority = client_authority(kind, now());
        let certificate = parsed(root(&authority));
        assert_eq!(common_names(&certificate), [name]);
        assert_eq!(
            certificate.subject().as_raw(),
            certificate.issuer().as_raw()
        );
        let constraints = certificate.basic_constraints().unwrap().unwrap();
        assert!(constraints.critical && constraints.value.ca);
        assert_eq!(constraints.value.path_len_constraint, Some(0));
        assert!(
            certificate
                .key_usage()
                .unwrap()
                .unwrap()
                .value
                .key_cert_sign()
        );
        assert!(certificate.extended_key_usage().unwrap().is_none());
        let validity = certificate.validity();
        assert_eq!(
            validity.not_before.timestamp(),
            i64::try_from(NOW_SECS - 120).unwrap()
        );
        assert_eq!(
            validity.not_after.timestamp(),
            i64::try_from(NOW_SECS + 5 * 365 * DAY).unwrap()
        );
        assert_eq!(authority.slot.ca.kind(), kind);
    }
    assert_eq!(CLIENT_ROOT_VALIDITY, Duration::from_secs(1825 * DAY));

    let user = client_authority(CaKind::UserX509, now());
    let db = client_authority(CaKind::DbClient, now());
    let signer = |authority: &ClientAuthority| {
        let (_, backend) = crate::file::FileBackend::load(
            authority.dir.path(),
            authority.slot.ca.kind(),
            &authority.identity,
        )
        .unwrap();
        std::sync::Arc::new(backend)
    };
    assert!(matches!(
        ClientCa::new(signer(&user), root(&db).to_vec()),
        Err(CaError::InvalidRootCertificate { .. })
    ));
    let internal = Fixture::new();
    assert!(matches!(
        ClientCa::new(
            internal.authority.shared_signer(),
            internal.root.certificate_der.clone()
        ),
        Err(CaError::NotAClientAuthority(CaKind::Internal))
    ));
    for kind in [CaKind::User, CaKind::Host] {
        let ssh = authority(kind);
        assert!(matches!(
            ClientCa::create_root(&ssh.backend, now()),
            Err(CaError::NotAClientAuthority(found)) if found == kind
        ));
    }
    assert!(ClientCa::new(signer(&user), root(&user).to_vec()).is_ok());
}

enum Expect {
    Accepted,
    NotYetValid,
    Expired,
    Rejected,
}

type Row<'a> = (&'a str, &'a [u8], &'a [u8], u64, Expect);

#[test]
fn rustls_accepts_client_certificates_only_from_their_own_root_inside_their_window() {
    let user = client_authority(CaKind::UserX509, now());
    let db = client_authority(CaKind::DbClient, now());
    let other_user = client_authority(CaKind::UserX509, now());
    let internal = Fixture::new();
    let user_leaf = user_cert(&user);
    let db_leaf = db_cert(&db);
    let window = window(now(), DEFAULT_NODE_VALIDITY, DEFAULT_NODE_VALIDITY).unwrap();
    let server_leaf = user
        .slot
        .ca
        .issue_raw(
            &subject(),
            &window,
            "kube.example.com",
            ExtendedKeyUsagePurpose::ServerAuth,
        )
        .unwrap();
    let (user_first, user_last) = (seconds(user_leaf.not_before), seconds(user_leaf.not_after));
    let (db_first, db_last) = (seconds(db_leaf.not_before), seconds(db_leaf.not_after));
    let user_cert_der = user_leaf.certificate_der.as_slice();
    let db_cert_der = db_leaf.certificate_der.as_slice();
    let internal_root = internal.root.certificate_der.as_slice();

    let rows: Vec<Row<'_>> = vec![
        (
            "user at issue time",
            root(&user),
            user_cert_der,
            NOW_SECS,
            Expect::Accepted,
        ),
        (
            "user first second",
            root(&user),
            user_cert_der,
            user_first,
            Expect::Accepted,
        ),
        (
            "user last second",
            root(&user),
            user_cert_der,
            user_last,
            Expect::Accepted,
        ),
        (
            "user before",
            root(&user),
            user_cert_der,
            user_first - 1,
            Expect::NotYetValid,
        ),
        (
            "user after",
            root(&user),
            user_cert_der,
            user_last + 1,
            Expect::Expired,
        ),
        (
            "db at issue time",
            root(&db),
            db_cert_der,
            NOW_SECS,
            Expect::Accepted,
        ),
        (
            "db first second",
            root(&db),
            db_cert_der,
            db_first,
            Expect::Accepted,
        ),
        (
            "db last second",
            root(&db),
            db_cert_der,
            db_last,
            Expect::Accepted,
        ),
        (
            "db before",
            root(&db),
            db_cert_der,
            db_first - 1,
            Expect::NotYetValid,
        ),
        (
            "db after",
            root(&db),
            db_cert_der,
            db_last + 1,
            Expect::Expired,
        ),
        (
            "user against db",
            root(&db),
            user_cert_der,
            NOW_SECS,
            Expect::Rejected,
        ),
        (
            "db against user",
            root(&user),
            db_cert_der,
            NOW_SECS,
            Expect::Rejected,
        ),
        (
            "user against another user slot",
            root(&other_user),
            user_cert_der,
            NOW_SECS,
            Expect::Rejected,
        ),
        (
            "user against internal",
            internal_root,
            user_cert_der,
            NOW_SECS,
            Expect::Rejected,
        ),
        (
            "db against internal",
            internal_root,
            db_cert_der,
            NOW_SECS,
            Expect::Rejected,
        ),
        (
            "server usage",
            root(&user),
            &server_leaf.certificate_der,
            NOW_SECS,
            Expect::Rejected,
        ),
    ];
    for (label, root_der, cert_der, seconds, expect) in rows {
        let outcome = verify_client(root_der, cert_der, seconds);
        let fits = match (&expect, &outcome) {
            (Expect::Accepted, Ok(())) => true,
            (Expect::NotYetValid, Err(err)) => is_not_yet_valid(err),
            (Expect::Expired, Err(err)) => is_expired(err),
            (Expect::Rejected, Err(TlsError::InvalidCertificate(err))) => !matches!(
                err,
                CertificateError::Expired
                    | CertificateError::ExpiredContext { .. }
                    | CertificateError::NotValidYet
                    | CertificateError::NotValidYetContext { .. }
            ),
            _ => false,
        };
        assert!(fits, "{label}: {outcome:?}");
    }
    assert!(matches!(
        verify_server(root(&user), user_cert_der, "kube.example.com", NOW_SECS),
        Err(TlsError::InvalidCertificate(_))
    ));
}

#[test]
fn openssl_accepts_client_certificates_only_from_their_own_root() {
    let Some(openssl) = openssl() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let user = client_authority(CaKind::UserX509, now());
    let db = client_authority(CaKind::DbClient, now());
    let user_root = pem(openssl, dir.path(), "user-root", root(&user));
    let db_root = pem(openssl, dir.path(), "db-root", root(&db));
    let user_leaf = pem(
        openssl,
        dir.path(),
        "user-leaf",
        &user_cert(&user).certificate_der,
    );
    let db_leaf = pem(
        openssl,
        dir.path(),
        "db-leaf",
        &db_cert(&db).certificate_der,
    );

    assert!(openssl_verify(
        openssl,
        &user_root,
        &user_leaf,
        "sslclient",
        NOW_SECS
    ));
    assert!(openssl_verify(
        openssl,
        &db_root,
        &db_leaf,
        "sslclient",
        NOW_SECS
    ));
    assert!(!openssl_verify(
        openssl,
        &db_root,
        &user_leaf,
        "sslclient",
        NOW_SECS
    ));
    assert!(!openssl_verify(
        openssl,
        &user_root,
        &db_leaf,
        "sslclient",
        NOW_SECS
    ));
    assert!(!openssl_verify(
        openssl,
        &user_root,
        &user_leaf,
        "sslserver",
        NOW_SECS
    ));
    assert!(!openssl_verify(
        openssl,
        &db_root,
        &db_leaf,
        "sslclient",
        NOW_SECS + 301
    ));
    assert!(!openssl_verify(
        openssl,
        &db_root,
        &db_leaf,
        "sslclient",
        NOW_SECS - 61
    ));
}

#[test]
fn user_certificate_validity_comes_from_the_parent_certificate() {
    let authority = client_authority(CaKind::UserX509, now());
    let ca = &authority.slot.ca;
    let issue = |valid_before: SystemTime, at: SystemTime| {
        ca.issue_user_certificate(user_params(valid_before), at)
    };
    let max = NOW_SECS + MAX_USER_X509_VALIDITY.as_secs();
    for (label, valid_before) in [
        ("now", at(NOW_SECS)),
        ("in the past", at(NOW_SECS - 1)),
        (
            "a sub-second ahead",
            at(NOW_SECS) + Duration::from_millis(900),
        ),
        ("past the 24 hour limit", at(max + 1)),
    ] {
        assert!(
            matches!(
                issue(valid_before, now()),
                Err(CaError::InvalidValidity { .. })
            ),
            "{label}"
        );
    }
    assert!(matches!(
        issue(UNIX_EPOCH - Duration::from_secs(1), now()),
        Err(CaError::InvalidTime)
    ));
    assert_eq!(issue(at(max), now()).unwrap().not_after, at(max));
    assert_eq!(
        issue(at(NOW_SECS + 1) + Duration::from_millis(900), now())
            .unwrap()
            .not_after,
        at(NOW_SECS + 1)
    );

    let root_end = NOW_SECS + CLIENT_ROOT_VALIDITY.as_secs();
    assert!(issue(at(root_end), at(root_end - HOUR)).is_ok());
    assert!(matches!(
        issue(at(root_end + 1), at(root_end - HOUR)),
        Err(CaError::ExceedsRootValidity)
    ));
    assert!(matches!(
        issue(at(root_end + 2 * HOUR), at(root_end + 1)),
        Err(CaError::RootNotValid)
    ));
}

#[test]
fn client_certificate_parameters_are_validated() {
    let user = client_authority(CaKind::UserX509, now());
    let db = client_authority(CaKind::DbClient, now());
    let valid_before = at(NOW_SECS + HOUR);
    let issue_user = |edit: &dyn Fn(&mut UserX509Params)| {
        let mut params = user_params(valid_before);
        edit(&mut params);
        user.slot.ca.issue_user_certificate(params, now())
    };
    type Edit = fn(&mut UserX509Params);
    type Check = fn(&CaError) -> bool;
    let user_rows: [(&str, Edit, Check); 4] = [
        (
            "nil user",
            |params| params.user_id = Uuid::nil(),
            |err| matches!(err, CaError::InvalidUserId),
        ),
        (
            "serial zero",
            |params| params.serial = 0,
            |err| matches!(err, CaError::InvalidSerial),
        ),
        (
            "empty email",
            |params| params.email.clear(),
            |err| matches!(err, CaError::InvalidEmail),
        ),
        (
            "email with a space",
            |params| params.email = "a b@example.com".to_owned(),
            |err| matches!(err, CaError::InvalidEmail),
        ),
    ];
    for (label, edit, expected) in user_rows {
        let err = issue_user(&edit).unwrap_err();
        assert!(expected(&err), "{label}: {err:?}");
    }

    let issue_db = |role: &str| {
        db.slot
            .ca
            .issue_db_client_certificate(db_params(role), now())
    };
    let longest_role = "r".repeat(63);
    for role in [longest_role.as_str(), "app_reader", "a", "app-user.v2@ro"] {
        assert!(issue_db(role).is_ok(), "{role}");
    }
    let too_long = "r".repeat(64);
    for role in [
        "",
        too_long.as_str(),
        "app reader",
        "app\0",
        "app\n",
        "r\u{f4}le",
    ] {
        assert!(
            matches!(issue_db(role), Err(CaError::InvalidDatabaseRole)),
            "{role:?}"
        );
    }

    assert!(matches!(
        db.slot
            .ca
            .issue_user_certificate(user_params(valid_before), now()),
        Err(CaError::WrongAuthorityKind {
            expected: CaKind::UserX509
        })
    ));
    assert!(matches!(
        user.slot
            .ca
            .issue_db_client_certificate(db_params(ROLE), now()),
        Err(CaError::WrongAuthorityKind {
            expected: CaKind::DbClient
        })
    ));
    let own_key = SubjectPublicKey::from_ssh_key(user.slot.trust.active()).unwrap();
    let mut params = user_params(valid_before);
    params.subject_public_key = own_key;
    assert!(matches!(
        user.slot.ca.issue_user_certificate(params, now()),
        Err(CaError::InvalidSubjectKey)
    ));
}

#[test]
fn user_certificate_names_the_user_id_when_the_email_does_not_fit_the_common_name() {
    let authority = client_authority(CaKind::UserX509, now());
    let fits = format!("{}@example.com", "a".repeat(64 - "@example.com".len()));
    let too_long = format!("{}@example.com", "a".repeat(65 - "@example.com".len()));
    assert_eq!((fits.len(), too_long.len()), (64, 65));
    for (email, expected) in [(fits.as_str(), fits.as_str()), (too_long.as_str(), USER_ID)] {
        let mut params = user_params(at(NOW_SECS + HOUR));
        params.email = email.to_owned();
        let issued = authority
            .slot
            .ca
            .issue_user_certificate(params, now())
            .unwrap();
        let leaf = parsed(&issued.certificate_der);
        assert_eq!(common_names(&leaf), [expected], "{email}");
        assert_eq!(sans(&leaf), [format!("URI(urn:jaunt:user:{USER_ID})")]);
        assert!(verify_client(root(&authority), &issued.certificate_der, NOW_SECS).is_ok());
    }
}
