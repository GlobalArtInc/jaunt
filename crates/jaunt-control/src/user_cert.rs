use std::time::Duration;

use jaunt_ca::ssh_key::PublicKey;
use jaunt_ca::{UserCertParams, Uuid, sign_user_certificate, sign_web_user_certificate};
use jaunt_store::{NewCertificate, User};

use crate::clock::Moment;
use crate::control::Control;
use crate::finish::{CERTIFICATE_KIND, key_fingerprint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertOrigin {
    Cli,
    Web,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserCertFailure {
    Store,
    CorruptRecord,
    Signing,
}

pub(crate) struct SignedUserCertificate {
    pub(crate) serial: i64,
    pub(crate) line: String,
    pub(crate) key_id: String,
    pub(crate) valid_after: i64,
    pub(crate) valid_before: i64,
    pub(crate) host_ca_keys: Vec<String>,
}

pub(crate) async fn issue(
    control: &Control,
    user: &User,
    subject_key: PublicKey,
    validity: Duration,
    origin: CertOrigin,
    now: Moment,
) -> Result<SignedUserCertificate, UserCertFailure> {
    let user_uuid = Uuid::parse_str(&user.id).map_err(|_| {
        tracing::error!(target: "jaunt::control", "a stored user id is not a uuid");
        UserCertFailure::CorruptRecord
    })?;

    let ca = control.ca_snapshot();
    let certificates = control.store.certificates();
    let serial = certificates.allocate_serial().await.map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "allocating a serial failed");
        UserCertFailure::Store
    })?;
    let serial_number = u64::try_from(serial).map_err(|_| {
        tracing::error!(target: "jaunt::control", "the serial counter is not positive");
        UserCertFailure::CorruptRecord
    })?;

    let params = UserCertParams {
        subject_public_key: subject_key,
        user_id: user_uuid,
        email: user.email.clone(),
        serial: serial_number,
        validity,
    };
    let signed = match origin {
        CertOrigin::Cli => sign_user_certificate(ca.user_signer().as_ref(), params, now.system),
        CertOrigin::Web => sign_web_user_certificate(ca.user_signer().as_ref(), params, now.system),
    };
    let certificate = signed.map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "signing the user certificate failed");
        UserCertFailure::Signing
    })?;
    let line = certificate.to_openssh().map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "encoding the user certificate failed");
        UserCertFailure::Signing
    })?;
    let valid_after =
        i64::try_from(certificate.valid_after()).map_err(|_| UserCertFailure::Signing)?;
    let valid_before =
        i64::try_from(certificate.valid_before()).map_err(|_| UserCertFailure::Signing)?;

    certificates
        .record(&NewCertificate {
            serial,
            user_id: user.id.clone(),
            kind: CERTIFICATE_KIND.to_owned(),
            key_id: certificate.key_id().to_owned(),
            valid_after,
            valid_before,
            issued_at: now.secs,
            ca_fingerprint: Some(key_fingerprint(certificate.signature_key())),
            host_trust_id: Some(ca.host_trust_id().to_owned()),
            subject_fingerprint: Some(key_fingerprint(certificate.public_key())),
        })
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "recording the certificate failed");
            UserCertFailure::Store
        })?;

    Ok(SignedUserCertificate {
        serial,
        line,
        key_id: certificate.key_id().to_owned(),
        valid_after,
        valid_before,
        host_ca_keys: ca.host_ca_keys().to_vec(),
    })
}
