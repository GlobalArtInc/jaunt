use jaunt_ca::fingerprint_hex;
use jaunt_proto::{ControlError as PlaneError, DenyReason, ServiceIdentity};
use jaunt_store::{Certificate, User};

use crate::control::Control;
use crate::finish::CERTIFICATE_KIND;
use crate::plane::store_failure;
use crate::x509_cert::X509_KIND;

pub(crate) struct ServiceHolder {
    pub(crate) user: User,
    pub(crate) serial: i64,
}

pub(crate) async fn verify(
    control: &Control,
    identity: &ServiceIdentity,
    now: i64,
) -> Result<Result<ServiceHolder, DenyReason>, PlaneError> {
    let Some(user) = control
        .store
        .users()
        .get(&identity.user_id)
        .await
        .map_err(store_failure("loading the user"))?
    else {
        return Ok(Err(DenyReason::UnknownUser));
    };
    let Ok(serial) = i64::try_from(identity.serial) else {
        return Ok(Err(DenyReason::CertificateNotIssued));
    };
    let certificates = control.store.certificates();
    let Some(certificate) = certificates
        .get(serial)
        .await
        .map_err(store_failure("loading the certificate"))?
    else {
        return Ok(Err(DenyReason::CertificateNotIssued));
    };
    let Some(parent_serial) = certificate.parent_serial else {
        return Ok(Err(DenyReason::CertificateNotIssued));
    };
    if certificate.user_id != user.id || certificate.kind != X509_KIND {
        return Ok(Err(DenyReason::CertificateNotIssued));
    }
    if certificate.subject_fingerprint.as_deref() != Some(identity.subject_fingerprint.as_str()) {
        return Ok(Err(DenyReason::SubjectKeyMismatch));
    }
    if certificate.ca_fingerprint.as_deref() != Some(identity.issuer_fingerprint.as_str()) {
        return Ok(Err(DenyReason::IssuerMismatch));
    }
    if !issuer_trusted(control, &identity.issuer_fingerprint) {
        return Ok(Err(DenyReason::IssuerUntrusted));
    }
    if !valid_at(&certificate, now) {
        return Ok(Err(DenyReason::CertificateExpired));
    }
    let Some(parent) = certificates
        .get(parent_serial)
        .await
        .map_err(store_failure("loading the parent certificate"))?
    else {
        return Ok(Err(DenyReason::CertificateNotIssued));
    };
    if parent.user_id != user.id || parent.kind != CERTIFICATE_KIND {
        return Ok(Err(DenyReason::CertificateNotIssued));
    }
    if !valid_at(&parent, now) {
        return Ok(Err(DenyReason::CertificateExpired));
    }
    Ok(Ok(ServiceHolder { user, serial }))
}

fn valid_at(certificate: &Certificate, now: i64) -> bool {
    certificate.valid_after <= now && now < certificate.valid_before
}

fn issuer_trusted(control: &Control, fingerprint: &str) -> bool {
    control.user_x509().is_some_and(|slot| {
        slot.trust
            .keys()
            .iter()
            .any(|key| fingerprint_hex(key) == fingerprint)
    })
}
