use jaunt_proto::{ControlError as PlaneError, DenyReason};
use jaunt_store::User;

use crate::control::Control;
use crate::finish::CERTIFICATE_KIND;
use crate::plane::store_failure;

pub(crate) struct Presented<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) serial: u64,
    pub(crate) key_id: &'a str,
}

pub(crate) struct Holder {
    pub(crate) user: User,
    pub(crate) serial: i64,
}

pub(crate) async fn verify(
    control: &Control,
    presented: &Presented<'_>,
    now: i64,
) -> Result<Result<Holder, DenyReason>, PlaneError> {
    let Some(user) = control
        .store
        .users()
        .get(presented.user_id)
        .await
        .map_err(store_failure("loading the user"))?
    else {
        return Ok(Err(DenyReason::UnknownUser));
    };
    let Ok(serial) = i64::try_from(presented.serial) else {
        return Ok(Err(DenyReason::CertificateNotIssued));
    };
    let Some(certificate) = control
        .store
        .certificates()
        .get(serial)
        .await
        .map_err(store_failure("loading the certificate"))?
    else {
        return Ok(Err(DenyReason::CertificateNotIssued));
    };
    if certificate.user_id != user.id
        || certificate.key_id != presented.key_id
        || certificate.kind != CERTIFICATE_KIND
    {
        return Ok(Err(DenyReason::CertificateNotIssued));
    }
    if now < certificate.valid_after || now >= certificate.valid_before {
        return Ok(Err(DenyReason::CertificateExpired));
    }
    Ok(Ok(Holder { user, serial }))
}
