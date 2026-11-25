use jaunt_proto::{ControlError as PlaneError, DenyReason};
use jaunt_store::User;

use crate::control::Control;
use crate::finish::CERTIFICATE_KIND;
use crate::plane::store_failure;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Absent {
    Refused,
    Accepted,
}

pub(crate) struct Presented<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) serial: u64,
    pub(crate) key_id: &'a str,
    pub(crate) subject_fingerprint: Option<&'a str>,
    pub(crate) absent: Absent,
}

pub(crate) struct Holder {
    pub(crate) user: User,
    pub(crate) serial: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubjectKey {
    Matches,
    Unrecorded,
    NotPresented,
    Mismatch,
}

fn subject_key(stored: Option<&str>, presented: Option<&str>, absent: Absent) -> SubjectKey {
    match (stored, presented) {
        (None, _) => SubjectKey::Unrecorded,
        (Some(stored), Some(presented)) if stored == presented => SubjectKey::Matches,
        (Some(_), Some(_)) => SubjectKey::Mismatch,
        (Some(_), None) if absent == Absent::Accepted => SubjectKey::NotPresented,
        (Some(_), None) => SubjectKey::Mismatch,
    }
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
    match subject_key(
        certificate.subject_fingerprint.as_deref(),
        presented.subject_fingerprint,
        presented.absent,
    ) {
        SubjectKey::Matches => {}
        SubjectKey::Mismatch => return Ok(Err(DenyReason::SubjectKeyMismatch)),
        SubjectKey::Unrecorded => tracing::debug!(
            target: "jaunt::control",
            serial,
            "the certificate was issued before subject keys were recorded"
        ),
        SubjectKey::NotPresented => tracing::debug!(
            target: "jaunt::control",
            serial,
            "the request does not name the certified key, as an older agent does"
        ),
    }
    if now < certificate.valid_after || now >= certificate.valid_before {
        return Ok(Err(DenyReason::CertificateExpired));
    }
    Ok(Ok(Holder { user, serial }))
}

#[cfg(test)]
mod tests {
    use super::{Absent, SubjectKey, subject_key};

    #[test]
    fn the_subject_key_rule_decides_every_combination() {
        let rows = [
            (None, None, Absent::Refused, SubjectKey::Unrecorded),
            (None, Some("aa"), Absent::Refused, SubjectKey::Unrecorded),
            (None, None, Absent::Accepted, SubjectKey::Unrecorded),
            (Some("aa"), Some("aa"), Absent::Refused, SubjectKey::Matches),
            (
                Some("aa"),
                Some("aa"),
                Absent::Accepted,
                SubjectKey::Matches,
            ),
            (
                Some("aa"),
                Some("bb"),
                Absent::Refused,
                SubjectKey::Mismatch,
            ),
            (
                Some("aa"),
                Some("bb"),
                Absent::Accepted,
                SubjectKey::Mismatch,
            ),
            (
                Some("aa"),
                Some("AA"),
                Absent::Accepted,
                SubjectKey::Mismatch,
            ),
            (Some("aa"), Some(""), Absent::Accepted, SubjectKey::Mismatch),
            (Some("aa"), None, Absent::Refused, SubjectKey::Mismatch),
            (Some("aa"), None, Absent::Accepted, SubjectKey::NotPresented),
        ];
        for (stored, presented, absent, expected) in rows {
            assert_eq!(
                subject_key(stored, presented, absent),
                expected,
                "{stored:?} {presented:?} {absent:?}"
            );
        }
    }
}
