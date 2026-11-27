use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_ca::{CaError, DEFAULT_SERVICE_VALIDITY, ServiceCertParams, SubjectPublicKey};
use jaunt_store::StoreError;

use crate::clock::Moment;
use crate::control::Control;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ServerIssueError {
    #[error("allocating a serial failed: {0}")]
    Serial(#[source] StoreError),
    #[error("the serial counter is not positive")]
    SerialRange,
    #[error("the service certificate authority root is not valid now")]
    RootNotValid,
    #[error("signing failed: {0}")]
    Signing(#[source] CaError),
    #[error("a certificate validity time does not fit the record")]
    Time,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerIssued {
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) serial: i64,
    pub(crate) valid_after: i64,
    pub(crate) valid_before: i64,
}

pub(crate) fn unix_secs(time: SystemTime) -> Option<i64> {
    let secs = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(secs).ok()
}

pub(crate) fn capped_validity(now: i64, wanted_end: i64, root_end: i64) -> Option<Duration> {
    let end = wanted_end.min(root_end);
    let remaining = end.checked_sub(now).filter(|remaining| *remaining > 0)?;
    u64::try_from(remaining).ok().map(Duration::from_secs)
}

pub(crate) async fn issue(
    control: &Control,
    subject: &SubjectPublicKey,
    dns_name: &str,
    now: Moment,
) -> Result<ServerIssued, ServerIssueError> {
    let root_end =
        unix_secs(control.internal_ca.root_not_after()).ok_or(ServerIssueError::RootNotValid)?;
    let service_secs =
        i64::try_from(DEFAULT_SERVICE_VALIDITY.as_secs()).map_err(|_| ServerIssueError::Time)?;
    let validity = capped_validity(now.secs, now.secs.saturating_add(service_secs), root_end)
        .ok_or(ServerIssueError::RootNotValid)?;
    let serial = control
        .store
        .certificates()
        .allocate_serial()
        .await
        .map_err(ServerIssueError::Serial)?;
    let serial_number = u64::try_from(serial).map_err(|_| ServerIssueError::SerialRange)?;
    let issued = control
        .internal_ca
        .issue_service_certificate(
            ServiceCertParams {
                subject_public_key: subject.clone(),
                dns_names: vec![dns_name.to_owned()],
                serial: serial_number,
                validity,
            },
            now.system,
        )
        .map_err(ServerIssueError::Signing)?;
    Ok(ServerIssued {
        serial,
        valid_after: unix_secs(issued.not_before).ok_or(ServerIssueError::Time)?,
        valid_before: unix_secs(issued.not_after).ok_or(ServerIssueError::Time)?,
        certificate_der: issued.certificate_der,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::capped_validity;

    #[test]
    fn the_validity_ends_at_the_earlier_of_the_wanted_end_and_the_root() {
        let now = 1_000;
        for (wanted, root, expected) in [
            (2_000, 5_000, Some(1_000)),
            (5_000, 2_000, Some(1_000)),
            (2_000, 2_000, Some(1_000)),
            (1_001, 5_000, Some(1)),
            (5_000, 1_001, Some(1)),
            (1_000, 5_000, None),
            (5_000, 1_000, None),
            (5_000, 999, None),
            (999, 5_000, None),
        ] {
            assert_eq!(
                capped_validity(now, wanted, root),
                expected.map(Duration::from_secs),
                "{wanted} {root}"
            );
        }
    }
}
