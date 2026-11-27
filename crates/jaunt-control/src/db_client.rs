use jaunt_ca::ssh_key::HashAlg;
use jaunt_ca::{CaError, CaKind, ClientSlot, DbClientParams, FileBackend};
use jaunt_limits::{Decision, Rate, RateLimiter};
use jaunt_proto::DenyReason;

use crate::clock::Moment;
use crate::control::Control;
use crate::node_keys;
use crate::server_cert::unix_secs;

pub(crate) const ISSUANCE_PER_USER: Rate = Rate::clamped(16, 20);
const USERS_TRACKED: usize = 10_000;

pub(crate) fn user_issuance_limiter() -> RateLimiter<String> {
    RateLimiter::new(ISSUANCE_PER_USER, USERS_TRACKED)
}

pub(crate) struct DbClientCertificate {
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) serial: i64,
    pub(crate) valid_after: i64,
    pub(crate) valid_before: i64,
}

pub(crate) async fn issue(
    control: &Control,
    user_id: &str,
    role: &str,
    agent_key: &str,
    now: Moment,
) -> Result<DbClientCertificate, DenyReason> {
    if let Decision::Limited { .. } = control
        .db_client_user_issuance
        .check(&user_id.to_owned(), control.tick())
    {
        return Err(DenyReason::IssuanceLimited);
    }
    let Some(key) = node_keys::parse_tls(agent_key) else {
        return Err(DenyReason::InvalidAgentKey);
    };
    let Some(slot) = control.db_client() else {
        tracing::error!(
            target: "jaunt::control",
            "a database session was allowed but the db-client authority is not initialized: run jauntd ca init --add-missing"
        );
        return Err(DenyReason::AuthorityUnavailable);
    };
    signs_with_the_active_key(control, &slot).await?;
    let serial = control
        .store
        .certificates()
        .allocate_serial()
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "allocating a serial failed");
            DenyReason::AuthorityUnavailable
        })?;
    let serial_number = u64::try_from(serial).map_err(|_| {
        tracing::error!(target: "jaunt::control", "the serial counter is not positive");
        DenyReason::AuthorityUnavailable
    })?;
    let issued = slot
        .ca
        .issue_db_client_certificate(
            DbClientParams {
                subject_public_key: key.subject.clone(),
                role: role.to_owned(),
                serial: serial_number,
            },
            now.system,
        )
        .map_err(|err| match err {
            CaError::InvalidSubjectKey => DenyReason::InvalidAgentKey,
            other => {
                tracing::error!(target: "jaunt::control", error = %other, "signing the db-client certificate failed");
                DenyReason::AuthorityUnavailable
            }
        })?;
    let (Some(valid_after), Some(valid_before)) =
        (unix_secs(issued.not_before), unix_secs(issued.not_after))
    else {
        return Err(DenyReason::AuthorityUnavailable);
    };
    Ok(DbClientCertificate {
        certificate_der: issued.certificate_der,
        serial,
        valid_after,
        valid_before,
    })
}

async fn signs_with_the_active_key(control: &Control, slot: &ClientSlot) -> Result<(), DenyReason> {
    let ca_dir = control.ca_dir.clone();
    let on_disk =
        tokio::task::spawn_blocking(move || FileBackend::read_active(&ca_dir, CaKind::DbClient))
            .await;
    match on_disk {
        Ok(Ok(active)) if active == slot.trust.active().fingerprint(HashAlg::Sha256) => Ok(()),
        Ok(Ok(_)) => {
            tracing::error!(
                target: "jaunt::control",
                "the db-client key in memory is not the active key on disk: issuance waits for the next reload"
            );
            Err(DenyReason::AuthorityUnavailable)
        }
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading the active db-client key failed");
            Err(DenyReason::AuthorityUnavailable)
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "reading the active db-client key did not finish");
            Err(DenyReason::AuthorityUnavailable)
        }
    }
}
