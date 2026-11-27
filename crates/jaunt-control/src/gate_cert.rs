use jaunt_ca::{CaError, SubjectPublicKey};
use jaunt_proto::{BoxFuture, GateTlsCertificate, GateTlsIssueError, GateTlsIssuer};

use crate::cert_audit;
use crate::control::Control;
use crate::server_cert::{self, ServerIssueError};

impl GateTlsIssuer for Control {
    fn issue<'a>(
        &'a self,
        subject_public_key_der: &'a [u8],
        server_name: &'a str,
    ) -> BoxFuture<'a, Result<GateTlsCertificate, GateTlsIssueError>> {
        Box::pin(issue(self, subject_public_key_der, server_name))
    }
}

async fn issue(
    control: &Control,
    subject_public_key_der: &[u8],
    server_name: &str,
) -> Result<GateTlsCertificate, GateTlsIssueError> {
    let Some(domain) = control.services_domain.clone() else {
        return Err(GateTlsIssueError::NotConfigured);
    };
    if server_name != domain.as_str() {
        tracing::warn!(
            target: "jaunt::control",
            "a gate certificate was requested for a name other than the services domain"
        );
        return Err(GateTlsIssueError::NameRefused);
    }
    let subject = SubjectPublicKey::from_spki_der(subject_public_key_der)
        .map_err(|_| GateTlsIssueError::InvalidKey)?;
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(GateTlsIssueError::Unavailable);
    };
    let owned = control.clone();
    let task = tokio::spawn(async move {
        let issued = server_cert::issue(&owned, &subject, domain.as_str(), now).await;
        if let Ok(issued) = &issued {
            cert_audit::gate_issued(issued.serial, issued.valid_before);
        }
        issued
    });
    let issued = match task.await {
        Ok(Ok(issued)) => issued,
        Ok(Err(ServerIssueError::Signing(CaError::InvalidSubjectKey))) => {
            return Err(GateTlsIssueError::InvalidKey);
        }
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "issuing the gate certificate failed");
            return Err(GateTlsIssueError::Unavailable);
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the gate certificate task did not finish");
            return Err(GateTlsIssueError::Unavailable);
        }
    };
    let time = |secs: i64| u64::try_from(secs).map_err(|_| GateTlsIssueError::Unavailable);
    Ok(GateTlsCertificate {
        serial: time(issued.serial)?,
        valid_after: time(issued.valid_after)?,
        valid_before: time(issued.valid_before)?,
        certificate_der: issued.certificate_der,
    })
}
