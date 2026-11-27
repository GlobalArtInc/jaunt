use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::ssh_key::HashAlg;
use jaunt_ca::{CaError, CaKind, ClientSlot, FileBackend, UserX509Params, Uuid, fingerprint_hex};
use jaunt_limits::{Decision, Rate, RateLimiter};
use jaunt_proto::{X509CertificateRequest, X509CertificateResponse};
use jaunt_store::{Certificate, NewCertificate, Parent, ValidApiToken};

use crate::cert_audit::{self, X509Issued};
use crate::clock::Moment;
use crate::control::Control;
use crate::device::net::ClientAddress;
use crate::finish::CERTIFICATE_KIND;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};
use crate::limits::too_many_requests;
use crate::node_keys::{self, TlsKey};
use crate::server_cert::{capped_validity, unix_secs};
use crate::whoami::authenticate;

pub(crate) const X509_KIND: &str = "x509";
pub(crate) const ISSUANCE_PER_USER: Rate = Rate::clamped(10, 10);
const USERS_TRACKED: usize = 10_000;

pub(crate) fn issuance_limiter() -> RateLimiter<String> {
    RateLimiter::new(ISSUANCE_PER_USER, USERS_TRACKED)
}

enum Refused {
    ParentNotValid,
    InvalidPublicKey,
    AuthorityChanged,
    Unavailable,
}

impl Refused {
    fn into_response(self) -> Response {
        match self {
            Refused::ParentNotValid => {
                let mut response = empty_response(StatusCode::UNAUTHORIZED);
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                response
            }
            Refused::InvalidPublicKey => {
                error_response(StatusCode::BAD_REQUEST, "invalid_public_key")
            }
            Refused::AuthorityChanged => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable")
            }
            Refused::Unavailable => server_error(),
        }
    }
}

pub(crate) async fn handle(
    State(control): State<Control>,
    client: Option<Extension<ClientAddress>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let valid = match authenticate(&control, &headers).await {
        Ok(valid) => valid,
        Err(failure) => return failure.into_response(),
    };
    if let Decision::Limited { retry_after } =
        control.x509_issuance.check(&valid.user.id, control.tick())
    {
        return too_many_requests(retry_after);
    }
    let request = match json_body::<X509CertificateRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let Some(key) = node_keys::parse_tls(&request.public_key) else {
        return Refused::InvalidPublicKey.into_response();
    };
    let Some(slot) = control.user_x509() else {
        return error_response(StatusCode::NOT_FOUND, "not_configured");
    };
    let client_addr = client.map(|Extension(ClientAddress(ip))| ip.to_string());
    let task = tokio::spawn(async move {
        match issue(&control, &valid, &slot, &key).await {
            Ok(response) => {
                cert_audit::x509_issued(&X509Issued {
                    user_id: &valid.user.id,
                    serial: response.serial,
                    parent_serial: response.parent_serial,
                    valid_before: response.valid_before,
                    client_addr: client_addr.as_deref(),
                });
                json_response(StatusCode::OK, &response)
            }
            Err(refused) => refused.into_response(),
        }
    });
    task.await.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the x509 certificate task did not finish");
        server_error()
    })
}

fn current_parent(parent: &Certificate, valid: &ValidApiToken, now: Moment) -> Result<(), Refused> {
    if parent.user_id != valid.user.id
        || parent.kind != CERTIFICATE_KIND
        || parent.parent_serial.is_some()
    {
        tracing::warn!(
            target: "jaunt::control",
            serial = parent.serial,
            "an api token is bound to a record that is not a user certificate of its user"
        );
        return Err(Refused::ParentNotValid);
    }
    if now.secs < parent.valid_after || now.secs >= parent.valid_before {
        return Err(Refused::ParentNotValid);
    }
    Ok(())
}

async fn issue(
    control: &Control,
    valid: &ValidApiToken,
    slot: &Arc<ClientSlot>,
    key: &TlsKey,
) -> Result<X509CertificateResponse, Refused> {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(Refused::Unavailable);
    };
    let certificates = control.store.certificates();
    let parent = certificates
        .get(valid.token.cert_serial)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "loading the parent certificate failed");
            Refused::Unavailable
        })?
        .ok_or_else(|| {
            tracing::error!(target: "jaunt::control", "an api token names a missing certificate");
            Refused::Unavailable
        })?;
    current_parent(&parent, valid, now)?;
    signs_with_the_active_key(control, slot).await?;
    let Some(root_end) = unix_secs(slot.ca.root_not_after()) else {
        return Err(Refused::Unavailable);
    };
    if root_end <= now.secs {
        tracing::error!(target: "jaunt::control", "the active user-x509 root has expired: run the rotation");
        return Err(Refused::Unavailable);
    }
    let validity =
        capped_validity(now.secs, parent.valid_before, root_end).ok_or(Refused::ParentNotValid)?;
    let user_id = Uuid::parse_str(&valid.user.id).map_err(|_| {
        tracing::error!(target: "jaunt::control", "a stored user id is not a uuid");
        Refused::Unavailable
    })?;
    let serial = certificates.allocate_serial().await.map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "allocating a serial failed");
        Refused::Unavailable
    })?;
    let serial_number = u64::try_from(serial).map_err(|_| {
        tracing::error!(target: "jaunt::control", "the serial counter is not positive");
        Refused::Unavailable
    })?;
    let valid_before = UNIX_EPOCH
        + Duration::from_secs(u64::try_from(now.secs).map_err(|_| Refused::Unavailable)?)
        + validity;
    let issued = slot
        .ca
        .issue_user_certificate(
            UserX509Params {
                subject_public_key: key.subject.clone(),
                user_id,
                email: valid.user.email.clone(),
                serial: serial_number,
                valid_before,
            },
            now.system,
        )
        .map_err(|err| match err {
            CaError::InvalidSubjectKey => Refused::InvalidPublicKey,
            other => {
                tracing::error!(target: "jaunt::control", error = %other, "signing the x509 certificate failed");
                Refused::Unavailable
            }
        })?;
    let (Some(not_before), Some(not_after)) =
        (unix_secs(issued.not_before), unix_secs(issued.not_after))
    else {
        return Err(Refused::Unavailable);
    };
    let recorded = certificates
        .record_child(
            &NewCertificate {
                serial,
                user_id: valid.user.id.clone(),
                kind: X509_KIND.to_owned(),
                key_id: issued.sha256_hex(),
                valid_after: not_before,
                valid_before: not_after,
                issued_at: now.secs,
                ca_fingerprint: Some(fingerprint_hex(slot.trust.active())),
                host_trust_id: None,
                subject_fingerprint: Some(fingerprint_hex(&key.subject.to_ssh_key())),
            },
            Parent {
                serial: parent.serial,
                kind: CERTIFICATE_KIND,
            },
        )
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "recording the x509 certificate failed");
            Refused::Unavailable
        })?;
    if !recorded {
        return Err(Refused::ParentNotValid);
    }
    Ok(X509CertificateResponse {
        certificate_der: STANDARD.encode(&issued.certificate_der),
        serial,
        parent_serial: parent.serial,
        valid_after: not_before,
        valid_before: not_after,
    })
}

async fn signs_with_the_active_key(control: &Control, slot: &ClientSlot) -> Result<(), Refused> {
    let ca_dir = control.ca_dir.clone();
    let on_disk =
        tokio::task::spawn_blocking(move || FileBackend::read_active(&ca_dir, CaKind::UserX509))
            .await;
    match on_disk {
        Ok(Ok(active)) if active == slot.trust.active().fingerprint(HashAlg::Sha256) => Ok(()),
        Ok(Ok(_)) => {
            tracing::error!(
                target: "jaunt::control",
                "the user-x509 key in memory is not the active key on disk: issuance waits for the next reload"
            );
            Err(Refused::AuthorityChanged)
        }
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading the active user-x509 key failed");
            Err(Refused::AuthorityChanged)
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "reading the active user-x509 key did not finish");
            Err(Refused::AuthorityChanged)
        }
    }
}
