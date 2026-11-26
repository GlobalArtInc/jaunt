use std::time::Duration;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::{EnrollRequest, EnrollResponse};
use jaunt_store::{CreateOutcome, EnrollmentLimits, NewEnrollment};

use crate::control::Control;
use crate::device::net::ClientAddress;
use crate::enroll_secrets;
use crate::http::{error_response, json_body, json_response, server_error};
use crate::join_enroll;
use crate::labels::Labels;
use crate::limits;
use crate::naming::is_dns_label;
use crate::node_audit::{self, EnrollRequested};
use crate::node_keys::{self, SshHostKey, TlsKey};
use crate::source_ip::source_of;

pub(crate) const ENROLLMENT_TTL_SECS: i64 = 900;
pub(crate) const POLL_INTERVAL_SECS: u32 = 3;
pub(crate) const MAX_PENDING_ENROLLMENTS: i64 = 1000;
pub(crate) const MAX_PENDING_PER_IP: i64 = 20;
const PENDING_RETRY_AFTER: Duration = Duration::from_secs(60);
const CODE_RETRIES: usize = 5;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_AGENT_VERSION_LEN: usize = 64;

const LIMITS: EnrollmentLimits = EnrollmentLimits {
    max_pending: MAX_PENDING_ENROLLMENTS,
    max_pending_per_ip: MAX_PENDING_PER_IP,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invalid {
    Name,
    Labels,
    Hostname,
    TlsPublicKey,
    SshHostPublicKey,
    AgentVersion,
}

impl Invalid {
    const fn code(self) -> &'static str {
        match self {
            Invalid::Name => "invalid_name",
            Invalid::Labels => "invalid_labels",
            Invalid::Hostname => "invalid_hostname",
            Invalid::TlsPublicKey => "invalid_tls_public_key",
            Invalid::SshHostPublicKey => "invalid_ssh_host_public_key",
            Invalid::AgentVersion => "invalid_agent_version",
        }
    }

    pub(crate) fn into_response(self) -> Response {
        error_response(StatusCode::BAD_REQUEST, self.code())
    }
}

pub(crate) struct ValidEnroll {
    pub(crate) name: String,
    pub(crate) labels: Labels,
    pub(crate) hostname: String,
    pub(crate) tls: TlsKey,
    pub(crate) ssh: SshHostKey,
    pub(crate) replace: bool,
    pub(crate) agent_version: String,
}

fn is_visible_ascii(text: &str) -> bool {
    text.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn validate(request: EnrollRequest) -> Result<ValidEnroll, Invalid> {
    if !is_dns_label(&request.name) {
        return Err(Invalid::Name);
    }
    let labels = Labels::new(request.labels).map_err(|_| Invalid::Labels)?;
    if request.hostname.is_empty()
        || request.hostname.len() > MAX_HOSTNAME_LEN
        || !is_visible_ascii(&request.hostname)
    {
        return Err(Invalid::Hostname);
    }
    let tls = node_keys::parse_tls(&request.tls_public_key).ok_or(Invalid::TlsPublicKey)?;
    let ssh =
        node_keys::parse_ssh(&request.ssh_host_public_key).ok_or(Invalid::SshHostPublicKey)?;
    if request.agent_version.len() > MAX_AGENT_VERSION_LEN
        || !is_visible_ascii(&request.agent_version)
    {
        return Err(Invalid::AgentVersion);
    }
    Ok(ValidEnroll {
        name: request.name,
        labels,
        hostname: request.hostname,
        tls,
        ssh,
        replace: request.replace,
        agent_version: request.agent_version,
    })
}

pub(crate) async fn handle(
    State(control): State<Control>,
    client: Option<Extension<ClientAddress>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(ClientAddress(client))) = client else {
        tracing::error!(target: "jaunt::control", "the peer address is not available");
        return server_error();
    };
    let source = source_of(client);
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let mut request = match json_body::<EnrollRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let join_token = request.join_token.take();
    let valid = match validate(request) {
        Ok(valid) => valid,
        Err(invalid) => return invalid.into_response(),
    };

    match control.store.nodes().get_active_by_name(&valid.name).await {
        Ok(Some(_)) if !valid.replace => return error_response(StatusCode::CONFLICT, "name_taken"),
        Ok(_) => {}
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "looking up the node name failed");
            return server_error();
        }
    }
    if let Some(presented) = join_token {
        return join_enroll::enroll(&control, &valid, &source, now, &presented).await;
    }

    let Ok(handle) = enroll_secrets::issue_handle() else {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        return server_error();
    };
    for _ in 0..=CODE_RETRIES {
        let Ok(code) = enroll_secrets::issue_code() else {
            tracing::error!(target: "jaunt::control", "the system entropy source failed");
            return server_error();
        };
        let created = control
            .store
            .enrollments()
            .create(
                &NewEnrollment {
                    handle_hash: handle.hash.clone(),
                    code_hash: code.hash,
                    name: valid.name.clone(),
                    labels: valid.labels.as_map().clone(),
                    hostname: valid.hostname.clone(),
                    source_ip: source.network.clone(),
                    peer_addr: source.address.clone(),
                    tls_public_key: valid.tls.canonical.clone(),
                    ssh_host_public_key: valid.ssh.canonical.clone(),
                    replace_existing: valid.replace,
                    agent_version: valid.agent_version.clone(),
                    ttl_secs: ENROLLMENT_TTL_SECS,
                },
                LIMITS,
                now.secs,
            )
            .await;
        match created {
            Ok(CreateOutcome::Created(enrollment)) => {
                node_audit::enroll_requested(&EnrollRequested {
                    enrollment_id: &enrollment.id,
                    name: &enrollment.name,
                    hostname: &enrollment.hostname,
                    source_ip: &enrollment.peer_addr,
                    source_network: &enrollment.source_ip,
                    agent_version: &enrollment.agent_version,
                    replace: enrollment.replace_existing,
                });
                return json_response(
                    StatusCode::OK,
                    &EnrollResponse {
                        handle: handle.secret,
                        code: Some(code.shown),
                        expires_at: enrollment.expires_at,
                        poll_interval: POLL_INTERVAL_SECS,
                    },
                );
            }
            Ok(CreateOutcome::TooManyPending | CreateOutcome::TooManyFromIp) => {
                return limits::too_many_requests(PENDING_RETRY_AFTER);
            }
            Ok(CreateOutcome::CodeCollision) => {}
            Err(err) => {
                tracing::error!(target: "jaunt::control", error = %err, "creating the enrollment failed");
                return server_error();
            }
        }
    }
    tracing::error!(target: "jaunt::control", "no unused enrollment code could be drawn");
    server_error()
}
