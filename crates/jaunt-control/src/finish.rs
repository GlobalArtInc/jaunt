use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_ca::ssh_key::{Algorithm, PublicKey};
use jaunt_ca::{UserCertParams, Uuid, sign_user_certificate};
use jaunt_proto::{FinishRequest, FinishResponse};
use jaunt_store::{LoginRequestState, NewApiToken, NewCertificate};

use crate::audit::{self, FinishReason};
use crate::completion;
use crate::control::Control;
use crate::http::{BodyFailure, error_response, json_body, json_response, server_error};
use crate::pkce;
use crate::start::LOGIN_KIND;
use crate::token;

const MAX_PUBLIC_KEY_LEN: usize = 1024;
const CERTIFICATE_KIND: &str = "user";

enum Outcome {
    InvalidRequest,
    PayloadTooLarge,
    InvalidGrant,
    ServerError,
}

struct Failure {
    outcome: Outcome,
    reason: FinishReason,
    login_id: Option<String>,
    user_id: Option<String>,
}

impl Failure {
    fn new(outcome: Outcome, reason: FinishReason) -> Failure {
        Failure {
            outcome,
            reason,
            login_id: None,
            user_id: None,
        }
    }

    fn grant(reason: FinishReason) -> Failure {
        Failure::new(Outcome::InvalidGrant, reason)
    }

    fn internal(reason: FinishReason) -> Failure {
        Failure::new(Outcome::ServerError, reason)
    }

    fn for_login(mut self, login_id: &str) -> Failure {
        self.login_id = Some(login_id.to_owned());
        self
    }

    fn for_user(mut self, user_id: &str) -> Failure {
        self.user_id = Some(user_id.to_owned());
        self
    }

    fn into_response(self) -> Response {
        match self.outcome {
            Outcome::InvalidRequest => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
            Outcome::PayloadTooLarge => {
                error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
            }
            Outcome::InvalidGrant => error_response(StatusCode::BAD_REQUEST, "invalid_grant"),
            Outcome::ServerError => server_error(),
        }
    }
}

impl From<BodyFailure> for Failure {
    fn from(failure: BodyFailure) -> Failure {
        match failure {
            BodyFailure::TooLarge => {
                Failure::new(Outcome::PayloadTooLarge, FinishReason::BodyTooLarge)
            }
            BodyFailure::Malformed => {
                Failure::new(Outcome::InvalidRequest, FinishReason::Malformed)
            }
        }
    }
}

struct Issued {
    login_id: String,
    user_id: String,
    email: String,
    serial: i64,
    certificate: String,
    key_id: String,
    valid_after: i64,
    valid_before: i64,
    api_token: String,
}

pub(crate) async fn handle(
    State(control): State<Control>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let outcome = match json_body::<FinishRequest>(&headers, body) {
        Ok(request) => issue(&control, request).await,
        Err(failure) => Err(Failure::from(failure)),
    };
    match outcome {
        Ok(issued) => {
            audit::cert_issued(
                &issued.login_id,
                &issued.user_id,
                &issued.email,
                issued.serial,
            );
            json_response(
                StatusCode::OK,
                &FinishResponse {
                    certificate: issued.certificate,
                    serial: issued.serial,
                    key_id: issued.key_id,
                    valid_after: issued.valid_after,
                    valid_before: issued.valid_before,
                    api_token: issued.api_token,
                    token_expires_at: issued.valid_before,
                    user_id: issued.user_id,
                    email: issued.email,
                    host_ca_keys: control.host_ca_keys.clone(),
                },
            )
        }
        Err(failure) => {
            audit::finish_failed(
                failure.login_id.as_deref(),
                failure.user_id.as_deref(),
                failure.reason,
            );
            failure.into_response()
        }
    }
}

fn parse_public_key(text: &str) -> Option<PublicKey> {
    let text = text.trim_end_matches(['\r', '\n']);
    if text.len() > MAX_PUBLIC_KEY_LEN || text.chars().any(char::is_control) {
        return None;
    }
    let key = PublicKey::from_openssh(text).ok()?;
    if key.algorithm() != Algorithm::Ed25519 {
        return None;
    }
    Some(PublicKey::from(key.key_data().clone()))
}

fn canonical_login_id(text: &str) -> Option<String> {
    let parsed = Uuid::parse_str(text).ok()?;
    let canonical = parsed.hyphenated().to_string();
    (canonical == text).then_some(canonical)
}

async fn issue(control: &Control, request: FinishRequest) -> Result<Issued, Failure> {
    let well_formed = pkce::is_valid_verifier(&request.code_verifier);
    let login_id = match canonical_login_id(&request.login_id) {
        Some(login_id) if well_formed => login_id,
        _ => return Err(Failure::from(BodyFailure::Malformed)),
    };
    let now = control.now().ok_or_else(|| {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        Failure::internal(FinishReason::Clock).for_login(&login_id)
    })?;

    let requests = control.store.login_requests();
    let stored = requests
        .get(&login_id)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "loading the login request failed");
            Failure::internal(FinishReason::Store).for_login(&login_id)
        })?
        .ok_or_else(|| Failure::grant(FinishReason::UnknownRequest).for_login(&login_id))?;

    let denied = |reason| Failure::grant(reason).for_login(&login_id);
    if stored.kind != LOGIN_KIND {
        return Err(denied(FinishReason::WrongKind));
    }
    if stored.state != LoginRequestState::Approved {
        return Err(denied(FinishReason::NotApproved));
    }
    if stored.expires_at <= now.secs {
        return Err(denied(FinishReason::Expired));
    }
    let Some(completion_hash) = stored.completion_hash.as_deref() else {
        tracing::error!(target: "jaunt::control", "an approved loopback login request has no completion hash");
        return Err(Failure::internal(FinishReason::CorruptRecord).for_login(&login_id));
    };
    let verifier_ok = pkce::verifier_matches(&request.code_verifier, &stored.pkce_challenge);
    let completion_ok = completion::matches(request.completion_code.as_deref(), completion_hash);
    if !verifier_ok {
        return Err(denied(FinishReason::BadVerifier));
    }
    if !completion_ok {
        return Err(denied(FinishReason::BadCompletionCode));
    }
    let subject_key =
        parse_public_key(&request.public_key).ok_or_else(|| denied(FinishReason::BadPublicKey))?;
    let user_id = stored.user_id.clone().ok_or_else(|| {
        tracing::error!(target: "jaunt::control", "an approved login request has no user");
        Failure::internal(FinishReason::CorruptRecord).for_login(&login_id)
    })?;

    let failed = |failure: Failure| failure.for_login(&login_id).for_user(&user_id);
    let redeemed = requests
        .redeem(&login_id, now.secs)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "redeeming the login request failed");
            failed(Failure::internal(FinishReason::Store))
        })?;
    if redeemed.is_none() {
        return Err(failed(Failure::grant(FinishReason::LostRace)));
    }

    let user = control
        .store
        .users()
        .get(&user_id)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "loading the user failed");
            failed(Failure::internal(FinishReason::Store))
        })?
        .ok_or_else(|| {
            tracing::error!(target: "jaunt::control", "an approved login request names a missing user");
            failed(Failure::internal(FinishReason::CorruptRecord))
        })?;
    let user_uuid = Uuid::parse_str(&user.id).map_err(|_| {
        tracing::error!(target: "jaunt::control", "a stored user id is not a uuid");
        failed(Failure::internal(FinishReason::CorruptRecord))
    })?;

    let certificates = control.store.certificates();
    let serial = certificates.allocate_serial().await.map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "allocating a serial failed");
        failed(Failure::internal(FinishReason::Store))
    })?;
    let serial_number = u64::try_from(serial).map_err(|_| {
        tracing::error!(target: "jaunt::control", "the serial counter is not positive");
        failed(Failure::internal(FinishReason::CorruptRecord))
    })?;

    let certificate = sign_user_certificate(
        control.user_authority.as_ref(),
        UserCertParams {
            subject_public_key: subject_key,
            user_id: user_uuid,
            email: user.email.clone(),
            serial: serial_number,
            validity: control.cert_ttl,
        },
        now.system,
    )
    .map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "signing the user certificate failed");
        failed(Failure::internal(FinishReason::Signing))
    })?;
    let certificate_line = certificate.to_openssh().map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "encoding the user certificate failed");
        failed(Failure::internal(FinishReason::Signing))
    })?;
    let valid_after = i64::try_from(certificate.valid_after())
        .map_err(|_| failed(Failure::internal(FinishReason::Signing)))?;
    let valid_before = i64::try_from(certificate.valid_before())
        .map_err(|_| failed(Failure::internal(FinishReason::Signing)))?;

    certificates
        .record(&NewCertificate {
            serial,
            user_id: user.id.clone(),
            kind: CERTIFICATE_KIND.to_owned(),
            key_id: certificate.key_id().to_owned(),
            valid_after,
            valid_before,
            issued_at: now.secs,
        })
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "recording the certificate failed");
            failed(Failure::internal(FinishReason::Store))
        })?;

    let api_token = token::issue().map_err(|_| {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        failed(Failure::internal(FinishReason::Entropy))
    })?;
    control
        .store
        .api_tokens()
        .create(&NewApiToken {
            token_hash: api_token.hash,
            user_id: user.id.clone(),
            cert_serial: serial,
            created_at: now.secs,
            expires_at: valid_before,
        })
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "storing the api token failed");
            failed(Failure::internal(FinishReason::Store))
        })?;

    Ok(Issued {
        login_id,
        user_id: user.id,
        email: user.email,
        serial,
        certificate: certificate_line,
        key_id: certificate.key_id().to_owned(),
        valid_after,
        valid_before,
        api_token: api_token.secret,
    })
}
