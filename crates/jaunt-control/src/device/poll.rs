use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::DevicePollRequest;
use jaunt_store::LoginRequestState;

use crate::audit::{self, FinishReason};
use crate::control::Control;
use crate::finish::{self, Failure, Issued};
use crate::http::{BodyFailure, error_response, json_body};
use crate::pkce;

use super::DEVICE_KIND;

const AUTHORIZATION_PENDING: &str = "authorization_pending";
const SLOW_DOWN: &str = "slow_down";
const ACCESS_DENIED: &str = "access_denied";
const EXPIRED_TOKEN: &str = "expired_token";

enum Stop {
    Answer(&'static str),
    Failed(Failure),
}

impl From<Failure> for Stop {
    fn from(failure: Failure) -> Stop {
        Stop::Failed(failure)
    }
}

pub(super) async fn handle(
    State(control): State<Control>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let outcome = match json_body::<DevicePollRequest>(&headers, body) {
        Ok(request) => poll(&control, request).await,
        Err(failure) => Err(Stop::Failed(Failure::from(failure))),
    };
    match outcome {
        Ok(issued) => finish::success_response(&control, issued),
        Err(Stop::Answer(code)) => error_response(StatusCode::BAD_REQUEST, code),
        Err(Stop::Failed(failure)) => finish::failure_response(failure),
    }
}

async fn poll(control: &Control, request: DevicePollRequest) -> Result<Issued, Stop> {
    let well_formed = pkce::is_valid_verifier(&request.code_verifier);
    let login_id = match finish::canonical_login_id(&request.login_id) {
        Some(login_id) if well_formed => login_id,
        _ => return Err(Failure::from(BodyFailure::Malformed).into()),
    };
    let now = control.now().ok_or_else(|| {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        Failure::internal(FinishReason::Clock).for_login(&login_id)
    })?;

    let stored = control
        .store
        .login_requests()
        .get(&login_id)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "loading the device request failed");
            Failure::internal(FinishReason::Store).for_login(&login_id)
        })?
        .ok_or_else(|| Failure::grant(FinishReason::UnknownRequest).for_login(&login_id))?;

    let refused = |reason| Failure::grant(reason).for_login(&login_id);
    if stored.kind != DEVICE_KIND {
        return Err(refused(FinishReason::WrongKind).into());
    }
    if !pkce::verifier_matches(&request.code_verifier, &stored.pkce_challenge) {
        return Err(refused(FinishReason::BadVerifier).into());
    }
    if !control
        .device
        .polls
        .admit(&login_id, now.secs, stored.expires_at)
    {
        return Err(Stop::Answer(SLOW_DOWN));
    }
    let expired = stored.expires_at <= now.secs;
    match (stored.state, expired) {
        (LoginRequestState::Redeemed, _) => return Err(refused(FinishReason::NotApproved).into()),
        (_, true) => {
            audit::finish_failed(Some(&login_id), None, FinishReason::Expired);
            return Err(Stop::Answer(EXPIRED_TOKEN));
        }
        (LoginRequestState::Pending, false) => return Err(Stop::Answer(AUTHORIZATION_PENDING)),
        (LoginRequestState::Denied, false) => return Err(Stop::Answer(ACCESS_DENIED)),
        (LoginRequestState::Approved, false) => {}
    }

    let subject_key = finish::parse_public_key(&request.public_key)
        .ok_or_else(|| refused(FinishReason::BadPublicKey))?;
    let user_id = stored.user_id.clone().ok_or_else(|| {
        tracing::error!(target: "jaunt::control", "an approved login request has no user");
        Failure::internal(FinishReason::CorruptRecord).for_login(&login_id)
    })?;

    let issued = finish::redeem_and_issue(control, login_id.clone(), user_id, subject_key, now)
        .await
        .map_err(Stop::Failed)?;
    control.device.polls.forget(&login_id);
    Ok(issued)
}
