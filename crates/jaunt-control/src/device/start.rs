use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::{DeviceStartRequest, DeviceStartResponse};
use jaunt_store::{LoginRequest, LoginRequests, NewDeviceLoginRequest, StoreError};

use crate::audit;
use crate::control::Control;
use crate::http::{error_response, json_body, json_response, server_error};
use crate::pkce;
use crate::start::{CHALLENGE_METHOD, LOGIN_TTL_SECS, busy, is_valid_label};
use crate::token::EntropyUnavailable;

use super::net::ClientAddress;
use super::{EXPIRES_IN_SECS, POLL_INTERVAL_SECS, code};

const MAX_CODE_ATTEMPTS: usize = 5;

#[derive(Debug)]
pub(super) enum CreateFailure {
    Store(StoreError),
    Entropy,
    Exhausted,
}

pub(super) async fn create_with_unique_code(
    requests: &LoginRequests,
    template: &NewDeviceLoginRequest,
    next_code: &mut impl FnMut() -> Result<String, EntropyUnavailable>,
    now: i64,
) -> Result<(LoginRequest, String), CreateFailure> {
    for _ in 0..MAX_CODE_ATTEMPTS {
        let user_code = next_code().map_err(|_| CreateFailure::Entropy)?;
        let candidate = NewDeviceLoginRequest {
            user_code_hash: code::hash(&user_code),
            ..template.clone()
        };
        let created = requests
            .create_device(&candidate, now)
            .await
            .map_err(CreateFailure::Store)?;
        if let Some(request) = created {
            return Ok((request, user_code));
        }
    }
    Err(CreateFailure::Exhausted)
}

fn is_valid_request(request: &DeviceStartRequest) -> bool {
    request.code_challenge_method == CHALLENGE_METHOD
        && pkce::is_valid_challenge(&request.code_challenge)
        && request.client_label.as_deref().is_none_or(is_valid_label)
}

pub(super) async fn handle(
    State(control): State<Control>,
    Extension(ClientAddress(ip)): Extension<ClientAddress>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request = match json_body::<DeviceStartRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if !is_valid_request(&request) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };

    let requests = control.store.login_requests();
    match requests.count_live_device(now.secs).await {
        Ok(live) if usize::try_from(live).is_ok_and(|live| live < control.device.capacity) => {}
        Ok(_) => return busy(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "counting device requests failed");
            return server_error();
        }
    }

    let template = NewDeviceLoginRequest {
        pkce_challenge: request.code_challenge,
        client_label: request.client_label,
        user_code_hash: String::new(),
        requester_ip: ip.to_string(),
        ttl_secs: LOGIN_TTL_SECS,
    };
    let created =
        create_with_unique_code(&requests, &template, &mut code::generate, now.secs).await;
    let (stored, user_code) = match created {
        Ok(created) => created,
        Err(CreateFailure::Store(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "creating the device request failed");
            return server_error();
        }
        Err(CreateFailure::Entropy) => {
            tracing::error!(target: "jaunt::control", "the system entropy source failed");
            return server_error();
        }
        Err(CreateFailure::Exhausted) => {
            tracing::error!(target: "jaunt::control", "no unused device code was found");
            return server_error();
        }
    };

    audit::device_started(&stored.id, ip);
    json_response(
        StatusCode::OK,
        &DeviceStartResponse {
            login_id: stored.id,
            user_code: code::display(&user_code),
            verification_url: control.device.verification_url(),
            expires_in: EXPIRES_IN_SECS,
            interval: POLL_INTERVAL_SECS,
        },
    )
}

#[cfg(test)]
mod tests {
    use jaunt_store::{NewDeviceLoginRequest, Store};

    use crate::token::EntropyUnavailable;

    use super::{CreateFailure, code, create_with_unique_code};

    const NOW: i64 = 1_000;

    fn template() -> NewDeviceLoginRequest {
        NewDeviceLoginRequest {
            pkce_challenge: "challenge".to_owned(),
            client_label: None,
            user_code_hash: String::new(),
            requester_ip: "203.0.113.9".to_owned(),
            ttl_secs: 300,
        }
    }

    async fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        (dir, store)
    }

    fn scripted(codes: &[&str]) -> impl FnMut() -> Result<String, EntropyUnavailable> {
        let mut remaining: Vec<String> = codes.iter().rev().map(|c| (*c).to_owned()).collect();
        move || remaining.pop().ok_or(EntropyUnavailable)
    }

    #[tokio::test]
    async fn a_code_already_held_by_a_pending_request_is_replaced_by_a_fresh_one() {
        let (_dir, store) = store().await;
        let requests = store.login_requests();
        let (first, first_code) =
            create_with_unique_code(&requests, &template(), &mut scripted(&["AAAAAAAA"]), NOW)
                .await
                .unwrap();

        let (second, second_code) = create_with_unique_code(
            &requests,
            &template(),
            &mut scripted(&["AAAAAAAA", "AAAAAAAA", "BBBBBBBB"]),
            NOW,
        )
        .await
        .unwrap();

        assert_eq!(first_code, "AAAAAAAA");
        assert_eq!(second_code, "BBBBBBBB");
        assert_ne!(first.user_code_hash, second.user_code_hash);
        assert_eq!(second.user_code_hash, Some(code::hash("BBBBBBBB")));
        assert_eq!(requests.count_live_device(NOW).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn giving_up_after_five_collisions_stores_nothing_more() {
        let (_dir, store) = store().await;
        let requests = store.login_requests();
        create_with_unique_code(&requests, &template(), &mut scripted(&["AAAAAAAA"]), NOW)
            .await
            .unwrap();

        let mut calls = 0;
        let mut always_taken = || {
            calls += 1;
            Ok("AAAAAAAA".to_owned())
        };
        let outcome = create_with_unique_code(&requests, &template(), &mut always_taken, NOW).await;

        assert!(matches!(outcome, Err(CreateFailure::Exhausted)));
        assert_eq!(calls, 5);
        assert_eq!(requests.count_live_device(NOW).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn an_entropy_failure_is_reported_and_nothing_is_stored() {
        let (_dir, store) = store().await;
        let requests = store.login_requests();

        let outcome =
            create_with_unique_code(&requests, &template(), &mut scripted(&[]), NOW).await;

        assert!(matches!(outcome, Err(CreateFailure::Entropy)));
        assert_eq!(requests.count_live_device(NOW).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn only_the_hash_of_the_code_is_stored() {
        let (_dir, store) = store().await;
        let requests = store.login_requests();

        let (stored, plain) =
            create_with_unique_code(&requests, &template(), &mut scripted(&["WXYZ2345"]), NOW)
                .await
                .unwrap();

        let reread = requests.get(&stored.id).await.unwrap().unwrap();
        assert_eq!(reread.user_code_hash, Some(code::hash(&plain)));
        let shown = format!("{reread:?}");
        assert!(!shown.contains(&plain), "{shown}");
    }
}
