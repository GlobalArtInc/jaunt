use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::router;
use crate::settings::User;
use crate::state::{Settings, State};

const ISSUER: &str = "https://idp.example.test";
const CLIENT: &str = "client-one";
const SECRET: &str = "secret-one";
const REDIRECT: &str = "https://app.example.test/callback";
const VERIFIER: &str = "verifier-value-with-enough-length-0123456789";

fn user(hint: &str, subject: &str) -> User {
    User {
        login_hint: hint.to_owned(),
        subject: subject.to_owned(),
        email: format!("{hint}@example.test"),
        username: hint.to_owned(),
        name: hint.to_uppercase(),
        groups: vec!["g1".to_owned()],
        email_verified: true,
    }
}

fn app_with_ttl(session_ttl: Duration) -> (Router, Arc<State>) {
    let state = Arc::new(State::new(Settings {
        issuer: ISSUER.to_owned(),
        client_id: CLIENT.to_owned(),
        client_secret: SECRET.to_owned(),
        redirect_uris: vec![REDIRECT.to_owned()],
        users: vec![user("alice", "sub-alice"), user("bob", "sub-bob")],
        session_ttl,
    }));
    (router(state.clone()), state)
}

fn app() -> (Router, Arc<State>) {
    app_with_ttl(Duration::from_secs(3600))
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn authorize_query(extra: &[(&str, &str)]) -> String {
    let challenge = challenge();
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", CLIENT),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", "state-1"),
        ("nonce", "nonce-1"),
    ];
    pairs.extend_from_slice(extra);
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

struct Answer {
    status: StatusCode,
    location: Option<String>,
    cookie: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn location_param(&self, name: &str) -> Option<String> {
        let location = self.location.as_deref()?;
        let (_, query) = location.split_once('?')?;
        form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let header_text = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let location = header_text(header::LOCATION);
    let cookie = header_text(header::SET_COOKIE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        location,
        cookie,
        body: body.to_vec(),
    }
}

async fn authorize(app: &Router, extra: &[(&str, &str)], cookie: Option<&str>) -> Answer {
    let mut request = Request::get(format!("/authorize?{}", authorize_query(extra)));
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

fn token_form(code: &str, verifier: &str, redirect: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("code_verifier", verifier)
        .append_pair("redirect_uri", redirect)
        .append_pair("client_id", CLIENT)
        .append_pair("client_secret", SECRET);
    serializer.finish()
}

async fn exchange(app: &Router, body: String) -> Answer {
    let request = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    send(app, request).await
}

async fn code_for(app: &Router, hint: &str) -> String {
    let answer = authorize(app, &[("login_hint", hint)], None).await;
    assert_eq!(answer.status, StatusCode::FOUND);
    answer.location_param("code").unwrap()
}

#[tokio::test]
async fn discovery_names_the_endpoints_under_the_issuer() {
    let (app, _) = app();
    let answer = send(
        &app,
        Request::get("/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let document = answer.json();
    assert_eq!(document["issuer"], ISSUER);
    assert_eq!(
        document["authorization_endpoint"],
        format!("{ISSUER}/authorize")
    );
    assert_eq!(document["token_endpoint"], format!("{ISSUER}/token"));
}

#[tokio::test]
async fn an_unknown_client_is_refused_without_a_redirect() {
    let (app, _) = app();
    let answer = authorize(
        &app,
        &[("client_id", "other"), ("login_hint", "alice")],
        None,
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert!(answer.location.is_none());
}

#[tokio::test]
async fn the_redirect_uri_must_match_a_registered_one_exactly() {
    let (app, _) = app();
    for uri in [
        "https://app.example.test/callback/",
        "https://app.example.test/callback?x=1",
        "https://app.example.test/callbac",
        "http://app.example.test/callback",
        "https://evil.example.test/callback",
    ] {
        let answer = authorize(
            &app,
            &[("redirect_uri", uri), ("login_hint", "alice")],
            None,
        )
        .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(answer.location.is_none(), "{uri}");
    }
}

#[tokio::test]
async fn a_request_without_pkce_is_refused_with_the_state_echoed() {
    let (app, _) = app();
    let query = "response_type=code&client_id=client-one&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&state=s9&login_hint=alice";
    let answer = send(
        &app,
        Request::get(format!("/authorize?{query}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(answer.status, StatusCode::FOUND);
    assert_eq!(
        answer.location_param("error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(answer.location_param("state").as_deref(), Some("s9"));
}

#[tokio::test]
async fn an_unknown_login_hint_or_no_identity_at_all_is_not_signed_in() {
    let (app, _) = app();
    let unknown = authorize(&app, &[("login_hint", "mallory")], None).await;
    assert_eq!(
        unknown.location_param("error").as_deref(),
        Some("access_denied")
    );
    assert!(unknown.cookie.is_none());
    let anonymous = authorize(&app, &[], None).await;
    assert_eq!(
        anonymous.location_param("error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn a_session_from_an_earlier_hint_signs_the_same_user_in_again() {
    let (app, _) = app();
    let first = authorize(&app, &[("login_hint", "bob")], None).await;
    let cookie = first.cookie.unwrap();
    let pair = cookie.split(';').next().unwrap().to_owned();
    let second = authorize(&app, &[], Some(&pair)).await;
    let code = second.location_param("code").unwrap();
    let issued = exchange(&app, token_form(&code, VERIFIER, REDIRECT)).await;
    let claims = id_token_claims(&app, &issued).await;
    assert_eq!(claims["sub"], "sub-bob");
}

#[tokio::test]
async fn an_expired_session_no_longer_signs_anyone_in() {
    let (app, _) = app_with_ttl(Duration::ZERO);
    let first = authorize(&app, &[("login_hint", "alice")], None).await;
    let pair = first.cookie.unwrap().split(';').next().unwrap().to_owned();
    let later = authorize(&app, &[], Some(&pair)).await;
    assert_eq!(
        later.location_param("error").as_deref(),
        Some("login_required")
    );
}

async fn id_token_claims(app: &Router, issued: &Answer) -> Value {
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&issued.body)
    );
    let token = issued.json()["id_token"].as_str().unwrap().to_owned();
    let jwks = send(app, Request::get("/jwks").body(Body::empty()).unwrap())
        .await
        .json();
    let x = jwks["keys"][0]["x"].as_str().unwrap().to_owned();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[CLIENT]);
    validation.set_issuer(&[ISSUER]);
    let decoded = jsonwebtoken::decode::<Value>(
        &token,
        &DecodingKey::from_ed_components(&x).unwrap(),
        &validation,
    )
    .unwrap();
    decoded.claims
}

#[tokio::test]
async fn the_id_token_belongs_to_the_user_of_the_code_and_carries_the_nonce() {
    let (app, _) = app();
    let alice = exchange(
        &app,
        token_form(&code_for(&app, "alice").await, VERIFIER, REDIRECT),
    )
    .await;
    let claims = id_token_claims(&app, &alice).await;
    assert_eq!(claims["sub"], "sub-alice");
    assert_eq!(claims["email"], "alice@example.test");
    assert_eq!(claims["preferred_username"], "alice");
    assert_eq!(claims["nonce"], "nonce-1");
    assert_eq!(claims["groups"][0], "g1");
    let bob = exchange(
        &app,
        token_form(&code_for(&app, "bob").await, VERIFIER, REDIRECT),
    )
    .await;
    assert_eq!(id_token_claims(&app, &bob).await["sub"], "sub-bob");
}

#[tokio::test]
async fn the_code_verifier_must_match_the_challenge() {
    let (app, _) = app();
    let code = code_for(&app, "alice").await;
    let wrong = exchange(
        &app,
        token_form(&code, "another-verifier-value-0123456789abcdef", REDIRECT),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.json()["error"], "invalid_grant");
    let retried = exchange(&app, token_form(&code, VERIFIER, REDIRECT)).await;
    assert_eq!(retried.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn a_code_works_once_and_only_for_its_redirect_uri() {
    let (app, _) = app();
    let code = code_for(&app, "alice").await;
    let elsewhere = exchange(
        &app,
        token_form(&code, VERIFIER, "https://app.example.test/other"),
    )
    .await;
    assert_eq!(elsewhere.json()["error"], "invalid_grant");
    let code = code_for(&app, "alice").await;
    assert_eq!(
        exchange(&app, token_form(&code, VERIFIER, REDIRECT))
            .await
            .status,
        StatusCode::OK
    );
    let replay = exchange(&app, token_form(&code, VERIFIER, REDIRECT)).await;
    assert_eq!(replay.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn the_token_endpoint_authenticates_the_client() {
    let (app, _) = app();
    let code = code_for(&app, "alice").await;
    let body = token_form(&code, VERIFIER, REDIRECT).replace(SECRET, "wrong");
    let refused = exchange(&app, body).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.json()["error"], "invalid_client");
}
