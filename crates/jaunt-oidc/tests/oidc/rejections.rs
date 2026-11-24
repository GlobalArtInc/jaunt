use std::time::{Duration, SystemTime};

use jaunt_oidc::{ExchangeFailure, OidcClient, OidcError, Secret, TokenCheck};
use serde_json::json;

use crate::provider::{CLIENT_ID, FakeProvider, Signer, TokenSpec, now};

async fn rejected(spec: TokenSpec) -> (FakeProvider, OidcError) {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let err = provider.login(&client, spec).await.unwrap_err();
    (provider, err)
}

fn assert_check(err: OidcError, expected: TokenCheck) {
    match err {
        OidcError::TokenValidation(check) => assert_eq!(check, expected),
        other => panic!("expected token validation failure {expected:?}, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_issuer_is_rejected() {
    let spec = TokenSpec::default().set("iss", json!("https://evil.example.com"));
    assert_check(rejected(spec).await.1, TokenCheck::Issuer);
}

#[tokio::test(flavor = "multi_thread")]
async fn issuer_differing_only_by_trailing_slash_is_rejected() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let spec = TokenSpec::default().set("iss", json!(format!("{}/", provider.base)));
    let err = provider.login(&client, spec).await.unwrap_err();
    assert_check(err, TokenCheck::Issuer);
}

#[tokio::test(flavor = "multi_thread")]
async fn audience_without_this_client_is_rejected() {
    let spec = TokenSpec::default().set("aud", json!("another-client"));
    assert_check(rejected(spec).await.1, TokenCheck::Audience);
}

#[tokio::test(flavor = "multi_thread")]
async fn several_audiences_need_a_matching_authorized_party() {
    let audiences = json!([CLIENT_ID, "another-client"]);

    let missing = TokenSpec::default().set("aud", audiences.clone());
    assert_check(rejected(missing).await.1, TokenCheck::AuthorizedParty);

    let other = TokenSpec::default()
        .set("aud", audiences.clone())
        .set("azp", json!("another-client"));
    assert_check(rejected(other).await.1, TokenCheck::AuthorizedParty);

    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let matching = TokenSpec::default()
        .set("aud", audiences)
        .set("azp", json!(CLIENT_ID));
    provider.login(&client, matching).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_or_missing_nonce_is_rejected() {
    let wrong = TokenSpec::default().set("nonce", json!("replayed-nonce"));
    assert_check(rejected(wrong).await.1, TokenCheck::Nonce);

    let missing = TokenSpec::default().remove("nonce");
    assert_check(rejected(missing).await.1, TokenCheck::Nonce);
}

#[tokio::test(flavor = "multi_thread")]
async fn signature_from_a_foreign_key_is_rejected() {
    let spec = TokenSpec::default().signer(Signer::ForeignRsaWithKnownKid);
    assert_check(rejected(spec).await.1, TokenCheck::Signature);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_key_id_is_rejected_after_a_single_jwks_refetch() {
    let spec = TokenSpec::default().signer(Signer::RotatedRsa);
    let (provider, err) = rejected(spec).await;
    assert_check(err, TokenCheck::Signature);
    assert_eq!(provider.jwks_hits(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_is_enforced_with_a_sixty_second_tolerance() {
    let expired = TokenSpec::default().set("exp", json!(now() - 120));
    assert_check(rejected(expired).await.1, TokenCheck::Expired);

    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let within_tolerance = TokenSpec::default().set("exp", json!(now() - 30));
    provider.login(&client, within_tolerance).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn issue_time_in_the_future_is_rejected_beyond_sixty_seconds() {
    let future = TokenSpec::default().set("iat", json!(now() + 120));
    assert_check(rejected(future).await.1, TokenCheck::IssuedInFuture);

    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let within_tolerance = TokenSpec::default().set("iat", json!(now() + 30));
    provider.login(&client, within_tolerance).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn token_signed_with_the_client_secret_is_rejected() {
    let spec = TokenSpec::default().signer(Signer::Hs256WithClientSecret);
    assert_check(rejected(spec).await.1, TokenCheck::Algorithm);
}

#[tokio::test(flavor = "multi_thread")]
async fn unsigned_token_is_rejected() {
    let spec = TokenSpec::default().signer(Signer::Unsigned);
    assert_check(rejected(spec).await.1, TokenCheck::Algorithm);
}

#[tokio::test(flavor = "multi_thread")]
async fn state_mismatch_is_rejected_before_any_exchange() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let pending = client.begin();
    let code = provider.grant(&pending, TokenSpec::default());

    let err = client
        .complete(pending, &code, "forged-state")
        .await
        .unwrap_err();

    assert!(matches!(err, OidcError::StateMismatch));
    assert_eq!(provider.token_hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn state_that_is_a_prefix_of_the_expected_value_is_rejected() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let pending = client.begin();
    let code = provider.grant(&pending, TokenSpec::default());
    let prefix = pending.state[..pending.state.len() - 1].to_owned();

    let err = client.complete(pending, &code, &prefix).await.unwrap_err();

    assert!(matches!(err, OidcError::StateMismatch));
    assert_eq!(provider.token_hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_returned_state_is_rejected() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let pending = client.begin();
    let code = provider.grant(&pending, TokenSpec::default());

    let err = client.complete(pending, &code, "").await.unwrap_err();

    assert!(matches!(err, OidcError::StateMismatch));
    assert_eq!(provider.token_hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_expected_state_is_rejected_even_when_the_returned_state_is_empty() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let mut pending = client.begin();
    let code = provider.grant(&pending, TokenSpec::default());
    pending.state = String::new();

    let err = client.complete(pending, &code, "").await.unwrap_err();

    assert!(matches!(err, OidcError::StateMismatch));
    assert_eq!(provider.token_hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_auth_without_nonce_or_verifier_is_rejected() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let mut no_nonce = client.begin();
    let code = provider.grant(&no_nonce, TokenSpec::default());
    no_nonce.nonce = Secret::new("");
    let state = no_nonce.state.clone();
    let err = client.complete(no_nonce, &code, &state).await.unwrap_err();
    assert!(matches!(
        err,
        OidcError::Exchange(ExchangeFailure::InvalidPendingAuth)
    ));

    let mut no_verifier = client.begin();
    let code = provider.grant(&no_verifier, TokenSpec::default());
    no_verifier.pkce_verifier = Secret::new("");
    let state = no_verifier.state.clone();
    let err = client
        .complete(no_verifier, &code, &state)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        OidcError::Exchange(ExchangeFailure::InvalidPendingAuth)
    ));
    assert_eq!(provider.token_hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_pending_auth_is_rejected_before_any_exchange() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let mut stale = client.begin();
    let code = provider.grant(&stale, TokenSpec::default());
    stale.created_at = SystemTime::now() - Duration::from_secs(601);
    let state = stale.state.clone();
    let err = client.complete(stale, &code, &state).await.unwrap_err();
    assert!(matches!(err, OidcError::PendingExpired));
    assert_eq!(provider.token_hits(), 0);

    let mut recent = client.begin();
    let code = provider.grant(&recent, TokenSpec::default());
    recent.created_at = SystemTime::now() - Duration::from_secs(590);
    let state = recent.state.clone();
    client.complete(recent, &code, &state).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_ttl_is_configurable() {
    let provider = FakeProvider::start().await;
    let mut config = provider.config();
    config.pending_ttl_secs = 5;
    let client = OidcClient::discover(config).await.unwrap();

    let mut pending = client.begin();
    let code = provider.grant(&pending, TokenSpec::default());
    pending.created_at = SystemTime::now() - Duration::from_secs(30);
    let state = pending.state.clone();
    let err = client.complete(pending, &code, &state).await.unwrap_err();

    assert!(matches!(err, OidcError::PendingExpired));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_authorization_code_is_an_exchange_failure() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let pending = client.begin();

    let state = pending.state.clone();
    let err = client
        .complete(pending, "never-issued", &state)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        OidcError::Exchange(ExchangeFailure::Rejected)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn unverified_email_is_rejected_when_verification_is_required() {
    for spec in [
        TokenSpec::default().set("email_verified", json!(false)),
        TokenSpec::default().remove("email_verified"),
    ] {
        assert!(matches!(
            rejected(spec).await.1,
            OidcError::EmailNotVerified
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unverified_email_is_allowed_when_verification_is_disabled() {
    let provider = FakeProvider::start().await;
    let mut config = provider.config();
    config.require_verified_email = false;
    let client = OidcClient::discover(config).await.unwrap();

    let spec = TokenSpec::default().set("email_verified", json!(false));
    let identity = provider.login(&client, spec).await.unwrap();

    assert!(!identity.email_verified);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_email_is_rejected() {
    let spec = TokenSpec::default()
        .remove("email")
        .remove("email_verified");
    match rejected(spec).await.1 {
        OidcError::MissingClaim(claim) => assert_eq!(claim, "email"),
        other => panic!("expected a missing claim, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn groups_of_the_wrong_type_are_rejected() {
    for bad in [json!(7), json!([1, 2]), json!({ "admin": true })] {
        let spec = TokenSpec::default().set("groups", bad);
        match rejected(spec).await.1 {
            OidcError::InvalidClaim(claim) => assert_eq!(claim, "groups"),
            other => panic!("expected an invalid claim, got {other:?}"),
        }
    }
}

async fn assert_invalid_claim(spec: TokenSpec, expected: &str) {
    match rejected(spec).await.1 {
        OidcError::InvalidClaim(claim) => assert_eq!(claim, expected),
        other => panic!("expected an invalid {expected} claim, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_oversized_or_control_character_values_are_rejected() {
    let oversized = "x".repeat(257);
    let too_many_groups: Vec<String> = (0..257).map(|n| format!("g{n}")).collect();
    let cases = [
        ("groups", json!([""])),
        ("groups", json!("")),
        ("groups", json!(["dev", "ops\nadmin"])),
        ("groups", json!([oversized.clone()])),
        ("groups", json!(too_many_groups)),
        ("preferred_username", json!("")),
        ("preferred_username", json!("ali\u{7}ce")),
        ("preferred_username", json!(oversized)),
    ];
    for (claim, value) in cases {
        assert_invalid_claim(TokenSpec::default().set(claim, value), claim).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn values_at_the_size_limits_are_accepted() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let longest = "x".repeat(256);
    let most_groups: Vec<String> = (0..256).map(|n| format!("g{n}")).collect();

    let spec = TokenSpec::default()
        .set("preferred_username", json!(longest))
        .set("groups", json!(most_groups));
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.username.len(), 256);
    assert_eq!(identity.groups.len(), 256);
}

#[tokio::test(flavor = "multi_thread")]
async fn email_must_contain_exactly_one_at_sign_with_both_parts() {
    for email in ["a@b@c", "@example.com", "alice@", "alice.example.com"] {
        assert_invalid_claim(TokenSpec::default().set("email", json!(email)), "email").await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn not_before_is_enforced_with_a_sixty_second_tolerance() {
    let future = TokenSpec::default().set("nbf", json!(now() + 120));
    assert_check(rejected(future).await.1, TokenCheck::NotYetValid);

    assert_invalid_claim(TokenSpec::default().set("nbf", json!("soon")), "nbf").await;

    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let within_tolerance = TokenSpec::default().set("nbf", json!(now() + 30));
    provider.login(&client, within_tolerance).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn jwks_refetch_happens_at_most_once_per_window() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    assert_eq!(provider.jwks_hits(), 1);

    let unknown_kid = || TokenSpec::default().signer(Signer::RotatedRsa);
    for _ in 0..3 {
        let err = provider.login(&client, unknown_kid()).await.unwrap_err();
        assert_check(err, TokenCheck::Signature);
    }
    assert_eq!(provider.jwks_hits(), 2);

    provider.publish_key("rsa2");
    let err = provider.login(&client, unknown_kid()).await.unwrap_err();
    assert_check(err, TokenCheck::Signature);
    assert_eq!(provider.jwks_hits(), 2);
}
