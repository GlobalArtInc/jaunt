use jaunt_oidc::{ClientSecret, ExchangeFailure, OidcError, OidcIdentity, Secret, UserInfoFailure};
use serde_json::json;

use crate::provider::{CLIENT_SECRET, FakeProvider, Signer, TokenSpec};

#[tokio::test(flavor = "multi_thread")]
async fn successful_login_maps_claims() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let identity = provider.login(&client, TokenSpec::default()).await.unwrap();

    assert_eq!(
        identity,
        OidcIdentity {
            issuer: provider.base.clone(),
            subject: "user-1".to_owned(),
            email: "alice@example.com".to_owned(),
            email_verified: true,
            username: "alice".to_owned(),
            groups: vec!["dev".to_owned(), "ops".to_owned()],
            display_name: Some("Alice Example".to_owned()),
        }
    );
    assert_eq!(provider.token_hits(), 1);
    assert_eq!(provider.userinfo_hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn rs256_es256_and_eddsa_signatures_are_accepted() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    for signer in [Signer::Rsa, Signer::Ec, Signer::Ed] {
        let spec = TokenSpec::default().signer(signer);
        let identity = provider.login(&client, spec).await.unwrap();
        assert_eq!(identity.subject, "user-1");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn groups_claim_accepts_a_single_string() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let spec = TokenSpec::default().set("groups", json!("platform"));
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.groups, vec!["platform".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_groups_give_an_empty_list() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let identity = provider
        .login(&client, TokenSpec::default().remove("groups"))
        .await
        .unwrap();

    assert!(identity.groups.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn username_falls_back_to_the_email_local_part() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let spec = TokenSpec::default().remove("preferred_username");
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.username, "alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_claim_names_are_used() {
    let provider = FakeProvider::start().await;
    let mut config = provider.config();
    config.username_claim = "upn".to_owned();
    config.groups_claim = "roles".to_owned();
    let client = jaunt_oidc::OidcClient::discover(config).await.unwrap();

    let spec = TokenSpec::default()
        .set("upn", json!("alice.example"))
        .set("roles", json!(["admins"]));
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.username, "alice.example");
    assert_eq!(identity.groups, vec!["admins".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn userinfo_supplies_only_the_claims_missing_from_the_id_token() {
    let provider = FakeProvider::start().await;
    provider.enable_userinfo(json!({
        "sub": "user-1",
        "preferred_username": "mallory",
        "groups": ["from-userinfo"],
    }));
    let client = provider.client().await;

    let spec = TokenSpec::default().remove("groups");
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.username, "alice");
    assert_eq!(identity.groups, vec!["from-userinfo".to_owned()]);
    assert_eq!(provider.userinfo_hits(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn userinfo_can_supply_the_email() {
    let provider = FakeProvider::start().await;
    provider.enable_userinfo(json!({
        "sub": "user-1",
        "email": "bob@example.com",
        "email_verified": true,
    }));
    let client = provider.client().await;

    let spec = TokenSpec::default()
        .remove("email")
        .remove("email_verified");
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.email, "bob@example.com");
    assert!(identity.email_verified);
}

#[tokio::test(flavor = "multi_thread")]
async fn userinfo_for_another_subject_is_rejected() {
    let provider = FakeProvider::start().await;
    provider.enable_userinfo(json!({ "sub": "someone-else", "groups": ["root"] }));
    let client = provider.client().await;

    let err = provider
        .login(&client, TokenSpec::default().remove("groups"))
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        OidcError::UserInfo(UserInfoFailure::SubjectMismatch)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn userinfo_verification_flag_is_bound_to_the_id_token_email() {
    let provider = FakeProvider::start().await;
    provider.enable_userinfo(json!({
        "sub": "user-1",
        "email": "someone-else@example.com",
        "email_verified": true,
    }));
    let client = provider.client().await;

    let err = provider
        .login(&client, TokenSpec::default().remove("email_verified"))
        .await
        .unwrap_err();

    assert!(matches!(err, OidcError::EmailNotVerified));
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_signing_key_triggers_one_jwks_refetch() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    assert_eq!(provider.jwks_hits(), 1);

    provider.publish_key("rsa2");
    let spec = TokenSpec::default().signer(Signer::RotatedRsa);
    let identity = provider.login(&client, spec).await.unwrap();

    assert_eq!(identity.subject, "user-1");
    assert_eq!(provider.jwks_hits(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_secret_post_is_used_when_basic_is_not_offered() {
    let provider = FakeProvider::start().await;
    provider.set_metadata(
        "token_endpoint_auth_methods_supported",
        json!(["client_secret_post"]),
    );
    let client = provider.client().await;

    provider.login(&client, TokenSpec::default()).await.unwrap();

    assert_eq!(provider.last_auth_method(), Some("post"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exchange_with_a_wrong_pkce_verifier_is_rejected_without_leaking_values() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;
    let mut pending = client.begin();
    let code = provider.grant(&pending, TokenSpec::default());
    pending.pkce_verifier = Secret::new("not-the-verifier-from-begin");
    let state = pending.state.clone();
    let nonce = pending.nonce.expose().to_owned();

    let err = client.complete(pending, &code, &state).await.unwrap_err();

    assert!(matches!(
        err,
        OidcError::Exchange(ExchangeFailure::Rejected)
    ));
    let rendered = format!("{err} {err:?}");
    for secret in [
        code.as_str(),
        CLIENT_SECRET,
        state.as_str(),
        nonce.as_str(),
        "not-the-verifier-from-begin",
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn string_email_verified_values_are_interpreted() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let verified = TokenSpec::default().set("email_verified", json!("true"));
    let identity = provider.login(&client, verified).await.unwrap();
    assert!(identity.email_verified);

    let unverified = TokenSpec::default().set("email_verified", json!("false"));
    let err = provider.login(&client, unverified).await.unwrap_err();
    assert!(matches!(err, OidcError::EmailNotVerified));
}

#[tokio::test(flavor = "multi_thread")]
async fn userinfo_cannot_override_an_unverified_email_from_the_id_token() {
    let provider = FakeProvider::start().await;
    provider.enable_userinfo(json!({
        "sub": "user-1",
        "email": "alice@example.com",
        "email_verified": true,
        "groups": ["from-userinfo"],
    }));
    let client = provider.client().await;

    let spec = TokenSpec::default()
        .set("email_verified", json!(false))
        .remove("groups");
    let err = provider.login(&client, spec).await.unwrap_err();

    assert!(matches!(err, OidcError::EmailNotVerified));
    assert_eq!(provider.userinfo_hits(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_endpoint_redirects_are_not_followed() {
    let provider = FakeProvider::start().await;
    let elsewhere = FakeProvider::start().await;
    provider.redirect_token_endpoint_to(format!("{}/token", elsewhere.base));
    let client = provider.client().await;

    let err = provider
        .login(&client, TokenSpec::default())
        .await
        .unwrap_err();

    assert!(matches!(err, OidcError::Exchange(_)), "{err:?}");
    assert_eq!(provider.token_hits(), 1);
    assert_eq!(elsewhere.token_hits(), 0);
}

#[test]
fn public_types_are_thread_safe_and_pending_auth_is_single_use() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<jaunt_oidc::OidcClient>();
    assert_send_sync::<jaunt_oidc::PendingAuth>();
    assert_send_sync::<ClientSecret>();

    trait NotClone<Marker> {
        fn assert_not_clone() {}
    }
    impl<T: ?Sized> NotClone<()> for T {}
    impl<T: Clone> NotClone<u8> for T {}
    <jaunt_oidc::PendingAuth as NotClone<_>>::assert_not_clone();
}
