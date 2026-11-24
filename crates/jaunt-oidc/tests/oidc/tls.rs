use jaunt_oidc::{DiscoveryFailure, OidcClient, OidcError};
use serde_json::json;

use crate::provider::{FakeProvider, TokenSpec};

#[tokio::test(flavor = "multi_thread")]
async fn login_works_over_tls_with_a_configured_root_certificate() {
    let provider = FakeProvider::start_tls().await;
    let client = provider.client().await;

    let identity = provider.login(&client, TokenSpec::default()).await.unwrap();

    assert_eq!(identity.issuer, provider.base);
    assert_eq!(identity.username, "alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_over_tls_fails_without_the_root_certificate() {
    let provider = FakeProvider::start_tls().await;

    let err = OidcClient::discover(provider.config_without_root())
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        OidcError::Discovery(DiscoveryFailure::Request)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unrelated_root_certificate_does_not_make_the_provider_trusted() {
    let provider = FakeProvider::start_tls().await;
    let other = FakeProvider::start_tls().await;
    let mut config = provider.config_without_root();
    config.extra_root_certificates_pem = vec![other.root_certificate_pem()];

    let err = OidcClient::discover(config).await.unwrap_err();

    assert!(matches!(
        err,
        OidcError::Discovery(DiscoveryFailure::Request)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn https_issuer_rejects_plain_http_metadata_endpoints_before_any_request() {
    let plain = FakeProvider::start().await;
    for field in [
        "jwks_uri",
        "token_endpoint",
        "authorization_endpoint",
        "userinfo_endpoint",
    ] {
        let provider = FakeProvider::start_tls().await;
        provider.set_metadata(field, json!(format!("{}/endpoint", plain.base)));

        let err = OidcClient::discover(provider.config()).await.unwrap_err();

        match err {
            OidcError::InsecureUrl { field: reported } => assert_eq!(reported, field),
            other => panic!("expected an insecure {field}, got {other:?}"),
        }
        assert_eq!(provider.jwks_hits(), 0);
    }
    assert_eq!(plain.jwks_hits(), 0);
    assert_eq!(plain.token_hits(), 0);
    assert_eq!(plain.userinfo_hits(), 0);
}
