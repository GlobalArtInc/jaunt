use std::collections::HashSet;

use jaunt_oidc::{ClientSecret, DiscoveryFailure, OidcClient, OidcConfig, OidcError};
use openidconnect::url::Url;
use serde_json::json;

use crate::provider::{CLIENT_SECRET, FakeProvider, REDIRECT_URL};

fn config(issuer: &str, redirect: &str) -> OidcConfig {
    OidcConfig::new(issuer, "client", ClientSecret::new(CLIENT_SECRET), redirect)
}

async fn discovery_error(provider: &FakeProvider) -> OidcError {
    OidcClient::discover(provider.config()).await.unwrap_err()
}

#[test]
fn defaults_follow_the_documented_values() {
    let config = config("https://idp.example.com", "https://gate.example.com/cb");

    assert_eq!(config.scopes, ["openid", "email", "profile", "groups"]);
    assert_eq!(config.username_claim, "preferred_username");
    assert_eq!(config.groups_claim, "groups");
    assert!(config.require_verified_email);
}

#[tokio::test]
async fn plain_http_is_rejected_for_non_loopback_hosts() {
    let cases = [
        (
            "http://idp.example.com",
            "https://gate.example.com/cb",
            "issuer_url",
        ),
        (
            "http://localhost.example.com",
            "https://gate.example.com/cb",
            "issuer_url",
        ),
        (
            "http://127.0.0.1.example.com",
            "https://gate.example.com/cb",
            "issuer_url",
        ),
        (
            "http://10.0.0.1",
            "https://gate.example.com/cb",
            "issuer_url",
        ),
        (
            "http://[2001:db8::1]",
            "https://gate.example.com/cb",
            "issuer_url",
        ),
        (
            "https://idp.example.com",
            "http://gate.example.com/cb",
            "redirect_url",
        ),
        (
            "https://idp.example.com",
            "http://10.0.0.1/cb",
            "redirect_url",
        ),
        (
            "https://idp.example.com",
            "http://[2001:db8::1]/cb",
            "redirect_url",
        ),
        (
            "ftp://idp.example.com",
            "https://gate.example.com/cb",
            "issuer_url",
        ),
    ];
    for (issuer, redirect, field) in cases {
        let err = OidcClient::discover(config(issuer, redirect))
            .await
            .unwrap_err();
        match err {
            OidcError::InsecureUrl { field: reported } => assert_eq!(reported, field),
            other => panic!("expected an insecure url for {issuer} / {redirect}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn loopback_hosts_pass_url_validation() {
    for issuer in ["http://localhost:1", "http://127.0.0.1:1", "http://[::1]:1"] {
        let err = OidcClient::discover(config(issuer, REDIRECT_URL))
            .await
            .unwrap_err();
        assert!(
            matches!(err, OidcError::Discovery(DiscoveryFailure::Request)),
            "{issuer}: {err:?}"
        );
    }
}

#[tokio::test]
async fn malformed_configuration_is_rejected() {
    let mut empty_client_id = config("https://idp.example.com", "https://gate.example.com/cb");
    empty_client_id.client_id = " ".to_owned();
    let mut bad_scope = config("https://idp.example.com", "https://gate.example.com/cb");
    bad_scope.scopes.push("two words".to_owned());
    let with_fragment = config(
        "https://idp.example.com",
        "https://gate.example.com/cb#frag",
    );
    let with_credentials = config(
        "https://user:pw@idp.example.com",
        "https://gate.example.com/cb",
    );

    for (broken, expect_insecure) in [
        (empty_client_id, false),
        (bad_scope, false),
        (with_fragment, false),
        (with_credentials, true),
    ] {
        let err = OidcClient::discover(broken).await.unwrap_err();
        assert_eq!(
            matches!(err, OidcError::InsecureUrl { .. }),
            expect_insecure,
            "{err:?}"
        );
        assert!(
            expect_insecure || matches!(err, OidcError::InvalidConfig { .. }),
            "{err:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_with_a_different_issuer_is_rejected() {
    let provider = FakeProvider::start().await;
    provider.set_metadata("issuer", json!("https://other.example.com"));
    assert!(matches!(
        discovery_error(&provider).await,
        OidcError::Discovery(DiscoveryFailure::IssuerMismatch)
    ));

    provider.set_metadata("issuer", json!(format!("{}/", provider.base)));
    assert!(matches!(
        discovery_error(&provider).await,
        OidcError::Discovery(DiscoveryFailure::IssuerMismatch)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_without_code_flow_is_rejected() {
    let provider = FakeProvider::start().await;
    provider.set_metadata(
        "response_types_supported",
        json!(["id_token", "code id_token"]),
    );
    assert!(matches!(
        discovery_error(&provider).await,
        OidcError::Discovery(DiscoveryFailure::CodeFlowUnsupported)
    ));

    provider.set_metadata("response_types_supported", json!(["code"]));
    provider.set_metadata("grant_types_supported", json!(["implicit"]));
    assert!(matches!(
        discovery_error(&provider).await,
        OidcError::Discovery(DiscoveryFailure::CodeFlowUnsupported)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_without_pkce_s256_is_rejected() {
    let provider = FakeProvider::start().await;
    provider.set_metadata("code_challenge_methods_supported", json!(["plain"]));
    assert!(matches!(
        discovery_error(&provider).await,
        OidcError::Discovery(DiscoveryFailure::PkceUnsupported)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_with_only_symmetric_algorithms_is_rejected() {
    let provider = FakeProvider::start().await;
    provider.set_metadata(
        "id_token_signing_alg_values_supported",
        json!(["HS256", "none"]),
    );
    assert!(matches!(
        discovery_error(&provider).await,
        OidcError::Discovery(DiscoveryFailure::NoSupportedSigningAlgorithm)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn insecure_endpoints_in_the_metadata_are_rejected() {
    let endpoints = [
        "token_endpoint",
        "authorization_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
    ];
    let addresses = [
        "http://idp.example.com/endpoint",
        "http://10.0.0.1/endpoint",
        "http://[2001:db8::1]/endpoint",
    ];
    for field in endpoints {
        for address in addresses {
            let provider = FakeProvider::start().await;
            provider.set_metadata(field, json!(address));
            match discovery_error(&provider).await {
                OidcError::InsecureUrl { field: reported } => assert_eq!(reported, field),
                other => panic!("expected an insecure {field} for {address}, got {other:?}"),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn loopback_metadata_endpoints_are_allowed_for_a_loopback_http_issuer() {
    let provider = FakeProvider::start().await;
    provider.enable_userinfo(json!({ "sub": "user-1" }));

    OidcClient::discover(provider.config()).await.unwrap();
}

#[tokio::test]
async fn extra_root_certificates_must_be_valid_pem_certificates() {
    let not_pem = "this is not a certificate".to_owned();
    let broken_body = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_owned();
    let broken_armor = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_owned();
    for pem in [not_pem, broken_body, broken_armor] {
        let mut config = config("https://idp.example.com", "https://gate.example.com/cb");
        config.extra_root_certificates_pem = vec![pem];
        match OidcClient::discover(config).await.unwrap_err() {
            OidcError::InvalidConfig { field, .. } => {
                assert_eq!(field, "extra_root_certificates_pem")
            }
            other => panic!("expected an invalid certificate, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn zero_pending_ttl_is_rejected() {
    let mut config = config("https://idp.example.com", "https://gate.example.com/cb");
    config.pending_ttl_secs = 0;
    assert!(matches!(
        OidcClient::discover(config).await.unwrap_err(),
        OidcError::InvalidConfig {
            field: "pending_ttl_secs",
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_begin_call_uses_fresh_random_values() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let attempts: Vec<_> = (0..8).map(|_| client.begin()).collect();

    let states: HashSet<_> = attempts.iter().map(|p| p.state.clone()).collect();
    let nonces: HashSet<_> = attempts
        .iter()
        .map(|p| p.nonce.expose().to_owned())
        .collect();
    let verifiers: HashSet<_> = attempts
        .iter()
        .map(|p| p.pkce_verifier.expose().to_owned())
        .collect();
    let challenges: HashSet<_> = attempts
        .iter()
        .map(|p| {
            let url = Url::parse(&p.authorize_url).unwrap();
            let pair = url.query_pairs().find(|(k, _)| k == "code_challenge");
            pair.unwrap().1.into_owned()
        })
        .collect();
    assert_eq!(states.len(), 8);
    assert_eq!(nonces.len(), 8);
    assert_eq!(verifiers.len(), 8);
    assert_eq!(challenges.len(), 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn authorization_request_asks_for_the_configured_scopes_once() {
    let provider = FakeProvider::start().await;
    let client = provider.client().await;

    let pending = client.begin();

    let url = Url::parse(&pending.authorize_url).unwrap();
    let scope = url
        .query_pairs()
        .find(|(k, _)| k == "scope")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(scope, "openid email profile groups");
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_output_never_contains_secret_values() {
    let provider = FakeProvider::start().await;
    let config = provider.config();
    let client = OidcClient::discover(config.clone()).await.unwrap();
    let pending = client.begin();

    let rendered = [
        format!("{config:?}"),
        format!("{:?}", config.client_secret),
        format!("{client:?}"),
        format!("{pending:?}"),
    ]
    .join("\n");

    assert!(rendered.contains("[redacted]"));
    for secret in [
        CLIENT_SECRET,
        pending.state.as_str(),
        pending.nonce.expose(),
        pending.pkce_verifier.expose(),
    ] {
        assert!(!rendered.contains(secret), "leaked {secret}");
    }
}
