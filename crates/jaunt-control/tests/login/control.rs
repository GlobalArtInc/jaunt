use jaunt_ca::CaKind;
use jaunt_control::ControlError;

use crate::support::{Harness, Options};

#[tokio::test(flavor = "multi_thread")]
async fn only_a_user_authority_can_sign_user_certificates() {
    let refused = Harness::try_with(Options {
        authority: CaKind::Host,
        ..Options::default()
    })
    .await;
    assert!(matches!(refused, Err(ControlError::NotUserAuthority)));

    let accepted = Harness::try_with(Options::default()).await;
    assert!(accepted.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_public_origin_and_the_client_header_must_be_usable() {
    for origin in [
        "http://jaunt.example",
        "https://jaunt.example/",
        "jaunt.example",
        "",
    ] {
        let refused = Harness::try_with(Options {
            public_origin: origin,
            ..Options::default()
        })
        .await;
        assert!(
            matches!(refused, Err(ControlError::InvalidPublicOrigin)),
            "{origin}"
        );
    }
    for header in ["", "not a header", "x:y"] {
        let refused = Harness::try_with(Options {
            client_ip_header: Some(header),
            ..Options::default()
        })
        .await;
        assert!(
            matches!(refused, Err(ControlError::InvalidClientIpHeader)),
            "{header}"
        );
    }
    let accepted = Harness::try_with(Options {
        client_ip_header: Some("X-Forwarded-For"),
        ..Options::default()
    })
    .await;
    assert!(accepted.is_ok());
}
