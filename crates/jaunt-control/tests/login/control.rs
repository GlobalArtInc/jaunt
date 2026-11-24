use jaunt_ca::CaKind;
use jaunt_control::ControlError;
use jaunt_policy::{Identity, NodeInfo, PolicySet};

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

#[tokio::test(flavor = "multi_thread")]
async fn the_client_address_header_needs_trusted_proxies_and_they_need_the_header() {
    type Check = fn(&ControlError) -> bool;
    let cases: [(Option<&'static str>, &'static [&'static str], Check); 3] = [
        (Some("x-forwarded-for"), &[], |error| {
            matches!(error, ControlError::ClientIpHeaderWithoutTrustedProxies)
        }),
        (None, &["10.0.0.0/8"], |error| {
            matches!(error, ControlError::TrustedProxiesWithoutClientIpHeader)
        }),
        (
            Some("x-forwarded-for"),
            &["10.0.0.0/8", "0.0.0.0/0"],
            |error| matches!(error, ControlError::UnusableTrustedProxy(unusable) if unusable.index == 1),
        ),
    ];
    for (header, proxies, check) in cases {
        let refused = Harness::try_with(Options {
            client_ip_header: header,
            trusted_proxies: Some(proxies),
            ..Options::default()
        })
        .await;
        let error = refused.err().expect("the settings were accepted");
        assert!(check(&error), "{error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn control_exposes_the_policy_it_was_given() {
    let harness = Harness::new().await;
    let policy = harness.control.policy().snapshot();
    assert_ne!(policy.hash(), PolicySet::empty().hash());
    let alice = Identity {
        email: "alice@example.com".to_owned(),
        username: "alice".to_owned(),
        groups: vec!["ops".to_owned()],
    };
    let node = NodeInfo {
        name: "web-1".to_owned(),
        labels: [("env".to_owned(), "prod".to_owned())].into(),
    };
    assert!(policy.authorize_ssh(&alice, &node, "alice").allowed);
    assert!(!policy.authorize_ssh(&alice, &node, "root").allowed);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_public_origin_must_be_written_the_way_a_browser_sends_it() {
    for origin in [
        "https://JAUNT.example",
        "https://Jaunt.example:8443",
        "https://jaunt.example:443",
        "https://jaunt.example:0443",
        "https://jaunt.example:",
    ] {
        let refused = Harness::try_with(Options {
            public_origin: origin,
            ..Options::default()
        })
        .await;
        assert!(
            matches!(refused, Err(ControlError::NonCanonicalPublicOrigin)),
            "{origin}"
        );
    }
    for origin in ["https://jaunt.example:8443", "https://127.0.0.1:8443"] {
        let accepted = Harness::try_with(Options {
            public_origin: origin,
            ..Options::default()
        })
        .await;
        assert!(accepted.is_ok(), "{origin}");
    }
}
