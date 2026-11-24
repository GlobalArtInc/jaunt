use axum::http::{Method, StatusCode};

use crate::support::{Harness, PUBLIC_ORIGIN};
use crate::web_support::{APPROVER_AND_OPS_ROLES, WebSignedIn};

const LOGOUT: &str = "/v1/web/logout";

#[derive(Clone, Copy, Debug)]
enum Token {
    Missing,
    Wrong,
    Right,
}

struct OriginCase {
    label: &'static str,
    headers: &'static [(&'static str, &'static str)],
    accepted: bool,
}

const ORIGINS: [OriginCase; 6] = [
    OriginCase {
        label: "no origin",
        headers: &[],
        accepted: false,
    },
    OriginCase {
        label: "foreign origin",
        headers: &[("origin", "https://evil.example")],
        accepted: false,
    },
    OriginCase {
        label: "null origin",
        headers: &[("origin", "null")],
        accepted: false,
    },
    OriginCase {
        label: "own origin",
        headers: &[("origin", PUBLIC_ORIGIN)],
        accepted: true,
    },
    OriginCase {
        label: "no origin, same-origin fetch",
        headers: &[("sec-fetch-site", "same-origin")],
        accepted: true,
    },
    OriginCase {
        label: "no origin, cross-site fetch",
        headers: &[("sec-fetch-site", "cross-site")],
        accepted: false,
    },
];

fn expected(method: &Method, token: Token, origin_ok: bool) -> StatusCode {
    match (token, origin_ok) {
        (Token::Right, true) if method == Method::POST => StatusCode::NO_CONTENT,
        (Token::Right, true) => StatusCode::METHOD_NOT_ALLOWED,
        _ => StatusCode::FORBIDDEN,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_state_changing_method_needs_the_token_and_an_acceptable_origin() {
    let harness = Harness::with_web().await;
    let mut signed = harness.web_sign_in().await;
    let mut token = harness.csrf_token(&signed).await;

    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        for token_state in [Token::Missing, Token::Wrong, Token::Right] {
            for case in &ORIGINS {
                let wanted = expected(&method, token_state, case.accepted);
                let mut headers: Vec<(&str, &str)> = case.headers.to_vec();
                let wrong_token = format!("{}A", &token[1..]);
                match token_state {
                    Token::Missing => {}
                    Token::Wrong => headers.push(("x-jaunt-csrf", &wrong_token)),
                    Token::Right => headers.push(("x-jaunt-csrf", &token)),
                }

                let reply = harness
                    .web_request(method.clone(), LOGOUT, Some(&signed.cookie()), &headers)
                    .await;

                assert_eq!(
                    reply.status, wanted,
                    "{method} token {token_state:?} {}",
                    case.label
                );
                if wanted == StatusCode::NO_CONTENT {
                    signed = harness.web_sign_in().await;
                    token = harness.csrf_token(&signed).await;
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_belongs_to_its_own_session_and_a_duplicated_header_is_refused() {
    let harness = Harness::with_web().await;
    let mine = harness.web_sign_in().await;
    let theirs = harness.web_sign_in().await;
    let their_token = harness.csrf_token(&theirs).await;
    let my_token = harness.csrf_token(&mine).await;
    assert_ne!(my_token, their_token);

    let swapped = harness
        .web_request(
            Method::POST,
            LOGOUT,
            Some(&mine.cookie()),
            &[("x-jaunt-csrf", &their_token), ("origin", PUBLIC_ORIGIN)],
        )
        .await;
    let doubled = harness
        .web_request(
            Method::POST,
            LOGOUT,
            Some(&mine.cookie()),
            &[
                ("x-jaunt-csrf", &my_token),
                ("x-jaunt-csrf", &my_token),
                ("origin", PUBLIC_ORIGIN),
            ],
        )
        .await;
    let two_origins = harness
        .web_request(
            Method::POST,
            LOGOUT,
            Some(&mine.cookie()),
            &[
                ("x-jaunt-csrf", &my_token),
                ("origin", PUBLIC_ORIGIN),
                ("origin", PUBLIC_ORIGIN),
            ],
        )
        .await;

    for reply in [swapped, doubled, two_origins] {
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.error_code(), "forbidden");
    }
    assert_eq!(
        harness.web_post_with_csrf(LOGOUT, &mine).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_state_changing_request_without_a_session_is_unauthorised_not_forbidden() {
    let harness = Harness::with_web().await;
    let signed = harness.web_sign_in().await;
    let token = harness.csrf_token(&signed).await;

    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let reply = harness
            .web_request(
                method.clone(),
                LOGOUT,
                None,
                &[("x-jaunt-csrf", &token), ("origin", PUBLIC_ORIGIN)],
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method}");
        assert_eq!(reply.error_code(), "unauthorized");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reading_never_needs_the_token_or_the_origin() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let signed: WebSignedIn = harness.web_sign_in().await;
    let cross_site = [
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://evil.example"),
    ];

    for method in [Method::GET, Method::HEAD] {
        for path in ["/v1/web/session", "/v1/admin/whoami"] {
            let reply = harness
                .web_request(method.clone(), path, Some(&signed.cookie()), &cross_site)
                .await;
            assert_eq!(reply.status, StatusCode::OK, "{method} {path}");
        }
    }
}
