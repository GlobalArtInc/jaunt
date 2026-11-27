use axum::http::{Method, StatusCode};
use jaunt_control::RevokeRequest;
use jaunt_store::RevocationKind;
use serde_json::json;

use crate::audit::{start_recording, take_recording};
use crate::signed_support::NOISE_GAP_SECS;
use crate::support::{DEFAULT_PEER, Harness, Options};
use crate::token_support::{
    AUDIT, DAY, Planted, ROLES, SESSIONS, TOKENS, WHOAMI, assert_nowhere, assert_status, bearer,
    bearer_from, last_used, named, plant, set_scope, stored_user, token_harness,
    token_harness_with,
};
use crate::web_support::SESSION_COOKIE;

const PEER_ADDRESS: &str = "198.51.100.7";

async fn alice_token(harness: &Harness, id: &str, scope: &[&str], cidrs: &[&str]) -> String {
    let alice = stored_user(harness, "alice").await;
    plant(
        harness,
        Planted {
            creator: &alice.id,
            id,
            scope,
            cidrs,
            ttl_secs: DAY,
        },
    )
    .await
}

#[tokio::test]
async fn a_token_reaches_the_admin_routes_of_its_scope_and_every_use_is_audited() {
    let harness = token_harness().await;
    let token = alice_token(&harness, "scopedAAAAA", &["audit.read"], &[]).await;
    let alice = stored_user(&harness, "alice").await;
    start_recording();

    let allowed = bearer(&harness, &token, AUDIT).await;
    let denied = bearer(&harness, &token, SESSIONS).await;

    let events = take_recording();
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text());
    assert_status(&denied, StatusCode::FORBIDDEN, "forbidden");
    let used = named(&events, "token.used");
    assert_eq!(used.len(), 2);
    for (event, permission, decision) in [
        (used[0], "audit.read", "allowed"),
        (used[1], "sessions.read", "denied"),
    ] {
        assert_eq!(event["target"], "jaunt::audit");
        assert_eq!(event["jat_id"], "scopedAAAAA");
        assert_eq!(event["user_id"], alice.id);
        assert_eq!(event["permission"], permission);
        assert_eq!(event["decision"], decision);
        assert_eq!(event["client_addr"], PEER_ADDRESS);
    }
    assert!(named(&events, "authz.deny").is_empty());
    assert_nowhere(&events, &token[16..]);
}

#[tokio::test]
async fn format_and_secret_failures_are_generic_401s_with_anonymous_noisy_refusals() {
    let harness = token_harness().await;
    let token = alice_token(&harness, "formatAAAAA", &["audit.read"], &[]).await;
    let unknown = token.replace("formatAAAAA", "unknownAAAA");
    let wrong_secret = format!("jat_formatAAAAA_{}", "x".repeat(43));
    let truncated = token[..token.len() - 1].to_owned();
    let extra = format!("{token}A");
    let renamed = token.replacen("jat_", "Jat_", 1);
    let bearer_of = |text: &str| vec![format!("Bearer {text}")];
    let cases = [
        ("unknown id", bearer_of(&unknown), "unknown_id"),
        ("wrong secret", bearer_of(&wrong_secret), "bad_secret"),
        ("truncated", bearer_of(&truncated), "malformed"),
        ("extra bytes", bearer_of(&extra), "malformed"),
        ("other prefix", bearer_of(&renamed), "malformed"),
        ("padded", bearer_of(&format!(" {token}")), "malformed"),
        ("no value", vec!["Bearer".to_owned()], "malformed"),
        (
            "two headers",
            [bearer_of(&token), bearer_of(&token)].concat(),
            "malformed",
        ),
    ];
    for (label, values, reason) in cases {
        harness.clock.advance(NOISE_GAP_SECS);
        let headers: Vec<(&str, &str)> = values
            .iter()
            .map(|value| ("authorization", value.as_str()))
            .collect();
        start_recording();
        let reply = harness
            .request_as(Method::GET, AUDIT, DEFAULT_PEER, &headers, None)
            .await;
        let events = take_recording();
        assert_status(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
        let refused = named(&events, "token.refused");
        assert_eq!(refused.len(), 1, "{label}: {events:?}");
        assert_eq!(refused[0]["reason"], reason, "{label}");
        assert_eq!(refused[0]["client_addr"], PEER_ADDRESS, "{label}");
        assert!(refused[0].get("jat_id").is_none(), "{label}");
        assert!(refused[0].get("user_id").is_none(), "{label}");
        assert!(named(&events, "token.used").is_empty(), "{label}");
        assert_nowhere(&events, "formatAAAAA");
    }
    assert_eq!(bearer(&harness, &token, AUDIT).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_token_stops_at_its_expiry_on_the_injected_clock() {
    let harness = token_harness().await;
    let alice = stored_user(&harness, "alice").await;
    let token = plant(
        &harness,
        Planted {
            creator: &alice.id,
            id: "expiringAAA",
            scope: &["audit.read"],
            cidrs: &[],
            ttl_secs: 60,
        },
    )
    .await;

    harness.clock.advance(59);
    assert_eq!(bearer(&harness, &token, AUDIT).await.status, StatusCode::OK);
    harness.clock.advance(1);
    start_recording();
    let expired = bearer(&harness, &token, AUDIT).await;
    let events = take_recording();

    assert_status(&expired, StatusCode::UNAUTHORIZED, "unauthorized");
    let used = named(&events, "token.used");
    assert_eq!(used[0]["decision"], "refused");
    assert_eq!(used[0]["reason"], "expired");
    assert_eq!(used[0]["jat_id"], "expiringAAA");
}

#[tokio::test]
async fn listed_networks_restrict_the_client_address_and_an_empty_list_allows_any() {
    let harness = token_harness().await;
    let fenced = alice_token(
        &harness,
        "fencedAAAAA",
        &["audit.read"],
        &["203.0.113.0/24", "2001:db8::/32"],
    )
    .await;
    let open = alice_token(&harness, "openAAAAAAA", &["audit.read"], &[]).await;
    for (token, peer, status) in [
        (&fenced, "203.0.113.9:4000", StatusCode::OK),
        (&fenced, "[2001:db8::5]:4000", StatusCode::OK),
        (&fenced, "192.0.2.1:4000", StatusCode::UNAUTHORIZED),
        (&fenced, "[2001:db9::5]:4000", StatusCode::UNAUTHORIZED),
        (&open, "192.0.2.1:4000", StatusCode::OK),
    ] {
        harness.clock.advance(NOISE_GAP_SECS);
        start_recording();
        let reply = bearer_from(&harness, token, Method::GET, AUDIT, peer, &[]).await;
        let events = take_recording();
        assert_eq!(reply.status, status, "{peer}: {}", reply.text());
        if status == StatusCode::UNAUTHORIZED {
            let used = named(&events, "token.used");
            assert_eq!(used[0]["reason"], "address", "{peer}");
        }
    }
}

#[tokio::test]
async fn the_address_checked_is_the_client_behind_a_trusted_proxy() {
    let harness = token_harness_with(Options {
        client_ip_header: Some("x-forwarded-for"),
        ..Options::default()
    })
    .await;
    let token = alice_token(
        &harness,
        "proxiedAAAA",
        &["audit.read"],
        &["203.0.113.0/24"],
    )
    .await;
    for (peer, forwarded, status) in [
        (DEFAULT_PEER, "203.0.113.5", StatusCode::OK),
        (DEFAULT_PEER, "192.0.2.5", StatusCode::UNAUTHORIZED),
        ("192.0.2.9:4000", "203.0.113.5", StatusCode::UNAUTHORIZED),
    ] {
        let reply = bearer_from(
            &harness,
            &token,
            Method::GET,
            AUDIT,
            peer,
            &[("x-forwarded-for", forwarded)],
        )
        .await;
        assert_eq!(reply.status, status, "{peer} {forwarded}: {}", reply.text());
    }
}

#[tokio::test]
async fn demoting_removing_or_revoking_the_creator_takes_effect_at_once() {
    let harness = token_harness().await;
    let alice = stored_user(&harness, "alice").await;
    let token = alice_token(
        &harness,
        "creatorAAAA",
        &["audit.read", "sessions.read"],
        &[],
    )
    .await;
    assert_eq!(
        bearer(&harness, &token, SESSIONS).await.status,
        StatusCode::OK
    );

    harness.load_policy(&ROLES.replace(
        "[nodes.approve, sessions.read, audit.read, tokens.write]",
        "[audit.read]",
    ));
    assert_status(
        &bearer(&harness, &token, SESSIONS).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_eq!(bearer(&harness, &token, AUDIT).await.status, StatusCode::OK);
    let whoami = bearer(&harness, &token, WHOAMI).await;
    assert_eq!(whoami.status, StatusCode::OK, "{}", whoami.text());
    assert_eq!(
        whoami.json(),
        json!({ "token": {
            "id": "creatorAAAA",
            "name": "planted-creatoraaaa",
            "scope": ["sessions.read", "audit.read"],
            "rights": ["audit.read"],
            "expires_at": harness.clock.now_secs() + DAY,
        } })
    );

    harness.load_policy(&ROLES.replace("alice@example.com", "nobody@example.com"));
    assert_status(
        &bearer(&harness, &token, AUDIT).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );

    harness.load_policy(ROLES);
    assert_eq!(bearer(&harness, &token, AUDIT).await.status, StatusCode::OK);
    harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::User,
                subject: alice.id.clone(),
                reason: "left the company".to_owned(),
            },
            "cli:test",
        )
        .await
        .unwrap();
    harness.clock.advance(NOISE_GAP_SECS);
    start_recording();
    let revoked = bearer(&harness, &token, AUDIT).await;
    let orphan = plant(
        &harness,
        Planted {
            creator: "6d0c2f4e-1b3a-4c5d-9e8f-7a6b5c4d3e2f",
            id: "orphanAAAAA",
            scope: &["audit.read"],
            cidrs: &[],
            ttl_secs: DAY,
        },
    )
    .await;
    let unknown = bearer(&harness, &orphan, AUDIT).await;
    let events = take_recording();

    assert_status(&revoked, StatusCode::UNAUTHORIZED, "unauthorized");
    assert_status(&unknown, StatusCode::UNAUTHORIZED, "unauthorized");
    let reasons: Vec<&str> = named(&events, "token.used")
        .iter()
        .map(|event| event["reason"].as_str())
        .collect();
    assert_eq!(reasons, ["creator_revoked", "creator_unknown"]);
}

#[tokio::test]
async fn a_token_never_opens_routes_outside_the_admin_api() {
    let harness = token_harness().await;
    let token = alice_token(
        &harness,
        "outsideAAAA",
        &["nodes.approve", "sessions.read", "audit.read"],
        &[],
    )
    .await;
    for path in [
        "/v1/whoami",
        "/v1/nodes",
        "/v1/web/session",
        "/v1/web/terminal/targets",
    ] {
        let reply = bearer(&harness, &token, path).await;
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "{path}: {}",
            reply.text()
        );
    }
    for path in ["/v1/web/logout", "/v1/web/terminal/ticket"] {
        let reply = bearer_from(&harness, &token, Method::POST, path, DEFAULT_PEER, &[]).await;
        assert!(
            matches!(
                reply.status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ),
            "{path}: {} {}",
            reply.status,
            reply.text()
        );
    }
}

#[tokio::test]
async fn a_token_with_a_session_cookie_or_signature_headers_is_refused_as_ambiguous() {
    let harness = token_harness().await;
    let signed_in = harness.web_sign_in().await;
    let cookie = signed_in.cookie();
    let token = alice_token(&harness, "ambiguousAA", &["audit.read"], &[]).await;
    let stray_cookie = format!("{SESSION_COOKIE}=x; {SESSION_COOKIE}=y");
    for (label, extra) in [
        ("cookie", vec![("cookie", cookie.as_str())]),
        ("duplicated cookie", vec![("cookie", stray_cookie.as_str())]),
        ("signature input", vec![("signature-input", "jaunt=()")]),
        (
            "certificate",
            vec![("jaunt-certificate", "ssh-ed25519-cert-v01@openssh.com AAAA")],
        ),
    ] {
        harness.clock.advance(NOISE_GAP_SECS);
        start_recording();
        let reply = bearer_from(&harness, &token, Method::GET, AUDIT, DEFAULT_PEER, &extra).await;
        let events = take_recording();
        assert_status(&reply, StatusCode::BAD_REQUEST, "ambiguous_credentials");
        assert_eq!(
            named(&events, "token.refused")[0]["reason"],
            "ambiguous",
            "{label}"
        );
        assert!(named(&events, "token.used").is_empty(), "{label}");
    }
    let basic = harness
        .web_request(
            Method::GET,
            AUDIT,
            Some(&cookie),
            &[("authorization", "Basic dXNlcjpwYXNz")],
        )
        .await;
    assert_eq!(basic.status, StatusCode::OK, "{}", basic.text());
}

#[tokio::test]
async fn each_token_makes_at_most_sixty_requests_a_minute() {
    let harness = token_harness().await;
    let busy = alice_token(&harness, "busyAAAAAAA", &["audit.read"], &[]).await;
    let other = alice_token(&harness, "otherAAAAAA", &["audit.read"], &[]).await;
    for index in 0..60 {
        let reply = bearer(&harness, &busy, AUDIT).await;
        assert_eq!(reply.status, StatusCode::OK, "{index}");
    }
    start_recording();
    let limited = bearer(&harness, &busy, AUDIT).await;
    let events = take_recording();

    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.header("retry-after"), "1");
    assert_eq!(limited.error_code(), "too_many_requests");
    let used = named(&events, "token.used");
    assert_eq!(used[0]["reason"], "rate_limited");
    assert!(
        named(&events, "token.used")
            .iter()
            .all(|event| event["decision"] == "refused")
    );
    assert_eq!(bearer(&harness, &other, AUDIT).await.status, StatusCode::OK);
    harness.clock.advance(1);
    assert_eq!(bearer(&harness, &busy, AUDIT).await.status, StatusCode::OK);
    assert_eq!(
        bearer(&harness, &busy, AUDIT).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn whoami_names_the_token_and_its_scope_without_the_secret() {
    let harness = token_harness().await;
    let token = alice_token(&harness, "selfAAAAAAA", &["audit.read"], &[]).await;
    start_recording();
    let reply = bearer(&harness, &token, WHOAMI).await;
    let events = take_recording();
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let used = named(&events, "token.used");
    assert_eq!(used.len(), 1);
    assert_eq!(used[0]["jat_id"], "selfAAAAAAA");
    assert_eq!(used[0]["decision"], "allowed");
    assert!(used[0].get("permission").is_none());
    let body = reply.json();
    assert_eq!(body["token"]["name"], "planted-selfaaaaaaa");
    assert_eq!(body["token"]["scope"], json!(["audit.read"]));
    assert_eq!(body["token"]["rights"], json!(["audit.read"]));
    assert!(!reply.text().contains(&token[16..]));
    assert!(body.get("email").is_none());
    let listed = bearer(&harness, &token, TOKENS).await;
    assert_status(&listed, StatusCode::FORBIDDEN, "forbidden");
}

#[tokio::test]
async fn the_rate_limit_counts_only_requests_whose_secret_was_verified() {
    let harness = token_harness().await;
    let token = alice_token(&harness, "quotaAAAAAA", &["audit.read"], &[]).await;
    let wrong = format!("jat_quotaAAAAAA_{}", "w".repeat(43));
    for _ in 0..61 {
        let reply = bearer(&harness, &wrong, AUDIT).await;
        assert_status(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let reply = bearer(&harness, &token, AUDIT).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
}

#[tokio::test]
async fn the_last_use_is_written_only_after_the_validity_checks_and_at_most_once_a_minute() {
    let harness = token_harness().await;
    let alice = stored_user(&harness, "alice").await;
    let fenced = alice_token(
        &harness,
        "fencedAAAAA",
        &["audit.read"],
        &["203.0.113.0/24"],
    )
    .await;
    let revoked = alice_token(&harness, "revokedAAAA", &["audit.read"], &[]).await;
    let expiring = plant(
        &harness,
        Planted {
            creator: &alice.id,
            id: "expiringAAA",
            scope: &["audit.read"],
            cidrs: &[],
            ttl_secs: 60,
        },
    )
    .await;
    let steady = alice_token(&harness, "steadyAAAAA", &["audit.read"], &[]).await;
    harness
        .store
        .admin_tokens()
        .revoke("revokedAAAA", harness.clock.now_secs(), 100)
        .await
        .unwrap();
    harness.clock.advance(60);

    for (token, id) in [
        (&fenced, "fencedAAAAA"),
        (&revoked, "revokedAAAA"),
        (&expiring, "expiringAAA"),
    ] {
        let reply = bearer(&harness, token, AUDIT).await;
        assert_status(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
        assert_eq!(last_used(&harness, id).await, None, "{id}");
    }
    let first = harness.clock.now_secs();
    assert_eq!(
        bearer(&harness, &steady, AUDIT).await.status,
        StatusCode::OK
    );
    assert_eq!(last_used(&harness, "steadyAAAAA").await, Some(first));
    harness.clock.advance(60);
    assert_eq!(
        bearer(&harness, &steady, AUDIT).await.status,
        StatusCode::OK
    );
    assert_eq!(last_used(&harness, "steadyAAAAA").await, Some(first));
    harness.clock.advance(1);
    assert_eq!(
        bearer(&harness, &steady, AUDIT).await.status,
        StatusCode::OK
    );
    assert_eq!(last_used(&harness, "steadyAAAAA").await, Some(first + 61));
}

#[tokio::test]
async fn a_token_outside_the_admin_api_is_a_generic_401_that_is_neither_audited_nor_recorded() {
    let harness = token_harness().await;
    let token = alice_token(&harness, "webAAAAAAAA", &["audit.read"], &[]).await;
    start_recording();
    let reply = bearer(&harness, &token, "/v1/web/session").await;
    let events = take_recording();
    assert_status(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
    assert!(named(&events, "token.used").is_empty());
    assert!(named(&events, "token.refused").is_empty());
    assert_eq!(last_used(&harness, "webAAAAAAAA").await, None);
}

#[tokio::test]
async fn refusals_are_held_back_and_counted_before_and_after_the_secret_is_verified() {
    let harness = token_harness().await;
    let token = alice_token(&harness, "heldAAAAAAA", &["audit.read"], &[]).await;
    harness
        .store
        .admin_tokens()
        .revoke("heldAAAAAAA", harness.clock.now_secs(), 100)
        .await
        .unwrap();
    harness.clock.advance(NOISE_GAP_SECS);
    start_recording();
    for _ in 0..4 {
        bearer(&harness, "jat_malformed", AUDIT).await;
    }
    harness.clock.advance(NOISE_GAP_SECS);
    bearer(&harness, "jat_malformed", AUDIT).await;
    for _ in 0..7 {
        bearer(&harness, &token, AUDIT).await;
    }
    harness.clock.advance(NOISE_GAP_SECS);
    bearer(&harness, &token, AUDIT).await;
    let events = take_recording();

    let unproven: Vec<&str> = named(&events, "token.refused")
        .iter()
        .map(|event| event["suppressed"].as_str())
        .collect();
    assert_eq!(unproven, ["0", "3"]);
    let proven: Vec<&str> = named(&events, "token.used")
        .iter()
        .map(|event| event["suppressed"].as_str())
        .collect();
    assert_eq!(proven, ["0", "0", "0", "0", "0", "2"]);
}

#[tokio::test]
async fn a_stored_scope_naming_rights_a_token_cannot_hold_is_narrowed_and_warned_about_hourly() {
    let harness = token_harness().await;
    let mut planted = Vec::new();
    for (id, scope) in [
        ("writerAAAAA", r#"["audit.read","tokens.write"]"#),
        ("futureAAAAA", r#"["audit.read","future.right"]"#),
    ] {
        let token = alice_token(&harness, id, &["audit.read"], &[]).await;
        set_scope(&harness, id, scope).await;
        planted.push((id, token));
    }
    for (id, token) in &planted {
        start_recording();
        let audit = bearer(&harness, token, AUDIT).await;
        let listed = bearer(&harness, token, TOKENS).await;
        let whoami = bearer(&harness, token, WHOAMI).await;
        let early = take_recording();
        harness.clock.advance(3_600);
        start_recording();
        bearer(&harness, token, AUDIT).await;
        let later = take_recording();

        assert_eq!(audit.status, StatusCode::OK, "{id}: {}", audit.text());
        assert_status(&listed, StatusCode::FORBIDDEN, "forbidden");
        assert_eq!(
            whoami.json()["token"]["rights"],
            json!(["audit.read"]),
            "{id}"
        );
        assert_eq!(
            whoami.json()["token"]["scope"],
            json!(["audit.read"]),
            "{id}"
        );
        let warned = |events: &[crate::audit::Captured]| {
            events
                .iter()
                .filter(|event| {
                    event["target"] == "jaunt::control"
                        && event.get("jat_id").map(String::as_str) == Some(*id)
                })
                .count()
        };
        assert_eq!(warned(&early), 1, "{id}");
        assert_eq!(warned(&later), 1, "{id}");
        assert_nowhere(&early, &token[16..]);
    }
}
