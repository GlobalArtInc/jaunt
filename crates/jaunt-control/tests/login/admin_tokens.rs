use std::collections::BTreeSet;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::audit::{start_recording, take_recording};
use crate::provider::Identity;
use crate::signed_support::cli_login;
use crate::support::{DEFAULT_PEER, PUBLIC_ORIGIN, sha256_hex};
use crate::token_support::{
    AUDIT, DAY, Planted, TOKENS, all_tokens, assert_nowhere, assert_status, bearer, bearer_from,
    console, console_call, create_signed, named, plant, signed_call, stored_user, token_harness,
};
use crate::web_support::carol;

fn request(name: &str, scope: &[&str]) -> Value {
    json!({ "name": name, "scope": scope })
}

#[tokio::test]
async fn a_person_creates_a_token_whose_secret_is_shown_once_and_never_stored_or_logged() {
    let harness = token_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let now = harness.clock.now_secs();
    start_recording();

    let reply = create_signed(
        &harness,
        &alice,
        &json!({ "name": "ci-audit", "scope": ["audit.read"], "cidrs": ["203.0.113.0/24"] }),
    )
    .await;

    let events = take_recording();
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
    let body = reply.json();
    let secret = body["secret"].as_str().unwrap().to_owned();
    let id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(jaunt_proto::admin_token_id(&secret), Some(id.as_str()));
    assert_eq!(body["creator"], alice.user_id());
    assert_eq!(body["scope"], json!(["audit.read"]));
    assert_eq!(body["cidrs"], json!(["203.0.113.0/24"]));
    assert_eq!(body["expires_at"], now + 30 * DAY);

    let stored = harness
        .store
        .admin_tokens()
        .get_for_use(&id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.secret_hash.expose(), sha256_hex(&secret));
    assert_nowhere(&events, &secret);
    assert_nowhere(&events, &secret[16..]);
    assert_nowhere(&events, stored.secret_hash.expose());

    let created = named(&events, "token.created");
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["jat_id"], id);
    assert_eq!(created[0]["name"], "ci-audit");
    assert_eq!(created[0]["scope"], "audit.read");
    assert_eq!(created[0]["cidrs"], "203.0.113.0/24");
    assert_eq!(created[0]["expires_at"], (now + 30 * DAY).to_string());
    assert_eq!(
        created[0]["created_by"],
        format!("signed:{}", alice.user_id())
    );

    let listed = signed_call(&harness, &alice, Method::GET, TOKENS, b"").await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text());
    let tokens = listed.json()["tokens"].as_array().unwrap().clone();
    assert_eq!(tokens.len(), 1);
    assert_eq!(listed.json()["truncated"], false);
    let keys: BTreeSet<&str> = tokens[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "id",
            "name",
            "creator",
            "scope",
            "cidrs",
            "created_at",
            "expires_at",
            "revoked_at",
            "last_used_at"
        ])
    );
    assert!(!listed.text().contains(&secret[16..]));
    assert!(!listed.text().contains(stored.secret_hash.expose()));
    assert_eq!(tokens[0]["last_used_at"], Value::Null);

    let used = bearer_from(
        &harness,
        &secret,
        Method::GET,
        AUDIT,
        "203.0.113.9:4000",
        &[],
    )
    .await;
    assert_eq!(used.status, StatusCode::OK, "{}", used.text());
    let listed = signed_call(&harness, &alice, Method::GET, TOKENS, b"").await;
    assert_eq!(listed.json()["tokens"][0]["last_used_at"], now);
}

#[tokio::test]
async fn the_scope_lifetime_names_and_networks_are_checked_at_creation() {
    let harness = token_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    for (body, status, code) in [
        (
            request("ci", &["revocations.write"]),
            StatusCode::FORBIDDEN,
            "scope_not_held",
        ),
        (
            request("ci", &["audit.read", "recordings.read"]),
            StatusCode::FORBIDDEN,
            "scope_not_held",
        ),
        (
            request("ci", &["tokens.write"]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_scope",
        ),
        (
            request("ci", &[]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_scope",
        ),
        (
            request("ci", &["ssh"]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_scope",
        ),
        (
            request("CI", &["audit.read"]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_name",
        ),
        (
            json!({ "name": "ci", "scope": ["audit.read"], "ttl_secs": 59 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_ttl",
        ),
        (
            json!({ "name": "ci", "scope": ["audit.read"], "ttl_secs": 90 * DAY + 1 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_ttl",
        ),
        (
            json!({ "name": "ci", "scope": ["audit.read"], "cidrs": ["203.0.113.1/24"] }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_cidrs",
        ),
        (
            json!({ "name": "ci", "scope": ["audit.read"], "cidrs": ["0.0.0.0/0"] }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_cidrs",
        ),
        (
            json!({ "name": "ci", "scope": ["audit.read"], "secret": "mine" }),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ] {
        let reply = create_signed(&harness, &alice, &body).await;
        assert_status(&reply, status, code);
    }
    for (name, ttl) in [("shortest", 60), ("longest", 90 * DAY)] {
        let reply = create_signed(
            &harness,
            &alice,
            &json!({ "name": name, "scope": ["audit.read"], "ttl_secs": ttl }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
        assert_eq!(reply.json()["expires_at"], harness.clock.now_secs() + ttl);
    }
    assert_eq!(all_tokens(&harness).await.len(), 2);
}

#[tokio::test]
async fn a_creator_holds_at_most_twenty_live_tokens_with_distinct_names() {
    let harness = token_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    for index in 0..20 {
        let reply = create_signed(
            &harness,
            &alice,
            &request(&format!("t{index}"), &["audit.read"]),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::CREATED,
            "{index}: {}",
            reply.text()
        );
    }
    let taken = create_signed(&harness, &alice, &request("t3", &["audit.read"])).await;
    assert_status(&taken, StatusCode::CONFLICT, "name_taken");
    let full = create_signed(&harness, &alice, &request("t20", &["audit.read"])).await;
    assert_status(&full, StatusCode::CONFLICT, "too_many_tokens");
}

#[tokio::test]
async fn only_a_person_holding_tokens_write_may_create_list_or_revoke() {
    let harness = token_harness().await;
    let carol = cli_login(&harness, carol()).await;
    let id_path = format!("{TOKENS}/AAAAAAAAAAA");
    for (method, path, body) in [
        (
            Method::POST,
            TOKENS,
            serde_json::to_vec(&request("ci", &["audit.read"])).unwrap(),
        ),
        (Method::GET, TOKENS, Vec::new()),
        (Method::DELETE, id_path.as_str(), Vec::new()),
    ] {
        let reply = signed_call(&harness, &carol, method.clone(), path, &body).await;
        assert_status(&reply, StatusCode::FORBIDDEN, "forbidden");
    }
    assert!(all_tokens(&harness).await.is_empty());
}

#[tokio::test]
async fn a_token_cannot_create_list_or_revoke_tokens() {
    let harness = token_harness().await;
    let alice = stored_user(&harness, "alice").await;
    let token = plant(
        &harness,
        Planted {
            creator: &alice.id,
            id: "minterAAAAA",
            scope: &["audit.read"],
            cidrs: &[],
            ttl_secs: DAY,
        },
    )
    .await;
    start_recording();

    let body = serde_json::to_vec(&request("child", &["audit.read"])).unwrap();
    let authorization = format!("Bearer {token}");
    let create = harness
        .request_as(
            Method::POST,
            TOKENS,
            DEFAULT_PEER,
            &[("authorization", &authorization)],
            Some(("application/json", body)),
        )
        .await;
    let list = bearer(&harness, &token, TOKENS).await;
    let revoke = bearer_from(
        &harness,
        &token,
        Method::DELETE,
        &format!("{TOKENS}/minterAAAAA"),
        DEFAULT_PEER,
        &[],
    )
    .await;

    let events = take_recording();
    for reply in [&create, &list, &revoke] {
        assert_status(reply, StatusCode::FORBIDDEN, "forbidden");
    }
    let used = named(&events, "token.used");
    assert_eq!(used.len(), 3);
    for event in used {
        assert_eq!(event["permission"], "tokens.write");
        assert_eq!(event["decision"], "denied");
    }
    assert_eq!(all_tokens(&harness).await.len(), 1);
    assert!(
        harness
            .store
            .admin_tokens()
            .get_for_use("minterAAAAA")
            .await
            .unwrap()
            .unwrap()
            .token
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn revocation_takes_effect_at_the_next_request_and_is_audited() {
    let harness = token_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let created = create_signed(&harness, &alice, &request("ci", &["audit.read"])).await;
    let secret = created.json()["secret"].as_str().unwrap().to_owned();
    let id = created.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(
        bearer(&harness, &secret, AUDIT).await.status,
        StatusCode::OK
    );
    start_recording();

    let path = format!("{TOKENS}/{id}");
    let revoked = signed_call(&harness, &alice, Method::DELETE, &path, b"").await;
    let refused = bearer(&harness, &secret, AUDIT).await;
    let again = signed_call(&harness, &alice, Method::DELETE, &path, b"").await;
    let bob = stored_user(&harness, "bob").await;
    plant(
        &harness,
        Planted {
            creator: &bob.id,
            id: "bobsAAAAAAA",
            scope: &["audit.read"],
            cidrs: &[],
            ttl_secs: DAY,
        },
    )
    .await;
    let foreign = signed_call(
        &harness,
        &alice,
        Method::DELETE,
        &format!("{TOKENS}/bobsAAAAAAA"),
        b"",
    )
    .await;
    let unknown = signed_call(
        &harness,
        &alice,
        Method::DELETE,
        &format!("{TOKENS}/AAAAAAAAAAA"),
        b"",
    )
    .await;
    let malformed = signed_call(
        &harness,
        &alice,
        Method::DELETE,
        &format!("{TOKENS}/bad.id"),
        b"",
    )
    .await;

    let events = take_recording();
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.text());
    assert_status(&refused, StatusCode::UNAUTHORIZED, "unauthorized");
    assert_status(&again, StatusCode::CONFLICT, "already_revoked");
    assert_eq!(foreign.status, StatusCode::NO_CONTENT, "{}", foreign.text());
    assert_status(&unknown, StatusCode::NOT_FOUND, "not_found");
    assert_status(&malformed, StatusCode::NOT_FOUND, "not_found");
    let audited = named(&events, "token.revoked");
    assert_eq!(audited.len(), 2);
    assert_eq!(audited[1]["creator"], bob.id);
    assert_eq!(audited[0]["jat_id"], id);
    assert_eq!(audited[0]["name"], "ci");
    assert_eq!(audited[0]["creator"], alice.user_id());
    assert_eq!(
        audited[0]["revoked_by"],
        format!("signed:{}", alice.user_id())
    );
    let used = named(&events, "token.used");
    assert_eq!(used.len(), 1);
    assert_eq!(used[0]["decision"], "refused");
    assert_eq!(used[0]["reason"], "revoked");
}

#[tokio::test]
async fn a_web_session_creates_a_token_only_with_its_csrf_token() {
    let harness = token_harness().await;
    let signed_in = harness.web_sign_in().await;
    let cookie = signed_in.cookie();
    let csrf = harness.csrf_token(&signed_in).await;
    let body = serde_json::to_vec(&request("console", &["sessions.read"])).unwrap();

    let without = harness
        .request_as(
            Method::POST,
            TOKENS,
            DEFAULT_PEER,
            &[("cookie", &cookie)],
            Some(("application/json", body.clone())),
        )
        .await;
    start_recording();
    let with = harness
        .request_as(
            Method::POST,
            TOKENS,
            DEFAULT_PEER,
            &[
                ("cookie", &cookie),
                ("x-jaunt-csrf", &csrf),
                ("origin", PUBLIC_ORIGIN),
            ],
            Some(("application/json", body)),
        )
        .await;

    let events = take_recording();
    assert_status(&without, StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(with.status, StatusCode::CREATED, "{}", with.text());
    let creator = with.json()["creator"].as_str().unwrap().to_owned();
    assert_eq!(
        named(&events, "token.created")[0]["created_by"],
        format!("web:{creator}")
    );
}

#[tokio::test]
async fn the_sweeper_deletes_a_token_thirty_days_after_it_was_revoked_or_expired() {
    let harness = token_harness().await;
    let alice = stored_user(&harness, "alice").await;
    for (id, ttl_secs) in [("expiredAAAA", 60), ("revokedAAAA", 90 * DAY)] {
        plant(
            &harness,
            Planted {
                creator: &alice.id,
                id,
                scope: &["audit.read"],
                cidrs: &[],
                ttl_secs,
            },
        )
        .await;
    }
    harness
        .store
        .admin_tokens()
        .revoke("revokedAAAA", harness.clock.now_secs(), 100)
        .await
        .unwrap();

    harness.clock.advance(30 * 86_400);
    assert_eq!(harness.control.purge_admin_tokens().await.unwrap(), 0);
    harness.clock.advance(1);
    assert_eq!(harness.control.purge_admin_tokens().await.unwrap(), 1);
    harness.clock.advance(59);
    assert_eq!(harness.control.purge_admin_tokens().await.unwrap(), 0);
    harness.clock.advance(1);
    assert_eq!(harness.control.purge_admin_tokens().await.unwrap(), 1);
    assert!(all_tokens(&harness).await.is_empty());
}

#[tokio::test]
async fn a_creator_makes_at_most_thirty_tokens_an_hour() {
    let harness = token_harness().await;
    let alice = stored_user(&harness, "alice").await;
    let console = console(&harness, &alice.id).await;
    for index in 0..30 {
        let created = console_call(
            &harness,
            &console,
            Method::POST,
            TOKENS,
            Some(&request(&format!("h{index}"), &["audit.read"])),
        )
        .await;
        assert_eq!(
            created.status,
            StatusCode::CREATED,
            "{index}: {}",
            created.text()
        );
        let id = created.json()["id"].as_str().unwrap().to_owned();
        let revoked = console_call(
            &harness,
            &console,
            Method::DELETE,
            &format!("{TOKENS}/{id}"),
            None,
        )
        .await;
        assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{index}");
    }
    let next = request("next", &["audit.read"]);

    let limited = console_call(&harness, &console, Method::POST, TOKENS, Some(&next)).await;
    harness.clock.advance(3_599);
    let edge = console_call(&harness, &console, Method::POST, TOKENS, Some(&next)).await;
    harness.clock.advance(1);
    let later = console_call(&harness, &console, Method::POST, TOKENS, Some(&next)).await;

    assert_status(&limited, StatusCode::TOO_MANY_REQUESTS, "too_many_requests");
    assert_eq!(limited.header("retry-after"), "3600");
    assert_status(&edge, StatusCode::TOO_MANY_REQUESTS, "too_many_requests");
    assert_eq!(edge.header("retry-after"), "1");
    assert_eq!(later.status, StatusCode::CREATED, "{}", later.text());
}

#[tokio::test]
async fn the_list_shows_live_and_recently_dead_tokens_newest_first_and_says_when_it_was_cut() {
    let harness = token_harness().await;
    for (id, age) in [("agedAAAAAAA", 7 * 86_400 + 1), ("recentAAAAA", 7 * 86_400)] {
        plant(
            &harness,
            Planted {
                creator: "creator-dead",
                id,
                scope: &["audit.read"],
                cidrs: &[],
                ttl_secs: 90 * DAY,
            },
        )
        .await;
        harness
            .store
            .admin_tokens()
            .revoke(id, harness.clock.now_secs(), 100)
            .await
            .unwrap();
        harness.clock.advance(age - 7 * 86_400);
    }
    harness.clock.advance(7 * 86_400);
    let alice = cli_login(&harness, Identity::alice()).await;
    let few = signed_call(&harness, &alice, Method::GET, TOKENS, b"").await;
    assert_eq!(few.status, StatusCode::OK, "{}", few.text());
    let listed = few.json();
    let ids: Vec<&str> = listed["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|token| token["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["recentAAAAA"]);
    assert_eq!(listed["truncated"], false);
    for index in 0..501_usize {
        let creator = format!("creator-{:02}", index / 20);
        let id = format!("bulk{index:07}");
        plant(
            &harness,
            Planted {
                creator: &creator,
                id: &id,
                scope: &["audit.read"],
                cidrs: &[],
                ttl_secs: DAY,
            },
        )
        .await;
        if index % 100 == 0 {
            harness.clock.advance(1);
        }
    }

    let reply = signed_call(&harness, &alice, Method::GET, TOKENS, b"").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    assert_eq!(body["truncated"], true);
    let tokens = body["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 500);
    let created: Vec<i64> = tokens
        .iter()
        .map(|token| token["created_at"].as_i64().unwrap())
        .collect();
    assert!(created.windows(2).all(|pair| pair[0] >= pair[1]));
    assert_eq!(tokens[0]["id"], "bulk0000500");
}
