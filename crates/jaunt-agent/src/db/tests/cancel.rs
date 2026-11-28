use std::time::Duration;

use jaunt_pgwire::BackendMessage;

use super::fake_pg::{FakePg, message};
use super::harness::{DbHarness, DbOptions, PgClient, fatal, packet, query};
use crate::runtime::tests::support::{Opened, UserCert};

const CANCEL_REQUEST: u32 = (1234 << 16) | 5678;

fn pair(greeting: &[BackendMessage]) -> (i32, Vec<u8>) {
    greeting
        .iter()
        .find_map(|message| match message {
            BackendMessage::BackendKeyData(key) => {
                Some((key.process_id(), key.secret_key().to_vec()))
            }
            _ => None,
        })
        .unwrap()
}

async fn cancel(harness: &DbHarness, session: &str, user: &UserCert, process_id: i32, key: &[u8]) {
    let (opened, mut client) = harness.connect_as(session, user).await;
    let mut body = process_id.to_be_bytes().to_vec();
    body.extend_from_slice(key);
    client.send(&packet(CANCEL_REQUEST, &body)).await;
    assert!(client.rest().await.is_empty());
    opened.finished().await;
}

async fn sleeping(harness: &DbHarness, session: &str) -> (Opened, PgClient, (i32, Vec<u8>)) {
    let (opened, mut client, greeting) = harness.login(session).await;
    client.send(&query("SLEEP")).await;
    harness
        .pg
        .wait("the query to reach the database", |seen| {
            !seen.messages.is_empty()
        })
        .await;
    (opened, client, pair(&greeting))
}

#[tokio::test]
async fn a_cancel_for_an_own_session_reaches_the_database_and_nothing_else() {
    let harness = DbHarness::with(DbOptions {
        key_bytes: 32,
        ..DbOptions::default()
    })
    .await;
    let (_opened, mut client, (process_id, key)) = sleeping(&harness, "s-busy").await;
    assert_eq!(key, harness.pg.secret_key(1));
    cancel(&harness, "s-cancel", &harness.user(), process_id, &key).await;
    let seen = harness
        .pg
        .wait("the cancel to arrive", |seen| !seen.cancels.is_empty())
        .await;
    assert_eq!(seen.cancels, [(FakePg::process_id(1), key)]);
    let answer = client.until_ready().await;
    assert_eq!(
        fatal(&answer).map(|(code, _)| code).as_deref(),
        Some("57014")
    );
    assert_eq!(harness.control.authorizations().len(), 1);
    assert!(
        harness
            .control
            .ends()
            .iter()
            .all(|end| end.session_id != "s-cancel")
    );
}

#[tokio::test]
async fn cancels_with_a_pair_of_another_user_or_an_unknown_pair_are_dropped_silently() {
    let harness = DbHarness::new().await;
    let (_opened, _client, (process_id, key)) = sleeping(&harness, "s-busy").await;
    let mut wrong = key.clone();
    wrong[0] ^= 1;
    cancel(
        &harness,
        "s-foreign",
        &harness.other_user(),
        process_id,
        &key,
    )
    .await;
    cancel(&harness, "s-wrong-key", &harness.user(), process_id, &wrong).await;
    cancel(
        &harness,
        "s-wrong-pid",
        &harness.user(),
        process_id + 1,
        &key,
    )
    .await;
    let seen = harness.pg.seen();
    assert!(seen.cancels.is_empty());
    assert_eq!(seen.connections, 1);
}

#[tokio::test]
async fn a_user_sends_at_most_ten_cancels_a_minute() {
    let harness = DbHarness::new().await;
    let (_opened, _client, (process_id, key)) = sleeping(&harness, "s-busy").await;
    let user = harness.user();
    for attempt in 0..10 {
        cancel(
            &harness,
            &format!("s-cancel-{attempt}"),
            &user,
            process_id,
            &key,
        )
        .await;
    }
    assert_eq!(harness.pg.seen().cancels.len(), 10);
    cancel(&harness, "s-eleventh", &user, process_id, &key).await;
    harness.clock.advance(Duration::from_secs(5));
    cancel(&harness, "s-after-five", &user, process_id, &key).await;
    assert_eq!(harness.pg.seen().cancels.len(), 10);
    harness.clock.advance(Duration::from_secs(1));
    cancel(&harness, "s-after-six", &user, process_id, &key).await;
    assert_eq!(harness.pg.seen().cancels.len(), 11);
}

#[tokio::test]
async fn the_pair_is_forgotten_when_its_session_ends() {
    let harness = DbHarness::new().await;
    let (opened, mut client, greeting) = harness.login("s-short").await;
    let (process_id, key) = pair(&greeting);
    assert_eq!(harness.handler.cancels().len(), 1);
    client.send(&message(b'X', &[])).await;
    assert!(client.rest().await.is_empty());
    opened.finished().await;
    harness.ended("s-short").await;
    assert_eq!(harness.handler.cancels().len(), 0);
    cancel(&harness, "s-late", &harness.user(), process_id, &key).await;
    assert!(harness.pg.seen().cancels.is_empty());
}
