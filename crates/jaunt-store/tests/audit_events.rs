use jaunt_store::{
    AuditCursor, AuditQuery, AuditRecord, MAX_AUDIT_PAGE, MAX_AUDIT_PAYLOAD_BYTES, Store,
    StoreError,
};
use tempfile::TempDir;

async fn fixture() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
    store.migrate().await.unwrap();
    (dir, store)
}

fn record(id: &str, time_ms: i64, event_type: &str, actor: &str) -> AuditRecord {
    AuditRecord {
        id: id.to_owned(),
        time_ms,
        event_type: event_type.to_owned(),
        actor: actor.to_owned(),
        node: None,
        session_id: None,
        policy_hash: None,
        payload: "{}".to_owned(),
        v: 1,
    }
}

fn ids(records: &[AuditRecord]) -> Vec<String> {
    records.iter().map(|record| record.id.clone()).collect()
}

#[tokio::test]
async fn a_batch_round_trips_and_a_repeated_id_is_ignored() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let mut first = record("a", 100, "login.started", "anonymous");
    first.node = Some("node-1".to_owned());
    first.session_id = Some("s-1".to_owned());
    first.policy_hash = Some("abc".to_owned());
    first.payload = "{\"login_id\":\"x\"}".to_owned();

    let inserted = events
        .append(&[first.clone(), record("b", 101, "cert.issued", "u-1")])
        .await
        .unwrap();
    let again = events.append(&[first.clone()]).await.unwrap();

    assert_eq!((inserted, again), (2, 0));
    let all = events.query(&AuditQuery::newest(10)).await.unwrap();
    assert_eq!(ids(&all), ["b", "a"]);
    assert_eq!(all[1], first);
}

#[tokio::test]
async fn invalid_records_are_refused_before_anything_is_written() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let mut oversized = record("big", 1, "login.started", "anonymous");
    oversized.payload = "x".repeat(MAX_AUDIT_PAYLOAD_BYTES + 1);
    let mut unversioned = record("v0", 1, "login.started", "anonymous");
    unversioned.v = 0;
    let cases = [
        record("", 1, "login.started", "anonymous"),
        record("no-type", 1, "", "anonymous"),
        record("no-actor", 1, "login.started", ""),
        oversized,
        unversioned,
    ];

    for bad in cases {
        let good = record("good", 1, "login.started", "anonymous");
        let result = events.append(&[good, bad]).await;
        assert!(matches!(result, Err(StoreError::InvalidInput(_))));
    }

    let stored = events.query(&AuditQuery::newest(10)).await.unwrap();
    assert!(stored.is_empty());
}

async fn find(
    events: &jaunt_store::AuditEvents,
    change: impl FnOnce(&mut AuditQuery),
) -> Vec<String> {
    let mut query = AuditQuery::newest(10);
    change(&mut query);
    ids(&events.query(&query).await.unwrap())
}

#[tokio::test]
async fn filters_combine_and_a_type_prefix_treats_wildcard_characters_literally() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let mut routed = record("1", 10, "session.routed", "u-1");
    routed.node = Some("n-1".to_owned());
    routed.session_id = Some("s-1".to_owned());
    let mut started = record("2", 20, "session.start", "u-1");
    started.node = Some("n-2".to_owned());
    started.session_id = Some("s-2".to_owned());
    events
        .append(&[
            routed,
            started,
            record("3", 30, "login.device.code_failed", "anonymous"),
            record("4", 40, "login.denied", "anonymous"),
            record("5", 50, "loginXdenied", "anonymous"),
        ])
        .await
        .unwrap();

    let prefix =
        |text: &'static str| move |q: &mut AuditQuery| q.type_prefix = Some(text.to_owned());
    assert_eq!(find(&events, prefix("login.")).await, ["4", "3"]);
    assert_eq!(find(&events, prefix("login.device.code_")).await, ["3"]);
    assert!(find(&events, prefix("login.device.code%")).await.is_empty());
    assert!(
        find(&events, prefix("login.device.code_f_iled"))
            .await
            .is_empty()
    );
    assert_eq!(
        find(&events, |q| q.actor = Some("u-1".to_owned())).await,
        ["2", "1"]
    );
    assert_eq!(
        find(&events, |q| q.node = Some("n-2".to_owned())).await,
        ["2"]
    );
    assert_eq!(
        find(&events, |q| q.session_id = Some("s-1".to_owned())).await,
        ["1"]
    );
    let window = |q: &mut AuditQuery| {
        q.from_ms = Some(20);
        q.to_ms = Some(40);
    };
    assert_eq!(find(&events, window).await, ["3", "2"]);
    let combined = |q: &mut AuditQuery| {
        q.actor = Some("u-1".to_owned());
        q.type_prefix = Some("session.s".to_owned());
    };
    assert_eq!(find(&events, combined).await, ["2"]);
}

#[tokio::test]
async fn keyset_pagination_visits_every_event_once_even_with_one_timestamp_and_new_inserts() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let mut batch: Vec<AuditRecord> = (0..7)
        .map(|index| record(&format!("same-{index}"), 500, "gate.connect", "anonymous"))
        .collect();
    batch.push(record("old", 400, "gate.connect", "anonymous"));
    batch.push(record("new", 600, "gate.connect", "anonymous"));
    events.append(&batch).await.unwrap();

    let mut seen: Vec<String> = Vec::new();
    let mut after = None;
    let mut pages = 0;
    loop {
        let mut query = AuditQuery::newest(4);
        query.after = after.clone();
        let page = events.query(&query).await.unwrap();
        pages += 1;
        seen.extend(ids(&page));
        if pages == 1 {
            events
                .append(&[
                    record("late-newest", 9_000, "gate.connect", "anonymous"),
                    record("late-oldest", 1, "gate.connect", "anonymous"),
                ])
                .await
                .unwrap();
        }
        match page.last() {
            Some(last) if page.len() == 4 => {
                after = Some(AuditCursor {
                    time_ms: last.time_ms,
                    id: last.id.clone(),
                });
            }
            _ => break,
        }
    }

    let mut expected = vec!["new".to_owned()];
    expected.extend((0..7).rev().map(|index| format!("same-{index}")));
    expected.extend(["old", "late-oldest"].map(str::to_owned));
    assert_eq!(seen, expected);
    assert_eq!(pages, 3);
}

#[tokio::test]
async fn the_page_size_must_be_in_range() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();

    for limit in [0, MAX_AUDIT_PAGE + 1] {
        let result = events.query(&AuditQuery::newest(limit)).await;
        assert!(
            matches!(result, Err(StoreError::InvalidInput(_))),
            "{limit}"
        );
    }
    assert!(
        events
            .query(&AuditQuery::newest(MAX_AUDIT_PAGE))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn pruning_deletes_only_events_before_the_cutoff_in_bounded_batches() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let batch: Vec<AuditRecord> = (0..5)
        .map(|index| {
            record(
                &format!("e{index}"),
                100 + index,
                "gate.connect",
                "anonymous",
            )
        })
        .collect();
    events.append(&batch).await.unwrap();

    let first = events.delete_before(103, 2).await.unwrap();
    let second = events.delete_before(103, 2).await.unwrap();
    let third = events.delete_before(103, 2).await.unwrap();

    assert_eq!((first, second, third), (2, 1, 0));
    let left = events.query(&AuditQuery::newest(10)).await.unwrap();
    assert_eq!(ids(&left), ["e4", "e3"]);
    assert!(matches!(
        events.delete_before(103, 0).await,
        Err(StoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn the_newest_time_is_none_for_an_empty_table_and_the_maximum_otherwise() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    assert_eq!(events.newest_time_ms().await.unwrap(), None);

    events
        .append(&[
            record("a", 30, "gate.connect", "anonymous"),
            record("b", 90, "gate.connect", "anonymous"),
            record("c", 10, "gate.connect", "anonymous"),
        ])
        .await
        .unwrap();

    assert_eq!(events.newest_time_ms().await.unwrap(), Some(90));
}

#[tokio::test]
async fn the_keyset_query_walks_the_time_index_backwards_without_a_temporary_sort() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let batch: Vec<AuditRecord> = (0..200)
        .map(|index| {
            record(
                &format!("e{index:03}"),
                1000 + index / 3,
                "gate.connect",
                "anonymous",
            )
        })
        .collect();
    events.append(&batch).await.unwrap();
    let mut query = AuditQuery::newest(50);
    query.after = Some(AuditCursor {
        time_ms: 1030,
        id: "e090".to_owned(),
    });

    let plan = events.query_plan(&query).await.unwrap();

    let text = plan.join(" | ");
    assert!(text.contains("audit_events_time_ms_id_idx"), "{text}");
    assert!(!text.to_uppercase().contains("TEMP B-TREE"), "{text}");
    assert!(!text.contains("SCAN audit_events USING"), "{text}");
}

#[tokio::test]
async fn the_counts_cover_the_whole_table_and_the_rows_before_a_cutoff() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    assert_eq!(events.count_all().await.unwrap(), 0);
    assert_eq!(events.count_before(100).await.unwrap(), 0);

    events
        .append(&[
            record("a", 10, "gate.connect", "anonymous"),
            record("b", 20, "gate.connect", "anonymous"),
            record("c", 30, "gate.connect", "anonymous"),
        ])
        .await
        .unwrap();

    assert_eq!(events.count_all().await.unwrap(), 3);
    assert_eq!(events.count_before(20).await.unwrap(), 1);
    assert_eq!(events.count_before(31).await.unwrap(), 3);
}

#[tokio::test]
async fn a_reference_in_the_payload_is_indexed_and_found_with_the_other_filters() {
    let (_dir, store) = fixture().await;
    let events = store.audit_events();
    let with = |id: &str, time_ms: i64, event_type: &str, actor: &str, reference: &str| {
        let mut made = record(id, time_ms, event_type, actor);
        made.payload = format!("{{\"reason\":\"denied\",\"ref\":\"{reference}\"}}");
        made
    };
    events
        .append(&[
            with("a", 100, "terminal.denied", "u-1", "D-0000ABCD"),
            with("b", 200, "terminal.closed", "u-2", "D-0000ABCD"),
            with("c", 300, "host_user.refused", "u-1", "H-9D0311FE"),
            with("d", 400, "terminal.denied", "u-1", "D-0000abcd"),
            with("e", 500, "terminal.denied", "u-1", "D-0000ABCDX"),
            record("f", 600, "terminal.denied", "u-1"),
        ])
        .await
        .unwrap();
    let found = |reference: &str, adjust: &dyn Fn(&mut AuditQuery)| {
        let mut query = AuditQuery::newest(10);
        query.reference = Some(reference.to_owned());
        adjust(&mut query);
        let events = events.clone();
        async move { ids(&events.query(&query).await.unwrap()) }
    };

    assert_eq!(found("D-0000ABCD", &|_| {}).await, ["b", "a"]);
    assert_eq!(found("H-9D0311FE", &|_| {}).await, ["c"]);
    assert!(found("D-FFFFFFFF", &|_| {}).await.is_empty());
    assert_eq!(
        found("D-0000ABCD", &|query| query.actor = Some("u-1".to_owned())).await,
        ["a"]
    );
    assert_eq!(
        found("D-0000ABCD", &|query| {
            query.type_prefix = Some("terminal.closed".to_owned());
        })
        .await,
        ["b"]
    );
    assert_eq!(
        found("D-0000ABCD", &|query| query.from_ms = Some(150)).await,
        ["b"]
    );
    let mut invalid = AuditQuery::newest(10);
    invalid.reference = Some("D-0000abcd".to_owned());
    assert!(matches!(
        events.query(&invalid).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut planned = AuditQuery::newest(10);
    planned.reference = Some("D-0000ABCD".to_owned());
    let plan = events.query_plan(&planned).await.unwrap().join(" | ");
    assert!(
        plan.contains("audit_events_reference_time_ms_idx"),
        "{plan}"
    );
}
