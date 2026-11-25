use jaunt_store::{
    ActivateSession, NewCertificate, NewSession, NewUser, Reconciled, RecordingCursor,
    RecordingState, SessionState, Store, StoreError, StoredRecording, is_session_id,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 1_000;
const NODE: &str = "node-a";
const OTHER_NODE: &str = "node-b";

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', 'active', 'cli:root', 1)";

struct Fixture {
    _dir: TempDir,
    store: Store,
    user_id: String,
    serial: i64,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();
    let raw = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    for (id, name) in [(NODE, "web-a"), (OTHER_NODE, "web-b")] {
        sqlx::query(RAW_NODE)
            .bind(id)
            .bind(name)
            .execute(&raw)
            .await
            .unwrap();
    }
    let user = store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "alice".to_owned(),
                email: "alice@example.com".to_owned(),
                username: "alice".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            NOW,
        )
        .await
        .unwrap();
    let serial = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user.id.clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:alice@example.com:{serial}"),
            valid_after: NOW - 120,
            valid_before: NOW + 3600,
            issued_at: NOW,
        })
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        user_id: user.id,
        serial,
    }
}

impl Fixture {
    async fn routed(&self, node_id: &str) -> String {
        self.store
            .sessions()
            .create(
                &NewSession {
                    user_id: self.user_id.clone(),
                    serial: self.serial,
                    node_id: node_id.to_owned(),
                    ttl_secs: 60,
                },
                NOW,
            )
            .await
            .unwrap()
            .id
    }

    async fn active(&self, node_id: &str, pty: bool, record_input: bool) -> String {
        let id = self.routed(node_id).await;
        self.store
            .sessions()
            .activate(ActivateSession {
                id: &id,
                node_id,
                user_id: &self.user_id,
                serial: self.serial,
                login: "deploy",
                max_duration_secs: 3600,
                pty,
                record_input,
                now: NOW + 1,
            })
            .await
            .unwrap()
            .unwrap();
        id
    }
}

fn stored<'a>(session_id: &'a str, node_id: &'a str) -> StoredRecording<'a> {
    StoredRecording {
        session_id,
        node_id,
        chunks: 3,
        raw_bytes: 300,
        digest: Some("d1"),
        input_recorded: true,
        dropped_chunks: 0,
        location: "1970/01/x",
        cast_sha256: Some("c1"),
        manifest_sha256: "m1",
        now: NOW + 9,
    }
}

#[tokio::test]
async fn the_session_id_format_is_exactly_what_the_store_generates() {
    let fixture = fixture().await;
    let id = fixture.routed(NODE).await;
    assert!(is_session_id(&id), "{id}");
    let mut too_long = id.clone();
    too_long.push('0');
    for bad in [
        String::new(),
        id.to_uppercase(),
        id.replace('-', "_"),
        too_long,
        id[..35].to_owned(),
        format!("../{}", &id[3..]),
        format!("{}\0", &id[..35]),
        format!("{}é", &id[..34]),
        "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c1g".to_owned(),
    ] {
        assert!(!is_session_id(&bad), "{bad:?}");
    }
}

#[tokio::test]
async fn activation_stores_the_permissions_and_the_target_joins_the_recording() {
    let fixture = fixture().await;
    let recordings = fixture.store.recordings();
    let routed = fixture.routed(NODE).await;
    let target = recordings.upload_target(&routed).await.unwrap().unwrap();
    assert_eq!(target.state, SessionState::Routed);
    assert_eq!((target.pty, target.record_input), (None, None));
    assert!(target.recording.is_none());

    let active = fixture.active(NODE, false, true).await;
    let target = recordings.upload_target(&active).await.unwrap().unwrap();
    assert_eq!(target.state, SessionState::Active);
    assert_eq!((target.pty, target.record_input), (Some(false), Some(true)));
    assert_eq!(target.node_id, NODE);
    assert_eq!(target.user_id, fixture.user_id);
    assert_eq!(target.login.as_deref(), Some("deploy"));
    assert_eq!(target.authorized_at, Some(NOW + 1));

    recordings.begin(&active, NODE, NOW + 2).await.unwrap();
    let joined = recordings.upload_target(&active).await.unwrap().unwrap();
    assert_eq!(
        joined.recording.map(|recording| recording.state),
        Some(RecordingState::Receiving)
    );
    assert!(recordings.upload_target("missing").await.unwrap().is_none());
}

#[tokio::test]
async fn begin_inserts_once_and_state_changes_only_leave_receiving() {
    let fixture = fixture().await;
    let recordings = fixture.store.recordings();
    let id = fixture.active(NODE, true, false).await;
    let begun = recordings.begin(&id, NODE, NOW + 2).await.unwrap();
    assert_eq!(begun.state, RecordingState::Receiving);
    assert_eq!(begun.created_at, NOW + 2);
    let again = recordings.begin(&id, NODE, NOW + 50).await.unwrap();
    assert_eq!(again, begun);

    assert!(
        !recordings
            .mark_complete(&stored(&id, OTHER_NODE))
            .await
            .unwrap()
    );
    assert!(recordings.mark_complete(&stored(&id, NODE)).await.unwrap());
    assert!(
        !recordings
            .mark_incomplete(&stored(&id, NODE))
            .await
            .unwrap()
    );
    assert!(!recordings.mark_failed(&id, NOW + 10).await.unwrap());
    let done = recordings.get(&id).await.unwrap().unwrap();
    assert_eq!(done.state, RecordingState::Complete);
    assert_eq!((done.chunks, done.raw_bytes), (3, 300));
    assert_eq!(done.location.as_deref(), Some("1970/01/x"));
    assert_eq!(done.manifest_sha256.as_deref(), Some("m1"));
    assert_eq!(done.completed_at, Some(NOW + 9));
    assert!(!done.incomplete && done.input_recorded);
    assert_eq!(
        recordings.begin(&id, NODE, NOW + 60).await.unwrap().state,
        RecordingState::Complete
    );

    let partial = fixture.active(NODE, true, false).await;
    recordings.begin(&partial, NODE, NOW + 2).await.unwrap();
    assert!(
        recordings
            .mark_incomplete(&stored(&partial, NODE))
            .await
            .unwrap()
    );
    let partial = recordings.get(&partial).await.unwrap().unwrap();
    assert_eq!(partial.state, RecordingState::Incomplete);
    assert!(partial.incomplete);

    let overflow = StoredRecording {
        chunks: u64::MAX,
        ..stored(&id, NODE)
    };
    assert!(matches!(
        recordings.mark_complete(&overflow).await,
        Err(StoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn progress_is_tracked_while_receiving_and_a_salvaged_prefix_is_stored_as_incomplete() {
    let fixture = fixture().await;
    let recordings = fixture.store.recordings();
    let receiving = fixture.active(NODE, true, false).await;
    let failed = fixture.active(NODE, true, false).await;
    for id in [&receiving, &failed] {
        recordings.begin(id, NODE, NOW + 2).await.unwrap();
    }
    assert!(recordings.mark_failed(&failed, NOW + 3).await.unwrap());
    assert!(
        recordings
            .record_progress(&receiving, 4, 4096, "p4")
            .await
            .unwrap()
    );
    assert!(
        !recordings
            .record_progress(&failed, 4, 4096, "p4")
            .await
            .unwrap()
    );

    let listed: Vec<(String, u64, u64, Option<String>)> = recordings
        .list_receiving()
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                row.session_id,
                row.chunks,
                row.raw_bytes,
                row.progress_sha256,
            )
        })
        .collect();
    assert_eq!(
        listed,
        [(receiving.clone(), 4, 4096, Some("p4".to_owned()))]
    );

    let salvage = StoredRecording {
        digest: None,
        ..stored(&receiving, NODE)
    };
    assert!(recordings.mark_salvaged(&salvage).await.unwrap());
    let row = recordings.get(&receiving).await.unwrap().unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    assert!(row.salvaged && row.incomplete && row.digest.is_none());
    assert!(recordings.list_receiving().await.unwrap().is_empty());
    assert!(
        !recordings
            .record_progress(&receiving, 5, 5000, "p5")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn reconciling_the_two_incomplete_flags_happens_once_and_keeps_the_stricter() {
    let fixture = fixture().await;
    let recordings = fixture.store.recordings();
    let cases = [
        (false, false, None, RecordingState::Complete),
        (false, true, Some((false, true)), RecordingState::Incomplete),
        (true, false, Some((true, false)), RecordingState::Incomplete),
        (true, true, None, RecordingState::Incomplete),
    ];
    for (manifest_incomplete, session_incomplete, disagreement, final_state) in cases {
        let id = fixture.active(NODE, true, false).await;
        recordings.begin(&id, NODE, NOW + 2).await.unwrap();
        let record = stored(&id, NODE);
        if manifest_incomplete {
            recordings.mark_incomplete(&record).await.unwrap();
        } else {
            recordings.mark_complete(&record).await.unwrap();
        }
        let reconciled = recordings
            .reconcile(&id, session_incomplete)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reconciled,
            Reconciled {
                manifest_incomplete,
                session_incomplete,
                state: final_state,
            }
        );
        assert_eq!(
            (reconciled.manifest_incomplete != reconciled.session_incomplete)
                .then_some((manifest_incomplete, session_incomplete)),
            disagreement
        );
        assert_eq!(
            recordings
                .reconcile(&id, !session_incomplete)
                .await
                .unwrap(),
            None
        );
        let row = recordings.get(&id).await.unwrap().unwrap();
        assert_eq!(row.state, final_state);
        assert_eq!(row.incomplete, final_state == RecordingState::Incomplete);
        assert_eq!(row.session_incomplete, Some(session_incomplete));
    }

    let receiving = fixture.active(NODE, true, false).await;
    recordings.begin(&receiving, NODE, NOW + 2).await.unwrap();
    assert_eq!(recordings.reconcile(&receiving, true).await.unwrap(), None);
    assert_eq!(recordings.reconcile("missing", true).await.unwrap(), None);
}

#[tokio::test]
async fn listing_a_nodes_recordings_pages_by_creation_time_and_id() {
    let fixture = fixture().await;
    let recordings = fixture.store.recordings();
    let mut expected = Vec::new();
    for offset in [5, 1, 3, 3, 2] {
        let id = fixture.active(NODE, true, false).await;
        recordings.begin(&id, NODE, NOW + offset).await.unwrap();
        expected.push((NOW + offset, id));
    }
    let foreign = fixture.active(OTHER_NODE, true, false).await;
    recordings.begin(&foreign, OTHER_NODE, NOW).await.unwrap();
    expected.sort();

    let mut seen = Vec::new();
    let mut cursor: Option<RecordingCursor> = None;
    loop {
        let page = recordings
            .list_for_node(NODE, cursor.as_ref(), 2)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2);
        let last = page.last().unwrap();
        cursor = Some(RecordingCursor {
            created_at: last.created_at,
            session_id: last.session_id.clone(),
        });
        seen.extend(page.into_iter().map(|row| (row.created_at, row.session_id)));
    }
    assert_eq!(seen, expected);
    for limit in [0, 1001] {
        assert!(matches!(
            recordings.list_for_node(NODE, None, limit).await,
            Err(StoreError::InvalidInput(_))
        ));
    }
}
