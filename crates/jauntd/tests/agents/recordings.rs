use std::time::SystemTime;

use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingKey, RecordingSink};
use jaunt_store::{ActivateSession, NewCertificate, NewSession, NewUser, RecordingState};
use jauntd::recordings::RecordingsSection;

use crate::support::{Harness, Options, unix_secs};

const STRAY: &str = "8c7d6e5f-4a3b-4c2d-9e1f-0a1b2c3d4e5f";

#[tokio::test]
async fn startup_stores_interrupted_uploads_before_it_removes_leftover_parts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("recordings");
    let settings = RecordingsSection {
        dir: Some(root.clone()),
        min_free_bytes: 0,
        ..RecordingsSection::default()
    }
    .into_settings()
    .unwrap()
    .unwrap();
    let harness = Harness::start(Options {
        recordings: Some(settings),
        ..Options::default()
    })
    .await;
    let enrolled = harness.enroll("web-01").await;
    let store = &harness.store;
    let now = i64::try_from(unix_secs(SystemTime::now())).unwrap();
    let user_id = store
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
            now,
        )
        .await
        .unwrap()
        .id;
    let serial = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user_id.clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:alice@example.com:{serial}"),
            valid_after: now - 60,
            valid_before: now + 3600,
            issued_at: now,
        })
        .await
        .unwrap();
    let session = store
        .sessions()
        .create(
            &NewSession {
                user_id: user_id.clone(),
                serial,
                node_id: enrolled.node_id.clone(),
                ttl_secs: 60,
            },
            now,
        )
        .await
        .unwrap();
    let active = store
        .sessions()
        .activate(ActivateSession {
            id: &session.id,
            node_id: &enrolled.node_id,
            user_id: &user_id,
            serial,
            login: "deploy",
            max_duration_secs: 3600,
            pty: true,
            record_input: false,
            now,
        })
        .await
        .unwrap()
        .unwrap();
    store
        .recordings()
        .begin(&session.id, &enrolled.node_id, now)
        .await
        .unwrap();
    let previous_run = DirectorySink::open_existing(
        &root,
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1024,
        },
    )
    .unwrap();
    let key = RecordingKey::new(&session.id, active.authorized_at.unwrap()).unwrap();
    let mut staged = previous_run.begin(&key).unwrap();
    staged.write(0, b"zero\n").unwrap();
    let prefix = staged.prefix_sha256();
    std::mem::forget(staged);
    store
        .recordings()
        .record_progress(&session.id, 1, 5, &prefix)
        .await
        .unwrap();
    let month = root.join(key.location()).parent().unwrap().to_path_buf();
    std::fs::write(month.join(format!("{STRAY}.cast.part")), b"stray").unwrap();

    jauntd::recordings::recover(harness.recordings.as_ref().unwrap(), &harness.control)
        .await
        .unwrap();

    let mut names: Vec<String> = std::fs::read_dir(&month)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            format!("{}.cast", session.id),
            format!("{}.manifest.json", session.id)
        ]
    );
    let row = store.recordings().get(&session.id).await.unwrap().unwrap();
    assert_eq!((row.state, row.chunks), (RecordingState::Incomplete, 1));
}
