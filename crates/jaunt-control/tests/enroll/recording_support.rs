use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_audit::{
    AuditEvent, Committed, RecordingKey, RecordingSink, RecordingStoreError, StagedRecording,
    StoredRecording,
};
use jaunt_proto::{AuthorizeDecision, RouteDecision, SessionEnd};
use jaunt_record::{
    Assembler, Chunk, Clock, Limits, MANIFEST_VERSION, MetadataOnly, Recorder, RecorderConfig,
    SessionKind, SessionManifest, Sink, SinkError,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::session_support::{
    Holder, LOGIN, NODE_NAME, apply_policy, authorize, end, holder, node, raw_pool, role, route,
    routed,
};
use crate::support::{Harness, Options, RecordingOptions, Reply, request_raw, send};

pub struct Steps(AtomicU64);

impl Clock for Steps {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.fetch_add(7, Ordering::SeqCst))
    }
}

pub struct SplitMix(u64);

impl SplitMix {
    pub fn new(seed: u64) -> SplitMix {
        SplitMix(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    pub fn text(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| b"abcdefghijklmnopqrstuvwxyz0123456789 \n"[self.below(38)])
            .collect()
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            items.swap(index, self.below(index + 1));
        }
    }
}

pub struct Rec {
    pub harness: Harness,
    pub alice: Holder,
    pub node_id: String,
}

pub struct Session {
    pub id: String,
    pub node_id: String,
    pub user_id: String,
}

pub async fn rec(options: RecordingOptions, record_input: bool) -> Rec {
    let harness = Harness::with(Options {
        recordings: Some(options),
        ..Options::default()
    })
    .await;
    let node_id = node(&harness, NODE_NAME).await;
    apply_policy(&harness, &[role("ops", "ops", false, record_input)]);
    let alice = holder(&harness, "alice", &["ops"]).await;
    Rec {
        harness,
        alice,
        node_id,
    }
}

pub async fn default_rec() -> Rec {
    rec(RecordingOptions::default(), true).await
}

impl Rec {
    pub async fn routed(&self) -> Session {
        Session {
            id: routed(&self.harness, &self.alice).await,
            node_id: self.node_id.clone(),
            user_id: self.alice.user_id.clone(),
        }
    }

    pub async fn active(&self) -> Session {
        self.active_on(NODE_NAME, &self.node_id).await
    }

    pub async fn active_on(&self, node_name: &str, node_id: &str) -> Session {
        let RouteDecision::Allow { session_id, .. } =
            route(&self.harness, self.alice.route_to(node_name)).await
        else {
            panic!("the route to {node_name} was denied");
        };
        let decision = authorize(
            &self.harness,
            node_id,
            self.alice.authorize(&session_id, LOGIN),
        )
        .await;
        assert!(matches!(decision, AuthorizeDecision::Allow { .. }));
        Session {
            id: session_id,
            node_id: node_id.to_owned(),
            user_id: self.alice.user_id.clone(),
        }
    }

    pub async fn end(&self, session: &Session, recording_incomplete: bool) {
        end(
            &self.harness,
            &session.node_id,
            SessionEnd {
                session_id: session.id.clone(),
                exit_status: Some(0),
                bytes_in: 1,
                bytes_out: 2,
                recording_incomplete,
            },
        )
        .await;
    }

    pub async fn without_pty(&self, session: &Session) {
        sqlx::query("UPDATE sessions SET pty = 0 WHERE id = ?")
            .bind(&session.id)
            .execute(&raw_pool(&self.harness).await)
            .await
            .unwrap();
    }

    pub async fn legacy_permissions(&self, session: &Session) {
        sqlx::query("UPDATE sessions SET pty = NULL, record_input = NULL WHERE id = ?")
            .bind(&session.id)
            .execute(&raw_pool(&self.harness).await)
            .await
            .unwrap();
    }

    pub async fn post(&self, node_id: Option<&str>, path: &str, body: Vec<u8>) -> Reply {
        send(
            self.harness.agent_router.clone(),
            request_raw(path, "application/json", body, None, node_id),
        )
        .await
    }

    pub async fn chunk(&self, session: &Session, body: &Value) -> Reply {
        self.chunk_as(&session.node_id, &session.id, body).await
    }

    pub async fn chunk_as(&self, node_id: &str, session_id: &str, body: &Value) -> Reply {
        self.post(
            Some(node_id),
            &format!("/v1/agent/recordings/{session_id}/chunks"),
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }

    pub async fn complete(&self, session: &Session, manifest: &SessionManifest) -> Reply {
        self.post(
            Some(&session.node_id),
            &format!("/v1/agent/recordings/{}/complete", session.id),
            serde_json::to_vec(&json!({ "manifest": manifest })).unwrap(),
        )
        .await
    }

    pub fn files(&self) -> Vec<String> {
        let mut found = Vec::new();
        walk(
            &self.harness.recordings_dir,
            &self.harness.recordings_dir,
            &mut found,
        );
        found.sort();
        found
    }

    pub async fn row(&self, session: &Session) -> Option<jaunt_store::Recording> {
        self.harness
            .store
            .recordings()
            .get(&session.id)
            .await
            .unwrap()
    }

    pub async fn key(&self, session: &Session) -> RecordingKey {
        let stored = self
            .harness
            .store
            .sessions()
            .get(&session.id)
            .await
            .unwrap()
            .unwrap();
        RecordingKey::new(&session.id, stored.authorized_at.unwrap()).unwrap()
    }

    pub fn sink(&self) -> Arc<dyn RecordingSink> {
        Arc::new(
            jaunt_audit::DirectorySink::open_existing(
                &self.harness.recordings_dir,
                jaunt_audit::DirectoryLimits::default(),
            )
            .unwrap(),
        )
    }
}

pub fn files_in(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();
    found
}

fn walk(root: &Path, dir: &Path, found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path: PathBuf = entry.unwrap().path();
        if path.is_dir() {
            walk(root, &path, found);
        } else {
            found.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
}

pub fn recorder(session: &Session, record_input: bool) -> Recorder {
    Recorder::new(
        RecorderConfig {
            session_id: session.id.clone(),
            kind: SessionKind::Shell,
            node: session.node_id.clone(),
            user: session.user_id.clone(),
            login: LOGIN.to_owned(),
            command: None,
            started_at: 1_700_000_000,
            width: 80,
            height: 24,
            shell: "/bin/bash".to_owned(),
            term: "xterm-256color".to_owned(),
            record_input,
        },
        Box::new(Steps(AtomicU64::new(0))),
    )
    .unwrap()
}

pub fn recorded(session: &Session, raw_target: usize, seed: u64) -> (Vec<Chunk>, SessionManifest) {
    let mut random = SplitMix::new(seed);
    let mut recorder = recorder(session, true);
    let mut chunks = Vec::new();
    let mut produced = 0;
    while produced < raw_target {
        let len = 1 + random.below(8 * 1024);
        let piece = random.text(len);
        produced += piece.len();
        if random.below(16) == 0 {
            recorder.push_input(&piece[..piece.len().min(16)]).unwrap();
        }
        recorder.push_output(&piece).unwrap();
        if random.below(64) == 0 {
            recorder.flush().unwrap();
        }
        chunks.extend(recorder.take_chunks());
    }
    let manifest = recorder.finish(Some(0), 1_700_000_100).unwrap();
    chunks.extend(recorder.take_chunks());
    (chunks, manifest)
}

pub fn metadata_only(session: &Session, kind: SessionKind) -> SessionManifest {
    Recorder::metadata_only(MetadataOnly {
        session_id: session.id.clone(),
        kind,
        node: session.node_id.clone(),
        user: session.user_id.clone(),
        login: LOGIN.to_owned(),
        command: (kind == SessionKind::Exec).then(|| "uptime".to_owned()),
        started_at: 1_700_000_000,
        ended_at: Some(1_700_000_010),
        exit_status: Some(0),
        bytes_out: 5,
        bytes_in: 0,
    })
    .unwrap()
}

pub fn wire(chunk: &Chunk) -> Value {
    json!({
        "seq": chunk.seq,
        "raw_len": chunk.raw_len,
        "sha256": chunk.sha256,
        "is_last": chunk.is_last,
        "data": STANDARD.encode(&chunk.compressed),
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn crafted(session_id: &str, seq: u64, raw: &[u8], is_last: bool) -> Chunk {
    let compressed = zstd::bulk::compress(raw, 3).unwrap();
    Chunk {
        session_id: session_id.to_owned(),
        seq,
        raw_len: u64::try_from(raw.len()).unwrap(),
        sha256: hex(&Sha256::digest(&compressed)),
        compressed,
        is_last,
    }
}

pub fn digest_of(chunks: &[Chunk]) -> String {
    let mut hasher = Sha256::new();
    let mut ordered: Vec<&Chunk> = chunks.iter().collect();
    ordered.sort_by_key(|chunk| chunk.seq);
    for chunk in ordered {
        hasher.update(Sha256::digest(&chunk.compressed));
    }
    hex(&hasher.finalize())
}

pub fn manifest_for(session: &Session, chunks: &[Chunk]) -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: session.id.clone(),
        kind: SessionKind::Shell,
        node: session.node_id.clone(),
        user: session.user_id.clone(),
        login: LOGIN.to_owned(),
        started_at: 1_700_000_000,
        ended_at: Some(1_700_000_100),
        exit_status: Some(0),
        command: None,
        bytes_out: 1,
        bytes_in: 0,
        input_recorded: false,
        chunks: u64::try_from(chunks.len()).unwrap(),
        raw_bytes: chunks.iter().map(|chunk| chunk.raw_len).sum(),
        incomplete: false,
        dropped_chunks: 0,
        digest: Some(digest_of(chunks)),
    }
}

struct Collected(Vec<u8>);

impl Sink for Collected {
    fn write(&mut self, _: u64, raw: &[u8]) -> Result<(), SinkError> {
        self.0.extend_from_slice(raw);
        Ok(())
    }
}

pub fn cast_of(session_id: &str, chunks: &[Chunk]) -> Vec<u8> {
    let mut ordered: Vec<&Chunk> = chunks.iter().collect();
    ordered.sort_by_key(|chunk| chunk.seq);
    let mut assembler = Assembler::new(session_id, Limits::default());
    let mut collected = Collected(Vec::new());
    for chunk in ordered {
        assembler.accept(chunk, &mut collected).unwrap();
    }
    collected.0
}

pub fn named<'a>(events: &'a [Arc<AuditEvent>], name: &str) -> Vec<&'a AuditEvent> {
    events
        .iter()
        .filter(|event| event.kind().name() == name)
        .map(Arc::as_ref)
        .collect()
}

pub fn reasons(events: &[Arc<AuditEvent>]) -> Vec<String> {
    named(events, "recording.rejected")
        .iter()
        .map(|event| event.text("reason").unwrap().to_owned())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Write,
    Commit,
}

#[derive(Default)]
pub struct Gate {
    armed: std::sync::Mutex<Option<Stage>>,
    entered: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    opened: std::sync::Condvar,
    fail_commit: std::sync::atomic::AtomicBool,
    unavailable_commits: std::sync::atomic::AtomicU64,
    commit_attempts: std::sync::atomic::AtomicU64,
    unavailable_opens: std::sync::atomic::AtomicU64,
    existing_commits: std::sync::atomic::AtomicU64,
    on_commit: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl Gate {
    pub fn fail_next_commit(&self) {
        self.fail_commit.store(true, Ordering::SeqCst);
    }

    pub fn unavailable_for(&self, attempts: u64) {
        self.unavailable_commits.store(attempts, Ordering::SeqCst);
    }

    pub fn existing_for(&self, attempts: u64) {
        self.existing_commits.store(attempts, Ordering::SeqCst);
    }

    pub fn on_commit(&self, action: Arc<dyn Fn() + Send + Sync>) {
        *self.on_commit.lock().unwrap() = Some(action);
    }

    pub fn unavailable_opens_for(&self, attempts: u64) {
        self.unavailable_opens.store(attempts, Ordering::SeqCst);
    }

    pub fn commit_attempts(&self) -> u64 {
        self.commit_attempts.load(Ordering::SeqCst)
    }

    pub fn arm(&self, stage: Stage) {
        *self.armed.lock().unwrap() = Some(stage);
        *self.released.lock().unwrap() = false;
    }

    pub async fn entered(&self) {
        self.entered.notified().await;
    }

    pub fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.opened.notify_all();
    }

    fn pass(&self, stage: Stage) {
        let armed = {
            let mut armed = self.armed.lock().unwrap();
            if *armed == Some(stage) {
                *armed = None;
                true
            } else {
                false
            }
        };
        if armed {
            self.entered.notify_one();
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.opened.wait(released).unwrap();
            }
        }
    }

    pub fn wrapper(self: &Arc<Self>) -> crate::support::SinkWrapper {
        let gate = self.clone();
        Arc::new(move |inner| {
            Arc::new(GatedSink {
                inner,
                gate: gate.clone(),
            }) as Arc<dyn RecordingSink>
        })
    }
}

struct GatedSink {
    inner: Arc<dyn RecordingSink>,
    gate: Arc<Gate>,
}

struct GatedStaged {
    inner: Box<dyn StagedRecording>,
    gate: Arc<Gate>,
}

impl RecordingSink for GatedSink {
    fn begin(&self, key: &RecordingKey) -> Result<Box<dyn StagedRecording>, RecordingStoreError> {
        Ok(Box::new(GatedStaged {
            inner: self.inner.begin(key)?,
            gate: self.gate.clone(),
        }))
    }

    fn holds_staged_manifest(&self, key: &RecordingKey) -> bool {
        self.inner.holds_staged_manifest(key)
    }

    fn holds_staged_part(&self, key: &RecordingKey) -> bool {
        self.inner.holds_staged_part(key)
    }

    fn open(&self, key: &RecordingKey) -> Result<Option<StoredRecording>, RecordingStoreError> {
        let remaining = self.gate.unavailable_opens.load(Ordering::SeqCst);
        if remaining > 0 {
            self.gate
                .unavailable_opens
                .store(remaining - 1, Ordering::SeqCst);
            return Err(RecordingStoreError::Unavailable);
        }
        self.inner.open(key)
    }

    fn resume(
        &self,
        key: &RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<Box<dyn StagedRecording>>, RecordingStoreError> {
        self.inner.resume(key, raw_bytes, prefix_sha256)
    }
}

impl StagedRecording for GatedStaged {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), RecordingStoreError> {
        self.gate.pass(Stage::Write);
        self.inner.write(seq, raw)
    }

    fn written(&self) -> u64 {
        self.inner.written()
    }

    fn prefix_sha256(&self) -> String {
        self.inner.prefix_sha256()
    }

    fn commit(&mut self, manifest: &SessionManifest) -> Result<Committed, RecordingStoreError> {
        self.gate.pass(Stage::Commit);
        self.gate.commit_attempts.fetch_add(1, Ordering::SeqCst);
        let remaining = self.gate.unavailable_commits.load(Ordering::SeqCst);
        if remaining > 0 {
            self.gate
                .unavailable_commits
                .store(remaining - 1, Ordering::SeqCst);
            return Err(RecordingStoreError::Unavailable);
        }
        let action = self.gate.on_commit.lock().unwrap().take();
        if let Some(action) = action {
            action();
        }
        let existing = self.gate.existing_commits.load(Ordering::SeqCst);
        if existing > 0 {
            self.gate
                .existing_commits
                .store(existing - 1, Ordering::SeqCst);
            return Err(RecordingStoreError::Exists);
        }
        if self.gate.fail_commit.swap(false, Ordering::SeqCst) {
            return Err(RecordingStoreError::Io {
                operation: "commit",
                source: std::io::Error::other("injected"),
            });
        }
        self.inner.commit(manifest)
    }

    fn keep_files(&mut self) {
        self.inner.keep_files();
    }

    fn abort(self: Box<Self>) -> Result<(), RecordingStoreError> {
        self.inner.abort()
    }
}
