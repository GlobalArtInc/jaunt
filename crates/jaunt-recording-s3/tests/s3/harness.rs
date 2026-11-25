use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jaunt_audit::{Committed, DirectoryLimits, DirectorySink, RecordingKey, StagedRecording};
use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};
use jaunt_recording_s3::{RetryPolicy, S3Sink, SinkOptions, SystemTimer, Timer};
use jaunt_store::{Recording, RecordingState};
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::runtime::Runtime;

use crate::chaos::{Chaos, ChaosState, Fault, Rule, VirtualTimer};

pub struct OffsetTimer {
    real: SystemTimer,
    offset: std::sync::Mutex<Duration>,
}

impl OffsetTimer {
    pub fn new() -> OffsetTimer {
        OffsetTimer {
            real: SystemTimer::new(),
            offset: std::sync::Mutex::new(Duration::ZERO),
        }
    }

    pub fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap() += by;
    }
}

impl Timer for OffsetTimer {
    fn elapsed(&self) -> Duration {
        self.real.elapsed() + *self.offset.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> jaunt_recording_s3::Sleep {
        self.real.sleep(duration)
    }
}

pub const ID: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";
pub const OTHER: &str = "0b1c2d3e-4f50-4617-8829-3a4b5c6d7e8f";
pub const THIRD: &str = "7a7a7a7a-1111-4222-8333-444444444444";

pub fn started() -> i64 {
    static STARTED: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *STARTED.get_or_init(|| {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    })
}

#[derive(Clone)]
pub struct Backend {
    pub store: Arc<dyn ObjectStore>,
    pub timer: Arc<dyn Timer>,
    pub virtual_timer: Option<Arc<VirtualTimer>>,
    pub offset_timer: Option<Arc<OffsetTimer>>,
    pub deadline: Duration,
    pub first_delay: Duration,
    pub part_size: usize,
    pub prefix: String,
    pub breaker_window: Duration,
}

impl Backend {
    pub fn memory(part_size: usize) -> Backend {
        let timer = Arc::new(VirtualTimer::default());
        Backend {
            store: Arc::new(object_store::memory::InMemory::new()),
            timer: timer.clone(),
            virtual_timer: Some(timer),
            offset_timer: None,
            deadline: Duration::from_secs(120),
            first_delay: Duration::from_millis(250),
            part_size,
            prefix: "recordings/".to_owned(),
            breaker_window: Duration::from_secs(15),
        }
    }

    pub fn real(store: Arc<dyn ObjectStore>, part_size: usize, prefix: String) -> Backend {
        let timer = Arc::new(OffsetTimer::new());
        Backend {
            store,
            timer: timer.clone(),
            virtual_timer: None,
            offset_timer: Some(timer),
            deadline: Duration::from_secs(2),
            first_delay: Duration::from_millis(100),
            part_size,
            prefix,
            breaker_window: Duration::from_millis(300),
        }
    }
}

pub struct Harness {
    pub runtime: Runtime,
    pub staging: TempDir,
    pub chaos: Arc<ChaosState>,
    pub backend: Backend,
}

pub fn key(id: &str) -> RecordingKey {
    RecordingKey::new(id, started()).unwrap()
}

pub fn manifest(id: &str, chunks: u64, raw_bytes: u64) -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: id.to_owned(),
        kind: SessionKind::Shell,
        node: "node-1".to_owned(),
        user: "user-1".to_owned(),
        login: "deploy".to_owned(),
        started_at: 1_764_028_800,
        ended_at: Some(1_764_028_900),
        exit_status: Some(3),
        command: None,
        bytes_out: 10,
        bytes_in: 0,
        input_recorded: false,
        chunks,
        raw_bytes,
        incomplete: false,
        dropped_chunks: 0,
        digest: Some("d".repeat(64)),
    }
}

pub fn row(committed: &Committed, manifest: &SessionManifest) -> Recording {
    Recording {
        session_id: manifest.session_id.clone(),
        node_id: manifest.node.clone(),
        state: RecordingState::Complete,
        chunks: manifest.chunks,
        raw_bytes: committed.cast_bytes,
        progress_sha256: None,
        digest: manifest.digest.clone(),
        input_recorded: manifest.input_recorded,
        incomplete: false,
        session_incomplete: None,
        salvaged: false,
        dropped_chunks: 0,
        location: Some(committed.location.clone()),
        cast_sha256: committed.cast_sha256.clone(),
        manifest_sha256: Some(committed.manifest_sha256.clone()),
        created_at: started(),
        completed_at: Some(started()),
    }
}

pub fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| {
                b"abcdefghijklmnopqrstuvwxyz0123456789 \n"
                    [usize::try_from(self.next() % 38).unwrap()]
            })
            .collect()
    }
}

pub fn write_pieces(staged: &mut dyn StagedRecording, data: &[u8], seed: u64) -> u64 {
    let mut random = SplitMix::new(seed);
    let mut seq = 0u64;
    let mut offset = 0;
    while offset < data.len() {
        let len = usize::try_from(1 + random.next() % 65_536)
            .unwrap()
            .min(data.len() - offset);
        staged.write(seq, &data[offset..offset + len]).unwrap();
        offset += len;
        seq += 1;
    }
    seq
}

pub fn down_rules() -> Vec<Rule> {
    [
        "head",
        "get",
        "put",
        "multipart",
        "part",
        "complete",
        "delete",
        "list",
    ]
    .into_iter()
    .map(|op| Rule {
        op,
        path_has: "",
        remaining: None,
        fault: Fault::Transient,
    })
    .collect()
}

pub fn files_under(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, found: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, found);
            } else {
                found.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();
    found
}

impl Harness {
    pub fn new(backend: &Backend) -> Harness {
        Harness {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
            staging: tempfile::tempdir().unwrap(),
            chaos: Arc::new(ChaosState::default()),
            backend: backend.clone(),
        }
    }

    pub fn staging_root(&self) -> std::path::PathBuf {
        self.staging.path().join("staging")
    }

    pub fn staging_files(&self) -> Vec<String> {
        files_under(&self.staging_root())
    }

    pub fn sink(&self) -> S3Sink {
        let staging = DirectorySink::create(
            &self.staging_root(),
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(Chaos::new(self.backend.store.clone(), self.chaos.clone()));
        S3Sink::with_store(
            store,
            SinkOptions {
                prefix: self.backend.prefix.clone(),
                part_size: self.backend.part_size,
                conditional_put: true,
                retry: RetryPolicy {
                    deadline: self.backend.deadline,
                    first_delay: self.backend.first_delay,
                    max_delay: Duration::from_secs(8),
                },
                secrets: Vec::new(),
                breaker_window: self.backend.breaker_window,
            },
            staging,
            self.runtime.handle().clone(),
            self.backend.timer.clone(),
        )
    }

    pub fn object_path(&self, id: &str, suffix: &str) -> object_store::path::Path {
        object_store::path::Path::parse(format!(
            "{}{}{suffix}",
            self.backend.prefix,
            key(id).location()
        ))
        .unwrap()
    }

    pub fn raw_get(&self, id: &str, suffix: &str) -> Option<Vec<u8>> {
        let path = self.object_path(id, suffix);
        self.runtime.block_on(async {
            match self.backend.store.get(&path).await {
                Ok(found) => Some(found.bytes().await.unwrap().to_vec()),
                Err(object_store::Error::NotFound { .. }) => None,
                Err(other) => panic!("{other}"),
            }
        })
    }

    pub fn raw_put(&self, id: &str, suffix: &str, bytes: Vec<u8>) {
        let path = self.object_path(id, suffix);
        self.runtime.block_on(async {
            self.backend
                .store
                .put(&path, PutPayload::from(bytes))
                .await
                .unwrap();
        });
    }

    pub fn objects_of(&self, id: &str) -> Vec<String> {
        [".cast", ".manifest.json"]
            .into_iter()
            .filter(|suffix| self.raw_get(id, suffix).is_some())
            .map(str::to_owned)
            .collect()
    }

    pub fn settle(&self) {
        self.advance(self.backend.breaker_window + Duration::from_secs(1));
    }

    pub fn advance(&self, by: Duration) {
        match (&self.backend.virtual_timer, &self.backend.offset_timer) {
            (Some(timer), _) => timer.advance(by),
            (None, Some(timer)) => timer.advance(by),
            (None, None) => panic!("the backend has no adjustable timer"),
        }
    }

    pub fn raw_put_with_sha(&self, id: &str, suffix: &str, bytes: Vec<u8>) {
        let path = self.object_path(id, suffix);
        let mut attributes = object_store::Attributes::new();
        attributes.insert(
            object_store::Attribute::Metadata("sha256".into()),
            object_store::AttributeValue::from(sha_hex(&bytes)),
        );
        self.runtime.block_on(async {
            self.backend
                .store
                .put_opts(
                    &path,
                    PutPayload::from(bytes),
                    object_store::PutOptions {
                        attributes,
                        ..object_store::PutOptions::default()
                    },
                )
                .await
                .unwrap();
        });
    }

    pub fn virtual_elapsed(&self) -> Option<Duration> {
        self.backend.virtual_timer.as_ref().map(|timer| timer.now())
    }
}
