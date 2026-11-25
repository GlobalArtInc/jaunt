use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use jaunt_audit::DirectorySink;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use tokio::runtime::Handle;

use crate::retry::{RetryPolicy, Sleep, Timer};
use crate::sink::{DEFAULT_BREAKER_WINDOW, S3Sink, SinkOptions};

#[derive(Debug, Default)]
pub struct ManualTimer {
    now: Mutex<Duration>,
}

impl ManualTimer {
    pub fn advance(&self, by: Duration) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) += by;
    }
}

impl Timer for ManualTimer {
    fn elapsed(&self) -> Duration {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        self.advance(duration);
        Box::pin(async {})
    }
}

pub struct SwitchedStore {
    gets_left: Arc<AtomicI64>,
    lists: Arc<AtomicU64>,
    inner: Arc<dyn ObjectStore>,
    down: Arc<AtomicBool>,
    rejecting: Arc<AtomicBool>,
}

impl SwitchedStore {
    fn check_write(&self) -> object_store::Result<()> {
        self.check()?;
        if self.rejecting.load(Ordering::SeqCst) {
            return Err(object_store::Error::Generic {
                store: "switched",
                source: "Server returned non-2xx status code: 501 Not Implemented".into(),
            });
        }
        Ok(())
    }

    fn check(&self) -> object_store::Result<()> {
        if self.down.load(Ordering::SeqCst) {
            Err(object_store::Error::Generic {
                store: "switched",
                source: "the store is switched off".into(),
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for SwitchedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SwitchedStore({})", self.inner)
    }
}

impl fmt::Debug for SwitchedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SwitchedStore")
    }
}

#[async_trait]
impl ObjectStore for SwitchedStore {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.check_write()?;
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.check()?;
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        let left = self.gets_left.load(Ordering::SeqCst);
        if left == 0 {
            self.down.store(true, Ordering::SeqCst);
        } else if left > 0 {
            self.gets_left.fetch_sub(1, Ordering::SeqCst);
        }
        self.check()?;
        self.inner.get_opts(location, options).await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.check()?;
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: CopyOptions,
    ) -> object_store::Result<()> {
        self.check()?;
        self.inner.copy_opts(from, to, options).await
    }
}

fn sink_options(deadline: Duration) -> SinkOptions {
    SinkOptions {
        prefix: "recordings/".to_owned(),
        part_size: 1024 * 1024,
        conditional_put: true,
        retry: RetryPolicy::new(deadline),
        secrets: Vec::new(),
        breaker_window: DEFAULT_BREAKER_WINDOW,
    }
}

pub struct MemoryStore {
    switched: Arc<dyn ObjectStore>,
    deadline: Duration,
    pub sink: Arc<S3Sink>,
    pub down: Arc<AtomicBool>,
    pub rejecting: Arc<AtomicBool>,
    pub lists: Arc<AtomicU64>,
    pub gets_left: Arc<AtomicI64>,
    pub timer: Arc<ManualTimer>,
    pub store: Arc<dyn ObjectStore>,
}

impl MemoryStore {
    pub fn new(staging: DirectorySink, handle: Handle, deadline: Duration) -> MemoryStore {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let down = Arc::new(AtomicBool::new(false));
        let rejecting = Arc::new(AtomicBool::new(false));
        let lists = Arc::new(AtomicU64::new(0));
        let gets_left = Arc::new(AtomicI64::new(-1));
        let timer = Arc::new(ManualTimer::default());
        let switched: Arc<dyn ObjectStore> = Arc::new(SwitchedStore {
            gets_left: gets_left.clone(),
            lists: lists.clone(),
            inner: store.clone(),
            down: down.clone(),
            rejecting: rejecting.clone(),
        });
        let sink = S3Sink::with_store(
            switched.clone(),
            sink_options(deadline),
            staging,
            handle,
            timer.clone(),
        );
        MemoryStore {
            switched,
            deadline,
            sink: Arc::new(sink),
            down,
            rejecting,
            lists,
            gets_left,
            timer,
            store,
        }
    }

    pub fn sibling_sink(&self, staging: DirectorySink, handle: Handle) -> Arc<S3Sink> {
        Arc::new(S3Sink::with_store(
            self.switched.clone(),
            sink_options(self.deadline),
            staging,
            handle,
            self.timer.clone(),
        ))
    }

    pub async fn object_bytes(&self, path: &str) -> Option<Vec<u8>> {
        use object_store::ObjectStoreExt;
        let got = self.store.get(&Path::from(path)).await.ok()?;
        got.bytes().await.ok().map(|bytes| bytes.to_vec())
    }

    pub async fn put_object(&self, path: &str, bytes: Vec<u8>) {
        use object_store::ObjectStoreExt;
        self.store
            .put(&Path::from(path), bytes.into())
            .await
            .expect("a test object is stored");
    }

    pub async fn delete_object(&self, path: &str) {
        use object_store::ObjectStoreExt;
        self.store
            .delete(&Path::from(path))
            .await
            .expect("a test object is deleted");
    }

    pub fn down_after_gets(&self, gets: i64) {
        self.gets_left.store(gets, Ordering::SeqCst);
    }

    pub fn list_calls(&self) -> u64 {
        self.lists.load(Ordering::SeqCst)
    }

    pub fn switch_off(&self) {
        self.down.store(true, Ordering::SeqCst);
    }

    pub fn reject_writes(&self) {
        self.rejecting.store(true, Ordering::SeqCst);
    }

    pub fn switch_on(&self) {
        self.down.store(false, Ordering::SeqCst);
    }

    pub fn accept_writes(&self) {
        self.rejecting.store(false, Ordering::SeqCst);
    }

    pub fn wait_out_the_breaker(&self) {
        self.timer
            .advance(DEFAULT_BREAKER_WINDOW + Duration::from_secs(1));
    }
}
