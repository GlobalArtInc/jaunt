use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use jaunt_recording_s3::{Sleep, Timer};
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult, UploadPart,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Transient,
    Denied,
    Status(u16),
}

impl fmt::Debug for Hook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hook").field("op", &self.op).finish()
    }
}

pub type Action = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

#[derive(Clone)]
pub struct Hook {
    pub op: &'static str,
    pub path_has: &'static str,
    pub once: bool,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub op: &'static str,
    pub path_has: &'static str,
    pub remaining: Option<u32>,
    pub fault: Fault,
}

#[derive(Debug, Default)]
pub struct ChaosState {
    rules: Mutex<Vec<Rule>>,
    log: Mutex<Vec<String>>,
    hooks: Mutex<Vec<Hook>>,
}

impl ChaosState {
    pub fn fail(&self, rule: Rule) {
        self.rules.lock().unwrap().push(rule);
    }

    pub fn clear(&self) {
        self.rules.lock().unwrap().clear();
    }

    pub fn after(&self, hook: Hook) {
        self.hooks.lock().unwrap().push(hook);
    }

    async fn fire(&self, op: &'static str, path: &Path) {
        let due: Vec<Action> = {
            let mut hooks = self.hooks.lock().unwrap();
            let due = hooks
                .iter()
                .filter(|hook| hook.op == op && path.as_ref().contains(hook.path_has))
                .map(|hook| hook.action.clone())
                .collect();
            hooks.retain(|hook| {
                !(hook.once && hook.op == op && path.as_ref().contains(hook.path_has))
            });
            due
        };
        for action in due {
            action().await;
        }
    }

    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    pub fn count(&self, entry: &str) -> usize {
        self.log()
            .iter()
            .filter(|seen| seen.as_str() == entry)
            .count()
    }

    fn check(
        &self,
        op: &'static str,
        path: &Path,
        detail: &str,
    ) -> Result<(), object_store::Error> {
        let name = kind(path);
        self.log
            .lock()
            .unwrap()
            .push(format!("{op}:{name}{detail}"));
        let mut rules = self.rules.lock().unwrap();
        for rule in rules.iter_mut() {
            if rule.op == op && path.as_ref().contains(rule.path_has) && rule.remaining != Some(0) {
                if let Some(left) = rule.remaining.as_mut() {
                    *left -= 1;
                }
                return Err(match rule.fault {
                    Fault::Transient => object_store::Error::Generic {
                        store: "chaos",
                        source: "injected failure".into(),
                    },
                    Fault::Denied => object_store::Error::PermissionDenied {
                        path: path.to_string(),
                        source: "injected denial".into(),
                    },
                    Fault::Status(status) => object_store::Error::Generic {
                        store: "chaos",
                        source: format!("Server returned non-2xx status code: {status} injected")
                            .into(),
                    },
                });
            }
        }
        Ok(())
    }
}

fn kind(path: &Path) -> &'static str {
    let text = path.as_ref();
    if text.ends_with(".manifest.json") {
        "manifest"
    } else if text.ends_with(".cast") {
        "cast"
    } else {
        "other"
    }
}

pub struct Chaos {
    inner: Arc<dyn ObjectStore>,
    state: Arc<ChaosState>,
}

impl Chaos {
    pub fn new(inner: Arc<dyn ObjectStore>, state: Arc<ChaosState>) -> Chaos {
        Chaos { inner, state }
    }
}

impl fmt::Display for Chaos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chaos({})", self.inner)
    }
}

impl fmt::Debug for Chaos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chaos")
    }
}

#[async_trait]
impl ObjectStore for Chaos {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.state.check("put", location, "")?;
        let done = self.inner.put_opts(location, payload, opts).await?;
        self.state.fire("put", location).await;
        Ok(done)
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.state.check("multipart", location, "")?;
        let inner = self.inner.put_multipart_opts(location, opts).await?;
        Ok(Box::new(ChaosUpload {
            inner,
            state: self.state.clone(),
            path: location.clone(),
        }))
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        let op = if options.head { "head" } else { "get" };
        self.state.check(op, location, "")?;
        let found = self.inner.get_opts(location, options).await;
        self.state.fire(op, location).await;
        found
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        let state = self.state.clone();
        let checked = locations.map(move |location| {
            let location = location?;
            state.check("delete", &location, "")?;
            Ok(location)
        });
        self.inner.delete_stream(checked.boxed())
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        let probe = Path::from("listing");
        self.state.check("list", &probe, "")?;
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}

#[derive(Debug)]
struct ChaosUpload {
    inner: Box<dyn MultipartUpload>,
    state: Arc<ChaosState>,
    path: Path,
}

#[async_trait]
impl MultipartUpload for ChaosUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        let size = data.content_length();
        match self.state.check("part", &self.path, &format!(":{size}")) {
            Ok(()) => {
                let state = self.state.clone();
                let path = self.path.clone();
                let part = self.inner.put_part(data);
                Box::pin(async move {
                    part.await?;
                    state.fire("part", &path).await;
                    Ok(())
                })
            }
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    async fn complete(&mut self) -> object_store::Result<PutResult> {
        self.state.check("complete", &self.path, "")?;
        let done = self.inner.complete().await?;
        self.state.fire("complete", &self.path).await;
        Ok(done)
    }

    async fn abort(&mut self) -> object_store::Result<()> {
        self.state.log.lock().unwrap().push("abort:cast".to_owned());
        self.inner.abort().await
    }
}

#[derive(Default)]
pub struct VirtualTimer {
    now: Mutex<Duration>,
}

impl VirtualTimer {
    pub fn now(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    pub fn advance(&self, by: Duration) {
        *self.now.lock().unwrap() += by;
    }
}

impl Timer for VirtualTimer {
    fn elapsed(&self) -> Duration {
        self.now()
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        *self.now.lock().unwrap() += duration;
        Box::pin(async {})
    }
}
