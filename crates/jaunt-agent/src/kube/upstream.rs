use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, UNIX_EPOCH};

use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderValue, Request, Response, Uri};
use hyper::body::Incoming;
use hyper::client::conn::http2::{Builder, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use jaunt_limits::LogThrottle;
use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;

use super::KubeLimits;
use super::body::RequestBody;
use super::token::{FileStamp, TokenSource, file_stamp};
use crate::clock::Clock;

const IN_CLUSTER_URL: &str = "https://kubernetes.default.svc";
const IN_CLUSTER_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const IN_CLUSTER_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const ALPN_H2: &[u8] = b"h2";
const MAX_CA_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: u32 = 1024 * 1024;
const FAILURE_LOG_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesUpstream {
    pub base_url: String,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
}

impl Default for KubernetesUpstream {
    fn default() -> Self {
        Self {
            base_url: IN_CLUSTER_URL.to_owned(),
            ca_file: PathBuf::from(IN_CLUSTER_CA),
            token_file: PathBuf::from(IN_CLUSTER_TOKEN),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("the Kubernetes API server address must be https://host[:port] without a path")]
    BaseUrl,
    #[error("cannot read the CA file of the Kubernetes API server: {0}")]
    CaRead(io::ErrorKind),
    #[error("the CA file of the Kubernetes API server holds no usable certificate")]
    CaEmpty,
    #[error("cannot build the TLS client configuration for the Kubernetes API server: {0}")]
    Tls(#[source] rustls::Error),
    #[error("connecting to the Kubernetes API server failed: {0}")]
    Connect(io::ErrorKind),
    #[error("connecting to the Kubernetes API server timed out")]
    ConnectTimeout,
    #[error("the TLS handshake with the Kubernetes API server failed: {0}")]
    Handshake(String),
    #[error("the Kubernetes API server did not agree to HTTP/2")]
    NotHttp2,
    #[error("the HTTP/2 handshake with the Kubernetes API server failed: {0}")]
    Http2(#[source] hyper::Error),
    #[error("the request to the Kubernetes API server failed: {0}")]
    Request(#[source] hyper::Error),
    #[error("the pool of connections to the Kubernetes API server is closed")]
    PoolClosed,
    #[error("every connection to the Kubernetes API server is in use")]
    PoolFull,
}

impl UpstreamError {
    const fn kind(&self) -> &'static str {
        match self {
            Self::BaseUrl => "base_url",
            Self::CaRead(_) => "ca_read",
            Self::CaEmpty => "ca_empty",
            Self::Tls(_) => "tls_config",
            Self::Connect(_) => "connect",
            Self::ConnectTimeout => "connect_timeout",
            Self::Handshake(_) => "handshake",
            Self::NotHttp2 => "not_http2",
            Self::Http2(_) => "http2",
            Self::Request(_) => "request",
            Self::PoolClosed => "pool_closed",
            Self::PoolFull => "pool_full",
        }
    }
}

struct Target {
    authority: Authority,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
}

impl Target {
    fn parse(base_url: &str) -> Result<Self, UpstreamError> {
        let uri: Uri = base_url.parse().map_err(|_| UpstreamError::BaseUrl)?;
        if uri.scheme() != Some(&Scheme::HTTPS) {
            return Err(UpstreamError::BaseUrl);
        }
        let path_ok = uri
            .path_and_query()
            .is_none_or(|path| path.as_str().is_empty() || path.as_str() == "/");
        let authority = uri.authority().cloned().ok_or(UpstreamError::BaseUrl)?;
        if !path_ok || authority.as_str().contains('@') {
            return Err(UpstreamError::BaseUrl);
        }
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let server_name = ServerName::try_from(host.clone()).map_err(|_| UpstreamError::BaseUrl)?;
        Ok(Self {
            port: authority.port_u16().unwrap_or(443),
            authority,
            host,
            server_name,
        })
    }
}

struct Lane {
    sender: SendRequest<RequestBody>,
    slots: Arc<Semaphore>,
}

pub(crate) struct Reserved(OwnedSemaphorePermit);

pub(crate) struct Slot {
    _total: OwnedSemaphorePermit,
    _lane: OwnedSemaphorePermit,
}

struct Pool {
    lanes: Mutex<Vec<Arc<Lane>>>,
    total: Arc<Semaphore>,
    opening: tokio::sync::Mutex<()>,
    max_lanes: usize,
    streams_per_lane: usize,
}

impl Pool {
    fn new(max_lanes: usize, streams_per_lane: usize) -> Self {
        let max_lanes = max_lanes.max(1);
        let streams_per_lane = streams_per_lane.max(1);
        Self {
            lanes: Mutex::new(Vec::new()),
            total: Arc::new(Semaphore::new(max_lanes.saturating_mul(streams_per_lane))),
            opening: tokio::sync::Mutex::new(()),
            max_lanes,
            streams_per_lane,
        }
    }

    fn lanes(&self) -> MutexGuard<'_, Vec<Arc<Lane>>> {
        self.lanes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn free_lane(&self) -> Option<(Arc<Lane>, OwnedSemaphorePermit)> {
        let mut lanes = self.lanes();
        lanes.retain(|lane| !lane.sender.is_closed());
        lanes.iter().find_map(|lane| {
            Arc::clone(&lane.slots)
                .try_acquire_owned()
                .ok()
                .map(|permit| (Arc::clone(lane), permit))
        })
    }

    fn retire(&self, retired: &Arc<Lane>) {
        self.lanes().retain(|lane| !Arc::ptr_eq(lane, retired));
    }

    fn has_room(&self) -> bool {
        self.lanes().len() < self.max_lanes
    }
}

#[derive(Default)]
struct CaState {
    config: Option<Arc<ClientConfig>>,
    stamp: Option<FileStamp>,
}

pub(crate) struct Upstream {
    target: Target,
    ca_file: PathBuf,
    tls: Mutex<CaState>,
    token: TokenSource,
    pool: Pool,
    clock: Arc<dyn Clock>,
    limits: KubeLimits,
    failures: LogThrottle,
}

impl Upstream {
    pub(crate) fn new(
        settings: &KubernetesUpstream,
        clock: Arc<dyn Clock>,
        limits: KubeLimits,
    ) -> Result<Self, UpstreamError> {
        Ok(Self {
            target: Target::parse(&settings.base_url)?,
            ca_file: settings.ca_file.clone(),
            tls: Mutex::new(CaState::default()),
            token: TokenSource::new(settings.token_file.clone(), Arc::clone(&clock), limits),
            pool: Pool::new(limits.api_connections, limits.api_streams_per_connection),
            clock,
            limits,
            failures: LogThrottle::new(FAILURE_LOG_EVERY),
        })
    }

    pub(crate) fn bearer(&self) -> Option<HeaderValue> {
        self.token.bearer()
    }

    pub(crate) fn uri(&self, path: &PathAndQuery) -> Option<Uri> {
        Uri::builder()
            .scheme(Scheme::HTTPS)
            .authority(self.target.authority.clone())
            .path_and_query(path.clone())
            .build()
            .ok()
    }

    pub(crate) fn log_failure(&self, error: &UpstreamError) {
        let tick = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        if let Some(suppressed) = self.failures.admit(tick) {
            tracing::warn!(
                target: "jaunt::agent",
                kind = error.kind(),
                error = %error,
                suppressed,
                "a request to the Kubernetes API server failed; the client got 502"
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn open_connections(&self) -> usize {
        let mut lanes = self.pool.lanes();
        lanes.retain(|lane| !lane.sender.is_closed());
        lanes.len()
    }

    pub(crate) async fn reserve(&self) -> Result<Reserved, UpstreamError> {
        Arc::clone(&self.pool.total)
            .acquire_owned()
            .await
            .map(Reserved)
            .map_err(|_| UpstreamError::PoolClosed)
    }

    pub(crate) async fn send(
        &self,
        reserved: Reserved,
        request: Request<RequestBody>,
    ) -> Result<(Response<Incoming>, Slot), UpstreamError> {
        let (lane, permit) = self.lane().await?;
        let mut sender = lane.sender.clone();
        match sender.try_send_request(request).await {
            Ok(response) => Ok((response, slot(reserved.0, permit))),
            Err(mut failed) => {
                let Some(request) = failed.take_message() else {
                    return Err(UpstreamError::Request(failed.into_error()));
                };
                self.pool.retire(&lane);
                drop(permit);
                let (lane, permit) = self.lane().await?;
                let mut sender = lane.sender.clone();
                match sender.try_send_request(request).await {
                    Ok(response) => Ok((response, slot(reserved.0, permit))),
                    Err(failed) => {
                        if sender.is_closed() {
                            self.pool.retire(&lane);
                        }
                        Err(UpstreamError::Request(failed.into_error()))
                    }
                }
            }
        }
    }

    async fn lane(&self) -> Result<(Arc<Lane>, OwnedSemaphorePermit), UpstreamError> {
        if let Some(found) = self.pool.free_lane() {
            return Ok(found);
        }
        let _opening = self.pool.opening.lock().await;
        if let Some(found) = self.pool.free_lane() {
            return Ok(found);
        }
        if !self.pool.has_room() {
            return Err(UpstreamError::PoolFull);
        }
        let sender = self.connect().await?;
        let lane = Arc::new(Lane {
            sender,
            slots: Arc::new(Semaphore::new(self.pool.streams_per_lane)),
        });
        let permit = Arc::clone(&lane.slots)
            .try_acquire_owned()
            .map_err(|_| UpstreamError::PoolFull)?;
        self.pool.lanes().push(Arc::clone(&lane));
        Ok((lane, permit))
    }

    fn tls(&self) -> Result<Arc<ClientConfig>, UpstreamError> {
        let stamp = file_stamp(&self.ca_file);
        let mut cached = self.tls.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(config) = cached.config.as_ref()
            && stamp.is_some()
            && stamp == cached.stamp
        {
            return Ok(Arc::clone(config));
        }
        match client_config(&self.ca_file) {
            Ok(config) => {
                let config = Arc::new(config);
                cached.config = Some(Arc::clone(&config));
                cached.stamp = stamp;
                Ok(config)
            }
            Err(error) => match cached.config.as_ref() {
                Some(config) => {
                    let kept = Arc::clone(config);
                    drop(cached);
                    self.log_ca_failure(&error);
                    Ok(kept)
                }
                None => Err(error),
            },
        }
    }

    fn log_ca_failure(&self, error: &UpstreamError) {
        let tick = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        if let Some(suppressed) = self.failures.admit(tick) {
            tracing::warn!(
                target: "jaunt::agent",
                kind = error.kind(),
                error = %error,
                suppressed,
                "reading the CA file of the Kubernetes API server failed; new connections keep the CA read before"
            );
        }
    }

    async fn connect(&self) -> Result<SendRequest<RequestBody>, UpstreamError> {
        let tls = self.tls()?;
        let now = self.clock.now();
        let deadline = now.checked_add(self.limits.connect_timeout).unwrap_or(now);
        tokio::select! {
            () = self.clock.sleep_until(deadline) => Err(UpstreamError::ConnectTimeout),
            connected = self.dial(tls) => connected,
        }
    }

    async fn dial(
        &self,
        tls: Arc<ClientConfig>,
    ) -> Result<SendRequest<RequestBody>, UpstreamError> {
        let tcp = TcpStream::connect((self.target.host.as_str(), self.target.port))
            .await
            .map_err(|error| UpstreamError::Connect(error.kind()))?;
        if let Err(error) = tcp.set_nodelay(true) {
            tracing::debug!(
                target: "jaunt::agent",
                error = %error,
                "cannot disable Nagle's algorithm on the connection to the Kubernetes API server"
            );
        }
        let stream = TlsConnector::from(tls)
            .connect(self.target.server_name.clone(), tcp)
            .await
            .map_err(|error| UpstreamError::Handshake(error.to_string()))?;
        if stream.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
            return Err(UpstreamError::NotHttp2);
        }
        let limits = &self.limits;
        let (sender, connection) = Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .initial_stream_window_size(limits.stream_window)
            .initial_connection_window_size(limits.api_connection_window())
            .max_send_buf_size(limits.send_buffer)
            .max_header_list_size(MAX_RESPONSE_HEADER_BYTES)
            .keep_alive_interval(limits.ping_interval)
            .keep_alive_timeout(limits.ping_timeout)
            .keep_alive_while_idle(true)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(UpstreamError::Http2)?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(
                    target: "jaunt::agent",
                    error = %error,
                    "a connection to the Kubernetes API server ended with an error"
                );
            }
        });
        Ok(sender)
    }
}

fn slot(total: OwnedSemaphorePermit, lane: OwnedSemaphorePermit) -> Slot {
    Slot {
        _total: total,
        _lane: lane,
    }
}

fn client_config(ca_file: &Path) -> Result<ClientConfig, UpstreamError> {
    let file = std::fs::File::open(ca_file).map_err(|error| UpstreamError::CaRead(error.kind()))?;
    let mut pem = Vec::new();
    file.take(MAX_CA_BYTES)
        .read_to_end(&mut pem)
        .map_err(|error| UpstreamError::CaRead(error.kind()))?;
    let mut certificates: Vec<CertificateDer<'static>> = Vec::new();
    let mut unreadable = 0_usize;
    for item in CertificateDer::pem_slice_iter(&pem) {
        match item {
            Ok(certificate) => certificates.push(certificate),
            Err(_) => unreadable += 1,
        }
    }
    let mut roots = RootCertStore::empty();
    let (added, unparsable) = roots.add_parsable_certificates(certificates);
    let ignored = unparsable + unreadable;
    if added == 0 {
        return Err(UpstreamError::CaEmpty);
    }
    if ignored > 0 {
        tracing::warn!(
            target: "jaunt::agent",
            ignored,
            added,
            "some certificates in the CA file of the Kubernetes API server cannot be used; the others are trusted"
        );
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(UpstreamError::Tls)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    config.resumption = Resumption::disabled();
    Ok(config)
}
