use std::error::Error as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Method, StatusCode};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use super::mount::{self, FileStamp, MountError, is_dns_label, is_dns_subdomain};
use crate::clock::Clock;

pub const IN_CLUSTER_API: &str = "https://kubernetes.default.svc";
pub const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
pub const TOKEN_REFRESH: Duration = Duration::from_secs(60);
const TOKEN_FILE: &str = "token";
const CA_FILE: &str = "ca.crt";
const NAMESPACE_FILE: &str = "namespace";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE_HOST_VAR: &str = "KUBERNETES_SERVICE_HOST";
const SERVICE_PORT_VAR: &str = "KUBERNETES_SERVICE_PORT";
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_CA_BYTES: u64 = 1024 * 1024;
const MAX_NAMESPACE_BYTES: u64 = 253;
const JSON: &str = "application/json";

pub struct ClusterSettings {
    pub api: String,
    pub service_account_dir: PathBuf,
    pub secret_name: String,
    pub timeout: Duration,
}

impl ClusterSettings {
    pub fn in_cluster(secret_name: String) -> Self {
        let host = std::env::var(SERVICE_HOST_VAR).ok();
        let port = std::env::var(SERVICE_PORT_VAR).ok();
        Self {
            api: api_address(host.as_deref(), port.as_deref()),
            service_account_dir: PathBuf::from(SERVICE_ACCOUNT_DIR),
            secret_name,
            timeout: REQUEST_TIMEOUT,
        }
    }
}

pub fn api_address(host: Option<&str>, port: Option<&str>) -> String {
    match (host.map(str::trim), port.map(str::trim)) {
        (Some(host), Some(port)) if !host.is_empty() && !port.is_empty() => {
            if host.contains(':') {
                format!("https://[{host}]:{port}")
            } else {
                format!("https://{host}:{port}")
            }
        }
        _ => IN_CLUSTER_API.to_owned(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error(
        "this is not a Kubernetes pod with a service account: {} does not exist; the kubernetes state backend runs only inside a cluster, with the service account token mounted",
        path.display()
    )]
    NotInCluster { path: PathBuf },
    #[error(transparent)]
    Mount(#[from] MountError),
    #[error("{} does not hold a namespace name", path.display())]
    Namespace { path: PathBuf },
    #[error(
        "the Secret name must be a DNS subdomain name: lowercase letters, digits, - and ., at most 253 characters"
    )]
    SecretName,
    #[error("{} holds no usable CA certificate", path.display())]
    Ca { path: PathBuf },
    #[error("{} does not hold a usable token", path.display())]
    Token { path: PathBuf },
    #[error("the Kubernetes API address must be an https URL without a path")]
    Address,
    #[error("cannot set up the HTTP client for the Kubernetes API")]
    Http,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("the request to the Kubernetes API timed out")]
    TimedOut,
    #[error("cannot reach the Kubernetes API ({detail})")]
    Connect { detail: String },
    #[error("the request to the Kubernetes API failed ({detail})")]
    Transport { detail: String },
    #[error("the Kubernetes API refused the service account token (HTTP 401)")]
    Unauthorized,
    #[error(
        "the service account may not {verb} the Secret {secret} (HTTP 403); it needs get and update on exactly this Secret"
    )]
    Forbidden { verb: &'static str, secret: String },
    #[error(
        "the Secret {secret} does not exist (HTTP 404); create it empty before the agent starts, the agent may not create it"
    )]
    NotFound { secret: String },
    #[error("the Secret changed since the agent read it (HTTP 409)")]
    Conflict,
    #[error("the Kubernetes API answered HTTP {status}")]
    Status { status: u16 },
    #[error("the Kubernetes API sent a response larger than {MAX_BODY_BYTES} bytes")]
    BodyTooLarge,
    #[error("the Kubernetes API sent a response that is not a Secret")]
    BadResponse,
    #[error("cannot encode the Secret")]
    Encode,
    #[error("cannot read the service account token: {0}")]
    Token(#[source] MountError),
    #[error("the service account token is empty or holds characters that cannot be sent")]
    TokenFormat,
}

pub struct SecretObject {
    raw: Value,
    body_len: usize,
}

impl SecretObject {
    fn parse(body: &[u8]) -> Result<Self, ApiError> {
        let raw: Value = serde_json::from_slice(body).map_err(|_| ApiError::BadResponse)?;
        let kind_ok = raw
            .get("kind")
            .is_none_or(|kind| kind.as_str() == Some("Secret"));
        let version_ok = raw
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .is_some_and(|version| !version.is_empty());
        let data_ok = raw
            .get("data")
            .is_none_or(|data| data.is_object() || data.is_null());
        if !(raw.is_object() && kind_ok && version_ok && data_ok) {
            return Err(ApiError::BadResponse);
        }
        Ok(Self {
            raw,
            body_len: body.len(),
        })
    }

    pub fn body_len(&self) -> usize {
        self.body_len
    }

    pub fn data(&self) -> Option<&Map<String, Value>> {
        self.raw.get("data").and_then(Value::as_object)
    }

    pub fn with_data(&self, data: Map<String, Value>) -> Self {
        let mut raw = self.raw.clone();
        if let Some(object) = raw.as_object_mut() {
            object.insert("data".to_owned(), Value::Object(data));
        }
        Self {
            raw,
            body_len: self.body_len,
        }
    }
}

struct CachedToken {
    token: Zeroizing<String>,
    stamp: FileStamp,
    read_at: SystemTime,
}

pub struct SecretClient {
    http: reqwest::Client,
    url: String,
    secret: String,
    token_path: PathBuf,
    agent_uid: u32,
    token: Mutex<Option<CachedToken>>,
    clock: Arc<dyn Clock>,
}

impl SecretClient {
    pub fn new(
        settings: &ClusterSettings,
        clock: Arc<dyn Clock>,
        agent_uid: u32,
    ) -> Result<Self, SetupError> {
        let dir = &settings.service_account_dir;
        let token_path = dir.join(TOKEN_FILE);
        match mount::stamp(&token_path) {
            Ok(_) => {}
            Err(MountError::Missing { .. }) => {
                return Err(SetupError::NotInCluster { path: token_path });
            }
            Err(error) => return Err(error.into()),
        }
        if !is_dns_subdomain(&settings.secret_name) {
            return Err(SetupError::SecretName);
        }
        let namespace = read_namespace(&dir.join(NAMESPACE_FILE), agent_uid)?;
        let roots = read_roots(&dir.join(CA_FILE), agent_uid)?;
        let base = api_origin(&settings.api)?;
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| SetupError::Http)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(settings.timeout)
            .timeout(settings.timeout)
            .build()
            .map_err(|_| SetupError::Http)?;
        let client = Self {
            http,
            url: format!(
                "{base}/api/v1/namespaces/{namespace}/secrets/{}",
                settings.secret_name
            ),
            secret: format!("{namespace}/{}", settings.secret_name),
            token_path,
            agent_uid,
            token: Mutex::new(None),
            clock,
        };
        client.bearer().map_err(|error| match error {
            ApiError::Token(source) => SetupError::Mount(source),
            _ => SetupError::Token {
                path: client.token_path.clone(),
            },
        })?;
        Ok(client)
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub async fn get(&self) -> Result<SecretObject, ApiError> {
        let (status, body) = self.request(Method::GET, None).await?;
        self.check(status, "get")?;
        SecretObject::parse(&body)
    }

    pub async fn put(&self, object: &SecretObject) -> Result<SecretObject, ApiError> {
        let body = serde_json::to_vec(&object.raw).map_err(|_| ApiError::Encode)?;
        let (status, reply) = self.request(Method::PUT, Some(body)).await?;
        self.check(status, "update")?;
        SecretObject::parse(&reply)
    }

    fn cache(&self) -> MutexGuard<'_, Option<CachedToken>> {
        self.token.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bearer(&self) -> Result<HeaderValue, ApiError> {
        let stamp = mount::stamp(&self.token_path).map_err(ApiError::Token)?;
        let now = self.clock.now();
        let mut cache = self.cache();
        let fresh = cache.as_ref().is_some_and(|cached| {
            cached.stamp == stamp
                && now
                    .duration_since(cached.read_at)
                    .is_ok_and(|age| age < TOKEN_REFRESH)
        });
        if !fresh {
            let (content, stamp) =
                mount::read_mounted(&self.token_path, MAX_TOKEN_BYTES, self.agent_uid)
                    .map_err(ApiError::Token)?;
            let text = std::str::from_utf8(&content).map_err(|_| ApiError::TokenFormat)?;
            let token = text.trim_matches(|ch: char| ch.is_ascii_whitespace());
            if token.is_empty() || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
                return Err(ApiError::TokenFormat);
            }
            *cache = Some(CachedToken {
                token: Zeroizing::new(token.to_owned()),
                stamp,
                read_at: now,
            });
        }
        let token = cache
            .as_ref()
            .map(|cached| &cached.token)
            .ok_or(ApiError::TokenFormat)?;
        let line = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let mut header = HeaderValue::from_str(&line).map_err(|_| ApiError::TokenFormat)?;
        header.set_sensitive(true);
        Ok(header)
    }

    async fn request(
        &self,
        method: Method,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Zeroizing<Vec<u8>>), ApiError> {
        let mut request = self
            .http
            .request(method, &self.url)
            .header(ACCEPT, JSON)
            .header(AUTHORIZATION, self.bearer()?);
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, JSON).body(body);
        }
        let mut response = request.send().await.map_err(classify)?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| usize::try_from(length).map_or(true, |n| n > MAX_BODY_BYTES))
        {
            return Err(ApiError::BodyTooLarge);
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(classify)? {
            if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(ApiError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    }

    fn check(&self, status: StatusCode, verb: &'static str) -> Result<(), ApiError> {
        match status.as_u16() {
            200 => Ok(()),
            401 => {
                *self.cache() = None;
                Err(ApiError::Unauthorized)
            }
            403 => Err(ApiError::Forbidden {
                verb,
                secret: self.secret.clone(),
            }),
            404 => Err(ApiError::NotFound {
                secret: self.secret.clone(),
            }),
            409 => Err(ApiError::Conflict),
            status => Err(ApiError::Status { status }),
        }
    }
}

fn read_namespace(path: &Path, agent_uid: u32) -> Result<String, SetupError> {
    let (content, _) = mount::read_mounted(path, MAX_NAMESPACE_BYTES, agent_uid)?;
    let namespace = std::str::from_utf8(&content)
        .map(|text| text.trim_matches(|ch: char| ch.is_ascii_whitespace()))
        .unwrap_or_default();
    if is_dns_label(namespace) {
        Ok(namespace.to_owned())
    } else {
        Err(SetupError::Namespace {
            path: path.to_path_buf(),
        })
    }
}

fn read_roots(path: &Path, agent_uid: u32) -> Result<RootCertStore, SetupError> {
    let (content, _) = mount::read_mounted(path, MAX_CA_BYTES, agent_uid)?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&content) {
        let certificate = certificate.map_err(|_| SetupError::Ca {
            path: path.to_path_buf(),
        })?;
        roots.add(certificate).map_err(|_| SetupError::Ca {
            path: path.to_path_buf(),
        })?;
    }
    if roots.is_empty() {
        return Err(SetupError::Ca {
            path: path.to_path_buf(),
        });
    }
    Ok(roots)
}

fn api_origin(text: &str) -> Result<String, SetupError> {
    let url = Url::parse(text).map_err(|_| SetupError::Address)?;
    let plain = url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if plain {
        Ok(url.origin().ascii_serialization())
    } else {
        Err(SetupError::Address)
    }
}

fn classify(error: reqwest::Error) -> ApiError {
    if error.is_timeout() {
        return ApiError::TimedOut;
    }
    let connect = error.is_connect();
    let error = error.without_url();
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    if connect {
        ApiError::Connect { detail }
    } else {
        ApiError::Transport { detail }
    }
}
