use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::kube_state::client::{ClusterSettings, REQUEST_TIMEOUT};
use crate::testkit::TestPki;

pub const NAMESPACE: &str = "jaunt";
pub const SECRET: &str = "jaunt-agent-state";
pub const SECRET_PATH: &str = "/api/v1/namespaces/jaunt/secrets/jaunt-agent-state";
pub const SA_TOKEN: &str = "sa-token-1";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stored {
    pub version: u64,
    pub data: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
}

impl Stored {
    pub fn holding(data: BTreeMap<String, String>) -> Self {
        Self {
            version: 1,
            data,
            annotations: BTreeMap::new(),
        }
    }

    pub fn file(&self, name: &str) -> Vec<u8> {
        STANDARD.decode(&self.data[name]).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub status: u16,
}

pub enum Step {
    Pass,
    Status(u16),
    Conflict(Box<dyn FnOnce(&mut Stored) + Send>),
    Raw(u16, Vec<u8>),
    Redirect(u16),
    Hang,
}

#[derive(Default)]
struct Inner {
    secret: Mutex<Option<Stored>>,
    seen: Mutex<Vec<Seen>>,
    gets: Mutex<VecDeque<Step>>,
    puts: Mutex<VecDeque<Step>>,
}

pub struct FakeKube {
    pub api: String,
    pub accounts: tempfile::TempDir,
    inner: Arc<Inner>,
    task: JoinHandle<()>,
}

struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((tcp, addr)) = self.tcp.accept().await else {
                continue;
            };
            let handshake =
                tokio::time::timeout(Duration::from_secs(10), self.acceptor.accept(tcp)).await;
            if let Ok(Ok(tls)) = handshake {
                return (tls, addr);
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

fn pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

impl FakeKube {
    pub async fn start(secret: Option<Stored>) -> Self {
        let pki = TestPki::new();
        let (chain, key) = pki.server_leaf("127.0.0.1");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("https://{}", tcp.local_addr().unwrap());
        let listener = TlsListener {
            tcp,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        };
        let accounts = tempfile::tempdir().unwrap();
        std::fs::write(accounts.path().join("ca.crt"), pem(pki.root_der())).unwrap();
        std::fs::write(accounts.path().join("namespace"), NAMESPACE).unwrap();
        std::fs::write(accounts.path().join("token"), format!("{SA_TOKEN}\n")).unwrap();
        let inner = Arc::new(Inner::default());
        *inner.secret.lock().unwrap() = secret;
        let router = Router::new().fallback(handle).with_state(inner.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            api,
            accounts,
            inner,
            task,
        }
    }

    pub fn settings(&self) -> ClusterSettings {
        ClusterSettings {
            api: self.api.clone(),
            service_account_dir: self.accounts.path().to_path_buf(),
            secret_name: SECRET.to_owned(),
            timeout: REQUEST_TIMEOUT,
        }
    }

    pub fn secret(&self) -> Option<Stored> {
        self.inner.secret.lock().unwrap().clone()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.inner.seen.lock().unwrap().clone()
    }

    pub fn methods(&self) -> Vec<(String, u16)> {
        self.seen()
            .into_iter()
            .map(|seen| (seen.method, seen.status))
            .collect()
    }

    pub fn script_get(&self, step: Step) {
        self.inner.gets.lock().unwrap().push_back(step);
    }

    pub fn script_put(&self, step: Step) {
        self.inner.puts.lock().unwrap().push_back(step);
    }

    pub fn replace_token(&self, token: &str) {
        let temp = self.accounts.path().join(".token.new");
        std::fs::write(&temp, token).unwrap();
        std::fs::rename(&temp, self.accounts.path().join("token")).unwrap();
    }

    pub fn rewrite_token_in_place(&self, token: &str) {
        let path = self.accounts.path().join("token");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, token).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }

    pub fn assert_only_the_secret_was_touched(&self) {
        let seen = self.seen();
        assert!(!seen.is_empty());
        for request in seen {
            assert!(
                request.method == "GET" || request.method == "PUT",
                "{request:?}"
            );
            assert_eq!(request.path, SECRET_PATH, "{request:?}");
            assert!(
                request
                    .authorization
                    .as_deref()
                    .is_some_and(|value| value.starts_with("Bearer sa-token-")),
                "{request:?}"
            );
        }
    }

    pub fn remove_token(&self) {
        std::fs::remove_file(self.accounts.path().join("token")).unwrap();
    }

    pub fn accounts_path(&self) -> &Path {
        self.accounts.path()
    }
}

impl Drop for FakeKube {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn object(stored: &Stored) -> Value {
    let mut metadata = json!({
        "name": SECRET,
        "namespace": NAMESPACE,
        "resourceVersion": stored.version.to_string(),
        "uid": "5f1d0c2e-0000-4000-8000-000000000001",
    });
    if !stored.annotations.is_empty() {
        metadata["annotations"] = json!(stored.annotations);
    }
    let mut object = json!({
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": metadata,
        "type": "Opaque",
    });
    if !stored.data.is_empty() {
        object["data"] = json!(stored.data);
    }
    object
}

fn reply(status: u16, body: Vec<u8>) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [("content-type", "application/json")],
        body,
    )
        .into_response()
}

fn status_reply(status: u16) -> Response {
    let body = json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": status});
    reply(status, serde_json::to_vec(&body).unwrap())
}

fn strings(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .unwrap_or(&Map::new())
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
        .collect()
}

impl Inner {
    fn scripted(&self, method: &Method) -> Option<Step> {
        let steps = if *method == Method::GET {
            &self.gets
        } else {
            &self.puts
        };
        steps.lock().unwrap().pop_front()
    }

    fn apply(&self, step: Step) -> Option<Response> {
        match step {
            Step::Pass | Step::Hang => None,
            Step::Status(status) => Some(status_reply(status)),
            Step::Raw(status, body) => Some(reply(status, body)),
            Step::Redirect(status) => Some(
                (
                    StatusCode::from_u16(status).unwrap(),
                    [("location", SECRET_PATH)],
                )
                    .into_response(),
            ),
            Step::Conflict(change) => {
                if let Some(stored) = self.secret.lock().unwrap().as_mut() {
                    change(stored);
                    stored.version += 1;
                }
                Some(status_reply(409))
            }
        }
    }

    fn answer(&self, method: &Method, path: &str, body: &[u8]) -> Response {
        if path != SECRET_PATH {
            return status_reply(404);
        }
        if *method == Method::GET {
            return match &*self.secret.lock().unwrap() {
                Some(stored) => reply(200, serde_json::to_vec(&object(stored)).unwrap()),
                None => status_reply(404),
            };
        }
        if *method != Method::PUT {
            return status_reply(405);
        }
        let update: Value = serde_json::from_slice(body).unwrap();
        let version = update
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|text| text.parse::<u64>().ok());
        let mut secret = self.secret.lock().unwrap();
        let Some(stored) = secret.as_mut() else {
            return status_reply(404);
        };
        if version != Some(stored.version) {
            return status_reply(409);
        }
        assert_eq!(update["kind"], "Secret");
        assert_eq!(update.pointer("/metadata/name"), Some(&json!(SECRET)));
        stored.version += 1;
        stored.data = strings(update.get("data"));
        stored.annotations = strings(update.pointer("/metadata/annotations"));
        reply(200, serde_json::to_vec(&object(stored)).unwrap())
    }
}

async fn handle(
    State(inner): State<Arc<Inner>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri
        .path_and_query()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    let step = (path == SECRET_PATH)
        .then(|| inner.scripted(&method))
        .flatten();
    let hang = matches!(step, Some(Step::Hang));
    let scripted = step.and_then(|step| inner.apply(step));
    let response = scripted.unwrap_or_else(|| inner.answer(&method, &path, &body));
    let status = if hang { 0 } else { response.status().as_u16() };
    inner.seen.lock().unwrap().push(Seen {
        method: method.to_string(),
        path,
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        status,
    });
    if hang {
        std::future::pending::<()>().await;
    }
    response
}
