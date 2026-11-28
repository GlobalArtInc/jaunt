use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt::lock::ProfileLock;
use jaunt_proto::GATE_ALPN_SVC;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::CertificateDer;
use rustls::server::{Acceptor, WebPkiClientVerifier};
use rustls::version::{TLS12, TLS13};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};

use crate::cli::write_profile;
use crate::gate::{GATE_NAME, Leaf, TestCa, services_json};
use crate::support::{Behavior, CertSpec, FakeServer, X509Reply, ca_key, new_key_data, sign};

pub const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
pub const TRAILER: &[u8] = b"bye";
pub const DEADLINE: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);

pub struct Pki {
    pub internal: TestCa,
    pub users: TestCa,
}

impl Pki {
    pub fn new() -> Pki {
        Pki {
            internal: TestCa::new("internal root"),
            users: TestCa::new("user-x509 root"),
        }
    }
}

pub fn requiring_client(
    leaf: Leaf,
    users: &TestCa,
    tls12_only: bool,
    alpn: &[&str],
) -> ServerConfig {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(users.der())).unwrap();
    let provider = Arc::new(default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .unwrap();
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls12_only { &[&TLS12] } else { &[&TLS13] };
    let (chain, key) = leaf;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    config.send_tls13_tickets = 0;
    config
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum App {
    Echo,
    Postgres,
}

pub struct Setup {
    pub outer: ServerConfig,
    pub inner: Option<ServerConfig>,
    pub app: App,
    pub lock_probe: Option<(PathBuf, PathBuf)>,
    pub silent: bool,
}

impl Setup {
    pub fn standard(pki: &Pki, inner_name: &str, app: App) -> Setup {
        Setup {
            outer: requiring_client(
                pki.internal.server_leaf(GATE_NAME),
                &pki.users,
                false,
                &[GATE_ALPN_SVC],
            ),
            inner: Some(requiring_client(
                pki.internal.server_leaf(inner_name),
                &pki.users,
                false,
                &[],
            )),
            app,
            lock_probe: None,
            silent: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Session {
    pub outer_alpn: Option<Vec<u8>>,
    pub outer_client: Option<Vec<u8>>,
    pub lock_free: Option<bool>,
    pub inner_sni: Option<String>,
    pub inner_client: Option<Vec<u8>>,
    pub first_bytes: Vec<u8>,
    pub client_ended: bool,
}

#[derive(Default)]
pub struct SvcLog {
    pub accepted: usize,
    pub outer_failed: usize,
    pub inner_failed: usize,
    pub sessions: Vec<Session>,
}

struct Shared {
    outer: TlsAcceptor,
    inner: Option<Arc<ServerConfig>>,
    app: App,
    lock_probe: Option<(PathBuf, PathBuf)>,
    silent: bool,
    log: Mutex<SvcLog>,
}

impl Shared {
    fn update(&self, index: usize, change: impl FnOnce(&mut Session)) {
        change(&mut self.log.lock().unwrap().sessions[index]);
    }
}

pub struct FakeSvc {
    pub port: u16,
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

fn leaf_of(certificates: Option<&[CertificateDer<'_>]>) -> Option<Vec<u8>> {
    match certificates {
        Some([leaf]) => Some(leaf.to_vec()),
        _ => None,
    }
}

async fn serve_one(tcp: tokio::net::TcpStream, shared: Arc<Shared>) {
    let outer = match shared.outer.accept(tcp).await {
        Ok(outer) => outer,
        Err(_) => {
            shared.log.lock().unwrap().outer_failed += 1;
            return;
        }
    };
    let index = {
        let mut log = shared.log.lock().unwrap();
        log.sessions.push(Session {
            outer_alpn: outer.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
            outer_client: leaf_of(outer.get_ref().1.peer_certificates()),
            ..Session::default()
        });
        log.sessions.len() - 1
    };
    if let Some((home, lock_path)) = &shared.lock_probe {
        let free = ProfileLock::acquire(home, lock_path, Instant::now(), &mut || {}).is_ok();
        shared.update(index, |session| session.lock_free = Some(free));
    }
    if shared.silent {
        let mut outer = outer;
        let mut sink = Vec::new();
        drop(outer.read_to_end(&mut sink).await);
        return;
    }
    let Some(inner_config) = &shared.inner else {
        let mut outer = outer;
        drop(outer.shutdown().await);
        return;
    };
    let start = match LazyConfigAcceptor::new(Acceptor::default(), outer).await {
        Ok(start) => start,
        Err(_) => {
            shared.log.lock().unwrap().inner_failed += 1;
            return;
        }
    };
    let sni = start.client_hello().server_name().map(str::to_owned);
    shared.update(index, |session| session.inner_sni = sni);
    let inner = match start.into_stream(Arc::clone(inner_config)).await {
        Ok(inner) => inner,
        Err(_) => {
            shared.log.lock().unwrap().inner_failed += 1;
            return;
        }
    };
    let client = leaf_of(inner.get_ref().1.peer_certificates());
    shared.update(index, |session| session.inner_client = client);
    answer(inner, index, &shared).await;
}

async fn answer<S>(mut stream: S, index: usize, shared: &Shared)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if shared.app == App::Postgres {
        let mut request = [0_u8; 8];
        if stream.read_exact(&mut request).await.is_err() {
            return;
        }
        shared.update(index, |session| session.first_bytes = request.to_vec());
        if request == SSL_REQUEST
            && (stream.write_all(b"N").await.is_err() || stream.flush().await.is_err())
        {
            return;
        }
    }
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                shared.update(index, |session| session.client_ended = true);
                if stream.write_all(TRAILER).await.is_ok() && stream.flush().await.is_ok() {
                    drop(stream.shutdown().await);
                }
                return;
            }
            Ok(count) => {
                if stream.write_all(&buffer[..count]).await.is_err()
                    || stream.flush().await.is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

impl FakeSvc {
    pub fn start(setup: Setup) -> FakeSvc {
        let shared = Arc::new(Shared {
            outer: TlsAcceptor::from(Arc::new(setup.outer)),
            inner: setup.inner.map(Arc::new),
            app: setup.app,
            lock_probe: setup.lock_probe,
            silent: setup.silent,
            log: Mutex::new(SvcLog::default()),
        });
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread_shared = Arc::clone(&shared);
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready_tx
                    .send(listener.local_addr().unwrap().port())
                    .unwrap();
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        accepted = listener.accept() => {
                            let (tcp, _) = accepted.unwrap();
                            thread_shared.log.lock().unwrap().accepted += 1;
                            tokio::spawn(serve_one(tcp, Arc::clone(&thread_shared)));
                        }
                    }
                }
            });
        });
        let port = ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        FakeSvc {
            port,
            shared,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }

    pub fn log<T>(&self, read: impl FnOnce(&SvcLog) -> T) -> T {
        read(&self.shared.log.lock().unwrap())
    }

    pub fn wait_for(&self, what: &str, done: impl Fn(&SvcLog) -> bool) {
        poll_until(what, || self.log(&done));
    }
}

impl Drop for FakeSvc {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).ok();
        }
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

pub fn poll_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + DEADLINE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(POLL);
    }
}

pub fn within_deadline<T>(work: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(DEADLINE, work)
                .await
                .expect("the exchange did not finish in time")
        })
}

pub fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("jt")
        .tempdir_in("/tmp")
        .unwrap()
}

pub fn issuing_api(pki: &Pki, valid_before: i64) -> FakeServer {
    FakeServer::start(Behavior {
        x509: X509Reply::IssueUnder {
            valid_before,
            root_der: pki.users.der(),
            root_key_der: pki.users.key_der(),
        },
        ..Behavior::default()
    })
}

pub fn svc_services_json(port: u16, pki: &Pki) -> Value {
    services_json(port, &[pki.internal.pinned()])
}

pub fn sign_in(home: &Path, api: &FakeServer, ssh_valid_before: i64, services: Option<&Value>) {
    write_profile(home, &api.url(), ssh_valid_before);
    let mut spec = CertSpec::user(new_key_data(), 3600);
    spec.valid_before = u64::try_from(ssh_valid_before).unwrap();
    let certificate = sign(&ca_key(), &spec).to_openssh().unwrap();
    let dir = home.join("default");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(dir.join("id_ed25519-cert.pub"), certificate).unwrap();
    if let Some(services) = services {
        fs::write(dir.join("services.json"), services.to_string()).unwrap();
    }
}

pub fn pem_certificate(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).unwrap());
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

pub fn json_alpn(services: &mut Value, alpn: &[&str]) {
    services["services"]["alpn"] = json!(alpn);
}
