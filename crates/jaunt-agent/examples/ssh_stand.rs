use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_gate::{AgentApiHandler, AgentHub, AgentHubConfig, HostCertIssuer, IssueError};
use jaunt_gate::{SshGate, SshGateConfig};
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlError, ControlPlane, EnrollRequest, EnrollResponse,
    EnrollmentApproved, NodeCaller, NodeCertificates, PollResponse, RECORDINGS_PATH_PREFIX,
    RecordingChunk, RecordingComplete, RouteDecision, RouteRequest, SessionEnd, SessionEndOutcome,
};
use jaunt_record::{Assembler, Chunk, Limits, SessionKind, SessionManifest, Sink, SinkError};
use jaunt_ssh::{UserCaKeys, UserCaSource};
use jaunt_tunnel::{
    BoxFuture, NodeId, PeerAuthenticator, RejectReason, Rejection, TunnelOptions,
    agent_server_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::RootCertStore;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

const NODE_ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const SUFFIX: &str = "jaunt.test";
const GATE_NAME: &str = "gate.jaunt.test";
const AGENTS_NAME: &str = "localhost";
const USER_ID: &str = "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11";
const EMAIL: &str = "alice@example.com";
const SERIAL: u64 = 7;
const ENROLL_ADDR: &str = "127.0.0.1:7001";
const HUB_ADDR: &str = "127.0.0.1:7002";
const GATE_ADDR: &str = "127.0.0.1:2222";
const HANDLE: &str = "stand-handle";
const WEEK: u64 = 7 * 24 * 3600;
const MAX_BODY: usize = 64 * 1024;
const MAX_RECORDING_BODY: usize = 2 * 1024 * 1024;
const RECORDINGS_DIR: &str = "recordings";

type Failure = Box<dyn Error + Send + Sync>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn signed(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

struct Stand {
    dir: PathBuf,
    root: CertifiedIssuer<'static, KeyPair>,
    host_ca: PrivateKey,
    user_ca_line: String,
    enrolled: Mutex<Option<EnrollRequest>>,
    sessions: AtomicU64,
    uploads: Mutex<HashMap<String, Upload>>,
}

#[derive(Default)]
struct CastBytes(Vec<u8>);

impl Sink for CastBytes {
    fn write(&mut self, _seq: u64, raw: &[u8]) -> Result<(), SinkError> {
        self.0.extend_from_slice(raw);
        Ok(())
    }
}

struct Upload {
    assembler: Assembler,
    cast: CastBytes,
    stored: Option<serde_json::Value>,
}

fn stand_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= 64
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

impl Stand {
    fn flag(&self, name: &str) -> bool {
        self.dir.join(name).exists()
    }

    fn record(&self, name: &str, body: &[u8]) {
        let appended = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(name))
            .and_then(|mut file| {
                file.write_all(body)?;
                file.write_all(b"\n")
            });
        if let Err(error) = appended {
            tracing::error!(error = %error, file = name, "cannot record a request");
        }
    }

    fn recording(&self, path: &str, body: &[u8]) -> (StatusCode, serde_json::Value) {
        let refused = |status, code: &str| (status, serde_json::json!({ "error": code }));
        let Some((session_id, action)) = path
            .strip_prefix(RECORDINGS_PATH_PREFIX)
            .and_then(|rest| rest.split_once('/'))
        else {
            return refused(StatusCode::NOT_FOUND, "not_found");
        };
        if !stand_session_id(session_id) {
            return refused(StatusCode::NOT_FOUND, "session_unknown");
        }
        let mut uploads = self.uploads.lock().unwrap_or_else(PoisonError::into_inner);
        let upload = uploads
            .entry(session_id.to_owned())
            .or_insert_with(|| Upload {
                assembler: Assembler::new(session_id, Limits::default()),
                cast: CastBytes::default(),
                stored: None,
            });
        let outcome = match action {
            "chunks" => accept_chunk(session_id, upload, body),
            "complete" => self.accept_complete(session_id, upload, body),
            _ => return refused(StatusCode::NOT_FOUND, "not_found"),
        };
        outcome.unwrap_or_else(|(status, code)| {
            tracing::warn!(session_id, code, "refused a recording upload");
            refused(status, code)
        })
    }

    fn accept_complete(
        &self,
        session_id: &str,
        upload: &mut Upload,
        body: &[u8],
    ) -> Result<(StatusCode, serde_json::Value), (StatusCode, &'static str)> {
        let request: RecordingComplete = serde_json::from_slice(body)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_request"))?;
        let wire = serde_json::to_value(&request.manifest)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_request"))?;
        if let Some(stored) = &upload.stored {
            return if *stored == wire {
                Ok(receipt(&request))
            } else {
                Err((StatusCode::CONFLICT, "conflict"))
            };
        }
        let manifest: SessionManifest = serde_json::from_value(wire.clone())
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_request"))?;
        upload
            .assembler
            .complete(
                &manifest,
                manifest.kind == SessionKind::Shell,
                &mut upload.cast,
            )
            .map_err(|_| (StatusCode::CONFLICT, "conflict"))?;
        let dir = self.dir.join(RECORDINGS_DIR);
        let written = fs::create_dir_all(&dir)
            .and_then(|()| fs::write(dir.join(format!("{session_id}.cast")), &upload.cast.0))
            .and_then(|()| {
                fs::write(
                    dir.join(format!("{session_id}.manifest.json")),
                    wire.to_string(),
                )
            });
        if let Err(error) = written {
            tracing::error!(error = %error, "cannot store a recording");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "internal"));
        }
        upload.stored = Some(wire);
        Ok(receipt(&request))
    }

    fn host_certificate(
        &self,
        public: &PublicKey,
        principals: &[&str],
        key_id: &str,
    ) -> Result<String, Failure> {
        let now = now();
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            public.key_data().clone(),
            now.saturating_sub(60),
            now + WEEK,
        )?;
        builder.cert_type(CertType::Host)?;
        builder.key_id(key_id)?;
        for principal in principals {
            builder.valid_principal(*principal)?;
        }
        Ok(builder.sign(&self.host_ca)?.to_openssh()?)
    }

    fn node_x509(&self, spki: &[u8]) -> Result<Vec<u8>, Failure> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(
            format!("urn:jaunt:node:{NODE_ID}").try_into()?,
        )];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = offset(now().saturating_sub(60))?;
        params.not_after = offset(now() + WEEK)?;
        let subject = rcgen::SubjectPublicKeyInfo::from_der(spki)?;
        Ok(params.signed_by(&subject, &*self.root)?.der().to_vec())
    }

    fn approve(&self, enroll: &EnrollRequest) -> Result<EnrollmentApproved, Failure> {
        let spki = STANDARD.decode(&enroll.tls_public_key)?;
        let host = PublicKey::from_openssh(&enroll.ssh_host_public_key)?;
        let qualified = format!("{}.{SUFFIX}", enroll.name);
        let not_after = signed(now() + WEEK);
        Ok(EnrollmentApproved {
            node_id: NODE_ID.to_owned(),
            certificates: NodeCertificates {
                x509_certificate_der: STANDARD.encode(self.node_x509(&spki)?),
                x509_not_after: not_after,
                ssh_host_certificate: self.host_certificate(
                    &host,
                    &[qualified.as_str(), enroll.name.as_str()],
                    &format!("jaunt-host:{qualified}:1"),
                )?,
                ssh_not_after: not_after,
            },
            internal_ca_root_der: STANDARD.encode(self.root.der()),
            agent_endpoint: format!("{AGENTS_NAME}:{}", port(HUB_ADDR)?),
        })
    }
}

fn accept_chunk(
    session_id: &str,
    upload: &mut Upload,
    body: &[u8],
) -> Result<(StatusCode, serde_json::Value), (StatusCode, &'static str)> {
    let request: RecordingChunk =
        serde_json::from_slice(body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid_request"))?;
    let chunk = Chunk {
        session_id: session_id.to_owned(),
        seq: request.seq,
        raw_len: request.raw_len,
        compressed: STANDARD
            .decode(request.data.as_bytes())
            .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "bad_chunk"))?,
        sha256: request.sha256,
        is_last: request.is_last,
    };
    upload
        .assembler
        .accept(&chunk, &mut upload.cast)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "bad_chunk"))?;
    Ok((
        StatusCode::OK,
        serde_json::json!({ "acked_through": request.seq }),
    ))
}

fn receipt(request: &RecordingComplete) -> (StatusCode, serde_json::Value) {
    let state = if request.manifest.incomplete {
        "incomplete"
    } else {
        "complete"
    };
    (
        StatusCode::OK,
        serde_json::json!({ "state": state, "chunks": request.manifest.chunks }),
    )
}

fn offset(seconds: u64) -> Result<time::OffsetDateTime, Failure> {
    Ok(time::OffsetDateTime::from_unix_timestamp(signed(seconds))?)
}

fn port(addr: &str) -> Result<u16, Failure> {
    Ok(addr.parse::<SocketAddr>()?.port())
}

fn json(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn enroll(State(stand): State<Arc<Stand>>, body: Bytes) -> Response {
    match serde_json::from_slice::<EnrollRequest>(&body) {
        Ok(request) => {
            *stand
                .enrolled
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(request);
            let response = EnrollResponse {
                handle: HANDLE.to_owned(),
                code: "STND-0001".to_owned(),
                expires_at: signed(now() + 3600),
                poll_interval: 1,
            };
            match serde_json::to_value(&response) {
                Ok(value) => json(StatusCode::OK, &value),
                Err(_) => json(StatusCode::INTERNAL_SERVER_ERROR, &serde_json::json!({})),
            }
        }
        Err(_) => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": "invalid_request"}),
        ),
    }
}

async fn poll(State(stand): State<Arc<Stand>>) -> Response {
    let enrolled = stand
        .enrolled
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let state = match enrolled.map(|request| stand.approve(&request)) {
        Some(Ok(approved)) => PollResponse::Approved(approved),
        Some(Err(error)) => {
            tracing::error!(error = %error, "cannot approve the enrollment");
            PollResponse::Rejected
        }
        None => PollResponse::Pending,
    };
    match serde_json::to_value(&state) {
        Ok(value) => json(StatusCode::OK, &value),
        Err(_) => json(StatusCode::INTERNAL_SERVER_ERROR, &serde_json::json!({})),
    }
}

struct AnyEnrolledNode;

impl PeerAuthenticator for AnyEnrolledNode {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(async move {
            let unknown = || Rejection::new(RejectReason::UnknownNode);
            let (_, certificate) = parse_x509_certificate(peer_cert_der).map_err(|_| unknown())?;
            let san = certificate
                .subject_alternative_name()
                .ok()
                .flatten()
                .ok_or_else(unknown)?;
            match san.value.general_names.as_slice() {
                [GeneralName::URI(uri)] if *uri == format!("urn:jaunt:node:{NODE_ID}") => {
                    Ok(NodeId::new(NODE_ID)?)
                }
                _ => Err(unknown()),
            }
        })
    }
}

struct AgentApi(Arc<Stand>);

impl AgentApiHandler for AgentApi {
    fn serve(
        &self,
        _node: NodeId,
        stream: TlsStream<TcpStream>,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let stand = Arc::clone(&self.0);
        Box::pin(async move {
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            loop {
                let accepted = tokio::select! {
                    () = shutdown.cancelled() => return,
                    accepted = connection.accept() => accepted,
                };
                let Some(Ok((request, respond))) = accepted else {
                    return;
                };
                tokio::spawn(answer(Arc::clone(&stand), request, respond));
            }
        })
    }
}

async fn answer(
    stand: Arc<Stand>,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    let (parts, mut body) = request.into_parts();
    let limit = if parts.uri.path().starts_with(RECORDINGS_PATH_PREFIX) {
        MAX_RECORDING_BODY
    } else {
        MAX_BODY
    };
    let mut received = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        if body.flow_control().release_capacity(chunk.len()).is_err()
            || received.len() + chunk.len() > limit
        {
            return;
        }
        received.extend_from_slice(&chunk);
    }
    let (status, reply) = match parts.uri.path() {
        "/v1/agent/trust" if stand.flag("no-trust") => (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error": "unavailable"}),
        ),
        "/v1/agent/trust" => (
            StatusCode::OK,
            serde_json::json!({"user_ca_keys": [stand.user_ca_line]}),
        ),
        "/v1/agent/authorize" => {
            stand.record("authorize.log", &received);
            if stand.flag("deny") {
                (StatusCode::OK, serde_json::json!({"decision": "deny"}))
            } else {
                (
                    StatusCode::OK,
                    serde_json::json!({"decision": "allow", "permissions": {
                        "pty": true, "port_forwarding": stand.flag("forward"), "record_input": false,
                        "max_duration_secs": 3600,
                    }}),
                )
            }
        }
        "/v1/agent/session/end" => {
            stand.record("session-end.log", &received);
            (StatusCode::OK, serde_json::json!({"outcome": "recorded"}))
        }
        path if path.starts_with(RECORDINGS_PATH_PREFIX) => stand.recording(path, &received),
        _ => (
            StatusCode::NOT_FOUND,
            serde_json::json!({"error": "not_found"}),
        ),
    };
    let response = http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("date", httpdate::fmt_http_date(SystemTime::now()))
        .body(());
    let Ok(response) = response else {
        return;
    };
    if let Ok(mut send) = respond.send_response(response, false)
        && let Err(error) = send.send_data(Bytes::from(reply.to_string()), true)
    {
        tracing::warn!(error = %error, "cannot answer an agent API call");
    }
}

struct AllowEverything {
    sessions: Arc<Stand>,
}

impl ControlPlane for AllowEverything {
    fn route(&self, _request: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
        let number = self.sessions.sessions.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            Ok(RouteDecision::Allow {
                session_id: format!("stand-session-{number}"),
                node_id: NODE_ID.to_owned(),
            })
        })
    }

    fn authorize(
        &self,
        _node: NodeCaller,
        _request: AuthorizeRequest,
    ) -> BoxFuture<'_, Result<AuthorizeDecision, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn session_end(
        &self,
        _node: NodeCaller,
        _request: SessionEnd,
    ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }
}

struct GateIssuer(Arc<Stand>);

impl HostCertIssuer for GateIssuer {
    fn issue<'a>(
        &'a self,
        public_key_openssh: &'a str,
        hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>> {
        Box::pin(async move {
            let public = PublicKey::from_openssh(public_key_openssh)
                .map_err(|_| IssueError::InvalidRequest)?;
            let names: Vec<&str> = hostnames.iter().map(String::as_str).collect();
            self.0
                .host_certificate(&public, &names, "jaunt-host:gate:1")
                .map_err(|_| IssueError::Unavailable)
        })
    }
}

fn internal_root() -> Result<CertifiedIssuer<'static, KeyPair>, Failure> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "jaunt stand internal root");
    Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
}

fn hub_tls(stand: &Stand) -> Result<rustls::ServerConfig, Failure> {
    let mut params = CertificateParams::new(vec![AGENTS_NAME.to_owned()])?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let leaf = params.signed_by(&key, &*stand.root)?;
    let mut roots = RootCertStore::empty();
    roots.add(stand.root.der().clone())?;
    Ok(agent_server_config(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        roots,
    )?)
}

fn write_private(path: &Path, content: &str) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

fn write_client(stand: &Stand, user_ca: &PrivateKey) -> Result<(), Failure> {
    let client = stand.dir.join("client");
    fs::create_dir_all(&client)?;
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    let identity = client.join("id");
    write_private(&identity, &key.to_openssh(LineEnding::LF)?)?;
    let now = now();
    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng,
        key.public_key().key_data().clone(),
        now.saturating_sub(120),
        now + 3600,
    )?;
    builder.serial(SERIAL)?;
    builder.cert_type(CertType::User)?;
    builder.key_id(format!("jaunt:{EMAIL}:{SERIAL}"))?;
    builder.valid_principal(USER_ID)?;
    builder.extension("permit-pty", "")?;
    let certificate = builder.sign(user_ca)?;
    fs::write(
        client.join("id-cert.pub"),
        format!("{}\n", certificate.to_openssh()?),
    )?;
    fs::write(
        client.join("known_hosts"),
        format!(
            "@cert-authority {GATE_NAME},*.{SUFFIX} {}\n",
            stand.host_ca.public_key().to_openssh()?
        ),
    )?;
    let config = format!(
        "Host gate\n  HostName 127.0.0.1\n  Port {gate_port}\n  User jaunt\n  HostKeyAlias {GATE_NAME}\n\
         Host *.{SUFFIX}\n  ProxyJump gate\n\
         Host *\n  UserKnownHostsFile {known}\n  GlobalKnownHostsFile /dev/null\n  \
         StrictHostKeyChecking yes\n  CheckHostIP no\n  BatchMode yes\n  IdentitiesOnly yes\n  \
         IdentityAgent none\n  IdentityFile {identity}\n  CertificateFile {certificate}\n  \
         ConnectTimeout 30\n",
        gate_port = port(GATE_ADDR)?,
        known = client.join("known_hosts").display(),
        identity = identity.display(),
        certificate = client.join("id-cert.pub").display(),
    );
    fs::write(client.join("config"), config)?;
    Ok(())
}

async fn serve(dir: PathBuf) -> Result<(), Failure> {
    fs::create_dir_all(&dir)?;
    let user_ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    let stand = Arc::new(Stand {
        dir,
        root: internal_root()?,
        host_ca: PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?,
        user_ca_line: user_ca.public_key().to_openssh()?,
        enrolled: Mutex::new(None),
        sessions: AtomicU64::new(0),
        uploads: Mutex::new(HashMap::new()),
    });
    write_client(&stand, &user_ca)?;

    let enroll_router = Router::new()
        .route("/v1/agent/enroll", post(enroll))
        .route("/v1/agent/enroll/poll", post(poll))
        .with_state(Arc::clone(&stand));
    let enroll_listener = TcpListener::bind(ENROLL_ADDR).await?;
    let enroll_task =
        tokio::spawn(async move { axum::serve(enroll_listener, enroll_router).await });

    let mut hub_config = AgentHubConfig::new(AGENTS_NAME, Arc::new(hub_tls(&stand)?));
    hub_config.tunnel = TunnelOptions {
        stream_window: 1024 * 1024,
        connection_window: 16 * 1024 * 1024,
        ..TunnelOptions::default()
    };
    let hub = AgentHub::start(
        TcpListener::bind(HUB_ADDR).await?,
        hub_config,
        Arc::new(AnyEnrolledNode),
        Arc::new(AgentApi(Arc::clone(&stand))),
    )?;

    let gate = SshGate::new(
        SshGateConfig::new(vec![GATE_NAME.to_owned()], SUFFIX),
        Arc::new(GateIssuer(Arc::clone(&stand))),
        Arc::new(UserCaSource::new(UserCaKeys::from_openssh_lines([stand
            .user_ca_line
            .as_str()])?)),
        Arc::new(AllowEverything {
            sessions: Arc::clone(&stand),
        }),
        hub.registry().clone(),
    )
    .await?;
    let gate_listener = TcpListener::bind(GATE_ADDR).await?;
    fs::write(stand.dir.join("ready"), b"ready\n")?;
    tracing::info!("the stand is ready");

    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            stop.cancel();
        }
    });
    gate.serve(gate_listener, shutdown).await?;
    enroll_task.abort();
    hub.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

fn main() -> Result<(), Failure> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: ssh_stand <directory>")?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(dir))
}
