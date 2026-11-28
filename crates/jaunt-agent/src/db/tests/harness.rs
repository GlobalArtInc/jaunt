use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_pgwire::{BackendDecoder, BackendMessage, Event, Limits};
use jaunt_proto::{
    AgentEventBatch, AgentEventValue, AgentEventsAccepted, AnnouncedService, DbAccess,
    PostgresAudit, PostgresSettings, PostgresTls, ServiceAccess, ServiceAnnouncement,
    ServiceAuthorizeRequest, ServiceAuthorizeResponse, ServiceCertificateRequest,
    ServiceCertificateResponse, ServiceEnd, ServiceKind, SessionEndOutcome, TrustRole,
};
use jaunt_tunnel::{BoxFuture, ServiceName, SessionId, StreamKind, StreamMeta};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use super::fake_pg::{Authority, FakePg, FakePgOptions, SERVER_NAME, cstr, message};
use crate::clock::{Clock, unix_secs};
use crate::db::{DB_LIMITS, DbHandler};
use crate::run::api::{ApiError, EventsAnswer};
use crate::runtime::certs::{SERVICE_CERTIFICATE_BACKOFF, ServiceCertificates};
use crate::runtime::control::ServiceControl;
use crate::runtime::directory::ServiceDirectory;
use crate::runtime::events::{EventSink, EventTransport, SINK_LIMITS, SinkLimits};
use crate::runtime::handler::HandlerRegistry;
use crate::runtime::limits::SERVICE_LIMITS;
use crate::runtime::tests::support::{
    Opened, UserCa, UserCert, UserSpec, approved, client_config, dns_name, fixed, handshake,
    user_uri,
};
use crate::runtime::x509::UserX509Trust;
use crate::runtime::{RuntimeParts, ServiceRuntime};
use crate::testkit::{ManualClock, TestPki, eventually, soon};

pub const SERVICE: &str = "billing";
pub const OTHER_USER: &str = "9b1d3c55-0a7e-4c2f-8e61-5f3a2b7c9d04";
const V3_0: u32 = 3 << 16;

pub enum Decision {
    Allow,
    AllowAs(&'static str, &'static str),
    Deny,
    Fail(u16),
}

pub struct FakeDbControl {
    pki: Arc<TestPki>,
    clients: Arc<Authority>,
    clock: Arc<ManualClock>,
    names: HashMap<String, String>,
    decisions: Mutex<VecDeque<Decision>>,
    max_duration: Mutex<u64>,
    authorizations: Mutex<Vec<ServiceAuthorizeRequest>>,
    ends: Mutex<Vec<ServiceEnd>>,
    batches: Mutex<Vec<AgentEventBatch>>,
    stalled: AtomicBool,
}

impl FakeDbControl {
    pub fn script(&self, decision: Decision) {
        self.decisions.lock().unwrap().push_back(decision);
    }

    pub fn set_max_duration(&self, secs: u64) {
        *self.max_duration.lock().unwrap() = secs;
    }

    pub fn stall_events(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }

    pub fn authorizations(&self) -> Vec<ServiceAuthorizeRequest> {
        self.authorizations.lock().unwrap().clone()
    }

    pub fn ends(&self) -> Vec<ServiceEnd> {
        self.ends.lock().unwrap().clone()
    }

    pub fn batches(&self) -> Vec<AgentEventBatch> {
        self.batches.lock().unwrap().clone()
    }
}

impl ServiceControl for FakeDbControl {
    fn authorize<'a>(
        &'a self,
        request: &'a ServiceAuthorizeRequest,
    ) -> BoxFuture<'a, Result<ServiceAuthorizeResponse, ApiError>> {
        self.authorizations.lock().unwrap().push(request.clone());
        let decision = self
            .decisions
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Decision::Allow);
        let max_duration_secs = *self.max_duration.lock().unwrap();
        Box::pin(async move {
            let db = request.db.clone().unwrap();
            let (user, name) = match decision {
                Decision::Allow => (db.user, db.name),
                Decision::AllowAs(user, name) => (user.to_owned(), name.to_owned()),
                Decision::Deny => return Ok(ServiceAuthorizeResponse::Deny),
                Decision::Fail(status) => {
                    return Err(ApiError::Status {
                        status,
                        code: "unavailable".to_owned(),
                        retry_after: None,
                    });
                }
            };
            let spki = STANDARD.decode(&db.agent_key).unwrap();
            let now = unix_secs(self.clock.now());
            Ok(ServiceAuthorizeResponse::Allow {
                access: ServiceAccess::Db(DbAccess {
                    certificate_der: STANDARD.encode(self.clients.client_leaf(&spki, &user)),
                    user,
                    name,
                    serial: 77,
                    valid_after: now - 60,
                    valid_before: now + 300,
                }),
                max_duration_secs,
            })
        })
    }

    fn end<'a>(
        &'a self,
        end: &'a ServiceEnd,
    ) -> BoxFuture<'a, Result<SessionEndOutcome, ApiError>> {
        self.ends.lock().unwrap().push(end.clone());
        Box::pin(async { Ok(SessionEndOutcome::Recorded) })
    }

    fn issue_certificate<'a>(
        &'a self,
        request: &'a ServiceCertificateRequest,
    ) -> BoxFuture<'a, Result<ServiceCertificateResponse, ApiError>> {
        Box::pin(async move {
            let dns_name = self.names.get(&request.service_id).cloned().unwrap();
            let spki = STANDARD.decode(&request.public_key).unwrap();
            let now = unix_secs(self.clock.now());
            Ok(ServiceCertificateResponse {
                certificate_der: self
                    .pki
                    .service_x509(&spki, &dns_name, now - 60, now + 3600),
                serial: 1000,
                dns_name,
                valid_after: now - 60,
                valid_before: now + 3600,
            })
        })
    }
}

impl EventTransport for FakeDbControl {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>> {
        let stalled = self.stalled.load(Ordering::SeqCst);
        if !stalled {
            self.batches.lock().unwrap().push(batch.clone());
        }
        let accepted = u64::try_from(batch.events.len()).unwrap();
        Box::pin(async move {
            if stalled {
                std::future::pending::<()>().await;
            }
            Ok(EventsAnswer::Accepted(AgentEventsAccepted {
                accepted,
                ..AgentEventsAccepted::default()
            }))
        })
    }
}

pub struct DbOptions {
    pub audit: PostgresAudit,
    pub server_name: Option<&'static str>,
    pub ca_file: bool,
    pub foreign_server_ca: bool,
    pub names: Vec<&'static str>,
    pub tls12_only: bool,
    pub key_bytes: usize,
    pub sink: SinkLimits,
    pub address: Option<String>,
    pub ca_file_bytes: Option<usize>,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            audit: PostgresAudit::default(),
            server_name: Some(SERVER_NAME),
            ca_file: true,
            foreign_server_ca: false,
            names: vec![SERVER_NAME],
            tls12_only: false,
            key_bytes: 4,
            sink: SINK_LIMITS,
            address: None,
            ca_file_bytes: None,
        }
    }
}

pub struct DbHarness {
    pub runtime: Arc<ServiceRuntime>,
    pub control: Arc<FakeDbControl>,
    pub clock: Arc<ManualClock>,
    pub pki: Arc<TestPki>,
    pub users: UserCa,
    pub pg: FakePg,
    pub handler: Arc<DbHandler>,
    pub events: EventSink,
    pub now: i64,
    stop: CancellationToken,
    _ca_dir: tempfile::TempDir,
    _directory: watch::Sender<Arc<ServiceDirectory>>,
}

impl Drop for DbHarness {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl DbHarness {
    pub async fn new() -> Self {
        Self::with(DbOptions::default()).await
    }

    pub async fn with(options: DbOptions) -> Self {
        let start = SystemTime::now();
        let now = unix_secs(start);
        let clock = ManualClock::new(start);
        let pki = Arc::new(TestPki::new());
        let users = UserCa::new(now);
        let clients = Arc::new(Authority::new("db-client test root"));
        let trusted = Authority::new("pg test root");
        let foreign = Authority::new("another pg root");
        let pg = FakePg::start(FakePgOptions {
            server: if options.foreign_server_ca {
                &foreign
            } else {
                &trusted
            },
            names: &options.names,
            clients: &clients,
            tls12_only: options.tls12_only,
            key_bytes: options.key_bytes,
        })
        .await;
        let ca_dir = tempfile::tempdir().unwrap();
        let ca_path = ca_dir.path().join("pg-ca.pem");
        let mut pem = trusted.pem().into_bytes();
        if let Some(size) = options.ca_file_bytes {
            pem.resize(size, b'\n');
        }
        std::fs::write(&ca_path, pem).unwrap();
        let service = approved(StreamKind::Db, SERVICE);
        let local = ServiceAnnouncement {
            ssh_enabled: false,
            services: vec![AnnouncedService {
                kind: ServiceKind::Postgres,
                name: SERVICE.to_owned(),
                labels: BTreeMap::new(),
                address: Some(options.address.unwrap_or_else(|| pg.address.clone())),
                kubernetes: None,
                postgres: Some(PostgresSettings {
                    tls: PostgresTls {
                        ca_file: options
                            .ca_file
                            .then(|| ca_path.to_str().unwrap().to_owned()),
                        server_name: options.server_name.map(str::to_owned),
                    },
                    audit: options.audit,
                }),
                tcp: None,
            }],
        };
        let control = Arc::new(FakeDbControl {
            pki: pki.clone(),
            clients,
            clock: clock.clone(),
            names: HashMap::from([(service.id.clone(), dns_name(StreamKind::Db, SERVICE))]),
            decisions: Mutex::new(VecDeque::new()),
            max_duration: Mutex::new(3600),
            authorizations: Mutex::new(Vec::new()),
            ends: Mutex::new(Vec::new()),
            batches: Mutex::new(Vec::new()),
            stalled: AtomicBool::new(false),
        });
        let user_x509 = Arc::new(UserX509Trust::default());
        user_x509.install(UserCa::roots(&[(&users, TrustRole::Active)]));
        let handler = Arc::new(DbHandler::with_limits(&local, clock.clone(), DB_LIMITS));
        let mut handlers = HandlerRegistry::default();
        handlers.register(StreamKind::Db, handler.clone()).unwrap();
        let (directory, directory_changes) = watch::channel(Arc::new(ServiceDirectory::new(
            &local,
            std::slice::from_ref(&service),
        )));
        let certificates = Arc::new(ServiceCertificates::new(
            control.clone(),
            clock.clone(),
            fixed(1.0),
            SERVICE_CERTIFICATE_BACKOFF,
        ));
        let events = EventSink::new(control.clone(), clock.clone(), fixed(1.0), options.sink);
        let stop = CancellationToken::new();
        tokio::spawn(events.clone().run(stop.clone()));
        let runtime = Arc::new(ServiceRuntime::new(RuntimeParts {
            control: control.clone(),
            clock: clock.clone(),
            user_x509,
            certificates,
            handlers: Arc::new(handlers),
            directory: directory_changes,
            limits: SERVICE_LIMITS,
            events: events.clone(),
        }));
        Self {
            runtime,
            control,
            clock,
            pki,
            users,
            pg,
            handler,
            events,
            now,
            stop,
            _ca_dir: ca_dir,
            _directory: directory,
        }
    }

    pub fn user(&self) -> UserCert {
        self.users.issue(&UserSpec::valid(self.now))
    }

    pub fn other_user(&self) -> UserCert {
        self.users.issue(&UserSpec {
            sans: vec![user_uri(OTHER_USER)],
            ..UserSpec::valid(self.now)
        })
    }

    pub fn open(&self, session: &str) -> Opened {
        let meta = StreamMeta::with_service(
            SessionId::new(session).unwrap(),
            StreamKind::Db,
            ServiceName::new(SERVICE).unwrap(),
            "203.0.113.5:40000",
        )
        .unwrap();
        let (client, agent) = tokio::io::duplex(64 * 1024);
        let cancel = CancellationToken::new();
        let runtime = self.runtime.clone();
        let token = cancel.clone();
        let serving = tokio::spawn(async move {
            runtime.serve(meta, Box::new(agent), token).await;
        });
        Opened {
            client: Some(client),
            serving,
            cancel,
        }
    }

    pub async fn connect_as(&self, session: &str, user: &UserCert) -> (Opened, PgClient) {
        let mut opened = self.open(session);
        let config = client_config(&self.pki, Some(user), &[]);
        let stream = handshake(opened.take(), &dns_name(StreamKind::Db, SERVICE), config)
            .await
            .unwrap();
        (opened, PgClient::new(stream))
    }

    pub async fn connect(&self, session: &str) -> (Opened, PgClient) {
        self.connect_as(session, &self.user()).await
    }

    pub async fn login(&self, session: &str) -> (Opened, PgClient, Vec<BackendMessage>) {
        let (opened, mut client) = self.connect(session).await;
        client.send(&startup(&default_startup())).await;
        let greeting = client.until_ready().await;
        (opened, client, greeting)
    }

    pub async fn ended(&self, session: &str) -> ServiceEnd {
        let reported = |end: &ServiceEnd| end.session_id == session;
        eventually("the session end to be reported", || {
            self.control.ends().iter().any(reported)
        })
        .await;
        self.control.ends().into_iter().find(reported).unwrap()
    }

    pub fn session_events(
        &self,
        session: &str,
    ) -> Vec<(String, BTreeMap<String, AgentEventValue>)> {
        self.control
            .batches()
            .into_iter()
            .flat_map(|batch| batch.events)
            .filter(|event| event.session_id == session)
            .map(|event| (event.name, event.fields))
            .collect()
    }

    pub fn named(&self, session: &str, name: &str) -> Vec<BTreeMap<String, AgentEventValue>> {
        self.session_events(session)
            .into_iter()
            .filter(|(event, _)| event == name)
            .map(|(_, fields)| fields)
            .collect()
    }
}

pub fn default_startup() -> Vec<(&'static str, &'static str)> {
    vec![
        ("user", "app"),
        ("database", "main"),
        ("application_name", "psql"),
    ]
}

pub fn packet(code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len() + 8)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn startup(parameters: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in parameters {
        body.extend(cstr(name));
        body.extend(cstr(value));
    }
    body.push(0);
    packet(V3_0, &body)
}

pub fn query(text: &str) -> Vec<u8> {
    message(b'Q', &cstr(text))
}

pub fn text(fields: &BTreeMap<String, AgentEventValue>, name: &str) -> Option<String> {
    match fields.get(name) {
        Some(AgentEventValue::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

pub struct PgClient {
    pub stream: TlsStream<DuplexStream>,
    decoder: BackendDecoder,
}

impl PgClient {
    fn new(stream: TlsStream<DuplexStream>) -> Self {
        Self {
            stream,
            decoder: BackendDecoder::new(Limits::default()).unwrap(),
        }
    }

    pub async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    pub async fn next(&mut self) -> Option<BackendMessage> {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            match self.decoder.next_event().unwrap() {
                Some(Event::Frame(frame)) => return Some(frame.into_message()),
                Some(Event::Continuation(_)) => continue,
                None => {}
            }
            let read = soon("a message from the agent", self.stream.read(&mut buffer)).await;
            match read {
                Ok(0) | Err(_) => return None,
                Ok(read) => self.decoder.push(&buffer[..read]).unwrap(),
            }
        }
    }

    pub async fn until_ready(&mut self) -> Vec<BackendMessage> {
        let mut messages = Vec::new();
        while let Some(message) = self.next().await {
            let done = matches!(message, BackendMessage::ReadyForQuery(_));
            messages.push(message);
            if done {
                return messages;
            }
        }
        panic!("the agent closed the session before ReadyForQuery: {messages:?}");
    }

    pub async fn rest(&mut self) -> Vec<BackendMessage> {
        let mut messages = Vec::new();
        while let Some(message) = self.next().await {
            messages.push(message);
        }
        messages
    }

    pub async fn byte(&mut self) -> Option<u8> {
        let mut answer = [0_u8; 1];
        match soon("a byte from the agent", self.stream.read(&mut answer)).await {
            Ok(1) => Some(answer[0]),
            _ => None,
        }
    }
}

pub fn fatal(messages: &[BackendMessage]) -> Option<(String, String)> {
    messages.iter().find_map(|message| match message {
        BackendMessage::ErrorResponse(notice) => {
            Some((notice.code.clone(), notice.message.clone()))
        }
        _ => None,
    })
}
