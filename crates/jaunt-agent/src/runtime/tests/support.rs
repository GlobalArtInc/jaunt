use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{
    AgentEventBatch, AgentEventsAccepted, AnnouncedService, DbAccessRequest, ServiceAccess,
    ServiceAnnouncement, ServiceAuthorizeRequest, ServiceAuthorizeResponse,
    ServiceCertificateRequest, ServiceCertificateResponse, ServiceEnd, ServiceKind, ServiceOutcome,
    SessionEndOutcome, TrustRole, TrustedX509Root,
};
use jaunt_tunnel::{BoxFuture, ServiceName, SessionId, StreamKind, StreamMeta};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::clock::{Clock, unix_secs};
use crate::run::api::{ApiError, EventsAnswer};
use crate::runtime::certs::ServiceCertificates;
use crate::runtime::control::ServiceControl;
use crate::runtime::directory::{ApprovedService, ServiceDirectory};
use crate::runtime::events::{EventSink, EventTransport, SINK_LIMITS, SessionEvent};
use crate::runtime::handler::{
    HandlerError, HandlerRegistry, Prepared, ServiceConnection, ServiceGrant, ServiceHandler,
    ServiceSession,
};
use crate::runtime::limits::{SERVICE_LIMITS, ServiceLimits};
use crate::runtime::x509::{UserRoots, UserX509Trust, VerifiedUser};
use crate::runtime::{RuntimeParts, ServiceRuntime};
use crate::testkit::{ManualClock, TestPki, soon};
use crate::trust::Sampler;

pub const DOMAIN: &str = "svc.test";
pub const USER_ID: &str = "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11";
pub const CLIENT: &str = "203.0.113.5:40000";
pub const TCP_ADDRESS: &str = "10.0.0.5:3000";
pub const DAY: i64 = 24 * 3600;

fn offset(secs: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(secs).unwrap()
}

pub fn ssh_fingerprint(raw: &[u8]) -> String {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(raw);
    Sha256::digest(&blob)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn dns_name(kind: StreamKind, name: &str) -> String {
    format!("{name}.{}.{DOMAIN}", kind.as_str())
}

pub fn service_id(name: &str) -> String {
    format!("id-{name}")
}

pub fn approved(kind: StreamKind, name: &str) -> ApprovedService {
    ApprovedService {
        id: service_id(name),
        kind,
        name: ServiceName::new(name).unwrap(),
    }
}

pub struct UserCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
    raw: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Clone)]
pub struct UserSpec {
    pub not_before: i64,
    pub not_after: i64,
    pub sans: Vec<SanType>,
    pub usages: Vec<ExtendedKeyUsagePurpose>,
    pub ed25519: bool,
    pub serial: Vec<u8>,
    pub ca: bool,
}

impl UserSpec {
    pub fn valid(now: i64) -> Self {
        Self {
            not_before: now - 60,
            not_after: now + 8 * 3600,
            sans: vec![user_uri(USER_ID)],
            usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
            ed25519: true,
            serial: 4242_u64.to_be_bytes().to_vec(),
            ca: false,
        }
    }
}

pub fn user_uri(user_id: &str) -> SanType {
    SanType::URI(Ia5String::try_from(format!("urn:jaunt:user:{user_id}")).unwrap())
}

pub struct UserCert {
    pub der: Vec<u8>,
    pub key: KeyPair,
}

impl UserCert {
    pub fn client_auth(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![CertificateDer::from(self.der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der())),
        )
    }

    pub fn subject_fingerprint(&self) -> String {
        ssh_fingerprint(self.key.public_key_raw())
    }
}

fn root_params(not_before: i64, not_after: i64, ca: bool, name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    }
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = offset(not_before);
    params.not_after = offset(not_after);
    params
}

impl UserCa {
    pub fn new(now: i64) -> Self {
        Self::with_validity(now - DAY, now + 5 * 365 * DAY)
    }

    pub fn with_validity(not_before: i64, not_after: i64) -> Self {
        Self::build(root_params(
            not_before,
            not_after,
            true,
            "test user x509 root",
        ))
    }

    pub fn self_signed_leaf(now: i64) -> Self {
        Self::build(root_params(
            now - DAY,
            now + DAY,
            false,
            "test self-signed leaf",
        ))
    }

    fn build(params: CertificateParams) -> Self {
        let (not_before, not_after) = (
            params.not_before.unix_timestamp(),
            params.not_after.unix_timestamp(),
        );
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let raw = key.public_key_raw().to_vec();
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).unwrap(),
            raw,
            not_before,
            not_after,
        }
    }

    pub fn intermediate(&self, now: i64) -> Self {
        let params = root_params(now - DAY, now + DAY, true, "test intermediate");
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let raw = key.public_key_raw().to_vec();
        Self {
            issuer: CertifiedIssuer::signed_by(params, key, &self.issuer).unwrap(),
            raw,
            not_before: now - DAY,
            not_after: now + DAY,
        }
    }

    pub fn fingerprint(&self) -> String {
        ssh_fingerprint(&self.raw)
    }

    pub fn root(&self, role: TrustRole) -> TrustedX509Root {
        TrustedX509Root {
            role,
            fingerprint: self.fingerprint(),
            certificate_der: STANDARD.encode(self.issuer.der()),
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }

    pub fn roots(cas: &[(&UserCa, TrustRole)]) -> UserRoots {
        let entries: Vec<TrustedX509Root> = cas.iter().map(|(ca, role)| ca.root(*role)).collect();
        UserRoots::from_trust(&entries, crate::testkit::unix_now()).unwrap()
    }

    pub fn issue(&self, spec: &UserSpec) -> UserCert {
        let mut params = CertificateParams::default();
        params.subject_alt_names = spec.sans.clone();
        params.extended_key_usages = spec.usages.clone();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = offset(spec.not_before);
        params.not_after = offset(spec.not_after);
        params.serial_number = Some(SerialNumber::from(spec.serial.clone()));
        params
            .distinguished_name
            .push(DnType::CommonName, "alice@example.com");
        if spec.ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        let algorithm = if spec.ed25519 {
            &rcgen::PKCS_ED25519
        } else {
            &rcgen::PKCS_ECDSA_P256_SHA256
        };
        let key = KeyPair::generate_for(algorithm).unwrap();
        let der = params
            .signed_by(&key, &*self.issuer)
            .unwrap()
            .der()
            .to_vec();
        UserCert { der, key }
    }
}

pub enum AuthorizeStep {
    Allow(ServiceAccess, u64),
    Deny,
    Hold,
    Fail(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lie {
    OtherKey,
    OtherName,
    SanDiffers,
    OtherKind,
    Expired,
    Garbage,
}

pub struct FakeServiceControl {
    pki: Arc<TestPki>,
    clock: Arc<ManualClock>,
    names: HashMap<String, String>,
    steps: Mutex<VecDeque<AuthorizeStep>>,
    standing: Mutex<Option<(ServiceAccess, u64)>>,
    authorizations: Mutex<Vec<ServiceAuthorizeRequest>>,
    ends: Mutex<Vec<ServiceEnd>>,
    certificates: AtomicUsize,
    failing: Mutex<bool>,
    certificate_gate: Mutex<Option<Arc<Notify>>>,
    lie: Mutex<Option<Lie>>,
    lifetime: i64,
    calls: Mutex<Vec<&'static str>>,
    batches: Mutex<Vec<AgentEventBatch>>,
}

impl FakeServiceControl {
    pub fn new(pki: Arc<TestPki>, clock: Arc<ManualClock>, services: &[ApprovedService]) -> Self {
        Self {
            pki,
            clock,
            names: services
                .iter()
                .map(|service| {
                    (
                        service.id.clone(),
                        dns_name(service.kind, service.name.as_str()),
                    )
                })
                .collect(),
            steps: Mutex::new(VecDeque::new()),
            standing: Mutex::new(Some((ServiceAccess::Tcp, 3600))),
            authorizations: Mutex::new(Vec::new()),
            ends: Mutex::new(Vec::new()),
            certificates: AtomicUsize::new(0),
            failing: Mutex::new(false),
            certificate_gate: Mutex::new(None),
            lie: Mutex::new(None),
            lifetime: 7 * DAY,
            calls: Mutex::new(Vec::new()),
            batches: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    pub fn batches(&self) -> Vec<AgentEventBatch> {
        self.batches.lock().unwrap().clone()
    }

    pub fn script(&self, step: AuthorizeStep) {
        self.steps.lock().unwrap().push_back(step);
    }

    pub fn allow_by_default(&self, access: ServiceAccess, max_duration_secs: u64) {
        *self.standing.lock().unwrap() = Some((access, max_duration_secs));
    }

    pub fn authorizations(&self) -> Vec<ServiceAuthorizeRequest> {
        self.authorizations.lock().unwrap().clone()
    }

    pub fn ends(&self) -> Vec<ServiceEnd> {
        self.ends.lock().unwrap().clone()
    }

    pub fn certificate_calls(&self) -> usize {
        self.certificates.load(Ordering::SeqCst)
    }

    pub fn fail_certificates(&self, failing: bool) {
        *self.failing.lock().unwrap() = failing;
    }

    pub fn lie(&self, lie: Option<Lie>) {
        *self.lie.lock().unwrap() = lie;
    }

    pub fn hold_certificates(&self) -> Arc<Notify> {
        let gate = Arc::new(Notify::new());
        *self.certificate_gate.lock().unwrap() = Some(gate.clone());
        gate
    }
}

fn unavailable(status: u16) -> ApiError {
    ApiError::Status {
        status,
        code: "unavailable".to_owned(),
        retry_after: None,
    }
}

impl ServiceControl for FakeServiceControl {
    fn authorize<'a>(
        &'a self,
        request: &'a ServiceAuthorizeRequest,
    ) -> BoxFuture<'a, Result<ServiceAuthorizeResponse, ApiError>> {
        self.authorizations.lock().unwrap().push(request.clone());
        let step = self.steps.lock().unwrap().pop_front();
        let step = step.unwrap_or_else(|| match self.standing.lock().unwrap().clone() {
            Some((access, secs)) => AuthorizeStep::Allow(access, secs),
            None => AuthorizeStep::Deny,
        });
        Box::pin(async move {
            match step {
                AuthorizeStep::Allow(access, max_duration_secs) => {
                    Ok(ServiceAuthorizeResponse::Allow {
                        access,
                        max_duration_secs,
                    })
                }
                AuthorizeStep::Deny => Ok(ServiceAuthorizeResponse::Deny),
                AuthorizeStep::Hold => std::future::pending().await,
                AuthorizeStep::Fail(status) => Err(unavailable(status)),
            }
        })
    }

    fn end<'a>(
        &'a self,
        end: &'a ServiceEnd,
    ) -> BoxFuture<'a, Result<SessionEndOutcome, ApiError>> {
        self.ends.lock().unwrap().push(end.clone());
        self.calls.lock().unwrap().push("end");
        Box::pin(async { Ok(SessionEndOutcome::Recorded) })
    }

    fn issue_certificate<'a>(
        &'a self,
        request: &'a ServiceCertificateRequest,
    ) -> BoxFuture<'a, Result<ServiceCertificateResponse, ApiError>> {
        let call = self.certificates.fetch_add(1, Ordering::SeqCst);
        let gate = self.certificate_gate.lock().unwrap().clone();
        let failing = *self.failing.lock().unwrap();
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.notified().await;
            }
            if failing {
                return Err(unavailable(503));
            }
            let mut dns_name = self.names.get(&request.service_id).cloned().unwrap();
            let mut spki = STANDARD.decode(&request.public_key).unwrap();
            let now = unix_secs(self.clock.now());
            let (mut not_before, mut not_after) = (now - 60, now + self.lifetime);
            let lie = *self.lie.lock().unwrap();
            let mut signed_name = dns_name.clone();
            match lie {
                Some(Lie::OtherKey) => {
                    spki = crate::keys::TlsKey::generate().unwrap().spki_der().to_vec();
                }
                Some(Lie::OtherName) => {
                    dns_name = format!("loki.tcp.{DOMAIN}");
                    signed_name = dns_name.clone();
                }
                Some(Lie::SanDiffers) => signed_name = format!("other.tcp.{DOMAIN}"),
                Some(Lie::OtherKind) => {
                    dns_name = dns_name.replacen(".tcp.", ".db.", 1);
                    signed_name = dns_name.clone();
                }
                Some(Lie::Expired) => (not_before, not_after) = (now - 120, now - 1),
                Some(Lie::Garbage) | None => {}
            }
            let certificate_der = if lie == Some(Lie::Garbage) {
                STANDARD.encode(b"not a certificate")
            } else {
                self.pki
                    .service_x509(&spki, &signed_name, not_before, not_after)
            };
            Ok(ServiceCertificateResponse {
                certificate_der,
                serial: 1000 + i64::try_from(call).unwrap(),
                dns_name,
                valid_after: not_before,
                valid_before: not_after,
            })
        })
    }
}

impl EventTransport for FakeServiceControl {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>> {
        self.calls.lock().unwrap().push("events");
        self.batches.lock().unwrap().push(batch.clone());
        let accepted = u64::try_from(batch.events.len()).unwrap();
        Box::pin(async move {
            Ok(EventsAnswer::Accepted(AgentEventsAccepted {
                accepted,
                ..AgentEventsAccepted::default()
            }))
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    Echo,
    Stubborn,
    Panic,
    PanicAtOnce,
    Fail,
    Hold,
}

pub struct Served {
    pub grant: ServiceGrant,
    pub session_id: String,
    pub service: String,
    pub user: VerifiedUser,
    pub alpn: Option<Vec<u8>>,
    pub client_addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preparing {
    Nothing,
    Hang,
    Db(DbAccessRequest),
}

pub struct TestHandler {
    behaviour: Mutex<Behaviour>,
    preparing: Mutex<Preparing>,
    served: Mutex<Vec<Served>>,
    emitting: Mutex<Vec<SessionEvent>>,
}

impl TestHandler {
    pub fn new(behaviour: Behaviour) -> Arc<Self> {
        Arc::new(Self {
            behaviour: Mutex::new(behaviour),
            preparing: Mutex::new(Preparing::Nothing),
            served: Mutex::new(Vec::new()),
            emitting: Mutex::new(Vec::new()),
        })
    }

    pub fn emit_on_serve(&self, events: Vec<SessionEvent>) {
        *self.emitting.lock().unwrap() = events;
    }

    pub fn prepare_with(&self, preparing: Preparing) {
        *self.preparing.lock().unwrap() = preparing;
    }

    pub fn served(&self) -> std::sync::MutexGuard<'_, Vec<Served>> {
        self.served.lock().unwrap()
    }
}

impl ServiceHandler for TestHandler {
    fn prepare<'a>(
        &'a self,
        _connection: &'a mut ServiceConnection,
    ) -> BoxFuture<'a, Result<Prepared, HandlerError>> {
        let preparing = self.preparing.lock().unwrap().clone();
        Box::pin(async move {
            match preparing {
                Preparing::Nothing => Ok(Prepared::default()),
                Preparing::Hang => std::future::pending().await,
                Preparing::Db(db) => Ok(Prepared { db: Some(db) }),
            }
        })
    }

    fn serve(
        &self,
        connection: ServiceConnection,
        grant: ServiceGrant,
        session: ServiceSession,
    ) -> BoxFuture<'static, Result<ServiceOutcome, HandlerError>> {
        self.served.lock().unwrap().push(Served {
            grant,
            session_id: session.session_id.clone(),
            service: session.service.as_str().to_owned(),
            user: connection.user.clone(),
            alpn: connection.alpn.clone(),
            client_addr: connection.client_addr.clone(),
        });
        for event in self.emitting.lock().unwrap().iter() {
            session.events.emit(event.clone());
        }
        let behaviour = *self.behaviour.lock().unwrap();
        assert!(
            behaviour != Behaviour::PanicAtOnce,
            "the test handler fails before it returns a future"
        );
        let mut stream = connection.stream;
        Box::pin(async move {
            match behaviour {
                Behaviour::Echo => {
                    let mut buffer = [0_u8; 1024];
                    loop {
                        let read = stream.read(&mut buffer).await.map_err(|_| HandlerError)?;
                        if read == 0 {
                            stream.shutdown().await.map_err(|_| HandlerError)?;
                            return Ok(ServiceOutcome::Closed);
                        }
                        stream
                            .write_all(&buffer[..read])
                            .await
                            .map_err(|_| HandlerError)?;
                        stream.flush().await.map_err(|_| HandlerError)?;
                    }
                }
                Behaviour::Stubborn => {
                    let mut buffer = [0_u8; 1024];
                    loop {
                        let read = match stream.read(&mut buffer).await {
                            Ok(read) if read > 0 => read,
                            Ok(_) | Err(_) => return std::future::pending().await,
                        };
                        if stream.write_all(&buffer[..read]).await.is_err()
                            || stream.flush().await.is_err()
                        {
                            return std::future::pending().await;
                        }
                    }
                }
                Behaviour::Panic | Behaviour::PanicAtOnce => {
                    panic!("the test handler fails on purpose")
                }
                Behaviour::Fail => Err(HandlerError),
                Behaviour::Hold => {
                    session.cancel.cancelled().await;
                    Ok(ServiceOutcome::Closed)
                }
            }
        })
    }
}

pub fn fixed(sample: f64) -> Sampler {
    Arc::new(move || sample)
}

pub fn local_services(services: &[ApprovedService]) -> ServiceAnnouncement {
    ServiceAnnouncement {
        ssh_enabled: false,
        services: services
            .iter()
            .map(|service| AnnouncedService {
                kind: match service.kind {
                    StreamKind::Kube => ServiceKind::Kubernetes,
                    StreamKind::Db => ServiceKind::Postgres,
                    StreamKind::Tcp | StreamKind::Ssh => ServiceKind::Tcp,
                },
                name: service.name.as_str().to_owned(),
                labels: Default::default(),
                address: (service.kind == StreamKind::Tcp).then(|| TCP_ADDRESS.to_owned()),
                kubernetes: None,
                postgres: None,
                tcp: None,
            })
            .collect(),
    }
}

pub struct Harness {
    pub runtime: Arc<ServiceRuntime>,
    pub control: Arc<FakeServiceControl>,
    pub clock: Arc<ManualClock>,
    pub pki: Arc<TestPki>,
    pub ca: UserCa,
    pub handler: Arc<TestHandler>,
    pub events: EventSink,
    pub now: i64,
    _directory: watch::Sender<Arc<ServiceDirectory>>,
}

pub struct HarnessOptions {
    pub services: Vec<ApprovedService>,
    pub handled: Vec<StreamKind>,
    pub behaviour: Behaviour,
    pub limits: ServiceLimits,
    pub trusted: bool,
    pub clock: Option<Arc<ManualClock>>,
    pub tcp: Option<Arc<dyn ServiceHandler>>,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            services: vec![
                approved(StreamKind::Tcp, "grafana"),
                approved(StreamKind::Kube, "prod-eu"),
                approved(StreamKind::Db, "billing"),
            ],
            handled: vec![StreamKind::Tcp, StreamKind::Kube],
            behaviour: Behaviour::Echo,
            limits: SERVICE_LIMITS,
            trusted: true,
            clock: None,
            tcp: None,
        }
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with(HarnessOptions::default())
    }

    pub fn with(options: HarnessOptions) -> Self {
        let clock = options
            .clock
            .unwrap_or_else(|| ManualClock::new(SystemTime::now()));
        let now = unix_secs(clock.now());
        let pki = Arc::new(TestPki::new());
        let ca = UserCa::new(now);
        let control = Arc::new(FakeServiceControl::new(
            pki.clone(),
            clock.clone(),
            &options.services,
        ));
        let user_x509 = Arc::new(UserX509Trust::default());
        if options.trusted {
            user_x509.install(UserCa::roots(&[(&ca, TrustRole::Active)]));
        }
        let handler = TestHandler::new(options.behaviour);
        let mut handlers = HandlerRegistry::default();
        for kind in &options.handled {
            handlers.register(*kind, handler.clone()).unwrap();
        }
        if let Some(tcp) = options.tcp {
            handlers.register(StreamKind::Tcp, tcp).unwrap();
        }
        let local = local_services(&options.services);
        let (directory, directory_changes) =
            watch::channel(Arc::new(ServiceDirectory::new(&local, &options.services)));
        let certificates = Arc::new(ServiceCertificates::new(
            control.clone(),
            clock.clone(),
            fixed(1.0),
            crate::runtime::certs::SERVICE_CERTIFICATE_BACKOFF,
        ));
        let events = EventSink::new(control.clone(), clock.clone(), fixed(1.0), SINK_LIMITS);
        tokio::spawn(events.clone().run(CancellationToken::new()));
        let runtime = Arc::new(ServiceRuntime::new(RuntimeParts {
            control: control.clone(),
            clock: clock.clone(),
            user_x509: user_x509.clone(),
            certificates,
            handlers: Arc::new(handlers),
            directory: directory_changes,
            limits: options.limits,
            events: events.clone(),
        }));
        Self {
            runtime,
            control,
            clock,
            pki,
            ca,
            handler,
            events,
            now,
            _directory: directory,
        }
    }

    pub fn user(&self) -> UserCert {
        self.ca.issue(&UserSpec::valid(self.now))
    }

    pub fn open(&self, kind: StreamKind, service: &str, session: &str) -> Opened {
        self.open_from(kind, service, session, CLIENT)
    }

    pub fn open_from(
        &self,
        kind: StreamKind,
        service: &str,
        session: &str,
        client: &str,
    ) -> Opened {
        let meta = StreamMeta::with_service(
            SessionId::new(session).unwrap(),
            kind,
            ServiceName::new(service).unwrap(),
            client,
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

    pub fn client_config(&self, user: Option<&UserCert>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
        client_config(&self.pki, user, alpn)
    }
}

pub fn client_config(pki: &TestPki, user: Option<&UserCert>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(pki.roots());
    let mut config = match user {
        Some(user) => {
            let (chain, key) = user.client_auth();
            builder.with_client_auth_cert(chain, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

pub struct Opened {
    pub client: Option<DuplexStream>,
    pub serving: JoinHandle<()>,
    pub cancel: CancellationToken,
}

impl Opened {
    pub fn take(&mut self) -> DuplexStream {
        self.client.take().unwrap()
    }

    pub async fn finished(self) {
        soon("the stream to be served", self.serving).await.unwrap();
    }
}

pub async fn handshake(
    io: DuplexStream,
    sni: &str,
    config: Arc<ClientConfig>,
) -> std::io::Result<TlsStream<DuplexStream>> {
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    TlsConnector::from(config).connect(name, io).await
}

pub async fn hello_then_read(
    mut io: DuplexStream,
    sni: &str,
    config: Arc<ClientConfig>,
) -> Vec<u8> {
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    let mut connection = rustls::ClientConnection::new(config, name).unwrap();
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).unwrap();
    drop(io.write_all(&hello).await);
    let mut received = Vec::new();
    soon(
        "the agent to close the stream",
        io.read_to_end(&mut received),
    )
    .await
    .unwrap();
    received
}

pub async fn closed_without_data(stream: &mut TlsStream<DuplexStream>) -> bool {
    let mut buffer = [0_u8; 64];
    match soon("the agent to close the session", stream.read(&mut buffer)).await {
        Ok(read) => read == 0,
        Err(_) => true,
    }
}

pub async fn wait_until(what: &str, condition: impl FnMut() -> bool) {
    crate::testkit::eventually(what, condition).await;
}

pub fn later(clock: &ManualClock, by: Duration) -> SystemTime {
    clock.now() + by
}
