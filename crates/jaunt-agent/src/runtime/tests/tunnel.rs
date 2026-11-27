use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::TrustRole;
use jaunt_tunnel::{
    BoxFuture, H2Io, IncomingStream, NodeId, OpenError, ServiceName, SessionId, StreamHandler,
    StreamKind, StreamMeta, SwappableClientCert, TunnelClient, TunnelClientConfig,
    agent_client_config_swappable,
};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use super::support::{
    Behaviour, CLIENT, FakeServiceControl, TestHandler, UserCa, UserSpec, approved, client_config,
    dns_name, fixed, local_services, wait_until,
};
use crate::clock::unix_secs;
use crate::keys::{HostKey, TlsKey};
use crate::run::api::API_KEEPALIVE;
use crate::runtime::approvals::{APPROVAL_TIMING, ApprovalPoller};
use crate::runtime::certs::{SERVICE_CERTIFICATE_BACKOFF, ServiceCertificates};
use crate::runtime::directory::{Approvals, ApprovedService, ServiceDirectory};
use crate::runtime::handler::HandlerRegistry;
use crate::runtime::limits::SERVICE_LIMITS;
use crate::runtime::x509::UserX509Trust;
use crate::runtime::{KindRouter, RuntimeParts, ServiceRuntime};
use crate::testkit::{
    AGENT_HOST, ApiStep, FakeGate, ManualClock, NODE_ID, NODE_NAME, NodeIdentity, TestPki,
    agent_api, soon,
};
use jaunt_proto::AGENT_SERVICES_PATH;

struct DropSsh;

impl StreamHandler for DropSsh {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        drop(stream);
        Box::pin(async {})
    }
}

struct Agent {
    gate: FakeGate,
    pki: Arc<TestPki>,
    ca: UserCa,
    now: i64,
    control: Arc<FakeServiceControl>,
    approved: Option<watch::Sender<Vec<ApprovedService>>>,
    announced: Arc<Notify>,
    served: watch::Receiver<Option<jaunt_tunnel::ServedKinds>>,
    stop: CancellationToken,
    tunnel: JoinHandle<Result<(), jaunt_tunnel::ClientError>>,
}

const GRAFANA: &str = "grafana";

async fn agent(services: &[ApprovedService]) -> Agent {
    agent_with(services, false, None).await
}

async fn agent_with(
    services: &[ApprovedService],
    ssh_enabled: bool,
    polled: Option<Option<ApiStep>>,
) -> Agent {
    let start = SystemTime::now();
    let now = unix_secs(start);
    let clock = ManualClock::new(start);
    let pki = Arc::new(TestPki::new());
    let tls = TlsKey::generate().unwrap();
    let host = HostKey::generate().unwrap();
    let mut gate = FakeGate::start(
        pki.clone(),
        NodeIdentity {
            spki: tls.spki_der().to_vec(),
            host_key: host.key_data().clone(),
        },
        &[],
    )
    .await;
    let node = pki.node_certificates(tls.spki_der(), host.key_data(), NODE_ID, NODE_NAME);
    let identity = Arc::new(
        SwappableClientCert::new(
            vec![CertificateDer::from(
                STANDARD.decode(&node.x509_certificate_der).unwrap(),
            )],
            tls.rustls_key(),
        )
        .unwrap(),
    );
    let client = agent_client_config_swappable(pki.roots(), identity).unwrap();
    let mut config = TunnelClientConfig::new(
        Arc::new(client),
        gate.endpoint(),
        AGENT_HOST,
        "jaunt-agent/test",
    );
    let control = Arc::new(FakeServiceControl::new(
        pki.clone(),
        clock.clone(),
        services,
    ));
    let ca = UserCa::new(now);
    let user_x509 = Arc::new(UserX509Trust::default());
    user_x509.install(UserCa::roots(&[(&ca, TrustRole::Active)]));
    let mut handlers = HandlerRegistry::default();
    handlers
        .register(StreamKind::Tcp, TestHandler::new(Behaviour::Stubborn))
        .unwrap();
    let handlers = Arc::new(handlers);
    let certificates = Arc::new(ServiceCertificates::new(
        control.clone(),
        clock.clone(),
        fixed(1.0),
        SERVICE_CERTIFICATE_BACKOFF,
    ));
    let (directory, directory_changes) = watch::channel(Arc::new(ServiceDirectory::default()));
    let (served, served_changes) = watch::channel(None);
    config.follow_served_kinds(served_changes.clone());
    let mut local = local_services(services);
    local.ssh_enabled = ssh_enabled;
    let approvals = Approvals {
        local: Arc::new(local),
        handlers: handlers.clone(),
        directory,
        served,
        certificates: certificates.clone(),
    };
    approvals.publish(&[]);
    let stop = CancellationToken::new();
    let (approved, approved_changes) = watch::channel(Vec::new());
    tokio::spawn(approvals.follow(approved_changes, stop.clone()));
    let announced = Arc::new(Notify::new());
    let approved = match polled {
        None => Some(approved),
        Some(listed) => {
            if let Some(listed) = listed {
                gate.set_standing(AGENT_SERVICES_PATH, listed);
            }
            let (api, _) = agent_api(&pki, &gate.endpoint(), API_KEEPALIVE);
            let poller = ApprovalPoller {
                source: Arc::new(api),
                approved,
                events: config.subscribe(),
                announced: announced.clone(),
                sample: fixed(1.0),
                timing: APPROVAL_TIMING,
            };
            tokio::spawn(poller.run(stop.clone()));
            None
        }
    };
    let runtime = Arc::new(ServiceRuntime::new(RuntimeParts {
        control: control.clone(),
        clock,
        user_x509,
        certificates,
        handlers,
        directory: directory_changes,
        limits: SERVICE_LIMITS,
    }));
    let router = Arc::new(KindRouter {
        ssh: Arc::new(DropSsh),
        services: runtime,
    });
    let tunnel = tokio::spawn(TunnelClient::run(config, router, stop.clone()));
    gate.wait_connected().await;
    Agent {
        gate,
        pki,
        ca,
        now,
        control,
        approved,
        announced,
        served: served_changes,
        stop,
        tunnel,
    }
}

impl Agent {
    async fn approve(&mut self, services: &[ApprovedService]) {
        self.served.mark_unchanged();
        self.approved
            .as_ref()
            .unwrap()
            .send_replace(services.to_vec());
        soon(
            "the served kinds to follow the approvals",
            self.served.changed(),
        )
        .await
        .unwrap();
    }

    async fn open(&self, session: &str) -> Result<H2Io, OpenError> {
        self.open_service(StreamKind::Tcp, GRAFANA, session).await
    }

    async fn open_service(
        &self,
        kind: StreamKind,
        service: &str,
        session: &str,
    ) -> Result<H2Io, OpenError> {
        let meta = StreamMeta::with_service(
            SessionId::new(session).unwrap(),
            kind,
            ServiceName::new(service).unwrap(),
            CLIENT,
        )
        .unwrap();
        self.gate
            .registry
            .open_stream(&NodeId::new(NODE_ID).unwrap(), &meta)
            .await
    }

    async fn session(&self, session: &str) -> TlsStream<H2Io> {
        let io = self.open(session).await.unwrap();
        let user = self.ca.issue(&UserSpec::valid(self.now));
        let config = client_config(&self.pki, Some(&user), &[]);
        let name = ServerName::try_from(dns_name(StreamKind::Tcp, GRAFANA)).unwrap();
        let mut stream = soon(
            "the inner TLS handshake",
            TlsConnector::from(config).connect(name, io),
        )
        .await
        .unwrap();
        echo(&mut stream, session.as_bytes()).await;
        stream
    }

    async fn stop(self) {
        self.stop.cancel();
        soon("the tunnel to stop", self.tunnel)
            .await
            .unwrap()
            .unwrap();
        self.gate.stop().await;
    }
}

async fn echo(stream: &mut TlsStream<H2Io>, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut echoed = vec![0_u8; message.len()];
    soon("the echo", stream.read_exact(&mut echoed))
        .await
        .unwrap();
    assert_eq!(echoed, message);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tunnel_serves_a_service_kind_only_while_it_is_approved_and_handled() {
    let grafana = approved(StreamKind::Tcp, GRAFANA);
    let billing = approved(StreamKind::Db, "billing");
    let mut agent = agent(&[grafana.clone(), billing.clone()]).await;
    assert!(matches!(
        agent.open("s-before").await,
        Err(OpenError::Refused(400))
    ));

    agent.approve(std::slice::from_ref(&grafana)).await;
    let mut stream = agent.session("s-approved").await;
    echo(&mut stream, b"still approved").await;

    agent.approve(&[]).await;
    assert!(matches!(
        agent.open("s-after").await,
        Err(OpenError::Refused(400))
    ));
    agent.approve(&[grafana, billing]).await;
    assert!(matches!(
        agent
            .open_service(StreamKind::Db, "billing", "s-unhandled")
            .await,
        Err(OpenError::Refused(400))
    ));
    assert!(agent.open("s-handled").await.is_ok());
    drop(stream);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminating_a_session_closes_only_its_connection_within_five_seconds() {
    let grafana = approved(StreamKind::Tcp, GRAFANA);
    let mut agent = agent(std::slice::from_ref(&grafana)).await;
    agent.approve(std::slice::from_ref(&grafana)).await;
    let mut doomed = agent.session("s-doomed").await;
    let mut kept = agent.session("s-kept").await;

    agent
        .gate
        .registry
        .terminate_session(
            &NodeId::new(NODE_ID).unwrap(),
            &SessionId::new("s-doomed").unwrap(),
        )
        .unwrap();
    let mut buffer = [0_u8; 16];
    let closed = tokio::time::timeout(Duration::from_secs(5), doomed.read(&mut buffer))
        .await
        .expect("the terminated connection must close within five seconds");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    echo(&mut kept, b"the other session lives").await;
    wait_until("the end of the terminated session", || {
        agent
            .control
            .ends()
            .iter()
            .any(|end| end.session_id == "s-doomed")
    })
    .await;
    let ends = agent.control.ends();
    assert_eq!(ends.len(), 1, "{ends:?}");
    drop(kept);
    agent.stop().await;
}

fn grafana_listed() -> serde_json::Value {
    serde_json::json!({"services": [{"id": "id-grafana", "kind": "tcp", "name": GRAFANA}]})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_serves_what_the_control_plane_lists_after_one_read() {
    let grafana = approved(StreamKind::Tcp, GRAFANA);
    let mut agent = agent_with(
        std::slice::from_ref(&grafana),
        false,
        Some(Some(ApiStep::Json(
            200,
            serde_json::json!({"services": []}),
        ))),
    )
    .await;
    wait_until("the first read of the approved services", || {
        !agent.gate.requests(AGENT_SERVICES_PATH).is_empty()
    })
    .await;
    assert!(matches!(
        agent.open("s-before").await,
        Err(OpenError::Refused(400))
    ));

    agent
        .gate
        .set_standing(AGENT_SERVICES_PATH, ApiStep::Json(200, grafana_listed()));
    agent.served.mark_unchanged();
    agent.announced.notify_one();
    soon(
        "the served kinds to follow one read",
        agent.served.changed(),
    )
    .await
    .unwrap();
    let mut stream = agent.session("s-listed").await;
    echo(&mut stream, b"approved by control").await;

    agent.gate.set_standing(
        AGENT_SERVICES_PATH,
        ApiStep::Json(200, serde_json::json!({"services": []})),
    );
    agent.served.mark_unchanged();
    agent.announced.notify_one();
    soon(
        "the served kinds to drop the service",
        agent.served.changed(),
    )
    .await
    .unwrap();
    assert!(matches!(
        agent.open("s-withdrawn").await,
        Err(OpenError::Refused(400))
    ));
    assert!(
        agent
            .gate
            .requests(AGENT_SERVICES_PATH)
            .iter()
            .all(|seen| seen.method == "GET")
    );
    drop(stream);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_of_an_old_control_plane_serves_ssh_only() {
    let grafana = approved(StreamKind::Tcp, GRAFANA);
    let answers = [
        None,
        Some(ApiStep::Json(
            405,
            serde_json::json!({"error": "method_not_allowed"}),
        )),
    ];
    for answer in answers {
        let agent = agent_with(std::slice::from_ref(&grafana), true, Some(answer)).await;
        wait_until("the refused read of the approved services", || {
            !agent.gate.requests(AGENT_SERVICES_PATH).is_empty()
        })
        .await;
        agent.announced.notify_one();
        wait_until("a second read", || {
            agent.gate.requests(AGENT_SERVICES_PATH).len() >= 2
        })
        .await;
        assert_eq!(
            agent
                .served
                .borrow()
                .as_ref()
                .map(|kinds| kinds.as_slice().to_vec()),
            Some(vec![StreamKind::Ssh])
        );
        assert!(matches!(
            agent.open("s-tcp").await,
            Err(OpenError::Refused(400))
        ));
        let ssh =
            StreamMeta::new(SessionId::new("s-ssh").unwrap(), StreamKind::Ssh, CLIENT).unwrap();
        assert!(
            agent
                .gate
                .registry
                .open_stream(&NodeId::new(NODE_ID).unwrap(), &ssh)
                .await
                .is_ok()
        );
        agent.stop().await;
    }
}
