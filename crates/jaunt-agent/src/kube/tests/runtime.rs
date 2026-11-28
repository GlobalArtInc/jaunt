use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use jaunt_proto::{ServiceAccess, ServiceOutcome, TrustRole};
use jaunt_tunnel::{ServiceName, SessionId, StreamKind, StreamMeta};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::support::{
    FakeApi, PODS, SESSION, TestBody, alice, body_text, h2, h2_request, h2_watched,
};
use crate::clock::Clock;
use crate::clock::unix_secs;
use crate::kube::{KUBE_LIMITS, KubeHandler, KubeParts, declares_kubernetes};
use crate::runtime::certs::{SERVICE_CERTIFICATE_BACKOFF, ServiceCertificates};
use crate::runtime::directory::ServiceDirectory;
use crate::runtime::events::{EventSink, SINK_LIMITS};
use crate::runtime::handler::HandlerRegistry;
use crate::runtime::limits::SERVICE_LIMITS;
use crate::runtime::tests::support::{
    AuthorizeStep, CLIENT, FakeServiceControl, UserCa, UserSpec, approved, client_config, dns_name,
    fixed, handshake, local_services,
};
use crate::runtime::x509::UserX509Trust;
use crate::runtime::{RuntimeParts, ServiceRuntime};
use crate::testkit::{ManualClock, TestPki, eventually, soon};

const CUT: Duration = Duration::from_secs(1);

struct Stand {
    api: FakeApi,
    clock: Arc<ManualClock>,
    pki: Arc<TestPki>,
    ca: UserCa,
    now: i64,
    control: Arc<FakeServiceControl>,
    runtime: Arc<ServiceRuntime>,
    _directory: watch::Sender<Arc<ServiceDirectory>>,
    _stop: DropGuard,
}

struct Opened {
    tls: TlsStream<DuplexStream>,
    cancel: CancellationToken,
    serving: JoinHandle<()>,
}

impl Stand {
    async fn new() -> Self {
        let api = FakeApi::start().await;
        let start = SystemTime::now();
        let now = unix_secs(start);
        let clock = ManualClock::new(start);
        let pki = Arc::new(TestPki::new());
        let ca = UserCa::new(now);
        let services = vec![
            approved(StreamKind::Kube, "prod-eu"),
            approved(StreamKind::Tcp, "grafana"),
        ];
        let control = Arc::new(FakeServiceControl::new(
            pki.clone(),
            clock.clone(),
            &services,
        ));
        let user_x509 = Arc::new(UserX509Trust::default());
        user_x509.install(UserCa::roots(&[(&ca, TrustRole::Active)]));
        let local = local_services(&services);
        assert!(declares_kubernetes(&local));
        let handler = KubeHandler::new(KubeParts {
            upstream: &api.upstream(),
            services: &local,
            clock: clock.clone(),
            limits: KUBE_LIMITS,
        })
        .unwrap();
        let mut handlers = HandlerRegistry::default();
        handlers
            .register(StreamKind::Kube, Arc::new(handler))
            .unwrap();
        let (directory_sender, directory) =
            watch::channel(Arc::new(ServiceDirectory::new(&local, &services)));
        let events = EventSink::new(control.clone(), clock.clone(), fixed(1.0), SINK_LIMITS);
        let stop = CancellationToken::new();
        tokio::spawn(events.clone().run(stop.clone()));
        let runtime = Arc::new(ServiceRuntime::new(RuntimeParts {
            control: control.clone(),
            clock: clock.clone(),
            user_x509,
            certificates: Arc::new(ServiceCertificates::new(
                control.clone(),
                clock.clone(),
                fixed(1.0),
                SERVICE_CERTIFICATE_BACKOFF,
            )),
            handlers: Arc::new(handlers),
            directory,
            limits: SERVICE_LIMITS,
            events,
        }));
        Self {
            api,
            clock,
            pki,
            ca,
            now,
            control,
            runtime,
            _directory: directory_sender,
            _stop: stop.drop_guard(),
        }
    }

    async fn open(&self, access: ServiceAccess, max_secs: u64, alpn: &[u8]) -> Opened {
        self.control.script(AuthorizeStep::Allow(access, max_secs));
        let meta = StreamMeta::with_service(
            SessionId::new(SESSION).unwrap(),
            StreamKind::Kube,
            ServiceName::new("prod-eu").unwrap(),
            CLIENT,
        )
        .unwrap();
        let (client, agent) = tokio::io::duplex(64 * 1024);
        let cancel = CancellationToken::new();
        let serving = tokio::spawn({
            let runtime = self.runtime.clone();
            let cancel = cancel.clone();
            async move { runtime.serve(meta, Box::new(agent), cancel).await }
        });
        let user = self.ca.issue(&UserSpec::valid(self.now));
        let config = client_config(&self.pki, Some(&user), &[alpn]);
        let tls = handshake(client, &dns_name(StreamKind::Kube, "prod-eu"), config)
            .await
            .unwrap();
        Opened {
            tls,
            cancel,
            serving,
        }
    }

    async fn end_reason(&self) -> String {
        eventually("the end of the session to reach control", || {
            !self.control.ends().is_empty() && self.reasons().len() == 1
        })
        .await;
        self.reasons().remove(0)
    }

    fn reasons(&self) -> Vec<String> {
        self.control
            .batches()
            .iter()
            .flat_map(|batch| batch.events.clone())
            .filter(|event| event.name == "kube.session.end")
            .filter_map(|event| super::support::text(&event, "reason"))
            .collect()
    }
}

async fn ends_cleanly_within(body: &mut Incoming, limit: Duration) -> bool {
    tokio::time::timeout(limit, async {
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                return false;
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

#[tokio::test]
async fn the_runtime_gives_the_handler_the_name_of_the_service_certificate_as_the_host() {
    let stand = Stand::new().await;
    let opened = stand.open(alice(), 600, b"h2").await;
    let mut client = h2(opened.tls).await;
    let path = "/api/v1/namespaces/default/configmaps/c";
    let (status, body) = body_text(
        client
            .send_request(h2_request(Method::GET, path, TestBody::empty()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut other = h2_request(Method::GET, path, TestBody::empty());
    *other.uri_mut() = format!("https://grafana.tcp.svc.test{path}")
        .parse()
        .unwrap();
    let (status, _) = body_text(client.send_request(other).await.unwrap()).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(stand.api.seen().len(), 1);
    opened.cancel.cancel();
    soon("the runtime to end the session", opened.serving)
        .await
        .unwrap();
    assert_eq!(stand.control.ends()[0].outcome, ServiceOutcome::Closed);
    assert_eq!(stand.end_reason().await, "closed");
}

#[tokio::test]
async fn a_cancelled_session_ends_its_watch_cleanly_with_a_goaway_within_a_second() {
    let stand = Stand::new().await;
    let opened = stand.open(alice(), 600, b"h2").await;
    let (mut client, connection) = h2_watched(opened.tls).await;
    let response = client
        .send_request(h2_request(
            Method::GET,
            &format!("{PODS}?watch=1"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    let mut body = response.into_body();
    stand.api.watch_event("event-0").await;
    assert!(soon("a watch event", body.frame()).await.is_some());
    opened.cancel.cancel();
    assert!(ends_cleanly_within(&mut body, CUT).await);
    let closed = tokio::time::timeout(CUT, connection)
        .await
        .expect("the connection did not close within a second")
        .unwrap();
    assert!(
        closed.is_ok(),
        "the connection ended without a GOAWAY: {closed:?}"
    );
    tokio::time::timeout(CUT, opened.serving)
        .await
        .expect("the runtime did not end the session within a second")
        .unwrap();
    assert_eq!(stand.control.ends()[0].outcome, ServiceOutcome::Closed);
    assert_eq!(stand.end_reason().await, "closed");
}

#[tokio::test]
async fn the_granted_duration_ends_a_watch_cleanly_and_both_reports_agree() {
    let stand = Stand::new().await;
    let granted = Duration::from_secs(90);
    let mut opened = stand.open(alice(), granted.as_secs(), b"http/1.1").await;
    let started = stand.clock.now();
    let request = format!(
        "GET {PODS}?watch=1 HTTP/1.1\r\nHost: {}\r\n\r\n",
        dns_name(StreamKind::Kube, "prod-eu")
    );
    opened.tls.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        soon("the watch head", opened.tls.read_exact(&mut byte))
            .await
            .unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    stand.clock.wait_for_sleeper(started + granted).await;
    stand.clock.advance(granted);
    let mut rest = Vec::new();
    let read = tokio::time::timeout(CUT, opened.tls.read_to_end(&mut rest))
        .await
        .expect("the watch did not end within a second");
    assert!(
        read.is_ok(),
        "the connection was cut without close_notify: {read:?}"
    );
    assert!(rest.ends_with(b"0\r\n\r\n"), "{rest:?}");
    tokio::time::timeout(CUT, opened.serving)
        .await
        .expect("the runtime did not end the session within a second")
        .unwrap();
    assert_eq!(stand.control.ends()[0].outcome, ServiceOutcome::MaxDuration);
    assert_eq!(stand.end_reason().await, "max_duration");
}
