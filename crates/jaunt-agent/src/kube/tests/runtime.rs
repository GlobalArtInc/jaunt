use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use jaunt_proto::{ServiceAccess, ServiceOutcome, TrustRole};
use jaunt_tunnel::BoxFuture;
use jaunt_tunnel::{ServiceName, SessionId, StreamKind, StreamMeta};
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::support::{
    CONFIGMAPS, FakeApi, PODS, SESSION, TestBody, alice, body_text, h1, h1_request, h2, h2_request,
    h2_watched, h2_windowed, write_all,
};
use crate::clock::{Clock, unix_secs};
use crate::kube::{KUBE_LIMITS, KubeHandler, KubeLimits, KubeParts, declares_kubernetes};
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

struct FailingClock {
    inner: Arc<ManualClock>,
    armed: AtomicBool,
}

impl Clock for FailingClock {
    fn now(&self) -> SystemTime {
        assert!(
            !self.armed.swap(false, Ordering::SeqCst),
            "the handler clock fails on purpose"
        );
        self.inner.now()
    }

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'_, ()> {
        self.inner.sleep_until(deadline)
    }
}

impl Stand {
    async fn new() -> Self {
        let clock = ManualClock::new(SystemTime::now());
        Self::with(clock.clone(), clock, KUBE_LIMITS).await
    }

    async fn with(
        clock: Arc<ManualClock>,
        handler_clock: Arc<dyn Clock>,
        limits: KubeLimits,
    ) -> Self {
        let api = FakeApi::start().await;
        let now = unix_secs(clock.now());
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
            clock: handler_clock,
            limits,
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
        let tls = soon(
            "the TLS handshake through the runtime",
            handshake(client, &dns_name(StreamKind::Kube, "prod-eu"), config),
        )
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
    write_all(&mut opened.tls, request.as_bytes()).await;
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

#[tokio::test]
async fn a_panicking_handler_reports_an_upstream_error_in_the_event_and_the_end() {
    let clock = ManualClock::new(SystemTime::now());
    let failing = Arc::new(FailingClock {
        inner: clock.clone(),
        armed: AtomicBool::new(false),
    });
    let stand = Stand::with(clock, failing.clone(), KUBE_LIMITS).await;
    let opened = stand.open(alice(), 600, b"http/1.1").await;
    let mut client = h1(opened.tls).await;
    failing.armed.store(true, Ordering::SeqCst);
    let failed = client
        .send_request(h1_request(
            Method::GET,
            &format!("{CONFIGMAPS}/c"),
            TestBody::empty(),
        ))
        .await;
    assert!(failed.is_err(), "{failed:?}");
    soon("the runtime to end the session", opened.serving)
        .await
        .unwrap();
    assert_eq!(
        stand.control.ends()[0].outcome,
        ServiceOutcome::UpstreamError
    );
    assert_eq!(stand.end_reason().await, "upstream_error");
}

#[tokio::test]
async fn a_handler_cut_after_its_grace_time_still_reports_its_end_before_the_runtime() {
    let clock = ManualClock::new(SystemTime::now());
    let limits = KubeLimits {
        shutdown_grace: Duration::from_secs(5),
        ..KUBE_LIMITS
    };
    let stand = Stand::with(clock.clone(), clock, limits).await;
    stand.api.serve_download(64 * 1024 * 1024);
    let opened = stand.open(alice(), 600, b"h2").await;
    let mut client = h2_windowed(opened.tls, 16 * 1024).await;
    let response = client
        .send_request(h2_request(
            Method::GET,
            &format!("{CONFIGMAPS}/big"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cancelled = Instant::now();
    opened.cancel.cancel();
    soon("the runtime to end the session", opened.serving)
        .await
        .unwrap();
    let waited = cancelled.elapsed();
    assert!(
        waited >= crate::runtime::HANDLER_STOP_GRACE && waited < limits.shutdown_grace,
        "{waited:?}"
    );
    let calls = stand.control.calls();
    let end_at = calls.iter().position(|call| *call == "end").unwrap();
    let sent_before = calls[..end_at]
        .iter()
        .filter(|call| **call == "events")
        .count();
    let with_end = stand
        .control
        .batches()
        .iter()
        .position(|batch| {
            batch
                .events
                .iter()
                .any(|event| event.name == "kube.session.end")
        })
        .expect("no kube.session.end was sent");
    assert!(with_end < sent_before, "{calls:?}");
    assert_eq!(stand.end_reason().await, "closed");
    drop(response);
}
