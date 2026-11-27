use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, UNIX_EPOCH};

use jaunt_limits::{
    ClientKey, ConcurrencyGuard, ConcurrencyLimiter, DEFAULT_CAPACITY, LogThrottle,
};
use jaunt_proto::{ControlPlane, RouteDecision, ServiceRouteRequest};
use jaunt_tunnel::{
    AgentRegistry, H2Io, NodeId, Replay, RotatingCertificate, SessionId, StreamMeta,
};
use rustls::ServerConfig;
use rustls::pki_types::UnixTime;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use super::gate_class::server_config;
use super::identity::{UserX509Roots, UserX509Source};
use super::kube::open_refusal;
use super::refusals::{StreamRefusal, StreamRefusals};
use super::splice::{Ledger, splice};
use super::target::{ServiceTarget, service_target};
use super::{Gauge, Held, close_quietly};
use crate::audit::{self, SvcStream};
use crate::entry::{ALPN_SVC, EntryStream, RefusalLog, Route, TlsRefusal, capture_client_hello};
use crate::host_cert::Clock;
use crate::route::{CONTROL_TIMEOUT, OPEN_TIMEOUT};

const MISSING_ROOTS_LOG_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) struct SvcParts {
    pub(crate) domain: String,
    pub(crate) resolver: Arc<RotatingCertificate>,
    pub(crate) user_x509: Arc<dyn UserX509Source>,
    pub(crate) control: Arc<dyn ControlPlane>,
    pub(crate) registry: AgentRegistry,
    pub(crate) per_address: usize,
    pub(crate) per_user: usize,
    pub(crate) inner_hello_timeout: Duration,
    pub(crate) half_close_grace: Duration,
    pub(crate) clock: Clock,
}

type Prepared = (Arc<UserX509Roots>, Arc<ServerConfig>);

pub(crate) struct SvcTls {
    pub(crate) roots: Arc<UserX509Roots>,
    pub(crate) config: Arc<ServerConfig>,
}

pub(crate) struct SvcGate {
    domain: String,
    resolver: Arc<RotatingCertificate>,
    user_x509: Arc<dyn UserX509Source>,
    prepared: Mutex<Option<Prepared>>,
    control: Arc<dyn ControlPlane>,
    registry: AgentRegistry,
    per_address: ConcurrencyLimiter<ClientKey>,
    per_user: ConcurrencyLimiter<String>,
    refusals: StreamRefusals,
    streams: Gauge,
    missing_roots: LogThrottle,
    started: Instant,
    inner_hello_timeout: Duration,
    half_close_grace: Duration,
    clock: Clock,
}

impl SvcGate {
    pub(crate) fn new(parts: SvcParts) -> Self {
        Self {
            domain: parts.domain,
            resolver: parts.resolver,
            user_x509: parts.user_x509,
            prepared: Mutex::new(None),
            control: parts.control,
            registry: parts.registry,
            per_address: ConcurrencyLimiter::new(parts.per_address, DEFAULT_CAPACITY),
            per_user: ConcurrencyLimiter::new(parts.per_user, DEFAULT_CAPACITY),
            refusals: StreamRefusals::new(),
            streams: Gauge::default(),
            missing_roots: LogThrottle::new(MISSING_ROOTS_LOG_INTERVAL),
            started: Instant::now(),
            inner_hello_timeout: parts.inner_hello_timeout,
            half_close_grace: parts.half_close_grace,
            clock: parts.clock,
        }
    }

    fn now(&self) -> UnixTime {
        UnixTime::since_unix_epoch(
            (self.clock)()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        )
    }

    pub(crate) fn refused(&self, reason: StreamRefusal) -> u64 {
        self.refusals.refused(reason)
    }

    pub(super) fn stats(&self) -> Held {
        Held {
            streams: self.streams.current(),
            keys: self.per_address.tracked(),
            groups: self.per_user.tracked(),
        }
    }

    pub(crate) fn admit_address(&self, client: SocketAddr) -> Option<ConcurrencyGuard<ClientKey>> {
        self.per_address
            .try_acquire(ClientKey::of(client.ip()))
            .ok()
    }

    fn prepared(&self) -> MutexGuard<'_, Option<Prepared>> {
        self.prepared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn tls(&self) -> Option<SvcTls> {
        let Some(roots) = self.user_x509.current() else {
            if let Some(suppressed) = self.missing_roots.admit(self.started.elapsed()) {
                tracing::warn!(
                    target: "jaunt::gate",
                    suppressed,
                    "no user-x509 root is available, so every database and tcp connection is refused"
                );
            }
            return None;
        };
        let mut prepared = self.prepared();
        if let Some((seen, config)) = prepared.as_ref()
            && Arc::ptr_eq(seen, &roots)
        {
            return Some(SvcTls {
                roots,
                config: Arc::clone(config),
            });
        }
        let resolver: Arc<RotatingCertificate> = Arc::clone(&self.resolver);
        let config = match server_config(roots.verifier(), resolver, ALPN_SVC) {
            Ok(config) => Arc::new(config),
            Err(error) => {
                tracing::error!(
                    target: "jaunt::gate",
                    error = %error,
                    "the tls configuration for database and tcp connections cannot be built"
                );
                return None;
            }
        };
        *prepared = Some((Arc::clone(&roots), Arc::clone(&config)));
        Some(SvcTls { roots, config })
    }

    pub(crate) async fn serve(
        &self,
        mut tls: TlsStream<EntryStream>,
        roots: &UserX509Roots,
        route: &Route,
        refusals: &RefusalLog,
        shutdown: &CancellationToken,
    ) {
        let identity = match roots.identify(tls.get_ref().1.peer_certificates(), self.now()) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::debug!(
                    target: "jaunt::gate",
                    client_addr = %route.client_addr,
                    error = %error,
                    "a client certificate was refused"
                );
                refusals.refuse(TlsRefusal::ClientCertificate, route.client_addr);
                close_quietly(tls).await;
                return;
            }
        };
        let mut record = SvcStream {
            client_addr: route.client_addr,
            user_id: &identity.user_id,
            serial: identity.serial,
            kind: None,
            service: None,
            node_id: None,
            session_id: None,
        };
        let Ok(_user) = self.per_user.try_acquire(identity.user_id.clone()) else {
            return self.refuse(tls, &record, StreamRefusal::UserLimit).await;
        };
        let deadline = tokio::time::Instant::now() + self.inner_hello_timeout;
        let captured = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            captured = capture_client_hello(&mut tls, deadline) => captured,
        };
        let Ok(captured) = captured else {
            return self.refuse(tls, &record, StreamRefusal::InnerHello).await;
        };
        let (hello, info) = captured.into_parts();
        let Some(target) = service_target(info.server_name(), &self.domain) else {
            return self.refuse(tls, &record, StreamRefusal::ServiceName).await;
        };
        record.kind = Some(target.kind.label());
        record.service = Some(target.name.as_str());
        let request = ServiceRouteRequest {
            identity: identity.clone(),
            kind: target.kind.service_kind(),
            service: target.name.as_str().to_owned(),
            client_addr: route.client_addr.to_string(),
        };
        let decision = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            decision = timeout(CONTROL_TIMEOUT, self.control.route_service(request)) => decision,
        };
        let (session_id, node_id) = match decision {
            Ok(Ok(RouteDecision::Allow {
                session_id,
                node_id,
            })) => (session_id, node_id),
            Ok(Ok(RouteDecision::Deny { .. })) => {
                return self.refuse(tls, &record, StreamRefusal::Denied).await;
            }
            Ok(Err(_)) | Err(_) => {
                return self
                    .refuse(tls, &record, StreamRefusal::ControlUnavailable)
                    .await;
            }
        };
        record.node_id = Some(node_id.as_str());
        record.session_id = Some(session_id.as_str());
        let opened = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            opened = self.open(&node_id, &session_id, &target, route.client_addr) => opened,
        };
        let io = match opened {
            Ok(io) => io,
            Err(reason) => return self.refuse(tls, &record, reason).await,
        };
        let _open = self.streams.enter();
        let (client_addr, serial, kind) = (route.client_addr, identity.serial, target.kind.label());
        let (user_id, service) = (identity.user_id.clone(), target.name.as_str().to_owned());
        let mut ledger = Ledger::new(move |carried| {
            let stream = SvcStream {
                client_addr,
                user_id: &user_id,
                serial,
                kind: Some(kind),
                service: Some(&service),
                node_id: Some(&node_id),
                session_id: Some(&session_id),
            };
            audit::svc_stream_closed(&stream, carried);
        });
        splice(
            Replay::new(hello, tls),
            io,
            shutdown,
            self.half_close_grace,
            &mut ledger,
        )
        .await;
    }

    async fn open(
        &self,
        node_id: &str,
        session_id: &str,
        target: &ServiceTarget,
        client: SocketAddr,
    ) -> Result<H2Io, StreamRefusal> {
        let node = NodeId::new(node_id).map_err(|_| StreamRefusal::AgentUnavailable)?;
        let meta = SessionId::new(session_id)
            .and_then(|session| {
                StreamMeta::with_service(
                    session,
                    target.kind.stream_kind(),
                    target.name.clone(),
                    client.to_string(),
                )
            })
            .map_err(|_| StreamRefusal::AgentUnavailable)?;
        match timeout(OPEN_TIMEOUT, self.registry.open_stream(&node, &meta)).await {
            Ok(Ok(io)) => Ok(io),
            Ok(Err(error)) => Err(open_refusal(&error)),
            Err(_) => Err(StreamRefusal::AgentUnavailable),
        }
    }

    async fn refuse(
        &self,
        tls: TlsStream<EntryStream>,
        record: &SvcStream<'_>,
        reason: StreamRefusal,
    ) {
        if let Some(suppressed) = self.refusals.throttled(reason) {
            audit::svc_stream_refused(record, reason.as_str(), suppressed);
        }
        close_quietly(tls).await;
    }
}
