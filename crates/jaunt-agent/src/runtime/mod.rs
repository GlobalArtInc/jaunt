pub mod approvals;
pub mod certs;
pub mod control;
pub mod directory;
pub mod events;
pub mod handler;
pub mod limits;
pub mod tcp;
#[cfg(test)]
pub(crate) mod tests;
pub mod x509;

use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_proto::{
    ServiceAccess, ServiceAuthorizeRequest, ServiceAuthorizeResponse, ServiceEnd, ServiceIdentity,
    ServiceOutcome,
};
use jaunt_tunnel::{BoxFuture, IncomingStream, StreamHandler, StreamKind, StreamMeta};
use rustls::crypto::CryptoProvider;
use rustls::server::{Acceptor, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, version::TLS13};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use certs::{IssuedCertificate, ServiceCertificates};
use control::{ServiceControl, may_have_started};
use directory::{ServiceDirectory, ServiceEntry, service_kind};
use events::EventSink;
use handler::{
    ByteCounts, Counted, EndReason, HandlerRegistry, ServiceConnection, ServiceGrant,
    ServiceHandler, ServiceSession, Transport, Unauthorized,
};
use limits::{Gauges, Refusal, RefusalLog, ServiceLimits};
use x509::{CertRefusal, UserVerifier, UserX509Trust, VerifiedUser};

const ALPN_KUBE: [&[u8]; 2] = [b"h2", b"http/1.1"];
pub const MAX_GRANT_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
pub const HANDLER_STOP_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct FixedCertificate(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCertificate {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct RuntimeParts {
    pub control: Arc<dyn ServiceControl>,
    pub clock: Arc<dyn Clock>,
    pub user_x509: Arc<UserX509Trust>,
    pub certificates: Arc<ServiceCertificates>,
    pub handlers: Arc<HandlerRegistry>,
    pub directory: watch::Receiver<Arc<ServiceDirectory>>,
    pub limits: ServiceLimits,
    pub events: EventSink,
}

pub struct ServiceRuntime {
    control: Arc<dyn ServiceControl>,
    clock: Arc<dyn Clock>,
    user_x509: Arc<UserX509Trust>,
    certificates: Arc<ServiceCertificates>,
    handlers: Arc<HandlerRegistry>,
    directory: watch::Receiver<Arc<ServiceDirectory>>,
    limits: ServiceLimits,
    gauges: Gauges,
    refusals: RefusalLog,
    provider: Arc<CryptoProvider>,
    events: EventSink,
}

struct Accepted {
    stream: TlsStream<Transport>,
    user: VerifiedUser,
    alpn: Option<Vec<u8>>,
    dns_name: String,
}

enum Decided {
    Answer(Result<ServiceAuthorizeResponse, crate::run::api::ApiError>),
    TimedOut,
    Cancelled,
}

enum Ended {
    Handler(ServiceOutcome),
    Failed,
    Panicked,
    Cancelled,
    MaxDuration,
}

impl ServiceRuntime {
    pub fn new(parts: RuntimeParts) -> Self {
        let refusals = RefusalLog::new(parts.clock.clone(), parts.limits.refusal_log_every);
        Self {
            gauges: Gauges::new(&parts.limits),
            refusals,
            control: parts.control,
            clock: parts.clock,
            user_x509: parts.user_x509,
            certificates: parts.certificates,
            handlers: parts.handlers,
            directory: parts.directory,
            limits: parts.limits,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            events: parts.events,
        }
    }

    #[cfg(test)]
    pub fn gauges(&self) -> &Gauges {
        &self.gauges
    }

    fn deadline(&self, after: Duration) -> SystemTime {
        let now = self.clock.now();
        now.checked_add(after).unwrap_or(now)
    }

    async fn sleep_until(&self, deadline: SystemTime) {
        let clock = Arc::clone(&self.clock);
        clock.sleep_until(deadline).await;
    }

    pub async fn serve(&self, meta: StreamMeta, io: Transport, cancel: CancellationToken) {
        let kind = meta.kind();
        let Some(name) = meta.service().cloned() else {
            return;
        };
        let session_id = meta.session().as_str().to_owned();
        let refuse = |refusal: Refusal| {
            self.refusals
                .refused(kind, refusal, name.as_str(), &session_id);
        };
        let directory = Arc::clone(&self.directory.borrow());
        let Some(entry) = directory.find(kind, &name).cloned() else {
            refuse(Refusal::UnknownService);
            return;
        };
        drop(directory);
        let Some(handler) = self.handlers.get(kind).cloned() else {
            refuse(Refusal::NotServed);
            return;
        };
        let Some(_connection_slot) = self.gauges.connection(&entry.service.id) else {
            refuse(Refusal::ServiceLimit);
            return;
        };
        let Some(handshake_slot) = self.gauges.handshake(&entry.service.id) else {
            refuse(Refusal::HandshakeLimit);
            return;
        };
        let deadline = self.deadline(self.limits.handshake_timeout);
        let accepted = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = self.sleep_until(deadline) => Err(Refusal::HandshakeTimeout),
            accepted = self.accept(io, &entry) => accepted,
        };
        drop(handshake_slot);
        let accepted = match accepted {
            Ok(accepted) => accepted,
            Err(refusal) => {
                refuse(refusal);
                return;
            }
        };
        let Some(_user_slot) = self.gauges.user(&entry.service.id, &accepted.user.user_id) else {
            refuse(Refusal::UserLimit);
            return;
        };
        let counts = Arc::new(ByteCounts::default());
        let dns_name = accepted.dns_name;
        let mut connection = ServiceConnection {
            stream: Counted::new(accepted.stream, Arc::clone(&counts)),
            alpn: accepted.alpn,
            user: accepted.user,
            client_addr: meta.client().to_owned(),
            prepared: None,
        };
        let deadline = self.deadline(self.limits.handshake_timeout);
        let prepared = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = self.sleep_until(deadline) => {
                tracing::debug!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    "the client did not start the service protocol in time"
                );
                return;
            }
            prepared = handler.prepare(&mut connection) => prepared,
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::debug!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    error = %error,
                    "the service handler refused the connection before authorization"
                );
                return;
            }
        };
        if prepared.handled {
            tracing::debug!(
                target: "jaunt::agent",
                session_id = session_id.as_str(),
                service = %name,
                "the service handler finished the connection without a session"
            );
            return;
        }
        let Some(wire_kind) = service_kind(kind) else {
            return;
        };
        let request = ServiceAuthorizeRequest {
            session_id: session_id.clone(),
            kind: wire_kind,
            service: name.as_str().to_owned(),
            identity: ServiceIdentity {
                user_id: connection.user.user_id.clone(),
                serial: connection.user.serial,
                subject_fingerprint: connection.user.subject_fingerprint.clone(),
                issuer_fingerprint: connection.user.issuer_fingerprint.clone(),
            },
            client_addr: connection.client_addr.clone(),
            db: prepared.db,
        };
        let deadline = self.deadline(self.limits.authorize_timeout);
        let decided = tokio::select! {
            biased;
            () = cancel.cancelled() => Decided::Cancelled,
            () = self.sleep_until(deadline) => Decided::TimedOut,
            answer = self.control.authorize(&request) => Decided::Answer(answer),
        };
        let (access, max_duration_secs) = match decided {
            Decided::Answer(Ok(ServiceAuthorizeResponse::Allow {
                access,
                max_duration_secs,
            })) if access_fits(kind, &access) => (access, max_duration_secs),
            Decided::Answer(Ok(ServiceAuthorizeResponse::Allow { .. })) => {
                tracing::error!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    kind = kind.as_str(),
                    "the control plane allowed a session with access of another kind; the connection is closed"
                );
                self.refuse(&handler, connection, Unauthorized::Unavailable, &cancel)
                    .await;
                self.end(&session_id, ServiceOutcome::UpstreamError, &counts)
                    .await;
                return;
            }
            Decided::Answer(Ok(ServiceAuthorizeResponse::Deny)) => {
                tracing::debug!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    "the control plane denied the service session"
                );
                self.refuse(&handler, connection, Unauthorized::Denied, &cancel)
                    .await;
                return;
            }
            Decided::Answer(Err(error)) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    error = %error,
                    "asking the control plane about a service session failed; the connection is closed"
                );
                self.refuse(&handler, connection, Unauthorized::Unavailable, &cancel)
                    .await;
                if may_have_started(&error) {
                    self.end(&session_id, ServiceOutcome::UpstreamError, &counts)
                        .await;
                }
                return;
            }
            Decided::TimedOut => {
                tracing::warn!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    "the control plane did not answer about a service session in time; the connection is closed"
                );
                self.refuse(&handler, connection, Unauthorized::Unavailable, &cancel)
                    .await;
                self.end(&session_id, ServiceOutcome::UpstreamError, &counts)
                    .await;
                return;
            }
            Decided::Cancelled => {
                self.end(&session_id, ServiceOutcome::Closed, &counts).await;
                return;
            }
        };
        let max_duration = Duration::from_secs(max_duration_secs).min(MAX_GRANT_DURATION);
        let grant = ServiceGrant {
            access,
            max_duration,
            target: matches!(kind, StreamKind::Tcp)
                .then(|| entry.address.clone())
                .flatten(),
        };
        let reason = EndReason::default();
        let stop = cancel.child_token();
        let session = ServiceSession {
            session_id: session_id.clone(),
            service: name.clone(),
            dns_name,
            cancel: stop.clone(),
            reason: reason.clone(),
            events: self.events.session(&session_id),
        };
        let deadline = self.deadline(max_duration);
        let mut task = tokio::spawn(async move { handler.serve(connection, grant, session).await });
        let _abort = AbortOnDrop(task.abort_handle());
        let ended = tokio::select! {
            biased;
            () = cancel.cancelled() => Ended::Cancelled,
            joined = &mut task => match joined {
                Ok(Ok(outcome)) => Ended::Handler(outcome),
                Ok(Err(_)) => Ended::Failed,
                Err(_) => Ended::Panicked,
            },
            () = self.sleep_until(deadline) => Ended::MaxDuration,
        };
        let outcome = match ended {
            Ended::Handler(outcome) => reason.decide(outcome),
            Ended::Failed => reason.decide(ServiceOutcome::UpstreamError),
            Ended::Panicked => {
                tracing::error!(
                    target: "jaunt::agent",
                    session_id = session_id.as_str(),
                    service = %name,
                    "the service handler failed unexpectedly; the session is ended"
                );
                reason.decide(ServiceOutcome::UpstreamError)
            }
            Ended::Cancelled | Ended::MaxDuration => {
                let decided = reason.decide(if matches!(ended, Ended::MaxDuration) {
                    ServiceOutcome::MaxDuration
                } else {
                    ServiceOutcome::Closed
                });
                stop.cancel();
                match tokio::time::timeout(HANDLER_STOP_GRACE, &mut task).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => tracing::error!(
                        target: "jaunt::agent",
                        session_id = session_id.as_str(),
                        service = %name,
                        "the service handler failed unexpectedly while it was stopping"
                    ),
                    Err(_) => tracing::debug!(
                        target: "jaunt::agent",
                        session_id = session_id.as_str(),
                        service = %name,
                        "the service handler did not stop within its grace time; it is aborted"
                    ),
                }
                decided
            }
        };
        if !task.is_finished() {
            task.abort();
            drop(task.await);
        }
        let flushed = self
            .events
            .flush(&session_id, self.deadline(self.limits.event_flush_timeout))
            .await;
        self.events.session_ended(&session_id);
        if !flushed {
            tracing::debug!(
                target: "jaunt::agent",
                session_id = session_id.as_str(),
                "the audit events of the session were not delivered before its end was reported; they stay queued"
            );
        }
        self.end(&session_id, outcome, &counts).await;
    }

    async fn refuse(
        &self,
        handler: &Arc<dyn ServiceHandler>,
        connection: ServiceConnection,
        reason: Unauthorized,
        cancel: &CancellationToken,
    ) {
        let deadline = self.deadline(self.limits.handshake_timeout);
        tokio::select! {
            biased;
            () = cancel.cancelled() => {}
            () = self.sleep_until(deadline) => {}
            () = handler.refuse(connection, reason) => {}
        }
    }

    async fn end(&self, session_id: &str, outcome: ServiceOutcome, counts: &ByteCounts) {
        let end = ServiceEnd {
            session_id: session_id.to_owned(),
            outcome,
            bytes_in: counts.read(),
            bytes_out: counts.written(),
        };
        let deadline = self.deadline(self.limits.end_timeout);
        let reported = tokio::select! {
            () = self.sleep_until(deadline) => None,
            reported = self.control.end(&end) => Some(reported),
        };
        match reported {
            Some(Ok(_)) => tracing::debug!(
                target: "jaunt::agent",
                session_id,
                outcome = outcome.as_str(),
                bytes_in = end.bytes_in,
                bytes_out = end.bytes_out,
                "reported the end of a service session"
            ),
            Some(Err(error)) => tracing::warn!(
                target: "jaunt::agent",
                session_id,
                outcome = outcome.as_str(),
                error = %error,
                "reporting the end of a service session failed"
            ),
            None => tracing::warn!(
                target: "jaunt::agent",
                session_id,
                outcome = outcome.as_str(),
                "reporting the end of a service session timed out"
            ),
        }
    }

    async fn accept(&self, io: Transport, entry: &ServiceEntry) -> Result<Accepted, Refusal> {
        let start = LazyConfigAcceptor::new(Acceptor::default(), io)
            .await
            .map_err(|_| Refusal::NotTls)?;
        let sni = start
            .client_hello()
            .server_name()
            .map(str::to_ascii_lowercase)
            .ok_or(Refusal::NoSni)?;
        let prefix = format!("{}.{}.", entry.service.name, entry.service.kind.as_str());
        if sni.len() <= prefix.len() || !sni.starts_with(&prefix) {
            return Err(Refusal::SniMismatch);
        }
        let issued = self
            .certificates
            .get(&entry.service)
            .await
            .map_err(|_| Refusal::CertificateUnavailable)?;
        if sni != issued.dns_name() {
            return Err(Refusal::SniMismatch);
        }
        let roots = self.user_x509.snapshot();
        if roots.is_empty() {
            self.user_x509.notice_empty(
                self.clock
                    .now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default(),
            );
        }
        let verifier = Arc::new(UserVerifier::new(roots, Arc::clone(&self.clock)));
        let config = self
            .server_config(&issued, Arc::clone(&verifier), entry.service.kind)
            .map_err(|_| Refusal::HandshakeFailed)?;
        let handshake = start.into_stream(config).await;
        let outcome = verifier.take_outcome();
        let stream = match handshake {
            Ok(stream) => stream,
            Err(error) => {
                return Err(match outcome {
                    Some(Err(refusal)) => Refusal::Certificate(refusal),
                    Some(Ok(_)) => Refusal::HandshakeFailed,
                    None if presented_no_certificate(&error) => Refusal::NoCertificate,
                    None => Refusal::HandshakeFailed,
                });
            }
        };
        let user = match outcome {
            Some(Ok(user)) => user,
            Some(Err(refusal)) => return Err(Refusal::Certificate(refusal)),
            None => return Err(Refusal::Certificate(CertRefusal::Malformed)),
        };
        let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Ok(Accepted {
            stream,
            user,
            alpn,
            dns_name: issued.dns_name().to_owned(),
        })
    }

    fn server_config(
        &self,
        issued: &IssuedCertificate,
        verifier: Arc<UserVerifier>,
        kind: StreamKind,
    ) -> Result<Arc<ServerConfig>, rustls::Error> {
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&TLS13])?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(FixedCertificate(issued.certified_key())));
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.alpn_protocols = match kind {
            StreamKind::Kube => ALPN_KUBE.iter().map(|protocol| protocol.to_vec()).collect(),
            StreamKind::Db | StreamKind::Tcp | StreamKind::Ssh => Vec::new(),
        };
        Ok(Arc::new(config))
    }
}

fn access_fits(kind: StreamKind, access: &ServiceAccess) -> bool {
    matches!(
        (kind, access),
        (StreamKind::Kube, ServiceAccess::Kube(_))
            | (StreamKind::Db, ServiceAccess::Db(_))
            | (StreamKind::Tcp, ServiceAccess::Tcp)
    )
}

fn presented_no_certificate(error: &io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::NoCertificatesPresented)
    )
}

pub struct KindRouter {
    pub ssh: Arc<dyn StreamHandler>,
    pub services: Arc<ServiceRuntime>,
}

impl StreamHandler for KindRouter {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        if stream.meta.kind() == StreamKind::Ssh {
            return self.ssh.handle(stream);
        }
        let services = Arc::clone(&self.services);
        Box::pin(async move {
            let IncomingStream { meta, io, cancel } = stream;
            services.serve(meta, Box::new(io), cancel).await;
        })
    }

    fn trust_update(&self) {
        self.ssh.trust_update();
    }
}
