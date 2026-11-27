use std::io;
use std::sync::Arc;
use std::time::Duration;

use jaunt_limits::LogThrottle;
use jaunt_tunnel::BoxFuture;
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{Acceptor, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier};
use rustls::version::TLS13;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use super::certificate::GateCertificate;
use super::close_quietly;
use super::svc::SvcGate;
use crate::entry::{
    ALPN_SSH, ClassConnection, ClassHandler, EntryClass, EntryIo, EntryStream, GateProtocol,
    TlsRefusal,
};
use crate::ssh::{NetworkOrigin, SshGate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeFailure {
    Certificate,
    Timeout,
    Failed,
    Shutdown,
}

impl HandshakeFailure {
    const fn refusal(self) -> Option<TlsRefusal> {
        match self {
            Self::Certificate => Some(TlsRefusal::ClientCertificate),
            Self::Timeout => Some(TlsRefusal::HelloTimeout),
            Self::Failed => Some(TlsRefusal::TlsHandshake),
            Self::Shutdown => None,
        }
    }
}

pub(crate) fn server_config(
    verifier: Arc<dyn ClientCertVerifier>,
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[u8],
) -> Result<ServerConfig, rustls::Error> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![alpn.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

const EXPIRED_LOG_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) struct GateClass {
    ssh: Option<Arc<SshGate>>,
    ssh_tls: Arc<ServerConfig>,
    svc: SvcGate,
    certificate: Arc<GateCertificate>,
    handshakes: Arc<Semaphore>,
    max_handshaking: usize,
    expired_log: LogThrottle,
    started: std::time::Instant,
}

impl GateClass {
    pub(crate) fn new(
        ssh: Option<Arc<SshGate>>,
        certificate: Arc<GateCertificate>,
        svc: SvcGate,
        max_handshaking: usize,
    ) -> Result<Self, rustls::Error> {
        let ssh_tls = server_config(
            WebPkiClientVerifier::no_client_auth(),
            certificate.resolver(),
            ALPN_SSH,
        )?;
        Ok(Self {
            ssh,
            ssh_tls: Arc::new(ssh_tls),
            svc,
            certificate,
            handshakes: Arc::new(Semaphore::new(max_handshaking)),
            max_handshaking,
            expired_log: LogThrottle::new(EXPIRED_LOG_INTERVAL),
            started: std::time::Instant::now(),
        })
    }

    fn certificate_expired(&self) -> bool {
        if !self.certificate.expired() {
            return false;
        }
        if let Some(suppressed) = self.expired_log.admit(self.started.elapsed()) {
            tracing::error!(
                target: "jaunt::gate",
                valid_before = self.certificate.valid_before(),
                suppressed,
                "the gate tls certificate has expired and could not be renewed; tls connections to the services domain are refused"
            );
        }
        true
    }

    pub(crate) fn svc(&self) -> &SvcGate {
        &self.svc
    }

    pub(crate) fn handshaking(&self) -> usize {
        self.max_handshaking
            .saturating_sub(self.handshakes.available_permits())
    }

    async fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) {
        if matches!(connection.route.class, EntryClass::Gate(_)) && self.certificate_expired() {
            connection.refusals.refuse(
                TlsRefusal::GateCertificateExpired,
                connection.route.client_addr,
            );
            return close_quietly(connection.stream).await;
        }
        match connection.route.class {
            EntryClass::Gate(GateProtocol::Ssh) => self.serve_ssh(connection, shutdown).await,
            EntryClass::Gate(GateProtocol::Svc) => self.serve_svc(connection, shutdown).await,
            EntryClass::Agents | EntryClass::Main | EntryClass::Kube(_) => {
                connection
                    .refusals
                    .refuse(TlsRefusal::UnsupportedClass, connection.route.client_addr);
                close_quietly(connection.stream).await;
            }
        }
    }

    async fn serve_ssh(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) {
        let ClassConnection {
            route,
            stream,
            refusals,
            ..
        } = connection;
        let Some(ssh) = &self.ssh else {
            refusals.refuse(TlsRefusal::UnsupportedClass, route.client_addr);
            return close_quietly(stream).await;
        };
        let Ok(permit) = Arc::clone(&self.handshakes).try_acquire_owned() else {
            refusals.refuse(TlsRefusal::Limit, route.client_addr);
            return close_quietly(stream).await;
        };
        let Some(admission) = ssh.admit_network(route.client_addr, route.local) else {
            return close_quietly(stream).await;
        };
        let tls = match terminate(
            stream,
            Arc::clone(&self.ssh_tls),
            route.handshake_deadline,
            &shutdown,
        )
        .await
        {
            Ok(tls) => tls,
            Err(failure) => {
                if let Some(reason) = failure.refusal() {
                    refusals.refuse(reason, route.client_addr);
                }
                return;
            }
        };
        drop(permit);
        let origin = NetworkOrigin {
            client: route.client_addr,
            peer: route.peer_addr,
            proxied: route.proxied,
        };
        ssh.serve_network(admission, tls, origin, shutdown).await;
    }

    async fn serve_svc(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) {
        let ClassConnection {
            route,
            stream,
            refusals,
            ..
        } = connection;
        let _address = if route.local {
            None
        } else {
            let Some(address) = self.svc.admit_address(route.client_addr) else {
                refusals.refuse(TlsRefusal::Limit, route.client_addr);
                return close_quietly(stream).await;
            };
            Some(address)
        };
        let Some(prepared) = self.svc.tls() else {
            refusals.refuse(TlsRefusal::ClientCertificate, route.client_addr);
            return close_quietly(stream).await;
        };
        let Ok(permit) = Arc::clone(&self.handshakes).try_acquire_owned() else {
            refusals.refuse(TlsRefusal::Limit, route.client_addr);
            return close_quietly(stream).await;
        };
        let tls =
            match terminate(stream, prepared.config, route.handshake_deadline, &shutdown).await {
                Ok(tls) => tls,
                Err(failure) => {
                    if let Some(reason) = failure.refusal() {
                        refusals.refuse(reason, route.client_addr);
                    }
                    return;
                }
            };
        drop(permit);
        self.svc
            .serve(tls, &prepared.roots, &route, &refusals, &shutdown)
            .await;
    }
}

async fn terminate(
    stream: EntryStream,
    config: Arc<ServerConfig>,
    deadline: Instant,
    shutdown: &CancellationToken,
) -> Result<TlsStream<EntryStream>, HandshakeFailure> {
    let handshake = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), stream)
            .await
            .map_err(|error| classify(&error))?;
        start
            .into_stream(config)
            .await
            .map_err(|error| classify(&error))
    };
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Err(HandshakeFailure::Shutdown),
        finished = timeout_at(deadline, handshake) => finished.unwrap_or(Err(HandshakeFailure::Timeout)),
    }
}

fn classify(error: &io::Error) -> HandshakeFailure {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::NoCertificatesPresented | rustls::Error::InvalidCertificate(_)) => {
            HandshakeFailure::Certificate
        }
        _ => HandshakeFailure::Failed,
    }
}

pub(crate) struct GateClassHandler {
    gate: Arc<GateClass>,
}

impl GateClassHandler {
    pub(crate) fn new(gate: Arc<GateClass>) -> Self {
        Self { gate }
    }
}

impl ClassHandler for GateClassHandler {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let gate = Arc::clone(&self.gate);
        Box::pin(async move { gate.serve(connection, shutdown).await })
    }
}
