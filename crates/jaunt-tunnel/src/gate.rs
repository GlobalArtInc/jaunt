use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout, timeout_at};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::options::{OptionsError, TunnelOptions};
use crate::proto::NodeId;
use crate::registry::AgentRegistry;
use crate::server::TunnelConnection;
use crate::stats::GateStats;
use crate::tls::{Accepted, GateAcceptor, PeerStream};
use crate::{PeerAuthenticator, RejectReason, Rejection};

const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);
const REJECT_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

pub struct MainConnection {
    pub stream: TlsStream<TcpStream>,
    pub peer_addr: SocketAddr,
}

pub struct AgentApiConnection {
    pub stream: TlsStream<TcpStream>,
    pub node: NodeId,
    pub peer_cert: CertificateDer<'static>,
    pub peer_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GateError {
    #[error("no tokio runtime is running")]
    NoRuntime,
}

pub trait Handover: Send + Sync {
    fn main(&self, connection: MainConnection);
    fn agent_api(&self, connection: AgentApiConnection);
}

pub trait GateObserver: Send + Sync {
    fn tunnel_registered(&self, node: &NodeId, peer_addr: SocketAddr, replaced: bool);
    fn peer_rejected(&self, peer_addr: SocketAddr, rejection: &Rejection);
}

#[derive(Clone)]
pub struct Gate {
    acceptor: Arc<GateAcceptor>,
    registry: AgentRegistry,
    authenticator: Arc<dyn PeerAuthenticator>,
    handover: Arc<dyn Handover>,
    observer: Option<Arc<dyn GateObserver>>,
    options: Arc<TunnelOptions>,
}

impl Gate {
    pub fn new(
        acceptor: GateAcceptor,
        registry: AgentRegistry,
        authenticator: Arc<dyn PeerAuthenticator>,
        handover: Arc<dyn Handover>,
        options: TunnelOptions,
    ) -> Result<Self, OptionsError> {
        options.validate()?;
        Ok(Self {
            acceptor: Arc::new(acceptor),
            registry,
            authenticator,
            handover,
            observer: None,
            options: Arc::new(options),
        })
    }

    pub fn with_observer(mut self, observer: Arc<dyn GateObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub fn stats(&self) -> &Arc<GateStats> {
        self.acceptor.stats()
    }

    pub fn handshaking(&self) -> usize {
        self.acceptor.handshaking()
    }

    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> Result<(), GateError> {
        Handle::try_current().map_err(|_| GateError::NoRuntime)?;
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                Some(finished) = connections.join_next() => {
                    if finished.is_err_and(|error| error.is_panic()) {
                        self.stats().record_task_panic();
                    }
                }
                accepted = listener.accept() => match accepted {
                    Ok((tcp, peer_addr)) => {
                        let gate = self.clone();
                        let token = shutdown.child_token();
                        connections.spawn(async move {
                            gate.handle(tcp, peer_addr, token).await;
                        });
                    }
                    Err(_) => {
                        self.stats().record_accept_error();
                        tokio::select! {
                            () = shutdown.cancelled() => return Ok(()),
                            () = sleep(ACCEPT_ERROR_PAUSE) => {}
                        }
                    }
                },
            }
        }
    }

    async fn handle(&self, tcp: TcpStream, peer_addr: SocketAddr, token: CancellationToken) {
        if tcp.set_nodelay(true).is_err() {
            self.stats().record_accept_error();
            return;
        }
        let (accepted, permit) = match self.acceptor.accept(tcp).await {
            Ok(accepted) => accepted,
            Err(error) => {
                if error.is_missing_peer_certificate() {
                    self.observe_rejection(peer_addr, &Rejection::new(RejectReason::NoCertificate));
                }
                return;
            }
        };
        let deadline = permit.deadline();
        match accepted {
            Accepted::Main(stream) => {
                self.stats().record_main_handed_over();
                self.handover.main(MainConnection { stream, peer_addr });
            }
            Accepted::AgentApi(peer) => {
                let PeerStream { stream, peer_cert } = peer;
                match self.authenticate(&peer_cert, deadline).await {
                    Ok(node) => {
                        self.stats().record_agent_api_handed_over();
                        self.handover.agent_api(AgentApiConnection {
                            stream,
                            node,
                            peer_cert,
                            peer_addr,
                        });
                    }
                    Err(rejection) => {
                        self.observe_rejection(peer_addr, &rejection);
                        close_rejected(stream).await;
                    }
                }
            }
            Accepted::Tunnel(peer) => {
                let PeerStream { stream, peer_cert } = peer;
                match self.authenticate(&peer_cert, deadline).await {
                    Ok(node) => {
                        self.establish_tunnel(node, stream, peer_addr, &token, deadline)
                            .await;
                    }
                    Err(rejection) => {
                        self.observe_rejection(peer_addr, &rejection);
                        close_rejected(stream).await;
                    }
                }
            }
        }
        drop(permit);
    }

    fn observe_rejection(&self, peer_addr: SocketAddr, rejection: &Rejection) {
        if let Some(observer) = &self.observer {
            observer.peer_rejected(peer_addr, rejection);
        }
    }

    async fn authenticate(
        &self,
        peer_cert: &CertificateDer<'static>,
        deadline: Instant,
    ) -> Result<NodeId, Rejection> {
        let decision = timeout_at(
            deadline,
            self.authenticator.authenticate(peer_cert.as_ref()),
        )
        .await;
        let rejection = match decision {
            Ok(Ok(node)) => return Ok(node),
            Ok(Err(rejection)) => rejection,
            Err(_) => Rejection::new(RejectReason::Timeout),
        };
        self.stats().record_auth_rejection();
        Err(rejection)
    }

    async fn establish_tunnel(
        &self,
        node: NodeId,
        stream: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        token: &CancellationToken,
        deadline: Instant,
    ) {
        let established = timeout_at(
            deadline,
            TunnelConnection::establish(stream, &self.options, token),
        )
        .await;
        let Ok(Ok(connection)) = established else {
            self.stats().record_tunnel_setup_failure();
            return;
        };
        match self.registry.register_tracked(node.clone(), connection) {
            Ok((_, replaced)) => {
                self.stats().record_tunnel_established();
                if let Some(observer) = &self.observer {
                    observer.tunnel_registered(&node, peer_addr, replaced);
                }
            }
            Err(_) => self.stats().record_tunnel_setup_failure(),
        }
    }
}

async fn close_rejected(mut stream: TlsStream<TcpStream>) {
    drop(timeout(REJECT_CLOSE_TIMEOUT, stream.shutdown()).await);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rustls::pki_types::CertificateDer;
    use tokio::time::Instant;

    use super::{AgentApiConnection, Gate, Handover, MainConnection};
    use crate::options::TunnelOptions;
    use crate::proto::NodeId;
    use crate::registry::AgentRegistry;
    use crate::stats::GateStats;
    use crate::tls::{AcceptorConfig, GateAcceptor, refusing_server_config};
    use crate::{BoxFuture, PeerAuthenticator, RejectReason, Rejection};

    struct Hanging;

    impl PeerAuthenticator for Hanging {
        fn authenticate<'a>(
            &'a self,
            _peer_cert_der: &'a [u8],
        ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
            Box::pin(std::future::pending())
        }
    }

    struct Nobody;

    impl Handover for Nobody {
        fn main(&self, _connection: MainConnection) {}

        fn agent_api(&self, _connection: AgentApiConnection) {}
    }

    #[tokio::test]
    async fn authentication_gets_only_what_is_left_of_the_handshake_deadline() {
        let refusing = Arc::new(refusing_server_config().unwrap());
        let mut config = AcceptorConfig::new(Vec::new(), refusing.clone(), refusing);
        config.handshake_timeout = Duration::from_secs(3600);
        let acceptor = GateAcceptor::new(config, Arc::new(GateStats::default())).unwrap();
        let gate = Gate::new(
            acceptor,
            AgentRegistry::new(),
            Arc::new(Hanging),
            Arc::new(Nobody),
            TunnelOptions::default(),
        )
        .unwrap();
        let certificate = CertificateDer::from(vec![1_u8]);
        let refused = tokio::time::timeout(
            Duration::from_secs(10),
            gate.authenticate(&certificate, Instant::now()),
        )
        .await
        .expect("authentication outlived the handshake deadline");
        assert_eq!(
            refused.err().map(|rejection| rejection.reason),
            Some(RejectReason::Timeout)
        );
        assert_eq!(gate.stats().snapshot().auth_rejections, 1);
    }
}
