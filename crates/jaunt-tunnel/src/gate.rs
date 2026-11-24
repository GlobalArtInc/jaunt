use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::options::{OptionsError, TunnelOptions};
use crate::proto::NodeId;
use crate::registry::AgentRegistry;
use crate::server::TunnelConnection;
use crate::stats::GateStats;
use crate::tls::{Accepted, GateAcceptor, PeerStream};
use crate::{PeerAuthenticator, Rejection};

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

#[derive(Clone)]
pub struct Gate {
    acceptor: Arc<GateAcceptor>,
    registry: AgentRegistry,
    authenticator: Arc<dyn PeerAuthenticator>,
    handover: Arc<dyn Handover>,
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
            options: Arc::new(options),
        })
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
        let Ok((accepted, permit)) = self.acceptor.accept(tcp).await else {
            return;
        };
        match accepted {
            Accepted::Main(stream) => {
                self.stats().record_main_handed_over();
                self.handover.main(MainConnection { stream, peer_addr });
            }
            Accepted::AgentApi(peer) => {
                let PeerStream { stream, peer_cert } = peer;
                match self.authenticate(&peer_cert).await {
                    Ok(node) => {
                        self.stats().record_agent_api_handed_over();
                        self.handover.agent_api(AgentApiConnection {
                            stream,
                            node,
                            peer_cert,
                            peer_addr,
                        });
                    }
                    Err(Rejection) => close_rejected(stream).await,
                }
            }
            Accepted::Tunnel(peer) => {
                let PeerStream { stream, peer_cert } = peer;
                match self.authenticate(&peer_cert).await {
                    Ok(node) => self.establish_tunnel(node, stream, &token).await,
                    Err(Rejection) => close_rejected(stream).await,
                }
            }
        }
        drop(permit);
    }

    async fn authenticate(&self, peer_cert: &CertificateDer<'static>) -> Result<NodeId, Rejection> {
        let decision = timeout(
            self.acceptor.handshake_timeout(),
            self.authenticator.authenticate(peer_cert.as_ref()),
        )
        .await;
        match decision {
            Ok(Ok(node)) => Ok(node),
            Ok(Err(Rejection)) | Err(_) => {
                self.stats().record_auth_rejection();
                Err(Rejection)
            }
        }
    }

    async fn establish_tunnel(
        &self,
        node: NodeId,
        stream: TlsStream<TcpStream>,
        token: &CancellationToken,
    ) {
        let established = TunnelConnection::establish(stream, &self.options, token).await;
        let Ok(connection) = established else {
            self.stats().record_tunnel_setup_failure();
            return;
        };
        match self.registry.register(node, connection) {
            Ok(_) => self.stats().record_tunnel_established(),
            Err(_) => self.stats().record_tunnel_setup_failure(),
        }
    }
}

async fn close_rejected(mut stream: TlsStream<TcpStream>) {
    drop(timeout(REJECT_CLOSE_TIMEOUT, stream.shutdown()).await);
}
