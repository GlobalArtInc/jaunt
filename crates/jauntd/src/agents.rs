mod api;
mod auth;
mod certificate;
mod reconcile;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_ca::CaError;
use jaunt_control::{Clock, Control};
use jaunt_gate::{AgentHub, AgentHubConfig, HubError, HubStatsSnapshot, ShutdownReport};
use jaunt_store::Store;
use jaunt_tunnel::{AgentRegistry, GateStats, TlsConfigError, rotating_agent_server_config};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

pub use api::ApiLimits;

use api::AgentApi;
use auth::NodeAuthenticator;
use certificate::ServerCertificate;
use reconcile::StoreNodes;

pub const DEFAULT_AGENTS_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8444);
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
pub const CERTIFICATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

const _: () = assert!(RECONCILE_INTERVAL.as_secs() <= 5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentsSettings {
    pub listen: SocketAddr,
    pub server_name: String,
}

pub struct AgentServerParts {
    pub settings: AgentsSettings,
    pub control: Control,
    pub store: Store,
    pub clock: Clock,
    pub reconcile_interval: Duration,
    pub certificate_check_interval: Duration,
    pub api_limits: ApiLimits,
}

impl AgentServerParts {
    pub fn new(settings: AgentsSettings, control: Control, store: Store, clock: Clock) -> Self {
        Self {
            settings,
            control,
            store,
            clock,
            reconcile_interval: RECONCILE_INTERVAL,
            certificate_check_interval: CERTIFICATE_CHECK_INTERVAL,
            api_limits: ApiLimits::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentsError {
    #[error("cannot listen for agents on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("cannot generate the key of the agents' server certificate: {0}")]
    Key(#[source] rcgen::Error),
    #[error("cannot issue the agents' server certificate: {0}")]
    Certificate(#[source] CaError),
    #[error("the internal root cannot be the agents' client root: {0}")]
    ClientRoot(#[source] rustls::Error),
    #[error("cannot build the agents' tls configuration: {0}")]
    Tls(#[from] TlsConfigError),
    #[error("cannot start the agents' listener: {0}")]
    Hub(#[from] HubError),
}

pub struct AgentServer {
    hub: AgentHub,
    certificate: Arc<ServerCertificate>,
    tasks: Vec<JoinHandle<()>>,
    stop_tasks: DropGuard,
}

impl AgentServer {
    pub async fn start(parts: AgentServerParts) -> Result<Self, AgentsError> {
        let AgentServerParts {
            settings,
            control,
            store,
            clock,
            reconcile_interval,
            certificate_check_interval,
            api_limits,
        } = parts;
        let certificate = Arc::new(ServerCertificate::issue(
            control.clone(),
            settings.server_name.clone(),
            clock,
        )?);
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(CertificateDer::from(control.internal_root_der().to_vec()))
            .map_err(AgentsError::ClientRoot)?;
        let tls = rotating_agent_server_config(certificate.slot(), client_roots)?;
        let listener =
            TcpListener::bind(settings.listen)
                .await
                .map_err(|source| AgentsError::Listen {
                    addr: settings.listen,
                    source,
                })?;
        let hub = AgentHub::start(
            listener,
            AgentHubConfig::new(settings.server_name, Arc::new(tls)),
            Arc::new(NodeAuthenticator::new(store.nodes())),
            Arc::new(AgentApi::new(control.agent_router(), api_limits)),
        )?;
        let stop = CancellationToken::new();
        let tasks = vec![
            tokio::spawn(reconcile::run(
                StoreNodes::new(store.nodes()),
                hub.agents(),
                reconcile_interval,
                stop.clone(),
            )),
            tokio::spawn(certificate::rotate_forever(
                certificate.clone(),
                certificate_check_interval,
                stop.clone(),
            )),
        ];
        Ok(Self {
            hub,
            certificate,
            tasks,
            stop_tasks: stop.drop_guard(),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.hub.local_addr()
    }

    pub fn registry(&self) -> &AgentRegistry {
        self.hub.registry()
    }

    pub fn stats(&self) -> &Arc<GateStats> {
        self.hub.stats()
    }

    pub fn hub_stats(&self) -> HubStatsSnapshot {
        self.hub.hub_stats()
    }

    pub fn certificate_not_after(&self) -> SystemTime {
        self.certificate.not_after()
    }

    pub async fn shutdown(self, grace: Duration) -> ShutdownReport {
        let Self {
            hub,
            tasks,
            stop_tasks,
            ..
        } = self;
        drop(stop_tasks);
        for task in tasks {
            if let Err(error) = task.await
                && error.is_panic()
            {
                tracing::error!(target: "jaunt::agents", "a background task of the agents' listener panicked");
            }
        }
        hub.shutdown(grace).await
    }
}
