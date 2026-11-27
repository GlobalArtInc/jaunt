mod api;
mod auth;
mod certificate;
mod reconcile;
mod sessions;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ipnet::IpNet;
use jaunt_ca::CaError;
use jaunt_control::{Clock, Control, REVOCATION_WATCH_INTERVAL, SESSION_SWEEP_INTERVAL};
use jaunt_gate::{
    AgentHub, AgentHubConfig, ClassHandlers, ConnectedAgents, DEFAULT_AGENT_CLIENT_LIMITS,
    DEFAULT_KUBE_CLIENT_LIMITS, HubError, HubStatsSnapshot, ServicesEntry, ShutdownReport,
    TlsRefusal,
};
use jaunt_limits::AddressLimits;
use jaunt_store::Store;
use jaunt_tunnel::{
    AgentRegistry, GateStats, TlsConfigError, TunnelOptions, rotating_agent_server_config,
};
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
use sessions::{Presence, Registrations, SweepPlan};

pub const DEFAULT_AGENTS_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8444);
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
pub const CERTIFICATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const SSH_STREAM_WINDOW: u32 = 1024 * 1024;
pub const SSH_CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
pub const AGENT_GONE_AFTER: Duration = Duration::from_secs(120);

const _: () = assert!(RECONCILE_INTERVAL.as_secs() <= 5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentsSettings {
    pub listen: SocketAddr,
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicesSettings {
    pub domain: String,
    pub proxy_protocol: bool,
    pub trusted_proxies: Vec<IpNet>,
}

pub struct AgentServerParts {
    pub settings: AgentsSettings,
    pub control: Control,
    pub store: Store,
    pub clock: Clock,
    pub reconcile_interval: Duration,
    pub certificate_check_interval: Duration,
    pub session_sweep_interval: Duration,
    pub revocation_watch_interval: Duration,
    pub agent_gone_after: Duration,
    pub api_limits: ApiLimits,
    pub tunnel: TunnelOptions,
    pub client_limits: AddressLimits,
    pub kube_limits: AddressLimits,
    pub services: Option<ServicesSettings>,
}

pub fn ssh_tunnel_options() -> TunnelOptions {
    TunnelOptions {
        stream_window: SSH_STREAM_WINDOW,
        connection_window: SSH_CONNECTION_WINDOW,
        ..TunnelOptions::default()
    }
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
            session_sweep_interval: SESSION_SWEEP_INTERVAL,
            revocation_watch_interval: REVOCATION_WATCH_INTERVAL,
            agent_gone_after: AGENT_GONE_AFTER,
            api_limits: ApiLimits::default(),
            tunnel: ssh_tunnel_options(),
            client_limits: DEFAULT_AGENT_CLIENT_LIMITS,
            kube_limits: DEFAULT_KUBE_CLIENT_LIMITS,
            services: None,
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
            session_sweep_interval,
            revocation_watch_interval,
            agent_gone_after,
            api_limits,
            tunnel,
            client_limits,
            kube_limits,
            services,
        } = parts;
        tracing::info!(
            target: "jaunt::daemon",
            "single-process assumption: this jauntd is the only one using its database, so open \
             sessions of earlier runs are closed at start and agent presence is kept in this \
             process memory; running several jauntd processes on one database is not supported"
        );
        match control.close_sessions_of_earlier_runs().await {
            Ok(0) => {}
            Ok(closed) => tracing::info!(
                target: "jaunt::daemon",
                closed,
                "sessions left open by an earlier run were closed"
            ),
            Err(error) => tracing::warn!(
                target: "jaunt::daemon",
                error = %error,
                "closing the sessions left open by an earlier run failed"
            ),
        }
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
        let mut hub_config = AgentHubConfig::new(settings.server_name, Arc::new(tls));
        hub_config.tunnel = tunnel;
        hub_config.client_limits = client_limits;
        hub_config.services = services.map(|services| ServicesEntry {
            proxy_protocol: services.proxy_protocol,
            trusted_proxies: services.trusted_proxies,
            kube_limits,
            ..ServicesEntry::new(services.domain)
        });
        let hub = AgentHub::start(
            listener,
            hub_config,
            Arc::new(NodeAuthenticator::new(store.nodes())),
            Arc::new(AgentApi::new(control.agent_router(), api_limits)),
        )?;
        let events = hub.registry().subscribe();
        let presence = Arc::new(Presence::default());
        let stop = CancellationToken::new();
        let tasks = vec![
            tokio::spawn(sessions::follow_registrations(
                Registrations {
                    closer: control.clone(),
                    agents: hub.agents(),
                    nodes: StoreNodes::new(store.nodes()),
                    presence: Arc::clone(&presence),
                },
                events,
                stop.clone(),
            )),
            tokio::spawn(sessions::sweep_forever(
                control.clone(),
                presence,
                SweepPlan {
                    every: session_sweep_interval,
                    agent_gone_after,
                },
                stop.clone(),
            )),
            tokio::spawn(sessions::watch_revocations(
                control.clone(),
                revocation_watch_interval,
                stop.clone(),
            )),
            tokio::spawn(sessions::watch_access(control.clone(), stop.clone())),
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

    pub fn agents(&self) -> ConnectedAgents {
        self.hub.agents()
    }

    pub fn stats(&self) -> &Arc<GateStats> {
        self.hub.stats()
    }

    pub fn hub_stats(&self) -> HubStatsSnapshot {
        self.hub.hub_stats()
    }

    pub fn services_domain(&self) -> Option<&str> {
        self.hub.services_domain()
    }

    pub fn tls_refused(&self, reason: TlsRefusal) -> u64 {
        self.hub.tls_refused(reason)
    }

    pub fn install_class_handlers(&self, handlers: ClassHandlers) -> bool {
        self.hub.install_class_handlers(handlers)
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

#[cfg(test)]
mod tests {
    use jaunt_tunnel::TunnelOptions;

    use super::{SSH_CONNECTION_WINDOW, SSH_STREAM_WINDOW, ssh_tunnel_options};

    #[test]
    fn the_agents_tunnel_uses_the_ssh_windows() {
        let options = ssh_tunnel_options();
        assert_eq!(options.stream_window, 1024 * 1024);
        assert_eq!(options.connection_window, 16 * 1024 * 1024);
        assert_eq!(SSH_CONNECTION_WINDOW / SSH_STREAM_WINDOW, 16);
        assert_eq!(
            TunnelOptions {
                stream_window: TunnelOptions::default().stream_window,
                connection_window: TunnelOptions::default().connection_window,
                ..options.clone()
            },
            TunnelOptions::default()
        );
        assert_eq!(options.validate(), Ok(()));
    }
}
