use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use jaunt_ca::ssh_key::PublicKey;
use jaunt_ca::{CaError, DEFAULT_HOST_VALIDITY, HostCertParams, Signer, sign_host_certificate};
use jaunt_control::Clock;
use jaunt_gate::{HostCertIssuer, IssueError, SshGate, SshGateConfig, SshGateError};
use jaunt_proto::{BoxFuture, ControlPlane};
use jaunt_ssh::{OuterLimits, UserCaSource};
use jaunt_store::Store;
use jaunt_tunnel::AgentRegistry;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateSshSettings {
    pub listen: SocketAddr,
    pub hostnames: Vec<String>,
    pub proxy_protocol: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub max_unauthenticated: usize,
    pub write_stall: Option<Duration>,
}

pub struct HostAuthorityIssuer {
    signer: Arc<dyn Signer>,
    store: Store,
    clock: Clock,
}

impl HostAuthorityIssuer {
    pub fn new(signer: Arc<dyn Signer>, store: Store, clock: Clock) -> Self {
        Self {
            signer,
            store,
            clock,
        }
    }

    async fn sign(
        &self,
        public_key_openssh: &str,
        hostnames: &[String],
    ) -> Result<String, IssueError> {
        let subject_public_key =
            PublicKey::from_openssh(public_key_openssh).map_err(|_| IssueError::InvalidRequest)?;
        let serial = self
            .store
            .certificates()
            .allocate_serial()
            .await
            .map_err(|error| {
                tracing::error!(target: "jaunt::gate", error = %error, "cannot allocate a serial for the gate host certificate");
                IssueError::Unavailable
            })?;
        let serial = u64::try_from(serial).map_err(|_| IssueError::Unavailable)?;
        let certificate = sign_host_certificate(
            self.signer.as_ref(),
            HostCertParams {
                subject_public_key,
                hostnames: hostnames.to_vec(),
                serial,
                validity: DEFAULT_HOST_VALIDITY,
            },
            (self.clock)(),
        )
        .map_err(signing_failure)?;
        certificate
            .to_openssh()
            .map_err(|_| IssueError::Unavailable)
    }
}

fn signing_failure(error: CaError) -> IssueError {
    tracing::error!(target: "jaunt::gate", error = %error, "cannot sign the gate host certificate");
    match error {
        CaError::InvalidHostnames | CaError::InvalidValidity { .. } => IssueError::InvalidRequest,
        _ => IssueError::Unavailable,
    }
}

impl HostCertIssuer for HostAuthorityIssuer {
    fn issue<'a>(
        &'a self,
        public_key_openssh: &'a str,
        hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>> {
        Box::pin(self.sign(public_key_openssh, hostnames))
    }
}

pub fn gate_config(settings: GateSshSettings, ssh_suffix: String) -> SshGateConfig {
    let mut config = SshGateConfig::new(settings.hostnames, ssh_suffix);
    config.proxy_protocol = settings.proxy_protocol;
    config.trusted_proxies = settings.trusted_proxies;
    config.max_unauthenticated = settings.max_unauthenticated;
    config.limits = OuterLimits {
        write_stall_timeout: settings.write_stall,
        ..OuterLimits::default()
    };
    config
}

pub struct GateSshParts {
    pub settings: GateSshSettings,
    pub ssh_suffix: String,
    pub issuer: Arc<dyn HostCertIssuer>,
    pub user_cas: Arc<UserCaSource>,
    pub control: Arc<dyn ControlPlane>,
    pub registry: AgentRegistry,
}

#[derive(Debug, thiserror::Error)]
pub enum GateSshError {
    #[error("cannot start the ssh gate: {0}")]
    Gate(#[from] SshGateError),
    #[error("cannot listen for ssh on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
}

pub struct GateSshServer {
    gate: Arc<SshGate>,
    local_addr: SocketAddr,
    task: JoinHandle<()>,
    stop: CancellationToken,
    _stop_on_drop: DropGuard,
}

impl GateSshServer {
    pub async fn start(parts: GateSshParts) -> Result<Self, GateSshError> {
        let GateSshParts {
            settings,
            ssh_suffix,
            issuer,
            user_cas,
            control,
            registry,
        } = parts;
        let listen = settings.listen;
        let listen_error = |source| GateSshError::Listen {
            addr: listen,
            source,
        };
        let listener = TcpListener::bind(listen).await.map_err(listen_error)?;
        let local_addr = listener.local_addr().map_err(listen_error)?;
        let config = gate_config(settings, ssh_suffix);
        let gate = Arc::new(SshGate::new(config, issuer, user_cas, control, registry).await?);
        let stop = CancellationToken::new();
        let serving = Arc::clone(&gate);
        let token = stop.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = serving.serve(listener, token).await {
                tracing::error!(target: "jaunt::gate", error = %error, "the ssh gate stopped");
            }
        });
        Ok(Self {
            gate,
            local_addr,
            task,
            _stop_on_drop: stop.clone().drop_guard(),
            stop,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn gate(&self) -> &Arc<SshGate> {
        &self.gate
    }

    pub async fn shutdown(self, grace: Duration) -> bool {
        let Self { mut task, stop, .. } = self;
        stop.cancel();
        match tokio::time::timeout(grace, &mut task).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => {
                tracing::error!(target: "jaunt::gate", "the ssh gate task panicked");
                false
            }
            Err(_) => {
                task.abort();
                tracing::warn!(
                    target: "jaunt::gate",
                    "the ssh gate did not stop within the shutdown grace and was aborted"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jaunt_ssh::OuterLimits;

    use super::{GateSshSettings, gate_config};

    #[test]
    fn the_settings_reach_the_gate_configuration() {
        for stall in [
            Some(Duration::from_secs(900)),
            Some(Duration::from_secs(1)),
            None,
        ] {
            let settings = GateSshSettings {
                listen: "127.0.0.1:2222".parse().unwrap(),
                hostnames: vec!["gate.example.com".to_owned()],
                proxy_protocol: true,
                trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
                max_unauthenticated: 7,
                write_stall: stall,
            };
            let config = gate_config(settings, "nodes.example.com".to_owned());
            assert_eq!(config.limits.write_stall_timeout, stall);
            assert_eq!(
                OuterLimits {
                    write_stall_timeout: OuterLimits::default().write_stall_timeout,
                    ..config.limits
                },
                OuterLimits::default()
            );
            assert_eq!(config.hostnames, ["gate.example.com"]);
            assert_eq!(config.ssh_suffix, "nodes.example.com");
            assert!(config.proxy_protocol);
            assert_eq!(config.trusted_proxies.len(), 1);
            assert_eq!(config.max_unauthenticated, 7);
        }
    }
}
