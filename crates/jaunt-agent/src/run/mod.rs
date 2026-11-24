pub(crate) mod api;
pub(crate) mod config;
pub mod logging;
mod renew;
#[cfg(test)]
mod tests;

use std::env::{self, VarError};
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Args;
use jaunt_ssh::{AgentLimits, InnerCa, InnerTarget, SshError};
use jaunt_tunnel::{
    BackoffPolicy, ClientError, ClientEvent, Keepalive, SwappableClientCert, TlsConfigError,
    TunnelClient, TunnelClientConfig, agent_client_config_swappable,
};
use rustls::pki_types::CertificateDer;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::AGENT_VERSION;
use crate::clock::{Clock, SystemClock, format_utc, unix_secs};
use crate::endpoint::{AgentEndpoint, EndpointError};
use crate::fsio::running_as_root;
use crate::ssh::{self, ControlAuthority, InnerTargetError, SshService};
use crate::state::{DEFAULT_STATE_DIR, StateDir, StateError};
use crate::trust::{TRUST_TIMING, TrustLoader, TrustTiming, random_sampler};
use crate::verify::{self, VerifyError};
use api::{API_KEEPALIVE, AgentApi, ApiError};
use config::{ConfigError, InnerConfig};
use logging::LoggingError;
use renew::{RENEWAL_BACKOFF, Renewer};

const DEFAULT_CONFIG: &str = "/etc/jaunt/agent.yaml";
const FILTER_VAR: &str = "RUST_LOG";
pub const SSH_STREAM_WINDOW: u32 = 1024 * 1024;
pub const SSH_CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    #[arg(long, value_name = "DIR")]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("the state directory must be an absolute path")]
    StateDirRelative,
    #[error("{FILTER_VAR} is not valid unicode")]
    FilterNotUnicode,
    #[error("cannot set up logging: {0}")]
    Logging(#[from] LoggingError),
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("cannot install the signal handlers: {0}")]
    Signals(#[source] io::Error),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(
        "the stored node certificate does not belong to this enrollment ({0}); re-enroll with `jaunt-agent enroll --replace`"
    )]
    Identity(#[source] VerifyError),
    #[error("the stored agent endpoint is not usable: {0}")]
    Endpoint(#[source] EndpointError),
    #[error("the stored internal CA root is not usable: {0}")]
    Root(#[source] VerifyError),
    #[error("cannot build the TLS client configuration: {0}")]
    Tls(#[source] TlsConfigError),
    #[error("cannot set up the agent API client: {0}")]
    Api(#[source] ApiError),
    #[error("the local sshd cannot be used for SSH sessions: {0}")]
    InnerTarget(#[source] InnerTargetError),
    #[error("cannot create the inner CA: {0}")]
    InnerCa(#[source] SshError),
    #[error("cannot publish the inner CA for sshd: {0}")]
    InnerCaFile(#[source] StateError),
    #[error("the tunnel client stopped: {0}")]
    Tunnel(#[source] ClientError),
    #[error("the tunnel client task failed")]
    TunnelTask,
}

pub struct RunSettings {
    pub state_dir: PathBuf,
    pub inner: InnerConfig,
    pub ssh_limits: AgentLimits,
    pub tunnel_backoff: BackoffPolicy,
    pub renewal_backoff: BackoffPolicy,
    pub trust: TrustTiming,
    pub api_keepalive: Keepalive,
    pub privileged: bool,
}

impl RunSettings {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            inner: InnerConfig::default(),
            ssh_limits: AgentLimits::default(),
            tunnel_backoff: BackoffPolicy::default(),
            renewal_backoff: RENEWAL_BACKOFF,
            trust: TRUST_TIMING,
            api_keepalive: API_KEEPALIVE,
            privileged: running_as_root(),
        }
    }
}

pub struct RunEnv {
    pub clock: Arc<dyn Clock>,
    pub jitter: Box<dyn FnMut() -> f64 + Send + Sync>,
}

pub fn command(args: &RunArgs) -> ExitCode {
    crate::finish_on_stderr(run_command(args))
}

fn run_command(args: &RunArgs) -> Result<(), RunError> {
    let config = config::load(&args.config)?;
    let state_dir = args
        .state_dir
        .clone()
        .or(config.state_dir)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    if !state_dir.is_absolute() {
        return Err(RunError::StateDirRelative);
    }
    let env_filter = match env::var(FILTER_VAR) {
        Ok(spec) => Some(spec),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => return Err(RunError::FilterNotUnicode),
    };
    logging::init(logging::choose_filter(
        env_filter.as_deref(),
        config.log_level.as_deref(),
    ))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RunError::Runtime)?;
    runtime.block_on(async {
        let mut terminate = signal(SignalKind::terminate()).map_err(RunError::Signals)?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(RunError::Signals)?;
        let shutdown = CancellationToken::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            tracing::info!(target: "jaunt::agent", "shutting down");
            trigger.cancel();
        });
        let env = RunEnv {
            clock: Arc::new(SystemClock),
            jitter: Box::new(|| rand::random_range(0.0..=1.0)),
        };
        let settings = RunSettings {
            inner: config.inner,
            ..RunSettings::new(state_dir)
        };
        run(settings, env, shutdown).await
    })
}

pub async fn run(
    settings: RunSettings,
    env: RunEnv,
    shutdown: CancellationToken,
) -> Result<(), RunError> {
    let state = StateDir::open(&settings.state_dir, settings.privileged)?;
    let loaded = state.load()?;
    let record = loaded.record;
    if !verify::is_node_id(&record.node_id) {
        return Err(RunError::Identity(VerifyError::NodeId));
    }
    let validity =
        verify::node_identity(&loaded.x509_der, &record.node_id, loaded.tls_key.spki_der())
            .map_err(RunError::Identity)?;
    let endpoint = AgentEndpoint::parse(&record.agent_endpoint).map_err(RunError::Endpoint)?;
    let roots = verify::root_store(&loaded.ca_root_der).map_err(RunError::Root)?;
    let tls_spki = loaded.tls_key.spki_der().to_vec();
    let identity = Arc::new(
        SwappableClientCert::new(
            vec![CertificateDer::from(loaded.x509_der)],
            loaded.tls_key.rustls_key(),
        )
        .map_err(RunError::Tls)?,
    );
    drop(loaded.tls_key);
    let ssh_key = loaded.host_key.key_data().clone();
    drop(loaded.host_key);
    let target = InnerTarget {
        sshd_addr: settings.inner.sshd_addr,
        sshd_host_key: settings.inner.sshd_host_key.clone(),
    };
    ssh::check_inner_target(&target).map_err(RunError::InnerTarget)?;
    let inner_ca = InnerCa::generate().map_err(RunError::InnerCa)?;
    let inner_ca_line = inner_ca.public_openssh().map_err(RunError::InnerCa)?;
    state
        .store_inner_ca(&inner_ca_line)
        .map_err(RunError::InnerCaFile)?;
    let tls =
        Arc::new(agent_client_config_swappable(roots, identity.clone()).map_err(RunError::Tls)?);
    let stop = shutdown.child_token();
    let api_stop = CancellationToken::new();
    let _api_stop_on_drop = api_stop.clone().drop_guard();
    let api = Arc::new(
        AgentApi::new(&tls, &endpoint, settings.api_keepalive, api_stop.clone())
            .map_err(RunError::Api)?,
    );
    let service = Arc::new(SshService::new(
        Arc::new(inner_ca),
        target,
        Arc::new(ControlAuthority::new(api.clone())),
        settings.ssh_limits,
    ));
    match ssh::load_host_identity(&state, now_unix(env.clock.as_ref())) {
        Ok(host) => service.install_host_identity(host),
        Err(error) => tracing::error!(
            target: "jaunt::agent",
            error = %error,
            "cannot load the SSH host certificate; SSH sessions are refused until a renewal succeeds"
        ),
    }
    let tunnel_config = tunnel_config(tls, &endpoint, settings.tunnel_backoff);
    let events = tunnel_config.subscribe();
    let trust_events = tunnel_config.subscribe();
    tracing::info!(
        target: "jaunt::agent",
        node_id = %record.node_id,
        name = %record.name,
        endpoint = %endpoint.as_str(),
        x509_not_after = %format_utc(validity.not_after),
        "starting the agent"
    );
    let reload = {
        let service = service.clone();
        let clock = env.clock.clone();
        Box::new(move |state: &StateDir| {
            service.reload_host_identity(state, now_unix(clock.as_ref()));
        })
    };
    let loader = TrustLoader {
        api: api.clone(),
        ssh: service.clone(),
        clock: env.clock.clone(),
        timing: settings.trust,
        events: Some(trust_events),
        sample: random_sampler(),
    };
    let renewer = Renewer {
        api,
        state,
        identity,
        record,
        ssh_key,
        tls_spki,
        root_der: loaded.ca_root_der,
        validity,
        clock: env.clock,
        jitter: env.jitter,
        backoff: settings.renewal_backoff,
        after_renewal: reload,
    };
    let trust = tokio::spawn(loader.run(stop.child_token()));
    let mut tunnel = tokio::spawn(TunnelClient::run(
        tunnel_config,
        service,
        stop.child_token(),
    ));
    let event_log = tokio::spawn(log_tunnel_events(events, stop.child_token()));
    let renewal = tokio::spawn(renewer.run(stop.child_token()));

    let outcome = tokio::select! {
        () = shutdown.cancelled() => None,
        joined = &mut tunnel => Some(joined),
    };
    stop.cancel();
    let tunnel_result = match outcome {
        Some(joined) => joined,
        None => tunnel.await,
    };
    api_stop.cancel();
    match renewal.await {
        Ok(end) => {
            tracing::info!(target: "jaunt::agent", end = ?end, "certificate renewal stopped")
        }
        Err(error) => {
            tracing::error!(target: "jaunt::agent", error = %error, "the renewal task failed");
        }
    }
    match trust.await {
        Ok(end) => {
            tracing::info!(target: "jaunt::agent", end = ?end, "user CA trust loading stopped")
        }
        Err(error) => {
            tracing::error!(target: "jaunt::agent", error = %error, "the trust loading task failed");
        }
    }
    if let Err(error) = event_log.await {
        tracing::error!(target: "jaunt::agent", error = %error, "the tunnel event task failed");
    }
    match tunnel_result {
        Ok(Ok(())) if shutdown.is_cancelled() => Ok(()),
        Ok(Ok(())) => Err(RunError::TunnelTask),
        Ok(Err(error)) => Err(RunError::Tunnel(error)),
        Err(_) => Err(RunError::TunnelTask),
    }
}

fn tunnel_config(
    tls: Arc<rustls::ClientConfig>,
    endpoint: &AgentEndpoint,
    backoff: BackoffPolicy,
) -> TunnelClientConfig {
    let mut config = TunnelClientConfig::new(
        tls,
        endpoint.as_str(),
        endpoint.server_name(),
        AGENT_VERSION,
    );
    config.backoff = backoff;
    config.options.stream_window = SSH_STREAM_WINDOW;
    config.options.connection_window = SSH_CONNECTION_WINDOW;
    config
}

fn now_unix(clock: &dyn Clock) -> u64 {
    u64::try_from(unix_secs(clock.now())).unwrap_or(0)
}

async fn log_tunnel_events(mut events: broadcast::Receiver<ClientEvent>, stop: CancellationToken) {
    loop {
        let event = tokio::select! {
            () = stop.cancelled() => return,
            event = events.recv() => event,
        };
        match event {
            Ok(ClientEvent::Connected) => {
                tracing::info!(target: "jaunt::agent", "the tunnel is connected");
            }
            Ok(ClientEvent::Disconnected { lasted }) => tracing::warn!(
                target: "jaunt::agent",
                lasted_secs = lasted.as_secs(),
                "the tunnel disconnected; reconnecting"
            ),
            Ok(ClientEvent::ConnectFailed(failure)) => tracing::warn!(
                target: "jaunt::agent",
                failure = ?failure,
                "connecting the tunnel failed; retrying"
            ),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::debug!(target: "jaunt::agent", skipped, "tunnel events were skipped");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}
