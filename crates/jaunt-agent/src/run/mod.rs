mod api;
pub(crate) mod config;
pub mod logging;
mod refuse;
mod renew;
#[cfg(test)]
mod tests;

use std::env::{self, VarError};
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Args;
use jaunt_tunnel::{
    BackoffPolicy, ClientError, ClientEvent, Keepalive, SwappableClientCert, TlsConfigError,
    TunnelClient, TunnelClientConfig, agent_client_config_swappable,
};
use rustls::pki_types::CertificateDer;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::AGENT_VERSION;
use crate::clock::{Clock, SystemClock, format_utc};
use crate::endpoint::{AgentEndpoint, EndpointError};
use crate::fsio::running_as_root;
use crate::state::{DEFAULT_STATE_DIR, StateDir, StateError};
use crate::verify::{self, VerifyError};
use api::{API_KEEPALIVE, AgentApi, ApiError};
use config::ConfigError;
use logging::LoggingError;
use refuse::RefusingHandler;
use renew::{RENEWAL_BACKOFF, Renewer};

const DEFAULT_CONFIG: &str = "/etc/jaunt/agent.yaml";
const FILTER_VAR: &str = "RUST_LOG";

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
    #[error("the tunnel client stopped: {0}")]
    Tunnel(#[source] ClientError),
    #[error("the tunnel client task failed")]
    TunnelTask,
}

pub struct RunSettings {
    pub state_dir: PathBuf,
    pub tunnel_backoff: BackoffPolicy,
    pub renewal_backoff: BackoffPolicy,
    pub api_keepalive: Keepalive,
    pub privileged: bool,
}

impl RunSettings {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            tunnel_backoff: BackoffPolicy::default(),
            renewal_backoff: RENEWAL_BACKOFF,
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
        run(RunSettings::new(state_dir), env, shutdown).await
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
    let tls =
        Arc::new(agent_client_config_swappable(roots, identity.clone()).map_err(RunError::Tls)?);
    let stop = shutdown.child_token();
    let api = Arc::new(
        AgentApi::new(&tls, &endpoint, settings.api_keepalive, stop.child_token())
            .map_err(RunError::Api)?,
    );
    let mut tunnel_config = TunnelClientConfig::new(
        tls,
        endpoint.as_str(),
        endpoint.server_name(),
        AGENT_VERSION,
    );
    tunnel_config.backoff = settings.tunnel_backoff;
    let events = tunnel_config.subscribe();
    tracing::info!(
        target: "jaunt::agent",
        node_id = %record.node_id,
        name = %record.name,
        endpoint = %endpoint.as_str(),
        x509_not_after = %format_utc(validity.not_after),
        "starting the agent"
    );
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
    };
    let handler = Arc::new(RefusingHandler::default());
    let mut tunnel = tokio::spawn(TunnelClient::run(
        tunnel_config,
        handler,
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
    match renewal.await {
        Ok(end) => {
            tracing::info!(target: "jaunt::agent", end = ?end, "certificate renewal stopped")
        }
        Err(error) => {
            tracing::error!(target: "jaunt::agent", error = %error, "the renewal task failed");
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
