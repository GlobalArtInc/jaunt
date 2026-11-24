use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jaunt_control::{Control, ControlError, ControlParts, PENDING_CAPACITY, system_clock};
use jaunt_oidc::{OidcClient, OidcError};
use jaunt_policy::Watcher;
use jaunt_store::{Store, StoreError};
use jauntd::agents::{AgentServer, AgentServerParts, AgentsError, AgentsSettings, SHUTDOWN_GRACE};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::ca::{self, Authorities};
use crate::config::{self, ConfigError, EnvLookup, RunSettings};
use crate::logging::{self, LoggingError};
use crate::policy::{self, PolicyError};
use crate::storage::{self, Exposure, StorageError};

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Settings(#[from] ConfigError),
    #[error("cannot load the certificate authorities: {0}")]
    Authorities(String),
    #[error(transparent)]
    Logging(#[from] LoggingError),
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("cannot install the signal handlers: {0}")]
    Signals(#[source] io::Error),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("cannot open the database {}: {source}", path.display())]
    Database {
        path: PathBuf,
        #[source]
        source: StoreError,
    },
    #[error("cannot migrate the database: {0}")]
    Migrate(#[source] StoreError),
    #[error("cannot set up the identity provider: {0}")]
    Oidc(#[source] OidcError),
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Agents(#[from] AgentsError),
}

pub fn run(config_path: &Path, env: EnvLookup<'_>) -> Result<(), ServeError> {
    let config = config::load(config_path).map_err(ServeError::Config)?;
    let settings = config.into_run_settings(env)?;
    let authorities =
        ca::load_authorities(&settings.data_dir, env).map_err(ServeError::Authorities)?;
    logging::init(env)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::Runtime)?;
    runtime.block_on(serve(settings, authorities))
}

struct Started {
    control: Control,
    watcher: Watcher,
    listen: SocketAddr,
    store: Store,
    agents: Option<AgentsSettings>,
}

async fn serve(settings: RunSettings, authorities: Authorities) -> Result<(), ServeError> {
    let mut terminate = signal(SignalKind::terminate()).map_err(ServeError::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(ServeError::Signals)?;

    let Started {
        control,
        watcher,
        listen,
        store,
        agents,
    } = start(settings, authorities).await?;
    let listener = match bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            policy::stop_watcher(watcher).await;
            return Err(err);
        }
    };
    let agents = match start_agents(agents, &control, store).await {
        Ok(agents) => agents,
        Err(err) => {
            policy::stop_watcher(watcher).await;
            return Err(err);
        }
    };

    let (deadline_tx, mut deadline_rx) = watch::channel(None);
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        tracing::info!(target: "jaunt::daemon", "shutting down");
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        deadline_tx.send_replace(Some(deadline));
        if let Some(agents) = agents {
            agents
                .shutdown(deadline.saturating_duration_since(Instant::now()))
                .await;
        }
        policy::stop_watcher(watcher).await;
    };
    let overdue = async move {
        let deadline = match deadline_rx.wait_for(Option::is_some).await {
            Ok(seen) => *seen,
            Err(_) => None,
        };
        match deadline {
            Some(deadline) => sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        served = control.serve(listener, shutdown) => served?,
        () = overdue => {
            tracing::warn!(
                target: "jaunt::daemon",
                "the http server did not stop within the shutdown grace"
            );
        }
    }
    Ok(())
}

async fn start_agents(
    settings: Option<AgentsSettings>,
    control: &Control,
    store: Store,
) -> Result<Option<AgentServer>, ServeError> {
    let Some(settings) = settings else {
        tracing::info!(target: "jaunt::daemon", "the agents' listener is disabled");
        return Ok(None);
    };
    let parts = AgentServerParts::new(settings, control.clone(), store, system_clock());
    let server = AgentServer::start(parts).await?;
    tracing::info!(
        target: "jaunt::daemon",
        listen = %server.local_addr(),
        "serving agents"
    );
    Ok(Some(server))
}

async fn start(settings: RunSettings, authorities: Authorities) -> Result<Started, ServeError> {
    let policy = policy::load_at_startup(&settings.policy_dir)?;

    let prepared = storage::prepare(&settings.data_dir)?;
    for exposure in &prepared.exposures {
        log_exposure(&prepared.database, &settings.data_dir, *exposure);
    }
    let store = Store::open(&prepared.database)
        .await
        .map_err(|source| ServeError::Database {
            path: prepared.database.clone(),
            source,
        })?;
    store.migrate().await.map_err(ServeError::Migrate)?;

    let oidc = OidcClient::discover(settings.oidc)
        .await
        .map_err(ServeError::Oidc)?;
    let agents_store = store.clone();
    let control = Control::new(ControlParts {
        store,
        oidc,
        user_authority: Arc::new(authorities.user),
        user_trust: authorities.user_trust,
        host_trust: authorities.host_trust,
        host_authority: Arc::new(authorities.host),
        internal_ca: authorities.internal,
        ssh_suffix: settings.ssh_suffix,
        gate_endpoint: settings.gate_endpoint,
        agent_endpoint: settings.agent_endpoint,
        cert_ttl: settings.cert_ttl,
        pending_capacity: PENDING_CAPACITY,
        device: settings.device,
        policy: policy.clone(),
        web_enabled: settings.web,
        clock: system_clock(),
    })?;
    let watcher = policy::start_watcher(policy, settings.policy_dir, settings.policy_poll);
    Ok(Started {
        control,
        watcher,
        listen: settings.listen,
        store: agents_store,
        agents: settings.agents,
    })
}

async fn bind(listen: SocketAddr) -> Result<TcpListener, ServeError> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|source| ServeError::Listen {
            addr: listen,
            source,
        })?;
    let bound = listener.local_addr().map_err(|source| ServeError::Listen {
        addr: listen,
        source,
    })?;
    tracing::info!(target: "jaunt::daemon", listen = %bound, "serving plain http");
    Ok(listener)
}

fn log_exposure(database: &Path, data_dir: &Path, exposure: Exposure) {
    match exposure {
        Exposure::DataDirAccessibleByOthers { mode } => tracing::warn!(
            target: "jaunt::daemon",
            path = %data_dir.display(),
            mode = format_args!("{mode:03o}"),
            "the data directory is accessible by users outside the owner and the group"
        ),
        Exposure::DatabaseAccessibleByGroupOrOthers { mode } => tracing::warn!(
            target: "jaunt::daemon",
            path = %database.display(),
            mode = format_args!("{mode:03o}"),
            "the database file is accessible by group or others"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    use jaunt_ca::{AgeIdentity, CaKind, FileBackend, InternalCa};
    use jaunt_policy::PolicySet;

    use super::{ServeError, run, serve, start};
    use crate::ca::Authorities;
    use crate::config;
    use crate::policy::PolicyError;

    mod trust;

    fn secret_only(name: &str) -> Option<OsString> {
        (name == "JAUNT_OIDC_CLIENT_SECRET").then(|| OsString::from("never-printed-secret"))
    }

    fn write_config(dir: &std::path::Path, extra: &str) -> std::path::PathBuf {
        let path = dir.join("jauntd.yaml");
        let text = format!(
            "data_dir: {}\npublic_url: https://jaunt.example.com\n{extra}\
             ssh_suffix: jaunt.example.com\nagent_endpoint: agents.example.com:443\n\
             oidc:\n  issuer_url: https://idp.example.com\n  client_id: jaunt\n",
            dir.display()
        );
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn startup_stops_before_serving_when_the_authorities_are_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(dir.path(), "");

        let err = run(&config, &secret_only).err().unwrap();

        assert!(matches!(err, ServeError::Authorities(_)), "{err}");
        assert!(!err.to_string().contains("never-printed-secret"));
        assert!(!dir.path().join("jaunt.db").exists());
    }

    #[test]
    fn startup_stops_on_an_invalid_config_before_touching_the_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(dir.path(), "cert_ttl_secs: 5\n");

        let err = run(&config, &secret_only).err().unwrap();

        assert!(matches!(err, ServeError::Settings(_)), "{err}");
        assert!(!dir.path().join("jaunt.db").exists());
    }

    fn authorities(dir: &std::path::Path) -> Authorities {
        let root = dir.join("test-ca");
        let identity = AgeIdentity::generate();
        for kind in [CaKind::User, CaKind::Host, CaKind::Internal] {
            FileBackend::init(&root, kind, &identity.recipient()).unwrap();
        }
        let (user_trust, user) = FileBackend::load(&root, CaKind::User, &identity).unwrap();
        let (host_trust, host) = FileBackend::load(&root, CaKind::Host, &identity).unwrap();
        let (_, internal) = FileBackend::load(&root, CaKind::Internal, &identity).unwrap();
        let certificate = InternalCa::create_root(&internal, SystemTime::now()).unwrap();
        Authorities {
            user,
            user_trust,
            host_trust,
            host,
            internal: InternalCa::new(Arc::new(internal), certificate.certificate_der).unwrap(),
        }
    }

    #[test]
    fn an_invalid_policy_stops_startup_before_the_database_and_the_listener() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("roles.yaml"), "kind: Role\nbogus: 1\n").unwrap();
        let path = write_config(dir.path(), "");
        let settings = config::load(&path)
            .unwrap()
            .into_run_settings(&secret_only)
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let err = runtime
            .block_on(serve(settings, authorities(dir.path())))
            .err()
            .unwrap();

        assert!(
            matches!(err, ServeError::Policy(PolicyError::Invalid { .. })),
            "{err}"
        );
        let shown = err.to_string();
        assert!(shown.contains("roles.yaml"), "{shown}");
        assert!(!dir.path().join("jaunt.db").exists());
    }

    fn role(login: &str) -> String {
        format!(
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: ops }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [{login}] }}\n"
        )
    }

    fn fake_discovery() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let discovery = format!(
            "{{\"issuer\":\"{base}\",\"authorization_endpoint\":\"{base}/authorize\",\
             \"token_endpoint\":\"{base}/token\",\"jwks_uri\":\"{base}/jwks\",\
             \"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],\
             \"id_token_signing_alg_values_supported\":[\"EdDSA\"]}}"
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                let body = if request.starts_with(b"GET /jwks") {
                    "{\"keys\":[]}".to_owned()
                } else {
                    discovery.clone()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        base
    }

    #[test]
    fn control_follows_the_edits_the_watcher_applies() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("roles.yaml"), role("deploy")).unwrap();
        let path = write_config(dir.path(), "");
        let mut settings = config::load(&path)
            .unwrap()
            .into_run_settings(&secret_only)
            .unwrap();
        settings.oidc.issuer_url = fake_discovery();
        settings.policy_poll = Duration::from_millis(20);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let started = runtime
            .block_on(start(settings, authorities(dir.path())))
            .unwrap();

        let loaded = started.control.policy().snapshot().hash().to_owned();
        assert_ne!(loaded, PolicySet::empty().hash());
        let temporary = policy_dir.join(".roles.yaml.tmp");
        std::fs::write(&temporary, role("ops")).unwrap();
        std::fs::rename(&temporary, policy_dir.join("roles.yaml")).unwrap();
        let begun = Instant::now();
        while started.control.policy().snapshot().hash() == loaded {
            assert!(
                begun.elapsed() < Duration::from_secs(5),
                "the control never saw the edit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        started.watcher.stop();
    }

    fn client_config_answer(extra: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("policy")).unwrap();
        let path = write_config(dir.path(), extra);
        let mut settings = config::load(&path)
            .unwrap()
            .into_run_settings(&secret_only)
            .unwrap();
        settings.oidc.issuer_url = fake_discovery();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = runtime
            .block_on(start(settings, authorities(dir.path())))
            .unwrap();
        let answer = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(
                started
                    .control
                    .clone()
                    .serve(listener, std::future::pending()),
            );
            let fetched = tokio::task::spawn_blocking(move || {
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                write!(
                    stream,
                    "GET /v1/client-config HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
                )
                .unwrap();
                let mut answer = String::new();
                stream.read_to_string(&mut answer).unwrap();
                answer
            })
            .await
            .unwrap();
            server.abort();
            fetched
        });
        started.watcher.stop();
        answer
    }

    #[test]
    fn the_configured_gate_endpoint_reaches_the_client_config_route() {
        let configured = client_config_answer("gate_endpoint: Gate.Example.org:2222\n");

        assert!(configured.starts_with("HTTP/1.1 200"), "{configured}");
        assert!(
            configured.contains(
                r#""ssh_suffix":"jaunt.example.com","gate":{"host":"gate.example.org","port":2222}"#
            ),
            "{configured}"
        );

        let defaulted = client_config_answer("gate_endpoint: gate.example.org\n");
        assert!(
            defaulted.contains(r#""gate":{"host":"gate.example.org","port":22}"#),
            "{defaulted}"
        );

        let absent = client_config_answer("");
        assert!(absent.starts_with("HTTP/1.1 404"), "{absent}");
        assert!(absent.contains(r#"{"error":"not_configured"}"#), "{absent}");
    }
}
