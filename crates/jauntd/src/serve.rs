use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jaunt_audit::{AuditTap, system_clock as audit_clock};
use jaunt_ca::{Signer, TrustSet};
use jaunt_control::{Control, ControlError, ControlParts, PENDING_CAPACITY, system_clock};
use jaunt_gate::HostCertIssuer;
use jaunt_limits::AddressLimits;
use jaunt_oidc::{OidcClient, OidcError};
use jaunt_policy::Watcher;
use jaunt_proto::ControlPlane;
use jaunt_ssh::{UserCaKeys, UserCaSource};
use jaunt_store::{Store, StoreError};
use jauntd::agents::{AgentServer, AgentServerParts, AgentsError, AgentsSettings, SHUTDOWN_GRACE};
use jauntd::gate_ssh::{
    GateSshError, GateSshParts, GateSshServer, GateSshSettings, HostAuthorityIssuer,
};
use jauntd::killer::InProcessKiller;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::policy::{self, PolicyError};
use crate::storage::{self, Exposure, StorageError};
use jauntd::audit::{self, AuditRuntime, AuditStartError, Surface};
use jauntd::ca::{self, Authorities};
use jauntd::config::{self, ConfigError, EnvLookup, RunSettings};
use jauntd::logging::{self, LoggingError};
use jauntd::recordings::{self, RecordingsStartError};

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
    #[error("cannot read the user certificate authority keys for the ssh gate: {0}")]
    GateTrust(String),
    #[error(transparent)]
    Gate(#[from] GateSshError),
    #[error("cannot start the audit pipeline: {0}")]
    Audit(#[from] AuditStartError),
    #[error(transparent)]
    Recordings(#[from] RecordingsStartError),
}

pub fn run(config_path: &Path, env: EnvLookup<'_>) -> Result<(), ServeError> {
    let config = config::load(config_path).map_err(ServeError::Config)?;
    let settings = config.into_run_settings(env)?;
    let authorities =
        ca::load_authorities(&settings.data_dir, env).map_err(ServeError::Authorities)?;
    let tap = AuditTap::new(audit_clock());
    logging::init(env, &tap)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::Runtime)?;
    let served = runtime.block_on(serve(settings, authorities, tap));
    audit::finish_runtime(runtime, audit::RUNTIME_GRACE);
    served
}

struct Started {
    control: Control,
    watcher: Watcher,
    listen: SocketAddr,
    store: Store,
    agents: Option<AgentsSettings>,
    agent_limits: AddressLimits,
    gate: Option<GatePlan>,
    audit: AuditRuntime,
}

struct GatePlan {
    settings: GateSshSettings,
    ssh_suffix: String,
    issuer: Arc<dyn HostCertIssuer>,
    user_cas: Arc<UserCaSource>,
}

async fn serve(
    settings: RunSettings,
    authorities: Authorities,
    tap: AuditTap,
) -> Result<(), ServeError> {
    let mut terminate = signal(SignalKind::terminate()).map_err(ServeError::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(ServeError::Signals)?;

    let Started {
        control,
        watcher,
        listen,
        store,
        agents,
        agent_limits,
        gate,
        audit,
    } = start(settings, authorities, &tap).await?;
    let listener = match bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            policy::stop_watcher(watcher).await;
            audit.shutdown(audit::FLUSH_DEADLINE).await;
            return Err(err);
        }
    };
    let agents = match start_agents(agents, agent_limits, &control, store).await {
        Ok(agents) => agents,
        Err(err) => {
            policy::stop_watcher(watcher).await;
            audit.shutdown(audit::FLUSH_DEADLINE).await;
            return Err(err);
        }
    };
    let gate = match start_gate(gate, agents.as_ref(), &control).await {
        Ok(gate) => gate,
        Err(err) => {
            if let Some(agents) = agents {
                agents.shutdown(SHUTDOWN_GRACE).await;
            }
            policy::stop_watcher(watcher).await;
            audit.shutdown(audit::FLUSH_DEADLINE).await;
            return Err(err);
        }
    };
    install_killer(&control, agents.as_ref(), gate.as_ref());

    let (deadline_tx, mut deadline_rx) = watch::channel(None);
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        tracing::info!(target: "jaunt::daemon", "shutting down");
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        deadline_tx.send_replace(Some(deadline));
        if let Some(gate) = gate {
            gate.shutdown(deadline.saturating_duration_since(Instant::now()))
                .await;
        }
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
    let served = tokio::select! {
        served = control.serve(listener, shutdown) => served.map_err(ServeError::from),
        () = overdue => {
            tracing::warn!(
                target: "jaunt::daemon",
                "the http server did not stop within the shutdown grace"
            );
            Ok(())
        }
    };
    audit.shutdown(audit::FLUSH_DEADLINE).await;
    served
}

async fn start_agents(
    settings: Option<AgentsSettings>,
    client_limits: AddressLimits,
    control: &Control,
    store: Store,
) -> Result<Option<AgentServer>, ServeError> {
    let Some(settings) = settings else {
        tracing::info!(target: "jaunt::daemon", "the agents' listener is disabled");
        return Ok(None);
    };
    let mut parts = AgentServerParts::new(settings, control.clone(), store, system_clock());
    parts.client_limits = client_limits;
    let server = AgentServer::start(parts).await?;
    tracing::info!(
        target: "jaunt::daemon",
        listen = %server.local_addr(),
        "serving agents"
    );
    Ok(Some(server))
}

async fn start_gate(
    plan: Option<GatePlan>,
    agents: Option<&AgentServer>,
    control: &Control,
) -> Result<Option<GateSshServer>, ServeError> {
    let Some(plan) = plan else {
        tracing::info!(target: "jaunt::daemon", "the ssh gate is disabled");
        return Ok(None);
    };
    let Some(agents) = agents else {
        return Err(ServeError::Settings(ConfigError::GateWithoutAgents));
    };
    let control: Arc<dyn ControlPlane> = Arc::new(control.clone());
    let server = GateSshServer::start(GateSshParts {
        settings: plan.settings,
        ssh_suffix: plan.ssh_suffix,
        issuer: plan.issuer,
        user_cas: plan.user_cas,
        control,
        registry: agents.registry().clone(),
    })
    .await?;
    tracing::info!(
        target: "jaunt::daemon",
        listen = %server.local_addr(),
        "serving ssh"
    );
    Ok(Some(server))
}

fn install_killer(control: &Control, agents: Option<&AgentServer>, gate: Option<&GateSshServer>) {
    let Some(agents) = agents else {
        return;
    };
    let gate = gate.map(|server| Arc::clone(server.gate()));
    let closes_outer = gate.is_some();
    control.install_session_killer(Arc::new(InProcessKiller::new(agents.agents(), gate)));
    tracing::info!(
        target: "jaunt::daemon",
        closes_outer,
        "revocations tear down live sessions in this process, where the gate and control run together"
    );
}

fn gate_plan(
    settings: GateSshSettings,
    ssh_suffix: &str,
    user_trust: &TrustSet,
    host_authority: &Arc<dyn Signer>,
    store: &Store,
) -> Result<GatePlan, ServeError> {
    let lines = user_trust
        .to_authorized_lines()
        .map_err(|err| ServeError::GateTrust(err.to_string()))?;
    let keys = UserCaKeys::from_openssh_lines(lines)
        .map_err(|err| ServeError::GateTrust(err.to_string()))?;
    Ok(GatePlan {
        settings,
        ssh_suffix: ssh_suffix.to_owned(),
        issuer: Arc::new(HostAuthorityIssuer::new(
            Arc::clone(host_authority),
            store.clone(),
            system_clock(),
        )),
        user_cas: Arc::new(UserCaSource::new(keys)),
    })
}

async fn start(
    settings: RunSettings,
    authorities: Authorities,
    tap: &AuditTap,
) -> Result<Started, ServeError> {
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
    let audit = audit::start(&settings.audit, Surface::Daemon, &store, tap, audit_clock())?;

    let started: Result<Started, ServeError> = async {
        let oidc = OidcClient::discover(settings.oidc)
            .await
            .map_err(ServeError::Oidc)?;
        let agents_store = store.clone();
        let host_authority: Arc<dyn Signer> = Arc::new(authorities.host);
        let gate = settings
            .ssh_gate
            .map(|gate| {
                gate_plan(
                    gate,
                    settings.ssh_suffix.as_str(),
                    &authorities.user_trust,
                    &host_authority,
                    &store,
                )
            })
            .transpose()?;
        let prepared_recordings = settings
            .recordings
            .as_ref()
            .map(recordings::prepare)
            .transpose()?;
        if prepared_recordings.is_some() {
            recordings::raise_open_file_limit();
        }
        let control = Control::with_request_limits(
            ControlParts {
                store,
                oidc,
                user_authority: Arc::new(authorities.user),
                user_trust: authorities.user_trust,
                host_trust: authorities.host_trust,
                host_authority,
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
                recordings: prepared_recordings
                    .as_ref()
                    .map(|prepared| prepared.settings.clone()),
            },
            settings.limits.http,
        )?;
        if let Some(prepared) = &prepared_recordings {
            recordings::recover(prepared, &control).await?;
        }
        let watcher = policy::start_watcher(policy, settings.policy_dir, settings.policy_poll);
        Ok(Started {
            control,
            watcher,
            listen: settings.listen,
            store: agents_store,
            agents: settings.agents,
            agent_limits: settings.limits.agents,
            gate,
            audit: audit.clone(),
        })
    }
    .await;
    if started.is_err() {
        audit.shutdown(audit::FLUSH_DEADLINE).await;
    }
    started
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

    use jaunt_audit::{
        AuditEvent, AuditTap, keep_callsites_enabled_for_scoped_capture,
        system_clock as audit_clock,
    };
    use jaunt_ca::{AgeIdentity, CaKind, FileBackend, InternalCa};
    use jaunt_policy::PolicySet;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{ServeError, run, serve, start};
    use crate::policy::PolicyError;
    use jauntd::ca::Authorities;
    use jauntd::config;

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
            .block_on(serve(
                settings,
                authorities(dir.path()),
                AuditTap::new(audit_clock()),
            ))
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

    #[test]
    fn stopping_the_daemon_flushes_the_queued_audit_events() {
        keep_callsites_enabled_for_scoped_capture();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let path = write_config(
            dir.path(),
            &format!("audit:\n  jsonl:\n    file: {}\n", log.display()),
        );
        let mut settings = config::load(&path)
            .unwrap()
            .into_run_settings(&secret_only)
            .unwrap();
        settings.oidc.issuer_url = fake_discovery();
        settings.listen = "127.0.0.1:0".parse().unwrap();
        settings.agents = None;
        let tap = AuditTap::new(audit_clock());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = tracing::subscriber::set_default(Registry::default().with(tap.layer()));

        let served = runtime.block_on(async {
            let emit_then_stop = async {
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let before = tap.snapshot().captured;
                    tracing::info!(
                        target: "jaunt::audit",
                        event = "login.started",
                        login_id = "flush-me"
                    );
                    if tap.snapshot().captured > before {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "the daemon never bound the audit tap"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::TERM,
                )
                .unwrap();
            };
            let serving = serve(settings, authorities(dir.path()), tap.clone());
            let (served, ()) = tokio::join!(serving, emit_then_stop);
            served
        });

        assert!(served.is_ok(), "{:?}", served.err());
        let text = std::fs::read_to_string(&log).unwrap();
        let written: Vec<AuditEvent> = text
            .lines()
            .map(|line| AuditEvent::from_json_line(line).unwrap())
            .collect();
        assert!(
            written
                .iter()
                .any(|event| event.text("login_id") == Some("flush-me"))
        );
        let captured = usize::try_from(tap.snapshot().captured).unwrap();
        assert_eq!(written.len(), captured);
        tracing::info!(
            target: "jaunt::audit",
            event = "login.started",
            login_id = "after-the-stop"
        );
        assert_eq!(tap.snapshot().dropped_after_close, 1);
    }

    fn issuer_failing_on_demand() -> (String, std::sync::mpsc::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (go, wait) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
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
                wait.recv().ok();
                stream
                    .write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .ok();
            }
        });
        (base, go)
    }

    #[test]
    fn a_startup_that_fails_after_the_audit_pipeline_started_flushes_it_before_returning() {
        keep_callsites_enabled_for_scoped_capture();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let path = write_config(
            dir.path(),
            &format!("audit:\n  jsonl:\n    file: {}\n", log.display()),
        );
        let mut settings = config::load(&path)
            .unwrap()
            .into_run_settings(&secret_only)
            .unwrap();
        let (issuer, release) = issuer_failing_on_demand();
        settings.oidc.issuer_url = issuer;
        let tap = AuditTap::new(audit_clock());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = tracing::subscriber::set_default(Registry::default().with(tap.layer()));

        let served = runtime.block_on(async {
            let emit_then_fail_discovery = async {
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let before = tap.snapshot().captured;
                    tracing::info!(
                        target: "jaunt::audit",
                        event = "login.started",
                        login_id = "flush-on-failure"
                    );
                    if tap.snapshot().captured > before {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "the startup never bound the audit tap"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                release.send(()).unwrap();
            };
            let serving = serve(settings, authorities(dir.path()), tap.clone());
            let (served, ()) = tokio::join!(serving, emit_then_fail_discovery);
            served
        });

        assert!(matches!(served, Err(ServeError::Oidc(_))), "{served:?}");
        runtime.block_on(async {
            tracing::info!(
                target: "jaunt::audit",
                event = "login.started",
                login_id = "after-the-failure"
            );
        });
        assert_eq!(tap.snapshot().dropped_after_close, 1);
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("flush-on-failure"), "{text}");
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
            .block_on(start(
                settings,
                authorities(dir.path()),
                &AuditTap::new(audit_clock()),
            ))
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

    fn started_with(extra: &str) -> (tempfile::TempDir, tokio::runtime::Runtime, super::Started) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("policy")).unwrap();
        let path = write_config(dir.path(), extra);
        let mut settings = config::load(&path)
            .unwrap()
            .into_run_settings(&secret_only)
            .unwrap();
        settings.oidc.issuer_url = fake_discovery();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let started = runtime
            .block_on(start(
                settings,
                authorities(dir.path()),
                &AuditTap::new(audit_clock()),
            ))
            .unwrap();
        (dir, runtime, started)
    }

    fn answers(extra: &str, path: &'static str, count: usize) -> Vec<String> {
        let (_dir, runtime, started) = started_with(extra);
        let answers = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(
                started
                    .control
                    .clone()
                    .serve(listener, std::future::pending()),
            );
            let fetched = tokio::task::spawn_blocking(move || {
                (0..count)
                    .map(|_| {
                        let mut stream = std::net::TcpStream::connect(address).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        write!(
                            stream,
                            "GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
                        )
                        .unwrap();
                        let mut answer = String::new();
                        stream.read_to_string(&mut answer).unwrap();
                        answer
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap();
            server.abort();
            fetched
        });
        started.watcher.stop();
        answers
    }

    fn client_config_answer(extra: &str) -> String {
        answers(extra, "/v1/client-config", 1).remove(0)
    }

    #[test]
    fn the_configured_http_limits_reach_the_running_server() {
        let answered = answers(
            "limits:\n  http:\n    other: { burst: 2, per_minute: 1 }\n",
            "/v1/client-config",
            3,
        );
        assert!(!answered[0].starts_with("HTTP/1.1 429"), "{}", answered[0]);
        assert!(!answered[1].starts_with("HTTP/1.1 429"), "{}", answered[1]);
        assert!(answered[2].starts_with("HTTP/1.1 429"), "{}", answered[2]);
        assert!(answered[2].contains("retry-after: 60"), "{}", answered[2]);
    }

    #[test]
    fn the_configured_agent_limits_reach_the_agents_listener() {
        let (_dir, runtime, started) = started_with(
            "agents_listen: 127.0.0.1:0\nlimits:\n  agents:\n    handshaking_per_address: 1\n",
        );
        assert_eq!(started.agent_limits.concurrent, 1);
        runtime.block_on(async {
            let agents = super::start_agents(
                started.agents.clone(),
                started.agent_limits,
                &started.control,
                started.store.clone(),
            )
            .await
            .unwrap()
            .unwrap();
            let address = agents.local_addr();
            let _first = tokio::net::TcpStream::connect(address).await.unwrap();
            let _second = tokio::net::TcpStream::connect(address).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while agents.stats().snapshot().refused_per_address != 1 {
                assert!(
                    Instant::now() < deadline,
                    "the second connection was not refused"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            agents.shutdown(Duration::from_secs(5)).await;
        });
        started.watcher.stop();
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
