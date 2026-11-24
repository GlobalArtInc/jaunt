use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jaunt_control::{Control, ControlError, ControlParts, PENDING_CAPACITY, system_clock};
use jaunt_oidc::{OidcClient, OidcError};
use jaunt_store::{Store, StoreError};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

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

async fn serve(settings: RunSettings, authorities: Authorities) -> Result<(), ServeError> {
    let mut terminate = signal(SignalKind::terminate()).map_err(ServeError::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(ServeError::Signals)?;

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
    let control = Control::new(ControlParts {
        store,
        oidc,
        user_authority: Arc::new(authorities.user),
        host_trust: authorities.host_trust,
        host_authority: Arc::new(authorities.host),
        internal_ca: authorities.internal,
        ssh_suffix: settings.ssh_suffix,
        agent_endpoint: settings.agent_endpoint,
        cert_ttl: settings.cert_ttl,
        pending_capacity: PENDING_CAPACITY,
        device: settings.device,
        policy: policy.clone(),
        clock: system_clock(),
    })?;

    let listen = settings.listen;
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

    let watcher = policy::start_watcher(policy, settings.policy_dir, settings.policy_poll);
    control
        .serve(listener, async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            tracing::info!(target: "jaunt::daemon", "shutting down");
            policy::stop_watcher(watcher).await;
        })
        .await?;
    Ok(())
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
    use std::sync::Arc;
    use std::time::SystemTime;

    use jaunt_ca::{AgeIdentity, CaKind, FileBackend, InternalCa};

    use super::{ServeError, run, serve};
    use crate::ca::Authorities;
    use crate::config;
    use crate::policy::PolicyError;

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
        let (_, user) = FileBackend::load(&root, CaKind::User, &identity).unwrap();
        let (host_trust, host) = FileBackend::load(&root, CaKind::Host, &identity).unwrap();
        let (_, internal) = FileBackend::load(&root, CaKind::Internal, &identity).unwrap();
        let certificate = InternalCa::create_root(&internal, SystemTime::now()).unwrap();
        Authorities {
            user,
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
}
