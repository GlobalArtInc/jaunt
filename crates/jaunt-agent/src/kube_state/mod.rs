pub mod args;
pub mod client;
pub mod mount;
pub mod persist;
pub mod secret;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use jaunt_tunnel::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use crate::enroll::args::{DEFAULT_TIMEOUT_SECS, ServerUrl, parse_hostname};
use crate::enroll::token::{self, JoinToken, MAX_FILE_BYTES};
use crate::enroll::{EnrollEnv, EnrollError, EnrollOptions, enroll};
use crate::fsio::effective_uid;
use crate::pin::CaPin;
use crate::run::{RunEnv, RunError, RunSettings, run};
use crate::state::{MAX_MIRRORED_FILE_BYTES, StateChanges, StateDir, StateError};
use crate::verify::{self, VerifyError};
use args::SelectError;
use client::{ApiError, ClusterSettings, SecretClient, SetupError};
use mount::MountError;
use persist::{Outcome, PersistTiming, Persister};
use secret::{KubernetesSecret, check_enrollment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    Local,
    Enrollment,
    Empty,
}

#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(
        "the state directory {dir} must belong to the agent's user (uid {uid}); point state_dir at a directory the agent creates itself, such as a subdirectory of the emptyDir mount"
    )]
    DirAccess { dir: String, uid: u32 },
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("the Secret is larger than 1 MiB")]
    TooLarge,
    #[error("the Secret holds the key {key}, which is not a file of the agent state")]
    UnknownEntry { key: String },
    #[error("the Secret key {key} is larger than {MAX_MIRRORED_FILE_BYTES} bytes")]
    EntryTooLarge { key: &'static str },
    #[error("the Secret key {key} is not valid base64")]
    Encoding { key: &'static str },
    #[error("it holds part of an enrollment: the file {missing} is missing")]
    Incomplete { missing: &'static str },
    #[error("its state.json is not a valid enrollment record")]
    Record,
    #[error("it does not hold a valid enrollment: {0}")]
    Invalid(#[source] StateError),
    #[error("its internal CA root does not match --ca-pin")]
    PinMismatch,
    #[error("the Secret holds a different enrollment than this agent")]
    Foreign,
    #[error("the Secret kept changing while the agent wrote it ({0} conflicts in a row)")]
    Conflicts(usize),
    #[error(
        "the state directory holds no complete enrollment to store: {missing} is missing or invalid"
    )]
    LocalIncomplete { missing: &'static str },
}

pub trait StateMirror: Send + Sync {
    fn restore<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<Restored, MirrorError>>;

    fn probe<'a>(&'a self) -> BoxFuture<'a, Result<(), MirrorError>>;

    fn persist<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<(), MirrorError>>;
}

pub struct NoMirror;

impl StateMirror for NoMirror {
    fn restore<'a>(&'a self, _dir: &'a Path) -> BoxFuture<'a, Result<Restored, MirrorError>> {
        Box::pin(async { Ok(Restored::Local) })
    }

    fn probe<'a>(&'a self) -> BoxFuture<'a, Result<(), MirrorError>> {
        Box::pin(async { Ok(()) })
    }

    fn persist<'a>(&'a self, _dir: &'a Path) -> BoxFuture<'a, Result<(), MirrorError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error(transparent)]
    Select(#[from] SelectError),
    #[error("cannot use the Kubernetes API: {0}")]
    Setup(#[source] SetupError),
    #[error("cannot restore the agent state from {from}: {source}; nothing in it was changed")]
    Restore {
        from: String,
        #[source]
        source: MirrorError,
    },
    #[error("the state mirror asked for an enrollment but no Kubernetes backend is configured")]
    NoBackend,
    #[error(
        "the Secret {secret} holds no enrollment and the state directory of this pod holds one that cannot be used: {source}; nothing was stored; delete the pod to start with an empty directory"
    )]
    Local {
        secret: String,
        #[source]
        source: MirrorError,
    },
    #[error(
        "the Secret {secret} holds no enrollment and the state directory of this pod holds one whose certificate does not match its key: {source}; nothing was stored; delete the pod to start with an empty directory"
    )]
    LocalIdentity {
        secret: String,
        #[source]
        source: VerifyError,
    },
    #[error(
        "the Secret {secret} holds no enrollment and there is no join token at {}; create a join token for the name {name} (with --allow-replace when this cluster was enrolled before) and mount it there",
        path.display()
    )]
    NoJoinToken {
        secret: String,
        name: String,
        path: PathBuf,
    },
    #[error("cannot use the join token: {0}")]
    JoinToken(#[source] MountError),
    #[error("{} does not hold a join token", path.display())]
    NotAToken { path: PathBuf },
    #[error(
        "the agent may not write the Secret {secret} ({source}); the join token was not used; give the service account update on this Secret"
    )]
    Probe {
        secret: String,
        #[source]
        source: MirrorError,
    },
    #[error("cannot determine the pod's hostname for the enrollment request")]
    Hostname,
    #[error(
        "the server refused the join token: it is unknown, expired, used up or revoked, it does not allow the name {name} or these labels, or the name is enrolled already and the token was not created with --allow-replace; create a new join token for {name}, with --allow-replace when this cluster was enrolled before"
    )]
    TokenRefused { name: String },
    #[error("the enrollment from the join token failed: {0}")]
    Enroll(#[source] EnrollError),
    #[error(
        "the agent was stopped before it had an enrollment; nothing was stored; if the join token was sent already, the server may count it as used"
    )]
    Interrupted,
    #[error(
        "the agent stopped before it could store its enrollment in the Secret {secret}: {source}; the enrollment stays in the state directory of this pod and is stored at the next start of the container"
    )]
    NotStored {
        secret: String,
        #[source]
        source: MirrorError,
    },
    #[error(
        "the Secret {secret} holds a different enrollment than this agent; it was not overwritten; run exactly one replica with the Recreate strategy"
    )]
    Foreign { secret: String },
    #[error("the task that stores the agent state in the Secret failed")]
    PersisterTask,
}

pub const TOKEN_ATTEMPTS: u32 = 10;
pub const TOKEN_RETRY_EVERY: Duration = Duration::from_secs(1);

pub struct EnrollPlan {
    pub server: ServerUrl,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub ca_pin: CaPin,
    pub token_file: PathBuf,
    pub token_attempts: u32,
    pub token_retry_every: Duration,
    pub hostname: Option<String>,
}

pub struct KubernetesBackend {
    pub cluster: ClusterSettings,
    pub enrollment: EnrollPlan,
    pub timing: PersistTiming,
}

pub enum StateBackend {
    File,
    Kubernetes(Box<KubernetesBackend>),
}

pub async fn serve(
    settings: RunSettings,
    env: RunEnv,
    shutdown: CancellationToken,
    backend: StateBackend,
) -> Result<(), RunError> {
    let StateBackend::Kubernetes(backend) = backend else {
        return serve_mirrored(settings, env, shutdown, Arc::new(NoMirror), None).await;
    };
    let client = SecretClient::new(&backend.cluster, env.clock.clone(), effective_uid())
        .map_err(ClusterError::Setup)?;
    let secret = client.secret().to_owned();
    let mirror = KubernetesSecret::new(
        client,
        settings.privileged,
        backend.enrollment.ca_pin.clone(),
        effective_uid(),
    );
    serve_mirrored(
        settings,
        env,
        shutdown,
        Arc::new(mirror),
        Some((*backend, secret)),
    )
    .await
}

async fn serve_mirrored(
    settings: RunSettings,
    mut env: RunEnv,
    shutdown: CancellationToken,
    mirror: Arc<dyn StateMirror>,
    backend: Option<(KubernetesBackend, String)>,
) -> Result<(), RunError> {
    let dir = settings.state_dir.clone();
    let from = backend.as_ref().map_or_else(
        || dir.display().to_string(),
        |(_, secret)| format!("the Secret {secret}"),
    );
    let restored = mirror
        .restore(&dir)
        .await
        .map_err(|source| ClusterError::Restore { from, source })?;
    let (backend, secret) = match (restored, backend) {
        (Restored::Local, _) => return run(settings, env, shutdown).await,
        (_, None) => return Err(ClusterError::NoBackend.into()),
        (_, Some(backend)) => backend,
    };
    if restored == Restored::Empty {
        let start = Start {
            settings: &settings,
            mirror: mirror.as_ref(),
            plan: &backend.enrollment,
            secret: &secret,
            shutdown: &shutdown,
        };
        obtain_enrollment(&start, &mut env).await?;
    }
    let mut persister = Persister::new(mirror, dir, env.clock.clone(), backend.timing);
    if restored == Restored::Empty {
        match persister.store(&shutdown).await {
            Outcome::Stored => {}
            Outcome::Foreign => return Err(ClusterError::Foreign { secret }.into()),
            Outcome::Stopped => {
                return match persister.last_attempt().await {
                    Ok(()) => Ok(()),
                    Err(MirrorError::Foreign) => Err(ClusterError::Foreign { secret }.into()),
                    Err(source) => Err(ClusterError::NotStored { secret, source }.into()),
                };
            }
        }
    }
    let (changes, receiver) = StateChanges::channel();
    let agent_stop = shutdown.child_token();
    let persist_stop = CancellationToken::new();
    let following =
        tokio::spawn(persister.follow(receiver, persist_stop.clone(), agent_stop.clone()));
    let settings = RunSettings {
        state_changes: Some(changes),
        ..settings
    };
    let outcome = run(settings, env, agent_stop).await;
    persist_stop.cancel();
    match following.await {
        Ok(Outcome::Foreign) => Err(ClusterError::Foreign { secret }.into()),
        Ok(Outcome::Stored | Outcome::Stopped) => outcome,
        Err(_) => outcome.and(Err(ClusterError::PersisterTask.into())),
    }
}

struct Start<'a> {
    settings: &'a RunSettings,
    mirror: &'a dyn StateMirror,
    plan: &'a EnrollPlan,
    secret: &'a str,
    shutdown: &'a CancellationToken,
}

async fn obtain_enrollment(start: &Start<'_>, env: &mut RunEnv) -> Result<(), RunError> {
    let Start {
        settings,
        mirror,
        plan,
        secret,
        shutdown,
    } = *start;
    let state = StateDir::open(&settings.state_dir, settings.privileged)?;
    if state.holds_enrollment()? {
        return adopt(&state, plan, secret);
    }
    drop(state);
    let token = wait_for_token(plan, secret, env.clock.as_ref(), shutdown).await?;
    mirror.probe().await.map_err(|source| ClusterError::Probe {
        secret: secret.to_owned(),
        source,
    })?;
    let hostname = match &plan.hostname {
        Some(hostname) => hostname.clone(),
        None => system_hostname()?,
    };
    let options = EnrollOptions {
        server: plan.server.clone(),
        name: plan.name.clone(),
        labels: plan.labels.clone(),
        replace: true,
        ca_pin: Some(plan.ca_pin.clone()),
        state_dir: settings.state_dir.clone(),
        hostname,
        timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        join_token: Some(token),
    };
    tracing::info!(
        target: "jaunt::agent",
        secret,
        name = %plan.name,
        "the Secret holds no enrollment; enrolling with the join token"
    );
    let mut out = TraceLines::default();
    let mut err = TraceLines::default();
    let enrolled = {
        let mut enroll_env = EnrollEnv {
            privileged: settings.privileged,
            clock: env.clock.as_ref(),
            jitter: &mut *env.jitter,
            out: &mut out,
            err: &mut err,
        };
        tokio::select! {
            biased;
            () = shutdown.cancelled() => None,
            result = enroll(&options, &mut enroll_env) => Some(result),
        }
    };
    drop(options);
    out.finish();
    err.finish();
    match enrolled {
        None => Err(ClusterError::Interrupted.into()),
        Some(Ok(())) => Ok(()),
        Some(Err(EnrollError::TokenRefused)) => Err(ClusterError::TokenRefused {
            name: plan.name.clone(),
        }
        .into()),
        Some(Err(error)) => Err(ClusterError::Enroll(error).into()),
    }
}

fn adopt(state: &StateDir, plan: &EnrollPlan, secret: &str) -> Result<(), RunError> {
    let local = |source| ClusterError::Local {
        secret: secret.to_owned(),
        source,
    };
    let files = state
        .read_mirrored()
        .map_err(|error| local(MirrorError::State(error)))?;
    check_enrollment(&files, "the state directory", &plan.ca_pin).map_err(local)?;
    let loaded = state
        .load()
        .map_err(|error| local(MirrorError::Invalid(error)))?;
    verify::node_identity(
        &loaded.x509_der,
        &loaded.record.node_id,
        loaded.tls_key.spki_der(),
    )
    .map_err(|source| ClusterError::LocalIdentity {
        secret: secret.to_owned(),
        source,
    })?;
    tracing::warn!(
        target: "jaunt::agent",
        secret,
        "the Secret holds no enrollment but the state directory holds one from an earlier start of this pod; it is stored in the Secret instead of enrolling again"
    );
    Ok(())
}

async fn wait_for_token(
    plan: &EnrollPlan,
    secret: &str,
    clock: &dyn Clock,
    shutdown: &CancellationToken,
) -> Result<JoinToken, ClusterError> {
    let limit = u64::try_from(MAX_FILE_BYTES).unwrap_or(u64::MAX);
    let mut attempt = 1;
    loop {
        let path = match mount::read_mounted(&plan.token_file, limit, effective_uid()) {
            Ok((content, _)) => {
                return token::parse_token(&content).ok_or_else(|| ClusterError::NotAToken {
                    path: plan.token_file.clone(),
                });
            }
            Err(MountError::Missing { path }) => path,
            Err(error) => return Err(ClusterError::JoinToken(error)),
        };
        if attempt >= plan.token_attempts {
            return Err(ClusterError::NoJoinToken {
                secret: secret.to_owned(),
                name: plan.name.clone(),
                path,
            });
        }
        tracing::warn!(
            target: "jaunt::agent",
            path = %path.display(),
            attempt,
            "the join token file is being replaced or is not there yet; retrying"
        );
        attempt += 1;
        let now = clock.now();
        let wake = now.checked_add(plan.token_retry_every).unwrap_or(now);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Err(ClusterError::Interrupted),
            () = clock.sleep_until(wake) => {}
        }
    }
}

fn system_hostname() -> Result<String, ClusterError> {
    let raw = hostname::get().map_err(|_| ClusterError::Hostname)?;
    let text = raw.into_string().map_err(|_| ClusterError::Hostname)?;
    parse_hostname(&text).map_err(|_| ClusterError::Hostname)
}

#[derive(Default)]
struct TraceLines(Vec<u8>);

impl TraceLines {
    fn emit(&mut self, upto: usize) {
        let line: Vec<u8> = self.0.drain(..upto).collect();
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end();
        if !text.is_empty() {
            tracing::info!(target: "jaunt::agent", "{text}");
        }
    }

    fn finish(&mut self) {
        let all = self.0.len();
        self.emit(all);
    }
}

impl io::Write for TraceLines {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        while let Some(end) = self.0.iter().position(|byte| *byte == b'\n') {
            self.emit(end + 1);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
