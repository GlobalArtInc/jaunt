use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, AuthorizeResponse, DenyReason, SessionEnd,
    SessionEndOutcome,
};
use jaunt_ssh::{
    AgentLimits, AuthorityError, HostIdentity, InnerCa, InnerTarget, NoObserver, ServerConfigCell,
    ServerProfile, SessionAuthority, SshError, StreamContext, Terminator, UserCaKeys, UserCaSource,
    read_pinned_host_key,
};
use jaunt_tunnel::{BoxFuture, H2Io, IncomingStream, StreamHandler, StreamMeta};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

use crate::run::api::{AgentApi, ApiError};
use crate::state::{StateDir, StateError};

#[derive(Debug, thiserror::Error)]
pub enum InnerTargetError {
    #[error("inner.sshd_addr {0} is not a loopback address")]
    NotLoopback(SocketAddr),
    #[error(
        "inner.sshd_host_key {path} cannot be used ({source}); point it at the Ed25519 public host key of sshd"
    )]
    HostKey {
        path: PathBuf,
        #[source]
        source: SshError,
    },
}

pub fn check_inner_target(target: &InnerTarget) -> Result<(), InnerTargetError> {
    if !target.sshd_addr.ip().is_loopback() {
        return Err(InnerTargetError::NotLoopback(target.sshd_addr));
    }
    read_pinned_host_key(&target.sshd_host_key).map_err(|source| InnerTargetError::HostKey {
        path: target.sshd_host_key.clone(),
        source,
    })?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum HostIdentityError {
    #[error(transparent)]
    Read(#[from] StateError),
    #[error(transparent)]
    Invalid(#[from] SshError),
}

pub fn load_host_identity(
    state: &StateDir,
    now_unix: u64,
) -> Result<HostIdentity, HostIdentityError> {
    let files = state.read_ssh_host_files()?;
    Ok(HostIdentity::from_openssh(
        &files.private_key,
        &files.certificate,
        now_unix,
    )?)
}

pub struct ControlAuthority {
    api: Arc<AgentApi>,
}

impl ControlAuthority {
    pub fn new(api: Arc<AgentApi>) -> Self {
        Self { api }
    }
}

fn authority_error(error: &ApiError) -> AuthorityError {
    match error {
        ApiError::BadResponse | ApiError::BodyTooLarge | ApiError::Request => {
            AuthorityError::InvalidResponse
        }
        _ => AuthorityError::Unavailable,
    }
}

impl SessionAuthority for ControlAuthority {
    fn authorize<'a>(
        &'a self,
        request: AuthorizeRequest,
    ) -> BoxFuture<'a, Result<AuthorizeDecision, AuthorityError>> {
        Box::pin(async move {
            match self.api.authorize(&request).await {
                Ok(AuthorizeResponse::Allow { permissions }) => {
                    Ok(AuthorizeDecision::Allow { permissions })
                }
                Ok(AuthorizeResponse::Deny) => Ok(AuthorizeDecision::Deny {
                    reason: DenyReason::PolicyDenied,
                }),
                Err(error) => {
                    tracing::warn!(
                        target: "jaunt::agent",
                        event = "agent.ssh.authorize_failed",
                        session_id = request.session_id.as_str(),
                        error = %error,
                        "asking the control plane to authorize a session failed"
                    );
                    Err(authority_error(&error))
                }
            }
        })
    }

    fn session_end<'a>(&'a self, end: SessionEnd) -> BoxFuture<'a, Result<(), AuthorityError>> {
        Box::pin(async move {
            match self.api.session_end(&end).await {
                Ok(SessionEndOutcome::Recorded) => Ok(()),
                Ok(SessionEndOutcome::Rejected) => {
                    tracing::warn!(
                        target: "jaunt::audit",
                        event = "agent.ssh.session_end_rejected",
                        session_id = end.session_id.as_str(),
                        "the control plane did not accept the end of this session"
                    );
                    Ok(())
                }
                Err(error) => {
                    tracing::warn!(
                        target: "jaunt::agent",
                        event = "agent.ssh.session_end_failed",
                        session_id = end.session_id.as_str(),
                        error = %error,
                        "reporting the end of a session failed"
                    );
                    Err(authority_error(&error))
                }
            }
        })
    }
}

#[derive(Default)]
struct Parts {
    config: Option<Arc<ServerConfigCell>>,
    cas: Option<Arc<UserCaSource>>,
}

pub struct SshService {
    ready: OnceLock<Arc<Terminator>>,
    parts: Mutex<Parts>,
    inner_ca: Arc<InnerCa>,
    target: InnerTarget,
    authority: Arc<dyn SessionAuthority>,
    limits: AgentLimits,
    trust_changed: Arc<Notify>,
    refused: AtomicU64,
}

impl SshService {
    pub fn new(
        inner_ca: Arc<InnerCa>,
        target: InnerTarget,
        authority: Arc<dyn SessionAuthority>,
        limits: AgentLimits,
    ) -> Self {
        Self {
            ready: OnceLock::new(),
            parts: Mutex::new(Parts::default()),
            inner_ca,
            target,
            authority,
            limits,
            trust_changed: Arc::new(Notify::new()),
            refused: AtomicU64::new(0),
        }
    }

    pub fn trust_changed(&self) -> Arc<Notify> {
        Arc::clone(&self.trust_changed)
    }

    fn parts(&self) -> MutexGuard<'_, Parts> {
        self.parts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn install_trust(&self, keys: UserCaKeys) {
        let mut parts = self.parts();
        match &parts.cas {
            Some(cas) => cas.replace(keys),
            None => {
                parts.cas = Some(Arc::new(UserCaSource::new(keys)));
                self.complete(&parts);
            }
        }
    }

    pub fn install_host_identity(&self, identity: HostIdentity) {
        let mut parts = self.parts();
        match &parts.config {
            Some(config) => config.replace(identity),
            None => {
                parts.config = Some(Arc::new(ServerConfigCell::new(
                    identity,
                    ServerProfile::Agent,
                )));
                self.complete(&parts);
            }
        }
    }

    pub fn reload_host_identity(&self, state: &StateDir, now_unix: u64) {
        match load_host_identity(state, now_unix) {
            Ok(identity) => {
                self.install_host_identity(identity);
                tracing::info!(
                    target: "jaunt::agent",
                    "new SSH connections use the renewed host certificate"
                );
            }
            Err(error) => tracing::error!(
                target: "jaunt::agent",
                error = %error,
                "cannot load the renewed SSH host certificate; new SSH connections keep the previous one"
            ),
        }
    }

    #[cfg(test)]
    pub fn trust(&self) -> Option<Arc<UserCaKeys>> {
        self.parts().cas.as_ref().map(|cas| cas.current())
    }

    #[cfg(test)]
    pub fn server_config(&self) -> Option<Arc<russh::server::Config>> {
        self.parts().config.as_ref().map(|config| config.current())
    }

    fn complete(&self, parts: &Parts) {
        let (Some(config), Some(cas)) = (&parts.config, &parts.cas) else {
            return;
        };
        let terminator = Terminator::new(
            Arc::clone(config),
            Arc::clone(cas),
            Arc::clone(&self.inner_ca),
            self.target.clone(),
            Arc::clone(&self.authority),
            self.limits,
            Arc::new(NoObserver),
        );
        if self.ready.set(Arc::new(terminator)).is_ok() {
            tracing::info!(target: "jaunt::agent", "the agent now accepts SSH sessions");
        }
    }

    fn refuse(&self, meta: &StreamMeta, io: H2Io) -> BoxFuture<'static, ()> {
        let reason = {
            let parts = self.parts();
            if parts.cas.is_none() {
                "trust_not_loaded"
            } else {
                "host_certificate_not_loaded"
            }
        };
        let refused = self
            .refused
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        tracing::warn!(
            target: "jaunt::agent",
            event = "agent.ssh.refused",
            session_id = meta.session().as_str(),
            client = meta.client(),
            reason,
            refused_streams = refused,
            "refused a session stream: the agent is not ready to serve SSH yet"
        );
        let mut io = io;
        Box::pin(async move {
            if let Err(error) = io.shutdown().await {
                tracing::debug!(
                    target: "jaunt::agent",
                    error = %error,
                    "closing a refused stream failed"
                );
            }
        })
    }
}

impl StreamHandler for SshService {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        let IncomingStream { meta, io, cancel } = stream;
        let Some(terminator) = self.ready.get().cloned() else {
            return self.refuse(&meta, io);
        };
        let context = StreamContext {
            session_id: meta.session().as_str().to_owned(),
            client_addr: meta.client().to_owned(),
        };
        Box::pin(async move {
            let outcome = terminator.serve(io, context, cancel).await;
            tracing::debug!(
                target: "jaunt::agent",
                session = %meta.session(),
                reason = outcome.reason.as_str(),
                "a session stream ended"
            );
        })
    }

    fn trust_update(&self) {
        tracing::info!(target: "jaunt::agent", "the control plane announced a new user CA trust set");
        self.trust_changed.notify_one();
    }
}

#[cfg(test)]
mod tests;
