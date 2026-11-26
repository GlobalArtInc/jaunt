use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, BoxFuture, SessionEnd, SessionPermissions,
    is_portable_login,
};
use russh::keys::Certificate;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, Disconnect, Pty, Sig, client};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tokio_util::task::TaskTracker;

use crate::bridge::{
    BridgeContext, InnerOpen, LiveChannels, SessionBridge, StartReply, Traffic, Verdict,
    audit_forward,
};
use crate::cert::{CertRejection, UserCaSource, UserIdentity, verify_user_certificate};
use crate::config::ServerConfigCell;
use crate::forward::{ForwardBridge, ForwardOpen, Originator, loopback_destination};
use crate::inner::{self, InnerClient, InnerSession, InnerTarget};
use crate::inner_ca::{InnerCa, InnerCertRequest};
use crate::intake::IntakeError;
use crate::observer::{
    ChannelProgram, ObserverCell, ObserverFactory, Recording, SessionInfo, Terminal, TerminalSize,
};
use crate::outer::TunnelStream;

const GRACE: Duration = Duration::from_secs(1);
const TASK_DRAIN: Duration = Duration::from_secs(5);
const MAX_LOGGED_LOGIN: usize = 64;
const STDERR: u32 = 1;
const SFTP: &str = "sftp";
const TIME_LIMIT_TEXT: &str = "jaunt: session time limit reached";
const TIME_LIMIT_LINE: &[u8] = b"jaunt: session time limit reached\r\n";
const NODE_CLOSED_TEXT: &str = "jaunt: the node closed the session";
const FORWARDING_REFUSED: &str = "jaunt: port forwarding is not allowed by your roles";
const LOOPBACK_ONLY: &str = "jaunt: forwarding is limited to localhost on the node";
const TOO_MANY_FORWARDS: &str = "jaunt: too many open sessions";

type RefusalHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("the control plane cannot be reached")]
    Unavailable,
    #[error("the control plane sent an unexpected response")]
    InvalidResponse,
}

pub trait SessionAuthority: Send + Sync + 'static {
    fn authorize<'a>(
        &'a self,
        request: AuthorizeRequest,
    ) -> BoxFuture<'a, Result<AuthorizeDecision, AuthorityError>>;

    fn session_end<'a>(&'a self, end: SessionEnd) -> BoxFuture<'a, Result<(), AuthorityError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamContext {
    pub session_id: String,
    pub client_addr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentLimits {
    pub max_sessions: usize,
    pub max_forwards: usize,
    pub max_env: usize,
    pub reply_timeout: Duration,
    pub authorize_timeout: Duration,
    pub inner_login_timeout: Duration,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_sessions: 10,
            max_forwards: 32,
            max_env: 16,
            reply_timeout: Duration::from_secs(30),
            authorize_timeout: Duration::from_secs(10),
            inner_login_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    ClientClosed,
    TransportFailed,
    Unauthenticated,
    Denied,
    LoginTimeout,
    InnerLoginFailed,
    NodeClosed,
    TimeLimit,
    ProtocolViolation,
    ObserverFailed,
    Cancelled,
    Abandoned,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::TransportFailed => "transport_failed",
            Self::Unauthenticated => "unauthenticated",
            Self::Denied => "denied",
            Self::LoginTimeout => "login_timeout",
            Self::InnerLoginFailed => "inner_login_failed",
            Self::NodeClosed => "node_closed",
            Self::TimeLimit => "time_limit",
            Self::ProtocolViolation => "protocol_violation",
            Self::ObserverFailed => "observer_failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOutcome {
    pub authorized: bool,
    pub exit_status: Option<i32>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub reason: EndReason,
}

pub struct Terminator {
    config: Arc<ServerConfigCell>,
    cas: Arc<UserCaSource>,
    inner_ca: Arc<InnerCa>,
    target: Arc<InnerTarget>,
    authority: Arc<dyn SessionAuthority>,
    limits: AgentLimits,
    observers: Arc<dyn ObserverFactory>,
    inner_config: Arc<client::Config>,
    untrusted_ca: Option<RefusalHook>,
}

impl Terminator {
    pub fn new(
        config: Arc<ServerConfigCell>,
        cas: Arc<UserCaSource>,
        inner_ca: Arc<InnerCa>,
        target: InnerTarget,
        authority: Arc<dyn SessionAuthority>,
        limits: AgentLimits,
        observers: Arc<dyn ObserverFactory>,
    ) -> Self {
        Self {
            config,
            cas,
            inner_ca,
            target: Arc::new(target),
            authority,
            limits,
            observers,
            inner_config: Arc::new(inner::client_config()),
            untrusted_ca: None,
        }
    }

    pub fn on_untrusted_ca(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.untrusted_ca = Some(Arc::new(hook));
        self
    }

    pub async fn serve<S: TunnelStream>(
        &self,
        stream: S,
        context: StreamContext,
        cancel: CancellationToken,
    ) -> SessionOutcome {
        let shared = Arc::new(Shared::new(context));
        let report = EndReport {
            shared: Arc::clone(&shared),
            authority: Arc::clone(&self.authority),
            timeout: self.limits.authorize_timeout,
            finished: false,
        };
        shared
            .tracker
            .spawn(cut_after_stop(shared.stop.clone(), shared.cut.clone()));
        shared
            .tracker
            .spawn(stop_on_cancel(Arc::clone(&shared), cancel));
        shared.tracker.spawn(login_deadline(
            Arc::clone(&shared),
            self.config.profile().auth_deadline(),
        ));
        let config = self.config.current();
        let handler = Gatekeeper {
            bridge: BridgeContext {
                session_id: Arc::from(shared.session_id.as_str()),
                tracker: shared.tracker.clone(),
                stop: shared.stop.clone(),
                traffic: Arc::clone(&shared.traffic),
                observer: Arc::clone(&shared.observer),
                live: Arc::clone(&shared.live),
            },
            shared: Arc::clone(&shared),
            cas: Arc::clone(&self.cas),
            inner_ca: Arc::clone(&self.inner_ca),
            target: Arc::clone(&self.target),
            authority: Arc::clone(&self.authority),
            observers: Arc::clone(&self.observers),
            inner_config: Arc::clone(&self.inner_config),
            untrusted_ca: self.untrusted_ca.clone(),
            limits: self.limits,
            window: config.window_size,
            attempted: false,
            login: None,
            bridges: HashMap::new(),
            forwards: HashMap::new(),
        };
        let stream = Guarded::new(stream, &shared.cut);
        let ended = match server::run_stream(config, stream, handler).await {
            Ok(running) => running.await,
            Err(error) => Err(error),
        };
        shared.settle(&ended);
        report.finish().await
    }
}

struct Shared {
    session_id: String,
    client_addr: String,
    started: Instant,
    stop: CancellationToken,
    cut: CancellationToken,
    logged_in: CancellationToken,
    tracker: TaskTracker,
    traffic: Arc<Traffic>,
    observer: Arc<ObserverCell>,
    live: Arc<LiveChannels>,
    authorized: AtomicBool,
    inner_gone: OnceLock<CancellationToken>,
    reason: OnceLock<EndReason>,
}

impl Shared {
    fn new(context: StreamContext) -> Self {
        let stop = CancellationToken::new();
        Self {
            session_id: context.session_id,
            client_addr: context.client_addr,
            started: Instant::now(),
            observer: Arc::new(ObserverCell::new(stop.clone())),
            stop,
            cut: CancellationToken::new(),
            logged_in: CancellationToken::new(),
            tracker: TaskTracker::new(),
            traffic: Arc::new(Traffic::default()),
            live: Arc::new(LiveChannels::default()),
            authorized: AtomicBool::new(false),
            inner_gone: OnceLock::new(),
            reason: OnceLock::new(),
        }
    }

    fn end_with(&self, reason: EndReason) {
        self.reason.get_or_init(|| reason);
    }

    fn authorized(&self) -> bool {
        self.authorized.load(Ordering::Acquire)
    }

    fn settle(&self, ended: &Result<(), russh::Error>) {
        if self.observer.failed() {
            self.end_with(EndReason::ObserverFailed);
        }
        if !self.logged_in.is_cancelled() {
            self.end_with(EndReason::Unauthenticated);
        }
        self.end_with(match ended {
            Ok(()) => EndReason::ClientClosed,
            Err(russh::Error::IO(_)) => EndReason::TransportFailed,
            Err(_) => EndReason::ProtocolViolation,
        });
    }

    async fn bounded<F: Future>(&self, limit: Duration, work: F) -> Bounded<F::Output> {
        match self
            .stop
            .run_until_cancelled(tokio::time::timeout(limit, work))
            .await
        {
            Some(Ok(output)) => Bounded::Done(output),
            Some(Err(_)) => Bounded::TimedOut,
            None => Bounded::Stopped,
        }
    }

    fn conclude(&self) -> (SessionOutcome, Option<SessionEnd>) {
        let reason = *self.reason.get_or_init(|| EndReason::Abandoned);
        let recording = self.observer.finish();
        let outcome = SessionOutcome {
            authorized: self.authorized(),
            exit_status: self.traffic.exit_status(),
            bytes_in: self.traffic.bytes_in(),
            bytes_out: self.traffic.bytes_out(),
            reason,
        };
        tracing::info!(
            target: "jaunt::audit",
            event = "agent.ssh.end",
            session_id = self.session_id.as_str(),
            authorized = outcome.authorized,
            exit_status = outcome.exit_status,
            bytes_in = outcome.bytes_in,
            bytes_out = outcome.bytes_out,
            duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            reason = reason.as_str()
        );
        let end = outcome.authorized.then(|| SessionEnd {
            session_id: self.session_id.clone(),
            exit_status: outcome.exit_status,
            bytes_in: outcome.bytes_in,
            bytes_out: outcome.bytes_out,
            recording_incomplete: recording == Recording::Incomplete,
        });
        (outcome, end)
    }
}

enum Bounded<T> {
    Done(T),
    TimedOut,
    Stopped,
}

struct EndReport {
    shared: Arc<Shared>,
    authority: Arc<dyn SessionAuthority>,
    timeout: Duration,
    finished: bool,
}

impl EndReport {
    async fn finish(mut self) -> SessionOutcome {
        let shared = Arc::clone(&self.shared);
        shared.stop.cancel();
        shared.cut.cancel();
        shared.tracker.close();
        if tokio::time::timeout(TASK_DRAIN, shared.tracker.wait())
            .await
            .is_err()
        {
            tracing::error!(
                target: "jaunt::agent",
                event = "agent.ssh.tasks_lingering",
                session_id = shared.session_id.as_str(),
                tasks = shared.tracker.len()
            );
        }
        if let Some(gone) = shared.inner_gone.get()
            && tokio::time::timeout(TASK_DRAIN, gone.cancelled())
                .await
                .is_err()
        {
            tracing::error!(
                target: "jaunt::agent",
                event = "agent.ssh.inner_lingering",
                session_id = shared.session_id.as_str()
            );
        }
        self.finished = true;
        let (outcome, end) = shared.conclude();
        if let Some(end) = end {
            let delivery =
                tokio::spawn(deliver_end(Arc::clone(&self.authority), end, self.timeout));
            if delivery.await.is_err() {
                tracing::error!(
                    target: "jaunt::audit",
                    event = "agent.ssh.session_end_lost",
                    session_id = shared.session_id.as_str()
                );
            }
        }
        outcome
    }
}

impl Drop for EndReport {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.shared.stop.cancel();
        self.shared.cut.cancel();
        self.shared.tracker.close();
        let (_, end) = self.shared.conclude();
        let Some(end) = end else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let authority = Arc::clone(&self.authority);
                let timeout = self.timeout;
                runtime.spawn(deliver_end(authority, end, timeout));
            }
            Err(_) => tracing::error!(
                target: "jaunt::audit",
                event = "agent.ssh.session_end_lost",
                session_id = self.shared.session_id.as_str()
            ),
        }
    }
}

async fn deliver_end(authority: Arc<dyn SessionAuthority>, end: SessionEnd, timeout: Duration) {
    let session_id = end.session_id.clone();
    let error = match tokio::time::timeout(timeout, authority.session_end(end)).await {
        Ok(Ok(())) => return,
        Ok(Err(error)) => error.to_string(),
        Err(_) => "timeout".to_owned(),
    };
    tracing::warn!(
        target: "jaunt::audit",
        event = "agent.ssh.session_end_failed",
        session_id,
        error
    );
}

async fn cut_after_stop(stop: CancellationToken, cut: CancellationToken) {
    if cut.run_until_cancelled(stop.cancelled()).await.is_none() {
        return;
    }
    if cut
        .run_until_cancelled(tokio::time::sleep(GRACE))
        .await
        .is_some()
    {
        cut.cancel();
    }
}

async fn stop_on_cancel(shared: Arc<Shared>, cancel: CancellationToken) {
    tokio::select! {
        biased;
        () = shared.stop.cancelled() => {}
        () = cancel.cancelled() => {
            shared.end_with(EndReason::Cancelled);
            shared.stop.cancel();
        }
    }
}

async fn login_deadline(shared: Arc<Shared>, deadline: Duration) {
    tokio::select! {
        biased;
        () = shared.logged_in.cancelled() => {}
        () = shared.stop.cancelled() => {}
        () = tokio::time::sleep(deadline) => {
            shared.end_with(EndReason::LoginTimeout);
            shared.stop.cancel();
            shared.cut.cancel();
        }
    }
}

async fn supervise(
    shared: Arc<Shared>,
    server: server::Handle,
    inner_gone: CancellationToken,
    limit: Duration,
) {
    let text = tokio::select! {
        biased;
        () = shared.stop.cancelled() => return,
        () = inner_gone.cancelled() => {
            shared.end_with(EndReason::NodeClosed);
            NODE_CLOSED_TEXT
        }
        () = tokio::time::sleep(limit) => {
            shared.end_with(EndReason::TimeLimit);
            for id in shared.live.snapshot() {
                let line = server.extended_data(id, STDERR, Bytes::from_static(TIME_LIMIT_LINE));
                if !matches!(tokio::time::timeout(GRACE, line).await, Ok(Ok(()))) {
                    break;
                }
            }
            TIME_LIMIT_TEXT
        }
    };
    shared.stop.cancel();
    let disconnect = server.disconnect(Disconnect::ByApplication, text.to_owned(), String::new());
    if !matches!(tokio::time::timeout(GRACE, disconnect).await, Ok(Ok(()))) {
        tracing::debug!(
            target: "jaunt::agent",
            event = "agent.ssh.disconnect_lost",
            session_id = shared.session_id.as_str()
        );
    }
}

struct Login {
    inner: Arc<client::Handle<InnerClient>>,
    gone: CancellationToken,
    permissions: SessionPermissions,
}

struct Gatekeeper {
    shared: Arc<Shared>,
    bridge: BridgeContext,
    cas: Arc<UserCaSource>,
    inner_ca: Arc<InnerCa>,
    target: Arc<InnerTarget>,
    authority: Arc<dyn SessionAuthority>,
    observers: Arc<dyn ObserverFactory>,
    inner_config: Arc<client::Config>,
    untrusted_ca: Option<RefusalHook>,
    limits: AgentLimits,
    window: u32,
    attempted: bool,
    login: Option<Login>,
    bridges: HashMap<ChannelId, SessionBridge>,
    forwards: HashMap<ChannelId, ForwardBridge>,
}

impl Drop for Gatekeeper {
    fn drop(&mut self) {
        self.shared.stop.cancel();
    }
}

impl Gatekeeper {
    async fn authorize(
        &self,
        identity: &UserIdentity,
        login: &str,
    ) -> Result<SessionPermissions, &'static str> {
        let request = AuthorizeRequest {
            session_id: self.shared.session_id.clone(),
            user_id: identity.user_id.clone(),
            serial: identity.serial,
            key_id: identity.key_id.clone(),
            login: login.to_owned(),
            client_addr: self.shared.client_addr.clone(),
            subject_fingerprint: Some(identity.subject_fingerprint.clone()),
        };
        match self
            .shared
            .bounded(
                self.limits.authorize_timeout,
                self.authority.authorize(request),
            )
            .await
        {
            Bounded::Done(Ok(AuthorizeDecision::Allow { permissions })) => Ok(permissions),
            Bounded::Done(Ok(AuthorizeDecision::Deny { reason })) => Err(reason.code()),
            Bounded::Done(Err(_)) => Err("authority_error"),
            Bounded::TimedOut => Err("authorize_timeout"),
            Bounded::Stopped => Err("stopped"),
        }
    }

    async fn inner_login(
        &self,
        identity: &UserIdentity,
        login: &str,
        permissions: &SessionPermissions,
    ) -> Result<InnerSession, &'static str> {
        let request = InnerCertRequest {
            login: login.to_owned(),
            session_id: self.shared.session_id.clone(),
            email: identity.email.clone(),
            pty: permissions.pty,
            port_forwarding: permissions.port_forwarding,
        };
        let started = Instant::now();
        let attempt = inner::login(
            Arc::clone(&self.inner_config),
            &self.target,
            &self.inner_ca,
            &request,
            unix_now(),
        );
        let result = match self
            .shared
            .bounded(self.limits.inner_login_timeout, attempt)
            .await
        {
            Bounded::Done(Ok(session)) => Ok(session),
            Bounded::Done(Err(error)) => Err(error.reason()),
            Bounded::TimedOut => Err("timeout"),
            Bounded::Stopped => Err("stopped"),
        };
        tracing::info!(
            target: "jaunt::audit",
            event = "agent.ssh.inner_login",
            session_id = self.shared.session_id.as_str(),
            outcome = if result.is_ok() { "ok" } else { "failed" },
            reason = result.as_ref().err().copied(),
            login = ?shown_login(login),
            latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
        );
        result
    }

    fn refuse(&self, reason: &str, identity: Option<&UserIdentity>, login: &str) -> Auth {
        audit_auth(&self.shared, "denied", reason, identity, login);
        Auth::reject()
    }

    fn violation(&self, error: IntakeError) -> russh::Error {
        if error != IntakeError::SessionGone {
            self.shared.end_with(EndReason::ProtocolViolation);
            tracing::warn!(
                target: "jaunt::audit",
                event = "agent.ssh.protocol_violation",
                session_id = self.shared.session_id.as_str(),
                error = %error
            );
        }
        russh::Error::Inconsistent
    }

    async fn start(
        &mut self,
        channel: ChannelId,
        program: ChannelProgram,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let kind = program_kind(&program);
        let reply = match self.bridges.get_mut(&channel) {
            Some(bridge) => bridge.start(program, self.limits.reply_timeout).await,
            None => StartReply::Refused,
        };
        let outcome = match reply {
            StartReply::Refused => "refused",
            StartReply::TimedOut => "reply_timeout",
            StartReply::Started | StartReply::StartedWithNotice(_) => "started",
        };
        audit_channel(&self.shared, kind, outcome);
        match reply {
            StartReply::Refused => session.channel_failure(channel),
            StartReply::TimedOut => abandon(session, channel),
            StartReply::Started => session.channel_success(channel),
            StartReply::StartedWithNotice(notice) => {
                session.channel_success(channel)?;
                session.extended_data(channel, STDERR, Bytes::from_static(notice))
            }
        }
    }
}

async fn refuse_forward(reply: ChannelOpenHandle, code: u32, reason: &str) {
    reply
        .reject(ChannelOpenFailure::Other {
            code,
            reason: reason.to_owned(),
        })
        .await;
}

fn abandon(session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
    session.channel_failure(channel)?;
    session.close(channel)
}

fn answer(session: &mut Session, channel: ChannelId, granted: bool) -> Result<(), russh::Error> {
    if granted {
        session.channel_success(channel)
    } else {
        session.channel_failure(channel)
    }
}

impl server::Handler for Gatekeeper {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        login: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.refuse("plain_key", None, login))
    }

    async fn auth_openssh_certificate(
        &mut self,
        login: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        if self.attempted {
            return Ok(self.refuse("attempt_used", None, login));
        }
        let identity = match verify_user_certificate(certificate, &self.cas.current(), unix_now()) {
            Ok(identity) => identity,
            Err(rejection) => {
                if rejection == CertRejection::UntrustedCa
                    && let Some(hook) = &self.untrusted_ca
                {
                    hook();
                }
                return Ok(self.refuse(rejection.reason(), None, login));
            }
        };
        if !is_portable_login(login) {
            return Ok(self.refuse("login", Some(&identity), login));
        }
        self.attempted = true;
        let permissions = match self.authorize(&identity, login).await {
            Ok(permissions) => permissions,
            Err(reason) => {
                self.shared.end_with(EndReason::Denied);
                return Ok(self.refuse(reason, Some(&identity), login));
            }
        };
        self.shared.authorized.store(true, Ordering::Release);
        let inner = match self.inner_login(&identity, login, &permissions).await {
            Ok(inner) => inner,
            Err(reason) => {
                self.shared.end_with(EndReason::InnerLoginFailed);
                return Ok(self.refuse(reason, Some(&identity), login));
            }
        };
        let session = SessionInfo {
            session_id: self.shared.session_id.clone(),
            user_id: identity.user_id.clone(),
            login: login.to_owned(),
            client_addr: self.shared.client_addr.clone(),
        };
        if self
            .shared
            .observer
            .create(self.observers.as_ref(), &session, &permissions)
            .is_err()
        {
            self.shared.end_with(EndReason::ObserverFailed);
            return Ok(self.refuse("observer", Some(&identity), login));
        }
        self.shared.inner_gone.get_or_init(|| inner.gone.clone());
        self.login = Some(Login {
            inner: Arc::new(inner.handle),
            gone: inner.gone,
            permissions,
        });
        self.shared.logged_in.cancel();
        audit_auth(&self.shared, "ok", "allowed", Some(&identity), login);
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if let Some(login) = &self.login {
            let limit = Duration::from_secs(login.permissions.max_duration_secs);
            self.shared.tracker.spawn(supervise(
                Arc::clone(&self.shared),
                session.handle(),
                login.gone.clone(),
                limit,
            ));
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(login) = &self.login else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        self.bridges.retain(|_, bridge| !bridge.finished());
        if self.bridges.len() >= self.limits.max_sessions {
            audit_channel(&self.shared, "session", "limit");
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }
        let inner = InnerOpen {
            handle: Arc::clone(&login.inner),
            deadline: self.limits.inner_login_timeout,
        };
        let id = channel.id();
        let bridge = SessionBridge::open(
            channel,
            reply,
            inner,
            session.handle(),
            self.window,
            &self.bridge,
        );
        self.bridges.insert(id, bridge);
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(login) = &self.login else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let session_id = self.shared.session_id.as_str();
        if !login.permissions.port_forwarding {
            audit_forward(session_id, port_to_connect, "refused");
            refuse_forward(reply, 1, FORWARDING_REFUSED).await;
            return Ok(());
        }
        let Some(target) = loopback_destination(host_to_connect, port_to_connect) else {
            audit_forward(session_id, port_to_connect, "bad_target");
            refuse_forward(reply, 1, LOOPBACK_ONLY).await;
            return Ok(());
        };
        self.forwards.retain(|_, forward| !forward.finished());
        if self.forwards.len() >= self.limits.max_forwards {
            audit_forward(session_id, port_to_connect, "limit");
            refuse_forward(reply, 4, TOO_MANY_FORWARDS).await;
            return Ok(());
        }
        let open = ForwardOpen {
            inner: InnerOpen {
                handle: Arc::clone(&login.inner),
                deadline: self.limits.inner_login_timeout,
            },
            target,
            originator: Originator::of_client(&self.shared.client_addr),
        };
        let id = channel.id();
        let forward = ForwardBridge::open(
            channel,
            reply,
            open,
            session.handle(),
            self.window,
            &self.bridge,
        );
        self.forwards.insert(id, forward);
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        audit_channel(&self.shared, "forwarded-tcpip", "refused");
        refuse_forward(reply, 1, LOOPBACK_ONLY).await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        audit_channel(&self.shared, "direct-streamlocal", "refused");
        refuse_forward(reply, 1, LOOPBACK_ONLY).await;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        audit_channel(&self.shared, "tcpip-forward", "refused");
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        audit_channel(&self.shared, "streamlocal-forward", "refused");
        Ok(false)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let permitted = self
            .login
            .as_ref()
            .is_some_and(|login| login.permissions.pty);
        let terminal = Terminal {
            term: term.to_owned(),
            size: TerminalSize {
                columns: col_width,
                rows: row_height,
                pixel_width: pix_width,
                pixel_height: pix_height,
            },
        };
        let verdict = match self.bridges.get_mut(&channel) {
            Some(bridge) => {
                bridge
                    .request_pty(
                        permitted,
                        terminal,
                        modes.to_vec(),
                        self.limits.reply_timeout,
                    )
                    .await
            }
            None => Verdict::Refused,
        };
        let outcome = match verdict {
            Verdict::Granted => "granted",
            Verdict::Refused => "refused",
            Verdict::TimedOut => "reply_timeout",
        };
        audit_channel(&self.shared, "pty", outcome);
        match verdict {
            Verdict::TimedOut => abandon(session, channel),
            other => answer(session, channel, other == Verdict::Granted),
        }
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let max_env = self.limits.max_env;
        let accepted = self
            .bridges
            .get_mut(&channel)
            .is_some_and(|bridge| bridge.env(variable_name, variable_value, max_env));
        answer(session, channel, accepted)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, ChannelProgram::Shell, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, ChannelProgram::Exec(data.to_vec()), session)
            .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != SFTP {
            audit_channel(&self.shared, "subsystem", "refused");
            return session.channel_failure(channel);
        }
        self.start(channel, ChannelProgram::Subsystem(name.to_owned()), session)
            .await
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        audit_channel(&self.shared, "x11", "refused");
        session.channel_failure(channel)
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        audit_channel(&self.shared, "auth-agent", "refused");
        Ok(false)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(bridge) = self.bridges.get(&channel) {
            bridge.resize(TerminalSize {
                columns: col_width,
                rows: row_height,
                pixel_width: pix_width,
                pixel_height: pix_height,
            });
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let forwarded = self
            .bridges
            .get(&channel)
            .is_some_and(|bridge| bridge.signal(signal));
        if !forwarded {
            tracing::debug!(
                target: "jaunt::agent",
                event = "agent.ssh.signal_dropped",
                session_id = self.shared.session_id.as_str()
            );
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let pushed = match (self.bridges.get(&channel), self.forwards.get(&channel)) {
            (Some(bridge), _) => bridge.data(data),
            (None, Some(forward)) => forward.data(data),
            (None, None) => Ok(()),
        };
        pushed.map_err(|error| self.violation(error))
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        _code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let consumed = match (self.bridges.get(&channel), self.forwards.get(&channel)) {
            (Some(bridge), _) => bridge.extended_data(data.len()),
            (None, Some(forward)) => forward.extended_data(data.len()),
            (None, None) => Ok(()),
        };
        consumed.map_err(|error| self.violation(error))
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(bridge) = self.bridges.get(&channel) {
            bridge.eof();
        } else if let Some(forward) = self.forwards.get(&channel) {
            forward.eof();
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(bridge) = self.bridges.remove(&channel) {
            bridge.close();
        } else if let Some(forward) = self.forwards.remove(&channel) {
            forward.close();
        }
        Ok(())
    }
}

fn program_kind(program: &ChannelProgram) -> &'static str {
    match program {
        ChannelProgram::Shell => "shell",
        ChannelProgram::Exec(_) => "exec",
        ChannelProgram::Subsystem(_) => "subsystem",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn shown_login(login: &str) -> String {
    login.chars().take(MAX_LOGGED_LOGIN).collect()
}

fn audit_auth(
    shared: &Shared,
    outcome: &str,
    reason: &str,
    identity: Option<&UserIdentity>,
    login: &str,
) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.ssh.auth",
        outcome,
        reason,
        session_id = shared.session_id.as_str(),
        user_id = identity.map(|identity| identity.user_id.as_str()),
        serial = identity.map(|identity| identity.serial),
        login = ?shown_login(login)
    );
}

fn audit_channel(shared: &Shared, kind: &str, outcome: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.ssh.channel",
        session_id = shared.session_id.as_str(),
        kind,
        outcome
    );
}

struct Guarded<S> {
    inner: S,
    read_cut: Pin<Box<WaitForCancellationFutureOwned>>,
    write_cut: Pin<Box<WaitForCancellationFutureOwned>>,
    severed: bool,
}

impl<S> Guarded<S> {
    fn new(inner: S, cut: &CancellationToken) -> Self {
        Self {
            inner,
            read_cut: Box::pin(cut.clone().cancelled_owned()),
            write_cut: Box::pin(cut.clone().cancelled_owned()),
            severed: false,
        }
    }

    fn check(&mut self, cx: &mut Context<'_>, reading: bool) -> io::Result<()> {
        if !self.severed {
            let cut = if reading {
                self.read_cut.as_mut()
            } else {
                self.write_cut.as_mut()
            };
            self.severed = cut.poll(cx).is_ready();
        }
        if self.severed {
            Err(io::Error::from(io::ErrorKind::ConnectionAborted))
        } else {
            Ok(())
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx, true)?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check(cx, false)?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx, false)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx, false)?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use super::Guarded;

    #[tokio::test]
    async fn a_cut_wakes_a_pending_read_and_fails_every_later_operation() {
        let (near, mut far) = tokio::io::duplex(64);
        let cut = CancellationToken::new();
        let mut guarded = Guarded::new(near, &cut);
        far.write_all(b"ab").await.unwrap();
        let mut buffer = [0; 2];
        guarded.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ab");
        let pending = tokio::spawn(async move {
            let mut byte = [0; 1];
            let read = guarded.read(&mut byte).await;
            (read.map_err(|error| error.kind()), guarded)
        });
        tokio::task::yield_now().await;
        cut.cancel();
        let (read, mut guarded) = tokio::time::timeout(Duration::from_secs(10), pending)
            .await
            .expect("the cut did not wake the reader")
            .unwrap();
        assert_eq!(read, Err(std::io::ErrorKind::ConnectionAborted));
        far.write_all(b"c").await.unwrap();
        let mut byte = [0; 1];
        assert!(guarded.read(&mut byte).await.is_err());
        assert!(guarded.write_all(b"d").await.is_err());
        assert!(guarded.shutdown().await.is_err());
    }
}
