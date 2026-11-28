mod audit;
mod cancel;
mod lexer;
mod relay;
#[cfg(test)]
mod tests;
mod upstream;
mod wire;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jaunt_pgwire::{
    CancelRequest, DEFAULT_MAX_DATA_MESSAGE, DEFAULT_MAX_PENDING, DEFAULT_MAX_STATEMENT_MESSAGE,
    DecodeError, Event, FrontendDecoder, FrontendMessage, Limits, StartupMessage, StartupPolicy,
    StartupRefusal,
};
use jaunt_proto::{
    DbAccessRequest, MAX_SERVICES_PER_AGENT, PostgresAudit, PostgresTls, ServiceAccess,
    ServiceAnnouncement, ServiceKind, ServiceOutcome,
};
use jaunt_tunnel::BoxFuture;
use rustls::crypto::CryptoProvider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use crate::keys::TlsKey;
use crate::runtime::handler::{
    HandlerError, Prepared, ServiceConnection, ServiceGrant, ServiceHandler, ServiceSession,
    ServiceStream, Unauthorized,
};
use crate::runtime::limits::SERVICE_LIMITS;
use audit::{ProtocolProblem, QuerySettings, SessionAudit, SessionStart};
use cancel::{CancelMap, CancelTarget};
use relay::{Relay, RelayContext};
use upstream::{LoginError, UpstreamError};
use wire::{
    ACCESS_DENIED, DATABASE_REFUSED, ENCODING_REFUSED, INVALID_STARTUP, NO_ENCRYPTION,
    PASSWORD_REQUESTED, PROTOCOL_VIOLATION, UNAVAILABLE, error_response, is_sqlstate,
};

pub const MAX_STARTUP_BYTES: usize = 10 * 1024;
pub const MAX_STARTUP_PARAMETERS: usize = 64;
const STARTUP_READ: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbLimits {
    pub connect_timeout: Duration,
    pub startup_timeout: Duration,
    pub close_timeout: Duration,
    pub cancel_close_timeout: Duration,
    pub cancel_entries: usize,
    pub frontend: Limits,
}

pub const DB_LIMITS: DbLimits = DbLimits {
    connect_timeout: Duration::from_secs(10),
    startup_timeout: Duration::from_secs(10),
    close_timeout: Duration::from_secs(5),
    cancel_close_timeout: Duration::from_millis(500),
    cancel_entries: SERVICE_LIMITS.connections_per_service * MAX_SERVICES_PER_AGENT,
    frontend: Limits {
        max_data_message: DEFAULT_MAX_DATA_MESSAGE,
        max_statement_message: DEFAULT_MAX_STATEMENT_MESSAGE,
        max_startup_message: MAX_STARTUP_BYTES,
        max_startup_parameters: MAX_STARTUP_PARAMETERS,
        max_pending: DEFAULT_MAX_PENDING,
    },
};

struct Target {
    address: String,
    tls: PostgresTls,
    audit: PostgresAudit,
}

struct Inner {
    targets: HashMap<String, Target>,
    cancels: Arc<CancelMap>,
    clock: Arc<dyn Clock>,
    provider: Arc<CryptoProvider>,
    policy: StartupPolicy,
    limits: DbLimits,
}

pub struct DbHandler {
    inner: Arc<Inner>,
}

struct Startup {
    startup: StartupMessage,
    decoder: FrontendDecoder,
    key: TlsKey,
    application_name: Option<String>,
}

fn refusal_kind(refusal: &StartupRefusal) -> &'static str {
    match refusal {
        StartupRefusal::Replication => "replication",
        StartupRefusal::ParameterNotAllowed { .. } => "parameter_not_allowed",
        StartupRefusal::TooManyParameters { .. } => "too_many_parameters",
        StartupRefusal::ParametersTooLarge { .. } => "parameters_too_large",
        StartupRefusal::ClientEncodingNotAllowed => "client_encoding",
        StartupRefusal::MissingUser => "missing_user",
        StartupRefusal::NameTooLong { .. } => "name_too_long",
        StartupRefusal::UserMismatch => "user_mismatch",
        StartupRefusal::DatabaseMismatch => "database_mismatch",
        StartupRefusal::InvalidName { .. } => "invalid_name",
    }
}

async fn write_fatal(stream: &mut ServiceStream, code: &str, message: &str) {
    if stream
        .write_all(&error_response(code, message))
        .await
        .is_ok()
    {
        drop(stream.flush().await);
    }
    drop(stream.shutdown().await);
}

impl DbHandler {
    pub fn new(services: &ServiceAnnouncement, clock: Arc<dyn Clock>) -> Self {
        Self::with_limits(services, clock, DB_LIMITS)
    }

    pub fn with_limits(
        services: &ServiceAnnouncement,
        clock: Arc<dyn Clock>,
        limits: DbLimits,
    ) -> Self {
        let targets = services
            .services
            .iter()
            .filter(|service| service.kind == ServiceKind::Postgres)
            .filter_map(|service| {
                let address = service.address.clone()?;
                let settings = service.postgres.clone()?;
                Some((
                    service.name.clone(),
                    Target {
                        address,
                        tls: settings.tls,
                        audit: settings.audit,
                    },
                ))
            })
            .collect();
        Self {
            inner: Arc::new(Inner {
                targets,
                cancels: Arc::new(CancelMap::new(limits.cancel_entries, Arc::clone(&clock))),
                clock,
                provider: Arc::new(rustls::crypto::ring::default_provider()),
                policy: StartupPolicy::default(),
                limits,
            }),
        }
    }

    #[cfg(test)]
    fn cancels(&self) -> &Arc<CancelMap> {
        &self.inner.cancels
    }
}

impl Inner {
    async fn tell(
        &self,
        stream: &mut ServiceStream,
        (code, message): (&str, &str),
        cancel: &CancellationToken,
    ) {
        let by = upstream::deadline(&self.clock, self.limits.close_timeout);
        tokio::select! {
            biased;
            () = cancel.cancelled() => {}
            () = write_fatal(stream, code, message) => {}
            () = self.clock.sleep_until(by) => {}
        }
    }

    async fn prepare(&self, connection: &mut ServiceConnection) -> Result<Prepared, HandlerError> {
        let mut decoder = FrontendDecoder::with_streamed_queries(self.limits.frontend)
            .map_err(|_| HandlerError)?;
        let mut buffer = vec![0_u8; STARTUP_READ];
        loop {
            let event = match decoder.next_event() {
                Ok(Some(event)) => event,
                Ok(None) => {
                    let read = connection
                        .stream
                        .read(&mut buffer)
                        .await
                        .map_err(|_| HandlerError)?;
                    if read == 0 {
                        return Err(HandlerError);
                    }
                    if decoder.push(&buffer[..read]).is_err() {
                        write_fatal(&mut connection.stream, PROTOCOL_VIOLATION, INVALID_STARTUP)
                            .await;
                        return Err(HandlerError);
                    }
                    continue;
                }
                Err(DecodeError::RepeatedNegotiation { .. }) => {
                    drop(connection.stream.shutdown().await);
                    return Err(HandlerError);
                }
                Err(_) => {
                    write_fatal(&mut connection.stream, PROTOCOL_VIOLATION, INVALID_STARTUP).await;
                    return Err(HandlerError);
                }
            };
            let message = match event {
                Event::Frame(frame) => frame.into_message(),
                Event::Continuation(_) => {
                    write_fatal(&mut connection.stream, PROTOCOL_VIOLATION, INVALID_STARTUP).await;
                    return Err(HandlerError);
                }
            };
            match message {
                FrontendMessage::SslRequest | FrontendMessage::GssEncRequest => {
                    connection
                        .stream
                        .write_all(&[NO_ENCRYPTION])
                        .await
                        .map_err(|_| HandlerError)?;
                    connection.stream.flush().await.map_err(|_| HandlerError)?;
                }
                FrontendMessage::Cancel(request) => {
                    self.cancel(&connection.user.user_id, &request).await;
                    drop(connection.stream.shutdown().await);
                    return Ok(Prepared::handled());
                }
                FrontendMessage::Startup(startup) => {
                    return self.startup(connection, startup, decoder).await;
                }
                _ => {
                    write_fatal(&mut connection.stream, PROTOCOL_VIOLATION, INVALID_STARTUP).await;
                    return Err(HandlerError);
                }
            }
        }
    }

    async fn startup(
        &self,
        connection: &mut ServiceConnection,
        startup: StartupMessage,
        decoder: FrontendDecoder,
    ) -> Result<Prepared, HandlerError> {
        let (db, application_name) = match self.policy.inspect(&startup) {
            Ok(request) => (
                DbAccessRequest {
                    user: request.user.to_owned(),
                    name: request.database.to_owned(),
                    agent_key: String::new(),
                },
                request.application_name.map(str::to_owned),
            ),
            Err(refusal) => {
                tracing::debug!(
                    target: "jaunt::agent",
                    reason = refusal_kind(&refusal),
                    "the startup message of a database connection was refused"
                );
                write_fatal(
                    &mut connection.stream,
                    PROTOCOL_VIOLATION,
                    &refusal.to_string(),
                )
                .await;
                return Err(HandlerError);
            }
        };
        let key = TlsKey::generate().map_err(|error| {
            tracing::error!(
                target: "jaunt::agent",
                error = %error,
                "cannot generate the key of a database session"
            );
            HandlerError
        })?;
        let db = DbAccessRequest {
            agent_key: key.spki_base64(),
            ..db
        };
        connection.prepared = Some(Box::new(Startup {
            startup,
            decoder,
            key,
            application_name,
        }));
        Ok(Prepared {
            db: Some(db),
            handled: false,
        })
    }

    async fn cancel(&self, user_id: &str, request: &CancelRequest) {
        if !self.cancels.admit(user_id) {
            tracing::debug!(
                target: "jaunt::agent",
                "a cancel request was dropped: the user sent too many"
            );
            return;
        }
        let Some(found) = self.cancels.find(user_id, request) else {
            tracing::debug!(
                target: "jaunt::agent",
                "a cancel request was dropped: it names no session of this user"
            );
            return;
        };
        match upstream::send_cancel(
            &found.target,
            &found.key,
            &self.clock,
            self.limits.connect_timeout,
        )
        .await
        {
            Ok(()) => tracing::debug!(
                target: "jaunt::agent",
                "a cancel request was passed to the database"
            ),
            Err(error) => tracing::warn!(
                target: "jaunt::agent",
                error = %error,
                "passing a cancel request to the database failed"
            ),
        }
    }

    async fn serve(
        self: Arc<Self>,
        mut connection: ServiceConnection,
        grant: ServiceGrant,
        session: ServiceSession,
    ) -> Result<ServiceOutcome, HandlerError> {
        let session_id = session.session_id.as_str();
        let Some(prepared) = connection
            .prepared
            .take()
            .and_then(|state| state.downcast::<Startup>().ok())
        else {
            tracing::error!(
                target: "jaunt::agent",
                session_id,
                "a database session reached the relay without its startup message"
            );
            return Err(HandlerError);
        };
        let Startup {
            startup,
            decoder: frontend,
            key,
            application_name,
        } = *prepared;
        let ServiceAccess::Db(access) = grant.access else {
            tracing::error!(
                target: "jaunt::agent",
                session_id,
                "a database session was granted access of another kind"
            );
            return Err(HandlerError);
        };
        let user_id = connection.user.user_id;
        let mut client = connection.stream;
        let Some(target) = self.targets.get(session.service.as_str()) else {
            tracing::warn!(
                target: "jaunt::agent",
                session_id,
                service = %session.service,
                error = %UpstreamError::NotConfigured,
                "the database session cannot start"
            );
            self.tell(&mut client, UNAVAILABLE, &session.cancel).await;
            return Ok(ServiceOutcome::UpstreamError);
        };
        let audit = SessionAudit::start(
            session.events.clone(),
            Arc::clone(&self.clock),
            QuerySettings {
                mode: target.audit.queries,
                limit: usize::try_from(target.audit.max_query_bytes).unwrap_or(audit::QUERY_LIMIT),
            },
            &SessionStart {
                db_user: &access.user,
                db_name: &access.name,
                application_name: application_name.as_deref(),
                server: &target.address,
            },
        );
        if startup.parameter("user") != Some(access.user.as_str()) {
            tracing::debug!(
                target: "jaunt::agent",
                session_id,
                "the database user granted by control differs from the requested one; the granted one is used"
            );
        }
        let failed = |error: UpstreamError| {
            tracing::warn!(
                target: "jaunt::agent",
                session_id,
                service = %session.service,
                error = %error,
                "the database session cannot start"
            );
        };
        let Ok(forwarded) = self.policy.forward(&startup, &access.user, &access.name) else {
            failed(UpstreamError::GrantedNames);
            self.tell(&mut client, UNAVAILABLE, &session.cancel).await;
            return Ok(ServiceOutcome::UpstreamError);
        };
        let starting = async {
            let (server_name, session_config, cancel_config) =
                upstream::load_trust(&target.tls, &target.address)
                    .await
                    .and_then(|trust| {
                        let session = upstream::session_config(
                            &self.provider,
                            &trust.roots,
                            &access.certificate_der,
                            &key,
                        )?;
                        let cancel = upstream::cancel_config(&self.provider, &trust.roots)?;
                        Ok((trust.server_name, session, cancel))
                    })
                    .map_err(LoginError::Upstream)?;
            let mut connection = upstream::open(
                &target.address,
                &server_name,
                session_config,
                &self.clock,
                self.limits.connect_timeout,
            )
            .await
            .map_err(LoginError::Upstream)?;
            let login = upstream::login(
                &mut connection,
                &forwarded,
                &self.clock,
                self.limits.startup_timeout,
            )
            .await?;
            Ok::<_, LoginError>((server_name, cancel_config, connection, login))
        };
        let started = tokio::select! {
            biased;
            () = session.cancel.cancelled() => return Ok(ServiceOutcome::Closed),
            started = starting => started,
        };
        drop(key);
        let (server_name, cancel_config, upstream, login) = match started {
            Ok(started) => started,
            Err(LoginError::Password) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    session_id,
                    service = %session.service,
                    "the database asked for a password; configure the cert authentication method for the agent"
                );
                audit.protocol_error(ProtocolProblem::PasswordRequested);
                self.tell(&mut client, PASSWORD_REQUESTED, &session.cancel)
                    .await;
                return Ok(ServiceOutcome::UpstreamError);
            }
            Err(LoginError::Refused(notice)) => {
                let code = if is_sqlstate(&notice.code) {
                    notice.code.as_str()
                } else {
                    UNAVAILABLE.0
                };
                tracing::warn!(
                    target: "jaunt::agent",
                    session_id,
                    service = %session.service,
                    sqlstate = code,
                    "the database refused the session"
                );
                audit.error(&notice);
                self.tell(&mut client, (code, DATABASE_REFUSED), &session.cancel)
                    .await;
                return Ok(ServiceOutcome::UpstreamError);
            }
            Err(LoginError::Protocol(problem)) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    session_id,
                    service = %session.service,
                    reason = problem.as_str(),
                    "the database broke the protocol during the startup"
                );
                audit.protocol_error(problem);
                let answer = if problem == ProtocolProblem::ClientEncoding {
                    ENCODING_REFUSED
                } else {
                    UNAVAILABLE
                };
                self.tell(&mut client, answer, &session.cancel).await;
                return Ok(ServiceOutcome::ProtocolError);
            }
            Err(LoginError::Upstream(error)) => {
                failed(error);
                self.tell(&mut client, UNAVAILABLE, &session.cancel).await;
                return Ok(ServiceOutcome::UpstreamError);
            }
        };
        let _registration = login.key_data.clone().and_then(|key| {
            let target = Arc::new(CancelTarget {
                address: target.address.clone(),
                server_name: server_name.clone(),
                config: cancel_config,
            });
            let registered = self.cancels.register(&user_id, key, target);
            if registered.is_none() {
                tracing::warn!(
                    target: "jaunt::agent",
                    session_id,
                    "the cancel map is full; this session cannot be cancelled"
                );
            }
            registered
        });
        audit.set_backslash_escapes(login.backslash_escapes);
        if client.write_all(&login.client_bytes).await.is_err() || client.flush().await.is_err() {
            return Ok(ServiceOutcome::Closed);
        }
        tracing::debug!(
            target: "jaunt::agent",
            session_id,
            service = %session.service,
            "the database session started"
        );
        Ok(relay::relay(
            Relay {
                client,
                upstream,
                frontend,
                backend: login.decoder,
            },
            RelayContext {
                audit: &audit,
                cancel: &session.cancel,
                clock: &self.clock,
                close_timeout: self.limits.close_timeout,
                cancel_close_timeout: self.limits.cancel_close_timeout,
                session_id,
            },
        )
        .await)
    }
}

impl ServiceHandler for DbHandler {
    fn prepare<'a>(
        &'a self,
        connection: &'a mut ServiceConnection,
    ) -> BoxFuture<'a, Result<Prepared, HandlerError>> {
        Box::pin(self.inner.prepare(connection))
    }

    fn refuse(
        &self,
        connection: ServiceConnection,
        reason: Unauthorized,
    ) -> BoxFuture<'static, ()> {
        let answer = match reason {
            Unauthorized::Denied => ACCESS_DENIED,
            Unauthorized::Unavailable => UNAVAILABLE,
        };
        Box::pin(async move {
            let mut stream = connection.stream;
            write_fatal(&mut stream, answer.0, answer.1).await;
        })
    }

    fn serve(
        &self,
        connection: ServiceConnection,
        grant: ServiceGrant,
        session: ServiceSession,
    ) -> BoxFuture<'static, Result<ServiceOutcome, HandlerError>> {
        Box::pin(Arc::clone(&self.inner).serve(connection, grant, session))
    }
}
