use std::collections::HashMap;
use std::convert::Infallible;
use std::future::{Future, pending};
use std::net::IpAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http::header::AUTHORIZATION;
use http::{Request, Response, Version};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use jaunt_kube::{ApiRequest, classify};
use jaunt_proto::{KubernetesAudit, ServiceAccess, ServiceOutcome};
use tokio_util::sync::CancellationToken;

use super::KubeLimits;
use super::audit::{SessionAudit, describe};
use super::body::{Held, ProxyBody, RequestBody};
use super::lease::{ConnectionSlots, UserSlots};
use super::policy::{Decision, DecisionError, client_ip, upstream_headers};
use super::request::{
    ExpectedHost, answers_late, authority_matches, check_path, framing_supported, method_supported,
    wants_upgrade,
};
use super::status;
use super::upstream::Upstream;
use crate::clock::Clock;
use crate::runtime::handler::{
    ByteCounts, Counted, EndReason, HandlerError, ServiceConnection, ServiceGrant, ServiceSession,
};

const ALPN_H2: &[u8] = b"h2";

pub(crate) struct Shared {
    pub(crate) upstream: Upstream,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) audits: HashMap<String, KubernetesAudit>,
    pub(crate) users: UserSlots,
    pub(crate) limits: KubeLimits,
}

struct Connection {
    shared: Arc<Shared>,
    decision: Result<Decision, DecisionError>,
    host: ExpectedHost,
    client_ip: Option<IpAddr>,
    slots: ConnectionSlots,
    audit: Arc<SessionAudit>,
    stopping: CancellationToken,
}

struct SessionGuard {
    audit: Arc<SessionAudit>,
    counts: Arc<ByteCounts>,
    stopping: CancellationToken,
    reason: EndReason,
    outcome: Option<ServiceOutcome>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stopping.cancel();
        let outcome = self.outcome.unwrap_or_else(|| {
            self.reason.decide(if std::thread::panicking() {
                ServiceOutcome::UpstreamError
            } else {
                ServiceOutcome::Closed
            })
        });
        self.audit
            .end(outcome, self.counts.read(), self.counts.written());
    }
}

pub(crate) async fn serve(
    shared: Arc<Shared>,
    connection: ServiceConnection,
    grant: ServiceGrant,
    session: ServiceSession,
) -> Result<ServiceOutcome, HandlerError> {
    let ServiceAccess::Kube(access) = &grant.access else {
        tracing::error!(
            target: "jaunt::agent",
            session_id = session.session_id.as_str(),
            service = %session.service,
            "a Kubernetes connection was given access of another kind; it is closed"
        );
        return Err(HandlerError);
    };
    let clock = Arc::clone(&shared.clock);
    let mode = shared
        .audits
        .get(session.service.as_str())
        .copied()
        .unwrap_or_default();
    let decision = Decision::from_access(access, &session.session_id);
    if let Err(error) = &decision {
        tracing::error!(
            target: "jaunt::agent",
            session_id = session.session_id.as_str(),
            service = %session.service,
            reason = error.as_str(),
            "the access decision of a Kubernetes session cannot be applied; every request of the connection is refused"
        );
    }
    let audit = Arc::new(SessionAudit::new(
        session.events.clone(),
        Arc::clone(&clock),
        mode,
    ));
    audit.start(decision.as_ref().ok(), &connection.client_addr);
    let counts = Arc::new(ByteCounts::default());
    let stopping = CancellationToken::new();
    let mut guard = SessionGuard {
        audit: Arc::clone(&audit),
        counts: Arc::clone(&counts),
        stopping: stopping.clone(),
        reason: session.reason.clone(),
        outcome: None,
    };
    let limits = shared.limits;
    let context = Arc::new(Connection {
        slots: ConnectionSlots::new(&connection.user.user_id, limits.slots_per_connection),
        client_ip: client_ip(&connection.client_addr),
        shared,
        decision,
        host: ExpectedHost::new(&session.dns_name),
        audit,
        stopping: stopping.clone(),
    });
    let io = TokioIo::new(Counted::new(connection.stream, counts));
    let service = service_fn(move |request: Request<Incoming>| {
        let context = Arc::clone(&context);
        async move { Ok::<_, Infallible>(context.handle(request).await) }
    });
    let ending = Ending {
        cancel: session.cancel,
        stopping,
        reason: session.reason,
        limits,
    };
    let outcome = if connection.alpn.as_deref() == Some(ALPN_H2) {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .max_concurrent_streams(limits.max_concurrent_streams)
            .max_header_list_size(u32::try_from(limits.max_header_bytes).unwrap_or(u32::MAX))
            .initial_stream_window_size(limits.stream_window)
            .initial_connection_window_size(limits.client_connection_window)
            .max_send_buf_size(limits.send_buffer)
            .keep_alive_interval(limits.ping_interval)
            .keep_alive_timeout(limits.ping_timeout);
        ending
            .drive(builder.serve_connection(io, service), |connection| {
                connection.graceful_shutdown();
            })
            .await
    } else {
        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .keep_alive(true)
            .header_read_timeout(limits.idle_keep_alive)
            .max_header_size(limits.max_header_bytes);
        ending
            .drive(
                builder.serve_connection(io, service).with_upgrades(),
                |connection| connection.graceful_shutdown(),
            )
            .await
    };
    guard.outcome = Some(outcome);
    drop(guard);
    Ok(outcome)
}

struct Ending {
    cancel: CancellationToken,
    stopping: CancellationToken,
    reason: EndReason,
    limits: KubeLimits,
}

impl Ending {
    async fn drive<C>(self, connection: C, shut_down: impl FnOnce(Pin<&mut C>)) -> ServiceOutcome
    where
        C: Future<Output = Result<(), hyper::Error>>,
    {
        let mut connection = pin!(connection);
        tokio::select! {
            served = connection.as_mut() => return self.reason.decide(served_outcome(served)),
            () = self.cancel.cancelled() => {}
        }
        self.stopping.cancel();
        shut_down(connection.as_mut());
        tokio::select! {
            served = connection.as_mut() => {
                if let Err(error) = served {
                    tracing::debug!(
                        target: "jaunt::agent",
                        error = %error,
                        "a Kubernetes connection ended with an error while shutting down"
                    );
                }
            }
            () = tokio::time::sleep(self.limits.shutdown_grace) => {}
        }
        self.reason.decide(ServiceOutcome::Closed)
    }
}

fn served_outcome(served: Result<(), hyper::Error>) -> ServiceOutcome {
    match served {
        Ok(()) => ServiceOutcome::Closed,
        Err(error) => {
            tracing::debug!(
                target: "jaunt::agent",
                error = %error,
                "a Kubernetes connection ended with an error"
            );
            if error.is_timeout() {
                ServiceOutcome::IdleTimeout
            } else if error.is_parse() || error.is_parse_too_large() {
                ServiceOutcome::ProtocolError
            } else {
                ServiceOutcome::Closed
            }
        }
    }
}

impl Connection {
    async fn handle(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        let classified = classify(
            request.method(),
            request.uri().path(),
            request.uri().query(),
        );
        let described = describe(&classified, self.audit.mode());
        let Some(record) = self.audit.begin(described) else {
            return status::ending();
        };
        let response = self.respond(request, &classified).await;
        record.answered(response.status());
        response
    }

    async fn respond(
        &self,
        request: Request<Incoming>,
        classified: &ApiRequest,
    ) -> Response<ProxyBody> {
        if !authority_matches(&request, &self.host) {
            return status::misdirected();
        }
        if check_path(request.uri().path()).is_err() {
            return status::bad_path();
        }
        if !method_supported(request.method()) {
            return status::method_not_allowed();
        }
        if !framing_supported(request.headers()) {
            return status::bad_framing();
        }
        if wants_upgrade(&request, classified) {
            return self.upgrade(request);
        }
        let Ok(decision) = &self.decision else {
            return status::decision_unusable();
        };
        let late = answers_late(classified, request.uri().query());
        let (mut parts, body) = request.into_parts();
        let headers =
            match upstream_headers(std::mem::take(&mut parts.headers), decision, self.client_ip) {
                Ok(headers) => headers,
                Err(refused) => return status::refused(refused, decision),
            };
        let shared = &self.shared;
        let upstream = &shared.upstream;
        let Some(bearer) = upstream.bearer() else {
            return status::unreachable();
        };
        let Some(uri) = parts
            .uri
            .path_and_query()
            .and_then(|path| upstream.uri(path))
        else {
            return status::bad_path();
        };
        let Some(lease) = self.slots.lease(&shared.users) else {
            return status::too_many(shared.limits);
        };
        let stalled = Arc::new(AtomicBool::new(false));
        let body = RequestBody::new(
            body,
            Arc::clone(&shared.clock),
            shared.limits.progress_timeout,
            Arc::clone(&stalled),
        );
        let mut forwarded = Request::new(body);
        *forwarded.method_mut() = parts.method;
        *forwarded.uri_mut() = uri;
        *forwarded.version_mut() = Version::HTTP_2;
        *forwarded.headers_mut() = headers;
        forwarded.headers_mut().insert(AUTHORIZATION, bearer);
        let clock = &shared.clock;
        let now = clock.now();
        let slot_deadline = now.checked_add(shared.limits.slot_wait).unwrap_or(now);
        let reserved = tokio::select! {
            biased;
            () = self.stopping.cancelled() => return status::ending(),
            () = clock.sleep_until(slot_deadline) => return status::busy(),
            reserved = upstream.reserve() => match reserved {
                Ok(reserved) => reserved,
                Err(error) => {
                    upstream.log_failure(&error);
                    return status::unreachable();
                }
            },
        };
        let now = clock.now();
        let deadline = now.checked_add(shared.limits.head_timeout).unwrap_or(now);
        let head_timeout = async {
            if late {
                pending::<()>().await;
            } else {
                clock.sleep_until(deadline).await;
            }
        };
        tokio::select! {
            biased;
            () = self.stopping.cancelled() => status::ending(),
            () = head_timeout => status::timeout(),
            sent = upstream.send(reserved, forwarded) => match sent {
                Ok((response, slot)) => {
                    let (mut head, body) = response.into_parts();
                    head.version = Version::HTTP_11;
                    let held = Held::new(lease, slot);
                    Response::from_parts(
                        head,
                        ProxyBody::upstream(
                            body,
                            held,
                            self.stopping.clone(),
                            Arc::clone(clock),
                            shared.limits.progress_timeout,
                        ),
                    )
                }
                Err(_) if stalled.load(Ordering::Acquire) => {
                    tracing::debug!(
                        target: "jaunt::agent",
                        "a client stopped sending its request body for too long; the request was reset"
                    );
                    status::client_stalled()
                }
                Err(error) => {
                    upstream.log_failure(&error);
                    status::unreachable()
                }
            },
        }
    }

    fn upgrade(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        drop(request);
        status::upgrades_unavailable()
    }
}
