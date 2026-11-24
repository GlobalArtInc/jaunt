use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_proto::{ControlError, ControlPlane, RouteDecision, RouteRequest};
use jaunt_ssh::{RouteBackend, RouteFuture, RouteRefusal, RouteTarget, RoutedStream, UserIdentity};
use jaunt_tunnel::{AgentRegistry, H2Io, NodeId, OpenError, SessionId, StreamKind, StreamMeta};

pub const DEFAULT_MAX_STREAMS_PER_USER_NODE: usize = 8;
pub(crate) const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(4);

type StreamKey = (String, String);

pub(crate) struct StreamBook {
    limit: usize,
    open: Mutex<HashMap<StreamKey, usize>>,
}

impl StreamBook {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            open: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<StreamKey, usize>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn reserve(self: &Arc<Self>, user_id: &str, node: &str) -> Option<Reservation> {
        let key = (user_id.to_owned(), node.to_owned());
        let mut open = self.lock();
        let count = open.get(&key).copied().unwrap_or(0);
        if count >= self.limit {
            return None;
        }
        open.insert(key.clone(), count.saturating_add(1));
        Some(Reservation {
            book: Arc::clone(self),
            key: Some(key),
        })
    }

    fn release(&self, user_id: &str, node: &str) {
        let key = (user_id.to_owned(), node.to_owned());
        let mut open = self.lock();
        let Some(count) = open.get_mut(&key) else {
            drop(open);
            tracing::error!(
                target: "jaunt::gate",
                user_id,
                node,
                "a stream was released that was never reserved"
            );
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            open.remove(&key);
        }
    }

    pub(crate) fn total(&self) -> usize {
        self.lock().values().sum()
    }
}

struct Reservation {
    book: Arc<StreamBook>,
    key: Option<StreamKey>,
}

impl Reservation {
    fn keep(mut self) {
        self.key = None;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some((user_id, node)) = self.key.take() {
            self.book.release(&user_id, &node);
        }
    }
}

pub(crate) struct ControlRoute {
    control: Arc<dyn ControlPlane>,
    registry: AgentRegistry,
    book: Arc<StreamBook>,
    control_timeout: Duration,
    open_timeout: Duration,
}

impl ControlRoute {
    pub(crate) fn new(
        control: Arc<dyn ControlPlane>,
        registry: AgentRegistry,
        book: Arc<StreamBook>,
    ) -> Self {
        Self {
            control,
            registry,
            book,
            control_timeout: CONTROL_TIMEOUT,
            open_timeout: OPEN_TIMEOUT,
        }
    }

    async fn open(&self, target: RouteTarget) -> Result<RoutedStream, RouteRefusal> {
        let RouteTarget {
            identity,
            node,
            client_addr,
        } = target;
        let reservation = self
            .book
            .reserve(&identity.user_id, &node)
            .ok_or(RouteRefusal::Limit)?;
        let client = client_addr.to_string();
        let request = RouteRequest {
            user_id: identity.user_id.clone(),
            serial: identity.serial,
            key_id: identity.key_id.clone(),
            node_name: node.clone(),
            client_addr: client.clone(),
        };
        let decision =
            tokio::time::timeout(self.control_timeout, self.control.route(request)).await;
        let (session_id, node_id) = match decision {
            Ok(Ok(RouteDecision::Allow {
                session_id,
                node_id,
            })) => (session_id, node_id),
            Ok(Ok(RouteDecision::Deny { reason })) => {
                return Err(refused(
                    &identity,
                    &node,
                    RouteRefusal::Denied,
                    reason.code(),
                ));
            }
            Ok(Err(error)) => {
                return Err(refused(
                    &identity,
                    &node,
                    RouteRefusal::Unavailable,
                    control_failure(error),
                ));
            }
            Err(_) => {
                return Err(refused(
                    &identity,
                    &node,
                    RouteRefusal::Unavailable,
                    "control_timeout",
                ));
            }
        };
        let stream = self
            .open_stream(&session_id, &node_id, &client)
            .await
            .map_err(|cause| refused(&identity, &node, RouteRefusal::Unavailable, cause))?;
        reservation.keep();
        Ok(RoutedStream {
            session_id,
            stream: Box::new(stream),
        })
    }

    async fn open_stream(
        &self,
        session_id: &str,
        node_id: &str,
        client: &str,
    ) -> Result<H2Io, &'static str> {
        let node = NodeId::new(node_id).map_err(|_| "invalid_node_id")?;
        let session = SessionId::new(session_id).map_err(|_| "invalid_session_id")?;
        let meta =
            StreamMeta::new(session, StreamKind::Ssh, client).map_err(|_| "invalid_stream_meta")?;
        tokio::time::timeout(self.open_timeout, self.registry.open_stream(&node, &meta))
            .await
            .map_err(|_| "agent_open_timeout")?
            .map_err(open_failure)
    }
}

impl RouteBackend for ControlRoute {
    fn route(&self, target: RouteTarget) -> RouteFuture<'_> {
        Box::pin(self.open(target))
    }

    fn released(&self, identity: &UserIdentity, node: &str) {
        self.book.release(&identity.user_id, node);
    }
}

fn refused(
    identity: &UserIdentity,
    node: &str,
    refusal: RouteRefusal,
    cause: &'static str,
) -> RouteRefusal {
    tracing::info!(
        target: "jaunt::gate",
        user_id = identity.user_id.as_str(),
        serial = identity.serial,
        node,
        cause,
        "a route to a node was refused"
    );
    refusal
}

fn control_failure(error: ControlError) -> &'static str {
    match error {
        ControlError::InvalidRequest => "control_invalid_request",
        ControlError::Store => "control_store",
        ControlError::Clock => "control_clock",
    }
}

fn open_failure(error: OpenError) -> &'static str {
    match error {
        OpenError::NotConnected => "agent_not_connected",
        OpenError::InvalidMetadata(_) => "invalid_stream_meta",
        OpenError::AtCapacity => "agent_at_capacity",
        OpenError::Refused(_) => "agent_refused",
        OpenError::Closed => "agent_closed",
        OpenError::Timeout => "agent_timeout",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex, Once};
    use std::task::{Context, Waker};
    use std::time::Duration;

    use jaunt_proto::{
        AuthorizeDecision, AuthorizeRequest, BoxFuture, ControlError, ControlPlane, DenyReason,
        NodeCaller, RouteDecision, RouteRequest, SessionEnd, SessionEndOutcome,
    };
    use jaunt_ssh::{RouteBackend, RouteRefusal, RouteTarget, UserIdentity};
    use jaunt_tunnel::AgentRegistry;

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Metadata, Subscriber};

    use super::{CONTROL_TIMEOUT, ControlRoute, OPEN_TIMEOUT, StreamBook};

    enum Answer {
        Deny(DenyReason),
        Fail(ControlError),
        Allow,
        Hang,
    }

    struct FakeControl {
        answer: Answer,
        seen: Mutex<Vec<RouteRequest>>,
    }

    impl ControlPlane for FakeControl {
        fn route(
            &self,
            request: RouteRequest,
        ) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
            self.seen.lock().unwrap().push(request);
            let answer = match &self.answer {
                Answer::Deny(reason) => Some(Ok(RouteDecision::Deny { reason: *reason })),
                Answer::Fail(error) => Some(Err(*error)),
                Answer::Allow => Some(Ok(RouteDecision::Allow {
                    session_id: "0b6c8f9e-6b1c-4f3e-9d65-6d3c1f4e8a21".to_owned(),
                    node_id: "node-id-1".to_owned(),
                })),
                Answer::Hang => None,
            };
            Box::pin(async move {
                match answer {
                    Some(answer) => answer,
                    None => std::future::pending().await,
                }
            })
        }

        fn authorize(
            &self,
            _node: NodeCaller,
            _request: AuthorizeRequest,
        ) -> BoxFuture<'_, Result<AuthorizeDecision, ControlError>> {
            Box::pin(async { Err(ControlError::InvalidRequest) })
        }

        fn session_end(
            &self,
            _node: NodeCaller,
            _request: SessionEnd,
        ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>> {
            Box::pin(async { Err(ControlError::InvalidRequest) })
        }
    }

    fn identity() -> UserIdentity {
        UserIdentity {
            user_id: "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
            serial: 42,
            key_id: "jaunt:alice@example.com:42".to_owned(),
            email: "alice@example.com".to_owned(),
            valid_before: u64::MAX,
        }
    }

    fn target(node: &str) -> RouteTarget {
        RouteTarget {
            identity: identity(),
            node: node.to_owned(),
            client_addr: "192.0.2.7:50000".parse::<SocketAddr>().unwrap(),
        }
    }

    fn route_with(answer: Answer, limit: usize) -> (ControlRoute, Arc<FakeControl>) {
        let control = Arc::new(FakeControl {
            answer,
            seen: Mutex::new(Vec::new()),
        });
        let route = ControlRoute::new(
            control.clone(),
            AgentRegistry::new(),
            StreamBook::new(limit),
        );
        (route, control)
    }

    #[test]
    fn the_book_admits_up_to_the_limit_per_user_and_node() {
        let book = StreamBook::new(2);
        let first = book.reserve("u1", "web").unwrap();
        let second = book.reserve("u1", "web").unwrap();
        assert!(book.reserve("u1", "web").is_none());
        let other_node = book.reserve("u1", "db").unwrap();
        let other_user = book.reserve("u2", "web").unwrap();
        assert_eq!(book.total(), 4);
        drop(first);
        assert_eq!(book.total(), 3);
        let third = book.reserve("u1", "web").unwrap();
        third.keep();
        second.keep();
        assert_eq!(book.total(), 4);
        book.release("u1", "web");
        book.release("u1", "web");
        book.release("u1", "web");
        drop((other_node, other_user));
        assert_eq!(book.total(), 0);
        assert!(book.lock().is_empty());
    }

    #[tokio::test]
    async fn every_deny_and_every_failure_collapses_into_a_refusal_without_a_reservation() {
        let cases = [
            (Answer::Deny(DenyReason::PolicyDenied), RouteRefusal::Denied),
            (Answer::Deny(DenyReason::Revoked), RouteRefusal::Denied),
            (
                Answer::Deny(DenyReason::NodeUnavailable),
                RouteRefusal::Denied,
            ),
            (Answer::Fail(ControlError::Store), RouteRefusal::Unavailable),
            (Answer::Fail(ControlError::Clock), RouteRefusal::Unavailable),
            (Answer::Allow, RouteRefusal::Unavailable),
        ];
        for (answer, expected) in cases {
            let (route, control) = route_with(answer, 8);
            let refusal = route.route(target("web")).await.err();
            assert_eq!(refusal, Some(expected));
            assert_eq!(route.book.total(), 0);
            let seen = control.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].node_name, "web");
            assert_eq!(seen[0].user_id, identity().user_id);
            assert_eq!(seen[0].serial, 42);
            assert_eq!(seen[0].key_id, "jaunt:alice@example.com:42");
            assert_eq!(seen[0].client_addr, "192.0.2.7:50000");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_plane_that_never_answers_is_cut_off_before_the_outer_deadline() {
        let (route, _) = route_with(Answer::Hang, 8);
        let started = tokio::time::Instant::now();
        let refusal = route.route(target("web")).await.err();
        assert_eq!(refusal, Some(RouteRefusal::Unavailable));
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(route.book.total(), 0);
        assert!(CONTROL_TIMEOUT + OPEN_TIMEOUT < Duration::from_secs(10));
    }

    thread_local! {
        static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    struct Fields;

    struct Visitor<'a>(&'a mut Vec<String>);

    impl Visit for Visitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push(format!("{}={value:?}", field.name()));
        }
    }

    impl Subscriber for Fields {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }

        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = Vec::new();
            event.record(&mut Visitor(&mut fields));
            LINES.with(|lines| lines.borrow_mut().push(fields.join(" ")));
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[tokio::test]
    async fn the_refusal_log_names_the_cause_but_not_the_key_id_or_the_email() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| tracing::subscriber::set_global_default(Fields).unwrap());
        LINES.with(|lines| lines.borrow_mut().clear());
        for answer in [
            Answer::Deny(DenyReason::Revoked),
            Answer::Fail(ControlError::Store),
            Answer::Allow,
        ] {
            let (route, _) = route_with(answer, 8);
            assert!(route.route(target("web")).await.is_err());
        }
        let lines = LINES.with(|lines| lines.borrow().clone());
        assert_eq!(lines.len(), 3, "{lines:?}");
        for (line, cause) in lines
            .iter()
            .zip(["revoked", "control_store", "agent_not_connected"])
        {
            assert!(line.contains(&format!("cause={cause:?}")), "{line}");
            assert!(line.contains(identity().user_id.as_str()), "{line}");
            assert!(!line.contains("alice"), "{line}");
            assert!(!line.contains("jaunt:"), "{line}");
        }
    }

    #[tokio::test]
    async fn a_route_dropped_while_pending_returns_its_reservation() {
        let (route, _) = route_with(Answer::Hang, 1);
        let mut pending = route.route(target("web"));
        let mut context = Context::from_waker(Waker::noop());
        assert!(pending.as_mut().poll(&mut context).is_pending());
        assert_eq!(route.book.total(), 1);
        drop(pending);
        assert_eq!(route.book.total(), 0);
    }

    #[tokio::test]
    async fn the_limit_refuses_before_asking_the_control_plane() {
        let (route, control) = route_with(Answer::Hang, 1);
        let mut context = Context::from_waker(Waker::noop());
        let mut first = route.route(target("web"));
        assert!(first.as_mut().poll(&mut context).is_pending());
        let refusal = route.route(target("web")).await.err();
        assert_eq!(refusal, Some(RouteRefusal::Limit));
        assert_eq!(control.seen.lock().unwrap().len(), 1);
        drop(first);
        assert_eq!(route.book.total(), 0);
    }
}
