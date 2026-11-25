use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use jaunt_control::{Control, ControlError};
use jaunt_gate::ConnectedAgents;
use jaunt_tunnel::{BoxFuture, NodeId, RegistryEvent};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use super::reconcile::ActiveNodes;

#[derive(Default)]
pub(crate) struct Presence {
    absent_since: Mutex<HashMap<NodeId, Instant>>,
}

impl Presence {
    fn lock(&self) -> MutexGuard<'_, HashMap<NodeId, Instant>> {
        self.absent_since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn connected(&self, node: &NodeId) {
        self.lock().remove(node);
    }

    fn disconnected(&self, node: NodeId, at: Instant) {
        self.lock().entry(node).or_insert(at);
    }

    fn absent_longer_than(&self, limit: Duration, now: Instant) -> Vec<NodeId> {
        self.lock()
            .iter()
            .filter(|(_, since)| now.saturating_duration_since(**since) > limit)
            .map(|(node, _)| node.clone())
            .collect()
    }

    fn forget(&self, node: &NodeId) {
        self.lock().remove(node);
    }
}

pub(crate) struct SweepPlan {
    pub(crate) every: Duration,
    pub(crate) agent_gone_after: Duration,
}

pub(crate) async fn sweep_forever(
    control: Control,
    presence: Arc<Presence>,
    plan: SweepPlan,
    stop: CancellationToken,
) {
    let mut ticker = tokio::time::interval(plan.every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let swept = tokio::select! {
            () = stop.cancelled() => return,
            swept = sweep_once(&control, &presence, plan.agent_gone_after) => swept,
        };
        if swept > 0 {
            tracing::info!(
                target: "jaunt::daemon",
                closed = swept,
                "the session sweep closed sessions"
            );
        }
    }
}

async fn sweep_once(control: &Control, presence: &Presence, agent_gone_after: Duration) -> usize {
    let mut closed = match control.sweep_sessions().await {
        Ok(swept) => swept.expired + swept.revoked + swept.node_removed,
        Err(error) => {
            tracing::warn!(target: "jaunt::daemon", error = %error, "the session sweep failed");
            0
        }
    };
    for node in presence.absent_longer_than(agent_gone_after, Instant::now()) {
        match control.agent_gone(node.as_str()).await {
            Ok(count) => {
                closed += count;
                presence.forget(&node);
            }
            Err(error) => tracing::warn!(
                target: "jaunt::daemon",
                node_id = node.as_str(),
                error = %error,
                "closing the sessions of an absent agent failed"
            ),
        }
    }
    closed
}

pub(crate) async fn watch_revocations(control: Control, every: Duration, stop: CancellationToken) {
    tokio::select! {
        () = stop.cancelled() => {}
        () = control.watch_revocations(every) => {}
    }
}

pub(crate) trait SessionCloser: Send + Sync {
    fn agent_registered<'a>(
        &'a self,
        node: &'a NodeId,
        registered_at: SystemTime,
    ) -> BoxFuture<'a, Result<usize, ControlError>>;
}

impl SessionCloser for Control {
    fn agent_registered<'a>(
        &'a self,
        node: &'a NodeId,
        registered_at: SystemTime,
    ) -> BoxFuture<'a, Result<usize, ControlError>> {
        Box::pin(Control::agent_registered(
            self,
            node.as_str(),
            registered_at,
        ))
    }
}

pub(crate) trait LiveAgents: Send + Sync {
    fn connected_nodes(&self) -> Vec<NodeId>;
    fn registered_at(&self, node: &NodeId) -> Option<SystemTime>;
}

impl LiveAgents for ConnectedAgents {
    fn connected_nodes(&self) -> Vec<NodeId> {
        ConnectedAgents::connected_nodes(self)
    }

    fn registered_at(&self, node: &NodeId) -> Option<SystemTime> {
        ConnectedAgents::registered_at(self, node)
    }
}

pub(crate) struct Registrations<C, A, N> {
    pub(crate) closer: C,
    pub(crate) agents: A,
    pub(crate) nodes: N,
    pub(crate) presence: Arc<Presence>,
}

impl<C: SessionCloser, A: LiveAgents, N: ActiveNodes> Registrations<C, A, N> {
    async fn registered(&self, node: &NodeId, registered_at: SystemTime) {
        if let Err(error) = self.closer.agent_registered(node, registered_at).await {
            tracing::warn!(
                target: "jaunt::daemon",
                node_id = node.as_str(),
                error = %error,
                "closing the sessions of a registering agent failed"
            );
        }
    }

    async fn caught_up(&self) {
        let connected = self.agents.connected_nodes();
        for node in &connected {
            self.presence.connected(node);
            if let Some(registered_at) = self.agents.registered_at(node) {
                self.registered(node, registered_at).await;
            }
        }
        let known = match self.nodes.active_node_ids().await {
            Ok(known) => known,
            Err(error) => {
                tracing::warn!(
                    target: "jaunt::daemon",
                    error = %error,
                    "listing the nodes after missed registrations failed"
                );
                return;
            }
        };
        let now = Instant::now();
        for id in known {
            let Ok(node) = NodeId::new(id) else {
                continue;
            };
            if !connected.contains(&node) {
                self.presence.disconnected(node, now);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Registration {
    Registered(NodeId, SystemTime),
    Gone(NodeId),
}

pub(crate) trait RegistrationEvent: Clone + Send + 'static {
    fn registration(self) -> Registration;
}

impl RegistrationEvent for RegistryEvent {
    fn registration(self) -> Registration {
        match self {
            RegistryEvent::Connected {
                node,
                registered_at,
                ..
            }
            | RegistryEvent::Replaced {
                node,
                registered_at,
                ..
            } => Registration::Registered(node, registered_at),
            RegistryEvent::Disconnected { node, .. } => Registration::Gone(node),
        }
    }
}

impl RegistrationEvent for Registration {
    fn registration(self) -> Registration {
        self
    }
}

pub(crate) async fn follow_registrations<C, A, N, E>(
    registrations: Registrations<C, A, N>,
    mut events: Receiver<E>,
    stop: CancellationToken,
) where
    C: SessionCloser,
    A: LiveAgents,
    N: ActiveNodes,
    E: RegistrationEvent,
{
    loop {
        let event = tokio::select! {
            () = stop.cancelled() => return,
            event = events.recv() => event,
        };
        match event.map(RegistrationEvent::registration) {
            Ok(Registration::Registered(node, registered_at)) => {
                registrations.presence.connected(&node);
                registrations.registered(&node, registered_at).await;
            }
            Ok(Registration::Gone(node)) => {
                registrations.presence.disconnected(node, Instant::now());
            }
            Err(RecvError::Lagged(missed)) => {
                tracing::warn!(
                    target: "jaunt::daemon",
                    missed,
                    "agent registrations were missed; every connected node is checked against its registration time"
                );
                registrations.caught_up().await;
            }
            Err(RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use jaunt_control::ControlError;
    use jaunt_store::StoreError;
    use jaunt_tunnel::{BoxFuture, NodeId};
    use tokio::sync::broadcast;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::{
        ActiveNodes, LiveAgents, Presence, Registration, Registrations, SessionCloser,
        follow_registrations,
    };

    fn node(name: &str) -> NodeId {
        NodeId::new(name).unwrap()
    }

    #[derive(Default)]
    struct Closer(Mutex<Vec<(String, SystemTime)>>);

    impl SessionCloser for Arc<Closer> {
        fn agent_registered<'a>(
            &'a self,
            node: &'a NodeId,
            registered_at: SystemTime,
        ) -> BoxFuture<'a, Result<usize, ControlError>> {
            self.0
                .lock()
                .unwrap()
                .push((node.as_str().to_owned(), registered_at));
            Box::pin(async { Ok(1) })
        }
    }

    struct Agents(HashMap<NodeId, SystemTime>);

    impl LiveAgents for Agents {
        fn connected_nodes(&self) -> Vec<NodeId> {
            let mut nodes: Vec<NodeId> = self.0.keys().cloned().collect();
            nodes.sort();
            nodes
        }

        fn registered_at(&self, node: &NodeId) -> Option<SystemTime> {
            self.0.get(node).copied()
        }
    }

    struct Known(HashSet<String>);

    impl ActiveNodes for Known {
        fn active_node_ids(&self) -> BoxFuture<'_, Result<HashSet<String>, StoreError>> {
            let known = self.0.clone();
            Box::pin(async move { Ok(known) })
        }
    }

    #[test]
    fn a_node_counts_as_gone_only_while_it_stays_away_past_the_limit() {
        let presence = Presence::default();
        let start = Instant::now();
        presence.disconnected(node("a"), start);
        presence.disconnected(node("b"), start + Duration::from_secs(60));
        presence.disconnected(node("a"), start + Duration::from_secs(100));
        presence.disconnected(node("c"), start);
        presence.connected(&node("c"));

        let limit = Duration::from_secs(120);
        assert!(presence.absent_longer_than(limit, start + limit).is_empty());
        assert_eq!(
            presence.absent_longer_than(limit, start + limit + Duration::from_secs(1)),
            [node("a")]
        );
        let mut later = presence.absent_longer_than(limit, start + Duration::from_secs(200));
        later.sort();
        assert_eq!(later, [node("a"), node("b")]);
        presence.forget(&node("a"));
        assert_eq!(
            presence.absent_longer_than(limit, start + Duration::from_secs(200)),
            [node("b")]
        );
    }

    #[tokio::test]
    async fn missed_registrations_close_by_the_registration_time_of_every_connected_node() {
        let at_a = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let at_b = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let event_at = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000);
        let closer = Arc::new(Closer::default());
        let presence = Arc::new(Presence::default());
        let (events, receiver) = broadcast::channel(2);
        for name in ["x1", "x2", "x3", "a", "b"] {
            events
                .send(Registration::Registered(node(name), event_at))
                .unwrap();
        }
        drop(events);

        follow_registrations(
            Registrations {
                closer: Arc::clone(&closer),
                agents: Agents([(node("a"), at_a), (node("b"), at_b)].into()),
                nodes: Known(["a", "b", "c"].map(str::to_owned).into()),
                presence: Arc::clone(&presence),
            },
            receiver,
            CancellationToken::new(),
        )
        .await;

        let calls = closer.0.lock().unwrap().clone();
        assert_eq!(
            calls,
            [
                ("a".to_owned(), at_a),
                ("b".to_owned(), at_b),
                ("a".to_owned(), event_at),
                ("b".to_owned(), event_at),
            ]
        );
        let later = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            presence.absent_longer_than(Duration::ZERO, later),
            [node("c")]
        );
    }

    #[tokio::test]
    async fn a_registration_closes_by_the_time_its_event_carries_not_by_a_later_lookup() {
        let connected_at = SystemTime::UNIX_EPOCH + Duration::from_secs(5_000);
        let replaced_at = SystemTime::UNIX_EPOCH + Duration::from_secs(6_000);
        let stale = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let closer = Arc::new(Closer::default());
        let (events, receiver) = broadcast::channel(4);
        events
            .send(Registration::Registered(node("new"), connected_at))
            .unwrap();
        events
            .send(Registration::Registered(node("again"), replaced_at))
            .unwrap();
        drop(events);

        follow_registrations(
            Registrations {
                closer: Arc::clone(&closer),
                agents: Agents([(node("again"), stale)].into()),
                nodes: Known(HashSet::new()),
                presence: Arc::new(Presence::default()),
            },
            receiver,
            CancellationToken::new(),
        )
        .await;

        assert_eq!(
            closer.0.lock().unwrap().clone(),
            [
                ("new".to_owned(), connected_at),
                ("again".to_owned(), replaced_at),
            ]
        );
    }
}
