use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_audit::DEFAULT_QUEUE;
use jaunt_limits::Rate;

use super::ledger::Gate;

const MINUTE: Duration = Duration::from_secs(60);
const NODE_EDGES: Rate = Rate::clamped(200, 50 * 60);
const NODE_LIFECYCLE: Rate = Rate::clamped(500, 100 * 60);
const NODE_MARKS: Rate = Rate::clamped(100, 20 * 60);
const AGENTS_PER_MINUTE: u32 = 200 * 60;
const EDGES_PER_MINUTE: u32 = 100 * 60;
const QUEUE_SHARE: usize = 4;
const MIN_AGENTS_BURST: u32 = 64;
const NODE_BURST_SHARE: u32 = 4;
const NODE_RATE_SHARE: u32 = 2;
const LANES: usize = 3;
const POOLS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lane {
    Edges,
    Lifecycle,
    Marks,
}

impl Lane {
    const fn slot(self) -> usize {
        match self {
            Lane::Edges => 0,
            Lane::Lifecycle => 1,
            Lane::Marks => 2,
        }
    }

    const fn pool(self) -> usize {
        match self {
            Lane::Edges => 0,
            Lane::Lifecycle | Lane::Marks => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentEventLimits {
    nodes: [Rate; LANES],
    agents: [Rate; POOLS],
}

impl AgentEventLimits {
    pub fn for_audit_queue(queue: usize) -> AgentEventLimits {
        let share = u32::try_from(queue / QUEUE_SHARE).unwrap_or(u32::MAX);
        let total = share.max(MIN_AGENTS_BURST);
        let edges_burst = total / 2;
        let rest_burst = total - edges_burst;
        let edges = Rate::clamped(edges_burst, EDGES_PER_MINUTE);
        let rest = Rate::clamped(rest_burst, AGENTS_PER_MINUTE - EDGES_PER_MINUTE);
        let capped = |node: Rate, pool: Rate| {
            Rate::clamped(
                node.burst().min(pool.burst() / NODE_BURST_SHARE),
                node.per_minute().min(pool.per_minute() / NODE_RATE_SHARE),
            )
        };
        AgentEventLimits {
            nodes: [
                capped(NODE_EDGES, edges),
                capped(NODE_LIFECYCLE, rest),
                capped(NODE_MARKS, rest),
            ],
            agents: [edges, rest],
        }
    }

    fn node(&self, lane: Lane) -> Rate {
        self.nodes[lane.slot()]
    }

    fn agents(&self, lane: Lane) -> Rate {
        self.agents[lane.pool()]
    }
}

impl Default for AgentEventLimits {
    fn default() -> AgentEventLimits {
        AgentEventLimits::for_audit_queue(DEFAULT_QUEUE)
    }
}

struct State {
    nodes: HashMap<String, [Duration; LANES]>,
    agents: [Duration; POOLS],
}

pub(crate) struct Buckets {
    limits: AgentEventLimits,
    capacity: usize,
    state: Mutex<State>,
}

fn take(rate: Rate, ready_at: Duration, now: Duration) -> Option<Duration> {
    let interval = MINUTE.checked_div(rate.per_minute()).unwrap_or(MINUTE);
    let tolerance = interval.saturating_mul(rate.burst().saturating_sub(1));
    let ready_at = ready_at.max(now);
    (ready_at.saturating_sub(now) <= tolerance).then(|| ready_at.saturating_add(interval))
}

impl Buckets {
    pub(crate) fn new(limits: AgentEventLimits, capacity: usize) -> Buckets {
        Buckets {
            limits,
            capacity: capacity.max(1),
            state: Mutex::new(State {
                nodes: HashMap::new(),
                agents: [Duration::ZERO; POOLS],
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn admit(&self, node: &str, lane: Lane, now: Duration) -> Gate {
        let mut state = self.lock();
        let held = state
            .nodes
            .get(node)
            .map_or(Duration::ZERO, |ready| ready[lane.slot()]);
        let Some(node_next) = take(self.limits.node(lane), held, now) else {
            return Gate::Node;
        };
        let Some(agents_next) = take(self.limits.agents(lane), state.agents[lane.pool()], now)
        else {
            return Gate::Agents;
        };
        state.agents[lane.pool()] = agents_next;
        if !state.nodes.contains_key(node) && state.nodes.len() >= self.capacity {
            self.make_room(&mut state, now);
        }
        state
            .nodes
            .entry(node.to_owned())
            .or_insert([Duration::ZERO; LANES])[lane.slot()] = node_next;
        Gate::Open
    }

    fn make_room(&self, state: &mut State, now: Duration) {
        state
            .nodes
            .retain(|_, ready| ready.iter().any(|at| *at > now));
        if state.nodes.len() < self.capacity {
            return;
        }
        let fullest = state
            .nodes
            .iter()
            .min_by_key(|(_, ready)| ready.iter().copied().max().unwrap_or(Duration::ZERO))
            .map(|(node, _)| node.clone());
        if let Some(node) = fullest {
            state.nodes.remove(&node);
        }
    }

    pub(crate) fn sweep(&self, now: Duration) -> usize {
        let mut state = self.lock();
        let before = state.nodes.len();
        state
            .nodes
            .retain(|_, ready| ready.iter().any(|at| *at > now));
        before - state.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jaunt_audit::MAX_QUEUE;

    use super::{AgentEventLimits, Buckets, Lane};
    use crate::agent_events::ledger::Gate;

    const AT: Duration = Duration::from_secs(1_000);
    const LANES: [Lane; 3] = [Lane::Edges, Lane::Lifecycle, Lane::Marks];

    fn drain(buckets: &Buckets, nodes: usize, now: Duration) -> u64 {
        let mut opened = 0;
        for node in 0..nodes {
            let name = format!("n{node}");
            for lane in LANES {
                while buckets.admit(&name, lane, now) == Gate::Open {
                    opened += 1;
                }
            }
        }
        opened
    }

    #[test]
    fn everything_agents_can_write_at_once_is_a_quarter_of_the_audit_queue_and_at_least_64() {
        for (queue, expected) in [
            (1, 64),
            (64, 64),
            (256, 64),
            (1000, 250),
            (1024, 256),
            (4096, 1024),
            (MAX_QUEUE, 250_000),
        ] {
            let buckets = Buckets::new(AgentEventLimits::for_audit_queue(queue), 10_000);
            let nodes = usize::try_from(expected).unwrap() / 32 + 2;
            let opened = drain(&buckets, nodes, AT);
            assert_eq!(opened, expected, "{queue}");
            assert!(queue < 256 || opened <= u64::try_from(queue / 4).unwrap());
            let later = drain(&buckets, nodes, AT + Duration::from_secs(1));
            assert!(later <= 200, "{queue}: {later}");
        }
    }

    fn count(buckets: &Buckets, node: &str, lane: Lane, at: Duration) -> u32 {
        let mut opened = 0;
        while buckets.admit(node, lane, at) == Gate::Open {
            opened += 1;
        }
        opened
    }

    #[test]
    fn session_starts_and_ends_have_their_own_pool_the_rest_share_the_other() {
        let buckets = Buckets::new(AgentEventLimits::default(), 16);
        let lifecycle: u32 = ["a", "b", "c", "d"]
            .into_iter()
            .map(|node| count(&buckets, node, Lane::Lifecycle, AT))
            .sum();
        assert_eq!(lifecycle, 128);
        assert_eq!(buckets.admit("e", Lane::Marks, AT), Gate::Agents);
        assert_eq!(count(&buckets, "e", Lane::Edges, AT), 32);
        assert_eq!(buckets.admit("e", Lane::Edges, AT), Gate::Node);
        let edges: u32 = ["f", "g", "h"]
            .into_iter()
            .map(|node| count(&buckets, node, Lane::Edges, AT))
            .sum();
        assert_eq!(edges, 96);
        assert_eq!(buckets.admit("i", Lane::Edges, AT), Gate::Agents);
    }

    #[test]
    fn a_refusal_by_either_bucket_takes_no_token_from_the_other() {
        let buckets = Buckets::new(AgentEventLimits::default(), 16);
        for node in ["a", "b", "c", "d"] {
            assert_eq!(count(&buckets, node, Lane::Edges, AT), 32);
        }
        for _ in 0..200 {
            assert_eq!(buckets.admit("z", Lane::Edges, AT), Gate::Agents);
        }
        let refilled = AT + Duration::from_millis(500);
        assert_eq!(count(&buckets, "z", Lane::Edges, refilled), 32);

        let quiet = Buckets::new(AgentEventLimits::default(), 16);
        assert_eq!(count(&quiet, "m", Lane::Marks, AT), 32);
        for _ in 0..50 {
            assert_eq!(quiet.admit("m", Lane::Marks, AT), Gate::Node);
        }
        let others: u32 = ["o1", "o2", "o3", "o4"]
            .into_iter()
            .map(|node| count(&quiet, node, Lane::Lifecycle, AT))
            .sum();
        assert_eq!(others, 96);
    }

    #[test]
    fn a_node_takes_at_most_a_quarter_of_a_pool_at_once_and_refills_at_half_its_rate() {
        let limits = AgentEventLimits::default();
        let buckets = Buckets::new(limits, 16);
        for node in ["a", "b", "c", "d"] {
            assert_eq!(count(&buckets, node, Lane::Lifecycle, AT), 32);
        }
        let later = AT + Duration::from_millis(200);
        assert_eq!(count(&buckets, "a", Lane::Lifecycle, later), 10);
        assert_eq!(buckets.admit("a", Lane::Lifecycle, later), Gate::Node);
        assert_eq!(count(&buckets, "b", Lane::Lifecycle, later), 10);
        assert_eq!(buckets.admit("c", Lane::Lifecycle, later), Gate::Agents);
        for queue in [1, 256, 1024, 4096] {
            let limits = AgentEventLimits::for_audit_queue(queue);
            for lane in LANES {
                let node = limits.node(lane);
                let pool = limits.agents(lane);
                assert!(node.burst() <= pool.burst() / 4, "{queue} {lane:?}");
                assert!(
                    node.per_minute() <= pool.per_minute() / 2,
                    "{queue} {lane:?}"
                );
            }
        }
        let marks = limits.node(Lane::Marks);
        assert_eq!((marks.burst(), marks.per_minute()), (32, 1200));
    }

    #[test]
    fn the_table_of_nodes_is_bounded_and_swept_when_every_bucket_is_full_again() {
        let buckets = Buckets::new(AgentEventLimits::default(), 2);
        assert_eq!(buckets.admit("a", Lane::Marks, AT), Gate::Open);
        assert_eq!(buckets.admit("b", Lane::Marks, AT), Gate::Open);
        assert_eq!(buckets.admit("c", Lane::Marks, AT), Gate::Open);
        assert_eq!(buckets.lock().nodes.len(), 2);
        assert_eq!(buckets.sweep(AT), 0);
        assert_eq!(buckets.sweep(AT + Duration::from_millis(50)), 2);
        assert!(buckets.lock().nodes.is_empty());
    }
}
