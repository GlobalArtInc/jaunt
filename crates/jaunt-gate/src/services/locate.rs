use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use jaunt_proto::SERVICE_LOCATION_CACHE_SECS;
use jaunt_tunnel::NodeId;
use tokio::sync::OnceCell;

pub const KUBE_MISS_CACHE: Duration = Duration::from_secs(2);
pub const KUBE_LOCATION_CACHE: Duration = Duration::from_secs(SERVICE_LOCATION_CACHE_SECS);
pub(crate) const MAX_CACHED_CLUSTERS: usize = 4096;

pub(crate) type Now = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Located {
    Node(NodeId),
    Unknown,
    Unavailable,
}

impl Located {
    fn lifetime(&self) -> Duration {
        match self {
            Self::Node(_) => KUBE_LOCATION_CACHE,
            Self::Unknown | Self::Unavailable => KUBE_MISS_CACHE,
        }
    }
}

#[derive(Debug, Clone)]
struct Settled {
    located: Located,
    expires: Instant,
}

#[derive(Default)]
struct Lookup {
    settled: OnceCell<Settled>,
}

impl Lookup {
    fn fresh_at(&self, now: Instant) -> bool {
        self.settled
            .get()
            .is_none_or(|settled| now < settled.expires)
    }
}

pub(crate) struct LocationCache {
    entries: Mutex<HashMap<String, Arc<Lookup>>>,
    capacity: usize,
    now: Now,
}

impl LocationCache {
    pub(crate) fn new(capacity: usize, now: Now) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            now,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Arc<Lookup>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) async fn locate<F, Fut>(&self, cluster: &str, fetch: F) -> Located
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Located>,
    {
        let Some(lookup) = self.lookup(cluster) else {
            return fetch().await;
        };
        let settled = lookup
            .settled
            .get_or_init(|| async {
                let located = fetch().await;
                Settled {
                    expires: (self.now)() + located.lifetime(),
                    located,
                }
            })
            .await;
        settled.located.clone()
    }

    pub(crate) fn forget(&self, cluster: &str, node: &NodeId) {
        let mut entries = self.lock();
        let holds_node = entries.get(cluster).is_some_and(|lookup| {
            lookup
                .settled
                .get()
                .is_some_and(|settled| settled.located == Located::Node(node.clone()))
        });
        if holds_node {
            entries.remove(cluster);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    fn lookup(&self, cluster: &str) -> Option<Arc<Lookup>> {
        let now = (self.now)();
        let mut entries = self.lock();
        if let Some(found) = entries.get(cluster)
            && found.fresh_at(now)
        {
            return Some(Arc::clone(found));
        }
        if entries.len() >= self.capacity && !entries.contains_key(cluster) {
            entries.retain(|_, lookup| lookup.fresh_at(now));
            if entries.len() >= self.capacity {
                return None;
            }
        }
        let fresh = Arc::new(Lookup::default());
        entries.insert(cluster.to_owned(), Arc::clone(&fresh));
        Some(fresh)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use jaunt_tunnel::NodeId;
    use tokio::sync::Notify;

    use super::{KUBE_LOCATION_CACHE, KUBE_MISS_CACHE, Located, LocationCache};

    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    fn cache(clock: &Arc<ManualClock>, capacity: usize) -> LocationCache {
        let clock = Arc::clone(clock);
        LocationCache::new(capacity, Arc::new(move || *clock.0.lock().unwrap()))
    }

    fn node() -> NodeId {
        NodeId::new("node-1").unwrap()
    }

    async fn counted(
        cache: &LocationCache,
        calls: &AtomicUsize,
        name: &str,
        answer: Located,
    ) -> Located {
        cache
            .locate(name, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                answer
            })
            .await
    }

    #[test]
    fn the_cache_lifetimes_are_two_seconds_for_misses_and_ten_for_hits() {
        assert_eq!(KUBE_MISS_CACHE, Duration::from_secs(2));
        assert_eq!(KUBE_LOCATION_CACHE, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn misses_live_two_seconds_and_hits_ten() {
        let clock = ManualClock::new();
        let cache = cache(&clock, 16);
        let calls = AtomicUsize::new(0);
        for _ in 0..50 {
            assert_eq!(
                counted(&cache, &calls, "ghost", Located::Unknown).await,
                Located::Unknown
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(KUBE_MISS_CACHE - Duration::from_millis(1));
        counted(&cache, &calls, "ghost", Located::Unknown).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_millis(1));
        counted(&cache, &calls, "ghost", Located::Unknown).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let hits = AtomicUsize::new(0);
        assert_eq!(
            counted(&cache, &hits, "prod", Located::Node(node())).await,
            Located::Node(node())
        );
        clock.advance(KUBE_LOCATION_CACHE - Duration::from_millis(1));
        counted(&cache, &hits, "prod", Located::Unknown).await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            counted(&cache, &hits, "prod", Located::Unknown).await,
            Located::Unknown
        );
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        let failures = AtomicUsize::new(0);
        counted(&cache, &failures, "down", Located::Unavailable).await;
        counted(&cache, &failures, "down", Located::Unavailable).await;
        assert_eq!(failures.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_lookups_of_one_name_ask_once() {
        let clock = ManualClock::new();
        let cache = Arc::new(cache(&clock, 16));
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let mut waiting = Vec::new();
        for _ in 0..8 {
            let (cache, calls, release) =
                (Arc::clone(&cache), Arc::clone(&calls), Arc::clone(&release));
            waiting.push(tokio::spawn(async move {
                cache
                    .locate("prod", || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        release.notified().await;
                        Located::Node(NodeId::new("node-1").unwrap())
                    })
                    .await
            }));
        }
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        release.notify_waiters();
        for waiter in waiting {
            assert_eq!(waiter.await.unwrap(), Located::Node(node()));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_forgotten_node_is_asked_again_and_a_full_table_stops_caching_new_names() {
        let clock = ManualClock::new();
        let cache = cache(&clock, 2);
        let calls = AtomicUsize::new(0);
        counted(&cache, &calls, "prod", Located::Node(node())).await;
        cache.forget("prod", &NodeId::new("other").unwrap());
        counted(&cache, &calls, "prod", Located::Node(node())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        cache.forget("prod", &node());
        counted(&cache, &calls, "prod", Located::Node(node())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let other = AtomicUsize::new(0);
        counted(&cache, &other, "a", Located::Unknown).await;
        assert_eq!(cache.len(), 2);
        counted(&cache, &other, "b", Located::Unknown).await;
        counted(&cache, &other, "b", Located::Unknown).await;
        assert_eq!(other.load(Ordering::SeqCst), 3);
        assert_eq!(cache.len(), 2);
        clock.advance(KUBE_MISS_CACHE);
        counted(&cache, &other, "b", Located::Unknown).await;
        counted(&cache, &other, "b", Located::Unknown).await;
        assert_eq!(other.load(Ordering::SeqCst), 4);
    }
}
