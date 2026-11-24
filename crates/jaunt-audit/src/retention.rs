use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_store::{Store, StoreError};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::clock::Clock;

pub const PRUNE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
pub const DEFAULT_RETENTION_DAYS: u32 = 365;
pub const MAX_RETENTION_DAYS: u32 = 36_500;

pub const MASS_DELETE_MIN_ROWS: u64 = 10_000;

const PRUNE_BATCH: u32 = 1000;
const MAX_BATCHES_PER_RUN: u32 = 1000;
const LOG_TARGET: &str = "jaunt::daemon";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneOutcome {
    Pruned { removed: u64, capped: bool },
    SkippedFutureCutoff { cutoff_ms: i64, newest_ms: i64 },
    RefusedMassDeletion { total: u64, would_remove: u64 },
}

pub async fn prune_once(
    store: &Store,
    clock: &dyn Clock,
    retention_days: u32,
) -> Result<PruneOutcome, StoreError> {
    prune_with_limits(
        store,
        clock,
        retention_days,
        PRUNE_BATCH,
        MAX_BATCHES_PER_RUN,
    )
    .await
}

pub async fn prune_with_limits(
    store: &Store,
    clock: &dyn Clock,
    retention_days: u32,
    batch_rows: u32,
    max_batches: u32,
) -> Result<PruneOutcome, StoreError> {
    let cutoff_ms = clock.now().minus_days(retention_days).millis();
    let events = store.audit_events();
    let Some(newest_ms) = events.newest_time_ms().await? else {
        return Ok(PruneOutcome::Pruned {
            removed: 0,
            capped: false,
        });
    };
    if cutoff_ms > newest_ms {
        return Ok(PruneOutcome::SkippedFutureCutoff {
            cutoff_ms,
            newest_ms,
        });
    }
    let total = events.count_all().await?;
    let would_remove = events.count_before(cutoff_ms).await?;
    if total > MASS_DELETE_MIN_ROWS && would_remove.saturating_mul(2) > total {
        return Ok(PruneOutcome::RefusedMassDeletion {
            total,
            would_remove,
        });
    }
    let mut removed = 0;
    for _ in 0..max_batches {
        let batch = events.delete_before(cutoff_ms, batch_rows).await?;
        removed += batch;
        if batch < u64::from(batch_rows) {
            return Ok(PruneOutcome::Pruned {
                removed,
                capped: false,
            });
        }
    }
    Ok(PruneOutcome::Pruned {
        removed,
        capped: true,
    })
}

pub struct Pruner {
    task: JoinHandle<()>,
    refused: Arc<AtomicU64>,
}

impl Pruner {
    pub fn spawn(
        store: Store,
        clock: Arc<dyn Clock>,
        retention_days: u32,
        interval: Duration,
    ) -> Pruner {
        let refused = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&refused);
        let task = tokio::spawn(async move {
            loop {
                match prune_once(&store, clock.as_ref(), retention_days).await {
                    Ok(PruneOutcome::Pruned { removed: 0, .. }) => {}
                    Ok(PruneOutcome::Pruned { removed, capped }) => tracing::info!(
                        target: LOG_TARGET,
                        removed,
                        capped,
                        retention_days,
                        "pruned audit events past the retention"
                    ),
                    Ok(PruneOutcome::SkippedFutureCutoff {
                        cutoff_ms,
                        newest_ms,
                    }) => tracing::warn!(
                        target: LOG_TARGET,
                        cutoff_ms,
                        newest_ms,
                        retention_days,
                        "the audit retention cutoff is later than the newest stored event, so \
                         pruning was skipped: check the system clock"
                    ),
                    Ok(PruneOutcome::RefusedMassDeletion {
                        total,
                        would_remove,
                    }) => {
                        let refused_runs = counter.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::error!(
                            target: LOG_TARGET,
                            total,
                            would_remove,
                            retention_days,
                            refused_runs,
                            "the audit retention would remove most of the table, so pruning was \
                             refused: check the system clock"
                        );
                    }
                    Err(error) => tracing::error!(
                        target: LOG_TARGET,
                        error = %error,
                        "pruning the audit events failed"
                    ),
                }
                sleep(interval).await;
            }
        });
        Pruner { task, refused }
    }

    pub fn refused_runs(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use jaunt_store::{AuditQuery, AuditRecord, Store};

    use super::{PruneOutcome, Pruner, prune_once, prune_with_limits};
    use crate::clock::ManualClock;

    const DAY_MS: i64 = 86_400_000;

    fn record(id: &str, time_ms: i64) -> AuditRecord {
        AuditRecord {
            id: id.to_owned(),
            time_ms,
            event_type: "gate.connect".to_owned(),
            actor: "anonymous".to_owned(),
            node: None,
            session_id: None,
            policy_hash: None,
            payload: "{}".to_owned(),
            v: 1,
        }
    }

    async fn store_with_events() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        let now = 100 * DAY_MS;
        let mut batch = vec![
            record("older", now - 31 * DAY_MS),
            record("just-outside", now - 30 * DAY_MS - 1),
            record("boundary", now - 30 * DAY_MS),
            record("recent", now - DAY_MS),
        ];
        batch.extend((0..1500).map(|index| record(&format!("bulk-{index:04}"), 1 + index)));
        store.audit_events().append(&batch).await.unwrap();
        (dir, store)
    }

    async fn remaining(store: &Store) -> Vec<String> {
        store
            .audit_events()
            .query(&AuditQuery::newest(10))
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect()
    }

    async fn count(store: &Store) -> usize {
        let mut total = 0;
        let mut query = AuditQuery::newest(1000);
        loop {
            let page = store.audit_events().query(&query).await.unwrap();
            total += page.len();
            match page.last() {
                Some(last) if page.len() == 1000 => {
                    query.after = Some(jaunt_store::AuditCursor {
                        time_ms: last.time_ms,
                        id: last.id.clone(),
                    });
                }
                _ => return total,
            }
        }
    }

    #[tokio::test]
    async fn events_older_than_the_retention_are_removed_across_batches_and_the_boundary_is_kept() {
        let (_dir, store) = store_with_events().await;
        let clock = ManualClock::new(100 * DAY_MS);

        let outcome = prune_once(&store, &clock, 30).await.unwrap();

        assert_eq!(
            outcome,
            PruneOutcome::Pruned {
                removed: 1502,
                capped: false
            }
        );
        assert_eq!(remaining(&store).await, ["recent", "boundary"]);
        assert_eq!(
            prune_once(&store, &clock, 30).await.unwrap(),
            PruneOutcome::Pruned {
                removed: 0,
                capped: false
            }
        );
    }

    #[tokio::test]
    async fn a_clock_that_jumped_forward_erases_nothing() {
        let (_dir, store) = store_with_events().await;
        let clock = ManualClock::new(100 * DAY_MS);
        clock.advance(5 * 365 * DAY_MS);

        let outcome = prune_once(&store, &clock, 30).await.unwrap();

        assert_eq!(
            outcome,
            PruneOutcome::SkippedFutureCutoff {
                cutoff_ms: 100 * DAY_MS + 5 * 365 * DAY_MS - 30 * DAY_MS,
                newest_ms: 100 * DAY_MS - DAY_MS,
            }
        );
        assert_eq!(count(&store).await, 1504);
    }

    async fn store_with_a_year_of_events(old: i64, recent: i64) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        let now = 1000 * DAY_MS;
        let mut batch: Vec<AuditRecord> = (0..old)
            .map(|index| record(&format!("old-{index:05}"), now - 100 * DAY_MS + index))
            .collect();
        batch.extend((0..recent).map(|index| record(&format!("new-{index:05}"), now - index)));
        store.audit_events().append(&batch).await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn a_clock_that_jumped_forward_while_running_cannot_erase_most_of_a_large_table() {
        let (_dir, store) = store_with_a_year_of_events(11_000, 50).await;
        let clock = ManualClock::new(1000 * DAY_MS);
        clock.advance(2 * 365 * DAY_MS);
        let jumped_newest = 1000 * DAY_MS + 2 * 365 * DAY_MS;
        store
            .audit_events()
            .append(&[record("written-after-the-jump", jumped_newest)])
            .await
            .unwrap();

        let outcome = prune_once(&store, &clock, 365).await.unwrap();

        assert_eq!(
            outcome,
            PruneOutcome::RefusedMassDeletion {
                total: 11_051,
                would_remove: 11_051 - 1
            }
        );
        assert_eq!(store.audit_events().count_all().await.unwrap(), 11_051);
    }

    #[tokio::test]
    async fn a_normal_run_on_a_large_table_removes_its_small_share_and_a_small_table_is_exempt() {
        let (_dir, store) = store_with_a_year_of_events(100, 11_000).await;
        let clock = ManualClock::new(1000 * DAY_MS);

        let outcome = prune_once(&store, &clock, 30).await.unwrap();

        assert_eq!(
            outcome,
            PruneOutcome::Pruned {
                removed: 100,
                capped: false
            }
        );
        assert_eq!(store.audit_events().count_all().await.unwrap(), 11_000);

        let (_small_dir, small) = store_with_a_year_of_events(90, 10).await;
        let everything = prune_once(&small, &clock, 30).await.unwrap();
        assert_eq!(
            everything,
            PruneOutcome::Pruned {
                removed: 90,
                capped: false
            }
        );
    }

    #[tokio::test]
    async fn the_exact_half_is_still_pruned_and_one_more_is_refused() {
        let (_dir, store) = store_with_a_year_of_events(5_500, 5_500).await;
        let clock = ManualClock::new(1000 * DAY_MS);
        let allowed = prune_once(&store, &clock, 30).await.unwrap();
        assert_eq!(
            allowed,
            PruneOutcome::Pruned {
                removed: 5_500,
                capped: false
            }
        );

        let (_other, over) = store_with_a_year_of_events(5_501, 5_500).await;
        let refused = prune_once(&over, &clock, 30).await.unwrap();
        assert!(matches!(refused, PruneOutcome::RefusedMassDeletion { .. }));
    }

    #[tokio::test]
    async fn the_background_pruner_counts_the_runs_it_refuses() {
        let (_dir, store) = store_with_a_year_of_events(11_000, 50).await;
        let clock = Arc::new(ManualClock::new(1000 * DAY_MS + 2 * 365 * DAY_MS));
        store
            .audit_events()
            .append(&[record("fresh", 1000 * DAY_MS + 2 * 365 * DAY_MS)])
            .await
            .unwrap();

        let pruner = Pruner::spawn(store.clone(), clock, 365, Duration::from_secs(3600));
        let deadline = Instant::now() + Duration::from_secs(10);
        while pruner.refused_runs() == 0 {
            assert!(Instant::now() < deadline, "the pruner did not run");
            tokio::task::yield_now().await;
        }
        pruner.stop();

        assert_eq!(store.audit_events().count_all().await.unwrap(), 11_051);
    }

    #[tokio::test]
    async fn pruning_an_empty_table_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();

        let outcome = prune_once(&store, &ManualClock::new(100 * DAY_MS), 30)
            .await
            .unwrap();

        assert_eq!(
            outcome,
            PruneOutcome::Pruned {
                removed: 0,
                capped: false
            }
        );
    }

    #[tokio::test]
    async fn one_run_removes_at_most_the_batch_cap_and_the_next_run_continues() {
        let (_dir, store) = store_with_events().await;
        let clock = ManualClock::new(100 * DAY_MS);

        let first = prune_with_limits(&store, &clock, 30, 400, 2).await.unwrap();
        let second = prune_with_limits(&store, &clock, 30, 400, 2).await.unwrap();

        assert_eq!(
            first,
            PruneOutcome::Pruned {
                removed: 800,
                capped: true
            }
        );
        assert_eq!(
            second,
            PruneOutcome::Pruned {
                removed: 702,
                capped: false
            }
        );
        assert_eq!(count(&store).await, 2);
    }

    #[tokio::test]
    async fn the_background_pruner_runs_at_start_and_can_be_stopped() {
        let (_dir, store) = store_with_events().await;
        let clock = Arc::new(ManualClock::new(100 * DAY_MS));

        let pruner = Pruner::spawn(store.clone(), clock, 30, Duration::from_secs(3600));
        let deadline = Instant::now() + Duration::from_secs(10);
        while count(&store).await > 2 {
            assert!(Instant::now() < deadline, "the pruner did not run");
            tokio::task::yield_now().await;
        }
        pruner.stop();

        assert_eq!(remaining(&store).await, ["recent", "boundary"]);
    }
}
