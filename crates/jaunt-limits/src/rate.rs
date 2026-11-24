use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use thiserror::Error;

pub const MAX_BURST: u32 = 1_000_000;
pub const MAX_PER_MINUTE: u32 = 6_000_000;
pub const DEFAULT_CAPACITY: usize = 65_536;

const MINUTE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RateError {
    #[error("burst must be between 1 and {MAX_BURST}")]
    Burst,
    #[error("per_minute must be between 1 and {MAX_PER_MINUTE}")]
    PerMinute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    burst: u32,
    per_minute: u32,
}

impl Rate {
    pub const fn new(burst: u32, per_minute: u32) -> Result<Self, RateError> {
        if burst == 0 || burst > MAX_BURST {
            return Err(RateError::Burst);
        }
        if per_minute == 0 || per_minute > MAX_PER_MINUTE {
            return Err(RateError::PerMinute);
        }
        Ok(Self { burst, per_minute })
    }

    pub const fn clamped(burst: u32, per_minute: u32) -> Self {
        Self {
            burst: clamp(burst, MAX_BURST),
            per_minute: clamp(per_minute, MAX_PER_MINUTE),
        }
    }

    pub const fn burst(self) -> u32 {
        self.burst
    }

    pub const fn per_minute(self) -> u32 {
        self.per_minute
    }

    fn interval(self) -> Duration {
        MINUTE / self.per_minute
    }

    fn tolerance(self) -> Duration {
        self.interval().saturating_mul(self.burst.saturating_sub(1))
    }
}

const fn clamp(value: u32, max: u32) -> u32 {
    if value == 0 {
        1
    } else if value > max {
        max
    } else {
        value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Limited { retry_after: Duration },
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

struct Slot {
    ready_at: Duration,
    touched: u64,
}

struct Table<K> {
    slots: HashMap<K, Slot>,
    idle_order: BTreeMap<u64, K>,
    stamp: u64,
}

impl<K: Hash + Eq + Clone> Table<K> {
    fn evict_oldest(&mut self) -> bool {
        match self.idle_order.pop_first() {
            Some((_, key)) => {
                self.slots.remove(&key);
                true
            }
            None => false,
        }
    }
}

pub struct RateLimiter<K> {
    rate: Rate,
    capacity: usize,
    table: Mutex<Table<K>>,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    pub fn new(rate: Rate, capacity: usize) -> Self {
        Self {
            rate,
            capacity: capacity.max(1),
            table: Mutex::new(Table {
                slots: HashMap::new(),
                idle_order: BTreeMap::new(),
                stamp: 0,
            }),
        }
    }

    pub fn rate(&self) -> Rate {
        self.rate
    }

    pub fn check(&self, key: &K, now: Duration) -> Decision {
        let interval = self.rate.interval();
        let tolerance = self.rate.tolerance();
        let mut guard = self.lock();
        let table = &mut *guard;
        table.stamp = table.stamp.wrapping_add(1);
        let touched = table.stamp;
        let previous = match table.slots.get(key) {
            Some(slot) => {
                let ready_at = slot.ready_at;
                table.idle_order.remove(&slot.touched);
                Some(ready_at)
            }
            None => {
                while table.slots.len() >= self.capacity && table.evict_oldest() {}
                None
            }
        };
        let ready_at = previous.map_or(now, |ready_at| ready_at.max(now));
        let wait = ready_at.saturating_sub(now);
        let (decision, stored) = if wait > tolerance {
            (
                Decision::Limited {
                    retry_after: wait.saturating_sub(tolerance),
                },
                ready_at,
            )
        } else {
            (Decision::Allowed, ready_at.saturating_add(interval))
        };
        table.slots.insert(
            key.clone(),
            Slot {
                ready_at: stored,
                touched,
            },
        );
        table.idle_order.insert(touched, key.clone());
        decision
    }

    pub fn sweep(&self, now: Duration) -> usize {
        let mut guard = self.lock();
        let table = &mut *guard;
        let before = table.slots.len();
        let Table {
            slots, idle_order, ..
        } = table;
        slots.retain(|_, slot| {
            let keep = slot.ready_at > now;
            if !keep {
                idle_order.remove(&slot.touched);
            }
            keep
        });
        before - slots.len()
    }

    pub fn len(&self) -> usize {
        self.lock().slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, Table<K>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::{Decision, MAX_BURST, MAX_PER_MINUTE, Rate, RateError, RateLimiter};
    use crate::ClientKey;

    fn secs(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    fn limited(retry_after: Duration) -> Decision {
        Decision::Limited { retry_after }
    }

    #[test]
    fn a_full_bucket_lets_the_burst_through_and_then_tells_when_the_next_token_is_due() {
        let limiter = RateLimiter::new(Rate::new(3, 6).unwrap(), 16);
        for _ in 0..3 {
            assert_eq!(limiter.check(&"a", secs(100)), Decision::Allowed);
        }
        assert_eq!(limiter.check(&"a", secs(100)), limited(secs(10)));
        assert_eq!(limiter.check(&"a", secs(104)), limited(secs(6)));
        assert_eq!(limiter.check(&"b", secs(104)), Decision::Allowed);
        assert_eq!(limiter.check(&"a", secs(110)), Decision::Allowed);
        assert_eq!(limiter.check(&"a", secs(110)), limited(secs(10)));
    }

    #[test]
    fn tokens_refill_at_the_rate_up_to_the_burst_and_no_further() {
        let limiter = RateLimiter::new(Rate::new(2, 60).unwrap(), 16);
        assert!(limiter.check(&1, secs(0)).is_allowed());
        assert!(limiter.check(&1, secs(0)).is_allowed());
        assert!(!limiter.check(&1, secs(0)).is_allowed());
        assert!(limiter.check(&1, secs(1)).is_allowed());
        assert!(!limiter.check(&1, secs(1)).is_allowed());

        assert!(limiter.check(&1, secs(3_600)).is_allowed());
        assert!(limiter.check(&1, secs(3_600)).is_allowed());
        assert_eq!(limiter.check(&1, secs(3_600)), limited(secs(1)));
    }

    #[test]
    fn refusals_do_not_push_the_next_token_further_away() {
        let limiter = RateLimiter::new(Rate::new(1, 1).unwrap(), 16);
        assert!(limiter.check(&1, secs(0)).is_allowed());
        for second in 1..60 {
            assert_eq!(limiter.check(&1, secs(second)), limited(secs(60 - second)));
        }
        assert!(limiter.check(&1, secs(60)).is_allowed());
    }

    #[test]
    fn a_clock_that_goes_back_refills_nothing_and_does_not_panic() {
        let limiter = RateLimiter::new(Rate::new(1, 1).unwrap(), 16);
        assert!(limiter.check(&1, secs(1_000)).is_allowed());
        assert_eq!(limiter.check(&1, secs(10)), limited(secs(1_050)));
        assert_eq!(limiter.check(&1, Duration::ZERO), limited(secs(1_060)));
        assert!(limiter.check(&1, secs(1_060)).is_allowed());
    }

    #[test]
    fn a_full_table_forgets_the_key_idle_for_the_longest_time() {
        let limiter = RateLimiter::new(Rate::new(1, 1).unwrap(), 2);
        assert!(limiter.check(&"a", secs(0)).is_allowed());
        assert!(limiter.check(&"b", secs(1)).is_allowed());
        assert!(!limiter.check(&"a", secs(2)).is_allowed());

        assert!(limiter.check(&"c", secs(3)).is_allowed());
        assert_eq!(limiter.len(), 2);
        assert!(!limiter.check(&"a", secs(4)).is_allowed());
        assert!(!limiter.check(&"c", secs(4)).is_allowed());
        assert_eq!(limiter.len(), 2);
        assert!(limiter.check(&"b", secs(5)).is_allowed());
        assert!(limiter.check(&"a", secs(5)).is_allowed());
    }

    #[test]
    fn a_million_distinct_addresses_never_grow_the_table_past_its_capacity() {
        let capacity = 4_096;
        let limiter = RateLimiter::new(Rate::new(1, 1).unwrap(), capacity);
        for index in 0..1_000_000_u32 {
            let ip = if index % 2 == 0 {
                IpAddr::V4(Ipv4Addr::from(index))
            } else {
                IpAddr::V6(Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    u16::try_from(index >> 16).unwrap(),
                    u16::try_from(index & 0xffff).unwrap(),
                    0,
                    0,
                    0,
                    1,
                ))
            };
            assert!(limiter.check(&ClientKey::of(ip), secs(10)).is_allowed());
            assert!(limiter.len() <= capacity);
        }
        assert_eq!(limiter.len(), capacity);
        assert_eq!(limiter.table.lock().unwrap().idle_order.len(), capacity);
    }

    #[test]
    fn sweeping_drops_only_keys_whose_bucket_is_full_again() {
        let limiter = RateLimiter::new(Rate::new(2, 2).unwrap(), 16);
        limiter.check(&"spent", secs(100));
        limiter.check(&"spent", secs(100));
        limiter.check(&"once", secs(100));
        limiter.check(&"recent", secs(105));

        assert_eq!(limiter.sweep(secs(129)), 0);
        assert_eq!(limiter.sweep(secs(130)), 1);
        assert_eq!(limiter.len(), 2);
        assert_eq!(limiter.sweep(secs(200)), 2);
        assert!(limiter.is_empty());
        assert!(limiter.table.lock().unwrap().idle_order.is_empty());
    }

    #[test]
    fn rates_outside_the_supported_range_are_refused_or_clamped() {
        assert_eq!(Rate::new(0, 1), Err(RateError::Burst));
        assert_eq!(Rate::new(MAX_BURST + 1, 1), Err(RateError::Burst));
        assert_eq!(Rate::new(1, 0), Err(RateError::PerMinute));
        assert_eq!(Rate::new(1, MAX_PER_MINUTE + 1), Err(RateError::PerMinute));
        assert_eq!(
            Rate::new(MAX_BURST, MAX_PER_MINUTE).unwrap(),
            Rate::clamped(u32::MAX, u32::MAX)
        );
        assert_eq!(Rate::clamped(0, 0), Rate::new(1, 1).unwrap());
        let fastest = RateLimiter::new(Rate::new(MAX_BURST, MAX_PER_MINUTE).unwrap(), 1);
        assert!(fastest.check(&1, Duration::MAX).is_allowed());
        assert!(fastest.check(&1, Duration::MAX).is_allowed());
    }
}
