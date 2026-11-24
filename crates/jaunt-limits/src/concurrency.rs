use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Saturated {
    Key,
    Table,
}

struct Shared<K> {
    per_key: usize,
    capacity: usize,
    held: Mutex<HashMap<K, usize>>,
}

impl<K> Shared<K> {
    fn lock(&self) -> MutexGuard<'_, HashMap<K, usize>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub struct ConcurrencyLimiter<K> {
    shared: Arc<Shared<K>>,
}

impl<K> Clone for ConcurrencyLimiter<K> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<K: Hash + Eq + Clone> ConcurrencyLimiter<K> {
    pub fn new(per_key: usize, capacity: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                per_key,
                capacity: capacity.max(1),
                held: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn per_key(&self) -> usize {
        self.shared.per_key
    }

    pub fn try_acquire(&self, key: K) -> Result<ConcurrencyGuard<K>, Saturated> {
        let mut held = self.shared.lock();
        let tracked = held.len();
        match held.get_mut(&key) {
            Some(count) if *count >= self.shared.per_key => return Err(Saturated::Key),
            Some(count) => *count += 1,
            None if self.shared.per_key == 0 => return Err(Saturated::Key),
            None if tracked >= self.shared.capacity => return Err(Saturated::Table),
            None => {
                held.insert(key.clone(), 1);
            }
        }
        drop(held);
        Ok(ConcurrencyGuard {
            shared: Arc::clone(&self.shared),
            key,
        })
    }

    pub fn held(&self, key: &K) -> usize {
        self.shared.lock().get(key).copied().unwrap_or(0)
    }

    pub fn tracked(&self) -> usize {
        self.shared.lock().len()
    }
}

pub struct ConcurrencyGuard<K: Hash + Eq> {
    shared: Arc<Shared<K>>,
    key: K,
}

impl<K: Hash + Eq> ConcurrencyGuard<K> {
    pub fn key(&self) -> &K {
        &self.key
    }
}

impl<K: Hash + Eq + fmt::Debug> fmt::Debug for ConcurrencyGuard<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConcurrencyGuard")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl<K: Hash + Eq> Drop for ConcurrencyGuard<K> {
    fn drop(&mut self) {
        let mut held = self.shared.lock();
        let emptied = match held.get_mut(&self.key) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if emptied {
            held.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::AssertUnwindSafe;

    use super::{ConcurrencyLimiter, Saturated};

    #[test]
    fn each_key_holds_at_most_its_share_and_a_released_guard_frees_a_slot() {
        let limiter = ConcurrencyLimiter::new(2, 16);
        let first = limiter.try_acquire("a").unwrap();
        let second = limiter.try_acquire("a").unwrap();
        assert_eq!(limiter.try_acquire("a").err(), Some(Saturated::Key));
        let other = limiter.try_acquire("b").unwrap();
        assert_eq!(limiter.held(&"a"), 2);

        drop(first);
        assert_eq!(limiter.held(&"a"), 1);
        let third = limiter.try_acquire("a").unwrap();
        drop((second, third, other));
        assert_eq!(limiter.held(&"a"), 0);
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn the_table_refuses_new_keys_when_full_but_not_known_ones() {
        let limiter = ConcurrencyLimiter::new(4, 2);
        let a = limiter.try_acquire(1).unwrap();
        let b = limiter.try_acquire(2).unwrap();
        assert_eq!(limiter.try_acquire(3).err(), Some(Saturated::Table));
        let again = limiter.try_acquire(1).unwrap();
        assert_eq!(limiter.tracked(), 2);
        drop(b);
        let c = limiter.try_acquire(3).unwrap();
        drop((a, again, c));
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn a_zero_share_admits_nobody() {
        let limiter = ConcurrencyLimiter::new(0, 2);
        assert_eq!(limiter.try_acquire(1).err(), Some(Saturated::Key));
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn a_guard_is_released_when_its_holder_panics_and_the_limiter_keeps_working() {
        let limiter = ConcurrencyLimiter::new(1, 4);
        let guard = limiter.try_acquire("a").unwrap();
        let outcome = std::thread::spawn(move || {
            let _held = guard;
            panic!("the holder failed");
        })
        .join();
        assert!(outcome.is_err());
        assert_eq!(limiter.held(&"a"), 0);

        let poisoner = limiter.clone();
        let poisoned = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _lock = poisoner.shared.held.lock().unwrap();
            panic!("poison the table");
        }));
        assert!(poisoned.is_err());
        assert!(limiter.shared.held.is_poisoned());
        let guard = limiter.try_acquire("a").unwrap();
        assert_eq!(limiter.held(&"a"), 1);
        drop(guard);
        assert_eq!(limiter.held(&"a"), 0);
    }
}
