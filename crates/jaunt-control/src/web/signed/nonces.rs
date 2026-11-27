use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) const MAX_NONCES: usize = 32_768;
pub(crate) const MAX_NONCES_PER_KEY: usize = 256;
pub(crate) const MAX_NONCES_PER_USER: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceRefusal {
    Replayed,
    KeyFull { retry_after: i64 },
    UserFull { retry_after: i64 },
    Full { retry_after: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) total: usize,
    pub(crate) per_key: usize,
    pub(crate) per_user: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    expires_at: i64,
    serial: i64,
    nonce: String,
    user_id: String,
}

#[derive(Default)]
struct State {
    seen: HashSet<(i64, String)>,
    by_expiry: BTreeSet<Entry>,
    per_key: HashMap<i64, usize>,
    per_user: HashMap<String, usize>,
}

fn decrement<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, usize>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

impl State {
    fn purge(&mut self, now: i64) {
        while self
            .by_expiry
            .first()
            .is_some_and(|entry| entry.expires_at < now)
        {
            let Some(entry) = self.by_expiry.pop_first() else {
                break;
            };
            self.seen.remove(&(entry.serial, entry.nonce));
            decrement(&mut self.per_key, &entry.serial);
            decrement(&mut self.per_user, &entry.user_id);
        }
    }

    fn wait(&self, now: i64, matches: impl Fn(&Entry) -> bool) -> i64 {
        self.by_expiry
            .iter()
            .find(|entry| matches(entry))
            .map_or(1, |entry| {
                entry.expires_at.saturating_sub(now).saturating_add(1)
            })
            .max(1)
    }
}

pub(crate) struct NonceCache {
    state: Mutex<State>,
    limits: Limits,
}

impl Default for NonceCache {
    fn default() -> NonceCache {
        NonceCache::with_limits(Limits {
            total: MAX_NONCES,
            per_key: MAX_NONCES_PER_KEY,
            per_user: MAX_NONCES_PER_USER,
        })
    }
}

impl NonceCache {
    pub(crate) fn with_limits(limits: Limits) -> NonceCache {
        NonceCache {
            state: Mutex::new(State::default()),
            limits,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn admit(
        &self,
        user_id: &str,
        serial: i64,
        nonce: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<(), NonceRefusal> {
        let mut state = self.lock();
        state.purge(now);
        let key = (serial, nonce.to_owned());
        if state.seen.contains(&key) {
            return Err(NonceRefusal::Replayed);
        }
        if state.per_key.get(&serial).copied().unwrap_or(0) >= self.limits.per_key {
            let retry_after = state.wait(now, |entry| entry.serial == serial);
            return Err(NonceRefusal::KeyFull { retry_after });
        }
        if state.per_user.get(user_id).copied().unwrap_or(0) >= self.limits.per_user {
            let retry_after = state.wait(now, |entry| entry.user_id == user_id);
            return Err(NonceRefusal::UserFull { retry_after });
        }
        if state.seen.len() >= self.limits.total {
            let retry_after = state.wait(now, |_| true);
            return Err(NonceRefusal::Full { retry_after });
        }
        state.by_expiry.insert(Entry {
            expires_at,
            serial,
            nonce: key.1.clone(),
            user_id: user_id.to_owned(),
        });
        state.seen.insert(key);
        *state.per_key.entry(serial).or_insert(0) += 1;
        *state.per_user.entry(user_id.to_owned()).or_insert(0) += 1;
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        let state = self.lock();
        assert_eq!(state.seen.len(), state.by_expiry.len());
        assert_eq!(state.per_key.values().sum::<usize>(), state.seen.len());
        assert_eq!(state.per_user.values().sum::<usize>(), state.seen.len());
        state.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Limits, MAX_NONCES, MAX_NONCES_PER_KEY, MAX_NONCES_PER_USER, NonceCache, NonceRefusal,
    };

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn a_nonce_is_refused_until_its_window_closes_and_then_forgotten() {
        let cache = NonceCache::default();
        assert_eq!(cache.admit("u", 7, "n-1", NOW + 120, NOW), Ok(()));
        assert_eq!(
            cache.admit("u", 7, "n-1", NOW + 120, NOW + 1),
            Err(NonceRefusal::Replayed)
        );
        assert_eq!(
            cache.admit("u", 7, "n-1", NOW + 240, NOW + 120),
            Err(NonceRefusal::Replayed)
        );
        assert_eq!(cache.admit("v", 8, "n-1", NOW + 120, NOW), Ok(()));
        assert_eq!(cache.len(), 2);

        assert_eq!(cache.admit("w", 9, "n-2", NOW + 241, NOW + 121), Ok(()));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.admit("u", 7, "n-1", NOW + 241, NOW + 121), Ok(()));
    }

    #[test]
    fn one_key_and_one_user_cannot_fill_the_cache_and_a_full_cache_refuses_instead_of_forgetting() {
        let cache = NonceCache::with_limits(Limits {
            total: 5,
            per_key: 2,
            per_user: 3,
        });
        assert_eq!(cache.admit("u", 1, "a", NOW + 10, NOW), Ok(()));
        assert_eq!(cache.admit("u", 1, "b", NOW + 12, NOW), Ok(()));
        assert_eq!(
            cache.admit("u", 1, "c", NOW + 10, NOW),
            Err(NonceRefusal::KeyFull { retry_after: 11 })
        );
        assert_eq!(cache.admit("u", 2, "a", NOW + 20, NOW), Ok(()));
        assert_eq!(
            cache.admit("u", 3, "a", NOW + 20, NOW),
            Err(NonceRefusal::UserFull { retry_after: 11 })
        );
        assert_eq!(cache.admit("v", 4, "a", NOW + 30, NOW), Ok(()));
        assert_eq!(cache.admit("w", 5, "a", NOW + 30, NOW), Ok(()));
        assert_eq!(
            cache.admit("x", 6, "a", NOW + 30, NOW),
            Err(NonceRefusal::Full { retry_after: 11 })
        );
        assert_eq!(
            cache.admit("u", 1, "a", NOW + 10, NOW),
            Err(NonceRefusal::Replayed)
        );
        assert_eq!(cache.len(), 5);

        assert_eq!(cache.admit("u", 3, "a", NOW + 40, NOW + 11), Ok(()));
        assert_eq!(cache.admit("x", 6, "a", NOW + 40, NOW + 13), Ok(()));
        assert_eq!(cache.len(), 5);
    }

    #[test]
    fn the_default_bounds_fit_the_window() {
        assert_eq!(MAX_NONCES_PER_KEY, 256);
        assert_eq!(MAX_NONCES_PER_USER, 2 * MAX_NONCES_PER_KEY);
        assert_eq!(MAX_NONCES, 64 * MAX_NONCES_PER_USER);
    }
}
