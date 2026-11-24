use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::completion;

struct Held<B> {
    hash: String,
    bound: B,
    expires_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IssueError {
    Full,
    Entropy,
}

pub(crate) struct TokenBook<B> {
    capacity: usize,
    entries: Mutex<HashMap<String, Held<B>>>,
}

impl<B> TokenBook<B> {
    pub(crate) fn new(capacity: usize) -> TokenBook<B> {
        TokenBook {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn issue(
        &self,
        login_id: &str,
        bound: B,
        expires_at: i64,
        now: i64,
    ) -> Result<String, IssueError> {
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(login_id) {
            entries.retain(|_, held| held.expires_at > now);
            if entries.len() >= self.capacity {
                return Err(IssueError::Full);
            }
        }
        let issued = completion::issue().map_err(|_| IssueError::Entropy)?;
        entries.insert(
            login_id.to_owned(),
            Held {
                hash: issued.hash,
                bound,
                expires_at,
            },
        );
        Ok(issued.secret)
    }

    pub(crate) fn redeem(&self, login_id: &str, presented: &str, now: i64) -> Option<B> {
        let mut entries = self.lock();
        let held = entries.get(login_id)?;
        if held.expires_at <= now {
            entries.remove(login_id);
            return None;
        }
        if !completion::matches(Some(presented), &held.hash) {
            return None;
        }
        entries.remove(login_id).map(|held| held.bound)
    }

    pub(crate) fn sweep(&self, now: i64) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, held| held.expires_at > now);
        before - entries.len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Held<B>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::{IssueError, TokenBook};

    #[test]
    fn a_token_redeems_once_and_returns_what_it_was_bound_to() {
        let book = TokenBook::new(4);
        let token = book.issue("login-a", "user-1", 100, 0).unwrap();

        assert_eq!(book.redeem("login-a", &token, 1), Some("user-1"));
        assert_eq!(book.redeem("login-a", &token, 1), None);
    }

    #[test]
    fn a_wrong_token_or_another_login_is_refused_without_burning_the_real_one() {
        let book = TokenBook::new(4);
        let first = book.issue("login-a", (), 100, 0).unwrap();
        let second = book.issue("login-b", (), 100, 0).unwrap();

        assert_eq!(book.redeem("login-a", &second, 1), None);
        assert_eq!(book.redeem("login-b", &first, 1), None);
        assert_eq!(book.redeem("login-a", "", 1), None);
        assert_eq!(book.redeem("login-a", &first[1..], 1), None);
        assert_eq!(book.redeem("login-c", &first, 1), None);
        assert_eq!(book.redeem("login-a", &first, 1), Some(()));
        assert_eq!(book.redeem("login-b", &second, 1), Some(()));
    }

    #[test]
    fn a_token_stops_working_at_the_expiry_of_its_request() {
        let book = TokenBook::new(4);
        let token = book.issue("login-a", (), 100, 0).unwrap();
        let late = book.issue("login-b", (), 100, 0).unwrap();

        assert_eq!(book.redeem("login-b", &late, 99), Some(()));
        assert_eq!(book.redeem("login-a", &token, 100), None);
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn issuing_again_for_a_login_replaces_the_earlier_token() {
        let book = TokenBook::new(1);
        let first = book.issue("login-a", (), 100, 0).unwrap();
        let second = book.issue("login-a", (), 100, 0).unwrap();

        assert_ne!(first, second);
        assert_eq!(book.redeem("login-a", &first, 1), None);
        assert_eq!(book.redeem("login-a", &second, 1), Some(()));
    }

    #[test]
    fn a_full_book_sweeps_expired_entries_before_it_refuses() {
        let book = TokenBook::new(2);
        book.issue("login-a", (), 10, 0).unwrap();
        book.issue("login-b", (), 100, 0).unwrap();

        assert_eq!(
            book.issue("login-c", (), 100, 5).err(),
            Some(IssueError::Full)
        );
        assert!(book.issue("login-c", (), 100, 10).is_ok());
        assert_eq!(book.len(), 2);
        assert_eq!(book.sweep(100), 2);
        assert_eq!(book.len(), 0);
    }
}
