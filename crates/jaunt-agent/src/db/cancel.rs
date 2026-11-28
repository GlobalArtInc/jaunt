use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::UNIX_EPOCH;

use jaunt_limits::{Rate, RateLimiter};
use jaunt_pgwire::{BackendKeyData, CancelRequest};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;

use crate::clock::Clock;

const CANCELS_PER_MINUTE: u32 = 10;
const USERS_TRACKED: usize = 10_000;

pub struct CancelTarget {
    pub address: String,
    pub server_name: ServerName<'static>,
    pub config: Arc<ClientConfig>,
}

struct Entry {
    id: u64,
    user_id: String,
    key: BackendKeyData,
    target: Arc<CancelTarget>,
}

#[derive(Default)]
struct Table {
    entries: HashMap<i32, Vec<Entry>>,
    count: usize,
    next_id: u64,
}

pub struct CancelMap {
    table: Mutex<Table>,
    capacity: usize,
    rate: RateLimiter<String>,
    clock: Arc<dyn Clock>,
}

pub struct Found {
    pub key: BackendKeyData,
    pub target: Arc<CancelTarget>,
}

pub struct CancelRegistration {
    map: Arc<CancelMap>,
    process_id: i32,
    id: u64,
}

impl Drop for CancelRegistration {
    fn drop(&mut self) {
        let mut table = self.map.table();
        let mut removed = false;
        if let Some(entries) = table.entries.get_mut(&self.process_id) {
            let before = entries.len();
            entries.retain(|entry| entry.id != self.id);
            removed = entries.len() < before;
            if entries.is_empty() {
                table.entries.remove(&self.process_id);
            }
        }
        if removed {
            table.count = table.count.saturating_sub(1);
        }
    }
}

impl CancelMap {
    pub fn new(capacity: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            table: Mutex::new(Table::default()),
            capacity,
            rate: RateLimiter::new(
                Rate::clamped(CANCELS_PER_MINUTE, CANCELS_PER_MINUTE),
                USERS_TRACKED,
            ),
            clock,
        }
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn register(
        self: &Arc<Self>,
        user_id: &str,
        key: BackendKeyData,
        target: Arc<CancelTarget>,
    ) -> Option<CancelRegistration> {
        let mut table = self.table();
        if table.count >= self.capacity {
            return None;
        }
        table.next_id = table.next_id.wrapping_add(1);
        let id = table.next_id;
        let process_id = key.process_id();
        table.entries.entry(process_id).or_default().push(Entry {
            id,
            user_id: user_id.to_owned(),
            key,
            target,
        });
        table.count += 1;
        Some(CancelRegistration {
            map: Arc::clone(self),
            process_id,
            id,
        })
    }

    pub fn admit(&self, user_id: &str) -> bool {
        let now = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        self.rate.check(&user_id.to_owned(), now).is_allowed()
    }

    pub fn find(&self, user_id: &str, request: &CancelRequest) -> Option<Found> {
        let table = self.table();
        let entries = table.entries.get(&request.process_id())?;
        entries
            .iter()
            .find(|entry| request.matches(&entry.key) && entry.user_id == user_id)
            .map(|entry| Found {
                key: entry.key.clone(),
                target: Arc::clone(&entry.target),
            })
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.table().count
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use jaunt_pgwire::{
        BackendDecoder, BackendKeyData, BackendMessage, CancelRequest, Event, FrontendDecoder,
        FrontendMessage, Limits,
    };
    use rustls::RootCertStore;
    use rustls::pki_types::ServerName;

    use super::{CancelMap, CancelTarget};
    use crate::db::upstream::cancel_config;
    use crate::testkit::ManualClock;

    fn key_data(process_id: i32, key: &[u8]) -> BackendKeyData {
        let mut body = process_id.to_be_bytes().to_vec();
        body.extend_from_slice(key);
        let mut bytes = vec![b'K'];
        bytes.extend(u32::try_from(body.len() + 4).unwrap().to_be_bytes());
        bytes.extend(body);
        let mut decoder = BackendDecoder::new(Limits::default()).unwrap();
        decoder.push(&bytes).unwrap();
        match decoder.next_event().unwrap() {
            Some(Event::Frame(frame)) => match frame.into_message() {
                BackendMessage::BackendKeyData(key) => key,
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }

    fn request(process_id: i32, key: &[u8]) -> CancelRequest {
        let mut bytes = u32::try_from(12 + key.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        bytes.extend(((1234_u32 << 16) | 5678).to_be_bytes());
        bytes.extend(process_id.to_be_bytes());
        bytes.extend_from_slice(key);
        let mut decoder = FrontendDecoder::new(Limits::default()).unwrap();
        decoder.push(&bytes).unwrap();
        match decoder.next_event().unwrap() {
            Some(Event::Frame(frame)) => match frame.into_message() {
                FrontendMessage::Cancel(request) => request,
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }

    fn target() -> Arc<CancelTarget> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(CancelTarget {
            address: "127.0.0.1:5432".to_owned(),
            server_name: ServerName::try_from("db.test").unwrap(),
            config: cancel_config(&provider, &Arc::new(RootCertStore::empty())).unwrap(),
        })
    }

    #[test]
    fn the_map_is_bounded_owned_and_forgets_a_pair_when_its_session_ends() {
        let map = Arc::new(CancelMap::new(2, ManualClock::new(SystemTime::now())));
        let first = map.register("u-1", key_data(7, &[1; 4]), target()).unwrap();
        let second = map.register("u-1", key_data(7, &[2; 4]), target()).unwrap();
        assert!(
            map.register("u-1", key_data(8, &[3; 4]), target())
                .is_none()
        );
        assert!(map.find("u-1", &request(7, &[2; 4])).is_some());
        assert!(map.find("u-2", &request(7, &[2; 4])).is_none());
        assert!(map.find("u-1", &request(7, &[3; 4])).is_none());
        drop(second);
        assert!(map.find("u-1", &request(7, &[2; 4])).is_none());
        assert!(map.find("u-1", &request(7, &[1; 4])).is_some());
        assert_eq!(map.len(), 1);
        drop(first);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn a_user_is_admitted_ten_times_and_then_once_every_six_seconds() {
        let clock = ManualClock::new(SystemTime::now());
        let map = CancelMap::new(4, clock.clone());
        for _ in 0..10 {
            assert!(map.admit("u-1"));
        }
        assert!(!map.admit("u-1"));
        assert!(map.admit("u-2"));
        clock.advance(Duration::from_secs(5));
        assert!(!map.admit("u-1"));
        clock.advance(Duration::from_secs(1));
        assert!(map.admit("u-1"));
        assert!(!map.admit("u-1"));
    }
}
