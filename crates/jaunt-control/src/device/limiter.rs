use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) per_ip: usize,
    pub(crate) per_ip_window_secs: i64,
    pub(crate) max_tracked_ips: usize,
    pub(crate) global: usize,
    pub(crate) global_window_secs: i64,
}

impl Limits {
    pub(crate) const STANDARD: Limits = Limits {
        per_ip: 10,
        per_ip_window_secs: 300,
        max_tracked_ips: 10_000,
        global: 300,
        global_window_secs: 60,
    };
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allowed,
    Limited {
        retry_after_secs: i64,
        newly_locked: bool,
    },
}

#[derive(Default)]
struct Window {
    attempts: VecDeque<i64>,
    lockout_reported: bool,
}

#[derive(Default)]
struct State {
    per_ip: HashMap<IpAddr, Window>,
    global: VecDeque<i64>,
}

pub(crate) struct FailureLimiter {
    limits: Limits,
    state: Mutex<State>,
}

fn tracked_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
}

fn expire(queue: &mut VecDeque<i64>, now: i64, window_secs: i64) {
    while queue
        .front()
        .is_some_and(|at| at.saturating_add(window_secs) <= now)
    {
        queue.pop_front();
    }
}

fn wait_for(oldest: Option<&i64>, now: i64, window_secs: i64) -> i64 {
    oldest.map_or(window_secs, |at| {
        at.saturating_add(window_secs).saturating_sub(now).max(1)
    })
}

impl FailureLimiter {
    pub(crate) fn new(limits: Limits) -> FailureLimiter {
        FailureLimiter {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn admit(&self, ip: IpAddr, now: i64) -> Verdict {
        let key = tracked_key(ip);
        let limits = self.limits;
        let mut guard = self.lock();
        let state = &mut *guard;

        if let Some(window) = state.per_ip.get_mut(&key) {
            expire(&mut window.attempts, now, limits.per_ip_window_secs);
            if window.attempts.len() >= limits.per_ip {
                let newly_locked = !window.lockout_reported;
                window.lockout_reported = true;
                return Verdict::Limited {
                    retry_after_secs: wait_for(
                        window.attempts.front(),
                        now,
                        limits.per_ip_window_secs,
                    ),
                    newly_locked,
                };
            }
            window.lockout_reported = false;
        } else if state.per_ip.len() >= limits.max_tracked_ips {
            prune(&mut state.per_ip, now, limits.per_ip_window_secs);
            if state.per_ip.len() >= limits.max_tracked_ips {
                return Verdict::Limited {
                    retry_after_secs: limits.per_ip_window_secs,
                    newly_locked: false,
                };
            }
        }
        expire(&mut state.global, now, limits.global_window_secs);
        if state.global.len() >= limits.global {
            return Verdict::Limited {
                retry_after_secs: wait_for(state.global.front(), now, limits.global_window_secs),
                newly_locked: false,
            };
        }

        state.global.push_back(now);
        state.per_ip.entry(key).or_default().attempts.push_back(now);
        Verdict::Allowed
    }

    pub(crate) fn refund(&self, ip: IpAddr) {
        let key = tracked_key(ip);
        let mut guard = self.lock();
        let state = &mut *guard;
        if let Some(window) = state.per_ip.get_mut(&key) {
            window.attempts.pop_back();
            if window.attempts.is_empty() {
                state.per_ip.remove(&key);
            }
        }
        state.global.pop_back();
    }

    pub(crate) fn sweep(&self, now: i64) {
        let mut guard = self.lock();
        let state = &mut *guard;
        expire(&mut state.global, now, self.limits.global_window_secs);
        prune(&mut state.per_ip, now, self.limits.per_ip_window_secs);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().per_ip.len()
    }
}

fn prune(per_ip: &mut HashMap<IpAddr, Window>, now: i64, window_secs: i64) {
    per_ip.retain(|_, window| {
        expire(&mut window.attempts, now, window_secs);
        !window.attempts.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{FailureLimiter, Limits, Verdict};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn standard() -> FailureLimiter {
        FailureLimiter::new(Limits::STANDARD)
    }

    fn exhaust(limiter: &FailureLimiter, address: IpAddr, now: i64) {
        for _ in 0..10 {
            assert_eq!(limiter.admit(address, now), Verdict::Allowed);
        }
    }

    #[test]
    fn the_eleventh_failure_inside_five_minutes_is_limited_and_the_window_slides() {
        let limiter = standard();
        let client = ip("203.0.113.9");
        exhaust(&limiter, client, 1_000);

        assert_eq!(
            limiter.admit(client, 1_299),
            Verdict::Limited {
                retry_after_secs: 1,
                newly_locked: true
            }
        );
        assert_eq!(limiter.admit(client, 1_300), Verdict::Allowed);
    }

    #[test]
    fn a_lockout_is_reported_once_per_window() {
        let limiter = standard();
        let client = ip("203.0.113.9");
        exhaust(&limiter, client, 1_000);

        let newly_locked = |at: i64| match limiter.admit(client, at) {
            Verdict::Limited { newly_locked, .. } => newly_locked,
            Verdict::Allowed => panic!("{at} was allowed"),
        };
        assert!(newly_locked(1_001));
        assert!(!newly_locked(1_002));
        assert!(!newly_locked(1_299));

        exhaust(&limiter, client, 1_300);
        assert!(newly_locked(1_301));
        assert!(!newly_locked(1_302));
    }

    #[test]
    fn a_lockout_is_reported_again_after_a_refund_frees_a_slot() {
        let limiter = standard();
        let client = ip("203.0.113.9");
        exhaust(&limiter, client, 1_000);
        assert!(matches!(
            limiter.admit(client, 1_001),
            Verdict::Limited {
                newly_locked: true,
                ..
            }
        ));

        limiter.refund(client);
        assert_eq!(limiter.admit(client, 1_002), Verdict::Allowed);

        assert!(matches!(
            limiter.admit(client, 1_003),
            Verdict::Limited {
                newly_locked: true,
                ..
            }
        ));
    }

    #[test]
    fn refusals_do_not_extend_the_window_and_other_addresses_are_unaffected() {
        let limiter = standard();
        let client = ip("203.0.113.9");
        exhaust(&limiter, client, 1_000);

        for second in 1_001..1_100 {
            assert!(matches!(
                limiter.admit(client, second),
                Verdict::Limited { .. }
            ));
        }
        assert_eq!(limiter.admit(ip("203.0.113.10"), 1_100), Verdict::Allowed);
        assert_eq!(limiter.admit(client, 1_300), Verdict::Allowed);
    }

    #[test]
    fn a_refund_gives_the_attempt_back() {
        let limiter = standard();
        let client = ip("203.0.113.9");
        exhaust(&limiter, client, 1_000);
        assert!(matches!(
            limiter.admit(client, 1_001),
            Verdict::Limited { .. }
        ));

        limiter.refund(client);

        assert_eq!(limiter.admit(client, 1_001), Verdict::Allowed);
    }

    #[test]
    fn addresses_in_one_ipv6_prefix_and_mapped_ipv4_share_a_budget() {
        let limiter = standard();
        for index in 0..10 {
            let address = ip(&format!("2001:db8:1:2:{index}::1"));
            assert_eq!(limiter.admit(address, 1_000), Verdict::Allowed);
        }
        assert!(matches!(
            limiter.admit(ip("2001:db8:1:2:ffff::9"), 1_000),
            Verdict::Limited { .. }
        ));
        assert_eq!(
            limiter.admit(ip("2001:db8:1:3::1"), 1_000),
            Verdict::Allowed
        );

        exhaust(&limiter, ip("198.51.100.4"), 1_000);
        assert!(matches!(
            limiter.admit(ip("::ffff:198.51.100.4"), 1_000),
            Verdict::Limited { .. }
        ));
    }

    #[test]
    fn three_hundred_failures_in_a_minute_limit_everybody_until_the_minute_passes() {
        let limiter = standard();
        for index in 0..300_u32 {
            let address = ip(&format!("10.{}.{}.1", index / 250, index % 250));
            assert_eq!(limiter.admit(address, 2_000), Verdict::Allowed);
        }

        assert_eq!(
            limiter.admit(ip("192.0.2.1"), 2_059),
            Verdict::Limited {
                retry_after_secs: 1,
                newly_locked: false
            }
        );
        assert_eq!(limiter.admit(ip("192.0.2.1"), 2_060), Verdict::Allowed);
    }

    #[test]
    fn a_full_table_forgets_stale_addresses_before_it_refuses_new_ones() {
        let limiter = FailureLimiter::new(Limits {
            max_tracked_ips: 2,
            ..Limits::STANDARD
        });
        assert_eq!(limiter.admit(ip("192.0.2.1"), 100), Verdict::Allowed);
        assert_eq!(limiter.admit(ip("192.0.2.2"), 200), Verdict::Allowed);

        assert_eq!(
            limiter.admit(ip("192.0.2.3"), 250),
            Verdict::Limited {
                retry_after_secs: 300,
                newly_locked: false
            }
        );
        assert_eq!(limiter.admit(ip("192.0.2.1"), 250), Verdict::Allowed);
        assert_eq!(limiter.admit(ip("192.0.2.3"), 500), Verdict::Allowed);
        assert_eq!(limiter.tracked(), 2);
    }

    #[test]
    fn sweeping_drops_addresses_whose_failures_all_expired() {
        let limiter = standard();
        limiter.admit(ip("192.0.2.1"), 100);
        limiter.admit(ip("192.0.2.2"), 350);

        limiter.sweep(400);

        assert_eq!(limiter.tracked(), 1);
    }
}
