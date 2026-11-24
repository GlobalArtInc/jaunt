use std::net::IpAddr;
use std::time::Duration;

use thiserror::Error;

use crate::concurrency::{ConcurrencyGuard, ConcurrencyLimiter, Saturated};
use crate::key::ClientKey;
use crate::rate::{Decision, Rate, RateLimiter};

pub const MAX_TRACKED_ADDRESSES: usize = 1 << 22;
pub const MAX_CONCURRENT_PER_ADDRESS: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressLimits {
    pub rate: Rate,
    pub concurrent: usize,
    pub tracked: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AddressLimitsError {
    #[error("the concurrent limit per address must be between 1 and {MAX_CONCURRENT_PER_ADDRESS}")]
    Concurrent,
    #[error("the number of tracked addresses must be between 1 and {MAX_TRACKED_ADDRESSES}")]
    Tracked,
}

impl AddressLimits {
    pub fn validate(&self) -> Result<(), AddressLimitsError> {
        if !(1..=MAX_CONCURRENT_PER_ADDRESS).contains(&self.concurrent) {
            return Err(AddressLimitsError::Concurrent);
        }
        if !(1..=MAX_TRACKED_ADDRESSES).contains(&self.tracked) {
            return Err(AddressLimitsError::Tracked);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Rate { retry_after: Duration },
    Concurrent,
    Table,
}

impl Refused {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Rate { .. } => "rate",
            Self::Concurrent => "concurrent",
            Self::Table => "table_full",
        }
    }
}

pub struct AddressGate {
    rate: RateLimiter<ClientKey>,
    open: ConcurrencyLimiter<ClientKey>,
}

impl AddressGate {
    pub fn new(limits: AddressLimits) -> Self {
        let tracked = limits.tracked.clamp(1, MAX_TRACKED_ADDRESSES);
        Self {
            rate: RateLimiter::new(limits.rate, tracked),
            open: ConcurrencyLimiter::new(limits.concurrent, tracked),
        }
    }

    pub fn admit(&self, ip: IpAddr, now: Duration) -> Result<ConcurrencyGuard<ClientKey>, Refused> {
        let key = ClientKey::of(ip);
        if let Decision::Limited { retry_after } = self.rate.check(&key, now) {
            return Err(Refused::Rate { retry_after });
        }
        self.open
            .try_acquire(key)
            .map_err(|saturated| match saturated {
                Saturated::Key => Refused::Concurrent,
                Saturated::Table => Refused::Table,
            })
    }

    pub fn held(&self, ip: IpAddr) -> usize {
        self.open.held(&ClientKey::of(ip))
    }

    pub fn tracked(&self) -> usize {
        self.rate.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::{AddressGate, AddressLimits, AddressLimitsError, Refused};
    use crate::Rate;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn limits() -> AddressLimits {
        AddressLimits {
            rate: Rate::new(3, 1).unwrap(),
            concurrent: 2,
            tracked: 16,
        }
    }

    #[test]
    fn an_address_is_held_to_its_rate_and_its_concurrent_share_and_others_are_not() {
        let gate = AddressGate::new(limits());
        let now = Duration::from_secs(10);
        let first = gate.admit(ip("192.0.2.1"), now).unwrap();
        let second = gate.admit(ip("::ffff:192.0.2.1"), now).unwrap();
        assert_eq!(
            gate.admit(ip("192.0.2.1"), now).err(),
            Some(Refused::Concurrent)
        );
        assert_eq!(
            gate.admit(ip("192.0.2.1"), now).err(),
            Some(Refused::Rate {
                retry_after: Duration::from_secs(60)
            })
        );
        let elsewhere = gate.admit(ip("192.0.2.2"), now).unwrap();
        assert_eq!(gate.held(ip("192.0.2.1")), 2);
        drop((first, second, elsewhere));
        assert_eq!(gate.held(ip("192.0.2.1")), 0);
        assert!(
            gate.admit(ip("192.0.2.1"), now + Duration::from_secs(60))
                .is_ok()
        );
    }

    #[test]
    fn limits_outside_the_range_are_refused() {
        assert_eq!(limits().validate(), Ok(()));
        assert_eq!(
            AddressLimits {
                concurrent: 0,
                ..limits()
            }
            .validate(),
            Err(AddressLimitsError::Concurrent)
        );
        assert_eq!(
            AddressLimits {
                tracked: 0,
                ..limits()
            }
            .validate(),
            Err(AddressLimitsError::Tracked)
        );
    }
}
