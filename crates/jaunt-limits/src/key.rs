use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

pub const IPV6_PREFIX_BITS: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientKey(IpAddr);

impl ClientKey {
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                Self(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            v4 => Self(v4),
        }
    }

    pub fn network(self) -> IpAddr {
        self.0
    }
}

impl From<IpAddr> for ClientKey {
    fn from(ip: IpAddr) -> Self {
        Self::of(ip)
    }
}

impl fmt::Display for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(v4) => write!(f, "{v4}"),
            IpAddr::V6(v6) => write!(f, "{v6}/{IPV6_PREFIX_BITS}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::ClientKey;

    fn key(text: &str) -> ClientKey {
        ClientKey::of(text.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn ipv4_stays_whole_mapped_ipv4_is_unwrapped_and_ipv6_is_cut_to_its_64_bit_prefix() {
        for (given, shown) in [
            ("203.0.113.7", "203.0.113.7"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
            ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
            ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"),
            ("::1", "::/64"),
            ("::", "::/64"),
        ] {
            assert_eq!(key(given).to_string(), shown, "{given}");
        }
        assert_eq!(key("::ffff:203.0.113.7"), key("203.0.113.7"));
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:3::1"), key("2001:db8:1:2::1"));
        assert_ne!(key("203.0.113.7"), key("203.0.113.8"));
        assert_eq!(
            key("2001:db8:1:2::1").network(),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
    }
}
