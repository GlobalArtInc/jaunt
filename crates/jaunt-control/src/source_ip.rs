use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::http::HeaderMap;

const IPV6_PREFIX_BITS: u32 = 64;

pub(crate) struct Source {
    pub(crate) address: String,
    pub(crate) network: String,
}

pub(crate) fn source_of(peer: SocketAddr, _headers: &HeaderMap) -> Source {
    let ip = peer.ip().to_canonical();
    Source {
        address: ip.to_string(),
        network: network_of(ip),
    }
}

fn network_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let segments = address.segments();
            let network = Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            );
            format!("{network}/{IPV6_PREFIX_BITS}")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::http::HeaderMap;

    use super::source_of;

    fn key(peer: &str) -> String {
        source_of(peer.parse::<SocketAddr>().unwrap(), &HeaderMap::new()).network
    }

    fn address(peer: &str) -> String {
        source_of(peer.parse::<SocketAddr>().unwrap(), &HeaderMap::new()).address
    }

    #[test]
    fn v4_addresses_are_kept_v4_mapped_ones_are_unwrapped_and_v6_is_reduced_to_its_64_bit_prefix() {
        assert_eq!(key("203.0.113.7:5000"), "203.0.113.7");
        assert_eq!(key("[::ffff:203.0.113.7]:5000"), "203.0.113.7");
        assert_eq!(key("[2001:db8:1:2::1]:5000"), "2001:db8:1:2::/64");
        assert_eq!(
            key("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:5000"),
            "2001:db8:1:2::/64"
        );
        assert_ne!(key("[2001:db8:1:3::1]:5000"), key("[2001:db8:1:2::1]:5000"));
    }

    #[test]
    fn the_exact_peer_address_is_kept_apart_from_the_network_key() {
        assert_eq!(address("203.0.113.7:5000"), "203.0.113.7");
        assert_eq!(address("[::ffff:203.0.113.7]:5000"), "203.0.113.7");
        assert_eq!(address("[2001:db8:1:2::1]:5000"), "2001:db8:1:2::1");
        assert_ne!(
            address("[2001:db8:1:2::1]:5000"),
            address("[2001:db8:1:2::2]:5000")
        );
    }
}
