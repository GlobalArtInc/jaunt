use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;

pub const MIN_IPV4_PREFIX: u8 = 8;
pub const MIN_IPV6_PREFIX: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrustedProxyProblem {
    #[error("an IPv4-mapped IPv6 network never matches, write it in the IPv4 form")]
    Ipv4Mapped,
    #[error("a network of prefix length 0 trusts every peer and defeats the proxy check")]
    Everything,
    #[error(
        "the network is too wide to be a proxy fleet (IPv4 needs /{MIN_IPV4_PREFIX} or longer, \
         IPv6 /{MIN_IPV6_PREFIX} or longer) and would trust a large part of the internet"
    )]
    TooWide,
}

pub fn trusted_proxy_problem(network: &IpNet) -> Option<TrustedProxyProblem> {
    if network.prefix_len() == 0 {
        return Some(TrustedProxyProblem::Everything);
    }
    match network {
        IpNet::V6(v6) if v6.network().to_ipv4_mapped().is_some() => {
            Some(TrustedProxyProblem::Ipv4Mapped)
        }
        IpNet::V4(v4) if v4.prefix_len() < MIN_IPV4_PREFIX => Some(TrustedProxyProblem::TooWide),
        IpNet::V6(v6) if v6.prefix_len() < MIN_IPV6_PREFIX => Some(TrustedProxyProblem::TooWide),
        IpNet::V4(_) | IpNet::V6(_) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("trusted proxy network {index}: {problem}")]
pub struct UnusableProxy {
    pub index: usize,
    pub problem: TrustedProxyProblem,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    pub fn new(networks: Vec<IpNet>) -> Result<Self, UnusableProxy> {
        if let Some((index, problem)) = networks.iter().enumerate().find_map(|(index, network)| {
            trusted_proxy_problem(network).map(|problem| (index, problem))
        }) {
            return Err(UnusableProxy { index, problem });
        }
        Ok(Self(networks))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|network| network.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ipnet::IpNet;

    use super::{TrustedProxies, TrustedProxyProblem, UnusableProxy, trusted_proxy_problem};

    fn nets(given: &[&str]) -> Vec<IpNet> {
        given.iter().map(|net| net.parse().unwrap()).collect()
    }

    #[test]
    fn the_trust_check_matches_canonical_peer_addresses() {
        let mixed = TrustedProxies::new(nets(&[
            "10.0.0.0/8",
            "192.0.2.7/32",
            "2001:db8::1/128",
            "fd00::/16",
        ]))
        .unwrap();
        let v4 = TrustedProxies::new(nets(&["10.0.0.0/8"])).unwrap();
        let v6 = TrustedProxies::new(nets(&["fd00::/16"])).unwrap();
        let none = TrustedProxies::default();
        for (proxies, peer, trusted) in [
            (&mixed, "10.1.2.3", true),
            (&mixed, "::ffff:10.1.2.3", true),
            (&mixed, "192.0.2.7", true),
            (&mixed, "192.0.2.8", false),
            (&mixed, "::ffff:192.0.2.8", false),
            (&mixed, "2001:db8::1", true),
            (&mixed, "2001:db8::2", false),
            (&mixed, "fd00:12::1", true),
            (&mixed, "fd12::1", false),
            (&mixed, "11.0.0.1", false),
            (&v4, "fd00::a00:1", false),
            (&v6, "10.0.0.1", false),
            (&none, "10.0.0.1", false),
            (&none, "::1", false),
        ] {
            let peer: IpAddr = peer.parse().unwrap();
            assert_eq!(proxies.contains(peer), trusted, "{peer} in {proxies:?}");
        }
    }

    #[test]
    fn trusted_proxy_networks_that_cannot_work_are_refused() {
        for (network, problem) in [
            ("10.0.0.0/8", None),
            ("2001:db8::/32", None),
            ("0.0.0.0/0", Some(TrustedProxyProblem::Everything)),
            ("::/0", Some(TrustedProxyProblem::Everything)),
            ("::ffff:10.0.0.0/104", Some(TrustedProxyProblem::Ipv4Mapped)),
            ("::ffff:0:0/96", Some(TrustedProxyProblem::Ipv4Mapped)),
            ("0.0.0.0/1", Some(TrustedProxyProblem::TooWide)),
            ("128.0.0.0/1", Some(TrustedProxyProblem::TooWide)),
            ("8.0.0.0/7", Some(TrustedProxyProblem::TooWide)),
            ("::/1", Some(TrustedProxyProblem::TooWide)),
            ("2000::/15", Some(TrustedProxyProblem::TooWide)),
            ("2001::/16", None),
            ("::/64", None),
            ("::/96", None),
            ("192.0.2.7/32", None),
            ("2001:db8::1/128", None),
        ] {
            let parsed: IpNet = network.parse().unwrap();
            assert_eq!(trusted_proxy_problem(&parsed), problem, "{network}");
        }
        assert_eq!(
            TrustedProxies::new(nets(&["10.0.0.0/8", "::/0"])),
            Err(UnusableProxy {
                index: 1,
                problem: TrustedProxyProblem::Everything
            })
        );
    }
}
