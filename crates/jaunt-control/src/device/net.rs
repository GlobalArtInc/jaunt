use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderName, header};
use jaunt_limits::{LogThrottle, TrustedProxies};

const IGNORED_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientAddress(pub(crate) IpAddr);

pub(crate) struct ClientIp {
    header: Option<HeaderName>,
    proxies: TrustedProxies,
    ignored: AtomicU64,
    ignored_log: LogThrottle,
    origin: Instant,
}

impl ClientIp {
    pub(crate) fn new(header: Option<HeaderName>, proxies: TrustedProxies) -> ClientIp {
        ClientIp {
            header,
            proxies,
            ignored: AtomicU64::new(0),
            ignored_log: LogThrottle::new(IGNORED_LOG_INTERVAL),
            origin: Instant::now(),
        }
    }

    pub(crate) fn trusted_proxies(&self) -> &TrustedProxies {
        &self.proxies
    }

    #[cfg(test)]
    pub(crate) fn ignored(&self) -> u64 {
        self.ignored.load(Ordering::Relaxed)
    }

    pub(crate) fn resolve(&self, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
        let peer = peer.ip().to_canonical();
        let Some(name) = &self.header else {
            return peer;
        };
        if !self.proxies.contains(peer) {
            if headers.contains_key(name) {
                self.report_ignored(peer);
            }
            return peer;
        }
        forwarded_address(headers, name, &self.proxies).unwrap_or(peer)
    }

    fn report_ignored(&self, peer: IpAddr) {
        let total = self
            .ignored
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if let Some(suppressed) = self.ignored_log.admit(self.origin.elapsed()) {
            tracing::info!(
                target: "jaunt::audit",
                event = "http.client_ip_header_ignored",
                peer_addr = %peer,
                total,
                suppressed
            );
        }
    }
}

fn forwarded_address(
    headers: &HeaderMap,
    name: &HeaderName,
    proxies: &TrustedProxies,
) -> Option<IpAddr> {
    let mut elements = Vec::new();
    for value in headers.get_all(name) {
        elements.extend(value.to_str().ok()?.split(','));
    }
    let mut leftmost = None;
    for element in elements.iter().rev() {
        let ip = element.trim().parse::<IpAddr>().ok()?.to_canonical();
        if !proxies.contains(ip) {
            return Some(ip);
        }
        leftmost = Some(ip);
    }
    leftmost
}

pub(crate) fn origin_allowed(headers: &HeaderMap, public_origin: &str) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    match (values.next(), values.next()) {
        (None, _) => true,
        (Some(value), None) => value.as_bytes() == public_origin.as_bytes(),
        (Some(_), Some(_)) => false,
    }
}

pub(crate) fn is_valid_origin(text: &str) -> bool {
    let Some(host) = text.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'?' && byte != b'#')
        && !host.contains('@')
}

pub(crate) fn is_canonical_origin(text: &str) -> bool {
    let Some(authority) = text.strip_prefix("https://") else {
        return false;
    };
    if authority.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return false;
    }
    let port = if authority.starts_with('[') {
        authority.rsplit_once("]:").map(|(_, port)| port)
    } else if authority.matches(':').count() > 1 {
        return false;
    } else {
        authority.rsplit_once(':').map(|(_, port)| port)
    };
    port.is_none_or(|port| {
        port.parse::<u16>()
            .is_ok_and(|number| number != 443 && number.to_string() == port)
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use jaunt_limits::TrustedProxies;

    use super::{ClientIp, is_canonical_origin, is_valid_origin, origin_allowed};

    const PROXY: &str = "198.51.100.7:40000";
    const STRANGER: &str = "203.0.113.200:40000";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn client_ip(configured: Option<&'static str>) -> ClientIp {
        let proxies = TrustedProxies::new(vec![
            "198.51.100.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ])
        .unwrap();
        ClientIp::new(configured.map(HeaderName::from_static), proxies)
    }

    fn resolve_from(
        peer: &str,
        configured: Option<&'static str>,
        pairs: &[(&'static str, &str)],
    ) -> IpAddr {
        let peer: SocketAddr = peer.parse().unwrap();
        client_ip(configured).resolve(&headers(pairs), peer)
    }

    fn resolve(configured: Option<&'static str>, pairs: &[(&'static str, &str)]) -> IpAddr {
        resolve_from(PROXY, configured, pairs)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn without_a_configured_header_the_peer_is_used_whatever_the_request_claims() {
        let forged = [
            ("x-forwarded-for", "203.0.113.1"),
            ("x-real-ip", "203.0.113.2"),
        ];
        assert_eq!(resolve(None, &forged), ip("198.51.100.7"));
    }

    #[test]
    fn a_header_from_a_peer_outside_the_trusted_networks_is_ignored_and_counted() {
        let resolver = client_ip(Some("x-forwarded-for"));
        let stranger: SocketAddr = STRANGER.parse().unwrap();
        let forged = headers(&[("x-forwarded-for", "192.0.2.1")]);
        for _ in 0..3 {
            assert_eq!(resolver.resolve(&forged, stranger), ip("203.0.113.200"));
        }
        assert_eq!(
            resolver.resolve(&headers(&[]), stranger),
            ip("203.0.113.200")
        );
        assert_eq!(resolver.ignored(), 3);
        let proxy: SocketAddr = PROXY.parse().unwrap();
        assert_eq!(resolver.resolve(&forged, proxy), ip("192.0.2.1"));
        assert_eq!(resolver.ignored(), 3);
    }

    #[test]
    fn the_walk_skips_trusted_hops_from_the_right_and_takes_the_first_stranger() {
        let name = Some("x-forwarded-for");
        for (lines, expected) in [
            (vec!["203.0.113.1, 10.0.0.1, 203.0.113.50"], "203.0.113.50"),
            (
                vec!["203.0.113.1, 203.0.113.50, 10.0.0.1, 10.0.0.2"],
                "203.0.113.50",
            ),
            (vec!["203.0.113.1", "192.0.2.4, 192.0.2.5"], "192.0.2.5"),
            (vec!["192.0.2.4", "10.0.0.9", "198.51.100.3"], "192.0.2.4"),
            (vec!["10.0.0.5, 10.0.0.6"], "10.0.0.5"),
            (vec!["2001:db8::1"], "2001:db8::1"),
            (vec!["::ffff:192.0.2.9"], "192.0.2.9"),
            (vec!["192.0.2.4, ::ffff:10.0.0.9"], "192.0.2.4"),
        ] {
            let pairs: Vec<(&'static str, &str)> = lines
                .iter()
                .map(|line| ("x-forwarded-for", *line))
                .collect();
            assert_eq!(resolve(name, &pairs), ip(expected), "{lines:?}");
        }
        assert_eq!(
            resolve(Some("x-real-ip"), &[("x-real-ip", " 192.0.2.8 ")]),
            ip("192.0.2.8")
        );
    }

    #[test]
    fn a_missing_or_invalid_value_falls_back_to_the_peer() {
        let name = Some("x-forwarded-for");
        let peer = ip("198.51.100.7");
        assert_eq!(resolve(name, &[]), peer);
        for value in [
            "",
            "not an address",
            "192.0.2.1:8080",
            "[2001:db8::1]",
            "192.0.2.1,",
            "192.0.2.1, unknown",
            "unknown, 10.0.0.1",
            "192.0.2.256",
            "0192.0.2.1",
        ] {
            assert_eq!(
                resolve(name, &[("x-forwarded-for", value)]),
                peer,
                "{value}"
            );
        }
    }

    #[test]
    fn an_origin_header_is_optional_but_must_match_exactly_when_present() {
        let origin = "https://jaunt.example";
        assert!(origin_allowed(&headers(&[]), origin));
        assert!(origin_allowed(&headers(&[("origin", origin)]), origin));
        for value in [
            "https://evil.example",
            "null",
            "http://jaunt.example",
            "https://jaunt.example:8443",
            "https://jaunt.example/",
            "https://JAUNT.example",
            "",
        ] {
            assert!(
                !origin_allowed(&headers(&[("origin", value)]), origin),
                "{value}"
            );
        }
        let doubled = headers(&[("origin", origin), ("origin", origin)]);
        assert!(!origin_allowed(&doubled, origin));
    }

    #[test]
    fn a_public_origin_is_a_bare_https_authority() {
        for good in [
            "https://jaunt.example",
            "https://jaunt.example:8443",
            "https://[::1]:8443",
        ] {
            assert!(is_valid_origin(good), "{good}");
        }
        for bad in [
            "",
            "https://",
            "http://jaunt.example",
            "jaunt.example",
            "https://jaunt.example/",
            "https://jaunt.example/path",
            "https://jaunt.example?x",
            "https://jaunt.example#x",
            "https://user@jaunt.example",
            "https://jaunt example",
        ] {
            assert!(!is_valid_origin(bad), "{bad}");
        }
    }

    #[test]
    fn a_canonical_origin_has_a_lowercase_host_and_no_default_or_padded_port() {
        for good in [
            "https://jaunt.example",
            "https://jaunt.example:8443",
            "https://127.0.0.1:8443",
            "https://[::1]",
            "https://[::1]:8443",
        ] {
            assert!(is_canonical_origin(good), "{good}");
        }
        for bad in [
            "https://JAUNT.example",
            "https://Jaunt.example:8443",
            "https://jaunt.example:443",
            "https://jaunt.example:",
            "https://jaunt.example:0443",
            "https://jaunt.example:08443",
            "https://jaunt.example:65536",
            "https://jaunt.example:80a",
            "https://[::1]:443",
            "https://[::1]:",
            "https://[FE80::1]:8443",
            "https://a:b:c",
            "http://jaunt.example",
            "",
        ] {
            assert!(!is_canonical_origin(bad), "{bad}");
        }
    }
}
