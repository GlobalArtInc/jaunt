use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, HeaderName, header};

pub(crate) fn client_ip(
    forwarded_header: Option<&HeaderName>,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> IpAddr {
    forwarded_header
        .and_then(|name| forwarded_address(headers, name))
        .unwrap_or_else(|| peer.ip().to_canonical())
}

fn forwarded_address(headers: &HeaderMap, name: &HeaderName) -> Option<IpAddr> {
    let line = headers.get_all(name).iter().next_back()?.to_str().ok()?;
    let last = line.rsplit(',').next()?.trim();
    last.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
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

    use super::{client_ip, is_canonical_origin, is_valid_origin, origin_allowed};

    const PEER: &str = "198.51.100.7:40000";

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

    fn resolve(configured: Option<&'static str>, pairs: &[(&'static str, &str)]) -> IpAddr {
        let name = configured.map(HeaderName::from_static);
        let peer: SocketAddr = PEER.parse().unwrap();
        client_ip(name.as_ref(), &headers(pairs), peer)
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
    fn the_last_forwarded_value_wins_because_the_proxy_appends_the_real_peer() {
        let name = Some("x-forwarded-for");
        assert_eq!(
            resolve(
                name,
                &[("x-forwarded-for", "203.0.113.1, 10.0.0.1, 203.0.113.50")]
            ),
            ip("203.0.113.50")
        );
        assert_eq!(
            resolve(
                name,
                &[
                    ("x-forwarded-for", "203.0.113.1"),
                    ("x-forwarded-for", "192.0.2.4, 192.0.2.5")
                ]
            ),
            ip("192.0.2.5")
        );
        assert_eq!(
            resolve(Some("x-real-ip"), &[("x-real-ip", " 192.0.2.8 ")]),
            ip("192.0.2.8")
        );
        assert_eq!(
            resolve(name, &[("x-forwarded-for", "2001:db8::1")]),
            ip("2001:db8::1")
        );
        assert_eq!(
            resolve(name, &[("x-forwarded-for", "::ffff:192.0.2.9")]),
            ip("192.0.2.9")
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
