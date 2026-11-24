use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_LABEL_LEN: usize = 63;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_SUFFIX_LEN: usize = MAX_DNS_NAME_LEN - MAX_LABEL_LEN - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NamingError {
    #[error("the ssh suffix must be a lowercase dns name of at most {MAX_SUFFIX_LEN} characters")]
    SshSuffix,
    #[error(
        "the agent endpoint must be host:port with a lowercase dns name, not an ip address, and \
         a port from 1 to 65535"
    )]
    AgentEndpoint,
    #[error(
        "the gate endpoint must be a dns name or an ip address, optionally followed by a port \
         from 1 to 65535 (an ipv6 address goes in square brackets)"
    )]
    GateEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSuffix(String);

impl SshSuffix {
    pub fn parse(text: &str) -> Result<SshSuffix, NamingError> {
        if text.len() <= MAX_SUFFIX_LEN && is_dns_name(text) {
            Ok(SshSuffix(text.to_owned()))
        } else {
            Err(NamingError::SshSuffix)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEndpoint(String);

impl AgentEndpoint {
    pub fn parse(text: &str) -> Result<AgentEndpoint, NamingError> {
        let (host, port) = text.rsplit_once(':').ok_or(NamingError::AgentEndpoint)?;
        let host_ok = is_dns_name(host) && !ends_in_a_number(host);
        let port_ok = !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|number| number != 0);
        if host_ok && port_ok {
            Ok(AgentEndpoint(text.to_owned()))
        } else {
            Err(NamingError::AgentEndpoint)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn host(&self) -> &str {
        self.0
            .rsplit_once(':')
            .map_or(self.0.as_str(), |(host, _)| host)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEndpoint {
    host: String,
    port: u16,
}

impl GateEndpoint {
    pub const DEFAULT_PORT: u16 = 22;

    pub fn parse(text: &str) -> Result<GateEndpoint, NamingError> {
        let text = text.to_ascii_lowercase();
        let (host, port) = split_gate(&text)?;
        let host = match host {
            GateHost::Bracketed(inner) => inner
                .parse::<Ipv6Addr>()
                .map_err(|_| NamingError::GateEndpoint)?
                .to_string(),
            GateHost::Plain(plain) if plain.parse::<Ipv4Addr>().is_ok() || is_dns_name(plain) => {
                plain.to_owned()
            }
            GateHost::Plain(_) => return Err(NamingError::GateEndpoint),
        };
        let port = match port {
            None => GateEndpoint::DEFAULT_PORT,
            Some(digits) => parse_port(digits)?,
        };
        Ok(GateEndpoint { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

enum GateHost<'a> {
    Plain(&'a str),
    Bracketed(&'a str),
}

fn split_gate(text: &str) -> Result<(GateHost<'_>, Option<&str>), NamingError> {
    if let Some(rest) = text.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or(NamingError::GateEndpoint)?;
        return match after {
            "" => Ok((GateHost::Bracketed(inner), None)),
            _ => {
                let digits = after.strip_prefix(':').ok_or(NamingError::GateEndpoint)?;
                Ok((GateHost::Bracketed(inner), Some(digits)))
            }
        };
    }
    match text.split_once(':') {
        None => Ok((GateHost::Plain(text), None)),
        Some((host, digits)) => Ok((GateHost::Plain(host), Some(digits))),
    }
}

fn parse_port(digits: &str) -> Result<u16, NamingError> {
    let well_formed =
        !digits.is_empty() && digits.len() <= 5 && digits.bytes().all(|byte| byte.is_ascii_digit());
    digits
        .parse::<u16>()
        .ok()
        .filter(|number| well_formed && *number != 0)
        .ok_or(NamingError::GateEndpoint)
}

pub(crate) fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_LABEL_LEN
        && edge(*first)
        && edge(*last)
        && bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
}

fn is_dns_name(text: &str) -> bool {
    text.len() <= MAX_DNS_NAME_LEN && text.split('.').all(is_dns_label)
}

fn ends_in_a_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or(host);
    let decimal = !last.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit());
    let hexadecimal = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    decimal || hexadecimal
}

#[cfg(test)]
mod tests {
    use super::{AgentEndpoint, GateEndpoint, SshSuffix, is_dns_label};

    #[test]
    fn dns_labels_follow_the_lowercase_rule() {
        let long = "a".repeat(63);
        let too_long = "a".repeat(64);
        for (label, ok) in [
            ("web-01", true),
            ("a", true),
            ("0a", true),
            (long.as_str(), true),
            (too_long.as_str(), false),
            ("", false),
            ("-web", false),
            ("web-", false),
            ("Web", false),
            ("we_b", false),
            ("we.b", false),
            ("wéb", false),
        ] {
            assert_eq!(is_dns_label(label), ok, "{label:?}");
        }
    }

    #[test]
    fn the_suffix_is_a_lowercase_dns_name() {
        for (text, ok) in [
            ("jaunt.example.com", true),
            ("corp", true),
            ("", false),
            (".example.com", false),
            ("example.com.", false),
            ("a..b", false),
            ("Example.com", false),
            ("exa mple.com", false),
            ("*.example.com", false),
        ] {
            assert_eq!(SshSuffix::parse(text).is_ok(), ok, "{text:?}");
        }
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(2)
        );
        assert!(SshSuffix::parse(&long).is_err());
        assert_eq!(
            SshSuffix::parse("jaunt.test").unwrap().as_str(),
            "jaunt.test"
        );
    }

    #[test]
    fn the_endpoint_is_host_and_port() {
        for (text, ok) in [
            ("agents.example.com:443", true),
            ("localhost:8443", true),
            ("10.0.0.1:443", false),
            ("127.0.0.1:8444", false),
            ("[::1]:443", false),
            ("[2001:db8::1]:443", false),
            ("0x7f.1:443", false),
            ("2130706433:443", false),
            ("127.1:443", false),
            ("1.2.3:443", false),
            ("0x7f.0.0.1:443", false),
            ("017700000001:443", false),
            ("0:443", false),
            ("0x:443", false),
            ("agents.example.0x1f:443", false),
            ("agents.123:443", false),
            ("agents.0x1g:443", true),
            ("agents.example.1a:443", true),
            ("0x7f.example.com:443", true),
            ("1.2.3.example.com:443", true),
            ("agents.example.com", false),
            ("agents.example.com:", false),
            ("agents.example.com:0", false),
            ("agents.example.com:65536", false),
            ("agents.example.com:+443", false),
            ("agents.example.com:44 3", false),
            (":443", false),
            ("Agents.Example.com:443", false),
            ("https://agents.example.com:443", false),
            ("::1:443", false),
            ("[::1:443", false),
        ] {
            assert_eq!(AgentEndpoint::parse(text).is_ok(), ok, "{text:?}");
        }
    }

    #[test]
    fn the_gate_endpoint_is_a_host_with_an_optional_port() {
        for (text, host, port) in [
            ("gate.example.com", "gate.example.com", 22),
            ("gate.example.com:2222", "gate.example.com", 2222),
            ("GATE.Example.COM:22", "gate.example.com", 22),
            ("10.0.0.1", "10.0.0.1", 22),
            ("10.0.0.1:65535", "10.0.0.1", 65535),
            ("[::1]", "::1", 22),
            ("[2001:DB8::1]:2222", "2001:db8::1", 2222),
            ("[2001:0db8::1]:2222", "2001:db8::1", 2222),
            ("[2001:db8:0:0::1]", "2001:db8::1", 22),
            ("localhost:1", "localhost", 1),
        ] {
            let parsed = GateEndpoint::parse(text).unwrap();
            assert_eq!((parsed.host(), parsed.port()), (host, port), "{text:?}");
        }
        for text in [
            "",
            ":22",
            "gate.example.com:",
            "gate.example.com:0",
            "gate.example.com:65536",
            "gate.example.com:+22",
            "gate.example.com:2 2",
            "gate.example.com:99999999999",
            "gate..example.com",
            "gate_example.com",
            "gaté.example.com",
            "gate example.com",
            "gate.example.com\n",
            "ssh://gate.example.com",
            "jaunt@gate.example.com",
            "::1",
            "::1:22",
            "[::1",
            "[::1]x",
            "[::1]:",
            "[gate.example.com]:22",
            "[fe80::1%eth0]:22",
            "gate.example.com:22:22",
            "-gate.example.com",
        ] {
            assert!(GateEndpoint::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn the_endpoint_host_is_everything_before_the_port() {
        for (text, host) in [
            ("agents.example.com:443", "agents.example.com"),
            ("localhost:8443", "localhost"),
        ] {
            assert_eq!(AgentEndpoint::parse(text).unwrap().host(), host);
        }
    }
}
