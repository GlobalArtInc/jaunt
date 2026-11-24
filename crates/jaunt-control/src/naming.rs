use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_LABEL_LEN: usize = 63;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_SUFFIX_LEN: usize = MAX_DNS_NAME_LEN - MAX_LABEL_LEN - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NamingError {
    #[error("the ssh suffix must be a lowercase dns name of at most {MAX_SUFFIX_LEN} characters")]
    SshSuffix,
    #[error(
        "the agent endpoint must be host:port with a lowercase dns name or an ip address and a \
         port from 1 to 65535"
    )]
    AgentEndpoint,
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
        let host_ok = match host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            Some(inner) => inner.parse::<Ipv6Addr>().is_ok(),
            None => host.parse::<Ipv4Addr>().is_ok() || is_dns_name(host),
        };
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

#[cfg(test)]
mod tests {
    use super::{AgentEndpoint, SshSuffix, is_dns_label};

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
            ("10.0.0.1:443", true),
            ("[::1]:443", true),
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
}
