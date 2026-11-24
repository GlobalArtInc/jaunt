use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_LABEL_LEN: usize = 63;
const MAX_DNS_NAME_LEN: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the agent endpoint must be host:port with a lowercase DNS name or an IP address and a port from 1 to 65535"
)]
pub struct EndpointError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEndpoint {
    text: String,
    host: String,
}

impl AgentEndpoint {
    pub fn parse(text: &str) -> Result<Self, EndpointError> {
        let (host, port) = text.rsplit_once(':').ok_or(EndpointError)?;
        let bare = match host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            Some(inner) if inner.parse::<Ipv6Addr>().is_ok() => inner,
            Some(_) => return Err(EndpointError),
            None if host.parse::<Ipv4Addr>().is_ok() || is_dns_name(host) => host,
            None => return Err(EndpointError),
        };
        let port_ok = !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|number| number != 0);
        if !port_ok {
            return Err(EndpointError);
        }
        Ok(Self {
            text: text.to_owned(),
            host: bare.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn server_name(&self) -> &str {
        &self.host
    }
}

fn is_dns_label(label: &str) -> bool {
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

pub fn is_dns_name(text: &str) -> bool {
    text.len() <= MAX_DNS_NAME_LEN && text.split('.').all(is_dns_label)
}

pub fn is_name_label(text: &str) -> bool {
    is_dns_label(text)
}

#[cfg(test)]
mod tests {
    use super::{AgentEndpoint, EndpointError};

    #[test]
    fn endpoints_split_into_the_connect_address_and_the_server_name() {
        for (text, name) in [
            ("agents.example.com:443", "agents.example.com"),
            ("localhost:8443", "localhost"),
            ("10.0.0.5:443", "10.0.0.5"),
            ("[::1]:443", "::1"),
        ] {
            let endpoint = AgentEndpoint::parse(text).unwrap();
            assert_eq!(endpoint.as_str(), text);
            assert_eq!(endpoint.server_name(), name);
        }
        for bad in [
            "",
            "agents.example.com",
            "agents.example.com:0",
            "agents.example.com:65536",
            "agents.example.com:+443",
            "Agents.example.com:443",
            "::1:443",
            "[not-ip]:443",
            "agents..example.com:443",
            "agents.example.com/x:443",
        ] {
            assert_eq!(AgentEndpoint::parse(bad), Err(EndpointError), "{bad}");
        }
    }
}
