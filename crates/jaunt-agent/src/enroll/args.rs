use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Args;
use url::{Host, Url};

use crate::endpoint::is_name_label;
use crate::fsio::normalize;
use crate::pin::CaPin;
use crate::state::DEFAULT_STATE_DIR;

pub const DEFAULT_TIMEOUT_SECS: u64 = 900;
pub const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;
const MAX_LABELS: usize = 16;
const MAX_LABEL_KEY_LEN: usize = 63;
const MAX_LABEL_VALUE_LEN: usize = 63;
const MAX_HOSTNAME_LEN: usize = 253;

#[derive(Debug, Args)]
pub struct EnrollArgs {
    #[arg(long, value_name = "URL")]
    pub server: ServerUrl,
    #[arg(long, value_name = "NAME", value_parser = parse_name)]
    pub name: String,
    #[arg(long, value_name = "K=V,...")]
    pub labels: Option<Labels>,
    #[arg(long)]
    pub replace: bool,
    #[arg(long, value_name = "sha256:HEX")]
    pub ca_pin: Option<CaPin>,
    #[arg(long, value_name = "DIR", default_value = DEFAULT_STATE_DIR, value_parser = parse_state_dir)]
    pub state_dir: PathBuf,
    #[arg(long, value_name = "NAME", value_parser = parse_hostname)]
    pub hostname: Option<String>,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=MAX_TIMEOUT_SECS)
    )]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    #[error("the server address must use https (http is accepted only for a loopback IP address)")]
    InsecureScheme,
    #[error("the server address is not a valid URL")]
    Malformed,
    #[error("the server address must not contain a user name or password")]
    Credentials,
    #[error("the server address must be just a scheme, host and optional port")]
    NotAnOrigin,
    #[error(
        "a node name must be 1 to 63 lowercase letters, digits or -, starting and ending with a letter or digit"
    )]
    Name,
    #[error("labels must be key=value pairs separated by commas")]
    LabelSyntax,
    #[error("at most {MAX_LABELS} labels are allowed")]
    TooManyLabels,
    #[error("a label key must match [a-z][a-z0-9_.-]{{0,62}}")]
    LabelKey,
    #[error("a label value must match [A-Za-z0-9._-]{{0,63}}")]
    LabelValue,
    #[error("a label key appears more than once")]
    DuplicateLabel,
    #[error("a hostname must be 1 to {MAX_HOSTNAME_LEN} visible ASCII characters")]
    Hostname,
    #[error("the state directory must be an absolute path")]
    StateDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl(String);

impl ServerUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }

    pub fn is_plain_http(&self) -> bool {
        self.0.starts_with("http://")
    }
}

impl FromStr for ServerUrl {
    type Err = ArgError;

    fn from_str(text: &str) -> Result<Self, ArgError> {
        let url = Url::parse(text).map_err(|_| ArgError::Malformed)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ArgError::Credentials);
        }
        match (url.scheme(), url.host()) {
            ("https", Some(_)) => {}
            ("http", Some(Host::Ipv4(ip))) if ip.is_loopback() => {}
            ("http", Some(Host::Ipv6(ip))) if ip.is_loopback() => {}
            ("http" | "https", None) => return Err(ArgError::Malformed),
            _ => return Err(ArgError::InsecureScheme),
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ArgError::NotAnOrigin);
        }
        Ok(Self(url.origin().ascii_serialization()))
    }
}

impl fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels(BTreeMap<String, String>);

impl Labels {
    pub fn into_map(self) -> BTreeMap<String, String> {
        self.0
    }
}

impl FromStr for Labels {
    type Err = ArgError;

    fn from_str(text: &str) -> Result<Self, ArgError> {
        let mut map = BTreeMap::new();
        if text.is_empty() {
            return Ok(Self(map));
        }
        for pair in text.split(',') {
            let (key, value) = pair.split_once('=').ok_or(ArgError::LabelSyntax)?;
            if !is_label_key(key) {
                return Err(ArgError::LabelKey);
            }
            if !is_label_value(value) {
                return Err(ArgError::LabelValue);
            }
            if map.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(ArgError::DuplicateLabel);
            }
            if map.len() > MAX_LABELS {
                return Err(ArgError::TooManyLabels);
            }
        }
        Ok(Self(map))
    }
}

fn is_label_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes.len() <= MAX_LABEL_KEY_LEN
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn is_label_value(value: &str) -> bool {
    value.len() <= MAX_LABEL_VALUE_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

pub fn parse_name(text: &str) -> Result<String, ArgError> {
    if is_name_label(text) {
        Ok(text.to_owned())
    } else {
        Err(ArgError::Name)
    }
}

pub fn parse_hostname(text: &str) -> Result<String, ArgError> {
    let valid = !text.is_empty()
        && text.len() <= MAX_HOSTNAME_LEN
        && text.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
    if valid {
        Ok(text.to_owned())
    } else {
        Err(ArgError::Hostname)
    }
}

pub fn parse_state_dir(text: &str) -> Result<PathBuf, ArgError> {
    let path = Path::new(text);
    if path.is_absolute() {
        Ok(normalize(path))
    } else {
        Err(ArgError::StateDir)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ArgError, Labels, ServerUrl, parse_hostname, parse_name, parse_state_dir};

    #[test]
    fn state_directories_are_absolute_and_normalized() {
        for (input, expected) in [
            ("/var/lib/jaunt", "/var/lib/jaunt"),
            ("/var/lib/jaunt/", "/var/lib/jaunt"),
            ("/var//lib/./jaunt//", "/var/lib/jaunt"),
        ] {
            assert_eq!(
                parse_state_dir(input).unwrap(),
                Path::new(expected),
                "{input}"
            );
        }
        for bad in ["", "var/lib/jaunt", "./state"] {
            assert_eq!(parse_state_dir(bad), Err(ArgError::StateDir), "{bad}");
        }
    }

    #[test]
    fn server_urls_are_https_origins_or_plain_http_to_a_loopback_ip() {
        for (input, canonical) in [
            ("https://jaunt.example.com", "https://jaunt.example.com"),
            (
                "https://jaunt.example.com:8443/",
                "https://jaunt.example.com:8443",
            ),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://[::1]:8080", "http://[::1]:8080"),
        ] {
            assert_eq!(input.parse::<ServerUrl>().unwrap().as_str(), canonical);
        }
        for (input, expected) in [
            ("http://jaunt.example.com", ArgError::InsecureScheme),
            ("http://localhost:8080", ArgError::InsecureScheme),
            ("ftp://jaunt.example.com", ArgError::InsecureScheme),
            ("https://u:p@jaunt.example.com", ArgError::Credentials),
            ("https://jaunt.example.com/base", ArgError::NotAnOrigin),
            ("jaunt.example.com", ArgError::Malformed),
        ] {
            assert_eq!(input.parse::<ServerUrl>(), Err(expected), "{input}");
        }
    }

    #[test]
    fn labels_follow_the_server_rules() {
        let parsed: Labels = "env=prod,team=core-1".parse().unwrap();
        assert_eq!(parsed.into_map().len(), 2);
        assert!("".parse::<Labels>().unwrap().into_map().is_empty());
        let seventeen: Vec<String> = (0..17).map(|n| format!("k{n}=v")).collect();
        for (input, expected) in [
            ("env", ArgError::LabelSyntax),
            ("Env=prod", ArgError::LabelKey),
            ("=prod", ArgError::LabelKey),
            ("env=pr od", ArgError::LabelValue),
            ("env=a,env=b", ArgError::DuplicateLabel),
            (seventeen.join(",").as_str(), ArgError::TooManyLabels),
        ] {
            assert_eq!(input.parse::<Labels>(), Err(expected), "{input}");
        }
    }

    #[test]
    fn names_and_hostnames_are_checked_before_anything_is_sent() {
        assert_eq!(parse_name("web-01").unwrap(), "web-01");
        for bad in ["", "Web", "-web", "web_01", "web.01", &"a".repeat(64)] {
            assert_eq!(parse_name(bad), Err(ArgError::Name), "{bad}");
        }
        assert!(parse_hostname("web-01.example.com").is_ok());
        for bad in ["", "has space", "caf\u{e9}", &"h".repeat(254)] {
            assert_eq!(parse_hostname(bad), Err(ArgError::Hostname), "{bad}");
        }
    }
}
