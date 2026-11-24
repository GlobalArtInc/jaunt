use std::fmt;
use std::str::FromStr;

use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebUrlError {
    #[error("the address is not a valid URL")]
    Malformed,
    #[error("the address must use https (http is accepted only for a loopback IP address)")]
    InsecureScheme,
    #[error("the address must not contain a user name or password")]
    Credentials,
    #[error("the address must be just a scheme, host and optional port")]
    NotAnOrigin,
}

pub fn check_web_url(text: &str) -> Result<Url, WebUrlError> {
    let url = Url::parse(text).map_err(|_| WebUrlError::Malformed)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WebUrlError::Credentials);
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => Ok(url),
        ("http", Some(Host::Ipv4(ip))) if ip.is_loopback() => Ok(url),
        ("http", Some(Host::Ipv6(ip))) if ip.is_loopback() => Ok(url),
        ("http" | "https", None) => Err(WebUrlError::Malformed),
        _ => Err(WebUrlError::InsecureScheme),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl(String);

impl ServerUrl {
    pub fn parse(text: &str) -> Result<ServerUrl, WebUrlError> {
        let url = check_web_url(text)?;
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(WebUrlError::NotAnOrigin);
        }
        Ok(ServerUrl(url.origin().ascii_serialization()))
    }

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
    type Err = WebUrlError;

    fn from_str(text: &str) -> Result<ServerUrl, WebUrlError> {
        ServerUrl::parse(text)
    }
}

impl fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerUrl, WebUrlError, check_web_url};

    #[test]
    fn server_urls_are_https_or_plain_http_to_a_loopback_ip() {
        let accepted = [
            ("https://jaunt.example.com", "https://jaunt.example.com"),
            ("https://jaunt.example.com/", "https://jaunt.example.com"),
            ("https://jaunt.example.com:443", "https://jaunt.example.com"),
            (
                "https://jaunt.example.com:8443",
                "https://jaunt.example.com:8443",
            ),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://127.9.9.9", "http://127.9.9.9"),
            ("http://[::1]:8080", "http://[::1]:8080"),
        ];
        for (input, canonical) in accepted {
            let parsed = ServerUrl::parse(input).unwrap_or_else(|err| panic!("{input}: {err}"));
            assert_eq!(parsed.as_str(), canonical);
        }

        let rejected = [
            ("http://jaunt.example.com", WebUrlError::InsecureScheme),
            ("http://localhost:8080", WebUrlError::InsecureScheme),
            ("http://10.0.0.1", WebUrlError::InsecureScheme),
            ("http://0.0.0.0:8080", WebUrlError::InsecureScheme),
            ("ftp://jaunt.example.com", WebUrlError::InsecureScheme),
            ("javascript:alert(1)", WebUrlError::InsecureScheme),
            (
                "https://user:pw@jaunt.example.com",
                WebUrlError::Credentials,
            ),
            ("https://user@jaunt.example.com", WebUrlError::Credentials),
            ("https://jaunt.example.com/base", WebUrlError::NotAnOrigin),
            ("https://jaunt.example.com/?a=1", WebUrlError::NotAnOrigin),
            ("https://jaunt.example.com/#frag", WebUrlError::NotAnOrigin),
            ("jaunt.example.com", WebUrlError::Malformed),
            ("", WebUrlError::Malformed),
        ];
        for (input, expected) in rejected {
            assert_eq!(ServerUrl::parse(input), Err(expected), "{input}");
        }
    }

    #[test]
    fn web_urls_for_the_browser_keep_their_path_and_query_but_follow_the_scheme_rule() {
        assert!(check_web_url("https://idp.example.com/authorize?state=a&x=b").is_ok());
        assert!(check_web_url("http://127.0.0.1:9/authorize?x=1").is_ok());
        assert_eq!(
            check_web_url("http://idp.example.com/authorize"),
            Err(WebUrlError::InsecureScheme)
        );
        assert_eq!(
            check_web_url("file:///etc/passwd"),
            Err(WebUrlError::InsecureScheme)
        );
    }
}
