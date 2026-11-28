use http::header::{HOST, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, Method, Request, Version};
use jaunt_kube::{ApiRequest, Verb};

const DEFAULT_PORT: &str = "443";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedHost(String);

impl ExpectedHost {
    pub(crate) fn new(dns_name: &str) -> Self {
        Self(dns_name.to_ascii_lowercase())
    }

    pub(crate) fn matches(&self, value: &str) -> bool {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        };
        !self.0.is_empty()
            && host.eq_ignore_ascii_case(&self.0)
            && port.is_none_or(|port| port == DEFAULT_PORT)
    }
}

pub(crate) fn authority_matches<B>(request: &Request<B>, expected: &ExpectedHost) -> bool {
    let mut hosts = request.headers().get_all(HOST).iter();
    let header = hosts.next();
    if hosts.next().is_some() {
        return false;
    }
    let header = match header.map(|value| value.to_str()) {
        Some(Ok(value)) => Some(value),
        Some(Err(_)) => return false,
        None => None,
    };
    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str());
    let header_required = request.version() != Version::HTTP_2;
    if header_required && header.is_none() {
        return false;
    }
    if header.is_none() && authority.is_none() {
        return false;
    }
    [header, authority]
        .into_iter()
        .flatten()
        .all(|value| expected.matches(value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathProblem {
    NotOrigin,
    Byte,
    Backslash,
    EmptySegment,
    BadEscape,
    EncodedSlash,
    EncodedNul,
    NotUtf8,
    Control,
    DotSegment,
}

pub(crate) fn check_path(path: &str) -> Result<(), PathProblem> {
    if path == "/" {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(PathProblem::NotOrigin);
    };
    for byte in path.bytes() {
        if byte == b'\\' {
            return Err(PathProblem::Backslash);
        }
        if !(0x21..=0x7e).contains(&byte) {
            return Err(PathProblem::Byte);
        }
    }
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(PathProblem::EmptySegment);
        }
        let decoded = percent_decode(segment.as_bytes()).ok_or(PathProblem::BadEscape)?;
        if decoded.contains(&b'/') {
            return Err(PathProblem::EncodedSlash);
        }
        if decoded.contains(&b'\\') {
            return Err(PathProblem::Backslash);
        }
        if decoded.contains(&0) {
            return Err(PathProblem::EncodedNul);
        }
        let text = String::from_utf8(decoded).map_err(|_| PathProblem::NotUtf8)?;
        if text.chars().any(char::is_control) {
            return Err(PathProblem::Control);
        }
        if text == "." || text == ".." {
            return Err(PathProblem::DotSegment);
        }
    }
    Ok(())
}

fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let [high, low, after @ ..] = tail else {
                return None;
            };
            out.push((hex_value(*high)? << 4) | hex_value(*low)?);
            rest = after;
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn method_supported(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

pub(crate) fn framing_supported(headers: &HeaderMap) -> bool {
    let mut codings =
        headers
            .get_all(TRANSFER_ENCODING)
            .iter()
            .flat_map(|value| match value.to_str() {
                Ok(text) => text.split(',').map(str::trim).collect::<Vec<_>>(),
                Err(_) => vec![""],
            });
    match (codings.next(), codings.next()) {
        (None, _) => true,
        (Some(coding), None) => coding.eq_ignore_ascii_case("chunked"),
        (Some(_), Some(_)) => false,
    }
}

pub(crate) fn wants_upgrade<B>(request: &Request<B>, classified: &ApiRequest) -> bool {
    if request.headers().contains_key(UPGRADE) || request.method() == Method::CONNECT {
        return true;
    }
    match classified {
        ApiRequest::Resource(resource) => {
            matches!(
                resource.verb(),
                Verb::Exec | Verb::Attach | Verb::PortForward
            ) || matches!(
                resource.subresource(),
                Some("exec" | "attach" | "portforward")
            )
        }
        ApiRequest::NonResource(_) | ApiRequest::Unknown => false,
    }
}

pub(crate) fn answers_late(classified: &ApiRequest, query: Option<&str>) -> bool {
    let ApiRequest::Resource(resource) = classified else {
        return false;
    };
    match resource.verb() {
        Verb::Watch => true,
        Verb::Log => query.is_some_and(follows),
        _ => false,
    }
}

fn follows(query: &str) -> bool {
    query
        .split('&')
        .filter(|pair| !pair.contains(';'))
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(&key.replace('+', " ").into_bytes())?;
            let value = percent_decode(&value.replace('+', " ").into_bytes())?;
            Some((key, value))
        })
        .any(|(key, value)| {
            key == b"follow"
                && !matches!(
                    value.as_slice(),
                    b"0" | b"f" | b"F" | b"false" | b"FALSE" | b"False"
                )
        })
}
