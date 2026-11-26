use http::Method;

use crate::escape::{Plus, percent_decode};
use crate::query::Query;

const MAX_VERSION_BYTES: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    Get,
    List,
    Watch,
    Create,
    Update,
    Patch,
    Delete,
    DeleteCollection,
    Exec,
    Attach,
    PortForward,
    Log,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::List => "list",
            Self::Watch => "watch",
            Self::Create => "create",
            Self::Update => "update",
            Self::Patch => "patch",
            Self::Delete => "delete",
            Self::DeleteCollection => "deletecollection",
            Self::Exec => "exec",
            Self::Attach => "attach",
            Self::PortForward => "portforward",
            Self::Log => "log",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiRequest {
    Resource(ResourceRequest),
    NonResource(NonResourceRequest),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRequest {
    group: String,
    version: String,
    resource: String,
    subresource: Option<String>,
    namespace: Option<String>,
    name: Option<String>,
    verb: Verb,
}

impl ResourceRequest {
    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn subresource(&self) -> Option<&str> {
        self.subresource.as_deref()
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn verb(&self) -> Verb {
        self.verb
    }

    pub fn is_watch(&self) -> bool {
        self.verb == Verb::Watch
    }

    pub fn is_upgrade_candidate(&self) -> bool {
        matches!(
            self.subresource.as_deref(),
            Some("exec" | "attach" | "portforward" | "proxy")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonResourceRequest {
    Version,
    Healthz,
    Livez,
    Readyz,
    OpenApi,
    Discovery(Discovery),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    CoreVersions,
    CoreResources { version: String },
    Groups,
    GroupVersions { group: String },
    GroupResources { group: String, version: String },
}

pub fn classify(method: &Method, path: &str, query: Option<&str>) -> ApiRequest {
    let Some(decoded) = percent_decode(path.as_bytes(), Plus::Literal)
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return ApiRequest::Unknown;
    };
    if !decoded.starts_with('/') {
        return ApiRequest::Unknown;
    }
    let Some(query) = Query::parse(query) else {
        return ApiRequest::Unknown;
    };
    let trimmed = decoded.trim_matches('/');
    let parts: Vec<&str> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('/').collect()
    };
    let api = match parts.as_slice() {
        ["api", version, rest @ ..] if !rest.is_empty() => Some(("", *version, rest)),
        ["apis", group, version, rest @ ..] if !rest.is_empty() && is_api_token(group) => {
            Some((*group, *version, rest))
        }
        _ => None,
    };
    let classified = match api {
        Some((group, version, rest)) => {
            resource(method, group, version, rest, &query).map(ApiRequest::Resource)
        }
        None => non_resource(method, &parts).map(ApiRequest::NonResource),
    };
    classified.unwrap_or(ApiRequest::Unknown)
}

fn resource(
    method: &Method,
    group: &str,
    version: &str,
    rest: &[&str],
    query: &Query<'_>,
) -> Option<ResourceRequest> {
    if !is_version(version) {
        return None;
    }
    let (watch_prefix, rest) = match rest {
        ["proxy", ..] => return None,
        ["watch", tail @ ..] if !tail.is_empty() => (true, tail),
        ["watch"] => return None,
        _ => (false, rest),
    };
    let (namespace, parts) = match rest {
        ["namespaces", namespace, next, ..] if !matches!(*next, "status" | "finalize") => {
            (Some(*namespace), rest.get(2..).unwrap_or_default())
        }
        ["namespaces", namespace, ..] => (Some(*namespace), rest),
        _ => (None, rest),
    };
    let (resource, name, subresource, extra) = match parts {
        [resource] => (*resource, None, None, false),
        [resource, name] => (*resource, Some(*name), None, false),
        [resource, name, subresource, tail @ ..] => {
            (*resource, Some(*name), Some(*subresource), !tail.is_empty())
        }
        [] => return None,
    };
    if !is_api_token(resource)
        || subresource.is_some_and(|value| !is_api_token(value))
        || namespace.is_some_and(|value| !is_object_segment(value))
        || name.is_some_and(|value| !is_object_segment(value))
        || (extra && subresource != Some("proxy"))
        || (watch_prefix && subresource.is_some())
    {
        return None;
    }
    let method_verb = match *method {
        Method::GET | Method::HEAD => Verb::Get,
        Method::POST => Verb::Create,
        Method::PUT => Verb::Update,
        Method::PATCH => Verb::Patch,
        Method::DELETE => Verb::Delete,
        _ => return None,
    };
    let mut name = name.map(str::to_owned);
    let verb = match (watch_prefix, method_verb, name.is_some()) {
        (true, Verb::Get, _) => Verb::Watch,
        (true, _, _) => return None,
        (false, Verb::Get, false) => {
            name = query
                .name_from_field_selector()
                .filter(|value| is_object_segment(value));
            if query.is_watch() {
                Verb::Watch
            } else {
                Verb::List
            }
        }
        (false, Verb::Delete, false) => Verb::DeleteCollection,
        (false, verb, _) => verb,
    };
    let verb = match (group, resource, subresource) {
        ("", "pods", Some(special @ ("exec" | "attach" | "portforward" | "log"))) => {
            pod_verb(special, verb, namespace.is_some())?
        }
        _ => verb,
    };
    Some(ResourceRequest {
        group: group.to_owned(),
        version: version.to_owned(),
        resource: resource.to_owned(),
        subresource: subresource.map(str::to_owned),
        namespace: namespace.map(str::to_owned),
        name,
        verb,
    })
}

fn pod_verb(subresource: &str, verb: Verb, namespaced: bool) -> Option<Verb> {
    if !namespaced {
        return None;
    }
    match (subresource, verb) {
        ("exec", Verb::Get | Verb::Create) => Some(Verb::Exec),
        ("attach", Verb::Get | Verb::Create) => Some(Verb::Attach),
        ("portforward", Verb::Get | Verb::Create) => Some(Verb::PortForward),
        ("log", Verb::Get) => Some(Verb::Log),
        _ => None,
    }
}

fn non_resource(method: &Method, parts: &[&str]) -> Option<NonResourceRequest> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return None;
    }
    let request = match parts {
        ["version"] => NonResourceRequest::Version,
        ["healthz", checks @ ..] if checks.iter().all(|check| is_object_segment(check)) => {
            NonResourceRequest::Healthz
        }
        ["livez", checks @ ..] if checks.iter().all(|check| is_object_segment(check)) => {
            NonResourceRequest::Livez
        }
        ["readyz", checks @ ..] if checks.iter().all(|check| is_object_segment(check)) => {
            NonResourceRequest::Readyz
        }
        ["openapi", "v2"] => NonResourceRequest::OpenApi,
        ["openapi", "v3", tail @ ..] if tail.iter().all(|part| is_object_segment(part)) => {
            NonResourceRequest::OpenApi
        }
        ["api"] => NonResourceRequest::Discovery(Discovery::CoreVersions),
        ["api", version] if is_version(version) => {
            NonResourceRequest::Discovery(Discovery::CoreResources {
                version: (*version).to_owned(),
            })
        }
        ["apis"] => NonResourceRequest::Discovery(Discovery::Groups),
        ["apis", group] if is_api_token(group) => {
            NonResourceRequest::Discovery(Discovery::GroupVersions {
                group: (*group).to_owned(),
            })
        }
        ["apis", group, version] if is_api_token(group) && is_version(version) => {
            NonResourceRequest::Discovery(Discovery::GroupResources {
                group: (*group).to_owned(),
                version: (*version).to_owned(),
            })
        }
        _ => return None,
    };
    Some(request)
}

fn is_api_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && value != "."
        && value != ".."
}

fn is_version(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= MAX_VERSION_BYTES
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_object_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch == '%' || ch == '/')
}
