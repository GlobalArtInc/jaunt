use http::header::{
    CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use std::net::IpAddr;

use http::{HeaderMap, HeaderName, HeaderValue};
use jaunt_kube::{
    ImpersonationError, KubeGroup, KubeUser, MAX_IMPERSONATION_GROUPS, REMOTE_HEADER_PREFIX,
    SessionTag, SystemNames, has_system_prefix, impersonation_headers, strip_client_headers,
};
use jaunt_proto::KubeAccess;

const IMPERSONATE_PREFIX: &str = "impersonate-";
const HOP_BY_HOP: [HeaderName; 7] = [
    CONNECTION,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
    HOST,
    CONTENT_LENGTH,
];
const KEEP_ALIVE: &str = "keep-alive";
const PROXY_PREFIX: &str = "proxy-";
const FORWARDED_PREFIX: &str = "x-forwarded-";
const ORIGIN: [&str; 4] = ["forwarded", "x-real-ip", "via", "audit-id"];
const X_FORWARDED_FOR: &str = "x-forwarded-for";
pub(crate) const MAX_DECISION_USERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DecisionError {
    #[error("the decision names no Kubernetes user")]
    NoUser,
    #[error("a Kubernetes user of the decision is not a valid name")]
    User,
    #[error("the decision names more than {MAX_DECISION_USERS} Kubernetes users")]
    TooManyUsers,
    #[error("a Kubernetes user of the decision is a system name")]
    SystemUser,
    #[error("a Kubernetes group of the decision is not a valid name")]
    Group,
    #[error("a Kubernetes group of the decision is a system name")]
    SystemGroup,
    #[error("the decision names more than {MAX_IMPERSONATION_GROUPS} Kubernetes groups")]
    TooManyGroups,
    #[error("the session id cannot be sent in an impersonation header")]
    Session,
}

impl DecisionError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NoUser => "no_user",
            Self::User => "invalid_user",
            Self::TooManyUsers => "too_many_users",
            Self::SystemUser => "system_user",
            Self::Group => "invalid_group",
            Self::SystemGroup => "system_group",
            Self::TooManyGroups => "too_many_groups",
            Self::Session => "invalid_session",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decision {
    users: Vec<KubeUser>,
    groups: Vec<KubeGroup>,
    session: SessionTag,
}

impl Decision {
    pub(crate) fn from_access(
        access: &KubeAccess,
        session_id: &str,
    ) -> Result<Self, DecisionError> {
        if access.users.len() > MAX_DECISION_USERS {
            return Err(DecisionError::TooManyUsers);
        }
        if access.groups.len() > MAX_IMPERSONATION_GROUPS {
            return Err(DecisionError::TooManyGroups);
        }
        let mut users: Vec<KubeUser> = Vec::with_capacity(access.users.len());
        for name in &access.users {
            let user = KubeUser::new(name.as_str()).map_err(|_| DecisionError::User)?;
            if has_system_prefix(user.as_str()) {
                return Err(DecisionError::SystemUser);
            }
            if !users.contains(&user) {
                users.push(user);
            }
        }
        let mut groups: Vec<KubeGroup> = Vec::with_capacity(access.groups.len());
        for name in &access.groups {
            let group = KubeGroup::new(name.as_str()).map_err(|_| DecisionError::Group)?;
            if has_system_prefix(group.as_str()) {
                return Err(DecisionError::SystemGroup);
            }
            if !groups.contains(&group) {
                groups.push(group);
            }
        }
        let session = SessionTag::new(session_id).map_err(|_| DecisionError::Session)?;
        let Some(first) = users.first() else {
            return Err(DecisionError::NoUser);
        };
        impersonation_headers(first, &groups, &session, SystemNames::Refuse).map_err(|error| {
            match error {
                ImpersonationError::InvalidUser => DecisionError::User,
                ImpersonationError::SystemUser => DecisionError::SystemUser,
                ImpersonationError::InvalidGroup => DecisionError::Group,
                ImpersonationError::SystemGroup => DecisionError::SystemGroup,
                ImpersonationError::TooManyGroups => DecisionError::TooManyGroups,
                ImpersonationError::InvalidSession => DecisionError::Session,
            }
        })?;
        Ok(Self {
            users,
            groups,
            session,
        })
    }

    pub(crate) fn users(&self) -> &[KubeUser] {
        &self.users
    }

    pub(crate) fn groups(&self) -> &[KubeGroup] {
        &self.groups
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Header,
    LookalikeHeader,
    ChooseUser,
    SeveralUsers,
    UserNotAllowed,
    GroupNotAllowed,
}

pub(crate) fn upstream_headers(
    mut headers: HeaderMap,
    decision: &Decision,
    client_ip: Option<IpAddr>,
) -> Result<HeaderMap, Refused> {
    if headers.keys().any(is_lookalike) {
        return Err(Refused::LookalikeHeader);
    }
    let stripped = strip_client_headers(&mut headers);
    if stripped.must_refuse() {
        return Err(Refused::Header);
    }
    let user = select_user(decision, stripped.requested_users())?;
    let groups = select_groups(decision, stripped.requested_groups())?;
    remove_hop_by_hop(&mut headers);
    remove_origin(&mut headers);
    let identity = impersonation_headers(user, &groups, &decision.session, SystemNames::Refuse)
        .map_err(|_| Refused::Header)?;
    for (name, value) in &identity {
        headers.append(name.clone(), value.clone());
    }
    if let Some(ip) = client_ip
        && let Ok(value) = HeaderValue::from_str(&ip.to_string())
    {
        headers.insert(HeaderName::from_static(X_FORWARDED_FOR), value);
    }
    Ok(headers)
}

fn select_user<'a>(decision: &'a Decision, requested: &[String]) -> Result<&'a KubeUser, Refused> {
    match (requested, decision.users.as_slice()) {
        ([], [only]) => Ok(only),
        ([], _) => Err(Refused::ChooseUser),
        ([name], users) => users
            .iter()
            .find(|user| user.as_str() == name)
            .ok_or(Refused::UserNotAllowed),
        (_, _) => Err(Refused::SeveralUsers),
    }
}

fn select_groups(decision: &Decision, requested: &[String]) -> Result<Vec<KubeGroup>, Refused> {
    if requested.is_empty() {
        return Ok(decision.groups.clone());
    }
    let mut chosen: Vec<KubeGroup> = Vec::with_capacity(requested.len());
    for name in requested {
        let group = decision
            .groups
            .iter()
            .find(|group| group.as_str() == name)
            .ok_or(Refused::GroupNotAllowed)?;
        if !chosen.contains(group) {
            chosen.push(group.clone());
        }
    }
    Ok(chosen)
}

fn is_lookalike(name: &HeaderName) -> bool {
    let name = name.as_str();
    if !name.contains('_') {
        return false;
    }
    let hyphenated = name.replace('_', "-");
    hyphenated.starts_with(IMPERSONATE_PREFIX) || hyphenated.starts_with(REMOTE_HEADER_PREFIX)
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|name| HeaderName::from_bytes(name.trim_ascii()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in &HOP_BY_HOP {
        headers.remove(name);
    }
    headers.remove(EXPECT);
    let named: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str() == KEEP_ALIVE || name.as_str().starts_with(PROXY_PREFIX))
        .cloned()
        .collect();
    for name in named {
        headers.remove(name);
    }
}

fn remove_origin(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with(FORWARDED_PREFIX) || ORIGIN.contains(&name.as_str())
        })
        .cloned()
        .collect();
    for name in named {
        headers.remove(name);
    }
}

pub(crate) fn client_ip(client_addr: &str) -> Option<IpAddr> {
    client_addr
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
        .or_else(|_| client_addr.parse::<IpAddr>())
        .ok()
}
