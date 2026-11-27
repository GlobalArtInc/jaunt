use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use jaunt_policy::AdminPermission;
use jaunt_proto::{
    ADMIN_TOKEN_DEFAULT_TTL_SECS, ADMIN_TOKEN_MAX_CIDRS, ADMIN_TOKEN_MAX_TTL_SECS,
    ADMIN_TOKEN_MIN_TTL_SECS, is_admin_token_name,
};
use serde::Deserialize;

pub(crate) const TOKEN_RIGHTS: [AdminPermission; 5] = [
    AdminPermission::NodesApprove,
    AdminPermission::SessionsRead,
    AdminPermission::RecordingsRead,
    AdminPermission::RevocationsWrite,
    AdminPermission::AuditRead,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateBody {
    name: String,
    scope: Vec<String>,
    ttl_secs: Option<i64>,
    cidrs: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenRequest {
    pub(crate) name: String,
    pub(crate) scope: BTreeSet<AdminPermission>,
    pub(crate) ttl_secs: i64,
    pub(crate) cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invalid {
    Name,
    Scope,
    Ttl,
    Cidrs,
}

impl Invalid {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Invalid::Name => "invalid_name",
            Invalid::Scope => "invalid_scope",
            Invalid::Ttl => "invalid_ttl",
            Invalid::Cidrs => "invalid_cidrs",
        }
    }
}

pub(crate) fn validate(body: CreateBody) -> Result<TokenRequest, Invalid> {
    if !is_admin_token_name(&body.name) {
        return Err(Invalid::Name);
    }
    let scope = parse_scope(&body.scope).ok_or(Invalid::Scope)?;
    let ttl_secs = body.ttl_secs.unwrap_or(ADMIN_TOKEN_DEFAULT_TTL_SECS);
    if !(ADMIN_TOKEN_MIN_TTL_SECS..=ADMIN_TOKEN_MAX_TTL_SECS).contains(&ttl_secs) {
        return Err(Invalid::Ttl);
    }
    let cidrs = parse_networks(body.cidrs.as_deref().unwrap_or_default()).ok_or(Invalid::Cidrs)?;
    Ok(TokenRequest {
        name: body.name,
        scope,
        ttl_secs,
        cidrs,
    })
}

fn token_right(value: &str) -> Option<AdminPermission> {
    TOKEN_RIGHTS
        .into_iter()
        .find(|permission| permission.as_str() == value)
}

pub(crate) fn parse_scope(values: &[String]) -> Option<BTreeSet<AdminPermission>> {
    let mut scope = BTreeSet::new();
    for value in values {
        if !scope.insert(token_right(value)?) {
            return None;
        }
    }
    (!scope.is_empty()).then_some(scope)
}

pub(crate) struct StoredScope {
    pub(crate) rights: BTreeSet<AdminPermission>,
    pub(crate) dropped: usize,
}

pub(crate) fn stored_scope(values: &[String]) -> StoredScope {
    let rights: BTreeSet<AdminPermission> = values
        .iter()
        .filter_map(|value| token_right(value))
        .collect();
    let kept = values
        .iter()
        .filter(|value| token_right(value).is_some())
        .count();
    StoredScope {
        rights,
        dropped: values.len() - kept,
    }
}

pub(crate) fn parse_networks(values: &[String]) -> Option<Vec<IpNet>> {
    if values.len() > ADMIN_TOKEN_MAX_CIDRS {
        return None;
    }
    let mut networks: Vec<IpNet> = Vec::with_capacity(values.len());
    for value in values {
        let network = value.parse::<IpNet>().ok()?;
        let mapped = matches!(network, IpNet::V6(v6) if v6.network().to_ipv4_mapped().is_some());
        let everything = network.prefix_len() == 0;
        if network.trunc() != network || mapped || everything || networks.contains(&network) {
            return None;
        }
        networks.push(network);
    }
    Some(networks)
}

pub(crate) fn admits_address(networks: &[IpNet], client: Option<IpAddr>) -> bool {
    if networks.is_empty() {
        return true;
    }
    client.is_some_and(|ip| {
        let ip = ip.to_canonical();
        networks.iter().any(|network| network.contains(&ip))
    })
}

pub(crate) fn scope_names(scope: &BTreeSet<AdminPermission>) -> Vec<String> {
    scope
        .iter()
        .map(|permission| permission.as_str().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    use jaunt_policy::AdminPermission;

    use super::{CreateBody, Invalid, admits_address, parse_networks, parse_scope, validate};

    fn texts(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn body(ttl_secs: Option<i64>) -> CreateBody {
        CreateBody {
            name: "ci-audit".to_owned(),
            scope: texts(&["audit.read"]),
            ttl_secs,
            cidrs: None,
        }
    }

    #[test]
    fn the_lifetime_defaults_to_thirty_days_and_stays_between_a_minute_and_ninety_days() {
        assert_eq!(validate(body(None)).unwrap().ttl_secs, 30 * 86_400);
        for (ttl, valid) in [
            (60, true),
            (90 * 86_400, true),
            (59, false),
            (90 * 86_400 + 1, false),
            (0, false),
            (-60, false),
        ] {
            assert_eq!(
                validate(body(Some(ttl))).map(|request| request.ttl_secs),
                if valid { Ok(ttl) } else { Err(Invalid::Ttl) },
                "{ttl}"
            );
        }
        let unnamed = CreateBody {
            name: "CI".to_owned(),
            ..body(None)
        };
        assert_eq!(validate(unnamed), Err(Invalid::Name));
    }

    #[test]
    fn a_scope_is_a_non_empty_set_of_admin_rights_without_tokens_write() {
        assert_eq!(
            parse_scope(&texts(&["audit.read", "sessions.read"])),
            Some(BTreeSet::from([
                AdminPermission::AuditRead,
                AdminPermission::SessionsRead
            ]))
        );
        for bad in [
            texts(&[]),
            texts(&["tokens.write"]),
            texts(&["audit.read", "tokens.write"]),
            texts(&["audit.read", "audit.read"]),
            texts(&["ssh"]),
            texts(&["Audit.Read"]),
        ] {
            assert_eq!(parse_scope(&bad), None, "{bad:?}");
        }
        assert!(!super::TOKEN_RIGHTS.contains(&AdminPermission::TokensWrite));
    }

    #[test]
    fn a_stored_scope_keeps_only_token_rights_and_counts_what_it_dropped() {
        let stored = super::stored_scope(&texts(&[
            "audit.read",
            "tokens.write",
            "future.right",
            "sessions.read",
        ]));
        assert_eq!(
            stored.rights,
            BTreeSet::from([AdminPermission::SessionsRead, AdminPermission::AuditRead])
        );
        assert_eq!(stored.dropped, 2);
        assert_eq!(super::stored_scope(&texts(&["audit.read"])).dropped, 0);
    }

    #[test]
    fn networks_are_canonical_v4_or_v6_prefixes_and_at_most_sixteen() {
        let sixteen: Vec<String> = (0..16).map(|index| format!("10.{index}.0.0/16")).collect();
        let seventeen: Vec<String> = (0..17).map(|index| format!("10.{index}.0.0/16")).collect();
        assert_eq!(parse_networks(&sixteen).map(|nets| nets.len()), Some(16));
        assert_eq!(parse_networks(&seventeen), None);
        assert_eq!(parse_networks(&[]), Some(Vec::new()));
        assert!(parse_networks(&texts(&["192.0.2.0/24", "2001:db8::/32"])).is_some());
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "192.0.2.1/24",
            "192.0.2.1",
            "2001:db8::1/32",
            "::ffff:192.0.2.0/120",
            "192.0.2.0/33",
            "example.com/24",
            "",
        ] {
            assert_eq!(parse_networks(&texts(&[bad])), None, "{bad}");
        }
        assert_eq!(
            parse_networks(&texts(&["192.0.2.0/24", "192.0.2.0/24"])),
            None
        );
    }

    #[test]
    fn an_address_is_admitted_inside_a_listed_network_or_when_none_is_listed() {
        let networks = parse_networks(&texts(&["192.0.2.0/24", "2001:db8:1::/48"])).unwrap();
        let ip = |text: &str| Some(text.parse::<IpAddr>().unwrap());
        assert!(admits_address(&networks, ip("192.0.2.200")));
        assert!(admits_address(&networks, ip("::ffff:192.0.2.7")));
        assert!(admits_address(&networks, ip("2001:db8:1:ffff::1")));
        assert!(!admits_address(&networks, ip("192.0.3.1")));
        assert!(!admits_address(&networks, ip("2001:db8:2::1")));
        assert!(!admits_address(&networks, None));
        assert!(admits_address(&[], ip("203.0.113.9")));
        assert!(admits_address(&[], None));
    }
}
