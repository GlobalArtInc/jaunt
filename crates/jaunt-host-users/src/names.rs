use std::fmt;

use jaunt_proto::is_portable_login;
use serde::{Deserialize, Serialize};

pub const RESERVED_PREFIXES: [&str; 2] = ["systemd-", "_"];

pub const PRIVILEGED_GROUPS: [&str; 10] = [
    "root", "sudo", "wheel", "adm", "admin", "docker", "lxd", "libvirt", "disk", "shadow",
];

pub const RESERVED_NAMES: &[&str] = &[
    "audio",
    "backup",
    "bin",
    "cdrom",
    "daemon",
    "dialout",
    "dip",
    "fax",
    "floppy",
    "games",
    "gnats",
    "irc",
    "kmem",
    "list",
    "lp",
    "mail",
    "man",
    "news",
    "nobody",
    "nogroup",
    "operator",
    "plugdev",
    "proxy",
    "sasl",
    "src",
    "staff",
    "sync",
    "sys",
    "tape",
    "tty",
    "users",
    "utmp",
    "uucp",
    "video",
    "voice",
    "www-data",
    "administrator",
    "jaunt",
    "sshd",
    "postgres",
    "mysql",
    "redis",
    "nginx",
    "git",
    "gitlab-runner",
    "ubuntu",
    "debian",
    "rocky",
    "ec2-user",
    "shutdown",
    "halt",
    "ftp",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a portable user or group name")]
pub struct InvalidName;

impl Name {
    pub fn parse(value: &str) -> Result<Self, InvalidName> {
        if is_portable_login(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Name {
    type Error = InvalidName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_portable_login(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidName)
        }
    }
}

impl From<Name> for String {
    fn from(name: Name) -> Self {
        name.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn is_reserved(login: &Name, privileged_groups: &[Name]) -> bool {
    let login = login.as_str();
    RESERVED_NAMES.contains(&login)
        || PRIVILEGED_GROUPS.contains(&login)
        || RESERVED_PREFIXES
            .iter()
            .any(|prefix| login.starts_with(prefix))
        || privileged_groups
            .iter()
            .any(|group| group.as_str() == login)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameRules {
    pub(crate) deny: Vec<Name>,
    pub(crate) deny_prefixes: Vec<Name>,
    pub(crate) allow_prefixes: Vec<Name>,
}

impl NameRules {
    pub fn permits(&self, login: &Name) -> bool {
        let login = login.as_str();
        let starts_with = |prefix: &Name| login.starts_with(prefix.as_str());
        !self.deny.iter().any(|denied| denied.as_str() == login)
            && !self.deny_prefixes.iter().any(starts_with)
            && (self.allow_prefixes.is_empty() || self.allow_prefixes.iter().any(starts_with))
    }

    pub fn deny(&self) -> &[Name] {
        &self.deny
    }

    pub fn deny_prefixes(&self) -> &[Name] {
        &self.deny_prefixes
    }

    pub fn allow_prefixes(&self) -> &[Name] {
        &self.allow_prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Name, NameRules, PRIVILEGED_GROUPS, RESERVED_NAMES, RESERVED_PREFIXES, is_reserved,
    };

    fn name(value: &str) -> Name {
        Name::parse(value).unwrap()
    }

    #[test]
    fn names_follow_the_common_login_predicate() {
        let longest = "a".repeat(crate::MAX_LOGIN_BYTES);
        let too_long = "a".repeat(crate::MAX_LOGIN_BYTES + 1);
        for (value, valid) in [
            ("alice", true),
            ("_svc", true),
            (longest.as_str(), true),
            (too_long.as_str(), false),
            ("Alice", false),
            ("-o", false),
            ("", false),
            ("a b", false),
        ] {
            assert_eq!(Name::parse(value).is_ok(), valid, "{value:?}");
            assert_eq!(Name::try_from(value.to_owned()).is_ok(), valid, "{value:?}");
        }
    }

    #[test]
    fn the_built_in_list_the_prefixes_and_the_privileged_groups_are_reserved() {
        for reserved in RESERVED_NAMES.iter().chain(PRIVILEGED_GROUPS.iter()) {
            assert!(is_reserved(&name(reserved), &[]), "{reserved}");
        }
        for prefix in RESERVED_PREFIXES {
            let login = format!("{prefix}x");
            assert!(is_reserved(&name(&login), &[]), "{login}");
        }
        assert!(is_reserved(&name("ops"), &[name("ops")]));
        for free in ["alice", "deploy", "rootless", "git-user", "x_systemd-"] {
            assert!(!is_reserved(&name(free), &[name("ops")]), "{free}");
        }
    }

    #[test]
    fn name_rules_deny_exact_names_and_prefixes_and_restrict_to_allowed_prefixes() {
        let rules = NameRules {
            deny: vec![name("bob")],
            deny_prefixes: vec![name("svc")],
            allow_prefixes: Vec::new(),
        };
        for (login, permitted) in [
            ("alice", true),
            ("bob", false),
            ("bobby", true),
            ("svc", false),
            ("svc-db", false),
        ] {
            assert_eq!(rules.permits(&name(login)), permitted, "{login}");
        }
        let restricted = NameRules {
            allow_prefixes: vec![name("u-"), name("ext-")],
            ..rules
        };
        for (login, permitted) in [
            ("u-alice", true),
            ("ext-carol", true),
            ("alice", false),
            ("u", false),
        ] {
            assert_eq!(restricted.permits(&name(login)), permitted, "{login}");
        }
    }
}
