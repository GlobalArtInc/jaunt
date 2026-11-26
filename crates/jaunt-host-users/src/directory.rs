#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryUse {
    Local,
    Network,
}

const LOCAL_SOURCES: [&str; 6] = ["files", "compat", "systemd", "extrausers", "altfiles", "db"];
const SSSD_SOURCE: &str = "sss";
const COMPAT_SOURCE: &str = "compat";

pub fn detect_directory(nsswitch: Option<&str>, sssd_configured: bool) -> DirectoryUse {
    let Some(nsswitch) = nsswitch else {
        return DirectoryUse::Local;
    };
    let passwd = sources_of(nsswitch, "passwd");
    let uses_compat = passwd.iter().any(|source| source == COMPAT_SOURCE);
    let compat = if uses_compat {
        sources_of(nsswitch, "passwd_compat")
    } else {
        Vec::new()
    };
    let network = passwd
        .iter()
        .chain(compat.iter())
        .any(|source| is_network(source, sssd_configured));
    if network {
        DirectoryUse::Network
    } else {
        DirectoryUse::Local
    }
}

fn is_network(source: &str, sssd_configured: bool) -> bool {
    if source == SSSD_SOURCE {
        sssd_configured
    } else {
        !LOCAL_SOURCES.contains(&source)
    }
}

fn sources_of(nsswitch: &str, database: &str) -> Vec<String> {
    nsswitch
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or_default();
            let (name, sources) = line.split_once(':')?;
            (name.trim() == database).then_some(sources)
        })
        .flat_map(|sources| {
            without_actions(sources)
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn without_actions(sources: &str) -> String {
    let mut depth = 0_usize;
    let mut kept = String::with_capacity(sources.len());
    for character in sources.chars() {
        match character {
            '[' => {
                depth += 1;
                kept.push(' ');
            }
            ']' => {
                depth = depth.saturating_sub(1);
                kept.push(' ');
            }
            _ if depth == 0 => kept.push(character),
            _ => {}
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::{DirectoryUse, detect_directory};

    #[test]
    fn only_local_sources_on_the_passwd_line_keep_creation_on() {
        use DirectoryUse::{Local, Network};
        for source in ["files", "compat", "systemd", "extrausers", "altfiles", "db"] {
            let nsswitch = format!("passwd: {source}\n");
            assert_eq!(detect_directory(Some(&nsswitch), true), Local, "{source}");
        }
        for source in [
            "ldap",
            "nis",
            "nisplus",
            "winbind",
            "oslogin",
            "aad",
            "lsass",
            "centrifydc",
            "vas4",
            "something-new",
            "FILES",
        ] {
            let nsswitch = format!("passwd: files {source}\n");
            assert_eq!(
                detect_directory(Some(&nsswitch), false),
                Network,
                "{source}"
            );
        }
        for (nsswitch, sssd, expected) in [
            (None, false, Local),
            (Some(""), false, Local),
            (Some("group: ldap\nshadow: ldap\n"), false, Local),
            (Some("passwd:\n"), false, Local),
            (Some("passwd: files sss\n"), false, Local),
            (Some("passwd: files sss\n"), true, Network),
            (
                Some("passwd: files [NOTFOUND=return] systemd\n"),
                false,
                Local,
            ),
            (
                Some("passwd: files [NOTFOUND=return]ldap\n"),
                false,
                Network,
            ),
            (
                Some("passwd: files [ !UNAVAIL=return ldap ]\n"),
                false,
                Local,
            ),
            (Some("# passwd: ldap\npasswd: files\n"), false, Local),
            (Some("passwd: files # ldap\n"), false, Local),
            (Some("passwd: files\npasswd: ldap\n"), false, Network),
            (Some("passwd: compat\npasswd_compat: nis\n"), false, Network),
            (Some("passwd: compat\npasswd_compat: files\n"), false, Local),
            (Some("passwd: compat\npasswd_compat: sss\n"), true, Network),
            (Some("passwd: files\npasswd_compat: ldap\n"), false, Local),
        ] {
            assert_eq!(
                detect_directory(nsswitch, sssd),
                expected,
                "{nsswitch:?} {sssd}"
            );
        }
    }
}
