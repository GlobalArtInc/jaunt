use jaunt_host_users::{HostUsersSection, NamesSection};

use super::layout::inner_ca_path;

const UNIT_TEMPLATE: &str = include_str!("jaunt-agent.service.tpl");

pub const MANAGED_HEADER: &str = "# Managed by jaunt-agent. Do not edit.";

pub fn dropin(state_dir: &str) -> String {
    format!(
        "{MANAGED_HEADER}\nMatch Address 127.0.0.1,::1\n    TrustedUserCAKeys {}\n",
        inner_ca_path(state_dir)
    )
}

pub fn agent_config(state_dir: &str) -> String {
    format!("{MANAGED_HEADER}\nstate_dir: {state_dir}\nlog_level: info\n")
}

pub fn agent_config_with_host_users(state_dir: &str, section: &HostUsersSection) -> String {
    let HostUsersSection {
        enabled,
        groups,
        privileged_groups,
        shell,
        home_base,
        home_mode,
        uid_min,
        uid_max,
        max_users,
        names,
        allow_with_directory,
    } = section;
    let NamesSection {
        deny,
        deny_prefixes,
        allow_prefixes,
    } = names;
    format!(
        "{}host_users:\n  enabled: {enabled}\n  groups: {}\n  privileged_groups: {}\n  shell: {}\n  home_base: {}\n  home_mode: {}\n  uid_min: {uid_min}\n  uid_max: {uid_max}\n  max_users: {max_users}\n  names:\n    deny: {}\n    deny_prefixes: {}\n    allow_prefixes: {}\n  allow_with_directory: {allow_with_directory}\n",
        agent_config(state_dir),
        yaml_list(groups),
        yaml_list(privileged_groups),
        yaml_string(shell),
        yaml_string(home_base),
        yaml_string(home_mode),
        yaml_list(deny),
        yaml_list(deny_prefixes),
        yaml_list(allow_prefixes),
    )
}

fn yaml_string(value: &str) -> String {
    serde_json::Value::from(value).to_string()
}

fn yaml_list(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| yaml_string(value)).collect();
    format!("[{}]", items.join(", "))
}

pub fn helper_unit(
    template: &str,
    helper: &str,
    config: &str,
    user: &str,
    home_base: &str,
) -> String {
    template
        .replace("{{binary}}", helper)
        .replace("{{config}}", config)
        .replace("{{user}}", user)
        .replace("{{home_base}}", home_base)
}

pub fn carries_header(content: &[u8]) -> bool {
    let first_line = content.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    first_line == MANAGED_HEADER.as_bytes()
}

pub fn is_foreign(content: &[u8]) -> bool {
    !content.is_empty() && !carries_header(content)
}

pub fn unit(user: &str, binary: &str, config: &str, state_dir: &str) -> String {
    UNIT_TEMPLATE
        .replace("{{user}}", user)
        .replace("{{binary}}", binary)
        .replace("{{config}}", config)
        .replace("{{state_dir}}", state_dir)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use jaunt_host_users::{HostUsersSection, NamesSection, parse_agent_file};

    use super::{
        agent_config, agent_config_with_host_users, carries_header, dropin, is_foreign, unit,
    };
    use crate::paths::check_state_dir;
    use crate::run::config::{AgentConfig, InnerConfig, RecordingConfig, load};

    #[test]
    fn only_a_non_empty_file_without_the_exact_header_line_is_foreign() {
        let ours = dropin("/var/lib/jaunt");
        let cases: [(&[u8], bool); 7] = [
            (b"", false),
            (ours.as_bytes(), false),
            (b"# Managed by jaunt-agent. Do not edit.", false),
            (b"# Managed by jaunt-agent. Do not edit.\n", false),
            (b"# my own file\nMatch all\n", true),
            (b"# Managed by jaunt-agent. Do not edit. really\n", true),
            (b"Match all\n# Managed by jaunt-agent. Do not edit.\n", true),
        ];
        for (content, foreign) in cases {
            assert_eq!(is_foreign(content), foreign, "{content:?}");
            assert_eq!(carries_header(content), !foreign && !content.is_empty());
        }
    }

    #[test]
    fn agent_config_is_exactly_the_header_the_state_dir_and_the_log_level() {
        assert_eq!(
            agent_config("/var/lib/jaunt"),
            "# Managed by jaunt-agent. Do not edit.\nstate_dir: /var/lib/jaunt\nlog_level: info\n"
        );
    }

    #[test]
    fn agent_config_parses_with_the_agent_parser_for_every_whitelisted_character() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        for state_dir in [
            "/var/lib/jaunt",
            "/srv/jaunt/state",
            "/opt/1.0/state",
            "/opt/a+b/c-d_e.f",
            "/srv/-x/+y",
            "/srv/...x/.state",
            "/opt/true/null",
            "/opt/0x1F/1e3",
        ] {
            check_state_dir(state_dir).unwrap();
            std::fs::write(&path, agent_config(state_dir)).unwrap();
            assert_eq!(
                load(&path).unwrap(),
                AgentConfig {
                    state_dir: Some(PathBuf::from(state_dir)),
                    log_level: Some("info".to_owned()),
                    inner: InnerConfig::default(),
                    recording: RecordingConfig::default(),
                    host_users: jaunt_host_users::HostUsersSection::default(),
                    ..AgentConfig::default()
                },
                "{state_dir}"
            );
        }
    }

    #[test]
    fn the_host_users_section_is_rendered_with_every_library_key() {
        let enabled = HostUsersSection {
            enabled: true,
            ..HostUsersSection::default()
        };
        let text = agent_config_with_host_users("/var/lib/jaunt", &enabled);
        assert_eq!(
            text,
            concat!(
                "# Managed by jaunt-agent. Do not edit.\n",
                "state_dir: /var/lib/jaunt\n",
                "log_level: info\n",
                "host_users:\n",
                "  enabled: true\n",
                "  groups: []\n",
                "  privileged_groups: []\n",
                "  shell: \"/bin/bash\"\n",
                "  home_base: \"/home\"\n",
                "  home_mode: \"0750\"\n",
                "  uid_min: 30000\n",
                "  uid_max: 30999\n",
                "  max_users: 100\n",
                "  names:\n",
                "    deny: []\n",
                "    deny_prefixes: []\n",
                "    allow_prefixes: []\n",
                "  allow_with_directory: false\n",
            )
        );
        let expected = HostUsersSection {
            enabled: true,
            ..HostUsersSection::default()
        };
        assert_eq!(parse_agent_file(&text).unwrap(), expected);
        assert!(expected.settings().is_ok());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, &text).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.host_users, expected);
        assert_eq!(loaded.state_dir, Some(PathBuf::from("/var/lib/jaunt")));
    }

    #[test]
    fn an_edited_host_users_section_survives_rendering_with_every_value() {
        let section = HostUsersSection {
            enabled: false,
            groups: vec!["staff".to_owned(), "ssh-users".to_owned()],
            privileged_groups: vec!["sudo".to_owned()],
            shell: "/usr/bin/zsh".to_owned(),
            home_base: "/srv/home".to_owned(),
            home_mode: "0700".to_owned(),
            uid_min: 40_000,
            uid_max: 40_099,
            max_users: 10,
            names: NamesSection {
                deny: vec!["guest".to_owned()],
                deny_prefixes: vec!["svc-".to_owned()],
                allow_prefixes: vec!["ext-".to_owned(), "\"q\\".to_owned()],
            },
            allow_with_directory: true,
        };
        let text = agent_config_with_host_users("/var/lib/jaunt", &section);
        assert_eq!(parse_agent_file(&text).unwrap(), section);
    }

    #[test]
    fn dropin_is_exactly_the_match_block_with_the_inner_ca_path() {
        assert_eq!(
            dropin("/var/lib/jaunt"),
            "# Managed by jaunt-agent. Do not edit.\nMatch Address 127.0.0.1,::1\n    TrustedUserCAKeys /var/lib/jaunt/inner-ca.pub\n"
        );
    }

    #[test]
    fn unit_substitutes_every_placeholder_and_keeps_hardening() {
        let text = unit("svc", "/opt/j/agent", "/etc/j/a.yaml", "/srv/j/state");
        assert!(!text.contains("{{"));
        for line in [
            "User=svc",
            "Group=svc",
            "ExecStart=/opt/j/agent run --config /etc/j/a.yaml",
            "ReadWritePaths=/srv/j/state",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "SystemCallFilter=@system-service",
            "CapabilityBoundingSet=",
            "LimitCORE=0",
            "MemorySwapMax=0",
            "WantedBy=multi-user.target",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
        let service = text
            .split("[Service]\n")
            .nth(1)
            .and_then(|rest| rest.split("[Install]").next())
            .unwrap();
        for line in ["LimitCORE=0", "MemorySwapMax=0"] {
            assert!(service.lines().any(|l| l == line), "missing {line}");
        }
    }
}
