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

    use super::{agent_config, carries_header, dropin, is_foreign, unit};
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
                },
                "{state_dir}"
            );
        }
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
