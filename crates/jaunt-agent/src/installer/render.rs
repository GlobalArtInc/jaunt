use super::layout::inner_ca_path;

const UNIT_TEMPLATE: &str = include_str!("jaunt-agent.service.tpl");

pub const DROPIN_HEADER: &str = "# Managed by jaunt-agent. Do not edit.";

pub fn dropin(state_dir: &str) -> String {
    format!(
        "{DROPIN_HEADER}\nMatch Address 127.0.0.1,::1\n    TrustedUserCAKeys {}\n",
        inner_ca_path(state_dir)
    )
}

pub fn is_foreign_dropin(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }
    let first_line = content.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    first_line != DROPIN_HEADER.as_bytes()
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
    use super::{dropin, is_foreign_dropin, unit};

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
            assert_eq!(is_foreign_dropin(content), foreign, "{content:?}");
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
            "WantedBy=multi-user.target",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
    }
}
