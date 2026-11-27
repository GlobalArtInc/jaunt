pub const SOCKET_UNIT_TEMPLATE: &str = include_str!("../units/jaunt-host-users.socket");
pub const SERVICE_UNIT_TEMPLATE: &str = include_str!("../units/jaunt-host-users@.service");

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{SERVICE_UNIT_TEMPLATE, SOCKET_UNIT_TEMPLATE};
    use crate::store::STATE_DIR;

    fn entries(unit: &str) -> Vec<(String, String, String)> {
        let mut section = String::new();
        let mut entries = Vec::new();
        for line in unit.lines().filter(|line| !line.is_empty()) {
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                section = name.to_owned();
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("not a setting: {line:?}"));
            entries.push((section.clone(), key.to_owned(), value.to_owned()));
        }
        entries
    }

    fn settings_of<'a>(
        unit: &'a [(String, String, String)],
        wanted: &str,
    ) -> Vec<(&'a str, &'a str)> {
        unit.iter()
            .filter(|(section, _, _)| section == wanted)
            .map(|(_, key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn the_socket_is_a_per_connection_unix_socket_for_root_and_the_agent_group() {
        let unit = entries(SOCKET_UNIT_TEMPLATE);
        assert_eq!(
            settings_of(&unit, "Socket"),
            [
                ("ListenStream", "/run/jaunt/host-users.sock"),
                ("SocketUser", "root"),
                ("SocketGroup", "{{user}}"),
                ("SocketMode", "0660"),
                ("Accept", "yes"),
                ("MaxConnections", "4"),
                ("RemoveOnStop", "yes"),
            ]
        );
        assert_eq!(
            settings_of(&unit, "Install"),
            [("WantedBy", "sockets.target")]
        );
    }

    #[test]
    fn the_service_takes_the_connection_on_stdio_and_runs_in_the_designed_sandbox() {
        let unit = entries(SERVICE_UNIT_TEMPLATE);
        assert_eq!(
            settings_of(&unit, "Service"),
            [
                (
                    "ExecStart",
                    "{{binary}} serve --config {{config}} --agent-user {{user}}"
                ),
                ("StandardInput", "socket"),
                ("StandardOutput", "socket"),
                ("StandardError", "journal"),
                ("SyslogIdentifier", "jaunt-host-users"),
                ("RuntimeMaxSec", "30"),
                ("ProtectSystem", "strict"),
                ("StateDirectory", "jaunt-host-users"),
                ("StateDirectoryMode", "0700"),
                (
                    "ReadWritePaths",
                    "/etc {{home_base}} -/var/spool/mail /var/log"
                ),
                ("PrivateNetwork", "yes"),
                ("PrivateTmp", "yes"),
                ("RestrictAddressFamilies", "AF_UNIX"),
                ("NoNewPrivileges", "yes"),
                (
                    "CapabilityBoundingSet",
                    "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID"
                ),
                ("SystemCallFilter", "@system-service"),
            ]
        );
        assert_eq!(
            settings_of(&unit, "Unit"),
            [
                ("Description", "Jaunt host account helper"),
                ("CollectMode", "inactive-or-failed"),
            ]
        );
        assert!(settings_of(&unit, "Install").is_empty());
        assert_eq!(
            Path::new(STATE_DIR),
            Path::new("/var/lib").join("jaunt-host-users")
        );
    }
}
