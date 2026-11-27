use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jaunt_host_users::{
    DirectoryUse, HostUsersConfig, HostUsersSection, Settings, detect_directory,
};
use tokio::net::UnixStream;

pub const HELPER_SOCKET: &str = "/run/jaunt/host-users.sock";
pub const NSSWITCH_CONF: &str = "/etc/nsswitch.conf";
pub const SSSD_CONF: &str = "/etc/sssd/sssd.conf";

pub const HELPER_PROBE_WAIT: Duration = Duration::from_millis(500);

const MAX_NSSWITCH_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUsersPaths {
    pub socket: PathBuf,
    pub nsswitch: PathBuf,
    pub sssd_conf: PathBuf,
}

impl Default for HostUsersPaths {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(HELPER_SOCKET),
            nsswitch: PathBuf::from(NSSWITCH_CONF),
            sssd_conf: PathBuf::from(SSSD_CONF),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    Disabled,
    InvalidConfig,
    NoHelper,
    Directory,
}

impl Unavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidConfig => "invalid_config",
            Self::NoHelper => "no_helper",
            Self::Directory => "directory",
        }
    }
}

pub struct Availability {
    settings: Option<Settings>,
    paths: HostUsersPaths,
}

impl Availability {
    pub fn new(section: &HostUsersSection, paths: HostUsersPaths) -> Self {
        let settings = match section.settings() {
            Ok(settings) => Some(settings),
            Err(error) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    event = "agent.host_user.config_invalid",
                    error = %error,
                    "the host_users section is not valid; this node does not create accounts"
                );
                None
            }
        };
        Self { settings, paths }
    }

    pub fn socket(&self) -> &Path {
        &self.paths.socket
    }

    pub fn creation(&self) -> Result<&HostUsersConfig, Unavailable> {
        let config = match &self.settings {
            None => return Err(Unavailable::InvalidConfig),
            Some(Settings::Disabled) => return Err(Unavailable::Disabled),
            Some(Settings::Enabled(config)) => config,
        };
        if !is_socket(&self.paths.socket) {
            return Err(Unavailable::NoHelper);
        }
        if !config.allow_with_directory() && self.directory() == DirectoryUse::Network {
            return Err(Unavailable::Directory);
        }
        Ok(config)
    }

    pub async fn helper_listens(&self) -> bool {
        accepts_connections(&self.paths.socket).await
    }

    fn directory(&self) -> DirectoryUse {
        let Ok(nsswitch) = read_capped(&self.paths.nsswitch) else {
            return DirectoryUse::Network;
        };
        let sssd_configured = match fs::symlink_metadata(&self.paths.sssd_conf) {
            Ok(_) => true,
            Err(error) => error.kind() != io::ErrorKind::NotFound,
        };
        detect_directory(nsswitch.as_deref(), sssd_configured)
    }
}

fn is_socket(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

async fn accepts_connections(socket: &Path) -> bool {
    match tokio::time::timeout(HELPER_PROBE_WAIT, UnixStream::connect(socket)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            true
        }
        Ok(Err(error)) => {
            tracing::debug!(
                target: "jaunt::agent",
                error = %error,
                "the account helper socket does not accept connections"
            );
            false
        }
        Err(_) => {
            tracing::debug!(
                target: "jaunt::agent",
                "the account helper socket did not accept a connection in time"
            );
            false
        }
    }
}

fn read_capped(path: &Path) -> io::Result<Option<String>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut text = String::new();
    file.take(MAX_NSSWITCH_BYTES + 1)
        .read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_NSSWITCH_BYTES {
        return Err(io::Error::from(io::ErrorKind::FileTooLarge));
    }
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use jaunt_host_users::HostUsersSection;

    use super::{Availability, HostUsersPaths, Unavailable};

    fn enabled() -> HostUsersSection {
        HostUsersSection {
            enabled: true,
            ..HostUsersSection::default()
        }
    }

    fn paths(
        dir: &Path,
        nsswitch: Option<&str>,
        sssd: bool,
        socket: bool,
    ) -> (HostUsersPaths, Option<UnixListener>) {
        let paths = HostUsersPaths {
            socket: dir.join("h.sock"),
            nsswitch: dir.join("nsswitch.conf"),
            sssd_conf: dir.join("sssd.conf"),
        };
        if let Some(text) = nsswitch {
            std::fs::write(&paths.nsswitch, text).unwrap();
        }
        if sssd {
            std::fs::write(&paths.sssd_conf, "[sssd]\n").unwrap();
        }
        let listener = if socket {
            Some(UnixListener::bind(&paths.socket).unwrap())
        } else {
            std::fs::write(&paths.socket, "").unwrap();
            None
        };
        (paths, listener)
    }

    #[tokio::test]
    async fn creation_needs_a_valid_enabled_section_a_helper_socket_and_no_network_directory() {
        let invalid = HostUsersSection {
            uid_min: 10,
            ..enabled()
        };
        let with_directory = HostUsersSection {
            allow_with_directory: true,
            ..enabled()
        };
        let local = Some("passwd: files systemd\n");
        let cases = [
            ("ready", enabled(), local, false, true, Ok(())),
            ("no nsswitch", enabled(), None, false, true, Ok(())),
            (
                "disabled",
                HostUsersSection::default(),
                local,
                false,
                true,
                Err(Unavailable::Disabled),
            ),
            (
                "invalid",
                invalid,
                local,
                false,
                true,
                Err(Unavailable::InvalidConfig),
            ),
            (
                "not a socket",
                enabled(),
                local,
                false,
                false,
                Err(Unavailable::NoHelper),
            ),
            (
                "ldap",
                enabled(),
                Some("passwd: files ldap\n"),
                false,
                true,
                Err(Unavailable::Directory),
            ),
            (
                "sss with sssd.conf",
                enabled(),
                Some("passwd: sss files\n"),
                true,
                true,
                Err(Unavailable::Directory),
            ),
            (
                "sss without sssd.conf",
                enabled(),
                Some("passwd: sss files\n"),
                false,
                true,
                Ok(()),
            ),
            (
                "directory allowed",
                with_directory,
                Some("passwd: files ldap\n"),
                false,
                true,
                Ok(()),
            ),
        ];
        for (name, section, nsswitch, sssd, socket, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let (paths, _listener) = paths(dir.path(), nsswitch, sssd, socket);
            let availability = Availability::new(&section, paths);
            assert_eq!(availability.creation().map(|_| ()), expected, "{name}");
            assert_eq!(availability.helper_listens().await, socket, "{name}");
        }
    }

    #[tokio::test]
    async fn a_socket_without_a_listener_is_not_announced_but_logins_still_try_it() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, listener) = paths(dir.path(), Some("passwd: files\n"), false, true);
        let availability = Availability::new(&enabled(), paths);
        assert!(availability.helper_listens().await);
        drop(listener);
        assert!(availability.creation().is_ok());
        assert!(!availability.helper_listens().await);
    }

    #[test]
    fn a_missing_socket_an_oversized_nsswitch_and_an_unreadable_sssd_conf_turn_creation_off() {
        let dir = tempfile::tempdir().unwrap();
        let (mut gone, _listener) = paths(dir.path(), Some("passwd: files\n"), false, true);
        gone.socket = dir.path().join("absent.sock");
        assert_eq!(
            Availability::new(&enabled(), gone).creation().map(|_| ()),
            Err(Unavailable::NoHelper)
        );
        let huge = "#".repeat(70 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let (oversized, _listener) = paths(dir.path(), Some(&huge), false, true);
        assert_eq!(
            Availability::new(&enabled(), oversized)
                .creation()
                .map(|_| ()),
            Err(Unavailable::Directory)
        );
        let dir = tempfile::tempdir().unwrap();
        let (mut unreadable, _listener) =
            paths(dir.path(), Some("passwd: sss files\n"), false, true);
        std::fs::write(dir.path().join("file"), "").unwrap();
        unreadable.sssd_conf = dir.path().join("file").join("sssd.conf");
        assert_eq!(
            Availability::new(&enabled(), unreadable)
                .creation()
                .map(|_| ()),
            Err(Unavailable::Directory)
        );
    }
}
