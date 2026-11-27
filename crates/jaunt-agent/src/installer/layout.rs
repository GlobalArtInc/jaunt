use std::path::{Path, PathBuf};

use super::error::InstallError;

pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
pub const DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";
pub const DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/50-jaunt.conf";
pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const UNIT_PATH: &str = "/etc/systemd/system/jaunt-agent.service";
pub const HELPER_SOCKET_UNIT: &str = "jaunt-host-users.socket";
pub const HELPER_SOCKET_PATH: &str = "/etc/systemd/system/jaunt-host-users.socket";
pub const HELPER_SERVICE_PATH: &str = "/etc/systemd/system/jaunt-host-users@.service";
pub const CONFIG_DIR: &str = "/etc/jaunt";
pub const DEFAULT_CONFIG: &str = "/etc/jaunt/agent.yaml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/jaunt";
pub const INNER_CA_FILE: &str = "inner-ca.pub";
pub const DEFAULT_SSHD: &str = "/usr/sbin/sshd";
pub const NOLOGIN_SHELL: &str = "/usr/sbin/nologin";
pub const SERVICE_NAME: &str = "jaunt-agent";
pub const SYSTEM_USER: &str = "jaunt";
pub const ROOT_UID: u32 = 0;

#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    pub fn new(root: &Path) -> Result<Self, InstallError> {
        if !root.is_absolute() {
            return Err(InstallError::InvalidArgument {
                name: "--root",
                reason: "must be an absolute path",
            });
        }
        if root.to_str().is_none() {
            return Err(InstallError::InvalidArgument {
                name: "--root",
                reason: "must be valid UTF-8",
            });
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn is_live(&self) -> bool {
        self.root.parent().is_none()
    }

    pub fn path(&self, virtual_path: &str) -> PathBuf {
        self.root.join(virtual_path.trim_start_matches('/'))
    }

    pub fn path_string(&self, virtual_path: &str) -> String {
        self.path(virtual_path).to_string_lossy().into_owned()
    }
}

pub fn inner_ca_path(state_dir: &str) -> String {
    format!("{state_dir}/{INNER_CA_FILE}")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Layout;

    #[test]
    fn live_only_for_filesystem_root() {
        assert!(Layout::new(Path::new("/")).unwrap().is_live());
        assert!(!Layout::new(Path::new("/tmp/jaunt-root")).unwrap().is_live());
    }

    #[test]
    fn relative_root_is_rejected() {
        assert!(Layout::new(Path::new("relative/root")).is_err());
    }

    #[test]
    fn paths_are_prefixed_with_root() {
        let layout = Layout::new(Path::new("/tmp/jaunt-root")).unwrap();
        assert_eq!(
            layout.path("/etc/ssh/sshd_config"),
            Path::new("/tmp/jaunt-root/etc/ssh/sshd_config")
        );
        let live = Layout::new(Path::new("/")).unwrap();
        assert_eq!(live.path("/etc/jaunt"), Path::new("/etc/jaunt"));
    }
}
