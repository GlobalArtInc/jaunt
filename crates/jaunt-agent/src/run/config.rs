use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_SSHD_PORT: u16 = 22;
pub const DEFAULT_SSHD_HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key.pub";

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub inner: InnerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerConfig {
    #[serde(default = "default_sshd_addr")]
    pub sshd_addr: SocketAddr,
    #[serde(default = "default_sshd_host_key")]
    pub sshd_host_key: PathBuf,
}

impl Default for InnerConfig {
    fn default() -> Self {
        Self {
            sshd_addr: default_sshd_addr(),
            sshd_host_key: default_sshd_host_key(),
        }
    }
}

fn default_sshd_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_SSHD_PORT))
}

fn default_sshd_host_key() -> PathBuf {
    PathBuf::from(DEFAULT_SSHD_HOST_KEY)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not a valid agent configuration: {reason}")]
    Parse { path: String, reason: String },
    #[error("{path}: state_dir must be an absolute path")]
    StateDir { path: String },
    #[error("{path}: inner.sshd_addr must be a loopback address such as 127.0.0.1:22 or [::1]:22")]
    SshdAddr { path: String },
    #[error("{path}: inner.sshd_host_key must be an absolute path")]
    SshdHostKey { path: String },
}

pub fn load(path: &Path) -> Result<AgentConfig, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(AgentConfig::default());
        }
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let shown = || path.display().to_string();
    let config = parse(&text).map_err(|reason| ConfigError::Parse {
        path: shown(),
        reason,
    })?;
    if config
        .state_dir
        .as_ref()
        .is_some_and(|dir| !dir.is_absolute())
    {
        return Err(ConfigError::StateDir { path: shown() });
    }
    if !config.inner.sshd_addr.ip().is_loopback() {
        return Err(ConfigError::SshdAddr { path: shown() });
    }
    if !config.inner.sshd_host_key.is_absolute() {
        return Err(ConfigError::SshdHostKey { path: shown() });
    }
    Ok(config)
}

fn parse(text: &str) -> Result<AgentConfig, String> {
    let meaningful = text
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !line.starts_with('#') && line != "---");
    if !meaningful {
        return Ok(AgentConfig::default());
    }
    let options = serde_saphyr::options! { with_snippet: false };
    serde_saphyr::from_str_with_options(text, options).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AgentConfig, ConfigError, InnerConfig, load};

    type Expected = fn(&ConfigError) -> bool;

    #[test]
    fn the_config_file_is_optional_and_strict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        assert_eq!(load(&path).unwrap(), AgentConfig::default());

        for (text, expected) in [
            ("", AgentConfig::default()),
            ("# nothing here\n", AgentConfig::default()),
            (
                "state_dir: /srv/jaunt/state\nlog_level: debug\n",
                AgentConfig {
                    state_dir: Some(PathBuf::from("/srv/jaunt/state")),
                    log_level: Some("debug".to_owned()),
                    inner: InnerConfig::default(),
                },
            ),
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(load(&path).unwrap(), expected, "{text:?}");
        }

        std::fs::write(&path, "state_dir: /srv/jaunt\nserver: x\n").unwrap();
        assert!(matches!(load(&path), Err(ConfigError::Parse { .. })));
        std::fs::write(&path, "state_dir: relative/dir\n").unwrap();
        assert!(matches!(load(&path), Err(ConfigError::StateDir { .. })));
    }

    #[test]
    fn the_inner_section_defaults_to_local_sshd_and_accepts_only_loopback() {
        let defaults = InnerConfig::default();
        assert_eq!(defaults.sshd_addr, "127.0.0.1:22".parse().unwrap());
        assert_eq!(
            defaults.sshd_host_key,
            PathBuf::from("/etc/ssh/ssh_host_ed25519_key.pub")
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        let accepted = [
            (
                "inner: {}\n",
                "127.0.0.1:22",
                "/etc/ssh/ssh_host_ed25519_key.pub",
            ),
            (
                "inner:\n  sshd_addr: \"[::1]:2222\"\n",
                "[::1]:2222",
                "/etc/ssh/ssh_host_ed25519_key.pub",
            ),
            (
                "inner:\n  sshd_addr: 127.0.0.1:22\n  sshd_host_key: /srv/ssh/host.pub\n",
                "127.0.0.1:22",
                "/srv/ssh/host.pub",
            ),
        ];
        for (text, addr, key) in accepted {
            std::fs::write(&path, text).unwrap();
            let inner = load(&path).unwrap().inner;
            assert_eq!(inner.sshd_addr, addr.parse().unwrap(), "{text:?}");
            assert_eq!(inner.sshd_host_key, PathBuf::from(key), "{text:?}");
        }
        let refused: [(&str, Expected); 5] = [
            ("inner:\n  sshd_addr: 10.0.0.5:22\n", |error| {
                matches!(error, ConfigError::SshdAddr { .. })
            }),
            ("inner:\n  sshd_addr: 0.0.0.0:22\n", |error| {
                matches!(error, ConfigError::SshdAddr { .. })
            }),
            ("inner:\n  sshd_addr: localhost:22\n", |error| {
                matches!(error, ConfigError::Parse { .. })
            }),
            ("inner:\n  sshd_host_key: etc/ssh/key.pub\n", |error| {
                matches!(error, ConfigError::SshdHostKey { .. })
            }),
            ("inner:\n  sshd_port: 22\n", |error| {
                matches!(error, ConfigError::Parse { .. })
            }),
        ];
        for (text, expected) in refused {
            std::fs::write(&path, text).unwrap();
            let error = load(&path).unwrap_err();
            assert!(expected(&error), "{text:?}: {error}");
        }
    }
}
