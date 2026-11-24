use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    #[serde(default)]
    pub log_level: Option<String>,
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
    let config = parse(&text).map_err(|reason| ConfigError::Parse {
        path: path.display().to_string(),
        reason,
    })?;
    if config
        .state_dir
        .as_ref()
        .is_some_and(|dir| !dir.is_absolute())
    {
        return Err(ConfigError::StateDir {
            path: path.display().to_string(),
        });
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

    use super::{AgentConfig, ConfigError, load};

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
}
