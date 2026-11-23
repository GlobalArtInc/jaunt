use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_saphyr::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Config, load};

    #[test]
    fn parses_valid_config() {
        assert!(serde_saphyr::from_str::<Config>("data_dir: /var/lib/jaunt\n").is_ok());
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(serde_saphyr::from_str::<Config>("data_dir: /var/lib/jaunt\nextra: 1\n").is_err());
    }

    #[test]
    fn rejects_missing_data_dir() {
        assert!(serde_saphyr::from_str::<Config>("{}\n").is_err());
    }

    #[test]
    fn load_rejects_missing_file() {
        assert!(load(Path::new("/nonexistent/jauntd-missing.yaml")).is_err());
    }
}
