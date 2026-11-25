use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub login_hint: String,
    pub subject: String,
    pub email: String,
    pub username: String,
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "verified")]
    pub email_verified: bool,
}

fn verified() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("{path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path}: the user table repeats the login hint {hint}")]
    DuplicateHint { path: String, hint: String },
}

pub fn load_users(path: &Path) -> Result<Vec<User>, SettingsError> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| SettingsError::Read {
        path: shown.clone(),
        source,
    })?;
    let users: Vec<User> = serde_json::from_str(&text).map_err(|source| SettingsError::Parse {
        path: shown.clone(),
        source,
    })?;
    for (index, user) in users.iter().enumerate() {
        if users[..index]
            .iter()
            .any(|earlier| earlier.login_hint == user.login_hint)
        {
            return Err(SettingsError::DuplicateHint {
                path: shown,
                hint: user.login_hint.clone(),
            });
        }
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::{SettingsError, load_users};

    fn written(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.json");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn a_user_table_loads_and_defaults_to_a_verified_email() {
        let (_dir, path) = written(
            r#"[{"login_hint":"a","subject":"s","email":"a@x.test","username":"a","name":"A"}]"#,
        );
        let users = load_users(&path).unwrap();
        assert_eq!(users.len(), 1);
        assert!(users[0].email_verified);
        assert!(users[0].groups.is_empty());
    }

    #[test]
    fn unknown_fields_and_repeated_hints_are_refused() {
        let (_dir, unknown) = written(
            r#"[{"login_hint":"a","subject":"s","email":"e","username":"a","name":"A","x":1}]"#,
        );
        assert!(matches!(
            load_users(&unknown),
            Err(SettingsError::Parse { .. })
        ));
        let user = r#"{"login_hint":"a","subject":"s","email":"e","username":"a","name":"A"}"#;
        let (_dir, repeated) = written(&format!("[{user},{user}]"));
        assert!(matches!(
            load_users(&repeated),
            Err(SettingsError::DuplicateHint { .. })
        ));
    }
}
