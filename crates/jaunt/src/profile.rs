use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const MAX_NAME_LEN: usize = 32;
const DEFAULT_NAME: &str = "default";
const DEFAULT_HOME_DIR: &str = ".jaunt";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "profile names are 1 to 32 characters: a-z, 0-9, '_' and '-', starting with a letter or digit"
)]
pub struct ProfileNameError;

impl ProfileName {
    pub fn parse(text: &str) -> Result<ProfileName, ProfileNameError> {
        let mut bytes = text.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        let rest_ok = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
        if first_ok && rest_ok && text.len() <= MAX_NAME_LEN {
            Ok(ProfileName(text.to_owned()))
        } else {
            Err(ProfileNameError)
        }
    }

    pub fn default_name() -> ProfileName {
        ProfileName(DEFAULT_NAME.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProfileName {
    type Err = ProfileNameError;

    fn from_str(text: &str) -> Result<ProfileName, ProfileNameError> {
        ProfileName::parse(text)
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HomeError {
    #[error("JAUNT_HOME must be an absolute path")]
    RelativeOverride,
    #[error("cannot determine the home directory; set JAUNT_HOME")]
    Unknown,
}

pub fn resolve_home(
    override_dir: Option<OsString>,
    user_home: Option<PathBuf>,
) -> Result<PathBuf, HomeError> {
    match override_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => {
            let path = PathBuf::from(dir);
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(HomeError::RelativeOverride)
            }
        }
        None => match user_home {
            Some(home) if home.is_absolute() => Ok(home.join(DEFAULT_HOME_DIR)),
            _ => Err(HomeError::Unknown),
        },
    }
}

pub fn profile_dir(home: &Path, name: &ProfileName) -> PathBuf {
    home.join(name.as_str())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{HomeError, ProfileName, resolve_home};

    #[test]
    fn profile_names_follow_the_documented_alphabet_and_length() {
        let long_ok = "a".repeat(32);
        let long_bad = "a".repeat(33);
        let accepted = ["default", "a", "0", "work-2", "a_b", long_ok.as_str()];
        let rejected = [
            "",
            "-a",
            "_a",
            "A",
            "a b",
            "a.b",
            "a/b",
            "..",
            "a\n",
            "é",
            long_bad.as_str(),
        ];
        for name in accepted {
            assert!(
                ProfileName::parse(name).is_ok(),
                "{name:?} should be accepted"
            );
        }
        for name in rejected {
            assert!(
                ProfileName::parse(name).is_err(),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn home_prefers_an_absolute_override_and_falls_back_to_the_user_home() {
        assert_eq!(
            resolve_home(
                Some(OsString::from("/srv/jaunt")),
                Some(PathBuf::from("/home/u"))
            ),
            Ok(PathBuf::from("/srv/jaunt"))
        );
        assert_eq!(
            resolve_home(None, Some(PathBuf::from("/home/u"))),
            Ok(PathBuf::from("/home/u/.jaunt"))
        );
        assert_eq!(
            resolve_home(Some(OsString::new()), Some(PathBuf::from("/home/u"))),
            Ok(PathBuf::from("/home/u/.jaunt"))
        );
        assert_eq!(
            resolve_home(
                Some(OsString::from("relative")),
                Some(PathBuf::from("/home/u"))
            ),
            Err(HomeError::RelativeOverride)
        );
        assert_eq!(resolve_home(None, None), Err(HomeError::Unknown));
        assert_eq!(
            resolve_home(None, Some(PathBuf::from("relative"))),
            Err(HomeError::Unknown)
        );
    }
}
